# Codex plan-review r2 — #1608 v2

**Verdict:** PLAN-KILL

v2 fixes some v1 defects, but it introduces new structural defects that are not implementation nits. The biggest one: the rate limiter is configured as a Junos screen-profile feature, but v2 stores one `dst_ip` bucket with one `rate_pps`. That cannot represent per-zone/per-profile screen semantics. A second blocker is that the planned wrapper at the `poll_descriptor.rs:2393` call site does not actually make a rate-limit `Deny` drop in the current control flow.

## Kill-axis verification (v1 → v2)

### Axis 1 — per-source-IP RSS spray defeat

**Verdict: v1 source-RSS fatal addressed, but v2 creates a new rate-limit semantic fatal.**

v2's claimed fix is real as far as the original per-source RSS spray defect goes:

> `plan.md:58` — `**v2 fix: switch to per-DESTINATION-IP keying.**`

> `plan.md:66-70` — `A per-destination-IP per-worker token bucket sees **all** packets targeting a given destination on that worker. RSS still sprays across workers, BUT each worker now sees its share of the attack on the victim. Aggregate cap = \`dst_pps × N_workers\``

This no longer claims impossible per-source semantics. The operator-facing N multiplier is also explicit:

> `plan.md:89-91` — `Knob documentation explicitly states **per-worker semantics** with N multiplier. Operators sizing for a 4-worker firewall set \`per-dst 250\` to allow 1000 pps total per destination.`

That fixes the original axis by changing the primitive. It is not a proof of global per-destination enforcement, but it is at least honest AF_XDP-local enforcement.

New variant introduced by v2: the destination bucket is not keyed by zone/profile even though the knob is a screen-profile knob. v2 says the wire/CLI fields live on `ScreenProfileSnapshot` / `ids-option`:

> `plan.md:455-464` — add `cold_path_rate_limit_per_destination_pps`, `cold_path_rate_limit_aggregate_pps`, and `cold_path_verdict_cache_enabled` to `ScreenProfileSnapshot`

> `plan.md:472-478` — `set security screen ids-option <profile> cold-path-rate-limit ...`

But the table key is only destination IP:

> `plan.md:340-342` — `struct DestBucketEntry { dst_ip: Option<IpAddr>, bucket: TokenBucket }`

And v2 stores exactly one rate in the bucket:

> `plan.md:501-505` — `on snapshot reload we walk the bucket table once and update each \`rate_pps\` field`

The source confirms screen profiles are per-zone, not global: `ScreenProfileSnapshot` has `zone` at `userspace-dp/src/protocol/security.rs:9-10`, and runtime `ScreenState` stores `profiles: FxHashMap<String, ScreenProfile> // zone_name -> profile` at `userspace-dp/src/screen/mod.rs:75-78`.

So two zones/profiles hitting the same `dst_ip` cannot have different configured rates, and a disabled profile can be collateral-dropped by a bucket populated under an enabled profile. That is a Junos semantics break, not a tuning nit. The limiter key must include at least ingress zone/profile identity, or the feature must be redesigned as a truly global knob.

### Axis 2 — verdict cache wrong-verdict

**Verdict: current matcher key mostly fixed; the claimed #1431-style invariant is paper, and the hit-counter plan does not compile against the current API.**

v2's key now includes the current policy matcher dimensions:

> `plan.md:111` — `**v2 fix: key covers every \`try_match_rule\` input.**`

> `plan.md:116-124` — `from_zone_id`, `to_zone_id`, `protocol`, `src_port`, `dst_port`, `src_ip`, `dst_ip`

That is structurally correct for the current source. `evaluate_policy_result_with_len` keys by `zone_pair_key(from_id, to_id)` at `userspace-dp/src/policy.rs:425-431`, and `try_match_rule` consumes only `src_ip`, `dst_ip`, `protocol`, `src_port`, `dst_port`, and `packet_len` for counter accounting at `userspace-dp/src/policy.rs:467-503`.

But v2's future-proofing does not actually mirror #1431. The canonical invariant says every new match criterion must be classified as in-key or cache-sensitive, and explicitly warns that skipping classification silently breaks cache reuse at `userspace-dp/src/filter/mod.rs:48-76`.

v2 replaces that with a layout tripwire:

> `plan.md:149-159` — `Compile-time invariant ... assert!(std::mem::size_of::<PolicyRule>() <= EXPECTED_POLICY_RULE_SIZE);`

That is not equivalent. `PolicyRule` already contains `scheduler_name: String` at `userspace-dp/src/policy.rs:53-60`, and `PolicyRuleSnapshot` already carries `scheduler_name` at `userspace-dp/src/protocol/security.rs:173-178`. If a future PR starts enforcing scheduler/time-of-day semantics using the existing field, `mem::size_of::<PolicyRule>()` does not change. v2's asserted invariant will not fire.

The cache-hit accounting path is also underspecified against source. v2 says:

> `plan.md:223` — `state.rules[hit.rule_idx as usize].hit_counter.add(packet_len);`

But `PolicyEvaluationResult` contains only `action` and `policy_id` at `userspace-dp/src/policy.rs:47-50`; no `rule_idx` is returned by `evaluate_policy_result_with_len`. The plan leaves this as a placeholder:

> `plan.md:237-240` — `cold_gate.insert_verdict(... result, /* rule_idx */ /* ... */)`

And `PolicyRuleCounter::add` is private to `policy.rs` (`fn add`, not `pub(crate) fn add`) at `userspace-dp/src/policy.rs:127-128`, so `afxdp/cold_path_gate` cannot call the code v2 sketches. This is fixable with a policy API redesign, but v2 has not specified it.

### Axis 3 — wrong insertion point

**Verdict: the line numbers are corrected; the call-site semantics are not.**

v2 correctly identifies both policy-eval call sites:

> `plan.md:184-190` — `Line 1375 — evaluate_policy_result_with_len` and `Line 2393 — evaluate_policy_with_len`

The source agrees: `userspace-dp/src/afxdp/poll_descriptor/mod.rs:1375-1385` calls `evaluate_policy_result_with_len`, and `userspace-dp/src/afxdp/poll_descriptor/mod.rs:2393-2403` calls `evaluate_policy_with_len`.

The first call site can be wrapped cleanly because `policy_result.action` controls the permit/deny branch at `poll_descriptor/mod.rs:1386` and the deny path emits a policy deny at `poll_descriptor/mod.rs:1811-1821`.

The second call site is different. In the current source, the `if let PolicyAction::Permit = evaluate_policy_with_len(...)` at `poll_descriptor/mod.rs:2393-2403` only gates the source-NAT calculation. After the `if`, the missing-neighbor session is still built and installed at `poll_descriptor/mod.rs:2467-2484`. v2 says:

> `plan.md:489-494` — `Line 2393: same edit for \`evaluate_policy_with_len\` site.`

That is structurally wrong. If the helper returns a rate-limit `Deny` at line 2393, the caller does not drop. It just skips the inner NAT branch and continues to pending session install. v2 must restructure the missing-neighbor branch so a cold-gate deny recycles/drops before session installation. A mechanical wrapper is insufficient.

There is a second mechanical blocker: the helper signature lacks `now_ns`:

> `plan.md:196-209` — `evaluate_policy_with_verdict_cache(...)` takes `cold_gate`, policy state, generation, tuple fields, `packet_len`, and counters, but no timestamp.

But the rate gate requires `now_ns`: aggregate epochs are defined as `now_ns / 1_000_000_000` at `plan.md:72-75`, and the bucket API is `fn refill_and_take(&mut self, now_ns: u64)` at `plan.md:279-281`. The timestamp is in scope at `poll_descriptor.rs:448`, but v2 does not pass it.

### Axis 4 — token-bucket refill truncation

**Verdict: arithmetic fixed in isolation; integration still incomplete because the wrapper cannot supply time.**

v2's arithmetic fix is the right class of fix:

> `plan.md:263` — `**v2 fix: fixed-point token accumulator + conditional refill.**`

> `plan.md:281-290` — compute `elapsed`, add `elapsed * rate_pps` in fixed-point units, then set `last_refill_ns = now_ns` after crediting.

This addresses v1's truncation bug. There is no lost sub-token quantum because `tokens_ns` retains the fractional credit.

The new variant is the integration bug from Axis 3: v2's helper cannot call `refill_and_take(now_ns)` because it never receives `now_ns` (`plan.md:196-209`). If the intended recovery is to call `clock_gettime` inside `check_rate`, v2 needs to say so and price that per cold-path packet. As written, the math is correct but the proposed call graph cannot execute it.

### Axis 5 — storage exceeds 256 KB budget

**Verdict: v1's 416 KB design is gone, but v2's storage proof is false and the placement blows the stated per-worker budget model.**

v2 claims corrected sizing:

> `plan.md:341-345` — `dst_ip: Option<IpAddr> // 24 B`, `bucket: TokenBucket // 24 B`, `size_of::<DestBucketEntry>() == 48`

> `plan.md:381-389` — `src_ip: IpAddr // 24`, `dst_ip: IpAddr // 24`, `size_of::<VerdictCacheEntry>() == 88`

Those asserts are false on the toolchain in this worktree (`rustc 1.95.0`). `std::net::IpAddr` and `Option<IpAddr>` are 17 bytes with alignment 1. The sketched `TokenBucket` has three `u64`s plus a `u32`, so `#[repr(C)]` size is 32, not 24. The sketched structures are:

- `TokenBucket`: 32 B
- `DestBucketEntry`: 56 B, so 2048 entries = 112 KiB
- `VerdictCacheEntry`: 80 B, so 1024 entries = 80 KiB

The corrected total is still under 256 KiB, so this is not the same storage fatal as v1. But v2's compile-time asserts would fail to build, and the plan's proof cannot be accepted as written.

The deeper problem is placement. v2 says:

> `plan.md:399-400` — `**Total per worker:** 96 KB ... + 88 KB ... ≈ **184 KB**`

But the implementation outline says:

> `plan.md:449-450` — `ColdPathGate lives on \`BindingWorker\` ... Field name \`cold_gate\`.`

`BindingWorker` is per binding at `userspace-dp/src/afxdp/worker/mod.rs:93-155`, and the worker loop polls a slice of bindings at `userspace-dp/src/afxdp/worker/loop_body/mod.rs:567-575`. So v2's state is per binding, not per worker. A worker with multiple bindings gets multiple cold gates, and both the L2 budget and the documented N multiplier become binding-count-dependent. Either move the gate to worker-level state or rewrite the storage/semantic budget as per-binding.

### Axis 6 — cargo-bench substitute is dishonest

**Verdict: fixed.**

v2 stops claiming that an in-process bench proves the 1 Mpps AF_XDP/RSS acceptance result:

> `plan.md:413-414` — `**v2 fix: defer empirical CPU% gate to follow-up; ship mechanism with local microbench proving O(1) behavior.**`

> `plan.md:418-421` — the bench `does NOT claim a 1 Mpps wire-line number.`

That addresses v1's dishonest validation axis. The acceptance criteria at `plan.md:608-630` are now build/test/microbench/smoke gates plus a follow-up issue. I do not kill v2 on Axis 6.

## New v2-introduced concerns

### Fatal N1 — screen-profile semantics cannot be represented by a `dst_ip`-only bucket

This is the new PLAN-KILL. The config surface is per Junos `ids-option` / per screen profile (`plan.md:455-464`, `plan.md:472-478`), while runtime screen profiles are keyed by zone (`security.rs:9-10`, `screen/mod.rs:75-78`). The limiter state is keyed only by `dst_ip` and contains one `rate_pps` (`plan.md:340-342`, `plan.md:501-505`).

That cannot implement two zones/profiles with different cold-path rates for the same destination. It also cannot implement "profile disabled" for one zone when another zone has populated the same destination bucket. This requires redesigning the key/config plumbing, not just changing a constant.

### Fatal N2 — the `poll_descriptor.rs:2393` wrapper does not drop on deny

v2 treats both call sites as mechanically equivalent (`plan.md:489-494`). They are not. At `poll_descriptor.rs:2393-2403`, a non-permit only skips the NAT branch; execution continues to missing-neighbor session creation at `poll_descriptor.rs:2467-2484`. A rate-limit `Deny` from the helper therefore fails to enforce the rate limit on that path.

### Major N3 — v2's helper cannot implement its own rate math

The helper signature (`plan.md:196-209`) omits `now_ns`, but both the aggregate cap and token bucket require it (`plan.md:72-75`, `plan.md:279-281`). This is an implementation-shape miss, and it also hides the cost decision between passing the batch timestamp and taking a new timestamp per cold-path packet.

### Major N4 — verdict cache API changes are not specified

The current policy API returns no `rule_idx` (`policy.rs:47-50`), and `PolicyRuleCounter::add` is private (`policy.rs:127-128`). v2's cache-hit accounting code (`plan.md:223`) and insertion placeholder (`plan.md:237-240`) require API changes that are absent from the file list except a vague `policy.rs` invariant edit at `plan.md:521-523`.

### Major N5 — the #1431 invariant is weakened into a layout assert

The source invariant requires semantic classification of cache-sensitive fields (`filter/mod.rs:48-76`). v2's `size_of::<PolicyRule>() <= EXPECTED_POLICY_RULE_SIZE` (`plan.md:149-159`) does not catch semantic activation of existing fields such as `scheduler_name` (`policy.rs:53-60`, `security.rs:173-178`), and `<=` explicitly allows some additions without tripping. This needs a real policy cache-key invariant and tests, not a layout proxy.

### Major N6 — storage proof has false constants and wrong ownership level

The asserted `DestBucketEntry == 48` and `VerdictCacheEntry == 88` values (`plan.md:341-389`) are false. More importantly, `ColdPathGate` is placed on `BindingWorker` (`plan.md:449-450`), so the "per worker" budget in `plan.md:399-400` is not the implemented ownership boundary.

## Verdict and recommendation

**PLAN-KILL.**

Do not implement v2 as written. The source-RSS, token-refill, insertion-line-number, and validation axes are improved over v1, but v2 has new structural defects:

1. The rate limiter cannot honor Junos screen-profile semantics with a `dst_ip`-only bucket and one stored rate.
2. The second policy call site would not drop on a cold-gate deny.
3. The storage/ownership proof says per-worker while the plan installs per-binding state.
4. The verdict-cache hit-counter and #1431-invariant pieces require policy API and invariant redesign not specified by the plan.

Recovery requires a v3 plan, not implementation nits: choose global vs per-profile limiter semantics, key the bucket accordingly, pass the active profile/rate and `now_ns` into the helper, restructure the missing-neighbor call site, define the policy API that returns/stores `rule_idx` safely, and redo the size/placement proof at the actual ownership boundary.
