# #1608 — Phase 4c cold-path hardening — plan **v2**

> **v1 PLAN-KILLED 2026-05-27** (Codex + AGY + Claude SMR 3/3 converge).
> See `PLAN-KILL.md` + `claude-smr-plan-r1.md` + `codex-plan-r1.md` +
> `agy-plan-r1.md` for the six fatal axes. This file is the v2 redesign.
> v1 must NOT be resurrected — its semantic ("per-source-IP per-worker
> bucket") is structurally broken on AF_XDP zero-copy.

## 0 v2 thesis

The cold path that #1608 is trying to defend lives at
`userspace-dp/src/policy.rs:414 evaluate_policy_result_with_len` —
called from `poll_descriptor/mod.rs:1375` (ForwardCandidate slow path)
and `poll_descriptor/mod.rs:2393` (session-install slow path). The
policy matcher (`policy.rs:467 try_match_rule`) consumes ONLY
`(from_zone_id, to_zone_id, src_ip, dst_ip, protocol, src_port,
dst_port, packet_len)`. It has NO DSCP, NO TCP-flag, NO routing-
instance, NO time-of-day match dimensions today — those are firewall-
filter (`filter/mod.rs`) dimensions, a different code path that runs
BEFORE flow-cache and is not what #1608 is about.

That observation removes the v1-fatal axis 2 "wrong verdicts" risk
for the policy verdict cache provided the key covers every actual
policy-match input AND a compile-time gate fires if any future field
is added to `PolicyRule`. The #1431 cache-key invariant pattern
applies here at full strength.

v2 ships **two independent mechanisms**. Either can land alone if the
other PLAN-KILLs again:

1. **4c.1 v2 — per-DESTINATION-IP cold-path rate limit.** Per-worker
   bucket. RSS sprays sources but the DESTINATION is invariant
   (the victim service). 10× the protection of v1 with the same
   per-worker locality. Plus a per-worker AGGREGATE cold-path
   guard as a last-resort cap.
2. **4c.2 v2 — full-policy-key verdict micro-cache.** Key covers
   every `try_match_rule` input dimension (`from_zone_id`,
   `to_zone_id`, `src_ip`, `dst_ip`, `protocol`, `src_port`,
   `dst_port`). Compile-time `const_assert!` against
   `mem::size_of::<PolicyRule>` so any future field forces a
   v3 redesign.

Both are opt-in (default-off), per-zone-pair-overridable, sized to fit
in L2 cache with corrected `mem::size_of` math.

## 1 v1 PLAN-KILL kill-axis resolution

This section is mandatory per the protocol contract. Each of the six
fatal axes from `PLAN-KILL.md` is addressed below with a concrete v2
fix and the line-anchored justification.

### Axis 1 (FATAL v1) — Per-source-IP semantics unimplementable

**v1 broke:** "per source IP, per worker" bucket sees only 1/N of an
attacker spraying random src_ports across N workers. The acceptance
criterion was unmeetable.

**v2 fix: switch to per-DESTINATION-IP keying.**

The attack class #1608 defends against is "cold-path flood saturates
the policy linear scan." Every such flood has a finite set of
DESTINATIONS (the victim services). Even a 1-Mpps source-spoofed flood
with 10⁹ random src_ips converges on a small set of dst_ips: that's
what the attacker is targeting.

A per-destination-IP per-worker token bucket sees **all** packets
targeting a given destination on that worker. RSS still sprays across
workers, BUT each worker now sees its share of the attack on the
victim. Aggregate cap = `dst_pps × N_workers` — much closer to what
the operator means than v1's `src_pps × N_workers` overshoot.

**Layered backstop: per-worker AGGREGATE cold-path rate cap.** A
single `u64` counter per worker counts cold-path misses per
`now_ns / 1_000_000_000` second-bucket. If it crosses a configured
`cold_path_aggregate_pps` threshold, ALL further cold-path packets
drop until the next second-bucket. No per-IP state — single load +
branch on the hot path. Defends against the "attacker sprays 10⁶
destinations to defeat per-dst keying" case.

**CLI semantic (honest):**

```
set security screen ids-option <profile> \
    cold-path-rate-limit per-destination <pps>
set security screen ids-option <profile> \
    cold-path-rate-limit aggregate <pps>
```

Knob documentation explicitly states **per-worker semantics** with N
multiplier. Operators sizing for a 4-worker firewall set `per-dst 250`
to allow 1000 pps total per destination. The honest framing was Claude
SMR F1 option (b); v2 picks it AND combines it with the better
destination key.

Rejected alternatives:
- Cross-worker shared atomic — adds 50-100 cycles MESI per cold-path
  miss; the cold path already pays >500 cycles for the policy scan but
  MESI ping-pong across 12 workers is structurally worse than the
  policy scan it's trying to short-circuit (the policy scan is at
  least worker-local cache). Codex-killed.
- Pre-RSS aggregation at userspace-xdp shim — adds eBPF map writes per
  packet; perf regression for legitimate traffic. AGY-killed.
- Entropy-based detection — too much state, too many tunables, FN/FP
  risk. Out for v2.

### Axis 2 (FATAL v1) — Verdict cache key incomplete

**v1 broke:** 3-tuple `(src_ip, dst_ip, dst_port)` ignored zone IDs,
src_port, protocol, and any per-packet dimension.

**v2 fix: key covers every `try_match_rule` input.**

```rust
#[repr(C)]
struct VerdictCacheKey {
    from_zone_id: u16,
    to_zone_id: u16,
    protocol: u8,
    _pad0: u8,
    src_port: u16,
    dst_port: u16,
    _pad1: u16,
    src_ip: IpAddr,  // 17 bytes
    dst_ip: IpAddr,  // 17 bytes
}
// mem::size_of = 16 (head) + 17 + 17 = 50 bytes raw; aligned to 51 → 56.
```

This covers every dimension that `policy.rs:467 try_match_rule`
matches on TODAY:

| Field | Matches in `try_match_rule`? | In v2 key? |
|---|---|---|
| `from_zone_id` | yes (via `zone_pair_index.get(key)`) | yes |
| `to_zone_id` | yes (via zone_pair_key) | yes |
| `src_ip` | yes (`source_v4/v6.contains(src)`) | yes |
| `dst_ip` | yes (`destination_v4/v6.contains(dst)`) | yes |
| `protocol` | yes (`compiled_apps.matches`) | yes |
| `src_port` | yes (`compiled_apps.matches`) | yes |
| `dst_port` | yes (`compiled_apps.matches`) | yes |
| `packet_len` | NO (only used for `hit_counter.add`) | NO — bypass cache for the counter side |
| `inactive` | yes (gates rule) | covered by `config_generation` stamp |
| DSCP | NO — not in policy matcher | NO — filter dimension |
| TCP flags | NO | NO |
| forwarding-class | NO | NO |
| routing-instance | NO (decided pre-policy) | NO |
| time-of-day | NO | NO |

**Compile-time invariant** to catch silent breakage if a future PR
adds a per-packet dimension to `PolicyRule`:

```rust
// In policy.rs at PolicyRule struct end.
const _: () = {
    // Bumping this requires updating verdict cache key in
    // userspace-dp/src/afxdp/cold_path_gate/verdict_cache.rs
    // (#1608 CACHE-KEY INVARIANT, mirrors #1431).
    assert!(std::mem::size_of::<PolicyRule>() <= EXPECTED_POLICY_RULE_SIZE);
};
```

Plus a comment block on `PolicyRule` mirroring the
`filter/mod.rs:48-76` CACHE-KEY INVARIANT block, referencing #1608.

**Path (b) fallback (`has_<X>_match_terms` gate):** not needed for v2
because no in-key dimensions exist that vary per packet within a
(zone-pair, 5-tuple) group. If a future field is added, the
`assert!` fires at build time and either the key is extended OR a
per-field `policy.has_<X>_match_terms` aggregate flag gates the
cache off (path (b) per #1431).

**Wire-protocol scope:** the cache key uses runtime zone IDs from
`worker_ctx.forwarding.zone_name_to_id`. NO new wire fields needed
for the cache itself — no overlap with #1606.

### Axis 3 (FATAL v1) — Wrong insertion point

**v1 broke:** placed gate at `poll_descriptor/mod.rs:~605`, between
flow-cache miss and `resolve_flow_session_decision`. That's the
session-table lookup, NOT the policy linear scan.

**v2 fix: gate immediately wraps the policy eval calls.**

There are two `evaluate_policy_*_with_len` call sites in
`poll_descriptor/mod.rs`:

1. Line 1375 — `evaluate_policy_result_with_len` (ForwardCandidate
   slow path; the canonical "policy decision on new flow").
2. Line 2393 — `evaluate_policy_with_len` (session-install slow path
   for sessionless or NAT-driven forwarding).

v2 wraps BOTH via a single helper:

```rust
// In afxdp/cold_path_gate/mod.rs
pub(crate) fn evaluate_policy_with_verdict_cache(
    cold_gate: &mut ColdPathGate,
    state: &PolicyState,
    config_generation: u64,
    from_id: u16,
    to_id: u16,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    protocol: u8,
    src_port: u16,
    dst_port: u16,
    packet_len: u64,
    counters: &mut BatchCounters,
) -> PolicyEvaluationResult {
    // 4c.1 a) per-destination + aggregate rate gate. Returns Deny
    //        directly if rate-limited. Counts in BatchCounters.
    if let Some(deny) = cold_gate.check_rate(dst_ip, counters) {
        return deny;
    }
    // 4c.2 verdict cache lookup. On hit, packet_len is added to the
    //      cached rule's hit_counter (the only packet_len-dependent
    //      behavior in try_match_rule) so accounting is preserved.
    if let Some(hit) = cold_gate.lookup_verdict(
        from_id, to_id, src_ip, dst_ip, protocol, src_port, dst_port,
        config_generation,
    ) {
        counters.cold_path_verdict_cache_hits += 1;
        state.rules[hit.rule_idx as usize].hit_counter.add(packet_len);
        return PolicyEvaluationResult {
            action: hit.action,
            policy_id: hit.policy_id,
        };
    }
    counters.cold_path_verdict_cache_misses += 1;
    let result = evaluate_policy_result_with_len(
        state, from_id, to_id, src_ip, dst_ip, protocol,
        src_port, dst_port, packet_len,
    );
    // Insert only on Permit/Deny by rule (skip default_action with id=0,
    // since that's "no match" — caching it would block adding new rules
    // from taking effect on the cold path until eviction).
    if result.policy_id != 0 {
        cold_gate.insert_verdict(
            from_id, to_id, src_ip, dst_ip, protocol, src_port, dst_port,
            config_generation, result, /* rule_idx */ /* ... */,
        );
    }
    result
}
```

The two call sites become 9-arg → 11-arg (add `cold_gate` and
`counters` references; `config_generation` comes from `worker_ctx`).
Mechanical edit.

**Rate limit BEFORE cache lookup** — the cache hit must NOT bypass
the rate limit. Otherwise an attacker who can prime the cache with a
single "permit" verdict then floods that 7-tuple gets per-worker
free-pass at cache-lookup cost (still cheaper than policy scan but
defeats the rate-limit goal).

### Axis 4 (FATAL v1) — Token-bucket refill arithmetic loses sub-token quanta

**v1 broke:** `elapsed_ns * rate_pps / 1e9` returns 0 for typical
50 µs poll gaps at 1000 pps, but unconditionally bumps `last_refill_ns
= now_ns`. Permanent DoS.

**v2 fix: fixed-point token accumulator + conditional refill.**

```rust
struct TokenBucket {
    /// Tokens × 1_000_000_000 — fixed-point. One token-ns = 1 ns of
    /// budget. Refills add `elapsed_ns × rate_pps` (no division).
    /// Take subtracts `1_000_000_000` per packet.
    tokens_ns: u64,
    /// Cap = `burst_pps × 1_000_000_000`. Default burst = rate.
    burst_ns: u64,
    /// Wall-clock monotonic snapshot of last refill.
    last_refill_ns: u64,
    /// Configured rate (PPS) cached for refill math.
    rate_pps: u32,
}

impl TokenBucket {
    fn refill_and_take(&mut self, now_ns: u64) -> TakeResult {
        let elapsed = now_ns.saturating_sub(self.last_refill_ns);
        // elapsed (u64) × rate_pps (u32 ≤ 2³² − 1) fits in u128.
        let add = (elapsed as u128).saturating_mul(self.rate_pps as u128);
        let new_tokens = (self.tokens_ns as u128).saturating_add(add)
            .min(self.burst_ns as u128) as u64;
        // Critical: only update last_refill_ns AFTER we credit. This
        // guarantees no lost sub-token quanta — every nanosecond between
        // refills contributes exactly `rate_pps` to the accumulator.
        self.tokens_ns = new_tokens;
        self.last_refill_ns = now_ns;
        if self.tokens_ns >= 1_000_000_000 {
            self.tokens_ns -= 1_000_000_000;
            TakeResult::Allow
        } else {
            TakeResult::Deny
        }
    }
}
```

**Worked trace for 50 µs poll cadence at 1000 PPS:**
- Initial: `tokens_ns = burst_ns = 1_000_000_000_000` (1000 token-ns
  burst).
- Poll t=0: take 1 pkt → `tokens_ns = 999_000_000_000`.
- Poll t=50µs (50,000 ns): elapsed=50_000, add=50_000×1000=50_000_000
  → `tokens_ns = 999_050_000_000`. Take 1 → 998_050_000_000. Allow.
- After 1000 packets (~50ms), each tick credits 50M, bucket drains
  exactly 1B per packet at 1000 pps steady state. Bucket converges
  to ~burst_ns – 1_000_000_000 once steady. No drift.

**Worked trace for slow trickle (1 pkt every 10s at 1000 PPS):**
- t=0: bucket=burst, take 1 → bucket=burst − 1B.
- t=10s: elapsed=10⁹×10. add = 10¹⁰ × 1000 = 10¹³ — caps at `burst_ns`.
- Take 1, bucket=burst − 1B. Trickle source never goes negative.

**Worked trace for overflow (100s of inactivity):**
- elapsed = 10¹¹ ns, add = 10¹⁴ ≤ u64::MAX (1.8×10¹⁹). Saturating
  multiply is defensive only.

Critically — `last_refill_ns = now_ns` is set AFTER the refill credit
is applied, NOT before. The credit always reflects the full elapsed
window. There is no quantization loss because `tokens_ns` is in ns
units, not whole tokens.

### Axis 5 (FATAL v1) — 416 KB storage exceeds 256 KB budget

**v1 broke:** corrected `mem::size_of` math: `Option<IpAddr>=24` +
`TokenBucket=24` (with new fixed-point fields) → 48 B/entry; 4096 ×
48 = 192 KB just for bucket table. Plus 4096 × 64 verdict cache =
256 KB. Total 448 KB.

**v2 fix: per-table sizing with `mem::size_of` proofs + compile-time
budget assertions.**

```rust
// 4c.1 per-destination table: 1024 sets × 4 ways = 4096 entries.
// Per-entry: VerdictCacheKey approach NOT applicable; this table
// keys on dst_ip + bucket fields only.
#[repr(C)]
struct DestBucketEntry {
    dst_ip: Option<IpAddr>,    // 24 B (17 + tag + 6 pad)
    bucket: TokenBucket,       // 24 B (8+8+8 nicely aligned)
}
// mem::size_of::<DestBucketEntry>() = 48 (verified by const_assert)
const _: () = assert!(std::mem::size_of::<DestBucketEntry>() == 48);

// Drop to 2048 entries × 4 ways = 8192 sets total? — 8192 × 48 = 384 KB.
// Too big. Use 512 sets × 4 ways = 2048 entries.
//   2048 × 48 = 96 KB.  ✓
const DEST_TABLE_SETS: usize = 512;
const DEST_TABLE_WAYS: usize = 4;
const DEST_TABLE_ENTRIES: usize = DEST_TABLE_SETS * DEST_TABLE_WAYS; // 2048
const _: () = assert!(
    DEST_TABLE_ENTRIES * std::mem::size_of::<DestBucketEntry>() <= 96 * 1024
);

// Aggregate cap: single u64 + epoch + count
struct AggregateGate {
    epoch_ns: u64,    // start of current second-bucket
    count_pps: u32,   // cold-path packets observed this epoch
    cap_pps: u32,     // configured threshold
}
// Total = 16 B.  ✓
```

```rust
// 4c.2 verdict cache: 1024 entries (256 sets × 4 ways).
// Compact entry: hash(key) → bucket; full key stored in entry for
// verification. Per-entry budget aim: 80 B.
#[repr(C)]
struct VerdictCacheEntry {
    // Tagged 'empty' if key_hash == 0; reserved hash 0 is never
    // returned (re-hashed to 1 if it falls on 0).
    key_hash: u64,                // 8
    from_zone_id: u16,            // 2
    to_zone_id: u16,              // 2
    src_port: u16,                // 2
    dst_port: u16,                // 2
    protocol: u8,                 // 1
    _pad: u8,                     // 1
    src_ip: IpAddr,               // 24 (17 + tag + 6 pad)
    dst_ip: IpAddr,               // 24
    config_generation: u64,       // 8 (stamp)
    rule_idx: u32,                // 4 (index into PolicyState.rules)
    policy_id: u32,               // 4
    action: u8,                   // 1
    _pad2: [u8; 7],               // 7
}
const _: () = assert!(std::mem::size_of::<VerdictCacheEntry>() == 88);

const VERDICT_TABLE_SETS: usize = 256;
const VERDICT_TABLE_WAYS: usize = 4;
const VERDICT_TABLE_ENTRIES: usize = VERDICT_TABLE_SETS * VERDICT_TABLE_WAYS; // 1024
const _: () = assert!(
    VERDICT_TABLE_ENTRIES * std::mem::size_of::<VerdictCacheEntry>() <= 96 * 1024
);
```

**Total per worker:** 96 KB (dest bucket) + 88 KB (verdict cache) + 16 B
(aggregate) ≈ **184 KB**, within the 256 KB budget. 72 KB headroom.

If reviewers want tighter — drop verdict cache to 128 sets × 4 = 512
entries = 44 KB; total 140 KB. Pick the larger sizing for v2 since
smaller hits eviction faster and a port-scan over 1024 ports holds
1024 verdicts which fits the 1024-entry cache.

### Axis 6 (MAJOR v1) — Wire-line acceptance gate depends on #1607

**v1 broke:** acceptance criterion "≥50% CPU drop under 1 Mpps flood"
required #1607's microbench harness which is itself in plan-kill /
v2 redesign.

**v2 fix: defer empirical CPU% gate to follow-up; ship mechanism
with local microbench proving O(1) behavior.**

v2 acceptance:

- [ ] `cargo bench --bench cold_path_4c` shows verdict cache hit is
  O(1) hash + memcmp, ≤30 ns per hit on standard test box. The bench
  measures the cache structure in isolation; it does NOT claim a 1
  Mpps wire-line number.
- [ ] Token bucket refill+take is O(1), ≤15 ns per call (cargo bench).
- [ ] Unit-tested correctness: refill arithmetic under fast-poll, slow-
  trickle, and 100s-idle windows (each as named tests).
- [ ] Cluster smoke matrix (v4/v6 × push/-R × CoS-off/CoS-on) on
  loss userspace cluster — no regression vs master.
- [ ] `make test-failover` passes (cold-path-gate is per-worker, HA
  unaffected).
- [ ] **NEW follow-up issue** filed against #1607-v2: "Once
  cold-path microbench harness lands, gate Phase 4c.x defensive
  effectiveness with synthetic flood at 1 Mpps."

This is the honest framing per Claude SMR F3 v1 recommendation.

## 2 Implementation outline

### 2.1 New module layout (matches `feedback_refactor_module_dir_layout`)

```
userspace-dp/src/afxdp/cold_path_gate/
    mod.rs                  -- ColdPathGate struct + entry helper
    dest_bucket.rs          -- 4c.1 per-destination + aggregate
    verdict_cache.rs        -- 4c.2 verdict micro-cache
    tests.rs                -- unit tests
```

### 2.2 Per-worker storage

`ColdPathGate` lives on `BindingWorker` (per-worker, allocation-free)
beside `binding.flow.flow_cache`. Field name `cold_gate`.

### 2.3 Wire protocol (single Option field, end of struct)

```rust
// userspace-dp/src/protocol/security.rs
// Add to ScreenProfileSnapshot at end (avoids #1606 merge conflict).
#[serde(rename = "cold_path_rate_limit_per_destination_pps", default)]
pub cold_path_rate_limit_per_destination_pps: Option<u32>,

#[serde(rename = "cold_path_rate_limit_aggregate_pps", default)]
pub cold_path_rate_limit_aggregate_pps: Option<u32>,

#[serde(rename = "cold_path_verdict_cache_enabled", default)]
pub cold_path_verdict_cache_enabled: bool,
```

Three fields. `Some(0)` is treated as "drop everything matching this
gate" (no silent reinterpretation; F7 recovery).

### 2.4 Junos CLI (new entries, not overlap with #1606)

```
set security screen ids-option <profile> \
    cold-path-rate-limit per-destination <pps>
set security screen ids-option <profile> \
    cold-path-rate-limit aggregate <pps>
set security screen ids-option <profile> \
    cold-path-verdict-cache  (boolean, default off)
```

Wire-protocol both-sides check per `feedback_wire_protocol_both_sides`:
both `pkg/config/typed.go` (Go) and
`userspace-dp/src/protocol/security.rs` (Rust) get updated in same PR.

### 2.5 Insertion site exact edits

Two call sites in `poll_descriptor/mod.rs`:

- Line 1375: replace `evaluate_policy_result_with_len(state, from_id,
  to_id, src_ip, dst_ip, proto, sport, dport, len)` with
  `cold_path_gate::evaluate_policy_with_verdict_cache(&mut
  binding.cold_gate, state, validation.config_generation, from_id,
  to_id, src_ip, dst_ip, proto, sport, dport, len, &mut counters)`.
- Line 2393: same edit for `evaluate_policy_with_len` site.

### 2.6 Generation invalidation

The verdict cache stamps `config_generation: u64`. Lazy invalidation
on lookup (entry's stamp ≠ current → miss + evict). No bucket stamp:
buckets are policy-independent; an operator who changes
`cold_path_rate_limit_per_destination_pps` mid-run sees new rate
applied at next refill (rate stored on the bucket and re-read from
the snapshot per lookup is too expensive — instead, on snapshot
reload we walk the bucket table once and update each `rate_pps`
field. One-time cost on commit, ~µs).

## 3 Files touched (exact list)

Rust dataplane:
- NEW `userspace-dp/src/afxdp/cold_path_gate/mod.rs`
- NEW `userspace-dp/src/afxdp/cold_path_gate/dest_bucket.rs`
- NEW `userspace-dp/src/afxdp/cold_path_gate/verdict_cache.rs`
- NEW `userspace-dp/src/afxdp/cold_path_gate/tests.rs`
- EDIT `userspace-dp/src/afxdp/mod.rs` — `pub(super) mod cold_path_gate;`
  + add 3 fields to `BatchCounters` (cold_path_rate_limit_drops,
  cold_path_verdict_cache_hits, cold_path_verdict_cache_misses)
- EDIT `userspace-dp/src/afxdp/worker/mod.rs` — add `cold_gate:
  ColdPathGate` to `BindingWorker`
- EDIT `userspace-dp/src/afxdp/poll_descriptor/mod.rs` — two call-site
  edits (line 1375 + line 2393)
- EDIT `userspace-dp/src/policy.rs` — add CACHE-KEY INVARIANT block
  mirroring `filter/mod.rs:48-76`; add `const _:() = assert!()` on
  `PolicyRule` size; export `EXPECTED_POLICY_RULE_SIZE`
- EDIT `userspace-dp/src/protocol/security.rs` — three `Option`/`bool`
  fields at end of `ScreenProfileSnapshot`

Go control plane:
- EDIT `pkg/config/typed.go` — three new fields on per-zone screen
  struct
- EDIT `pkg/cmdtree/tree.go` — three CLI entries
- EDIT `pkg/config/compiler.go` — emit on snapshot

Benchmarks:
- NEW `userspace-dp/benches/cold_path_4c.rs` — O(1) microbench, no
  wire-line claims

Docs:
- EDIT `docs/userspace-jit-design.md` — Phase 4c row (note: empirical
  CPU% gate deferred to #1607-follow-up)
- NEW `docs/cold-path-gate.md` — operator-facing brief documenting
  per-worker semantics + N multiplier explicitly

## 4 Open questions for reviewers (must answer before PLAN-READY)

**Q1 v2 — Per-destination keying vs per-{dest, dport} keying.**
v2 keys the rate-limit on `dst_ip` alone. An attacker spraying
random dst_ports against the same dst_ip drains one bucket. Is
`dst_ip` alone the right granularity, or should we use `(dst_ip,
dst_port)` so a flood on port 80 doesn't rate-limit legitimate
traffic on port 443 to the same host? Trade-off: per-(ip,port)
doubles the key space (more entries, more collisions); per-ip
catches all-ports-of-victim floods more aggressively. My read: ship
v2 with per-ip; if operators report per-port granularity is needed,
add as a follow-up knob. **Hostile-pick please.**

**Q2 v2 — `policy_id == 0` (default-action) cache exclusion.**
v2 §1 axis 3 helper skips cache insert when `result.policy_id == 0`
(default action, no matching rule). Without that skip, a flood
matching the default-deny gets cached, then a config change adding
a permit-rule for that flow doesn't take effect until eviction.
Skipping costs 2× the policy-scan work for unmatched packets (no
cache hit ever). Is this the right trade or should the
default-action be cached with a special path that re-validates on
config bump? My read: skip; the default-action path is supposed to
be infrequent in production configs (most flows match a real rule).

**Q3 v2 — `packet_len` semantic in the cache.**
The policy matcher's `packet_len` parameter is consumed ONLY by
`hit_counter.add(packet_len)`. v2 helper preserves correct accounting
by calling `state.rules[hit.rule_idx].hit_counter.add(packet_len)`
on every cache hit. That requires storing the `rule_idx` in the
cache entry (4 B field already accounted in §1 axis 5 layout). Is
this the right approach, or should the verdict cache also cache the
`hit_counter` Arc? My read: rule_idx is correct — Arc clone on insert
is O(1) but ~8 B more per entry; index is cheaper.

**Q4 v2 — Bucket size for IPv6 source variety.**
The dest-bucket table has 512 sets × 4 ways = 2048 entries. A single
WAN-facing firewall serving 8 victim services from 8 distinct dst_ip
addresses uses 8 entries. A multi-tenant firewall fronting 200 VMs
uses 200 entries. Both fit comfortably. The pathological case (a
firewall fronting 50k loadbalancer VIPs) overflows; eviction is set-
LRU. Is 2048 entries enough, or should we extend to 4096? My read:
2048 is enough for the small-botnet flood case #1608 is about; large-
fleet deployments are a separate sizing concern.

**Q5 v2 — `make test-failover` interaction.**
The cold-path-gate state is per-worker, per-binding, not synced
across HA peers. On failover, the new master starts with empty
buckets and an empty verdict cache. An attacker mid-flood gets one
burst-window of unfiltered cold-path traffic on the new master
(same property as flow-cache). Is the right answer (a) document and
move on, (b) add HA sync for buckets/cache, or (c) something else?
My read: (a). Adding HA sync for a defensive-depth knob is over-
engineering; the empty bucket gives the attacker a few packets, not
a full bypass.

**Q6 v2 — Aggregate cap semantics under second-boundary jitter.**
The aggregate gate epochs on `now_ns / 1_000_000_000`. Across the
boundary, an attacker pacing exactly to land on the boundary gets
nearly 2× the configured rate (full cap from second N + full cap
from second N+1 in a sub-ms burst). Token-bucket-shaped aggregate
gate would fix this but doubles the storage. Acceptable jitter or
tighten? My read: 2× burst on second boundaries is fine for a
defensive-depth gate; the underlying per-destination buckets are the
primary mechanism.

## 5 Acceptance criteria (concrete, defer-microbench-to-#1607-v2)

- [ ] `cargo build --release -p userspace-dp` clean
- [ ] `cargo test --release -p userspace-dp` clean, 5/5 flake check on
  new tests
- [ ] `go test ./...` clean
- [ ] `cargo bench --bench cold_path_4c` shows O(1) verdict-cache hit
  (≤30 ns) + O(1) bucket refill (≤15 ns). No wire-line claims.
- [ ] `make cluster-deploy` + Pass A full smoke matrix on loss
  userspace cluster (v4/v6 × push/-R × CoS-off/CoS-on); no regression
- [ ] `make test-failover` clean
- [ ] `docs/userspace-jit-design.md` Phase 4c row updated with
  honest framing
- [ ] `docs/cold-path-gate.md` operator-facing brief written
- [ ] Compile-time `assert!` on `mem::size_of::<PolicyRule>` lands
  with cited #1431-style invariant comment
- [ ] Follow-up issue filed: "Gate 4c defensive effectiveness with
  #1607-v2 microbench"
- [ ] No file-zone overlap with #1606 (verified — different field
  block + different file region in `protocol/security.rs`)
- [ ] No file-zone overlap with #1607-v2 (test/incus/ vs
  cold_path_gate/)
- [ ] No touch of `pkg/cluster/` (verified)

## 6 PLAN-KILL exposure

- **R1 v2: per-destination keying could miss spray-dst attacks.**
  If an attacker has access to 10k distinct dst_ips on the firewall,
  per-dst buckets each see 1/10k of the flood and never trip. The
  aggregate cap is the backstop for this case. Both are needed.
- **R2 v2: verdict cache pollution under SCAN.**
  A horizontal port-scan over 1024 ports against one dst_ip fills
  1024 distinct verdict-cache entries (same (zone-pair, src_ip,
  dst_ip, proto) but varying dst_port + src_port). With 1024
  entries × 4 ways = 4096 slots, the scan fits comfortably. A
  source-spray scan (random src_ip × all dst_ports) overflows the
  cache rapidly; second-pass hit rate drops to ~25%. The bench must
  measure this. If reviewer pushes, tighten to "verdict cache
  enabled per zone-pair" so operator can disable on the noisy edge.
- **R3 v2: compile-time `assert!` on `PolicyRule` size is brittle.**
  Any cosmetic refactor of `PolicyRule` field order changes the
  computed size and breaks the assert. Mitigation: pick a generous
  `EXPECTED_POLICY_RULE_SIZE` that covers known fields with 8 B
  headroom; document on the assert that the value is a build-time
  CACHE-KEY INVARIANT trip and the right response is "add field to
  verdict cache key OR add path-(b) `has_<X>_match_terms` gate, not
  bump the constant."
- **R4 v2: per-zone-pair-overridable knob shape not in v2.**
  v2 keeps the knob per-screen-profile (matches `ids-option
  <profile>` shape). Operator wanting per-zone-pair tuning files
  follow-up. Acceptable scope.
- **R5 v2: aggregate gate sub-second jitter.**
  See Q6.
- **R6 v2: `now_ns` cadence under flood.**
  Claude SMR F4 (v1) raised this. Confirmed by re-reading
  `poll_descriptor/mod.rs:448-460`: `now_ns` is captured once per
  `poll_binding_process_descriptor` batch invocation. Under a
  policy-scan-bound flood, the batch IS the policy scan — but each
  batch is bounded by the AF_XDP rx ring size (typically 2048 desc).
  Per-batch `now_ns` lag is ≤ (2048 packets × policy_scan_ns/packet)
  ≈ 2048 × 500 ns = ~1ms. Acceptable for second-grained PPS gates.
  Sub-ms-grained gates would need mid-batch `now_ns` refresh which
  is not what 4c.1 is asking for.

## 7 Out of scope (filed as follow-ups if reviewers want)

- Per-zone-pair tuning of the knobs (currently profile-level)
- Per-/64 IPv6 dest aggregation (the issue is one /128 per service)
- HA peer cold-gate state sync
- Cross-worker shared per-destination atomic bucket (would meet
  aggregate-precise semantic but pays MESI cost)
- Operator-facing `clear security cold-path-gate` command
- 1 Mpps wire-line acceptance — gated on #1607-v2 microbench
- Adaptive PPS based on observed legitimate-cold-path rate
- Per-source allowlist (`never-rate-limit-source` knob)
- Token-bucket-shaped aggregate gate (replaces second-bucket counter)

## 8 Plan version

v2 — addresses all six v1 PLAN-KILL fatal axes with concrete fixes
and worked traces. Drafted with policy.rs:414/467 and
poll_descriptor/mod.rs:1375 + 2393 in front of me; symbol refs at HEAD
28421304e.
