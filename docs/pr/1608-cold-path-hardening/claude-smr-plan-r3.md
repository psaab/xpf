# Claude SMR plan-review r3 — #1608 v2 (post-Codex-r2 + AGY-r2)

**Reviewer hat:** HPC networking + DDoS mechanism + AF_XDP cache
design + CPU-arch + Junos policy-semantics SMR. Hostile by mandate.
This is a SELF-CORRECTION on my r2 PLAN-READY-WITH-NITS verdict in
light of Codex r2 + AGY r2 findings.

**Verdict:** PLAN-KILL — converging with Codex r2 + AGY r2 for 3/3 on v2

## Why I missed these in r2

My r2 verdict was PLAN-READY-WITH-NITS. After reading Codex r2 + AGY
r2, that verdict was structurally wrong. I checked the policy matcher
shape against the cache key (correct) and the token-bucket math
(correct) but I did NOT walk:

1. The call-graph at `poll_descriptor/mod.rs:2393` to see whether a
   helper returning `Deny` actually DROPS at that site, vs continuing
   to session install. Codex N2 caught this; I did not.
2. The deny-event emission downstream of policy result at
   `poll_descriptor/mod.rs:1810-1821`. AGY F2 caught this; a Deny
   from the cache gate triggers `emit_policy_deny_event` for every
   rate-limited packet — 1 Mpps event-stream DoS. I did not.
3. The actual Rust layout of `TokenBucket` (3×u64 + u32 = 32 B after
   alignment, NOT 24 B as plan claims). AGY F3 / Codex r2 §Axis 5
   caught this. I accepted the plan's size_of claim without rebuilding
   it. The compile-time `assert!(... == 48)` and
   `assert!(... == 88)` will fail to build.
4. The ownership boundary: `BindingWorker` is per-binding, NOT per-
   worker (a worker polls a slice of bindings at
   `worker/loop_body/mod.rs:567-575`). Codex N6 caught this; the
   "184 KB per worker" budget is wrong by a binding-count multiplier.
5. The screen-profile zone semantic: `ScreenProfileSnapshot` is keyed
   per-zone in runtime `screen/mod.rs:75-78`, but the plan's bucket
   table is keyed only by `dst_ip`. Two zones with different
   `cold_path_rate_limit_per_destination_pps` cannot coexist if they
   share a destination IP. Codex N1 caught this; classic Junos-
   semantic mismatch.
6. The eviction-storm bypass: on a high-entropy spray, each lookup
   evicts the LRU way and re-creates the entry with full `burst_ns`
   credit — every packet allowed. AGY F1 caught this. I did not
   audit the cache-miss-init path.
7. The default-deny-flood zero-hit case: skipping `policy_id == 0`
   means the cache misses on EVERY attack packet under a flood that
   doesn't match any permit rule (the exact attack class #1608 is
   trying to defend). AGY F4 caught this; my r2 endorsed the skip.
8. The `rule_idx` and `hit_counter.add` API gap: `PolicyEvaluationResult`
   doesn't carry `rule_idx`, and `PolicyRuleCounter::add` is `fn`-
   private. Codex N4 caught this. I treated v2 §1 axis 3's pseudo-
   code as if it could compile against the existing API.

## Axis-by-axis re-verdict (re-walked against Codex r2 + AGY r2)

### Axis 1 — per-source-IP RSS spray defeat

**Re-verdict: PLAN-KILL.** Plan v2's pivot to per-destination keying
is the right *primitive*, but the *implementation* has TWO new
fatals:

- AGY F1: cache-miss-init starts new bucket at `burst_ns` tokens.
  Under high-entropy spray, LRU evicts on every packet and every
  attacker packet gets a free pass.
- Codex N1: bucket table key omits zone/profile identity; cannot
  represent Junos per-zone screen-profile semantics. Two zones with
  different rates collide on the same dst_ip; profile-disabled-in-
  zone-A is collateral-rate-limited by zone-B's bucket.

Recovery requires *both* a zone-aware key AND a thrashing-safe init
policy (start new buckets with zero or single-packet credit). Neither
is a constant tweak; both are key/init-policy redesigns.

### Axis 2 — verdict cache wrong-verdict

**Re-verdict: PLAN-NEEDS-MAJOR (not fatal).** Cache key dimensions
cover the current `try_match_rule` inputs (verified). But:

- AGY F4: skipping `policy_id == 0` (default-deny) inserts ZERO cache
  entries for the dominant attack-traffic class. Default-deny flood
  hits 100% policy-scan-bound. Cache value is illusory under the
  exact attack #1608 cares about. Easy fix: cache `policy_id == 0`
  — `config_generation` already invalidates on commit so the "stuck
  on default-deny after rule add" worry is empty.
- AGY F5 / Codex N5: `mem::size_of<PolicyRule>` assert misses
  semantic field additions (e.g. activating the existing
  `scheduler_name` field for time-of-day match, or adding fields
  inside `compiled_apps`). Need a proper CACHE-KEY INVARIANT
  comment block matching `filter/mod.rs:48-76`, not a layout proxy.
- Codex N4: `PolicyEvaluationResult` has no `rule_idx`;
  `PolicyRuleCounter::add` is `fn`-private. The plan's cache-hit
  accounting `state.rules[hit.rule_idx as usize].hit_counter.add(
  packet_len)` cannot compile. Requires policy API changes the plan
  does not specify.

These are fixable but plan v2 does not specify the fixes.

### Axis 3 — wrong insertion point

**Re-verdict: PLAN-KILL.** The line numbers are corrected but the
call-site semantics are NOT:

- Codex N2: at `poll_descriptor/mod.rs:2393`, returning `Deny` from
  the helper only skips the inner NAT branch. Execution continues
  to missing-neighbor session install at `:2467-2484`. A rate-limit
  Deny FAILS to drop. The plan's "mechanical wrapper" is
  insufficient at this site.
- AGY F2: at `poll_descriptor/mod.rs:1810-1821`, a non-Permit
  result emits `emit_policy_deny_event` PER PACKET. Under 1 Mpps
  flood, that's 1M events/sec into the event stream — control-
  plane DoS. The rate-limiter must drop SILENTLY, not via the
  policy-Deny path.

Both fatals require restructuring, not parameter tweaks. The right
shape is: rate gate sits OUTSIDE the policy-eval helper, drops
silently with counter increment, bypasses both call sites entirely
when tripped. Verdict cache stays inside the helper (its hits go
through the normal permit/deny path; that's fine because cache hits
honor the actual policy verdict).

### Axis 4 — token-bucket arithmetic

**Re-verdict: PLAN-READY for the math.** The fixed-point accumulator
is correct in isolation (both Codex and AGY agree). But Codex N3 +
N6 surface integration gaps:

- Helper signature omits `now_ns`. The bucket cannot refill without
  it. Either pass `now_ns` (cheap, batch-cached) or call
  `clock_gettime` per cold-path packet (expensive). Plan doesn't
  specify.
- Ownership boundary: per-binding, not per-worker; budget math is
  off.

These are recoverable on a v3 but illustrate the v2 plan is
under-specified at integration time.

### Axis 5 — 256 KB budget

**Re-verdict: PLAN-KILL on the assertions, PLAN-READY on the budget
envelope.** Both reviewers independently re-did the layout math and
agree:

- `TokenBucket` is 32 B, not 24 B (3×u64 + u32 = 28 B padded to 32
  for u64 alignment).
- `DestBucketEntry` is 56 B, not 48 B.
- `VerdictCacheEntry` is 96 B, not 88 B.
- Both compile-time asserts will fail. The plan would not build.

Corrected total ≈ 208 KB per binding for 2048 + 1024 entries — still
under 256 KB but the proof is wrong. Plus the ownership boundary
issue from Axis 4: per-binding × multiple-bindings-per-worker easily
exceeds budget on busy hardware.

### Axis 6 — acceptance gate

**Re-verdict: PLAN-READY.** Deferring the empirical CPU% gate to a
follow-up against #1607-v2 is honest. Both reviewers agree.

## Convergent verdict

**3/3 PLAN-KILL on v2.** Codex r2 + AGY r2 + Claude SMR r3 (self-
correction) converge.

The defensive-depth goal of #1608 is real and salvageable, but v2 as
written would NOT compile (Axis 5 asserts), would NOT enforce its
own rate limit at one of two call sites (Axis 3 + Codex N2), would
DoS the event stream under attack (AGY F2), would NOT defend
default-deny floods (AGY F4), and would bypass on high-entropy
sprays (AGY F1).

These are not implementation nits — they are structural redesigns:
silent-drop path outside the policy helper, thrashing-safe bucket
init, zone-aware key, default-deny caching, correct API surface for
cache-hit accounting, corrected layout math, per-worker (not per-
binding) ownership.

## Stop condition met

Per `/engineer` contract: 2-of-3 PLAN-KILL → STOP. Do NOT spawn v3
without user authorization. The user codified this exact rule and
specified an escalation path.

## What a v3 author needs

If/when the user authorizes a v3:

1. Decouple silent rate-limit drop from policy-Deny. The drop path
   must be: counter-increment + descriptor-recycle. NO event emit,
   NO policy_id=0, NO downstream session-install.
2. Bucket key: `(ingress_zone_id, dst_ip)` or `(profile_id, dst_ip)`
   to honor Junos screen-profile per-zone semantics. Snapshot the
   per-profile rate at lookup so two zones can run different rates
   on the same destination.
3. Bucket init policy: new entries start with 0 credit OR with 1
   single-packet credit. Eviction-storm cannot grant burst_ns of
   free traffic.
4. Verdict cache: DO cache `policy_id == 0` (default action).
   `config_generation` lazy invalidation already covers commit-time
   safety.
5. Policy API: extend `PolicyEvaluationResult` to carry `rule_idx`
   (or `Option<rule_idx>`); expose `PolicyRuleCounter::add` as
   `pub(crate) fn add` so the cold-path-gate module can call it on
   cache hit. Or replace the rule_idx scheme with cached
   `Arc<PolicyRuleCounter>` (one Arc-clone per cache insert, then
   pure pointer-deref per hit).
6. Layout: re-derive every `mem::size_of` against the actual rustc
   1.95 layout BEFORE writing const_assert!. Or use
   `const_assert!(>=)` with a comment explaining the upper-bound
   slack.
7. Ownership: place `ColdPathGate` on `Worker` (per-worker), not
   `BindingWorker` (per-binding), or rewrite the budget math as
   per-binding × max-bindings.
8. CACHE-KEY INVARIANT block on `policy.rs` PolicyRule, mirroring
   `filter/mod.rs:48-76` literally — listing every match dimension
   in path (a) (in-key) and path (b) (cache-sensitive gate). Layout
   asserts are a tripwire complement, not a substitute.
9. now_ns + counter argument plumbing into the helper signature.
   Document the choice between batch-cached vs per-packet
   `clock_gettime`.

That is a v3 plan, not an implementation. Per the engineer contract,
this STOPS at "PLAN-KILLED — third kill, escalate to user, do not
spawn v3 without authorization."

— Claude SMR (round 3, self-correcting on r2)
