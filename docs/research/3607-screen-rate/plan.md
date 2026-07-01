# #3607 — Screen `RateCounter` over-throttles sustained at-threshold traffic

## 1. Status

`DRAFT v1 — pending adversarial plan review` (research branch
`research/3607-screen-rate`, base origin/master `9419bbc2c`).

This is a `/research` plan. It stops at PLAN-READY / PLAN-DEFER / PLAN-KILL.
No production source changes, no PR.

## 2. Issue framing

`userspace-dp/src/screen/rate.rs::RateCounter` is a two-bucket sliding-window
counter introduced in #2937 to kill a wall-second boundary double-burst. #3607
reports that this counter over-throttles a *legitimate* sender that sustains
traffic at exactly the configured threshold: the sender is admitted only in the
first second and then dropped in every subsequent second until a **fully idle
second** elapses and resets the window. The module's own doc claims "a sustained
sender is still admitted at ~`threshold` events per second" — that claim is
false.

The issue folds three sub-findings:

- **H02 (core):** over-throttle of sustained at-threshold traffic.
- **M09:** the existing test
  (`icmp_flood_sliding_window_blocks_boundary_burst_then_recovers`) only pins the
  anti-burst property, not the sustained-threshold contract, so the bug survives
  green.
- **L10:** operator docs must state the *actual* rate-limiter semantics.
- **L14:** the `u32` `saturating_add`s silently clamp with no visibility.

## 3. Honest scope / value framing

The win is **correctness fidelity to Junos flood-screen semantics**, not
performance. Junos flood thresholds are packets-per-second (the repo's own
operator doc frames them as pps — e.g. `icmp flood` default **1000 pps**,
`syn-flood attack-threshold` default **200 SYN segments/second**,
`docs/syn-cookie-flood-protection.md:31,55-56`). Junos admits a source that
sustains ≤ threshold pps and drops only the excess above threshold. xpf's current
counter drops a sustained-at-threshold source to ~0 pps after the first second.

Absolute-scale honesty:

- Flood thresholds are *defensive* — operators typically set them well above
  normal traffic, so a benign flow "sustained exactly at threshold" is unusual
  for the zone-aggregate ICMP/UDP flood screens.
- The bite is real for the tighter, more-likely-to-sit-at-threshold consumers:
  1. The **standby SYN-cookie ACK-validation limiter** (4096/s,
     `SYN_COOKIE_STANDBY_ACK_VALIDATION_RATE_LIMIT_PER_SEC`,
     `screen/mod.rs:502-512`) — legitimate returning clients during/after a
     failover can be suppressed.
  2. The **#3315 per-destination SYN sub-threshold sketch** (`screen/syn_rate.rs`)
     — a genuinely busy destination sitting at `destination-threshold` is
     throttled to ~0, a plausible false-positive against a popular internal
     server.
- No performance regression is expected; the counter is already on the hot path
  and the candidate fixes keep it integer-only and 16 bytes.

**If reviewers conclude the accuracy gain is too small to justify the churn on a
security-critical hot path, PLAN-DEFER (or PLAN-KILL) is an acceptable verdict.**
See §10a for the explicit defer/kill criteria.

## 4. What's already shipped / partially batched

- **#2937 (CLOSED, commit `1b1cb215b`)** replaced the original fixed wall-second
  window with the current two-bucket sliding window. #3607 refines that fix; it
  must NOT reintroduce the #2937 micro-burst.
- **#3315 (commit `44474b9ea`)** added `RateCounter::increment_and_classify`
  (single window advance, dual threshold — attack + alarm) and a count-min sketch
  of `RateCounter`s (`screen/syn_rate.rs`, ROWS×COLS cells, ~192 KiB/zone/worker)
  for per-source / per-destination SYN caps. Any `RateCounter` change ripples to
  the sketch, and the fix must preserve the single-advance dual-threshold
  property and the "over_attack ⇒ over_alarm when alarm ≤ attack" invariant.
- **#3032 (commits `490602ec9`, `17c6016e9`)** established that the SYN-cookie
  *epoch* uses a once-per-second cached **wall** clock (for cross-HA-peer cookie
  validation). This is orthogonal: the rate counter uses **monotonic** time,
  which is the correct clock for rate limiting. The fix must not entangle the two.
- **The enabling fact:** `loop_now_ns = monotonic_nanos()` is already read **once
  per poll-loop batch** (`afxdp/worker/loop_body/mod.rs:241`) and truncated to
  `loop_now_secs = loop_now_ns / 1_000_000_000` (:363) before it reaches the
  screen path as `now_secs`. Nanosecond-resolution monotonic time is therefore
  available on the hot path at **zero additional clock reads** — the screen path
  simply discards the sub-second part today.

### 4a. Root-cause analysis (confirmed against origin/master `9419bbc2c`)

`increment` (`rate.rs:79-83`) and `advance` (`rate.rs:60-71`):

```rust
fn advance(&mut self, now_secs: u64) {
    if now_secs == self.window_start_secs { return; }
    if now_secs == self.window_start_secs.wrapping_add(1) {
        self.prev_count = self.count;   // demote whole previous second
    } else { self.prev_count = 0; }
    self.count = 0;
    self.window_start_secs = now_secs;
}
pub(super) fn increment(&mut self, now_secs: u64, threshold: u32) -> bool {
    self.advance(now_secs);
    self.count = self.count.saturating_add(1);       // ALWAYS counted
    self.prev_count.saturating_add(self.count) > threshold
}
```

Two coupled defects produce the over-throttle:

1. **1-second clock granularity ⇒ no sub-second decay.** `advance` gives the
   entire previous second a **constant weight of 1.0** for the whole current
   second. A correct sliding-window counter weights `prev_count` by
   `(1 − elapsed_fraction_of_current_second)`. Because `now_secs` is integer
   seconds, there is no fraction, so the estimate `prev_count + count`
   over-estimates the trailing-1s rate by up to 2× at the start of a second.

2. **Rejected events are still counted.** `count` increments on every call
   regardless of the return value, so once the trailing sum crosses threshold,
   `count` keeps climbing while `prev_count` stays pinned at the full previous
   second — the sum stays saturated until a fully idle second resets `prev_count`
   to 0.

**Quantified over-throttle** (the clock is 1-s granular, so within-second arrival
distribution is invisible to the counter — model each second as delivering `c`
events; `T` = threshold; steady state, `i ≥ 1`):

`admitted(i) = max(0, T − c)` for the current code.

| sustained rate `c` | admitted/sec (current) | Junos-correct |
|---|---|---|
| `c ≤ T/2` | `c` (all) | `c` |
| `T/2 < c < T` | `T − c` (throttled) | `c` |
| `c = T` (exactly at threshold) | **0** after second 0 (needs a fully idle second) | `T` |
| `c > T` | 0 (correct: over limit) | drop excess |

So the **true sustained ceiling of the current counter is `T/2` pps**, not `T`.
The `sustained_at_threshold_is_admitted` unit test (`rate.rs:220-237`) passes
only because it feeds `T/2` events/sec (`half = THRESHOLD/2`), i.e. it tests a
source at *half* the threshold, not at the threshold — this is the M09 gap.

**Insight for the design:** #2937's implementation enforces a guarantee (strict
trailing-1s sum ≤ threshold at 1-s granularity) that is *stronger* than #2937
actually required (bound the sub-second micro-burst) and is *fundamentally
incompatible* with "sustained at threshold is admitted." #3607 is the direct
symptom. The fix must relax to the weaker, correct guarantee that both candidate
mechanisms provide: bound the micro-burst to ~threshold AND admit sustained ≤
threshold.

## 5. Concrete design

All candidates share these enablers/constraints:

- Thread the already-read `loop_now_ns` (monotonic ns) into the rate-counter call
  sites as a new `now_ns: u64` parameter, **alongside** the existing `now_secs`
  (which many other screen sub-systems still need in seconds: scan `WINDOW_SECS`,
  `syn_cookie_active_until_secs`, validated-cache TTL, alarm `last_emit_sec`,
  epoch refresh gate). `now_ns` and `now_secs` are the *same* monotonic instant
  (`loop_now_ns` and `loop_now_ns / 1e9`) so there is no intra-tick skew.
- Keep `RateCounter` at **16 bytes** (no growth ⇒ the #3315 sketch footprint is
  unchanged) and integer-only (no per-packet float, no per-packet division on the
  hot path — use fixed-point).
- Per-worker in-memory only: **no HA sync, no wire, no persistence** touched (no
  `protocol_wire_v1.json` regen, no Go changes for the counter itself).

### Option A — sub-second weighted (approximate) sliding-window counter — RECOMMENDED

Keep the two-bucket structure; store the window start in **nanoseconds** and add
the missing sub-second decay + stop counting rejected events.

```rust
pub(super) struct RateCounter {
    pub(super) count: u32,        // current sub-... bucket (this second)
    prev_count: u32,              // previous full second
    window_start_ns: u64,         // monotonic ns of the current 1-s bucket start
}

// pre-increment weighted estimate of the trailing-1s rate:
//   est = prev_count * (1e9 - elapsed_ns) / 1e9 + count
// admit iff est + 1 <= threshold, and count ONLY when admitted.
```

- `advance(now_ns)` rolls to a new 1-s bucket when `now_ns - window_start_ns >=
  1e9`; a gap ≥ 2s clears `prev_count`. The weight uses `elapsed_ns` within the
  current second.
- The `elapsed_ns / 1e9` scaling is done with a fixed-point reciprocal multiply
  (`elapsed_ns * K >> shift`), no per-packet 64-bit divide.
- **Dual threshold (`increment_and_classify`) is natural:** compute ONE weighted
  estimate, compare to `attack` and `alarm` — the single-advance property and the
  "over_attack ⇒ over_alarm" invariant are preserved by construction.
- Rejected events are **not** counted → recovery needs only a drop back to ≤
  threshold, not a fully idle second.

**Honest limitation:** at the exact second boundary (`elapsed_ns ≈ 0`)
`prev_count` still has ~full weight, so the *first batch* of each second can drop
a small fraction of a sustained-at-threshold stream. Because the clock advances
per batch and flood batches are sub-millisecond apart, this fraction is
negligible under load (< 0.1% at flood rates) and is strictly better than the
status quo (100% dropped after second 0). See §11 Q3.

### Option B — monotonic-ns token bucket (GCRA) — STRONG ALTERNATIVE

```rust
pub(super) struct RateCounter {
    tokens_q: u32,        // fixed-point tokens (capacity = threshold)
    last_refill_ns: u64,  // monotonic ns of last refill
    // 16B with alignment padding
}
// refill = (now_ns - last) * threshold / 1e9  (fixed-point, capped at capacity)
// admit iff tokens >= 1, then consume 1; else drop (do NOT consume)
```

- Capacity = threshold, refill = threshold/sec. Sustained ≤ threshold is admitted
  with **no boundary roughness** (refill exactly matches drain), the best Junos
  fidelity.
- Micro-burst is bounded to `capacity = threshold` tokens ⇒ satisfies #2937's
  real concern (no 2× sub-second burst). The classic token-bucket "up to 2×T over
  a *paced* second" is a lower instantaneous rate, not the #2937 micro-burst.
- **Cost:** the dual-threshold zone-aggregate SYN counter needs **two** buckets
  (alarm + attack) with different capacities/refills; the "over_attack ⇒
  over_alarm" invariant then holds because the tighter alarm bucket empties
  whenever the looser attack bucket does. Slightly more delicate than Option A's
  single-estimate compare. Single-threshold consumers (ICMP/UDP flood,
  standby-ACK, sketch) stay one bucket.

### Option C — minimal: stop counting rejected events only — REJECTED as sole fix

One-line change (`count` incremented only when admitted). Analysis: this
oscillates `T, 0, T, 0` → average `T/2` sustained, which still violates the
documented "~threshold/sec" contract and still deviates from Junos. Insufficient
alone; documented here so reviewers can see why the cheap fix does not close the
gap.

### Cross-cutting (all fix options)

- **L14 saturation visibility:** add an explicit per-zone (or per-`ScreenState`)
  `rate_counter_saturations` counter that increments when a `saturating_add`
  would have overflowed / the counter is pinned at `u32::MAX`, surfaced through
  the existing screen drop-reason / stats publish path (#3343) so operators can
  see when a flood exceeded the counter's representable range. Additive stat only.
- **L10 docs:** rewrite the sliding-window paragraph in
  `docs/syn-cookie-flood-protection.md:275-280` and the module docs in
  `screen/rate.rs` (top) + `screen/mod.rs` to state the real semantics: an
  approximate trailing-1s rate limiter that admits sustained ≤ threshold, bounds
  the micro-burst to ~threshold, the approximation-error bound, and the
  saturation-counter meaning.

### Recommendation

**Option A (sub-second weighted sliding window)** as primary, for lowest churn on
a security-critical hot path:

1. Minimal structural delta from the already-shipped, already-tested two-bucket
   `RateCounter` — only the clock unit and the admission math change.
2. Natural dual-threshold: preserves the `increment_and_classify` single-advance
   shape and the alarm/attack invariant with one estimate.
3. 16 bytes (sketch footprint unchanged), integer-only via fixed-point.
4. Repairs *both* root causes (sub-second weight kills the `T/2` ceiling;
   not-counting-rejected kills the idle-second recovery requirement).

Recommend switching to **Option B (token bucket)** only if reviewers weight
perfect boundary smoothness over churn and accept the two-bucket dual-threshold
cost — a legitimate call, hence /research rather than /engineer.

## 6. Public API preservation

- `RateCounter::increment(now, threshold) -> bool` — **signature changes**: the
  clock arg becomes `now_ns` (monotonic ns) instead of `now_secs`. Return
  semantics unchanged (true = over threshold / drop).
- `RateCounter::increment_and_classify(now, attack, alarm) -> (bool, bool)` —
  same clock-arg change; return semantics unchanged (single advance, dual
  compare).
- `RateCounter::reset()` (test-only) — preserved.
- `syn_rate.rs::SynRateSketch::increment(ip, now, threshold) -> bool` and
  `saturate_cell(...)` — clock-arg change threaded through.
- `ScreenState::check_packet` / `check_packet_with_zone_id` and
  `validate_syn_cookie_ack_on_session_miss` — gain a `now_ns` parameter
  (or an internal derivation); `now_secs` retained for the non-rate sub-systems.
- No Go / gRPC / CLI / protobuf change (the counter is internal to the dataplane).

## 7. Hidden invariants the change must preserve

- **#2937 anti-micro-burst:** `threshold` events at the end of second N followed
  by `threshold` at the start of N+1 (sub-ms straddle) must NOT admit ~2×.
  (`boundary_double_burst_is_bounded`, `icmp_flood_sliding_window_..._recovers`
  must stay green or be re-expressed with the same guarantee.)
- **#3315 single-advance dual-threshold:** `increment_and_classify` advances the
  window exactly once; `over_attack ⇒ over_alarm` when `alarm ≤ attack`.
- **#3315 sketch fail-closed:** count-min collisions may only over-count (never a
  false negative); no eviction; per-cell counters only increase within the
  window. The clock-unit change must not alter the AND-of-rows min-read.
- **Allocation rules:** no per-packet allocation; integer-only; no per-packet
  division on the hot path (`docs/engineering-style.md`).
- **Clock discipline:** rate counter uses **monotonic** ns; the SYN-cookie epoch
  keeps its once-per-second **wall** clock (#3032). Do not cross them.
- **16-byte layout / no HA-wire/persistence:** keep `RateCounter` at 16B; no
  session-sync, snapshot, or protobuf field changes.
- **Side-effect ordering in the SYN path:** the aggregate counter ALWAYS counts
  before the cookie-activation side effect (`screen/mod.rs:665-705`); per-dest
  runs even when cookie-active; per-source skipped when cookie-active. Unchanged.

## 8. Risk assessment

| Class | Level | Notes |
|---|---|---|
| Behavioral regression | **MED** | Security-critical drop path; must not reintroduce #2937 or weaken the SYN-flood/standby-ACK/sketch caps. Mitigated by RED-on-revert tests for BOTH #2937 (micro-burst bounded) and #3607 (sustained admitted) and the #3315 invariant tests. |
| Lifetime / borrow-checker | **LOW** | `RateCounter` is a plain per-zone value; the disjoint-field borrow story in `check_packet_with_zone_id` is unchanged; adding a `now_ns` scalar param is trivial. |
| Performance regression | **LOW** | No new clock read (reuse `loop_now_ns`); Option A adds one fixed-point multiply + shift per event, Option B one multiply + add + compare; both integer, 16B, cache-neutral. Verify SYN-flood iperf/CPU unchanged. |
| Architectural mismatch | **LOW** | Reuses the existing counter primitive and the existing per-batch monotonic clock; no new subsystem, no dead-end. The signature widening (`now_ns`) is the main blast radius (poll_stages, forwarding, sketch) but mechanical. |

## 9. Test plan

- `cargo build` clean; `cargo test screen::` (rate + sketch + enforcement),
  `cargo test afxdp::poll_stages`, full `cargo test` green; `go test ./...`
  (should be unaffected — no Go change beyond none).
- **M09 RED-on-revert sustained-at-threshold test** (the deliverable): feed
  exactly `threshold` events/sec for N seconds using the sub-second `now_ns`
  clock (spread across sub-second batches), assert the steady-state admit rate is
  ≈ threshold (e.g. ≥ 0.95·threshold under load-like batching), NOT ~0. Against
  the current two-bucket code this asserts RED (admits ~0 after second 0).
- **Recovery test:** after an over-limit second, a drop back to ≤ threshold/sec
  recovers admission WITHOUT requiring a fully idle second (current code RED).
- **#2937 guarantee retained:** keep/adapt `boundary_double_burst_is_bounded`
  and `icmp_flood_sliding_window_blocks_boundary_burst_then_recovers` — the
  sub-ms micro-burst must still be bounded to ~threshold.
- **#3315 invariants retained:** `increment_and_classify` single-advance dual
  threshold; sketch victim-always-trips / AND-not-OR / no-growth-under-flood.
- **L14 test:** drive the counter to `u32::MAX` and assert the saturation stat
  increments and is published.
- **Smoke (loss userspace cluster):** apply a screen profile with a low
  icmp/udp/syn threshold; confirm a sustained-at-threshold flow is admitted while
  an above-threshold flow is dropped; v4 + v6; confirm no forwarding-throughput
  regression. `make test-failover` is NOT required (no cluster/VRRP/session-sync
  code touched) but a screen smoke on the cluster is.

## 10. Out of scope (explicitly)

- **Per-destination ICMP/UDP flood modeling.** Junos ICMP/UDP flood thresholds
  are per-destination-address; xpf models them per-zone (aggregate). That is a
  separate modeling gap, not #3607, and is not addressed here.
- **Changing default thresholds** (#3024/#3230 owns those).
- **SYN-cookie epoch clock** (#3032) — untouched.
- **HA sync of rate-counter state** — out of scope; counters stay per-worker.
- Any Go/CLI/gRPC surface for the new saturation stat beyond wiring it into the
  existing screen stats publish path.

### 10a. PLAN-DEFER / PLAN-KILL criteria (explicit)

- **PLAN-DEFER-operator** is acceptable if reviewers judge that flood thresholds
  are defensive-only and sustained-at-threshold benign traffic is not a realistic
  operational case for the affected consumers — i.e. fix L10 (doc the real
  semantics) + L14 (saturation stat) now, defer the counter rewrite.
- **PLAN-KILL** is acceptable if reviewers conclude the current counter is
  "close enough" to Junos for the defensive use case AND the hot-path rewrite
  risk on a security-critical drop path outweighs the accuracy gain. In that case
  L10 must still be corrected (the doc currently makes a false claim).

## 11. Open questions for adversarial review

1. **Mechanism:** Option A (weighted sliding window) vs Option B (token bucket)?
   Is the boundary roughness of A (first-batch drops of a sustained-at-threshold
   stream) acceptable, or does Junos fidelity demand B's perfect smoothness — and
   is B's two-bucket dual-threshold cost worth it? (Invitable to pick B.)
2. **Count rejected or not?** For the weighted window, should rejected events
   count (fail-closed, keeps a real overload throttled) or not (cleaner sustained
   behavior)? Does not-counting open any flood-evasion where a source paces just
   over threshold to avoid the recovery penalty? (Invitable to PLAN-KILL if this
   weakens the screen.)
3. **Per-batch clock granularity.** `now_ns` advances once per poll batch, so all
   packets in a batch share a timestamp. Under a volumetric flood a batch can hold
   many packets at one `elapsed_ns`. Does that degrade either mechanism into the
   same 1-s-granularity failure at the *batch* level, and is sub-batch resolution
   ever needed? (Invitable to PLAN-DEFER.)
4. **Signature blast radius.** Threading `now_ns` through poll_stages →
   forwarding → screen → sketch is wide. Is a narrower alternative (store
   window_start in ns and pass only ns to `increment`, deriving secs where needed)
   cleaner, or does the screen path's heavy reliance on `now_secs` make a second
   parameter the right call?
5. **Is the whole fix worth it?** Given flood thresholds are defensive and set
   above normal traffic, is #3607 a PLAN-DEFER-operator (fix only L10 doc + L14
   stat) rather than a counter rewrite? What concrete operational scenario
   justifies the rewrite beyond the standby-ACK limiter and the #3315 per-dest
   sketch? (Invitable to PLAN-DEFER/PLAN-KILL.)
6. **#2937 non-regression.** Does either mechanism provably still bound the
   sub-ms micro-burst to ~threshold, and is the RED-on-revert coverage for BOTH
   #2937 and #3607 mutually consistent (no test that can only pass one)?
