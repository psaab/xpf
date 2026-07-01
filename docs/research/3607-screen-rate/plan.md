# #3607 — Screen `RateCounter` over-throttles sustained at-threshold traffic

## 1. Status

`DRAFT v2 — round-1 adversarial findings incorporated (Codex + AGY + Claude SMR),
pending convergence confirmation` (research branch `research/3607-screen-rate`,
base origin/master `9419bbc2c`).

This is a `/research` plan. It stops at PLAN-READY / PLAN-DEFER / PLAN-KILL.
No production source changes, no PR.

**v2 change summary (driven by round-1 review):** the recommendation flipped from
Option A (weighted sliding window) to **Option B (monotonic-ns token bucket),
applied ONLY to the single-threshold pure-drop / validate-budget limiters, with
the dual-threshold SYN-flood AGGREGATE counter left UNCHANGED**. Both companions
independently identified that (a) not-counting-rejected on the SYN aggregate opens
a T/sec SYN-cookie bypass and violates a signed-off invariant, and (b) Option A's
weighted window over-throttles at low thresholds (`T=1` → ~50% loss), which is
exactly the regime the #3315 per-source/per-destination sketches use.

## 2. Issue framing

`userspace-dp/src/screen/rate.rs::RateCounter` is a two-bucket sliding-window
counter introduced in #2937 to kill a wall-second boundary double-burst. #3607
reports that this counter over-throttles a *legitimate* sender that sustains
traffic at exactly the configured threshold: the sender is admitted only in the
first second and then dropped in every subsequent second until a **fully idle
second** elapses and resets the window. The module's own doc claims "a sustained
sender is still admitted at ~`threshold` events per second" — that claim is
false.

Folded sub-findings: **H02** (core over-throttle), **M09** (no
sustained-threshold test — the bug survives green), **L10** (operator docs must
state the real semantics), **L14** (`u32` `saturating_add`s silently clamp).

## 3. Honest scope / value framing

The win is **correctness fidelity to Junos flood-screen semantics**, not
performance. Junos flood thresholds are packets-per-second (the repo's own
operator doc frames them as pps — `icmp flood` default **1000 pps**, `syn-flood
attack-threshold` default **200 SYN segments/second**,
`docs/syn-cookie-flood-protection.md:31,55-56`). Junos admits a source that
sustains ≤ threshold pps and drops only the excess; xpf's current counter drops a
sustained-at-threshold source to ~0 pps after the first second.

Where the bite is real (and where the fix is scoped):

1. **Standby SYN-cookie ACK-validation limiter** (4096/s,
   `screen/mod.rs:502-512`) — legitimate returning clients during/after a
   failover are suppressed. "Admitted" here means "spend SipHash to validate this
   ACK"; an admitted-but-bogus ACK still fails the crypto check, so raising the
   admit rate to the intended 4096/s budget carries **no bypass risk**.
2. **#3315 per-destination SYN sub-threshold sketch** (`screen/syn_rate.rs`) — a
   genuinely busy destination at `destination-threshold` is throttled to ~0, a
   plausible false-positive against a popular internal server. Per-dest DROPS
   (does not skip cookies), so the shaper fix carries no bypass risk.
3. **ICMP flood / UDP flood** zone-aggregate counters — over = DROP; the shaper
   fix admits sustained-at-threshold, drops excess. No bypass risk.

Deliberately **out of the fix** (see §5 and §10): the **SYN-flood aggregate
counter** (`increment_and_classify` → SYN-cookie activation). There, "admitted" =
"skip the cookie challenge," so admitting a sustained-at-threshold stream would
let `threshold` spoofed SYNs/sec bypass cookies (round-1 BLOCKER). Its
over-throttle is benign when `syn-cookie` is on (a challenge is recoverable) and a
conservative defense when off, so it stays as-is.

**If reviewers conclude the accuracy gain for consumers (1)-(3) is too small to
justify a new counter primitive + threading a nanosecond clock through the screen
call chain + migrating the #3315 sketch, PLAN-DEFER-operator (fix only L10 docs +
L14) or PLAN-KILL is an acceptable verdict.** See §10a.

## 4. What's already shipped / partially batched

- **#2937 (CLOSED, `1b1cb215b`)** replaced the original fixed wall-second window
  with the current two-bucket sliding window. #3607 refines it; the fix must NOT
  reintroduce the #2937 sub-ms micro-burst.
- **#3315 (`44474b9ea`)** added `RateCounter::increment_and_classify` (single
  advance, dual threshold attack+alarm) driving SYN-cookie activation, plus a
  count-min sketch of `RateCounter`s (`screen/syn_rate.rs`, ROWS×COLS cells,
  ~192 KiB/zone/worker) for per-source / per-destination SYN caps.
- **#3032 (`490602ec9`, `17c6016e9`)** — the SYN-cookie *epoch* uses a
  once-per-second cached **wall** clock (cross-HA-peer cookie validation).
  Orthogonal: the rate counter uses **monotonic** time, which is correct for rate
  limiting. Do not entangle them.
- **Enabling fact:** `loop_now_ns = monotonic_nanos()` is already read **once per
  poll-loop batch** (`afxdp/worker/loop_body/mod.rs:241`) and truncated to
  `loop_now_secs = loop_now_ns / 1_000_000_000` (:363) before it reaches the
  screen path as `now_secs`. Nanosecond-resolution monotonic time is therefore
  available on the hot path at **zero additional clock reads** — but *reaching the
  screen counters still requires a signature change*: `stage_screen_check` accepts
  only `now_secs` today (`poll_stages.rs:312`); `now_ns` must be threaded
  loop_body → forwarding → poll_stages → `check_packet_with_zone_id` /
  `validate_syn_cookie_ack_on_session_miss` → the sketch. That plumbing is real
  work (round-1 finding), not zero-cost.

### 4a. Root-cause analysis (confirmed against origin/master `9419bbc2c`)

`increment` (`rate.rs:79-83`) advances the window then counts EVERY event
(admitted or rejected) before comparing `prev_count + count > threshold`;
`advance` (`rate.rs:60-71`) demotes the whole previous second to `prev_count`
with a **constant weight of 1.0** for the entire current second.

Two coupled defects:

1. **1-second clock granularity ⇒ no sub-second decay.** A correct sliding-window
   counter weights `prev_count` by `(1 − elapsed_fraction)`; with integer seconds
   there is no fraction, so `prev_count + count` over-estimates the trailing-1s
   rate by up to 2× at the start of a second.
2. **Rejected events are still counted**, so once the sum crosses threshold
   `count` keeps climbing while `prev_count` stays pinned — the sum stays
   saturated until a fully idle second resets `prev_count` to 0.

**Quantified** (clock is 1-s granular, so per-second arrival distribution is
invisible; model second `i` delivering `c` events, `T` = threshold, steady state
`i ≥ 1`): admitted per second = `max(0, min(c, T − c))`.

| sustained rate `c` | admitted/sec (current) | Junos-correct |
|---|---|---|
| `c ≤ T/2` | `c` (all) | `c` |
| `T/2 < c < T` | `T − c` (throttled) | `c` |
| `c = T` (at threshold) | **0** after second 0 (needs a fully idle second) | `T` |
| `c > T` | 0 | drop excess |

So the **true sustained ceiling of the current counter is `T/2`**, not `T`. The
`sustained_at_threshold_is_admitted` unit test (`rate.rs:220-237`) passes only
because it feeds `T/2` events/sec (`half = THRESHOLD/2`, `rate.rs:228`) — i.e. it
tests a source at *half* threshold. That is the M09 gap.

**Both defects are jointly necessary to the bug — neither single fix suffices:**

- **Granularity fix alone** (add sub-second weight, keep counting all arrivals):
  for uniform sustained-at-`T`, `count = T·f` and `prev = T` ⇒ `est =
  T·(1−f) + T·f ≡ T` for all `f`; the admission margin drops every packet. Still
  broken.
- **Not-counting-rejected alone** (Option C, no weighting): the recurrence is
  `a_i = min(c, T − a_{i-1})`; for `c ≥ T` it collapses to the waveform
  `T, 0, T, 0, …` (average `T/2`) — a **flood-evasion waveform** and still a
  contract violation.

This is why the fix must both use a finer clock AND change the accounting — which
the token bucket does natively (continuous refill = sub-ns granularity; tokens
are only consumed on admit).

**Design insight:** #2937 enforced a guarantee (strict trailing-1s sum ≤
threshold at 1-s granularity) *stronger* than #2937 needed (bound the sub-ms
micro-burst) and *fundamentally incompatible* with "sustained at threshold
admitted." #3607 is the symptom. The fix relaxes to the weaker correct guarantee:
bound the micro-burst to ~threshold AND admit sustained ≤ threshold.

## 5. Concrete design

### Recommended: Option B — monotonic-ns token bucket for the drop/validate limiters; SYN aggregate UNCHANGED

Introduce a new `TokenBucket` primitive **alongside** the retained `RateCounter`,
and split consumers by security semantics:

| Consumer | Counter | Semantic |
|---|---|---|
| ICMP flood (`icmp_counters`) | **TokenBucket** | shaper: admit ≤T/s, drop excess |
| UDP flood (`udp_counters`) | **TokenBucket** | shaper |
| Standby SYN-cookie ACK limiter | **TokenBucket** | validate-budget (4096/s) |
| missing-profile warn dampener | **TokenBucket** | log dampener |
| per-source / per-dest SYN sketch (`syn_rate.rs`) | **TokenBucket** | shaper (drop) |
| **SYN-flood aggregate** (`increment_and_classify` → cookie) | **RateCounter (UNCHANGED)** | defense-latch: count-all sticky |

```rust
pub(super) struct TokenBucket {
    tokens_q: u64,        // fixed-point tokens (integer part <= capacity = threshold)
    last_refill_ns: u64,  // monotonic ns of last refill
}
// refill = (now_ns - last) * threshold  (fixed-point tokens/ns via a precomputed
//          reciprocal-multiply; NO per-packet 64-bit divide), capped at capacity
// admit iff tokens >= 1 unit, then consume 1; else drop (do NOT consume)
```

Why token bucket over the weighted sliding window:

- **Low-threshold correctness (round-1 BLOCKER).** Capacity = threshold, refill =
  threshold/sec. At `T=1`, sustained 1 pps refills 1 token/sec and consumes 1/sec
  → admitted, zero loss. The weighted sliding window drops ~1 packet/sec at the
  boundary → at `T=1` that is ~50% loss, at `T=5` ~20% — catastrophic for the
  low-threshold per-source/per-dest sketches. Token bucket has no boundary
  roughness (refill exactly matches drain for a sustained-at-threshold sender).
- **No oscillation.** Continuous refill avoids Option C's `T,0,T,0` waveform.
- **#2937 preserved.** A sub-ms boundary micro-burst finds ≤ `capacity =
  threshold` tokens ⇒ ≤ threshold admitted; the classic token-bucket "up to 2×T
  over a *paced* second" is a lower instantaneous rate, not the #2937 micro-burst.
- **Single-threshold consumers only** ⇒ one bucket each, no dual-bucket 32-byte
  blow-up (round-1 MAJOR). Keep `TokenBucket` at 16 bytes (`u64 tokens_q + u64
  last_ns`, or `u32` fixed-point tokens + `u64` last_ns padded) so the #3315
  sketch footprint is unchanged.

Why the SYN aggregate is NOT migrated (round-1 BLOCKER, both companions):

- `increment_and_classify` counts **before** classification (`rate.rs:97-106`)
  and the caller relies on "the aggregate ALWAYS counts so its cookie-activation
  side-effect can never be skipped" (`screen/mod.rs:631-634`). This is a
  signed-off invariant.
- If the aggregate switched to count-only-admitted, during a sustained flood the
  first `threshold` SYNs/sec would never trip `over_attack`, so they would
  **bypass the cookie challenge**; and because other packets keep the zone
  `cookie_active`, the per-source cap is also skipped (`!cookie_active` false) —
  `threshold` spoofed SYNs/sec bypass BOTH cookies and per-source. Unacceptable.
- Its over-throttle is acceptable: with `syn-cookie` on, a challenge to a legit
  sustained-at-threshold client is recoverable (one extra RTT); with it off, an
  aggressive defense drop is the conservative posture an operator who set
  `attack-threshold` wants. Documented in L10 rather than "fixed."

### Alternative considered: Option A — sub-second weighted sliding window — NOT recommended

Reuses the two-bucket structure (store `window_start_ns`, add sub-second weight,
stop counting rejected). Rejected because: (a) low-threshold roughness (`T=1` →
~50% loss) hits the exact regime the sketches use; (b) applying it to the SYN
aggregate would require the count-all invariant change (BLOCKER). It remains the
lower-churn choice **only** if reviewers accept high thresholds everywhere and
scope out the sketches.

### Rejected: Option C — stop counting rejected only

`T,0,T,0` flood-evasion waveform, average `T/2`. Insufficient; documented so the
cheap fix is visibly ruled out.

### Cross-cutting (all fix options)

- **L14 saturation:** under a token bucket, `tokens ≤ capacity = threshold`, so
  the `u32`/`u64` saturation the current count-all design suffers **cannot occur**
  — L14 is resolved structurally. Operator-visible flood intensity is already the
  per-screen drop counters (#3343). Keep at most a `debug_assert`; do not build a
  dedicated saturation metric. (The SYN aggregate keeps `RateCounter`, whose
  `count` can still grow under a flood — its existing `saturating_add` stays; a
  one-line drop-reason/stat there is optional.)
- **L10 docs:** rewrite `docs/syn-cookie-flood-protection.md:275-280` and the
  module docs (`screen/rate.rs` top, `screen/mod.rs`) to state the real semantics
  per consumer: token-bucket shaper (admit sustained ≤ threshold, burst =
  threshold) for ICMP/UDP/standby-ACK/sketches; and the deliberate defense-latch
  behavior + rationale for the SYN aggregate.

## 6. Public API preservation

- `RateCounter::increment_and_classify(now_secs, attack, alarm) -> (bool, bool)`
  — **UNCHANGED** (SYN aggregate keeps it, including the `now_secs` arg and
  count-all semantics).
- `RateCounter::increment` / `reset` — retained (may become aggregate-only or
  test-only depending on whether any other caller stays on it).
- **New** `TokenBucket::admit(now_ns, threshold) -> bool` (true = drop / limited)
  for the migrated consumers.
- `syn_rate.rs::SynRateSketch::increment(ip, now, threshold)` and
  `saturate_cell` — internally swap `RateCounter` → `TokenBucket`, clock arg
  becomes `now_ns`; public method shapes preserved.
- `ScreenState::check_packet` / `check_packet_with_zone_id` /
  `validate_syn_cookie_ack_on_session_miss` — gain a `now_ns` parameter (the
  existing `now_secs` is retained for the non-rate sub-systems: scan
  `WINDOW_SECS`, `syn_cookie_active_until_secs`, validated-cache TTL, alarm
  `last_emit_sec`, epoch refresh gate).
- **No Go / gRPC / CLI / protobuf change.** The counters are internal to the
  dataplane; nothing is synced, serialized, or persisted.

## 7. Hidden invariants the change must preserve

- **SYN-aggregate count-before-classify + always-count (`rate.rs:97`,
  `mod.rs:631-634`)** — preserved by NOT migrating the aggregate. This is the
  primary round-1 constraint.
- **#2937 anti-micro-burst** — `threshold` at end of N + `threshold` at start of
  N+1 (sub-ms straddle) must not admit ~2× (token bucket: ≤ capacity tokens).
- **#3315 sketch fail-closed** — count-min collisions may only over-count (never a
  false negative); no eviction; the AND-of-rows min-read is unchanged; migrating
  the cell counter to `TokenBucket` must keep "victim always trips."
- **Allocation / hot-path rules** — no per-packet allocation; integer-only; no
  per-packet division (precompute fixed-point refill-per-ns);
  `docs/engineering-style.md`.
- **Clock discipline** — rate limiters use **monotonic** ns; the SYN-cookie epoch
  keeps its once-per-second **wall** clock (#3032). Do not cross them.
- **16-byte layout / no HA-wire/persistence** — `TokenBucket` ≤ 16 B; no
  session-sync / snapshot / protobuf field.
- **SYN-path side-effect ordering (`mod.rs:665-745`)** — aggregate first
  (unchanged), per-dest always (even cookie-active), per-source skipped when
  cookie-active. Migrating per-dest/per-source cell counters must not reorder.

## 8. Risk assessment

| Class | Level | Notes |
|---|---|---|
| Behavioral regression | **MED** | Security-critical drop path. Mitigated by keeping the SYN aggregate untouched, RED-on-revert tests for both #2937 (micro-burst) and #3607 (sustained admitted), and the #3315 sketch invariant tests. |
| Lifetime / borrow-checker | **LOW** | `TokenBucket` is a plain per-zone/per-cell value; the disjoint-field borrow story in `check_packet_with_zone_id` is unchanged; `now_ns` is a scalar param. |
| Performance regression | **LOW** | No new clock read (reuse `loop_now_ns`); token bucket = one fixed-point multiply + add + compare + conditional subtract per event; 16 B, cache-neutral. Verify SYN/ICMP flood iperf + CPU unchanged. |
| Architectural mismatch | **LOW–MED** | Reuses the existing per-batch monotonic clock and adds one small primitive; the main blast radius is the `now_ns` signature threading + the sketch cell-type swap (mechanical but wide). No new subsystem, no dead-end. |

## 9. Test plan

- `cargo build` clean; `cargo test screen::` (new `TokenBucket` unit tests +
  sketch + enforcement), `cargo test afxdp::poll_stages`, full `cargo test`
  green; `go test ./...` (unaffected — no Go change).
- **M09 RED-on-revert sustained-at-threshold test** (deliverable): drive a
  `TokenBucket` at exactly `threshold` events/sec for N seconds using the
  sub-second `now_ns` clock; assert steady-state admit ≈ threshold (≥ 0.99·T),
  NOT ~0. Against the current `RateCounter` this asserts RED.
- **Low-threshold test:** `T=1` sustained 1 pps admits every second (Option A
  would fail this — pins why token bucket was chosen).
- **Recovery test:** after an over-limit burst, dropping to ≤ threshold recovers
  admission without a fully idle second.
- **#2937 retained:** adapt `boundary_double_burst_is_bounded` /
  `icmp_flood_sliding_window_blocks_boundary_burst_then_recovers` to the token
  bucket — sub-ms micro-burst still bounded to ~threshold.
- **SYN aggregate untouched:** its existing tests
  (`increment_and_classify_single_advance_dual_threshold`, SYN-flood enforcement,
  cookie activation) stay green with NO edits — proof the aggregate is unchanged.
- **#3315 sketch invariants retained:** victim-always-trips, AND-not-OR,
  no-growth-under-flood, with cells now `TokenBucket`.
- **Smoke (loss userspace cluster):** screen profile with low icmp/udp thresholds
  + a low `destination-threshold`; confirm a sustained-at-threshold flow is
  admitted while above-threshold is dropped; v4 + v6; no forwarding-throughput
  regression. `make test-failover` NOT required (no cluster/VRRP/session-sync code
  touched) but a screen smoke on the cluster is; verify a standby-node cookie-ACK
  validation path admits at the 4096/s budget under sustained load.

## 10. Out of scope (explicitly)

- **The SYN-flood AGGREGATE over-throttle** — deliberately retained (defense-latch
  / cookie-bypass safety). Documented in L10, not fixed. A future refinement could
  make it count-only-admitted **only when `syn-cookie` is off** (no bypass to
  worry about then); tracked separately if desired.
- **Per-destination ICMP/UDP flood modeling** — Junos ICMP/UDP flood is
  per-destination-address; xpf models per-zone. Separate gap, not #3607.
- **Changing default thresholds** (#3024/#3230).
- **SYN-cookie epoch clock** (#3032).
- **HA sync of rate-counter state** — counters stay per-worker.

### 10a. PLAN-DEFER / PLAN-KILL criteria (explicit)

- **PLAN-DEFER-operator** is acceptable if reviewers judge the blast radius (new
  `TokenBucket` primitive + `now_ns` threading + sketch cell-type swap)
  disproportionate to the value — in which case fix L10 (correct the false doc
  claim) + optionally L14 now, and defer the counter work.
- **PLAN-KILL** is acceptable if reviewers conclude the shaper consumers are
  defensive-only and sustained-at-threshold benign traffic is not a realistic
  case even for the standby-ACK limiter and the per-dest sketch. L10 must still be
  corrected regardless (the doc currently makes a false claim).

## 11. Open questions for adversarial review (round 2)

1. **Consumer split correctness.** Is the RateCounter-for-aggregate /
   TokenBucket-for-the-rest split the right cut, or should the aggregate also move
   to count-only-admitted *conditioned on `syn-cookie` off* (fully fixing the
   cookie-off drop of legit sustained SYNs without a bypass)? (Invitable to widen
   or narrow scope.)
2. **Two primitives in `rate.rs`.** Is maintaining both `RateCounter` (aggregate)
   and `TokenBucket` (rest) acceptable, or is a single mode-parameterized type
   cleaner / more error-prone?
3. **Token-bucket fixed-point.** Does the precomputed reciprocal-multiply refill
   keep integer-only, no-divide, and correctly represent both large thresholds
   (1e6) and `T=1` without under/overflow in 16 bytes?
4. **Sketch migration fail-closed.** Does swapping the sketch cell type to
   `TokenBucket` preserve "collisions only over-count, victim always trips," given
   token buckets refill over time (a stale cell refills, so a returning victim
   after a gap gets a fresh budget — is that still fail-closed)?
5. **Per-batch clock granularity.** `now_ns` advances once per poll batch; under a
   volumetric flood batches are sub-ms apart (fine); a low-rate sender's whole
   second in one batch is below threshold anyway. Any rate where batch granularity
   reintroduces the failure? (Invitable to PLAN-DEFER.)
6. **Is the whole fix worth it?** Given the aggregate is scoped out, the remaining
   value is standby-ACK failover clients + busy-dest false-positives + ICMP/UDP
   sustained. Concrete enough to justify the blast radius, or PLAN-DEFER-operator?
