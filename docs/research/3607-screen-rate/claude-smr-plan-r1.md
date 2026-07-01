# Claude SMR — hostile plan review r1 (#3607)

Reviewing `docs/research/3607-screen-rate/plan.md` v1 against origin/master
`9419bbc2c`. Hostile posture: find where the plan is wrong or oversells.

## Verdict: NEEDS-REVISION → converging PLAN-READY on Option A

The architecture is sound and the root cause is correctly identified, but v1
contains one quantitative imprecision, one MIS-characterization that actually
*understates* the recommended option, and two analysis gaps that materially
change the L14 scope and the Q2 answer. None reject the design; all sharpen it.
Fix in v2, then PLAN-READY.

## Findings

### MAJOR-1 — v1's inline over-throttle formula is wrong for `c < T/2`
§4a states `admitted(i) = max(0, T − c)`. That is only correct for `c ≥ T/2`.
The correct closed form is `admitted(i) = max(0, min(c, T − c))`: for `c ≤ T/2`
the whole offered load `c` is admitted (`min(c, T−c) = c`). The TABLE directly
below is correct; the inline formula is not. A hostile reviewer will treat the
mismatch as a math error. Fix the inline formula to `max(0, min(c, T − c))`.

### MAJOR-2 — v1 UNDER-sells Option A's sustained behavior (boundary roughness overstated)
§5 Option A claims the "first batch of each second can drop a small fraction
(~0.1T)" of a sustained-at-threshold stream. Re-derivation says that is
pessimistic and only true for a sender that FRONT-LOADS a full-`T` burst at
`frac≈0` — which is precisely the burst shape #2937 is *supposed* to throttle.
For a genuinely UNIFORM sustained-at-`T` sender with count-only-admitted:

- by fraction `f` of the second, `prev = T`, admitted-so-far `count ≈ T·f − 1`
  (admit while `T·(1−f) + count + 1 ≤ T` ⇒ `count ≤ T·f − 1`);
- offered-so-far `= T·f` ⇒ per-second deficit is **O(1) packet**, not `~0.1T`.

So Option A admits `≈ T − O(1)` per second for a uniform sustained-at-threshold
sender — dramatically better than v1's own limitation text implies. v2 must
correct this: the deficit is O(1)/sec for uniform traffic; larger drops occur
only for front-loaded per-second bursts, which are the #2937 case. This
STRENGTHENS the Option A recommendation.

### MAJOR-3 — BOTH root causes are jointly necessary; v1 doesn't prove neither-alone-works, and the granularity-only fix is a trap
v1 says Option A "repairs both root causes" but does not show that fixing
granularity ALONE (sub-second weight while still counting all arrivals) STILL
fails. It does: with weighting + count-all-arrivals, for sustained-at-`T`,
`count = T·f` (all arrivals) and `prev = T`, so `est = T·(1−f) + T·f ≡ T` for
all `f`; the admission margin (`est + 1 > T`) then drops EVERY packet — the same
over-throttle. Therefore not-counting-rejected is NOT optional polish; it is
REQUIRED, and the two fixes are only correct *together*. v2 must state this
explicitly (it also pre-empts a reviewer proposing "just add sub-second time").

### MAJOR-4 — L14 (u32 saturation) is largely MOOT under the recommended design; v1 over-builds it
Under Option A with count-only-admitted, `count` is bounded by `~threshold` per
second (admission stops once `est` reaches the limit), and a token bucket bounds
`tokens ≤ capacity = threshold`. So `u32` saturation essentially cannot occur for
any realistic threshold — the saturation opacity L14 describes is an artifact of
the CURRENT count-ALL-arrivals design, where `count` grows unbounded within a
second under a volumetric flood. v2 should reframe L14: the recommended design
resolves it structurally (count bounded by threshold ⇒ no runaway `saturating_add`),
so a dedicated saturation metric is likely unnecessary; operator-visible flood
intensity is already the per-screen drop counters (#3343). Keep at most a
`debug_assert`/defensive clamp. This REDUCES scope.

### MINOR-5 — Q2 (count rejected?) is more answerable than v1 admits, incl. the SYN-aggregate cookie interaction
v1 lists Q2 as open. The analysis above (MAJOR-3) makes not-counting-rejected
mandatory. The one place this looks risky is the SYN AGGREGATE
(`increment_and_classify` drives cookie activation, and rate.rs:76-77 documents
the always-count as intentional "so a sustained over-limit sender keeps the
window saturated"). But cookie DEACTIVATION is time-latched: `over_attack` sets
`syn_cookie_active_until_secs = now + EPOCH_SECS` (64s, `screen/mod.rs:681-682`),
and there is NO counter-driven deactivation — so not-counting-rejected does not
shorten cookie-active mode. It also *improves* correctness: a legit sustained
stream at exactly `attack-threshold` no longer spuriously activates cookie mode.
v2 should down-grade Q2 from "open, invitable to PLAN-KILL" to "resolved: don't
count rejected; cookie persistence is time-latched, unaffected."

### MINOR-6 — Q4 (signature blast radius) is answerable; state the answer
Deriving `now_ns` inside the screen path would require a per-packet
`monotonic_nanos()` read, defeating the zero-extra-clock-read benefit. So
threading `loop_now_ns` from loop_body → forwarding → poll_stages → screen →
sketch is the right call, not a real fork. v2 should resolve Q4 rather than leave
it open.

### MINOR-7 — per-batch clock granularity (Q3) deserves a concrete bound, not just an open question
All packets in one poll batch share `loop_now_ns`. Under a volumetric flood,
batches are sub-millisecond apart (NAPI budget drained repeatedly), so `frac`
resolution is fine. The degenerate case is a LOW-rate sender whose whole
per-second load lands in one batch — but a low-rate sender is below threshold and
unaffected. So batch granularity does not reintroduce the 1-second failure at any
rate that matters. v2 should say so and close Q3 (or keep it as a
smoke-validation item, not a design fork).

## Cross-checks that PASS (no finding)
- The `sustained_at_threshold_is_admitted` unit test really does feed `T/2`
  (`half = THRESHOLD/2`, rate.rs:228), confirming the M09 gap. ✓
- No HA/wire/persistence impact — `RateCounter` is per-worker, not in any
  snapshot/protobuf/session-sync path. ✓ (grep of syn_rate.rs / mod.rs confirms
  in-memory only.)
- `loop_now_ns = monotonic_nanos()` at loop_body:241, truncated at :363. ✓
- 16-byte layout achievable for both options; sketch footprint unchanged. ✓
- #2937 tests (`boundary_double_burst_is_bounded`, the icmp recovery test) remain
  satisfiable by both options (drained bucket / saturated weighted estimate at a
  sub-ms straddle). ✓

## Bottom line
Fundamentally sound; recommend Option A. v2 must: fix the inline formula
(MAJOR-1), correct the over-stated Option A limitation to O(1)/sec deficit
(MAJOR-2), prove both-fixes-jointly-necessary and the granularity-only trap
(MAJOR-3), reframe/shrink L14 (MAJOR-4), resolve Q2/Q3/Q4 (MINOR-5/6/7). After
those edits: PLAN-READY on Option A; issue stays open with
`plan-deferred-research` pending manual `/engineer`.
