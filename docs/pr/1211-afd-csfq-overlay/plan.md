---
status: REVISED v2 — addressing Codex (PLAN-NEEDS-MAJOR, task-mou6uzry-lmcauh) and Gemini Pro 3 (PLAN-NEEDS-MINOR, task-mou6w83l-mkrcs9)
issue: #1211
phase: research only — produce a doc; no code; decide implement-vs-researched-negative
---

## Round-1 verdict resolution

Codex PLAN-NEEDS-MAJOR with 5 substantive findings; Gemini
PLAN-NEEDS-MINOR with 3 additional design questions. v2 expands
scope and corrects two factual errors.

### 1. Why #838 died — corrected per Codex

v1 Q1 said "#838 failed because multiple workers updated a shared
Count-Min sketch with torn/lost updates". Codex (with reference to
`docs/pr/838-afd-lite/findings.md:55`) says the actual record is
different: cross-binding failed on **period reset coherence,
fair-share denominator staleness, rollback semantics**; then
single-binding died on **"selector blind during scratch-build"**
because accounting happened at settle, one batch later.

**Single-writer sharded design only addresses write/write contention.
It does NOT close: reset epochs, read/write visibility, denominator
staleness, rollback, or batch-latency holes.**

v2's Q1 must enumerate each of these as a separate sub-question
the design has to answer, not collapse them all into "race-safety".

### 2. Scope expansion — Codex finding #2 + Gemini Q1/Q2

v1 had 6 questions. v2 adds:

- **Q1.5 — Sketch decay** (Gemini): how does the design age out
  byte counts? Periodic zero (sawtooth), EMA (memory/compute
  doubled), sliding window (double sketch buffers + extra cost).
  This is decision-load-bearing — the wrong choice destroys
  accuracy.
- **Q2.5 — Token-bucket admission ordering** (Gemini): does AFD
  fire BEFORE the existing `cos_queue_flow_share_limit` admission
  cap or AFTER? Before = early shedder (saves token capacity for
  conforming flows); after = double-penalty risk. Also: where
  exactly does AFD slot in vs `cos_classify.rs:717` and
  `queue_service/mod.rs:416`?
- **Q3.5 — V_min double-signal** (Codex): shared_exact already
  runs MQFQ + V_min sync. Does AFD ECN-marking / dropping interact
  badly with V_min throttle (worker stalls because peer V_min
  binds AND gets AFD-marked → two penalties for same condition)?
- **Q4.5 — Stable global flow hash** (Codex): current
  `flow_hash_seed` is per-queue-runtime (`flow_hash.rs:39`,
  `admission.rs:497`). A shared sketch needs a globally consistent
  hash so flow F maps to bucket B regardless of which worker hashes
  it. Re-using `cos_flow_bucket_index(seed, flow_key)` is NOT
  safe across workers without a coordinator-owned shared seed.
- **Q5.5 — Active-flow denominator estimation** (Codex): "fair share"
  needs N_active_flows. How estimated and how stale? Coupling to
  `active_flow_buckets_peak`?
- **Q6.5 — Per-packet sketch lookup latency** (Codex): hot-path
  cost of N hash probes + atomic loads at 25 G+. Real budget on
  this hardware?
- **Q6.7 — ECN-only behavior for non-ECT traffic** (Codex): TCP
  flows without ECN negotiation can't receive ECN signals. Does
  AFD drop them, or fall back to bytes-counted-only?

### 3. Empirical estimate — not defensible without prototype

Both reviewers flagged the +5-10pp guess. Codex: "Analytical math
can bound collision rate and CPU cost, but not CoV improvement.
Require a runnable simulator or trace-replay harness if the result
is decision (a). Analytical-only is acceptable only for
researched-negative." Gemini: "TCP's reaction to probabilistic ECN
(especially distinguishing between Cubic, Reno, BBR) is highly
non-linear and depends heavily on concurrent flow count and RTT.
Pure guessing will lead to a false positive for implementation."

**v2 changes the deliverable scope:**

- If the research direction looks like decision (a) (file
  implementation issue), the deliverable MUST include either a
  minimal Python simulator (simplified TCP state machine + AFD
  marker) or a direct mapping to a published paper at the same
  scale.
- If it looks like (b) researched-negative, analytical-only is
  acceptable.

### 4. #936 ordering — stale (Codex finding)

v1 said "defer pending #936 revisit". Codex notes #936 plan files
are absent from current tree (only in git history); the historical
#936 plan was withdrawn because shared_exact already had MQFQ +
V_min. v2 reframes:

> AFD is an overlay on current MQFQ + V_min sync. Any future
> shared per-flow scheduler is a competing implementation path
> for the same CoV gate, with AFD possibly complementary only
> after double-signal risk (Q3.5) is modeled.

### 5. CSFQ scope (Codex)

v1 had CSFQ in title but only AFD in body. v2: either renames to
AFD-only OR adds a short CSFQ evaluation. **v2 adopts the latter:**

> CSFQ requires edge rate labels stamped/propagated through the
> network. xpf does not stamp such labels and inheriting them from
> upstream is out of scope. Therefore the feasible design here
> is effectively AFD/no-edge — record this in the research doc
> and drop CSFQ from active consideration.

### 6. Race-safety (Gemini)

v1 sketched `[u64; ...]` non-atomic with single-writer discipline.
**Gemini correction**: in Rust, reading a plain `u64` from another
thread while it's being written is a **data race and Undefined
Behavior**, even single-writer. Use `AtomicU64` with
`Ordering::Relaxed` — overhead on x86 is effectively zero (compiles
to standard movs) but satisfies the language model. v2 records
this as a design constraint, not a TBD.

### 7. Decision criterion threshold (Gemini Q3)

v1 left "what % CoV improvement justifies multi-week implementation"
open. **v2 picks a concrete threshold:** decision (a) requires
projected CoV improvement ≥ 8 percentage points (28% → ≤ 20%) AND
aggregate regression ≤ 5%. Below that → (b) researched-negative.



## 1. Issue framing

Current ECN policy on `shared_exact` CoS queues uses **aggregate**
threshold only (`apply_cos_admission_ecn_policy`). Rationale: MQFQ
already orders by virtual finish time, so per-flow ECN would
double-signal. Trade-off: shared_exact lacks a precise per-flow
congestion signal.

Per Codex CoS findings retrospective:

> [Aggregate-only ECN] is plausible, but it also means shared_exact
> still lacks a precise per-flow congestion signal unless a later
> AFD/CSFQ-style mechanism is introduced.

This is **complementary** to #936 (cross-worker shared per-flow
vtime); both target the same residual cross-worker fairness gap (#789
≤20% CoV currently 24-29% on saturated workloads).

#838-afd-lite was a prior attempt; killed for race-safety. This issue
revisits with the question: can a single-writer sharded design close
those holes?

## 2. Honest scope/value framing

**This is a RESEARCH issue, not implementation.** The deliverable is
a doc that answers:

- What's the design space for AFD-on-shared_exact?
- Which sub-design closes the race-safety holes that killed #838?
- Empirical estimate: would AFD on top of current MQFQ + V_min sync
  close the 8 percentage points (24-29% → ≤20%) on iperf-c?
- Decision: file an implementation issue with a concrete plan, OR
  document as researched-negative.

**If the decision is "researched-negative", that's a successful
outcome of this issue.** Closing #1211 with a documented "explored,
won't ship" doc is a real result.

## 3. Research questions

### 3.1 Re-read the inputs

- `docs/cross-worker-flow-fairness-research.md` §2.3 (AFD section
  from #786 research doc). Confirms what was on the table at #786
  closure.
- `docs/pr/838-afd-lite/findings.md` — what the killed AFD-lite
  prototype actually did and why it was killed for race-safety.
- `userspace-dp/src/afxdp/cos/admission.rs` — current ECN policy
  arms (per-flow on owner-local; aggregate on shared_exact). Where
  exactly would AFD slot in?
- The #936 plan-review history (`docs/pr/789-phase2-byte-rate/plan.md`
  PLAN-KILL findings, `docs/pr/936-shared-perflow-vtime/plan.md` v1
  WITHDRAWN findings) for what the reviewers think about adjacent
  per-flow mechanisms.

### 3.2 Design questions

#### Q1: Single-writer sharded sketch — what does it look like?

The race-safety problem with #838-afd-lite was that multiple workers
updated a shared count-min sketch concurrently, causing torn reads
and lost updates.

Single-writer sharded design:
- Each worker owns its own shard of the sketch.
- Per-worker: `[AtomicU64; CMS_DEPTH × CMS_WIDTH / N_WORKERS]`?
  Or `[u64; CMS_DEPTH × CMS_WIDTH]` non-atomic with single-writer
  discipline (similar to #1209 BindingLiveLocal)?
- On read: scrub all worker shards and aggregate.

What's the read cadence? Real-time per-packet (every drop/mark
decision needs the aggregate)? That's expensive — coordination per
packet defeats the purpose of sharding.

Alternative: workers maintain local estimate + periodic sync (like
V_min). Imprecise but cheap. Imprecision tolerable for AFD because
it's probabilistic anyway.

#### Q2: Where in the pipeline does AFD-marking fire?

AFD as ECN-mark on enqueue:
- Hook into `apply_cos_admission_ecn_policy`. Per-flow shadow rate
  → mark when over fair share.
- Adjustment over current code: replace the aggregate threshold on
  shared_exact with a per-flow-rate-aware threshold derived from the
  sharded sketch.

AFD as drop on enqueue (more aggressive):
- Replace `cos_queue_flow_share_limit` cap with probabilistic drop
  proportional to (flow_rate / fair_share).
- Acceptance criterion: aggregate throughput preserved (TCP
  re-transmits cwnd-cut from the drop).

Both must NOT regress non-shared_exact admission.

#### Q3: Sketch size + memory cost

Count-Min sketch, 4 hashes × 4096 cells × 8 bytes = 128 KB per
shared_exact queue per worker.

At 6 shared_exact classes × 8 workers × 2 ifaces ≈ 12 MB total.
Acceptable.

#### Q4: Read cadence for the aggregator

Per-packet read: too expensive (multi-shard scan + per-flow rate
estimate per packet). Bad design.

Periodic read: 100 Hz? 10 Hz? The sketch's age tolerance bounds the
upper limit; 100 ms stale rate signal is fine for ECN purposes
(sub-RTT for typical TCP).

Tie to existing `COS_STATUS_INTERVAL_NS = 100ms`? That's the most
natural anchor — the worker already has a 10 Hz tick.

#### Q5: Per-flow rate estimate from the sketch

Count-Min over flow-bucket vs full 5-tuple? The existing
`cos_flow_bucket_index(seed, flow_key)` already hashes 5-tuple to
4096 buckets. AFD could reuse the same bucket index → no new hash.

Estimate: bytes-counted-into-bucket / sample-window. With 4096 buckets
and N flows, accuracy degrades when N >> 4096 (Birthday paradox
collision boost the estimate); at iperf-c P=12 (12 flows) collisions
are negligible.

#### Q6: Empirical fit on the gate

Will this clear ≤20% CoV on iperf-c P=12?

Hypothesis: ECN marks proportional to over-fair-share rate would let
TCP cwnd jitter converge faster. Empirically untested. Best estimate:
+5 to +10 percentage points improvement (from 28% → 18-23%). Could
clear the gate; might not.

Recommend a measurement-only prototype before committing to
implementation.

## 4. Deliverable shape

A research doc at `docs/pr/1211-afd-csfq-overlay/findings.md` with:

1. Re-read of #786 + #838-afd-lite findings, summarized.
2. Single-writer sharded design sketch addressing Q1-Q6.
3. Empirical estimate for whether the design could clear the gate.
4. Decision:
   - (a) **File implementation issue with concrete plan.** Triple-
     review that. Multi-week implementation effort.
   - (b) **Researched-negative**: document the design space + why
     the residual gap isn't worth this much engineering.
   - (c) **Defer pending #936 (shared per-flow vtime) revisit**: AFD
     as a complement, not a replacement.

## 5. Effort estimate

- Read + summarize #786 + #838-afd-lite: 4-8 hours.
- Design sketch addressing Q1-Q6 with explicit single-writer race
  analysis: 8-16 hours.
- Empirical estimate (probably analytical, not prototype): 2-4 hours.
- Decision write-up: 2-4 hours.
- Total: 16-32 hours research effort. **No code touched in this
  issue's scope.**

## 6. Risk

| Class | Level | Why |
|---|---|---|
| Research effort wasted | LOW-MED | Even researched-negative is a documented outcome; future fairness work cites this doc |
| Mis-estimate of empirical fit | MED | Without prototype, the +5-+10 pp estimate could be off by 2× |
| Race-safety design hole | MED | Single-writer sharded looks safe but Q1's coordination cost might force a different shape |

## 7. Acceptance for THIS issue

- [ ] `docs/pr/1211-afd-csfq-overlay/findings.md` exists.
- [ ] All 6 design questions (Q1-Q6) have a concrete answer.
- [ ] Decision (a/b/c) is explicit with rationale.
- [ ] If decision (a): a follow-up implementation issue is filed
  with a plan v1 stub.
- [ ] If decision (b/c): the doc serves as the closing artifact.

## 8. Out of scope

- Implementation — gated on decision (a) and a separate issue.
- CSFQ as a competing design — Codex retrospective lists CSFQ as
  alternative; this issue focuses on AFD per the title. CSFQ stays
  out unless AFD researched-negative AND CSFQ is resurrected.
- Per-flow ECN on owner-local-exact (already shipped).

## 9. Open questions for adversarial review

1. **Should the research doc include a runnable prototype harness?**
   The current scope is doc-only; reviewers may push for a
   minimum-viable simulator that estimates the empirical fit.
2. **Is single-writer sharded the right primitive?** Or should the
   design start from a different sketch shape (e.g., HyperLogLog
   for distinct-flow count, separate bytes-tracking)?
3. **Decision criterion for (a) vs (b).** What estimated CoV
   improvement justifies multi-week implementation? +10 pp is a
   real win for #789 but might not be worth weeks of work if the
   measured improvement turns out smaller.
4. **Order with #936.** If #936 is being reconsidered as a complement
   here, this research issue should explicitly call out the
   interaction model (overlay, alternative, sequencing).

## 10. Verdict request

PLAN-READY → execute the research (doc-only deliverable).
PLAN-NEEDS-MINOR → tweak the question list / acceptance.
PLAN-NEEDS-MAJOR → revise (e.g., add prototype harness; reorganize
around CSFQ instead).
PLAN-KILL → research not worth doing; close #1211.
