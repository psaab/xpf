# Claude-SMR plan-review r2 — #1692 (HOSTILE)

Reviewer seat: Claude SMR. Round 2 against plan v2.

Verdict: **PLAN-READY** (with one column-strengthening note folded below;
not a blocker).

## r1 findings — confirmed addressed in v2

- **F1 (my CRITICAL + Codex CRITICAL)** — `Σ share_i vs class_rate`
  DELETED. §4 rebuilt around `backlog_i` / `granted_i vs share_integral_i`
  / `p1_admit_i vs eligible_visits_i`. The constant-column defect is gone.
- **F2 (demand-bound aliasing)** — `backlog_i` added as the precedence-0
  column; the #1630 cause-2 transport-physics floor is now an explicit
  PLAN-KILL outcome (§8 exit 1). This is the most important fix.
- **F3 (share epoch-gauge)** — replaced by `share_integral_i` accumulated
  per epoch off the existing `snapshot_epoch_v8` seqlock read. Sound.
- **F4 (Option B my_share ordering)** — now explicitly seqlock-piggyback,
  not bare Relaxed.
- **F5 (L2 dead)** — demoted to CONFIRMED DEAD by the monotonic-sum
  argument, kept as a confirmation column only.

## r2 hostile pass — the residual-aliasing attack (the one that matters)

The only way v2's §4 can still fail its consumer criterion is if two of
the three live outcomes share a fingerprint. I attacked the most
dangerous candidate: **can an L1 share-capped worker show `backlog_i ≈ 0`,
aliasing it with the demand-bound (0) outcome?** Verified against the
drain path — the answer is NO, and here is the proof:

When the v8 lease refuses a worker (its `my_share` is exhausted), the
worker's `queue.hot.tokens` stays below `head_len`. The selector's
queue-token gate at `queue_service/mod.rs:879-901` then PARKS the queue
with items STILL ENQUEUED (`continue`, no `pop`). New arrivals keep
accumulating until the per-flow/per-queue admission cap
(`cos/admission.rs`, BDP-aware `buffer_bytes`) starts DROPPING them. So a
share-capped worker sits at `queued_bytes ≈ buffer_bytes` (**backlog > 0,
sustained**), never empty. A demand-bound worker, by contrast, drains
everything it is offered and sits at `queued_bytes ≈ 0`. The two are
cleanly separated. The AF_XDP RX-pull model reinforces this: a slow
worker's backpressure manifests as RX-ring fill / upstream drops, NOT as
the CoS queue emptying — the CoS queue is downstream of RX and only
empties when the worker successfully drains it (which is exactly what L1
prevents). **`backlog_i` is a sound demand proxy; no L1↔0 aliasing.**

BONUS confirmer the v2 table under-uses: the same park branch bumps
`drain_park_queue_tokens` per-(queue,worker) (`:882`). An L1 share-capped
worker shows `park_queue_i > 0` (the v8-gated token bucket starves); a
demand-bound worker shows `park_queue_i ≈ 0` (it never runs out of tokens
because it never asks for many). This is an INDEPENDENT second L1↔0
discriminator already in the worker-local state. v2 lists `park_queue` in
the §6 dump set but does not surface it as a §4 fingerprint column — it
should, as a redundant cross-check on `backlog_i`.

## Other residual-aliasing checks (all pass)

- **L1 vs L3:** L1 has `granted_i ≈ share_integral_i` (lease grants the
  full ceiling, worker just can't get more); L3 has `granted_i <
  share_integral_i` (lease WILLING but selector under-requests because the
  Phase-1 budget moved on). Independent on the `granted vs share_integral`
  column AND on `p1_admit vs eligible_visits` (L3 uniquely shows
  `p1_admit ≪ visits`). No aliasing.
- **L3 vs 0:** L3 has backlog>0 + `p1_admit ≪ visits`; (0) has backlog≈0
  + `p1_admit ≈ visits`. Two independent columns differ. No aliasing.
- **Mixed realization** (some workers demand-bound, some share-capped):
  the §4 rule is applied PER under-delivering busy worker, and the
  precedence (0→L3→L1) resolves each worker independently from the one
  scrape. A class whose under-delivery is PARTLY demand and PARTLY
  share-cap would show a MIX of per-worker fingerprints — which is itself
  a clean finding (the class is bounded by different layers on different
  workers), not an undecidable state. v2 §7 already says "applied per
  under-delivering busy worker"; good.

## Note to fold (non-blocking)

Add `park_queue_i` as an explicit §4 fingerprint column (the bonus
confirmer above): it is a free, already-computed, INDEPENDENT redundant
discriminator for L1↔0, hardening the decision against `backlog_i`
measurement noise (queued_bytes is sampled, not integrated). One sentence
in §4.

## Why PLAN-READY

The rebuilt §4 gives three outcomes three DISTINCT, code-grounded,
independent fingerprints, with a verified-sound demand proxy and a
verified-absent L1↔0 alias. The instrument is judged by whether it
DECIDES, and v2's columns decide. Three of four outcomes are PLAN-KILL
(the honest, #1630/#1220-consistent expectation); only L3 leads to a fix,
and that fix is well-scoped (#1614 Path A candidate 4) and ceiling-bounded.
Instrument-first discipline intact; no production source touched in
/research; no fix pre-chosen. This is a correct measurement-design
deliverable.
