# Claude SMR hostile plan review — #1863 round 1 (plan v2.1)

Reviewer stance: domain SMR (CoS scheduler + v8 lease), CPU/arch, SW
design. Hostile per `feedback_triple_review_includes_claude_smr`. I
re-derived the arithmetic, re-ran the analysis scripts against raw/,
and re-read every cited code line before writing this.

## Verification performed

- §3 arithmetic recomputed: water-fill level over {0.1,1,3,6,24} at
  22.6 G → smalls saturate, 24g residual 12.5 G (52.1%). Observed 24g
  11.8-12.1 G (49-51%) matches the residual; mids do not match their
  predicted saturation. Confirmed.
- §4.1 watermark chain re-traced: `compute_shared_cos_lease_config_with_bank`
  (`shared_cos_lease/mod.rs:876-937`) — `lease_ceiling =
  burst/8 = 12,000` for `burst = 96,000` (queue lease burst =
  `queue.buffer_bytes.max(64*1500)`, `coordinator/mod.rs:1573`);
  top-up watermark bank-floored at 32,768 (`token_bucket.rs:248-252`,
  `COS_EXACT_QUEUE_LEASE_BANK_BYTES = 8 × 4096`). Confirmed.
- §2.4/2.5 numbers recomputed from raw/ via honor-analysis.py +
  grants-analysis.py: B/honor 31,505→57,706, honors 537,005→280,570,
  grants≈sends (76.9 vs 77.2 GB; 59.5 vs 59.5 GB). Confirmed.
- `acquire_v8_with_cause` strict no-surplus reading: the
  ShareExhausted break at `shared_cos_lease/mod.rs:1386-1388` ends
  the primary path; the post-grace claiming the plan says was removed
  is indeed absent (comment block at :1486-1496 documents the
  deliberate removal); the only escape is `bypass_grace` whose
  arming requires three co-conditions (`rotate_epoch_v8.rs:313`).
  Confirmed.

## Findings

1. **HIGH (gate justification, fixable in-doc): the ≥21 G aggregate
   gate needs an existence proof under CoS overhead.** §6 targets
   ≥21 G on small4+24g, but the unshaped 23.2 G bound excludes CoS
   CPU cost, and no cell in this corpus exceeded 19.65 G with CoS
   loaded. The proof exists in the record: the #1691 plan documents
   a **22.72 G push aggregate WITH CoS** (all-11-classes parallel),
   so the CoS-overheaded ceiling is ≥22.7 G and the ≥21 G gate is
   reachable. The plan MUST cite this, else the gate is aspirational.
2. **MEDIUM: the cross-class coupling story (visit cadence × share
   evaporation) is consistent with but not uniquely proven by the
   data for 3g.** Pooled 3g eligible-visit spacing (~170 µs/worker
   average) is FASTER than the 200 µs lease epoch; only per-worker
   tails (not observable in the pooled counters — one worker at
   0.0 GB grants in p6g-r1 is suggestive, not conclusive) can carry
   the sampling-loss account. The plan is honest about this (Q3,
   §4.2 last paragraph), and the fix family covers both sub-causes —
   acceptable for /research — but the /engineer phase MUST carry an
   attribution instrument (per-class requested-vs-granted, or
   per-worker per-class grant deltas) so the fix's effect is
   attributable and the (a)/(b) split falls out. Recommend promoting
   that from "if needed" (Q3) to a Path-A deliverable.
3. **MEDIUM: udp3g drop-site not localized.** §2.7's 37-38% loss is
   internal to the shaped pipeline (wire loss otherwise 0), which
   suffices for the supply-side conclusion, but the snapshot regex
   (`xpf_userspace_cos_|xpf_userspace_worker_cos_`) captured no
   admission-drop counters, so whether the drops land at CoS
   admission (buffer/flow-share) vs elsewhere is unresolved. This
   does not weaken §2.7's discrimination (inelastic delivery ceiling
   == elastic delivery ceiling is the load-bearing fact) but the
   round-2 doc should either name the admission counter family and
   capture it, or state why it is not exported.
4. **LOW: Path A second-order CPU feedback.** "Reclaiming
   evaporating room cannot reduce peers' grants" is true per-epoch
   within a class, but more grants → more sends → more per-pass CPU
   on the reclaiming worker → cadence side-effects on OTHER classes
   sharing that worker. The §6 multi-class gates (small4+9g all ≥
   85%; fairness contract) already fence this; note it as a known
   risk in §5 rather than discovering it at code review.
5. **LOW: s24-r1/r2 carried a stale 6g buffer-size** (failed revert,
   honestly disclosed). Since cell P proves the knob rate-neutral
   and s24-r3 reproduces clean, the cells stand; no action.
6. **PROCESS (positive): the registered prediction of v1 was
   falsified by the plan's own cell P and the mechanism section was
   rewritten before first review** — this is the methodology working
   as intended, and the v1→v2 trail is preserved in git.

## Answers to §9

- **Q1**: The stale-token completion-lag reading is plausible and now
  immaterial to the thesis; agree to keep it as a flagged observation.
  Alternative (multiple eligible-visit top-ups between admissions
  accumulating above watermark) is excluded by the `tokens >=
  lease_bytes_wm` early-return; I found no third explanation.
- **Q2**: The room-bounded reclaim argument is sound IN-CLASS (the
  reclaimed bytes are bounded by `cap − class_granted`, which today
  evaporates), and the #1231 iperf-d regression came from
  cross-WORKER slack claiming that reduced a peer's effective share
  mid-epoch. Reclaim of UNCLAIMABLE-by-anyone room is different in
  kind. But finding 4's CPU feedback and the equal-flow interaction
  (reclaim must respect `equal_flow_cap_v8`) need explicit handling.
- **Q3**: See finding 2 — promote the attribution instrument to a
  Path-A deliverable.
- **Q4**: Yes, ship the `burst/8` queue-lease ceiling fix as hygiene
  in the same PR or a sibling: it silently discards configured rate
  and cell P shows it is behaviorally load-bearing for batching
  (B/honor, honor cadence) even though not for rate; batching
  granularity affects latency/jitter even when throughput is fixed.

## Verdict

**PLAN-READY-WITH-CHANGES** (round-2 doc edits, no re-measurement
required): fold findings 1 (cite #1691 22.72 G), 2 (attribution
instrument as deliverable), 3 (drop-site note), 4 (risk note). The
kill-exit closure is ratified on all three legs; the rate-setter
localization is ratified with finding 2's caveat; Path A is the
right lead.
