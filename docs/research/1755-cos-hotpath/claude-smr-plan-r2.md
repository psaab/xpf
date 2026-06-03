# Claude SMR plan review — #1755 v2 (round 2)

## Verdict: PLAN-READY

v2 resolves my r1 F1/F2/F3 and incorporates both external reviewers' findings.
No remaining blocker.

## Cross-reviewer convergence (round 1)

All three reviewers agree on the substance:
- **The codegen lever is correct and airtight.** Codex: "Probe attribution is
  sound." AGY: "correct and verified." Me: independently re-derived. The
  push_front control + the 0x56000-matches-FlowFairState size argument is
  unusually conclusive for a perf finding.
- **The headline candidate sub-levers are correctly KILLed.** No reviewer
  defended flow-hash caching / structural-compare bypass / descriptor-indexed
  queuing. Codex confirmed the per-queue-seed soundness argument and only noted a
  safe *intra-call* bucket reuse (now recorded for the #4-follow-up).
- **Change B (heap constructor) is the real soundness question, and v2 now
  specifies it correctly.** Codex finding 3 (zeroed Vec/VecDeque is invalid →
  must use `MaybeUninit` + raw field writes) is folded into §4.1 as a hard
  implementation guard. AGY wanted B mandatory; v2's §4.3 decision procedure
  makes B mandatory-if-relocation-only, measured post-A — which is the correct
  engineering answer (don't pay for B if A eliminates, but be ready because Rust
  has no placement-new guarantee).

## New finding folded in (AGY): the second probe site

AGY's catch of `ensure_cos_interface_runtime` (36 KB, 25.3% of its self-time, on
every ingress packet before the `contains_key` early-exit) is verified live
(`evidence/ensure-cos-iface-annotate.txt`) and is the identical defect class. v2
adds Change A2. This is exactly the kind of thing a hostile round is for — it
was a genuine blind spot in v1 and it's free CPU on the same mechanism.

## Residual risk (acceptable)

- The ≥1 pp ship gate (down from v1's 2 pp) is correct for zero-risk codegen; all
  three converged here.
- The min-bucket O(N) scan (§2.3) remains the only real *algorithmic* per-packet
  residual and is correctly DEFERed to its own CoV-gated PR; the closing comment
  must file it as a follow-up issue so it isn't lost.

PLAN-READY. Hand to `/engineer 1755` for implementation with the §4.3 decision
procedure and the §6 codegen-proof + full CoS smoke matrix as the gate.
