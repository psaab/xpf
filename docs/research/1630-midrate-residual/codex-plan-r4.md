Reviewed clean `research/1630-midrate-residual` at `aad7fe851`; `0e5bb3812` is the base `origin/master` and does not contain this plan file.

Core r3 fold-in is correct: [plan.md](/home/ps/git/bpfrx/.claude/worktrees/1630-research-midrate-residual/docs/research/1630-midrate-residual/plan.md:272) says `quantum_sum` is static over all configured queues, and lines 288-295 say the 1.85MB Phase-1 budget honors 3g/6g every epoch. §4 marks H-WATERFILL falsified, and §6 explicitly says “does NOT commit a fix” and “ONLY THEN design the fix.”

Findings:

1. Missing fifth-layer instrumentation is a real blocker. §5 lists counters through `iperf3 goodput` only: “phase1_honored_bytes”, “drain_sent_bytes”, “cap_granted”, and “iperf3 goodput” ([plan.md](/home/ps/git/bpfrx/.claude/worktrees/1630-research-midrate-residual/docs/research/1630-midrate-residual/plan.md:374)). But §11 admits the missing layer: “ingress/RX side limiting how fast the class's packets even ARRIVE” and “§5 must confirm offered load ≥ shape at the queue ingress” ([plan.md](/home/ps/git/bpfrx/.claude/worktrees/1630-research-midrate-residual/docs/research/1630-midrate-residual/plan.md:644)). That requirement is not actually in §5. Add per-class ingress/enqueue/offered bytes before shaping, ingress drops/refusals, and queue-backlogged/nonempty time. Otherwise RX/conntrack/forward caps can masquerade as shaper/TCP loss.

2. Instrumentation perturbation is acknowledged but not promoted into the deliverable. §5 proposes hot-path `AtomicU64` counters ([plan.md](/home/ps/git/bpfrx/.claude/worktrees/1630-research-midrate-residual/docs/research/1630-midrate-residual/plan.md:367)); §11 says the build “must be A/B'd” or use thread-local accumulators ([plan.md](/home/ps/git/bpfrx/.claude/worktrees/1630-research-midrate-residual/docs/research/1630-midrate-residual/plan.md:638)). But §6.1 only tells /engineer to “Run §5” and read ratios, with no A/B threshold. Make instrumented-vs-uninstrumented delta a §5 acceptance gate.

3. Stale H-WATERFILL/F-W1 text remains and conflicts with v4. §5 still calls H-WATERFILL “Expected primary” ([plan.md](/home/ps/git/bpfrx/.claude/worktrees/1630-research-midrate-residual/docs/research/1630-midrate-residual/plan.md:395)); §10 says “solo 3g/6g CANNOT be Phase-1-honored” ([plan.md](/home/ps/git/bpfrx/.claude/worktrees/1630-research-midrate-residual/docs/research/1630-midrate-residual/plan.md:572)) and “H-WATERFILL explains the SOLO/4-class residual” ([plan.md](/home/ps/git/bpfrx/.claude/worktrees/1630-research-midrate-residual/docs/research/1630-midrate-residual/plan.md:586)). Those are now false under r3.

Cause-1 + #1643 scope is handled well enough: §8 and §9 say Gate 1 requires both causes and that cause-1 must be scoped to 100m/1g until cause-2 lands.

This is an honest measurement-first convergence, not a dodge, but §5 is not yet complete enough to be the deliverable.

VERDICT: PLAN-NEEDS-MAJOR
