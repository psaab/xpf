PLAN-NEEDS-CHANGES

`gh issue view 1863` could not be verified here because the sandbox blocks GitHub network access. I verified the checked-in plan, source, and raw artifacts.

1. Section 3 is not killed, but the unshaped-headroom wording is too strong. `raw/unshaped-r2-034255` recomputes to 23.22 G, while shaped `raw/base-r3-033430` recomputes to 19.61 G, so removing CoS/classifier cost buys 3.61 G, about 15.5%. That means [plan.md](/home/ps/git/bpfrx/.claude/worktrees/1863-research/docs/research/1863-realization-gap/plan.md:165) should not use unshaped 23.2 G as direct shaped headroom. The +9 kill still holds: `raw/agg9-r2-022931` delivered 15.12 G against 19.1 G demand, below the already-observed shaped 19.61 G ceiling.

2. The `acquire_v8` code reading is correct, but the measurement proof is overclaimed. Strict no-surplus is real: own-share break at [mod.rs](/home/ps/git/bpfrx/.claude/worktrees/1863-research/userspace-dp/src/afxdp/types/shared_cos_lease/mod.rs:1386), class-cap break at [mod.rs](/home/ps/git/bpfrx/.claude/worktrees/1863-research/userspace-dp/src/afxdp/types/shared_cos_lease/mod.rs:1396), surplus gate at [mod.rs](/home/ps/git/bpfrx/.claude/worktrees/1863-research/userspace-dp/src/afxdp/types/shared_cos_lease/mod.rs:1495), share publication at [rotate_epoch_v8.rs](/home/ps/git/bpfrx/.claude/worktrees/1863-research/userspace-dp/src/afxdp/types/shared_cos_lease/rotate_epoch_v8.rs:350), and bypass arming at [rotate_epoch_v8.rs](/home/ps/git/bpfrx/.claude/worktrees/1863-research/userspace-dp/src/afxdp/types/shared_cos_lease/rotate_epoch_v8.rs:307). But `grants-analysis.py` is worker-pooled, not class-labeled ([grants-analysis.py](/home/ps/git/bpfrx/.claude/worktrees/1863-research/docs/research/1863-realization-gap/grants-analysis.py:11)). Recompute shows `p6g-r1` grants 79.2 GB vs sends 74.9 GB, and `p6g-r3` grants 83.6 GB vs sends 77.3 GB. Keep “lease path is implicated”; do not claim per-class `grants == sends` without the Step-0 per-class/per-worker grant instrumentation.

3. Cell P falsifies the selector watermark as sole rate-setter, but it does not fully close the admission-buffer confound. `buffer_bytes` feeds the lease burst source at [coordinator/mod.rs](/home/ps/git/bpfrx/.claude/worktrees/1863-research/userspace-dp/src/afxdp/coordinator/mod.rs:1573), the token watermark cap at [token_bucket.rs](/home/ps/git/bpfrx/.claude/worktrees/1863-research/userspace-dp/src/afxdp/cos/token_bucket.rs:248), and admission `buffer_limit` at [admission.rs](/home/ps/git/bpfrx/.claude/worktrees/1863-research/userspace-dp/src/afxdp/cos/admission.rs:218). The raw Prometheus scrape lacks admission-drop counters; add them or state they are unavailable. `raw/p6g-r1-033531` still supports rate-invariance, but not a complete admission-layer exclusion.

4. Path A-i is correctly rejected. “Reclaim only evaporating room” is not sound because a fast worker can consume class cap before a slow worker reaches its primary share; the primary path then stops on `ClassCap` ([mod.rs](/home/ps/git/bpfrx/.claude/worktrees/1863-research/userspace-dp/src/afxdp/types/shared_cos_lease/mod.rs:1396)). A-ii is the right lead only if it preserves per-worker isolation, respects equal-flow, and bounds carry against future class cap/outstanding credit.

5. Fix the #1691 ceiling citation. [plan.md](/home/ps/git/bpfrx/.claude/worktrees/1863-research/docs/research/1863-realization-gap/plan.md:343) says “22.72 G push aggregate WITH CoS,” but the checked-in sources describe 22.72 G as reverse-direction sanity: [fairness-regimes.md](/home/ps/git/bpfrx/.claude/worktrees/1863-research/docs/fairness-regimes.md:1296) and [1691 plan.md](/home/ps/git/bpfrx/.claude/worktrees/1863-research/docs/pr/1691-cos-push-ceiling-gate-rescope/plan.md:113). Do not use it as a push proof without a push artifact.

6. Measurement exclusions are defensible but should be made machine-auditable. Section 8 excludes `p6g-r2` and labels `p6g-r3` as extra baseline ([plan.md](/home/ps/git/bpfrx/.claude/worktrees/1863-research/docs/research/1863-realization-gap/plan.md:359)); the decisive claims rely on `base-r3`, `p6g-r1`, `agg9-r2`, and unshaped cells. Add a small raw manifest recording incident labels.

Q1: stale-token completion-lag is plausible; Phase 2 can reselect without honored lockout and debit happens at completion ([queue_service/mod.rs](/home/ps/git/bpfrx/.claude/worktrees/1863-research/userspace-dp/src/afxdp/cos/queue_service/mod.rs:1192), [tx_completion.rs](/home/ps/git/bpfrx/.claude/worktrees/1863-research/userspace-dp/src/afxdp/cos/tx_completion.rs:799)).

Q2: A-i no; A-ii conditionally yes.

Q3: make attribution instrumentation mandatory.

Q4: yes, ship `burst/8` queue-lease ceiling as a decoupled hygiene/latency PR, not the throughput fix.

Codex session ID: 019eb659-06f1-77b3-9cf0-d64f7bbcd17c
Resume in Codex: codex resume 019eb659-06f1-77b3-9cf0-d64f7bbcd17c
