**Verdict: PLAN-NEEDS-MAJOR**

The artifact math supports the structural PASS, but one key PLAN-KILL ground cracks: the plan equates existing `equal-flow-enforcement` with the issue’s “equal-flow-preserving surplus” option. That is not what the code ships.

Findings:

1. **HIGH - “Option 2 is already shipped” is false as written.**  
   The plan defines Option 2 as surplus donation constrained by an epoch per-flow cap ([plan.md](/home/ps/git/bpfrx/.claude/worktrees/1296-cos-surplus-cov/docs/pr/1296-cos-surplus-cov/plan.md:24)), then claims it is already implemented ([plan.md](/home/ps/git/bpfrx/.claude/worktrees/1296-cos-surplus-cov/docs/pr/1296-cos-surplus-cov/plan.md:80)). But config validation rejects `equal-flow-enforcement` with `surplus-sharing` ([compiler.go](/home/ps/git/bpfrx/.claude/worktrees/1296-cos-surplus-cov/pkg/config/compiler.go:432)), docs say enforcement is valid only on exact-rate schedulers without surplus-sharing ([state.md](/home/ps/git/bpfrx/.claude/worktrees/1296-cos-surplus-cov/docs/per-5-tuple/state.md:467)), and the Rust acquire path closes surplus when equal-flow is enforced: `surplus_open = bypass && !equal_flow_enforced` ([mod.rs](/home/ps/git/bpfrx/.claude/worktrees/1296-cos-surplus-cov/userspace-dp/src/afxdp/types/shared_cos_lease/mod.rs:1186)).  
   The shipped feature is real, but it is a non-work-conserving equal-flow suppressor, not equal-flow-preserving surplus-sharing.

2. **HIGH - strict-exact CoV numbers do not prove equal-flow-enforcement meets the raw CoV target.**  
   The plan treats q2/q3/q6 strict-exact numbers as evidence that equal-flow mode will likely hit `<= 0.20` ([plan.md](/home/ps/git/bpfrx/.claude/worktrees/1296-cos-surplus-cov/docs/pr/1296-cos-surplus-cov/plan.md:122)). That remains unverified. Equal-flow enforcement can fail open on incomplete, low-demand, stale, zero-target, or insufficient-streak samples ([publish_equal_flow_epoch_v8.rs](/home/ps/git/bpfrx/.claude/worktrees/1296-cos-surplus-cov/userspace-dp/src/afxdp/types/shared_cos_lease/publish_equal_flow_epoch_v8.rs:30)), and it caps per active SFQ bucket, not necessarily per original 5-tuple. The plan must require a real equal-flow run before claiming “nothing to ship” for that criterion.

3. **MEDIUM - the hot-path atomic claim is overstated.**  
   Normal equal-flow cap evaluation is mostly load-only, but `equal_flow_cap_v8` does a `fetch_add` on stale/tag mismatch ([mod.rs](/home/ps/git/bpfrx/.claude/worktrees/1296-cos-surplus-cov/userspace-dp/src/afxdp/types/shared_cos_lease/mod.rs:1467)). Cap-hit and suppressed-byte counters also increment on denied grants ([mod.rs](/home/ps/git/bpfrx/.claude/worktrees/1296-cos-surplus-cov/userspace-dp/src/afxdp/types/shared_cos_lease/mod.rs:1164)). This likely still satisfies “no shared global atomic on every packet,” but the plan should not call the cap path atomic-free.

Verified points:

- The quoted q3 sample is PASS by contract. `observed_cov=0.6700`, `cstruct=0.6753`, ceiling is `0.7253`; contract gap is `observed_cov - cstruct = -0.0053`, not gap-to-ceiling. The harness uses that convention ([verdict.rs](/home/ps/git/bpfrx/.claude/worktrees/1296-cos-surplus-cov/userspace-dp/src/fairness_eval/verdict.rs:107)).
- The CLI-to-dataplane wire exists: parser/compiler set the flag, Go snapshot serializes it, Rust protocol decodes it, forwarding build maps it onto queue config, and coordinator builds `V8RateMode::EqualFlowSuppress`.
- #1211 revisit criteria are not met by the cited artifact: the artifact is PASS, not a real production FAIL exceeding `Cstruct + epsilon` ([CLOSING-RATIONALE.md](/home/ps/git/bpfrx/.claude/worktrees/1296-cos-surplus-cov/docs/per-5-tuple/path2-archive/CLOSING-RATIONALE.md:54)).

Strongest outcome: revise the plan to stop claiming Option 2 is already shipped. Then either PLAN-KILL the new dataplane mechanism as a product decision, with an issue comment that accurately says existing equal-flow is non-work-conserving and mutually exclusive with surplus-sharing, or scope a small PR to label structural PASS clearly and run q2/q3/q6 under existing equal-flow enforcement.

Codex session ID: 019e6770-efb6-7672-80af-6616484d3729
Resume in Codex: codex resume 019e6770-efb6-7672-80af-6616484d3729
