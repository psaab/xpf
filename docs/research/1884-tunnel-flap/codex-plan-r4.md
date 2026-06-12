Codex Task started in the background as task-mqal3hio-w426sa. Check /codex:status task-mqal3hio-w426sa for progress.
CODEX_ID=task-mqal3hio-w426sa
PLAN-NEEDS-REVISION

The different-VRF fold closes only that narrower case, but the original same-apply list-bind blocker is still open for same-VRF moves.

Counterexample: previous apply records `appliedRI[gr-0-0-0] = "BLUE"` from a tunnel stanza. Next apply removes `tunnel routing-instance BLUE` and adds `routing-instances BLUE interface gr-0/0/0.0`. Step 0a binds tunnel list members before `ApplyTunnels` ([daemon_apply.go](/home/ps/git/bpfrx/.claude/worktrees/1884-research/pkg/daemon/daemon_apply.go:216), [daemon_apply.go](/home/ps/git/bpfrx/.claude/worktrees/1884-research/pkg/daemon/daemon_apply.go:257)); A.5 also acknowledges that ordering ([plan.md](/home/ps/git/bpfrx/.claude/worktrees/1884-research/docs/research/1884-tunnel-flap/plan.md:325)). But the proposed unbind guard still passes because `appliedRI != ""`, stanza RI is empty, and current master is still `vrf-BLUE` ([plan.md](/home/ps/git/bpfrx/.claude/worktrees/1884-research/docs/research/1884-tunnel-flap/plan.md:339)). That strips the 0a list bind, contradicting the stated net effect that 0a list bindings, including same-apply replacements, are never touched ([plan.md](/home/ps/git/bpfrx/.claude/worktrees/1884-research/docs/research/1884-tunnel-flap/plan.md:351)). The test matrix only pins replacement to a different VRF, not same VRF ([plan.md](/home/ps/git/bpfrx/.claude/worktrees/1884-research/docs/research/1884-tunnel-flap/plan.md:503)).

Q1: the name-to-current-index identity test is fine for VRF rename and cross-name ifindex reuse. Reconcile is name-based `vrf-<ri>` delete/create, not in-place rename ([daemon_apply.go](/home/ps/git/bpfrx/.claude/worktrees/1884-research/pkg/daemon/daemon_apply.go:170), [vrf.go](/home/ps/git/bpfrx/.claude/worktrees/1884-research/pkg/routing/vrf.go:89)), and resolving the VRF name at decision time avoids stored-ifindex reuse hazards. The lapse rule is right for mismatch/lookup-failure and successful unbind, but not as an unconditional “empty stanza” rule if `LinkSetNoMaster` fails; clearing then would lose retry state while the stale master remains ([plan.md](/home/ps/git/bpfrx/.claude/worktrees/1884-research/docs/research/1884-tunnel-flap/plan.md:347)).

Q2: no PLAN-KILL counterexample. The revision needed is local: A.5 needs current 0a list-bind intent in the unbind decision, and tests must include same-RI stanza-to-list replacement plus `LinkSetNoMaster` failure lifecycle.

Codex session ID: 019ebaa8-3dd2-7af1-ace6-118c16a9444b
Resume in Codex: codex resume 019ebaa8-3dd2-7af1-ace6-118c16a9444b
