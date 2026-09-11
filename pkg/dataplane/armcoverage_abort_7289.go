package dataplane

// #7289 R1 — an apply that ABORTS after CompileConfig's Phase-2 host mutation
// must leave behind a published arm-coverage verdict that describes THIS apply.
//
// THE HOLE. `ProveArmCoverage` is the only publisher of the #7191 coverage cell
// (armcoverage_publish.go), it is called from exactly one place — the tail of
// CompileUserspaceShim — and every abort between the host mutation and that
// tail returns first. The daemon's gate (`evaluateArmCoverage`,
// pkg/daemon/daemon_arm_coverage_7191.go) then reads a cell this apply never
// touched, and there are two reachable states, neither of which disarms:
//
//   - FIRST apply aborts: the cell has never been published, so
//     `ArmCoverageSummary` reports seen=false, `classifyArmCoverageVerdict`
//     returns armCoverageUnknown — and `evaluateArmCoverage`'s switch has NO
//     case for unknown. Nothing disarms, and before #9725 the apply tail then
//     wrote `writeTransitForwardSysctls(d.DataplaneArmed())` with the box still
//     armed; the tail now writes the transit gate (transitOpen). On a fresh boot
//     the runtime is armed before the first per-interface attach, so this was
//     an armed, open kernel transit path over an interface carrying no XDP
//     shim: the policy-free-router state #7191 exists to prevent.
//
//   - a LATER apply aborts: the cell still holds the PREVIOUS generation's
//     report, which said Ran=true, Uncovered=0. The gate classifies
//     armCoverageComplete and logs "arm coverage complete" — an affirmative
//     statement of coverage sourced from a proof about a different apply.
//     armcoverage_publish.go states the opposite as its own invariant ("a stale
//     report answering for a previous generation is worse than no report");
//     the abort path is where the implementation did not honour it.
//
// THE FIX IS TO RUN THE REAL PROOF, NOT TO SYNTHESISE A VERDICT. Publishing a
// hand-built "everything uncovered" report on abort would be both a lie in the
// data model (Ran means a proof ran) and wrong on the box: a re-attach can fail
// while the PREVIOUS shim is still attached and still adjudicating that
// interface's transit, and disarming there would brick a box whose forwarding
// was never unadjudicated. ProveArmCoverage reads LIVE kernel and bpf state, so
// it answers that question correctly in both directions — covered when a
// program really is attached, uncovered when none is — using the same
// classification the success path uses. It is also the only way to publish at
// all: publishArmCoverage is deliberately reachable only from inside the proof,
// so that a stashed or hand-built report cannot be published.
//
// SCOPE. This covers the aborts that happen with a CompileResult in hand — the
// two bpffs cleanups and runPostMutationSteps (preflightCheckIfindexCaps and
// attachUserspaceShimXDP). A failure inside CompileConfig's own later phases
// returns `nil` for the result (compiler.go returns `nil, err` on every phase
// error), so there is no pendingXDP to prove coverage against and this cannot
// help there; #7289's body classes those as "effectively unreachable
// post-#6894 on the live shim path", and closing them needs CompileConfig to
// return a partial result, which is a separate change.
//
// This is deliberately NOT an undo. Nothing here restores the host state Phase
// 2 already moved — PR #7288 makes that divergence VISIBLE and this makes the
// forwarding surface it leaves ADJUDICATED. An undo for live host state is
// itself fallible, and one that fails mid-rollback leaves a third state worse
// than the two it was reconciling.
func (m *Manager) abortAfterHostMutation(result *CompileResult, err error) error {
	if m == nil || result == nil {
		// Only reachable if a future caller moves this above CompileConfig's
		// success check. Nothing to prove against, so publishing would be the
		// synthesis this function exists to avoid.
		return err
	}
	// Same shape as the success-path call in CompileUserspaceShim: a LIVE proof
	// on the compile's own result, logged under its own stage so an operator can
	// tell an abort verdict from a post-attach one in a log archive.
	m.ProveArmCoverage(result).LogArmCoverage("apply-aborted", m.nextApplyGeneration())
	// #8285: remember the host state this abort leaves unconverged, so a RETRY
	// still reports it even though its own Phase 2 will find the host already in
	// the desired shape and record nothing.
	m.recordHostDivergence(result)
	return err
}
