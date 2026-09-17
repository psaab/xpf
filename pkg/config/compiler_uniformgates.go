package config

// runUniformGates runs the P6b "uniform fail-open gate" phase of config
// compilation — the long contiguous run of ~75 independent validation gates
// extracted from compileExpanded as step 4 of the #4406 god-orchestrator
// decomposition (ps-review-011 / codex-173 #4).
//
// Every gate in this phase has the SAME shape: it validates one typed
// sub-struct of the compiled *Config and either (a) returns its first error on
// the strict commit / commit-check path, or (b) downgrades to a warning
// appended to cfg.Warnings on its per-gate tolerant flag (load / peer-sync,
// #1960 no-brick). The phase performs NO cfg mutation — it only reads the
// compiled config, threads warnings, and dispatches the first strict error.
// (validateEventOptionsWithinAST is an AST pre-walk, so this phase also reads
// the group-expanded, inactive-pruned *ConfigTree; it is read-only there.)
//
// Behavior-preserving invariants (do NOT reorder relative to master): the
// source order of every gate is observable — on the strict path the FIRST
// failing gate wins the returned error slot (invariant #6), and on the
// tolerant path all gates run and their warnings accumulate in this exact
// sequence (invariant #7). This is a verbatim contiguous lift of the gate run;
// it runs AFTER P6a's early-strict + folds accumulator and BEFORE the P7 tail
// gates. Covered by the reusable golden-output gate in
// compile_golden_4406_test.go.
//
// The gate run is decomposed (#6423) into per-domain sub-runs living in
// compiler_uniformgates_<domain>.go sibling files. Each sub-run is a verbatim
// contiguous slice of the original flat gate sequence, and runUniformGates
// dispatches them in the SAME order, so the observable first-error and
// warning-accumulation ordering is unchanged.
func runUniformGates(tree *ConfigTree, cfg *Config, opts compileOpts) error {
	if err := runUniformGatesCoSPlatform(tree, cfg, opts); err != nil {
		return err
	}
	if err := runUniformGatesPolicy(tree, cfg, opts); err != nil {
		return err
	}
	if err := runUniformGatesScreen(tree, cfg, opts); err != nil {
		return err
	}
	if err := runUniformGatesClusterZone(tree, cfg, opts); err != nil {
		return err
	}
	if err := runUniformGatesNAT(tree, cfg, opts); err != nil {
		return err
	}
	if err := runUniformGatesDHCPApp(tree, cfg, opts); err != nil {
		return err
	}
	if err := runUniformGatesFilter(tree, cfg, opts); err != nil {
		return err
	}
	if err := runUniformGatesIPsecEvent(tree, cfg, opts); err != nil {
		return err
	}
	if err := runUniformGatesLogFeedRouting(tree, cfg, opts); err != nil {
		return err
	}
	if err := runUniformGatesFirewallNAT2(tree, cfg, opts); err != nil {
		return err
	}
	if err := runUniformGatesSamplingAppSet(tree, cfg, opts); err != nil {
		return err
	}
	if err := runUniformGatesRoutingRibRPM(tree, cfg, opts); err != nil {
		return err
	}
	// #9424: appended at the END of the phase deliberately. The source order of
	// the gates is observable — on the strict path the FIRST failing gate wins
	// the returned error slot (invariant #6) — so a NEW gate inserted between
	// existing ones would change which error an operator is shown for a config
	// that trips two. Last means it can only claim the slot when nothing else
	// failed.
	if err := runUniformGatesInterfaceAddr(tree, cfg, opts); err != nil {
		return err
	}
	// #9821: appended at the END of the phase deliberately, after the #9424
	// gate above — same doctrine as its comment: a NEW gate inserted between
	// existing ones would steal the first-error slot from a config that trips
	// two. Dead-last means the member-collision error only surfaces when no
	// earlier gate (in particular the #5832 canonical-name and #7795
	// kernel-device collision gates, which also see these shapes) failed.
	if err := runUniformGatesRIMemberCollision(tree, cfg, opts); err != nil {
		return err
	}
	// #9814: appended at the END of the phase deliberately, after the #9821
	// gate above — same doctrine as its comment: a NEW gate inserted between
	// existing ones would steal the first-error slot from a config that trips
	// two. Dead-last means the instance-type error only surfaces when no
	// earlier gate failed.
	if err := runUniformGatesRoutingInstanceType9814(tree, cfg, opts); err != nil {
		return err
	}
	return nil
}
