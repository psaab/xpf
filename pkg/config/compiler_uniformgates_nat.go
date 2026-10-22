package config

// runUniformGatesNAT runs the nat sub-run of the P6b uniform
// fail-open gate phase. It is a verbatim contiguous slice of the
// original runUniformGates god-function (#6423 decomposition): the
// gate order here and the segment-call order in runUniformGates together
// reproduce the exact flat gate sequence, so the first-failing-gate-wins
// strict ordering (invariant #6) and the tolerant warning-accumulation
// order (invariant #7) are preserved. See runUniformGates.
//
// #16145 W2.1: the gates themselves now live in the per-sub-run registry
// in compiler_uniformgates_nat_registry_16145.go (natGates, in censused
// execution order, essays verbatim). The trailing warning-only
// appendDNATOffShadowPotentialWarnings is not a strict/lenient gate
// (no strict error), so it stays outside the registry slice, called
// here in its censused position after the registry.
func runUniformGatesNAT(tree *ConfigTree, cfg *Config, opts compileOpts) error {
	if err := runNATGates16145(cfg, opts); err != nil {
		return err
	}
	appendDNATOffShadowPotentialWarnings(cfg)

	return nil
}
