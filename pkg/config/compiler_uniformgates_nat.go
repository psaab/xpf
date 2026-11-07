package config

// runUniformGatesNAT runs the NAT sub-run of the P6b uniform fail-open gate
// phase. The cross-gate order doctrine and pinned precedence exceptions are
// documented in the runUniformGates header.
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
