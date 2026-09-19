package config

// fabricStampSharedSegmentAdvisories10105 returns the commit-time operator
// warning for the unauthenticated zone-encoded fabric stamp (#10105).
//
// Software cannot observe whether a fabric NIC is direct-attached, on a
// two-member bridge, or on a shared switch. The compiled fabric-interface
// identity is nevertheless a real signal that the stamp trust boundary exists,
// so surface the required deployment constraint whenever a fabric is enabled.
// This is intentionally an advisory rather than a hard reject: the same
// configuration can be safe or unsafe depending on the operator's L2 plant,
// and rejecting every fabric would reject the supported direct-link topology.
func fabricStampSharedSegmentAdvisories10105(cfg *Config) []string {
	if cfg == nil || cfg.Chassis.Cluster == nil {
		return nil
	}
	cc := cfg.Chassis.Cluster
	if cc.FabricInterface == "" && cc.Fabric1Interface == "" {
		return nil
	}
	return []string{
		"chassis cluster fabric zone stamp (#10105): fabric links MUST be a private two-peer L2 domain (direct-attached, dedicated VLAN/bridge, or operator-provided MACsec); shared switching with a live RG split is unsupported because the zone stamp is cloneable by an L2-adjacent host",
	}
}
