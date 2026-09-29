// #11068: a bare interface name does not establish a management or cluster
// role. Only fxp0 is an unconditional host-inbound lifeline; em0 and fab<N>
// names are exempt only when the chassis-cluster config assigns that role.
//
// FAIL-ON-REVERT: restore the implicit em0/fab<N> matcher and the unconfigured
// names below become lifelines again, so their "want false" assertions go RED.
package config

import "testing"

func TestLifelineInterfacesRequireConfiguredRole11068(t *testing.T) {
	def := HostInboundLifelineSet(nil)

	// fxp0 alone is an unconditional lifeline, with or without a unit suffix.
	for _, name := range []string{"fxp0", "fxp0.0"} {
		if !HostInboundLifelineInterface(name, def) {
			t.Errorf("HostInboundLifelineInterface(%q) = false, want true (fxp0 default lifeline)", name)
		}
	}

	// Canonical-looking names do not establish a role; neither do other
	// "fab"-prefixed names.
	for _, name := range []string{"em0", "em0.0", "fab0", "fab0.0", "fab1", "fab1.0", "fab10",
		"fab", "fab-foo", "fab-foo.0", "fabric0", "fabx0", "fabulous", "fab0x", "fab_1"} {
		if HostInboundLifelineInterface(name, def) {
			t.Errorf("HostInboundLifelineInterface(%q) = true, want false (no configured lifeline role)", name)
		}
	}

	// Configured names, including the canonical spellings, remain lifelines
	// because the chassis-cluster stanza explicitly assigns those roles.
	cfg := &Config{}
	cfg.Chassis.Cluster = &ClusterConfig{ControlInterface: "em0", FabricInterface: "fab0", Fabric1Interface: "fab1"}
	set := HostInboundLifelineSet(cfg)
	for _, name := range []string{"em0", "em0.0", "fab0", "fab0.0", "fab1", "fab1.0"} {
		if !HostInboundLifelineInterface(name, set) {
			t.Errorf("configured lifeline %q not matched — narrowing the fallback must not strand a configured link", name)
		}
	}
}
