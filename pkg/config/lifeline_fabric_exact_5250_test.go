// #5250 (A3-b2 F3): the host-inbound LIFELINE fallback matched ANY interface
// whose base name started with "fab", so an interface literally named
// "fab-foo" / "fabric-uplink" was silently exempted from host-inbound
// default-deny with no configured management or cluster role. The daemon only
// ever creates fab0/fab1, and an operator-renamed fabric link already reaches
// the lifeline set through HostInboundLifelineSet, so the prefix bought
// nothing. Reachable in device-map mode (#1956), where a mapped NIC carries an
// operator-chosen name.
//
// FAIL-ON-REVERT: restore `strings.HasPrefix(base, "fab")` and the
// non-canonical names below become lifelines again — the "want false"
// assertions go RED.
package config

import "testing"

func TestLifelineFabricMatchIsExact_5250(t *testing.T) {
	def := HostInboundLifelineSet(nil)

	// Canonical daemon-created fabric devices stay exempt (#3070/#3172/#3224
	// behavior preserved), with and without a unit suffix.
	for _, name := range []string{"fab0", "fab1", "fab0.0", "fab1.0", "fab10", "em0", "em0.0", "fxp0"} {
		if !HostInboundLifelineInterface(name, def) {
			t.Errorf("HostInboundLifelineInterface(%q) = false, want true (canonical lifeline)", name)
		}
	}

	// Non-canonical "fab"-prefixed names are NOT lifelines by default: an
	// unrelated interface must not gain a silent host-inbound deny bypass.
	for _, name := range []string{"fab", "fab-foo", "fab-foo.0", "fabric0", "fabx0", "fabulous", "fab0x", "fab_1"} {
		if HostInboundLifelineInterface(name, def) {
			t.Errorf("HostInboundLifelineInterface(%q) = true, want false (prefix bypass must be gone)", name)
		}
	}

	// A CONFIGURED fabric/control interface with a non-canonical name is still
	// exempt — it comes from the chassis-cluster stanza, not from the prefix.
	// This is the #3277 contract and must survive the narrowing.
	cfg := &Config{}
	cfg.Chassis.Cluster = &ClusterConfig{ControlInterface: "hb0", FabricInterface: "fabx0", Fabric1Interface: "fab-foo"}
	set := HostInboundLifelineSet(cfg)
	for _, name := range []string{"hb0", "hb0.0", "fabx0", "fabx0.0", "fab-foo", "fab-foo.0"} {
		if !HostInboundLifelineInterface(name, set) {
			t.Errorf("configured lifeline %q not matched — narrowing the fallback must not strand a configured link", name)
		}
	}
}
