package config

import (
	"strings"
	"testing"
)

// #3682: host-inbound LIFELINE exemptions (management / cluster-control
// interfaces excluded from host-inbound deny scoping) must be OPERATOR-VISIBLE.
// #11068 narrows the role proof to fxp0 plus explicitly configured cluster
// control/fabric links; bare em0/fab* names remain ordinary ingress interfaces.
// These tests pin visibility on the shared presenter: configured exemptions
// render their marker, and the renderer must not silently exempt unconfigured
// names by spelling alone.

func TestHostInboundLifelineInterface3682(t *testing.T) {
	def := HostInboundLifelineSet(nil)
	// Only fxp0 is an unconditional lifeline; bare em0/fab names are not roles.
	for _, name := range []string{"fxp0", "fxp0.0"} {
		if !HostInboundLifelineInterface(name, def) {
			t.Errorf("HostInboundLifelineInterface(%q) = false, want true (fxp0 default lifeline)", name)
		}
	}
	for _, name := range []string{"em0", "em0.0", "fab0", "fab0.0", "fab1.0",
		"ge-0/0/0.0", "reth0.50", "xe-1/0/0.0", ""} {
		if HostInboundLifelineInterface(name, def) {
			t.Errorf("HostInboundLifelineInterface(%q) = true, want false (no configured role)", name)
		}
	}
	// A configured chassis-cluster control-interface is added to the set (#3277).
	cfg := &Config{}
	cfg.Chassis.Cluster = &ClusterConfig{ControlInterface: "hb0", FabricInterface: "fabx0"}
	cfg.Interfaces.Interfaces = map[string]*InterfaceConfig{
		"fab1": {Name: "fab1", FabricMembers: []string{"ge-7/0/1"}},
	}
	set := HostInboundLifelineSet(cfg)
	for _, name := range []string{"hb0", "hb0.0", "fabx0.0", "fab1", "fab1.0"} {
		if !HostInboundLifelineInterface(name, set) {
			t.Errorf("configured lifeline %q not matched", name)
		}
	}
}

// TestHostInboundViewLifelineExemptRendered3682 proves the presenter shows the
// fixed/configured exemption and does not infer a role from em0/fab0 spelling.
func TestHostInboundViewLifelineExemptRendered3682(t *testing.T) {
	labels := HostInboundLabels{
		Indent: "  ", Sep: ", ",
		ServicesLabel: "Host-inbound system-services", ProtocolsLabel: "Host-inbound protocols",
	}
	const marker = "Host-inbound lifeline-exempt interfaces (management/fabric, bypass host-inbound deny):"
	lifelines := HostInboundLifelineSet(nil)

	// A zone that also assigns the ordinary names em0/fab0 has only fxp0
	// exempted; the names alone do not establish cluster roles.
	z := &ZoneConfig{
		Interfaces:         []string{"ge-0/0/0.0", "fxp0.0", "em0.0", "fab0.0"},
		HostInboundTraffic: &HostInboundTraffic{SystemServices: []string{"ssh"}},
	}
	lines := z.HostInboundViewWithLifelines(lifelines).Render(labels)
	out := strings.Join(lines, "\n")
	if !strings.Contains(out, marker) {
		t.Fatalf("zone view missing lifeline-exempt line for fxp0\n%s", out)
	}
	lifelineLine := ""
	for _, line := range lines {
		if strings.Contains(line, marker) {
			lifelineLine = line
		}
	}
	if !strings.Contains(lifelineLine, "fxp0.0") {
		t.Errorf("fixed lifeline missing from exemption line: %q", lifelineLine)
	}
	for _, ordinary := range []string{"ge-0/0/0.0", "em0.0", "fab0.0"} {
		if strings.Contains(lifelineLine, ordinary) {
			t.Errorf("ordinary interface %q wrongly listed as lifeline-exempt: %q", ordinary, lifelineLine)
		}
	}

	// A zone with only ordinary interfaces must NOT render the lifeline line.
	zd := &ZoneConfig{
		Interfaces:         []string{"ge-0/0/0.0", "em0.0", "fab0.0"},
		HostInboundTraffic: &HostInboundTraffic{SystemServices: []string{"ssh"}},
	}
	if out := strings.Join(zd.HostInboundViewWithLifelines(lifelines).Render(labels), "\n"); strings.Contains(out, marker) {
		t.Errorf("zone without an actual lifeline wrongly rendered the exempt line\n%s", out)
	}
}

// TestHostInboundViewLifelineFromClusterConfig3682 proves a configured
// (non-default-named) control/fabric interface is surfaced too.
func TestHostInboundViewLifelineFromClusterConfig3682(t *testing.T) {
	labels := HostInboundLabels{Indent: "  ", Sep: ", "}
	cfg := &Config{}
	cfg.Chassis.Cluster = &ClusterConfig{ControlInterface: "hb0"}
	z := &ZoneConfig{Interfaces: []string{"hb0.0", "ge-0/0/1.0"}}
	out := strings.Join(z.HostInboundViewWithLifelines(HostInboundLifelineSet(cfg)).Render(labels), "\n")
	if !strings.Contains(out, "hb0.0") ||
		!strings.Contains(out, "lifeline-exempt interfaces") {
		t.Fatalf("configured control-interface hb0.0 not surfaced as lifeline-exempt\n%s", out)
	}
}

// TestRenderInterfaceHostInboundLifeline3682 pins the per-interface diagnostic:
// a lifeline interface renders the exempt marker in place of the default-deny
// line; a non-lifeline no-stanza interface still renders default-deny.
func TestRenderInterfaceHostInboundLifeline3682(t *testing.T) {
	labels := HostInboundLabels{Indent: "  ", Sep: ", ", ServicesLabel: "Host-inbound services", ProtocolsLabel: "Host-inbound protocols"}
	const exempt = "Host-inbound: lifeline-exempt (management/fabric, bypasses host-inbound deny)"

	z := &ZoneConfig{}
	// lifeline=true: exempt marker, NO default-deny line.
	out := strings.Join(z.RenderInterfaceHostInbound("fxp0.0", true, labels), "\n")
	if !strings.Contains(out, exempt) {
		t.Errorf("lifeline diagnostic missing exempt marker\n%s", out)
	}
	if strings.Contains(out, "default deny") {
		t.Errorf("lifeline diagnostic must not show default-deny\n%s", out)
	}
	// lifeline=false, no stanza: default-deny line, NO exempt marker.
	out = strings.Join(z.RenderInterfaceHostInbound("ge-0/0/0.0", false, labels), "\n")
	if !strings.Contains(out, "Host-inbound: default deny (no stanza)") {
		t.Errorf("non-lifeline diagnostic missing default-deny line\n%s", out)
	}
	if strings.Contains(out, exempt) {
		t.Errorf("non-lifeline diagnostic must not show lifeline-exempt marker\n%s", out)
	}
}
