package config

import (
	"strings"
	"testing"
)

// #12848 D3-15: dotted DECLARED lifeline names must not promote dotted siblings.
// ControlInterface "hb.1" declares interface hb.1 (bare), not hb. Its units are
// hb.1.<unit>; hb.2/hb.10 are separate declared interfaces, never lifelines.
func TestLifelineDottedDeclaredNames12848(t *testing.T) {
	cfg := &Config{}
	cfg.Chassis.Cluster = &ClusterConfig{
		ControlInterface: "hb.1",
		FabricInterface:  "ge-0/0/0.100",
	}
	cfg.Interfaces.Interfaces = map[string]*InterfaceConfig{
		"hb.1":         {Name: "hb.1", Units: map[int]*InterfaceUnit{0: {Number: 0}}},
		"hb.2":         {Name: "hb.2", Units: map[int]*InterfaceUnit{0: {Number: 0}}},
		"hb.10":        {Name: "hb.10", Units: map[int]*InterfaceUnit{0: {Number: 0}}},
		"ge-0/0/0.100": {Name: "ge-0/0/0.100", Units: map[int]*InterfaceUnit{0: {Number: 0}}},
		"ge-0/0/0.200": {Name: "ge-0/0/0.200", Units: map[int]*InterfaceUnit{0: {Number: 0}}},
	}
	set := HostInboundLifelineSet(cfg)
	for _, name := range []string{"hb.1", "hb.1.0", "hb.1.00", "ge-0/0/0.100", "ge-0/0/0.100.0", "fxp0", "fxp0.0"} {
		if !HostInboundLifelineInterface(name, set) {
			t.Errorf("HostInboundLifelineInterface(%q) = false, want true", name)
		}
	}
	for _, name := range []string{"hb", "hb.0", "hb.2", "hb.2.0", "hb.10", "hb.10.0", "ge-0/0/0", "ge-0/0/0.0", "ge-0/0/0.200", "ge-0/0/0.200.0"} {
		if HostInboundLifelineInterface(name, set) {
			t.Errorf("HostInboundLifelineInterface(%q) = true, want false (sibling/not that interface)", name)
		}
	}
	view := (&ZoneConfig{Interfaces: []string{"hb.1.0", "hb.2", "hb.10", "ge-0/0/0.200"}}).
		HostInboundViewWithLifelines(set)
	lines := view.Render(HostInboundLabels{})
	rendered := strings.Join(lines, "\n")
	if !strings.Contains(rendered, "hb.1.0") || !strings.Contains(rendered, "lifeline-exempt interfaces") {
		t.Errorf("rendered host-inbound view omitted configured dotted lifeline:\n%s", rendered)
	}
	for _, sibling := range []string{"hb.2", "hb.10", "ge-0/0/0.200"} {
		for _, line := range lines {
			if strings.Contains(line, "lifeline-exempt interfaces") && strings.Contains(line, sibling) {
				t.Errorf("rendered lifeline exemption included sibling %q: %s", sibling, line)
			}
		}
	}
}
