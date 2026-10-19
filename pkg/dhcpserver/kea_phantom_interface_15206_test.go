package dhcpserver

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #15206 (A17-03): the Kea renderer must never emit a device name no
// configured interface resolves to. A config that reached the renderer
// through the tolerant load / peer-sync path carrying an undeclared ref
// (post-resolution shape: `reth1.7`, `ge-0-0-9.0`) would otherwise render
// the phantom verbatim into interfaces-config AND into the per-subnet
// selector of a single-interface group; Kea refuses the whole file and
// every pool of the family stops. The belt (FilterKeaInterfaces15206,
// applied by the daemon on the resolved copy) drops the phantom with a
// warning naming it; surviving pools and devices render unchanged.
//
// FAIL-ON-REVERT: drop the FilterKeaInterfaces15206 calls in pkg/daemon
// (desiredStandaloneDHCPConfig / cluster tail) or the empty-interface
// skip in the generators and the phantom cells render `reth1.7`.

func activeCfg15206() *config.Config {
	return &config.Config{Interfaces: config.InterfacesConfig{Interfaces: map[string]*config.InterfaceConfig{
		"ge-0/0/1": {Name: "ge-0/0/1", Units: map[int]*config.InterfaceUnit{0: {Number: 0}}},
		"ge-0/0/2": {Name: "ge-0/0/2", RedundantParent: "reth1"},
		"reth1":    {Name: "reth1", RedundancyGroup: 1, Units: map[int]*config.InterfaceUnit{0: {Number: 0}, 80: {Number: 80, VlanID: 180}}},
	}}}
}

func phantomV4Config15206() *config.DHCPServerConfig {
	return &config.DHCPServerConfig{DHCPLocalServer: &config.DHCPLocalServerConfig{Groups: map[string]*config.DHCPServerGroup{
		"z-broken": {Name: "z-broken", Interfaces: []string{"reth1.7"}, Pools: []*config.DHCPPool{
			{Name: "broken-range", Subnet: "10.0.99.0/24", RangeLow: "10.0.99.100", RangeHigh: "10.0.99.199"},
		}},
		"lan": {Name: "lan", Interfaces: []string{"ge-0-0-1"}, Pools: []*config.DHCPPool{
			{Name: "lan-range", Subnet: "10.0.61.0/24", RangeLow: "10.0.61.100", RangeHigh: "10.0.61.199"},
		}},
	}}}
}

func phantomV6Config15206() *config.DHCPServerConfig {
	return &config.DHCPServerConfig{DHCPv6LocalServer: &config.DHCPLocalServerConfig{Groups: map[string]*config.DHCPServerGroup{
		"z-broken6": {Name: "z-broken6", Interfaces: []string{"reth9.0"}, Pools: []*config.DHCPPool{
			{Name: "broken6", Subnet: "2001:db8:99::/64", RangeLow: "2001:db8:99::100", RangeHigh: "2001:db8:99::199"},
		}},
		"lan6": {Name: "lan6", Interfaces: []string{"ge-0-0-1"}, Pools: []*config.DHCPPool{
			{Name: "lan6-range", Subnet: "2001:db8:61::/64", RangeLow: "2001:db8:61::100", RangeHigh: "2001:db8:61::199"},
		}},
	}}}
}

func interfaceWarnings15206(warned []string, name string) []string {
	var out []string
	for _, w := range warned {
		if strings.Contains(w, "not a configured device") && strings.Contains(w, name) {
			out = append(out, w)
		}
	}
	return out
}

// belt15206 applies the daemon's belt the way desired*DHCPConfig does.
func belt15206(t *testing.T, m *Manager, cfg *config.DHCPServerConfig, family string) *config.DHCPServerConfig {
	t.Helper()
	warn := func(msg string, args ...any) { m.warn(msg, args...) }
	filtered, changed := FilterKeaInterfaces15206(cfg, activeCfg15206(), family, warn)
	if !changed {
		t.Fatalf("belt must drop the phantom for family %s", family)
	}
	return filtered
}

func TestKea4PhantomInterfaceSkipped15206(t *testing.T) {
	m, _ := testManager(t, map[string]bool{}, "")
	warned := recordWarnings9785(m)
	cfg := belt15206(t, m, phantomV4Config15206(), "4")
	if err := m.generateKea4Config(cfg); err != nil {
		t.Fatalf("generateKea4Config: %v", err)
	}
	ifaces := renderedInterfaces15028(t, m.confPath4, "4")
	for _, iface := range ifaces {
		if iface == "reth1.7" {
			t.Fatalf("phantom device rendered into interfaces-config, which Kea refuses: %v", ifaces)
		}
	}
	if len(ifaces) != 1 || ifaces[0] != "ge-0-0-1" {
		t.Fatalf("want only the surviving device [ge-0-0-1], got %v", ifaces)
	}
	subnets := renderedSubnets9785(t, m.confPath4, "4")
	for _, s := range subnets {
		if s.Subnet == "10.0.99.0/24" {
			t.Fatalf("subnet of the phantom-only group must be skipped with it: %+v", subnets)
		}
	}
	if len(subnets) != 1 || subnets[0].Subnet != "10.0.61.0/24" {
		t.Fatalf("want the healthy subnet rendered unchanged, got %+v", subnets)
	}
	if drops := interfaceWarnings15206(*warned, "reth1.7"); len(drops) != 1 {
		t.Fatalf("want one phantom-drop warning naming reth1.7, got %v", *warned)
	}
}

func TestKea6PhantomInterfaceSkipped15206(t *testing.T) {
	m, _ := testManager(t, map[string]bool{}, "")
	warned := recordWarnings9785(m)
	cfg := belt15206(t, m, phantomV6Config15206(), "6")
	if err := m.generateKea6Config(cfg); err != nil {
		t.Fatalf("generateKea6Config: %v", err)
	}
	ifaces := renderedInterfaces15028(t, m.confPath6, "6")
	for _, iface := range ifaces {
		if iface == "reth9.0" {
			t.Fatalf("phantom device rendered into interfaces-config, which Kea refuses: %v", ifaces)
		}
	}
	if len(ifaces) != 1 || ifaces[0] != "ge-0-0-1" {
		t.Fatalf("want only the surviving device [ge-0-0-1], got %v", ifaces)
	}
	subnets := renderedSubnets9785(t, m.confPath6, "6")
	for _, s := range subnets {
		if s.Subnet == "2001:db8:99::/64" {
			t.Fatalf("subnet of the phantom-only group must be skipped with it: %+v", subnets)
		}
	}
	if len(subnets) != 1 || subnets[0].Subnet != "2001:db8:61::/64" {
		t.Fatalf("want the healthy subnet rendered unchanged, got %+v", subnets)
	}
	if drops := interfaceWarnings15206(*warned, "reth9.0"); len(drops) != 1 {
		t.Fatalf("want one phantom-drop warning naming reth9.0, got %v", *warned)
	}
}

// Control: a group mixing a phantom with a real device keeps the real
// device; its subnet renders via the surviving member.
func TestKea4MixedGroupKeepsRealDevice15206(t *testing.T) {
	cfg := &config.DHCPServerConfig{DHCPLocalServer: &config.DHCPLocalServerConfig{Groups: map[string]*config.DHCPServerGroup{
		"mixed": {Name: "mixed", Interfaces: []string{"ge-0-0-1", "reth1.7"}, Pools: []*config.DHCPPool{
			{Name: "m-range", Subnet: "10.0.61.0/24", RangeLow: "10.0.61.100", RangeHigh: "10.0.61.199"},
		}},
	}}}
	m, _ := testManager(t, map[string]bool{}, "")
	warned := recordWarnings9785(m)
	filtered := belt15206(t, m, cfg, "4")
	if err := m.generateKea4Config(filtered); err != nil {
		t.Fatalf("generateKea4Config: %v", err)
	}
	ifaces := renderedInterfaces15028(t, m.confPath4, "4")
	if len(ifaces) != 1 || ifaces[0] != "ge-0-0-1" {
		t.Fatalf("want the real device kept and the phantom dropped, got %v", ifaces)
	}
	subnets := renderedSubnets9785(t, m.confPath4, "4")
	if len(subnets) != 1 || subnets[0].Subnet != "10.0.61.0/24" {
		t.Fatalf("mixed group subnet must render on the surviving device: %+v", subnets)
	}
	if drops := interfaceWarnings15206(*warned, "reth1.7"); len(drops) != 1 {
		t.Fatalf("want one phantom-drop warning, got %v", *warned)
	}
}

// Control: no phantom -> belt is a no-op (same pointer, no warnings).
func TestKeaBeltNoPhantomIsNoop15206(t *testing.T) {
	m, _ := testManager(t, map[string]bool{}, "")
	warned := recordWarnings9785(m)
	cfg := phantomV4Config15206()
	delete(cfg.DHCPLocalServer.Groups, "z-broken")
	warn := func(msg string, args ...any) { m.warn(msg, args...) }
	out, changed := FilterKeaInterfaces15206(cfg, activeCfg15206(), "4", warn)
	if changed || out != cfg {
		t.Fatalf("belt must be a no-op without a phantom: changed=%v", changed)
	}
	if len(*warned) != 0 {
		t.Fatalf("no warnings expected, got %v", *warned)
	}
}
