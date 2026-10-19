package dhcpserver

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// renderedInterfaces15028 reads the interfaces-config list from a
// generated Kea config.
func renderedInterfaces15028(t *testing.T, path, family string) []string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var outer map[string]struct {
		InterfacesConfig struct {
			Interfaces []string `json:"interfaces"`
		} `json:"interfaces-config"`
	}
	if err := json.Unmarshal(raw, &outer); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	return outer["Dhcp"+family].InterfacesConfig.Interfaces
}

func dupIfaceV4Config15028() *config.DHCPServerConfig {
	// Post-resolution shape: the daemon has already translated reth1.0
	// and ge-0/0/1.0 to the one kernel device ge-0-0-1.
	return &config.DHCPServerConfig{DHCPLocalServer: &config.DHCPLocalServerConfig{Groups: map[string]*config.DHCPServerGroup{
		"g1": {Name: "g1", Interfaces: []string{"ge-0-0-1"}, Pools: []*config.DHCPPool{
			{Name: "p1", Subnet: "10.0.61.0/24", RangeLow: "10.0.61.100", RangeHigh: "10.0.61.199"},
		}},
		"g2": {Name: "g2", Interfaces: []string{"ge-0-0-1", "ge-0-0-2"}, Pools: []*config.DHCPPool{
			{Name: "p1", Subnet: "10.0.62.0/24", RangeLow: "10.0.62.100", RangeHigh: "10.0.62.199"},
		}},
	}}}
}

// TestKea4DuplicateInterfaceRendersOnce15028 binds the v4 render belt.
// The duplicate device must be emitted once, the distinct device kept,
// and a warning must name the dropped duplicate.
func TestKea4DuplicateInterfaceRendersOnce15028(t *testing.T) {
	m, _ := testManager(t, map[string]bool{}, "")
	warned := recordWarnings9785(m)
	if err := m.generateKea4Config(dupIfaceV4Config15028()); err != nil {
		t.Fatalf("generateKea4Config: %v", err)
	}
	got := renderedInterfaces15028(t, m.confPath4, "4")
	if len(got) != 2 || got[0] != "ge-0-0-1" || got[1] != "ge-0-0-2" {
		t.Fatalf("want [ge-0-0-1 ge-0-0-2] rendered once each, got %v", got)
	}
	found := false
	for _, w := range *warned {
		if strings.Contains(w, "duplicate DHCP interface") && strings.Contains(w, "ge-0-0-1") {
			found = true
		}
	}
	if !found {
		t.Errorf("want one duplicate-interface warning naming ge-0-0-1, got %v", *warned)
	}
}

// TestKea6DuplicateInterfaceRendersOnce15028 is the v6 twin.
func TestKea6DuplicateInterfaceRendersOnce15028(t *testing.T) {
	cfg := &config.DHCPServerConfig{DHCPv6LocalServer: &config.DHCPLocalServerConfig{Groups: map[string]*config.DHCPServerGroup{
		"a6": {Name: "a6", Interfaces: []string{"ge-0-0-1"}, Pools: []*config.DHCPPool{
			{Name: "p", Subnet: "2001:db8:61::/64", RangeLow: "2001:db8:61::10", RangeHigh: "2001:db8:61::20"},
		}},
		"b6": {Name: "b6", Interfaces: []string{"ge-0-0-1"}, Pools: []*config.DHCPPool{
			{Name: "p", Subnet: "2001:db8:62::/64", RangeLow: "2001:db8:62::10", RangeHigh: "2001:db8:62::20"},
		}},
	}}}
	m, _ := testManager(t, map[string]bool{}, "")
	warned := recordWarnings9785(m)
	if err := m.generateKea6Config(cfg); err != nil {
		t.Fatalf("generateKea6Config: %v", err)
	}
	got := renderedInterfaces15028(t, m.confPath6, "6")
	if len(got) != 1 || got[0] != "ge-0-0-1" {
		t.Fatalf("want [ge-0-0-1] rendered once, got %v", got)
	}
	found := false
	for _, w := range *warned {
		if strings.Contains(w, "duplicate DHCPv6 interface") && strings.Contains(w, "ge-0-0-1") {
			found = true
		}
	}
	if !found {
		t.Errorf("want one duplicate-interface warning naming ge-0-0-1, got %v", *warned)
	}
}

// TestKeaInterfacesWithoutDuplicateRenderUnchanged15028 is the control:
// distinct devices render in stable order with no warning.
func TestKeaInterfacesWithoutDuplicateRenderUnchanged15028(t *testing.T) {
	cfg := &config.DHCPServerConfig{DHCPLocalServer: &config.DHCPLocalServerConfig{Groups: map[string]*config.DHCPServerGroup{
		"g1": {Name: "g1", Interfaces: []string{"ge-0-0-1"}, Pools: []*config.DHCPPool{
			{Name: "p1", Subnet: "10.0.61.0/24", RangeLow: "10.0.61.100", RangeHigh: "10.0.61.199"},
		}},
		"g2": {Name: "g2", Interfaces: []string{"ge-0-0-2"}, Pools: []*config.DHCPPool{
			{Name: "p1", Subnet: "10.0.62.0/24", RangeLow: "10.0.62.100", RangeHigh: "10.0.62.199"},
		}},
	}}}
	m, _ := testManager(t, map[string]bool{}, "")
	warned := recordWarnings9785(m)
	if err := m.generateKea4Config(cfg); err != nil {
		t.Fatalf("generateKea4Config: %v", err)
	}
	got := renderedInterfaces15028(t, m.confPath4, "4")
	if len(got) != 2 || got[0] != "ge-0-0-1" || got[1] != "ge-0-0-2" {
		t.Fatalf("CONTROL BROKE: want [ge-0-0-1 ge-0-0-2], got %v", got)
	}
	if len(*warned) != 0 {
		t.Errorf("CONTROL BROKE: want no warnings, got %v", *warned)
	}
}

// TestDedupKeaInterfaces15028 pins the belt's keep-first semantics and
// its empty-string posture.
func TestDedupKeaInterfaces15028(t *testing.T) {
	out, dropped := dedupKeaInterfaces([]string{"ge-0-0-1", "ge-0-0-2", "ge-0-0-1", "", "ge-0-0-2"})
	if len(out) != 3 || out[0] != "ge-0-0-1" || out[1] != "ge-0-0-2" || out[2] != "" {
		t.Fatalf("want [ge-0-0-1 ge-0-0-2 ], got %v", out)
	}
	if len(dropped) != 2 || dropped[0] != "ge-0-0-1" || dropped[1] != "ge-0-0-2" {
		t.Fatalf("want dropped [ge-0-0-1 ge-0-0-2], got %v", dropped)
	}
	out, dropped = dedupKeaInterfaces(nil)
	if len(out) != 0 || len(dropped) != 0 {
		t.Fatalf("nil input: want empty, got %v / %v", out, dropped)
	}
}
