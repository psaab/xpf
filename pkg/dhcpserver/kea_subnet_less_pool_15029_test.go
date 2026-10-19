package dhcpserver

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #15029: a subnet-less pool that reached the renderer through the tolerant
// load / peer-sync path must be skipped with a warning naming group/pool,
// not rendered as "subnet": "". Kea refuses the empty subnet and then loads
// nothing, so emitting it would stop every healthy pool of the family.
// The healthy pools render unchanged (stable ids preserved: the skip is
// before resolveSubnetID).

func subnetLessV4Config15029() *config.DHCPServerConfig {
	return &config.DHCPServerConfig{DHCPLocalServer: &config.DHCPLocalServerConfig{Groups: map[string]*config.DHCPServerGroup{
		"lan-pool": {Name: "lan-pool", Interfaces: []string{"reth1.0"}, Pools: []*config.DHCPPool{
			{Name: "lan-range", Subnet: "10.0.61.0/24", RangeLow: "10.0.61.100", RangeHigh: "10.0.61.199"},
		}},
		"z-broken": {Name: "z-broken", Interfaces: []string{"reth1.0"}, Pools: []*config.DHCPPool{
			{Name: "no-subnet", DNSServers: []string{"10.0.61.53"}},
		}},
	}}}
}

func subnetLessV6Config15029() *config.DHCPServerConfig {
	return &config.DHCPServerConfig{DHCPv6LocalServer: &config.DHCPLocalServerConfig{Groups: map[string]*config.DHCPServerGroup{
		"lan6": {Name: "lan6", Interfaces: []string{"reth1.0"}, Pools: []*config.DHCPPool{
			{Name: "lan6-range", Subnet: "2001:db8:61::/64", RangeLow: "2001:db8:61::100", RangeHigh: "2001:db8:61::199"},
		}},
		"z-broken6": {Name: "z-broken6", Interfaces: []string{"reth1.0"}, Pools: []*config.DHCPPool{
			{Name: "no-subnet6", DNSServers: []string{"2001:db8:61::53"}},
		}},
	}}}
}

func skipWarnings15029(warned []string) []string {
	var out []string
	for _, w := range warned {
		if strings.Contains(w, "subnet-less") || strings.Contains(w, "no subnet") {
			out = append(out, w)
		}
	}
	return out
}

func TestKea4SubnetLessPoolSkipped15029(t *testing.T) {
	m, _ := testManager(t, map[string]bool{}, "")
	if err := m.generateKea4Config(subnetLessV4Config15029()); err != nil {
		t.Fatalf("generateKea4Config: %v", err)
	}
	// Baseline without the broken pool: record first, then with it.
	m2, _ := testManager(t, map[string]bool{}, "")
	baseCfg := subnetLessV4Config15029()
	delete(baseCfg.DHCPLocalServer.Groups, "z-broken")
	if err := m2.generateKea4Config(baseCfg); err != nil {
		t.Fatalf("control generateKea4Config: %v", err)
	}
	base := renderedSubnets9785(t, m2.confPath4, "4")

	warned := recordWarnings9785(m)
	// Regenerate with the recorder installed.
	if err := m.generateKea4Config(subnetLessV4Config15029()); err != nil {
		t.Fatalf("generateKea4Config with subnet-less pool: %v", err)
	}
	got := renderedSubnets9785(t, m.confPath4, "4")
	for _, s := range got {
		if s.Subnet == "" {
			t.Fatalf("subnet-less pool rendered as empty subnet, which Kea refuses: %+v", got)
		}
	}
	if len(got) != len(base) {
		t.Fatalf("want healthy pools rendered unchanged (%d), got %+v", len(base), got)
	}
	for i := range base {
		if got[i].Subnet != base[i].Subnet || got[i].ID != base[i].ID || len(got[i].Pools) != len(base[i].Pools) {
			t.Fatalf("healthy pool changed by the skip: base %+v got %+v", base, got)
		}
		for j := range base[i].Pools {
			if got[i].Pools[j].Pool != base[i].Pools[j].Pool {
				t.Fatalf("healthy pool changed by the skip: base %+v got %+v", base, got)
			}
		}
	}
	skips := skipWarnings15029(*warned)
	if len(skips) != 1 || !strings.Contains(skips[0], "no-subnet") {
		t.Fatalf("want one skip warning naming pool no-subnet, got %v", *warned)
	}
}

func TestKea6SubnetLessPoolSkipped15029(t *testing.T) {
	m, _ := testManager(t, map[string]bool{}, "")
	m2, _ := testManager(t, map[string]bool{}, "")
	baseCfg := subnetLessV6Config15029()
	delete(baseCfg.DHCPv6LocalServer.Groups, "z-broken6")
	if err := m2.generateKea6Config(baseCfg); err != nil {
		t.Fatalf("control generateKea6Config: %v", err)
	}
	base := renderedSubnets9785(t, m2.confPath6, "6")
	warned := recordWarnings9785(m)
	if err := m.generateKea6Config(subnetLessV6Config15029()); err != nil {
		t.Fatalf("generateKea6Config with subnet-less pool: %v", err)
	}
	got := renderedSubnets9785(t, m.confPath6, "6")
	for _, s := range got {
		if s.Subnet == "" {
			t.Fatalf("subnet-less pool rendered as empty subnet, which Kea refuses: %+v", got)
		}
	}
	if len(got) != len(base) {
		t.Fatalf("want healthy pools rendered unchanged (%d), got %+v", len(base), got)
	}
	for i := range base {
		if got[i].Subnet != base[i].Subnet || got[i].ID != base[i].ID {
			t.Fatalf("healthy pool changed by the skip: base %+v got %+v", base, got)
		}
	}
	skips := skipWarnings15029(*warned)
	if len(skips) != 1 || !strings.Contains(skips[0], "no-subnet6") {
		t.Fatalf("want one skip warning naming pool no-subnet6, got %v", *warned)
	}
}
