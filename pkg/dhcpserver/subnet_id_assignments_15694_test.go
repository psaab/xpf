package dhcpserver

import (
	"net/netip"
	"reflect"
	"strconv"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #15694: the `show dhcp server detail` renderers display the Kea subnet-id
// beside each pool via SubnetIDAssignments15694. That map must agree with
// the ids generateKea4Config / generateKea6Config actually write into the
// Kea config — a drift would correlate leases to the wrong pool, the exact
// confusion the display exists to prevent.
//
// FAIL-ON-REVERT: dropping a generator skip (interface-less group,
// subnet-less pool, duplicate masked prefix) from the assignment walk, or
// returning positional ids, makes the maps diverge from the rendered conf.
func TestSubnetIDAssignmentsMatchKeaRender_15694(t *testing.T) {
	cfg4 := multiGroupV4Config()
	// Skipped pools: interface-less group and subnet-less pool take no id.
	cfg4.DHCPLocalServer.Groups["noiface"] = &config.DHCPServerGroup{
		Name: "noiface",
		Pools: []*config.DHCPPool{
			{Name: "orphan", Subnet: "10.98.0.0/24", RangeLow: "10.98.0.10", RangeHigh: "10.98.0.20"},
		},
	}
	cfg4.DHCPLocalServer.Groups["alpha"].Pools = append(cfg4.DHCPLocalServer.Groups["alpha"].Pools,
		&config.DHCPPool{Name: "nosubnet"},
		&config.DHCPPool{Name: "dup", Subnet: dupSubnet15694(t, cfg4)},
	)

	m4, _ := testManager(t, map[string]bool{}, "")
	if err := m4.generateKea4Config(cfg4); err != nil {
		t.Fatalf("generateKea4Config: %v", err)
	}
	got4, _ := SubnetIDAssignments15694(cfg4)
	if want := subnetIDMap(t, m4.confPath4, "4"); !reflect.DeepEqual(got4, want) {
		t.Errorf("v4 SubnetIDAssignments15694 = %v, want Kea-rendered %v", got4, want)
	}

	cfg6 := multiGroupV6Config()
	m6, _ := testManager(t, map[string]bool{}, "")
	if err := m6.generateKea6Config(cfg6); err != nil {
		t.Fatalf("generateKea6Config: %v", err)
	}
	_, got6 := SubnetIDAssignments15694(cfg6)
	if want := subnetIDMap(t, m6.confPath6, "6"); !reflect.DeepEqual(got6, want) {
		t.Errorf("v6 SubnetIDAssignments15694 = %v, want Kea-rendered %v", got6, want)
	}

	if _, ok := got4["10.98.0.0/24"]; ok {
		t.Errorf("interface-less group's pool took a subnet id: %v", got4)
	}
}

// dupSubnet15694 returns a host-bit-set spelling of the first rendered v4
// subnet (e.g. 10.0.1.1/25 for 10.0.1.0/25), which masks to the same prefix
// and is therefore a #9785 duplicate that takes no subnet id.
func dupSubnet15694(t *testing.T, cfg *config.DHCPServerConfig) string {
	t.Helper()
	for _, group := range stableGroups(cfg.DHCPLocalServer.Groups) {
		for _, pool := range stablePools(group.Pools) {
			if pool.Subnet == "" {
				continue
			}
			p, err := netip.ParsePrefix(pool.Subnet)
			if err != nil {
				t.Fatalf("fixture subnet %q: %v", pool.Subnet, err)
			}
			return p.Masked().Addr().Next().String() + "/" + strconv.Itoa(p.Bits())
		}
	}
	t.Fatal("no rendered v4 subnet to duplicate")
	return ""
}
