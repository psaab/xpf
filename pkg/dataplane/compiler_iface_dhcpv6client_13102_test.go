package dataplane

import (
	"net"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #13102 (D4-07): a unit with only DHCPv6Client != nil (DHCPv6 == false)
// is a valid state reachable from synthesized/hand-built configs and
// from any producer that does not dual-write the bool. Its leased
// addresses must be protected exactly like the legacy DHCPv6 bool:
// planPhysDesired must skip reconciliation and networkd models must
// carry DHCPv6=true, otherwise reconcile deletes the live lease.

func dhcpv6ClientOnlyCfg13102() *config.Config {
	return &config.Config{
		Interfaces: config.InterfacesConfig{
			Interfaces: map[string]*config.InterfaceConfig{
				"ge-0/0/0": {Name: "ge-0/0/0", Units: map[int]*config.InterfaceUnit{
					0: {Number: 0, DHCPv6: true},
				}},
				"ge-0/0/1": {Name: "ge-0/0/1", Units: map[int]*config.InterfaceUnit{
					0: {Number: 0, DHCPv6Client: &config.DHCPv6ClientConfig{ClientType: "stateful"}},
				}},
				"st0": {Name: "st0", Units: map[int]*config.InterfaceUnit{
					0: {Number: 0, DHCPv6Client: &config.DHCPv6ClientConfig{ClientType: "stateful"}},
				}},
				"ge-0/0/2": {Name: "ge-0/0/2", VlanTagging: true, Units: map[int]*config.InterfaceUnit{
					0: {Number: 0, VlanID: 100, DHCPv6Client: &config.DHCPv6ClientConfig{ClientType: "stateful"}},
				}},
			},
		},
		Security: config.SecurityConfig{Zones: map[string]*config.ZoneConfig{
			"untrust": {Name: "untrust", Interfaces: []string{"ge-0/0/0.0", "ge-0/0/1.0"}},
		}},
	}
}

func TestDHCPv6ClientOnlyPreservesLease13102(t *testing.T) {
	cfg := dhcpv6ClientOnlyCfg13102()

	plan := planPhysDesired(cfg)
	for _, name := range []string{"ge-0-0-0", "ge-0-0-1"} {
		pd := plan[name]
		if pd == nil {
			t.Fatalf("no plan entry for %s", name)
		}
		if !pd.skipAddrs {
			t.Errorf("%s: skipAddrs=false; DHCPv6-client lease would be deleted by reconcileInterfaceAddresses", name)
		}
	}

	mac, _ := net.ParseMAC("02:00:5e:10:00:01")
	res := &CompileResult{ifCache: map[string]*net.Interface{
		"ge-0-0-0": {Index: 10, Name: "ge-0-0-0", HardwareAddr: mac},
		"ge-0-0-1": {Index: 11, Name: "ge-0-0-1", HardwareAddr: mac},
		"ge-0-0-2": {Index: 12, Name: "ge-0-0-2", HardwareAddr: mac},
	}}
	buildInterfaceNetworkdModels(cfg, res, make(map[string]bool))
	want := map[string]bool{"ge-0-0-0": true, "ge-0-0-1": true, "ge-0-0-2.100": true}
	for _, mi := range res.ManagedInterfaces {
		if _, ok := want[mi.Name]; ok {
			if !mi.DHCPv6 {
				t.Errorf("ManagedInterfaces[%s].DHCPv6=false; want true for DHCPv6-client unit", mi.Name)
			}
			delete(want, mi.Name)
		}
	}
	for name := range want {
		t.Errorf("no ManagedInterfaces entry for %s", name)
	}

}
