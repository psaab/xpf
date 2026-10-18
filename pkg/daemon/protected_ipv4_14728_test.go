package daemon

import (
	"net/netip"
	"sort"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dhcp"
)

// #14728 leg A wiring: reconcileDHCPClients installs ConfiguredIPv4Prefixes
// on the manager before reconcile; an empty config clears it.
func TestReconcileInstallsProtectedIPv4Set14728(t *testing.T) {
	mgr := dhcp.NewManagerForTesting(nil)
	d := &Daemon{dhcp: mgr}
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"ge-0/0/0": {Name: "ge-0/0/0", Units: map[int]*config.InterfaceUnit{
			0: {Addresses: []string{"10.0.1.1/24", "2606:4700:1111::1/64"}},
		}},
		"ge-0/0/1": {Name: "ge-0/0/1", Units: map[int]*config.InterfaceUnit{
			0: {Addresses: []string{"192.168.5.1/28"}},
		}},
	}
	d.reconcileDHCPClients(cfg)
	got := mgr.ProtectedIPv4PrefixesForTesting()
	want := []netip.Prefix{
		netip.MustParsePrefix("10.0.1.0/24"),
		netip.MustParsePrefix("192.168.5.0/28"),
	}
	sort.Slice(got, func(i, j int) bool { return got[i].String() < got[j].String() })
	sort.Slice(want, func(i, j int) bool { return want[i].String() < want[j].String() })
	if len(got) != len(want) {
		t.Fatalf("protected v4 set = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("protected v4 set = %v, want %v", got, want)
		}
	}
	d.reconcileDHCPClients(&config.Config{})
	if got := mgr.ProtectedIPv4PrefixesForTesting(); len(got) != 0 {
		t.Fatalf("protected v4 set after empty config = %v, want empty", got)
	}
}
