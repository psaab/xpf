package cmdtree

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestRequestDHCPRenewCompletionOffersResolvableNames15227 pins the
// A43-04 completion direction: `request dhcp renew <TAB>` offers the
// resolvable config-key unit spellings of DHCP units only — pre-fix it
// offered every bare interface name (including non-DHCP ones), whose
// renew then failed against the lease-keyed manager.
func TestRequestDHCPRenewCompletionOffersResolvableNames15227(t *testing.T) {
	cfg := &config.Config{Interfaces: config.InterfacesConfig{Interfaces: map[string]*config.InterfaceConfig{
		"ge-0/0/0": {Name: "ge-0/0/0", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, DHCP: true},
		}},
		"ge-0/0/3": {Name: "ge-0/0/3", Units: map[int]*config.InterfaceUnit{
			7: {Number: 7, VlanID: 50, DHCPv6: true},
		}},
		"ge-0/0/1": {Name: "ge-0/0/1", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0},
		}},
	}}}
	cands := CompleteFromTree(OperationalTree, []string{"request", "dhcp", "renew"}, "", cfg)
	got := map[string]bool{}
	for _, c := range cands {
		got[c] = true
	}
	for _, want := range []string{"ge-0/0/0.0", "ge-0/0/3.7"} {
		if !got[want] {
			t.Errorf("renew completion missing %q (got %v)", want, cands)
		}
	}
	for _, unwanted := range []string{"ge-0/0/0", "ge-0/0/1", "ge-0/0/1.0", "ge-0-0-3.50"} {
		if got[unwanted] {
			t.Errorf("renew completion offers unresolvable/non-DHCP name %q (got %v)", unwanted, cands)
		}
	}
}
