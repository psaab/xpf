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

// TestClearDHCPClientIdentifierCompletion15756 pins #15756: `clear dhcp
// client-identifier interface <TAB>` offers the resolvable config-key unit
// spellings (pre-fix the tree had no interface node at all, so no name
// completion existed), and the dangling `interface` keyword does not
// canonicalize (the handler rejects it before any mutation).
func TestClearDHCPClientIdentifierCompletion15756(t *testing.T) {
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
	cands := CompleteFromTree(OperationalTree, []string{"clear", "dhcp", "client-identifier", "interface"}, "", cfg)
	got := map[string]bool{}
	for _, cand := range cands {
		got[cand] = true
	}
	for _, want := range []string{"ge-0/0/0.0", "ge-0/0/3.7"} {
		if !got[want] {
			t.Errorf("clear completion missing %q (got %v)", want, cands)
		}
	}
	for _, unwanted := range []string{"ge-0/0/1.0", "ge-0-0-3.50"} {
		if got[unwanted] {
			t.Errorf("clear completion offers unresolvable/non-DHCP name %q (got %v)", unwanted, cands)
		}
	}
	if _, res := Canonicalize(OperationalTree, []string{"clear", "dhcp", "client-identifier", "interface"}); res == CanonicalOK {
		t.Error("dangling `clear dhcp client-identifier interface` canonicalized OK, want refusal")
	}
	if _, res := Canonicalize(OperationalTree, []string{"clear", "dhcp", "client-identifier", "interface", "ge-0/0/0"}); res != CanonicalOK {
		t.Errorf("scoped clear canonicalize = %v, want CanonicalOK", res)
	}
	if _, res := Canonicalize(OperationalTree, []string{"clear", "dhcp", "client-identifier"}); res != CanonicalOK {
		t.Errorf("bare clear-all canonicalize = %v, want CanonicalOK", res)
	}
}
