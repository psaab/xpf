package config

import (
	"strings"
	"testing"
)

// #15184 (C04-02): `protocols bgp [group G] neighbor <x>` (including under
// routing-instances) accepted any single token. 10.0.0.256, 192.0.2.0/24,
// peer-a and fe80::1%ge-0-0-1 passed CommitCheck and rendered verbatim;
// bgpd refuses them, so frr-reload exits 1 on every reload.
//
// Fix direction: require netip.ParseAddr with no zone and no prefix.
// Scoped link-local gets an explicit "unsupported" message.
//
// FAIL-ON-REVERT: revert ValidateBGPNeighborAddress / keyValidator /
// validateBGPNeighborAddressStrict IP check -> bad shapes commit clean.

var badNeighborAddrs15184 = []string{
	"10.0.0.256",
	"192.0.2.0/24",
	"peer-a",
	"peer.example.com",
	"fe80::1%ge-0-0-1",
	"fe80::1%eth0",
	"2001:db8::1/64",
	"not-an-ip",
}

var goodNeighborAddrs15184 = []string{
	"192.0.2.1",
	"2001:db8::1",
	"10.0.0.2",
	"2001:db8::2",
	"fe80::1",
}

func TestBGPNeighborAddressValidator15184(t *testing.T) {
	for _, bad := range badNeighborAddrs15184 {
		if err := ValidateBGPNeighborAddress(bad, nil); err == nil {
			t.Errorf("ValidateBGPNeighborAddress(%q) = nil, want rejection", bad)
		}
	}
	for _, good := range goodNeighborAddrs15184 {
		if err := ValidateBGPNeighborAddress(good, nil); err != nil {
			t.Errorf("ValidateBGPNeighborAddress(%q) = %v, want nil (control)", good, err)
		}
	}
	// Scoped link-local must say unsupported.
	err := ValidateBGPNeighborAddress("fe80::1%ge-0-0-1", nil)
	if err == nil || !strings.Contains(err.Error(), "unsupported") {
		t.Errorf("scoped link-local error must mention unsupported, got %v", err)
	}
}

func TestBGPNeighborAddressSchemaGate15184(t *testing.T) {
	for _, bad := range badNeighborAddrs15184 {
		for _, sets := range [][]string{
			{"set protocols bgp local-as 65001", "set protocols bgp group G peer-as 65002", "set protocols bgp group G neighbor " + bad},
			{"set routing-instances VR1 instance-type virtual-router", "set routing-instances VR1 protocols bgp local-as 65001", "set routing-instances VR1 protocols bgp group G peer-as 65002", "set routing-instances VR1 protocols bgp group G neighbor " + bad},
		} {
			// Zone contains % which is fine as a set token.
			tree := flatTreeFromSets(t, sets...)
			if err := SchemaValidate(tree, nil); err == nil {
				t.Errorf("SchemaValidate accepted bad neighbor %q in %v", bad, sets)
			}
		}
	}
	for _, good := range goodNeighborAddrs15184 {
		for _, sets := range [][]string{
			{"set protocols bgp local-as 65001", "set protocols bgp group G peer-as 65002", "set protocols bgp group G neighbor " + good},
			{"set routing-instances VR1 instance-type virtual-router", "set routing-instances VR1 protocols bgp local-as 65001", "set routing-instances VR1 protocols bgp group G peer-as 65002", "set routing-instances VR1 protocols bgp group G neighbor " + good},
		} {
			tree := flatTreeFromSets(t, sets...)
			if err := SchemaValidate(tree, nil); err != nil {
				t.Errorf("SchemaValidate rejected good neighbor %q in %v: %v", good, sets, err)
			}
		}
	}
}

func TestBGPNeighborAddressStrictGate15184(t *testing.T) {
	for _, bad := range badNeighborAddrs15184 {
		cfg := bgpNeighborConfig6796(bad)
		cfg.Protocols.BGP.Neighbors[0].GroupName = "G"
		if err := validateBGPNeighborAddressStrict(cfg); err == nil {
			t.Errorf("validateBGPNeighborAddressStrict accepted %q", bad)
		}
		// routing-instance leg
		cfg2 := &Config{}
		cfg2.RoutingInstances = []*RoutingInstanceConfig{{Name: "VR1", BGP: &BGPConfig{LocalAS: 65001, Neighbors: []*BGPNeighbor{{Address: bad, PeerAS: 65002, GroupName: "G"}}}}}
		if err := validateBGPNeighborAddressStrict(cfg2); err == nil {
			t.Errorf("validateBGPNeighborAddressStrict (RI) accepted %q", bad)
		}
	}
	for _, good := range goodNeighborAddrs15184 {
		if err := validateBGPNeighborAddressStrict(bgpNeighborConfig6796(good)); err != nil {
			t.Errorf("validateBGPNeighborAddressStrict rejected good %q: %v", good, err)
		}
	}
	// Scoped message via strict gate too
	err := validateBGPNeighborAddressStrict(bgpNeighborConfig6796("fe80::1%ge-0-0-1"))
	if err == nil || !strings.Contains(err.Error(), "unsupported") {
		t.Errorf("strict scoped error must mention unsupported, got %v", err)
	}
}

func TestBGPNeighborAddressStoreProbe15184(t *testing.T) {
	// Store probe: CompileConfig (strict) must reject bad, accept good.
	for _, bad := range badNeighborAddrs15184 {
		tree := buildTreeFromSet(t, []string{
			"set protocols bgp local-as 65001",
			"set protocols bgp group G peer-as 65002",
			"set protocols bgp group G neighbor " + bad,
		})
		if _, err := CompileConfig(tree); err == nil {
			t.Errorf("CompileConfig accepted bad neighbor %q", bad)
		}
	}
	for _, good := range goodNeighborAddrs15184 {
		tree := buildTreeFromSet(t, []string{
			"set protocols bgp local-as 65001",
			"set protocols bgp group G peer-as 65002",
			"set protocols bgp group G neighbor " + good,
		})
		if _, err := CompileConfig(tree); err != nil {
			t.Errorf("CompileConfig rejected good neighbor %q: %v", good, err)
		}
	}
}

func TestBGPNeighborAddressLenientWarns15184(t *testing.T) {
	tree := buildTreeFromSet(t, []string{
		"set protocols bgp local-as 65001",
		"set protocols bgp group G peer-as 65002",
		"set protocols bgp group G neighbor peer-a",
	})
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile must not fail (#1960): %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "neighbor") {
			found = true
		}
	}
	if !found {
		t.Errorf("lenient compile must warn about bad neighbor, warnings=%v", cfg.Warnings)
	}
}
