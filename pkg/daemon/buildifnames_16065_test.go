package daemon

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// buildifnames_16065_test.go — #16065 (SI-6) flow-export leg:
// buildIfNames used sorted first-wins over a bare ifindex map, so
// wg0.0/wg0.1 on the one TUN named every record on that device after
// the first-visited sibling and flow-export sampling judged both
// units by that name. Through config.SessionIfNamesByIfindex the
// shared ifindex is REFUSED (no name), while a VLAN child keeps its
// own ifindex and name.
//
// FAIL-ON-REVERT: restoring first-wins (or the old buildIfNames body)
// names ifindex 20 below and fails the first assertion.

func TestBuildIfNamesRefusesSharedWireGuard16065(t *testing.T) {
	cfg := &config.Config{
		Interfaces: config.InterfacesConfig{
			Interfaces: map[string]*config.InterfaceConfig{
				"wg0": {
					Name:   "wg0",
					Tunnel: &config.TunnelConfig{Mode: "wireguard", Name: "wg0"},
					Units: map[int]*config.InterfaceUnit{
						0: {Number: 0},
						1: {Number: 1},
					},
				},
				"ge-0/0/3": {
					Name: "ge-0/0/3",
					Units: map[int]*config.InterfaceUnit{
						80: {Number: 80, VlanID: 80},
					},
				},
			},
		},
	}
	lookup := func(name string) (int, error) {
		switch name {
		case "wg0":
			return 20, nil
		case "ge-0-0-3":
			return 14, nil
		case "ge-0-0-3.80":
			return 16, nil
		}
		t.Fatalf("unexpected lookup %q", name)
		return 0, nil
	}

	names := buildIfNamesWithLookup(cfg, lookup)
	if name, ok := names[20]; ok {
		t.Fatalf("shared TUN ifindex 20 named %q — flow export would attribute both "+
			"wg units' records to one sibling (#16065)", name)
	}
	// The parent ifindex has exactly ONE unit name across all its keys
	// (only .80 exists in this fixture), so the bare projection names
	// it after that unit — agreed, not a sibling pick. (With .50 also
	// present it would be refused; see pkg/config C5 test.)
	if name := names[14]; name != "ge-0/0/3.80" {
		t.Fatalf("parent ifindex 14 = %q, want ge-0/0/3.80 (sole claimant)", name)
	}
	if name := names[16]; name != "ge-0/0/3.80" {
		t.Fatalf("VLAN child ifindex 16 = %q, want ge-0/0/3.80 (child-keyed)", name)
	}
}
