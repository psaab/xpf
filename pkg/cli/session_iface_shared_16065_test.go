package cli

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
)

// session_iface_shared_16065_test.go — #16065 (SI-6) decisive check on
// the CLI surface (the same sessionFilter backs show AND clear):
// two WireGuard units share the one wg0 TUN, so their sessions share
// {ifindex 20, VID 0}. A filter naming wg0.1 must NOT select a session
// that arrived on wg0.0, and vice versa — pre-fix both units keyed to
// the one surviving name and clear-by-interface deleted the sibling.
//
// The zone arm is the honest fallback the refused key leaves behind:
// both units sit in the SAME zone here only on the wg0 unit rows
// themselves; the filter's zone lists are set so the precise arm is
// the only path that could name a wg unit (the zone binds a third,
// unrelated interface). Corroboration (#6987) therefore cannot supply
// the match either — a wg filter can reach these rows only if the
// name table wrongly names the shared device.

func wgSharedFilter16065(t *testing.T, iface string) *sessionFilter {
	t.Helper()
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
			},
		},
	}
	lookup := func(name string) (int, error) {
		if name == "wg0" {
			return 20, nil
		}
		t.Fatalf("unexpected lookup %q", name)
		return 0, nil
	}
	names := buildSessionEgressIfacesWithLookup(cfg, lookup)
	if name, ok := names[sessionIfaceKey{Ifindex: 20, VlanID: 0}]; ok {
		t.Fatalf("premise: shared wg key named %q; the table must refuse it (#16065)", name)
	}
	return &sessionFilter{
		iface: iface,
		// The ingress zone binds an unrelated interface only, so the
		// zone fallback cannot name either wg unit.
		zoneIfaces:      map[uint16][]string{1: {"ge-0/0/9.0"}},
		ifaceNamesByKey: names,
	}
}

func TestClearWgSiblingCannotDeleteOtherUnit16065(t *testing.T) {
	key := dataplane.SessionKey{Protocol: 6}
	// A session on the shared TUN: {20, 0} is all the identity it has.
	val := dataplane.SessionValue{IngressZone: 1, EgressZone: 1, IngressIfindex: 20, IngressVlanID: 0}

	for _, iface := range []string{"wg0.0", "wg0.1", "wg0"} {
		if f := wgSharedFilter16065(t, iface); f.matchesV4(key, val) {
			t.Errorf("filter %q selected a session on the shared wg TUN: with no per-unit "+
				"identity on the row, naming either sibling selects BOTH — clear %q would "+
				"delete the other unit's sessions (#16065)", iface, iface)
		}
	}
	// The unrelated zone member still matches through the zone arm, so
	// the refusal narrowed the filter rather than breaking it.
	if f := wgSharedFilter16065(t, "ge-0/0/9.0"); !f.matchesV4(key, val) {
		t.Error("zone-member filter ge-0/0/9.0 must still match via the zone fallback")
	}
}

func TestWgSharedDisplayNamesNeitherSibling16065(t *testing.T) {
	f := wgSharedFilter16065(t, "wg0.1")
	// Display is stricter than filtering: no name is printed for the
	// shared device, and the zone has one (unrelated) member, but the
	// row HAS an identity that the table refuses — soleZoneIface is
	// only for rows with no identity, and ingressIfaceDisplay returns
	// "" for a refused (absent) name with a non-single zone... the wg
	// zone here is single-member by construction of zoneIfaces[1], so
	// pin the resolver-level fact instead: no precise name exists.
	if name, ok := f.ingressIfaceIdentity(20, 0, 1); ok || name != "" {
		t.Errorf("ingressIfaceIdentity(20,0) = %q,%v — the shared TUN must name neither sibling", name, ok)
	}
	if got := f.resolveIngressIfaces(20, 0, 1); len(got) != 1 || got[0] != "ge-0/0/9.0" {
		t.Errorf("resolveIngressIfaces = %v, want the zone fallback [ge-0/0/9.0], not a wg sibling", got)
	}
}
