package frr

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #15011 (A10-02): redistProtocolsFiltered added explicit `from protocol`
// tokens to its result unfiltered — no self drop, no
// redistSourceFitsNode check — while those filters applied only to the
// no-from expansion. redistributeEntriesAt filters explicit tokens at
// its own loop, but then merges redistProtocolsForNode whenever any
// term lacks `from protocol`, re-adding every explicit token the loop
// had dropped. A very common Junos BGP export shape — one
// `from protocol bgp` term plus a local route-filter (no-from) term —
// therefore rendered `redistribute bgp route-map EXP-bgp-xpf-redist`
// under `router bgp` (self-redistribution, FRR "No such command") and
// explicit IPv6 sources such as `ospf6` under the IPv4 `router bgp`
// node. One rejected line fails the whole managed frr-reload.
//
// Fix: redistProtocolsFiltered gates explicit tokens through the same
// self + redistSourceFitsNode filters as the no-from expansion
// whenever a render node is in hand; the node-less explicit-only set
// (redistProtocols, self/node "") is unchanged.
//
// FAIL-ON-REVERT: removing the self/family gate on the explicit-token
// loop in redistProtocolsFiltered re-adds bgp at the BGP node and
// ospf6 at the IPv4 node, and every cell below reds.

func mixedExplicitPO15011() *config.PolicyOptionsConfig {
	return &config.PolicyOptionsConfig{
		PolicyStatements: map[string]*config.PolicyStatement{
			"EXP": {
				Name: "EXP",
				Terms: []*config.PolicyTerm{
					{Name: "bgp-term", FromProtocols: []string{"bgp"}, Action: "accept"},
					{Name: "ospf6-term", FromProtocols: []string{"ospf6"}, Action: "accept"},
					{Name: "local-term", RouteFilters: []*config.RouteFilter{{Prefix: "10.0.0.0/8", MatchType: "exact"}}, Action: "accept"},
				},
			},
		},
	}
}

func mixedExplicitBGPFc15011(po *config.PolicyOptionsConfig) *FullConfig {
	return &FullConfig{
		PolicyOptions: po,
		BGP: &config.BGPConfig{
			LocalAS:  65001,
			RouterID: "1.1.1.1",
			Export:   []string{"EXP"},
			Neighbors: []*config.BGPNeighbor{
				{Address: "192.0.2.2", PeerAS: 65002, FamilyInet: true},
				{Address: "2001:db8::2", PeerAS: 65002, FamilyInet6: true},
			},
		},
	}
}

func contains15011(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

// TestRedistProtocolsForNodeFiltersExplicit15011 is the unit cell: at
// the BGP IPv4 node the explicit bgp (self) and ospf6 (off-family)
// tokens must not survive the merge with the no-from expansion; at
// the BGP IPv6 node ospf6 survives (it fits) but bgp still does not.
func TestRedistProtocolsForNodeFiltersExplicit15011(t *testing.T) {
	ps := mixedExplicitPO15011().PolicyStatements["EXP"]

	atBGP := redistProtocolsForNode(ps, "bgp", "bgp")
	for _, bad := range []string{"bgp", "ospf6", "ripng"} {
		if contains15011(atBGP, bad) {
			t.Errorf("redistProtocolsForNode(bgp,bgp) = %v, must not contain %q", atBGP, bad)
		}
	}
	// Legitimate node-fitting sources from the no-from expansion stay.
	for _, want := range []string{"connected", "ospf", "static"} {
		if !contains15011(atBGP, want) {
			t.Errorf("redistProtocolsForNode(bgp,bgp) = %v, must contain %q (no-from expansion control)", atBGP, want)
		}
	}

	atBGP6 := redistProtocolsForNode(ps, "bgp", "bgp-ipv6")
	if contains15011(atBGP6, "bgp") {
		t.Errorf("redistProtocolsForNode(bgp,bgp-ipv6) = %v, must not contain self %q", atBGP6, "bgp")
	}
	if !contains15011(atBGP6, "ospf6") {
		t.Errorf("redistProtocolsForNode(bgp,bgp-ipv6) = %v, must contain %q (explicit token fits the IPv6 node)", atBGP6, "ospf6")
	}
	for _, bad := range []string{"ospf", "rip"} {
		if contains15011(atBGP6, bad) {
			t.Errorf("redistProtocolsForNode(bgp,bgp-ipv6) = %v, must not contain IPv4-only %q", atBGP6, bad)
		}
	}

	// Node-less explicit-only set is unchanged: no render node is in
	// hand for map definitions / the collision guard, so both
	// explicit tokens remain (the maps they name are inert unless an
	// attachment at a fitting node references them).
	explicit := redistProtocols(ps)
	for _, want := range []string{"bgp", "ospf6"} {
		if !contains15011(explicit, want) {
			t.Errorf("redistProtocols (node-less) = %v, must still contain explicit %q", explicit, want)
		}
	}
}

// TestRedistributeEntriesMixedExplicit15011 is the entry-level cell:
// the merged protocols map in redistributeEntriesAt must carry the
// same filtering (this is the exact merge the issue cites).
func TestRedistributeEntriesMixedExplicit15011(t *testing.T) {
	m := New()
	po := mixedExplicitPO15011()

	for _, e := range m.redistributeEntriesAt("EXP", po, "bgp", "bgp") {
		if e.proto == "bgp" || e.proto == "ospf6" || e.proto == "ripng" {
			t.Errorf("redistributeEntriesAt(bgp,bgp) leaked %q: entry %+v", e.proto, e)
		}
	}
	found6 := false
	for _, e := range m.redistributeEntriesAt("EXP", po, "bgp", "bgp-ipv6") {
		if e.proto == "bgp" {
			t.Errorf("redistributeEntriesAt(bgp,bgp-ipv6) leaked self bgp: %+v", e)
		}
		if e.proto == "ospf6" {
			found6 = true
		}
	}
	if !found6 {
		t.Errorf("redistributeEntriesAt(bgp,bgp-ipv6) must keep fitting explicit ospf6")
	}
}

// TestBGPExportMixedExplicitNoSelfOrOffFamily15011 is the acceptance
// cell from the issue: the probe render contains no `redistribute bgp`
// under router bgp and no `ospf6` under IPv4, while legitimate
// filtered redistribution through the same policy stays.
func TestBGPExportMixedExplicitNoSelfOrOffFamily15011(t *testing.T) {
	m := New()
	got := m.buildManagedSection(mixedExplicitBGPFc15011(mixedExplicitPO15011()))

	if strings.Contains(got, "redistribute bgp") {
		t.Errorf("BGP must never redistribute itself (any node):\n%s", got)
	}
	top, af6 := bgpRedistLines14586(t, got)
	for _, l := range top {
		if strings.Contains(l, "ospf6") || strings.Contains(l, "ripng") {
			t.Errorf("off-family line under router bgp (IPv4): %q\n%s", l, got)
		}
	}
	// Controls: the no-from term still originates the node-fitting
	// domain through filtered maps at both nodes, and the fitting
	// explicit ospf6 source originates under the IPv6 AF.
	assertRedistSet14586(t, "router bgp", top, []string{
		" redistribute connected route-map EXP-connected-xpf-redist",
		" redistribute isis route-map EXP-isis-xpf-redist",
		" redistribute kernel route-map EXP-kernel-xpf-redist",
		" redistribute ospf route-map EXP-ospf-xpf-redist",
		" redistribute rip route-map EXP-rip-xpf-redist",
		" redistribute static route-map EXP-static-xpf-redist",
	})
	assertRedistSet14586(t, "address-family ipv6 unicast", af6, []string{
		"  redistribute connected route-map EXP-connected-xpf-redist",
		"  redistribute isis route-map EXP-isis-xpf-redist",
		"  redistribute kernel route-map EXP-kernel-xpf-redist",
		"  redistribute ospf6 route-map EXP-ospf6-xpf-redist",
		"  redistribute ripng route-map EXP-ripng-xpf-redist",
		"  redistribute static route-map EXP-static-xpf-redist",
	})
	// Every referenced map is defined.
	for _, proto := range []string{"connected", "isis", "kernel", "ospf", "ospf6", "rip", "ripng", "static"} {
		if !strings.Contains(got, "route-map EXP-"+proto+"-xpf-redist permit") {
			t.Errorf("route-map EXP-%s-xpf-redist not defined:\n%s", proto, got)
		}
	}
}

// TestOSPFExportMixedExplicitNoOffFamily15011 pins the same mechanism
// at an IGP node: an explicit ospf6 term plus a no-from term under
// `router ospf` (IPv4) must not render `redistribute ospf6`, and the
// explicit ospf term (self at this node) must not render either.
func TestOSPFExportMixedExplicitNoOffFamily15011(t *testing.T) {
	m := New()
	po := &config.PolicyOptionsConfig{
		PolicyStatements: map[string]*config.PolicyStatement{
			"EXP": {
				Name: "EXP",
				Terms: []*config.PolicyTerm{
					{Name: "ospf-term", FromProtocols: []string{"ospf"}, Action: "accept"},
					{Name: "ospf6-term", FromProtocols: []string{"ospf6"}, Action: "accept"},
					{Name: "local-term", RouteFilters: []*config.RouteFilter{{Prefix: "10.0.0.0/8", MatchType: "exact"}}, Action: "accept"},
				},
			},
		},
	}
	entries := m.redistributeEntriesAt("EXP", po, "ospf", "ospf")
	for _, e := range entries {
		if e.proto == "ospf" || e.proto == "ospf6" || e.proto == "ripng" {
			t.Errorf("redistributeEntriesAt(ospf,ospf) leaked %q: %+v", e.proto, e)
		}
	}
	// Control: fitting non-self sources from the no-from expansion stay.
	found := map[string]bool{}
	for _, e := range entries {
		found[e.proto] = true
	}
	for _, want := range []string{"connected", "static", "bgp"} {
		if !found[want] {
			t.Errorf("redistributeEntriesAt(ospf,ospf) = %v, must contain %q", entries, want)
		}
	}
	// Same policy at the OSPFv3 node: ospf6 is self there, ospf is
	// off-family; neither may leak, fitting sources stay.
	entries6 := m.redistributeEntriesAt("EXP", po, "ospf6", "ospf6")
	for _, e := range entries6 {
		if e.proto == "ospf6" || e.proto == "ospf" || e.proto == "rip" {
			t.Errorf("redistributeEntriesAt(ospf6,ospf6) leaked %q: %+v", e.proto, e)
		}
	}
}
