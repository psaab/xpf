package frr

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #15159 (B08-05): a bare protocol token is a redistribute verb ONLY in the
// global `protocols bgp export` list, where protocols_render.go renders it
// from bgp.Export on the router-global redistribute path. At group/neighbour
// scope the same token renders as a route-map name and resolves to nothing:
// the strict commit path rejects it for exactly that reason
// (config.TestBGPNeighborExportProtocolTokenRejected), so it reaches the
// renderer only on the tolerant load / peer-sync / rollback path.
//
// Before the fix, chainEmptiedByUndefinedPolicies applied the redistribute
// exclusion to EVERY export scope, so a neighbour whose own export was
// [static] was treated as "operator asked for redistribution" and attached
// NO route-map out at all. That one own entry also suppresses the global
// export chain (most-specific-wins), so the peer ended up with no outbound
// filter AND no neighbour-scoped redistribution — a full-table fail-open to
// that peer (an absent attachment permits in FRR, #7625/#14584).

// THE FIX (emptied, neighbour scope). .3's own export is a lone protocol
// token: it is a ghost at neighbour scope and must attach the emptied-chain
// deny. Controls in the same fixture: .4 inherits the global export and
// keeps the global policy, .5's neighbour export names a defined policy and
// is unchanged, and the global bare token still renders its router-global
// `redistribute static`.
func TestNeighborProtocolTokenExportDenies15159(t *testing.T) {
	po := policyOptions7625("REAL")
	fc := &FullConfig{
		PolicyOptions: po,
		BGP: &config.BGPConfig{
			LocalAS: 65001, RouterID: "1.1.1.1",
			Export: []string{"static", "REAL"},
			Neighbors: []*config.BGPNeighbor{
				{Address: "10.0.2.3", PeerAS: 65004, FamilyInet: true, Export: []string{"static"}},
				{Address: "10.0.2.4", PeerAS: 65005, FamilyInet: true},
				{Address: "10.0.2.5", PeerAS: 65006, FamilyInet: true, Export: []string{"REAL"}},
			},
		},
	}
	section := New().buildManagedSection(fc)

	// .3: the neighbour-level token must not escape the #7625 deny.
	refs := neighborRouteMapRefs7625(section, "10.0.2.3", "out")
	if len(refs) != 1 || refs[0] != emptiedChainDenyName {
		t.Fatalf("neighbour-level protocol token in export must attach the emptied-chain deny "+
			"%q, got refs %v (no attachment is the PERMIT-ALL shape):\n%s", emptiedChainDenyName, refs, section)
	}
	if defined, allDeny := routeMapIsDeny7625(section, refs[0]); !defined || !allDeny {
		t.Errorf("route-map %q must be defined and an unconditional deny (defined=%v allDeny=%v):\n%s",
			refs[0], defined, allDeny, section)
	}
	if d := danglingRouteMapRefs6807(section); len(d) != 0 {
		t.Errorf("fix left dangling route-map refs %v", d)
	}

	// .4: no own export — inherits the global export chain (REAL) unchanged.
	if refs := neighborRouteMapRefs7625(section, "10.0.2.4", "out"); len(refs) != 1 || refs[0] != "REAL" {
		t.Errorf("neighbour inheriting the global export must reference REAL, got %v:\n%s", refs, section)
	}
	// .5: own export naming a defined policy is unchanged.
	if refs := neighborRouteMapRefs7625(section, "10.0.2.5", "out"); len(refs) != 1 || refs[0] != "REAL" {
		t.Errorf("neighbour with a defined export policy must reference REAL, got %v:\n%s", refs, section)
	}
	// The GLOBAL bare token keeps its router-global redistribute rendering.
	if !strings.Contains(section, " redistribute static\n") && !strings.Contains(section, "  redistribute static\n") {
		t.Errorf("global `export static` must still render `redistribute static`:\n%s", section)
	}
}

// The Junos spelling: `direct` normalises to `connected` for redistribution
// at global scope, which is why the pre-fix exclusion also recognised it at
// neighbour scope. At neighbour scope it is the same ghost.
func TestNeighborDirectTokenExportDenies15159(t *testing.T) {
	po := policyOptions7625("REAL")
	fc := &FullConfig{
		PolicyOptions: po,
		BGP: &config.BGPConfig{
			LocalAS: 65001, RouterID: "1.1.1.1",
			Neighbors: []*config.BGPNeighbor{
				{Address: "10.0.2.3", PeerAS: 65004, FamilyInet: true, Export: []string{"direct"}},
			},
		},
	}
	section := New().buildManagedSection(fc)
	refs := neighborRouteMapRefs7625(section, "10.0.2.3", "out")
	if len(refs) != 1 || refs[0] != emptiedChainDenyName {
		t.Fatalf("neighbour-level `direct` in export must attach the emptied-chain deny %q, got %v:\n%s",
			emptiedChainDenyName, refs, section)
	}
}

// NARROWED, neighbour scope. [REAL, static] at a neighbour: the token is a
// ghost ordered AFTER the survivor, so the chain is suffix-narrowed and the
// production narrowed handling (deny-terminated alias or the apply belt)
// must see it — before the fix the token was excluded as a redistribute
// verb and the site was invisible, leaving REAL's BGP-default permit
// fall-off in place.
func TestNeighborProtocolTokenNarrowedIsSeen15159(t *testing.T) {
	po := policyOptions7625("REAL")
	bgp := &config.BGPConfig{
		LocalAS: 65001, RouterID: "1.1.1.1",
		Neighbors: []*config.BGPNeighbor{
			{Address: "10.0.2.3", PeerAS: 65004, FamilyInet: true, Export: []string{"REAL", "static"}},
		},
	}
	sites := narrowedChainSites(bgp, po)
	if len(sites) != 1 {
		t.Fatalf("neighbour export [REAL static] must be one narrowed site, got %+v", sites)
	}
	if sites[0].Where != "neighbor 10.0.2.3 export" || !sites[0].GhostsAreSuffix ||
		len(sites[0].Dropped) != 1 || sites[0].Dropped[0] != "static" {
		t.Errorf("narrowed site must name the neighbour token as a suffix ghost: %+v", sites[0])
	}
}

// CONTROL: the same [REAL, static] shape INHERITED from the global export
// list is not narrowing at all — there the token is a genuine redistribute
// verb rendered from bgp.Export, and REAL is the intact global chain.
func TestGlobalProtocolTokenNarrowedControl15159(t *testing.T) {
	po := policyOptions7625("REAL")
	bgp := &config.BGPConfig{
		LocalAS: 65001, RouterID: "1.1.1.1",
		Export: []string{"REAL", "static"},
		Neighbors: []*config.BGPNeighbor{
			{Address: "10.0.2.4", PeerAS: 65005, FamilyInet: true},
		},
	}
	if sites := narrowedChainSites(bgp, po); len(sites) != 0 {
		t.Errorf("global [REAL static] inherited by a neighbour must not narrow, got %+v", sites)
	}
	section := New().buildManagedSection(&FullConfig{PolicyOptions: po, BGP: bgp})
	if refs := neighborRouteMapRefs7625(section, "10.0.2.4", "out"); len(refs) != 1 || refs[0] != "REAL" {
		t.Errorf("neighbour inheriting global [REAL static] must reference REAL, got %v:\n%s", refs, section)
	}
}
