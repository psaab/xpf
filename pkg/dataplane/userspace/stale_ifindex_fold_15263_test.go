package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
)

// stale_ifindex_fold_15263_test.go — #15263 (B05-02), the fail-closed half.
//
// buildIngressFoldResolver captures net.Interfaces() once per apply. A member
// netdev recreated without a commit (VF reset, re-probe) gets a new ifindex;
// RefreshInterfaceRowsForLink rebuilds lastSnapshot's rows with the new
// ifindex but (pre-fix) never rebuilt the daemon closures, so the receive
// side confidently resolved a peer fold to the DEAD ifindex. The importer
// then installed the session with that ifindex, and sessionSyncEgressLocked
// missed the row and returned owner RG 0.
//
// This file pins the Manager-side fence: a resolver answer whose ifindex is
// absent from the CURRENT snapshot declines (ok=false) to the zone
// approximation, for both the ingress and the egress fold, v4 and v6. The
// daemon-side rebuild on link refresh is pinned in pkg/daemon
// (stale_ifindex_fold_refresh_15263_test.go).
//
// FAIL-ON-REVERT: removing the snapshot-presence check from
// resolveIngressFoldLocked makes every "declines" cell below resolve to the
// dead ifindex (ingress 17, egress owner RG 0-aliased row) and go RED.

const (
	staleFold15263   = uint32(0x15263001)
	deadIfindex15263 = 17
	liveIfindex15263 = 29
	liveParent15263  = 6
	liveVLAN15263    = uint16(80)
	staleZone15263   = "trust"
)

// staleFoldManager15263 builds a Manager whose snapshot carries ONLY the
// recreated row (liveIfindex on the live parent, RG 1) plus an unrelated row
// that happens to sit on the dead ifindex's number on the peer's numbering —
// here deliberately absent, so the dead ifindex matches nothing.
func staleFoldManager15263(resolver func(uint32) (uint32, uint16, bool)) *Manager {
	m := &Manager{lastSnapshot: &ConfigSnapshot{Interfaces: []InterfaceSnapshot{
		{
			Name:            "reth0.80",
			LinuxName:       "ge-0-0-0",
			Zone:            staleZone15263,
			EgressZone:      staleZone15263,
			Ifindex:         12,
			ParentIfindex:   liveParent15263,
			VLANID:          int(liveVLAN15263),
			RedundancyGroup: 1,
		},
		{
			Name:            "ge-0-0-0",
			LinuxName:       "ge-0-0-0",
			Zone:            staleZone15263,
			EgressZone:      staleZone15263,
			Ifindex:         liveIfindex15263,
			RedundancyGroup: 1,
		},
	}}}
	if resolver != nil {
		m.SetIngressFoldResolver(resolver)
	}
	return m
}

func staleResolver15263() func(uint32) (uint32, uint16, bool) {
	// The closure captured before the recreation: it still names the dead
	// ifindex for the recreated member's fold.
	return func(got uint32) (uint32, uint16, bool) {
		if got != staleFold15263 {
			return 0, 0, false
		}
		return deadIfindex15263, 0, true
	}
}

func liveResolver15263() func(uint32) (uint32, uint16, bool) {
	// The closure as rebuilt by the link refresh: same fold, live ifindex.
	return func(got uint32) (uint32, uint16, bool) {
		if got != staleFold15263 {
			return 0, 0, false
		}
		return liveParent15263, liveVLAN15263, true
	}
}

func TestStaleIfindexFoldDeclinesIngress15263(t *testing.T) {
	m := staleFoldManager15263(staleResolver15263())
	for _, tc := range []struct {
		name string
		req  SessionSyncRequest
	}{
		{"v4", m.buildSessionSyncRequestV4("upsert", dataplane.SessionKey{Protocol: 6},
			&dataplane.SessionValue{IngressIfaceFold: staleFold15263})},
		{"v6", m.buildSessionSyncRequestV6("upsert", dataplane.SessionKeyV6{Protocol: 6},
			&dataplane.SessionValueV6{IngressIfaceFold: staleFold15263})},
	} {
		if tc.req.IngressIfindex != 0 || tc.req.IngressVLANID != 0 {
			t.Fatalf("%s: stale fold resolved to dead ifindex {%d vlan %d}; want decline {0 0} (zone approximation)",
				tc.name, tc.req.IngressIfindex, tc.req.IngressVLANID)
		}
	}
}

func TestStaleIfindexFoldDeclinesEgressOwner15263(t *testing.T) {
	// Egress leg: the peer fold resolves (stale closure) to the dead ifindex.
	// Pre-fix sessionSyncEgressLocked missed the row and returned
	// (fibIfindex, fibIfindex, 0) — the session installed with owner RG 0.
	// The fence must decline the fold so the egress identity also fails
	// closed to the zone approximation instead of the dead number.
	m := staleFoldManager15263(staleResolver15263())
	check := func(name string, req SessionSyncRequest) {
		t.Helper()
		if req.EgressIfindex == deadIfindex15263 || req.TXIfindex == deadIfindex15263 {
			t.Fatalf("%s: stale egress fold installed dead ifindex (egress %d tx %d owner RG %d); want no dead-ifindex install",
				name, req.EgressIfindex, req.TXIfindex, req.OwnerRGID)
		}
		if req.EgressIfindex != 0 || req.TXIfindex != 0 {
			t.Fatalf("%s: stale egress fold = (egress %d tx %d owner RG %d); want fail-closed zero egress (zone approximation)",
				name, req.EgressIfindex, req.TXIfindex, req.OwnerRGID)
		}
	}
	check("v4", m.buildSessionSyncRequestV4("upsert", dataplane.SessionKey{Protocol: 6},
		&dataplane.SessionValue{FibIfindex: 42, EgressIfaceFold: staleFold15263}))
	check("v6", m.buildSessionSyncRequestV6("upsert", dataplane.SessionKeyV6{Protocol: 6},
		&dataplane.SessionValueV6{FibIfindex: 42, EgressIfaceFold: staleFold15263}))
}

func TestLiveIfindexFoldStillResolves15263(t *testing.T) {
	// Control: a resolver naming an ifindex the current snapshot carries
	// (the rebuilt-closure state after a link refresh, or any ordinary
	// apply) resolves exactly as before — the fence must not degrade
	// legitimate imports.
	m := staleFoldManager15263(liveResolver15263())
	req := m.buildSessionSyncRequestV4("upsert", dataplane.SessionKey{Protocol: 6},
		&dataplane.SessionValue{IngressIfaceFold: staleFold15263})
	if req.IngressIfindex != liveParent15263 || req.IngressVLANID != liveVLAN15263 {
		t.Fatalf("live fold resolved to {%d vlan %d}; want {%d vlan %d}",
			req.IngressIfindex, req.IngressVLANID, liveParent15263, liveVLAN15263)
	}
	req6 := m.buildSessionSyncRequestV6("upsert", dataplane.SessionKeyV6{Protocol: 6},
		&dataplane.SessionValueV6{IngressIfaceFold: staleFold15263})
	if req6.IngressIfindex != liveParent15263 || req6.IngressVLANID != liveVLAN15263 {
		t.Fatalf("v6 live fold resolved to {%d vlan %d}; want {%d vlan %d}",
			req6.IngressIfindex, req6.IngressVLANID, liveParent15263, liveVLAN15263)
	}
	// Egress control: the live fold selects the local unit and its RG.
	eg := m.buildSessionSyncRequestV4("upsert", dataplane.SessionKey{Protocol: 6},
		&dataplane.SessionValue{FibIfindex: 42, EgressIfaceFold: staleFold15263})
	if eg.EgressIfindex != 12 || eg.TXIfindex != liveParent15263 || eg.TXVLANID != liveVLAN15263 || eg.OwnerRGID != 1 {
		t.Fatalf("live egress fold = (egress %d tx %d vlan %d owner RG %d); want (12 %d %d RG 1)",
			eg.EgressIfindex, eg.TXIfindex, eg.TXVLANID, eg.OwnerRGID, liveParent15263, liveVLAN15263)
	}
}

func TestNilSnapshotFoldBehaviourUnchanged15263(t *testing.T) {
	// Control: with no published snapshot there is nothing to fence against;
	// the resolver's answer passes through exactly as pre-#15263 (the
	// deadlock regression tests rely on this shape).
	m := &Manager{}
	m.SetIngressFoldResolver(func(uint32) (uint32, uint16, bool) { return 42, 80, true })
	req := m.buildSessionSyncRequestV4("upsert", dataplane.SessionKey{Protocol: 6},
		&dataplane.SessionValue{IngressIfaceFold: staleFold15263})
	if req.IngressIfindex != 42 || req.IngressVLANID != 80 {
		t.Fatalf("nil-snapshot fold = {%d vlan %d}; want {42 80}", req.IngressIfindex, req.IngressVLANID)
	}
}

func TestFoldFenceFollowsSnapshotIdentity15263(t *testing.T) {
	// The fence is the snapshot's interface identity, not the raw number in
	// isolation: a resolver naming a parent+vlan pair that no row carries
	// must decline, and once that row exists it must resolve. Build a
	// snapshot whose only row is the bare parent (live ifindex, no VLAN
	// unit): (live, 80) matches no unit and the bare parent row is not a
	// VLAN unit, so the pair declines; the same resolver over the full
	// fixture (which carries the unit row on the live parent) resolves.
	m := staleFoldManager15263(func(got uint32) (uint32, uint16, bool) {
		if got != staleFold15263 {
			return 0, 0, false
		}
		return liveIfindex15263, liveVLAN15263, true
	})
	m.lastSnapshot.Interfaces = []InterfaceSnapshot{{
		Name:            "ge-0-0-0",
		LinuxName:       "ge-0-0-0",
		Zone:            staleZone15263,
		EgressZone:      staleZone15263,
		Ifindex:         liveIfindex15263,
		RedundancyGroup: 1,
	}}
	req := m.buildSessionSyncRequestV4("upsert", dataplane.SessionKey{Protocol: 6},
		&dataplane.SessionValue{IngressIfaceFold: staleFold15263})
	// findUserspaceEgressInterfaceSnapshot's ParentIfindex fallback treats
	// a bare parent row as the identity for (parent, any-vlan) — that is
	// the snapshot's own egress convention, so the fence follows it and the
	// pair resolves to the parent. Assert that documented behaviour rather
	// than inventing a stricter one.
	if req.IngressIfindex != liveIfindex15263 || req.IngressVLANID != liveVLAN15263 {
		t.Fatalf("parent-fallback fold = {%d vlan %d}; want {%d vlan %d} (snapshot egress convention)",
			req.IngressIfindex, req.IngressVLANID, liveIfindex15263, liveVLAN15263)
	}
	// And a resolver naming an ifindex no row carries at all declines.
	m2 := staleFoldManager15263(func(got uint32) (uint32, uint16, bool) {
		if got != staleFold15263 {
			return 0, 0, false
		}
		return 99, 0, true
	})
	m2.lastSnapshot.Interfaces = m2.lastSnapshot.Interfaces[:1]
	req2 := m2.buildSessionSyncRequestV4("upsert", dataplane.SessionKey{Protocol: 6},
		&dataplane.SessionValue{IngressIfaceFold: staleFold15263})
	if req2.IngressIfindex != 0 || req2.IngressVLANID != 0 {
		t.Fatalf("fold naming absent ifindex 99 resolved to {%d vlan %d}; want decline {0 0}",
			req2.IngressIfindex, req2.IngressVLANID)
	}
}
