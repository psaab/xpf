package grpcapi

import (
	"context"
	"net"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// session_clear_16065_test.go — #16065 fold acceptance on the real
// ClearSessions RPC (the destructive surface):
//
// F1: parent-stamped VLAN ingress {14, VID} in a zone binding both
// units — clearing .80 deletes only the VID-80 row (v4+v6).
// F2: wg0.0/wg0.1 share one TUN and one zone — clearing wg0.1 deletes
// nothing on the shared device; an identity-less row keeps the zone
// fallback. F3: tagged unit 0 matches an explicit ".0" clear/filter.

const (
	clear16065Trust   uint16 = 1
	clear16065Untrust uint16 = 2
)

func vlanClearServer16065(t *testing.T, dp *ifaceIdentity6960DP) *Server {
	t.Helper()
	dp.Manager = dataplane.New()
	dp.apply = &dataplane.ApplyResult{ZoneIDs: map[string]uint16{
		"trust": clear16065Trust, "untrust": clear16065Untrust,
	}}
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if _, err := store.LoadSet(`set interfaces ge-0/0/0 unit 0 family inet address 10.0.1.10/24
set interfaces ge-0/0/1 unit 0 family inet address 10.0.2.10/24
set interfaces ge-0/0/3 vlan-tagging
set interfaces ge-0/0/3 unit 50 vlan-id 50
set interfaces ge-0/0/3 unit 50 family inet address 172.16.50.8/24
set interfaces ge-0/0/3 unit 80 vlan-id 80
set interfaces ge-0/0/3 unit 80 family inet address 172.16.80.8/24
set security zones security-zone trust interfaces ge-0/0/3.50
set security zones security-zone trust interfaces ge-0/0/3.80
set security zones security-zone untrust interfaces ge-0/0/1.0
set security policies default-policy deny-all`); err != nil {
		t.Fatalf("LoadSet: %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	return &Server{
		store: store,
		dp:    dp,
		ifindexByName: func(name string) (int, error) {
			switch name {
			case "ge-0-0-0":
				return 11, nil
			case "ge-0-0-1":
				return 12, nil
			case "ge-0-0-3":
				return 14, nil
			case "ge-0-0-3.50":
				return 15, nil
			case "ge-0-0-3.80":
				return 16, nil
			}
			return 0, net.UnknownNetworkError(name)
		},
	}
}

func TestClearSessionsParentStampedVlan16065(t *testing.T) {
	k50 := dataplane.SessionKey{Protocol: 6, SrcPort: hostToNetwork16(40050)}
	k80 := dataplane.SessionKey{Protocol: 6, SrcPort: hostToNetwork16(40080)}
	k6_50 := dataplane.SessionKeyV6{Protocol: 6, SrcPort: hostToNetwork16(40050)}
	k6_80 := dataplane.SessionKeyV6{Protocol: 6, SrcPort: hostToNetwork16(40080)}
	dp := &ifaceIdentity6960DP{
		sessions: map[dataplane.SessionKey]dataplane.SessionValue{
			// Parent-stamped ingress, unrelated precise egress (12).
			k50: {IngressZone: clear16065Trust, EgressZone: clear16065Untrust, IngressIfindex: 14, IngressVlanID: 50, FibIfindex: 12},
			k80: {IngressZone: clear16065Trust, EgressZone: clear16065Untrust, IngressIfindex: 14, IngressVlanID: 80, FibIfindex: 12},
		},
		v6: map[dataplane.SessionKeyV6]dataplane.SessionValueV6{
			k6_50: {IngressZone: clear16065Trust, EgressZone: clear16065Untrust, IngressIfindex: 14, IngressVlanID: 50, FibIfindex: 12},
			k6_80: {IngressZone: clear16065Trust, EgressZone: clear16065Untrust, IngressIfindex: 14, IngressVlanID: 80, FibIfindex: 12},
		},
	}
	s := vlanClearServer16065(t, dp)
	// Premise non-vacuous: parent-form entries exist.
	f := s.buildSessionFilter(&pb.GetSessionsRequest{})
	if f.egressIfaces[sessionEgressKey{Ifindex: 14, VlanID: 50}] != "ge-0/0/3.50" ||
		f.egressIfaces[sessionEgressKey{Ifindex: 14, VlanID: 80}] != "ge-0/0/3.80" {
		t.Fatalf("premise: parent-form table incomplete: %v", f.egressIfaces)
	}
	if _, err := s.ClearSessions(context.Background(), &pb.ClearSessionsRequest{Interface: "ge-0/0/3.80"}); err != nil {
		t.Fatalf("ClearSessions: %v", err)
	}
	if len(dp.deleted) != 1 || dp.deleted[0] != k80 {
		t.Fatalf("v4 deleted = %v, want exactly the VID-80 row (F1: parent-stamped .50 row must survive)", dp.deleted)
	}
	if len(dp.deletedV6) != 1 || dp.deletedV6[0] != k6_80 {
		t.Fatalf("v6 deleted = %v, want exactly the VID-80 row (F1)", dp.deletedV6)
	}
}

func TestClearSessionsSharedWireGuard16065(t *testing.T) {
	const wgPriv = "21a8e89546569ec63441fbc82a72e6a59c0528cb39896d0adf84e77c4758e6b3"
	const wgPeer = "00bedd4ed26623ab2f765d16af2dcba4f6dbe17c284a66c6494b48b823f4c654"
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if _, err := store.LoadSet(`set interfaces wg0 tunnel mode wireguard
set interfaces wg0 tunnel wireguard listen-port 51820
set interfaces wg0 tunnel wireguard private-key ` + wgPriv + `
set interfaces wg0 tunnel wireguard peer ` + wgPeer + ` allowed-ips 10.100.0.0/24
set interfaces wg0 unit 0 family inet address 10.66.0.1/24
set interfaces wg0 unit 1 family inet address 10.66.1.1/24
set interfaces ge-0/0/1 unit 0 family inet address 10.0.2.10/24
set security zones security-zone trust interfaces wg0.0
set security zones security-zone trust interfaces wg0.1
set security zones security-zone untrust interfaces ge-0/0/1.0
set security policies default-policy deny-all`); err != nil {
		t.Fatalf("LoadSet: %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	wgKey := dataplane.SessionKey{Protocol: 6, SrcPort: hostToNetwork16(41000)}
	peerKey := dataplane.SessionKey{Protocol: 6, SrcPort: hostToNetwork16(41001)}
	dp := &ifaceIdentity6960DP{
		sessions: map[dataplane.SessionKey]dataplane.SessionValue{
			// On the shared TUN, unrelated precise egress.
			wgKey: {IngressZone: clear16065Trust, EgressZone: clear16065Untrust, IngressIfindex: 20, IngressVlanID: 0, FibIfindex: 12},
			// Identity-less peer-synced row in the same zone.
			peerKey: {IngressZone: clear16065Trust, EgressZone: clear16065Untrust, IngressIfindex: 0, FibIfindex: 12},
		},
	}
	dp.Manager = dataplane.New()
	dp.apply = &dataplane.ApplyResult{ZoneIDs: map[string]uint16{
		"trust": clear16065Trust, "untrust": clear16065Untrust,
	}}
	s := &Server{
		store: store,
		dp:    dp,
		ifindexByName: func(name string) (int, error) {
			switch name {
			case "wg0":
				return 20, nil
			case "ge-0-0-1":
				return 12, nil
			}
			return 0, net.UnknownNetworkError(name)
		},
	}
	// Premise: the shared key is refused in the built filter.
	f := s.buildSessionFilter(&pb.GetSessionsRequest{InterfaceFilter: "wg0.1"})
	if _, refused := f.ambiguousKeys[sessionEgressKey{Ifindex: 20, VlanID: 0}]; !refused {
		t.Fatalf("premise: {20,0} must be ambiguous in the filter, table=%v amb=%v", f.egressIfaces, f.ambiguousKeys)
	}
	if _, err := s.ClearSessions(context.Background(), &pb.ClearSessionsRequest{Interface: "wg0.1"}); err != nil {
		t.Fatalf("ClearSessions wg0.1: %v", err)
	}
	for _, k := range dp.deleted {
		if k == wgKey {
			t.Fatal("clear wg0.1 deleted the shared-TUN session: sibling deletion through the zone fallback (#16065 F2)")
		}
	}
	// The identity-less peer row IS deleted via the zone fallback —
	// narrowing applies only to refused-identity rows. (It matches
	// wg0.1 through zone membership, as before.)
	foundPeer := false
	for _, k := range dp.deleted {
		if k == peerKey {
			foundPeer = true
		}
	}
	if !foundPeer {
		t.Fatalf("identity-less peer row must remain reachable (zone fallback), deleted=%v", dp.deleted)
	}
}

func TestTaggedUnitZeroGRPCFilter16065(t *testing.T) {
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if _, err := store.LoadSet(`set interfaces ge-0/0/0 vlan-tagging
set interfaces ge-0/0/0 unit 0 vlan-id 100
set interfaces ge-0/0/0 unit 0 family inet address 10.0.1.10/24
set interfaces ge-0/0/1 unit 0 family inet address 10.0.2.10/24
set security zones security-zone trust interfaces ge-0/0/0.0
set security zones security-zone untrust interfaces ge-0/0/1.0
set security policies default-policy deny-all`); err != nil {
		t.Fatalf("LoadSet: %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	dp := &ifaceIdentity6960DP{}
	dp.Manager = dataplane.New()
	dp.apply = &dataplane.ApplyResult{ZoneIDs: map[string]uint16{
		"trust": clear16065Trust, "untrust": clear16065Untrust,
	}}
	s := &Server{
		store: store,
		dp:    dp,
		ifindexByName: func(name string) (int, error) {
			switch name {
			case "ge-0-0-0":
				return 40, nil
			case "ge-0-0-0.100":
				return 41, nil
			case "ge-0-0-1":
				return 12, nil
			}
			return 0, net.UnknownNetworkError(name)
		},
	}
	f := s.buildSessionFilter(&pb.GetSessionsRequest{InterfaceFilter: "ge-0/0/0.0"})
	if f.egressIfaces[sessionEgressKey{Ifindex: 41, VlanID: 100}] != "ge-0/0/0.0" {
		t.Fatalf("premise: tagged unit 0 child must keep .0, table=%v", f.egressIfaces)
	}
	key := dataplane.SessionKey{Protocol: 6}
	ing := dataplane.SessionValue{IngressZone: clear16065Trust, EgressZone: clear16065Untrust, IngressIfindex: 40, IngressVlanID: 100, FibIfindex: 99}
	if !f.matchV4(key, ing) {
		t.Error("tagged unit 0: explicit ge-0/0/0.0 filter must match parent-stamped ingress {40,100} (F3)")
	}
	egr := dataplane.SessionValue{IngressZone: clear16065Trust, EgressZone: clear16065Untrust, IngressIfindex: 0, FibIfindex: 41, FibVlanID: 100}
	// Ingress 0 falls back to zone [ge-0/0/0.0] which also matches;
	// isolate egress by checking the resolver directly as well.
	if !f.matchV4(key, egr) {
		t.Error("tagged unit 0: ge-0/0/0.0 filter must match child-stamped egress {41,100} (F3)")
	}
	if got := resolveSessionEgressIfacesAmb(41, 100, clear16065Untrust, f.zoneIfaces, f.egressIfaces, f.ambiguousKeys); len(got) != 1 || got[0] != "ge-0/0/0.0" {
		t.Errorf("resolve egress {41,100} = %v, want [ge-0/0/0.0]", got)
	}
	// Bare parent filter control.
	fp := s.buildSessionFilter(&pb.GetSessionsRequest{InterfaceFilter: "ge-0/0/0"})
	if !fp.matchV4(key, ing) {
		t.Error("bare parent filter ge-0/0/0 must still match tagged unit 0")
	}
}
