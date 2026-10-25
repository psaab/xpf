// #6960/#6975: the gRPC session-interface filter resolved a session's INGRESS
// interface as `zone.Interfaces[0]` — a value that does not depend on the
// session at all, only on its ingress zone. The remote `cli` routes both `show`
// and `clear` through this filter (cmd/cli/show_flow.go, cmd/cli/clear.go ->
// ClearSessions -> the shared matchV4/matchV6), and a console clear propagates
// the operator's filter to the HA peer over the same RPC (#6975), so
// `clear security flow session interface <zone's first interface>` DELETED every
// session in that zone — including flows received on a sibling interface.
//
// The fixtures use a THREE-interface trust zone, two of whose members are VLAN
// units of ONE trunk NIC. A single-interface zone cannot distinguish the zone
// approximation from the recorded identity (they agree there), and with two
// members a fix that merely swapped one sibling for the other would still pass.
package grpcapi

import (
	"context"
	"net"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/dataplane"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

const (
	ifaceIdentity6960Trust   uint16 = 1
	ifaceIdentity6960Untrust uint16 = 2
)

// ifaceIdentity6960Store binds a trust zone to ge-0/0/0.0 plus two VLAN units
// of the ge-0/0/3 trunk, mirroring the loss cluster's reth0.50 / reth0.80
// wiring. ge-0/0/0.0 is FIRST, so it is the name the pre-fix zone reduction
// reported for every session in the zone.
func ifaceIdentity6960Store(t *testing.T) *configstore.Store {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	if _, err := store.LoadSet(`set interfaces ge-0/0/0 unit 0 family inet address 10.0.1.10/24
set interfaces ge-0/0/1 unit 0 family inet address 10.0.2.10/24
set interfaces ge-0/0/3 vlan-tagging
set interfaces ge-0/0/3 unit 50 vlan-id 50
set interfaces ge-0/0/3 unit 50 family inet address 172.16.50.8/24
set interfaces ge-0/0/3 unit 80 vlan-id 80
set interfaces ge-0/0/3 unit 80 family inet address 172.16.80.8/24
set security zones security-zone trust interfaces ge-0/0/0.0
set security zones security-zone trust interfaces ge-0/0/3.50
set security zones security-zone trust interfaces ge-0/0/3.80
set security zones security-zone untrust interfaces ge-0/0/1.0
set security policies default-policy deny-all`); err != nil {
		t.Fatalf("LoadSet() error = %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit() error = %v", err)
	}
	return store
}

// ifaceIdentity6960Ifindex is the injected kernel lookup. The test box has no
// ge-0-0-* netdevs, so without it the {ifindex, VLAN} name table would be
// empty, every session would fall back to the zone, and the assertions below
// would pass with the fix reverted.
// #16065: the injected lookup receives the unit's OWN kernel device
// ("ge-0-0-3.50", the VLAN child), not the parent netdev. Each child
// owns its ifindex; the parent device is never looked up by the
// session table (it has no unit of its own in this fixture).
func ifaceIdentity6960Ifindex(t *testing.T) func(string) (int, error) {
	t.Helper()
	return func(name string) (int, error) {
		switch name {
		case "ge-0-0-0":
			return 11, nil
		case "ge-0-0-1":
			return 12, nil
		case "ge-0-0-3":
			return 14, nil // parent/bind device: parent-stamped ingress {14,VID}
		case "ge-0-0-3.50":
			return 15, nil
		case "ge-0-0-3.80":
			return 16, nil
		}
		return 0, net.UnknownNetworkError(name)
	}
}

type ifaceIdentity6960DP struct {
	*dataplane.Manager
	apply     *dataplane.ApplyResult
	sessions  map[dataplane.SessionKey]dataplane.SessionValue
	v6        map[dataplane.SessionKeyV6]dataplane.SessionValueV6
	deleted   []dataplane.SessionKey
	deletedV6 []dataplane.SessionKeyV6
}

func (d *ifaceIdentity6960DP) LastApplyResult() *dataplane.ApplyResult { return d.apply }
func (d *ifaceIdentity6960DP) IsLoaded() bool                          { return true }

func (d *ifaceIdentity6960DP) IterateSessions(fn func(dataplane.SessionKey, dataplane.SessionValue) bool) error {
	for k, v := range d.sessions {
		if !fn(k, v) {
			break
		}
	}
	return nil
}

func (d *ifaceIdentity6960DP) IterateSessionsV6(fn func(dataplane.SessionKeyV6, dataplane.SessionValueV6) bool) error {
	for k, v := range d.v6 {
		if !fn(k, v) {
			break
		}
	}
	return nil
}

func (d *ifaceIdentity6960DP) IterateSessionsFrom(cursor *dataplane.SessionKey, fn func(dataplane.SessionKey, dataplane.SessionValue) bool) error {
	iterateV4From(d.sessions, cursor, fn)
	return nil
}

func (d *ifaceIdentity6960DP) IterateSessionsV6From(cursor *dataplane.SessionKeyV6, fn func(dataplane.SessionKeyV6, dataplane.SessionValueV6) bool) error {
	iterateV6From(d.v6, cursor, fn)
	return nil
}

func (d *ifaceIdentity6960DP) DeleteSession(key dataplane.SessionKey) error {
	if _, ok := d.sessions[key]; ok {
		d.deleted = append(d.deleted, key)
	}
	return nil
}

func (d *ifaceIdentity6960DP) DeleteSessionV6(key dataplane.SessionKeyV6) error {
	if _, ok := d.v6[key]; ok {
		d.deletedV6 = append(d.deletedV6, key)
	}
	return nil
}
func (d *ifaceIdentity6960DP) DeleteDNATEntry(dataplane.DNATKey) error     { return nil }
func (d *ifaceIdentity6960DP) DeleteDNATEntryV6(dataplane.DNATKeyV6) error { return nil }

func ifaceIdentity6960Server(t *testing.T, dp *ifaceIdentity6960DP) *Server {
	t.Helper()
	dp.Manager = dataplane.New()
	dp.apply = &dataplane.ApplyResult{ZoneIDs: map[string]uint32{
		"trust": uint32(ifaceIdentity6960Trust), "untrust": uint32(ifaceIdentity6960Untrust),
	}}
	return &Server{
		store:         ifaceIdentity6960Store(t),
		dp:            dp,
		ifindexByName: ifaceIdentity6960Ifindex(t),
	}
}

// TestSessionFilterKeepsEveryZoneInterface6960 pins the reduction itself.
// RED on revert: `f.zoneIfaces[zid] = zone.Interfaces[0]` yields one member.
func TestSessionFilterKeepsEveryZoneInterface6960(t *testing.T) {
	s := ifaceIdentity6960Server(t, &ifaceIdentity6960DP{})
	f := s.buildSessionFilter(&pb.GetSessionsRequest{})

	want := []string{"ge-0/0/0.0", "ge-0/0/3.50", "ge-0/0/3.80"}
	got := f.zoneIfaces[ifaceIdentity6960Trust]
	if len(got) != len(want) {
		t.Fatalf("zoneIfaces[trust] = %v, want all %d bound interfaces %v", got, len(want), want)
	}
	for _, w := range want {
		if !zoneBindsIface(got, w) {
			t.Errorf("zoneIfaces[trust] = %v is missing %q", got, w)
		}
	}

	// The {ifindex, VLAN} name table must actually be populated, or every
	// identity assertion below would pass vacuously via the zone fallback.
	// #16065 dual keying: BOTH the parent form {14,80} (the ingress
	// stamp these fixtures record) and the child form {16,80} must name
	// the trunk unit. A missing entry fails here, not silently.
	if name := f.egressIfaces[sessionEgressKey{Ifindex: 14, VlanID: 80}]; name != "ge-0/0/3.80" {
		t.Fatalf("iface name table missing the trunk unit at parent form: {14,80} = %q, want ge-0/0/3.80 (table=%v)", name, f.egressIfaces)
	}
	if name := f.egressIfaces[sessionEgressKey{Ifindex: 16, VlanID: 80}]; name != "ge-0/0/3.80" {
		t.Fatalf("iface name table missing the trunk unit at child form: {16,80} = %q, want ge-0/0/3.80 (table=%v)", name, f.egressIfaces)
	}
	if name := f.egressIfaces[sessionEgressKey{Ifindex: 15, VlanID: 50}]; name != "ge-0/0/3.50" {
		t.Fatalf("iface name table missing the sibling unit at child form: {15,50} = %q, want ge-0/0/3.50 (table=%v)", name, f.egressIfaces)
	}
}

// TestGRPCInterfaceFilterDoesNotMatchZoneSibling6960 is the filter binding.
// A session whose RECORDED ingress binding is ge-0/0/3.80 must not be selected
// by a filter naming a SIBLING interface of its zone.
//
// RED on revert: restoring `inIf := f.zoneIfaces[val.IngressZone]` makes the
// sibling subtests match. The same-interface control proves the fix did not
// simply stop matching.
func TestGRPCInterfaceFilterDoesNotMatchZoneSibling6960(t *testing.T) {
	s := ifaceIdentity6960Server(t, &ifaceIdentity6960DP{})

	// Arrived on ge-0/0/3.80 (trunk ge-0/0/3 == ifindex 14, VLAN 80).
	// FibIfindex 12 == ge-0/0/1, so the EGRESS arm can only match ge-0/0/1
	// and never rescues an ingress-arm assertion.
	key := dataplane.SessionKey{Protocol: 6, SrcPort: hostToNetwork16(54321), DstPort: hostToNetwork16(443)}
	val := dataplane.SessionValue{
		IngressZone:    ifaceIdentity6960Trust,
		EgressZone:     ifaceIdentity6960Untrust,
		IngressIfindex: 14,
		IngressVlanID:  80,
		FibIfindex:     12,
	}
	var key6 dataplane.SessionKeyV6
	key6.Protocol = 6
	copy(key6.SrcIP[:], net.ParseIP("2001:db8::10").To16())
	copy(key6.DstIP[:], net.ParseIP("2001:db8:80::8").To16())
	val6 := dataplane.SessionValueV6{
		IngressZone:    ifaceIdentity6960Trust,
		EgressZone:     ifaceIdentity6960Untrust,
		IngressIfindex: 14,
		IngressVlanID:  80,
		FibIfindex:     12,
	}

	for _, tc := range []struct {
		filter string
		want   bool
		why    string
	}{
		{"ge-0/0/0", false, "sibling interface of the ingress zone"},
		{"ge-0/0/3.50", false, "sibling VLAN unit on the SAME trunk NIC"},
		{"ge-0/0/3.80", true, "the interface the session actually arrived on"},
		{"ge-0/0/3", true, "the trunk parent of the arrival unit"},
		{"ge-0/0/1", true, "the egress interface (the filter ORs both arms)"},
	} {
		t.Run(tc.filter, func(t *testing.T) {
			f := s.buildSessionFilter(&pb.GetSessionsRequest{InterfaceFilter: tc.filter})
			if got := f.matchV4(key, val); got != tc.want {
				t.Errorf("matchV4(filter=%q) = %v, want %v (%s)", tc.filter, got, tc.want, tc.why)
			}
			if got := f.matchV6(key6, val6); got != tc.want {
				t.Errorf("matchV6(filter=%q) = %v, want %v (%s)", tc.filter, got, tc.want, tc.why)
			}
		})
	}
}

// TestClearSessionsSparesZoneSibling6960 drives the destructive surface: the
// real ClearSessions RPC, the one the remote `cli` and the #6975 peer-clear
// propagation both call. The sibling session must survive and the named one
// must go — an interface filter that deleted nothing would pass the first
// assertion alone.
func TestClearSessionsSparesZoneSibling6960(t *testing.T) {
	onTrunk := dataplane.SessionKey{Protocol: 6, SrcPort: hostToNetwork16(54321), DstPort: hostToNetwork16(443)}
	onGe000 := dataplane.SessionKey{Protocol: 6, SrcPort: hostToNetwork16(54322), DstPort: hostToNetwork16(443)}
	dp := &ifaceIdentity6960DP{
		sessions: map[dataplane.SessionKey]dataplane.SessionValue{
			onTrunk: {
				IngressZone: ifaceIdentity6960Trust, EgressZone: ifaceIdentity6960Untrust,
				IngressIfindex: 14, IngressVlanID: 80, FibIfindex: 12,
			},
			onGe000: {
				IngressZone: ifaceIdentity6960Trust, EgressZone: ifaceIdentity6960Untrust,
				IngressIfindex: 11, IngressVlanID: 0, FibIfindex: 12,
			},
		},
	}
	s := ifaceIdentity6960Server(t, dp)

	resp, err := s.ClearSessions(context.Background(), &pb.ClearSessionsRequest{Interface: "ge-0/0/0"})
	if err != nil {
		t.Fatalf("ClearSessions: %v", err)
	}
	for _, k := range dp.deleted {
		if k == onTrunk {
			t.Errorf("`clear ... interface ge-0/0/0` deleted the session received on ge-0/0/3.80 (#6960)")
		}
	}
	if len(dp.deleted) != 1 || dp.deleted[0] != onGe000 {
		t.Errorf("deleted = %v, want exactly the ge-0/0/0 session", dp.deleted)
	}
	if resp.Ipv4Cleared != 1 {
		t.Errorf("ipv4_cleared = %d, want 1", resp.Ipv4Cleared)
	}
}

// TestSessionEntryIngressInterfaceNotZoneFirst6960 pins the DISPLAY half: the
// name reported in `ingress_interface` must be the session's own, never the
// zone's first interface standing in for its siblings.
func TestSessionEntryIngressInterfaceNotZoneFirst6960(t *testing.T) {
	s := ifaceIdentity6960Server(t, &ifaceIdentity6960DP{})
	f := s.buildSessionFilter(&pb.GetSessionsRequest{})
	key := dataplane.SessionKey{Protocol: 6}

	t.Run("recorded identity is reported exactly", func(t *testing.T) {
		se := sessionEntryV4(key, dataplane.SessionValue{
			IngressZone: ifaceIdentity6960Trust, EgressZone: ifaceIdentity6960Untrust,
			IngressIfindex: 14, IngressVlanID: 80,
		}, 0, f.zoneNames, nil, f.zoneIfaces, f.egressIfaces, true)
		if se.IngressInterface != "ge-0/0/3.80" {
			t.Errorf("ingress_interface = %q, want ge-0/0/3.80", se.IngressInterface)
		}
	})

	// An HA peer-synced row carries no ingress identity (#6928 imports it as 0;
	// #7095 tracks syncing it). With a multi-interface ingress zone there is no
	// defensible interface name, so the zone is reported (#6987).
	t.Run("no identity in a multi-interface zone reports the zone", func(t *testing.T) {
		se := sessionEntryV4(key, dataplane.SessionValue{
			IngressZone: ifaceIdentity6960Trust, EgressZone: ifaceIdentity6960Untrust,
		}, 0, f.zoneNames, nil, f.zoneIfaces, f.egressIfaces, true)
		if se.IngressInterface == "ge-0/0/0.0" {
			t.Errorf("ingress_interface = %q: the zone's FIRST interface reported as fact for a session with no recorded identity (#6987)", se.IngressInterface)
		}
		if se.IngressInterface != "trust" {
			t.Errorf("ingress_interface = %q, want the zone name %q", se.IngressInterface, "trust")
		}
	})

	// Over-reach control: with a SINGLE bound interface the zone approximation
	// has exactly one answer, so the column still names it. Without this,
	// blanking the column unconditionally would pass.
	t.Run("no identity in a single-interface zone still names it", func(t *testing.T) {
		se := sessionEntryV4(key, dataplane.SessionValue{
			IngressZone: ifaceIdentity6960Untrust, EgressZone: ifaceIdentity6960Trust,
		}, 0, f.zoneNames, nil, f.zoneIfaces, f.egressIfaces, true)
		if se.IngressInterface != "ge-0/0/1.0" {
			t.Errorf("ingress_interface = %q, want ge-0/0/1.0", se.IngressInterface)
		}
	})
}

// TestPeerSyncedSessionStillReachableByZoneArm6960 guards the fallback: a row
// with NO ingress identity must stay selectable by an interface filter naming
// a member of its ingress zone. Narrowing the fallback to "unknown -> matches
// nothing" would hide every peer-synced session from `show`/`clear`.
func TestPeerSyncedSessionStillReachableByZoneArm6960(t *testing.T) {
	s := ifaceIdentity6960Server(t, &ifaceIdentity6960DP{})
	f := s.buildSessionFilter(&pb.GetSessionsRequest{InterfaceFilter: "ge-0/0/3.50"})
	key := dataplane.SessionKey{Protocol: 6}
	val := dataplane.SessionValue{
		IngressZone: ifaceIdentity6960Trust,
		EgressZone:  ifaceIdentity6960Untrust,
		// IngressIfindex deliberately 0 — peer-synced / reverse companion.
		FibIfindex: 12,
	}
	if !f.matchV4(key, val) {
		t.Errorf("a session with no ingress identity became unreachable by a filter naming a member of its ingress zone")
	}
}

// TestRecycledIfindexIsNotReportedAsFact6960 guards the corroboration check
// this change introduces alongside the identity read. The {ifindex, VLAN} name
// table is rebuilt from the CURRENT config and CURRENT kernel ifindexes on
// every query, while the session's ifindex was recorded at install, so a
// RECYCLED ifindex HITS the table and names an interface the session never
// arrived on (#6987, filed against the console CLI's copy of this resolution).
// Porting the identity read to these surfaces must not port that failure mode.
//
// Fixture: the session recorded ingress zone `untrust`, but ifindex 14 / VLAN
// 80 now names `ge-0/0/3.80`, bound to `trust`. The interface that held 14 at
// install is gone.
//
// RED on revert: `return ifName, zoneBindsIface(...)` -> `return ifName, true`
// reports ge-0/0/3.80 as the ingress interface of an untrust-zone session.
func TestRecycledIfindexIsNotReportedAsFact6960(t *testing.T) {
	s := ifaceIdentity6960Server(t, &ifaceIdentity6960DP{})
	f := s.buildSessionFilter(&pb.GetSessionsRequest{})
	key := dataplane.SessionKey{Protocol: 6}
	val := dataplane.SessionValue{
		IngressZone:    ifaceIdentity6960Untrust,
		EgressZone:     ifaceIdentity6960Trust,
		IngressIfindex: 14,
		IngressVlanID:  80,
		// A NAMEABLE FIB egress (ge-0/0/0) so the egress arm is precise and
		// cannot satisfy an ingress-arm assertion by falling back to the
		// trust zone's full member list, which contains ge-0/0/3.80.
		FibIfindex: 11,
	}

	se := sessionEntryV4(key, val, 0, f.zoneNames, nil, f.zoneIfaces, f.egressIfaces, true)
	if se.IngressInterface == "ge-0/0/3.80" {
		t.Errorf("ingress_interface = %q: a recycled ifindex reported as fact for a session whose recorded zone does not bind it (#6987)", se.IngressInterface)
	}
	if se.IngressInterface != "untrust" {
		t.Errorf("ingress_interface = %q, want the zone name %q: a DISPUTED hit reports no interface even though the untrust zone binds exactly one (#6987)", se.IngressInterface, "untrust")
	}

	// The FILTER treats the disputed hit as a MISS. It feeds `clear`, so
	// selecting on an untrustworthy name would DELETE sessions that never
	// touched the named interface — the failure #6960 exists to remove.
	// The row stays reachable through its ingress ZONE and its egress arm.
	for _, tc := range []struct {
		filter string
		want   bool
		why    string
	}{
		{"ge-0/0/3.80", false, "the disputed name is not acted on"},
		{"ge-0/0/1", true, "a member of the row's own recorded ingress zone"},
		{"ge-0/0/0", true, "the row's nameable FIB egress interface"},
	} {
		fq := s.buildSessionFilter(&pb.GetSessionsRequest{InterfaceFilter: tc.filter})
		if got := fq.matchV4(key, val); got != tc.want {
			t.Errorf("matchV4(filter=%q) = %v, want %v (%s)", tc.filter, got, tc.want, tc.why)
		}
	}
}
