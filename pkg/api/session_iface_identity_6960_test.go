// #6960: the REST session view reduced a zone to `zone.Interfaces[0]` and
// resolved every session's INGRESS interface from that single name, so an
// interface-scoped query reported — and, on the gRPC surface that shares the
// reduction, DELETED — sessions received on a sibling interface of the zone.
// These tests mirror pkg/grpcapi/session_iface_identity_6960_test.go so a fix
// applied to one API surface and not the other is visible.
package api

import (
	"net"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/dataplane"
)

const (
	restIface6960Trust   uint16 = 1
	restIface6960Untrust uint16 = 2
)

type restIface6960DP struct {
	*dataplane.Manager
	result *dataplane.ApplyResult
}

func (d *restIface6960DP) LastApplyResult() *dataplane.ApplyResult { return d.result }

// restIface6960Store binds a trust zone to ge-0/0/0.0 plus two VLAN units of
// the ge-0/0/3 trunk. ge-0/0/0.0 is FIRST, so it is the name the pre-fix
// reduction reported for every session in the zone. A single-interface zone
// could not tell the approximation from the recorded identity.
func restIface6960Store(t *testing.T) *configstore.Store {
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

func restIface6960View(t *testing.T) sessionView {
	t.Helper()
	s := &Server{
		store: restIface6960Store(t),
		dp: &restIface6960DP{
			Manager: dataplane.New(),
			result: &dataplane.ApplyResult{ZoneIDs: map[string]uint32{
				"trust": uint32(restIface6960Trust), "untrust": uint32(restIface6960Untrust),
			}},
		},
		// The test box has no ge-0-0-* netdevs; without the injected lookup
		// the identity table would be empty and every assertion below would
		// pass vacuously through the zone fallback.
		// #16065 dual keying: the lookup receives the PARENT device
		// ("ge-0-0-3" = 14, the ingress stamp form) and each unit's OWN
		// child device ("ge-0-0-3.50" = 15, "ge-0-0-3.80" = 16).
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
	v := s.buildSessionView()
	// Non-vacuous guard: a missing table entry must FAIL here. Both key
	// forms of the trunk unit must be present.
	if name := v.egressIfaces[sessionEgressKey{Ifindex: 14, VlanID: 80}]; name != "ge-0/0/3.80" {
		t.Fatalf("iface name table missing the trunk unit at parent form: {14,80} = %q, want ge-0/0/3.80 (table=%v)", name, v.egressIfaces)
	}
	if name := v.egressIfaces[sessionEgressKey{Ifindex: 16, VlanID: 80}]; name != "ge-0/0/3.80" {
		t.Fatalf("iface name table missing the trunk unit at child form: {16,80} = %q, want ge-0/0/3.80 (table=%v)", name, v.egressIfaces)
	}
	return v
}

// TestRESTSessionViewKeepsEveryZoneInterface6960 pins the reduction itself.
// RED on revert: `v.zoneIfaces[zid] = zone.Interfaces[0]` yields one member.
func TestRESTSessionViewKeepsEveryZoneInterface6960(t *testing.T) {
	v := restIface6960View(t)
	got := v.zoneIfaces[restIface6960Trust]
	if len(got) != 3 {
		t.Fatalf("zoneIfaces[trust] = %v, want all 3 bound interfaces", got)
	}
	for _, w := range []string{"ge-0/0/0.0", "ge-0/0/3.50", "ge-0/0/3.80"} {
		if !zoneBindsIface(got, w) {
			t.Errorf("zoneIfaces[trust] = %v is missing %q", got, w)
		}
	}
}

// TestRESTInterfaceFilterDoesNotMatchZoneSibling6960 is the filter binding.
// RED on revert: restoring `inIf := q.view.zoneIfaces[val.IngressZone]` makes
// the sibling subtests match. The same-interface rows are the over-reach
// control — they prove the fix narrowed rather than broke the filter.
func TestRESTInterfaceFilterDoesNotMatchZoneSibling6960(t *testing.T) {
	v := restIface6960View(t)

	key := dataplane.SessionKey{Protocol: 6, SrcPort: ntohs(54321), DstPort: ntohs(443)}
	// Arrived on ge-0/0/3.80; FIB egress is ge-0/0/1 (ifindex 12), so the
	// egress arm can never rescue an ingress-arm assertion.
	val := dataplane.SessionValue{
		IngressZone: restIface6960Trust, EgressZone: restIface6960Untrust,
		IngressIfindex: 14, IngressVlanID: 80, FibIfindex: 12,
	}
	var key6 dataplane.SessionKeyV6
	key6.Protocol = 6
	copy(key6.SrcIP[:], net.ParseIP("2001:db8::10").To16())
	copy(key6.DstIP[:], net.ParseIP("2001:db8:80::8").To16())
	val6 := dataplane.SessionValueV6{
		IngressZone: restIface6960Trust, EgressZone: restIface6960Untrust,
		IngressIfindex: 14, IngressVlanID: 80, FibIfindex: 12,
	}

	for _, tc := range []struct {
		filter string
		want   bool
		why    string
	}{
		{"ge-0/0/0", false, "sibling interface of the ingress zone"},
		{"ge-0/0/3.50", false, "sibling VLAN unit on the SAME trunk NIC"},
		{"ge-0/0/3.80", true, "the interface the session actually arrived on"},
		{"ge-0/0/1", true, "the egress interface (the filter ORs both arms)"},
	} {
		t.Run(tc.filter, func(t *testing.T) {
			q := &sessionQuery{iface: tc.filter, view: v}
			if got := q.matchV4(key, val); got != tc.want {
				t.Errorf("matchV4(filter=%q) = %v, want %v (%s)", tc.filter, got, tc.want, tc.why)
			}
			if got := q.matchV6(key6, val6); got != tc.want {
				t.Errorf("matchV6(filter=%q) = %v, want %v (%s)", tc.filter, got, tc.want, tc.why)
			}
		})
	}
}

// TestRESTSessionEntryIngressInterfaceNotZoneFirst6960 pins the reported name.
func TestRESTSessionEntryIngressInterfaceNotZoneFirst6960(t *testing.T) {
	v := restIface6960View(t)
	key := dataplane.SessionKey{Protocol: 6}

	se := sessionEntryV4(key, dataplane.SessionValue{
		IngressZone: restIface6960Trust, EgressZone: restIface6960Untrust,
		IngressIfindex: 14, IngressVlanID: 80,
	}, 0, v)
	if se.IngressInterface != "ge-0/0/3.80" {
		t.Errorf("ingress_interface = %q, want ge-0/0/3.80", se.IngressInterface)
	}

	// No recorded identity (HA peer-synced row / reverse companion) in a
	// multi-interface zone: report the zone, not a confident wrong sibling.
	noID := sessionEntryV4(key, dataplane.SessionValue{
		IngressZone: restIface6960Trust, EgressZone: restIface6960Untrust,
	}, 0, v)
	if noID.IngressInterface == "ge-0/0/0.0" {
		t.Errorf("ingress_interface = %q: the zone's FIRST interface reported as fact (#6987)", noID.IngressInterface)
	}
	if noID.IngressInterface != "trust" {
		t.Errorf("ingress_interface = %q, want the zone name %q", noID.IngressInterface, "trust")
	}

	// Over-reach control: a single-interface zone still names its one member.
	sole := sessionEntryV4(key, dataplane.SessionValue{
		IngressZone: restIface6960Untrust, EgressZone: restIface6960Trust,
	}, 0, v)
	if sole.IngressInterface != "ge-0/0/1.0" {
		t.Errorf("ingress_interface = %q, want ge-0/0/1.0", sole.IngressInterface)
	}
}

// TestRESTPeerSyncedSessionStillReachableByZoneArm6960 guards the fallback: a
// row with NO ingress identity must stay selectable by a filter naming a member
// of its ingress zone.
func TestRESTPeerSyncedSessionStillReachableByZoneArm6960(t *testing.T) {
	v := restIface6960View(t)
	q := &sessionQuery{iface: "ge-0/0/3.50", view: v}
	val := dataplane.SessionValue{
		IngressZone: restIface6960Trust, EgressZone: restIface6960Untrust,
		FibIfindex: 12,
	}
	if !q.matchV4(dataplane.SessionKey{Protocol: 6}, val) {
		t.Errorf("a session with no ingress identity became unreachable by a filter naming a member of its ingress zone")
	}
}

// TestRESTRecycledIfindexIsNotReportedAsFact6960 mirrors the gRPC guard: a
// kernel ifindex recycled onto a different interface HITS the rebuilt name
// table (#6987), so an identity the session's own recorded zone does not
// corroborate is never reported as fact.
//
// RED on revert: `return ifName, zoneBindsIface(...)` -> `return ifName, true`.
func TestRESTRecycledIfindexIsNotReportedAsFact6960(t *testing.T) {
	v := restIface6960View(t)
	key := dataplane.SessionKey{Protocol: 6}
	val := dataplane.SessionValue{
		IngressZone: restIface6960Untrust, EgressZone: restIface6960Trust,
		IngressIfindex: 14, IngressVlanID: 80,
		// A nameable FIB egress (ge-0/0/0), so the egress arm is precise and
		// cannot satisfy an ingress-arm assertion via the trust zone's list.
		FibIfindex: 11,
	}

	se := sessionEntryV4(key, val, 0, v)
	if se.IngressInterface == "ge-0/0/3.80" {
		t.Errorf("ingress_interface = %q: a recycled ifindex reported as fact (#6987)", se.IngressInterface)
	}
	if se.IngressInterface != "untrust" {
		t.Errorf("ingress_interface = %q, want the zone name %q: a DISPUTED hit reports no interface even though the untrust zone binds exactly one (#6987)", se.IngressInterface, "untrust")
	}

	// The filter treats the disputed hit as a MISS — see the gRPC mirror for
	// why — while the row stays reachable by its zone and its egress arm.
	for _, tc := range []struct {
		filter string
		want   bool
	}{
		{"ge-0/0/3.80", false},
		{"ge-0/0/1", true},
		{"ge-0/0/0", true},
	} {
		q := &sessionQuery{iface: tc.filter, view: v}
		if got := q.matchV4(key, val); got != tc.want {
			t.Errorf("matchV4(filter=%q) = %v, want %v", tc.filter, got, tc.want)
		}
	}
}
