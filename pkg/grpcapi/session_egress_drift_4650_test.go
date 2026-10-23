package grpcapi

import (
	"net"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
)

// restEgressOracle reproduces, independently of the shared
// sessionEgressIfaceDisplay helper, exactly how the REST path
// (pkg/api/sessions.go sessionEntryV4/V6) resolves a session's egress
// interface: the FibIfindex!=0-guarded egressIfaces lookup, then the egress
// zone's first bound interface, then the zone's display name. Used as a
// parity oracle so a revert of the
// gRPC entry paths back to the unconditional
// egressIfaces[{FibIfindex,FibVlanID}] lookup (the A9-F3 drift) makes the
// assertions below go RED.
func restEgressOracle(fibIfindex uint32, fibVlanID uint16, egressZone uint16, zoneNames map[uint16]string, zoneIfaces map[uint16][]string, egressIfaces map[sessionEgressKey]string) string {
	if fibIfindex != 0 {
		if name, ok := egressIfaces[sessionEgressKey{Ifindex: fibIfindex, VlanID: fibVlanID}]; ok && name != "" {
			return name
		}
	}
	if members := zoneIfaces[egressZone]; len(members) > 0 {
		return members[0]
	}
	return zoneNames[egressZone]
}

// TestSessionEntryEgressIfaceParity_4650 pins A9-F3: the gRPC
// sessionEntryV4/V6 egress-interface resolution must match the
// FibIfindex!=0-guarded REST/gRPC-filter resolution, so a session with
// FibIfindex==0 and a stale {ifindex:0, vlanID} egressIfaces entry does
// NOT print that bogus interface. Before the fix the gRPC entry paths
// indexed egressIfaces unconditionally and returned the stale name while
// REST returned the zone interface — a display drift between the two APIs.
func TestSessionEntryEgressIfaceParity_4650(t *testing.T) {
	const (
		ingressZone uint16 = 1
		egressZone  uint16 = 2
		vlanID      uint16 = 50
	)
	zoneNames := map[uint16]string{ingressZone: "trust", egressZone: "untrust"}
	zoneIfaces := map[uint16][]string{ingressZone: {"ge-0-0-1"}, egressZone: {"ge-0-0-2"}}

	// A stale {ifindex:0, vlanID:50} entry — the exact shape that a
	// FibIfindex==0 session used to mis-resolve to under the unconditional
	// gRPC lookup. The guarded helper must never consult it.
	egressIfaces := map[sessionEgressKey]string{
		{Ifindex: 0, VlanID: vlanID}: "ge-STALE-0",   // must be ignored (FibIfindex==0)
		{Ifindex: 7, VlanID: vlanID}: "ge-0-0-7-fib", // consulted only for FibIfindex==7
	}

	cases := []struct {
		name       string
		fibIfindex uint32
		fibVlanID  uint16
		want       string
	}{
		{
			// FibIfindex==0 + stale {0,vlan} entry: must fall through to the
			// egress zone's interface, NOT the stale name. RED on revert.
			name:       "fib0_stale_entry_falls_through_to_zone_iface",
			fibIfindex: 0,
			fibVlanID:  vlanID,
			want:       "ge-0-0-2",
		},
		{
			// Normal FibIfindex!=0 session: unchanged, resolves the FIB entry.
			name:       "fib_present_resolves_egress_entry",
			fibIfindex: 7,
			fibVlanID:  vlanID,
			want:       "ge-0-0-7-fib",
		},
	}

	key4 := dataplane.SessionKey{
		SrcIP:    [4]byte{198, 51, 100, 10},
		DstIP:    [4]byte{172, 16, 80, 8},
		SrcPort:  hostToNetwork16(54321),
		DstPort:  hostToNetwork16(443),
		Protocol: 6,
	}
	var src6, dst6 [16]byte
	copy(src6[:], net.ParseIP("2001:db8::10").To16())
	copy(dst6[:], net.ParseIP("2001:db8:80::8").To16())
	key6 := dataplane.SessionKeyV6{
		SrcIP:    src6,
		DstIP:    dst6,
		SrcPort:  hostToNetwork16(54321),
		DstPort:  hostToNetwork16(443),
		Protocol: 6,
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			oracle := restEgressOracle(tc.fibIfindex, tc.fibVlanID, egressZone, zoneNames, zoneIfaces, egressIfaces)
			if oracle != tc.want {
				t.Fatalf("oracle sanity: got %q want %q", oracle, tc.want)
			}

			val4 := dataplane.SessionValue{
				IngressZone: ingressZone,
				EgressZone:  egressZone,
				FibIfindex:  tc.fibIfindex,
				FibVlanID:   tc.fibVlanID,
			}
			se4 := sessionEntryV4(key4, val4, 0, zoneNames, map[uint32]string{}, zoneIfaces, egressIfaces, true)
			if se4.EgressInterface != tc.want {
				t.Errorf("v4 EgressInterface = %q, want %q", se4.EgressInterface, tc.want)
			}
			if se4.EgressInterface != oracle {
				t.Errorf("v4 EgressInterface = %q drifts from REST oracle %q", se4.EgressInterface, oracle)
			}

			val6 := dataplane.SessionValueV6{
				IngressZone: ingressZone,
				EgressZone:  egressZone,
				FibIfindex:  tc.fibIfindex,
				FibVlanID:   tc.fibVlanID,
			}
			se6 := sessionEntryV6(key6, val6, 0, zoneNames, map[uint32]string{}, zoneIfaces, egressIfaces, true)
			if se6.EgressInterface != tc.want {
				t.Errorf("v6 EgressInterface = %q, want %q", se6.EgressInterface, tc.want)
			}
			if se6.EgressInterface != oracle {
				t.Errorf("v6 EgressInterface = %q drifts from REST oracle %q", se6.EgressInterface, oracle)
			}
		})
	}
}
