package userspace

import (
	"testing"

	"github.com/cilium/ebpf"
)

// #13953: a LAND packet (src == dst) to a firewall-local address must be
// dropped at the shim on the session-miss local-destination arm, not passed
// to the kernel. On master this case returns XDP_PASS (2): the miss arm has
// no LAND check, and the Linux stack has no IPv6 LAND backstop, so the
// packet reaches local sockets. The #11087 drop exists only on the
// established PASS_TO_KERNEL arm.
//
// These cells run the retained XDP program itself through BPF_PROG_TEST_RUN
// (same harness as xdp_shim_dispatch_10864_test.go), so they exercise the
// lib.rs wiring, not a modelled predicate. The host-executed twin in
// userspace-dp tests_shim_land_13953.rs runs the exact `is_land` predicate.
func TestUserspaceXDPLandSessionMissDropped13953(t *testing.T) {
	local6 := [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	peer6 := [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}
	local4 := [4]byte{192, 0, 2, 1}
	peer4 := [4]byte{198, 51, 100, 1}

	cases := []struct {
		name       string
		packet     []byte
		seed       func(*testing.T, *ebpf.Collection)
		wantAction uint32
		wantStats  []string
	}{
		{
			name:   "IPv6 LAND to local address on session miss is dropped",
			packet: icmpv6TestPacket(local6, local6, 128),
			seed: func(t *testing.T, coll *ebpf.Collection) {
				updateUserspaceXDPTestLocalV6(t, coll, local6)
			},
			wantAction: xdpActionDrop,
			wantStats:  []string{"land_drop"},
		},
		{
			name:   "IPv4 LAND to local address on session miss is dropped",
			packet: ipv4TestPacket(local4, local4, 1, 8),
			seed: func(t *testing.T, coll *ebpf.Collection) {
				updateUserspaceXDPTestLocalV4(t, coll, local4)
			},
			wantAction: xdpActionDrop,
			wantStats:  []string{"land_drop"},
		},
		{
			name:   "IPv6 non-LAND to local address still reaches kernel",
			packet: icmpv6TestPacket(peer6, local6, 128),
			seed: func(t *testing.T, coll *ebpf.Collection) {
				updateUserspaceXDPTestLocalV6(t, coll, local6)
			},
			wantAction: xdpActionPass,
		},
		{
			name:   "IPv4 non-LAND to local address still reaches kernel",
			packet: ipv4TestPacket(peer4, local4, 1, 8),
			seed: func(t *testing.T, coll *ebpf.Collection) {
				updateUserspaceXDPTestLocalV4(t, coll, local4)
			},
			wantAction: xdpActionPass,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			coll := loadUserspaceXDPTestCollection(t)
			updateUserspaceXDPTestCtrl(t, coll, userspaceCtrlValue{
				Enabled:            1,
				MetadataVersion:    userspaceMetadataVersion,
				Workers:            1,
				QueueCount:         1,
				Flags:              0,
				HeartbeatTimeoutMS: userspaceHeartbeatTimeoutMS,
			})
			ifindex := userspaceXDPTestRunIfindex(t)
			updateUserspaceXDPTestIngress(t, coll, ifindex)
			updateUserspaceXDPTestBinding(t, coll, userspaceXDPTestRunBindingIndex(t, 0), userspaceBindingValue{
				Slot:  0,
				Flags: userspaceBindingReady,
			})
			updateUserspaceXDPTestHeartbeat(t, coll, 0)
			if tc.seed != nil {
				tc.seed(t, coll)
			}
			got := runUserspaceXDPTestPacket(t, coll, tc.packet)
			for _, stat := range tc.wantStats {
				assertUserspaceXDPDegradedPathStat(t, coll, stat)
			}
			if tc.wantAction == xdpActionDrop {
				assertUserspaceXDPDegradedPathStat(t, coll, "transit_drop")
				assertUserspaceXDPDegradedPathStatAbsent(t, coll, "pass_to_kernel")
			}
			if got != tc.wantAction {
				t.Fatalf("XDP action = %d, want %d", got, tc.wantAction)
			}
		})
	}
}

// #15789: the shim's LAND disposition follows the ingress zone's
// published ScreenProfile.land / alarm-without-drop. The zone is
// resolved through userspace_wg_ingress_zones (the same (ifindex, VLAN)
// resolver the WG steer uses) and the disposition read from
// userspace_land_screen. FAIL-ON-REVERT: restoring the #13953
// unconditional drop makes the audit and LAND-disabled-via-absent-zone
// rows RED (they return XDP_DROP instead of reaching the kernel).
func TestUserspaceXDPLandProfileGated15789(t *testing.T) {
	local6 := [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	const zoneID = uint16(4242)

	seedZone := func(t *testing.T, coll *ebpf.Collection, disposition uint8, publish bool) {
		t.Helper()
		updateUserspaceXDPTestLocalV6(t, coll, local6)
		updateUserspaceXDPTestMap(t, coll, mapNameUserspaceWgIngressZones, userspaceWGIngressZoneKey{
			Ifindex: userspaceXDPTestRunIfindex(t), VLANID: userspaceWGUnTaggedVLANID,
		}, zoneID)
		if publish {
			updateUserspaceXDPTestMap(t, coll, mapNameUserspaceLandScreen, zoneID, disposition)
		}
	}

	cases := []struct {
		name        string
		seed        func(*testing.T, *ebpf.Collection)
		wantAction  uint32
		wantStats   []string
		absentStats []string
	}{
		{
			name: "LAND enabled drops",
			seed: func(t *testing.T, coll *ebpf.Collection) {
				seedZone(t, coll, landScreenDrop, true)
			},
			wantAction:  xdpActionDrop,
			wantStats:   []string{"land_drop"},
			absentStats: []string{"pass_to_kernel", "land_alarm"},
		},
		{
			name: "LAND alarm-without-drop passes with land_alarm",
			seed: func(t *testing.T, coll *ebpf.Collection) {
				seedZone(t, coll, landScreenAlarm, true)
			},
			wantAction:  xdpActionPass,
			wantStats:   []string{"land_alarm"},
			absentStats: []string{"land_drop", "transit_drop"},
		},
		{
			name: "LAND disabled passes unscreened",
			seed: func(t *testing.T, coll *ebpf.Collection) {
				seedZone(t, coll, landScreenPass, true)
			},
			wantAction:  xdpActionPass,
			absentStats: []string{"land_drop", "land_alarm", "transit_drop"},
		},
		{
			name: "resolved zone with no land row passes as LAND-off",
			seed: func(t *testing.T, coll *ebpf.Collection) {
				// Resolved zone, absent row: the shim reads PASS (the
				// Go sync publishes explicit rows for screened zones;
				// absence under a resolved zone is the LAND-off shape).
				// Unresolved zones fail closed — covered by the
				// pre-existing TestUserspaceXDPLandSessionMissDropped13953,
				// which seeds no zone row at all.
				seedZone(t, coll, 0, false)
			},
			wantAction:  xdpActionPass,
			absentStats: []string{"land_drop", "land_alarm", "transit_drop"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			coll := loadUserspaceXDPTestCollection(t)
			updateUserspaceXDPTestCtrl(t, coll, userspaceCtrlValue{
				Enabled:            1,
				MetadataVersion:    userspaceMetadataVersion,
				Workers:            1,
				QueueCount:         1,
				Flags:              0,
				HeartbeatTimeoutMS: userspaceHeartbeatTimeoutMS,
			})
			ifindex := userspaceXDPTestRunIfindex(t)
			updateUserspaceXDPTestIngress(t, coll, ifindex)
			updateUserspaceXDPTestBinding(t, coll, userspaceXDPTestRunBindingIndex(t, 0), userspaceBindingValue{
				Slot:  0,
				Flags: userspaceBindingReady,
			})
			updateUserspaceXDPTestHeartbeat(t, coll, 0)
			tc.seed(t, coll)
			got := runUserspaceXDPTestPacket(t, coll, icmpv6TestPacket(local6, local6, 128))
			for _, stat := range tc.wantStats {
				assertUserspaceXDPDegradedPathStat(t, coll, stat)
			}
			for _, stat := range tc.absentStats {
				assertUserspaceXDPDegradedPathStatAbsent(t, coll, stat)
			}
			if got != tc.wantAction {
				t.Fatalf("XDP action = %d, want %d", got, tc.wantAction)
			}
		})
	}
}
