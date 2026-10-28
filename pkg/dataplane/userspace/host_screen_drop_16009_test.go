package userspace

import (
	"encoding/binary"
	"testing"

	"github.com/cilium/ebpf"
)

// #16009 decisive regression: a malformed packet to a firewall-local
// address on a screened untrust zone must drop at the shim with the
// host_screen_drop counter, not pass to the kernel. The transit twin
// (same shape, non-local destination) is the control: it must NOT
// take the host-screen drop (it falls through to the XSK redirect /
// degraded transit handling, where the worker screens it).
//
// These cells run the retained XDP program itself through
// BPF_PROG_TEST_RUN (same harness as land_drop_13953_test.go), so
// they exercise the lib.rs wiring, not a modelled predicate.
// FAIL-ON-REVERT: removing the shim's host_screen_gate makes every
// drop row below return XDP_PASS / redirect instead.
func TestUserspaceXDPHostScreenDropped16009(t *testing.T) {
	local4 := [4]byte{192, 0, 2, 1}
	peer4 := [4]byte{198, 51, 100, 1}
	remote4 := [4]byte{203, 0, 113, 7}
	local6 := [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	peer6 := [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}
	const zoneID = uint32(4243)

	seedZone := func(mask uint8, publish bool) func(*testing.T, *ebpf.Collection) {
		return func(t *testing.T, coll *ebpf.Collection) {
			t.Helper()
			updateUserspaceXDPTestLocalV4(t, coll, local4)
			updateUserspaceXDPTestLocalV6(t, coll, local6)
			updateUserspaceXDPTestMap(t, coll, mapNameUserspaceWgIngressZones, userspaceWGIngressZoneKey{
				Ifindex: userspaceXDPTestRunIfindex(t), VLANID: userspaceWGUnTaggedVLANID,
			}, zoneID)
			if publish {
				updateUserspaceXDPTestMap(t, coll, mapNameUserspaceHostScreen, zoneID, mask)
			}
		}
	}
	teardropMask := hostScreenMaskFor(false, true, false, false, false, false, false, false)

	cases := []struct {
		name        string
		packet      []byte
		seed        func(*testing.T, *ebpf.Collection)
		wantDrop    bool
		wantStats   []string
		absentStats []string
	}{
		{
			name:        "IPv4 teardrop fragment to local address is dropped",
			packet:      ipv4TeardropTestPacket(peer4, local4),
			seed:        seedZone(teardropMask, true),
			wantDrop:    true,
			wantStats:   []string{"host_screen_drop"},
			absentStats: []string{"pass_to_kernel", "host_screen_alarm"},
		},
		{
			name:        "IPv4 LSRR to local address is dropped",
			packet:      ipv4LSRRTestPacket(peer4, local4),
			seed:        seedZone(hostScreenMaskFor(false, false, false, false, true, false, false, false), true),
			wantDrop:    true,
			wantStats:   []string{"host_screen_drop"},
			absentStats: []string{"pass_to_kernel"},
		},
		{
			name:        "IPv6 ICMP fragment to local address is dropped",
			packet:      icmpv6FragmentTestPacket(peer6, local6),
			seed:        seedZone(hostScreenMaskFor(false, false, true, false, false, false, false, false), true),
			wantDrop:    true,
			wantStats:   []string{"host_screen_drop"},
			absentStats: []string{"pass_to_kernel"},
		},
		{
			name:        "teardrop under alarm-without-drop passes with host_screen_alarm",
			packet:      ipv4TeardropTestPacket(peer4, local4),
			seed:        seedZone(hostScreenMaskFor(false, true, false, false, false, false, false, true), true),
			wantStats:   []string{"host_screen_alarm"},
			absentStats: []string{"host_screen_drop", "transit_drop"},
		},
		{
			name:        "teardrop with check disabled for zone passes unscreened",
			packet:      ipv4TeardropTestPacket(peer4, local4),
			seed:        seedZone(hostScreenMaskFor(true, false, false, false, false, false, false, false), true),
			absentStats: []string{"host_screen_drop", "host_screen_alarm", "transit_drop"},
		},
		{
			name:        "clean packet to local address still reaches kernel",
			packet:      ipv4TestPacket(peer4, local4, 1, 8),
			seed:        seedZone(teardropMask, true),
			absentStats: []string{"host_screen_drop", "host_screen_alarm", "transit_drop"},
		},

		{
			name:        "IPv4 ping-of-death fragment to local address is dropped",
			packet:      ipv4PingDeathTestPacket(peer4, local4),
			seed:        seedZone(hostScreenMaskFor(true, false, false, false, false, false, false, false), true),
			wantDrop:    true,
			wantStats:   []string{"host_screen_drop"},
			absentStats: []string{"pass_to_kernel"},
		},
		{
			name:        "IPv4 SYN-frag to local address is dropped",
			packet:      ipv4SynFragTestPacket(peer4, local4),
			seed:        seedZone(hostScreenMaskFor(false, false, false, true, false, false, false, false), true),
			wantDrop:    true,
			wantStats:   []string{"host_screen_drop"},
			absentStats: []string{"pass_to_kernel"},
		},
		{
			name:        "TCP SYN+FIN to local address is dropped",
			packet:      tcpFlagsTestPacket(peer4, local4, 0x03, 443),
			seed:        seedZone(hostScreenMaskFor(false, false, false, false, false, true, false, false), true),
			wantDrop:    true,
			wantStats:   []string{"host_screen_drop"},
			absentStats: []string{"pass_to_kernel"},
		},
		{
			name:        "TCP no-flag to local address is dropped",
			packet:      tcpFlagsTestPacket(peer4, local4, 0x00, 443),
			seed:        seedZone(hostScreenMaskFor(false, false, false, false, false, false, true, false), true),
			wantDrop:    true,
			wantStats:   []string{"host_screen_drop"},
			absentStats: []string{"pass_to_kernel"},
		},
		{
			name:        "IPv6 RH0 to local address is dropped",
			packet:      ipv6RH0TestPacket(peer6, local6),
			seed:        seedZone(hostScreenMaskFor(false, false, false, false, true, false, false, false), true),
			wantDrop:    true,
			wantStats:   []string{"host_screen_drop"},
			absentStats: []string{"pass_to_kernel"},
		},
		{
			// Control: same teardrop shape to a NON-local (transit)
			// destination must not take the host-screen drop. Without
			// a live XSK binding it takes the degraded transit drop;
			// the worker screens the redirected twin.
			name:        "IPv4 teardrop fragment to transit address is not host-screen dropped",
			packet:      ipv4TeardropTestPacket(peer4, remote4),
			seed:        seedZone(teardropMask, true),
			wantStats:   []string{"transit_drop"},
			absentStats: []string{"host_screen_drop", "pass_to_kernel"},
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
			for _, stat := range tc.absentStats {
				assertUserspaceXDPDegradedPathStatAbsent(t, coll, stat)
			}
			if tc.wantDrop && got != xdpActionDrop {
				t.Fatalf("XDP action = %d, want XDP_DROP (%d)", got, xdpActionDrop)
			}
			if !tc.wantDrop && got == xdpActionDrop && tc.name == "clean packet to local address still reaches kernel" {
				t.Fatalf("XDP action = XDP_DROP, want kernel pass for clean local packet")
			}
		})
	}
}

// ipv4TeardropTestPacket builds a non-last first IPv4 fragment
// (MF=1, offset 0) whose 4-byte payload is not a multiple of 8 — the
// #16030 teardrop shape.
func ipv4TeardropTestPacket(src, dst [4]byte) []byte {
	packet := make([]byte, 14+20+4)
	copy(packet[0:6], []byte{0x02, 0, 0, 0, 0, 1})
	copy(packet[6:12], []byte{0x02, 0, 0, 0, 0, 2})
	binary.BigEndian.PutUint16(packet[12:14], 0x0800)
	ip := packet[14:34]
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], 24) // total: 20 header + 4 payload
	binary.BigEndian.PutUint16(ip[6:8], 0x2000)
	ip[8] = 64
	ip[9] = 17
	copy(ip[12:16], src[:])
	copy(ip[16:20], dst[:])
	return packet
}

// ipv4LSRRTestPacket builds an IPv4 TCP packet with IHL=6 carrying an
// LSRR (131) source-route option.
func ipv4LSRRTestPacket(src, dst [4]byte) []byte {
	packet := make([]byte, 14+24+20)
	copy(packet[0:6], []byte{0x02, 0, 0, 0, 0, 1})
	copy(packet[6:12], []byte{0x02, 0, 0, 0, 0, 2})
	binary.BigEndian.PutUint16(packet[12:14], 0x0800)
	ip := packet[14:38]
	ip[0] = 0x46
	binary.BigEndian.PutUint16(ip[2:4], 44)
	ip[8] = 64
	ip[9] = 6
	copy(ip[12:16], src[:])
	copy(ip[16:20], dst[:])
	ip[20] = 131 // LSRR
	ip[21] = 3   // opt len
	ip[22] = 4   // pointer
	ip[23] = 0   // route data pad
	tcp := packet[38:]
	binary.BigEndian.PutUint16(tcp[0:2], 12345)
	binary.BigEndian.PutUint16(tcp[2:4], 443)
	tcp[12] = 5 << 4
	tcp[13] = 0x10 // ACK (not SYN: keep syn-frag out of this cell)
	return packet
}

// icmpv6FragmentTestPacket builds an IPv6 packet whose first header
// is a Fragment header (non-first, offset 8 bytes) naming ICMPv6.
func icmpv6FragmentTestPacket(src, dst [16]byte) []byte {
	packet := make([]byte, 14+40+8+8)
	copy(packet[0:6], []byte{0x02, 0, 0, 0, 0, 1})
	copy(packet[6:12], []byte{0x02, 0, 0, 0, 0, 2})
	binary.BigEndian.PutUint16(packet[12:14], 0x86dd)
	ip := packet[14:54]
	ip[0] = 0x60
	binary.BigEndian.PutUint16(ip[4:6], 16)
	ip[6] = 44 // Fragment
	ip[7] = 255
	copy(ip[8:24], src[:])
	copy(ip[24:40], dst[:])
	frag := packet[54:62]
	frag[0] = 58 // ICMPv6
	binary.BigEndian.PutUint16(frag[2:4], 0x0008)
	return packet
}

// ipv4PingDeathTestPacket builds an IPv4 fragment at maximal offset
// whose offset+length exceeds 65535.
func ipv4PingDeathTestPacket(src, dst [4]byte) []byte {
	packet := make([]byte, 14+20+8)
	copy(packet[0:6], []byte{0x02, 0, 0, 0, 0, 1})
	copy(packet[6:12], []byte{0x02, 0, 0, 0, 0, 2})
	binary.BigEndian.PutUint16(packet[12:14], 0x0800)
	ip := packet[14:34]
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], 28)
	binary.BigEndian.PutUint16(ip[6:8], 0x1FFF)
	ip[8] = 64
	ip[9] = 17
	copy(ip[12:16], src[:])
	copy(ip[16:20], dst[:])
	return packet
}

// ipv4SynFragTestPacket builds a TCP SYN on a first fragment.
func ipv4SynFragTestPacket(src, dst [4]byte) []byte {
	packet := make([]byte, 14+20+20)
	copy(packet[0:6], []byte{0x02, 0, 0, 0, 0, 1})
	copy(packet[6:12], []byte{0x02, 0, 0, 0, 0, 2})
	binary.BigEndian.PutUint16(packet[12:14], 0x0800)
	ip := packet[14:34]
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], 40)
	binary.BigEndian.PutUint16(ip[6:8], 0x2000)
	ip[8] = 64
	ip[9] = 6
	copy(ip[12:16], src[:])
	copy(ip[16:20], dst[:])
	tcp := packet[34:]
	binary.BigEndian.PutUint16(tcp[0:2], 12345)
	binary.BigEndian.PutUint16(tcp[2:4], 443)
	tcp[12] = 5 << 4
	tcp[13] = 0x02 // SYN
	return packet
}

// tcpFlagsTestPacket builds a whole IPv4 TCP packet with the given
// flags byte to the given destination port.
func tcpFlagsTestPacket(src, dst [4]byte, flags byte, dstPort uint16) []byte {
	packet := make([]byte, 14+20+20)
	copy(packet[0:6], []byte{0x02, 0, 0, 0, 0, 1})
	copy(packet[6:12], []byte{0x02, 0, 0, 0, 0, 2})
	binary.BigEndian.PutUint16(packet[12:14], 0x0800)
	ip := packet[14:34]
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], 40)
	ip[8] = 64
	ip[9] = 6
	copy(ip[12:16], src[:])
	copy(ip[16:20], dst[:])
	tcp := packet[34:]
	binary.BigEndian.PutUint16(tcp[0:2], 12345)
	binary.BigEndian.PutUint16(tcp[2:4], dstPort)
	tcp[12] = 5 << 4
	tcp[13] = flags
	return packet
}

// ipv6RH0TestPacket builds an IPv6 packet with a Routing header of
// type 0 (RH0 source route) naming TCP.
func ipv6RH0TestPacket(src, dst [16]byte) []byte {
	packet := make([]byte, 14+40+8+20)
	copy(packet[0:6], []byte{0x02, 0, 0, 0, 0, 1})
	copy(packet[6:12], []byte{0x02, 0, 0, 0, 0, 2})
	binary.BigEndian.PutUint16(packet[12:14], 0x86dd)
	ip := packet[14:54]
	ip[0] = 0x60
	binary.BigEndian.PutUint16(ip[4:6], 28)
	ip[6] = 43 // Routing
	ip[7] = 64
	copy(ip[8:24], src[:])
	copy(ip[24:40], dst[:])
	rh := packet[54:62]
	rh[0] = 6 // TCP
	rh[1] = 0 // Hdr Ext Len
	rh[2] = 0 // Routing type 0
	rh[3] = 0
	tcp := packet[62:]
	binary.BigEndian.PutUint16(tcp[0:2], 12345)
	binary.BigEndian.PutUint16(tcp[2:4], 443)
	tcp[12] = 5 << 4
	tcp[13] = 0x10 // ACK
	return packet
}
