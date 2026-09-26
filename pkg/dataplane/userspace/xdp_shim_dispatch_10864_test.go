package userspace

import (
	"encoding/binary"
	"testing"

	"github.com/cilium/ebpf"
)

const (
	xdpDispatchNativeGREFlag10864   = uint32(4)
	xdpDispatchSessionPass10864     = uint8(2)
	xdpDispatchSessionRedirect10864 = uint8(1)
)

type xdpDispatchSessionKey10864 struct {
	AddrFamily uint8
	Protocol   uint8
	Pad        uint16
	SrcPort    uint16
	DstPort    uint16
	SrcAddr    [16]byte
	DstAddr    [16]byte
}

// These cases run the retained XDP program itself through BPF_PROG_TEST_RUN.
// The prior module tests executed GRE and early-filter predicates with
// caller-supplied inputs, leaving `lib.rs` dispatch wiring unchecked. These
// fixtures send real GRE and NDP frames through the retained object. Transit
// frames reach the XSK redirect; an empty XSK map records `redirect_err` and
// drops them, distinguishing that path from kernel delivery.
func TestUserspaceXDPDispatchUsesLibWiring10864(t *testing.T) {
	localOuter := [4]byte{192, 0, 2, 1}
	remoteOuter := [4]byte{203, 0, 113, 1}
	innerSource := [4]byte{10, 0, 0, 1}
	innerLocal := [4]byte{192, 0, 2, 99}
	innerTransit := [4]byte{198, 51, 100, 9}
	globalV6 := [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9}
	localV6 := [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10}
	globalV6Source := [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	multicastV6 := [16]byte{0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	ipv4Multicast := [4]byte{224, 0, 0, 1}
	broadcastV4 := [4]byte{255, 255, 255, 255}

	cases := []struct {
		name             string
		packet           []byte
		seed             func(*testing.T, *ebpf.Collection)
		disableNativeGRE bool
		wantAction       uint32
		wantStats        []string
		absentStats      []string
	}{
		{
			name: "GRE local outer and inner PASS reach kernel",
			packet: xdpDispatchGREIPv4Packet10864(remoteOuter, localOuter, innerSource, innerTransit,
				12345, 443),
			seed: func(t *testing.T, coll *ebpf.Collection) {
				updateUserspaceXDPTestLocalV4(t, coll, localOuter)
				seedXDPDispatchInnerSession10864(t, coll, innerSource, innerTransit,
					12345, 443, xdpDispatchSessionPass10864)
			},
			wantAction:  xdpActionPass,
			wantStats:   []string{"pass_to_kernel"},
			absentStats: []string{"redirect_err", "transit_drop"},
		},
		{
			name: "inner PASS session fixture matches a direct IPv4 tuple",
			packet: xdpDispatchIPv4TCPPacket10864(innerSource, innerTransit,
				12345, 443),
			seed: func(t *testing.T, coll *ebpf.Collection) {
				seedXDPDispatchInnerSession10864(t, coll, innerSource, innerTransit,
					12345, 443, xdpDispatchSessionPass10864)
			},
			wantAction:  xdpActionPass,
			wantStats:   []string{"pass_to_kernel"},
			absentStats: []string{"redirect_err", "transit_drop"},
		},
		{
			name:             "non-native GRE honors an outer PASS session",
			packet:           xdpDispatchGREIPv4Packet10864(localOuter, remoteOuter, innerSource, innerTransit, 12345, 443),
			disableNativeGRE: true,
			seed: func(t *testing.T, coll *ebpf.Collection) {
				seedXDPDispatchOuterGREPassSession10864(t, coll, localOuter, remoteOuter)
			},
			wantAction:  xdpActionPass,
			wantStats:   []string{"pass_to_kernel"},
			absentStats: []string{"redirect_err", "transit_drop"},
		},
		{
			name:   "healthy IPv4 local destination reaches kernel",
			packet: xdpDispatchIPv4TCPPacket10864(innerSource, localOuter, 12345, 443),
			seed: func(t *testing.T, coll *ebpf.Collection) {
				updateUserspaceXDPTestLocalV4(t, coll, localOuter)
			},
			wantAction:  xdpActionPass,
			absentStats: []string{"redirect_err", "transit_drop", "pass_to_kernel"},
		},
		{
			name: "GRE inner-local PASS cannot authorize a remote outer",
			packet: xdpDispatchGREIPv4Packet10864(localOuter, remoteOuter, innerSource, innerLocal,
				12345, 443),
			seed: func(t *testing.T, coll *ebpf.Collection) {
				updateUserspaceXDPTestLocalV4(t, coll, innerLocal)
				seedXDPDispatchInnerSession10864(t, coll, innerSource, innerLocal,
					12345, 443, xdpDispatchSessionPass10864)
				seedXDPDispatchOuterGREPassSession10864(t, coll, localOuter, remoteOuter)
			},
			wantAction:  xdpActionDrop,
			wantStats:   []string{"redirect_err", "transit_drop"},
			absentStats: []string{"pass_to_kernel"},
		},
		{
			name: "GRE inner REDIRECT stays on userspace path",
			packet: xdpDispatchGREIPv4Packet10864(remoteOuter, localOuter, innerSource, innerTransit,
				12345, 443),
			seed: func(t *testing.T, coll *ebpf.Collection) {
				updateUserspaceXDPTestLocalV4(t, coll, localOuter)
				seedXDPDispatchInnerSession10864(t, coll, innerSource, innerTransit,
					12345, 443, xdpDispatchSessionRedirect10864)
			},
			wantAction:  xdpActionDrop,
			wantStats:   []string{"redirect_err", "transit_drop"},
			absentStats: []string{"pass_to_kernel"},
		},
		{
			name:        "transit unicast NDP is adjudicated by userspace",
			packet:      icmpv6TestPacket(globalV6Source, globalV6, 135),
			wantAction:  xdpActionDrop,
			wantStats:   []string{"redirect_err", "transit_drop"},
			absentStats: []string{"early_filter", "pass_to_kernel"},
		},
		{
			name:        "multicast NDP still reaches kernel",
			packet:      icmpv6TestPacket(globalV6Source, multicastV6, 135),
			wantAction:  xdpActionPass,
			wantStats:   []string{"early_filter", "pass_to_kernel"},
			absentStats: []string{"redirect_err", "transit_drop"},
		},
		{
			name:   "unicast NDP to a local IPv6 address reaches kernel",
			packet: icmpv6TestPacket(globalV6Source, localV6, 135),
			seed: func(t *testing.T, coll *ebpf.Collection) {
				updateUserspaceXDPTestMap(t, coll, "userspace_local_v6", userspaceLocalV6Key{Addr: localV6}, uint8(1))
			},
			wantAction:  xdpActionPass,
			absentStats: []string{"early_filter", "redirect_err"},
		},
		{
			name:        "IPv4 multicast selects the IPv4 early filter",
			packet:      ipv4TestPacket([4]byte{198, 51, 100, 1}, ipv4Multicast, 17, 8),
			wantAction:  xdpActionPass,
			wantStats:   []string{"early_filter", "pass_to_kernel"},
			absentStats: []string{"redirect_err", "transit_drop"},
		},
		{
			name:        "IPv4 limited broadcast still passes early",
			packet:      ipv4TestPacket([4]byte{198, 51, 100, 1}, broadcastV4, 17, 8),
			wantAction:  xdpActionPass,
			wantStats:   []string{"early_filter", "pass_to_kernel"},
			absentStats: []string{"redirect_err", "transit_drop"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			coll := loadUserspaceXDPTestCollection(t)
			flags := xdpDispatchNativeGREFlag10864
			if tc.disableNativeGRE {
				flags = 0
			}
			updateUserspaceXDPTestCtrl(t, coll, userspaceCtrlValue{
				Enabled:            1,
				MetadataVersion:    userspaceMetadataVersion,
				Workers:            1,
				QueueCount:         1,
				Flags:              flags,
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
			if got != tc.wantAction {
				t.Fatalf("XDP action = %d, want %d", got, tc.wantAction)
			}
		})
	}
}

func seedXDPDispatchInnerSession10864(
	t *testing.T,
	coll *ebpf.Collection,
	src, dst [4]byte,
	srcPort, dstPort uint16,
	action uint8,
) {
	t.Helper()
	key := xdpDispatchSessionKey10864{
		AddrFamily: 2,
		Protocol:   6,
		SrcPort:    srcPort,
		DstPort:    dstPort,
	}
	copy(key.SrcAddr[:4], src[:])
	copy(key.DstAddr[:4], dst[:])
	updateUserspaceXDPTestMap(t, coll, "userspace_sessions", key, action)
}
func seedXDPDispatchOuterGREPassSession10864(
	t *testing.T,
	coll *ebpf.Collection,
	src, dst [4]byte,
) {
	t.Helper()
	key := xdpDispatchSessionKey10864{
		AddrFamily: 2,
		Protocol:   47,
	}
	copy(key.SrcAddr[:4], src[:])
	copy(key.DstAddr[:4], dst[:])
	updateUserspaceXDPTestMap(t, coll, "userspace_sessions", key, xdpDispatchSessionPass10864)
}

func xdpDispatchGREIPv4Packet10864(
	outerSrc, outerDst, innerSrc, innerDst [4]byte,
	srcPort, dstPort uint16,
) []byte {
	const ethernetLen, ipv4Len, greLen, tcpLen = 14, 20, 4, 20
	packet := make([]byte, ethernetLen+ipv4Len+greLen+ipv4Len+tcpLen)
	copy(packet[:6], []byte{0x02, 0, 0, 0, 0, 1})
	copy(packet[6:12], []byte{0x02, 0, 0, 0, 0, 2})
	binary.BigEndian.PutUint16(packet[12:14], 0x0800)

	outer := packet[ethernetLen : ethernetLen+ipv4Len]
	outer[0] = 0x45
	binary.BigEndian.PutUint16(outer[2:4], uint16(len(packet)-ethernetLen))
	outer[8] = 64
	outer[9] = 47
	copy(outer[12:16], outerSrc[:])
	copy(outer[16:20], outerDst[:])

	greOffset := ethernetLen + ipv4Len
	binary.BigEndian.PutUint16(packet[greOffset+2:greOffset+4], 0x0800)
	innerOffset := greOffset + greLen
	inner := packet[innerOffset : innerOffset+ipv4Len]
	inner[0] = 0x45
	binary.BigEndian.PutUint16(inner[2:4], uint16(ipv4Len+tcpLen))
	inner[8] = 64
	inner[9] = 6
	copy(inner[12:16], innerSrc[:])
	copy(inner[16:20], innerDst[:])

	tcp := packet[innerOffset+ipv4Len:]
	binary.BigEndian.PutUint16(tcp[0:2], srcPort)
	binary.BigEndian.PutUint16(tcp[2:4], dstPort)
	tcp[12] = 0x50
	tcp[13] = 0x02
	return packet
}
func xdpDispatchIPv4TCPPacket10864(
	src, dst [4]byte,
	srcPort, dstPort uint16,
) []byte {
	packet := ipv4TestPacket(src, dst, 6, 20)
	tcp := packet[34:]
	binary.BigEndian.PutUint16(tcp[0:2], srcPort)
	binary.BigEndian.PutUint16(tcp[2:4], dstPort)
	tcp[12] = 0x50
	tcp[13] = 0x02
	return packet
}
