package userspace

import (
	"encoding/binary"
	"testing"

	"github.com/cilium/ebpf"
)

func TestUserspaceXDPTaggedOnlyIngressIfindexes12055(t *testing.T) {
	base := []InterfaceSnapshot{
		{Name: "ge-0/0/1", Ifindex: 10, IsUnit: false},
		{Name: "ge-0/0/1.50", Ifindex: 11, ParentIfindex: 10, ParentLinuxName: "ge-0-0-1", LinuxName: "ge-0-0-1.50", VLANID: 50, IsUnit: true},
		{Name: "ge-0/0/1.80", Ifindex: 12, ParentIfindex: 10, ParentLinuxName: "ge-0-0-1", LinuxName: "ge-0-0-1.80", VLANID: 80, IsUnit: true},
	}
	clone := func(rows []InterfaceSnapshot) []InterfaceSnapshot {
		return append([]InterfaceSnapshot(nil), rows...)
	}
	tests := []struct {
		name string
		rows []InterfaceSnapshot
		want map[uint32]bool
	}{
		{
			name: "tagged-only parent and child ifindexes",
			rows: clone(base),
			want: map[uint32]bool{10: true, 11: true, 12: true},
		},
		{
			name: "explicit untagged unit zero owns the parent only",
			rows: append(clone(base), InterfaceSnapshot{
				Name: "ge-0/0/1.0", Ifindex: 10, LinuxName: "ge-0-0-1", VLANID: 0, IsUnit: true,
			}),
			want: map[uint32]bool{11: true, 12: true},
		},
		{
			name: "resolved native vlan owns parent but child remains tagged-only",
			rows: func() []InterfaceSnapshot {
				rows := clone(base)
				rows[0].NativeVLANID = 50
				return rows
			}(),
			want: map[uint32]bool{11: true, 12: true},
		},
		{
			name: "unresolved native vlan keeps parent tagged-only",
			rows: func() []InterfaceSnapshot {
				rows := clone(base)
				rows[0].NativeVLANID = 99
				return rows
			}(),
			want: map[uint32]bool{10: true, 11: true, 12: true},
		},
		{
			name: "ambiguous native selection keeps parent tagged-only",
			rows: func() []InterfaceSnapshot {
				rows := clone(base)
				rows = append(rows, InterfaceSnapshot{Name: "ge-alias", Ifindex: 10, NativeVLANID: 50})
				rows[0].NativeVLANID = 80
				return rows
			}(),
			want: map[uint32]bool{10: true, 11: true, 12: true},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := buildUserspaceTaggedOnlyIngressIfindexes(&ConfigSnapshot{Interfaces: tc.rows})
			if len(got) != len(tc.want) {
				t.Fatalf("tagged-only ifindexes = %v, want %v", got, tc.want)
			}
			for ifindex := range got {
				if !tc.want[ifindex] {
					t.Errorf("unexpected tagged-only ifindex %d; want %v", ifindex, tc.want)
				}
			}
			for ifindex := range tc.want {
				if _, ok := got[ifindex]; !ok {
					t.Errorf("tagged-only ifindex %d missing; got %v", ifindex, got)
				}
			}
		})
	}
}

func TestUserspaceXDPTaggedOnlyIngressMapPublishesFlag12055(t *testing.T) {
	m, ifaceMap := newIngressManager(t, ebpf.Hash, 32)
	snapshot := &ConfigSnapshot{Interfaces: []InterfaceSnapshot{
		{Name: "ge-0/0/1", LinuxName: "ge-0-0-1", Zone: "wan", Ifindex: 10},
		{Name: "ge-0/0/1.50", LinuxName: "ge-0-0-1.50", ParentLinuxName: "ge-0-0-1", Zone: "wan", Ifindex: 11, ParentIfindex: 10, VLANID: 50, IsUnit: true},
		{Name: "ge-0/0/1.80", LinuxName: "ge-0-0-1.80", ParentLinuxName: "ge-0-0-1", Zone: "wan", Ifindex: 12, ParentIfindex: 10, VLANID: 80, IsUnit: true},
		{Name: "ge-0/0/2", LinuxName: "ge-0-0-2", Zone: "lan", Ifindex: 20},
	}}
	if err := m.syncIngressIfaceMapLocked(snapshot); err != nil {
		t.Fatalf("syncIngressIfaceMapLocked: %v", err)
	}
	for ifindex, want := range map[uint32]uint8{
		10: userspaceIngressIfaceFlagAdjudicated | userspaceIngressIfaceFlagTaggedOnly,
		11: userspaceIngressIfaceFlagAdjudicated | userspaceIngressIfaceFlagTaggedOnly,
		12: userspaceIngressIfaceFlagAdjudicated | userspaceIngressIfaceFlagTaggedOnly,
		20: userspaceIngressIfaceFlagAdjudicated,
	} {
		var got uint8
		if err := ifaceMap.Lookup(ifindex, &got); err != nil {
			t.Fatalf("lookup userspace_ingress_ifaces[%d]: %v", ifindex, err)
		}
		if got != want {
			t.Errorf("userspace_ingress_ifaces[%d] = %#02x, want %#02x", ifindex, got, want)
		}
	}
}

func TestUserspaceXDPTaggedOnlyVID0LocalDropsAndControls12055(t *testing.T) {
	localV4 := [4]byte{192, 0, 2, 1}
	localV6 := [16]byte{0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	srcV4 := [4]byte{198, 51, 100, 10}
	srcV6 := [16]byte{0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10}
	tests := []struct {
		name         string
		flags        uint8
		packet       func() []byte
		localV4      bool
		localV6      bool
		ctrlDisabled bool
		wantAction   uint32
		wantTagged   bool
	}{
		{
			name:    "untagged local ipv4 drops",
			flags:   userspaceIngressIfaceFlagAdjudicated | userspaceIngressIfaceFlagTaggedOnly,
			packet:  func() []byte { return udpIPv4TestPacket(srcV4, localV4) },
			localV4: true, wantAction: xdpActionDrop, wantTagged: true,
		},
		{
			name:  "priority-tagged local ipv4 drops",
			flags: userspaceIngressIfaceFlagAdjudicated | userspaceIngressIfaceFlagTaggedOnly,
			packet: func() []byte {
				pkt := singleTagIPv4UDP(0x8100, srcV4, localV4)
				binary.BigEndian.PutUint16(pkt[14:16], 0x6000)
				return pkt
			},
			localV4: true, wantAction: xdpActionDrop, wantTagged: true,
		},
		{
			name:         "untagged local ipv4 drops while ctrl disabled",
			flags:        userspaceIngressIfaceFlagAdjudicated | userspaceIngressIfaceFlagTaggedOnly,
			packet:       func() []byte { return udpIPv4TestPacket(srcV4, localV4) },
			localV4:      true,
			ctrlDisabled: true,
			wantAction:   xdpActionDrop,
			wantTagged:   true,
		},
		{
			name:    "untagged local ipv6 drops",
			flags:   userspaceIngressIfaceFlagAdjudicated | userspaceIngressIfaceFlagTaggedOnly,
			packet:  func() []byte { return udpIPv6TestPacket(srcV6, localV6) },
			localV6: true, wantAction: xdpActionDrop, wantTagged: true,
		},
		{
			name:    "tagged local ipv4 remains local",
			flags:   userspaceIngressIfaceFlagAdjudicated | userspaceIngressIfaceFlagTaggedOnly,
			packet:  func() []byte { return singleTagIPv4UDP(0x8100, srcV4, localV4) },
			localV4: true, wantAction: xdpActionPass,
		},
		{
			name:    "untagged local ipv4 on ordinary ingress remains local",
			flags:   userspaceIngressIfaceFlagAdjudicated,
			packet:  func() []byte { return udpIPv4TestPacket(srcV4, localV4) },
			localV4: true, wantAction: xdpActionPass,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			coll := loadUserspaceXDPTestCollection(t)
			enabled := uint32(1)
			if tc.ctrlDisabled {
				enabled = 0
			}
			updateUserspaceXDPTestCtrl(t, coll, userspaceCtrlValue{
				Enabled:            enabled,
				MetadataVersion:    userspaceMetadataVersion,
				Workers:            1,
				QueueCount:         1,
				HeartbeatTimeoutMS: userspaceHeartbeatTimeoutMS,
			})
			ifindex := userspaceXDPTestRunIfindex(t)
			updateUserspaceXDPTestMap(t, coll, mapNameUserspaceIngressIfaces, ifindex, tc.flags)
			updateUserspaceXDPTestBinding(t, coll, userspaceXDPTestRunBindingIndex(t, 0), userspaceBindingValue{
				Slot: 0, Flags: userspaceBindingReady,
			})
			updateUserspaceXDPTestHeartbeat(t, coll, 0)
			if tc.localV4 {
				updateUserspaceXDPTestLocalV4(t, coll, localV4)
			}
			if tc.localV6 {
				updateUserspaceXDPTestLocalV6(t, coll, localV6)
			}
			ret := runUserspaceXDPTestPacket(t, coll, tc.packet())
			if ret != tc.wantAction {
				t.Fatalf("action = %d, want %d", ret, tc.wantAction)
			}
			if tc.wantTagged {
				assertUserspaceXDPDegradedPathStat(t, coll, "tagged_only_local_drop")
				assertUserspaceXDPDegradedPathStat(t, coll, "transit_drop")
				assertUserspaceXDPDegradedPathStatAbsent(t, coll, "pass_to_kernel")
			} else {
				assertUserspaceXDPDegradedPathStatAbsent(t, coll, "tagged_only_local_drop")
				assertUserspaceXDPDegradedPathStatAbsent(t, coll, "transit_drop")
				assertUserspaceXDPDegradedPathStatAbsent(t, coll, "pass_to_kernel")
			}
		})
	}
}

func udpIPv6TestPacket(src, dst [16]byte) []byte {
	packet := make([]byte, 14+40+8)
	copy(packet[0:6], []byte{0x02, 0, 0, 0, 0, 1})
	copy(packet[6:12], []byte{0x02, 0, 0, 0, 0, 2})
	binary.BigEndian.PutUint16(packet[12:14], 0x86dd)
	ip := packet[14:54]
	ip[0] = 0x60
	binary.BigEndian.PutUint16(ip[4:6], 8)
	ip[6] = 17
	ip[7] = 64
	copy(ip[8:24], src[:])
	copy(ip[24:40], dst[:])
	udp := packet[54:]
	binary.BigEndian.PutUint16(udp[0:2], 12345)
	binary.BigEndian.PutUint16(udp[2:4], 443)
	binary.BigEndian.PutUint16(udp[4:6], 8)
	return packet
}
