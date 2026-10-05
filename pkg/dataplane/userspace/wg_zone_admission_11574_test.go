package userspace

import (
	"encoding/binary"
	"errors"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

var wgAdmissionTestAddress = [4]byte{198, 51, 100, 1}

func wgAdmissionTestSnapshot(outerZone, tunnelZone string) *ConfigSnapshot {
	return &ConfigSnapshot{
		ZoneSetValidated: true,
		Zones: []ZoneSnapshot{
			{Name: "lan", ID: 1},
			{Name: "wan", ID: 2},
		},
		Interfaces: []InterfaceSnapshot{
			{
				Name: "lan0", Zone: "lan", Ifindex: 10,
				Addresses: []InterfaceAddressSnapshot{{Family: "inet", Address: "192.0.2.1/24"}},
			},
			{
				Name: "wan0", Zone: outerZone, Ifindex: 20,
				Addresses: []InterfaceAddressSnapshot{{Family: "inet", Address: "198.51.100.1/24"}},
			},
		},
		TunnelEndpoints: []TunnelEndpointSnapshot{{
			Mode: "wireguard", Zone: tunnelZone, Source: "198.51.100.1", WgListenPort: 51820,
		}},
		WgSteeredListenPorts: []uint16{51820},
	}
}

func wgAdmissionTestKey(zoneID uint16, address [4]byte) userspaceWGAdmissionKey {
	key := userspaceWGAdmissionKey{ZoneID: zoneID, Port: 51820, AddrFamily: 2}
	copy(key.Addr[:4], address[:])
	return key
}

func TestBuildUserspaceWGZoneAdmissionRequiresSameUniqueZone11574(t *testing.T) {
	snapshot := wgAdmissionTestSnapshot("wan", "lan")
	plan, err := buildUserspaceWGZoneMaps(snapshot)
	if err != nil {
		t.Fatalf("build zone maps: %v", err)
	}
	if got := plan.admission[wgAdmissionTestKey(2, wgAdmissionTestAddress)]; got != 1 {
		t.Fatalf("same-zone local WG listener admission = %d, want 1", got)
	}
	if _, ok := plan.admission[wgAdmissionTestKey(1, wgAdmissionTestAddress)]; ok {
		t.Fatal("destination owned by wan was admitted to the lan zone")
	}
	if _, ok := plan.admission[wgAdmissionTestKey(2, [4]byte{192, 0, 2, 1})]; ok {
		t.Fatal("lan destination was admitted to the wan WG listener")
	}

	ambiguous := wgAdmissionTestSnapshot("wan", "lan")
	ambiguous.Interfaces = append(ambiguous.Interfaces, InterfaceSnapshot{
		Name: "lan1", Zone: "lan", Ifindex: 30,
		Addresses: []InterfaceAddressSnapshot{{Family: "inet", Address: "198.51.100.1/24"}},
	})
	ambiguousPlan, err := buildUserspaceWGZoneMaps(ambiguous)
	if err != nil {
		t.Fatalf("build ambiguous zone maps: %v", err)
	}
	if _, ok := ambiguousPlan.admission[wgAdmissionTestKey(2, wgAdmissionTestAddress)]; ok {
		t.Fatal("address with cross-zone duplicate owners retained WG admission")
	}
}

func TestSyncUserspaceWGZoneMapsRemovesStaleSnapshotAuthority11574(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("RemoveMemlock: %v", err)
	}
	m := New()
	injectUserspaceBootstrapMaps(t, m)
	ingressMap, err := ebpf.NewMap(&ebpf.MapSpec{
		Type: ebpf.Hash, KeySize: 8, ValueSize: 2,
		MaxEntries: userspaceWGIngressZoneMapCapacity,
	})
	if err != nil {
		skipIfBPFMapUnavailable(t, "new userspace_wg_ingress_zones map", err)
	}
	t.Cleanup(func() { ingressMap.Close() })
	admissionMap, err := ebpf.NewMap(&ebpf.MapSpec{
		Type: ebpf.Hash, KeySize: uint32(binary.Size(userspaceWGAdmissionKey{})), ValueSize: 1,
		MaxEntries: userspaceWGAdmissionMapCapacity,
	})
	if err != nil {
		skipIfBPFMapUnavailable(t, "new userspace_wg_zone_admission map", err)
	}
	t.Cleanup(func() { admissionMap.Close() })
	injectShimMap(t, m.bpfShim, mapNameUserspaceWgIngressZones, ingressMap)
	injectShimMap(t, m.bpfShim, mapNameUserspaceWgZoneAdmission, admissionMap)

	before := wgAdmissionTestSnapshot("wan", "lan")
	if err := m.syncUserspaceClassifierMapsLocked(before); err != nil {
		t.Fatalf("sync initial classifier snapshot: %v", err)
	}
	oldIngress := userspaceWGIngressZoneKey{Ifindex: 20, VLANID: userspaceWGUnTaggedVLANID}
	oldAdmission := wgAdmissionTestKey(2, wgAdmissionTestAddress)
	var zone uint16
	if err := ingressMap.Lookup(oldIngress, &zone); err != nil || zone != 2 {
		t.Fatalf("initial ingress zone = %d, err=%v; want zone 2", zone, err)
	}
	var admitted uint8
	if err := admissionMap.Lookup(oldAdmission, &admitted); err != nil || admitted != 1 {
		t.Fatalf("initial admission = %d, err=%v; want admitted", admitted, err)
	}

	after := wgAdmissionTestSnapshot("lan", "lan")
	if err := m.syncUserspaceClassifierMapsLocked(after); err != nil {
		t.Fatalf("sync rebound classifier snapshot: %v", err)
	}
	if err := ingressMap.Lookup(oldIngress, &zone); err != nil || zone != 1 {
		t.Fatalf("rebound ingress zone = %d, err=%v; want zone 1", zone, err)
	}
	if err := admissionMap.Lookup(oldAdmission, &admitted); !errors.Is(err, ebpf.ErrKeyNotExist) {
		t.Fatalf("stale zone-2 WG admission lookup err=%v, want ErrKeyNotExist", err)
	}
	newAdmission := wgAdmissionTestKey(1, wgAdmissionTestAddress)
	if err := admissionMap.Lookup(newAdmission, &admitted); err != nil || admitted != 1 {
		t.Fatalf("new zone-1 admission = %d, err=%v; want admitted", admitted, err)
	}
}

func TestUserspaceXDPWireGuardZoneGate11574(t *testing.T) {
	const (
		zoneOne = uint16(1)
		zoneTwo = uint16(2)
	)
	for _, tc := range []struct {
		name          string
		arrivalZone   uint16
		admissionZone uint16
		wantAction    uint32
		wantRedirect  bool
	}{
		{name: "cross-zone returns to kernel", arrivalZone: zoneOne, admissionZone: zoneTwo, wantAction: xdpActionPass},
		{name: "same-zone reaches worker redirect", arrivalZone: zoneTwo, admissionZone: zoneTwo, wantAction: xdpActionDrop, wantRedirect: true},
		{name: "ambiguous ingress is denied", arrivalZone: 0, admissionZone: zoneTwo, wantAction: xdpActionPass},
	} {
		t.Run(tc.name, func(t *testing.T) {
			coll := loadUserspaceXDPTestCollection(t)
			ifindex := userspaceXDPTestRunIfindex(t)
			bindingIndex := userspaceXDPTestRunBindingIndex(t, 0)
			ctrl := userspaceCtrlValue{
				Enabled: 1, MetadataVersion: userspaceMetadataVersion, Workers: 1, QueueCount: 1,
				Flags: userspaceCtrlFlagWgRx, WgPortCount: 1, HeartbeatTimeoutMS: userspaceHeartbeatTimeoutMS,
			}
			ctrl.WgPorts[0] = 51820
			updateUserspaceXDPTestCtrl(t, coll, ctrl)
			updateUserspaceXDPTestIngress(t, coll, ifindex)
			updateUserspaceXDPTestBinding(t, coll, bindingIndex, userspaceBindingValue{Slot: 0, Flags: userspaceBindingReady})
			updateUserspaceXDPTestHeartbeat(t, coll, 0)
			updateUserspaceXDPTestLocalV4(t, coll, wgAdmissionTestAddress)
			updateUserspaceXDPTestMap(t, coll, "userspace_wg_ingress_zones", userspaceWGIngressZoneKey{
				Ifindex: ifindex, VLANID: userspaceWGUnTaggedVLANID,
			}, tc.arrivalZone)
			updateUserspaceXDPTestMap(t, coll, "userspace_wg_zone_admission", wgAdmissionTestKey(tc.admissionZone, wgAdmissionTestAddress), uint8(1))

			packet := ipv4TestPacket([4]byte{203, 0, 113, 9}, wgAdmissionTestAddress, 17, 24)
			binary.BigEndian.PutUint16(packet[36:38], 51820)
			packet[42] = 4 // WireGuard transport-data record.
			if got := runUserspaceXDPTestPacket(t, coll, packet); got != tc.wantAction {
				t.Fatalf("XDP action = %d, want %d", got, tc.wantAction)
			}
			redirectErrs := userspaceXDPDegradedPathStat(t, coll, "redirect_err")
			if tc.wantRedirect && redirectErrs == 0 {
				t.Fatal("same-zone admission did not reach the worker redirect attempt")
			}
			if !tc.wantRedirect && redirectErrs != 0 {
				t.Fatalf("denied WG record reached worker redirect path %d times", redirectErrs)
			}
		})
	}
}
func TestBuildUserspaceWGZoneAdmissionIncludesInterfaceSNATAddress11574(t *testing.T) {
	snapshot := wgAdmissionTestSnapshot("wan", "lan")
	snapshot.SourceNAT = []SourceNATRuleSnapshot{{
		ToZone:        "wan",
		InterfaceMode: true,
	}}
	plan, err := buildUserspaceWGZoneMaps(snapshot)
	if err != nil {
		t.Fatalf("build zone maps with interface SNAT: %v", err)
	}
	if got := plan.admission[wgAdmissionTestKey(2, wgAdmissionTestAddress)]; got != 1 {
		t.Fatalf("primary WAN address with active interface SNAT admission = %d, want 1", got)
	}
	if _, ok := plan.admission[wgAdmissionTestKey(1, wgAdmissionTestAddress)]; ok {
		t.Fatal("interface-SNAT destination owned by wan was admitted to the lan zone")
	}
}

func TestUserspaceXDPWireGuardSNATControlSteering12119(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("RemoveMemlock: %v", err)
	}
	for _, tc := range []struct {
		name              string
		arrivalZone       uint16
		ownerZone         uint16
		hasOwnerAdmission bool
		interfaceSNAT     bool
		wantAction        uint32
	}{
		{name: "same-zone SNAT listener handshake reaches kernel", arrivalZone: 2, ownerZone: 2, hasOwnerAdmission: true, interfaceSNAT: true, wantAction: xdpActionPass},
		{name: "wrong-zone SNAT listener handshake does not reach kernel", arrivalZone: 1, ownerZone: 2, hasOwnerAdmission: true, interfaceSNAT: true, wantAction: xdpActionDrop},
		{name: "transit handshake on listener port does not reach kernel", arrivalZone: 2, ownerZone: 2, wantAction: xdpActionDrop},
	} {
		t.Run(tc.name, func(t *testing.T) {
			coll := loadUserspaceXDPTestCollection(t)
			ifindex := userspaceXDPTestRunIfindex(t)
			bindingIndex := userspaceXDPTestRunBindingIndex(t, 0)
			ctrl := userspaceCtrlValue{
				Enabled: 1, MetadataVersion: userspaceMetadataVersion, Workers: 1, QueueCount: 1,
				Flags: userspaceCtrlFlagWgRx, WgPortCount: 1, HeartbeatTimeoutMS: userspaceHeartbeatTimeoutMS,
			}
			ctrl.WgPorts[0] = 51820
			updateUserspaceXDPTestCtrl(t, coll, ctrl)
			updateUserspaceXDPTestIngress(t, coll, ifindex)
			updateUserspaceXDPTestBinding(t, coll, bindingIndex, userspaceBindingValue{Slot: 0, Flags: userspaceBindingReady})
			updateUserspaceXDPTestHeartbeat(t, coll, 0)
			if tc.interfaceSNAT {
				updateUserspaceXDPTestInterfaceNATV4(t, coll, wgAdmissionTestAddress)
			}
			updateUserspaceXDPTestMap(t, coll, "userspace_wg_ingress_zones", userspaceWGIngressZoneKey{
				Ifindex: ifindex, VLANID: userspaceWGUnTaggedVLANID,
			}, tc.arrivalZone)
			if tc.hasOwnerAdmission {
				updateUserspaceXDPTestMap(t, coll, "userspace_wg_zone_admission", wgAdmissionTestKey(tc.ownerZone, wgAdmissionTestAddress), uint8(1))
			}

			packet := ipv4TestPacket([4]byte{203, 0, 113, 9}, wgAdmissionTestAddress, 17, 24)
			binary.BigEndian.PutUint16(packet[36:38], 51820)
			packet[42] = 1 // WireGuard initiation: it belongs at the kernel socket.
			if got := runUserspaceXDPTestPacket(t, coll, packet); got != tc.wantAction {
				t.Fatalf("XDP action = %d, want %d", got, tc.wantAction)
			}
		})
	}
}

// A live interface-SNAT session owns replies even when their source port is a
// configured WireGuard listen port. This is the return path for LAN WireGuard
// clients whose handshake response arrives at WAN:51820.
func TestUserspaceXDPWireGuardSNATSessionRedirectsLANHandshakeReply12119(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("RemoveMemlock: %v", err)
	}
	for _, tc := range []struct {
		name       string
		payloadLen int
		wgType     byte
	}{
		{name: "WireGuard type-2 handshake response", payloadLen: 100, wgType: 2},
		{name: "other UDP on live tuple", payloadLen: 9, wgType: 0xAA},
	} {
		t.Run(tc.name, func(t *testing.T) {
			coll := loadUserspaceXDPTestCollection(t)
			ifindex := userspaceXDPTestRunIfindex(t)
			bindingIndex := userspaceXDPTestRunBindingIndex(t, 0)
			ctrl := userspaceCtrlValue{
				Enabled: 1, MetadataVersion: userspaceMetadataVersion, Workers: 1, QueueCount: 1,
				Flags: userspaceCtrlFlagWgRx, WgPortCount: 1, HeartbeatTimeoutMS: userspaceHeartbeatTimeoutMS,
			}
			ctrl.WgPorts[0] = 51820
			updateUserspaceXDPTestCtrl(t, coll, ctrl)
			updateUserspaceXDPTestIngress(t, coll, ifindex)
			updateUserspaceXDPTestBinding(t, coll, bindingIndex, userspaceBindingValue{Slot: 0, Flags: userspaceBindingReady})
			updateUserspaceXDPTestHeartbeat(t, coll, 0)
			updateUserspaceXDPTestInterfaceNATV4(t, coll, wgAdmissionTestAddress)
			updateUserspaceXDPTestMap(t, coll, "userspace_wg_ingress_zones", userspaceWGIngressZoneKey{
				Ifindex: ifindex, VLANID: userspaceWGUnTaggedVLANID,
			}, uint16(2))
			updateUserspaceXDPTestMap(t, coll, "userspace_wg_zone_admission", wgAdmissionTestKey(2, wgAdmissionTestAddress), uint8(1))

			// A LAN client's source port is preserved by interface SNAT. Its
			// handshake response therefore arrives server:51820 -> WAN:51820.
			session := xdpDispatchSessionKey10864{
				AddrFamily: 2, Protocol: 17, SrcPort: 51820, DstPort: 51820,
			}
			copy(session.SrcAddr[:4], []byte{203, 0, 113, 9})
			copy(session.DstAddr[:4], wgAdmissionTestAddress[:])
			updateUserspaceXDPTestMap(t, coll, "userspace_sessions", session, xdpDispatchSessionRedirect10864)

			packet := ipv4TestPacket([4]byte{203, 0, 113, 9}, wgAdmissionTestAddress, 17, tc.payloadLen)
			binary.BigEndian.PutUint16(packet[34:36], 51820)
			binary.BigEndian.PutUint16(packet[36:38], 51820)
			packet[42] = tc.wgType
			if got := runUserspaceXDPTestPacket(t, coll, packet); got != xdpActionDrop {
				t.Fatalf("live SNAT session reply XDP action = %d, want failed worker redirect (XDP_DROP=%d), not kernel delivery",
					got, xdpActionDrop)
			}
			assertUserspaceXDPDegradedPathStat(t, coll, "redirect_err")
			assertUserspaceXDPDegradedPathStatAbsent(t, coll, "pass_to_kernel")
		})
	}
}
