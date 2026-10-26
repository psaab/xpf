package userspace

import (
	"bytes"
	"encoding/binary"
	"errors"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
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

func wgAdmissionTestKey(zoneID uint32, address [4]byte) userspaceWGAdmissionKey {
	key := userspaceWGAdmissionKey{ZoneID: zoneID, Port: 51820, AddrFamily: 2}
	copy(key.Addr[:4], address[:])
	return key
}

func TestWGZoneMapLayoutsMatchRust17996(t *testing.T) {
	if got := binary.Size(userspaceWGIngressZoneKey{}); got != 8 {
		t.Fatalf("Go WG ingress key size = %d, want 8", got)
	}
	if got := binary.Size(uint32(0)); got != 4 {
		t.Fatalf("Go WG ingress value size = %d, want 4", got)
	}
	if got := binary.Size(userspaceWGAdmissionKey{}); got != 28 {
		t.Fatalf("Go WG admission key size = %d, want 28", got)
	}
	if got := binary.Size(uint8(0)); got != 1 {
		t.Fatalf("Go WG admission value size = %d, want 1", got)
	}
	if got := binary.Size(uint32(0)); got != 4 {
		t.Fatalf("Go LAND-screen key size = %d, want 4", got)
	}
	plan, err := buildUserspaceWGZoneMaps(nil)
	if err != nil {
		t.Fatalf("build empty WG zone maps: %v", err)
	}
	if got := reflect.TypeOf(plan.ingress).Elem(); got != reflect.TypeOf(uint32(0)) {
		t.Fatalf("Go WG ingress map value type = %v, want uint32", got)
	}
	if got := reflect.TypeOf(plan.admission).Key().Field(0).Type; got != reflect.TypeOf(uint32(0)) {
		t.Fatalf("Go WG admission zone ID type = %v, want uint32", got)
	}
	if got := reflect.TypeOf(plan.admission).Elem(); got != reflect.TypeOf(uint8(0)) {
		t.Fatalf("Go WG admission map value type = %v, want uint8", got)
	}
	land := buildUserspaceLandScreenEntries(nil)
	if got := reflect.TypeOf(land).Key(); got != reflect.TypeOf(uint32(0)) {
		t.Fatalf("Go LAND-screen key type = %v, want uint32", got)
	}
	if got := reflect.TypeOf(land).Elem(); got != reflect.TypeOf(uint8(0)) {
		t.Fatalf("Go LAND-screen value type = %v, want uint8", got)
	}

	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "userspace-xdp", "src", "lib.rs"))
	if err != nil {
		t.Fatalf("read Rust shim source: %v", err)
	}
	src := string(raw)
	rustFields := func(name string) []string {
		t.Helper()
		marker := "struct " + name + " {"
		start := strings.Index(src, marker)
		if start < 0 {
			t.Fatalf("Rust struct %s not found", name)
		}
		block := src[start+len(marker):]
		end := strings.Index(block, "\n}")
		if end < 0 {
			t.Fatalf("Rust struct %s has no closing brace", name)
		}
		var fields []string
		for _, line := range strings.Split(block[:end], "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "//") {
				continue
			}
			fields = append(fields, strings.TrimSuffix(line, ","))
		}
		return fields
	}
	for _, tc := range []struct {
		name string
		want []string
	}{
		{name: "UserspaceWgIngressZoneKey", want: []string{
			"ifindex: u32", "vlan_id: u16", "reserved: u16",
		}},
		{name: "UserspaceWgAdmissionKey", want: []string{
			"zone_id: u32", "port: u16", "addr_family: u8", "pad: [u8; 3]",
			"addr: [u8; 16]", "reserved: [u8; 2]",
		}},
	} {
		if got := rustFields(tc.name); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("Rust %s fields = %q, want %q", tc.name, got, tc.want)
		}
	}
	for _, want := range []string{
		"static USERSPACE_WG_INGRESS_ZONES: HashMap<UserspaceWgIngressZoneKey, u32>",
		"static USERSPACE_WG_ZONE_ADMISSION: HashMap<UserspaceWgAdmissionKey, u8>",
		"static USERSPACE_LAND_SCREEN: HashMap<u32, u8>",
		"const _: [(); 28] = [(); mem::size_of::<UserspaceWgAdmissionKey>()];",
	} {
		if !strings.Contains(src, want) {
			t.Errorf("Rust shim is missing layout contract %q", want)
		}
	}
	object, err := os.ReadFile(filepath.Join("..", "userspace_xdp_bpfel.o"))
	if err != nil {
		t.Fatalf("read embedded Rust object: %v", err)
	}
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(object))
	if err != nil {
		t.Fatalf("load embedded Rust object: %v", err)
	}
	for _, tc := range []struct {
		name      string
		keySize   uint32
		valueSize uint32
	}{
		{"userspace_wg_ingress_zones", 8, 4},
		{"userspace_wg_zone_admission", 28, 1},
		{"userspace_land_screen", 4, 1},
	} {
		mapSpec := spec.Maps[tc.name]
		if mapSpec == nil {
			t.Errorf("embedded Rust object is missing %s", tc.name)
			continue
		}
		if mapSpec.KeySize != tc.keySize || mapSpec.ValueSize != tc.valueSize {
			t.Errorf("embedded %s key/value sizes = %d/%d, want %d/%d",
				tc.name, mapSpec.KeySize, mapSpec.ValueSize, tc.keySize, tc.valueSize)
		}
	}
	ingressSpec := spec.Maps["userspace_wg_ingress_zones"]
	if ingressSpec == nil {
		t.Fatal("embedded Rust object is missing userspace_wg_ingress_zones")
	}
	ingressPlan, err := buildUserspaceWGZoneMaps(wg12855TrunkSnapshot())
	if err != nil {
		t.Fatalf("build WG ingress plan: %v", err)
	}
	for key, want := range map[userspaceWGIngressZoneKey]uint32{
		wgZone12855Key(10, userspaceWGUnTaggedVLANID): 2,
		wgZone12855Key(10, 100):                       1,
	} {
		value, ok := ingressPlan.ingress[key]
		if !ok || value != want {
			t.Fatalf("planned ingress row %+v = (%d, %v), want %d", key, value, ok, want)
		}
		encoded, err := binary.Append(nil, binary.NativeEndian, value)
		if err != nil {
			t.Fatalf("marshal planned ingress value: %v", err)
		}
		if got := uint32(len(encoded)); got != ingressSpec.ValueSize {
			t.Fatalf("planned ingress value marshals to %d bytes, embedded Rust map expects %d", got, ingressSpec.ValueSize)
		}
	}
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

func TestSyncUserspaceWGZoneMapsMarshalsRustWidths17996(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("RemoveMemlock: %v", err)
	}
	if got := binary.Size(userspaceWGIngressZoneKey{}); got != 8 {
		t.Fatalf("WG ingress key size = %d, want Rust key size 8", got)
	}
	if got := binary.Size(uint32(0)); got != 4 {
		t.Fatalf("WG ingress value size = %d, want Rust value size 4", got)
	}
	if got := binary.Size(userspaceWGAdmissionKey{}); got != 28 {
		t.Fatalf("WG admission key size = %d, want Rust key size 28", got)
	}
	if got := binary.Size(uint8(0)); got != 1 {
		t.Fatalf("WG admission value size = %d, want Rust value size 1", got)
	}

	ingressMap, err := ebpf.NewMap(&ebpf.MapSpec{
		Type: ebpf.Hash, KeySize: uint32(binary.Size(userspaceWGIngressZoneKey{})),
		ValueSize: uint32(binary.Size(uint32(0))), MaxEntries: userspaceWGIngressZoneMapCapacity,
	})
	if err != nil {
		skipIfBPFMapUnavailable(t, "new userspace_wg_ingress_zones map", err)
	}
	t.Cleanup(func() { ingressMap.Close() })
	admissionMap, err := ebpf.NewMap(&ebpf.MapSpec{
		Type: ebpf.Hash, KeySize: uint32(binary.Size(userspaceWGAdmissionKey{})),
		ValueSize: uint32(binary.Size(uint8(0))), MaxEntries: userspaceWGAdmissionMapCapacity,
	})
	if err != nil {
		skipIfBPFMapUnavailable(t, "new userspace_wg_zone_admission map", err)
	}
	t.Cleanup(func() { admissionMap.Close() })

	m := New()
	injectShimMap(t, m.bpfShim, mapNameUserspaceWgIngressZones, ingressMap)
	injectShimMap(t, m.bpfShim, mapNameUserspaceWgZoneAdmission, admissionMap)
	snapshot := wg12855TrunkSnapshot()
	const fullZoneID = uint32(2868932339)
	snapshot.Zones[1].ID = fullZoneID
	snapshot.Interfaces[2].VLANID = 4094
	plan, err := buildUserspaceWGZoneMaps(snapshot)
	if err != nil {
		t.Fatalf("build WG zone maps: %v", err)
	}
	untagged := wgZone12855Key(10, userspaceWGUnTaggedVLANID)
	tagged := wgZone12855Key(10, 4094)
	if got, ok := plan.ingress[untagged]; !ok || got != fullZoneID {
		t.Fatalf("planned untagged row = (%d, %v), want full zone ID %d", got, ok, fullZoneID)
	}
	if got, ok := plan.ingress[tagged]; !ok || got != 1 {
		t.Fatalf("planned VLAN 4094 row = (%d, %v), want zone 1", got, ok)
	}
	if len(plan.admission) == 0 {
		t.Fatal("fixture produced no WG admission row to exercise sibling map marshaling")
	}

	if err := m.syncUserspaceWGZoneMapsLocked(snapshot); err != nil {
		t.Fatalf("sync WG zone maps through ebpf.Map.Update: %v", err)
	}
	for key, want := range map[userspaceWGIngressZoneKey]uint32{untagged: fullZoneID, tagged: 1} {
		var got uint32
		if err := ingressMap.Lookup(key, &got); err != nil || got != want {
			t.Errorf("ingress row %+v = (%d, %v), want zone %d", key, got, err, want)
		}
	}
	for key := range plan.admission {
		if key.ZoneID != fullZoneID {
			t.Errorf("admission key zone ID = %d, want full-width %d", key.ZoneID, fullZoneID)
		}
		var got uint8
		if err := admissionMap.Lookup(key, &got); err != nil || got != 1 {
			t.Errorf("admission row %+v = (%d, %v), want 1", key, got, err)
		}
	}
}

func TestSyncUserspaceWGZoneMapsRemovesStaleSnapshotAuthority11574(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("RemoveMemlock: %v", err)
	}
	m := New()
	injectUserspaceBootstrapMaps(t, m)
	ingressMap, err := ebpf.NewMap(&ebpf.MapSpec{
		Type: ebpf.Hash, KeySize: 8, ValueSize: 4,
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
	var zone uint32
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
		zoneOne = uint32(1)
		zoneTwo = uint32(2)
	)
	for _, tc := range []struct {
		name          string
		arrivalZone   uint32
		admissionZone uint32
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
		arrivalZone       uint32
		ownerZone         uint32
		hasOwnerAdmission bool
		interfaceSNAT     bool
		wgType            byte
		wantAction        uint32
	}{
		{name: "same-zone SNAT listener initiation reaches kernel", arrivalZone: 2, ownerZone: 2, hasOwnerAdmission: true, interfaceSNAT: true, wgType: 1, wantAction: xdpActionPass},
		{name: "same-zone SNAT listener response reaches kernel without a LocalMiss row", arrivalZone: 2, ownerZone: 2, hasOwnerAdmission: true, interfaceSNAT: true, wgType: 2, wantAction: xdpActionPass},
		{name: "wrong-zone SNAT listener handshake does not reach kernel", arrivalZone: 1, ownerZone: 2, hasOwnerAdmission: true, interfaceSNAT: true, wgType: 1, wantAction: xdpActionDrop},
		{name: "transit handshake on listener port does not reach kernel", arrivalZone: 2, ownerZone: 2, wgType: 1, wantAction: xdpActionDrop},
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
			packet[42] = tc.wgType
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
			}, uint32(2))
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
