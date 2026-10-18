package userspace

import (
	"encoding/binary"
	"os"
	"regexp"
	"strconv"
	"testing"

	"github.com/cilium/ebpf"
)

// #14842: VLAN units in different routing domains sharing one parent
// ifindex must resolve to their own domain. The pre-fix map was keyed by
// ifindex only, so Go deleted the parent entry as ambiguous (domain
// u32::MAX, fail-closed for every VLAN on that parent) — and any
// ifindex-only resolution that did land picked one unit's domain for all.

const (
	ingressDomain14842VID50 = uint32(100050)
	ingressDomain14842VID80 = uint32(100080)
	ingressDomain14842VID0  = uint32(100000)
)

func ingressDomainSnapshot14842() *ConfigSnapshot {
	return &ConfigSnapshot{Interfaces: []InterfaceSnapshot{
		{Name: "ge-0/0/1", LinuxName: "ge-0-0-1", Zone: "trust", Ifindex: 10},
		{Name: "ge-0/0/1.50", LinuxName: "ge-0-0-1.50", ParentLinuxName: "ge-0-0-1", Zone: "trust", Ifindex: 11, ParentIfindex: 10, VLANID: 50, IsUnit: true, RoutingDomain: ingressDomain14842VID50},
		{Name: "ge-0/0/1.80", LinuxName: "ge-0-0-1.80", ParentLinuxName: "ge-0-0-1", Zone: "trust", Ifindex: 12, ParentIfindex: 10, VLANID: 80, IsUnit: true, RoutingDomain: ingressDomain14842VID80},
		{Name: "ge-0/0/2", LinuxName: "ge-0-0-2", Zone: "trust", Ifindex: 20, RoutingDomain: ingressDomain14842VID0},
		{Name: "ge-0/0/2.0", LinuxName: "ge-0-0-2", ParentLinuxName: "ge-0-0-2", Zone: "trust", Ifindex: 20, ParentIfindex: 20, VLANID: 0, IsUnit: true, RoutingDomain: ingressDomain14842VID0},
	}}
}

func TestBuildUserspaceIngressDomainEntriesPerVLAN14842(t *testing.T) {
	entries := buildUserspaceIngressDomainEntries(ingressDomainSnapshot14842())
	want := map[userspaceIngressDomainKey]uint32{
		{Ifindex: 10, VLANID: 50}:                                   ingressDomain14842VID50,
		{Ifindex: 10, VLANID: 80}:                                   ingressDomain14842VID80,
		{Ifindex: 10, VLANID: userspaceIngressDomainUntaggedVLANID}: 0,
		{Ifindex: 20, VLANID: userspaceIngressDomainUntaggedVLANID}: ingressDomain14842VID0,
		{Ifindex: 11, VLANID: userspaceIngressDomainUntaggedVLANID}: ingressDomain14842VID50,
		{Ifindex: 12, VLANID: userspaceIngressDomainUntaggedVLANID}: ingressDomain14842VID80,
	}
	if len(entries) != len(want) {
		t.Fatalf("ingress domain entries = %v, want %v", entries, want)
	}
	for key, domain := range want {
		if got, ok := entries[key]; !ok || got != domain {
			t.Fatalf("ingress domain entry %v = (%d, %v), want %d (all: %v)", key, got, ok, domain, entries)
		}
	}
}

func TestBuildUserspaceIngressDomainEntriesConflictingVIDPoisoned14842(t *testing.T) {
	snap := ingressDomainSnapshot14842()
	// A second unit claiming VID 50 on the same parent in another domain:
	// no domain may win that (ifindex, VID) key.
	snap.Interfaces = append(snap.Interfaces, InterfaceSnapshot{
		Name: "ge-0/0/1.51", LinuxName: "ge-0-0-1.51", ParentLinuxName: "ge-0-0-1", Zone: "trust",
		Ifindex: 13, ParentIfindex: 10, VLANID: 50, IsUnit: true, RoutingDomain: 999,
	})
	entries := buildUserspaceIngressDomainEntries(snap)
	key := userspaceIngressDomainKey{Ifindex: 10, VLANID: 50}
	if got, ok := entries[key]; !ok || got != ^uint32(0) {
		t.Fatalf("conflicting (parent, VID 50) entry = (%d, %v), want fail-closed sentinel %d", got, ok, ^uint32(0))
	}
}

func TestBuildUserspaceIngressDomainEntriesNativeVLANOwnsUntagged14842(t *testing.T) {
	snap := &ConfigSnapshot{Interfaces: []InterfaceSnapshot{
		{Name: "ge-0/0/1", LinuxName: "ge-0-0-1", Zone: "trust", Ifindex: 10, NativeVLANID: 50, RoutingDomain: 7},
		{Name: "ge-0/0/1.50", LinuxName: "ge-0-0-1.50", ParentLinuxName: "ge-0-0-1", Zone: "trust", Ifindex: 11, ParentIfindex: 10, VLANID: 50, IsUnit: true, RoutingDomain: ingressDomain14842VID50},
	}}
	entries := buildUserspaceIngressDomainEntries(snap)
	key := userspaceIngressDomainKey{Ifindex: 10, VLANID: userspaceIngressDomainUntaggedVLANID}
	if got := entries[key]; got != ingressDomain14842VID50 {
		t.Fatalf("native-VLAN untagged entry = %d, want the native unit's domain %d (entries: %v)", got, ingressDomain14842VID50, entries)
	}
}

func TestSyncIngressDomainsPerVLANAndReap14842(t *testing.T) {
	m, _ := newIngressManager(t, ebpf.Hash, 64)
	if err := m.syncIngressIfaceMapLocked(ingressDomainSnapshot14842()); err != nil {
		t.Fatalf("syncIngressIfaceMapLocked: %v", err)
	}
	domainMap := m.bpfShim.Map(mapNameUserspaceIngressDomains)
	if domainMap == nil {
		t.Fatal("userspace_ingress_domains_vlan map not loaded")
	}
	var domain uint32
	key50 := userspaceIngressDomainKey{Ifindex: 10, VLANID: 50}
	if err := domainMap.Lookup(key50, &domain); err != nil || domain != ingressDomain14842VID50 {
		t.Fatalf("domain[(parent,50)] = (%d, %v), want %d", domain, err, ingressDomain14842VID50)
	}
	key80 := userspaceIngressDomainKey{Ifindex: 10, VLANID: 80}
	if err := domainMap.Lookup(key80, &domain); err != nil || domain != ingressDomain14842VID80 {
		t.Fatalf("domain[(parent,80)] = (%d, %v), want %d", domain, err, ingressDomain14842VID80)
	}
	// Reap: an empty config must remove every (ifindex, VID) row, including
	// rows a previous daemon left in the pinned map.
	if err := m.syncIngressIfaceMapLocked(&ConfigSnapshot{}); err != nil {
		t.Fatalf("reap sync: %v", err)
	}
	var k userspaceIngressDomainKey
	var v uint32
	iter := domainMap.Iterate()
	count := 0
	for iter.Next(&k, &v) {
		count++
	}
	if err := iter.Err(); err != nil {
		t.Fatalf("iterate domain map: %v", err)
	}
	if count != 0 {
		t.Fatalf("domain map still holds %d rows after reap, want 0", count)
	}
}

func taggedIPv4Packet14842(src, dst [4]byte, vid uint16) []byte {
	pkt := ipv4TestPacket(src, dst, 17, 8)
	out := make([]byte, 0, len(pkt)+4)
	out = append(out, pkt[:12]...)
	var tag [4]byte
	binary.BigEndian.PutUint16(tag[0:2], 0x8100)
	binary.BigEndian.PutUint16(tag[2:4], vid)
	out = append(out, tag[:]...)
	out = append(out, pkt[12:]...)
	return out
}

// BPF cell: a local address owned only by the VID-50 unit's domain. The
// same packet arriving under VID 80 must not resolve to that domain.
func TestUserspaceXDPResolvesIngressDomainPerVLAN14842(t *testing.T) {
	dst := [4]byte{10, 0, 0, 1}
	src := [4]byte{198, 51, 100, 9}
	for _, tc := range []struct {
		name       string
		vid        uint16
		wantAction uint32
	}{
		{name: "vid50 local passes in its own domain", vid: 50, wantAction: xdpActionPass},
		{name: "vid80 does not inherit vid50 domain", vid: 80, wantAction: xdpActionDrop},
	} {
		t.Run(tc.name, func(t *testing.T) {
			coll := loadUserspaceXDPTestCollection(t)
			ifindex := userspaceXDPTestRunIfindex(t)
			updateUserspaceXDPTestCtrl(t, coll, userspaceCtrlValue{
				Enabled: 1, MetadataVersion: userspaceMetadataVersion, Workers: 1, QueueCount: 1,
				HeartbeatTimeoutMS: userspaceHeartbeatTimeoutMS,
			})
			updateUserspaceXDPTestMap(t, coll, "userspace_ingress_ifaces", ifindex, uint8(userspaceIngressIfaceFlagAdjudicated))
			domainMap := coll.Maps[mapNameUserspaceIngressDomains]
			if domainMap == nil {
				t.Fatalf("%s map not loaded", mapNameUserspaceIngressDomains)
			}
			info, err := domainMap.Info()
			if err != nil {
				t.Fatalf("ingress domain map info: %v", err)
			}
			if info.KeySize == 4 {
				// Pre-fix ABI can only state one domain per ifindex.
				updateUserspaceXDPTestMap(t, coll, mapNameUserspaceIngressDomains, ifindex, ingressDomain14842VID50)
			} else {
				updateUserspaceXDPTestMap(t, coll, mapNameUserspaceIngressDomains,
					userspaceIngressDomainKey{Ifindex: ifindex, VLANID: 50}, ingressDomain14842VID50)
				updateUserspaceXDPTestMap(t, coll, mapNameUserspaceIngressDomains,
					userspaceIngressDomainKey{Ifindex: ifindex, VLANID: 80}, ingressDomain14842VID80)
			}
			updateUserspaceXDPTestBinding(t, coll, userspaceXDPTestRunBindingIndex(t, 0), userspaceBindingValue{Slot: 0, Flags: userspaceBindingReady})
			updateUserspaceXDPTestHeartbeat(t, coll, 0)
			updateUserspaceXDPTestMap(t, coll, mapNameUserspaceLocalV4,
				userspaceLocalV4Key{Domain: ingressDomain14842VID50, Addr: binary.BigEndian.Uint32(dst[:])}, uint8(1))

			got := runUserspaceXDPTestPacket(t, coll, taggedIPv4Packet14842(src, dst, tc.vid))
			if got != tc.wantAction {
				t.Fatalf("XDP action for VID %d = %d, want %d", tc.vid, got, tc.wantAction)
			}
		})
	}
}

func TestIngressDomainMapCapacityMatchesTheShim14842(t *testing.T) {
	src, err := os.ReadFile("../../../userspace-xdp/src/lib.rs")
	if err != nil {
		t.Fatalf("read shim source: %v", err)
	}
	re := regexp.MustCompile(`static USERSPACE_INGRESS_DOMAINS: [^;]*with_max_entries\(([0-9_]+),`)
	match := re.FindSubmatch(src)
	if match == nil {
		t.Fatal("no with_max_entries declaration found for USERSPACE_INGRESS_DOMAINS")
	}
	got, _ := strconv.Atoi(string(match[1]))
	if got != userspaceIngressDomainMapCapacity {
		t.Errorf("USERSPACE_INGRESS_DOMAINS max_entries is %d in the shim but the Go preflight checks %d", got, userspaceIngressDomainMapCapacity)
	}
	if err := checkIngressDomainCapacity(userspaceIngressDomainMapCapacity); err != nil {
		t.Errorf("capacity-sized set refused: %v", err)
	}
	if err := checkIngressDomainCapacity(userspaceIngressDomainMapCapacity + 1); err == nil {
		t.Error("over-capacity set accepted, want refusal")
	}
}
