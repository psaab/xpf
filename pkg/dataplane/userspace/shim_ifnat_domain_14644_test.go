package userspace

import (
	"encoding/binary"
	"testing"

	"github.com/cilium/ebpf"
)

// #14644: the interface-NAT (interface-mode source-NAT) address of one
// routing instance must produce classifier entries only in its owning
// routing domain. The address-only exclusions erased the owner, so the
// same address owned by two instances collapsed to one shim entry and a
// foreign-domain ingress matched it.
func TestInterfaceNATEntriesRemainDistinctAcrossRoutingDomains14644(t *testing.T) {
	snapshot := &ConfigSnapshot{
		Interfaces: []InterfaceSnapshot{
			{
				Name: "reth0.0", Zone: "untrust", EgressZone: "untrust", Ifindex: 5,
				RoutingDomain: 100042, RoutingInstance: "VR1",
				Addresses: []InterfaceAddressSnapshot{
					{Family: "inet", Address: "192.0.2.2/24"},
					{Family: "inet6", Address: "2001:db8:1::2/64"},
				},
			},
			{
				Name: "reth1.0", Zone: "untrust", EgressZone: "untrust", Ifindex: 6,
				Addresses: []InterfaceAddressSnapshot{
					{Family: "inet", Address: "192.0.2.2/24"},
					{Family: "inet6", Address: "2001:db8:1::2/64"},
				},
			},
		},
		SourceNAT: []SourceNATRuleSnapshot{{Name: "snat", InterfaceMode: true}},
	}

	entries := buildInterfaceNATAddressEntries(snapshot)
	if len(entries) != 4 {
		t.Fatalf("len(interface-NAT entries) = %d, want 4 (same IPv4/IPv6 SNAT address in two routing domains): %+v", len(entries), entries)
	}
	seen := make(map[userspaceLocalAddressEntry]bool)
	for _, e := range entries {
		if seen[e] {
			t.Fatalf("duplicate interface-NAT entry %+v", e)
		}
		seen[e] = true
	}

	desiredV4, desiredV6, _, _ := buildDesiredInterfaceNATAddressSets(snapshot)
	if len(desiredV4) != 2 || len(desiredV6) != 2 {
		t.Fatalf("desired IFNAT sets v4=%d v6=%d, want 2/2 domain-scoped entries", len(desiredV4), len(desiredV6))
	}
	addr4 := binary.BigEndian.Uint32([]byte{192, 0, 2, 2})
	for _, d := range []uint32{0, 100042} {
		if _, ok := desiredV4[userspaceLocalV4Key{Domain: d, Addr: addr4}]; !ok {
			t.Fatalf("desired IFNAT v4 missing domain %d entry", d)
		}
	}
}

// #14644 BPF cell: echo/ESP/GRE to a VR1-owned interface-NAT address
// arriving at ingress domain 0 must take the worker redirect, not
// XDP_PASS; the same packet at the owning domain still PASSes.
// The cell inspects map ABI sizes so it also runs (and fails) against
// the address-only master object.
func TestUserspaceXDPDoesNotPassForeignDomainInterfaceNAT14644(t *testing.T) {
	const vr1 = uint32(100042)
	dst4 := [4]byte{192, 0, 2, 2}
	src4 := [4]byte{198, 51, 100, 9}

	setup := func(t *testing.T, ingressDomain uint32) *ebpf.Collection {
		t.Helper()
		coll := loadUserspaceXDPTestCollection(t)
		updateUserspaceXDPTestIngressDomain(t, coll, userspaceXDPTestRunIfindex(t), ingressDomain)
		updateUserspaceXDPTestCtrl(t, coll, userspaceCtrlValue{
			Enabled: 1, MetadataVersion: userspaceMetadataVersion, Workers: 1, QueueCount: 1,
			HeartbeatTimeoutMS: userspaceHeartbeatTimeoutMS,
		})
		updateUserspaceXDPTestBinding(t, coll, userspaceXDPTestRunBindingIndex(t, 0), userspaceBindingValue{Slot: 0, Flags: userspaceBindingReady})
		updateUserspaceXDPTestHeartbeat(t, coll, 0)
		nat := coll.Maps[mapNameUserspaceInterfaceNATv4]
		if nat == nil {
			t.Skip("interface-NAT v4 map absent")
		}
		info, err := nat.Info()
		if err != nil {
			t.Fatalf("interface-NAT map info: %v", err)
		}
		addr := binary.BigEndian.Uint32(dst4[:])
		if info.KeySize == 4 {
			updateUserspaceXDPTestMap(t, coll, mapNameUserspaceInterfaceNATv4, addr, uint8(1))
		} else {
			updateUserspaceXDPTestMap(t, coll, mapNameUserspaceInterfaceNATv4, userspaceLocalV4Key{Domain: vr1, Addr: addr}, uint8(1))
		}
		return coll
	}

	icmpEcho := func() []byte {
		pkt := ipv4TestPacket(src4, dst4, 1, 8)
		pkt[34] = 8 // ICMP echo request
		return pkt
	}
	gre := func() []byte { return ipv4TestPacket(src4, dst4, 47, 8) }

	for _, tc := range []struct {
		name          string
		ingressDomain uint32
		packet        func() []byte
		wantAction    uint32
	}{
		{name: "foreign-domain icmp echo redirects", ingressDomain: 0, packet: icmpEcho, wantAction: xdpActionDrop},
		{name: "foreign-domain esp redirects", ingressDomain: 0, packet: func() []byte { return espIPv4TestPacket(src4, dst4) }, wantAction: xdpActionDrop},
		{name: "foreign-domain gre redirects", ingressDomain: 0, packet: gre, wantAction: xdpActionDrop},
		{name: "same-domain icmp echo passes", ingressDomain: vr1, packet: icmpEcho, wantAction: xdpActionPass},
		{name: "same-domain esp passes", ingressDomain: vr1, packet: func() []byte { return espIPv4TestPacket(src4, dst4) }, wantAction: xdpActionPass},
		{name: "same-domain gre passes", ingressDomain: vr1, packet: gre, wantAction: xdpActionPass},
	} {
		t.Run(tc.name, func(t *testing.T) {
			coll := setup(t, tc.ingressDomain)
			got := runUserspaceXDPTestPacket(t, coll, tc.packet())
			if got != tc.wantAction {
				t.Fatalf("XDP action = %d, want %d", got, tc.wantAction)
			}
		})
	}
}
