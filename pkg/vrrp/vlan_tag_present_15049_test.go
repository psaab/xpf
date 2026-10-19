package vrrp

import (
	"encoding/binary"
	"net"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

// #15049 (A25-02): an untagged-unit VRRP instance bound to a vlan-tagging
// parent is driven by a same-VRID election on a tagged sibling unit.
//
// Mechanism: the parent has vlan-tagging enabled, so its untagged unit
// (e.g. ge-0/0/0.0 with no vlan-id) binds its AF_PACKET ETH_P_ALL tap to the
// PARENT netdev. A peer advert for a tagged sibling (VLAN 100) arrives on
// the wire 802.1Q-tagged; the NIC/driver strips the tag into skb metadata
// (skb->vlan_tci, VLAN_TAG_PRESENT) before the parent's ptype_all tap, so
// receiverAfPacket sees an UNTAGGED Ethernet frame. Neither the cBPF
// prefilter (in-data ethertype only) nor the Go parser (in-data ethertype
// only) can tell it was tagged, so a same-VRID, higher-priority advert from
// VLAN 100 is enqueued on the parent instance: the native MASTER is demoted
// / its master-down timer keeps resetting and the native VIP has no owner.
//
// Fix: the AF_PACKET socket requests PACKET_AUXDATA and receiverAfPacket
// drops a frame whose auxdata carries TP_STATUS_VLAN_VALID when the
// instance is bound to a non-VLAN (parent) netdev. A VLAN child (bound to
// the .100 sub-interface) keeps its own tagged adverts, and an untagged
// native advert on the parent is kept. This is the user-space half of the
// issue's "PACKET_AUXDATA and TP_STATUS_VLAN_VALID" option; the cBPF
// vlan_avail load cannot discriminate per-socket (see instance_receive.go).
//
// These tests drive receiverAfPacket through the afPacketRecvmsg seam with
// a synthetic PACKET_AUXDATA cmsg. Pre-fix that seam and the drop do not
// exist, so the parent case cannot pass; the untagged control and the
// VLAN-child control pin the neighbouring legitimate behaviour.

// vlanDelivery is one synthetic AF_PACKET delivery: a wire frame plus the
// VLAN TCI the kernel stripped into the skb (0 == untagged / no auxdata tag).
type vlanDelivery struct {
	frame   []byte
	vlanTCI uint16
}

// auxdataOOB builds a PACKET_AUXDATA control message carrying vlanTCI, or
// nil for an untagged frame. The layout mirrors what the kernel delivers
// for SOL_PACKET/PACKET_AUXDATA: a cmsghdr followed by TpacketAuxdata.
func auxdataOOB(vlanTCI uint16) []byte {
	if vlanTCI == 0 {
		return nil
	}
	aux := unix.TpacketAuxdata{
		Status:    unix.TP_STATUS_VLAN_VALID,
		Vlan_tci:  vlanTCI,
		Vlan_tpid: 0x8100,
	}
	size := unix.SizeofCmsghdr + int(unsafe.Sizeof(aux))
	buf := make([]byte, unix.CmsgSpace(int(unsafe.Sizeof(aux))))
	hdr := (*unix.Cmsghdr)(unsafe.Pointer(&buf[0]))
	hdr.Level = unix.SOL_PACKET
	hdr.Type = unix.PACKET_AUXDATA
	hdr.SetLen(size)
	copy(buf[unix.SizeofCmsghdr:], (*[unsafe.Sizeof(aux)]byte)(unsafe.Pointer(&aux))[:])
	return buf
}

// runVLANReplay feeds deliveries to a fresh instance whose cfg.Interface
// spelling decides the VLAN-child vs parent classification (exactly as
// openSocketWith derives isVLAN) and returns the source IPs enqueued.
func runVLANReplay(t *testing.T, ifaceName string, deliveries []vlanDelivery) []string {
	t.Helper()
	const vrid = 42

	vi := &vrrpInstance{
		afPacketFD: 3, // never touched: the recvmsg seam is stubbed
		rxCh:       make(chan *VRRPPacket, 8),
		stopCh:     make(chan struct{}),
	}
	vi.cfg.GroupID = vrid
	vi.cfg.Family = "inet"
	vi.cfg.Interface = ifaceName
	vi.setLocalIP(nil)

	orig := afPacketRecvmsg
	defer func() { afPacketRecvmsg = orig }()
	idx := 0
	afPacketRecvmsg = func(_ int, p, oob []byte, _ int) (int, int, int, unix.Sockaddr, error) {
		if idx >= len(deliveries) {
			close(vi.stopCh)
			return 0, 0, 0, nil, unix.EAGAIN
		}
		d := deliveries[idx]
		idx++
		n := copy(p, d.frame)
		oobn := copy(oob, auxdataOOB(d.vlanTCI))
		return n, oobn, 0, &unix.SockaddrLinklayer{Pkttype: unix.PACKET_HOST}, nil
	}

	done := make(chan struct{})
	go func() { vi.receiverAfPacket(); close(done) }()
	<-done

	var got []string
	for {
		select {
		case pkt := <-vi.rxCh:
			got = append(got, pkt.SrcIP.String())
			continue
		default:
		}
		break
	}
	return got
}

// untaggedAdvert builds a valid untagged IPv4 VRRP advert frame: exactly
// what receiverAfPacket sees after the kernel strips an 802.1Q tag (the
// in-data bytes are identical for a native advert and a stripped VLAN-100
// advert — only the out-of-band auxdata differs).
func untaggedAdvert(t *testing.T, srcIP net.IP, vrid, prio uint8) []byte {
	t.Helper()
	return buildSelfAdvertFrame6560(t, srcIP, vrid, prio)
}

// taggedAdvert builds a valid 802.1Q-tagged IPv4 VRRP advert frame as it
// appears on a VLAN sub-interface tap, where the tag is still in-data.
func taggedAdvert(t *testing.T, srcIP net.IP, vrid, prio uint8, vlanID uint16) []byte {
	t.Helper()
	inner := buildSelfAdvertFrame6560(t, srcIP, vrid, prio)
	frame := make([]byte, 0, len(inner)+4)
	frame = append(frame, inner[:12]...)
	var tag [4]byte
	binary.BigEndian.PutUint16(tag[0:2], 0x8100)
	binary.BigEndian.PutUint16(tag[2:4], vlanID)
	frame = append(frame, tag[:]...)
	frame = append(frame, inner[12:]...)
	return frame
}

func TestReceiverAfPacketParentDropsStrippedVLANAdvert_15049(t *testing.T) {
	const vrid = 42
	nativePeer := net.IPv4(10, 0, 61, 2)
	vlanPeer := net.IPv4(10, 0, 61, 3)

	// Parent-bound (untagged unit) instance: cfg.Interface has no "."
	// suffix, exactly the vlan-tagging parent case.
	got := runVLANReplay(t, "ge-0-0-0", []vlanDelivery{
		// Stripped VLAN-100 advert: in-data untagged, auxdata vlan_tci=100.
		{untaggedAdvert(t, vlanPeer, vrid, 200), 100},
		// Untagged native control: must still be enqueued.
		{untaggedAdvert(t, nativePeer, vrid, 100), 0},
	})

	if len(got) != 1 || got[0] != nativePeer.String() {
		t.Fatalf("parent received %v; want exactly the untagged native advert %s — "+
			"the stripped VLAN-100 advert (vlan_tci=100) must be dropped on a "+
			"non-VLAN netdev and the untagged control kept (#15049)",
			got, nativePeer.String())
	}
}

func TestReceiverAfPacketVLANChildKeepsOwnVLAN_15049(t *testing.T) {
	const vrid = 42
	vlanPeer := net.IPv4(10, 0, 61, 3)

	// VLAN-child instance (ge-0-0-0.100): its own VLAN advert arrives
	// single-tagged in-data and MUST still be enqueued. Dropping tagged
	// frames on the child would deafen it.
	got := runVLANReplay(t, "ge-0-0-0.100", []vlanDelivery{
		{taggedAdvert(t, vlanPeer, vrid, 200, 100), 100},
	})

	if len(got) != 1 || got[0] != vlanPeer.String() {
		t.Fatalf("VLAN child received %v; want exactly its own VLAN-100 advert %s "+
			"(#15049 control: the child still receives its own VLAN)", got, vlanPeer.String())
	}
}

// TestAfPacketAuxdataVLANTag pins the cmsg parser the loop gates on:
// TP_STATUS_VLAN_VALID reports the stripped TCI; absent/invalid auxdata
// reports no tag (fail open for the native path, exactly like the #2886
// arrival-ifindex helper).
func TestAfPacketAuxdataVLANTag_15049(t *testing.T) {
	if tci, ok := afPacketAuxdataVLANTag(auxdataOOB(100), len(auxdataOOB(100))); !ok || tci != 100 {
		t.Fatalf("vlan 100 auxdata: got (%d,%v), want (100,true)", tci, ok)
	}
	if _, ok := afPacketAuxdataVLANTag(nil, 0); ok {
		t.Fatal("no auxdata must report no VLAN tag")
	}
	// A cmsg that is not PACKET_AUXDATA must not be misread as a tag.
	other := make([]byte, unix.CmsgSpace(4))
	hdr := (*unix.Cmsghdr)(unsafe.Pointer(&other[0]))
	hdr.Level = unix.SOL_PACKET
	hdr.Type = unix.PACKET_IGNORE_OUTGOING
	hdr.SetLen(unix.SizeofCmsghdr + 4)
	if _, ok := afPacketAuxdataVLANTag(other, len(other)); ok {
		t.Fatal("non-auxdata cmsg must report no VLAN tag")
	}
}
