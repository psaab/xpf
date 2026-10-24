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
// out-of-band auxdata the kernel delivered with it. hasAuxdata distinguishes
// "no PACKET_AUXDATA / VLAN_VALID clear" (native untagged frame) from
// "PACKET_AUXDATA with TP_STATUS_VLAN_VALID and this TCI" — the latter must
// be expressible even when the TCI is 0 or carries only PCP bits (VID 0,
// #16426), so vlanTCI==0 alone cannot encode "no auxdata".
type vlanDelivery struct {
	frame      []byte
	vlanTCI    uint16
	hasAuxdata bool
}

// auxdataOOB builds a PACKET_AUXDATA control message carrying vlanTCI with
// TP_STATUS_VLAN_VALID set, for any TCI including 0 (VID 0 with VLAN_VALID,
// #16426). The layout mirrors what the kernel delivers for
// SOL_PACKET/PACKET_AUXDATA: a cmsghdr followed by TpacketAuxdata. Callers
// modelling a native untagged frame deliver no cmsg at all (see
// runVLANReplay), not a zero-TCI cmsg.
func auxdataOOB(vlanTCI uint16) []byte {
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
		oobn := 0
		if d.hasAuxdata {
			oobn = copy(oob, auxdataOOB(d.vlanTCI))
		}
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
		{frame: untaggedAdvert(t, vlanPeer, vrid, 200), vlanTCI: 100, hasAuxdata: true},
		// Untagged native control: must still be enqueued.
		{frame: untaggedAdvert(t, nativePeer, vrid, 100)},
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
		{frame: taggedAdvert(t, vlanPeer, vrid, 200, 100), vlanTCI: 100, hasAuxdata: true},
	})

	if len(got) != 1 || got[0] != vlanPeer.String() {
		t.Fatalf("VLAN child received %v; want exactly its own VLAN-100 advert %s "+
			"(#15049 control: the child still receives its own VLAN)", got, vlanPeer.String())
	}
}

// TestReceiverAfPacketParentKeepsVID0PriorityTaggedAdvert_16426 pins
// #16426: Linux treats VID 0 as native — only a non-zero VID marks a
// frame as belonging to a VLAN sub-interface. A peer advert priority-
// tagged on the wire (VID 0, PCP 6 => TCI 0xC000) is stripped into
// auxdata with TP_STATUS_VLAN_VALID set, exactly like a VLAN-100 advert,
// but it belongs to the native election and MUST be enqueued on the
// parent. Dropping it deafens the backup: its master-down timer expires
// and both nodes hold the VIP (dual MASTER).
func TestReceiverAfPacketParentKeepsVID0PriorityTaggedAdvert_16426(t *testing.T) {
	const vrid = 42
	prioPeer := net.IPv4(10, 0, 61, 2)
	zeroPeer := net.IPv4(10, 0, 61, 4)
	vlanPeer := net.IPv4(10, 0, 61, 3)

	got := runVLANReplay(t, "ge-0-0-0", []vlanDelivery{
		// Priority-tagged VID 0, PCP 6 (TCI 0xC000), VLAN_VALID set:
		// native advert, must be enqueued.
		{frame: untaggedAdvert(t, prioPeer, vrid, 200), vlanTCI: 0xC000, hasAuxdata: true},
		// VID 0 with TCI exactly 0 but VLAN_VALID set: also native.
		{frame: untaggedAdvert(t, zeroPeer, vrid, 200), vlanTCI: 0, hasAuxdata: true},
		// Reference: stripped VLAN-100 advert must still drop (#15049).
		{frame: untaggedAdvert(t, vlanPeer, vrid, 200), vlanTCI: 100, hasAuxdata: true},
	})

	want := []string{prioPeer.String(), zeroPeer.String()}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("parent received %v; want exactly the VID-0 adverts %v — "+
			"a priority-tagged (VID 0) frame is native and must be enqueued, "+
			"while the stripped VLAN-100 advert must still drop (#16426/#15049)",
			got, want)
	}
}

// TestAfPacketAuxdataVLANTag pins the cmsg parser the loop gates on:
// TP_STATUS_VLAN_VALID reports the stripped TCI (including a VID-0
// priority-tag TCI, #16426 — the parser must surface it so the loop can
// mask the VID itself); absent/invalid auxdata reports no tag (fail open
// for the native path, exactly like the #2886 arrival-ifindex helper).
func TestAfPacketAuxdataVLANTag_15049(t *testing.T) {
	if tci, ok := afPacketAuxdataVLANTag(auxdataOOB(100), len(auxdataOOB(100))); !ok || tci != 100 {
		t.Fatalf("vlan 100 auxdata: got (%d,%v), want (100,true)", tci, ok)
	}
	if tci, ok := afPacketAuxdataVLANTag(auxdataOOB(0xC000), len(auxdataOOB(0xC000))); !ok || tci != 0xC000 {
		t.Fatalf("VID-0 priority-tag auxdata: got (0x%x,%v), want (0xc000,true)", tci, ok)
	}
	if tci, ok := afPacketAuxdataVLANTag(auxdataOOB(0), len(auxdataOOB(0))); !ok || tci != 0 {
		t.Fatalf("VID-0 zero-TCI auxdata: got (0x%x,%v), want (0,true)", tci, ok)
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
