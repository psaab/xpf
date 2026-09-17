package userspace

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	"github.com/psaab/xpf/pkg/dataplane"
	"github.com/psaab/xpf/pkg/logging"
)

// buildSessionOpenV4Payload builds a binary SessionOpen payload for an IPv4 session.
func buildSessionOpenV4Payload(
	proto uint8,
	srcPort, dstPort uint16,
	srcIP, dstIP [4]byte,
	natSrcIP, natDstIP [4]byte,
	natSrcPort, natDstPort uint16,
	ownerRG int32,
	egressIfindex, txIfindex int32,
	tunnelEndpoint, txVLAN uint16,
	flags uint8,
	ingressZone, egressZone uint16, disposition uint8,
	neighborMAC, srcMAC [6]byte,
	nextHop [4]byte,
) []byte {
	// #3075: 32 fixed (zone fields widened u8->u16, Disposition moved to [31])
	// + 4*4 IPs + 6+6 MACs + 4 NextHop = 64 bytes. (#2467: the three identity
	// fields at [10:22] are int32.)
	buf := make([]byte, 64)
	buf[0] = 4 // AddrFamily
	buf[1] = proto
	binary.LittleEndian.PutUint16(buf[2:4], srcPort)
	binary.LittleEndian.PutUint16(buf[4:6], dstPort)
	binary.LittleEndian.PutUint16(buf[6:8], natSrcPort)
	binary.LittleEndian.PutUint16(buf[8:10], natDstPort)
	binary.LittleEndian.PutUint32(buf[10:14], uint32(ownerRG))
	binary.LittleEndian.PutUint32(buf[14:18], uint32(egressIfindex))
	binary.LittleEndian.PutUint32(buf[18:22], uint32(txIfindex))
	binary.LittleEndian.PutUint16(buf[22:24], tunnelEndpoint)
	binary.LittleEndian.PutUint16(buf[24:26], txVLAN)
	buf[26] = flags
	binary.LittleEndian.PutUint16(buf[27:29], ingressZone)
	binary.LittleEndian.PutUint16(buf[29:31], egressZone)
	buf[31] = disposition
	copy(buf[32:36], srcIP[:])
	copy(buf[36:40], dstIP[:])
	copy(buf[40:44], natSrcIP[:])
	copy(buf[44:48], natDstIP[:])
	copy(buf[48:54], neighborMAC[:])
	copy(buf[54:60], srcMAC[:])
	copy(buf[60:64], nextHop[:])
	return buf
}

// buildSessionCloseV4Payload builds a binary SessionClose payload for IPv4.
// #3075: includes the trailing ingress/egress zone-id u16 LE bytes (widened
// from u8).
func buildSessionCloseV4Payload(
	proto uint8,
	srcPort, dstPort uint16,
	srcIP, dstIP [4]byte,
	ownerRG int32,
	flags uint8,
	ingressZoneID, egressZoneID uint16,
) []byte {
	// #3075: 6 + 4+4 + 4 (OwnerRGID int32) + 1 (Flags) + 4 (u16 zones) = 23 bytes
	buf := make([]byte, 23)
	buf[0] = 4 // AddrFamily
	buf[1] = proto
	binary.LittleEndian.PutUint16(buf[2:4], srcPort)
	binary.LittleEndian.PutUint16(buf[4:6], dstPort)
	copy(buf[6:10], srcIP[:])
	copy(buf[10:14], dstIP[:])
	binary.LittleEndian.PutUint32(buf[14:18], uint32(ownerRG))
	buf[18] = flags
	binary.LittleEndian.PutUint16(buf[19:21], ingressZoneID)
	binary.LittleEndian.PutUint16(buf[21:23], egressZoneID)
	return buf
}

func buildDataplaneEventV4Payload(
	proto uint8,
	srcPort, dstPort uint16,
	srcIP, dstIP [4]byte,
	natSrcIP [4]byte,
	natSrcPort uint16,
	ingressZone, egressZone uint16,
	reason uint16,
	policyID uint32,
	timestampNS uint64,
) []byte {
	return buildTypedDataplaneEventV4Payload(
		dataplane.EventTypePolicyDeny,
		dataplane.ActionDeny,
		proto,
		srcPort, dstPort,
		srcIP, dstIP,
		natSrcIP,
		natSrcPort,
		ingressZone, egressZone,
		policyID,
		0,
		0,
		0,
		uint8(reason),
		timestampNS,
	)
}

func buildTypedDataplaneEventV4Payload(
	eventType uint8,
	action uint8,
	proto uint8,
	srcPort, dstPort uint16,
	srcIP, dstIP [4]byte,
	natSrcIP [4]byte,
	natSrcPort uint16,
	ingressZone, egressZone uint16,
	policyOrReasonID uint32,
	ruleID uint32,
	termID uint32,
	ownerRG int16,
	reason uint8,
	timestampNS uint64,
) []byte {
	buf := make([]byte, int(unsafe.Sizeof(dataplane.Event{})))
	binary.LittleEndian.PutUint64(buf[0:8], timestampNS)
	copy(buf[8:12], srcIP[:])
	copy(buf[24:28], dstIP[:])
	binary.BigEndian.PutUint16(buf[40:42], srcPort)
	binary.BigEndian.PutUint16(buf[42:44], dstPort)
	binary.LittleEndian.PutUint32(buf[44:48], policyOrReasonID)
	binary.LittleEndian.PutUint16(buf[48:50], ingressZone)
	binary.LittleEndian.PutUint16(buf[50:52], egressZone)
	buf[52] = eventType
	buf[53] = proto
	buf[54] = action
	buf[55] = dataplane.AFInet
	binary.LittleEndian.PutUint32(buf[56:60], ruleID)
	binary.LittleEndian.PutUint32(buf[60:64], termID)
	binary.LittleEndian.PutUint16(buf[64:66], uint16(ownerRG))
	copy(buf[72:76], natSrcIP[:])
	binary.BigEndian.PutUint16(buf[104:106], natSrcPort)
	buf[134] = reason
	return buf
}

func writeFrame(w io.Writer, typ uint8, seq uint64, payload []byte) error {
	var hdr [EventFrameHeaderSize]byte
	binary.LittleEndian.PutUint32(hdr[0:4], uint32(len(payload)))
	hdr[4] = typ
	binary.LittleEndian.PutUint64(hdr[8:16], seq)
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	if len(payload) > 0 {
		if _, err := w.Write(payload); err != nil {
			return err
		}
	}
	return nil
}

func readFrame(r io.Reader) (typ uint8, seq uint64, payload []byte, err error) {
	var hdr [EventFrameHeaderSize]byte
	if _, err = io.ReadFull(r, hdr[:]); err != nil {
		return
	}
	length := binary.LittleEndian.Uint32(hdr[0:4])
	typ = hdr[4]
	seq = binary.LittleEndian.Uint64(hdr[8:16])
	if length > 0 {
		payload = make([]byte, length)
		_, err = io.ReadFull(r, payload)
	}
	return
}

// #4565: decodeSessionEvent must read the FLAG_NAT64 marker (bit 1<<5) and the
// trailing snat_v4 (4 bytes after the #3301 metadata) so a peer-PROMOTED NAT64
// session can rebuild its reverse (v4->v6) BIB after failover. RED-on-revert:
// dropping the eventstream.go decode leaves d.Nat64 false / d.Nat64SnatV4Bin zero.
func TestDecodeSessionEventNat64_4565(t *testing.T) {
	// Minimal v6 SESSION_OPEN payload. Layout: fixed 32 bytes, then 5 v6
	// addresses (16 each) + 2 MACs (6 each) = 92, reaching off=124; then the
	// #3301 trailing fields (policy_id/counter/apptimeout = 12) -> off=136; then
	// the #4565 trailing snat_v4 (4) -> off=140.
	payload := make([]byte, 140)
	payload[0] = 6                                 // AddrFamily = v6
	payload[1] = 6                                 // Protocol = TCP
	payload[26] = SessionEventFlagNat64            // flags: NAT64 marker
	copy(payload[136:140], []byte{203, 0, 113, 5}) // trailing snat_v4

	d, ok := decodeSessionEvent(payload)
	if !ok {
		t.Fatal("decodeSessionEvent returned false")
	}
	if !d.Nat64 {
		t.Fatal("d.Nat64 = false, want true for a FLAG_NAT64 frame")
	}
	if d.Nat64SnatV4Bin != [4]byte{203, 0, 113, 5} {
		t.Fatalf("d.Nat64SnatV4Bin = %v, want 203.0.113.5", d.Nat64SnatV4Bin)
	}
	if d.Nat64SnatV4 != "" {
		t.Fatalf("d.Nat64SnatV4 = %q, want empty on the binary leg", d.Nat64SnatV4)
	}
	if d.BinAddrLen != 16 {
		t.Fatalf("d.BinAddrLen = %d, want 16", d.BinAddrLen)
	}

	// A legacy frame that omits the trailing snat_v4 (and the flag) decodes to
	// not-NAT64, rolling-upgrade safe.
	legacy := make([]byte, 136)
	legacy[0] = 6
	legacy[1] = 6
	dl, ok := decodeSessionEvent(legacy)
	if !ok {
		t.Fatal("decodeSessionEvent returned false for legacy frame")
	}
	if dl.Nat64 || dl.Nat64SnatV4 != "" {
		t.Fatalf("legacy frame: Nat64=%v snat=%q, want false/empty", dl.Nat64, dl.Nat64SnatV4)
	}
	if dl.Nat64SnatV4Bin != [4]byte{} {
		t.Fatalf("legacy frame: snat bin = %v, want zero", dl.Nat64SnatV4Bin)
	}
	if dl.BinAddrLen != 16 {
		t.Fatalf("legacy frame: BinAddrLen = %d, want 16", dl.BinAddrLen)
	}
}

// TestDecodeSessionEventRTFlowSessionID5212 verifies the trailing u64 RT_FLOW
// session id (the LAST open-frame field, after the #4565 snat_v4) decodes into
// SessionDeltaInfo.RTFlowSessionID, and a legacy frame that omits it decodes to
// 0 (the standby then allocs a fresh local id). Reverting the eventstream.go
// decode drops the id and this fails RED.
func TestDecodeSessionEventRTFlowSessionID5212(t *testing.T) {
	// v6 SESSION_OPEN layout (see TestDecodeSessionEventNat64_4565): off reaches
	// 140 after the #4565 snat_v4; the #5212 session id occupies [140:148].
	payload := make([]byte, 148)
	payload[0] = 6 // AddrFamily = v6
	payload[1] = 6 // Protocol = TCP
	// Originating node's stable id: worker 7 high bits + counter 0x2a.
	wantID := uint64(7)<<48 | 0x2a
	binary.LittleEndian.PutUint64(payload[140:148], wantID)

	d, ok := decodeSessionEvent(payload)
	if !ok {
		t.Fatal("decodeSessionEvent returned false")
	}
	if d.RTFlowSessionID != wantID {
		t.Fatalf("d.RTFlowSessionID = %#x, want %#x", d.RTFlowSessionID, wantID)
	}

	// A legacy frame that omits the trailing id (stops after snat_v4) decodes to
	// 0 — the standby falls back to a fresh local id (rolling-upgrade safe).
	legacy := make([]byte, 140)
	legacy[0] = 6
	legacy[1] = 6
	dl, ok := decodeSessionEvent(legacy)
	if !ok {
		t.Fatal("decodeSessionEvent returned false for legacy frame")
	}
	if dl.RTFlowSessionID != 0 {
		t.Fatalf("legacy frame RTFlowSessionID = %#x, want 0", dl.RTFlowSessionID)
	}
}

func TestDecodeSessionEventV4(t *testing.T) {
	payload := buildSessionOpenV4Payload(
		6,          // TCP
		12345, 443, // ports
		[4]byte{10, 0, 1, 102}, [4]byte{172, 16, 80, 200}, // src, dst
		[4]byte{172, 16, 80, 8}, [4]byte{0, 0, 0, 0}, // nat src, nat dst
		40000, 0, // nat ports
		1,      // ownerRG
		12, 11, // egress/tx ifindex
		0, 80, // tunnel, vlan
		SessionEventFlagFabricRedirect, // flags
		1, 2, 0,                        // ingress/egress zone, disposition
		[6]byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}, // neighbor MAC
		[6]byte{0x02, 0xbf, 0x72, 0x00, 0x50, 0x08}, // src MAC
		[4]byte{172, 16, 80, 1},                     // next hop
	)

	d, ok := decodeSessionEvent(payload)
	if !ok {
		t.Fatal("decodeSessionEvent returned false")
	}
	if d.AddrFamily != dataplane.AFInet {
		t.Fatalf("AddrFamily = %d, want %d (AFInet)", d.AddrFamily, dataplane.AFInet)
	}
	// #3075: zone IDs decoded as u16 LE from payload[27:29]/[29:31].
	if d.IngressZoneID != 1 {
		t.Fatalf("IngressZoneID = %d, want 1", d.IngressZoneID)
	}
	if d.EgressZoneID != 2 {
		t.Fatalf("EgressZoneID = %d, want 2", d.EgressZoneID)
	}
	if d.Protocol != 6 {
		t.Fatalf("Protocol = %d, want 6", d.Protocol)
	}
	if d.SrcPort != 12345 {
		t.Fatalf("SrcPort = %d, want 12345", d.SrcPort)
	}
	if d.DstPort != 443 {
		t.Fatalf("DstPort = %d, want 443", d.DstPort)
	}
	if d.NATSrcPort != 40000 {
		t.Fatalf("NATSrcPort = %d, want 40000", d.NATSrcPort)
	}
	if d.OwnerRGID != 1 {
		t.Fatalf("OwnerRGID = %d, want 1", d.OwnerRGID)
	}
	if d.BinAddrLen != 4 {
		t.Fatalf("BinAddrLen = %d, want 4", d.BinAddrLen)
	}
	if d.SrcAddr != [16]byte{10, 0, 1, 102} {
		t.Fatalf("SrcAddr = %v, want 10.0.1.102", d.SrcAddr[:4])
	}
	if d.DstAddr != [16]byte{172, 16, 80, 200} {
		t.Fatalf("DstAddr = %v, want 172.16.80.200", d.DstAddr[:4])
	}
	if d.NATSrcAddr != [16]byte{172, 16, 80, 8} {
		t.Fatalf("NATSrcAddr = %v, want 172.16.80.8", d.NATSrcAddr[:4])
	}
	if d.NATDstAddr != [16]byte{} {
		t.Fatalf("NATDstAddr = %v, want zero", d.NATDstAddr[:4])
	}
	if d.SrcIP != "" || d.DstIP != "" || d.NATSrcIP != "" || d.NATDstIP != "" {
		t.Fatalf("strings = %q/%q/%q/%q, want all empty on the binary leg", d.SrcIP, d.DstIP, d.NATSrcIP, d.NATDstIP)
	}
	if !d.FabricRedirect {
		t.Fatal("FabricRedirect should be true")
	}
	if d.FabricIngress {
		t.Fatal("FabricIngress should be false")
	}
	if d.EgressIfindex != 12 {
		t.Fatalf("EgressIfindex = %d, want 12", d.EgressIfindex)
	}
	if d.TXIfindex != 11 {
		t.Fatalf("TXIfindex = %d, want 11", d.TXIfindex)
	}
	if d.TXVLANID != 80 {
		t.Fatalf("TXVLANID = %d, want 80", d.TXVLANID)
	}
	if d.NeighborMACBin != [6]byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff} {
		t.Fatalf("NeighborMACBin = %x, want aa:bb:cc:dd:ee:ff", d.NeighborMACBin)
	}
	if d.SrcMACBin != [6]byte{0x02, 0xbf, 0x72, 0x00, 0x50, 0x08} {
		t.Fatalf("SrcMACBin = %x, want 02:bf:72:00:50:08", d.SrcMACBin)
	}
	if d.NeighborMAC != "" || d.SrcMAC != "" || d.NextHop != "" {
		t.Fatalf("strings = %q/%q/%q, want all empty on the binary leg", d.NeighborMAC, d.SrcMAC, d.NextHop)
	}
}

// TestDecodeSessionEventZoneIDAbove255 is the #3075 cross-language fail-on-revert
// guard for the widened u16 zone wire field. The Rust codec encodes a stable
// name-hash zone id > 255; the Go decoder must read the full u16 (not truncate
// to the low byte). Reverting decodeSessionEvent to the u8 [27]/[28] read makes
// 300/1000 decode as 44/232 and this fails RED.
func TestDecodeSessionEventZoneIDAbove255(t *testing.T) {
	payload := buildSessionOpenV4Payload(
		6, 12345, 443,
		[4]byte{10, 0, 1, 102}, [4]byte{172, 16, 80, 200},
		[4]byte{0, 0, 0, 0}, [4]byte{0, 0, 0, 0},
		0, 0,
		1, 12, 11, 0, 0, 0,
		300, 1000, 0, // ingress/egress zone u16 (#3075), disposition
		[6]byte{}, [6]byte{}, [4]byte{},
	)
	d, ok := decodeSessionEvent(payload)
	if !ok {
		t.Fatal("decodeSessionEvent returned false for a zone id > 255")
	}
	if d.IngressZoneID != 300 {
		t.Fatalf("IngressZoneID = %d, want 300 (u16 truncated to u8?)", d.IngressZoneID)
	}
	if d.EgressZoneID != 1000 {
		t.Fatalf("EgressZoneID = %d, want 1000 (u16 truncated to u8?)", d.EgressZoneID)
	}
}

// TestDecodeSessionCloseEventZoneIDAbove255 is the close-frame sibling of the
// above: the +4 u16 zone trailer must round-trip an id > 255.
func TestDecodeSessionCloseEventZoneIDAbove255(t *testing.T) {
	payload := buildSessionCloseV4Payload(
		6, 12345, 443,
		[4]byte{10, 0, 1, 102}, [4]byte{172, 16, 80, 200},
		7, 0,
		300, 1000, // ingress/egress zone u16 (#3075)
	)
	d, ok := decodeSessionCloseEvent(payload)
	if !ok {
		t.Fatal("decodeSessionCloseEvent returned false for a zone id > 255")
	}
	if d.IngressZoneID != 300 || d.EgressZoneID != 1000 {
		t.Fatalf("close zones = (%d,%d), want (300,1000)", d.IngressZoneID, d.EgressZoneID)
	}
}

// #2785: the per-policy `then log` selection rides the open-frame flags
// byte (bits 1<<3/1<<4) so a synced session logs identically after failover.
// Reverting the eventstream.go decode drops the flags and this fails RED.
func TestDecodeSessionEventV4CarriesLogFlags(t *testing.T) {
	payload := buildSessionOpenV4Payload(
		6, 12345, 443,
		[4]byte{10, 0, 1, 102}, [4]byte{172, 16, 80, 200},
		[4]byte{}, [4]byte{},
		0, 0, 1, 1, 0, 0, 0,
		SessionEventFlagLogSessionInit|SessionEventFlagLogSessionClose,
		1, 2, 0,
		[6]byte{}, [6]byte{}, [4]byte{},
	)
	d, ok := decodeSessionEvent(payload)
	if !ok {
		t.Fatal("decodeSessionEvent returned false")
	}
	if !d.LogSessionInit || !d.LogSessionClose {
		t.Fatalf("expected both log flags decoded, got init=%t close=%t",
			d.LogSessionInit, d.LogSessionClose)
	}

	// Only close bit set: init must NOT leak true.
	payloadCloseOnly := buildSessionOpenV4Payload(
		6, 12345, 443,
		[4]byte{10, 0, 1, 102}, [4]byte{172, 16, 80, 200},
		[4]byte{}, [4]byte{},
		0, 0, 1, 1, 0, 0, 0,
		SessionEventFlagLogSessionClose,
		1, 2, 0,
		[6]byte{}, [6]byte{}, [4]byte{},
	)
	dCloseOnly, ok := decodeSessionEvent(payloadCloseOnly)
	if !ok {
		t.Fatal("decodeSessionEvent (close-only) returned false")
	}
	if dCloseOnly.LogSessionInit || !dCloseOnly.LogSessionClose {
		t.Fatalf("close-only: init=%t close=%t, want false/true",
			dCloseOnly.LogSessionInit, dCloseOnly.LogSessionClose)
	}

	// No log bits: both false.
	payloadNone := buildSessionOpenV4Payload(
		6, 12345, 443,
		[4]byte{10, 0, 1, 102}, [4]byte{172, 16, 80, 200},
		[4]byte{}, [4]byte{},
		0, 0, 1, 1, 0, 0, 0,
		0,
		1, 2, 0,
		[6]byte{}, [6]byte{}, [4]byte{},
	)
	dNone, ok := decodeSessionEvent(payloadNone)
	if !ok {
		t.Fatal("decodeSessionEvent (none) returned false")
	}
	if dNone.LogSessionInit || dNone.LogSessionClose {
		t.Fatalf("none: expected both false, got init=%t close=%t",
			dNone.LogSessionInit, dNone.LogSessionClose)
	}
}

// #3301: the admitting policy's firewall metadata (policy_id,
// policy_counter_idx, inactivity_timeout seconds) rides the open frame as
// trailing fields after NextHop. Reverting the eventstream.go decode drops
// them and this fails RED. A legacy (62-byte) frame without the trailing
// block must still decode with the fields at 0 (rolling-upgrade safe).
func TestDecodeSessionEventV4CarriesPolicyFields3301(t *testing.T) {
	base := buildSessionOpenV4Payload(
		6, 12345, 443,
		[4]byte{10, 0, 1, 102}, [4]byte{172, 16, 80, 200},
		[4]byte{}, [4]byte{},
		0, 0, 1, 1, 0, 0, 0,
		0,
		1, 2, 0,
		[6]byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
		[6]byte{0x02, 0xbf, 0x72, 0x00, 0x50, 0x08},
		[4]byte{172, 16, 80, 1},
	)
	// Append the 12-byte trailing block: policy_id, policy_counter_idx,
	// inactivity_timeout (seconds), each u32 LE.
	trailer := make([]byte, 12)
	binary.LittleEndian.PutUint32(trailer[0:4], 42)
	binary.LittleEndian.PutUint32(trailer[4:8], 7)
	binary.LittleEndian.PutUint32(trailer[8:12], 30)
	payload := append(append([]byte{}, base...), trailer...)

	d, ok := decodeSessionEvent(payload)
	if !ok {
		t.Fatal("decodeSessionEvent returned false")
	}
	if d.NextHop != "" {
		t.Fatalf("NextHop = %q, want empty on the binary leg", d.NextHop)
	}
	if d.BinAddrLen != 4 {
		t.Fatalf("BinAddrLen = %d, want 4", d.BinAddrLen)
	}
	if d.PolicyID != 42 {
		t.Fatalf("PolicyID = %d, want 42", d.PolicyID)
	}
	if d.PolicyCounterIdx != 7 {
		t.Fatalf("PolicyCounterIdx = %d, want 7", d.PolicyCounterIdx)
	}
	if d.AppTimeout != 30 {
		t.Fatalf("AppTimeout = %d, want 30", d.AppTimeout)
	}

	// Mixed-version: a legacy frame WITHOUT the trailing block still decodes,
	// with the new fields at 0 (unattributed / no counter / global timeout).
	dLegacy, ok := decodeSessionEvent(base)
	if !ok {
		t.Fatal("decodeSessionEvent (legacy, no trailer) returned false")
	}
	if dLegacy.PolicyID != 0 || dLegacy.PolicyCounterIdx != 0 || dLegacy.AppTimeout != 0 {
		t.Fatalf("legacy frame: policy=%d counter=%d appto=%d, want all 0",
			dLegacy.PolicyID, dLegacy.PolicyCounterIdx, dLegacy.AppTimeout)
	}
}

func TestDecodeSessionEventV4LocalDelivery(t *testing.T) {
	payload := buildSessionOpenV4Payload(
		17, 53, 53,
		[4]byte{10, 0, 1, 1}, [4]byte{10, 0, 1, 10},
		[4]byte{}, [4]byte{},
		0, 0, 0, 0, 0, 0, 0,
		0,
		1, 2, 1, // disposition=1 → local_delivery
		[6]byte{}, [6]byte{}, [4]byte{},
	)
	d, ok := decodeSessionEvent(payload)
	if !ok {
		t.Fatal("decodeSessionEvent returned false")
	}
	if d.Disposition != "local_delivery" {
		t.Fatalf("Disposition = %q, want local_delivery", d.Disposition)
	}
}

func TestDecodeSessionCloseEventV4(t *testing.T) {
	payload := buildSessionCloseV4Payload(
		6,          // TCP
		12345, 443, // ports
		[4]byte{10, 0, 1, 102}, [4]byte{172, 16, 80, 200},
		1,                              // ownerRG
		SessionEventFlagFabricRedirect, // flags
		3, 4,                           // ingress/egress zone IDs
	)

	d, ok := decodeSessionCloseEvent(payload)
	if !ok {
		t.Fatal("decodeSessionCloseEvent returned false")
	}
	if d.IngressZoneID != 3 || d.EgressZoneID != 4 {
		t.Fatalf("ZoneIDs = (%d,%d), want (3,4)", d.IngressZoneID, d.EgressZoneID)
	}
	if d.AddrFamily != dataplane.AFInet {
		t.Fatalf("AddrFamily = %d, want %d (AFInet)", d.AddrFamily, dataplane.AFInet)
	}
	if d.Protocol != 6 {
		t.Fatalf("Protocol = %d, want 6", d.Protocol)
	}
	if d.SrcPort != 12345 || d.DstPort != 443 {
		t.Fatalf("ports = %d/%d, want 12345/443", d.SrcPort, d.DstPort)
	}
	if d.BinAddrLen != 4 {
		t.Fatalf("BinAddrLen = %d, want 4", d.BinAddrLen)
	}
	if d.SrcAddr != [16]byte{10, 0, 1, 102} {
		t.Fatalf("SrcAddr = %v, want 10.0.1.102", d.SrcAddr[:4])
	}
	if d.DstAddr != [16]byte{172, 16, 80, 200} {
		t.Fatalf("DstAddr = %v, want 172.16.80.200", d.DstAddr[:4])
	}
	if d.SrcIP != "" || d.DstIP != "" {
		t.Fatalf("strings = %q/%q, want empty on the binary leg", d.SrcIP, d.DstIP)
	}
	if d.OwnerRGID != 1 {
		t.Fatalf("OwnerRGID = %d, want 1", d.OwnerRGID)
	}
	if !d.FabricRedirect {
		t.Fatal("FabricRedirect should be true")
	}
}

// TestDecodeSessionEventHighIfindex is the #2467 fail-on-revert guard. Linux
// ifindexes are a full `int` and exceed 32767 on long-running systems with
// interface churn. The wire fields used to be int16, so an ifindex of 70000
// truncated and decoded as a negative number. The builder writes the value via
// the now-int32 PutUint32 path; with a revert to int16 these high values would
// wrap negative and the assertions below fail RED.
func TestDecodeSessionEventHighIfindex(t *testing.T) {
	const (
		hiOwnerRG = int32(40000) // > int16 max (32767)
		hiEgress  = int32(70000) // > uint16 max (65535)
		hiTX      = int32(65536) // exactly uint16 max + 1 (would be 0 as int16)
	)
	payload := buildSessionOpenV4Payload(
		6,
		12345, 443,
		[4]byte{10, 0, 1, 102}, [4]byte{172, 16, 80, 200},
		[4]byte{}, [4]byte{},
		0, 0,
		hiOwnerRG,
		hiEgress, hiTX,
		0, 80,
		0,
		1, 2, 0,
		[6]byte{}, [6]byte{}, [4]byte{},
	)

	d, ok := decodeSessionEvent(payload)
	if !ok {
		t.Fatal("decodeSessionEvent returned false")
	}
	if d.OwnerRGID != int(hiOwnerRG) {
		t.Fatalf("OwnerRGID = %d, want %d (must not wrap negative)", d.OwnerRGID, hiOwnerRG)
	}
	if d.EgressIfindex != int(hiEgress) {
		t.Fatalf("EgressIfindex = %d, want %d (must not wrap negative)", d.EgressIfindex, hiEgress)
	}
	if d.TXIfindex != int(hiTX) {
		t.Fatalf("TXIfindex = %d, want %d (must not wrap)", d.TXIfindex, hiTX)
	}
	// Downstream fields must still decode correctly after the +6-byte shift.
	if d.TXVLANID != 80 {
		t.Fatalf("TXVLANID = %d, want 80", d.TXVLANID)
	}
	if d.IngressZoneID != 1 || d.EgressZoneID != 2 {
		t.Fatalf("ZoneIDs = (%d,%d), want (1,2)", d.IngressZoneID, d.EgressZoneID)
	}
}

// TestDecodeSessionCloseEventHighOwnerRG is the #2467 close-side fail-on-revert
// guard: the close frame's owner RG must survive past int16 too.
func TestDecodeSessionCloseEventHighOwnerRG(t *testing.T) {
	const hiOwnerRG = int32(40000) // > int16 max
	payload := buildSessionCloseV4Payload(
		6,
		12345, 443,
		[4]byte{10, 0, 1, 102}, [4]byte{172, 16, 80, 200},
		hiOwnerRG,
		SessionEventFlagFabricRedirect,
		3, 4,
	)

	d, ok := decodeSessionCloseEvent(payload)
	if !ok {
		t.Fatal("decodeSessionCloseEvent returned false")
	}
	if d.OwnerRGID != int(hiOwnerRG) {
		t.Fatalf("OwnerRGID = %d, want %d (must not wrap negative)", d.OwnerRGID, hiOwnerRG)
	}
	if d.IngressZoneID != 3 || d.EgressZoneID != 4 {
		t.Fatalf("ZoneIDs = (%d,%d), want (3,4)", d.IngressZoneID, d.EgressZoneID)
	}
	if !d.FabricRedirect {
		t.Fatal("FabricRedirect should be true")
	}
}

func TestDecodeSessionEventRejectsTruncated(t *testing.T) {
	// Too short for v4 (#2467: need 62 bytes minimum, 30-byte fixed header).
	_, ok := decodeSessionEvent([]byte{4, 6, 0, 0})
	if ok {
		t.Fatal("should reject truncated v4 payload")
	}
	// Invalid address family (long enough to pass the length gate so the AF
	// switch is what rejects it).
	badAF := make([]byte, 64)
	badAF[0] = 99
	_, ok = decodeSessionEvent(badAF)
	if ok {
		t.Fatal("should reject unknown address family")
	}
}

func TestDecodeDataplaneEventPolicyDenyRTFlow(t *testing.T) {
	payload := buildDataplaneEventV4Payload(
		6,
		12345, 443,
		[4]byte{10, 0, 1, 102}, [4]byte{172, 16, 80, 200},
		[4]byte{172, 16, 80, 8},
		40000,
		1, 2,
		7,
		99,
		1700000000000000000,
	)
	if !dataplaneEventPayloadMatchesFrame(EventFrameTypePolicyDeny, payload) {
		t.Fatal("RT_FLOW payload did not match policy-deny event-stream frame type")
	}
	binary.LittleEndian.PutUint32(payload[56:60], 1234)
	binary.LittleEndian.PutUint32(payload[60:64], 5678)
	binary.LittleEndian.PutUint16(payload[64:66], 3)
	payload[134] = dataplane.CloseReasonPolicy
	rec, ok := decodeDataplaneEventPayload(payload)
	if !ok {
		t.Fatal("decodeDataplaneEventPayload returned false")
	}
	if rec.Type != "POLICY_DENY" || rec.Action != "deny" {
		t.Fatalf("event = %s/%s, want POLICY_DENY/deny", rec.Type, rec.Action)
	}
	if rec.Protocol != "TCP" {
		t.Fatalf("Protocol = %q, want TCP", rec.Protocol)
	}
	if rec.SrcAddr != "10.0.1.102:12345" {
		t.Fatalf("SrcAddr = %q, want 10.0.1.102:12345", rec.SrcAddr)
	}
	if rec.DstAddr != "172.16.80.200:443" {
		t.Fatalf("DstAddr = %q, want 172.16.80.200:443", rec.DstAddr)
	}
	if rec.NATSrcAddr != "172.16.80.8:40000" {
		t.Fatalf("NATSrcAddr = %q, want 172.16.80.8:40000", rec.NATSrcAddr)
	}
	if rec.PolicyID != 99 || rec.InZone != 1 || rec.OutZone != 2 {
		t.Fatalf("identity = policy %d zones %d->%d, want policy 99 zones 1->2", rec.PolicyID, rec.InZone, rec.OutZone)
	}
	if rec.ScreenCheck != "" {
		t.Fatalf("ScreenCheck/reason = %q, want empty for policy-deny RT_FLOW", rec.ScreenCheck)
	}
	if rec.RuleID != 1234 || rec.TermID != 5678 || rec.OwnerRGID != 3 || rec.Reason != "Rejected by policy" {
		t.Fatalf("metadata = rule %d term %d owner_rg %d reason %q, want 1234/5678/3/Rejected by policy",
			rec.RuleID, rec.TermID, rec.OwnerRGID, rec.Reason)
	}
	if rec.SessionPkts != 0 || rec.SessionBytes != 0 {
		t.Fatalf("security metadata must not leak through session counters: pkts=%d bytes=%d",
			rec.SessionPkts, rec.SessionBytes)
	}
}

func TestFrameRoundTrip(t *testing.T) {
	payload := buildSessionOpenV4Payload(
		6, 1234, 80,
		[4]byte{10, 0, 1, 1}, [4]byte{10, 0, 2, 1},
		[4]byte{}, [4]byte{},
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		[6]byte{}, [6]byte{}, [4]byte{},
	)

	r, w := io.Pipe()
	go func() {
		_ = writeFrame(w, EventTypeSessionOpen, 42, payload)
		w.Close()
	}()

	typ, seq, got, err := readFrame(r)
	if err != nil {
		t.Fatalf("readFrame: %v", err)
	}
	if typ != EventTypeSessionOpen {
		t.Fatalf("type = %d, want %d", typ, EventTypeSessionOpen)
	}
	if seq != 42 {
		t.Fatalf("seq = %d, want 42", seq)
	}
	if len(got) != len(payload) {
		t.Fatalf("payload len = %d, want %d", len(got), len(payload))
	}
}

// TestEventStreamStartReturnsErrorOnListenFailure verifies that a failed
// listener setup surfaces an error from Start() rather than being logged and
// swallowed, and that ListenerBound() stays false so callers can refuse to
// treat the stream as healthy (#5273). Binding a socket inside a non-existent
// directory reliably fails with ENOENT.
func TestEventStreamStartReturnsErrorOnListenFailure(t *testing.T) {
	unbindable := filepath.Join(t.TempDir(), "missing-dir", "events.sock")
	es := NewEventStream(unbindable)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := es.Start(ctx); err == nil {
		t.Fatal("Start() = nil error for an unbindable socket path, want error")
	}
	if es.ListenerBound() {
		t.Fatal("ListenerBound() = true after a failed Start, want false")
	}
}

// TestEventStreamListenerBoundReflectsLifecycle verifies ListenerBound tracks
// the bind: false before Start, true after a successful bind, false after Close.
func TestEventStreamListenerBoundReflectsLifecycle(t *testing.T) {
	es := NewEventStream(filepath.Join(t.TempDir(), "events.sock"))
	if es.ListenerBound() {
		t.Fatal("ListenerBound() = true before Start, want false")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := es.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if !es.ListenerBound() {
		t.Fatal("ListenerBound() = false after a successful Start, want true")
	}
	es.Close()
	if es.ListenerBound() {
		t.Fatal("ListenerBound() = true after Close, want false")
	}
}

// TestEventStreamListenerOwnershipIsFailClosed proves that a competing daemon
// cannot unlink or replace a live listener. The contender fails on the
// process-lifetime sidecar lock, and even an explicit Close on that non-owner
// leaves the first listener reachable. Once the owner closes, the lock is
// released and the path can be acquired again (#5273).
func TestEventStreamListenerOwnershipIsFailClosed(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "events.sock")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	owner := NewEventStream(socketPath)
	if err := owner.Start(ctx); err != nil {
		t.Fatalf("owner Start: %v", err)
	}
	defer owner.Close()

	contender := NewEventStream(socketPath)
	if err := contender.Start(ctx); err == nil {
		contender.Close()
		t.Fatal("contender Start = nil, want ownership error")
	}
	contender.Close()
	if contender.ListenerBound() {
		t.Fatal("contender ListenerBound = true after rejected Start")
	}

	conn, err := net.DialTimeout("unix", socketPath, time.Second)
	if err != nil {
		t.Fatalf("owner listener was unlinked by contender cleanup: %v", err)
	}
	_ = conn.Close()

	owner.Close()
	replacement := NewEventStream(socketPath)
	if err := replacement.Start(ctx); err != nil {
		t.Fatalf("replacement Start after owner Close: %v", err)
	}
	replacement.Close()
}

// TestEventStreamStartDoesNotDialLegacyLiveOwner covers a mixed-version owner
// that predates the sidecar lock. Kernel-table inspection must reject its live
// socket without dialing it: a dial would be accepted as a replacement helper
// and disconnect the old daemon's real helper connection.
func TestEventStreamStartDoesNotDialLegacyLiveOwner(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "events.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("legacy listener: %v", err)
	}
	defer listener.Close()
	unixListener, ok := listener.(*net.UnixListener)
	if !ok {
		t.Fatalf("listener type = %T, want *net.UnixListener", listener)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	contender := NewEventStream(socketPath)
	if err := contender.Start(ctx); err == nil {
		contender.Close()
		t.Fatal("Start against legacy live owner = nil, want ownership error")
	}
	contender.Close()

	if err := unixListener.SetDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		t.Fatalf("SetDeadline: %v", err)
	}
	conn, err := unixListener.Accept()
	if err == nil {
		_ = conn.Close()
		t.Fatal("legacy listener accepted a liveness-probe connection")
	}
	if ne, ok := err.(net.Error); !ok || !ne.Timeout() {
		t.Fatalf("legacy Accept error = %v, want timeout with no probe connection", err)
	}
	if _, err := os.Lstat(socketPath); err != nil {
		t.Fatalf("contender removed legacy owner's socket: %v", err)
	}
}

// TestEventStreamStartReclaimsProvenStaleSocket keeps crash recovery intact:
// an orphaned socket inode with no accepting listener is removed only after the
// ownership lock is held and the kernel socket table proves no live owner.
func TestEventStreamStartReclaimsProvenStaleSocket(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "events.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("seed stale listener: %v", err)
	}
	unixListener, ok := listener.(*net.UnixListener)
	if !ok {
		t.Fatalf("listener type = %T, want *net.UnixListener", listener)
	}
	unixListener.SetUnlinkOnClose(false)
	if err := listener.Close(); err != nil {
		t.Fatalf("close stale listener: %v", err)
	}
	if _, err := os.Lstat(socketPath); err != nil {
		t.Fatalf("stale socket precondition: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	es := NewEventStream(socketPath)
	if err := es.Start(ctx); err != nil {
		t.Fatalf("Start with proven stale socket: %v", err)
	}
	es.Close()
}

func TestEventStreamAcceptAndRead(t *testing.T) {
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "test-events.sock")

	es := NewEventStream(sockPath)
	var received atomic.Int32
	var lastSeq atomic.Uint64
	es.SetOnEvent(func(eventType uint8, seq uint64, delta SessionDeltaInfo) bool {
		received.Add(1)
		lastSeq.Store(seq)
		return true
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	es.Start(ctx)
	defer es.Close()

	// Wait for listener.
	time.Sleep(50 * time.Millisecond)

	// Connect as the "helper".
	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// Wait for connection to be accepted.
	deadline := time.Now().Add(2 * time.Second)
	for !es.IsConnected() {
		if time.Now().After(deadline) {
			t.Fatal("event stream did not become connected")
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Send 3 SessionOpen events.
	payload := buildSessionOpenV4Payload(
		6, 1000, 80,
		[4]byte{10, 0, 1, 1}, [4]byte{10, 0, 2, 1},
		[4]byte{}, [4]byte{},
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		[6]byte{}, [6]byte{}, [4]byte{},
	)
	for i := uint64(1); i <= 3; i++ {
		if err := writeFrame(conn, EventTypeSessionOpen, i, payload); err != nil {
			t.Fatalf("write frame %d: %v", i, err)
		}
	}

	// Wait for events to be processed.
	deadline = time.Now().Add(2 * time.Second)
	for received.Load() < 3 {
		if time.Now().After(deadline) {
			t.Fatalf("received only %d events, want 3", received.Load())
		}
		time.Sleep(10 * time.Millisecond)
	}

	if lastSeq.Load() != 3 {
		t.Fatalf("lastSeq = %d, want 3", lastSeq.Load())
	}
}

func TestEventStreamSessionEventBeforeCallbackQueuesUntilCallback(t *testing.T) {
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "test-events.sock")

	es := NewEventStream(sockPath)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	es.Start(ctx)
	defer es.Close()

	time.Sleep(50 * time.Millisecond)
	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	deadline := time.Now().Add(2 * time.Second)
	for !es.IsConnected() {
		if time.Now().After(deadline) {
			t.Fatal("event stream did not become connected")
		}
		time.Sleep(10 * time.Millisecond)
	}

	payload := buildSessionOpenV4Payload(
		6, 1000, 80,
		[4]byte{10, 0, 1, 1}, [4]byte{10, 0, 2, 1},
		[4]byte{}, [4]byte{},
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		[6]byte{}, [6]byte{}, [4]byte{},
	)
	if err := writeFrame(conn, EventTypeSessionOpen, 5, payload); err != nil {
		t.Fatalf("write session event: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
	if typ, seq, _, err := readFrame(conn); err == nil {
		t.Fatalf("unexpected ack before callback was wired: type %d seq %d", typ, seq)
	}

	got := make(chan uint64, 1)
	es.SetOnEvent(func(_ uint8, seq uint64, _ SessionDeltaInfo) bool {
		got <- seq
		return true
	})
	select {
	case seq := <-got:
		if seq != 5 {
			t.Fatalf("callback seq = %d, want 5", seq)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("callback not invoked after late registration")
	}
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	typ, seq, _, err := readFrame(conn)
	if err != nil {
		t.Fatalf("read ack after callback: %v", err)
	}
	if typ != EventTypeAck || seq != 5 {
		t.Fatalf("ack after callback = type %d seq %d, want type %d seq 5", typ, seq, EventTypeAck)
	}
}

func TestEventStreamSessionCallbackFalseWithholdsAck(t *testing.T) {
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "test-events.sock")

	es := NewEventStream(sockPath)
	es.SetOnEvent(func(_ uint8, _ uint64, _ SessionDeltaInfo) bool {
		return false
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	es.Start(ctx)
	defer es.Close()

	time.Sleep(50 * time.Millisecond)
	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	deadline := time.Now().Add(2 * time.Second)
	for !es.IsConnected() {
		if time.Now().After(deadline) {
			t.Fatal("event stream did not become connected")
		}
		time.Sleep(10 * time.Millisecond)
	}

	payload := buildSessionOpenV4Payload(
		6, 1000, 80,
		[4]byte{10, 0, 1, 1}, [4]byte{10, 0, 2, 1},
		[4]byte{}, [4]byte{},
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		[6]byte{}, [6]byte{}, [4]byte{},
	)
	if err := writeFrame(conn, EventTypeSessionOpen, 9, payload); err != nil {
		t.Fatalf("write session event: %v", err)
	}

	_ = conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	if typ, seq, _, err := readFrame(conn); err == nil {
		t.Fatalf("unexpected ack for unapplied callback: type %d seq %d", typ, seq)
	}
	if acked := es.LastAckedSequence(); acked != 0 {
		t.Fatalf("LastAckedSequence = %d, want 0 after callback returned false", acked)
	}

	es.SetOnEvent(func(_ uint8, _ uint64, _ SessionDeltaInfo) bool {
		return true
	})
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	typ, seq, _, err := readFrame(conn)
	if err != nil {
		t.Fatalf("read ack after callback became ready: %v", err)
	}
	if typ != EventTypeAck || seq != 9 {
		t.Fatalf("ack after callback ready = type %d seq %d, want type %d seq 9", typ, seq, EventTypeAck)
	}
}

func TestEventStreamDataplaneEventAckAndCallback(t *testing.T) {
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "test-events.sock")

	es := NewEventStream(sockPath)
	type dataplaneEventResult struct {
		seq uint64
		rec logging.EventRecord
	}
	got := make(chan dataplaneEventResult, 1)
	es.SetOnDataplaneEvent(func(seq uint64, rec logging.EventRecord) {
		got <- dataplaneEventResult{seq: seq, rec: rec}
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	es.Start(ctx)
	defer es.Close()

	waitCtx, waitCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer waitCancel()
	var conn net.Conn
	for conn == nil {
		var err error
		conn, err = net.Dial("unix", sockPath)
		if err == nil {
			break
		}
		select {
		case <-waitCtx.Done():
			t.Fatalf("dial: %v", err)
		case <-time.After(10 * time.Millisecond):
		}
	}
	defer conn.Close()

	connectCtx, connectCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer connectCancel()
	for !es.IsConnected() {
		select {
		case <-connectCtx.Done():
			t.Fatal("event stream did not become connected")
		case <-time.After(10 * time.Millisecond):
		}
	}

	payload := buildDataplaneEventV4Payload(
		6, 1111, 443,
		[4]byte{10, 0, 1, 5}, [4]byte{172, 16, 80, 200},
		[4]byte{172, 16, 80, 8},
		40000,
		1, 2,
		0, 77,
		0,
	)
	if err := writeFrame(conn, EventFrameTypePolicyDeny, 7, payload); err != nil {
		t.Fatalf("write dataplane event: %v", err)
	}

	select {
	case result := <-got:
		if result.seq != 7 {
			t.Fatalf("seq = %d, want 7", result.seq)
		}
		if result.rec.Type != "POLICY_DENY" || result.rec.PolicyID != 77 {
			t.Fatalf("rec = %+v, want policy deny policy 77", result.rec)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("dataplane event callback not called")
	}

	_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	typ, seq, _, err := readFrame(conn)
	if err != nil {
		t.Fatalf("read ack: %v", err)
	}
	if typ != EventTypeAck || seq != 7 {
		t.Fatalf("ack = type %d seq %d, want type %d seq 7", typ, seq, EventTypeAck)
	}
	if got := es.PolicyDenyEvents.Load(); got != 1 {
		t.Fatalf("PolicyDenyEvents = %d, want 1", got)
	}
}

func TestEventStreamDataplaneEventRawCallbackPreferred(t *testing.T) {
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "test-events.sock")

	es := NewEventStream(sockPath)
	rawGot := make(chan []byte, 1)
	decodedGot := make(chan struct{}, 1)
	es.SetOnRawDataplaneEvent(func(seq uint64, payload []byte) {
		if seq != 11 {
			t.Fatalf("seq = %d, want 11", seq)
		}
		rawGot <- append([]byte(nil), payload...)
	})
	es.SetOnDataplaneEvent(func(uint64, logging.EventRecord) {
		decodedGot <- struct{}{}
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	es.Start(ctx)
	defer es.Close()

	waitCtx, waitCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer waitCancel()
	var conn net.Conn
	for conn == nil {
		var err error
		conn, err = net.Dial("unix", sockPath)
		if err == nil {
			break
		}
		select {
		case <-waitCtx.Done():
			t.Fatalf("dial: %v", err)
		case <-time.After(10 * time.Millisecond):
		}
	}
	defer conn.Close()

	connectCtx, connectCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer connectCancel()
	for !es.IsConnected() {
		select {
		case <-connectCtx.Done():
			t.Fatal("event stream did not become connected")
		case <-time.After(10 * time.Millisecond):
		}
	}

	payload := buildDataplaneEventV4Payload(
		6, 1111, 443,
		[4]byte{10, 0, 1, 5}, [4]byte{172, 16, 80, 200},
		[4]byte{172, 16, 80, 8},
		40000,
		1, 2,
		0, 77,
		0,
	)
	if err := writeFrame(conn, EventFrameTypePolicyDeny, 11, payload); err != nil {
		t.Fatalf("write dataplane event: %v", err)
	}

	select {
	case got := <-rawGot:
		if !bytes.Equal(got, payload) {
			t.Fatalf("raw payload changed: got %d bytes, want %d", len(got), len(payload))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("raw dataplane event callback not called")
	}
	select {
	case <-decodedGot:
		t.Fatal("decoded callback should not fire when raw callback is installed")
	default:
	}
}

// waitFrameApplied blocks until the dispatcher has FINISHED frame seq.
//
// #7563: the dispatcher invokes the raw/decoded callback BEFORE it accounts
// the frame — both in dispatchOrQueueDataplaneFrame and in the pending-flush
// path — and advances lastAppliedSeq after both. A test that observes the
// callback and then reads a counter is therefore racing the accounting: the
// callback has fired by construction, the Add(1) has not. On an idle box the
// dispatcher goroutine wins that race every time and the read looks
// deterministic; under a loaded `go test ./...` it does not. That is exactly
// why TestEventStreamSessionCloseRTFlowRoutesToRawCallback failed only under
// full-tree parallel load and passed on re-run of the same tree.
//
// lastAppliedSeq is this package's existing completion signal for that
// question — eventstream_fullresync_prevseq_5362_test.go already waits on it
// the same way — and it is advanced by the SAME goroutine after the
// accounting, so a counter read taken once it covers the frame happens-after
// the Add(1).
//
// This is a wait on a real observable, not a retry: a frame that never
// applies still fails, naming the watermark it never reached.
func waitFrameApplied(t *testing.T, es *EventStream, seq uint64) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if es.lastAppliedSeq.Load() >= seq {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("frame seq=%d never reached the applied watermark (last_applied=%d): "+
				"the dispatcher never finished the frame", seq, es.lastAppliedSeq.Load())
		}
		time.Sleep(time.Millisecond)
	}
}

// TestEventStreamSessionCloseRTFlowRoutesToRawCallback proves the #2460
// EventFrameTypeSessionClose (type 14) frame is accepted by the event-stream
// frame dispatcher and routed to the raw dataplane-event callback (the path
// the daemon wires to eventReader.ProcessRawEvent so the NetFlow/IPFIX
// session-close exporters fire). It further feeds the decoded payload through
// a real EventReader and asserts a single Type=="SESSION_CLOSE" record with
// the correct tuple results — closing the helper-emit -> Go-decode loop.
//
// Fail-on-revert: drop EventFrameTypeSessionClose from the dispatcher switch
// (the type-14 case) and the frame is treated as unknown and dropped, so the
// raw callback never fires.
func TestEventStreamSessionCloseRTFlowRoutesToRawCallback(t *testing.T) {
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "test-events.sock")

	es := NewEventStream(sockPath)
	reader := logging.NewEventReader(nil, logging.NewEventBuffer(8))
	rawSeen := make(chan logging.EventRecord, 4)
	es.SetOnRawDataplaneEvent(func(_ uint64, payload []byte) {
		if !reader.ProcessRawEvent(payload) {
			return
		}
		rec, ok := logging.DecodeRawEventRecord(payload)
		if ok {
			rawSeen <- rec
		}
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	es.Start(ctx)
	defer es.Close()

	waitCtx, waitCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer waitCancel()
	var conn net.Conn
	for conn == nil {
		var err error
		conn, err = net.Dial("unix", sockPath)
		if err == nil {
			break
		}
		select {
		case <-waitCtx.Done():
			t.Fatalf("dial: %v", err)
		case <-time.After(10 * time.Millisecond):
		}
	}
	defer conn.Close()
	for !es.IsConnected() {
		select {
		case <-waitCtx.Done():
			t.Fatal("event stream did not become connected")
		case <-time.After(10 * time.Millisecond):
		}
	}

	// 136-byte dataplane.Event payload, EventType = SESSION_CLOSE (2),
	// mirroring the Rust encode_session_close_rt_flow layout.
	payload := buildTypedDataplaneEventV4Payload(
		dataplane.EventTypeSessionClose,
		dataplane.ActionDeny, // inert for a close
		6,                    // TCP
		12345, 443,
		[4]byte{10, 0, 1, 102}, [4]byte{172, 16, 80, 200},
		[4]byte{172, 16, 80, 8},
		40000,
		2, 3,
		0, 0, 0, 0,
		0, // close reason none
		0,
	)
	if err := writeFrame(conn, EventFrameTypeSessionClose, 11, payload); err != nil {
		t.Fatalf("write session-close frame: %v", err)
	}

	select {
	case rec := <-rawSeen:
		if rec.Type != "SESSION_CLOSE" {
			t.Fatalf("Type = %q, want SESSION_CLOSE", rec.Type)
		}
		if rec.SrcAddr != "10.0.1.102:12345" || rec.DstAddr != "172.16.80.200:443" {
			t.Fatalf("tuple = %s -> %s, want 10.0.1.102:12345 -> 172.16.80.200:443",
				rec.SrcAddr, rec.DstAddr)
		}
		if rec.SessionPkts != 0 || rec.SessionBytes != 0 {
			t.Fatalf("counters = (%d,%d), want (0,0) pending #2501",
				rec.SessionPkts, rec.SessionBytes)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("session-close RT_FLOW frame did not reach the raw callback")
	}

	// The raw callback above fires BEFORE the frame is accounted, so read the
	// counter only once the dispatcher has finished the frame (#7563).
	waitFrameApplied(t, es, 11)
	if got := es.SessionCloseEvents.Load(); got != 1 {
		t.Fatalf("SessionCloseEvents = %d, want 1", got)
	}

	// #2510: the public Status() DTO must surface the close counter so
	// operators can observe session-close RT_FLOW volume via CLI/REST/
	// gRPC/Prometheus. Fails on master, where Status() omitted it.
	if st := es.Status(); st.SessionCloseEvents != 1 {
		t.Fatalf("Status().SessionCloseEvents = %d, want 1", st.SessionCloseEvents)
	}
}

// TestEventStreamSessionCloseDropSurfacedInStatus proves #2510: a dropped
// session-close frame increments SessionCloseDrops AND that drop is visible
// through the public Status() DTO. On master Status() omitted the close
// drop counter, so this assertion fails.
func TestEventStreamSessionCloseDropSurfacedInStatus(t *testing.T) {
	es := NewEventStream("")
	es.recordDataplaneEventDrop(EventFrameTypeSessionClose)
	es.recordDataplaneEventDrop(EventFrameTypeSessionCreate)

	if got := es.SessionCloseDrops.Load(); got != 1 {
		t.Fatalf("SessionCloseDrops = %d, want 1", got)
	}
	st := es.Status()
	if st.SessionCloseDrops != 1 {
		t.Fatalf("Status().SessionCloseDrops = %d, want 1", st.SessionCloseDrops)
	}
	if st.SessionCreateDrops != 1 {
		t.Fatalf("Status().SessionCreateDrops = %d, want 1", st.SessionCreateDrops)
	}
}

func TestEventStreamRawDataplaneEventsFeedSyslogFanout(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	addr := pc.LocalAddr().(*net.UDPAddr)

	client, err := logging.NewSyslogClient("127.0.0.1", addr.Port)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	client.MinSeverity = logging.SyslogInfo
	client.Categories = logging.CategoryAll

	reader := logging.NewEventReader(nil, logging.NewEventBuffer(8))
	reader.SetSyslogClients([]*logging.SyslogClient{client})

	dir := t.TempDir()
	sockPath := filepath.Join(dir, "test-events.sock")
	es := NewEventStream(sockPath)
	rawProcessed := make(chan bool, 4)
	es.SetOnRawDataplaneEvent(func(_ uint64, payload []byte) {
		rawProcessed <- reader.ProcessRawEvent(payload)
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	es.Start(ctx)
	defer es.Close()

	waitCtx, waitCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer waitCancel()
	var conn net.Conn
	for conn == nil {
		conn, err = net.Dial("unix", sockPath)
		if err == nil {
			break
		}
		select {
		case <-waitCtx.Done():
			t.Fatalf("dial: %v", err)
		case <-time.After(10 * time.Millisecond):
		}
	}
	defer conn.Close()
	for !es.IsConnected() {
		select {
		case <-waitCtx.Done():
			t.Fatal("event stream did not become connected")
		case <-time.After(10 * time.Millisecond):
		}
	}

	frames := []struct {
		label     string
		typ       uint8
		seq       uint64
		payload   []byte
		want      string
		wantExtra string
	}{
		{
			label: "policy-deny",
			typ:   EventFrameTypePolicyDeny,
			seq:   31,
			payload: buildTypedDataplaneEventV4Payload(
				dataplane.EventTypePolicyDeny,
				dataplane.ActionDeny,
				6,
				1111, 443,
				[4]byte{10, 0, 1, 5}, [4]byte{172, 16, 80, 200},
				[4]byte{},
				0,
				1, 2,
				77,
				77,
				0,
				3,
				dataplane.CloseReasonPolicy,
				0,
			),
			want: "RT_FLOW POLICY_DENY",
		},
		{
			label: "screen-drop",
			typ:   EventFrameTypeScreenDrop,
			seq:   32,
			payload: buildTypedDataplaneEventV4Payload(
				dataplane.EventTypeScreenDrop,
				dataplane.ActionDeny,
				6,
				2222, 80,
				[4]byte{203, 0, 113, 10}, [4]byte{203, 0, 113, 10},
				[4]byte{},
				0,
				1, 0,
				dataplane.ScreenLandAttack,
				0,
				0,
				0,
				dataplane.CloseReasonNone,
				0,
			),
			want: "RT_FLOW SCREEN_DROP",
		},
		{
			label: "pbr-filter-log",
			typ:   EventFrameTypeFilterLog,
			seq:   33,
			payload: buildTypedDataplaneEventV4Payload(
				dataplane.EventTypeFilterLog,
				dataplane.ActionPermit,
				6,
				3333, 443,
				[4]byte{10, 0, 1, 6}, [4]byte{198, 51, 100, 20},
				[4]byte{},
				0,
				1, 2,
				23,
				0,
				5,
				0,
				1,
				0,
			),
			want:      "RT_FLOW FILTER_LOG",
			wantExtra: "source=pbr",
		},
		{
			label: "input-filter-log-deny",
			typ:   EventFrameTypeFilterLog,
			seq:   34,
			payload: buildTypedDataplaneEventV4Payload(
				dataplane.EventTypeFilterLog,
				dataplane.ActionDeny,
				6,
				4444, 22,
				[4]byte{10, 0, 1, 7}, [4]byte{198, 51, 100, 30},
				[4]byte{},
				0,
				1, 0,
				42,
				0,
				9,
				0,
				2,
				0,
			),
			want:      "RT_FLOW FILTER_LOG",
			wantExtra: "source=input",
		},
	}
	for _, frame := range frames {
		if err := writeFrame(conn, frame.typ, frame.seq, frame.payload); err != nil {
			t.Fatalf("write dataplane frame %d: %v", frame.seq, err)
		}
	}

	seen := make(map[string]bool, len(frames))
	deadline := time.Now().Add(2 * time.Second)
	buf := make([]byte, 4096)
	for len(seen) < len(frames) {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for syslog fanout, saw %v", seen)
		}
		_ = pc.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		n, _, err := pc.ReadFrom(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			t.Fatalf("read syslog: %v", err)
		}
		msg := string(buf[:n])
		for _, frame := range frames {
			if strings.Contains(msg, frame.want) &&
				(frame.wantExtra == "" || strings.Contains(msg, frame.wantExtra)) &&
				(frame.label != "input-filter-log-deny" || strings.Contains(msg, "action=deny")) {
				seen[frame.label] = true
			}
		}
	}

	for i := 0; i < len(frames); i++ {
		select {
		case ok := <-rawProcessed:
			if !ok {
				t.Fatal("raw dataplane event was rejected by EventReader")
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("timed out waiting for raw callback %d", i+1)
		}
	}
	// Same #7563 race as the session-close test: draining the raw-callback
	// channel proves every callback fired, NOT that every frame was accounted.
	// The last frame's Add(1) trails its callback, so wait for the watermark
	// to cover the highest seq written above before reading the counters.
	var maxSeq uint64
	for _, frame := range frames {
		if frame.seq > maxSeq {
			maxSeq = frame.seq
		}
	}
	waitFrameApplied(t, es, maxSeq)
	if got := es.PolicyDenyEvents.Load(); got != 1 {
		t.Fatalf("PolicyDenyEvents = %d, want 1", got)
	}
	if got := es.ScreenDropEvents.Load(); got != 1 {
		t.Fatalf("ScreenDropEvents = %d, want 1", got)
	}
	if got := es.FilterLogEvents.Load(); got != 2 {
		t.Fatalf("FilterLogEvents = %d, want 2", got)
	}
}

func TestEventStreamDataplaneEventBeforeCallbackQueuesUntilCallback(t *testing.T) {
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "test-events.sock")

	es := NewEventStream(sockPath)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	es.Start(ctx)
	defer es.Close()

	time.Sleep(50 * time.Millisecond)

	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	deadline := time.Now().Add(2 * time.Second)
	for !es.IsConnected() {
		if time.Now().After(deadline) {
			t.Fatal("event stream did not become connected")
		}
		time.Sleep(10 * time.Millisecond)
	}

	payload := buildDataplaneEventV4Payload(
		6, 1111, 443,
		[4]byte{10, 0, 1, 5}, [4]byte{172, 16, 80, 200},
		[4]byte{172, 16, 80, 8},
		40000,
		1, 2,
		0, 77,
		0,
	)
	if err := writeFrame(conn, EventFrameTypePolicyDeny, 21, payload); err != nil {
		t.Fatalf("write first dataplane event: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
	if typ, seq, _, err := readFrame(conn); err == nil {
		t.Fatalf("unexpected ack before callback was wired: type %d seq %d", typ, seq)
	}
	if got := es.PolicyDenyDrops.Load(); got != 0 {
		t.Fatalf("PolicyDenyDrops = %d, want 0", got)
	}

	got := make(chan uint64, 1)
	es.SetOnDataplaneEvent(func(seq uint64, _ logging.EventRecord) {
		got <- seq
	})

	select {
	case gotSeq := <-got:
		if gotSeq != 21 {
			t.Fatalf("callback seq = %d, want 21", gotSeq)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("callback not invoked after late registration")
	}
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	typ, seq, _, err := readFrame(conn)
	if err != nil {
		t.Fatalf("read ack after callback: %v", err)
	}
	if typ != EventTypeAck || seq != 21 {
		t.Fatalf("ack after callback = type %d seq %d, want type %d seq 21", typ, seq, EventTypeAck)
	}
	if got := es.PolicyDenyEvents.Load(); got != 1 {
		t.Fatalf("PolicyDenyEvents = %d, want 1", got)
	}
}

func TestEventStreamMalformedDataplaneEventDropsAndAcks(t *testing.T) {
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "test-events.sock")

	es := NewEventStream(sockPath)
	var callbackCalled atomic.Bool
	es.SetOnDataplaneEvent(func(uint64, logging.EventRecord) {
		callbackCalled.Store(true)
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	es.Start(ctx)
	defer es.Close()

	time.Sleep(50 * time.Millisecond)

	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	deadline := time.Now().Add(2 * time.Second)
	for !es.IsConnected() {
		if time.Now().After(deadline) {
			t.Fatal("event stream did not become connected")
		}
		time.Sleep(10 * time.Millisecond)
	}

	if err := writeFrame(conn, EventFrameTypeScreenDrop, 9, []byte{4, 6}); err != nil {
		t.Fatalf("write malformed dataplane event: %v", err)
	}

	_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	typ, seq, _, err := readFrame(conn)
	if err != nil {
		t.Fatalf("read ack: %v", err)
	}
	if typ != EventTypeAck || seq != 9 {
		t.Fatalf("ack = type %d seq %d, want type %d seq 9", typ, seq, EventTypeAck)
	}
	if got := es.ScreenDropDrops.Load(); got != 1 {
		t.Fatalf("ScreenDropDrops = %d, want 1", got)
	}
	if got := es.DecodeErrors.Load(); got != 1 {
		t.Fatalf("DecodeErrors = %d, want 1", got)
	}
	if callbackCalled.Load() {
		t.Fatal("malformed dataplane event must not call callback")
	}
}

func TestEventStreamUnknownFrameDropsAndAcks(t *testing.T) {
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "test-events.sock")

	es := NewEventStream(sockPath)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	es.Start(ctx)
	defer es.Close()

	time.Sleep(50 * time.Millisecond)

	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	deadline := time.Now().Add(2 * time.Second)
	for !es.IsConnected() {
		if time.Now().After(deadline) {
			t.Fatal("event stream did not become connected")
		}
		time.Sleep(10 * time.Millisecond)
	}

	if err := writeFrame(conn, 250, 11, nil); err != nil {
		t.Fatalf("write unknown frame: %v", err)
	}

	_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	typ, seq, _, err := readFrame(conn)
	if err != nil {
		t.Fatalf("read ack: %v", err)
	}
	if typ != EventTypeAck || seq != 11 {
		t.Fatalf("ack = type %d seq %d, want type %d seq 11", typ, seq, EventTypeAck)
	}
	if got := es.UnknownFrameDrops.Load(); got != 1 {
		t.Fatalf("UnknownFrameDrops = %d, want 1", got)
	}
}

func TestEventStreamAcksSent(t *testing.T) {
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "test-events.sock")

	es := NewEventStream(sockPath)
	es.SetOnEvent(func(uint8, uint64, SessionDeltaInfo) bool { return true })

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	es.Start(ctx)
	defer es.Close()

	time.Sleep(50 * time.Millisecond)

	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	deadline := time.Now().Add(2 * time.Second)
	for !es.IsConnected() {
		if time.Now().After(deadline) {
			t.Fatal("not connected")
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Send a SessionOpen event.
	payload := buildSessionOpenV4Payload(
		6, 1000, 80,
		[4]byte{10, 0, 1, 1}, [4]byte{10, 0, 2, 1},
		[4]byte{}, [4]byte{},
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		[6]byte{}, [6]byte{}, [4]byte{},
	)
	if err := writeFrame(conn, EventTypeSessionOpen, 1, payload); err != nil {
		t.Fatalf("write: %v", err)
	}

	// Read the Ack frame from the daemon side (within 200ms).
	_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	typ, seq, _, err := readFrame(conn)
	if err != nil {
		t.Fatalf("read ack: %v", err)
	}
	if typ != EventTypeAck {
		t.Fatalf("type = %d, want %d (Ack)", typ, EventTypeAck)
	}
	if seq != 1 {
		t.Fatalf("ack seq = %d, want 1", seq)
	}
}

func TestEventStreamFullResyncCallback(t *testing.T) {
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "test-events.sock")

	es := NewEventStream(sockPath)
	var resyncCalled atomic.Bool
	es.SetOnFullResync(func() bool {
		resyncCalled.Store(true)
		return true
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	es.Start(ctx)
	defer es.Close()

	time.Sleep(50 * time.Millisecond)

	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	deadline := time.Now().Add(2 * time.Second)
	for !es.IsConnected() {
		if time.Now().After(deadline) {
			t.Fatal("not connected")
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Send FullResync frame.
	if err := writeFrame(conn, EventTypeFullResync, 0, nil); err != nil {
		t.Fatalf("write: %v", err)
	}

	deadline = time.Now().Add(2 * time.Second)
	for !resyncCalled.Load() {
		if time.Now().After(deadline) {
			t.Fatal("onFullResync not called")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestEventStreamFullResyncBeforeCallbackQueuesUntilCallback(t *testing.T) {
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "test-events.sock")

	es := NewEventStream(sockPath)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	es.Start(ctx)
	defer es.Close()

	time.Sleep(50 * time.Millisecond)
	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	deadline := time.Now().Add(2 * time.Second)
	for !es.IsConnected() {
		if time.Now().After(deadline) {
			t.Fatal("not connected")
		}
		time.Sleep(10 * time.Millisecond)
	}

	if err := writeFrame(conn, EventTypeFullResync, 7, nil); err != nil {
		t.Fatalf("write FullResync: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
	if typ, seq, _, err := readFrame(conn); err == nil {
		t.Fatalf("unexpected ack before FullResync callback was wired: type %d seq %d", typ, seq)
	}

	var resyncCalled atomic.Bool
	es.SetOnFullResync(func() bool {
		resyncCalled.Store(true)
		return true
	})
	deadline = time.Now().Add(2 * time.Second)
	for !resyncCalled.Load() {
		if time.Now().After(deadline) {
			t.Fatal("onFullResync not called after late registration")
		}
		time.Sleep(10 * time.Millisecond)
	}
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	typ, seq, _, err := readFrame(conn)
	if err != nil {
		t.Fatalf("read ack after FullResync callback: %v", err)
	}
	if typ != EventTypeAck || seq != 7 {
		t.Fatalf("ack after FullResync callback = type %d seq %d, want type %d seq 7", typ, seq, EventTypeAck)
	}
}

func TestEventStreamDrainRequestComplete(t *testing.T) {
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "test-events.sock")

	es := NewEventStream(sockPath)
	var applied atomic.Int32
	es.SetOnEvent(func(uint8, uint64, SessionDeltaInfo) bool {
		applied.Add(1)
		return true
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	es.Start(ctx)
	defer es.Close()

	time.Sleep(50 * time.Millisecond)

	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	deadline := time.Now().Add(2 * time.Second)
	for !es.IsConnected() {
		if time.Now().After(deadline) {
			t.Fatal("not connected")
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Send some events so lastAppliedSeq is non-zero before draining.
	payload := buildSessionOpenV4Payload(
		6, 1000, 80,
		[4]byte{10, 0, 1, 1}, [4]byte{10, 0, 2, 1},
		[4]byte{}, [4]byte{},
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		[6]byte{}, [6]byte{}, [4]byte{},
	)
	for i := uint64(1); i <= 5; i++ {
		if err := writeFrame(conn, EventTypeSessionOpen, i, payload); err != nil {
			t.Fatalf("write event %d: %v", i, err)
		}
	}

	// Wait for all events to be applied.
	deadline = time.Now().Add(2 * time.Second)
	for applied.Load() < 5 {
		if time.Now().After(deadline) {
			t.Fatalf("applied = %d, want 5", applied.Load())
		}
		time.Sleep(10 * time.Millisecond)
	}

	// In background, the daemon sends DrainRequest. We respond with DrainComplete.
	done := make(chan uint64, 1)
	go func() {
		drainCtx, drainCancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer drainCancel()
		seq, err := es.SendDrainRequest(drainCtx)
		if err != nil {
			t.Errorf("SendDrainRequest: %v", err)
			return
		}
		done <- seq
	}()

	// Read the DrainRequest from the "helper" side.
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	var drainTargetSeq uint64
	for {
		typ, seq, _, err := readFrame(conn)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		if typ == EventTypeDrainRequest {
			drainTargetSeq = seq
			break
		}
	}

	// Issue #267: DrainRequest must carry the real lastAppliedSeq, not zero.
	if drainTargetSeq == 0 {
		t.Fatal("DrainRequest target seq = 0, want non-zero (lastAppliedSeq)")
	}
	if drainTargetSeq != 5 {
		t.Fatalf("DrainRequest target seq = %d, want 5", drainTargetSeq)
	}

	// Respond with DrainComplete.
	if err := writeFrame(conn, EventTypeDrainComplete, 99, nil); err != nil {
		t.Fatalf("write DrainComplete: %v", err)
	}

	select {
	case seq := <-done:
		if seq != 99 {
			t.Fatalf("drain complete seq = %d, want 99", seq)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("SendDrainRequest did not complete")
	}
}

// TestEventStreamDrainBelowFenceFails is the #2876 fail-on-revert guard: a
// DrainComplete whose seq is BELOW the target fence must be rejected as a hard
// error (helper timed out below the fence, post-fence sessions not flushed), and
// a DrainComplete that reaches the fence must succeed. This goes RED if the
// `seq < targetSeq` gate in SendDrainRequest is removed.
func TestEventStreamDrainBelowFenceFails(t *testing.T) {
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "test-events.sock")

	es := NewEventStream(sockPath)
	var applied atomic.Int32
	es.SetOnEvent(func(uint8, uint64, SessionDeltaInfo) bool {
		applied.Add(1)
		return true
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	es.Start(ctx)
	defer es.Close()

	time.Sleep(50 * time.Millisecond)

	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	deadline := time.Now().Add(2 * time.Second)
	for !es.IsConnected() {
		if time.Now().After(deadline) {
			t.Fatal("not connected")
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Apply 5 events so the fence (lastAppliedSeq) is 5.
	payload := buildSessionOpenV4Payload(
		6, 1000, 80,
		[4]byte{10, 0, 1, 1}, [4]byte{10, 0, 2, 1},
		[4]byte{}, [4]byte{},
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		[6]byte{}, [6]byte{}, [4]byte{},
	)
	for i := uint64(1); i <= 5; i++ {
		if err := writeFrame(conn, EventTypeSessionOpen, i, payload); err != nil {
			t.Fatalf("write event %d: %v", i, err)
		}
	}
	deadline = time.Now().Add(2 * time.Second)
	for applied.Load() < 5 {
		if time.Now().After(deadline) {
			t.Fatalf("applied = %d, want 5", applied.Load())
		}
		time.Sleep(10 * time.Millisecond)
	}

	// drainOnce issues a DrainRequest and replies with DrainComplete carrying
	// completeSeq, returning the (seq, err) from SendDrainRequest.
	drainOnce := func(completeSeq uint64) (uint64, error) {
		type res struct {
			seq uint64
			err error
		}
		out := make(chan res, 1)
		go func() {
			drainCtx, drainCancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer drainCancel()
			seq, err := es.SendDrainRequest(drainCtx)
			out <- res{seq, err}
		}()

		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		for {
			typ, seq, _, rerr := readFrame(conn)
			if rerr != nil {
				t.Fatalf("read drain request: %v", rerr)
			}
			if typ == EventTypeDrainRequest {
				if seq != 5 {
					t.Fatalf("drain target seq = %d, want 5", seq)
				}
				break
			}
		}
		if werr := writeFrame(conn, EventTypeDrainComplete, completeSeq, nil); werr != nil {
			t.Fatalf("write DrainComplete %d: %v", completeSeq, werr)
		}
		select {
		case r := <-out:
			return r.seq, r.err
		case <-time.After(2 * time.Second):
			t.Fatal("SendDrainRequest did not return")
			return 0, nil
		}
	}

	// Below the fence: must be a hard error (the #2876 guard).
	if seq, err := drainOnce(4); err == nil {
		t.Fatalf("drain below fence (seq 4 < target 5) returned nil error, want failure (seq=%d)", seq)
	}

	// At the fence: must succeed.
	if seq, err := drainOnce(5); err != nil {
		t.Fatalf("drain at fence (seq 5 == target 5) returned error %v, want success", err)
	} else if seq != 5 {
		t.Fatalf("drain at fence returned seq %d, want 5", seq)
	}
}

func TestEventStreamDisconnectReconnect(t *testing.T) {
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "test-events.sock")

	es := NewEventStream(sockPath)
	var received atomic.Int32
	es.SetOnEvent(func(uint8, uint64, SessionDeltaInfo) bool {
		received.Add(1)
		return true
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	es.Start(ctx)
	defer es.Close()

	time.Sleep(50 * time.Millisecond)

	// First connection.
	conn1, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	dl := time.Now().Add(2 * time.Second)
	for !es.IsConnected() {
		if time.Now().After(dl) {
			t.Fatal("not connected")
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Send one event.
	payload := buildSessionOpenV4Payload(
		6, 1000, 80,
		[4]byte{10, 0, 1, 1}, [4]byte{10, 0, 2, 1},
		[4]byte{}, [4]byte{},
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		[6]byte{}, [6]byte{}, [4]byte{},
	)
	_ = writeFrame(conn1, EventTypeSessionOpen, 1, payload)
	time.Sleep(50 * time.Millisecond)
	if received.Load() != 1 {
		t.Fatalf("received = %d, want 1", received.Load())
	}

	// Disconnect.
	conn1.Close()

	dl = time.Now().Add(2 * time.Second)
	for es.IsConnected() {
		if time.Now().After(dl) {
			t.Fatal("still connected after close")
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Reconnect.
	conn2, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("reconnect dial: %v", err)
	}
	defer conn2.Close()

	dl = time.Now().Add(2 * time.Second)
	for !es.IsConnected() {
		if time.Now().After(dl) {
			t.Fatal("not reconnected")
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Send event on second connection.
	_ = writeFrame(conn2, EventTypeSessionOpen, 2, payload)
	dl = time.Now().Add(2 * time.Second)
	for received.Load() < 2 {
		if time.Now().After(dl) {
			t.Fatalf("received = %d after reconnect, want 2", received.Load())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestEventStreamPauseResume(t *testing.T) {
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "test-events.sock")

	es := NewEventStream(sockPath)
	es.SetOnEvent(func(uint8, uint64, SessionDeltaInfo) bool { return true })

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	es.Start(ctx)
	defer es.Close()

	time.Sleep(50 * time.Millisecond)

	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	dl := time.Now().Add(2 * time.Second)
	for !es.IsConnected() {
		if time.Now().After(dl) {
			t.Fatal("not connected")
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Send Pause.
	if err := es.SendPause(); err != nil {
		t.Fatalf("SendPause: %v", err)
	}

	// Read Pause frame on helper side.
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	for {
		typ, _, _, err := readFrame(conn)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		if typ == EventTypePause {
			break
		}
	}

	// Send Resume.
	if err := es.SendResume(); err != nil {
		t.Fatalf("SendResume: %v", err)
	}

	for {
		typ, _, _, err := readFrame(conn)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		if typ == EventTypeResume {
			break
		}
	}
}

func TestEventStreamSequenceGapDetection(t *testing.T) {
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "test-events.sock")

	es := NewEventStream(sockPath)
	es.SetOnEvent(func(uint8, uint64, SessionDeltaInfo) bool { return true })

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	es.Start(ctx)
	defer es.Close()

	time.Sleep(50 * time.Millisecond)

	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	dl := time.Now().Add(2 * time.Second)
	for !es.IsConnected() {
		if time.Now().After(dl) {
			t.Fatal("not connected")
		}
		time.Sleep(10 * time.Millisecond)
	}

	payload := buildSessionOpenV4Payload(
		6, 1000, 80,
		[4]byte{10, 0, 1, 1}, [4]byte{10, 0, 2, 1},
		[4]byte{}, [4]byte{},
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		[6]byte{}, [6]byte{}, [4]byte{},
	)

	// Send seq 1, then skip to seq 5 (gap of 3).
	_ = writeFrame(conn, EventTypeSessionOpen, 1, payload)
	_ = writeFrame(conn, EventTypeSessionOpen, 5, payload)

	time.Sleep(100 * time.Millisecond)
	if gaps := es.SeqGaps.Load(); gaps != 1 {
		t.Fatalf("SeqGaps = %d, want 1", gaps)
	}
}

// TestEventStreamSessionGapTriggersResyncWithholdsAck is the #2874 regression
// for the Go consumer half: a sequence gap on a correctness-critical
// session-sync frame must (a) trigger a full bulk re-export and (b) NOT advance
// the cumulative ACK past the missing sequence (which would trim the helper's
// replay window over the dropped delta → permanent standby session loss).
//
// Fail-on-revert: with the pre-fix behavior the gapped frame is dispatched and
// markFrameApplied advances lastAppliedSeq to the gapped seq (ACKing past the
// hole) and onFullResync is never called, so both assertions go red.
func TestEventStreamSessionGapTriggersResyncWithholdsAck(t *testing.T) {
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "test-events.sock")

	es := NewEventStream(sockPath)
	es.SetOnEvent(func(uint8, uint64, SessionDeltaInfo) bool { return true })
	var resyncCalled atomic.Bool
	es.SetOnFullResync(func() bool {
		resyncCalled.Store(true)
		return true
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	es.Start(ctx)
	defer es.Close()

	time.Sleep(50 * time.Millisecond)
	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	dl := time.Now().Add(2 * time.Second)
	for !es.IsConnected() {
		if time.Now().After(dl) {
			t.Fatal("not connected")
		}
		time.Sleep(10 * time.Millisecond)
	}

	payload := buildSessionOpenV4Payload(
		6, 1000, 80,
		[4]byte{10, 0, 1, 1}, [4]byte{10, 0, 2, 1},
		[4]byte{}, [4]byte{},
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		[6]byte{}, [6]byte{}, [4]byte{},
	)

	// Send the first contiguous frame and wait for it to be applied + acked so
	// the ACK watermark is established at seq 1.
	if err := writeFrame(conn, EventTypeSessionOpen, 1, payload); err != nil {
		t.Fatalf("write seq 1: %v", err)
	}
	dl = time.Now().Add(2 * time.Second)
	for es.lastAppliedSeq.Load() != 1 {
		if time.Now().After(dl) {
			t.Fatalf("seq 1 not applied; lastApplied=%d", es.lastAppliedSeq.Load())
		}
		time.Sleep(5 * time.Millisecond)
	}

	// Now skip to seq 5 — a gap on a session-sync frame.
	if err := writeFrame(conn, EventTypeSessionOpen, 5, payload); err != nil {
		t.Fatalf("write seq 5: %v", err)
	}

	dl = time.Now().Add(2 * time.Second)
	for !resyncCalled.Load() {
		if time.Now().After(dl) {
			t.Fatal("onFullResync not called on session-sync gap")
		}
		time.Sleep(5 * time.Millisecond)
	}

	if es.SessionSyncResyncs.Load() != 1 {
		t.Fatalf("SessionSyncResyncs = %d, want 1", es.SessionSyncResyncs.Load())
	}
	// The cumulative ACK must NOT have advanced past the hole: lastAppliedSeq
	// stays at the last contiguous sequence (1), never 5.
	if applied := es.lastAppliedSeq.Load(); applied != 1 {
		t.Fatalf("lastAppliedSeq advanced past hole: got %d, want 1", applied)
	}
	if acked := es.lastAckSeq.Load(); acked > 1 {
		t.Fatalf("ACK advanced past hole: lastAckSeq=%d, want <=1", acked)
	}
}

func TestEventSocketPathRemoved(t *testing.T) {
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "test-events.sock")

	es := NewEventStream(sockPath)
	ctx, cancel := context.WithCancel(context.Background())
	es.Start(ctx)

	// Verify socket file exists.
	if _, err := os.Stat(sockPath); err != nil {
		t.Fatalf("socket not created: %v", err)
	}

	cancel()
	es.Close()

	// Verify socket file removed.
	if _, err := os.Stat(sockPath); !os.IsNotExist(err) {
		t.Fatal("socket file not cleaned up")
	}
}

// TestRecordDataplaneEventScreenAlarmNotDrop is the #2298 regression: the
// scan-table-pressure saturation alarm (#2234) is a screen event with
// action=PERMIT (the packet forwards). It must be counted as a screen ALARM,
// NOT a screen drop — otherwise the alarm inflates ScreenDropEvents under
// exactly the condition it fires, masking real screen drops. A real screen
// drop (action=DENY/REJECT) must still bump ScreenDropEvents.
//
// Fail-on-revert: if recordDataplaneEvent reverts to classifying by frame
// type alone, the permit alarm would land in ScreenDropEvents and both the
// "alarm != drop" and "alarm is counted" assertions below would fail.
func TestRecordDataplaneEventScreenAlarmNotDrop(t *testing.T) {
	cases := []struct {
		name      string
		action    uint8
		wantDrop  uint64
		wantAlarm uint64
	}{
		{"permit_alarm", dataplane.ActionPermit, 0, 1},
		{"deny_drop", dataplane.ActionDeny, 1, 0},
		{"reject_drop", dataplane.ActionReject, 1, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			es := &EventStream{}
			es.recordDataplaneEvent(EventFrameTypeScreenDrop, tc.action)
			if got := es.ScreenDropEvents.Load(); got != tc.wantDrop {
				t.Fatalf("ScreenDropEvents = %d, want %d (action=%d)",
					got, tc.wantDrop, tc.action)
			}
			if got := es.ScreenAlarmEvents.Load(); got != tc.wantAlarm {
				t.Fatalf("ScreenAlarmEvents = %d, want %d (action=%d)",
					got, tc.wantAlarm, tc.action)
			}
		})
	}
}

// TestRecordDataplaneEventNonScreenIgnoresAction confirms the action gate is
// scoped to screen events: a policy-deny/filter-log event is counted by type
// regardless of action.
func TestRecordDataplaneEventNonScreenIgnoresAction(t *testing.T) {
	es := &EventStream{}
	es.recordDataplaneEvent(EventFrameTypePolicyDeny, dataplane.ActionPermit)
	es.recordDataplaneEvent(EventFrameTypeFilterLog, dataplane.ActionPermit)
	if got := es.PolicyDenyEvents.Load(); got != 1 {
		t.Fatalf("PolicyDenyEvents = %d, want 1", got)
	}
	if got := es.FilterLogEvents.Load(); got != 1 {
		t.Fatalf("FilterLogEvents = %d, want 1", got)
	}
	if got := es.ScreenAlarmEvents.Load(); got != 0 {
		t.Fatalf("ScreenAlarmEvents = %d, want 0", got)
	}
}

// TestDataplaneEventActionFromPayload verifies the action byte is read from the
// canonical wire offset (54) and that a truncated payload reports ActionDeny so
// it is never misclassified as a permit alarm (#2298).
func TestDataplaneEventActionFromPayload(t *testing.T) {
	permit := buildTypedDataplaneEventV4Payload(
		dataplane.EventTypeScreenDrop,
		dataplane.ActionPermit,
		6,          // proto
		1234, 5678, // ports
		[4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2},
		[4]byte{}, 0,
		1, 0, // zones
		0, 0, 0, 0,
		19, // SCREEN_SCAN_TABLE_PRESSURE reason bit (1<<19, #2234)
		0,
	)
	if got := dataplaneEventAction(permit); got != dataplane.ActionPermit {
		t.Fatalf("dataplaneEventAction(permit) = %d, want %d", got, dataplane.ActionPermit)
	}
	deny := buildTypedDataplaneEventV4Payload(
		dataplane.EventTypeScreenDrop,
		dataplane.ActionDeny,
		6, 1234, 5678,
		[4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2},
		[4]byte{}, 0, 1, 0, 0, 0, 0, 0, 0, 0,
	)
	if got := dataplaneEventAction(deny); got != dataplane.ActionDeny {
		t.Fatalf("dataplaneEventAction(deny) = %d, want %d", got, dataplane.ActionDeny)
	}
	// Truncated payload (<= offset 54) must default to ActionDeny.
	if got := dataplaneEventAction([]byte{4, 6}); got != dataplane.ActionDeny {
		t.Fatalf("dataplaneEventAction(truncated) = %d, want %d", got, dataplane.ActionDeny)
	}
}

func TestDecodeSessionCloseEventCarriesThePurgeRetirementMarker9752(t *testing.T) {
	base := buildSessionCloseV4Payload(6, 12345, 443,
		[4]byte{10, 0, 1, 102}, [4]byte{172, 16, 80, 200}, 1, 0, 3, 4)
	payload := append(append(append([]byte{}, base...),
		0, 0, 0, 0, 0, 0, 0, 0, // discriminator
		0, 0, 0, 0), // routing domain
		1) // purge-retirement marker
	d, ok := decodeSessionCloseEvent(payload)
	if !ok {
		t.Fatal("decodeSessionCloseEvent returned false")
	}
	if !d.PurgeRetirement {
		t.Fatal("#9752: close frame with marker byte set decoded PurgeRetirement=false; " +
			"downstream retractions would derive companions the purge preserved")
	}
	// Legacy (marker absent) keeps the historical behavior.
	legacy, ok := decodeSessionCloseEvent(payload[:len(payload)-1])
	if !ok {
		t.Fatal("decodeSessionCloseEvent returned false for a legacy close")
	}
	if legacy.PurgeRetirement {
		t.Fatal("legacy close decoded PurgeRetirement=true")
	}
}
