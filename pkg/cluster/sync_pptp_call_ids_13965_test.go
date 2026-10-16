package cluster

import (
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
)

// #13965: the PPTP call-id pair must round-trip on the cluster sync wire.
// The helper's import gate (verify_synced_pptp_association) withholds a
// Pptp(handle) session unless the pair arrives and recomputes the handle;
// before this fix no producer ever set PptpCallIDs, so every synced PPTP
// session was withheld on the standby.

// pptpWireDiscriminator is TunnelDiscriminator::Pptp(handle).to_wire():
// tag 2 in the high 32 bits, handle in the low 32.
func pptpWireDiscriminator(handle uint32) uint64 {
	return uint64(2)<<32 | uint64(handle)
}

// pptpWireCallIDs is PptpCall::to_wire_call_ids():
// PRESENT (1<<32) | lo<<16 | hi.
func pptpWireCallIDs(lo, hi uint16) uint64 {
	return uint64(1)<<32 | uint64(lo)<<16 | uint64(hi)
}

func TestPptpCallIDsRoundTripV4_13965(t *testing.T) {
	key := greSessionKey7188()
	val := sessionValue7188(pptpWireDiscriminator(0xABCD1234))
	val.PptpCallIDs = pptpWireCallIDs(0x1111, 0x2222)
	payload := encodeSessionV4Payload(key, val)
	_, got, ok := decodeSessionV4Payload(payload)
	if !ok {
		t.Fatal("decode failed")
	}
	if got.PptpCallIDs != val.PptpCallIDs {
		t.Fatalf("PptpCallIDs round-tripped as %#x, want %#x", got.PptpCallIDs, val.PptpCallIDs)
	}
	if got.TunnelDiscriminator != val.TunnelDiscriminator {
		t.Fatalf("TunnelDiscriminator disturbed: got %#x want %#x", got.TunnelDiscriminator, val.TunnelDiscriminator)
	}
}

func TestPptpCallIDsRoundTripV6_13965(t *testing.T) {
	var key dataplane.SessionKeyV6
	copy(key.SrcIP[:], []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7})
	copy(key.DstIP[:], []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9})
	key.Protocol = 47
	val := dataplane.SessionValueV6{
		State:               2,
		TunnelDiscriminator: pptpWireDiscriminator(0xABCD1234),
		PptpCallIDs:         pptpWireCallIDs(0x3333, 0x4444),
	}
	payload := encodeSessionV6Payload(key, val)
	_, got, ok := decodeSessionV6Payload(payload)
	if !ok {
		t.Fatal("decode failed")
	}
	if got.PptpCallIDs != val.PptpCallIDs {
		t.Fatalf("V6 PptpCallIDs round-tripped as %#x, want %#x", got.PptpCallIDs, val.PptpCallIDs)
	}
}

// A non-PPTP session must not gain a pair from trailing bytes, and a PPTP
// session from a legacy peer (no pair appended) must decode the pair as
// absent (0) so the helper withholds rather than aliases it.
func TestPptpCallIDsAbsentForLegacyAndNonPptp_13965(t *testing.T) {
	key := greSessionKey7188()
	// Legacy PPTP: discriminator carried, pair not appended.
	val := sessionValue7188(pptpWireDiscriminator(0xABCD1234))
	payload := encodeSessionV4Payload(key, val)
	_, got, ok := decodeSessionV4Payload(payload)
	if !ok {
		t.Fatal("decode failed")
	}
	if got.PptpCallIDs != 0 {
		t.Fatalf("legacy PPTP payload decoded PptpCallIDs=%#x, want 0 (not carried)", got.PptpCallIDs)
	}
	// Non-PPTP: a clean Keyed record without the field stays zero.
	val3 := sessionValue7188(uint64(1)<<32 | 100)
	payload3 := encodeSessionV4Payload(key, val3)
	_, got3, ok := decodeSessionV4Payload(payload3)
	if !ok {
		t.Fatal("decode failed")
	}
	if got3.PptpCallIDs != 0 {
		t.Fatalf("non-PPTP payload decoded PptpCallIDs=%#x, want 0", got3.PptpCallIDs)
	}
}
