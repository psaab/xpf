package cluster

import (
	"encoding/binary"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
)

func scopedCodecKeyV4() dataplane.SessionKey {
	return dataplane.SessionKey{
		SrcIP:    [4]byte{10, 0, 0, 1},
		DstIP:    [4]byte{10, 0, 0, 2},
		Protocol: 6, SrcPort: 1234, DstPort: 80,
	}
}

func scopedCodecKeyV6() dataplane.SessionKeyV6 {
	return dataplane.SessionKeyV6{
		SrcIP:    [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
		DstIP:    [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2},
		Protocol: 6, SrcPort: 1234, DstPort: 80,
	}
}

// Scoped v4 delete: exact 37-byte layout, tail at [25:37], round-trips all fields.
func TestEncodeDeleteScopedV4RoundTrip10512(t *testing.T) {
	key := scopedCodecKeyV4()
	msg := encodeDeleteScopedV4(key, 0x1122, true, 100007, 0xF10512)
	payload := msg[syncHeaderSize:]
	if len(payload) != 37 {
		t.Fatalf("scoped v4 payload len = %d, want 37", len(payload))
	}
	if got := binary.LittleEndian.Uint32(msg[8:12]); got != 37 {
		t.Fatalf("header length = %d, want 37", got)
	}
	if got := binary.LittleEndian.Uint32(payload[25:29]); got != 100007 {
		t.Fatalf("domain at [25:29] = %d, want 100007", got)
	}
	if got := binary.LittleEndian.Uint64(payload[29:37]); got != 0xF10512 {
		t.Fatalf("expected id at [29:37] = %#x, want 0xF10512", got)
	}
	k, gen, fwd, domain, id, scoped, ok := parseDeleteV4Wire(payload)
	if !ok || !scoped {
		t.Fatal("scoped v4 payload does not decode as scoped")
	}
	if k != key || gen != 0x1122 || !fwd || domain != 100007 || id != 0xF10512 {
		t.Fatalf("round-trip mismatch: %+v", k)
	}
}

// Scoped v6 twin: exact 61-byte layout, tail at [49:61].
func TestEncodeDeleteScopedV6RoundTrip10512(t *testing.T) {
	key := scopedCodecKeyV6()
	msg := encodeDeleteScopedV6(key, 0x3344, false, 200007, 0xC10512)
	payload := msg[syncHeaderSize:]
	if len(payload) != 61 {
		t.Fatalf("scoped v6 payload len = %d, want 61", len(payload))
	}
	if got := binary.LittleEndian.Uint32(msg[8:12]); got != 61 {
		t.Fatalf("header length = %d, want 61", got)
	}
	if got := binary.LittleEndian.Uint32(payload[49:53]); got != 200007 {
		t.Fatalf("domain at [49:53] = %d, want 200007", got)
	}
	if got := binary.LittleEndian.Uint64(payload[53:61]); got != 0xC10512 {
		t.Fatalf("expected id at [53:61] = %#x, want 0xC10512", got)
	}
	k, gen, fwd, domain, id, scoped, ok := parseDeleteV6Wire(payload)
	if !ok || !scoped {
		t.Fatal("scoped v6 payload does not decode as scoped")
	}
	if k != key || gen != 0x3344 || fwd || domain != 200007 || id != 0xC10512 {
		t.Fatalf("round-trip mismatch: %+v", k)
	}
}

// Bare deletes are byte-frozen: 25/49 bytes, parse back with zero scope.
func TestEncodeDeleteBareLayoutFrozen10512(t *testing.T) {
	v4 := encodeDeleteV4(scopedCodecKeyV4(), 7, true)[syncHeaderSize:]
	if len(v4) != 25 {
		t.Fatalf("bare v4 payload len = %d, want 25", len(v4))
	}
	_, _, _, domain, id, scoped, ok := parseDeleteV4Wire(v4)
	if !ok || scoped || domain != 0 || id != 0 {
		t.Fatalf("bare v4 must decode unscoped with zero scope, got domain=%d id=%d ok=%v", domain, id, ok)
	}
	v6 := encodeDeleteV6(scopedCodecKeyV6(), 7, false)[syncHeaderSize:]
	if len(v6) != 49 {
		t.Fatalf("bare v6 payload len = %d, want 49", len(v6))
	}
	_, _, _, domain6, id6, scoped6, ok6 := parseDeleteV6Wire(v6)
	if !ok6 || scoped6 || domain6 != 0 || id6 != 0 {
		t.Fatalf("bare v6 must decode unscoped with zero scope, got domain=%d id=%d ok=%v", domain6, id6, ok6)
	}
}

// The tail is both-or-neither with fail-closed gaps: a partial tail
// (encoder never emits one) is REJECTED, never decoded as an
// unconditional bare delete (the §1 downgrade ban). Hostile truncation
// cells for both families.
func TestParseDeletePartialTailRejected10512(t *testing.T) {
	full := encodeDeleteScopedV4(scopedCodecKeyV4(), 9, false, 100007, 0xF10512)[syncHeaderSize:]
	for _, n := range []int{26, 29, 33, 36} {
		_, _, _, _, _, _, ok := parseDeleteV4Wire(full[:n])
		if ok {
			t.Fatalf("len-%d payload must be rejected, decoded as bare", n)
		}
	}
	full6 := encodeDeleteScopedV6(scopedCodecKeyV6(), 9, false, 200007, 0xC10512)[syncHeaderSize:]
	for _, n := range []int{50, 53, 57, 60} {
		_, _, _, _, _, _, ok := parseDeleteV6Wire(full6[:n])
		if ok {
			t.Fatalf("len-%d v6 payload must be rejected, decoded as bare", n)
		}
	}
}

// New→old direction: an old decoder (reads only the first 25/49 bytes)
// sees the scoped frame exactly as a bare delete — key, gen, and marker
// intact, tail invisible.
func TestScopedDeleteReadableByOldDecoder10512(t *testing.T) {
	scoped := encodeDeleteScopedV4(scopedCodecKeyV4(), 0x55, true, 100007, 0xF10512)[syncHeaderSize:]
	k, gen, fwd, _, _, isScoped, ok := parseDeleteV4Wire(scoped[:25])
	if !ok || isScoped {
		t.Fatal("old-length prefix must decode as bare, not scoped")
	}
	if k != scopedCodecKeyV4() || gen != 0x55 || !fwd {
		t.Fatal("old decoder must see key, gen, and marker intact")
	}
	scoped6 := encodeDeleteScopedV6(scopedCodecKeyV6(), 0x66, false, 200007, 0xC10512)[syncHeaderSize:]
	k6, gen6, fwd6, _, _, isScoped6, ok6 := parseDeleteV6Wire(scoped6[:49])
	if !ok6 || isScoped6 {
		t.Fatal("old-length v6 prefix must decode as bare, not scoped")
	}
	if k6 != scopedCodecKeyV6() || gen6 != 0x66 || fwd6 {
		t.Fatal("old v6 decoder must see key, gen, and marker intact")
	}
}

// Scoped-by-id with zero domain (default instance, stated identity) still
// carries the tail — the condition is domain-OR-id, never domain-alone.
func TestEncodeDeleteScopedByIDOnlyCarriesTail10512(t *testing.T) {
	msg := encodeDeleteScopedV4(scopedCodecKeyV4(), 3, false, 0, 0xABCDEF)[syncHeaderSize:]
	if len(msg) != 37 {
		t.Fatalf("id-only scoped payload len = %d, want 37", len(msg))
	}
	_, _, _, domain, id, scoped, ok := parseDeleteV4Wire(msg)
	if !ok || !scoped || domain != 0 || id != 0xABCDEF {
		t.Fatalf("id-only tail must round-trip as scoped, got domain=%d id=%#x ok=%v", domain, id, ok)
	}
}

// Hostile zero-ID tails: a full scoped shape carrying no identity is
// corrupt (the encoder only emits scoped with domain-or-id set, and id 0
// names no incarnation) — rejected, never reclassified as a bare
// unconditional delete. Both families, both zero shapes.
func TestParseDeleteZeroIDTailRejected10512(t *testing.T) {
	full := encodeDeleteScopedV4(scopedCodecKeyV4(), 9, false, 100007, 0xF10512)[syncHeaderSize:]
	zeroID := append([]byte(nil), full...)
	for i := 29; i < 37; i++ {
		zeroID[i] = 0
	}
	if _, _, _, _, _, _, ok := parseDeleteV4Wire(zeroID); ok {
		t.Fatal("scoped-shaped (domain, id 0) must be rejected")
	}
	zeroBoth := append([]byte(nil), full...)
	for i := 25; i < 37; i++ {
		zeroBoth[i] = 0
	}
	if _, _, _, _, _, _, ok := parseDeleteV4Wire(zeroBoth); ok {
		t.Fatal("scoped-shaped (0, 0) must be rejected, never bare")
	}
	full6 := encodeDeleteScopedV6(scopedCodecKeyV6(), 9, false, 200007, 0xC10512)[syncHeaderSize:]
	zeroID6 := append([]byte(nil), full6...)
	for i := 53; i < 61; i++ {
		zeroID6[i] = 0
	}
	if _, _, _, _, _, _, ok := parseDeleteV6Wire(zeroID6); ok {
		t.Fatal("scoped-shaped v6 (domain, id 0) must be rejected")
	}
	zeroBoth6 := append([]byte(nil), full6...)
	for i := 49; i < 61; i++ {
		zeroBoth6[i] = 0
	}
	if _, _, _, _, _, _, ok := parseDeleteV6Wire(zeroBoth6); ok {
		t.Fatal("scoped-shaped v6 (0, 0) must be rejected, never bare")
	}
}
