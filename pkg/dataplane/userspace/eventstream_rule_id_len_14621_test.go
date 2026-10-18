package userspace

import (
	"encoding/binary"
	"strings"
	"testing"
)

// #14621 (Y22-01): the Go consumer side of the session open/update
// rule_id sweep. The Rust encoder must never emit a frame past the
// 512-byte EVENT_FRAME_CAPACITY for any rule_id length in 0..=600, and
// every frame it does emit must decode here with the full trailer
// (handshake byte, provenance byte, PPTP pair) intact.
//
// These payloads are the encoder's wire layout reconstructed from the
// decoder's own walk: decodeSessionEvent consumes the fixed header and
// every length-gated trailer field (36 bytes of gated fields precede
// the ingress-identity field) before it reaches the rule_id prefix, so
// payloads can be synthesised by running that walk over zero bytes and
// stamping the tail. The encoder's real frames are asserted end to end
// by the Rust sweep in codec_tests.rs
// (session_open_update_rule_id_len_sweep_never_panics_14621), which is
// the mutation-RED leg for the guard; this test pins that the carried,
// exact-fit and zero-length-fallback forms all decode here.
//
// prefixOff derives the rule_id prefix offset the same way the decoder
// reaches it: start-of-trailer `off` after the fixed header + gated
// fields, +6 for the ingress ifindex/VLAN pair.
func ruleIDPrefixOff(t *testing.T, af byte) int {
	t.Helper()
	// A payload of all zeros except the address family: every gated
	// field decodes as absent, leaving off positioned exactly where a
	// real helper frame's ingress identity starts.
	probe := make([]byte, 512)
	probe[0] = af
	if _, ok := decodeSessionEvent(probe); !ok {
		t.Fatal("probe payload rejected")
	}
	// Recompute the walk: 32-byte header + 4*addrSize IPs + 12 MAC/nh
	// + gated fields (4+4+4+4+8+8+4+1+8+3 = 48) + 6 ingress identity.
	addrSize := 4
	if af == 6 {
		addrSize = 16
	}
	return 32 + 5*addrSize + 12 + 48 + 6
}

func TestDecodeSessionEventRuleIDLenSweep14621(t *testing.T) {
	const pptp = uint64(0x0102030405060708)
	for _, tc := range []struct {
		name string
		af   byte
	}{
		{"v6", 6},
		{"v4", 4},
	} {
		prefixOff := ruleIDPrefixOff(t, tc.af)
		// Longest id the 512-byte frame carries with prefix + 10-byte
		// trailer (payload excludes the 16-byte frame header).
		maxFit := 512 - 16 - prefixOff - 2 - 10
		for idLen := 0; idLen <= 600; idLen++ {
			carried := idLen
			if carried > maxFit {
				carried = 0
			}
			payload := make([]byte, prefixOff+2+carried+10)
			payload[0] = tc.af
			payload[1] = 6 // TCP
			binary.LittleEndian.PutUint16(payload[prefixOff:prefixOff+2], uint16(carried))
			copy(payload[prefixOff+2:], strings.Repeat("x", carried))
			off := prefixOff + 2 + carried
			payload[off] = 3   // handshake: SynAckFirstPending
			payload[off+1] = 2 // provenance: static
			binary.LittleEndian.PutUint64(payload[off+2:off+10], pptp)

			d, ok := decodeSessionEvent(payload)
			if !ok {
				t.Fatalf("%s idLen=%d: decodeSessionEvent rejected sweep payload", tc.name, idLen)
			}
			if d.PolicyRuleID != strings.Repeat("x", carried) {
				t.Fatalf("%s idLen=%d: PolicyRuleID len=%d, want %d", tc.name, idLen, len(d.PolicyRuleID), carried)
			}
			if d.TCPHandshakeState != 3 {
				t.Fatalf("%s idLen=%d: TCPHandshakeState=%d, want 3", tc.name, idLen, d.TCPHandshakeState)
			}
			if d.SourceNatProvenance != 2 {
				t.Fatalf("%s idLen=%d: SourceNatProvenance=%d, want 2", tc.name, idLen, d.SourceNatProvenance)
			}
			if d.PptpCallIDs != pptp {
				t.Fatalf("%s idLen=%d: PptpCallIDs=%#x, want %#x", tc.name, idLen, d.PptpCallIDs, pptp)
			}
		}
	}
}

// The exact panic windows from the report: v6 rule_ids of 307..=314
// bytes and v4 rule_ids of 367..=374 bytes were admitted by the old
// guard and then overflowed the frame. On the wire after the fix they
// are the zero-length fallback with the trailer intact; the decoder
// must surface exactly that (empty id, trailer values preserved), not
// a partial id.
func TestDecodeSessionEventRuleIDPanicWindowFallsBack14621(t *testing.T) {
	const pptp = uint64(0x0102030405060708)
	for _, tc := range []struct {
		name   string
		af     byte
		window [2]int
	}{
		{"v6", 6, [2]int{307, 314}},
		{"v4", 4, [2]int{367, 374}},
	} {
		prefixOff := ruleIDPrefixOff(t, tc.af)
		for idLen := tc.window[0]; idLen <= tc.window[1]; idLen++ {
			payload := make([]byte, prefixOff+2+10)
			payload[0] = tc.af
			payload[1] = 6
			// prefix already 0 (fallback); trailer follows immediately.
			payload[prefixOff+2] = 3
			payload[prefixOff+3] = 2
			binary.LittleEndian.PutUint64(payload[prefixOff+4:prefixOff+12], pptp)
			d, ok := decodeSessionEvent(payload)
			if !ok {
				t.Fatalf("%s idLen=%d: fallback frame rejected", tc.name, idLen)
			}
			if d.PolicyRuleID != "" || d.TCPHandshakeState != 3 ||
				d.SourceNatProvenance != 2 || d.PptpCallIDs != pptp {
				t.Fatalf("%s idLen=%d: fallback decoded wrongly: rule=%q hs=%d prov=%d pptp=%#x",
					tc.name, idLen, d.PolicyRuleID, d.TCPHandshakeState, d.SourceNatProvenance, d.PptpCallIDs)
			}
		}
	}
}
