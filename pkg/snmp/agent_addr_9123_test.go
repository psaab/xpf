package snmp

import (
	"fmt"
	"net"
	"strings"
	"testing"
)

// berChildren9123 walks the TLVs directly inside one BER value and returns
// (tag, value) for each.
//
// A BYTE SCAN IS UNSOUND HERE AND I SHIPPED ONE FIRST. tagIPAddress is 0x40,
// and the SNMPv2c PDU carries a RANDOMIZED request-id, so roughly one build in
// three contained a 0x40 byte inside an integer and my "is there an IpAddress
// TLV" check reported one that did not exist. The cell passed alone and failed
// about one full-package run in three — a flaky red, which is worse than no
// cell, because it teaches everyone to re-run.
//
// The same unsoundness was in the v1 decoder: it took the first 0x40 byte in
// the packet, which the TimeTicks value or an OID can supply.
//
// Definite-length BER, short and long form. The long form is required, not
// optional: the v2c message is 132 bytes and its outer SEQUENCE is encoded
// `30 81 81`. A first version of this walker refused the long form rather than
// guessing at it, which is why that showed up as a clear message instead of a
// misparse — a decoder that guesses a length is how a byte scan's unsoundness
// comes back wearing a parser's clothes.
func berChildren9123(t *testing.T, v []byte) [][2]interface{} {
	t.Helper()
	var out [][2]interface{}
	for i := 0; i < len(v); {
		tag := v[i]
		if i+1 >= len(v) {
			t.Fatalf("truncated TLV at %d", i)
		}
		n, hdr := 0, 2
		if b := v[i+1]; b&0x80 == 0 {
			n = int(b)
		} else {
			nb := int(b & 0x7f)
			if nb == 0 || nb > 4 {
				t.Fatalf("indefinite or oversized BER length at %d (%d bytes)", i, nb)
			}
			if i+2+nb > len(v) {
				t.Fatalf("truncated long-form length at %d", i)
			}
			for k := 0; k < nb; k++ {
				n = n<<8 | int(v[i+2+k])
			}
			hdr = 2 + nb
		}
		if i+hdr+n > len(v) {
			t.Fatalf("TLV at %d claims %d bytes, %d remain", i, n, len(v)-i-hdr)
		}
		out = append(out, [2]interface{}{tag, v[i+hdr : i+hdr+n]})
		i += hdr + n
	}
	return out
}

// berFind9123 returns the value of the first TLV with the given tag among the
// direct children of v.
func berFind9123(t *testing.T, v []byte, tag byte) ([]byte, bool) {
	t.Helper()
	for _, kv := range berChildren9123(t, v) {
		if kv[0].(byte) == tag {
			return kv[1].([]byte), true
		}
	}
	return nil, false
}

// v1PDUBody9123 returns the Trap-PDU body of a v1 trap message.
func v1PDUBody9123(t *testing.T, pkt []byte) []byte {
	t.Helper()
	msg, ok := berFind9123(t, pkt, tagSequence)
	if !ok {
		t.Fatal("no outer SEQUENCE")
	}
	pdu, ok := berFind9123(t, msg, pduSNMPv1Trap)
	if !ok {
		t.Fatal("no v1 Trap-PDU")
	}
	return pdu
}

// decodeAgentAddr9123 returns the agent-addr, located STRUCTURALLY: it is the
// second TLV of the Trap-PDU body (enterprise, agent-addr, generic, specific,
// timestamp, varbinds).
func decodeAgentAddr9123(t *testing.T, pkt []byte) net.IP {
	t.Helper()
	kids := berChildren9123(t, v1PDUBody9123(t, pkt))
	if len(kids) < 2 {
		t.Fatalf("Trap-PDU has %d fields, want at least 2", len(kids))
	}
	if got := kids[1][0].(byte); got != tagIPAddress {
		t.Fatalf("field 2 of the Trap-PDU has tag %#x, want IpAddress %#x", got, tagIPAddress)
	}
	b := kids[1][1].([]byte)
	if len(b) != 4 {
		t.Fatalf("agent-addr length = %d, want 4", len(b))
	}
	return net.IPv4(b[0], b[1], b[2], b[3])
}

// #9123: agent-addr was hardcoded to 0.0.0.0, and its justifying comment cited
// RFC 2576 §3.1 — the wrong direction of the mapping. RFC 3584 §3.2 says a
// notification originator sending over IP SHALL set agent-addr to its own IP
// address; 0.0.0.0 is the fallback for a NON-IP transport.
//
// A receiver that keys its inventory on agent-addr filed every link-up/down
// against node 0.0.0.0.
func TestV1TrapCarriesTheSourceAddress9123(t *testing.T) {
	// A real listener on loopback, so the routing table has a genuine answer to
	// give and the derived source is one this box actually holds. Using a
	// fabricated address instead would test the fixture.
	ln, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Skipf("no udp4 loopback available: %v", err)
	}
	defer ln.Close()
	target := ln.LocalAddr().String()

	a := &Agent{}
	pkt := a.buildLinkTrapV1("public", target, true, 5, "ge-0-0-0", true)
	got := decodeAgentAddr9123(t, pkt)

	if got.Equal(net.IPv4zero) {
		t.Fatalf("agent-addr is still 0.0.0.0 for a routable IPv4 target (%s). "+
			"RFC 3584 §3.2 requires the originator's own address here; a receiver "+
			"that trusts agent-addr files this alarm against node 0.0.0.0", target)
	}
	if !got.Equal(net.IPv4(127, 0, 0, 1)) {
		t.Errorf("agent-addr = %v, want the source toward %s (127.0.0.1)", got, target)
	}
}

// The 0.0.0.0 fallback must SURVIVE for the case the RFC actually sanctions it
// for: no IPv4 source can be determined. Without this row, "populate the field"
// is satisfied by a fix that writes garbage when the lookup fails.
func TestV1TrapFallsBackToZeroWhenNoSourceExists9123(t *testing.T) {
	a := &Agent{}
	for _, tc := range []struct{ name, target string }{
		{"empty target", ""},
		{"unresolvable host", "no-such-host.invalid.:162"},
		{"IPv6-only target", "[::1]:162"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := decodeAgentAddr9123(t, a.buildLinkTrapV1("public", tc.target, true, 5, "ge-0-0-0", true))
			if !got.Equal(net.IPv4zero) {
				t.Errorf("agent-addr = %v for %q, want 0.0.0.0 — that value is the "+
					"RFC's fallback for exactly this case, and inventing an address "+
					"here would be worse than the field being empty", got, tc.target)
			}
		})
	}
}

// The v2c packet must remain UNAFFECTED by the target, and v2c is the DEFAULT
// version — so a restructuring that quietly changed it would hit most
// deployments.
//
// This asserts the actual invariant (v2c carries no agent-addr, and the target
// changes nothing structural) rather than byte-identity. Byte-identity was my
// first attempt and it was simply wrong: the v2c PDU carries a RANDOMIZED
// request-id, so two builds of the same trap differ at bytes 18-21 with no
// change to anything. It reported a difference for every target including the
// empty one, which is what showed it was measuring the randomness rather than
// the change.
func TestV2cTrapIsUnaffectedByTheTargetMove9123(t *testing.T) {
	a := &Agent{}
	var lens []string
	for _, target := range []string{"", "127.0.0.1:162", "10.9.9.9:162"} {
		pkts := a.buildLinkTrapsForVersion("public", "v2", target, true, 5, "ge-0-0-0", true)
		if len(pkts) != 1 {
			t.Fatalf("v2 emitted %d packets for target %q, want 1", len(pkts), target)
		}
		msg, ok := berFind9123(t, pkts[0], tagSequence)
		if !ok {
			t.Fatalf("v2c packet for target %q has no outer SEQUENCE", target)
		}
		for _, kv := range berChildren9123(t, msg) {
			if kv[0].(byte) == tagIPAddress {
				t.Errorf("the v2c packet for target %q carries an IpAddress TLV; v2c "+
					"has no agent-addr field and must not have grown one", target)
			}
		}
		lens = append(lens, berShape9335(t, msg))
	}
	for i := 1; i < len(lens); i++ {
		if lens[i] != lens[0] {
			t.Errorf("the v2c packet SHAPE varies with the target:\n  %s\n  %s\n"+
				"it does not depend on the target and must not start to",
				lens[0], lens[i])
			break
		}
	}

	// REFERENCE ARM: the v1 packet DOES vary with the target, which is the whole
	// change. If it did not, the assertions above would be trivially satisfied
	// by a build that ignores the target entirely.
	v1a := a.buildLinkTrapV1("public", "", true, 5, "ge-0-0-0", true)
	ln, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Skipf("no udp4 loopback available: %v", err)
	}
	defer ln.Close()
	v1b := a.buildLinkTrapV1("public", ln.LocalAddr().String(), true, 5, "ge-0-0-0", true)
	if decodeAgentAddr9123(t, v1a).Equal(decodeAgentAddr9123(t, v1b)) {
		t.Error("the v1 agent-addr did not change between an empty target and a " +
			"routable one, so nothing above is distinguishing v1 from v2c")
	}
}

// The four-byte narrowing, driven directly.
//
// net.IP may hold an IPv4 address in a 4-byte OR a 16-byte v4-mapped form, and
// which one a udp4 socket returns is a runtime detail. Taking the first four
// bytes of the 16-byte form gives 0.0.0.0 — the leading zeros of ::ffff: — so
// the trap would carry exactly the value this change exists to stop emitting,
// on a platform where nothing in this file changed.
//
// This is here because the guard was NOT exercisable through the socket path:
// with it inline, a mutation removing `To4()` survived, since this platform
// returns the 4-byte form. Whether a guard is reachable through its only caller
// today is a different question from whether it is correct.
func TestIPv4NarrowingHandlesBothForms9123(t *testing.T) {
	want := [4]byte{10, 1, 2, 3}

	if got, ok := ipv4Bytes9123(net.IP{10, 1, 2, 3}); !ok || got != want {
		t.Errorf("4-byte form -> %v ok=%v, want %v", got, ok, want)
	}
	// The 16-byte v4-mapped form. Indexed naively this yields 0.0.0.0.
	mapped := net.IP{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 10, 1, 2, 3}
	if got, ok := ipv4Bytes9123(mapped); !ok || got != want {
		t.Errorf("16-byte v4-mapped form -> %v ok=%v, want %v — indexing without "+
			"To4() would give 0.0.0.0 here", got, ok, want)
	}
	// A genuine IPv6 address has no four-byte form, and that is the RFC's
	// 0.0.0.0 case rather than something to truncate.
	if got, ok := ipv4Bytes9123(net.ParseIP("2001:db8::1")); ok {
		t.Errorf("a real IPv6 address was narrowed to %v; it must be refused so the "+
			"caller emits the sanctioned 0.0.0.0", got)
	}
	if got, ok := ipv4Bytes9123(nil); ok {
		t.Errorf("nil narrowed to %v", got)
	}
}

// berShape9335 renders a BER value as a canonical structural signature:
// the tag tree, with every leaf's bytes included EXCEPT for INTEGERs, whose
// VALUE is deliberately discarded.
//
// #9335: the assertion this replaces compared packet LENGTHS across three
// builds, and that is unsound for the same reason the byte-identity check
// documented above it was unsound — one level down and with a much lower hit
// rate, which is why it survived review and then reddened `go test ./...` for
// every lane at a measured 1.08% over 20,000 iterations.
//
// The v2c PDU carries a RANDOMIZED request-id, and a BER INTEGER is
// minimal-width: a request-id that fits in one byte encodes shorter than one
// needing three. So the packet length varies by chance, with nothing about the
// target having changed. I wrote a comment saying byte-identity "was measuring
// the randomness rather than the change", and then asserted a length identity
// that measures exactly that same randomness.
//
// A LOW-RATE FLAKE IS WORSE THAN A LOUD ONE. At 1.08% it passes every time the
// author runs it and fails for someone else weeks later in an unrelated
// package, where the honest reading — "my change did this" — is wrong, and the
// cheap reading — "re-run it" — is how a suite stops being believed.
//
// Discarding INTEGER values is a real loss of strength, which is why
// TestTheShapeSignatureDiscriminates9335 exists: a signature that discards too
// much passes trivially, so the discarding has to be shown to still
// discriminate.
func berShape9335(t *testing.T, v []byte) string {
	t.Helper()
	var b strings.Builder
	var walk func(v []byte, depth int)
	walk = func(v []byte, depth int) {
		for _, kv := range berChildren9123(t, v) {
			tag := kv[0].(byte)
			body := kv[1].([]byte)
			fmt.Fprintf(&b, "%*s%#x", depth*2, "", tag)
			switch {
			case tag == tagInteger:
				// Value discarded: the request-id is random and
				// minimal-width, so its bytes AND its length are noise here.
				b.WriteString("(int)\n")
			case tag&0x20 != 0 || tag == tagSequence || tag >= 0xa0:
				// Constructed: recurse rather than compare opaque bytes, so a
				// structural change inside is visible.
				b.WriteString("{\n")
				walk(body, depth+1)
				fmt.Fprintf(&b, "%*s}\n", depth*2, "")
			default:
				fmt.Fprintf(&b, "=%x\n", body)
			}
		}
	}
	walk(v, 0)
	return b.String()
}

// The signature must still SEE a real difference. Without this, berShape9335
// could return a constant and every assertion built on it would pass — the
// failure mode of every summarising comparison.
func TestTheShapeSignatureDiscriminates9335(t *testing.T) {
	a := &Agent{}
	up := a.buildLinkTrapsForVersion("public", "v2", "", true, 5, "ge-0-0-0", true)
	down := a.buildLinkTrapsForVersion("public", "v2", "", false, 5, "ge-0-0-0", true)
	if len(up) != 1 || len(down) != 1 {
		t.Fatalf("want one packet each, got %d and %d", len(up), len(down))
	}
	upMsg, ok := berFind9123(t, up[0], tagSequence)
	if !ok {
		t.Fatal("no outer SEQUENCE in the link-up packet")
	}
	downMsg, ok := berFind9123(t, down[0], tagSequence)
	if !ok {
		t.Fatal("no outer SEQUENCE in the link-down packet")
	}
	if berShape9335(t, upMsg) == berShape9335(t, downMsg) {
		t.Error("linkUp and linkDown produce the SAME shape signature, so the " +
			"signature discards the very differences it is used to detect")
	}

	// And it must be STABLE across repeated builds of the same trap — the
	// property the old length check failed to have. Twenty iterations is not a
	// proof at a 1.08% rate, but a signature that varies at all here fails
	// immediately rather than in someone else's package.
	base := berShape9335(t, upMsg)
	for i := 0; i < 20; i++ {
		pkts := a.buildLinkTrapsForVersion("public", "v2", "", true, 5, "ge-0-0-0", true)
		msg, ok := berFind9123(t, pkts[0], tagSequence)
		if !ok {
			t.Fatal("no outer SEQUENCE")
		}
		if got := berShape9335(t, msg); got != base {
			t.Fatalf("shape varied across two builds of the SAME trap on iteration "+
				"%d; the signature is not invariant to the randomized request-id", i)
		}
	}
}
