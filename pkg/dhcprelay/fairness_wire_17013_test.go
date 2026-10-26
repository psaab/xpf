package dhcprelay

import (
	"bytes"
	"net"
	"testing"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv6"
)

// #17013: the production fairness gate peeks the sender key from the WIRE
// (fairSenderKeyFromWire / fairSenderKeyV6FromWire). Parsed-key twins were
// production-dead and hid the wire edges behind an oracle that disagreed
// with the peek: a 200-byte DUID was truncated by the peek but refused by
// pending6KeyFor. The wire peek now rejects that unrepresentable identity,
// matching the pending-key path. These cells pin the wire peeks directly.

// TestFairSenderKeyWireEdges17013 pins the v4 BOOTP peek edge table:
// hlen 0 and hlen > 16 have no usable client identity (ok=false, so the
// caller lumps the datagram into fairUnknownSenderV4), a short datagram
// is not-ok, and a well-formed DISCOVER keys on its chaddr with the
// hlen participating in the key.
func TestFairSenderKeyWireEdges17013(t *testing.T) {
	wire := discoverWire(t, 0x5A)
	pkt, err := dhcpv4.FromBytes(wire)
	if err != nil {
		t.Fatalf("FromBytes: %v", err)
	}
	got, ok := fairSenderKeyFromWire(wire)
	if !ok {
		t.Fatal("wire peek rejected a valid DISCOVER")
	}
	// Build the expected key from the parsed packet fields directly
	// (never via a parsed-key twin helper).
	want := fairSenderKeyV4{hlen: uint8(len(pkt.ClientHWAddr))}
	copy(want.chaddr[:], pkt.ClientHWAddr)
	if got != want {
		t.Fatalf("wire key = %+v, want %+v built from parsed chaddr", got, want)
	}

	for _, tc := range []struct {
		name string
		hlen byte
	}{
		{"hlen 0", 0},
		{"hlen 17", 17},
		{"hlen 255", 255},
	} {
		bad := append([]byte(nil), wire...)
		bad[v4HlenOff] = tc.hlen
		if _, ok := fairSenderKeyFromWire(bad); ok {
			t.Errorf("%s: wire peek accepted a datagram with no usable chaddr", tc.name)
		}
	}
	if _, ok := fairSenderKeyFromWire(wire[:v4ChaddrOff+15]); ok {
		t.Error("wire peek accepted a datagram too short for the chaddr field")
	}
	// hlen participates: the same chaddr bytes at hlen 6 vs hlen 16 must
	// not collide, so different-length identities keep distinct buckets.
	k6, ok6 := fairSenderKeyFromWire(wire)
	long := append([]byte(nil), wire...)
	long[v4HlenOff] = 16
	k16, ok16 := fairSenderKeyFromWire(long)
	if !ok6 || !ok16 || k6 == k16 {
		t.Errorf("hlen must participate in the key: k6=%+v ok=%v k16=%+v ok=%v", k6, ok6, k16, ok16)
	}
}

// TestFairSenderKeyV6WireOverlongDUID17013 pins the v6 wire peek at the
// DUID-length edge: a Client-ID DUID longer than pending6MaxDUIDSize has
// no representable fairness identity and reports ok=false, matching the
// parsed pending-key refusal. A DUID exactly pending6MaxDUIDSize remains
// representable in both paths.
func TestFairSenderKeyV6WireOverlongDUID17013(t *testing.T) {
	// Client-ID option (code 1) carrying a 200-byte opaque DUID
	// (type 0 + 198 payload bytes), framed as a DHCPv6 client message.
	duid := make([]byte, 200)
	duid[0], duid[1] = 0, 0 // DUID type 0 (opaque)
	for i := 2; i < len(duid); i++ {
		duid[i] = byte(i)
	}
	var buf bytes.Buffer
	buf.WriteByte(byte(dhcpv6.MessageTypeSolicit))
	buf.Write([]byte{0, 0, 1}) // xid
	buf.WriteByte(0)
	buf.WriteByte(byte(dhcpv6.OptionClientID))
	buf.WriteByte(byte(len(duid) >> 8))
	buf.WriteByte(byte(len(duid)))
	buf.Write(duid)

	if _, ok := fairSenderKeyV6FromWire(buf.Bytes()); ok {
		t.Fatal("wire peek accepted a >128-byte DUID; want no fairness identity")
	}

	// The parsed pending key also refuses the same DUID: the message parses,
	// but no upstream binding is created for this client.
	msg, err := dhcpv6.FromBytes(buf.Bytes())
	if err != nil {
		t.Fatalf("FromBytes(over-long DUID): %v", err)
	}
	if _, ok := pending6KeyFor(msg); ok {
		t.Fatal("pending6KeyFor accepted a >128-byte DUID; want refusal")
	}

	// Control: a DUID at exactly pending6MaxDUIDSize is representable in
	// both the peek (not truncated further) and the parsed key space.
	exact := make([]byte, pending6MaxDUIDSize)
	copy(exact, duid)
	var buf2 bytes.Buffer
	buf2.WriteByte(byte(dhcpv6.MessageTypeSolicit))
	buf2.Write([]byte{0, 0, 2})
	buf2.WriteByte(0)
	buf2.WriteByte(byte(dhcpv6.OptionClientID))
	buf2.WriteByte(byte(len(exact) >> 8))
	buf2.WriteByte(byte(len(exact)))
	buf2.Write(exact)
	k2, ok := fairSenderKeyV6FromWire(buf2.Bytes())
	if !ok || int(k2.duidLen) != pending6MaxDUIDSize || !bytes.Equal(k2.duid[:], exact) {
		t.Fatalf("exact-size DUID: key=%+v ok=%v, want full %d-byte identity", k2, ok, pending6MaxDUIDSize)
	}
	msg2, err := dhcpv6.FromBytes(buf2.Bytes())
	if err != nil {
		t.Fatalf("FromBytes(exact-size DUID): %v", err)
	}
	if _, ok := pending6KeyFor(msg2); !ok {
		t.Fatal("pending6KeyFor rejected a DUID exactly pending6MaxDUIDSize")
	}

	// Wire keys for the standard DUID forms still agree byte-for-byte
	// with the parsed pending key's DUID serialization.
	for i, d := range []dhcpv6.DUID{
		&dhcpv6.DUIDUUID{UUID: [16]byte{0x10, 0x21, 0x32}},
		&dhcpv6.DUIDLL{LinkLayerAddr: net.HardwareAddr{0x02, 0, 0, 0, 0, 9}},
		&dhcpv6.DUIDEN{EnterpriseNumber: 42, EnterpriseIdentifier: []byte{1, 2, 3}},
	} {
		m := newDHCPV6BindingMessage(t, dhcpv6.TransactionID{byte(i)})
		m.Options.Del(dhcpv6.OptionClientID)
		m.AddOption(dhcpv6.OptClientID(d))
		gotK, ok := fairSenderKeyV6FromWire(m.ToBytes())
		if !ok {
			t.Fatalf("duid %d: wire peek rejected a valid message", i)
		}
		pk, pok := pending6KeyFor(m)
		if !pok {
			t.Fatalf("duid %d: parsed pending key rejected a valid message", i)
		}
		wantK := fairSenderKeyV6{duid: pk.duid, duidLen: pk.duidLen}
		if gotK != wantK {
			t.Fatalf("duid %d: wire key %+v, want parsed-pending %+v", i, gotK, wantK)
		}
	}
}
