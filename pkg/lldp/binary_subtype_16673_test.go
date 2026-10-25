package lldp

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// #16673 (R3-A51-04): binary Chassis/Port ID subtypes were stored as
// lossy-sanitized text with the subtype byte dropped, so distinct neighbours
// under one chassis shared one table key, rendered as garbage, and either
// one's TTL=0 withdrawal removed the other. These tests pin the canonical
// decode, the raw+subtype keying, and the unchanged text/control cells.
//
// RED on the pre-fix code: MAC port IDs render "RT \ufffd\ufffd "-style
// sanitized garbage instead of 52:54:00:aa:bb:01, the two MAC-port neighbours
// below collapse onto one key, and withdrawing one deletes the other.

// frame16673 builds a wire LLDPDU from explicit chassis/port TLV values
// (subtype byte included), a TTL, and End.
func frame16673(chassis, port []byte, ttl int) []byte {
	return concat(
		rawTLV(tlvChassisID, chassis),
		rawTLV(tlvPortID, port),
		mustEncodeTLV(tlvTTL, encodeTTL(ttl)),
		mustEncodeTLV(tlvEnd, nil),
	)
}

func TestParseTLVs_BinaryPortMACSubtype16673(t *testing.T) {
	chassis := append([]byte{chassisSubtypeMACAddr}, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55)
	port := append([]byte{portSubtypeMACAddr}, 0x52, 0x54, 0x00, 0xaa, 0xbb, 0x01)

	n := ParseTLVs(frame16673(chassis, port, 120))
	if n == nil {
		t.Fatal("ParseTLVs returned nil for a MAC-subtype port ID frame")
	}
	if n.PortID != "52:54:00:aa:bb:01" {
		t.Errorf("PortID = %q, want canonical MAC %q", n.PortID, "52:54:00:aa:bb:01")
	}
	if n.PortSubtype != portSubtypeMACAddr {
		t.Errorf("PortSubtype = %d, want %d", n.PortSubtype, portSubtypeMACAddr)
	}
	if n.ChassisID != "00:11:22:33:44:55" || n.ChassisSubtype != chassisSubtypeMACAddr {
		t.Errorf("chassis = %q subtype %d, want 00:11:22:33:44:55 subtype %d",
			n.ChassisID, n.ChassisSubtype, chassisSubtypeMACAddr)
	}
	if !utf8.ValidString(n.PortID) || strings.ContainsRune(n.PortID, '\ufffd') {
		t.Errorf("PortID is not clean display text: %q", n.PortID)
	}
}

func TestParseTLVs_NetworkAddressChassis16673(t *testing.T) {
	port := encodePortID("ge-0/0/1")

	v4 := append([]byte{chassisSubtypeNetworkAddr, ianaAFIPv4}, 192, 0, 2, 1)
	n := ParseTLVs(frame16673(v4, port, 120))
	if n == nil {
		t.Fatal("ParseTLVs returned nil for a v4 network-address chassis")
	}
	if n.ChassisID != "192.0.2.1" {
		t.Errorf("ChassisID = %q, want %q", n.ChassisID, "192.0.2.1")
	}
	if n.ChassisSubtype != chassisSubtypeNetworkAddr {
		t.Errorf("ChassisSubtype = %d, want %d", n.ChassisSubtype, chassisSubtypeNetworkAddr)
	}

	v6addr := []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	v6 := append([]byte{chassisSubtypeNetworkAddr, ianaAFIPv6}, v6addr...)
	n = ParseTLVs(frame16673(v6, port, 120))
	if n == nil {
		t.Fatal("ParseTLVs returned nil for a v6 network-address chassis")
	}
	if n.ChassisID != "2001:db8::1" {
		t.Errorf("ChassisID = %q, want %q", n.ChassisID, "2001:db8::1")
	}

	// A non-IP family keeps family + every address byte visible.
	other := append([]byte{chassisSubtypeNetworkAddr, 99}, 0xaa, 0xbb)
	n = ParseTLVs(frame16673(other, port, 120))
	if n == nil {
		t.Fatal("ParseTLVs returned nil for a non-IP network-address chassis")
	}
	if n.ChassisID != "iana-99:aabb" {
		t.Errorf("ChassisID = %q, want %q", n.ChassisID, "iana-99:aabb")
	}

	// A malformed length for a known family also keeps every byte visible.
	short := append([]byte{chassisSubtypeNetworkAddr, ianaAFIPv4}, 10, 0, 1)
	n = ParseTLVs(frame16673(short, port, 120))
	if n == nil {
		t.Fatal("ParseTLVs returned nil for a short v4 network-address chassis")
	}
	if n.ChassisID != "iana-1:0a0001" {
		t.Errorf("ChassisID = %q, want %q", n.ChassisID, "iana-1:0a0001")
	}
}

func TestParseTLVs_HexFallbackAndTruncation16673(t *testing.T) {
	chassis := append([]byte{chassisSubtypeMACAddr}, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55)

	// Locally-assigned port ID carrying binary bytes: hex, byte-exact display.
	binPort := append([]byte{portSubtypeLocallyAssigned}, 0x01, 0x02, 0xff, 0x00)
	n := ParseTLVs(frame16673(chassis, binPort, 120))
	if n == nil {
		t.Fatal("ParseTLVs returned nil for a binary locally-assigned port ID")
	}
	if n.PortID != "0102ff00" {
		t.Errorf("PortID = %q, want hex %q", n.PortID, "0102ff00")
	}
	if n.PortSubtype != portSubtypeLocallyAssigned {
		t.Errorf("PortSubtype = %d, want %d", n.PortSubtype, portSubtypeLocallyAssigned)
	}

	// Subtype-truncated binary identifiers are rejected like any other
	// truncated mandatory TLV (#2551 gating, per-subtype).
	cases := []struct {
		name    string
		chassis []byte
		port    []byte
	}{
		{"port-mac-truncated",
			chassis,
			append([]byte{portSubtypeMACAddr}, 0x52, 0x54, 0x00)},
		{"chassis-network-no-address",
			[]byte{chassisSubtypeNetworkAddr, ianaAFIPv4},
			encodePortID("eth0")},
		{"port-network-no-address",
			chassis,
			[]byte{portSubtypeNetworkAddr, ianaAFIPv6}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ParseTLVs(frame16673(tc.chassis, tc.port, 120)); got != nil {
				t.Errorf("expected nil for truncated binary subtype, got chassis=%q port=%q",
					got.ChassisID, got.PortID)
			}
		})
	}
}

// TestBinaryPortIDsDistinctNeighbors16673 is the collision acceptance cell:
// two NICs of one host (same chassis, MAC port IDs differing only in bytes
// sanitization used to fold together) must be two neighbours, and a TTL=0
// withdrawal keyed from one must not remove the other.
func TestBinaryPortIDsDistinctNeighbors16673(t *testing.T) {
	chassis := append([]byte{chassisSubtypeMACAddr}, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55)
	// 0x01/0x02 are C0 controls: pre-fix both folded to a space, one key.
	portA := append([]byte{portSubtypeMACAddr}, 0x52, 0x54, 0x00, 0xaa, 0xbb, 0x01)
	portB := append([]byte{portSubtypeMACAddr}, 0x52, 0x54, 0x00, 0xaa, 0xbb, 0x02)

	a := ParseTLVs(frame16673(chassis, portA, 120))
	b := ParseTLVs(frame16673(chassis, portB, 120))
	if a == nil || b == nil {
		t.Fatal("ParseTLVs returned nil for a MAC-port neighbour")
	}
	if a.PortID != "52:54:00:aa:bb:01" || b.PortID != "52:54:00:aa:bb:02" {
		t.Fatalf("PortIDs = %q / %q, want 52:54:00:aa:bb:01 / 52:54:00:aa:bb:02", a.PortID, b.PortID)
	}
	ka, kb := neighborKeyFor("eth0", a), neighborKeyFor("eth0", b)
	if ka == kb {
		t.Fatal("distinct MAC port IDs share one neighbor key — the #16673 collision")
	}

	m := New()
	a.Interface, b.Interface = "eth0", "eth0"
	if !m.learnNeighbor(ka, a) || !m.learnNeighbor(kb, b) {
		t.Fatal("both MAC-port neighbours must be admitted")
	}
	if got := len(m.Neighbors()); got != 2 {
		t.Fatalf("%d neighbours, want 2 distinct entries", got)
	}

	// One NIC's shutdown withdraws only its own entry.
	m.withdrawNeighbor(ka)
	ns := m.Neighbors()
	if len(ns) != 1 {
		t.Fatalf("after one TTL=0 withdrawal %d neighbours remain, want 1", len(ns))
	}
	if ns[0].PortID != "52:54:00:aa:bb:02" {
		t.Errorf("surviving PortID = %q, want 52:54:00:aa:bb:02", ns[0].PortID)
	}
}

// TestSubtypeDistinguishesSameDisplayText16673: the subtype is part of the
// MSAP. The same identifier text under two subtypes is two neighbours, even
// though the display strings are identical.
func TestSubtypeDistinguishesSameDisplayText16673(t *testing.T) {
	chassis := append([]byte{chassisSubtypeMACAddr}, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55)
	byName := ParseTLVs(frame16673(chassis, encodePortID("eth0"), 120))
	byLocal := ParseTLVs(frame16673(chassis,
		append([]byte{portSubtypeLocallyAssigned}, []byte("eth0")...), 120))
	if byName == nil || byLocal == nil {
		t.Fatal("ParseTLVs returned nil")
	}
	if byName.PortID != "eth0" || byLocal.PortID != "eth0" {
		t.Fatalf("PortIDs = %q / %q, want both eth0 (positive control: text unchanged)",
			byName.PortID, byLocal.PortID)
	}
	if neighborKeyFor("eth0", byName) == neighborKeyFor("eth0", byLocal) {
		t.Fatal("same text under different port subtypes shares one key — subtype dropped from the MSAP")
	}
}

// TestBinaryIdentityKeyUsesRawBytes16673: even where two raw identities share
// one canonical display (a MAC body longer than 6 bytes displays its first 6),
// the key must follow the raw bytes, not the display string.
func TestBinaryIdentityKeyUsesRawBytes16673(t *testing.T) {
	port := encodePortID("eth0")
	longA := append([]byte{chassisSubtypeMACAddr}, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x01)
	longB := append([]byte{chassisSubtypeMACAddr}, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x02)
	a := ParseTLVs(frame16673(longA, port, 120))
	b := ParseTLVs(frame16673(longB, port, 120))
	if a == nil || b == nil {
		t.Fatal("ParseTLVs returned nil for an over-long MAC chassis body")
	}
	if a.ChassisID != b.ChassisID {
		t.Fatalf("precondition: displays should coincide, got %q / %q", a.ChassisID, b.ChassisID)
	}
	if neighborKeyFor("eth0", a) == neighborKeyFor("eth0", b) {
		t.Fatal("display-equal but byte-distinct chassis IDs share one key — key follows display, not raw bytes")
	}
}
