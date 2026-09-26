package lldp

import (
	"context"
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode"
	"unicode/utf8"
)

func TestEncodeTLV(t *testing.T) {
	// End TLV: type=0, length=0 → 0x0000
	end, err := EncodeTLV(tlvEnd, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(end) != 2 {
		t.Fatalf("expected 2 bytes, got %d", len(end))
	}
	if end[0] != 0 || end[1] != 0 {
		t.Fatalf("expected 0x0000 for end TLV, got %02x%02x", end[0], end[1])
	}

	// System Name TLV: type=5, value="test"
	name, err := EncodeTLV(tlvSystemName, []byte("test"))
	if err != nil {
		t.Fatal(err)
	}
	if len(name) != 6 {
		t.Fatalf("expected 6 bytes, got %d", len(name))
	}
	header := binary.BigEndian.Uint16(name[:2])
	tlvType := int(header >> 9)
	tlvLen := int(header & 0x1ff)
	if tlvType != tlvSystemName {
		t.Errorf("expected type %d, got %d", tlvSystemName, tlvType)
	}
	if tlvLen != 4 {
		t.Errorf("expected length 4, got %d", tlvLen)
	}
	if string(name[2:]) != "test" {
		t.Errorf("expected value 'test', got %q", string(name[2:]))
	}
}

func TestEncodeTLV_FailsClosedOnOverlength(t *testing.T) {
	// 511 bytes: the maximum a 9-bit length can express — accepted, and the
	// encoded header length matches.
	maxVal := make([]byte, maxTLVValueLen) // 511
	enc, err := EncodeTLV(tlvSystemDesc, maxVal)
	if err != nil {
		t.Fatalf("511-byte value should encode, got: %v", err)
	}
	if got := int(binary.BigEndian.Uint16(enc[:2]) & 0x1ff); got != maxTLVValueLen {
		t.Fatalf("encoded length should be %d, got %d", maxTLVValueLen, got)
	}
	// 512 and 600 bytes: would wrap the 9-bit length field — must be REJECTED,
	// not silently masked into a malformed frame (#2036).
	for _, n := range []int{maxTLVValueLen + 1, 600} {
		if _, err := EncodeTLV(tlvSystemDesc, make([]byte, n)); err == nil {
			t.Errorf("a %d-byte value must be rejected (would wrap the 9-bit length), got nil error", n)
		}
	}
}

func TestBuildFrame_FailsClosedOnOverlengthIdentity(t *testing.T) {
	mac := net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	// An overlength variable-length identity TLV (system description) must fail
	// the whole frame rather than emit a malformed advertisement.
	huge := string(make([]byte, 600))
	if _, err := BuildFrame(mac, "trust0", 120, "xpf", huge); err == nil {
		t.Fatal("BuildFrame must fail closed on an overlength system-description TLV")
	}
	// An overlength port name must also fail closed (not panic), since portName
	// is caller-supplied and BuildFrame now routes it through EncodeTLV (#2036).
	if _, err := BuildFrame(mac, huge, 120, "xpf", "ok"); err == nil {
		t.Fatal("BuildFrame must fail closed on an overlength port name TLV")
	}
	// A bounded frame still builds cleanly.
	if _, err := BuildFrame(mac, "trust0", 120, "xpf", "ok"); err != nil {
		t.Fatalf("bounded frame should build, got: %v", err)
	}
}

func TestEncodeChassisID(t *testing.T) {
	mac := net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	val := encodeChassisID(mac)
	if len(val) != 7 {
		t.Fatalf("expected 7 bytes, got %d", len(val))
	}
	if val[0] != chassisSubtypeMACAddr {
		t.Errorf("expected subtype %d, got %d", chassisSubtypeMACAddr, val[0])
	}
	if net.HardwareAddr(val[1:7]).String() != mac.String() {
		t.Errorf("MAC mismatch: got %s", net.HardwareAddr(val[1:7]))
	}
}

func TestEncodePortID(t *testing.T) {
	val := encodePortID("eth0")
	if len(val) != 5 {
		t.Fatalf("expected 5 bytes, got %d", len(val))
	}
	if val[0] != portSubtypeIfName {
		t.Errorf("expected subtype %d, got %d", portSubtypeIfName, val[0])
	}
	if string(val[1:]) != "eth0" {
		t.Errorf("expected 'eth0', got %q", string(val[1:]))
	}
}

func TestEncodeTTL(t *testing.T) {
	val := encodeTTL(120)
	if len(val) != 2 {
		t.Fatalf("expected 2 bytes, got %d", len(val))
	}
	ttl := binary.BigEndian.Uint16(val)
	if ttl != 120 {
		t.Errorf("expected TTL 120, got %d", ttl)
	}
}

// #4596: encodeTTL must clamp a computed TTL to the 16-bit wire maximum
// (65535) so a large transmit-interval × hold-multiplier product cannot wrap
// uint16 back to a small/zero TTL, which would make every peer IMMEDIATELY
// expire this neighbor. RED on revert: without the clamp, uint16(65536) is 0
// and uint16(160000) is 28928 (both wrong).
func TestEncodeTTL_ClampsOverflow_4596(t *testing.T) {
	cases := []struct {
		name    string
		seconds int
		want    uint16
	}{
		// transmit-interval 16384 × default hold-multiplier 4 = 65536,
		// which wraps to exactly 0 without the clamp — the issue's headline
		// "immediately expire the neighbor" scenario.
		{"16384x4-wraps-to-zero", 16384 * 4, 0xffff},
		// The in-range IEEE extreme: 32768 × 10 = 327680.
		{"ieee-extreme", 32768 * 10, 0xffff},
		{"exact-max", 0xffff, 0xffff},
		{"just-over-max", 0x10000, 0xffff},
		{"negative-guard", -1, 0},
		{"in-range-passthrough", 120, 120},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := binary.BigEndian.Uint16(encodeTTL(tc.seconds))
			if got != tc.want {
				t.Fatalf("encodeTTL(%d) TTL = %d, want %d", tc.seconds, got, tc.want)
			}
			if got == 0 && tc.want != 0 {
				t.Fatal("TTL wrapped to 0 — neighbors would immediately expire")
			}
		})
	}
}

func TestBuildFrame(t *testing.T) {
	mac := net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	frame, err := BuildFrame(mac, "trust0", 120, "xpf", "stateful firewall")
	if err != nil {
		t.Fatal(err)
	}

	// Check Ethernet header.
	if len(frame) < ethHdrLen {
		t.Fatalf("frame too short: %d bytes", len(frame))
	}

	// Destination MAC = LLDP multicast.
	if net.HardwareAddr(frame[:6]).String() != LLDPMulticast.String() {
		t.Errorf("dst MAC: got %s, want %s",
			net.HardwareAddr(frame[:6]), LLDPMulticast)
	}

	// Source MAC.
	if net.HardwareAddr(frame[6:12]).String() != mac.String() {
		t.Errorf("src MAC: got %s, want %s",
			net.HardwareAddr(frame[6:12]), mac)
	}

	// EtherType.
	etherType := binary.BigEndian.Uint16(frame[12:14])
	if etherType != etherTypeLLDP {
		t.Errorf("ethertype: got 0x%04x, want 0x%04x", etherType, etherTypeLLDP)
	}

	// Parse TLVs from the frame.
	neighbor := ParseTLVs(frame[ethHdrLen:])
	if neighbor == nil {
		t.Fatal("ParseTLVs returned nil for valid frame")
	}
	if neighbor.ChassisID != mac.String() {
		t.Errorf("chassis ID: got %s, want %s", neighbor.ChassisID, mac.String())
	}
	if neighbor.PortID != "trust0" {
		t.Errorf("port ID: got %s, want trust0", neighbor.PortID)
	}
	if neighbor.TTL != 120 {
		t.Errorf("TTL: got %d, want 120", neighbor.TTL)
	}
	if neighbor.SystemName != "xpf" {
		t.Errorf("system name: got %s, want xpf", neighbor.SystemName)
	}
	if neighbor.SystemDesc != "stateful firewall" {
		t.Errorf("system desc: got %s, want 'stateful firewall'", neighbor.SystemDesc)
	}
	if neighbor.PortDesc != "trust0" {
		t.Errorf("port desc: got %s, want trust0", neighbor.PortDesc)
	}
}

func TestParseTLVs_Incomplete(t *testing.T) {
	// Missing Port ID — should return nil.
	mac := net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	var data []byte
	data = append(data, mustEncodeTLV(tlvChassisID, encodeChassisID(mac))...)
	data = append(data, mustEncodeTLV(tlvTTL, encodeTTL(60))...)
	data = append(data, mustEncodeTLV(tlvEnd, nil)...)

	n := ParseTLVs(data)
	if n != nil {
		t.Error("expected nil for incomplete TLVs (missing Port ID)")
	}
}

func TestParseTLVs_Truncated(t *testing.T) {
	// Header says 100 bytes but only 2 bytes available.
	data, err := EncodeTLV(tlvSystemName, []byte("test"))
	if err != nil {
		t.Fatal(err)
	}
	// Corrupt the length to be larger than available.
	binary.BigEndian.PutUint16(data[:2], uint16(tlvSystemName)<<9|100)

	n := ParseTLVs(data)
	if n != nil {
		t.Error("expected nil for truncated TLV data")
	}
}

func TestParseTLVs_Empty(t *testing.T) {
	n := ParseTLVs(nil)
	if n != nil {
		t.Error("expected nil for empty data")
	}
}

// rawTLV builds a single TLV with an explicit (possibly short) value so a
// truncated mandatory TLV can be constructed directly. tlvLen is the 9-bit
// length field written to the header; value is the body that follows it.
func rawTLV(tlvType int, value []byte) []byte {
	header := uint16(tlvType&0x7f)<<9 | uint16(len(value)&0x1ff)
	out := make([]byte, 2+len(value))
	binary.BigEndian.PutUint16(out[:2], header)
	copy(out[2:], value)
	return out
}

// TestParseTLVs_TruncatedMandatory asserts that a mandatory TLV whose value is
// too short to yield a valid identifier is treated as absent, so the frame is
// rejected rather than cached under an empty key (#2551). Before the fix each
// hasX flag was set unconditionally, so these frames were ACCEPTED with empty
// ChassisID/PortID (or TTL 0) — these subtests FAIL on the pre-#2551 code,
// proving fail-on-revert.
func TestParseTLVs_TruncatedMandatory(t *testing.T) {
	mac := net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	goodChassis := mustEncodeTLV(tlvChassisID, encodeChassisID(mac))
	goodPort := mustEncodeTLV(tlvPortID, encodePortID("trust0"))
	goodTTL := mustEncodeTLV(tlvTTL, encodeTTL(120))
	end := mustEncodeTLV(tlvEnd, nil)

	cases := []struct {
		name string
		data []byte
	}{
		{
			// Chassis ID = subtype byte only (len 1), no identifier.
			name: "chassis-id-len-1",
			data: concat(rawTLV(tlvChassisID, []byte{chassisSubtypeMACAddr}), goodPort, goodTTL, end),
		},
		{
			// Chassis ID = empty value (len 0).
			name: "chassis-id-len-0",
			data: concat(rawTLV(tlvChassisID, nil), goodPort, goodTTL, end),
		},
		{
			// Chassis ID MAC subtype but value short of the 6-byte address
			// (subtype + 4 of 6 MAC bytes = len 5, < 7).
			name: "chassis-id-mac-subtype-truncated",
			data: concat(rawTLV(tlvChassisID, []byte{chassisSubtypeMACAddr, 0xaa, 0xbb, 0xcc, 0xdd}), goodPort, goodTTL, end),
		},
		{
			// Port ID = subtype byte only, no identifier.
			name: "port-id-len-1",
			data: concat(goodChassis, rawTLV(tlvPortID, []byte{portSubtypeIfName}), goodTTL, end),
		},
		{
			// TTL value is 1 byte, can't form the 2-byte hold time.
			name: "ttl-len-1",
			data: concat(goodChassis, goodPort, rawTLV(tlvTTL, []byte{0x05}), end),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			n := ParseTLVs(tc.data)
			if n != nil {
				t.Errorf("expected nil for truncated mandatory TLV, got neighbor "+
					"chassis=%q port=%q ttl=%d", n.ChassisID, n.PortID, n.TTL)
			}
		})
	}
}

// TestParseTLVs_ValidShutdownTTL asserts that a well-formed advert carrying a
// 2-byte TTL of 0 (a legitimate LLDP shutdown frame) is still accepted: the
// hasTTL gate is "the 2-byte value parsed", not "TTL != 0". A truncated TTL
// (covered above) is rejected; a parsed 0 is not.
func TestParseTLVs_ValidShutdownTTL(t *testing.T) {
	mac := net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	data := concat(
		mustEncodeTLV(tlvChassisID, encodeChassisID(mac)),
		mustEncodeTLV(tlvPortID, encodePortID("trust0")),
		mustEncodeTLV(tlvTTL, encodeTTL(0)),
		mustEncodeTLV(tlvEnd, nil),
	)
	n := ParseTLVs(data)
	if n == nil {
		t.Fatal("expected a neighbor for a valid 2-byte TTL=0 shutdown advert, got nil")
	}
	if n.TTL != 0 {
		t.Errorf("TTL: got %d, want 0", n.TTL)
	}
	if n.ChassisID != mac.String() {
		t.Errorf("chassis ID: got %s, want %s", n.ChassisID, mac.String())
	}
	if n.PortID != "trust0" {
		t.Errorf("port ID: got %s, want trust0", n.PortID)
	}
}

// TestSanitizeTLVString unit-tests the LLDP-receive control-char sanitizer
// (#4043): every C0/C1/DEL control character is replaced by a space, a normal
// ASCII or multi-byte UTF-8 string is returned unchanged, and no control byte
// survives. LLDP TLV strings are untrusted L2 input; leaving ESC/CR/LF raw
// would let a crafted neighbor inject ANSI sequences into an operator's
// terminal or forge/split a syslog line.
func TestSanitizeTLVString(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"plain ascii unchanged", "switch-core-1", "switch-core-1"},
		{"utf8 preserved", "café-λ-世界", "café-λ-世界"},
		{"ansi escape stripped", "\x1b[31mred", " [31mred"},
		{"crlf log injection", "a\r\nDROP", "a  DROP"},
		{"nul and c0", "x\x00y\x07z", "x y z"},
		{"del stripped", "a\x7fb", "a b"},
		{"c1 stripped", "aC", "a C"},
		{"trailing newline", "port0\n", "port0 "},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := sanitizeTLVString(tc.in)
			if got != tc.want {
				t.Errorf("sanitizeTLVString(%q) = %q, want %q", tc.in, got, tc.want)
			}
			if i := strings.IndexFunc(got, unicode.IsControl); i >= 0 {
				t.Errorf("sanitizeTLVString(%q) retained a control char at byte %d: %q", tc.in, i, got)
			}
		})
	}
}

// TestSanitizeTLVString_RawInvalidUTF8 is the #6482 regression. A raw invalid
// UTF-8 byte such as 0x9B — the 8-bit CSI introducer that an 8-bit terminal
// acts on exactly like ESC[ — is NOT a Unicode control rune: it decodes to
// U+FFFD, which unicode.IsControl reports false. The pre-#6482 fast path
// `strings.IndexFunc(s, unicode.IsControl) < 0` therefore returned such a
// string UNCHANGED, so the raw 0x9B reached the operator's terminal via `show
// lldp neighbors`. The fast path now also requires utf8.ValidString, so the
// strings.Map slow path runs and folds every invalid byte to U+FFFD.
//
// The `c1 stripped` case in TestSanitizeTLVString uses the VALID two-byte UTF-8
// encoding of U+009B (0xC2 0x9B) — a real control rune — and so never exercised
// this raw-byte path. Note the assertions below scan for the raw 0x9B BYTE
// (strings.IndexByte), not strings.ContainsRune(0x9B): rune U+009B encodes to
// 0xC2 0x9B, so ContainsRune looks for the wrong bytes and would false-negative.
func TestSanitizeTLVString_RawInvalidUTF8(t *testing.T) {
	cases := []struct {
		name string
		in   string
	}{
		{"raw 8-bit csi erase", "\x9b2J"},             // bare 0x9B + "2J" == 8-bit CSI 2J
		{"raw 8-bit osc plus bel", "n\x9d52;c;A\x07"}, // bare 0x9D (OSC) + C0 BEL
		{"lone continuation byte", "ge\x80-0-0"},      // stray 0x80 continuation
		{"truncated 2-byte lead", "a\xc3z"},           // 0xC3 with no continuation
		{"raw 0xff never valid", "x\xffy"},            // 0xFF is never valid UTF-8
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := sanitizeTLVString(tc.in)
			// Every smuggled byte must be folded away: the output is well-formed
			// UTF-8, carries no raw 0x9B, and holds no control rune.
			if !utf8.ValidString(got) {
				t.Errorf("sanitizeTLVString(%q) = %q is still not valid UTF-8", tc.in, got)
			}
			if i := strings.IndexByte(got, 0x9b); i >= 0 {
				t.Errorf("sanitizeTLVString(%q) = %q retained a raw 0x9b byte at %d", tc.in, got, i)
			}
			if i := strings.IndexFunc(got, unicode.IsControl); i >= 0 {
				t.Errorf("sanitizeTLVString(%q) = %q retained a control rune at byte %d", tc.in, got, i)
			}
		})
	}
}

// TestParseTLVs_SanitizesControlChars asserts the end-to-end store boundary:
// a received LLDP frame whose free-text TLVs (system-name, system-desc,
// port-desc, port-id, non-MAC chassis-id) carry ESC + CRLF + C0/DEL control
// characters is parsed into a neighbor whose stored strings are control-char
// free, so neither expiryLoop's log line nor the `show lldp neighbors` table
// can be poisoned by a hostile neighbor (#4043). Readable payload survives.
func TestParseTLVs_SanitizesControlChars(t *testing.T) {
	sysName := "\x1b[31mroot\r\nfake-log-line"
	sysDesc := "desc\x1b]0;title\x07"
	portDesc := "port\x00\x0bdesc"
	portID := "eth\x1b[2J0\n"
	// Non-MAC chassis-id subtype (7 = locally assigned) carrying a CRLF.
	chassisRaw := append([]byte{7}, []byte("host\r\nA")...)

	data := concat(
		rawTLV(tlvChassisID, chassisRaw),
		mustEncodeTLV(tlvPortID, encodePortID(portID)),
		mustEncodeTLV(tlvTTL, encodeTTL(120)),
		mustEncodeTLV(tlvSystemName, []byte(sysName)),
		mustEncodeTLV(tlvSystemDesc, []byte(sysDesc)),
		mustEncodeTLV(tlvPortDesc, []byte(portDesc)),
		mustEncodeTLV(tlvEnd, nil),
	)

	n := ParseTLVs(data)
	if n == nil {
		t.Fatal("ParseTLVs returned nil for a valid (if hostile) frame")
	}

	for name, got := range map[string]string{
		"SystemName": n.SystemName,
		"SystemDesc": n.SystemDesc,
		"PortDesc":   n.PortDesc,
		"PortID":     n.PortID,
		"ChassisID":  n.ChassisID,
	} {
		if i := strings.IndexFunc(got, unicode.IsControl); i >= 0 {
			t.Errorf("%s retained a control char at byte %d: %q", name, i, got)
		}
	}

	// The printable payload survives (control chars become spaces, not drops).
	if !strings.Contains(n.SystemName, "root") || !strings.Contains(n.SystemName, "fake-log-line") {
		t.Errorf("SystemName lost readable text: %q", n.SystemName)
	}
	if strings.ContainsAny(n.PortID, "\x1b\n") {
		t.Errorf("PortID still carries ESC/LF: %q", n.PortID)
	}
	if !strings.HasPrefix(n.ChassisID, "host") {
		t.Errorf("ChassisID lost readable text: %q", n.ChassisID)
	}
}

// TestParseTLVs_CleanStringsUnchanged is the negative control for #4043: a
// frame whose TLV strings contain no control characters is stored verbatim, so
// the sanitizer never mangles a normal neighbor name.
func TestParseTLVs_CleanStringsUnchanged(t *testing.T) {
	mac := net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	data := concat(
		mustEncodeTLV(tlvChassisID, encodeChassisID(mac)),
		mustEncodeTLV(tlvPortID, encodePortID("ge-0/0/1")),
		mustEncodeTLV(tlvTTL, encodeTTL(120)),
		mustEncodeTLV(tlvSystemName, []byte("switch-core-1")),
		mustEncodeTLV(tlvSystemDesc, []byte("Juniper EX4300")),
		mustEncodeTLV(tlvPortDesc, []byte("uplink to spine")),
		mustEncodeTLV(tlvEnd, nil),
	)
	n := ParseTLVs(data)
	if n == nil {
		t.Fatal("ParseTLVs returned nil for a valid clean frame")
	}
	if n.PortID != "ge-0/0/1" {
		t.Errorf("PortID: got %q, want %q", n.PortID, "ge-0/0/1")
	}
	if n.SystemName != "switch-core-1" {
		t.Errorf("SystemName: got %q, want %q", n.SystemName, "switch-core-1")
	}
	if n.SystemDesc != "Juniper EX4300" {
		t.Errorf("SystemDesc: got %q, want %q", n.SystemDesc, "Juniper EX4300")
	}
	if n.PortDesc != "uplink to spine" {
		t.Errorf("PortDesc: got %q, want %q", n.PortDesc, "uplink to spine")
	}
}

func concat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func TestNeighborTable(t *testing.T) {
	m := New()

	// Manually add neighbors and verify.
	m.mu.Lock()
	m.neighbors[mkNeighborKey("eth0", "aa:bb:cc:dd:ee:ff", "port1")] = &Neighbor{
		ChassisID: "aa:bb:cc:dd:ee:ff",
		PortID:    "port1",
		TTL:       120,
		Interface: "eth0",
		LastSeen:  time.Now(),
		ExpiresAt: time.Now().Add(120 * time.Second),
	}
	m.neighbors[mkNeighborKey("eth1", "11:22:33:44:55:66", "port2")] = &Neighbor{
		ChassisID: "11:22:33:44:55:66",
		PortID:    "port2",
		TTL:       60,
		Interface: "eth1",
		LastSeen:  time.Now(),
		ExpiresAt: time.Now().Add(60 * time.Second),
	}
	m.mu.Unlock()

	neighbors := m.Neighbors()
	if len(neighbors) != 2 {
		t.Fatalf("expected 2 neighbors, got %d", len(neighbors))
	}
	// Should be sorted by key.
	if neighbors[0].Interface != "eth0" {
		t.Errorf("first neighbor should be eth0, got %s", neighbors[0].Interface)
	}
	if neighbors[1].Interface != "eth1" {
		t.Errorf("second neighbor should be eth1, got %s", neighbors[1].Interface)
	}
}

func TestNeighborExpiry(t *testing.T) {
	m := New()

	// Add an already-expired neighbor.
	m.mu.Lock()
	m.neighbors[mkNeighborKey("eth0", "aa:bb:cc:dd:ee:ff", "port1")] = &Neighbor{
		ChassisID: "aa:bb:cc:dd:ee:ff",
		PortID:    "port1",
		TTL:       1,
		Interface: "eth0",
		LastSeen:  time.Now().Add(-10 * time.Second),
		ExpiresAt: time.Now().Add(-5 * time.Second),
	}
	// Add a still-valid neighbor.
	m.neighbors[mkNeighborKey("eth1", "11:22:33:44:55:66", "port2")] = &Neighbor{
		ChassisID: "11:22:33:44:55:66",
		PortID:    "port2",
		TTL:       300,
		Interface: "eth1",
		LastSeen:  time.Now(),
		ExpiresAt: time.Now().Add(300 * time.Second),
	}
	m.mu.Unlock()

	// Manually run expiry check.
	now := time.Now()
	m.mu.Lock()
	for key, n := range m.neighbors {
		if now.After(n.ExpiresAt) {
			delete(m.neighbors, key)
		}
	}
	m.mu.Unlock()

	neighbors := m.Neighbors()
	if len(neighbors) != 1 {
		t.Fatalf("expected 1 neighbor after expiry, got %d", len(neighbors))
	}
	if neighbors[0].ChassisID != "11:22:33:44:55:66" {
		t.Errorf("wrong surviving neighbor: %s", neighbors[0].ChassisID)
	}
}

func TestRoundTripTLVs(t *testing.T) {
	// Build a frame and parse it back — full round-trip test.
	mac := net.HardwareAddr{0xde, 0xad, 0xbe, 0xef, 0x00, 0x01}
	frame, err := BuildFrame(mac, "ge-0/0/1", 300, "switch1", "Juniper EX4300")
	if err != nil {
		t.Fatal(err)
	}

	n := ParseTLVs(frame[ethHdrLen:])
	if n == nil {
		t.Fatal("ParseTLVs returned nil")
	}
	if n.ChassisID != mac.String() {
		t.Errorf("chassis: %s != %s", n.ChassisID, mac.String())
	}
	if n.PortID != "ge-0/0/1" {
		t.Errorf("port: %s != ge-0/0/1", n.PortID)
	}
	if n.TTL != 300 {
		t.Errorf("ttl: %d != 300", n.TTL)
	}
	if n.SystemName != "switch1" {
		t.Errorf("sysname: %s != switch1", n.SystemName)
	}
	if n.SystemDesc != "Juniper EX4300" {
		t.Errorf("sysdesc: %s != Juniper EX4300", n.SystemDesc)
	}
}

func TestStopIdempotent(t *testing.T) {
	m := New()
	m.Stop() // should not panic
	m.Stop() // double stop should be fine
}

// mkNeighbor builds a Neighbor for the cap tests.
func mkNeighbor(iface, chassis, port string) *Neighbor {
	return &Neighbor{
		ChassisID: chassis,
		PortID:    port,
		TTL:       120,
		Interface: iface,
		LastSeen:  time.Now(),
		ExpiresAt: time.Now().Add(120 * time.Second),
	}
}

// #7176 (C179-026): this helper used to re-implement the production key as
// fmt.Sprintf("%s/%s/%s", ...) — a copy of the very construction under test, so
// it would have stayed green through any change to it. It now builds the
// production type, which is what makes the collision unrepresentable.
func mkNeighborKey(iface, chassis, port string) neighborKey {
	return neighborKey{Iface: iface, ChassisID: chassis, PortID: port}
}

// TestLearnNeighborCapPerInterface verifies the per-interface bound, LRU
// replacement when full, in-place refresh, and independent interface budgets.
func TestLearnNeighborCapPerInterface(t *testing.T) {
	m := New()
	base := time.Unix(1_800_000_000, 0)

	// Fill eth0 exactly to the cap with increasing LastSeen values.
	for i := range maxNeighborsPerInterface {
		chassis := fmt.Sprintf("02:00:00:00:00:%02x", i)
		n := mkNeighbor("eth0", chassis, "p")
		n.LastSeen = base.Add(time.Duration(i) * time.Second)
		if !m.learnNeighbor(mkNeighborKey("eth0", chassis, "p"), n) {
			t.Fatalf("add %d within cap should be admitted", i)
		}
	}
	if got := len(m.Neighbors()); got != maxNeighborsPerInterface {
		t.Fatalf("after filling to cap: got %d neighbors, want %d", got, maxNeighborsPerInterface)
	}

	// A new neighbor replaces the oldest entry rather than being rejected or
	// growing beyond the cap.
	newChassis := "02:00:00:00:ff:ff"
	newNeighbor := mkNeighbor("eth0", newChassis, "p")
	newNeighbor.LastSeen = base.Add(maxNeighborsPerInterface * time.Second)
	if !m.learnNeighbor(mkNeighborKey("eth0", newChassis, "p"), newNeighbor) {
		t.Fatal("a new neighbor at the cap must be admitted")
	}
	if got := len(m.Neighbors()); got != maxNeighborsPerInterface {
		t.Fatalf("table grew past the cap: got %d, want %d", got, maxNeighborsPerInterface)
	}
	m.mu.RLock()
	_, oldestPresent := m.neighbors[mkNeighborKey("eth0", "02:00:00:00:00:00", "p")]
	_, newestPresent := m.neighbors[mkNeighborKey("eth0", "02:00:00:00:00:3f", "p")]
	m.mu.RUnlock()
	if oldestPresent {
		t.Fatal("new admission at the cap must evict the least-recently-seen neighbor")
	}
	if !newestPresent {
		t.Fatal("new admission must preserve the most-recently-seen neighbor")
	}

	// A refresh of an EXISTING key still updates in place without growing the
	// table. Bump the TTL so we can confirm the update landed.
	refreshChassis := "02:00:00:00:00:3f"
	refreshed := mkNeighbor("eth0", refreshChassis, "p")
	refreshed.TTL = 999
	refreshed.LastSeen = base.Add((maxNeighborsPerInterface + 1) * time.Second)
	if !m.learnNeighbor(mkNeighborKey("eth0", refreshChassis, "p"), refreshed) {
		t.Fatal("a refresh of an existing neighbor must be accepted at the cap")
	}
	if got := len(m.Neighbors()); got != maxNeighborsPerInterface {
		t.Fatalf("refresh must not grow the table: got %d, want %d", got, maxNeighborsPerInterface)
	}
	m.mu.RLock()
	gotTTL := m.neighbors[mkNeighborKey("eth0", refreshChassis, "p")].TTL
	m.mu.RUnlock()
	if gotTTL != 999 {
		t.Fatalf("refresh did not update in place: TTL got %d, want 999", gotTTL)
	}

	// The cap is per interface: a neighbor on eth1 has its own budget.
	if !m.learnNeighbor(mkNeighborKey("eth1", "02:00:00:00:01:00", "p"), mkNeighbor("eth1", "02:00:00:00:01:00", "p")) {
		t.Fatal("a neighbor on a different interface must be admitted (cap is per-interface)")
	}
	if got := len(m.Neighbors()); got != maxNeighborsPerInterface+1 {
		t.Fatalf("per-interface cap should allow eth1 entry: got %d, want %d", got, maxNeighborsPerInterface+1)
	}
}

// captureHandler is a slog.Handler that records emitted records for assertions.
type captureHandler struct {
	mu      sync.Mutex
	records []slog.Record
}

func (h *captureHandler) Enabled(context.Context, slog.Level) bool { return true }
func (h *captureHandler) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	h.records = append(h.records, r.Clone())
	h.mu.Unlock()
	return nil
}
func (h *captureHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *captureHandler) WithGroup(string) slog.Handler      { return h }

// TestLearnNeighborCapWarnsRateLimited asserts that full-table LRU evictions
// emit a warning rate-limited to once per interval per interface (#4044).
func TestLearnNeighborCapWarnsRateLimited(t *testing.T) {
	h := &captureHandler{}
	prev := slog.Default()
	slog.SetDefault(slog.New(h))
	t.Cleanup(func() { slog.SetDefault(prev) })

	m := New()
	// Fill to the cap (no evictions, no warns yet).
	for i := range maxNeighborsPerInterface {
		chassis := fmt.Sprintf("02:00:00:00:00:%02x", i)
		m.learnNeighbor(mkNeighborKey("eth0", chassis, "p"), mkNeighbor("eth0", chassis, "p"))
	}
	// Admit 10 distinct replacements. Eviction warnings must be rate-limited.
	for i := range 10 {
		chassis := fmt.Sprintf("02:00:00:00:aa:%02x", i)
		if !m.learnNeighbor(mkNeighborKey("eth0", chassis, "p"), mkNeighbor("eth0", chassis, "p")) {
			t.Fatalf("full-table replacement %d should be admitted", i)
		}
	}

	h.mu.Lock()
	defer h.mu.Unlock()
	warns := 0
	var lastIface string
	for _, r := range h.records {
		if r.Level == slog.LevelWarn && strings.Contains(r.Message, "neighbor table full") {
			warns++
			r.Attrs(func(a slog.Attr) bool {
				if a.Key == "interface" {
					lastIface = a.Value.String()
				}
				return true
			})
		}
	}
	if warns != 1 {
		t.Fatalf("expected exactly 1 rate-limited cap warn for 10 drops, got %d", warns)
	}
	if lastIface != "eth0" {
		t.Fatalf("cap warn carried interface %q, want eth0", lastIface)
	}
}
