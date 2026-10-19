package snmp

import (
	"crypto/md5"
	"crypto/sha1"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

var (
	md5New   = md5.New
	md5Size  = md5.Size
	sha1New  = sha1.New
	sha1Size = sha1.Size
)

// --- BER encoding tests ---

func TestBerEncodeLength_Short(t *testing.T) {
	got := berEncodeLength(5)
	if len(got) != 1 || got[0] != 5 {
		t.Errorf("berEncodeLength(5) = %v, want [5]", got)
	}
}

func TestBerEncodeLength_OneByte(t *testing.T) {
	got := berEncodeLength(127)
	if len(got) != 1 || got[0] != 127 {
		t.Errorf("berEncodeLength(127) = %v, want [127]", got)
	}
}

func TestBerEncodeLength_TwoBytes(t *testing.T) {
	got := berEncodeLength(200)
	// 0x81, 0xC8 (200)
	if len(got) != 2 || got[0] != 0x81 || got[1] != 200 {
		t.Errorf("berEncodeLength(200) = %v, want [0x81, 200]", got)
	}
}

func TestBerEncodeIntegerValue(t *testing.T) {
	tests := []struct {
		val  int
		want []byte
	}{
		{0, []byte{0}},
		{1, []byte{1}},
		{127, []byte{127}},
		{128, []byte{0, 128}}, // high bit set needs leading zero
		{256, []byte{1, 0}},
	}
	for _, tt := range tests {
		got := berEncodeIntegerValue(tt.val)
		if !bytesEqual(got, tt.want) {
			t.Errorf("berEncodeIntegerValue(%d) = %v, want %v", tt.val, got, tt.want)
		}
	}
}

func TestBerEncodeOID(t *testing.T) {
	// 1.3.6.1.2.1.1.1.0 => first byte = 1*40+3 = 43, then 6,1,2,1,1,1,0
	got := berEncodeOID([]int{1, 3, 6, 1, 2, 1, 1, 1, 0})
	want := []byte{43, 6, 1, 2, 1, 1, 1, 0}
	if !bytesEqual(got, want) {
		t.Errorf("berEncodeOID(sysDescr) = %v, want %v", got, want)
	}
}

func TestBerEncodeOID_Short(t *testing.T) {
	got := berEncodeOID([]int{1})
	if got != nil {
		t.Errorf("berEncodeOID with < 2 components should return nil, got %v", got)
	}
}

func TestBerEncodeSubID(t *testing.T) {
	// #9133: the parameter is uint32 (RFC 2578 §7.1.3's sub-identifier type), so
	// the out-of-range case is unrepresentable at the call rather than checked
	// inside. The negative case that used to reach here is now bound by
	// TestEncoderRefusesAnOutOfRangeComponent9133 at berEncodeOID.
	tests := []struct {
		val  uint32
		want []byte
	}{
		{0, []byte{0}},
		{127, []byte{127}},
		{128, []byte{0x81, 0x00}},
		{16383, []byte{0xff, 0x7f}},
	}
	for _, tt := range tests {
		got := berEncodeSubID(tt.val)
		if !bytesEqual(got, tt.want) {
			t.Errorf("berEncodeSubID(%d) = %v, want %v", tt.val, got, tt.want)
		}
	}
}

func TestBerEncodeTimeTicks(t *testing.T) {
	got := berEncodeTimeTicks(100)
	// 100 = 0x00000064, strip leading zeros → 0x64
	if len(got) != 1 || got[0] != 0x64 {
		t.Errorf("berEncodeTimeTicks(100) = %v, want [0x64]", got)
	}
}

func TestBerEncodeTimeTicks_Large(t *testing.T) {
	got := berEncodeTimeTicks(360000) // 1 hour in hundredths
	// 360000 = 0x00057E40
	if len(got) != 3 { // should be [0x05, 0x7E, 0x40]
		t.Errorf("berEncodeTimeTicks(360000) = %v, expected 3 bytes", got)
	}
}

// --- BER decoding tests ---

func TestBerDecodeLength_Short(t *testing.T) {
	length, consumed, err := berDecodeLength([]byte{42})
	if err != nil || length != 42 || consumed != 1 {
		t.Errorf("got length=%d, consumed=%d, err=%v", length, consumed, err)
	}
}

func TestBerDecodeLength_Long(t *testing.T) {
	// 0x81 0xC8 = 200 bytes
	length, consumed, err := berDecodeLength([]byte{0x81, 0xC8})
	if err != nil || length != 200 || consumed != 2 {
		t.Errorf("got length=%d, consumed=%d, err=%v", length, consumed, err)
	}
}

func TestBerDecodeInteger(t *testing.T) {
	// Integer 42: tag=0x02, length=0x01, value=0x2A
	data := []byte{0x02, 0x01, 0x2A, 0xFF} // trailing byte
	val, rest, err := berDecodeInteger(data)
	if err != nil || val != 42 {
		t.Errorf("berDecodeInteger: val=%d, err=%v", val, err)
	}
	if len(rest) != 1 || rest[0] != 0xFF {
		t.Errorf("remaining bytes wrong: %v", rest)
	}
}

func TestBerDecodeInteger_Zero(t *testing.T) {
	data := []byte{0x02, 0x01, 0x00}
	val, _, err := berDecodeInteger(data)
	if err != nil || val != 0 {
		t.Errorf("berDecodeInteger(0): val=%d, err=%v", val, err)
	}
}

func TestBerDecodeOctetString(t *testing.T) {
	data := []byte{0x04, 0x05, 'h', 'e', 'l', 'l', 'o', 0xFF}
	val, rest, err := berDecodeOctetString(data)
	if err != nil || string(val) != "hello" {
		t.Errorf("berDecodeOctetString: val=%q, err=%v", val, err)
	}
	if len(rest) != 1 || rest[0] != 0xFF {
		t.Errorf("remaining bytes wrong: %v", rest)
	}
}

func TestBerDecodeOID(t *testing.T) {
	// 1.3.6.1.2.1.1.1.0 => [43, 6, 1, 2, 1, 1, 1, 0]
	raw := []byte{43, 6, 1, 2, 1, 1, 1, 0}
	oid, err := berDecodeOID(raw)
	if err != nil {
		t.Fatal(err)
	}
	want := []int{1, 3, 6, 1, 2, 1, 1, 1, 0}
	if !intsEqual(oid, want) {
		t.Errorf("berDecodeOID = %v, want %v", oid, want)
	}
}

func TestBerDecodeOID_Empty(t *testing.T) {
	_, err := berDecodeOID(nil)
	if err == nil {
		t.Error("expected error for empty OID")
	}
}

// --- OID comparison tests ---

func TestOIDEqual(t *testing.T) {
	if !oidEqual([]int{1, 3, 6}, []int{1, 3, 6}) {
		t.Error("same OIDs should be equal")
	}
	if oidEqual([]int{1, 3, 6}, []int{1, 3, 7}) {
		t.Error("different OIDs should not be equal")
	}
	if oidEqual([]int{1, 3}, []int{1, 3, 6}) {
		t.Error("different length OIDs should not be equal")
	}
}

func TestOIDCompare(t *testing.T) {
	tests := []struct {
		a, b []int
		want int
	}{
		{[]int{1, 3, 6}, []int{1, 3, 6}, 0},
		{[]int{1, 3, 5}, []int{1, 3, 6}, -1},
		{[]int{1, 3, 7}, []int{1, 3, 6}, 1},
		{[]int{1, 3}, []int{1, 3, 6}, -1},
		{[]int{1, 3, 6, 1}, []int{1, 3, 6}, 1},
	}
	for _, tt := range tests {
		if got := oidCompare(tt.a, tt.b); got != tt.want {
			t.Errorf("oidCompare(%v, %v) = %d, want %d", tt.a, tt.b, got, tt.want)
		}
	}
}

// --- Agent functional tests ---

func TestFindNextOID(t *testing.T) {
	a := NewAgent(&config.SNMPConfig{})

	// Asking for next after sysDescr should return sysObjectID
	next := a.findNextOID(oidSysDescr)
	if !oidEqual(next, oidSysObjectID) {
		t.Errorf("next after sysDescr should be sysObjectID, got %v", next)
	}

	// Asking for next after sysLocation should return ifNumber
	next = a.findNextOID(oidSysLocation)
	if !oidEqual(next, oidIfNumber) {
		t.Errorf("next after sysLocation should be ifNumber, got %v", next)
	}

	// With no ifDataFn, next after ifNumber should be nil (no ifTable entries)
	next = a.findNextOID(oidIfNumber)
	if next != nil {
		t.Errorf("next after ifNumber with no interfaces should be nil, got %v", next)
	}

	// Asking for next with a prefix before all OIDs should return sysDescr
	next = a.findNextOID([]int{1, 3, 6, 1, 2, 1, 0})
	if !oidEqual(next, oidSysDescr) {
		t.Errorf("next before tree should be sysDescr, got %v", next)
	}
}

func TestIsValidCommunity(t *testing.T) {
	a := NewAgent(&config.SNMPConfig{
		Communities: map[string]*config.SNMPCommunity{
			"public": {Name: "public", Authorization: "read-only"},
		},
	})

	if !a.isValidCommunity("public") {
		t.Error("public should be valid")
	}
	if a.isValidCommunity("private") {
		t.Error("private should be invalid")
	}
}

func TestIsValidCommunity_NilConfig(t *testing.T) {
	a := NewAgent(nil)
	if a.isValidCommunity("public") {
		t.Error("nil config should reject all communities")
	}
}

func TestGetOIDValue_SysDescr(t *testing.T) {
	a := NewAgent(&config.SNMPConfig{Description: "my firewall"})
	val, tag := a.getOIDValue(oidSysDescr)
	if tag != tagOctetString || string(val) != "my firewall" {
		t.Errorf("sysDescr: tag=%d val=%q", tag, val)
	}
}

func TestGetOIDValue_SysDescr_Default(t *testing.T) {
	a := NewAgent(&config.SNMPConfig{})
	val, tag := a.getOIDValue(oidSysDescr)
	if tag != tagOctetString || string(val) != "xpf stateful firewall" {
		t.Errorf("sysDescr default: tag=%d val=%q", tag, val)
	}
}

func TestGetOIDValue_SysContact(t *testing.T) {
	a := NewAgent(&config.SNMPConfig{Contact: "admin@example.com"})
	val, tag := a.getOIDValue(oidSysContact)
	if tag != tagOctetString || string(val) != "admin@example.com" {
		t.Errorf("sysContact: tag=%d val=%q", tag, val)
	}
}

func TestGetOIDValue_SysLocation(t *testing.T) {
	a := NewAgent(&config.SNMPConfig{Location: "datacenter-1"})
	val, tag := a.getOIDValue(oidSysLocation)
	if tag != tagOctetString || string(val) != "datacenter-1" {
		t.Errorf("sysLocation: tag=%d val=%q", tag, val)
	}
}

func TestGetOIDValue_SysUpTime(t *testing.T) {
	a := NewAgent(&config.SNMPConfig{})
	val, tag := a.getOIDValue(oidSysUpTime)
	if tag != tagTimeTicks || val == nil {
		t.Error("sysUpTime should return TimeTicks")
	}
}

func TestGetOIDValue_Unknown(t *testing.T) {
	a := NewAgent(&config.SNMPConfig{})
	val, _ := a.getOIDValue([]int{1, 3, 6, 1, 2, 1, 99, 0})
	if val != nil {
		t.Error("unknown OID should return nil")
	}
}

func TestGetOIDValue_IfNumber(t *testing.T) {
	a := NewAgent(&config.SNMPConfig{})
	a.SetIfDataFn(func() []IfData {
		return []IfData{
			{IfIndex: 2, IfDescr: "trust0"},
			{IfIndex: 3, IfDescr: "untrust0"},
		}
	})
	val, tag := a.getOIDValue(oidIfNumber)
	if tag != tagInteger {
		t.Errorf("ifNumber tag = %d, want INTEGER", tag)
	}
	// Decode the integer value
	encoded := berEncodeIntegerTLV(2)
	decoded, _, _ := berDecodeInteger(encoded)
	if decoded != 2 {
		t.Errorf("ifNumber value decode check failed: got %d", decoded)
	}
	_ = val
}

func TestIfTableWalk(t *testing.T) {
	a := NewAgent(&config.SNMPConfig{})
	a.SetIfDataFn(func() []IfData {
		return []IfData{
			{IfIndex: 2, IfDescr: "trust0", IfType: 6, IfMtu: 1500, AdminStatus: 1, OperStatus: 1},
			{IfIndex: 3, IfDescr: "untrust0", IfType: 6, IfMtu: 1500, AdminStatus: 1, OperStatus: 2},
		}
	})

	// Walking from ifNumber should reach ifTable column 1, ifIndex 2
	next := a.findNextOID(oidIfNumber)
	// Should be 1.3.6.1.2.1.2.2.1.1.2 (ifIndex.2)
	wantPrefix := append([]int{}, oidIfTablePrefix...)
	wantFirst := append(wantPrefix, 1, 2)
	if !oidEqual(next, wantFirst) {
		t.Errorf("first ifTable entry should be ifIndex.2, got %v", next)
	}

	// Get value of ifDescr.2
	ifDescrOID := append(append([]int{}, oidIfTablePrefix...), 2, 2)
	val, tag := a.getOIDValue(ifDescrOID)
	if tag != tagOctetString || string(val) != "trust0" {
		t.Errorf("ifDescr.2 = %q (tag %d), want 'trust0'", val, tag)
	}

	// Get value of ifOperStatus.3 (untrust0 is down)
	ifOperOID := append(append([]int{}, oidIfTablePrefix...), 8, 3)
	val, tag = a.getOIDValue(ifOperOID)
	if tag != tagInteger {
		t.Errorf("ifOperStatus.3 tag = %d, want INTEGER", tag)
	}
	// Value 2 = down
	decoded, _, _ := berDecodeInteger(berEncodeTLV(tagInteger, val))
	if decoded != 2 {
		t.Errorf("ifOperStatus.3 = %d, want 2 (down)", decoded)
	}
}

func TestIfXTableWalk(t *testing.T) {
	a := NewAgent(&config.SNMPConfig{})
	a.SetIfDataFn(func() []IfData {
		return []IfData{
			{
				IfIndex: 2, IfDescr: "trust0", IfName: "trust0",
				IfType: 6, IfMtu: 1500, AdminStatus: 1, OperStatus: 1,
				HCInOctets: 1234567890123, HCOutOctets: 9876543210987,
				HCInUcastPkts: 5000000, HCOutUcastPkts: 4000000,
				InMulticastPkts: 100, InBroadcastPkts: 50,
				OutMulticastPkts: 200, OutBroadcastPkts: 25,
				IfHighSpeed: 10000, IfAlias: "Trust LAN",
			},
		}
	})

	// Walking from last ifTable entry should reach ifXTable
	// Last ifTable OID: 1.3.6.1.2.1.2.2.1.20.2 (#15232)
	lastIfTable := append(append([]int{}, oidIfTablePrefix...), 20, 2)
	next := a.findNextOID(lastIfTable)
	// Should be ifXTable.1.2 (ifName.2)
	wantFirst := append(append([]int{}, oidIfXTablePrefix...), 1, 2)
	if !oidEqual(next, wantFirst) {
		t.Errorf("first ifXTable entry should be ifName.2, got %v", next)
	}

	// Get ifName.2
	val, tag := a.getOIDValue(wantFirst)
	if tag != tagOctetString || string(val) != "trust0" {
		t.Errorf("ifName.2 = %q (tag %d), want 'trust0'", val, tag)
	}

	// Get ifHCInOctets.2 (column 6)
	hcInOID := append(append([]int{}, oidIfXTablePrefix...), 6, 2)
	val, tag = a.getOIDValue(hcInOID)
	if tag != tagCounter64 {
		t.Errorf("ifHCInOctets tag = 0x%02x, want 0x%02x", tag, tagCounter64)
	}

	// Get ifHighSpeed.2 (column 15)
	hsOID := append(append([]int{}, oidIfXTablePrefix...), 15, 2)
	val, tag = a.getOIDValue(hsOID)
	if tag != tagGauge32 {
		t.Errorf("ifHighSpeed tag = 0x%02x, want 0x%02x", tag, tagGauge32)
	}

	// Get ifAlias.2 (column 18)
	aliasOID := append(append([]int{}, oidIfXTablePrefix...), 18, 2)
	val, tag = a.getOIDValue(aliasOID)
	if tag != tagOctetString || string(val) != "Trust LAN" {
		t.Errorf("ifAlias.2 = %q (tag %d), want 'Trust LAN'", val, tag)
	}

	// findNextOID after last ifXTable entry should return nil
	lastIfXTable := append(append([]int{}, oidIfXTablePrefix...), 18, 2)
	next = a.findNextOID(lastIfXTable)
	if next != nil {
		t.Errorf("next after last ifXTable should be nil, got %v", next)
	}
}

func TestCounter64Encoding(t *testing.T) {
	// 0 should encode to [0]
	got := berEncodeCounter64(0)
	if len(got) != 1 || got[0] != 0 {
		t.Errorf("Counter64(0) = %v, want [0]", got)
	}
	// 255 should need leading zero
	got = berEncodeCounter64(255)
	if len(got) != 2 || got[0] != 0 || got[1] != 255 {
		t.Errorf("Counter64(255) = %v, want [0, 255]", got)
	}
	// Large 64-bit value
	got = berEncodeCounter64(1234567890123)
	if len(got) == 0 {
		t.Error("Counter64(large) returned empty")
	}
	// Max uint64 should encode properly (9 bytes with leading zero)
	got = berEncodeCounter64(^uint64(0))
	if len(got) != 9 || got[0] != 0 {
		t.Errorf("Counter64(max) = %d bytes, first=%d; want 9 bytes with leading 0", len(got), got[0])
	}
}

func TestCounter32Encoding(t *testing.T) {
	// 0 should encode to [0]
	got := berEncodeCounter32(0)
	if len(got) != 1 || got[0] != 0 {
		t.Errorf("Counter32(0) = %v, want [0]", got)
	}
	// 255 should encode to [0, 255] (high bit set, needs leading zero)
	got = berEncodeCounter32(255)
	if len(got) != 2 || got[0] != 0 || got[1] != 255 {
		t.Errorf("Counter32(255) = %v, want [0, 255]", got)
	}
	// 100 should encode to [100]
	got = berEncodeCounter32(100)
	if len(got) != 1 || got[0] != 100 {
		t.Errorf("Counter32(100) = %v, want [100]", got)
	}
}

func TestBerEncodedLen(t *testing.T) {
	// A simple SEQUENCE: tag=0x30, length=0x03, value=3 bytes
	data := []byte{0x30, 0x03, 0x01, 0x02, 0x03, 0xFF} // trailing byte
	got := berEncodedLen(data)
	if got != 5 { // 1 (tag) + 1 (length) + 3 (value) = 5
		t.Errorf("berEncodedLen = %d, want 5", got)
	}
}

func TestBerDecodeHeader(t *testing.T) {
	// SEQUENCE of 3 bytes
	data := []byte{0x30, 0x03, 0xAA, 0xBB, 0xCC}
	tag, body, err := berDecodeHeader(data)
	if err != nil || tag != 0x30 || len(body) != 3 {
		t.Errorf("tag=%d, body=%v, err=%v", tag, body, err)
	}
}

// --- Roundtrip test: encode + decode ---

func TestBerOIDRoundtrip(t *testing.T) {
	original := []int{1, 3, 6, 1, 4, 1, 99999, 1}
	encoded := berEncodeOID(original)
	decoded, err := berDecodeOID(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if !intsEqual(original, decoded) {
		t.Errorf("roundtrip failed: %v -> %v", original, decoded)
	}
}

func TestBerIntegerRoundtrip(t *testing.T) {
	for _, val := range []int{0, 1, 127, 128, 255, 256, 65535, 100000} {
		encoded := berEncodeIntegerTLV(val)
		decoded, _, err := berDecodeInteger(encoded)
		if err != nil {
			t.Errorf("decode error for %d: %v", val, err)
			continue
		}
		if decoded != val {
			t.Errorf("roundtrip: %d -> %d", val, decoded)
		}
	}
}

// --- helpers ---

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func intsEqual(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// --- SNMPv3 USM tests ---

func TestPasswordToKey_MD5(t *testing.T) {
	engineID := []byte{0x80, 0x00, 0x01, 0x86, 0xa3, 0x04, 't', 'e', 's', 't'}
	key := passwordToKey("maplesyrup", engineID, md5New, md5Size)
	if key == nil {
		t.Fatal("passwordToKey returned nil")
	}
	if len(key) != md5Size {
		t.Errorf("key length = %d, want %d", len(key), md5Size)
	}
}

func TestPasswordToKey_SHA(t *testing.T) {
	engineID := []byte{0x80, 0x00, 0x01, 0x86, 0xa3, 0x04, 't', 'e', 's', 't'}
	key := passwordToKey("testpassword", engineID, sha1New, sha1Size)
	if key == nil {
		t.Fatal("passwordToKey returned nil")
	}
	if len(key) != sha1Size {
		t.Errorf("key length = %d, want %d", len(key), sha1Size)
	}
}

func TestPasswordToKey_EmptyPassword(t *testing.T) {
	engineID := []byte{0x80, 0x00, 0x01, 0x86, 0xa3}
	key := passwordToKey("", engineID, md5New, md5Size)
	if key != nil {
		t.Error("empty password should return nil")
	}
}

func TestInitV3Users(t *testing.T) {
	a := NewAgent(&config.SNMPConfig{
		V3Users: map[string]*config.SNMPv3User{
			"admin": {
				Name:         "admin",
				AuthProtocol: "sha",
				AuthPassword: "authpass123",
				PrivProtocol: "aes128",
				PrivPassword: "privpass456",
			},
		},
	})
	if len(a.v3Users) != 1 {
		t.Fatalf("v3Users count = %d, want 1", len(a.v3Users))
	}
	u := a.v3Users["admin"]
	if u == nil {
		t.Fatal("admin user not found")
	}
	if u.authProto != "sha" {
		t.Errorf("authProto = %q, want sha", u.authProto)
	}
	if u.authKey == nil {
		t.Error("authKey is nil")
	}
	if u.privProto != "aes128" {
		t.Errorf("privProto = %q, want aes128", u.privProto)
	}
	if u.privKey == nil {
		t.Error("privKey is nil")
	}
}

func TestInitV3Users_NilConfig(t *testing.T) {
	a := NewAgent(nil)
	if a.v3Users != nil {
		t.Error("nil config should leave v3Users nil")
	}
}

func TestV3Discovery(t *testing.T) {
	a := NewAgent(&config.SNMPConfig{
		V3Users: map[string]*config.SNMPv3User{
			"test": {Name: "test", AuthProtocol: "sha", AuthPassword: "testpass"},
		},
	})
	resp := a.buildV3Discovery(42)
	if resp == nil {
		t.Fatal("discovery response is nil")
	}
	// Should be a valid BER SEQUENCE.
	tag, _, err := berDecodeHeader(resp)
	if err != nil || tag != tagSequence {
		t.Errorf("discovery response: tag=%d, err=%v", tag, err)
	}
}

func TestV3UserDisplay(t *testing.T) {
	users := map[string]*config.SNMPv3User{
		"admin": {Name: "admin", AuthProtocol: "sha256", PrivProtocol: "aes128"},
		"guest": {Name: "guest", AuthProtocol: "md5"},
	}
	info := V3UserInfo(users)
	if len(info) != 2 {
		t.Fatalf("V3UserInfo count = %d, want 2", len(info))
	}
}

func TestEngineIDGeneration(t *testing.T) {
	// #5283: the EngineID is now always the 32-octet hashed form
	// prefix(5) || 0x05 || sha256(deviceID || 0x00 || hostname)[:26]. Use a
	// tempdir persistence path so the test does not touch /var/lib/xpf.
	a := newAgentWithEngineIDPath(t, &config.SNMPConfig{}, filepath.Join(t.TempDir(), "dev"))
	if a.engineID == nil {
		t.Fatal("engineID is nil")
	}
	if len(a.engineID) != snmpEngineIDMaxLen {
		t.Errorf("engineID length = %d, want %d", len(a.engineID), snmpEngineIDMaxLen)
	}
	// First 5 bytes are the fixed enterprise prefix; the 6th byte is the octets
	// format selector 0x05 (the binary SHA-256 payload).
	if a.engineID[5] != engineIDFormatOctets {
		t.Errorf("engineID format byte = %d, want %d (octets)", a.engineID[5], engineIDFormatOctets)
	}
}

func TestDESEncryptDecrypt(t *testing.T) {
	// Need a 16-byte key (8 for DES + 8 for preIV).
	key := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	plaintext := []byte("hello world test") // 16 bytes (multiple of 8)
	salt := testPrivSalt()
	enc, err := encryptDES(key, plaintext, salt)
	if err != nil || enc == nil {
		t.Fatalf("encryptDES failed: %v", err)
	}
	dec := decryptDES(key, salt, enc)
	if dec == nil {
		t.Fatal("decryptDES returned nil")
	}
	if !bytesEqual(dec, plaintext) {
		t.Errorf("DES roundtrip failed: got %v, want %v", dec, plaintext)
	}
}

func TestAES128EncryptDecrypt(t *testing.T) {
	key := make([]byte, 16)
	for i := range key {
		key[i] = byte(i + 1)
	}
	plaintext := []byte("test data for aes encryption roundtrip")
	salt := testPrivSalt()
	enc, err := encryptAES128(key, plaintext, salt, 1, 100)
	if err != nil || enc == nil {
		t.Fatalf("encryptAES128 failed: %v", err)
	}
	dec := decryptAES128(key, salt, enc, 1, 100)
	if dec == nil {
		t.Fatal("decryptAES128 returned nil")
	}
	if !bytesEqual(dec, plaintext) {
		t.Errorf("AES128 roundtrip failed: got %v, want %v", dec, plaintext)
	}
}

// --- ifXTable tests ---

// testIfXData returns test interface data with ifXTable fields populated.
func testIfXData() []IfData {
	return []IfData{
		{
			IfIndex: 2, IfDescr: "trust0", IfType: 6, IfMtu: 1500,
			IfSpeed: 1000000000, AdminStatus: 1, OperStatus: 1,
			InOctets: 123456, OutOctets: 789012,
			IfName: "trust0", IfAlias: "Trust LAN",
			HCInOctets: 5000000000, HCOutOctets: 3000000000,
			HCInUcastPkts: 1000000, HCOutUcastPkts: 800000,
			IfHighSpeed:     1000,
			InMulticastPkts: 500, InBroadcastPkts: 100,
			OutMulticastPkts: 200, OutBroadcastPkts: 50,
		},
		{
			IfIndex: 3, IfDescr: "untrust0", IfType: 6, IfMtu: 1500,
			IfSpeed: 4294967295, AdminStatus: 1, OperStatus: 1,
			InOctets: 0, OutOctets: 0,
			IfName: "untrust0", IfAlias: "WAN uplink",
			HCInOctets: 12345678901234, HCOutOctets: 98765432109876,
			HCInUcastPkts: 9876543210, HCOutUcastPkts: 1234567890,
			IfHighSpeed: 10000,
		},
	}
}

func TestIfXTable_ifName(t *testing.T) {
	a := NewAgent(&config.SNMPConfig{})
	a.SetIfDataFn(testIfXData)

	// ifName.2 = 1.3.6.1.2.1.31.1.1.1.1.2
	oid := append(append([]int{}, oidIfXTablePrefix...), 1, 2)
	val, tag := a.getOIDValue(oid)
	if tag != tagOctetString {
		t.Fatalf("ifName tag = 0x%02x, want OctetString (0x%02x)", tag, tagOctetString)
	}
	if string(val) != "trust0" {
		t.Errorf("ifName.2 = %q, want 'trust0'", string(val))
	}

	// ifName.3
	oid = append(append([]int{}, oidIfXTablePrefix...), 1, 3)
	val, tag = a.getOIDValue(oid)
	if tag != tagOctetString || string(val) != "untrust0" {
		t.Errorf("ifName.3 = %q (tag 0x%02x), want 'untrust0'", string(val), tag)
	}
}

func TestIfXTable_ifNameFallback(t *testing.T) {
	a := NewAgent(&config.SNMPConfig{})
	a.SetIfDataFn(func() []IfData {
		return []IfData{
			{IfIndex: 5, IfDescr: "loopback0"}, // IfName empty, should fall back to IfDescr
		}
	})

	oid := append(append([]int{}, oidIfXTablePrefix...), 1, 5)
	val, tag := a.getOIDValue(oid)
	if tag != tagOctetString || string(val) != "loopback0" {
		t.Errorf("ifName fallback = %q, want 'loopback0'", string(val))
	}
}

func TestIfXTable_ifHCInOctets(t *testing.T) {
	a := NewAgent(&config.SNMPConfig{})
	a.SetIfDataFn(testIfXData)

	// ifHCInOctets.2 = 1.3.6.1.2.1.31.1.1.1.6.2
	oid := append(append([]int{}, oidIfXTablePrefix...), 6, 2)
	val, tag := a.getOIDValue(oid)
	if tag != tagCounter64 {
		t.Fatalf("ifHCInOctets tag = 0x%02x, want Counter64 (0x%02x)", tag, tagCounter64)
	}
	// Decode: berEncodeCounter64(5000000000) should encode correctly
	decoded := decodeCounter64(val)
	if decoded != 5000000000 {
		t.Errorf("ifHCInOctets.2 = %d, want 5000000000", decoded)
	}
}

func TestIfXTable_ifHCOutOctets(t *testing.T) {
	a := NewAgent(&config.SNMPConfig{})
	a.SetIfDataFn(testIfXData)

	// ifHCOutOctets.3 = large value (98765432109876)
	oid := append(append([]int{}, oidIfXTablePrefix...), 10, 3)
	val, tag := a.getOIDValue(oid)
	if tag != tagCounter64 {
		t.Fatalf("ifHCOutOctets tag = 0x%02x, want Counter64", tag)
	}
	decoded := decodeCounter64(val)
	if decoded != 98765432109876 {
		t.Errorf("ifHCOutOctets.3 = %d, want 98765432109876", decoded)
	}
}

func TestIfXTable_ifHighSpeed(t *testing.T) {
	a := NewAgent(&config.SNMPConfig{})
	a.SetIfDataFn(testIfXData)

	// ifHighSpeed.2 = 1000 Mbps
	oid := append(append([]int{}, oidIfXTablePrefix...), 15, 2)
	val, tag := a.getOIDValue(oid)
	if tag != tagGauge32 {
		t.Fatalf("ifHighSpeed tag = 0x%02x, want Gauge32 (0x%02x)", tag, tagGauge32)
	}
	// Decode Gauge32 (same encoding as Counter32)
	decoded32 := decodeUint32(val)
	if decoded32 != 1000 {
		t.Errorf("ifHighSpeed.2 = %d, want 1000", decoded32)
	}

	// ifHighSpeed.3 = 10000 Mbps (10G)
	oid = append(append([]int{}, oidIfXTablePrefix...), 15, 3)
	val, _ = a.getOIDValue(oid)
	decoded32 = decodeUint32(val)
	if decoded32 != 10000 {
		t.Errorf("ifHighSpeed.3 = %d, want 10000", decoded32)
	}
}

func TestIfXTable_ifAlias(t *testing.T) {
	a := NewAgent(&config.SNMPConfig{})
	a.SetIfDataFn(testIfXData)

	// ifAlias.2
	oid := append(append([]int{}, oidIfXTablePrefix...), 18, 2)
	val, tag := a.getOIDValue(oid)
	if tag != tagOctetString {
		t.Fatalf("ifAlias tag = 0x%02x, want OctetString", tag)
	}
	if string(val) != "Trust LAN" {
		t.Errorf("ifAlias.2 = %q, want 'Trust LAN'", string(val))
	}

	// ifAlias.3
	oid = append(append([]int{}, oidIfXTablePrefix...), 18, 3)
	val, tag = a.getOIDValue(oid)
	if tag != tagOctetString || string(val) != "WAN uplink" {
		t.Errorf("ifAlias.3 = %q, want 'WAN uplink'", string(val))
	}
}

func TestIfXTable_UnknownIfIndex(t *testing.T) {
	a := NewAgent(&config.SNMPConfig{})
	a.SetIfDataFn(testIfXData)

	// ifName.99 (nonexistent interface)
	oid := append(append([]int{}, oidIfXTablePrefix...), 1, 99)
	val, _ := a.getOIDValue(oid)
	if val != nil {
		t.Error("expected nil for unknown ifIndex")
	}
}

func TestIfXTable_GETNEXTWalk(t *testing.T) {
	a := NewAgent(&config.SNMPConfig{})
	a.SetIfDataFn(testIfXData)

	// GETNEXT from last ifTable entry should reach ifXTable
	// Last ifTable entry is ifOutDiscards (col 20) for ifIndex 3 (#15232)
	lastIfTable := append(append([]int{}, oidIfTablePrefix...), 20, 3)
	next := a.findNextOID(lastIfTable)
	if next == nil {
		t.Fatal("expected ifXTable entry after last ifTable, got nil")
	}
	// Should be ifXTable.1.2 (ifName for first interface)
	wantFirst := append(append([]int{}, oidIfXTablePrefix...), 1, 2)
	if !oidEqual(next, wantFirst) {
		t.Errorf("first ifXTable entry = %v, want %v", next, wantFirst)
	}
}

func TestIfXTable_GETNEXTWalkColumns(t *testing.T) {
	a := NewAgent(&config.SNMPConfig{})
	a.SetIfDataFn(testIfXData)

	// Walk from ifName.3 → should go to ifInMulticastPkts.2 (col 2, first iface)
	ifName3 := append(append([]int{}, oidIfXTablePrefix...), 1, 3)
	next := a.findNextOID(ifName3)
	wantNext := append(append([]int{}, oidIfXTablePrefix...), 2, 2)
	if !oidEqual(next, wantNext) {
		t.Errorf("next after ifName.3 = %v, want %v (ifInMulticastPkts.2)", next, wantNext)
	}
}

func TestCounter64Roundtrip(t *testing.T) {
	tests := []struct {
		val  uint64
		name string
	}{
		{0, "zero"},
		{1, "one"},
		{127, "127"},
		{128, "128"},
		{255, "255"},
		{256, "256"},
		{65535, "65535"},
		{4294967295, "max32"},
		{4294967296, "max32+1"},
		{5000000000, "5G"},
		{12345678901234, "large"},
		{18446744073709551615, "max64"},
	}
	for _, tt := range tests {
		encoded := berEncodeCounter64(tt.val)
		if encoded == nil {
			t.Errorf("Counter64(%s) = nil", tt.name)
			continue
		}
		decoded := decodeCounter64(encoded)
		if decoded != tt.val {
			t.Errorf("Counter64 roundtrip %s: %d -> encoded %v -> %d",
				tt.name, tt.val, encoded, decoded)
		}
	}
}

func TestCounter64Encoding_HighBitPrefix(t *testing.T) {
	// Values with high bit set should get a leading zero byte
	encoded := berEncodeCounter64(128)
	if encoded[0] != 0 {
		t.Errorf("Counter64(128) should have leading zero, got %v", encoded)
	}
	encoded = berEncodeCounter64(255)
	if encoded[0] != 0 {
		t.Errorf("Counter64(255) should have leading zero, got %v", encoded)
	}
}

func TestIfXTable_MulticastBroadcastCounters(t *testing.T) {
	a := NewAgent(&config.SNMPConfig{})
	a.SetIfDataFn(testIfXData)

	// ifInMulticastPkts.2 (col 2)
	oid := append(append([]int{}, oidIfXTablePrefix...), 2, 2)
	val, tag := a.getOIDValue(oid)
	if tag != tagCounter32 {
		t.Fatalf("ifInMulticastPkts tag = 0x%02x, want Counter32", tag)
	}
	decoded := decodeUint32(val)
	if decoded != 500 {
		t.Errorf("ifInMulticastPkts.2 = %d, want 500", decoded)
	}

	// ifOutBroadcastPkts.2 (col 5)
	oid = append(append([]int{}, oidIfXTablePrefix...), 5, 2)
	val, tag = a.getOIDValue(oid)
	if tag != tagCounter32 {
		t.Fatalf("ifOutBroadcastPkts tag = 0x%02x, want Counter32", tag)
	}
	decoded = decodeUint32(val)
	if decoded != 50 {
		t.Errorf("ifOutBroadcastPkts.2 = %d, want 50", decoded)
	}
}

func TestIfXTable_HCUcastPkts(t *testing.T) {
	a := NewAgent(&config.SNMPConfig{})
	a.SetIfDataFn(testIfXData)

	// ifHCInUcastPkts.3 (col 7)
	oid := append(append([]int{}, oidIfXTablePrefix...), 7, 3)
	val, tag := a.getOIDValue(oid)
	if tag != tagCounter64 {
		t.Fatalf("ifHCInUcastPkts tag = 0x%02x, want Counter64", tag)
	}
	decoded := decodeCounter64(val)
	if decoded != 9876543210 {
		t.Errorf("ifHCInUcastPkts.3 = %d, want 9876543210", decoded)
	}

	// ifHCOutUcastPkts.3 (col 11)
	oid = append(append([]int{}, oidIfXTablePrefix...), 11, 3)
	val, tag = a.getOIDValue(oid)
	if tag != tagCounter64 {
		t.Fatalf("ifHCOutUcastPkts tag = 0x%02x, want Counter64", tag)
	}
	decoded = decodeCounter64(val)
	if decoded != 1234567890 {
		t.Errorf("ifHCOutUcastPkts.3 = %d, want 1234567890", decoded)
	}
}

// --- ifXTable test helpers ---

// decodeCounter64 decodes a BER-encoded unsigned 64-bit value.
func decodeCounter64(data []byte) uint64 {
	// Strip leading zero (unsigned padding)
	for len(data) > 1 && data[0] == 0 {
		data = data[1:]
	}
	var val uint64
	for _, b := range data {
		val = (val << 8) | uint64(b)
	}
	return val
}

// decodeUint32 decodes a BER-encoded unsigned 32-bit value (Counter32/Gauge32).
func decodeUint32(data []byte) uint32 {
	for len(data) > 1 && data[0] == 0 {
		data = data[1:]
	}
	var val uint32
	for _, b := range data {
		val = (val << 8) | uint32(b)
	}
	return val
}
