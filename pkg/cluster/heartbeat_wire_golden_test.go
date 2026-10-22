package cluster

import (
	"bytes"
	"encoding/hex"
	"reflect"
	"testing"
)

// #16169: golden byte vectors for the heartbeat wire codec, now housed in
// heartbeat_wire.go. These pin the exact on-wire bytes — including the
// XPFE echo trailer + epoch section + XPFA auth trailer ordering documented
// in README #10775 — so any accidental wire change (field order, endianness,
// trailer placement, HMAC span) fails here instead of breaking mixed-version
// interoperability in the field. Vectors were captured verbatim from the
// pre-split codec on origin/master; the move is byte-identical.
//
// Ordering invariant pinned by the epoch vector: body (with XPFE echo
// trailer inside the body, after the version section) || epoch section
// (key-derived marker + little-endian epoch) || XPFA auth trailer
// (magic + session + counter + HMAC over everything before the digest).
// The auth trailer stays at the fixed tail (len-52) so a pre-epoch reader
// still locates it, and the epoch sits INSIDE the signed span.

const goldenWireKey = "cluster-shared-secret"

func goldenWirePkt() *HeartbeatPacket {
	return &HeartbeatPacket{
		NodeID:    1,
		ClusterID: 0x1234,
		Groups: []HeartbeatGroup{
			{GroupID: 0, Priority: 100, Weight: 10, State: 1},
			{GroupID: 1, Priority: 200, Weight: 20, State: 2},
		},
		Monitors:          []HeartbeatMonitor{{RGID: 0, Weight: 5, Up: true, Interface: "ge-0/0/0"}},
		SoftwareVersion:   "1.2.3",
		HAProtocolVersion: 1,
	}
}

func goldenEchoPkt() *HeartbeatPacket {
	pkt := goldenWirePkt()
	pkt.HeartbeatSession = 0x0102030405060708
	pkt.HeartbeatSequence = 42
	pkt.PeerHeartbeatSession = 0x1112131415161718
	pkt.PeerHeartbeatSequence = 99
	return pkt
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("golden vector is not hex: %v", err)
	}
	return b
}

// goldenLegacyHex is MarshalHeartbeat(goldenWirePkt()): header + 2 groups +
// 1 monitor + version trailer, no echo/auth/epoch.
const goldenLegacyHex = "4250465801013412020064000a0101c8" +
	"001402010001050867652d302f302f30" +
	"05312e322e330100"

// goldenMinimalHex is MarshalHeartbeat(&HeartbeatPacket{NodeID:0, ClusterID:1}):
// the canonical 13-byte zero-group/zero-monitor body.
const goldenMinimalHex = "42504658010001000000000100"

// goldenEchoHex is MarshalHeartbeat(goldenEchoPkt()): legacy body plus the
// 36-byte XPFE echo trailer after the version section.
const goldenEchoHex = "4250465801013412020064000a0101c8" +
	"001402010001050867652d302f302f30" +
	"05312e322e3301005850464508070605" +
	"040302012a0000000000000018171615" +
	"141312116300000000000000"

// goldenAuthHex is MarshalHeartbeatAuth(goldenWirePkt(), key, 0xdeadbeef, 7):
// legacy body + 52-byte XPFA trailer at the fixed tail.
const goldenAuthHex = "4250465801013412020064000a0101c8" +
	"001402010001050867652d302f302f30" +
	"05312e322e33010058504641efbeadde" +
	"00000000070000000000000058171e1b" +
	"eef4933e59bca8de7ad418b5c6daf840" +
	"38844493f9d9c29316c5aae5"

// goldenEpochHex is marshalHeartbeatAuthEpoch(goldenEchoPkt(), key,
// 0xdeadbeef, 7, 4242424242): echo body || epoch section (marker
// f783553b5d7de433 + epoch LE) || XPFA trailer. Session/counter are the
// same as the auth vector so only the epoch section + HMAC differ.
const goldenEpochHex = "4250465801013412020064000a0101c8" +
	"001402010001050867652d302f302f30" +
	"05312e322e3301005850464508070605" +
	"040302012a0000000000000018171615" +
	"141312116300000000000000f783553b" +
	"5d7de433b241defc0000000058504641" +
	"efbeadde000000000700000000000000" +
	"e760b6fffe3e08651f9a9c63465581db" +
	"f0eddd1d75c3532a84ae366324a503c3"

func TestHeartbeatWireGoldenLegacy16169(t *testing.T) {
	want := mustHex(t, goldenLegacyHex)
	got := MarshalHeartbeat(goldenWirePkt())
	if !bytes.Equal(got, want) {
		t.Fatalf("legacy encode drift:\n got %x\nwant %x", got, want)
	}
	pkt, err := UnmarshalHeartbeat(want)
	if err != nil {
		t.Fatalf("golden legacy decode: %v", err)
	}
	if !reflect.DeepEqual(pkt, goldenWirePkt()) {
		t.Fatalf("golden legacy round-trip:\n got %+v\nwant %+v", pkt, goldenWirePkt())
	}
	// Re-encode of the decoded packet must reproduce the golden bytes.
	if re := MarshalHeartbeat(pkt); !bytes.Equal(re, want) {
		t.Fatalf("legacy decode->encode drift:\n got %x\nwant %x", re, want)
	}
}

func TestHeartbeatWireGoldenMinimal16169(t *testing.T) {
	want := mustHex(t, goldenMinimalHex)
	got := MarshalHeartbeat(&HeartbeatPacket{NodeID: 0, ClusterID: 1})
	if !bytes.Equal(got, want) {
		t.Fatalf("minimal encode drift:\n got %x\nwant %x", got, want)
	}
	pkt, err := UnmarshalHeartbeat(want)
	if err != nil {
		t.Fatalf("golden minimal decode: %v", err)
	}
	wantPkt := &HeartbeatPacket{NodeID: 0, ClusterID: 1, Groups: []HeartbeatGroup{}, HAProtocolVersion: LegacyHAProtocolVersion}
	// Groups decodes as an empty (non-nil) slice for a zero count.
	if pkt.NodeID != wantPkt.NodeID || pkt.ClusterID != wantPkt.ClusterID ||
		len(pkt.Groups) != 0 || len(pkt.Monitors) != 0 || pkt.HAProtocolVersion != wantPkt.HAProtocolVersion {
		t.Fatalf("golden minimal round-trip: got %+v", pkt)
	}
}

func TestHeartbeatWireGoldenEcho16169(t *testing.T) {
	want := mustHex(t, goldenEchoHex)
	got := MarshalHeartbeat(goldenEchoPkt())
	if !bytes.Equal(got, want) {
		t.Fatalf("echo encode drift:\n got %x\nwant %x", got, want)
	}
	// The XPFE magic must sit immediately after the version section
	// (end of the legacy body), before any fixed-tail trailers.
	legacyLen := len(mustHex(t, goldenLegacyHex))
	if string(want[legacyLen:legacyLen+4]) != heartbeatEchoMagic {
		t.Fatalf("echo magic at %d = %q, want %q", legacyLen, want[legacyLen:legacyLen+4], heartbeatEchoMagic)
	}
	pkt, err := UnmarshalHeartbeat(want)
	if err != nil {
		t.Fatalf("golden echo decode: %v", err)
	}
	if !reflect.DeepEqual(pkt, goldenEchoPkt()) {
		t.Fatalf("golden echo round-trip:\n got %+v\nwant %+v", pkt, goldenEchoPkt())
	}
}

func TestHeartbeatWireGoldenAuth16169(t *testing.T) {
	key := []byte(goldenWireKey)
	want := mustHex(t, goldenAuthHex)
	got := MarshalHeartbeatAuth(goldenWirePkt(), key, 0xdeadbeef, 7)
	if !bytes.Equal(got, want) {
		t.Fatalf("auth encode drift:\n got %x\nwant %x", got, want)
	}
	// Trailer ordering: body is exactly the legacy bytes; XPFA at len-52.
	legacy := mustHex(t, goldenLegacyHex)
	if !bytes.Equal(want[:len(legacy)], legacy) {
		t.Fatalf("auth body prefix drift:\n got %x\nwant %x", want[:len(legacy)], legacy)
	}
	if string(want[len(want)-heartbeatAuthTrailerSize:len(want)-heartbeatAuthTrailerSize+4]) != heartbeatAuthMagic {
		t.Fatalf("auth magic not at fixed tail (len-%d)", heartbeatAuthTrailerSize)
	}
	session, counter, present := heartbeatAuthTrailer(want)
	if !present || session != 0xdeadbeef || counter != 7 {
		t.Fatalf("auth trailer nonce = (%x,%d,%v), want (deadbeef,7,true)", session, counter, present)
	}
	if !verifyHeartbeatMAC(want, key) {
		t.Fatal("golden auth frame does not verify under its key")
	}
	if verifyHeartbeatMAC(want, []byte("wrong-key")) {
		t.Fatal("golden auth frame verifies under a wrong key")
	}
	pkt, err := UnmarshalHeartbeat(want)
	if err != nil {
		t.Fatalf("golden auth decode: %v", err)
	}
	if !reflect.DeepEqual(pkt, goldenWirePkt()) {
		t.Fatalf("golden auth round-trip:\n got %+v\nwant %+v", pkt, goldenWirePkt())
	}
	// No-key auth marshal is byte-identical to the legacy golden vector.
	if noKey := MarshalHeartbeatAuth(goldenWirePkt(), nil, 1, 1); !bytes.Equal(noKey, legacy) {
		t.Fatalf("no-key auth marshal drift from legacy:\n got %x\nwant %x", noKey, legacy)
	}
	// Epoch == 0 is byte-identical to the plain auth golden vector.
	if epoch0 := marshalHeartbeatAuthEpoch(goldenWirePkt(), key, 0xdeadbeef, 7, 0); !bytes.Equal(epoch0, want) {
		t.Fatalf("epoch=0 marshal drift from auth golden:\n got %x\nwant %x", epoch0, want)
	}
}

func TestHeartbeatWireGoldenEpoch16169(t *testing.T) {
	key := []byte(goldenWireKey)
	const epoch = uint64(4242424242)
	want := mustHex(t, goldenEpochHex)
	got := marshalHeartbeatAuthEpoch(goldenEchoPkt(), key, 0xdeadbeef, 7, epoch)
	if !bytes.Equal(got, want) {
		t.Fatalf("epoch encode drift:\n got %x\nwant %x", got, want)
	}
	// Ordering: echo body || epoch section || auth trailer at fixed tail.
	echoLen := len(mustHex(t, goldenEchoHex))
	if !bytes.Equal(want[:echoLen], mustHex(t, goldenEchoHex)) {
		t.Fatalf("epoch body prefix is not the echo golden body")
	}
	marker := heartbeatEpochMarker(key)
	if !bytes.Equal(want[echoLen:echoLen+heartbeatEpochMarkerSize], marker) {
		t.Fatalf("epoch marker at %d = %x, want key-derived %x", echoLen, want[echoLen:echoLen+heartbeatEpochMarkerSize], marker)
	}
	if string(want[len(want)-heartbeatAuthTrailerSize:len(want)-heartbeatAuthTrailerSize+4]) != heartbeatAuthMagic {
		t.Fatalf("epoch frame auth magic not at fixed tail (len-%d)", heartbeatAuthTrailerSize)
	}
	gotEpoch, present := heartbeatFrameEpoch(want, key)
	if !present || gotEpoch != epoch {
		t.Fatalf("golden epoch readback = (%d,%v), want (%d,true)", gotEpoch, present, epoch)
	}
	if !verifyHeartbeatMAC(want, key) {
		t.Fatal("golden epoch frame does not verify — epoch must be inside the signed span")
	}
	pkt, err := UnmarshalHeartbeat(want)
	if err != nil {
		t.Fatalf("golden epoch decode: %v", err)
	}
	if !reflect.DeepEqual(pkt, goldenEchoPkt()) {
		t.Fatalf("golden epoch round-trip:\n got %+v\nwant %+v", pkt, goldenEchoPkt())
	}
}

// Malformed/truncated frames must be rejected exactly as before the split:
// header-level truncations and bad magic/version error out, while a frame
// truncated inside the monitor tail still yields the groups (documented
// best-effort monitor behavior in UnmarshalHeartbeat).
func TestHeartbeatWireGoldenMalformed16169(t *testing.T) {
	legacy := mustHex(t, goldenLegacyHex)

	for _, tc := range []struct {
		name string
		data []byte
	}{
		{"empty", nil},
		{"one byte", legacy[:1]},
		{"short header", legacy[:heartbeatHeaderSize-1]},
		{"truncated groups", legacy[:heartbeatHeaderSize+2]},
	} {
		if _, err := UnmarshalHeartbeat(tc.data); err == nil {
			t.Errorf("%s: expected error, got nil", tc.name)
		}
	}

	badMagic := append([]byte(nil), legacy...)
	copy(badMagic[0:4], "DEAD")
	if _, err := UnmarshalHeartbeat(badMagic); err == nil {
		t.Error("bad magic: expected error, got nil")
	}
	badVersion := append([]byte(nil), legacy...)
	badVersion[4] = 99
	if _, err := UnmarshalHeartbeat(badVersion); err == nil {
		t.Error("bad version: expected error, got nil")
	}

	// Malformed epochs: an epoch frame truncated into the auth trailer no
	// longer verifies and must not report an epoch; a frame with a flipped
	// epoch byte fails the MAC (epoch is inside the signed span).
	key := []byte(goldenWireKey)
	epochFrame := mustHex(t, goldenEpochHex)
	if verifyHeartbeatMAC(epochFrame[:len(epochFrame)-1], key) {
		t.Error("truncated epoch frame verifies")
	}
	tampered := append([]byte(nil), epochFrame...)
	epochAt := len(tampered) - heartbeatAuthTrailerSize - heartbeatEpochFieldSize
	tampered[epochAt] ^= 0x01
	if verifyHeartbeatMAC(tampered, key) {
		t.Error("tampered epoch byte verifies — epoch outside signed span")
	}
	// A legacy (epochless) golden frame reports no epoch.
	if _, present := heartbeatFrameEpoch(mustHex(t, goldenAuthHex), key); present {
		t.Error("legacy auth frame reported an epoch section")
	}
	// A runt shorter than the auth trailer reports no trailer / no epoch.
	if _, _, present := heartbeatAuthTrailer(epochFrame[:heartbeatAuthTrailerSize-1]); present {
		t.Error("runt frame reported an auth trailer")
	}
}
