package cluster

import (
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
)

// rtflowKeyV4 / rtflowKeyV6 mint distinct 5-tuples for the #5212 wire tests.
func rtflowKeyV4(srcPort uint16) dataplane.SessionKey {
	return dataplane.SessionKey{
		Protocol: 6,
		SrcIP:    [4]byte{10, 0, 0, 2},
		DstIP:    [4]byte{172, 16, 80, 201},
		SrcPort:  srcPort,
		DstPort:  5201,
	}
}

func rtflowKeyV6(srcPort uint16) dataplane.SessionKeyV6 {
	k := dataplane.SessionKeyV6{Protocol: 6, SrcPort: srcPort, DstPort: 5201}
	k.SrcIP[15] = 3
	k.DstIP[15] = 4
	return k
}

// TestSessionWireRoundTripRTFlowSessionID5212V4 asserts the originating node's
// stable RT_FLOW session id round-trips on the cluster session-sync wire as a
// length-gated trailing field (appended after the #5274 ConfigEpoch), AND a
// legacy payload truncated before the #5212 block still decodes (id 0, prior
// fields preserved). Reverting the sync_protocol.go encode/decode drops the
// value and this fails RED.
func TestSessionWireRoundTripRTFlowSessionID5212V4(t *testing.T) {
	key := rtflowKeyV4(41001)
	val := dataplane.SessionValue{
		Flags:            dataplane.SessFlagClusterSynced,
		State:            dataplane.SessStateEstablished,
		IngressZone:      1,
		EgressZone:       2,
		PolicyID:         42,
		Generation:       0xDEADBEEFCAFE,
		AppTimeout:       30,
		PolicyCounterIdx: 7,
		ConfigEpoch:      0x1122334455667788,
		// The originating node's stable id: worker 7 in the high 16 bits.
		RTFlowSessionID: (7 << 48) | 0x0000_0000_1234_5678,
	}
	payload := encodeSessionV4Payload(key, val)
	dKey, dVal, ok := decodeSessionV4Payload(payload)
	if !ok {
		t.Fatal("decode failed")
	}
	if dKey != key {
		t.Fatalf("key mismatch: %+v vs %+v", dKey, key)
	}
	if dVal.RTFlowSessionID != val.RTFlowSessionID {
		t.Fatalf("RTFlowSessionID round-trip = %#x, want %#x", dVal.RTFlowSessionID, val.RTFlowSessionID)
	}
	// The #5274 config epoch (the trailing field before the id) must be intact.
	if dVal.ConfigEpoch != val.ConfigEpoch || dVal.Generation != val.Generation || dVal.PolicyCounterIdx != 7 {
		t.Fatalf("adjacent trailing fields corrupted: epoch=%#x gen=%#x idx=%d",
			dVal.ConfigEpoch, dVal.Generation, dVal.PolicyCounterIdx)
	}

	// Mixed-version: truncate the trailing 8-byte #5212 id AND everything
	// appended behind it — the 4-byte #7095 IngressIfaceFold and the 8-byte
	// #7188 TunnelDiscriminator — so the frame ends after ConfigEpoch, which is
	// where an old peer stops. Decode must still succeed with id 0 and the
	// epoch + prior fields preserved.
	legacy := payload[:len(payload)-34]
	_, lVal, ok := decodeSessionV4Payload(legacy)
	if !ok {
		t.Fatal("legacy (truncated) decode failed")
	}
	if lVal.RTFlowSessionID != 0 {
		t.Fatalf("legacy frame RTFlowSessionID = %#x, want 0", lVal.RTFlowSessionID)
	}
	if lVal.ConfigEpoch != val.ConfigEpoch {
		t.Fatalf("legacy frame corrupted the ConfigEpoch: got %#x want %#x", lVal.ConfigEpoch, val.ConfigEpoch)
	}
	if lVal.Flags&dataplane.SessFlagClusterSynced != 0 {
		t.Fatalf("legacy v4 frame origin flags=%#x, want clear", lVal.Flags)
	}
}

func TestSessionWireRoundTripRTFlowSessionID5212V6(t *testing.T) {
	key := rtflowKeyV6(41002)
	val := dataplane.SessionValueV6{
		Flags:            dataplane.SessFlagClusterSynced,
		State:            dataplane.SessStateEstablished,
		IngressZone:      1,
		EgressZone:       2,
		PolicyID:         99,
		Generation:       0x0102030405060708,
		AppTimeout:       45,
		PolicyCounterIdx: 11,
		Nat64SnatV4:      [4]byte{192, 0, 2, 9},
		ConfigEpoch:      0x99aabbccddeeff00,
		RTFlowSessionID:  (3 << 48) | 0x0000_0000_0000_002a,
	}
	payload := encodeSessionV6Payload(key, val)
	_, dVal, ok := decodeSessionV6Payload(payload)
	if !ok {
		t.Fatal("decode failed")
	}
	if dVal.RTFlowSessionID != val.RTFlowSessionID {
		t.Fatalf("RTFlowSessionID round-trip = %#x, want %#x", dVal.RTFlowSessionID, val.RTFlowSessionID)
	}
	// The #5274 epoch and #4565 NAT64 pool source (the fields before the id) must
	// be intact.
	if dVal.ConfigEpoch != val.ConfigEpoch || dVal.Nat64SnatV4 != val.Nat64SnatV4 {
		t.Fatalf("adjacent trailing fields corrupted by appended id: epoch=%#x snat=%v",
			dVal.ConfigEpoch, dVal.Nat64SnatV4)
	}

	// Mixed-version: truncate the trailing 8-byte id AND everything appended
	// behind it — the 4-byte #7095 IngressIfaceFold, the 8-byte
	// #7188 TunnelDiscriminator and the #10227 high-flags byte — so the frame
	// ends after ConfigEpoch, which is where an old peer stops. Decode still
	// succeeds with id 0 and the epoch preserved.
	legacy := payload[:len(payload)-34]
	_, lVal, ok := decodeSessionV6Payload(legacy)
	if !ok {
		t.Fatal("legacy (truncated) v6 decode failed")
	}
	if lVal.RTFlowSessionID != 0 {
		t.Fatalf("legacy v6 frame RTFlowSessionID = %#x, want 0", lVal.RTFlowSessionID)
	}
	if lVal.ConfigEpoch != val.ConfigEpoch {
		t.Fatalf("legacy v6 frame corrupted the ConfigEpoch: got %#x want %#x", lVal.ConfigEpoch, val.ConfigEpoch)
	}
	if lVal.Flags&dataplane.SessFlagClusterSynced != 0 {
		t.Fatalf("legacy v6 frame origin flags=%#x, want clear", lVal.Flags)
	}
}
