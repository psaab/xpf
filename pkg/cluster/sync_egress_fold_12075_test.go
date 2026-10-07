package cluster

import (
	"bytes"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
)

func TestEgressIfaceFoldV4RoundTripsAndAcceptsLegacyTail12075(t *testing.T) {
	const fold = uint32(0x12075001)
	key := dataplane.SessionKey{SrcPort: 1234, DstPort: 443, Protocol: 6}
	legacyValue := dataplane.SessionValue{
		SessionID:         0x1122334455667788,
		Generation:        44,
		PolicyRuleID:      "rule-12075",
		TCPHandshakeState: dataplane.TCPHandshakeStateOpening,
	}
	value := legacyValue
	value.EgressIfaceFold = fold

	payload := encodeSessionV4Payload(key, value)
	gotKey, got, ok := decodeSessionV4Payload(payload)
	if !ok || gotKey != key {
		t.Fatalf("v4 decode failed or changed key: ok=%v key=%+v", ok, gotKey)
	}
	if got.EgressIfaceFold != fold || got.PolicyRuleID != legacyValue.PolicyRuleID ||
		got.TCPHandshakeState != legacyValue.TCPHandshakeState ||
		got.SessionID != legacyValue.SessionID || got.Generation != legacyValue.Generation {
		t.Fatalf("v4 egress fold disturbed session tail: fold=%#x rule=%q handshake=%d session=%#x generation=%d",
			got.EgressIfaceFold, got.PolicyRuleID, got.TCPHandshakeState, got.SessionID, got.Generation)
	}

	legacyPayload := encodeSessionV4Payload(key, legacyValue)
	if len(payload) != len(legacyPayload)+4 || !bytes.Equal(payload[:len(legacyPayload)], legacyPayload) {
		t.Fatalf("v4 nonzero egress fold did not append exactly four bytes after the legacy tail: new=%d legacy=%d",
			len(payload), len(legacyPayload))
	}
	_, legacyGot, ok := decodeSessionV4Payload(payload[:len(payload)-4])
	if !ok || legacyGot.EgressIfaceFold != 0 ||
		legacyGot.PolicyRuleID != legacyValue.PolicyRuleID ||
		legacyGot.TCPHandshakeState != legacyValue.TCPHandshakeState {
		t.Fatalf("v4 legacy tail decode: ok=%v fold=%#x rule=%q handshake=%d",
			ok, legacyGot.EgressIfaceFold, legacyGot.PolicyRuleID, legacyGot.TCPHandshakeState)
	}
	zeroHandshakePayload := encodeSessionV4Payload(key, dataplane.SessionValue{EgressIfaceFold: fold})
	_, zeroHandshake, ok := decodeSessionV4Payload(zeroHandshakePayload)
	if !ok || zeroHandshake.EgressIfaceFold != fold ||
		zeroHandshake.TCPHandshakeState != dataplane.TCPHandshakeStateAbsent {
		t.Fatalf("v4 explicit zero handshake tail: ok=%v fold=%#x handshake=%d",
			ok, zeroHandshake.EgressIfaceFold, zeroHandshake.TCPHandshakeState)
	}
	_, legacyZeroHandshake, ok := decodeSessionV4Payload(zeroHandshakePayload[:len(zeroHandshakePayload)-4])
	if !ok || legacyZeroHandshake.EgressIfaceFold != 0 ||
		legacyZeroHandshake.TCPHandshakeState != dataplane.TCPHandshakeStateAbsent {
		t.Fatalf("v4 legacy zero-handshake tail: ok=%v fold=%#x handshake=%d",
			ok, legacyZeroHandshake.EgressIfaceFold, legacyZeroHandshake.TCPHandshakeState)
	}
}

func TestEgressIfaceFoldV6RoundTripsAndAcceptsLegacyTail12075(t *testing.T) {
	const fold = uint32(0x12075002)
	key := dataplane.SessionKeyV6{SrcPort: 2345, DstPort: 443, Protocol: 6}
	legacyValue := dataplane.SessionValueV6{
		SessionID:         0x2233445566778899,
		Generation:        55,
		PolicyRuleID:      "rule-12075-v6",
		TCPHandshakeState: dataplane.TCPHandshakeStateHandshakePending,
	}
	value := legacyValue
	value.EgressIfaceFold = fold

	payload := encodeSessionV6Payload(key, value)
	gotKey, got, ok := decodeSessionV6Payload(payload)
	if !ok || gotKey != key {
		t.Fatalf("v6 decode failed or changed key: ok=%v key=%+v", ok, gotKey)
	}
	if got.EgressIfaceFold != fold || got.PolicyRuleID != legacyValue.PolicyRuleID ||
		got.TCPHandshakeState != legacyValue.TCPHandshakeState ||
		got.SessionID != legacyValue.SessionID || got.Generation != legacyValue.Generation {
		t.Fatalf("v6 egress fold disturbed session tail: fold=%#x rule=%q handshake=%d session=%#x generation=%d",
			got.EgressIfaceFold, got.PolicyRuleID, got.TCPHandshakeState, got.SessionID, got.Generation)
	}

	legacyPayload := encodeSessionV6Payload(key, legacyValue)
	if len(payload) != len(legacyPayload)+4 || !bytes.Equal(payload[:len(legacyPayload)], legacyPayload) {
		t.Fatalf("v6 nonzero egress fold did not append exactly four bytes after the legacy tail: new=%d legacy=%d",
			len(payload), len(legacyPayload))
	}
	_, legacyGot, ok := decodeSessionV6Payload(payload[:len(payload)-4])
	if !ok || legacyGot.EgressIfaceFold != 0 ||
		legacyGot.PolicyRuleID != legacyValue.PolicyRuleID ||
		legacyGot.TCPHandshakeState != legacyValue.TCPHandshakeState {
		t.Fatalf("v6 legacy tail decode: ok=%v fold=%#x rule=%q handshake=%d",
			ok, legacyGot.EgressIfaceFold, legacyGot.PolicyRuleID, legacyGot.TCPHandshakeState)
	}
	zeroHandshakePayload := encodeSessionV6Payload(key, dataplane.SessionValueV6{EgressIfaceFold: fold})
	_, zeroHandshake, ok := decodeSessionV6Payload(zeroHandshakePayload)
	if !ok || zeroHandshake.EgressIfaceFold != fold ||
		zeroHandshake.TCPHandshakeState != dataplane.TCPHandshakeStateAbsent {
		t.Fatalf("v6 explicit zero handshake tail: ok=%v fold=%#x handshake=%d",
			ok, zeroHandshake.EgressIfaceFold, zeroHandshake.TCPHandshakeState)
	}
	_, legacyZeroHandshake, ok := decodeSessionV6Payload(zeroHandshakePayload[:len(zeroHandshakePayload)-4])
	if !ok || legacyZeroHandshake.EgressIfaceFold != 0 ||
		legacyZeroHandshake.TCPHandshakeState != dataplane.TCPHandshakeStateAbsent {
		t.Fatalf("v6 legacy zero-handshake tail: ok=%v fold=%#x handshake=%d",
			ok, legacyZeroHandshake.EgressIfaceFold, legacyZeroHandshake.TCPHandshakeState)
	}
}

func TestInstallStampFoldsLocalEgressV4V6_12075(t *testing.T) {
	const wantFold = uint32(0x12075001)
	ss := NewSessionSync(":0", "10.0.0.2:4785", nil)
	ss.SetIngressFoldFn(func(ifindex uint32, vlan uint16) uint32 {
		if ifindex == 12 && vlan == 80 {
			return wantFold
		}
		return 0
	})

	v4 := dataplane.SessionValue{FibIfindex: 12, FibVlanID: 80}
	ss.stampInstallGenV4(dataplane.SessionKey{Protocol: 6}, &v4)
	if v4.EgressIfaceFold != wantFold {
		t.Fatalf("v4 egress fold = %#x, want local fold %#x", v4.EgressIfaceFold, wantFold)
	}
	v6 := dataplane.SessionValueV6{FibIfindex: 12, FibVlanID: 80}
	ss.stampInstallGenV6(dataplane.SessionKeyV6{Protocol: 6}, &v6)
	if v6.EgressIfaceFold != wantFold {
		t.Fatalf("v6 egress fold = %#x, want local fold %#x", v6.EgressIfaceFold, wantFold)
	}

	unresolved := dataplane.SessionValue{FibIfindex: 0, FibVlanID: 80}
	ss.stampInstallGenV4(dataplane.SessionKey{Protocol: 17}, &unresolved)
	if unresolved.EgressIfaceFold != 0 {
		t.Fatalf("unresolved local egress stamped %#x, want unknown fold 0", unresolved.EgressIfaceFold)
	}
}
