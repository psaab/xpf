package userspace

import (
	"encoding/binary"
	"testing"
)

// The event-stream producer appends ingress identity and stable policy rule ID
// after existing metadata, followed by the handshake-state byte. The variable
// rule-ID length and truncated legacy frames must preserve their old defaults.
func TestDecodeSessionEventCarriesIngressRuleAndHandshakeState10888(t *testing.T) {
	const ruleID = "lan->wan/allow-web"
	payload := make([]byte, 181+len(ruleID))
	payload[0], payload[1] = 6, 6
	binary.LittleEndian.PutUint64(payload[140:148], 0x1234)
	binary.LittleEndian.PutUint64(payload[148:156], 0x55)
	binary.LittleEndian.PutUint32(payload[156:160], 7)
	payload[160] = 2
	binary.LittleEndian.PutUint32(payload[161:165], 8)
	binary.LittleEndian.PutUint32(payload[165:169], 9)
	payload[169] = 1  // source-NAT ICMP identity is present
	payload[170] = 13 // ICMP type
	payload[171] = 7  // ICMP code
	binary.LittleEndian.PutUint32(payload[172:176], 4242)
	binary.LittleEndian.PutUint16(payload[176:178], 51)
	binary.LittleEndian.PutUint16(payload[178:180], uint16(len(ruleID)))
	copy(payload[180:], ruleID)
	payload[180+len(ruleID)] = 3 // TCPHandshakeState: SynAckFirstPending

	delta, ok := decodeSessionEvent(payload)
	if !ok {
		t.Fatal("complete session-open payload was rejected")
	}
	if !delta.SourceNatICMPValid || delta.SourceNatICMPType != 13 || delta.SourceNatICMPCode != 7 ||
		delta.IngressIfindex != 4242 || delta.IngressVLANID != 51 || delta.PolicyRuleID != ruleID {
		t.Fatalf("decoded identity = ICMP %v/%d/%d ifindex %d vlan %d rule %q",
			delta.SourceNatICMPValid, delta.SourceNatICMPType, delta.SourceNatICMPCode,
			delta.IngressIfindex, delta.IngressVLANID, delta.PolicyRuleID)
	}
	if delta.TCPHandshakeState != 3 {
		t.Fatalf("decoded TCPHandshakeState = %d, want SynAckFirstPending (3)", delta.TCPHandshakeState)
	}
	unknownStagePayload := append([]byte(nil), payload...)
	unknownStagePayload[len(unknownStagePayload)-1] = 99
	unknownStageDelta, ok := decodeSessionEvent(unknownStagePayload)
	if !ok || unknownStageDelta.TCPHandshakeState != 4 {
		t.Fatalf("unknown handshake state: ok=%v state=%d, want true/Established (4)",
			ok, unknownStageDelta.TCPHandshakeState)
	}
	emptyRulePayload := append([]byte(nil), payload[:180]...)
	binary.LittleEndian.PutUint16(emptyRulePayload[178:180], 0)
	emptyRulePayload = append(emptyRulePayload, 2)
	emptyRuleDelta, ok := decodeSessionEvent(emptyRulePayload)
	if !ok || emptyRuleDelta.PolicyRuleID != "" || emptyRuleDelta.TCPHandshakeState != 2 {
		t.Fatalf("empty-rule frame: ok=%v rule=%q state=%d, want true/empty/HandshakePending",
			ok, emptyRuleDelta.PolicyRuleID, emptyRuleDelta.TCPHandshakeState)
	}
	// A legacy frame with the rule ID but without the appended state defaults
	// to 0 (established behavior).
	legacyWithoutHandshake, ok := decodeSessionEvent(payload[:len(payload)-1])
	if !ok || legacyWithoutHandshake.TCPHandshakeState != 0 {
		t.Fatalf("legacy frame without handshake state: ok=%v state=%d, want true/0",
			ok, legacyWithoutHandshake.TCPHandshakeState)
	}

	legacy, ok := decodeSessionEvent(payload[:169])
	if !ok {
		t.Fatal("legacy payload ending after install-table trailer was rejected")
	}
	if legacy.IngressIfindex != 0 || legacy.IngressVLANID != 0 || legacy.PolicyRuleID != "" {
		t.Fatalf("legacy payload fabricated identity: %+v", legacy)
	}
}

func TestDecodeSessionEventSourceNatProvenance12187(t *testing.T) {
	for _, family := range []struct {
		name     string
		wireAF   byte
		addrSize int
	}{
		{name: "v4", wireAF: 4, addrSize: 4},
		{name: "v6", wireAF: 6, addrSize: 16},
	} {
		t.Run(family.name, func(t *testing.T) {
			baseLen := 32 + 5*family.addrSize + 12
			handshakeOffset := baseLen + 56
			for _, tc := range []struct {
				name          string
				provenance    byte
				hasProvenance bool
				want          uint8
			}{
				{name: "legacy missing byte", want: 0},
				{name: "unknown", provenance: 0, hasProvenance: true, want: 0},
				{name: "dynamic", provenance: 1, hasProvenance: true, want: 1},
				{name: "static", provenance: 2, hasProvenance: true, want: 2},
				{name: "unknown future value", provenance: 255, hasProvenance: true, want: 0},
			} {
				t.Run(tc.name, func(t *testing.T) {
					payload := make([]byte, baseLen+57)
					payload[0], payload[1] = family.wireAF, 6
					// The fixed-width fields before this tail are zero-filled;
					// a zero-length policy-rule ID still has its two-byte prefix.
					payload[handshakeOffset] = 4
					if tc.hasProvenance {
						payload = append(payload, tc.provenance)
					}

					delta, ok := decodeSessionEvent(payload)
					if !ok {
						t.Fatal("decodeSessionEvent rejected a valid open/update payload")
					}
					if delta.TCPHandshakeState != 4 {
						t.Fatalf("TCPHandshakeState=%d, want 4", delta.TCPHandshakeState)
					}
					if delta.SourceNatProvenance != tc.want {
						t.Fatalf("SourceNatProvenance=%d, want %d", delta.SourceNatProvenance, tc.want)
					}
				})
			}
		})
	}
}

func TestDecodeSessionCloseCarriesIngressIdentity11070(t *testing.T) {
	payload := make([]byte, 42)
	payload[0] = 4
	payload[35] = 1 // legacy purge-retirement marker keeps its old offset
	binary.LittleEndian.PutUint32(payload[36:40], 4242)
	binary.LittleEndian.PutUint16(payload[40:42], 51)
	got, ok := decodeSessionCloseEvent(payload)
	if !ok || got.IngressIfindex != 4242 || got.IngressVLANID != 51 || !got.PurgeRetirement {
		t.Fatalf("new close decode: ok=%v delta=%+v", ok, got)
	}

	legacy := make([]byte, 36)
	copy(legacy[:35], payload[:35])
	legacy[35] = payload[35]
	got, ok = decodeSessionCloseEvent(legacy)
	if !ok || got.IngressIfindex != 0 || got.IngressVLANID != 0 || !got.PurgeRetirement {
		t.Fatalf("legacy close decode: ok=%v delta=%+v", ok, got)
	}
}
