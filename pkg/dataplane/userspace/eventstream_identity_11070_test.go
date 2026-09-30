package userspace

import (
	"encoding/binary"
	"testing"
)

// The event-stream producer appends ingress identity and stable policy rule ID
// after the install-table and source-NAT ICMP trailers. Reverting either decode
// leaves fabric ownership zone-approximate or drops the stable counter binding.
func TestDecodeSessionEventCarriesIngressAndRuleIdentity11070(t *testing.T) {
	const ruleID = "lan->wan/allow-web"
	payload := make([]byte, 180+len(ruleID))
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

	legacy, ok := decodeSessionEvent(payload[:169])
	if !ok {
		t.Fatal("legacy payload ending after install-table trailer was rejected")
	}
	if legacy.IngressIfindex != 0 || legacy.IngressVLANID != 0 || legacy.PolicyRuleID != "" {
		t.Fatalf("legacy payload fabricated identity: %+v", legacy)
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
