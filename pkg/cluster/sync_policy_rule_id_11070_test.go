package cluster

import (
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
)

// Stable rule identity must survive both cluster session codecs; otherwise the
// userspace sync request on the standby can only use a sender-local index.
func TestSessionPolicyRuleIDRoundTripsClusterWire11070(t *testing.T) {
	const ruleID = "lan->wan/allow-web"
	key4 := dataplane.SessionKey{Protocol: 6}
	val4 := dataplane.SessionValue{PolicyCounterIdx: 7, PolicyRuleID: ruleID}
	_, got4, ok := decodeSessionV4Payload(encodeSessionV4Payload(key4, val4))
	if !ok || got4.PolicyRuleID != ruleID || got4.PolicyCounterIdx != 7 {
		t.Fatalf("v4 round trip: ok=%v value=%+v", ok, got4)
	}
	legacy4 := encodeSessionV4Payload(key4, val4)
	_, old4, ok := decodeSessionV4Payload(legacy4[:len(legacy4)-2-len(ruleID)])
	if !ok || old4.PolicyRuleID != "" {
		t.Fatalf("v4 legacy decode: ok=%v rule_id=%q", ok, old4.PolicyRuleID)
	}

	key6 := dataplane.SessionKeyV6{Protocol: 6}
	val6 := dataplane.SessionValueV6{PolicyCounterIdx: 11, PolicyRuleID: ruleID}
	_, got6, ok := decodeSessionV6Payload(encodeSessionV6Payload(key6, val6))
	if !ok || got6.PolicyRuleID != ruleID || got6.PolicyCounterIdx != 11 {
		t.Fatalf("v6 round trip: ok=%v value=%+v", ok, got6)
	}
	legacy6 := encodeSessionV6Payload(key6, val6)
	_, old6, ok := decodeSessionV6Payload(legacy6[:len(legacy6)-2-len(ruleID)])
	if !ok || old6.PolicyRuleID != "" {
		t.Fatalf("v6 legacy decode: ok=%v rule_id=%q", ok, old6.PolicyRuleID)
	}
}
