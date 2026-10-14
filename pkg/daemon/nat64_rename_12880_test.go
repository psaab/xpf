package daemon

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// #12880: NAT64 (IPv6 session, IPv4 translated destination) must survive
// policy-rename rematch and rollback re-authorization. The translated dst
// is IPv4 even though the session family is 6; policymatch admits
// v6-source/v4-destination. Pre-fix, both helper paths rejected any
// DNAT dst with To4()!=nil on a family-6 session, and legacy
// rematchRenamedV6 queried the 16-byte NATDstIP as a v6 address with
// DstFamily="v6", so a still-permitting policy wrongly deleted the session.

func nat64RenameConfig12880() (oldCfg, newCfg *config.Config) {
	oldCfg = policyRenameEvaluatorConfig("p-old", config.PolicyPermit)
	newCfg = policyRenameEvaluatorConfig("p-new", config.PolicyPermit)
	for _, cfg := range []*config.Config{oldCfg, newCfg} {
		// Only the translated v4 dst matches; the v6 wire dst must not.
		cfg.Security.Policies[1].Policies[0].Match.DestinationAddresses = []string{"10.0.0.1/32"}
	}
	// Remove alternate so only the renamed rule can permit (else deny half vacuous).
	newCfg.Security.Policies[1].Policies = newCfg.Security.Policies[1].Policies[:1]
	return oldCfg, newCfg
}

func TestRematchRenamedMatchNAT6412880(t *testing.T) {
	oldCfg, newCfg := nat64RenameConfig12880()
	oldID, binding := helperRenameBinding10626(t, oldCfg, newCfg)
	match := helperRenameMatch10626(oldID)
	match.AddrFamily = 6
	match.Tuple.AddrFamily = 6
	match.Tuple.SrcIP = "2001:db8::10"
	match.Tuple.DstIP = "64:ff9b::a00:14" // NAT64 wire dst (2001:db8::20 equivalent shape; non-matching)
	match.DNAT = true
	match.NATDstIP = "10.0.0.1"
	match.NATDstPort = 8443
	record, permitted := rematchRenamedMatch(oldCfg, newCfg, binding, match)
	if !permitted || record.RuleID != "lan->wan/p-new" {
		t.Fatalf("NAT64 helper match not retained through renamed permit: %+v permitted=%v", record, permitted)
	}
	if record.DstIP != match.Tuple.DstIP || record.SrcIP != match.Tuple.SrcIP {
		t.Fatalf("NAT64 record must carry wire tuple: %+v", record)
	}
	// Out-of-scope translated v4 dst denies.
	match.NATDstIP = "10.9.9.9"
	if _, permitted := rematchRenamedMatch(oldCfg, newCfg, binding, match); permitted {
		t.Fatal("out-of-scope NAT64 translated dst retained, want denied")
	}
	// Garbage translated dst denies (fail closed).
	match.NATDstIP = "not-an-address!!"
	if _, permitted := rematchRenamedMatch(oldCfg, newCfg, binding, match); permitted {
		t.Fatal("garbage NAT64 translated dst retained, want denied")
	}
}

func TestRematchRenamedV6NAT64Legacy12880(t *testing.T) {
	oldCfg, newCfg := nat64RenameConfig12880()
	oldID, binding := helperRenameBinding10626(t, oldCfg, newCfg)
	// Legacy BPF v6 value: NATDstIP holds left-aligned IPv4 translated dst.
	var natDst [16]byte
	copy(natDst[:], []byte{10, 0, 0, 1})
	key := dataplane.SessionKeyV6{
		SrcIP:   [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x0a},
		DstIP:   [16]byte{0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, 0x0a, 0x00, 0x00, 0x14},
		SrcPort: 1234, DstPort: 443, Protocol: 6,
	}
	value := dataplane.SessionValueV6{
		PolicyID: oldID, IngressZone: config.StableZoneID("lan"), EgressZone: config.StableZoneID("wan"),
		Flags: dataplane.SessFlagDNAT | dataplane.SessFlagNAT64, NATDstIP: natDst, NATDstPort: 8443,
	}
	record, permitted := rematchRenamedV6(oldCfg, newCfg, binding, key, value)
	if !permitted || record.RuleID != "lan->wan/p-new" {
		t.Fatalf("NAT64 legacy v6 row not retained through renamed permit: %+v permitted=%v", record, permitted)
	}
	// Out-of-scope left-aligned v4 translation denies.
	var bad [16]byte
	copy(bad[:], []byte{10, 9, 9, 9})
	value.NATDstIP = bad
	if _, permitted := rematchRenamedV6(oldCfg, newCfg, binding, key, value); permitted {
		t.Fatal("out-of-scope NAT64 legacy translation retained, want denied")
	}
	// A genuine v6 translation ending in twelve zero bytes must not be
	// mistaken for left-aligned IPv4; the NAT64 flag is the discriminator.
	for _, cfg := range []*config.Config{oldCfg, newCfg} {
		cfg.Security.Policies[1].Policies[0].Match.DestinationAddresses = []string{"2001:db8::/128"}
	}
	value.Flags &^= dataplane.SessFlagNAT64
	value.NATDstIP = [16]byte{0x20, 0x01, 0x0d, 0xb8}
	if _, permitted := rematchRenamedV6(oldCfg, newCfg, binding, key, value); !permitted {
		t.Fatal("ordinary v6 DNAT row ending in zero bytes no longer retained")
	}
}

func TestReauthorizeNAT64Candidate12880(t *testing.T) {
	d := &Daemon{}
	restored := policyRenameEvaluatorConfig("p-old", config.PolicyPermit)
	restored.Security.Policies[1].Policies[0].Match.DestinationAddresses = []string{"10.0.0.1/32"}
	restored.Security.Policies[1].Policies = restored.Security.Policies[1].Policies[:1]
	match := dpuserspace.SessionPolicyMatch{
		AddrFamily: 6,
		Tuple: dpuserspace.SessionPolicyTuple{
			AddrFamily: 6, Protocol: 6, SrcIP: "2001:db8::10", DstIP: "64:ff9b::a00:14",
			SrcPort: 1234, DstPort: 443,
		},
		DNAT: true, NATDstIP: "10.0.0.1", NATDstPort: 8443,
		ExpectedRTFlowSessionID: 12880,
		IngressZoneID:           config.StableZoneID("lan"),
		EgressZoneID:            config.StableZoneID("wan"),
	}
	capture := &policyInvalidationCapture{candidateRuleIDs: map[policyInvalidationMatchIdentity]string{}}
	capture.deleted.policy = append(capture.deleted.policy, match)
	capture.candidateRuleIDs[policyInvalidationMatchID(match)] = "lan->wan/p-old"
	kept, permitted := d.reauthorizePolicyCandidates(capture, restored, false)
	if permitted == nil || permitted.candidateCount() != 1 || kept.candidateCount() != 0 {
		t.Fatalf("NAT64 candidate not re-authorized under restored permit: kept=%d permitted=%v", kept.candidateCount(), permitted)
	}
	// Out-of-scope translation stays kept (fail closed).
	match.NATDstIP = "10.9.9.9"
	capture2 := &policyInvalidationCapture{candidateRuleIDs: map[policyInvalidationMatchIdentity]string{}}
	capture2.deleted.policy = append(capture2.deleted.policy, match)
	capture2.candidateRuleIDs[policyInvalidationMatchID(match)] = "lan->wan/p-old"
	kept, permitted = d.reauthorizePolicyCandidates(capture2, restored, false)
	if permitted != nil || kept.candidateCount() != 1 {
		t.Fatalf("out-of-scope NAT64 candidate re-authorized: kept=%d permitted=%v", kept.candidateCount(), permitted)
	}
}
