package daemon

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// #13176 (D5-08): distinct session-store rows that share a bare 5-tuple but
// differ in RoutingDomain / TunnelDiscriminator / RTFlowSessionID are distinct
// sessions. Merge, re-authorization splitting, and captured-row pruning keyed
// them by 5-tuple only, so one VRF/tunnel/incarnation's row could drop or
// re-authorize another's.

func sessionEntryKey13176() dataplane.SessionKey {
	key := dataplane.SessionKey{Protocol: 6, SrcPort: 12345, DstPort: 443}
	copy(key.SrcIP[:], []byte{10, 0, 0, 10})
	copy(key.DstIP[:], []byte{10, 0, 0, 20})
	return key
}

func sessionEntryKeyV613176() dataplane.SessionKeyV6 {
	key := dataplane.SessionKeyV6{Protocol: 6, SrcPort: 12345, DstPort: 443}
	copy(key.SrcIP[:], []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1})
	copy(key.DstIP[:], []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2})
	return key
}

func TestMergeKeepsDistinctVRFSessionRows13176(t *testing.T) {
	key := sessionEntryKey13176()
	previous := &policyInvalidationCapture{
		deleted: capturedSessions{v4: []dataplane.SessionEntryV4{
			{Key: key, Value: dataplane.SessionValue{RoutingDomain: 1, RTFlowSessionID: 101}},
		}},
	}
	current := &policyInvalidationCapture{
		deleted: capturedSessions{v4: []dataplane.SessionEntryV4{
			{Key: key, Value: dataplane.SessionValue{RoutingDomain: 2, RTFlowSessionID: 202}},
		}},
	}
	merged := mergePolicyInvalidationCaptures(previous, current)
	if len(merged.deleted.v4) != 2 {
		t.Fatalf("#13176: merge dropped a distinct-VRF row: got %d rows %+v, want both RoutingDomain 1 and 2",
			len(merged.deleted.v4), merged.deleted.v4)
	}
}

func TestReauthorizeSplitKeysByFullIdentity13176(t *testing.T) {
	key := sessionEntryKey13176()
	tuple := dpuserspace.SessionPolicyTuple{
		AddrFamily: 4, Protocol: 6, SrcIP: "10.0.0.10", DstIP: "10.0.0.20",
		SrcPort: 12345, DstPort: 443,
	}
	// Two helper candidates share the 5-tuple but live in different VRFs.
	// The Tuple carries no routing domain, so both candidates resolve to the
	// same policy verdict; the v4 entries below carry the real per-row
	// identity. The permitted candidate names (via its match) the VRF-1
	// entry's session; the VRF-2 entry must not follow it into permitted.
	permittedMatch := dpuserspace.SessionPolicyMatch{
		AddrFamily: 4, Tuple: tuple, RoutingDomain: 1,
		ExpectedRTFlowSessionID: 101,
		IngressZoneID:           config.StableZoneID("trust"),
		EgressZoneID:            config.StableZoneID("untrust"),
	}
	deniedMatch := dpuserspace.SessionPolicyMatch{
		AddrFamily: 4, Tuple: tuple, RoutingDomain: 2,
		ExpectedRTFlowSessionID: 202,
		IngressZoneID:           config.StableZoneID("trust"),
		EgressZoneID:            config.StableZoneID("untrust"),
	}
	cfg := reauthConfig12879(config.PolicyDeny, []string{"trust", "untrust"},
		&config.ZonePairPolicies{FromZone: "trust", ToZone: "untrust", Policies: []*config.Policy{
			reauthRule12879("wide", config.PolicyPermit, "any"),
		}})
	capture := &policyInvalidationCapture{candidateRuleIDs: map[policyInvalidationMatchIdentity]string{}}
	capture.deleted.policy = []dpuserspace.SessionPolicyMatch{permittedMatch, deniedMatch}
	// Only the VRF-1 candidate's captured identity is bound to a rule that
	// permits it; the VRF-2 candidate has no provenance, so it stays debt.
	capture.candidateRuleIDs[policyInvalidationMatchID(permittedMatch)] = "trust->untrust/wide"
	capture.deleted.v4 = []dataplane.SessionEntryV4{
		{Key: key, Value: dataplane.SessionValue{RoutingDomain: 1, RTFlowSessionID: 101}},
		{Key: key, Value: dataplane.SessionValue{RoutingDomain: 2, RTFlowSessionID: 202}},
	}

	d := &Daemon{}
	kept, permitted := d.reauthorizePolicyCandidates(capture, cfg, false)
	if permitted == nil {
		t.Fatalf("#13176: premise: the permitted candidate must be discharged, got nil permitted (kept=%d)", kept.candidateCount())
	}
	for _, entry := range permitted.deleted.v4 {
		if entry.Value.RoutingDomain == 2 {
			t.Fatalf("#13176: denied VRF-2 entry contaminated into permitted: %+v", permitted.deleted.v4)
		}
	}
	foundKeptVRF2 := false
	for _, entry := range kept.deleted.v4 {
		if entry.Value.RoutingDomain == 2 && entry.Value.RTFlowSessionID == 202 {
			foundKeptVRF2 = true
		}
	}
	if !foundKeptVRF2 {
		t.Fatalf("#13176: denied VRF-2 entry missing from kept debt: kept=%+v permitted=%+v", kept.deleted.v4, permitted.deleted.v4)
	}
}

func TestPruneCapturedPolicyRowsKeepsDistinctVRFRow13176(t *testing.T) {
	key := sessionEntryKey13176()
	tuple := dpuserspace.SessionPolicyTuple{
		AddrFamily: 4, Protocol: 6, SrcIP: "10.0.0.10", DstIP: "10.0.0.20",
		SrcPort: 12345, DstPort: 443,
	}
	unsettled := dpuserspace.SessionPolicyMatch{
		AddrFamily: 4, Tuple: tuple, RoutingDomain: 1,
		ExpectedRTFlowSessionID: 101,
	}
	c := &capturedSessions{
		policy: []dpuserspace.SessionPolicyMatch{unsettled, unsettled},
		v4: []dataplane.SessionEntryV4{
			{Key: key, Value: dataplane.SessionValue{RoutingDomain: 1, RTFlowSessionID: 101}},
			{Key: key, Value: dataplane.SessionValue{RoutingDomain: 2, RTFlowSessionID: 202}},
		},
	}
	// First policy row settled, second still owed: only the VRF-1 entry is
	// backed by the surviving policy row.
	pruneCapturedPolicyRows(c, dpuserspace.PolicyDeleteResult{SettledPrefix: 1}, err13176{})
	if len(c.v4) != 1 || c.v4[0].Value.RoutingDomain != 1 {
		t.Fatalf("#13176: prune kept wrong rows: got %+v, want only RoutingDomain 1", c.v4)
	}
}

func TestPruneCapturedKeepsDistinctVRFRow13176(t *testing.T) {
	key := sessionEntryKey13176()
	key6 := sessionEntryKeyV613176()
	c := &capturedSessions{
		v4: []dataplane.SessionEntryV4{
			{Key: key, Value: dataplane.SessionValue{RoutingDomain: 1, RTFlowSessionID: 101}},
			{Key: key, Value: dataplane.SessionValue{RoutingDomain: 2, RTFlowSessionID: 202}},
		},
		v6: []dataplane.SessionEntryV6{
			{Key: key6, Value: dataplane.SessionValueV6{RoutingDomain: 1, RTFlowSessionID: 101}},
			{Key: key6, Value: dataplane.SessionValueV6{RoutingDomain: 2, RTFlowSessionID: 202}},
		},
	}
	pruneCapturedV4(c, []dataplane.SessionKey{key})
	if len(c.v4) != 1 || c.v4[0].Value.RoutingDomain != 2 {
		t.Fatalf("#13176: exact-v4 prune removed the surviving VRF-2 row: %+v", c.v4)
	}
	pruneCapturedV6(c, []dataplane.SessionKeyV6{key6})
	if len(c.v6) != 1 || c.v6[0].Value.RoutingDomain != 2 {
		t.Fatalf("#13176: exact-v6 prune removed the surviving VRF-2 row: %+v", c.v6)
	}
}

type err13176 struct{}

func (err13176) Error() string { return "partial delete (test)" }
