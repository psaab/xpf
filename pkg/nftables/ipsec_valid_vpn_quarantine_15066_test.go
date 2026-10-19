package nftables

import (
	"testing"
)

// #15066 A35-01: CandidateIfindices alone (no QuarantineAll, no reason
// mask/raw/primary) is bookkeeping for a possible future quarantine deny
// list, not a quarantine request. A valid route-based VPN stages its
// ifindex as a candidate; reading that as a request installed the
// box-wide DROP guard for every valid commit.

func TestIpsecCandidateOnlySpecIsNotQuarantine15066(t *testing.T) {
	spec := normalizeIpsecQuarantineSpec(IpsecDivertSpec{
		InetForward:        []IpsecDivertRule{{Ifname: "st0", Queue: 1001}},
		InetInput:          []IpsecDivertRule{{Ifname: "st0", Queue: 1002}},
		BridgeForward:      []IpsecDivertRule{{Ifname: "st0", Queue: 1003}},
		BridgeInput:        []IpsecDivertRule{{Ifname: "st0", Queue: 1004}},
		CandidateIfindices: []uint32{17},
		LifelineNetdevs:    []string{"fxp0"},
	})
	if spec.QuarantineAll {
		t.Fatalf("candidate-only spec quarantined: %+v", spec)
	}
	if len(spec.CandidateIfindices) != 0 {
		t.Fatalf("candidate-only spec retained candidates %v, want cleared when not quarantined", spec.CandidateIfindices)
	}
	if len(spec.LifelineNetdevs) != 0 {
		t.Fatalf("candidate-only spec retained lifelines %v, want cleared when not quarantined", spec.LifelineNetdevs)
	}
	if len(spec.InetForward) != 1 || len(spec.InetInput) != 1 || len(spec.BridgeForward) != 1 || len(spec.BridgeInput) != 1 {
		t.Fatalf("candidate-only spec lost divert rules: %+v", spec)
	}
	if err := validateIpsecDivertSpec(spec); err != nil {
		t.Fatalf("candidate-only spec rejected: %v", err)
	}
}

// Control: an explicit quarantine reason with candidates still quarantines
// and retains the (sorted, deduped) candidate deny list.
func TestIpsecQuarantineReasonRetainsCandidates15066(t *testing.T) {
	spec := normalizeIpsecQuarantineSpec(IpsecDivertSpec{
		QuarantineReasonMask: IpsecQuarantineMaskLinkLookup,
		CandidateIfindices:   []uint32{17, 3, 17},
		InetForward:          []IpsecDivertRule{{Ifname: "st0", Queue: 1001}},
	})
	if !spec.QuarantineAll {
		t.Fatalf("reasoned spec not quarantined: %+v", spec)
	}
	if len(spec.CandidateIfindices) != 2 || spec.CandidateIfindices[0] != 3 || spec.CandidateIfindices[1] != 17 {
		t.Fatalf("reasoned candidates = %v, want [3 17]", spec.CandidateIfindices)
	}
	if len(spec.InetForward) != 0 {
		t.Fatalf("reasoned spec retained admission rules: %+v", spec)
	}
}
