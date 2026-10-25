package userspace

import (
	"testing"

)

// Test_3063_RuntimePolicyIDsMatchSnapshot verifies the exported display helper
// returns, keyed by (policySetID, sliceIndex), the SAME span-accumulated policy
// ID that buildPolicySnapshots assigns to PolicyRuleSnapshot.PolicyID. This is
// the SSOT the CLI policy-detail Index render consumes (#3063) so the displayed
// Index never drifts from the runtime/RT_FLOW policy ID after a multi-app policy.
func Test_3063_RuntimePolicyIDsMatchSnapshot(t *testing.T) {
	cfg := multiAppExpansionConfig()

	ids := RuntimePolicyIDs(cfg)

	// Zone-pair set 0: allow-web (slice 0) expands to 2, allow-ssh (slice 1)
	// therefore occupies span-accumulated slot 2 — NOT the raw ordinal 1.
	if got := ids[[2]uint32{0, 0}]; got != 0 {
		t.Fatalf("allow-web runtime ID = %d, want 0", got)
	}
	if got := ids[[2]uint32{0, 1}]; got != 2 {
		t.Fatalf("allow-ssh runtime ID = %d, want 2 (span-accumulated, not raw ordinal 1)", got)
	}
	// Global set occupies policy-set index len(Policies)=1, contiguous base 3 (#16560: 2+1 expanded).
	if got := ids[[2]uint32{1, 0}]; got != 3 {
		t.Fatalf("global-allow runtime ID = %d, want 3", got)
	}

	// Cross-check against the authoritative snapshot PolicyID assignment.
	snaps, err := buildPolicySnapshots(cfg)
	if err != nil {
		t.Fatalf("buildPolicySnapshots: %v", err)
	}
	byName := map[string]uint32{}
	for _, s := range snaps {
		byName[s.Name] = s.PolicyID
	}
	if ids[[2]uint32{0, 1}] != byName["allow-ssh"] {
		t.Fatalf("RuntimePolicyIDs allow-ssh=%d disagrees with snapshot PolicyID=%d",
			ids[[2]uint32{0, 1}], byName["allow-ssh"])
	}
	if ids[[2]uint32{1, 0}] != byName["global-allow"] {
		t.Fatalf("RuntimePolicyIDs global-allow=%d disagrees with snapshot PolicyID=%d",
			ids[[2]uint32{1, 0}], byName["global-allow"])
	}
}
