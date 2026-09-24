package userspace

import (
	"strings"
	"testing"
)

// #10650: a same-incarnation refused_identity — the captured forward is the
// live entry but a companion the capture did not name exists (reply installed
// between the capture READ and the delete batch) — means the revoked forward
// SURVIVED: both Rust envelopes refuse without removing it. Merging that as
// benign stale success violates the #5578 surfaced-gap contract. It must
// surface a gap error, never nil.
func TestDeletePolicySessionsRefusedIdentityGaps10650(t *testing.T) {
	m, sessionSock := newBatchTestManager10512(t)
	fake := startScriptedBatchSocket10512(t, sessionSock, []ControlResponse{
		{OK: true, PolicyDeleteOutcomes: []string{"refused_identity"}, PolicyDeleteComplete: true},
	})
	matches := []SessionPolicyMatch{policyDeleteTestMatch10512(1)}
	result, err := m.DeletePolicySessions(matches)
	if err == nil {
		t.Fatalf("refused_identity must surface a gap error, got nil (result=%+v)", result)
	}
	if !strings.Contains(err.Error(), "INCOMPLETE") {
		t.Errorf("gap error must be labeled INCOMPLETE, got: %v", err)
	}
	if !strings.Contains(strings.ToLower(err.Error()), "refused") {
		t.Errorf("gap error must name the refused outcome, got: %v", err)
	}
	if result.Stale != 0 {
		t.Errorf("refused_identity merged as stale: result=%+v", result)
	}
	if result.Applied != 0 || result.Partial != 0 {
		t.Errorf("nothing was removed: result=%+v", result)
	}
	if got := fake.requestCount(); got != 1 {
		t.Errorf("request count = %d, want 1", got)
	}
}

// #10650 mixed batch: refused_identity must neither absorb its neighbors nor
// be absorbed by them — applied still applies, stale still counts, and the
// batch still gaps loud (revocation-maximizing, like the partial path).
func TestDeletePolicySessionsRefusedIdentityMixedBatch10650(t *testing.T) {
	m, sessionSock := newBatchTestManager10512(t)
	fake := startScriptedBatchSocket10512(t, sessionSock, []ControlResponse{
		{
			OK:                   true,
			PolicyDeleteOutcomes: []string{"applied", "refused_identity", "stale_forward"},
			PolicyDeleteComplete: true,
		},
	})
	matches := []SessionPolicyMatch{
		policyDeleteTestMatch10512(1),
		policyDeleteTestMatch10512(2),
		policyDeleteTestMatch10512(3),
	}
	result, err := m.DeletePolicySessions(matches)
	if err == nil {
		t.Fatalf("a batch containing refused_identity must surface a gap error, got nil (result=%+v)", result)
	}
	if !strings.Contains(err.Error(), "INCOMPLETE") {
		t.Errorf("gap error must be labeled INCOMPLETE, got: %v", err)
	}
	if result.Applied != 1 || result.Stale != 1 || result.Partial != 0 {
		t.Errorf("result = %+v, want {Applied:1 Stale:1 Partial:0} plus a refused gap", result)
	}
	if got := fake.requestCount(); got != 1 {
		t.Errorf("request count = %d, want 1", got)
	}
}
