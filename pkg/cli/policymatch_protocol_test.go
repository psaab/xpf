package cli

import (
	"strings"
	"testing"
)

// TestTestPolicyRejectsInvalidProtocol asserts the #3108 contract for the CLI
// `test policy` surface: a non-empty but unknown/out-of-range protocol token
// must return an error, not be treated as unspecified. Constrained terms would
// never match it, but the fixture's `application any` term may still match. A
// valid name/number and an absent protocol proceed without error.
//
// FAIL-ON-REVERT: removing the policymatch.ValidateProtocol guard in testPolicy
// lets "notaproto"/"999" pass into the matcher with no error, flipping the
// want-error cases red.
func TestTestPolicyRejectsInvalidProtocol(t *testing.T) {
	c := newPolicyMatchCLIStore(t)

	cases := []struct {
		name    string
		args    []string
		wantErr bool
	}{
		{"unknown name", []string{"from-zone", "trust", "to-zone", "untrust", "protocol", "notaproto"}, true},
		{"typo", []string{"from-zone", "trust", "to-zone", "untrust", "protocol", "tcpp"}, true},
		{"out of range", []string{"from-zone", "trust", "to-zone", "untrust", "protocol", "999"}, true},
		{"valid name", []string{"from-zone", "trust", "to-zone", "untrust", "protocol", "tcp"}, false},
		{"valid number", []string{"from-zone", "trust", "to-zone", "untrust", "protocol", "6"}, false},
		{"absent", []string{"from-zone", "trust", "to-zone", "untrust"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var err error
			captureStdout(t, func() { err = c.testPolicy(tc.args) })
			if (err != nil) != tc.wantErr {
				t.Fatalf("testPolicy(%v) err = %v, wantErr = %v", tc.args, err, tc.wantErr)
			}
			if tc.wantErr && !strings.Contains(err.Error(), "protocol") {
				t.Fatalf("testPolicy(%v) err = %v, want a protocol diagnostic", tc.args, err)
			}
		})
	}
}

// TestShowMatchPoliciesRejectsInvalidProtocol asserts the #3108 contract for
// the CLI `show security match-policies` surface.
//
// FAIL-ON-REVERT: removing the policymatch.ValidateProtocol guard in
// showMatchPolicies makes the invalid-protocol cases proceed with no error,
// flipping them red.
func TestShowMatchPoliciesRejectsInvalidProtocol(t *testing.T) {
	c := newPolicyMatchCLIStore(t)
	cfg := c.store.ActiveConfig()
	if cfg == nil {
		t.Fatal("ActiveConfig() = nil")
	}

	cases := []struct {
		name    string
		args    []string
		wantErr bool
	}{
		{"unknown name", []string{"from-zone", "trust", "to-zone", "untrust", "protocol", "notaproto"}, true},
		{"out of range", []string{"from-zone", "trust", "to-zone", "untrust", "protocol", "999"}, true},
		{"valid name", []string{"from-zone", "trust", "to-zone", "untrust", "protocol", "udp"}, false},
		{"valid number", []string{"from-zone", "trust", "to-zone", "untrust", "protocol", "17"}, false},
		{"absent", []string{"from-zone", "trust", "to-zone", "untrust"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var err error
			captureStdout(t, func() { err = c.showMatchPolicies(cfg, tc.args) })
			if (err != nil) != tc.wantErr {
				t.Fatalf("showMatchPolicies(%v) err = %v, wantErr = %v", tc.args, err, tc.wantErr)
			}
			if tc.wantErr && !strings.Contains(err.Error(), "protocol") {
				t.Fatalf("showMatchPolicies(%v) err = %v, want a protocol diagnostic", tc.args, err)
			}
		})
	}
}
