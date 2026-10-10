package main

import (
	"strings"
	"testing"
)

// TestShowMatchPoliciesRejectsInvalidPort covers the #3354 gap on the remote
// CLI surface: `show security match-policies source-port/destination-port` was
// parsed with an assign-on-success-only strconv.Atoi, so a malformed/out-of-
// range token was silently dropped and the field stayed unspecified. A
// constrained term would not match, but an unconstrained term could still match,
// allowing a skipped deny to reach a later permit. The remote CLI then asked the
// server for a partial query whose verdict was not exhaustive. The local CLI and
// `test policy` already route through policymatch.ParsePort; the remote CLI must
// too, returning an explicit error before any RPC.
//
// FAIL-ON-REVERT: restoring the inline `if v, err := strconv.Atoi(...); err ==
// nil (no error) and silently left the field unspecified, turning the assertions
// red.
func TestShowMatchPoliciesRejectsInvalidPort(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"dst non-numeric", []string{"from-zone", "trust", "to-zone", "untrust", "destination-port", "abc"}, "destination-port"},
		{"dst out of range", []string{"from-zone", "trust", "to-zone", "untrust", "destination-port", "70000"}, "destination-port"},
		{"dst negative", []string{"from-zone", "trust", "to-zone", "untrust", "destination-port", "-1"}, "destination-port"},
		{"src non-numeric", []string{"from-zone", "trust", "to-zone", "untrust", "source-port", "xyz"}, "source-port"},
		{"src out of range", []string{"from-zone", "trust", "to-zone", "untrust", "source-port", "65536"}, "source-port"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake := &fakeBpfrxClient{}
			c := &ctl{client: fake}
			err := c.showMatchPolicies(tc.args)
			if err == nil {
				t.Fatalf("showMatchPolicies(%v) err = nil, want an invalid-port diagnostic", tc.args)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("showMatchPolicies(%v) err = %v, want a %q diagnostic", tc.args, err, tc.want)
			}
			if fake.matchPoliciesCalls != 0 {
				t.Fatalf("MatchPolicies issued %d times on invalid input; want 0", fake.matchPoliciesCalls)
			}
		})
	}
}

// TestShowMatchPoliciesAcceptsValidPort confirms the fix does not break a valid
// port: a well-formed destination-port parses and reaches the RPC.
func TestShowMatchPoliciesAcceptsValidPort(t *testing.T) {
	fake := &fakeBpfrxClient{
		matchPoliciesResp: nil, // default-zero response renders fine
	}
	c := &ctl{client: fake}
	_ = captureStdout(t, func() {
		if err := c.showMatchPolicies([]string{"from-zone", "trust", "to-zone", "untrust", "destination-port", "443"}); err != nil {
			t.Fatalf("showMatchPolicies(valid port) err = %v, want nil", err)
		}
	})
	if fake.matchPoliciesCalls != 1 {
		t.Fatalf("MatchPolicies called %d times on valid input, want 1", fake.matchPoliciesCalls)
	}
}
