package main

import (
	"strings"
	"testing"
)

// TestRemotePolicySimulatorStrictParse is the #3696 RED-on-revert guard for the
// REMOTE CLI `show security match-policies` and `test policy` surfaces. Both used
// a per-surface `if i+1 < len(args)` loop with no default arm, so a value-taking
// selector present WITHOUT a value silently widened the query and an unknown
// selector token was silently dropped — the remote CLI then forwarded a broader
// query than the operator typed to the typed MatchPolicies RPC / test-policy
// topic. Both now route through the strict SSOT policymatch.ParseSelectorArgs and
// fail closed BEFORE any RPC.
//
// FAIL-ON-REVERT: restoring the loose per-surface loop lets the malformed inputs
// build a request/topic and dial the backend with no error, flipping the
// want-error + no-RPC assertions red.
func TestRemotePolicySimulatorStrictParse(t *testing.T) {
	rejectCases := []struct {
		name    string
		args    []string
		wantErr string
	}{
		{"missing value trailing selector", []string{"from-zone", "trust", "to-zone", "untrust", "destination-port"}, "requires a value"},
		{"unknown selector typo", []string{"from-zone", "trust", "to-zone", "untrust", "protcol", "tcp"}, "unknown selector"},
		{"empty typed value", []string{"from-zone", "trust", "to-zone", "untrust", "destination-port", ""}, "requires a value"},
	}
	for _, tc := range rejectCases {
		t.Run("show/"+tc.name, func(t *testing.T) {
			fake := &fakeBpfrxClient{}
			c := &ctl{client: fake}
			err := c.showMatchPolicies(tc.args)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("showMatchPolicies(%v) err = %v, want %q", tc.args, err, tc.wantErr)
			}
			if fake.matchPoliciesCalls != 0 {
				t.Fatalf("MatchPolicies issued %d times on malformed input; want 0", fake.matchPoliciesCalls)
			}
		})
		t.Run("test/"+tc.name, func(t *testing.T) {
			fake := &fakeBpfrxClient{}
			c := &ctl{client: fake}
			err := c.testPolicy(tc.args)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("testPolicy(%v) err = %v, want %q", tc.args, err, tc.wantErr)
			}
			if fake.showTextCalls != 0 {
				t.Fatalf("ShowText issued %d times on malformed input; want 0", fake.showTextCalls)
			}
		})
	}

	// Valid queries still reach the backend on both surfaces.
	t.Run("show valid reaches RPC", func(t *testing.T) {
		fake := &fakeBpfrxClient{}
		c := &ctl{client: fake}
		_ = captureStdout(t, func() {
			if err := c.showMatchPolicies([]string{"from-zone", "trust", "to-zone", "untrust", "protocol", "tcp", "destination-port", "443"}); err != nil {
				t.Fatalf("valid showMatchPolicies err = %v", err)
			}
		})
		if fake.matchPoliciesCalls != 1 {
			t.Fatalf("MatchPolicies called %d times on valid input, want 1", fake.matchPoliciesCalls)
		}
		if got := fake.matchPoliciesReq; got == nil || got.FromZone != "trust" || got.Protocol != "tcp" || (got.DestinationPort == nil || *got.DestinationPort != 443) {
			t.Fatalf("MatchPolicies req = %+v, want trust/tcp/443", got)
		}
	})
	t.Run("test valid reaches RPC and builds a well-formed topic", func(t *testing.T) {
		fake := &fakeBpfrxClient{}
		c := &ctl{client: fake}
		_ = captureStdout(t, func() {
			if err := c.testPolicy([]string{"from-zone", "trust", "to-zone", "untrust", "protocol", "tcp", "destination-port", "443"}); err != nil {
				t.Fatalf("valid testPolicy err = %v", err)
			}
		})
		if fake.showTextCalls != 1 {
			t.Fatalf("ShowText called %d times on valid input, want 1", fake.showTextCalls)
		}
		// The client-built topic must be exactly what the hardened server-side
		// parser accepts (round-trip: known keys, non-empty values).
		for _, want := range []string{"from=trust", "to=untrust", "proto=tcp", "port=443"} {
			if !strings.Contains(fake.showTextTopic, want) {
				t.Fatalf("test-policy topic %q missing %q", fake.showTextTopic, want)
			}
		}
	})
}
