package main

import (
	"strings"
	"testing"
)

// TestMatchPoliciesUsageAdvertisesSelectors is the #3628 call-site RED-on-revert
// guard for the REMOTE CLI. With the required from-zone/to-zone missing, both
// `show security match-policies` and `test policy` print the usage/help block
// before issuing any RPC. That block must advertise every selector the request
// parser accepts (source-port, icmp-type, icmp-code, protocol by name/number),
// not the stale tcp|udp-only subset.
//
// FAIL-ON-REVERT: re-hard-coding the old two-line "protocol <tcp|udp>" usage at
// the call site (bypassing the shared policymatch constant) drops these tokens
// and fails the assertions.
func TestMatchPoliciesUsageAdvertisesSelectors(t *testing.T) {
	wantTokens := []string{
		"source-port", "destination-port", "icmp-type", "icmp-code", "icmp6",
		"omitted source/destination IP matches", "any address.",
		"An omitted protocol, port, or icmp-type/code fails closed",
		"application term constrained on that dimension",
	}

	// No zones -> usage is printed, no RPC issued, so an empty client suffices.
	fake := &fakeBpfrxClient{}
	c := &ctl{client: fake}

	cases := []struct {
		name string
		run  func() error
	}{
		{"show security match-policies", func() error { return c.showMatchPolicies(nil) }},
		{"test policy", func() error { return c.testPolicy(nil) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := captureStdout(t, func() {
				if err := tc.run(); err != nil {
					t.Fatalf("%s: %v", tc.name, err)
				}
			})
			if strings.Contains(out, "protocol <tcp|udp>") {
				t.Fatalf("%s still prints the stale tcp|udp-only usage:\n%s", tc.name, out)
			}
			for _, tok := range wantTokens {
				if !strings.Contains(out, tok) {
					t.Fatalf("%s usage missing selector %q:\n%s", tc.name, tok, out)
				}
			}
		})
	}
	if fake.matchPoliciesCalls != 0 {
		t.Fatalf("usage path issued %d MatchPolicies RPCs; want 0", fake.matchPoliciesCalls)
	}
}
