package grpcapi

import (
	"context"
	"strings"
	"testing"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// TestShowTestPolicyStrictGrammar is the #3696 RED-on-revert guard for the gRPC
// ShowText "test-policy:" bridge (the server-boundary sibling of the strict CLI
// parser). The old handler used `if len(parts) != 2 { continue }` and had no
// default arm, so a comma segment lacking `key=value` left its query dimension
// unspecified (`...,port` left the destination port absent; `prot=tcp` left the
// protocol absent). A constrained term would not match, while an unconstrained
// term might; a skipped deny could let a later permit match. An explicit-empty
// typed value (`port=`) also read as omitted (ParsePort("") -> (0, nil)). These
// defects silently produced a non-exhaustive partial-query verdict.
//
// FAIL-ON-REVERT: removing the malformed-segment / empty-value / default-arm
// handling makes these inputs evaluate a partial query and print a "Policy
// match" (or a default verdict) with no diagnostic, flipping the assertions red.
func TestShowTestPolicyStrictGrammar(t *testing.T) {
	s := &Server{store: matchPoliciesTestStore(t)}
	cases := []struct {
		name    string
		topic   string
		wantBad string // substring wanted in output; "" = want a Policy match
	}{
		{"missing = segment", "test-policy:from=trust,to=untrust,port", "malformed"},
		{"unknown key", "test-policy:from=trust,to=untrust,prot=tcp", "unknown selector"},
		{"empty typed value", "test-policy:from=trust,to=untrust,port=", "malformed"},
		{"valid", "test-policy:from=trust,to=untrust,src=10.0.1.5,dst=10.0.1.6,proto=tcp", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := s.ShowText(context.Background(), &pb.ShowTextRequest{Topic: tc.topic})
			if err != nil {
				t.Fatalf("ShowText(%q) err = %v", tc.topic, err)
			}
			if tc.wantBad == "" {
				if !strings.Contains(resp.Output, "Policy match") {
					t.Fatalf("%s: output = %q, want a Policy match (valid grammar regressed)", tc.name, resp.Output)
				}
				return
			}
			if !strings.Contains(resp.Output, tc.wantBad) {
				t.Fatalf("%s: output = %q, want a %q diagnostic", tc.name, resp.Output, tc.wantBad)
			}
			if strings.Contains(resp.Output, "Policy match") {
				t.Fatalf("%s: malformed grammar produced a policy match (silent widen): %q", tc.name, resp.Output)
			}
		})
	}
}

// TestShowTestPolicyBareTopicStillMissingZones proves a bare `test-policy:`
// (empty params) is NOT reported as malformed grammar — it falls through to the
// existing missing-from/to-zone diagnostic (the #3696 params!="" gate), so the
// hardening does not turn a legitimate no-selector invocation into an error.
func TestShowTestPolicyBareTopicStillMissingZones(t *testing.T) {
	s := &Server{store: matchPoliciesTestStore(t)}
	resp, err := s.ShowText(context.Background(), &pb.ShowTextRequest{Topic: "test-policy:"})
	if err != nil {
		t.Fatalf("ShowText(bare topic) err = %v", err)
	}
	if strings.Contains(resp.Output, "malformed") {
		t.Fatalf("bare topic wrongly reported malformed: %q", resp.Output)
	}
	if !strings.Contains(resp.Output, "Missing from/to zone") {
		t.Fatalf("bare topic output = %q, want a missing-from/to-zone diagnostic", resp.Output)
	}
}
