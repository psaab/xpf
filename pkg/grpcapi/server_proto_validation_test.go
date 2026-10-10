package grpcapi

import (
	"context"
	"strings"
	"testing"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// TestMatchPoliciesRejectsInvalidProtocol asserts the #3108 contract for the
// gRPC MatchPolicies surface: a non-empty but unknown/out-of-range protocol
// token must be rejected with InvalidArgument, not passed through as unspecified.
// Constrained terms would never match it, but an `application any` term may
// still match. An empty protocol stays unspecified; a valid name/number proceeds.
//
// FAIL-ON-REVERT: removing the policymatch.ValidateProtocol guard in
// MatchPolicies lets Protocol="tcpp"/"999" reach the matcher and return a
// verdict instead of an error, flipping the want-error cases red.
func TestMatchPoliciesRejectsInvalidProtocol(t *testing.T) {
	s := &Server{store: matchPoliciesTestStore(t)}

	cases := []struct {
		name    string
		proto   string
		wantErr bool
	}{
		{"unknown name", "notaproto", true},
		{"typo", "tcpp", true},
		{"out of range", "999", true},
		{"valid name", "tcp", false},
		{"valid number", "6", false},
		{"absent wildcard", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := &pb.MatchPoliciesRequest{FromZone: "trust", ToZone: "untrust", Protocol: tc.proto}
			resp, err := s.MatchPolicies(context.Background(), req)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("%s: returned no error; resp = %+v (invalid protocol slipped through)", tc.name, resp)
				}
				if status.Code(err) != codes.InvalidArgument {
					t.Fatalf("%s: status code = %v, want InvalidArgument", tc.name, status.Code(err))
				}
				if resp != nil {
					t.Fatalf("%s: resp = %+v, want nil on InvalidArgument", tc.name, resp)
				}
				return
			}
			if err != nil {
				t.Fatalf("%s: error = %v, want nil", tc.name, err)
			}
		})
	}
}

// TestShowTestPolicyRejectsInvalidProtocol covers the #3108 gap on the ShowText
// "test-policy:" simulator (the operational `test policy` served via gRPC). An
// unknown/out-of-range protocol token must surface an "invalid protocol"
// diagnostic and must NOT produce a "Policy match" line — an unresolvable
// protocol that silently coerced to the match-any wildcard would yield a
// verdict for traffic that cannot exist. A valid protocol and an absent one
// still evaluate normally.
//
// FAIL-ON-REVERT: dropping the protoErr = policymatch.ValidateProtocol(...)
// branch in showTestPolicy makes "tcpp"/"999" pass straight into the matcher
// with no diagnostic, flipping the want-"invalid protocol" cases (and the
// no-"Policy match" assertion) red.
func TestShowTestPolicyRejectsInvalidProtocol(t *testing.T) {
	s := &Server{store: matchPoliciesTestStore(t)}

	cases := []struct {
		name      string
		topic     string
		wantBad   bool
		wantMatch bool
	}{
		{"unknown name", "test-policy:from=trust,to=untrust,proto=notaproto", true, false},
		{"typo", "test-policy:from=trust,to=untrust,proto=tcpp", true, false},
		{"out of range", "test-policy:from=trust,to=untrust,proto=999", true, false},
		{"valid name", "test-policy:from=trust,to=untrust,src=10.0.1.5,dst=10.0.1.6,proto=tcp", false, true},
		{"valid number", "test-policy:from=trust,to=untrust,src=10.0.1.5,dst=10.0.1.6,proto=6", false, true},
		{"absent", "test-policy:from=trust,to=untrust,src=10.0.1.5,dst=10.0.1.6", false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := s.ShowText(context.Background(), &pb.ShowTextRequest{Topic: tc.topic})
			if err != nil {
				t.Fatalf("ShowText(%q) error = %v", tc.topic, err)
			}
			if tc.wantBad {
				if !strings.Contains(resp.Output, "invalid protocol") {
					t.Fatalf("%s: output = %q, want an invalid-protocol diagnostic", tc.name, resp.Output)
				}
				if strings.Contains(resp.Output, "Policy match") {
					t.Fatalf("%s: invalid protocol produced a policy match (silent wildcard): %q", tc.name, resp.Output)
				}
				return
			}
			if tc.wantMatch && !strings.Contains(resp.Output, "Policy match") {
				t.Fatalf("%s: output = %q, want a Policy match (valid/absent protocol regressed)", tc.name, resp.Output)
			}
		})
	}
}
