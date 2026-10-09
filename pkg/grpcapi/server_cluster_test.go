package grpcapi

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// matchPoliciesTestStore builds a config with a single trust->untrust
// policy whose source/destination terms reference a RESTRICTED
// address-book entry (10.0.1.0/24), not "any". This shape proves the
// #1711 false-positive: with the bug a malformed IP collapses to nil
// and matchPolicyAddr returns true even though 10.0.1.0/24 should not
// match arbitrary input.
func matchPoliciesTestStore(t *testing.T) *configstore.Store {
	t.Helper()

	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	if err := store.LoadOverride(`
security {
    address-book {
        global {
            address trust-net 10.0.1.0/24;
        }
    }
    zones {
        security-zone trust;
        security-zone untrust;
    }
    policies {
        from-zone trust to-zone untrust {
            policy restricted-allow {
                match { source-address trust-net; destination-address trust-net; application any; }
                then { permit; }
            }
        }
    }
}
`); err != nil {
		t.Fatalf("LoadOverride() error = %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit() error = %v", err)
	}
	return store
}

func TestMatchPoliciesRejectsInvalidSourceIP(t *testing.T) {
	s := &Server{store: matchPoliciesTestStore(t)}

	resp, err := s.MatchPolicies(context.Background(), &pb.MatchPoliciesRequest{
		FromZone: "trust",
		ToZone:   "untrust",
		SourceIp: "10.0.0.999", // non-empty but unparseable
	})
	if err == nil {
		t.Fatalf("MatchPolicies(invalid source-ip) returned no error; resp = %+v (false-positive #1711)", resp)
	}
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("status code = %v, want InvalidArgument", status.Code(err))
	}
	if resp != nil {
		t.Fatalf("resp = %+v, want nil on InvalidArgument", resp)
	}
}

func TestMatchPoliciesRejectsInvalidDestinationIP(t *testing.T) {
	s := &Server{store: matchPoliciesTestStore(t)}

	resp, err := s.MatchPolicies(context.Background(), &pb.MatchPoliciesRequest{
		FromZone:      "trust",
		ToZone:        "untrust",
		DestinationIp: "not-an-ip",
	})
	if err == nil {
		t.Fatalf("MatchPolicies(invalid destination-ip) returned no error; resp = %+v", resp)
	}
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("status code = %v, want InvalidArgument", status.Code(err))
	}
	if resp != nil {
		t.Fatalf("resp = %+v, want nil on InvalidArgument", resp)
	}
}

// TestMatchPoliciesRejectsCIDRInIPField guards the resolved open
// question: a CIDR in the single-IP field is malformed input and must
// be rejected, not silently wildcarded.
func TestMatchPoliciesRejectsCIDRInIPField(t *testing.T) {
	s := &Server{store: matchPoliciesTestStore(t)}

	_, err := s.MatchPolicies(context.Background(), &pb.MatchPoliciesRequest{
		FromZone: "trust",
		ToZone:   "untrust",
		SourceIp: "10.0.0.0/24",
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("CIDR in source-ip: status code = %v, want InvalidArgument", status.Code(err))
	}
}

// TestMatchPoliciesEmptyIPsMatchAny proves the legitimate Junos "any"
// semantics survive: with both IP fields empty the simulator matches
// the (restricted-term) policy because an unspecified tuple field is
// treated as "any". This is the behavior the #1711 fix must NOT break.
func TestMatchPoliciesEmptyIPsMatchAny(t *testing.T) {
	s := &Server{store: matchPoliciesTestStore(t)}

	resp, err := s.MatchPolicies(context.Background(), &pb.MatchPoliciesRequest{
		FromZone: "trust",
		ToZone:   "untrust",
		// SourceIp / DestinationIp intentionally empty.
	})
	if err != nil {
		t.Fatalf("MatchPolicies(empty IPs) error = %v, want nil", err)
	}
	if !resp.Matched {
		t.Fatalf("empty-IP query did not match; the empty-means-any path regressed")
	}
	if resp.Action != "permit" {
		t.Fatalf("action = %q, want permit", resp.Action)
	}
}

// TestMatchPoliciesValidIPMatches proves the valid path is unaffected:
// a real IP inside the restricted 10.0.1.0/24 term matches.
func TestMatchPoliciesValidIPMatches(t *testing.T) {
	s := &Server{store: matchPoliciesTestStore(t)}

	resp, err := s.MatchPolicies(context.Background(), &pb.MatchPoliciesRequest{
		FromZone:      "trust",
		ToZone:        "untrust",
		SourceIp:      "10.0.1.5",
		DestinationIp: "10.0.1.6",
	})
	if err != nil {
		t.Fatalf("MatchPolicies(valid IPs) error = %v, want nil", err)
	}
	if !resp.Matched || resp.PolicyName != "restricted-allow" {
		t.Fatalf("valid IP inside term did not match expected policy; resp = %+v", resp)
	}
}

// TestMatchPoliciesValidIPOutsideTermNoFalsePositive confirms the
// matcher is actually constrained by the term: a valid IP OUTSIDE
// 10.0.1.0/24 does not match (proving the term restriction is live, so
// the malformed-input rejection closes a real gap rather than masking a
// matcher that always returns true).
func TestMatchPoliciesValidIPOutsideTermNoFalsePositive(t *testing.T) {
	s := &Server{store: matchPoliciesTestStore(t)}

	resp, err := s.MatchPolicies(context.Background(), &pb.MatchPoliciesRequest{
		FromZone:      "trust",
		ToZone:        "untrust",
		SourceIp:      "192.168.99.1",
		DestinationIp: "192.168.99.2",
	})
	if err != nil {
		t.Fatalf("MatchPolicies(valid out-of-term IPs) error = %v, want nil", err)
	}
	if resp.Matched {
		t.Fatalf("out-of-term IP unexpectedly matched; restricted term not enforced: resp = %+v", resp)
	}
}

// TestShowTestPolicyRejectsInvalidIP covers the ShowText "test-policy:"
// simulator (the operational `test policy` command served via gRPC).
// Since #3103 this routes through the shared pkg/policymatch simulator,
// but it must still reject a non-empty malformed IP rather than collapse
// it to a wildcard "any" (the #1711 false-positive): such input must not
// produce a "Policy match" line.
func TestShowTestPolicyRejectsInvalidIP(t *testing.T) {
	s := &Server{store: matchPoliciesTestStore(t)}

	resp, err := s.ShowText(context.Background(), &pb.ShowTextRequest{
		Topic: "test-policy:from=trust,to=untrust,src=10.0.0.999",
	})
	if err != nil {
		t.Fatalf("ShowText(test-policy invalid src) error = %v", err)
	}
	if strings.Contains(resp.Output, "Policy match") {
		t.Fatalf("invalid src produced a policy match (false-positive #1711): %q", resp.Output)
	}
	if !strings.Contains(resp.Output, "invalid src") {
		t.Fatalf("output = %q, want an invalid-src diagnostic", resp.Output)
	}
}

// TestShowTestPolicyEmptyIPMatches proves the ShowText simulator still
// treats empty IPs as "any" (matches the restricted-term policy).
func TestShowTestPolicyEmptyIPMatches(t *testing.T) {
	s := &Server{store: matchPoliciesTestStore(t)}

	resp, err := s.ShowText(context.Background(), &pb.ShowTextRequest{
		Topic: "test-policy:from=trust,to=untrust",
	})
	if err != nil {
		t.Fatalf("ShowText(test-policy empty IPs) error = %v", err)
	}
	if !strings.Contains(resp.Output, "Policy match") || !strings.Contains(resp.Output, "restricted-allow") {
		t.Fatalf("empty-IP test-policy did not match; empty-means-any regressed: %q", resp.Output)
	}
}

// TestMatchPoliciesRejectsInvalidPort asserts the #3116 contract for the gRPC
// surface: a negative or >65535 port in the int32 field must be rejected with
// InvalidArgument, not passed through to the shared matcher as an omitted port.
// A constrained term would then never match, while an unconstrained term may
// still match and yield a misleading verdict. 0 is also unspecified (proto3
// cannot distinguish an unset scalar from 0); a valid port proceeds.
//
// FAIL-ON-REVERT: removing the policymatch.ValidatePort guards in
// MatchPolicies lets DestinationPort=-1 / DestinationPort=70000 reach the
// matcher and return a (false) verdict instead of an error, flipping the
// want-error cases red.
func TestMatchPoliciesRejectsInvalidPort(t *testing.T) {
	s := &Server{store: matchPoliciesTestStore(t)}

	cases := []struct {
		name    string
		req     *pb.MatchPoliciesRequest
		wantErr bool
	}{
		{"dst negative", &pb.MatchPoliciesRequest{FromZone: "trust", ToZone: "untrust", DestinationPort: -1}, true},
		{"dst out of range", &pb.MatchPoliciesRequest{FromZone: "trust", ToZone: "untrust", DestinationPort: 70000}, true},
		{"src negative", &pb.MatchPoliciesRequest{FromZone: "trust", ToZone: "untrust", SourcePort: -1}, true},
		{"src out of range", &pb.MatchPoliciesRequest{FromZone: "trust", ToZone: "untrust", SourcePort: 65536}, true},
		{"dst valid", &pb.MatchPoliciesRequest{FromZone: "trust", ToZone: "untrust", DestinationPort: 443}, false},
		{"dst zero wildcard", &pb.MatchPoliciesRequest{FromZone: "trust", ToZone: "untrust", DestinationPort: 0}, false},
		{"ports absent", &pb.MatchPoliciesRequest{FromZone: "trust", ToZone: "untrust"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := s.MatchPolicies(context.Background(), tc.req)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("%s: returned no error; resp = %+v (invalid port slipped through)", tc.name, resp)
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

// TestShowTestPolicyRejectsInvalidPort covers the #3116 gap on the ShowText
// "test-policy:" simulator (the operational `test policy` command served via
// gRPC, routed through pkg/policymatch since #3103). A malformed or
// out-of-range port must surface an "invalid port" diagnostic and must NOT
// produce a "Policy match" line — a port that silently coerced to the 0
// wildcard would yield a verdict for a packet that cannot exist. A valid port
// and an absent port still evaluate normally.
//
// FAIL-ON-REVERT: restoring `dstPort, _ = strconv.Atoi(parts[1])` in
// showTestPolicy makes "abc"/"70000" coerce to 0/garbage with no diagnostic,
// so the want-"invalid port" cases (and the no-"Policy match" assertion) flip
// red.
func TestShowTestPolicyRejectsInvalidPort(t *testing.T) {
	s := &Server{store: matchPoliciesTestStore(t)}

	cases := []struct {
		name      string
		topic     string
		wantBad   bool // expect "invalid port" diagnostic, no policy match
		wantMatch bool // expect a "Policy match" line (valid path)
	}{
		{"malformed", "test-policy:from=trust,to=untrust,port=abc", true, false},
		{"out of range", "test-policy:from=trust,to=untrust,port=70000", true, false},
		{"valid", "test-policy:from=trust,to=untrust,src=10.0.1.5,dst=10.0.1.6,port=443", false, true},
		{"absent", "test-policy:from=trust,to=untrust,src=10.0.1.5,dst=10.0.1.6", false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := s.ShowText(context.Background(), &pb.ShowTextRequest{Topic: tc.topic})
			if err != nil {
				t.Fatalf("ShowText(%q) error = %v", tc.topic, err)
			}
			if tc.wantBad {
				if !strings.Contains(resp.Output, "invalid port") {
					t.Fatalf("%s: output = %q, want an invalid-port diagnostic", tc.name, resp.Output)
				}
				if strings.Contains(resp.Output, "Policy match") {
					t.Fatalf("%s: invalid port produced a policy match (silent wildcard): %q", tc.name, resp.Output)
				}
				return
			}
			if tc.wantMatch && !strings.Contains(resp.Output, "Policy match") {
				t.Fatalf("%s: output = %q, want a Policy match (valid/absent port regressed)", tc.name, resp.Output)
			}
		})
	}
}
