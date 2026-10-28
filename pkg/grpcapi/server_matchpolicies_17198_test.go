package grpcapi

import (
	"context"
	"path/filepath"
	"testing"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// TestMatchPoliciesGRPCNilConfigGrammar17198 is the #17198 RED-on-revert
// guard for divergence 1: gRPC returned the no-config default-deny BEFORE
// grammar validation, so malformed boot-window queries got a 200-equivalent
// verdict while REST returned 400 (#3709 fixed REST only). Shared
// (Request).Validate now runs before the cfg==nil verdict on both surfaces.
//
// FAIL-ON-REVERT: restoring the cfg==nil early return above validation
// makes every malformed case return err=nil + default-deny.
func TestMatchPoliciesGRPCNilConfigGrammar17198(t *testing.T) {
	s := &Server{store: newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))}
	if s.store.ActiveConfig() != nil {
		t.Skip("active config is not nil")
	}
	badPort := int32(70000)
	cases := []*pb.MatchPoliciesRequest{
		{},
		{FromZone: "trust", ToZone: "untrust", SourceIp: "not-an-ip"},
		{FromZone: "trust", ToZone: "untrust", DestinationPort: &badPort},
		{FromZone: "trust", ToZone: "untrust", Protocol: "tcpp"},
	}
	for i, req := range cases {
		resp, err := s.MatchPolicies(context.Background(), req)
		if status.Code(err) != codes.InvalidArgument || resp != nil {
			t.Fatalf("case %d: err=%v resp=%+v, want InvalidArgument/nil", i, err, resp)
		}
	}
	// Well-formed boot-window query still gets the fail-closed default deny.
	resp, err := s.MatchPolicies(context.Background(), &pb.MatchPoliciesRequest{FromZone: "trust", ToZone: "untrust"})
	if err != nil || resp == nil || !resp.DefaultUsed || resp.Action != "deny (default)" {
		t.Fatalf("well-formed nil-config = %+v, %v", resp, err)
	}
	// Config-present unsupported tuple carries the typed bit (control).
	s2 := &Server{store: matchPoliciesTestStore(t)}
	resp, err = s2.MatchPolicies(context.Background(), &pb.MatchPoliciesRequest{FromZone: "trust", ToZone: "untrust", SourceIp: "192.0.2.1", DestinationIp: "2001:db8::1"})
	if err != nil || resp == nil || !resp.UnsupportedTupleFamily {
		t.Fatalf("unsupported tuple = %+v, %v", resp, err)
	}
}
