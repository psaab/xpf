package grpcapi

import (
	"context"
	"testing"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"github.com/psaab/xpf/pkg/policymatch"
)

// TestMatchPoliciesHostOriginated16805 pins #16805 on the gRPC surface: a
// `from-zone junos-host` query must return the typed host_originated flag
// with HostOriginatedActionString, NOT the unknown-ingress-zone deny. The
// `from-zone nosuch` and `to-zone junos-host` controls are unchanged.
//
// FAIL-ON-REVERT: removing the policymatch host-originated arm (or the
// HostOriginated copy in MatchPolicies) makes the junos-host row return
// unzoned_ingress / the wrong action.
func TestMatchPoliciesHostOriginated16805(t *testing.T) {
	s := &Server{store: hostInboundStore(t)}

	resp, err := s.MatchPolicies(context.Background(), &pb.MatchPoliciesRequest{
		FromZone: "junos-host", ToZone: "untrust",
	})
	if err != nil {
		t.Fatalf("MatchPolicies error = %v", err)
	}
	if !resp.HostOriginated || resp.UnzonedIngress || resp.UnzonedEgress || resp.Matched || resp.DefaultUsed || resp.HostInboundUnmatched {
		t.Fatalf("from-zone junos-host must be host_originated only, got %+v", resp)
	}
	if resp.Action != policymatch.HostOriginatedActionString {
		t.Fatalf("Action = %q, want HostOriginatedActionString %q", resp.Action, policymatch.HostOriginatedActionString)
	}

	// Control: genuinely unknown from-zone unchanged.
	nosuch, err := s.MatchPolicies(context.Background(), &pb.MatchPoliciesRequest{
		FromZone: "nosuch", ToZone: "untrust",
	})
	if err != nil {
		t.Fatalf("MatchPolicies error = %v", err)
	}
	if nosuch.HostOriginated || !nosuch.UnzonedIngress || nosuch.Action != policymatch.UnzonedIngressActionString {
		t.Fatalf("from-zone nosuch control changed, got %+v", nosuch)
	}

	// Control: host-bound to-zone unchanged.
	hi, err := s.MatchPolicies(context.Background(), &pb.MatchPoliciesRequest{
		FromZone: "trust", ToZone: "junos-host",
	})
	if err != nil {
		t.Fatalf("MatchPolicies error = %v", err)
	}
	if hi.HostOriginated || !hi.HostInboundUnmatched || hi.Action != policymatch.HostInboundActionString {
		t.Fatalf("to-zone junos-host control changed, got %+v", hi)
	}
}
