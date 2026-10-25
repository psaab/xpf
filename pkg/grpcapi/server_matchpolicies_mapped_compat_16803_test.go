package grpcapi

import (
	"context"
	"testing"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"github.com/psaab/xpf/pkg/policymatch"
)

// #16803: a v4-mapped/compatible IPv6 tuple must surface on gRPC as the
// typed ingress-drop verdict (proto field 35 + the SSOT action string),
// not as the permit the zone-pair policy would otherwise certify — the
// dataplane drops the frame at ingress before policy (#10686).
//
// RED on revert: drop the V4MappedCompatIngressDrop branch in
// server_cluster.go (or the Match gate) and the mapped query returns
// Matched=true / action "permit" — the assertions below fail.
func TestMatchPoliciesGRPCV4MappedCompatIngressDrop16803(t *testing.T) {
	s := &Server{store: hostInboundStore(t)}

	resp, err := s.MatchPolicies(context.Background(), &pb.MatchPoliciesRequest{
		FromZone: "trust", ToZone: "untrust",
		SourceIp: "::ffff:192.0.2.1", DestinationIp: "2001:db8::1",
		Protocol: "tcp", DestinationPort: 80,
	})
	if err != nil {
		t.Fatalf("MatchPolicies error = %v", err)
	}
	if !resp.GetV4MappedCompatIngressDrop() {
		t.Fatalf("V4MappedCompatIngressDrop = false, want true; got %+v", resp)
	}
	if resp.Matched || resp.DefaultUsed {
		t.Fatalf("ingress-drop verdict must not report matched/default: %+v", resp)
	}
	if resp.Action != policymatch.V4MappedCompatIngressDropActionString {
		t.Fatalf("Action = %q, want V4MappedCompatIngressDropActionString", resp.Action)
	}

	// Control: an ordinary v6 tuple still permits via the zone-pair rule.
	ctrl, err := s.MatchPolicies(context.Background(), &pb.MatchPoliciesRequest{
		FromZone: "trust", ToZone: "untrust",
		SourceIp: "2001:db8::9", DestinationIp: "2001:db8::1",
		Protocol: "tcp", DestinationPort: 80,
	})
	if err != nil {
		t.Fatalf("MatchPolicies control error = %v", err)
	}
	if ctrl.GetV4MappedCompatIngressDrop() || !ctrl.Matched {
		t.Fatalf("ordinary v6 control must permit unmatched by the gate: %+v", ctrl)
	}
}
