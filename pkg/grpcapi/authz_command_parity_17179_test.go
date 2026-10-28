package grpcapi

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// #17179 Divergence A through the REAL gRPC gate: MatchPolicies with a
// protocol (and optionally a port) but NO zones/IPs used to return the
// bare charge from matchPoliciesArgumentForms, dropping every selector,
// so an argument-scoped deny never fired — while REST and the on-box
// line denied. The early return is deleted in pkg/argforms.MatchForms.
//
// FAIL-ON-REVERT: restoring the no-zone/no-IP bare-charge return makes
// the wantDeny cells below ALLOWED again.
func TestMatchPoliciesNoZoneParityGRPC17179(t *testing.T) {
	zero := int32(0)
	twentytwo := int32(22)
	for _, tc := range []struct {
		name, pattern string
		req           *pb.MatchPoliciesRequest
		wantDeny      bool
	}{
		{"protocol no zones denied", `protocol tcp`, &pb.MatchPoliciesRequest{Protocol: "tcp"}, true},
		{"protocol no zones other allowed", `protocol tcp`, &pb.MatchPoliciesRequest{Protocol: "udp"}, false},
		{"protocol and dport no zones denied", `protocol tcp`, &pb.MatchPoliciesRequest{Protocol: "tcp", DestinationPort: &twentytwo}, true},
		{"fragment no zones denied", `non-first-fragment`, &pb.MatchPoliciesRequest{NonFirstFragment: true}, true},
		{"ingress interface no zones denied", `ingress-interface ge-0/0/0`, &pb.MatchPoliciesRequest{IngressInterface: "ge-0/0/0"}, true},
		{"dst port zero no zones denied", `destination-port 0`, &pb.MatchPoliciesRequest{DestinationPort: &zero}, true},
		{"no selectors bare denied", `^show security match-policies$`, &pb.MatchPoliciesRequest{}, true},
		{"zones still denied", `^show security match-policies from-zone trust to-zone secret-zone$`, &pb.MatchPoliciesRequest{FromZone: "trust", ToZone: "secret-zone"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := cfg16067(t, tc.pattern, "")
			err := gateDecide7172(t, cfg, "MatchPolicies", tc.req)
			if tc.wantDeny && err == nil {
				t.Errorf("deny %q over MatchPolicies %+v was ALLOWED on gRPC; the no-zone selectors must be judged (#17179)", tc.pattern, tc.req)
			}
			if !tc.wantDeny && err != nil {
				t.Errorf("deny %q over MatchPolicies refused a command it does not name: %v", tc.pattern, err)
			}
		})
	}
}

// #17179 Divergence B through the REAL gRPC gate — the leg the pkg/api
// parity harness cannot run: GetEvents{Protocol:"tcp"} must be DENIED
// under `^show security log protocol tcp$` (judged on its reconstructed
// argument-bearing form), while the unfiltered and other-protocol
// requests are allowed. Unlike grpcVerdict17179 in pkg/api, this runs
// authorizeRPCCommand itself, so alias forms, canonical-command
// resolution and both rescues are exercised on the judged forms.
//
// FAIL-ON-REVERT: dropping the protocol selector from the GetEvents
// reconstruction (judging only the bare `show log` charge) makes the
// denied cell ALLOWED again.
func TestGetEventsProtocolParityGRPC17179(t *testing.T) {
	for _, tc := range []struct {
		name, pattern string
		req           *pb.GetEventsRequest
		wantDeny      bool
	}{
		{"events protocol denied", `^show security log protocol tcp$`, &pb.GetEventsRequest{Protocol: "tcp"}, true},
		{"events protocol other allowed", `^show security log protocol tcp$`, &pb.GetEventsRequest{Protocol: "udp"}, false},
		{"events unfiltered allowed", `^show security log protocol tcp$`, &pb.GetEventsRequest{}, false},
		{"events zone denied", `^show security log zone trust$`, &pb.GetEventsRequest{Zone: uint32(config.StableZoneID("trust")), HasZone: true}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := cfg16067(t, tc.pattern, "")
			err := gateDecide7172(t, cfg, "GetEvents", tc.req)
			if tc.wantDeny && err == nil {
				t.Errorf("deny %q over GetEvents %+v was ALLOWED on gRPC; the protocol/zone selector must be judged (#17179)", tc.pattern, tc.req)
			}
			if !tc.wantDeny && err != nil {
				t.Errorf("deny %q over GetEvents refused a command it does not name: %v", tc.pattern, err)
			}
		})
	}
}

var _ = config.StableZoneID
