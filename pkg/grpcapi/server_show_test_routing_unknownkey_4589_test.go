package grpcapi

import (
	"strings"
	"testing"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// #4589 A8-b2 F-002: showTestRouting used `if len(parts) != 2 { continue }`
// plus a switch with no default arm, so a malformed segment or an
// unknown/typo'd selector key was SILENTLY dropped — a typo'd
// `instnace=dmz` left `instance` at "" and the lookup fell back to the MAIN
// routing table for a VRF query with no warning (parity gap vs the #3696
// showTestPolicy hardening). The handler must now report the typo.
//
// routing is nil here (the default Server), so a valid selector proceeds to
// the "Routing manager not available" diagnostic; a typo is reported first.
//
// RED-on-revert: without the default arm the typo'd `instnace` case emits
// "Routing manager not available" (silently using the main table) instead
// of naming the unknown key.
func TestShowTestRoutingReportsUnknownSelector(t *testing.T) {
	s := &Server{}

	cases := []struct {
		name       string
		topic      string
		wantSubstr string
	}{
		{
			name:       "typo'd instance key",
			topic:      "test-routing:dest=10.0.0.0/24,instnace=dmz",
			wantSubstr: `unknown selector "instnace"`,
		},
		{
			name:       "malformed segment",
			topic:      "test-routing:dest=10.0.0.0/24,garbage",
			wantSubstr: "malformed selector segment",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf strings.Builder
			if _, err := s.showTestRouting(&pb.ShowTextRequest{Topic: tc.topic}, nil, &buf); err != nil {
				t.Fatalf("showTestRouting(%q) error = %v", tc.topic, err)
			}
			out := buf.String()
			if !strings.Contains(out, tc.wantSubstr) {
				t.Errorf("showTestRouting(%q) = %q; want it to contain %q", tc.topic, out, tc.wantSubstr)
			}
		})
	}
}

// A valid selector set (correct `instance=` key) does NOT report an unknown
// selector; with routing nil it falls through to the manager-unavailable
// diagnostic, proving the hardening does not false-positive on good input.
func TestShowTestRoutingValidSelectorNotFlagged(t *testing.T) {
	s := &Server{}
	var buf strings.Builder
	if _, err := s.showTestRouting(&pb.ShowTextRequest{Topic: "test-routing:dest=10.0.0.0/24,instance=dmz"}, nil, &buf); err != nil {
		t.Fatalf("showTestRouting error = %v", err)
	}
	out := buf.String()
	if strings.Contains(out, "unknown selector") || strings.Contains(out, "malformed selector") {
		t.Errorf("showTestRouting flagged a valid selector: %q", out)
	}
	if !strings.Contains(out, "Routing manager not available") {
		t.Errorf("showTestRouting(valid, routing=nil) = %q; want the manager-unavailable diagnostic", out)
	}
}
