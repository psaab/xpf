package main

import (
	"strings"
	"testing"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// showSecurityPolicies12902 runs the remote handleShowSecurity for `show
// security policies <args...>` and returns (output, error).
func showSecurityPolicies12902(t *testing.T, c *ctl, args ...string) (string, error) {
	t.Helper()
	var err error
	out := captureStdout(t, func() {
		err = c.handleShowSecurity(append([]string{"policies"}, args...))
	})
	return out, err
}

// TestRemotePolicies_TrailingViewKeywordForwarded_12902 is the operator-surface
// regression for the D9-12 defect on the remote CLI: the wrappers built the
// forwarded request from args[1] only, so `from-zone trust to-zone untrust
// detail|hit-count` fell through to GetPolicies and the keyword was silently
// discarded.
//
// FAIL-ON-REVERT: restore the args[1] ladder in handleShowSecurity and the
// showTextCalls/getPoliciesCalls assertions go RED (the standard-view RPC is
// issued instead of the ShowText topic).
func TestRemotePolicies_TrailingViewKeywordForwarded_12902(t *testing.T) {
	for _, tc := range []struct{ keyword, topic string }{
		{"detail", "policies-detail"},
		{"hit-count", "policies-hit-count"},
	} {
		t.Run(tc.keyword, func(t *testing.T) {
			fake := &fakeBpfrxClient{}
			c := &ctl{client: fake}
			out, err := showSecurityPolicies12902(t, c,
				"from-zone", "trust", "to-zone", "untrust", tc.keyword)
			if err != nil {
				t.Fatalf("trailing %s rejected: %v", tc.keyword, err)
			}
			if fake.showTextCalls != 1 {
				t.Fatalf("trailing %s: ShowText called %d times, want 1 (keyword dropped -> GetPolicies=%d)",
					tc.keyword, fake.showTextCalls, fake.getPoliciesCalls)
			}
			if fake.showTextTopic != tc.topic {
				t.Fatalf("trailing %s: ShowText topic = %q, want %q", tc.keyword, fake.showTextTopic, tc.topic)
			}
			if fake.showTextFilter != "from-zone trust to-zone untrust" {
				t.Fatalf("trailing %s: forwarded filter = %q, want the selector pair", tc.keyword, fake.showTextFilter)
			}
			if fake.getPoliciesCalls != 0 {
				t.Fatalf("trailing %s: GetPolicies issued %d times — the keyword was dropped",
					tc.keyword, fake.getPoliciesCalls)
			}
			if out != "" {
				t.Fatalf("trailing %s: client rendered locally: %q", tc.keyword, out)
			}
		})
	}
}

// TestRemotePolicies_TrailingBriefHonored_12902: trailing `brief` must reach
// the brief table with the selector still applied — not fall through to the
// standard GetPolicies inventory.
func TestRemotePolicies_TrailingBriefHonored_12902(t *testing.T) {
	fake := &fakeBpfrxClient{
		getPoliciesResp: scopedGlobalPoliciesResp(),
		getZonesResp: &pb.GetZonesResponse{Zones: []*pb.ZoneInfo{
			{Name: "trust"}, {Name: "untrust"}, {Name: "dmz"},
		}},
	}
	c := &ctl{client: fake}
	out, err := showSecurityPolicies12902(t, c, "from-zone", "trust", "to-zone", "untrust", "brief")
	if err != nil {
		t.Fatalf("trailing brief rejected: %v", err)
	}
	if fake.showTextCalls != 0 {
		t.Fatalf("trailing brief issued a ShowText RPC (topic %q)", fake.showTextTopic)
	}
	if fake.getPoliciesCalls != 1 {
		t.Fatalf("trailing brief: GetPolicies called %d times, want 1", fake.getPoliciesCalls)
	}
	if !strings.Contains(out, "Hits") {
		t.Fatalf("trailing brief did not render the brief table:\n%s", out)
	}
	// The selector must still scope the brief rows.
	if !strings.Contains(out, "zp-allow") || strings.Contains(out, "zp-dmz") {
		t.Fatalf("trailing brief lost the from-zone/to-zone selector:\n%s", out)
	}
}

// TestRemotePolicies_GlobalPositionIndependent_12902 is the decisive check
// from the research lane: `from-zone trust to-zone untrust global` must equal
// the leading `global` form — only the global group, no zone-pair rows.
func TestRemotePolicies_GlobalPositionIndependent_12902(t *testing.T) {
	newCtl := func() (*ctl, *fakeBpfrxClient) {
		fake := &fakeBpfrxClient{
			getPoliciesResp: scopedGlobalPoliciesResp(),
			getZonesResp: &pb.GetZonesResponse{Zones: []*pb.ZoneInfo{
				{Name: "trust"}, {Name: "untrust"}, {Name: "dmz"},
			}},
		}
		return &ctl{client: fake}, fake
	}

	leadCtl, _ := newCtl()
	leading, err := showSecurityPolicies12902(t, leadCtl, "global", "from-zone", "trust", "to-zone", "untrust")
	if err != nil {
		t.Fatalf("leading global rejected: %v", err)
	}
	trailCtl, _ := newCtl()
	trailing, err := showSecurityPolicies12902(t, trailCtl, "from-zone", "trust", "to-zone", "untrust", "global")
	if err != nil {
		t.Fatalf("trailing global rejected: %v", err)
	}
	if leading != trailing {
		t.Fatalf("global keyword is position-dependent:\n--- leading ---\n%s\n--- trailing ---\n%s",
			leading, trailing)
	}
	if strings.Contains(trailing, "Rule: zp-allow") {
		t.Fatalf("trailing global still rendered zone-pair policies (keyword dropped):\n%s", trailing)
	}
	if !strings.Contains(trailing, "Rule: open-global") {
		t.Fatalf("trailing global rendered no global policies at all:\n%s", trailing)
	}
}

// TestRemotePolicies_RejectsConflictingKeywords_12902 pins the fail-closed
// half: a second keyword no view can render is rejected BEFORE any RPC is
// issued, never silently narrowed. Before the fix each of these issued an RPC
// and returned nil with a keyword ignored.
func TestRemotePolicies_RejectsConflictingKeywords_12902(t *testing.T) {
	for _, args := range [][]string{
		{"brief", "global"},
		{"detail", "global"},
		{"global", "detail"},
		{"global", "hit-count"},
		{"hit-count", "global"},
		{"from-zone", "trust", "to-zone", "untrust", "brief", "global"},
		{"brief", "detail"},
		{"hit-count", "detail"},
	} {
		fake := &fakeBpfrxClient{}
		c := &ctl{client: fake}
		out, err := showSecurityPolicies12902(t, c, args...)
		if err == nil {
			t.Fatalf("policies %v: conflicting keywords accepted (keyword silently dropped)", args)
		}
		if !strings.Contains(err.Error(), "conflicting display keywords") &&
			!strings.Contains(err.Error(), "cannot be combined") {
			t.Fatalf("policies %v: error = %q, want a conflict rejection", args, err)
		}
		if fake.showTextCalls != 0 || fake.getPoliciesCalls != 0 {
			t.Fatalf("policies %v: RPC issued despite the conflict (ShowText=%d GetPolicies=%d)",
				args, fake.showTextCalls, fake.getPoliciesCalls)
		}
		if out != "" {
			t.Fatalf("policies %v: rendered output before rejecting:\n%s", args, out)
		}
	}
}
