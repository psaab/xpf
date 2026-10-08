package main

import (
	"strings"
	"testing"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

func wildcardPoliciesResp12094() *pb.GetPoliciesResponse {
	return &pb.GetPoliciesResponse{
		Policies: []*pb.PolicyInfo{
			{FromZone: "*", ToZone: "*", Rules: []*pb.PolicyRule{{Name: "open-global", Action: "permit", Count: true, HitPackets: 3}}},
			{FromZone: "any", ToZone: "any", Rules: []*pb.PolicyRule{{Name: "both-any-deny", Action: "deny", Count: true, HitPackets: 4}}},
			{FromZone: "trust", ToZone: "any", Rules: []*pb.PolicyRule{{Name: "wild-to-any", Action: "deny", Count: true, HitPackets: 2}}},
			{FromZone: "any", ToZone: "untrust", Rules: []*pb.PolicyRule{{Name: "wild-from-any", Action: "deny", Count: true, HitPackets: 1}}},
			{FromZone: "trust", ToZone: "untrust", Rules: []*pb.PolicyRule{{Name: "exact-allow", Action: "permit", Count: true}}},
			{FromZone: "dmz", ToZone: "untrust", Rules: []*pb.PolicyRule{{Name: "off-pair", Action: "deny", Count: true, HitPackets: 8}}},
		},
	}
}

func TestShowPoliciesFilteredIncludesWildcardZonePairs12094(t *testing.T) {
	c := &ctl{client: &fakeBpfrxClient{getPoliciesResp: wildcardPoliciesResp12094()}}
	out := captureStdout(t, func() {
		if err := c.showPoliciesFiltered("trust", "untrust", false); err != nil {
			t.Fatalf("showPoliciesFiltered: %v", err)
		}
	})

	prev := -1
	for _, name := range []string{"exact-allow", "wild-to-any", "wild-from-any", "both-any-deny", "open-global"} {
		needle := "Rule: " + name
		idx := strings.Index(out, needle)
		if idx < 0 {
			t.Fatalf("filtered remote policy view dropped %q (#12094 regression):\n%s", name, out)
		}
		if idx <= prev {
			t.Fatalf("filtered remote policy view placed %q out of tier order (exact -> single-wildcard -> both-any -> global):\n%s", name, out)
		}
		prev = idx
	}
	if strings.Contains(out, "Rule: off-pair") {
		t.Fatalf("filtered remote policy view leaked unrelated pair dmz->untrust:\n%s", out)
	}
	if strings.Count(out, "Hit count:") != 5 {
		t.Fatalf("filtered remote policy view hit-count rows = %d, want one per applicable policy tier:\n%s", strings.Count(out, "Hit count:"), out)
	}
}
