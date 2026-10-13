package main

import (
	"strings"
	"testing"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// #12524: brief policy requests must honor the from-zone/to-zone selectors and
// preserve zone-pair runtime precedence followed by applicable globals.
func TestShowPoliciesBriefAppliesZoneFilter12524(t *testing.T) {
	fake := &fakeBpfrxClient{
		getPoliciesResp: &pb.GetPoliciesResponse{Policies: []*pb.PolicyInfo{
			{FromZone: "*", ToZone: "*", Rules: []*pb.PolicyRule{
				{Name: "scoped-tu", Action: "deny", MatchFromZone: "trust", MatchToZone: "untrust"},
				{Name: "scoped-td", Action: "deny", MatchFromZone: "trust", MatchToZone: "dmz"},
				{Name: "scoped-ut", Action: "deny", MatchFromZone: "untrust", MatchToZone: "trust"},
				{Name: "open-global", Action: "permit"},
			}},
			{FromZone: "dmz", ToZone: "untrust", Rules: []*pb.PolicyRule{{Name: "off-pair", Action: "deny"}}},
			{FromZone: "any", ToZone: "any", Rules: []*pb.PolicyRule{{Name: "both-any-deny", Action: "deny"}}},
			{FromZone: "trust", ToZone: "any", Rules: []*pb.PolicyRule{{Name: "wild-to-any", Action: "deny"}}},
			{FromZone: "any", ToZone: "untrust", Rules: []*pb.PolicyRule{{Name: "wild-from-any", Action: "deny"}}},
			{FromZone: "trust", ToZone: "untrust", Rules: []*pb.PolicyRule{{Name: "exact-allow", Action: "permit"}}},
			{FromZone: "trust", ToZone: "dmz", Rules: []*pb.PolicyRule{{Name: "off-pair-2", Action: "deny"}}},
		}},
		getZonesResp: &pb.GetZonesResponse{Zones: []*pb.ZoneInfo{{Name: "trust"}, {Name: "untrust"}, {Name: "dmz"}}},
	}
	c := &ctl{client: fake}
	var err error
	out := captureStdout(t, func() {
		err = c.handleShowSecurity([]string{"policies", "brief", "from-zone", "trust", "to-zone", "untrust"})
	})
	if err != nil {
		t.Fatalf("handleShowSecurity(brief filtered): %v", err)
	}
	prev := -1
	for _, name := range []string{"exact-allow", "wild-to-any", "wild-from-any", "both-any-deny", "scoped-tu", "open-global"} {
		idx := strings.Index(out, name)
		if idx < 0 {
			t.Fatalf("filtered brief dropped %q (#12524 regression):\n%s", name, out)
		}
		if idx <= prev {
			t.Fatalf("filtered brief placed %q out of runtime order:\n%s", name, out)
		}
		prev = idx
	}
	for _, name := range []string{"off-pair", "off-pair-2", "scoped-td", "scoped-ut"} {
		if strings.Contains(out, name) {
			t.Fatalf("filtered brief leaked unrelated policy %q:\n%s", name, out)
		}
	}
}

func TestShowPoliciesBriefAppliesFromZoneOnly12524(t *testing.T) {
	fake := &fakeBpfrxClient{
		getPoliciesResp: wildcardPoliciesResp12094(),
		getZonesResp:    &pb.GetZonesResponse{Zones: []*pb.ZoneInfo{{Name: "trust"}, {Name: "untrust"}, {Name: "dmz"}}},
	}
	c := &ctl{client: fake}
	var err error
	out := captureStdout(t, func() {
		err = c.handleShowSecurity([]string{"policies", "brief", "from-zone", "trust"})
	})
	if err != nil {
		t.Fatalf("handleShowSecurity(brief from-only): %v", err)
	}
	for _, name := range []string{"exact-allow", "wild-to-any", "wild-from-any", "open-global"} {
		if !strings.Contains(out, name) {
			t.Fatalf("from-zone-only brief dropped %q:\n%s", name, out)
		}
	}
	if strings.Contains(out, "off-pair") {
		t.Fatalf("from-zone-only brief leaked unrelated pair:\n%s", out)
	}
}

func TestShowPoliciesBriefUnfilteredUnchanged12524(t *testing.T) {
	fake := &fakeBpfrxClient{getPoliciesResp: wildcardPoliciesResp12094()}
	c := &ctl{client: fake}
	var err error
	out := captureStdout(t, func() {
		err = c.handleShowSecurity([]string{"policies", "brief"})
	})
	if err != nil {
		t.Fatalf("handleShowSecurity(brief): %v", err)
	}
	for _, name := range []string{"open-global", "both-any-deny", "wild-to-any", "wild-from-any", "exact-allow", "off-pair"} {
		if !strings.Contains(out, name) {
			t.Fatalf("unfiltered brief dropped %q:\n%s", name, out)
		}
	}
}
