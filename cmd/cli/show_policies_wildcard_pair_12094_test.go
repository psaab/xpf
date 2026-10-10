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
	c := &ctl{client: &fakeBpfrxClient{
		getPoliciesResp: wildcardPoliciesResp12094(),
		getZonesResp: &pb.GetZonesResponse{Zones: []*pb.ZoneInfo{
			{Name: "trust"}, {Name: "untrust"}, {Name: "dmz"},
		}},
	}}
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
	for _, count := range []string{
		"Hit count: 2 packets", "Hit count: 1 packets",
		"Hit count: 4 packets", "Hit count: 3 packets",
	} {
		if !strings.Contains(out, count) {
			t.Errorf("remote view omitted wire counter %q:\n%s", count, out)
		}
	}
}

func TestShowPoliciesFilteredScopesUnknownAndLiteralAnyZones12094(t *testing.T) {
	newClient := func() *fakeBpfrxClient {
		return &fakeBpfrxClient{
			getPoliciesResp: wildcardPoliciesResp12094(),
			getZonesResp: &pb.GetZonesResponse{Zones: []*pb.ZoneInfo{
				{Name: "trust"}, {Name: "untrust"}, {Name: "dmz"},
			}},
		}
	}
	ghost := &ctl{client: newClient()}
	ghostOut := captureStdout(t, func() {
		if err := ghost.showPoliciesFiltered("ghost", "untrust", false); err != nil {
			t.Fatalf("showPoliciesFiltered(ghost): %v", err)
		}
	})
	for _, excluded := range []string{"wild-to-any", "wild-from-any", "both-any-deny"} {
		if strings.Contains(ghostOut, "Rule: "+excluded) {
			t.Errorf("unknown-zone remote view listed wildcard %q:\n%s", excluded, ghostOut)
		}
	}

	literalAny := &ctl{client: newClient()}
	anyOut := captureStdout(t, func() {
		if err := literalAny.showPoliciesFiltered("any", "untrust", false); err != nil {
			t.Fatalf("showPoliciesFiltered(any): %v", err)
		}
	})
	if strings.Contains(anyOut, "Rule: wild-from-any") ||
		strings.Contains(anyOut, "Rule: both-any-deny") ||
		strings.Contains(anyOut, "Rule: wild-to-any") {
		t.Fatalf("literal any filter listed wildcard policies as governing:\n%s", anyOut)
	}
}
func TestShowPoliciesFilteredPreservesExactQuarantinedZonePair12094(t *testing.T) {
	c := &ctl{client: &fakeBpfrxClient{
		getPoliciesResp: &pb.GetPoliciesResponse{Policies: []*pb.PolicyInfo{
			{FromZone: "z214", ToZone: "untrust", Rules: []*pb.PolicyRule{{Name: "quarantined-exact", Action: "permit"}}},
			{FromZone: "any", ToZone: "untrust", Rules: []*pb.PolicyRule{{Name: "quarantined-wildcard", Action: "deny"}}},
			{FromZone: "z214", ToZone: "junos-host", Rules: []*pb.PolicyRule{{Name: "quarantined-host-exact", Action: "permit"}}},
			{FromZone: "any", ToZone: "junos-host", Rules: []*pb.PolicyRule{{Name: "quarantined-host-wildcard", Action: "deny"}}},
		}},
		getZonesResp: &pb.GetZonesResponse{Zones: []*pb.ZoneInfo{
			{Name: "z174", QuarantineState: pb.ZoneQuarantineState_ZONE_QUARANTINE_STATE_NOT_QUARANTINED},
			{Name: "z214", QuarantineState: pb.ZoneQuarantineState_ZONE_QUARANTINE_STATE_QUARANTINED},
			{Name: "untrust", QuarantineState: pb.ZoneQuarantineState_ZONE_QUARANTINE_STATE_NOT_QUARANTINED},
		}},
	}}
	out := captureStdout(t, func() {
		if err := c.showPoliciesFiltered("z214", "untrust", false); err != nil {
			t.Fatalf("showPoliciesFiltered(quarantined zone): %v", err)
		}
	})
	if !strings.Contains(out, "Rule: quarantined-exact") {
		t.Fatalf("exact authored quarantined policy was hidden:\n%s", out)
	}
	if strings.Contains(out, "Rule: quarantined-wildcard") {
		t.Fatalf("quarantined zone filter expanded a wildcard policy:\n%s", out)
	}
	hostOut := captureStdout(t, func() {
		if err := c.showPoliciesFiltered("z214", "junos-host", false); err != nil {
			t.Fatalf("showPoliciesFiltered(quarantined host zone): %v", err)
		}
	})
	if !strings.Contains(hostOut, "Rule: quarantined-host-exact") {
		t.Fatalf("exact authored quarantined host policy was hidden:\n%s", hostOut)
	}
	if !strings.Contains(hostOut, "Rule: quarantined-host-wildcard") {
		t.Fatalf("quarantined host filter omitted the runtime from-any exception:\n%s", hostOut)
	}
}
