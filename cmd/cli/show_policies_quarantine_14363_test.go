package main

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// #14363: the remote CLI `show security policies` (showPoliciesFiltered) and
// `show security policies brief` (showPoliciesBriefFiltered) ignored the
// server-stamped PolicyRule.Quarantined verdict: quarantined rules rendered
// under raw zone headers, and their hit cells read as the generic
// "no counter published" / "n/a" instead of the quarantine-specific
// disposition, so a scrubbed rule read as live enforcement with a merely
// unpublished counter. These are the fail-on-revert guards.

func quarantinedPoliciesResp14363() *pb.GetPoliciesResponse {
	return &pb.GetPoliciesResponse{Policies: []*pb.PolicyInfo{
		{FromZone: "trust", ToZone: "z214", Rules: []*pb.PolicyRule{
			{Name: "loser-rule", Action: "permit", Count: true,
				HitPackets: 5, HitBytes: 500,
				HitCountersUnavailable: true, Quarantined: true},
		}},
		{FromZone: "trust", ToZone: "trust", Rules: []*pb.PolicyRule{
			{Name: "ordinary-rule", Action: "permit", Count: true, HitPackets: 7, HitBytes: 700},
		}},
		{FromZone: "*", ToZone: "*", Rules: []*pb.PolicyRule{
			{Name: "dropped-global", Action: "deny",
				MatchToZones:           []string{"z214"},
				HitCountersUnavailable: true, Quarantined: true},
			// #12897 control: a mixed-scope global stays enforced for its
			// live members, so the server leaves Quarantined=false and its
			// counters stay live — no qualifier, no unavailable cell.
			{Name: "mixed-global", Action: "deny",
				MatchFromZones: []string{"trust", "z214"}, MatchToZones: []string{"untrust"},
				Count: true, HitPackets: 17, HitBytes: 1700},
			{Name: "live-global", Action: "permit"},
		}},
	}}
}

// ruleSection14363 returns the standard-view text from "Rule: <name>" up to
// the next rule header or group header.
func ruleSection14363(t *testing.T, out, name string) string {
	t.Helper()
	start := strings.Index(out, "Rule: "+name)
	if start < 0 {
		t.Fatalf("rule %q not found in output:\n%s", name, out)
	}
	rest := out[start:]
	end := len(rest)
	for _, marker := range []string{"\n  Rule: ", "\nFrom zone: "} {
		if idx := strings.Index(rest[len("Rule: "):], marker); idx >= 0 && idx+len("Rule: ") < end {
			end = idx + len("Rule: ")
		}
	}
	return rest[:end]
}

func Test_14363_ShowPoliciesFilteredQualifiesQuarantined(t *testing.T) {
	c := &ctl{client: &fakeBpfrxClient{getPoliciesResp: quarantinedPoliciesResp14363()}}
	out := captureStdout(t, func() {
		if err := c.showPoliciesFiltered("", "", false); err != nil {
			t.Fatalf("showPoliciesFiltered: %v", err)
		}
	})

	// Quarantined zone-pair header carries the qualifier. The server
	// stamps the whole rule dropped (either endpoint quarantined), and
	// the wire carries no per-endpoint bit, so both endpoints are
	// qualified — the conservative reading that never presents the
	// pair as live.
	if !strings.Contains(out, "From zone: trust "+config.ZoneQuarantinePoliciesQualifier+", To zone: z214 "+config.ZoneQuarantinePoliciesQualifier) {
		t.Fatalf("standard remote view did not qualify the quarantined zone-pair header:\n%s", out)
	}
	// Its hit count reads as the quarantine disposition, never the generic
	// unpublished wording and never the (survivor-attributable) numbers.
	loser := ruleSection14363(t, out, "loser-rule")
	if !strings.Contains(loser, "Hit count: "+config.ZoneQuarantineLiveCountersUnavailable) {
		t.Fatalf("loser-rule section = %q, want the quarantine live-counter disposition (#14363 regression)", loser)
	}
	if strings.Contains(loser, "not available (no counter published") || strings.Contains(loser, "5 packets") {
		t.Fatalf("loser-rule section = %q, quarantined rule read as merely unpublished/live", loser)
	}

	// Quarantine-dropped scoped global: header + hit disposition qualified.
	dropped := ruleSection14363(t, out, "dropped-global")
	if !strings.Contains(out, "From zone: any, To zone: z214 "+config.ZoneQuarantinePoliciesQualifier) {
		t.Fatalf("standard remote view did not qualify the dropped-global header:\n%s", out)
	}
	if !strings.Contains(dropped, "Hit count: "+config.ZoneQuarantineLiveCountersUnavailable) {
		t.Fatalf("dropped-global section = %q, want the quarantine live-counter disposition", dropped)
	}

	// Controls: live rules keep real counters and no qualifier.
	if ordinary := ruleSection14363(t, out, "ordinary-rule"); !strings.Contains(ordinary, "Hit count: 7 packets, 700 bytes") ||
		strings.Contains(ordinary, config.ZoneQuarantinePoliciesQualifier) {
		t.Fatalf("ordinary-rule section = %q, want live 7/700 counters and no qualifier", ordinary)
	}
	if mixed := ruleSection14363(t, out, "mixed-global"); !strings.Contains(mixed, "Hit count: 17 packets, 1700 bytes") ||
		strings.Contains(mixed, config.ZoneQuarantinePoliciesQualifier) {
		t.Fatalf("mixed-global section = %q, want live 17/1700 counters and no qualifier (#12897 mixed scope stays live)", mixed)
	}
}

func Test_14363_ShowPoliciesBriefQualifiesQuarantined(t *testing.T) {
	c := &ctl{client: &fakeBpfrxClient{getPoliciesResp: quarantinedPoliciesResp14363()}}
	out := captureStdout(t, func() {
		if err := c.showPoliciesBriefFiltered("", ""); err != nil {
			t.Fatalf("showPoliciesBriefFiltered: %v", err)
		}
	})

	for _, name := range []string{"loser-rule", "dropped-global"} {
		row := briefRowFor(t, out, name)
		if !strings.Contains(row, config.ZoneQuarantinePoliciesQualifier) {
			t.Fatalf("%s brief row = %q, want the quarantine qualifier (#14363 regression)", name, row)
		}
		if !strings.Contains(row, config.ZoneQuarantineLiveCountersUnavailable) {
			t.Fatalf("%s brief row = %q, want the quarantine live-counter disposition instead of n/a", name, row)
		}
	}

	// Controls: live rows keep their real hits and no qualifier.
	if row := briefRowFor(t, out, "ordinary-rule"); !strings.Contains(row, "7") ||
		strings.Contains(row, config.ZoneQuarantinePoliciesQualifier) {
		t.Fatalf("ordinary-rule brief row = %q, want live hits and no qualifier", row)
	}
	if row := briefRowFor(t, out, "mixed-global"); !strings.Contains(row, "17") ||
		strings.Contains(row, config.ZoneQuarantinePoliciesQualifier) {
		t.Fatalf("mixed-global brief row = %q, want live hits and no qualifier (#12897 mixed scope stays live)", row)
	}
}
