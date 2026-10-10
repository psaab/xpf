// #7016 (remote CLI): GetPolicies now carries a per-rule
// hit_counters_unavailable flag for a rule whose hit counter no runtime source
// answered for — the dataplane is unloaded, or it is loaded and the helper has
// published nothing for that rule id (the window before the first status poll,
// or config skew after a non-abort-class apply failure, #5679). Before the
// field existed the RPC failed with codes.Internal in that window and the
// remote CLI printed nothing at all; now it succeeds, so the renderers must not
// present the accompanying 0/0 as an authoritative hit count.
//
// FAIL-ON-REVERT: dropping either `case rule.HitCountersUnavailable` arm makes
// the detail view print "Hit count: 0 packets, 0 bytes" and the brief view
// print "-", both indistinguishable from a rule that matched no traffic — the
// #3345 counter-unavailable-is-not-zero contract — and the assertions go RED.
package main

import (
	"strings"
	"testing"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

func unpublishedPoliciesResp() *pb.GetPoliciesResponse {
	return &pb.GetPoliciesResponse{
		Policies: []*pb.PolicyInfo{{
			FromZone: "trust",
			ToZone:   "untrust",
			Rules: []*pb.PolicyRule{{
				Name:                   "allow-web",
				Action:                 "permit",
				SrcAddresses:           []string{"any"},
				DstAddresses:           []string{"any"},
				Applications:           []string{"any"},
				Count:                  true,
				HitCountersUnavailable: true,
				// HitPackets/HitBytes deliberately 0: that is exactly the
				// value the flag says is not authoritative.
			}},
		}},
	}
}

func TestRenderRuleMarksUnavailableHitCounters(t *testing.T) {
	c := &ctl{client: &fakeBpfrxClient{
		getPoliciesResp: unpublishedPoliciesResp(),
		getZonesResp:    &pb.GetZonesResponse{Zones: []*pb.ZoneInfo{{Name: "trust"}, {Name: "untrust"}}},
	}}

	out := captureStdout(t, func() {
		if err := c.showPoliciesFiltered("trust", "untrust", false); err != nil {
			t.Fatalf("showPoliciesFiltered: %v", err)
		}
	})

	if strings.Contains(out, "Hit count: 0 packets, 0 bytes") {
		t.Errorf("detail view printed an authoritative 0/0 for a rule whose counter is unavailable (#7016):\n%s", out)
	}
	if !strings.Contains(out, "Hit count: not available") {
		t.Errorf("detail view did not mark the hit count unavailable:\n%s", out)
	}
}

func TestShowPoliciesBriefMarksUnavailableHitCounters(t *testing.T) {
	c := &ctl{client: &fakeBpfrxClient{getPoliciesResp: unpublishedPoliciesResp()}}

	out := captureStdout(t, func() {
		if err := c.showPoliciesBrief(); err != nil {
			t.Fatalf("showPoliciesBrief: %v", err)
		}
	})

	row := ""
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "allow-web") {
			row = line
		}
	}
	if row == "" {
		t.Fatalf("allow-web row missing from the brief table:\n%s", out)
	}
	if !strings.Contains(row, "n/a") {
		t.Errorf("brief row = %q, want an n/a Hits cell rather than the idle-rule \"-\" (#7016)\nfull:\n%s", row, out)
	}
}

// CONTROL: a rule with a HEALTHY counter read must be unaffected — the flag is
// false, so both views render the real numbers exactly as before.
func TestRenderRuleHealthyCountersUnchanged(t *testing.T) {
	resp := unpublishedPoliciesResp()
	rule := resp.Policies[0].Rules[0]
	rule.HitCountersUnavailable = false
	rule.HitPackets = 12
	rule.HitBytes = 1200

	c := &ctl{client: &fakeBpfrxClient{
		getPoliciesResp: resp,
		getZonesResp:    &pb.GetZonesResponse{Zones: []*pb.ZoneInfo{{Name: "trust"}, {Name: "untrust"}}},
	}}
	detail := captureStdout(t, func() {
		if err := c.showPoliciesFiltered("trust", "untrust", false); err != nil {
			t.Fatalf("showPoliciesFiltered: %v", err)
		}
	})
	if !strings.Contains(detail, "Hit count: 12 packets, 1200 bytes") {
		t.Errorf("healthy detail hit count regressed:\n%s", detail)
	}

	c2 := &ctl{client: &fakeBpfrxClient{getPoliciesResp: resp}}
	brief := captureStdout(t, func() {
		if err := c2.showPoliciesBrief(); err != nil {
			t.Fatalf("showPoliciesBrief: %v", err)
		}
	})
	if !strings.Contains(brief, "12") {
		t.Errorf("healthy brief hits cell regressed:\n%s", brief)
	}
}
