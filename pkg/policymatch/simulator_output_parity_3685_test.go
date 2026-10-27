package policymatch

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestMatchResultCarriesDescriptionAndScheduler pins #3685 M05/M06 at the
// simulator layer: a positive verdict against a policy that carries a
// `description` and a `scheduler-name` binding must expose BOTH on the
// policymatch.Result, so the REST/gRPC/CLI surfaces built over it can report
// the ticket/change context (M05) and the time-gate controlling the rule (M06).
//
// RED-on-revert:
//   - Removing `Description: pol.Description` from matchedResult drops the
//     description and the Description assertion fails.
//   - Removing the new `SchedulerName: pol.SchedulerName` copy from
//     matchedResult drops the scheduler binding and the SchedulerName assertion
//     fails.
//
// Description already round-tripped before #3685 (matchedResult set it), so its
// assertion is a regression anchor; SchedulerName is the field #3685 adds.
func TestMatchResultCarriesDescriptionAndScheduler(t *testing.T) {
	pol := scheduled(permit("allow-web", config.PolicyMatch{Applications: []string{"any"}}), "workhours")
	pol.Description = "CHG-4242-web-access"
	cfg := cfgWith(config.SecurityConfig{
		DefaultPolicy: config.PolicyDeny,
		Policies: []*config.ZonePairPolicies{
			zonePair("trust", "untrust", pol),
		},
	}, config.ApplicationsConfig{})

	// The scheduler is ACTIVE so the scheduled permit matches (a positive match
	// is by construction currently active — the live surfaces skip an inactive
	// rule before it can match).
	res := Match(cfg, Query{
		FromZone:         "trust",
		ToZone:           "untrust",
		Protocol:         "tcp",
		DstPort:          PortPtr(80),
		PolicyInactiveFn: inactiveFnFor(map[string]bool{"workhours": true}),
	})
	if !res.Matched || res.Action != config.PolicyPermit || res.PolicyName != "allow-web" {
		t.Fatalf("want permit by allow-web, got Matched=%v Action=%v PolicyName=%q",
			res.Matched, res.Action, res.PolicyName)
	}
	if res.Description != "CHG-4242-web-access" {
		t.Errorf("Description = %q, want %q (M05)", res.Description, "CHG-4242-web-access")
	}
	if res.SchedulerName != "workhours" {
		t.Errorf("SchedulerName = %q, want %q (M06)", res.SchedulerName, "workhours")
	}
}

// TestMatchResultNonScheduledHasEmptySchedulerName is the negative control: a
// matched policy WITHOUT a scheduler binding must leave SchedulerName empty, so
// a downstream surface can gate an effective-active flag on it (an always-on
// policy is not "scheduler-active").
func TestMatchResultNonScheduledHasEmptySchedulerName(t *testing.T) {
	cfg := cfgWith(config.SecurityConfig{
		DefaultPolicy: config.PolicyDeny,
		Policies: []*config.ZonePairPolicies{
			zonePair("trust", "untrust",
				permit("plain-allow", config.PolicyMatch{Applications: []string{"any"}})),
		},
	}, config.ApplicationsConfig{})
	res := Match(cfg, Query{FromZone: "trust", ToZone: "untrust", Protocol: "tcp", DstPort: PortPtr(80)})
	if !res.Matched {
		t.Fatalf("want match, got %+v", res)
	}
	if res.SchedulerName != "" {
		t.Errorf("SchedulerName = %q, want empty for a non-scheduled policy", res.SchedulerName)
	}
}
