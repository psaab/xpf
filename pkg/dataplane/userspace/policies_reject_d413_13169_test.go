package userspace

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #13169 (D4-13): buildOneRuleSnapshot and collectPolicyContentRejections
// fail open / mis-report on undefined-scheduler deny rules and carriers.

func d413Cfg(pol *config.Policy) *config.Config {
	return &config.Config{
		Schedulers: map[string]*config.SchedulerConfig{},
		Security: config.SecurityConfig{
			Zones: map[string]*config.ZoneConfig{
				"trust":   {Name: "trust"},
				"untrust": {Name: "untrust"},
			},
			Policies: []*config.ZonePairPolicies{{
				FromZone: "trust", ToZone: "untrust",
				Policies: []*config.Policy{pol},
			}},
		},
	}
}

func TestD413UnflaggedUndefinedSchedulerDenyPoisoned(t *testing.T) {
	for _, action := range []config.PolicyAction{config.PolicyDeny, config.PolicyReject} {
		cfg := d413Cfg(&config.Policy{
			Name: "deny-sched-unflagged", Action: action, SchedulerName: "missing-sched",
			Match: config.PolicyMatch{SourceAddresses: []string{"any"}, DestinationAddresses: []string{"any"}, Applications: []string{"junos-ssh"}},
		})
		snap, err := buildSnapshotWithSchedulerState(cfg, config.UserspaceConfig{}, 1, 1, map[string]bool{}, nil, nil)
		if err != nil {
			t.Fatalf("build: %v", err)
		}
		if len(snap.Policies) != 1 {
			t.Fatalf("policies=%d", len(snap.Policies))
		}
		p := snap.Policies[0]
		hasSentinel := false
		for _, term := range p.ApplicationTerms {
			if term.Protocol == unsupportedApplicationSentinel {
				hasSentinel = true
			}
		}
		if !hasSentinel {
			t.Errorf("action %v: undefined-scheduler deny without LenientContentDropped not poisoned (Inactive=%v terms=%v) - fail-open", action, p.Inactive, p.ApplicationTerms)
		}
		reasons := PolicyContentRejectionReasons(cfg, nil)
		joined := strings.Join(reasons, "\n")
		if !strings.Contains(joined, `scheduler "missing-sched"`) {
			t.Errorf("action %v: reasons %q want scheduler cause", action, reasons)
		}
		if strings.Contains(joined, lenientDroppedConstraintToken) {
			t.Errorf("action %v: reasons expose generic token: %q", action, reasons)
		}
	}
	// Permit with undefined scheduler, otherwise clean: must NOT be poisoned/reported.
	cfg := d413Cfg(&config.Policy{
		Name: "permit-sched-unflagged", Action: config.PolicyPermit, SchedulerName: "missing-sched",
		Match: config.PolicyMatch{SourceAddresses: []string{"any"}, DestinationAddresses: []string{"any"}, Applications: []string{"junos-ssh"}},
	})
	if reasons := PolicyContentRejectionReasons(cfg, nil); len(reasons) != 0 {
		t.Errorf("permit undefined scheduler must stay clean, got %q", reasons)
	}
}

func TestD413FlaggedUndefinedSchedulerNoSpuriousApp(t *testing.T) {
	cfg := d413Cfg(&config.Policy{
		Name: "deny-sched-flagged", Action: config.PolicyDeny, SchedulerName: "missing-sched", LenientContentDropped: true,
		Match: config.PolicyMatch{SourceAddresses: []string{"any"}, DestinationAddresses: []string{"any"}, Applications: []string{"junos-ssh"}},
	})
	reasons := PolicyContentRejectionReasons(cfg, nil)
	joined := strings.Join(reasons, "\n")
	if !strings.Contains(joined, `scheduler "missing-sched"`) {
		t.Fatalf("want scheduler cause, got %q", reasons)
	}
	if strings.Contains(joined, lenientDroppedConstraintToken) {
		t.Fatalf("spurious generic application token: %q", reasons)
	}
}

func TestD413CarrierCombinedShapesAndSrcBad(t *testing.T) {
	rules := []PolicyRuleSnapshot{
		{
			Name: "__malformed_carrier__", FromZone: "trust", ToZone: "untrust",
			ApplicationTerms:                []PolicyApplicationSnapshot{{Name: unsupportedApplicationSentinel, Protocol: unsupportedApplicationSentinel}},
			malformedZonePairShapes:         []string{"from-zone trust (missing to-zone)"},
			unknownSecurityPoliciesChildren: []string{"bogus-stanza"},
			rejectedApplications:            []string{lenientDroppedConstraintToken},
		},
		{
			Name: "real-rule", FromZone: "trust", ToZone: "untrust",
			SourceAddresses:         []string{unsupportedAddressSentinel},
			ApplicationTerms:        []PolicyApplicationSnapshot{{Name: unsupportedApplicationSentinel, Protocol: unsupportedApplicationSentinel}},
			malformedZonePairShapes: []string{"from-zone untrust (missing to-zone)"},
			rejectedSourceAddresses: []string{"missing-addr"},
			rejectedApplications:    []string{lenientDroppedConstraintToken},
		},
	}
	joined := strings.Join(collectPolicyContentRejections(rules), "\n")
	for _, want := range []string{`malformed zone-pair context`, `unknown security policies child "bogus-stanza"`, `source-address "missing-addr"`, `from-zone untrust (missing to-zone)`} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing %q in %q", want, joined)
		}
	}
	if strings.Contains(joined, lenientDroppedConstraintToken) {
		t.Errorf("generic token leaked: %q", joined)
	}
}

func TestD413ZoneSentinelLenientNoSpuriousApp(t *testing.T) {
	// Direct unit: sentinel rule with generic token only.
	rules := []PolicyRuleSnapshot{{
		Name: "bad-global-lenient", FromZone: "junos-global", ToZone: "untrust",
		ApplicationTerms:           []PolicyApplicationSnapshot{{Name: unsupportedApplicationSentinel, Protocol: unsupportedApplicationSentinel}},
		zonePairGlobalSentinelSide: "from-zone",
		rejectedApplications:       []string{lenientDroppedConstraintToken},
	}}
	if got := collectPolicyContentRejections(rules); len(got) != 0 {
		t.Fatalf("zone-sentinel carrier must not emit content rejection (zone arm reports it), got %q", got)
	}
	rules[0].zonePairGlobalSentinelSide = ""
	rules[0].zonePairDefinedAnySide = "from-zone"
	if got := collectPolicyContentRejections(rules); len(got) != 0 {
		t.Fatalf("defined-any carrier must not emit content rejection, got %q", got)
	}
}
