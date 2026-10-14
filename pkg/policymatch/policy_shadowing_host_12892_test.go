package policymatch

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestCrossTierShadowingHostScopeNotCoveredByTransitTiers12892 pins the
// #12892 fix: analyzeCrossTierGlobalShadowing must never report a
// host-inbound global (`match to-zone junos-host`, config.IsHostToZoneScope)
// as SHADOWED/REDUNDANT behind transit zone-pair stanzas. Host-bound traffic
// is enforced on the SEPARATE host gate (matchJunosHostWithMemo: exact
// `to-zone junos-host` pair, then `from-zone any to-zone junos-host`, then
// host globals) which never consults the transit tiers — so a
// `from-zone trust to-zone any` permit, however broad, cannot make a later
// `to-zone junos-host` deny unreachable, and crediting its (trust,
// junos-host) pair as covered is a false positive. The within-global-list
// pass already excludes this host/transit mixing (globalScopeCovers, #5720);
// the cross-tier pass must not regress it.
//
// RED on the research-validated master (255bd90c3), where expand() returned
// the authored to-scope verbatim and the transit stanza covered the
// (trust, junos-host) pair: "policy \"host-deny\" is SHADOWED: earlier
// zone-pair policies cover its entire scope with a different action". At
// later masters the observable flag is masked only by #12894's
// surviving-scope filter (the reserved junos-host token is never an
// installed zone, so the to-axis expands empty); the explicit IsHostToZoneScope
// gate states the enforcement-path reason so the exclusion no longer rides on
// the quarantine universe.
func TestCrossTierShadowingHostScopeNotCoveredByTransitTiers12892(t *testing.T) {
	zpol := func(name string, action config.PolicyAction) *config.Policy {
		return &config.Policy{Name: name, Action: action, Match: config.PolicyMatch{
			SourceAddresses: []string{"any"}, DestinationAddresses: []string{"any"}, Applications: []string{"any"}}}
	}
	gpol := func(name string, action config.PolicyAction, from, to []string) *config.Policy {
		return &config.Policy{Name: name, Action: action, Match: config.PolicyMatch{
			SourceAddresses: []string{"any"}, DestinationAddresses: []string{"any"}, Applications: []string{"any"},
			FromZones: from, ToZones: to}}
	}
	newCfg := func(stanzas []*config.ZonePairPolicies, globals ...*config.Policy) *config.Config {
		cfg := &config.Config{}
		cfg.Security.Zones = map[string]*config.ZoneConfig{
			"trust": {Name: "trust"}, "untrust": {Name: "untrust"},
		}
		cfg.Security.Policies = stanzas
		cfg.Security.GlobalPolicies = globals
		return cfg
	}
	subject := func(findings []string, name string) string {
		for _, line := range findings {
			if strings.Contains(line, "policy \""+name+"\" is ") {
				return line
			}
		}
		return ""
	}
	// The issue's transit coverer: a `to-zone any` stanza whose any-any-any
	// policy is a superset of the host global's match.
	transitAny := []*config.ZonePairPolicies{
		{FromZone: "trust", ToZone: "any", Policies: []*config.Policy{zpol("transit-permit", config.PolicyPermit)}},
	}

	// Decisive fixture: explicitly host-scoped global behind a transit
	// to-zone any stanza must stay unreported.
	findings := AnalyzePolicyShadowing(newCfg(transitAny,
		gpol("host-deny", config.PolicyDeny, []string{"trust"}, []string{"junos-host"})))
	if line := subject(findings, "host-deny"); line != "" {
		t.Fatalf("reachable host-inbound global must not be reported by the cross-tier pass, got: %s", line)
	}

	// Same shape from the wildcard from-axis (unscoped `match from-zone`),
	// with the both-any tier stacked on top: still a transit-only cover set.
	findings = AnalyzePolicyShadowing(newCfg([]*config.ZonePairPolicies{
		{FromZone: "trust", ToZone: "any", Policies: []*config.Policy{zpol("transit-permit", config.PolicyPermit)}},
		{FromZone: "any", ToZone: "any", Policies: []*config.Policy{zpol("both-any-permit", config.PolicyPermit)}},
	},
		gpol("host-anyfrom-deny", config.PolicyDeny, nil, []string{"junos-host"})))
	if line := subject(findings, "host-anyfrom-deny"); line != "" {
		t.Fatalf("unscoped-from host-inbound global must not be reported by the cross-tier pass, got: %s", line)
	}

	// Control (positive): the pass still fires on a TRANSIT scoped global
	// genuinely covered by the same stanza — the host gate must not
	// over-suppress cross-tier analysis.
	findings = AnalyzePolicyShadowing(newCfg(transitAny,
		gpol("transit-deny", config.PolicyDeny, []string{"trust"}, []string{"untrust"})))
	if len(findings) != 1 {
		t.Fatalf("transit scoped global fully covered by a transit stanza must be reported exactly once, got: %v", findings)
	}
	if !strings.Contains(findings[0], "transit-deny") || !strings.Contains(findings[0], "SHADOWED") {
		t.Fatalf("covered transit scoped global must be reported SHADOWED, got: %s", findings[0])
	}
}

// TestCrossTierShadowingHostGlobalIsReachable12892 is the matcher half of the
// #12892 decisive check: the host-inbound global the analyzer must NOT flag
// is REACHABLE at the runtime evaluator — a host-bound query returns its
// verdict, and the transit `to-zone any` stanza never answers it.
func TestCrossTierShadowingHostGlobalIsReachable12892(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"trust": {Name: "trust"}, "untrust": {Name: "untrust"},
	}
	cfg.Security.Policies = []*config.ZonePairPolicies{
		{FromZone: "trust", ToZone: "any", Policies: []*config.Policy{{
			Name:   "transit-permit",
			Action: config.PolicyPermit,
			Match: config.PolicyMatch{
				SourceAddresses:      []string{"any"},
				DestinationAddresses: []string{"any"},
				Applications:         []string{"any"},
			},
		}}},
	}
	cfg.Security.GlobalPolicies = []*config.Policy{{
		Name:   "host-deny",
		Action: config.PolicyDeny,
		Match: config.PolicyMatch{
			SourceAddresses:      []string{"any"},
			DestinationAddresses: []string{"any"},
			Applications:         []string{"any"},
			FromZones:            []string{"trust"},
			ToZones:              []string{"junos-host"},
		},
	}}

	res := Match(cfg, Query{FromZone: "trust", ToZone: "junos-host"})
	if !res.Matched {
		t.Fatalf("host-bound query must reach the host-inbound global (Matched=false, policy %q)", res.PolicyName)
	}
	if res.PolicyName != "host-deny" || res.Action != config.PolicyDeny {
		t.Fatalf("host-bound query must return the host global's deny, got policy %q action %v", res.PolicyName, res.Action)
	}
	if res.PolicyName == "transit-permit" {
		t.Fatalf("the transit to-zone any stanza must never answer a host-bound query")
	}
}
