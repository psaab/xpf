package policymatch

import (
	"strconv"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #12894: analyzeCrossTierGlobalShadowing counted quarantined zones,
// undefined zone tokens, and repeated FromZones/ToZones members in
// total := len(fromSet) * len(toSet) while the covered-pair map is
// DEDUPLICATED and can only ever realize pairs over the runtime's surviving
// zone scope. A scoped global that is 100% unreachable behind earlier tiers
// was downgraded to a false PARTIALLY SHADOWED, and a pair that exists only
// in the quarantined (never-installed) zone namespace could be credited to a
// zone-pair stanza the runtime drops.
//
// The fixture is the issue's decisive check: a scoped global whose authored
// scope carries a repeated member and a surviving/quarantined collision pair
// (z214 loses the frozen StableZoneID fold to z174), compared against the
// surviving runtime scope the snapshot builder publishes.
func TestCrossTierShadowingCountsSurvivingZoneScopeOnly12894(t *testing.T) {
	if config.StableZoneID("z174") != config.StableZoneID("z214") {
		t.Fatal("test premise broken: z174/z214 no longer collide under the frozen fold")
	}
	zpol := func(name string, action config.PolicyAction) *config.Policy {
		return &config.Policy{Name: name, Action: action, Match: config.PolicyMatch{
			SourceAddresses: []string{"any"}, DestinationAddresses: []string{"any"}, Applications: []string{"any"}}}
	}
	gpol := func(name string, action config.PolicyAction, from, to []string) *config.Policy {
		return &config.Policy{Name: name, Action: action, Match: config.PolicyMatch{
			SourceAddresses: []string{"any"}, DestinationAddresses: []string{"any"}, Applications: []string{"any"},
			FromZones: from, ToZones: to}}
	}
	cfg := &config.Config{}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"trust": {Name: "trust"}, "untrust": {Name: "untrust"},
		"z174": {Name: "z174"}, "z214": {Name: "z214"},
	}
	// The surviving runtime scope the snapshot builder publishes: zones minus
	// config.ZoneQuarantineExclusionsForConfig — the SAME SSOT
	// quarantineCollidingZones uses to prune scoped-global members and drop
	// rules whose whole match side collided (#5577). Anchoring the expected
	// universe here (not to a hand-listed zone set) is the "compare analyzer
	// pair set against the surviving runtime-snapshot scope" check.
	excluded := config.ZoneQuarantineExclusionsForConfig(cfg)
	if _, dead := excluded["z214"]; !dead {
		t.Fatalf("test premise broken: z214 not quarantined for this zone set: %v", excluded)
	}
	if _, dead := excluded["z174"]; dead {
		t.Fatalf("test premise broken: collision survivor z174 quarantined: %v", excluded)
	}
	var surviving []string
	for name := range cfg.Security.Zones {
		if _, dead := excluded[name]; !dead {
			surviving = append(surviving, name)
		}
	}
	cfg.Security.Policies = []*config.ZonePairPolicies{
		// Exact tier-1 stanza covering the global's whole SURVIVING scope.
		{FromZone: "trust", ToZone: "untrust", Policies: []*config.Policy{zpol("exact-permit", config.PolicyPermit)}},
		// Structurally bound to the quarantined zone: the runtime DROPS this
		// rule, so it must never be credited as a coverer.
		{FromZone: "z214", ToZone: "untrust", Policies: []*config.Policy{zpol("dead-permit", config.PolicyPermit)}},
	}
	cfg.Security.GlobalPolicies = []*config.Policy{
		// The two SILENT-subject globals come first: the within-list pass
		// reports only later rules shadowed by earlier ones, and none of the
		// scoped globals below has a universal scope, so ordering keeps that
		// pass quiet and every assertion below isolates the cross-tier one.
		//
		// Quarantine-only scope: the runtime drops the rule outright; the
		// analyzer must stay silent rather than invent coverage.
		gpol("quarantine-only", config.PolicyPermit, []string{"z214"}, []string{"untrust"}),
		// Surviving member with NO covering stanza for it: z174->untrust is
		// not covered, and the z214 side is not in the surviving universe.
		gpol("live-member", config.PolicyPermit, []string{"z174", "z214"}, []string{"untrust"}),
		// Repeated member + quarantined collision loser on the from side.
		gpol("dup-dead-scope", config.PolicyPermit, []string{"trust", "trust", "z214"}, []string{"untrust"}),
		// Undefined zone token (a tolerant load keeps it authored).
		gpol("ghost-scope", config.PolicyPermit, []string{"trust", "ghost"}, []string{"untrust"}),
		// Wildcard from-axis: must expand over the SURVIVING zones only.
		gpol("wildcard-from", config.PolicyPermit, []string{"any"}, []string{"untrust"}),
	}
	joined := strings.Join(AnalyzePolicyShadowing(cfg), "\n")
	subject := func(name string) string {
		for _, line := range strings.Split(joined, "\n") {
			if strings.Contains(line, "policy \""+name+"\" is ") {
				return line
			}
		}
		return ""
	}

	// Repeated + quarantined + undefined members must not dilute the total:
	// the entire surviving scope is covered by the same-action exact stanza,
	// so these are REDUNDANT, not PARTIALLY SHADOWED. RED on master: the
	// dead members inflate total (3 and 2) against one covered pair.
	for _, name := range []string{"dup-dead-scope", "ghost-scope"} {
		line := subject(name)
		if line == "" {
			t.Fatalf("%s must be reported, got nothing:\n%s", name, joined)
		}
		if !strings.Contains(line, "REDUNDANT") || strings.Contains(line, "PARTIALLY") {
			t.Fatalf("%s must be REDUNDANT over its surviving scope, got: %s", name, line)
		}
	}

	// Wildcard expansion excludes the quarantined zone: the rendered total
	// must equal the surviving-zone count derived from the runtime SSOT
	// (3 here: trust, untrust, z174), with only the exact pair covered.
	// RED on master: z214 joins the expansion AND its dead stanza covers
	// that pair, printing "2 of 4" instead.
	line := subject("wildcard-from")
	if line == "" {
		t.Fatalf("wildcard-from must be reported PARTIALLY SHADOWED, got nothing:\n%s", joined)
	}
	wantTotal := "PARTIALLY SHADOWED: 1 of " + strconv.Itoa(len(surviving)) + " zone pairs"
	if !strings.Contains(line, wantTotal) {
		t.Fatalf("wildcard-from total must follow the surviving runtime scope (%d zones), got: %s (want %q)", len(surviving), line, wantTotal)
	}

	// A pair that exists only in the quarantined namespace must not be
	// creditable: z174->untrust has NO covering stanza, so the global scoped
	// to the collision pair is NOT covered at all and must stay silent. RED
	// on master: the runtime-dropped z214 stanza covers the (z214,untrust)
	// pair and prints a false "PARTIALLY SHADOWED: 1 of 2".
	for _, name := range []string{"quarantine-only", "live-member"} {
		if line := subject(name); line != "" {
			t.Fatalf("%s must stay silent (no coverable pair in the surviving scope), got: %s", name, line)
		}
	}
}
