package policymatch

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestAnalyzePolicyShadowing pins the fable-167 C-1c shadow/redundancy pass.
func TestAnalyzePolicyShadowing(t *testing.T) {
	pol := func(name string, action config.PolicyAction, src, dst, apps []string) *config.Policy {
		return &config.Policy{
			Name:   name,
			Action: action,
			Match: config.PolicyMatch{
				SourceAddresses:      src,
				DestinationAddresses: dst,
				Applications:         apps,
			},
		}
	}
	cfg := &config.Config{}
	cfg.Security.Policies = []*config.ZonePairPolicies{
		{
			FromZone: "trust", ToZone: "untrust",
			Policies: []*config.Policy{
				// permit-any shadows every later rule in this pair.
				pol("permit-all", config.PolicyPermit, []string{"any"}, []string{"any"}, []string{"any"}),
				// SHADOWED with a different action (dangerous).
				pol("block-web", config.PolicyDeny, []string{"any"}, []string{"web-srv"}, []string{"http"}),
			},
		},
		{
			FromZone: "trust", ToZone: "dmz",
			Policies: []*config.Policy{
				pol("allow-http", config.PolicyPermit, []string{"any"}, []string{"any"}, []string{"http"}),
				// REDUNDANT: identical match+action to allow-http.
				pol("allow-http-dup", config.PolicyPermit, []string{"any"}, []string{"any"}, []string{"http"}),
				// NOT shadowed: distinct application not covered by allow-http.
				pol("allow-dns", config.PolicyPermit, []string{"any"}, []string{"any"}, []string{"dns"}),
			},
		},
	}

	findings := AnalyzePolicyShadowing(cfg)
	joined := strings.Join(findings, "\n")

	if !strings.Contains(joined, "block-web") || !strings.Contains(joined, "SHADOWED") {
		t.Fatalf("expected block-web reported SHADOWED, got:\n%s", joined)
	}
	if !strings.Contains(joined, "allow-http-dup") || !strings.Contains(joined, "REDUNDANT") {
		t.Fatalf("expected allow-http-dup reported REDUNDANT, got:\n%s", joined)
	}
	if strings.Contains(joined, "allow-dns") {
		t.Fatalf("allow-dns is not shadowed (distinct application) but was reported:\n%s", joined)
	}
}

// TestAnalyzePolicyShadowingExcludedLaterIsNotShadowed pins the fable-167 C-1c
// review MINOR fix: a later policy whose match sense is INVERTED
// (source/destination-address-excluded) is NOT reported as shadowed even when
// the named sets are identical — the two match sets are disjoint (in-set vs
// complement), so the later rule is fully reachable. RED on revert: without
// the b-excluded guard the lint reports it SHADOWED/UNREACHABLE (false
// positive).
func TestAnalyzePolicyShadowingExcludedLaterIsNotShadowed(t *testing.T) {
	src := func(name string, action config.PolicyAction, srcExcluded bool) *config.Policy {
		return &config.Policy{
			Name:   name,
			Action: action,
			Match: config.PolicyMatch{
				SourceAddresses:       []string{"A"},
				DestinationAddresses:  []string{"any"},
				Applications:          []string{"any"},
				SourceAddressExcluded: srcExcluded,
			},
		}
	}
	dst := func(name string, action config.PolicyAction, dstExcluded bool) *config.Policy {
		return &config.Policy{
			Name:   name,
			Action: action,
			Match: config.PolicyMatch{
				SourceAddresses:            []string{"any"},
				DestinationAddresses:       []string{"B"},
				Applications:               []string{"any"},
				DestinationAddressExcluded: dstExcluded,
			},
		}
	}
	cfg := &config.Config{}
	cfg.Security.Policies = []*config.ZonePairPolicies{
		{
			FromZone: "trust", ToZone: "untrust",
			Policies: []*config.Policy{
				// earlier permit src∈{A}; later deny src∉{A} — DISJOINT.
				src("permit-A", config.PolicyPermit, false),
				src("deny-not-A", config.PolicyDeny, true),
			},
		},
		{
			FromZone: "trust", ToZone: "dmz",
			Policies: []*config.Policy{
				// earlier permit dst∈{B}; later deny dst∉{B} — DISJOINT.
				dst("permit-B", config.PolicyPermit, false),
				dst("deny-not-B", config.PolicyDeny, true),
			},
		},
	}
	if findings := AnalyzePolicyShadowing(cfg); len(findings) != 0 {
		t.Fatalf("an excluded-sense later policy is reachable, must not shadow, got: %v", findings)
	}
}

// TestAnalyzePolicyShadowingGenuineStillReported guards that the b-excluded
// fix did not suppress a genuine shadow: earlier permit-any shadows a later
// deny [A] (both plain, no exclusion).
func TestAnalyzePolicyShadowingGenuineStillReported(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.Policies = []*config.ZonePairPolicies{
		{
			FromZone: "trust", ToZone: "untrust",
			Policies: []*config.Policy{
				{Name: "permit-any", Action: config.PolicyPermit, Match: config.PolicyMatch{
					SourceAddresses: []string{"any"}, DestinationAddresses: []string{"any"}, Applications: []string{"any"},
				}},
				{Name: "deny-A", Action: config.PolicyDeny, Match: config.PolicyMatch{
					SourceAddresses: []string{"A"}, DestinationAddresses: []string{"any"}, Applications: []string{"any"},
				}},
			},
		},
	}
	findings := AnalyzePolicyShadowing(cfg)
	if len(findings) != 1 || !strings.Contains(findings[0], "deny-A") || !strings.Contains(findings[0], "SHADOWED") {
		t.Fatalf("expected genuine shadow of deny-A still reported, got: %v", findings)
	}
}

// TestAnalyzePolicyShadowingScheduledEarlierIsNotShadower pins that a
// schedule-gated earlier policy (not always active) is NOT treated as a
// shadower — avoids false positives.
func TestAnalyzePolicyShadowingScheduledEarlierIsNotShadower(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.Policies = []*config.ZonePairPolicies{
		{
			FromZone: "trust", ToZone: "untrust",
			Policies: []*config.Policy{
				{
					Name:          "business-hours",
					Action:        config.PolicyPermit,
					SchedulerName: "work-week",
					Match: config.PolicyMatch{
						SourceAddresses: []string{"any"}, DestinationAddresses: []string{"any"}, Applications: []string{"any"},
					},
				},
				{
					Name:   "after-hours-block",
					Action: config.PolicyDeny,
					Match: config.PolicyMatch{
						SourceAddresses: []string{"any"}, DestinationAddresses: []string{"any"}, Applications: []string{"any"},
					},
				},
			},
		},
	}
	if findings := AnalyzePolicyShadowing(cfg); len(findings) != 0 {
		t.Fatalf("scheduled earlier policy must not shadow, got: %v", findings)
	}
}

// TestAnalyzePolicyShadowingGlobal pins codex-182 A10-b00-C01: the shadow pass
// must also analyze the ordered global policy list (`security policies
// global`), which it previously omitted entirely. An earlier global `permit
// any` shadows a later global `deny web`. RED on revert (drop the
// analyzePolicyListShadowing call over GlobalPolicies): the finding disappears.
func TestAnalyzePolicyShadowingGlobal(t *testing.T) {
	gpol := func(name string, action config.PolicyAction, apps []string) *config.Policy {
		return &config.Policy{
			Name:   name,
			Action: action,
			Match: config.PolicyMatch{
				SourceAddresses:      []string{"any"},
				DestinationAddresses: []string{"any"},
				Applications:         apps,
			},
		}
	}
	cfg := &config.Config{}
	cfg.Security.GlobalPolicies = []*config.Policy{
		gpol("g-permit-all", config.PolicyPermit, []string{"any"}),
		// SHADOWED: a superset permit-any precedes this deny in the same tier.
		gpol("g-block-web", config.PolicyDeny, []string{"http"}),
	}
	findings := AnalyzePolicyShadowing(cfg)
	joined := strings.Join(findings, "\n")
	if !strings.Contains(joined, "g-block-web") || !strings.Contains(joined, "SHADOWED") {
		t.Fatalf("expected global g-block-web reported SHADOWED, got:\n%s", joined)
	}
	if !strings.Contains(joined, "[global]") {
		t.Fatalf("expected the finding tagged with the [global] scope, got:\n%s", joined)
	}
}

// TestAnalyzePolicyShadowingGlobalDisjointScopeNotShadowed guards the
// globalScopeCovers gate: two global policies narrowed to DIFFERENT from-zone
// contexts (#3148/#4626) never shadow each other even when their
// address/application match sets nest. RED on revert (drop the extraSuperset
// gate for the global list): the lint falsely reports the later global
// SHADOWED.
func TestAnalyzePolicyShadowingGlobalDisjointScopeNotShadowed(t *testing.T) {
	scoped := func(name string, action config.PolicyAction, fromZones []string) *config.Policy {
		return &config.Policy{
			Name:   name,
			Action: action,
			Match: config.PolicyMatch{
				SourceAddresses:      []string{"any"},
				DestinationAddresses: []string{"any"},
				Applications:         []string{"any"},
				FromZones:            fromZones,
			},
		}
	}
	scopedTo := func(name string, action config.PolicyAction, toZones []string) *config.Policy {
		return &config.Policy{
			Name:   name,
			Action: action,
			Match: config.PolicyMatch{
				SourceAddresses:      []string{"any"},
				DestinationAddresses: []string{"any"},
				Applications:         []string{"any"},
				ToZones:              toZones,
			},
		}
	}
	cfg := &config.Config{}
	cfg.Security.GlobalPolicies = []*config.Policy{
		// earlier permit-any scoped to from-zone trust ONLY.
		scoped("g-permit-trust", config.PolicyPermit, []string{"trust"}),
		// later deny scoped to from-zone untrust — a DIFFERENT context, so the
		// earlier trust-only permit cannot make it unreachable.
		scoped("g-deny-untrust", config.PolicyDeny, []string{"untrust"}),
	}
	if findings := AnalyzePolicyShadowing(cfg); len(findings) != 0 {
		t.Fatalf("globals with disjoint from-zone scopes must not shadow, got: %v", findings)
	}

	// #5720 (codex, finding 5a): the guard must key on ToZones too, not only
	// FromZones. Two transit globals narrowed to DISJOINT to-zone contexts never
	// shadow each other even when their address/application match sets nest.
	cfg.Security.GlobalPolicies = []*config.Policy{
		scopedTo("g-permit-to-untrust", config.PolicyPermit, []string{"untrust"}),
		scopedTo("g-deny-to-dmz", config.PolicyDeny, []string{"dmz"}),
	}
	if findings := AnalyzePolicyShadowing(cfg); len(findings) != 0 {
		t.Fatalf("globals with disjoint to-zone scopes must not shadow, got: %v", findings)
	}

	// Control (positive, ToZones): an all-zones (nil) to-zone earlier global DOES
	// shadow a later to-zone-dmz global of a different action — the ToZones
	// dimension is exercised end-to-end, not just FromZones.
	cfg.Security.GlobalPolicies = []*config.Policy{
		scopedTo("g-permit-to-any", config.PolicyPermit, nil),
		scopedTo("g-deny-to-dmz", config.PolicyDeny, []string{"dmz"}),
	}
	findingsTo := AnalyzePolicyShadowing(cfg)
	if len(findingsTo) != 1 || !strings.Contains(findingsTo[0], "g-deny-to-dmz") || !strings.Contains(findingsTo[0], "SHADOWED") {
		t.Fatalf("an all-zones to-zone earlier global must shadow a to-zone-dmz later global, got: %v", findingsTo)
	}

	// Control: a later global with NO from-zone scope (all zones) is BROADER
	// than the earlier trust-only permit, so it is likewise not shadowed.
	cfg.Security.GlobalPolicies = []*config.Policy{
		scoped("g-permit-trust", config.PolicyPermit, []string{"trust"}),
		scoped("g-deny-all", config.PolicyDeny, nil),
	}
	if findings := AnalyzePolicyShadowing(cfg); len(findings) != 0 {
		t.Fatalf("an all-zones global is broader than a trust-only earlier, must not shadow, got: %v", findings)
	}

	// Control (positive): when the earlier global covers ALL zones it DOES
	// shadow a later trust-only global of a different action.
	cfg.Security.GlobalPolicies = []*config.Policy{
		scoped("g-permit-all", config.PolicyPermit, nil),
		scoped("g-deny-trust", config.PolicyDeny, []string{"trust"}),
	}
	findings := AnalyzePolicyShadowing(cfg)
	if len(findings) != 1 || !strings.Contains(findings[0], "g-deny-trust") || !strings.Contains(findings[0], "SHADOWED") {
		t.Fatalf("an all-zones earlier global must shadow a trust-only later global, got: %v", findings)
	}
}

// TestAnalyzePolicyShadowingGlobalHostVsTransitNotShadowed pins the #5720
// (codex, finding 1) cross-enforcement-path exclusion in globalScopeCovers.
// Host-inbound globals (`match to-zone junos-host`) and transit globals are
// enforced on SEPARATE dataplane paths: the host gate (matchJunosHost) never
// falls through to the transit global tier, and a transit global is only
// reached once no host policy matched. So a transit-scoped global can NEVER
// shadow a host-scoped one, and vice versa — regardless of address/application
// superset or zone-set nesting.
//
// RED on revert (drop the IsHostToZoneScope guard in globalScopeCovers): the
// unscoped transit permit's empty ToZones covers the `junos-host` token under
// zoneSetCovers, so the reachable host deny is falsely reported SHADOWED.
func TestAnalyzePolicyShadowingGlobalHostVsTransitNotShadowed(t *testing.T) {
	g := func(name string, action config.PolicyAction, toZones []string) *config.Policy {
		return &config.Policy{
			Name:   name,
			Action: action,
			Match: config.PolicyMatch{
				SourceAddresses:      []string{"any"},
				DestinationAddresses: []string{"any"},
				Applications:         []string{"any"},
				ToZones:              toZones,
			},
		}
	}

	// Transit permit (unscoped) authored BEFORE a reachable host-inbound deny:
	// the host deny takes the separate host gate and must NOT be reported
	// shadowed by the transit permit.
	cfg := &config.Config{}
	cfg.Security.GlobalPolicies = []*config.Policy{
		g("g-transit-permit", config.PolicyPermit, nil),
		g("g-host-deny", config.PolicyDeny, []string{"junos-host"}),
	}
	if findings := AnalyzePolicyShadowing(cfg); len(findings) != 0 {
		t.Fatalf("a transit global must not shadow a to-zone junos-host global, got: %v", findings)
	}

	// Vice versa: a host-inbound permit authored BEFORE a transit deny must not
	// shadow it either — the transit deny is on the other enforcement path.
	cfg.Security.GlobalPolicies = []*config.Policy{
		g("g-host-permit", config.PolicyPermit, []string{"junos-host"}),
		g("g-transit-deny", config.PolicyDeny, nil),
	}
	if findings := AnalyzePolicyShadowing(cfg); len(findings) != 0 {
		t.Fatalf("a host-inbound global must not shadow a transit global, got: %v", findings)
	}

	// Control (positive): two host-inbound globals on the SAME path DO shadow —
	// the earlier all-from-zones permit makes the later trust-scoped deny
	// unreachable. Confirms the guard only excludes CROSS-path pairs, not
	// genuine same-path host shadows.
	hostScoped := func(name string, action config.PolicyAction, fromZones []string) *config.Policy {
		return &config.Policy{
			Name:   name,
			Action: action,
			Match: config.PolicyMatch{
				SourceAddresses:      []string{"any"},
				DestinationAddresses: []string{"any"},
				Applications:         []string{"any"},
				FromZones:            fromZones,
				ToZones:              []string{"junos-host"},
			},
		}
	}
	cfg.Security.GlobalPolicies = []*config.Policy{
		hostScoped("g-host-permit-any", config.PolicyPermit, nil),
		hostScoped("g-host-deny-trust", config.PolicyDeny, []string{"trust"}),
	}
	findings := AnalyzePolicyShadowing(cfg)
	if len(findings) != 1 || !strings.Contains(findings[0], "g-host-deny-trust") || !strings.Contains(findings[0], "SHADOWED") {
		t.Fatalf("two host-inbound globals on the same path must still shadow, got: %v", findings)
	}
}

// TestAnalyzePolicyShadowingGlobalExplicitAnyScopeShadows pins the #5720
// (codex, finding 2) fix: zoneSetCovers must treat an explicit `["any"]` scope
// as the all-zones universal set, matching the runtime SSOT
// config.IsWildcardZoneSet (empty OR contains "any"). An explicit-`any`-scoped
// earlier global therefore covers — and makes redundant — a later narrower
// same-action global.
//
// RED on revert (restore the len(a)==0-only universality test in zoneSetCovers):
// the explicit `["any"]` scope is read as a concrete one-element set, so it no
// longer covers the trust-only later global and the redundancy goes unreported.
func TestAnalyzePolicyShadowingGlobalExplicitAnyScopeShadows(t *testing.T) {
	g := func(name string, action config.PolicyAction, fromZones, toZones []string) *config.Policy {
		return &config.Policy{
			Name:   name,
			Action: action,
			Match: config.PolicyMatch{
				SourceAddresses:      []string{"any"},
				DestinationAddresses: []string{"any"},
				Applications:         []string{"any"},
				FromZones:            fromZones,
				ToZones:              toZones,
			},
		}
	}
	cfg := &config.Config{}
	cfg.Security.GlobalPolicies = []*config.Policy{
		// earlier permit scoped with the EXPLICIT reserved token "any" on both
		// sides — the idiomatic Junos all-zones spelling.
		g("g-permit-any", config.PolicyPermit, []string{"any"}, []string{"any"}),
		// later permit narrowed to from-zone trust / to-zone untrust: the
		// explicit-any earlier permit already matches its superset with the same
		// action, so it is REDUNDANT.
		g("g-permit-narrow", config.PolicyPermit, []string{"trust"}, []string{"untrust"}),
	}
	findings := AnalyzePolicyShadowing(cfg)
	joined := strings.Join(findings, "\n")
	if !strings.Contains(joined, "g-permit-narrow") || !strings.Contains(joined, "REDUNDANT") {
		t.Fatalf("an explicit-any earlier global must make a narrower same-action later global REDUNDANT, got:\n%s", joined)
	}
}

// TestAnalyzeCrossTierGlobalShadowing11088 pins #11088: a scoped global
// fully covered by earlier wildcard zone-pair rules is SHADOWED (dead deny
// certified clean before); partially covered is PARTIALLY SHADOWED;
// uncovered and unscoped globals are silent.
func TestAnalyzeCrossTierGlobalShadowing11088(t *testing.T) {
	zpol := func(name string, action config.PolicyAction) *config.Policy {
		return &config.Policy{
			Name:   name,
			Action: action,
			Match: config.PolicyMatch{
				SourceAddresses:      []string{"any"},
				DestinationAddresses: []string{"any"},
				Applications:         []string{"any"},
			},
		}
	}
	gpol := func(name string, action config.PolicyAction, from, to []string) *config.Policy {
		return &config.Policy{
			Name:   name,
			Action: action,
			Match: config.PolicyMatch{
				SourceAddresses:      []string{"any"},
				DestinationAddresses: []string{"any"},
				Applications:         []string{"any"},
				FromZones:            from,
				ToZones:              to,
			},
		}
	}
	cfg := &config.Config{}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"trust": {Name: "trust"}, "untrust": {Name: "untrust"}, "dmz": {Name: "dmz"},
	}
	cfg.Security.Policies = []*config.ZonePairPolicies{
		{FromZone: "any", ToZone: "untrust", Policies: []*config.Policy{
			zpol("wide-permit", config.PolicyPermit),
		}},
	}
	cfg.Security.GlobalPolicies = []*config.Policy{
		gpol("dead-deny", config.PolicyDeny, []string{"trust"}, []string{"untrust"}),
		gpol("live-deny", config.PolicyDeny, []string{"trust"}, []string{"dmz"}),
		gpol("unscoped", config.PolicyDeny, nil, nil),
		gpol("half-covered", config.PolicyDeny, []string{"trust"}, []string{"untrust", "dmz"}),
	}
	joined := strings.Join(AnalyzePolicyShadowing(cfg), "\n")
	if !strings.Contains(joined, "dead-deny") || !strings.Contains(joined, "SHADOWED") {
		t.Fatalf("fully-covered scoped global must be SHADOWED:\n%s", joined)
	}
	if !strings.Contains(joined, "half-covered") || !strings.Contains(joined, "PARTIALLY SHADOWED") {
		t.Fatalf("half-covered scoped global must be PARTIALLY SHADOWED:\n%s", joined)
	}
	for _, quiet := range []string{"live-deny", "unscoped"} {
		for _, line := range strings.Split(joined, "\n") {
			// A rule is "reported" when it is the SUBJECT (policy "q" is ...),
			// not when named as another rule's coverer.
			if strings.Contains(line, "policy \""+quiet+"\" is ") {
				t.Fatalf("%s must stay silent, got line: %s\n%s", quiet, line, joined)
			}
		}
	}
}
