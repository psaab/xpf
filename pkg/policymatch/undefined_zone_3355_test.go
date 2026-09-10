package policymatch

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// undefinedZoneCfg builds a config with zones trust+untrust DEFINED, a
// `from-zone any to-zone untrust` wildcard permit, and a `junos-global` permit.
// It is used to prove that a query naming an UNDEFINED zone matches neither the
// wildcard nor the global tier (#3355), while a defined-zone query still does.
func undefinedZoneCfg() *config.Config {
	permitAny := func(name string) *config.Policy {
		return &config.Policy{
			Name:   name,
			Action: config.PolicyPermit,
			Match: config.PolicyMatch{
				SourceAddresses:      []string{"any"},
				DestinationAddresses: []string{"any"},
				Applications:         []string{"any"},
			},
		}
	}
	return &config.Config{
		Security: config.SecurityConfig{
			DefaultPolicy: config.PolicyDeny,
			Zones:         zones("trust", "untrust"),
			Policies: []*config.ZonePairPolicies{
				{FromZone: "any", ToZone: "untrust", Policies: []*config.Policy{permitAny("wild-permit")}},
			},
			GlobalPolicies: []*config.Policy{permitAny("global-permit")},
		},
		Applications: config.ApplicationsConfig{},
	}
}

// TestUndefinedFromZoneNoWildcardMatch mirrors policy.rs's
// `from_id != 0 && to_id != 0` transit guard: a query whose from-zone is not a
// configured zone resolves to the unknown sentinel (id 0) in the runtime and is
// ineligible for the #3090 wildcard tiers. Before #3355 the simulator matched
// the `from-zone any to-zone untrust` rule for ANY from-zone, including a
// typo'd/undefined one.
//
// FAIL-ON-REVERT: removing the zoneKnown guard in Match makes the wildcard
// match (Matched=true, permit), failing the want-default-deny assertion.
func TestUndefinedFromZoneNoWildcardMatch(t *testing.T) {
	cfg := undefinedZoneCfg()

	res := Match(cfg, Query{FromZone: "bogus", ToZone: "untrust", Protocol: "tcp", DstPort: 80})
	if res.Matched {
		t.Fatalf("undefined from-zone matched a wildcard/global rule (#3355); res = %+v", res)
	}
	// #8318: verdict unchanged (deny); attribution moved. An undefined FROM
	// zone is the unconditional unzoned-ingress deny, not a default-policy
	// verdict — the runtime denies from_id == 0 without consulting
	// default-policy (#6682). This fixture is deny-all, where the two are
	// indistinguishable by action alone.
	if !res.UnzonedIngress || res.Action != config.PolicyDeny {
		t.Fatalf("want unzoned-ingress deny for an undefined from-zone, got %+v", res)
	}
	if res.DefaultUsed {
		t.Fatalf("an unzoned-ingress deny must not be attributed to default-policy, got %+v", res)
	}
}

// TestUndefinedToZoneNoMatch covers the egress side of the same guard.
func TestUndefinedToZoneNoMatch(t *testing.T) {
	cfg := undefinedZoneCfg()

	res := Match(cfg, Query{FromZone: "trust", ToZone: "nowhere", Protocol: "tcp", DstPort: 80})
	if res.Matched {
		t.Fatalf("undefined to-zone matched (#3355); res = %+v", res)
	}
	if !res.DefaultUsed || res.Action != config.PolicyDeny {
		t.Fatalf("want default-policy deny for an undefined to-zone, got %+v", res)
	}
}

// TestDefinedZoneStillMatchesWildcard is the positive control: the guard must
// NOT over-block a DEFINED zone. trust->untrust is fully defined, so the
// wildcard permit still applies.
func TestDefinedZoneStillMatchesWildcard(t *testing.T) {
	cfg := undefinedZoneCfg()

	res := Match(cfg, Query{FromZone: "trust", ToZone: "untrust", Protocol: "tcp", DstPort: 80})
	if !res.Matched || res.Action != config.PolicyPermit {
		t.Fatalf("defined zone over-blocked by the #3355 guard; res = %+v", res)
	}
}

// TestNoZonesDefinedNoTransitMatch pins the faithful mirror of policy.rs's
// UNCONDITIONAL `from_id != 0 && to_id != 0` transit gate (policy.rs:1807): a
// config with an EMPTY Security.Zones map resolves every zone name to the
// unknown id 0 in the runtime, so the runtime matches NOTHING in the transit
// tiers. The simulator must agree — there is no empty-Zones leniency. This
// config is built directly (NOT via cfgWith, which injects the standard suite
// zones) so Security.Zones is genuinely empty.
//
// #9410 MOVED THE ATTRIBUTION, NOT THE VERDICT, and the fail-on-revert below had
// to be re-established rather than just re-worded.
//
// This fixture's policy names `trust`/`untrust` while Security.Zones is EMPTY, so
// it is simultaneously (a) a query whose from-zone is unknown and (b) a config
// whose policy carries an unresolvable zone reference. Those are different facts
// and #9410 made the second one observable: the helper refuses the WHOLE snapshot
// on an unresolvable zone, so `Match` now reports ContentRejected before any tier
// or zone check runs.
//
// ContentRejected is the CORRECT attribution here. UnzonedIngress describes what
// the runtime does to a query when a snapshot IS loaded; on a config whose
// snapshot the helper refuses, reporting it would be a verdict for something that
// was never loaded — the exact fabrication #9410 closes. The Action is unchanged
// (PolicyDeny), and this cell's primary property — a no-zones config must match
// NOTHING in the transit tiers — is unchanged and still asserted first.
//
// THE FAIL-ON-REVERT WAS HOLLOWED BY THAT CHANGE AND IS REBUILT BELOW. Measured:
// with #9410's arm in place, restoring the `len(cfg.Security.Zones) == 0` leniency
// in zoneKnown no longer reds this fixture, because the content-rejection gate
// returns before zoneKnown is ever called. A guard whose mutation its own cell
// can no longer see is not a guard, so TestNoZonesDefinedNoTransitMatchZoneGate
// below carries #3355's property on a fixture the new gate does NOT intercept:
// the policy's zones are DEFINED (so the snapshot resolves) and only the QUERY
// names an unknown zone.
func TestNoZonesDefinedNoTransitMatch(t *testing.T) {
	cfg := &config.Config{
		Security: config.SecurityConfig{
			DefaultPolicy: config.PolicyDeny,
			// Zones intentionally left nil/empty.
			Policies: []*config.ZonePairPolicies{
				{
					FromZone: "trust",
					ToZone:   "untrust",
					Policies: []*config.Policy{{
						Name:   "allow-all",
						Action: config.PolicyPermit,
						Match: config.PolicyMatch{
							SourceAddresses:      []string{"any"},
							DestinationAddresses: []string{"any"},
							Applications:         []string{"any"},
						},
					}},
				},
			},
		},
		Applications: config.ApplicationsConfig{},
	}

	res := Match(cfg, Query{FromZone: "trust", ToZone: "untrust", Protocol: "tcp", DstPort: 80})
	if res.Matched {
		t.Fatalf("no-zones config matched a transit rule the runtime would never evaluate (#3355 drift); res = %+v", res)
	}
	// #9410: the policy's own zone references are unresolvable, so the helper
	// refuses the snapshot and the simulator must say so instead of attributing a
	// query-level verdict to a snapshot that was never loaded. Action unchanged.
	if !res.ContentRejected || res.Action != config.PolicyDeny {
		t.Fatalf("want a content-rejected deny for a no-zones config whose policy names "+
			"undefined zones, got %+v", res)
	}
	if res.PolicyName != "" {
		t.Fatalf("a content-rejected config attributed policy %q", res.PolicyName)
	}
}

// TestNoZonesDefinedNoTransitMatchZoneGate carries #3355's property on a fixture
// the #9410 content-rejection gate does NOT intercept.
//
// #3355 is about the simulator mirroring policy.rs's unconditional
// `from_id != 0 && to_id != 0` transit gate: a query naming a zone the runtime
// resolves to id 0 must match nothing, with no empty-Zones leniency in zoneKnown.
// The original fixture expressed that with an EMPTY Zones map, which #9410 now
// content-rejects first — so the mutation that cell existed to catch became
// invisible to it (measured, not assumed).
//
// Here every zone the POLICY names is defined, so the snapshot resolves cleanly
// and the content gate stays silent; only the QUERY's from-zone is unknown. That
// isolates zoneKnown, which is what #3355 guards.
//
// FAIL-ON-REVERT: restoring `if len(cfg.Security.Zones) == 0 { return true }` in
// zoneKnown does NOT red this cell (Zones is non-empty here) — the leniency that
// matters for this fixture is any that treats an UNKNOWN query zone as known, so
// the mutation is `zoneKnown` returning true unconditionally, which makes the
// unknown-ingress query match the permit.
func TestNoZonesDefinedNoTransitMatchZoneGate(t *testing.T) {
	cfg := &config.Config{
		Security: config.SecurityConfig{
			DefaultPolicy: config.PolicyDeny,
			// DEFINED, so #9410's zone arm has nothing to report.
			Zones: map[string]*config.ZoneConfig{
				"trust":   {Name: "trust"},
				"untrust": {Name: "untrust"},
			},
			Policies: []*config.ZonePairPolicies{
				{
					FromZone: "trust",
					ToZone:   "untrust",
					Policies: []*config.Policy{{
						Name:   "allow-all",
						Action: config.PolicyPermit,
						Match: config.PolicyMatch{
							SourceAddresses:      []string{"any"},
							DestinationAddresses: []string{"any"},
							Applications:         []string{"any"},
						},
					}},
				},
			},
		},
		Applications: config.ApplicationsConfig{},
	}

	// POSITIVE CONTROL: the content gate must be SILENT on this fixture, or the
	// assertions below would pass for the wrong reason and this cell would be a
	// duplicate of the one above rather than the zone-gate isolation it claims.
	if res := Match(cfg, Query{FromZone: "trust", ToZone: "untrust", Protocol: "tcp", DstPort: 80}); res.ContentRejected {
		t.Fatalf("POSITIVE CONTROL: the #9410 content gate fired on a fixture whose policy "+
			"zones are all DEFINED (%v); this cell can no longer isolate zoneKnown",
			res.ContentRejectionReasons)
	} else if !res.Matched || res.Action != config.PolicyPermit {
		t.Fatalf("POSITIVE CONTROL: the defined-zone query did not match the permit; res = %+v", res)
	}

	// The property: an UNKNOWN ingress zone matches nothing in the transit tiers.
	res := Match(cfg, Query{FromZone: "nosuchzone", ToZone: "untrust", Protocol: "tcp", DstPort: 80})
	if res.Matched {
		t.Fatalf("an unknown ingress zone matched a transit rule the runtime would never "+
			"evaluate (#3355 drift); res = %+v", res)
	}
	if !res.UnzonedIngress || res.Action != config.PolicyDeny {
		t.Fatalf("want the unzoned-ingress deny (#8318) for an unknown query zone, got %+v", res)
	}
}

// TestUndefinedFromZoneJunosHostUnmatched covers matchJunosHost: an undefined
// ingress zone makes evaluate_junos_host_policy return None (from_id == 0), so
// the simulator returns HostInboundUnmatched (local delivery), never a matched
// host rule.
//
// FAIL-ON-REVERT: removing the zoneKnown guard in matchJunosHost makes the
// host rule match (Matched=true), failing the HostInboundUnmatched assertion.
func TestUndefinedFromZoneJunosHostUnmatched(t *testing.T) {
	cfg := &config.Config{
		Security: config.SecurityConfig{
			DefaultPolicy: config.PolicyDeny,
			Zones:         zones("trust", "untrust"),
			Policies: []*config.ZonePairPolicies{
				{
					FromZone: "any",
					ToZone:   JunosHostZone,
					Policies: []*config.Policy{{
						Name:   "host-permit",
						Action: config.PolicyPermit,
						Match: config.PolicyMatch{
							SourceAddresses:      []string{"any"},
							DestinationAddresses: []string{"any"},
							Applications:         []string{"any"},
						},
					}},
				},
			},
		},
		Applications: config.ApplicationsConfig{},
	}

	res := Match(cfg, Query{FromZone: "bogus", ToZone: JunosHostZone, Protocol: "tcp", DstPort: 22})
	if res.Matched {
		t.Fatalf("undefined ingress zone matched a junos-host rule (#3355); res = %+v", res)
	}
	if !res.HostInboundUnmatched {
		t.Fatalf("want HostInboundUnmatched for an undefined ingress zone, got %+v", res)
	}
}
