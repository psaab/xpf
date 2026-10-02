package policymatch

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// zoneQuarantineCfg builds a config carrying the verified StableZoneID
// collision pair z174/z214 (also used by
// pkg/dataplane/userspace/zones_collision_3719_test.go) plus a distinct
// "trust" zone. z214 is the later-sorting name, so config.QuarantinedZoneNames
// drops it — exactly what a lenient/HA-loaded config with an unrenamed
// collision produces at snapshot build (zoneid.go). A permit policy references
// z214 both as a zone-pair from-zone and as a junos-host from-zone.
func zoneQuarantineCfg(t *testing.T) *config.Config {
	t.Helper()
	if config.StableZoneID("z174") != config.StableZoneID("z214") {
		t.Fatalf("test premise broken: z174/z214 no longer collide under the frozen fold")
	}
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
			Zones:         zones("z174", "z214", "trust"),
			Policies: []*config.ZonePairPolicies{
				{FromZone: "z214", ToZone: "trust", Policies: []*config.Policy{permitAny("z214-to-trust")}},
				{FromZone: "z214", ToZone: JunosHostZone, Policies: []*config.Policy{permitAny("z214-host")}},
			},
		},
		Applications: config.ApplicationsConfig{},
	}
}

// TestQuarantinedZoneNoTransitMatch pins #5649 (C181-C14/C20): the simulator
// must treat a StableZoneID-collision-quarantined zone (z214, dropped from the
// dataplane by zoneid.go's #3719 runtime quarantine — see
// zones_collision_3719_test.go) the same way it treats an UNDEFINED zone
// (#3355) — id 0, ineligible for transit tiers — even though z214 is still
// present in the raw typed cfg.Security.Zones map. Before the fix, zoneKnown
// consulted only that raw map and reported z214 as policy-matchable, telling
// an operator that a policy the runtime never installed permits traffic.
//
// FAIL-ON-REVERT: dropping the quarantine check from zoneKnown makes this
// query match the z214-to-trust permit (Matched=true), failing the
// want-default-deny assertion.
func TestQuarantinedZoneNoTransitMatch(t *testing.T) {
	cfg := zoneQuarantineCfg(t)

	res := Match(cfg, Query{FromZone: "z214", ToZone: "trust", Protocol: "tcp", DstPort: 80})
	if res.Matched {
		t.Fatalf("quarantined from-zone z214 matched a transit rule the runtime dropped (#5649); res = %+v", res)
	}
	// #8318: a QUARANTINED zone is unknown to the built snapshot, so as a FROM
	// zone it is the unzoned-ingress deny rather than a default-policy verdict.
	// Verdict unchanged (deny); only the attribution moved.
	if !res.UnzonedIngress || res.Action != config.PolicyDeny {
		t.Fatalf("want unzoned-ingress deny for a quarantined from-zone, got %+v", res)
	}
}

// TestQuarantinedZoneJunosHostUnmatched covers matchJunosHost: a quarantined
// ingress is runtime zone 0 and cannot match its exact host rule. With no
// from-any/global policy, local delivery remains the host-gate fallback.
func TestQuarantinedZoneJunosHostUnmatched(t *testing.T) {
	cfg := zoneQuarantineCfg(t)

	res := Match(cfg, Query{FromZone: "z214", ToZone: JunosHostZone, Protocol: "tcp", DstPort: 22})
	if res.Matched {
		t.Fatalf("quarantined ingress zone matched a junos-host rule (#5649); res = %+v", res)
	}
	if !res.HostInboundUnmatched {
		t.Fatalf("want HostInboundUnmatched for a quarantined ingress zone, got %+v", res)
	}
}

// TestSurvivorZoneStillMatches is the positive control: z174 (the
// sorted-first survivor that OWNS the colliding id) must not be over-blocked
// by the quarantine projection — only the later-sorting collider is dropped.
func TestSurvivorZoneStillMatches(t *testing.T) {
	cfg := zoneQuarantineCfg(t)
	cfg.Security.Policies = append(cfg.Security.Policies, &config.ZonePairPolicies{
		FromZone: "z174", ToZone: "trust",
		Policies: []*config.Policy{{
			Name:   "z174-to-trust",
			Action: config.PolicyPermit,
			Match: config.PolicyMatch{
				SourceAddresses:      []string{"any"},
				DestinationAddresses: []string{"any"},
				Applications:         []string{"any"},
			},
		}},
	})

	res := Match(cfg, Query{FromZone: "z174", ToZone: "trust", Protocol: "tcp", DstPort: 80})
	if !res.Matched || res.Action != config.PolicyPermit {
		t.Fatalf("survivor zone z174 over-blocked by the #5649 quarantine guard; res = %+v", res)
	}
}

// TestNoCollisionZonesUnaffected proves the quarantine projection is a no-op
// when no zone name collides: a two-zone config with no id collision must
// match exactly as before.
func TestNoCollisionZonesUnaffected(t *testing.T) {
	cfg := undefinedZoneCfg()

	res := Match(cfg, Query{FromZone: "trust", ToZone: "untrust", Protocol: "tcp", DstPort: 80})
	if !res.Matched || res.Action != config.PolicyPermit {
		t.Fatalf("non-colliding zones affected by the #5649 quarantine projection; res = %+v", res)
	}
}
