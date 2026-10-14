package main

import (
	"strings"
	"testing"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// #12899: the remote standard `show security zones` summary hand-rolled its
// policy walk over the raw GetPolicies response and (a) matched a zone-pair
// group only when a side LITERALLY named the zone — dropping `any -> zone`,
// `zone -> any`, and `any -> any` rows the runtime evaluates, (b) printed the
// tier-one rows in raw response order instead of runtime precedence, and
// (c) ignored the structured quarantine fields (ZoneInfo.QuarantineState /
// QuarantineSurvivorZone, PolicyRule.Quarantined) the server already stamps,
// so a collision loser rendered as an ordinary installed zone and scrubbed
// rules read as live. These tests are the fail-on-revert guards; the selection
// and ordering semantics mirror policymatch.ZoneDetailPolicySummary.

// TestShowZonesZonePairWildcardTiersAndOrder: a healthy zone's tier-one rows
// must include the wildcard zone-pair sets that govern it AND print in runtime
// precedence order (exact, single-wildcard, both-any; config order within a
// bucket) — not raw response order.
//
// FAIL-ON-MASTER: the wildcard rows are dropped entirely by the literal
// `FromZone == z.Name || ToZone == z.Name` filter, and the only surviving row
// (exact-web) is joined by nothing, so every wildcard assertion and the
// ordering assertion go RED.
func TestShowZonesZonePairWildcardTiersAndOrder(t *testing.T) {
	fake := &fakeBpfrxClient{
		getZonesResp: &pb.GetZonesResponse{
			Zones: []*pb.ZoneInfo{{Name: "trust", Id: 3, Interfaces: []string{"ge-0-0-0"}}},
		},
		// Deliberate config order: both-any FIRST, then the single wildcards
		// around the exact set, so raw-order rendering inverts the precedence
		// the runtime actually evaluates.
		getPoliciesResp: &pb.GetPoliciesResponse{
			Policies: []*pb.PolicyInfo{
				{
					FromZone: "any",
					ToZone:   "any",
					Rules:    []*pb.PolicyRule{{Name: "catch-all-two", Action: "permit"}},
				},
				{
					FromZone: "any",
					ToZone:   "trust",
					Rules:    []*pb.PolicyRule{{Name: "ingress-any", Action: "permit"}},
				},
				{
					FromZone: "trust",
					ToZone:   "untrust",
					Rules:    []*pb.PolicyRule{{Name: "exact-web", Action: "permit"}},
				},
				{
					FromZone: "trust",
					ToZone:   "any",
					Rules:    []*pb.PolicyRule{{Name: "egress-any", Action: "deny"}},
				},
			},
		},
	}
	c := &ctl{client: fake}

	out := captureStdout(t, func() {
		if err := c.showZones(""); err != nil {
			t.Fatalf("showZones: %v", err)
		}
	})

	// Every wildcard row must appear: `any -> trust` and `trust -> any` govern
	// trust on one side, `any -> any` governs it on both.
	for _, row := range []string{
		"[zone-pair] any -> any: catch-all-two (permit)",
		"[zone-pair] any -> trust: ingress-any (permit)",
		"[zone-pair] trust -> any: egress-any (deny)",
		"[zone-pair] trust -> untrust: exact-web (permit)",
	} {
		if !strings.Contains(out, row) {
			t.Fatalf("remote zone summary dropped a governing zone-pair row %q:\n%s", row, out)
		}
	}
	// Runtime precedence: exact < single-wildcard (config order within the
	// bucket: any->trust authored before trust->any) < both-any.
	var last int
	for _, row := range []string{
		"[zone-pair] trust -> untrust: exact-web",
		"[zone-pair] any -> trust: ingress-any",
		"[zone-pair] trust -> any: egress-any",
		"[zone-pair] any -> any: catch-all-two",
	} {
		idx := strings.Index(out, row)
		if idx < 0 {
			t.Fatalf("row %q missing (order check):\n%s", row, out)
		}
		if idx < last {
			t.Fatalf("tier-one rows not in runtime precedence order (expected %q after its predecessors):\n%s", row, out)
		}
		last = idx
	}
}

// TestShowZonesQuarantinedZoneIndicatorAndScrubGating: the summary must render
// the structured quarantine indicator for a collision loser (zone-level
// qualifier, headline, interfaces qualifier, counters line, block-level
// policies qualifier), keep literally-naming rows visible with the per-rule
// scrub qualifier, and gate the wildcard legs (wildcard zone-pair sides and
// unscoped globals) exactly like policymatch.ZoneDetailPolicySummary: a
// quarantined zone is omitted by the builder, so nothing wildcard can govern
// it.
//
// FAIL-ON-MASTER: every indicator assertion and every with-qualifier row
// assertion goes RED (the fields were ignored); the healthy-zone half of the
// last test's wildcard coverage stays the ordering/wildcard guard.
func TestShowZonesQuarantinedZoneIndicatorAndScrubGating(t *testing.T) {
	loserPair := func() *pb.PolicyInfo {
		return &pb.PolicyInfo{
			FromZone: "dup",
			ToZone:   "untrust",
			Rules:    []*pb.PolicyRule{{Name: "loser-pair", Action: "permit", Quarantined: true}},
		}
	}
	wildBoth := func() *pb.PolicyInfo {
		return &pb.PolicyInfo{
			FromZone: "any",
			ToZone:   "any",
			Rules:    []*pb.PolicyRule{{Name: "wild-both", Action: "permit"}},
		}
	}
	wildToLoser := func() *pb.PolicyInfo {
		return &pb.PolicyInfo{
			FromZone: "any",
			ToZone:   "dup",
			// The server stamps the scrub verdict (either endpoint is a
			// collision loser) on every rule of the set.
			Rules: []*pb.PolicyRule{{Name: "wild-to-loser", Action: "permit", Quarantined: true}},
		}
	}
	globalGroup := func() *pb.PolicyInfo {
		return &pb.PolicyInfo{
			FromZone: "*",
			ToZone:   "*",
			Rules: []*pb.PolicyRule{
				{Name: "open-global", Action: "permit"},
				{Name: "scoped-loser", Action: "deny", MatchFromZones: []string{"dup"}, MatchToZones: []string{"untrust"}, Quarantined: true},
			},
		}
	}
	zonesResp := func() *pb.GetZonesResponse {
		return &pb.GetZonesResponse{
			Zones: []*pb.ZoneInfo{
				{Name: "trust", Id: 1, Interfaces: []string{"ge-0-0-0"}},
				{
					Name:                       "dup",
					Id:                         7,
					Interfaces:                 []string{"ge-0-0-1"},
					QuarantineState:            pb.ZoneQuarantineState_ZONE_QUARANTINE_STATE_QUARANTINED,
					QuarantineSurvivorZone:     "dup2",
					PerZoneCounterAvailability: pb.ZoneCounterAvailability_ZONE_COUNTER_AVAILABILITY_UNAVAILABLE,
				},
			},
		}
	}

	t.Run("quarantined zone", func(t *testing.T) {
		fake := &fakeBpfrxClient{
			getZonesResp: zonesResp(),
			getPoliciesResp: &pb.GetPoliciesResponse{Policies: []*pb.PolicyInfo{
				loserPair(), wildBoth(), wildToLoser(), globalGroup(),
			}},
		}
		c := &ctl{client: fake}
		out := captureStdout(t, func() {
			if err := c.showZones("dup"); err != nil {
				t.Fatalf("showZones(dup): %v", err)
			}
		})

		// Zone-level indicator: id-line qualifier + headline, the shared
		// spellings from config/zone_quarantine_show.go.
		if !strings.Contains(out, `Zone: dup (id: 7) (collides with "dup2" — would not be installed if this snapshot is applied)`) {
			t.Fatalf("quarantined zone id line missing the shared qualifier:\n%s", out)
		}
		if !strings.Contains(out, `QUARANTINED (id 7 collides with "dup2")`) {
			t.Fatalf("quarantined zone headline missing:\n%s", out)
		}
		if !strings.Contains(out, "would be unzoned if this snapshot is applied") {
			t.Fatalf("interfaces line missing the quarantine qualifier:\n%s", out)
		}
		// Counters: the quarantine line REPLACES the traffic block — the
		// survivor's volume must never read under the quarantined name.
		if !strings.Contains(out, "Traffic statistics: UNAVAILABLE (quarantined zone") {
			t.Fatalf("quarantined zone counters line missing:\n%s", out)
		}
		// Block-level policies qualifier for the viewed zone.
		if !strings.Contains(out, "(would be scrubbed if this snapshot is applied — quarantine candidate)") {
			t.Fatalf("block-level quarantine policies qualifier missing:\n%s", out)
		}
		// Literally-naming rows stay visible, each carrying the per-rule scrub
		// verdict the server stamped (PolicyRule.Quarantined).
		for _, row := range []string{
			"[zone-pair] dup -> untrust: loser-pair (permit) (would be scrubbed if this snapshot is applied — quarantine candidate)",
			"[zone-pair] any -> dup: wild-to-loser (permit) (would be scrubbed if this snapshot is applied — quarantine candidate)",
			"[global] dup -> untrust: scoped-loser (deny) (would be scrubbed if this snapshot is applied — quarantine candidate)",
		} {
			if !strings.Contains(out, row) {
				t.Fatalf("literally-naming row missing or missing its scrub qualifier: %q:\n%s", row, out)
			}
		}
		// Wildcard legs are gated: the builder omits this zone, so neither a
		// both-any zone-pair set nor an unscoped global can govern it.
		if strings.Contains(out, "wild-both") {
			t.Fatalf("wildcard zone-pair row attributed to a quarantined zone:\n%s", out)
		}
		if strings.Contains(out, "open-global") {
			t.Fatalf("unscoped global attributed to a quarantined zone:\n%s", out)
		}
	})

	t.Run("healthy peer keeps wildcard and global coverage", func(t *testing.T) {
		fake := &fakeBpfrxClient{
			getZonesResp: zonesResp(),
			getPoliciesResp: &pb.GetPoliciesResponse{Policies: []*pb.PolicyInfo{
				loserPair(), wildBoth(), wildToLoser(), globalGroup(),
			}},
		}
		c := &ctl{client: fake}
		out := captureStdout(t, func() {
			if err := c.showZones("trust"); err != nil {
				t.Fatalf("showZones(trust): %v", err)
			}
		})

		// A healthy installed zone is governed by the wildcard tiers...
		if !strings.Contains(out, "[zone-pair] any -> any: wild-both (permit)") {
			t.Fatalf("healthy zone lost the both-any wildcard row:\n%s", out)
		}
		// ...and carries no zone-level quarantine annotation of its own. (A
		// scrub-marked ROW is still correct here — `any -> dup` governs trust
		// via its wildcard from-side while its to-endpoint is a collision
		// loser, the peer-of-healthy-zone case — so only the zone-level
		// spellings are banned: the headline, the id-line and interfaces
		// qualifiers, the counters line, and the STANDALONE block qualifier.)
		for _, banned := range []string{
			"QUARANTINED",
			"would not be installed",
			"would be unzoned",
			"Traffic statistics: UNAVAILABLE (quarantined zone",
			"\n  (would be scrubbed if this snapshot is applied — quarantine candidate)\n",
		} {
			if strings.Contains(out, banned) {
				t.Fatalf("healthy zone rendered a zone-level quarantine annotation %q:\n%s", banned, out)
			}
		}
	})
}
