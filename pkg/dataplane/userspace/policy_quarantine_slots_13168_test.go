package userspace

import (
	"fmt"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #13168 (D4-12): walkPolicyRuleSlots runs before quarantineCollidingZones,
// so a quarantined zone's policies used to (a) brick snapshot compilation
// when their expansion exceeded MaxRulesPerPolicy or pushed the total past
// MaxTotalPolicyRuleExpansion, and (b) pollute PolicyIDsByStableKey /
// PoliciesByStableKey / RuntimePolicyIDs with phantom rules the published
// snapshot drops. The walker must skip quarantined zone-pair sets (still
// advancing policySetID so survivors keep their IDs) while the same
// overflow on a surviving zone stays fail-closed.

func d412CollidingZoneName(t *testing.T) string {
	t.Helper()
	targetID := config.StableZoneID("trust")
	for i := 0; i < 200000; i++ {
		cand := fmt.Sprintf("z-coll-%d", i)
		if config.StableZoneID(cand) == targetID {
			q := config.QuarantinedZoneNames([]string{"trust", cand})
			if _, ok := q[cand]; !ok {
				t.Fatalf("colliding zone %q not quarantined: %v", cand, q)
			}
			return cand
		}
	}
	t.Fatalf("no colliding zone name for trust (id=%d)", targetID)
	return ""
}

func d412Rules(prefix string, n int) []*config.Policy {
	out := make([]*config.Policy, 0, n)
	for i := range n {
		out = append(out, &config.Policy{
			Name:   fmt.Sprintf("%s-%d", prefix, i),
			Action: config.PolicyPermit,
			Match: config.PolicyMatch{
				SourceAddresses:      []string{"any"},
				DestinationAddresses: []string{"any"},
				Applications:         []string{"any"},
			},
		})
	}
	return out
}

func d412Cfg(colliding string, sets ...*config.ZonePairPolicies) *config.Config {
	return &config.Config{
		Security: config.SecurityConfig{
			Zones: map[string]*config.ZoneConfig{
				"trust":   {Name: "trust"},
				"untrust": {Name: "untrust"},
				colliding: {Name: colliding},
			},
			Policies: sets,
		},
	}
}

func d412SurvivorSet() *config.ZonePairPolicies {
	return &config.ZonePairPolicies{
		FromZone: "trust",
		ToZone:   "untrust",
		Policies: d412Rules("survivor", 1),
	}
}

func TestWalkPolicyRuleSlotsSkipsQuarantinedZones13168(t *testing.T) {
	colliding := d412CollidingZoneName(t)

	t.Run("quarantined_zone_beyond_max_rules_does_not_brick_snapshot", func(t *testing.T) {
		cfg := d412Cfg(colliding,
			d412SurvivorSet(),
			&config.ZonePairPolicies{FromZone: colliding, ToZone: "untrust", Policies: d412Rules("q", 257)},
		)
		snap, err := buildSnapshotWithSchedulerState(cfg, config.UserspaceConfig{}, 1, 1, nil, nil, nil)
		if err != nil {
			t.Fatalf("quarantined zone overflow bricked snapshot: %v", err)
		}
		if len(snap.Policies) != 1 {
			t.Fatalf("snap.Policies = %d, want 1 survivor", len(snap.Policies))
		}
		if got := snap.Policies[0].RuleID; !strings.HasPrefix(got, "trust->untrust/") {
			t.Fatalf("survivor rule ID = %q, want trust->untrust/...", got)
		}
		if reasons := PolicyContentRejectionReasons(cfg, nil); len(reasons) != 0 {
			t.Fatalf("PolicyContentRejectionReasons = %v, want none", reasons)
		}
	})

	t.Run("quarantined_zone_at_max_rules_keeps_stable_key_maps_clean", func(t *testing.T) {
		cfg := d412Cfg(colliding,
			d412SurvivorSet(),
			&config.ZonePairPolicies{FromZone: colliding, ToZone: "untrust", Policies: d412Rules("q", 256)},
		)
		snap, err := buildSnapshotWithSchedulerState(cfg, config.UserspaceConfig{}, 1, 1, nil, nil, nil)
		if err != nil {
			t.Fatalf("buildSnapshot: %v", err)
		}
		if len(snap.Policies) != 1 {
			t.Fatalf("snap.Policies = %d, want 1 survivor", len(snap.Policies))
		}
		ids := PolicyIDsByStableKey(cfg)
		if len(ids) != 1 {
			t.Fatalf("PolicyIDsByStableKey entries = %d, want 1 survivor only", len(ids))
		}
		if _, ok := ids["trust->untrust/survivor-0"]; !ok {
			t.Fatalf("PolicyIDsByStableKey missing survivor key, got %v", ids)
		}
		if got := PoliciesByStableKey(cfg); len(got) != 1 {
			t.Fatalf("PoliciesByStableKey entries = %d, want 1 survivor only", len(got))
		}
		if got := RuntimePolicyIDs(cfg); len(got) != 1 {
			t.Fatalf("RuntimePolicyIDs entries = %d, want 1 survivor only", len(got))
		}
	})

	t.Run("quarantined_zone_later_sets_keep_survivor_ids", func(t *testing.T) {
		// The quarantined set sits BEFORE the survivor set: skipping it must
		// still advance policySetID so the survivor keeps the ID the
		// snapshot assigns (set 1, not set 0).
		cfg := d412Cfg(colliding,
			&config.ZonePairPolicies{FromZone: colliding, ToZone: "untrust", Policies: d412Rules("q", 4)},
			d412SurvivorSet(),
		)
		snap, err := buildSnapshotWithSchedulerState(cfg, config.UserspaceConfig{}, 1, 1, nil, nil, nil)
		if err != nil {
			t.Fatalf("buildSnapshot: %v", err)
		}
		if len(snap.Policies) != 1 {
			t.Fatalf("snap.Policies = %d, want 1 survivor", len(snap.Policies))
		}
		ids := PolicyIDsByStableKey(cfg)
		want := snap.Policies[0].PolicyID
		if got, ok := ids["trust->untrust/survivor-0"]; !ok || got != want {
			t.Fatalf("PolicyIDsByStableKey survivor ID = %d (present=%v), want snapshot PolicyID %d", got, ok, want)
		}
	})

	t.Run("quarantined_expansion_does_not_exhaust_total_budget", func(t *testing.T) {
		// 300 quarantined sets x 256 rules = 76800 expanded rules > the
		// 65536 total cap; only the 1 survivor rule may count.
		sets := make([]*config.ZonePairPolicies, 0, 301)
		for range 300 {
			sets = append(sets, &config.ZonePairPolicies{FromZone: colliding, ToZone: "untrust", Policies: d412Rules("q", 256)})
		}
		sets = append(sets, d412SurvivorSet())
		cfg := d412Cfg(colliding, sets...)
		snap, err := buildSnapshotWithSchedulerState(cfg, config.UserspaceConfig{}, 1, 1, nil, nil, nil)
		if err != nil {
			t.Fatalf("quarantined expansion exhausted total budget: %v", err)
		}
		if len(snap.Policies) != 1 {
			t.Fatalf("snap.Policies = %d, want 1 survivor", len(snap.Policies))
		}
	})

	t.Run("survivor_overflow_still_fails_closed", func(t *testing.T) {
		cfg := d412Cfg(colliding,
			&config.ZonePairPolicies{FromZone: "trust", ToZone: "untrust", Policies: d412Rules("big", 257)},
		)
		if _, err := buildSnapshotWithSchedulerState(cfg, config.UserspaceConfig{}, 1, 1, nil, nil, nil); err == nil {
			t.Fatal("survivor set beyond MaxRulesPerPolicy built without error, want fail-closed")
		}
		if reasons := PolicyContentRejectionReasons(cfg, nil); len(reasons) == 0 {
			t.Fatal("PolicyContentRejectionReasons empty for survivor overflow, want rejection")
		}
	})
}
