package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #14330 (D5-03): PolicyResolvedFingerprints /
// PolicyResolvedIdentityStrippedFingerprints hashed the raw
// buildPolicySnapshotsWithAddressBook output, and PolicyIDsByStableKey /
// PoliciesByStableKey walked raw global policies, without the
// scrubPoliciesForQuarantinedZones step the publish path applies via
// quarantineCollidingZones / policySnapshotAfterZoneQuarantine. A commit
// whose only enforcement change is a zone becoming quarantined (StableZoneID
// collision z174/z214, or a poisoned zone) therefore produced identical
// fingerprints/ID maps while the published snapshot dropped or narrowed the
// rule, so daemon_policy_invalidate never flagged live sessions for
// policy-rematch re-evaluation.
//
// Fixture uses the verified colliding pair z174/z214 (z214 is the
// later-sorting loser). The "quarantined" config differs from "clean" only
// by adding z214 to the zone set — no policy text changes.

func fingerprintQuarantineConfig(zones []string, pol *config.Policy) *config.Config {
	z := make(map[string]*config.ZoneConfig, len(zones))
	for _, name := range zones {
		z[name] = &config.ZoneConfig{Name: name}
	}
	return &config.Config{
		Security: config.SecurityConfig{
			Zones:          z,
			GlobalPolicies: []*config.Policy{pol},
		},
	}
}

func fingerprintQuarantinePolicy(fromZones []string) *config.Policy {
	return &config.Policy{
		Name: "g-scoped",
		Match: config.PolicyMatch{
			SourceAddresses:      []string{"any"},
			DestinationAddresses: []string{"any"},
			Applications:         []string{"any"},
			FromZones:            fromZones,
			ToZones:              []string{"untrust"},
		},
		Action: config.PolicyPermit,
	}
}

func TestPolicyResolvedFingerprintsReflectZoneQuarantineScrub(t *testing.T) {
	if config.StableZoneID("z174") != config.StableZoneID("z214") {
		t.Fatalf("test premise broken: z174/z214 no longer collide under the frozen fold")
	}
	const key = "junos-global->junos-global/g-scoped"

	t.Run("multi_zone_partial_quarantine_changes_fingerprint", func(t *testing.T) {
		// Global policy scoped from [z174 z214]: quarantining z214 must
		// prune the scope to [z174] in the published snapshot, so the
		// resolved fingerprint must change even though policy text is
		// identical.
		clean := fingerprintQuarantineConfig(
			[]string{"z174", "untrust"},
			fingerprintQuarantinePolicy([]string{"z174", "z214"}),
		)
		quarantined := fingerprintQuarantineConfig(
			[]string{"z174", "z214", "untrust"},
			fingerprintQuarantinePolicy([]string{"z174", "z214"}),
		)

		// Positive control: the publish path really does narrow the rule.
		snap, err := buildSnapshot(quarantined, config.UserspaceConfig{}, 0, 0)
		if err != nil {
			t.Fatalf("buildSnapshot(quarantined): %v", err)
		}
		if len(snap.Policies) != 1 {
			t.Fatalf("published policies = %d, want 1 pruned survivor", len(snap.Policies))
		}
		if got := snap.Policies[0].effectiveMatchFromZones(); len(got) != 1 || got[0] != "z174" {
			t.Fatalf("published from-scope = %v, want [z174] (z214 pruned)", got)
		}

		before := PolicyResolvedFingerprints(clean, nil)
		after := PolicyResolvedFingerprints(quarantined, nil)
		if before[key] == "" {
			t.Fatalf("precondition: clean fingerprint missing %q: %v", key, before)
		}
		if after[key] == "" {
			t.Fatalf("pruned rule must retain fingerprint key %q: %v", key, after)
		}
		if after[key] == before[key] {
			t.Fatalf("#14330: quarantining z214 from a multi-zone global policy did not change "+
				"PolicyResolvedFingerprints (unscrubbed hash masks the published narrowing): %v", before)
		}

		strippedBefore := PolicyResolvedIdentityStrippedFingerprints(clean, nil)
		strippedAfter := PolicyResolvedIdentityStrippedFingerprints(quarantined, nil)
		// Identity-stripped fingerprints deliberately erase zone scope
		// (#12857) so a pure zone rename keeps rename continuity; a
		// quarantine prune is likewise identity-only content there. The
		// stripped map must still CONTAIN the surviving rule.
		if strippedBefore[key] == "" || strippedAfter[key] == "" {
			t.Fatalf("identity-stripped fingerprints must contain surviving rule %q: before=%v after=%v",
				key, strippedBefore, strippedAfter)
		}

		// The ID/policy maps must keep the pruned survivor.
		if _, ok := PolicyIDsByStableKey(quarantined)[key]; !ok {
			t.Fatalf("PolicyIDsByStableKey dropped pruned survivor %q: %v", key, PolicyIDsByStableKey(quarantined))
		}
		if _, ok := PoliciesByStableKey(quarantined)[key]; !ok {
			t.Fatalf("PoliciesByStableKey dropped pruned survivor %q", key)
		}
	})

	t.Run("sole_zone_quarantine_removes_key", func(t *testing.T) {
		// Global policy scoped solely to z214: quarantining z214 drops the
		// whole rule from the published snapshot (leaving the side empty
		// would broaden to all zones). Its key must vanish from the
		// fingerprint and ID maps so the deletion-clear / rematch paths
		// re-evaluate its live sessions.
		clean := fingerprintQuarantineConfig(
			[]string{"z174", "untrust"},
			fingerprintQuarantinePolicy([]string{"z214"}),
		)
		quarantined := fingerprintQuarantineConfig(
			[]string{"z174", "z214", "untrust"},
			fingerprintQuarantinePolicy([]string{"z214"}),
		)

		// Positive control: the publish path drops the rule entirely.
		snap, err := buildSnapshot(quarantined, config.UserspaceConfig{}, 0, 0)
		if err != nil {
			t.Fatalf("buildSnapshot(quarantined): %v", err)
		}
		if len(snap.Policies) != 0 {
			t.Fatalf("published policies = %d, want 0 (sole-zone rule dropped)", len(snap.Policies))
		}

		before := PolicyResolvedFingerprints(clean, nil)
		if before[key] == "" {
			t.Fatalf("precondition: clean fingerprint missing %q: %v", key, before)
		}
		after := PolicyResolvedFingerprints(quarantined, nil)
		if _, ok := after[key]; ok {
			t.Fatalf("#14330: sole-zone-quarantined rule retained fingerprint key %q: %v", key, after)
		}

		strippedAfter := PolicyResolvedIdentityStrippedFingerprints(quarantined, nil)
		if _, ok := strippedAfter[key]; ok {
			t.Fatalf("#14330: sole-zone-quarantined rule retained identity-stripped key %q: %v", key, strippedAfter)
		}

		if _, ok := PolicyIDsByStableKey(clean)[key]; !ok {
			t.Fatalf("precondition: clean PolicyIDsByStableKey missing %q", key)
		}
		if _, ok := PolicyIDsByStableKey(quarantined)[key]; ok {
			t.Fatalf("#14330: sole-zone-quarantined rule retained PolicyIDsByStableKey key %q: %v",
				key, PolicyIDsByStableKey(quarantined))
		}
		if _, ok := PoliciesByStableKey(quarantined)[key]; ok {
			t.Fatalf("#14330: sole-zone-quarantined rule retained PoliciesByStableKey key %q", key)
		}
	})

	t.Run("poisoned_sole_zone_quarantine_removes_key", func(t *testing.T) {
		// Same sole-zone drop via DroppedEnforcementChild poisoning rather
		// than a StableZoneID collision.
		clean := fingerprintQuarantineConfig(
			[]string{"trust", "untrust"},
			&config.Policy{
				Name: "g-scoped",
				Match: config.PolicyMatch{
					SourceAddresses:      []string{"any"},
					DestinationAddresses: []string{"any"},
					Applications:         []string{"any"},
					FromZones:            []string{"trust"},
					ToZones:              []string{"untrust"},
				},
				Action: config.PolicyPermit,
			},
		)
		poisoned := fingerprintQuarantineConfig(
			[]string{"trust", "untrust"},
			&config.Policy{
				Name: "g-scoped",
				Match: config.PolicyMatch{
					SourceAddresses:      []string{"any"},
					DestinationAddresses: []string{"any"},
					Applications:         []string{"any"},
					FromZones:            []string{"trust"},
					ToZones:              []string{"untrust"},
				},
				Action: config.PolicyPermit,
			},
		)
		poisoned.Security.Zones["trust"].DroppedEnforcementChild = true

		snap, err := buildSnapshot(poisoned, config.UserspaceConfig{}, 0, 0)
		if err != nil {
			t.Fatalf("buildSnapshot(poisoned): %v", err)
		}
		if len(snap.Policies) != 0 {
			t.Fatalf("published policies = %d, want 0 (poisoned sole-zone rule dropped)", len(snap.Policies))
		}

		if _, ok := PolicyResolvedFingerprints(clean, nil)[key]; !ok {
			t.Fatalf("precondition: clean fingerprint missing %q", key)
		}
		if _, ok := PolicyResolvedFingerprints(poisoned, nil)[key]; ok {
			t.Fatalf("#14330: poisoned sole-zone rule retained fingerprint key %q", key)
		}
		if _, ok := PolicyIDsByStableKey(poisoned)[key]; ok {
			t.Fatalf("#14330: poisoned sole-zone rule retained PolicyIDsByStableKey key %q", key)
		}
		if _, ok := PoliciesByStableKey(poisoned)[key]; ok {
			t.Fatalf("#14330: poisoned sole-zone rule retained PoliciesByStableKey key %q", key)
		}
	})

	t.Run("unscoped_global_unaffected", func(t *testing.T) {
		// Control: an unscoped global policy (all zones) must survive a
		// quarantine transition untouched — fingerprint and ID stable.
		mk := func(zones []string) *config.Config {
			return fingerprintQuarantineConfig(zones, &config.Policy{
				Name: "g-scoped",
				Match: config.PolicyMatch{
					SourceAddresses:      []string{"any"},
					DestinationAddresses: []string{"any"},
					Applications:         []string{"any"},
				},
				Action: config.PolicyPermit,
			})
		}
		before := PolicyResolvedFingerprints(mk([]string{"z174", "untrust"}), nil)
		after := PolicyResolvedFingerprints(mk([]string{"z174", "z214", "untrust"}), nil)
		if before[key] == "" || after[key] != before[key] {
			t.Fatalf("unscoped global fingerprint changed across quarantine: before=%v after=%v", before, after)
		}
		if _, ok := PolicyIDsByStableKey(mk([]string{"z174", "z214", "untrust"}))[key]; !ok {
			t.Fatalf("unscoped global missing from PolicyIDsByStableKey")
		}
	})
}
