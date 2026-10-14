package userspace

import (
	"slices"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #12849 (D4-01) — the full-build and scheduler-republish capability stamps
// omitted the #9410/#9570/#12249 zone arm and the #9584 duplicate-identity
// arm that PolicyContentRejectionReasons runs. A snapshot poisoned for
// `__unsupported__` by those paths therefore reached the pre-preflight disarm
// check in manager_ha.go with an empty PolicyContentRejected and was wrongly
// treated as healthy. These tests assert the stamps equal the standalone
// mirror reasons for triggers only those two arms produce.

// duplicateIdentityCfg12849 returns the lenient-compiled duplicate-rule config
// (two `security` roots, same zone pair, same policy name) that only the
// identity arm refuses, plus a healthy duplicate-free control.
func duplicateIdentityCfg12849(t *testing.T) (*config.Config, *config.Config) {
	t.Helper()
	dup := lenientHier9571(t, shapeA9584)
	control := lenientHier9571(t, `security { `+zones9584+
		` policies { from-zone trust to-zone untrust { `+pol9584("p1", "deny")+` } } }`)
	return dup, control
}

func assertStampEqualsMirror12849(t *testing.T, where string, cfg *config.Config, got []string) {
	t.Helper()
	want := PolicyContentRejectionReasons(cfg, nil)
	if len(want) == 0 {
		t.Fatalf("%s: fixture produces no mirror reasons; cannot prove the stamp", where)
	}
	if !slices.Equal(got, want) {
		t.Fatalf("%s: stamp = %v, want mirror reasons %v", where, got, want)
	}
}

func TestPolicyContentStampIncludesIdentityArm12849(t *testing.T) {
	cfg, control := duplicateIdentityCfg12849(t)

	snap, err := buildSnapshot(cfg, config.UserspaceConfig{}, 1, 0)
	if err != nil {
		t.Fatalf("buildSnapshot: %v", err)
	}
	if !strings.Contains(strings.Join(snap.Capabilities.PolicyContentRejected, "\n"), "DuplicateRuleId") {
		t.Fatalf("full-build stamp lacks the duplicate-identity reason: %v", snap.Capabilities.PolicyContentRejected)
	}
	assertStampEqualsMirror12849(t, "full-build", cfg, snap.Capabilities.PolicyContentRejected)

	controlSnap, err := buildSnapshot(control, config.UserspaceConfig{}, 1, 0)
	if err != nil {
		t.Fatalf("buildSnapshot(control): %v", err)
	}
	if len(controlSnap.Capabilities.PolicyContentRejected) != 0 {
		t.Fatalf("over-rejection control: stamp = %v, want empty", controlSnap.Capabilities.PolicyContentRejected)
	}
}

func TestPolicyContentStampIncludesZoneArm12849(t *testing.T) {
	cfg := compileLenient12249(t, []string{
		"set security zones security-zone any",
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		"set security policies from-zone any to-zone untrust policy from-any match source-address any",
		"set security policies from-zone any to-zone untrust policy from-any match destination-address any",
		"set security policies from-zone any to-zone untrust policy from-any match application any",
		"set security policies from-zone any to-zone untrust policy from-any then permit",
	})
	snap, err := buildSnapshot(cfg, config.UserspaceConfig{}, 1, 0)
	if err != nil {
		t.Fatalf("buildSnapshot: %v", err)
	}
	if len(snap.Capabilities.PolicyContentRejected) == 0 {
		t.Fatalf("full-build stamp empty for a defined-any policy the mirror refuses: %v", PolicyContentRejectionReasons(cfg, nil))
	}
	assertStampEqualsMirror12849(t, "full-build", cfg, snap.Capabilities.PolicyContentRejected)

	// The defined `any` zone is quarantined from the published zones, so the
	// stamp must use the pre-quarantine zone build, not snap.Zones.
	for _, z := range snap.Zones {
		if z.Name == config.ReservedWildcardZoneName {
			t.Fatal("fixture broken: defined `any` zone published")
		}
	}
}

func TestSchedulerRepublishStampIncludesIdentityAndZoneArms12849(t *testing.T) {
	cfg, control := duplicateIdentityCfg12849(t)

	m := New()
	m.lastSnapshot = mustBuildSnapshot(t, cfg, config.UserspaceConfig{}, 7, 0)
	next := *m.lastSnapshot
	if err := m.rebuildScheduledPolicySectionsWithLatchLocked(&next, cfg, map[string]bool{}, false); err != nil {
		t.Fatalf("rebuildScheduledPolicySections: %v", err)
	}
	assertStampEqualsMirror12849(t, "scheduler-republish", cfg, next.Capabilities.PolicyContentRejected)

	m.lastSnapshot = mustBuildSnapshot(t, control, config.UserspaceConfig{}, 7, 0)
	clean := *m.lastSnapshot
	if err := m.rebuildScheduledPolicySectionsWithLatchLocked(&clean, control, map[string]bool{}, false); err != nil {
		t.Fatalf("rebuildScheduledPolicySections(control): %v", err)
	}
	if len(clean.Capabilities.PolicyContentRejected) != 0 {
		t.Fatalf("over-rejection control: republish stamp = %v, want empty", clean.Capabilities.PolicyContentRejected)
	}
}

func TestSchedulerRepublishStampIncludesZoneArm12849(t *testing.T) {
	cfg := compileLenient12249(t, []string{
		"set security zones security-zone any",
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		"set security policies from-zone any to-zone untrust policy from-any match source-address any",
		"set security policies from-zone any to-zone untrust policy from-any match destination-address any",
		"set security policies from-zone any to-zone untrust policy from-any match application any",
		"set security policies from-zone any to-zone untrust policy from-any then permit",
	})
	m := New()
	m.lastSnapshot = mustBuildSnapshot(t, cfg, config.UserspaceConfig{}, 7, 0)
	next := *m.lastSnapshot
	if err := m.rebuildScheduledPolicySectionsWithLatchLocked(&next, cfg, map[string]bool{}, false); err != nil {
		t.Fatalf("rebuildScheduledPolicySections: %v", err)
	}
	if len(next.Capabilities.PolicyContentRejected) == 0 {
		t.Fatalf("scheduler-republish stamp empty for a defined-any policy the mirror refuses: %v", PolicyContentRejectionReasons(cfg, nil))
	}
	assertStampEqualsMirror12849(t, "scheduler-republish", cfg, next.Capabilities.PolicyContentRejected)
}
