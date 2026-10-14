package userspace

import (
	"slices"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #12850 D4-03: PolicyContentRejectionReasons must evaluate the POST-quarantine
// policy/zone view the helper actually receives.
func TestPolicyContentRejectionReasonsPostQuarantine12850(t *testing.T) {
	t.Run("reserved_junos_global_global_scope_is_reported", func(t *testing.T) {
		cfg := compileLenient9570(t, cat9570(
			[]string{
				"set security zones security-zone trust",
				"set security zones security-zone junos-global",
				"set security policies default-policy deny-all",
			},
			global9570("reserved-scope", "permit", "from-zone junos-global"),
		))
		snap := mustBuildSnapshot(t, cfg, config.UserspaceConfig{}, 1, 0)
		for _, z := range snap.Zones {
			if z.Name == "junos-global" {
				t.Fatalf("premise: reserved zone published in snapshot zones")
			}
		}
		found := false
		for _, p := range snap.Policies {
			if p.Name == "reserved-scope" {
				found = true
			}
		}
		if !found {
			t.Fatalf("premise: global rule should survive quarantine, policies=%v", snap.Policies)
		}
		reasons := PolicyContentRejectionReasons(cfg, nil)
		if len(reasons) == 0 || !strings.Contains(strings.Join(reasons, "\n"), "junos-global") || !strings.Contains(strings.Join(reasons, "\n"), "reserved-scope") {
			t.Fatalf("reserved junos-global global scope must be reported, got %q", reasons)
		}
		if !slices.Equal(snap.Capabilities.PolicyContentRejected, reasons) {
			t.Fatalf("stamp/mirror parity: snap=%q mirror=%q", snap.Capabilities.PolicyContentRejected, reasons)
		}
		schedulerSnap := publishCIDRMaskSchedulerSnapshot12122(t, cfg)
		if !slices.Equal(schedulerSnap.Capabilities.PolicyContentRejected, reasons) {
			t.Fatalf("scheduler stamp/mirror parity: scheduler=%q mirror=%q", schedulerSnap.Capabilities.PolicyContentRejected, reasons)
		}
	})

	t.Run("collision_loser_content_does_not_leave_phantom", func(t *testing.T) {
		if config.StableZoneID("z174") != config.StableZoneID("z214") {
			t.Fatalf("premise: z174/z214 no longer collide")
		}
		cfg := compileLenient9570(t, cat9570(
			[]string{
				"set security zones security-zone z174",
				"set security zones security-zone z214",
				"set security zones security-zone trust",
				"set security policies default-policy deny-all",
			},
			zonePair9570("trust", "z214", "loser-rule", "permit"),
			zonePair9570("trust", "z174", "winner-rule", "permit"),
		))
		// Make the loser rule independently helper-refused. Since quarantine
		// removes that whole rule, its content must not reject the snapshot.
		for _, pair := range cfg.Security.Policies {
			if pair.ToZone == "z214" {
				pair.Policies[0].Match.Applications = []string{"no-such-application"}
			}
		}
		snap := mustBuildSnapshot(t, cfg, config.UserspaceConfig{}, 1, 0)
		winnerFound := false
		for _, p := range snap.Policies {
			if p.Name == "loser-rule" {
				t.Fatalf("premise: loser-rule survived quarantine scrub")
			}
			winnerFound = winnerFound || p.Name == "winner-rule"
		}
		if !winnerFound {
			t.Fatal("premise: surviving collision winner rule was removed")
		}
		reasons := PolicyContentRejectionReasons(cfg, nil)
		if len(reasons) != 0 {
			t.Fatalf("collision-loser scrubbed rule must not produce phantom rejection, got %q", reasons)
		}
		if !slices.Equal(snap.Capabilities.PolicyContentRejected, reasons) {
			t.Fatalf("stamp/mirror parity: snap=%q mirror=%q", snap.Capabilities.PolicyContentRejected, reasons)
		}
		schedulerSnap := publishCIDRMaskSchedulerSnapshot12122(t, cfg)
		if !slices.Equal(schedulerSnap.Capabilities.PolicyContentRejected, reasons) {
			t.Fatalf("scheduler stamp/mirror parity: scheduler=%q mirror=%q", schedulerSnap.Capabilities.PolicyContentRejected, reasons)
		}
	})

	t.Run("partially_pruned_scoped_global_uses_survivors", func(t *testing.T) {
		cfg := compileLenient9570(t, cat9570(
			[]string{
				"set security zones security-zone z174",
				"set security zones security-zone z214",
				"set security zones security-zone trust",
				"set security policies default-policy deny-all",
			},
			global9570("pruned-global", "deny", "from-zone z214", "from-zone z174"),
		))
		snap := mustBuildSnapshot(t, cfg, config.UserspaceConfig{}, 1, 0)
		var found bool
		for _, p := range snap.Policies {
			if p.Name == "pruned-global" {
				found = true
				if !slices.Equal(p.effectiveMatchFromZones(), []string{"z174"}) || p.MatchFromZone != "z174" {
					t.Fatalf("scoped-global did not prune loser and preserve winner: plural=%v singular=%q", p.effectiveMatchFromZones(), p.MatchFromZone)
				}
			}
		}
		if !found {
			t.Fatalf("scoped-global was unexpectedly dropped: policies=%v", snap.Policies)
		}
		reasons := PolicyContentRejectionReasons(cfg, nil)
		if len(reasons) != 0 {
			t.Fatalf("pruned scoped-global must not produce phantom rejection, got %q snapPolicies=%v", reasons, snap.Policies)
		}
		if !slices.Equal(snap.Capabilities.PolicyContentRejected, reasons) {
			t.Fatalf("stamp/mirror parity: snap=%q mirror=%q", snap.Capabilities.PolicyContentRejected, reasons)
		}
	})

	t.Run("unscoped_and_wildcard_globals_unchanged", func(t *testing.T) {
		cfg := compileLenient9570(t, cat9570(
			base9570(),
			global9570("plain-global", "permit"),
			global9570("wild-global", "permit", "from-zone any"),
		))
		if reasons := PolicyContentRejectionReasons(cfg, nil); len(reasons) != 0 {
			t.Fatalf("unscoped/wildcard globals must not be rejected: %q", reasons)
		}
		snap := mustBuildSnapshot(t, cfg, config.UserspaceConfig{}, 1, 0)
		if len(snap.Capabilities.PolicyContentRejected) != 0 {
			t.Fatalf("stamp must be empty: %q", snap.Capabilities.PolicyContentRejected)
		}
	})

	t.Run("reserved_absent_typo_still_reported", func(t *testing.T) {
		cfg := compileLenient9570(t, cat9570(
			base9570(),
			global9570("typo-global", "permit", "from-zone no-such-zone"),
		))
		if reasons := PolicyContentRejectionReasons(cfg, nil); len(reasons) == 0 {
			t.Fatalf("typo scope must still be reported")
		}
	})
}
