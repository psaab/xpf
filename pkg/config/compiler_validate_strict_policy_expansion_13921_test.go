package config

import (
	"fmt"
	"strings"
	"testing"
)

// #14353 (D8-06): validatePolicyExpandedRuleCountStrict enforced only
// the per-set MaxPolicyRulesPerSet (256) bound. A config whose zone-pair
// sets each fit 256 but whose TOTAL expanded rules exceed the dataplane
// MaxTotalPolicyRuleExpansion (65536) committed green, then failed
// walkPolicyRuleSlots at apply, leaving the stale snapshot enforced.
// The validator was also only reachable at the tail of
// validatePolicyMatchApplicationsStrict, so on the tolerant path an
// earlier undefined-application error suppressed the #13921 warning
// wholesale.
//
// Decisive test named by the issue. fail-on-revert: dropping the total
// accumulator, the quarantine skip, or the independent tailgate
// registration turns the corresponding cell GREEN => RED here.

// collisionFreeZoneNames14353 returns n zone names with distinct
func collisionFreeZoneNames14353(n int) []string {
	seen := map[uint16]struct{}{StableZoneID("trust"): {}, StableZoneID("untrust"): {}}
	names := make([]string, 0, n)
	for i := 0; len(names) < n; i++ {
		name := fmt.Sprintf("z%d", i)
		if _, dup := seen[StableZoneID(name)]; dup {
			continue
		}
		seen[StableZoneID(name)] = struct{}{}
		names = append(names, name)
	}
	return names
}

// policyExpansionTotalCmds builds sets zone pairs (chained over
// collision-free zones), each with rulesPerSet plain policies.
func policyExpansionTotalCmds(sets, rulesPerSet int) []string {
	zones := collisionFreeZoneNames14353(sets + 1)
	cmds := []string{}
	for _, z := range zones {
		cmds = append(cmds, "set security zones security-zone "+z)
	}
	for pair := range sets {
		from, to := zones[pair], zones[pair+1]
		for i := range rulesPerSet {
			name := fmt.Sprintf("p%d", i)
			prefix := fmt.Sprintf("set security policies from-zone %s to-zone %s policy %s", from, to, name)
			cmds = append(cmds,
				prefix+" match source-address any",
				prefix+" match destination-address any",
				prefix+" match application any",
				prefix+" then permit",
			)
		}
	}
	return cmds
}

func hasExpansionWarning14353(cfg *Config, subs ...string) bool {
	for _, w := range cfg.Warnings {
		ok := true
		for _, s := range subs {
			if !strings.Contains(w, s) {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}

func TestPolicyExpandedRuleCountTotalLimit65536AndLenientIndependence(t *testing.T) {
	// Strict: total over 65536 rejected at commit even though every
	// individual set fits 256.
	t.Run("strict total 69632 rejected", func(t *testing.T) {
		tree := buildAppMatchTree(t, policyExpansionTotalCmds(272, 256)...)
		_, err := CompileConfig(tree)
		if err == nil || !strings.Contains(err.Error(), "MaxTotalPolicyRuleExpansion") {
			t.Fatalf("CompileConfig err = %v, want MaxTotalPolicyRuleExpansion reject", err)
		}
	})

	// Boundary: exactly 65536 (256 sets x 256) commits clean.
	t.Run("strict exact 65536 accepted", func(t *testing.T) {
		tree := buildAppMatchTree(t, policyExpansionTotalCmds(256, 256)...)
		if _, err := CompileConfig(tree); err != nil {
			t.Fatalf("CompileConfig exact-65536 err = %v, want nil", err)
		}
	})

	// Quarantine: sets touching a quarantined zone are excluded from
	// both the per-set and total accounting (mirroring
	// walkPolicyRuleSlots), while the same overflow on a surviving
	// zone stays fail-closed. trust collides with `colliding` (later
	// sorting, quarantined); its 257-rule set must not reject, and a
	// surviving 257-rule set must still reject.
	t.Run("quarantined set excluded, survivor overflow still rejected", func(t *testing.T) {
		colliding := ""
		target := StableZoneID("trust")
		for i := 0; colliding == ""; i++ {
			name := fmt.Sprintf("zcollide%d", i)
			if name > "trust" && StableZoneID(name) == target {
				colliding = name
			}
		}
		build := func(surviving int) []string {
			cmds := []string{
				"set security zones security-zone trust",
				"set security zones security-zone untrust",
				"set security zones security-zone " + colliding,
			}
			// Quarantined pair trust->colliding carries 257 rules.
			for i := range 257 {
				name := fmt.Sprintf("q%d", i)
				prefix := fmt.Sprintf("set security policies from-zone trust to-zone %s policy %s", colliding, name)
				cmds = append(cmds, prefix+" match source-address any", prefix+" match destination-address any", prefix+" match application any", prefix+" then permit")
			}
			// Surviving pair trust->untrust carries `surviving` rules.
			n := surviving
			for i := range n {
				name := fmt.Sprintf("p%d", i)
				prefix := fmt.Sprintf("set security policies from-zone trust to-zone untrust policy %s", name)
				cmds = append(cmds, prefix+" match source-address any", prefix+" match destination-address any", prefix+" match application any", prefix+" then permit")
			}
			return cmds
		}
		// Direct validator check: quarantined overflow alone passes.
		cfg, err := CompileConfigLenient(buildAppMatchTree(t, build(256)...))
		if err != nil {
			t.Fatalf("lenient err = %v", err)
		}
		if _, excluded := ZoneQuarantineExclusionsForConfig(cfg)[colliding]; !excluded {
			t.Fatalf("premise: %q not quarantined: %v", colliding, ZoneQuarantineExclusionsForConfig(cfg))
		}
		if err := validatePolicyExpandedRuleCountStrict(cfg); err != nil {
			t.Fatalf("quarantined 257-rule set rejected: %v (walkPolicyRuleSlots skips it)", err)
		}
		cfg2, err := CompileConfigLenient(buildAppMatchTree(t, build(257)...))
		if err != nil {
			t.Fatalf("lenient err = %v", err)
		}
		if err := validatePolicyExpandedRuleCountStrict(cfg2); err == nil || !strings.Contains(err.Error(), "MaxRulesPerPolicy") {
			t.Fatalf("surviving 257-rule set err = %v, want MaxRulesPerPolicy reject", err)
		}
	})

	// Scoped-global: a global rule whose configured scope side is
	// fully quarantined is dropped by the walker and must not count.
	t.Run("fully quarantined scoped global excluded", func(t *testing.T) {
		colliding := ""
		target := StableZoneID("trust")
		for i := 0; colliding == ""; i++ {
			name := fmt.Sprintf("zcollide%d", i)
			if name > "trust" && StableZoneID(name) == target {
				colliding = name
			}
		}
		cfg := &Config{}
		cfg.Security.Zones = map[string]*ZoneConfig{"trust": {}, "untrust": {}, colliding: {}}
		cfg.ZoneQuarantineNames = []string{"trust", "untrust", colliding}
		for i := range 257 {
			pol := &Policy{Name: fmt.Sprintf("g%d", i)}
			pol.Match.FromZones = []string{colliding}
			cfg.Security.GlobalPolicies = append(cfg.Security.GlobalPolicies, pol)
		}
		if _, excluded := ZoneQuarantineExclusionsForConfig(cfg)[colliding]; !excluded {
			t.Fatalf("premise: %q not quarantined", colliding)
		}
		if err := validatePolicyExpandedRuleCountStrict(cfg); err != nil {
			t.Fatalf("fully-quarantined scoped globals counted: %v (walker drops them)", err)
		}
		// Control: same rules unscoped count toward the global per-set cap.
		cfg2 := &Config{}
		cfg2.Security.Zones = map[string]*ZoneConfig{"trust": {}, "untrust": {}, colliding: {}}
		cfg2.ZoneQuarantineNames = []string{"trust", "untrust", colliding}
		for i := range 257 {
			cfg2.Security.GlobalPolicies = append(cfg2.Security.GlobalPolicies, &Policy{Name: fmt.Sprintf("g%d", i)})
		}
		if err := validatePolicyExpandedRuleCountStrict(cfg2); err == nil || !strings.Contains(err.Error(), "MaxRulesPerPolicy") {
			t.Fatalf("unscoped 257 globals err = %v, want MaxRulesPerPolicy reject", err)
		}
	})

	// Lenient independence: an undefined application in an earlier
	// policy must not suppress the expansion warning. One set of 257
	// plain policies (>256 per-set) plus a first policy referencing an
	// undefined application.
	t.Run("lenient warning survives undefined application", func(t *testing.T) {
		cmds := append([]string{}, zoneBoilerplate...)
		cmds = append(cmds,
			"set security policies from-zone trust to-zone untrust policy bad match source-address any",
			"set security policies from-zone trust to-zone untrust policy bad match destination-address any",
			"set security policies from-zone trust to-zone untrust policy bad match application NO_SUCH_APP_14353",
			"set security policies from-zone trust to-zone untrust policy bad then permit",
		)
		for i := range 257 {
			name := fmt.Sprintf("p%d", i)
			prefix := fmt.Sprintf("set security policies from-zone trust to-zone untrust policy %s", name)
			cmds = append(cmds,
				prefix+" match source-address any",
				prefix+" match destination-address any",
				prefix+" match application any",
				prefix+" then permit",
			)
		}
		tree := buildAppMatchTree(t, cmds...)
		cfg, err := CompileConfigLenient(tree)
		if err != nil {
			t.Fatalf("CompileConfigLenient err = %v, want nil", err)
		}
		if !hasExpansionWarning14353(cfg, "policy match application", "NO_SUCH_APP_14353") {
			t.Fatalf("lenient warnings missing undefined-application warning: %v", cfg.Warnings)
		}
		if !hasExpansionWarning14353(cfg, "MaxRulesPerPolicy") {
			t.Fatalf("lenient warnings missing expansion (MaxRulesPerPolicy) warning; expansion gate was suppressed by the earlier undefined application: %v", cfg.Warnings)
		}
	})

	// Lenient total-limit warning: 272 sets x 256 warns (not rejects).
	t.Run("lenient total 69632 warns not rejects", func(t *testing.T) {
		tree := buildAppMatchTree(t, policyExpansionTotalCmds(272, 256)...)
		cfg, err := CompileConfigLenient(tree)
		if err != nil {
			t.Fatalf("CompileConfigLenient err = %v, want nil", err)
		}
		if !hasExpansionWarning14353(cfg, "MaxTotalPolicyRuleExpansion") {
			t.Fatalf("lenient warnings missing MaxTotalPolicyRuleExpansion: %v", cfg.Warnings)
		}
	})
}
