package config

import (
	"fmt"
	"strings"
	"testing"
)

// #13921 (H02-02): a zone-pair or global policy set whose rules expand
// past 256 (MaxRulesPerPolicy) was ACCEPTED by strict commit, then
// failed at snapshot build (walkPolicyRuleSlots / legacy compiler),
// leaving the previously active config in place and no commit-time
// signal. The fix rejects the expanded count at commit time.
//
// fail-on-revert: removing validatePolicyExpandedRuleCountStrict (or
// its dispatch) turns the reject cases GREEN => RED here.

func policyExpansionCmds(scope string, nPolicies int, appsPerPolicy int) []string {
	cmds := append([]string{}, zoneBoilerplate...)
	if appsPerPolicy > 0 {
		for i := range appsPerPolicy {
			cmds = append(cmds, fmt.Sprintf("set applications application app%d protocol tcp destination-port %d", i, 1000+i))
			cmds = append(cmds, fmt.Sprintf("set applications application-set BIGSET application app%d", i))
		}
	}
	prefix := "set security policies global policy"
	if scope == "zonepair" {
		prefix = "set security policies from-zone trust to-zone untrust policy"
	}
	for i := range nPolicies {
		name := fmt.Sprintf("p%d", i)
		cmds = append(cmds,
			fmt.Sprintf("%s %s match source-address any", prefix, name),
			fmt.Sprintf("%s %s match destination-address any", prefix, name),
		)
		if appsPerPolicy > 0 {
			cmds = append(cmds, fmt.Sprintf("%s %s match application BIGSET", prefix, name))
		} else {
			cmds = append(cmds, fmt.Sprintf("%s %s match application any", prefix, name))
		}
		cmds = append(cmds, fmt.Sprintf("%s %s then permit", prefix, name))
	}
	return cmds
}

func TestPolicyExpandedRuleCountExceeds256RejectedAtCommit13921(t *testing.T) {
	for _, scope := range []string{"zonepair", "global"} {
		t.Run(scope+" 257 plain rules", func(t *testing.T) {
			tree := buildAppMatchTree(t, policyExpansionCmds(scope, 257, 0)...)
			if _, err := CompileConfig(tree); err == nil || !strings.Contains(err.Error(), "MaxRulesPerPolicy") {
				t.Fatalf("CompileConfig err = %v, want MaxRulesPerPolicy reject", err)
			}
		})
		t.Run(scope+" app-set multiplication", func(t *testing.T) {
			// 13 policies x 20-app set = 260 expanded > 256, raw count 13.
			tree := buildAppMatchTree(t, policyExpansionCmds(scope, 13, 20)...)
			if _, err := CompileConfig(tree); err == nil || !strings.Contains(err.Error(), "MaxRulesPerPolicy") {
				t.Fatalf("CompileConfig err = %v, want MaxRulesPerPolicy reject", err)
			}
		})
		t.Run(scope+" exact 256 accepted", func(t *testing.T) {
			tree := buildAppMatchTree(t, policyExpansionCmds(scope, 256, 0)...)
			if _, err := CompileConfig(tree); err != nil {
				t.Fatalf("CompileConfig exact-256 err = %v, want nil", err)
			}
		})
	}
	// Tolerant path downgrades to warning, still compiles (#1960).
	t.Run("lenient warns not rejects", func(t *testing.T) {
		tree := buildAppMatchTree(t, policyExpansionCmds("zonepair", 257, 0)...)
		cfg, err := CompileConfigLenient(tree)
		if err != nil {
			t.Fatalf("CompileConfigLenient err = %v, want nil", err)
		}
		found := false
		for _, w := range cfg.Warnings {
			if strings.Contains(w, "MaxRulesPerPolicy") {
				found = true
			}
		}
		if !found {
			t.Fatalf("lenient warnings missing MaxRulesPerPolicy: %v", cfg.Warnings)
		}
	})
}
