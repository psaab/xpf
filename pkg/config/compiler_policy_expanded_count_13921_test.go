package config

import (
	"fmt"
	"strings"
	"testing"
)

// #16560: the per-set 256 expanded-rule cap (#13921) is removed. Runtime
// policy IDs are contiguous per-set ranges, so 257 and 1000 rules in one
// zone pair (or the global set) commit; only the total
// MaxTotalPolicyRuleExpansion bound remains. Fail-on-revert: restoring
// the per-set cap makes the 257/1000 cases RED.

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

func TestPolicyExpandedRuleCountPerSetCapRemoved16560(t *testing.T) {
	for _, scope := range []string{"zonepair", "global"} {
		t.Run(scope+" 257 plain rules accepted", func(t *testing.T) {
			tree := buildAppMatchTree(t, policyExpansionCmds(scope, 257, 0)...)
			if _, err := CompileConfig(tree); err != nil {
				t.Fatalf("CompileConfig 257 err = %v, want nil (#16560)", err)
			}
		})
		t.Run(scope+" 1000 plain rules accepted", func(t *testing.T) {
			tree := buildAppMatchTree(t, policyExpansionCmds(scope, 1000, 0)...)
			if _, err := CompileConfig(tree); err != nil {
				t.Fatalf("CompileConfig 1000 err = %v, want nil (#16560)", err)
			}
		})
		t.Run(scope+" app-set multiplication accepted", func(t *testing.T) {
			// 13 policies x 20-app set = 260 expanded > legacy 256.
			tree := buildAppMatchTree(t, policyExpansionCmds(scope, 13, 20)...)
			if _, err := CompileConfig(tree); err != nil {
				t.Fatalf("CompileConfig app-set err = %v, want nil (#16560)", err)
			}
		})
		t.Run(scope+" exact 256 accepted", func(t *testing.T) {
			tree := buildAppMatchTree(t, policyExpansionCmds(scope, 256, 0)...)
			if _, err := CompileConfig(tree); err != nil {
				t.Fatalf("CompileConfig exact-256 err = %v, want nil", err)
			}
		})
	}
	// Tolerant path: 257 in one set is no longer even a warning.
	t.Run("lenient 257 no expansion warning", func(t *testing.T) {
		tree := buildAppMatchTree(t, policyExpansionCmds("zonepair", 257, 0)...)
		cfg, err := CompileConfigLenient(tree)
		if err != nil {
			t.Fatalf("CompileConfigLenient err = %v, want nil", err)
		}
		for _, w := range cfg.Warnings {
			if strings.Contains(w, "MaxRulesPerPolicy") || strings.Contains(w, "expanded rule count") {
				t.Fatalf("lenient 257 must not warn per-set cap: %v", cfg.Warnings)
			}
		}
	})
}
