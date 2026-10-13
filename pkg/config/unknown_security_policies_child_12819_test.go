package config

import (
	"strings"
	"testing"
)

// #12819: the #12628 exemption for `traceoptions`, `policy-stats`, and
// `pre-id-default-policy` under `security policies` was by keyword alone.
// A fused enforcement-bearing subtree under one of those names was
// accepted opaquely (schema walk) and skipped without poison (compiler),
// so a nested DENY rulebase vanished on strict and tolerant compiles.
// The exemption is now structural: only the exact non-enforcement grammar
// is exempt; any tail/subtree outside it is enforcement-bearing.

func fusedPoliciesConfig12819(child string) string {
	return policiesBase12628 + "  " + child + "\n" + policiesClose12628
}

func TestFusedEnforcementUnderNonEnforcementNamesPoisons12819(t *testing.T) {
	for _, tc := range []struct{ name, child string }{
		{"traceoptions-global-deny", `traceoptions { global { policy deny-bad { match { source-address any; destination-address any; application any; } then { deny; } } } }`},
		{"traceoptions-from-zone-deny", `traceoptions { from-zone trust to-zone untrust { policy deny-bad { match { source-address any; destination-address any; application any; } then { deny; } } } }`},
		{"traceoptions-default-policy-permit", `traceoptions { default-policy permit-all; }`},
		{"traceoptions-policy", `traceoptions { policy deny-bad { match { source-address any; destination-address any; application any; } then { deny; } } }`},
		{"traceoptions-packed-deny-tail", `traceoptions global policy deny-bad;`},
		{"traceoptions-file-packed-policy-tail", `traceoptions { file trace.log global policy deny-bad; }`},
		{"traceoptions-filter-packed-policy-tail", `traceoptions { packet-filter f1 { source-prefix 10.0.0.0/8 global policy deny-bad; } }`},
		{"traceoptions-flag-packed-policy-tail", `traceoptions { flag basic-datapath global policy deny-bad; }`},
		{"pre-id-default-policy-log-packed-policy-tail", `pre-id-default-policy { then { log session-init global policy deny-bad; } }`},
		{"policy-stats-global-deny", `policy-stats { global { policy deny-bad { then { deny; } } } }`},
		{"policy-stats-unknown-flag", `policy-stats { frobnicate enable; }`},
		{"pre-id-default-policy-deny", `pre-id-default-policy { then { deny; } }`},
		{"pre-id-default-policy-policy", `pre-id-default-policy { policy deny-bad { then { deny; } } }`},
		{"pre-id-default-policy-global", `pre-id-default-policy { global { policy deny-bad { then { deny; } } } }`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			text := fusedPoliciesConfig12819(tc.child)
			// Strict: schema + compile must reject.
			tree := parseUnknownSecurityPoliciesChildren12217(t, text)
			if err := SchemaValidate(tree, nil); err == nil {
				t.Fatalf("strict schema accepted fused enforcement child %s", tc.child)
			} else if !strings.Contains(err.Error(), "content") || !strings.Contains(err.Error(), "traceoptions") &&
				!strings.Contains(err.Error(), "policy-stats") && !strings.Contains(err.Error(), "pre-id-default-policy") {
				t.Fatalf("schema rejection does not identify rejected child content: %v", err)
			}
			treeS := parseUnknownSecurityPoliciesChildren12217(t, text)
			if _, err := CompileConfig(treeS); err == nil {
				t.Fatalf("strict compile accepted fused enforcement child %s", tc.child)
			}
			// Lenient: must record, warn as unknown (#12217, not #12628 benign), and poison.
			tree2 := parseUnknownSecurityPoliciesChildren12217(t, text)
			cfg, err := CompileConfigLenient(tree2)
			if err != nil {
				t.Fatalf("lenient compile: %v", err)
			}
			if len(cfg.Security.UnknownPoliciesChildren) != 1 {
				t.Fatalf("UnknownPoliciesChildren = %v, want 1 fused record", cfg.Security.UnknownPoliciesChildren)
			}
			if policiesCarrierCount12628(cfg) != 1 {
				t.Fatalf("poison carriers = %d, want 1 for fused %s (children=%v)",
					policiesCarrierCount12628(cfg), tc.child, cfg.Security.UnknownPoliciesChildren)
			}
			if !policiesHasPermit12628(cfg) {
				t.Fatal("valid permit policy lost alongside fused child")
			}
			var saw12217 bool
			for _, w := range cfg.Warnings {
				if strings.Contains(w, "#12628") && strings.Contains(w, cfg.Security.UnknownPoliciesChildren[0]) {
					t.Fatalf("fused child warned as benign #12628: %q", w)
				}
				if strings.Contains(w, "#12217") {
					saw12217 = true
				}
			}
			if !saw12217 {
				t.Fatalf("fused child missing #12217 quarantine warning: %v", cfg.Warnings)
			}
		})
	}
}

// Genuine non-enforcement forms remain exempt: strict + lenient clean,
// no poison, #12628 warning only (positive control / mutant guard).
func TestGenuineNonEnforcementStillExempt12819(t *testing.T) {
	for _, tc := range []struct{ name, child string }{
		{"traceoptions-flags", `traceoptions { file trace.log size 1048576 files 5; flag basic-datapath; }`},
		{"traceoptions-packet-filter", `traceoptions { packet-filter f1 { source-prefix 10.0.0.0/8; } }`},
		{"policy-stats-system-wide", `policy-stats { system-wide enable; }`},
		{"pre-id-default-policy-log", `pre-id-default-policy { then { log { session-init; session-close; } } }`},
		{"traceoptions-packed-flag", `traceoptions flag all;`},
		{"traceoptions-packed-file", `traceoptions file trace.log;`},
		{"policy-stats-packed-system-wide", `policy-stats system-wide enable;`},
		{"pre-id-default-policy-packed-log", `pre-id-default-policy then log session-init;`},
		{"pre-id-default-policy-braced-then-log", `pre-id-default-policy { then log session-init; }`},
		{"traceoptions-block-multi-flag-lines", `traceoptions { flag { basic-datapath; session; } }`},
		{"traceoptions-block-packed-multi-flag", `traceoptions { flag { basic-datapath session; } }`},
		{"pre-id-default-policy-block-packed-multi-log", `pre-id-default-policy { then { log { session-init session-close; } } }`},
		{"traceoptions-packed-packet-filter", `traceoptions packet-filter f1 source-prefix 10.0.0.0/8;`},
		{"traceoptions-no-remote-trace", `traceoptions { no-remote-trace; }`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			text := fusedPoliciesConfig12819(tc.child)
			tree := parseUnknownSecurityPoliciesChildren12217(t, text)
			if err := SchemaValidate(tree, nil); err != nil {
				t.Fatalf("strict schema rejected genuine %s: %v", tc.name, err)
			}
			if _, err := CompileConfig(tree); err != nil {
				t.Fatalf("strict compile rejected genuine %s: %v", tc.name, err)
			}
			tree2 := parseUnknownSecurityPoliciesChildren12217(t, text)
			cfg, err := CompileConfigLenient(tree2)
			if err != nil {
				t.Fatalf("lenient compile: %v", err)
			}
			if policiesCarrierCount12628(cfg) != 0 {
				t.Fatalf("genuine %s poisoned snapshot", tc.name)
			}
			if !policiesHasPermit12628(cfg) {
				t.Fatal("valid permit policy lost")
			}
		})
	}
}

func TestFusedPolicyDiagnosticsNameRejectedContentShape12819(t *testing.T) {
	text := fusedPoliciesConfig12819(`traceoptions { global { policy deny-bad { then { deny; } } } }`)
	const shape = "traceoptions/global/policy/then/deny"

	tree := parseUnknownSecurityPoliciesChildren12217(t, text)
	if err := SchemaValidate(tree, nil); err == nil || !strings.Contains(err.Error(), shape) {
		t.Fatalf("strict schema error = %v, want rejected content shape %q", err, shape)
	}
	tree = parseUnknownSecurityPoliciesChildren12217(t, text)
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile: %v", err)
	}
	for _, warning := range cfg.Warnings {
		if strings.Contains(warning, "#12217") {
			if !strings.Contains(warning, shape) {
				t.Fatalf("quarantine warning %q does not name rejected shape %q", warning, shape)
			}
			return
		}
	}
	t.Fatalf("missing #12217 quarantine warning: %v", cfg.Warnings)
}

// Per-entry retention: a benign child and a fused child co-present.
// The record list must keep BOTH entries; only the fused entry poisons.
func TestMixedBenignAndFusedChildren12819(t *testing.T) {
	text := policiesBase12628 +
		"  traceoptions { file trace.log; }\n" +
		"  policy-stats { global { policy deny-bad { then { deny; } } } }\n" +
		policiesClose12628
	tree := parseUnknownSecurityPoliciesChildren12217(t, text)
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile: %v", err)
	}
	if len(cfg.Security.UnknownPoliciesChildren) != 2 {
		t.Fatalf("UnknownPoliciesChildren = %v, want benign+fused both retained", cfg.Security.UnknownPoliciesChildren)
	}
	if policiesCarrierCount12628(cfg) != 1 {
		t.Fatalf("poison carriers = %d, want 1", policiesCarrierCount12628(cfg))
	}
	if !policiesHasPermit12628(cfg) {
		t.Fatal("valid permit policy lost")
	}
	// Strict rejects the fused sibling even with a benign sibling present.
	tree2 := parseUnknownSecurityPoliciesChildren12217(t, text)
	if _, err := CompileConfig(tree2); err == nil {
		t.Fatal("strict compile accepted fused sibling")
	}
}

// A benign and fused duplicate share one warning key; the fused instance must
// still cause quarantine instead of letting the benign instance mask it.
func TestFusedDuplicateExemptNamePoisons12819(t *testing.T) {
	text := policiesBase12628 +
		"  traceoptions { file trace.log; }\n" +
		"  traceoptions { global { policy deny-bad { then { deny; } } } }\n" +
		policiesClose12628
	tree := parseUnknownSecurityPoliciesChildren12217(t, text)
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile: %v", err)
	}
	if len(cfg.Security.UnknownPoliciesChildren) != 1 || cfg.Security.UnknownPoliciesChildren[0] != "traceoptions" {
		t.Fatalf("UnknownPoliciesChildren = %v, want deduped traceoptions", cfg.Security.UnknownPoliciesChildren)
	}
	if policiesCarrierCount12628(cfg) != 1 {
		t.Fatalf("fused duplicate poison carriers = %d, want 1", policiesCarrierCount12628(cfg))
	}
	if !policiesHasPermit12628(cfg) {
		t.Fatal("valid permit policy lost")
	}
}

// Duplicate benign children still deduplicate to a single warning record.
func TestDuplicateBenignTraceoptionsDeduped12819(t *testing.T) {
	text := policiesBase12628 +
		"  traceoptions { file a.log; }\n  traceoptions { file b.log; }\n" +
		policiesClose12628
	tree := parseUnknownSecurityPoliciesChildren12217(t, text)
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile: %v", err)
	}
	if len(cfg.Security.UnknownPoliciesChildren) != 1 {
		t.Fatalf("UnknownPoliciesChildren = %v, want single deduped traceoptions", cfg.Security.UnknownPoliciesChildren)
	}
	if policiesCarrierCount12628(cfg) != 0 {
		t.Fatal("duplicate benign traceoptions poisoned snapshot")
	}
}
