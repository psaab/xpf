package config

import (
	"strings"
	"testing"
)

// #12628: Junos-valid non-enforcement children of `security policies`
// (traceoptions, policy-stats, pre-id-default-policy) must not poison the
// policy snapshot on tolerant load. Only enforcement-bearing names poison.

func policiesCarrierCount12628(cfg *Config) int {
	n := 0
	for _, p := range cfg.Security.GlobalPolicies {
		if p != nil && p.Name == "xpf-unknown-policies-child-poison" {
			n++
		}
	}
	return n
}

func policiesHasPermit12628(cfg *Config) bool {
	for _, zp := range cfg.Security.Policies {
		for _, p := range zp.Policies {
			if p != nil && p.Action == PolicyPermit {
				return true
			}
		}
	}
	return false
}

const policiesBase12628 = `security {
 zones {
  security-zone trust;
  security-zone untrust;
 }
 policies {
  default-policy deny-all;
  from-zone trust to-zone untrust {
   policy ok { match { source-address any; destination-address any; application any; } then { permit; } }
  }
`
const policiesClose12628 = ` }
}`

func TestPoliciesWithoutUnknownChildrenDoNotPoison12628(t *testing.T) {
	tree := parseUnknownSecurityPoliciesChildren12217(t, policiesBase12628+policiesClose12628)
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile: %v", err)
	}
	if len(cfg.Security.UnknownPoliciesChildren) != 0 || policiesCarrierCount12628(cfg) != 0 {
		t.Fatalf("ordinary policy snapshot unexpectedly quarantined: children=%v carriers=%d",
			cfg.Security.UnknownPoliciesChildren, policiesCarrierCount12628(cfg))
	}
	if !policiesHasPermit12628(cfg) {
		t.Fatal("valid permit policy lost")
	}
}

func TestPoliciesJunosValidNonEnforcementChildrenDoNotPoison12628(t *testing.T) {
	for _, tc := range []struct{ name, child string }{
		{"traceoptions", "traceoptions { file trace.log; }"},
		{"policy-stats", "policy-stats { system-wide enable; }"},
		{"pre-id-default-policy", "pre-id-default-policy { then { log { session-init; } } }"},
		{"policy-rematch-known-control", "policy-rematch;"},
		{"default-policy-log-known-control", "default-policy-log session-init;"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			text := policiesBase12628 + "  " + tc.child + "\n" + policiesClose12628
			tree := parseUnknownSecurityPoliciesChildren12217(t, text)
			if err := SchemaValidate(tree, nil); err != nil {
				t.Fatalf("strict schema rejected Junos-valid child %s: %v", tc.name, err)
			}
			if _, err := CompileConfig(tree); err != nil {
				t.Fatalf("strict compile rejected Junos-valid child %s: %v", tc.name, err)
			}
			tree2 := parseUnknownSecurityPoliciesChildren12217(t, text)
			cfg, err := CompileConfigLenient(tree2)
			if err != nil {
				t.Fatalf("lenient compile: %v", err)
			}
			if nonEnforcementSecurityPoliciesChild12628(tc.name) {
				if len(cfg.Security.UnknownPoliciesChildren) != 1 || cfg.Security.UnknownPoliciesChildren[0] != tc.name {
					t.Fatalf("UnknownPoliciesChildren = %v, want [%s]", cfg.Security.UnknownPoliciesChildren, tc.name)
				}
			} else if len(cfg.Security.UnknownPoliciesChildren) != 0 {
				t.Fatalf("known child recorded as unknown: %v", cfg.Security.UnknownPoliciesChildren)
			}
			if policiesCarrierCount12628(cfg) != 0 {
				t.Fatal("poison carrier present for Junos-valid non-enforcement child")
			}
			if !policiesHasPermit12628(cfg) {
				t.Fatal("valid permit policy lost")
			}
			for _, w := range cfg.Warnings {
				if nonEnforcementSecurityPoliciesChild12628(tc.name) && !strings.Contains(w, "#12628") {
					t.Fatalf("missing non-enforcement compatibility warning: %q", w)
				}
			}
		})
	}
}

func TestPoliciesEnforcementBearingUnknownChildrenStillPoison12628(t *testing.T) {
	for _, tc := range []struct{ name, child string }{
		{"globel-typo-of-global", "globel { policy deny-bad { then { deny; } } }"},
		{"from-zon-typo-of-from-zone", "from-zon { x; }"},
		{"polici-typo", "polici { then { permit; } }"},
		{"unknown-container", "frobnicate { policy deny-bad { then { deny; } } }"},
		{"unknown-bare-keyword", "frob;"},
		{"one-letter", "g { policy deny-bad { then { deny; } } }"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			text := policiesBase12628 + "  " + tc.child + "\n" + policiesClose12628
			tree := parseUnknownSecurityPoliciesChildren12217(t, text)
			cfg, err := CompileConfigLenient(tree)
			if err != nil {
				t.Fatalf("lenient compile: %v", err)
			}
			if len(cfg.Security.UnknownPoliciesChildren) != 1 {
				t.Fatalf("UnknownPoliciesChildren = %v, want 1", cfg.Security.UnknownPoliciesChildren)
			}
			if policiesCarrierCount12628(cfg) != 1 {
				t.Fatalf("poison carriers = %d, want 1", policiesCarrierCount12628(cfg))
			}
			tree2 := parseUnknownSecurityPoliciesChildren12217(t, text)
			if _, err := CompileConfig(tree2); err == nil {
				t.Fatal("strict compile accepted enforcement-bearing unknown child")
			}
		})
	}
}

// Packed enforcement keyword in a later key slot: `foo global` drops a global
// rulebase tail; must poison (like #11575 packed-slot logic).
func TestPoliciesPackedEnforcementTailPoisons12628(t *testing.T) {
	text := policiesBase12628 + "  unknown global policy deny-bad;\n" + policiesClose12628
	tree := parseUnknownSecurityPoliciesChildren12217(t, text)
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile: %v", err)
	}
	if policiesCarrierCount12628(cfg) != 1 {
		t.Fatalf("packed enforcement tail did not poison: children=%v carriers=%d", cfg.Security.UnknownPoliciesChildren, policiesCarrierCount12628(cfg))
	}
}
