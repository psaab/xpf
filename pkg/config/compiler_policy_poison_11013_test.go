package config

import (
	"strings"
	"testing"
)

// These are fail-on-revert cells: removing the unsupported-then predicate or
// dropped-subtree poison makes the tolerant direct permit compile unpoisoned;
// removing the then-sibling gate also loses the named warning and strict reject.

func policyPoisonTree11013(t *testing.T, policyBody string) *ConfigTree {
	t.Helper()
	text := `security {
    zones {
        security-zone trust;
        security-zone untrust;
    }
    policies {
        from-zone trust to-zone untrust {
            policy p {
                match {
                    source-address any;
                    destination-address any;
                    application any;
                }
                ` + policyBody + `
            }
        }
    }
}`
	tree, errs := NewParser(text).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse policy fixture: %v", errs[0])
	}
	return tree
}

func policyPoisonPolicy11013(t *testing.T, cfg *Config) *Policy {
	t.Helper()
	for _, zpp := range cfg.Security.Policies {
		for _, pol := range zpp.Policies {
			if pol.Name == "p" {
				return pol
			}
		}
	}
	t.Fatal("compiled policy p is missing")
	return nil
}

func TestUnsupportedSecurityPolicyThenSiblingPoisonsLenientCompile11013(t *testing.T) {
	tree := policyPoisonTree11013(t, "then { permit; next term; }")
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile rejected the persisted policy: %v", err)
	}
	if !policyPoisonPolicy11013(t, cfg).LenientContentDropped {
		t.Fatal("unsupported `then next term` sibling did not poison the earlier permit")
	}
	warnings := strings.Join(cfg.Warnings, "\n")
	for _, want := range []string{"policy \"p\"", "next term", "#11013"} {
		if !strings.Contains(warnings, want) {
			t.Errorf("tolerant compile warning %q does not name %q", warnings, want)
		}
	}

	if _, err := CompileConfig(tree); err == nil || !strings.Contains(err.Error(), "#11013") || !strings.Contains(err.Error(), "next term") {
		t.Fatalf("strict compiler must reject the unsupported then sibling with a named diagnostic, got %v", err)
	}
}

func TestCompactUnsupportedSecurityPolicyThenTailPoisonsLenientCompile11013(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{
			name: "leaf sibling",
			body: "then { permit; }\n                    then next term;",
		},
		{
			name: "tail with child",
			body: "then next term { permit; }",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := policyPoisonTree11013(t, tc.body)
			cfg, err := CompileConfigLenient(tree)
			if err != nil {
				t.Fatalf("lenient compile rejected the persisted policy: %v", err)
			}
			if !policyPoisonPolicy11013(t, cfg).LenientContentDropped {
				t.Fatal("unsupported compact then tail did not poison the policy")
			}
			warnings := strings.Join(cfg.Warnings, "\n")
			if !strings.Contains(warnings, "next term") || !strings.Contains(warnings, "#11013") {
				t.Fatalf("tolerant compile warning does not name unsupported tail: %q", warnings)
			}
			if _, err := CompileConfig(tree); err == nil || !strings.Contains(err.Error(), "#11013") {
				t.Fatalf("strict compiler must reject compact unsupported then tail, got %v", err)
			}
		})
	}
}

func TestDroppedSecurityPolicyEnforcementSubtreesPoisonLenientCompile11014(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{
			name: "nested term deny",
			body: `then { permit; }
                    term nested {
                        match { source-address 10.0.0.0/8; }
                        then { deny; }
                    }`,
		},
		{
			name: "session options timeout",
			body: `then { permit; }
                    session-options { inactivity-timeout 60; }`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := CompileConfigLenient(policyPoisonTree11013(t, tc.body))
			if err != nil {
				t.Fatalf("lenient compile rejected the persisted policy: %v", err)
			}
			if !policyPoisonPolicy11013(t, cfg).LenientContentDropped {
				t.Fatal("dropped enforcement-bearing subtree did not poison the direct permit")
			}
			if !strings.Contains(strings.Join(cfg.Warnings, "\n"), "#11014") {
				t.Fatalf("tolerant compile did not name dropped enforcement subtree: %v", cfg.Warnings)
			}
		})
	}
}

func TestDroppedSecurityPolicyEnforcementSubtreesRejectStrictDirectCompile11014(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{
			name: "nested term deny",
			body: `then { permit; }
                    term nested {
                        match { source-address 10.0.0.0/8; }
                        then { deny; }
                    }`,
		},
		{
			name: "session options timeout",
			body: `then { permit; }
                    session-options { inactivity-timeout 60; }`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := policyPoisonTree11013(t, tc.body)
			if _, err := CompileConfig(tree); err == nil || !strings.Contains(err.Error(), "#11014") {
				t.Fatalf("strict direct compile must reject dropped enforcement subtree, got %v", err)
			}
		})
	}
}

func TestHarmlessUnknownSecurityPolicyChildRemainsAdvisory11014(t *testing.T) {
	cfg, err := CompileConfigLenient(policyPoisonTree11013(t,
		"then { permit; }\n                    session-optionz typo-control;"))
	if err != nil {
		t.Fatalf("lenient compile rejected harmless metadata: %v", err)
	}
	pol := policyPoisonPolicy11013(t, cfg)
	if pol.LenientContentDropped {
		t.Fatal("harmless policy metadata typo must remain advisory-only")
	}
	if len(pol.UnknownChildren) != 1 || pol.UnknownChildren[0] != "session-optionz" {
		t.Fatalf("test fixture did not produce an unknown harmless child: %v", pol.UnknownChildren)
	}
}

func TestTermOnlySecurityPolicyStillDefaultsToDeny11014(t *testing.T) {
	cfg, err := CompileConfigLenient(policyPoisonTree11013(t,
		`term nested { match { source-address 10.0.0.0/8; } then { permit; } }`))
	if err != nil {
		t.Fatalf("lenient compile rejected the term-only policy: %v", err)
	}
	pol := policyPoisonPolicy11013(t, cfg)
	if pol.Action != PolicyDeny {
		t.Fatalf("term-only policy action = %v, want fail-closed PolicyDeny", pol.Action)
	}
}
