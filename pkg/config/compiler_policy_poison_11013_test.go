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
		"then { permit; }\n                    descripton typo-control;"))
	if err != nil {
		t.Fatalf("lenient compile rejected harmless metadata: %v", err)
	}
	pol := policyPoisonPolicy11013(t, cfg)
	if pol.LenientContentDropped {
		t.Fatal("harmless policy metadata typo must remain advisory-only")
	}
	if len(pol.UnknownChildren) != 1 || pol.UnknownChildren[0] != "descripton" {
		t.Fatalf("test fixture did not produce an unknown harmless child: %v", pol.UnknownChildren)
	}
	if !strings.Contains(strings.Join(cfg.Warnings, "\n"), "#4232") {
		t.Fatalf("harmless policy metadata typo lost its advisory: %v", cfg.Warnings)
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

func policyUnknownEnforcementTree12234(t *testing.T, unknownChild string) *ConfigTree {
	t.Helper()
	text := `schedulers {
    scheduler permit-window {
        daily { start-time 08:30; stop-time 09:00; }
    }
}
security {
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
                then { permit; }
                ` + unknownChild + `
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

func TestUnknownEnforcementSecurityPolicyChildrenPoisonLenientCompile12234(t *testing.T) {
	cases := []struct {
		name         string
		unknownChild string
		keyword      string
		schedulerRef bool
	}{
		{
			name:         "scheduler-name typo",
			unknownChild: "scheduler-nam permit-window;",
			keyword:      "scheduler-nam",
			schedulerRef: true,
		},
		{
			name:         "scheduler-name extra letter",
			unknownChild: "scheduler-naeme permit-window;",
			keyword:      "scheduler-naeme",
			schedulerRef: true,
		},
		{
			name:         "scheduler-name repeated letter",
			unknownChild: "scheduler-namme permit-window;",
			keyword:      "scheduler-namme",
			schedulerRef: true,
		},
		{
			name:         "scheduler-name multiple edits",
			unknownChild: "schedulr-namme permit-window;",
			keyword:      "schedulr-namme",
			schedulerRef: true,
		},
		{
			name:         "match subtree typo",
			unknownChild: "mach { source-address 192.0.2.0/24; }",
			keyword:      "mach",
		},
		{
			name:         "then typo with a conflicting action",
			unknownChild: "thne deny;",
			keyword:      "thne",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := policyUnknownEnforcementTree12234(t, tc.unknownChild)
			cfg, err := CompileConfigLenient(tree)
			if err != nil {
				t.Fatalf("lenient compile rejected policy: %v", err)
			}
			pol := policyPoisonPolicy11013(t, cfg)
			if pol.Action != PolicyPermit {
				t.Fatalf("control permit action = %v, want permit", pol.Action)
			}
			if !pol.LenientContentDropped {
				t.Fatalf("unknown enforcement child %q did not poison the policy; the incomplete permit could be published", tc.keyword)
			}
			if len(pol.UnknownChildren) != 1 || pol.UnknownChildren[0] != tc.keyword {
				t.Fatalf("compiled unknown children = %v, want [%q]", pol.UnknownChildren, tc.keyword)
			}
			if tc.schedulerRef && (cfg.Schedulers["permit-window"] == nil || pol.SchedulerName != "") {
				t.Fatalf("fixture must define the window while the typo'd reference is dropped: schedulers=%v policy scheduler=%q",
					cfg.Schedulers, pol.SchedulerName)
			}
			warnings := strings.Join(cfg.Warnings, "\n")
			for _, want := range []string{"trust->untrust/p", tc.keyword, "#4232", "#12234"} {
				if !strings.Contains(warnings, want) {
					t.Errorf("lenient warning %q does not name %q", warnings, want)
				}
			}
			if _, err := CompileConfig(tree); err == nil || !strings.Contains(err.Error(), "#12234") {
				t.Fatalf("strict compiler must reject unknown enforcement child %q, got %v", tc.keyword, err)
			}
			if err := SchemaValidate(tree, nil); err == nil || !strings.Contains(err.Error(), tc.keyword) {
				t.Fatalf("strict schema must reject unknown enforcement child %q, got %v", tc.keyword, err)
			}
		})
	}
}
