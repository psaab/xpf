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
		{
			name:         "packed description typo with scheduler",
			unknownChild: `descripton "web" scheduler-name permit-window;`,
			keyword:      "descripton",
			schedulerRef: true,
		},
		{
			name:         "packed description typo with deny",
			unknownChild: "descripton x then deny;",
			keyword:      "descripton",
		},
		{
			name:         "description typo with two value tokens",
			unknownChild: "descripton x y;",
			keyword:      "descripton",
		},
		{
			name:         "nested description typo",
			unknownChild: "descriptio { x; }",
			keyword:      "descriptio",
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

func TestUnknownSecurityPolicyDescriptionTyposAndApplyStatementsStayAdvisory12234(t *testing.T) {
	cases := []struct {
		name  string
		child string
		want  string
	}{
		{name: "adjacent transposition", child: "descriptoin x;", want: "descriptoin"},
		{name: "multi-word description", child: `descripton "multi word";`, want: "descripton"},
		{name: "apply-groups-except", child: "apply-groups-except LOG;", want: "apply-groups-except"},
		{name: "apply-macro", child: "apply-macro M { k v; }", want: "apply-macro"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := CompileConfigLenient(policyUnknownEnforcementTree12234(t, tc.child))
			if err != nil {
				t.Fatalf("lenient compile rejected advisory child: %v", err)
			}
			pol := policyPoisonPolicy11013(t, cfg)
			if pol.LenientContentDropped {
				t.Fatalf("%s must remain advisory-only", tc.name)
			}
			if len(pol.UnknownChildren) != 1 || pol.UnknownChildren[0] != tc.want {
				t.Fatalf("unknown children = %v, want [%s]", pol.UnknownChildren, tc.want)
			}
			if !strings.Contains(strings.Join(cfg.Warnings, "\n"), "#4232") {
				t.Fatalf("%s lost its #4232 advisory: %v", tc.name, cfg.Warnings)
			}
		})
	}
}

func TestUnknownGlobalSecurityPolicyChildPoisonsLenientCompile12234(t *testing.T) {
	tree, errs := NewParser(`security {
    policies {
        global {
            policy p {
                match {
                    source-address any;
                    destination-address any;
                    application any;
                }
                then { permit; }
                descripton x scheduler-name permit-window;
            }
        }
    }
}`).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse global policy fixture: %v", errs[0])
	}
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile rejected global policy: %v", err)
	}
	if len(cfg.Security.GlobalPolicies) != 1 {
		t.Fatalf("global policies = %d, want 1", len(cfg.Security.GlobalPolicies))
	}
	pol := cfg.Security.GlobalPolicies[0]
	if !pol.LenientContentDropped {
		t.Fatal("packed description typo in global policy did not poison it")
	}
}

// #12634: a KNOWN scalar policy leaf (`description` or `scheduler-name`)
// carrying tokens beyond its single value, or children, that the packed/nested
// leaf-run expander does not fully resolve is skipped by the #12234
// unknown-child predicate (the keyword itself is recognized), so the typo'd
// scheduler binding silently dropped with zero diagnostics. Poison + warn +
// strict-reject, and keep legitimately resolved runs clean.
func policyUnknownEnforcementFlatTree12634(t *testing.T, tail string) *ConfigTree {
	t.Helper()
	tree := &ConfigTree{}
	commands := []string{
		"set schedulers scheduler permit-window daily start-time 08:30",
		"set schedulers scheduler permit-window daily stop-time 09:00",
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		"set security policies from-zone trust to-zone untrust policy p match source-address any",
		"set security policies from-zone trust to-zone untrust policy p match destination-address any",
		"set security policies from-zone trust to-zone untrust policy p match application any",
		"set security policies from-zone trust to-zone untrust policy p then permit",
		"set security policies from-zone trust to-zone untrust policy p " + tail,
	}
	for _, command := range commands {
		path, err := ParseSetCommand(command)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", command, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", command, err)
		}
	}
	return tree
}

func TestKnownScalarLeafUnresolvedTailPoisons12634(t *testing.T) {
	cases := []struct {
		name            string
		child           string
		leaf            string
		flat            bool
		wantDescription string
	}{
		{name: "braced description typo tail", child: `description "x" schedulr-name permit-window;`, leaf: "description", wantDescription: "x"},
		{name: "braced scheduler-name typo tail", child: `scheduler-name permit-window descripton "x";`, leaf: "scheduler-name"},
		{name: "braced description unknown tail", child: `description "x" bogus-token permit-window;`, leaf: "description", wantDescription: "x"},
		{name: "braced scheduler extra value token", child: `scheduler-name permit-window extra-window;`, leaf: "scheduler-name"},
		{name: "flat description typo tail", child: `description x schedulr-name permit-window`, leaf: "description", flat: true, wantDescription: "x"},
		{name: "flat scheduler-name nested typo tail", child: `scheduler-name permit-window descripton x`, leaf: "scheduler-name", flat: true},
		{name: "flat description nested child tail", child: `description x bogus-token permit-window`, leaf: "description", flat: true, wantDescription: "x"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var tree *ConfigTree
			if tc.flat {
				tree = policyUnknownEnforcementFlatTree12634(t, tc.child)
			} else {
				tree = policyUnknownEnforcementTree12234(t, tc.child)
			}
			cfg, err := CompileConfigLenient(tree)
			if err != nil {
				t.Fatalf("lenient compile rejected policy: %v", err)
			}
			pol := policyPoisonPolicy11013(t, cfg)
			if pol.Action != PolicyPermit {
				t.Fatalf("control permit action = %v, want permit", pol.Action)
			}
			if !pol.LenientContentDropped {
				t.Fatalf("known scalar leaf %q with unresolvable tail %q did not poison the policy", tc.leaf, tc.child)
			}
			if pol.Description != tc.wantDescription {
				t.Errorf("policy description = %q, want %q", pol.Description, tc.wantDescription)
			}
			if tc.wantDescription != "" && pol.SchedulerName != "" {
				t.Errorf("unresolved scheduler binding = %q, want empty", pol.SchedulerName)
			}
			warnings := strings.Join(cfg.Warnings, "\n")
			for _, want := range []string{tc.leaf, "#12634"} {
				if !strings.Contains(warnings, want) {
					t.Errorf("lenient warning %q does not name %q", warnings, want)
				}
			}
			if _, err := CompileConfig(tree); err == nil || !strings.Contains(err.Error(), "#12634") {
				t.Fatalf("strict compiler must reject known scalar leaf tail %q, got %v", tc.child, err)
			}
			if tc.leaf == "description" {
				if err := SchemaValidate(tree, nil); err == nil {
					t.Fatalf("strict schema must reject known scalar leaf tail %q", tc.child)
				}
			}
		})
	}
}

func TestKnownScalarLeafUnresolvedTailPoisonsGlobalPolicy12634(t *testing.T) {
	tree, errs := NewParser(`security {
    policies {
        global {
            policy p {
                match {
                    source-address any;
                    destination-address any;
                    application any;
                }
                then { permit; }
                description "x" scheduler-name permit-window extra-token;
            }
        }
    }
}`).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse global policy fixture: %v", errs[0])
	}
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile rejected global policy: %v", err)
	}
	if len(cfg.Security.GlobalPolicies) != 1 {
		t.Fatalf("global policies = %d, want 1", len(cfg.Security.GlobalPolicies))
	}
	pol := cfg.Security.GlobalPolicies[0]
	if pol.Description != "x" || pol.SchedulerName != "permit-window" {
		t.Fatalf("global policy fields = description %q, scheduler %q; want %q and permit-window", pol.Description, pol.SchedulerName, "x")
	}
	if !pol.LenientContentDropped || !strings.Contains(strings.Join(cfg.Warnings, "\n"), "#12634") {
		t.Fatalf("unresolved global scheduler tail must poison and warn #12634: dropped=%v warnings=%v", pol.LenientContentDropped, cfg.Warnings)
	}
	if _, err := CompileConfig(tree); err == nil || !strings.Contains(err.Error(), "#12634") {
		t.Fatalf("strict compiler must reject unresolved global scheduler tail, got %v", err)
	}
}

// #12634: resolved scalar runs and single-value leaves remain non-poisoned.
func TestKnownScalarLeafResolvedRunsStayClean12634(t *testing.T) {
	cases := []struct {
		name      string
		child     string
		scheduler string
		flat      bool
	}{
		{name: "single description", child: `description "x";`},
		{name: "single scheduler", child: `scheduler-name permit-window;`, scheduler: "permit-window"},
		{name: "packed resolved run", child: `description "x" scheduler-name permit-window;`, scheduler: "permit-window"},
		{name: "packed resolved run scheduler first", child: `scheduler-name permit-window description "x";`, scheduler: "permit-window"},
		{name: "flat resolved scheduler", child: `scheduler-name permit-window`, scheduler: "permit-window", flat: true},
		{name: "flat resolved packed run", child: `description x scheduler-name permit-window`, scheduler: "permit-window", flat: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var tree *ConfigTree
			if tc.flat {
				tree = policyUnknownEnforcementFlatTree12634(t, tc.child)
			} else {
				tree = policyUnknownEnforcementTree12234(t, tc.child)
			}
			cfg, err := CompileConfigLenient(tree)
			if err != nil {
				t.Fatalf("lenient compile rejected policy: %v", err)
			}
			pol := policyPoisonPolicy11013(t, cfg)
			if pol.LenientContentDropped {
				t.Fatalf("resolved scalar leaf %q must not poison", tc.child)
			}
			if pol.SchedulerName != tc.scheduler {
				t.Fatalf("scheduler = %q, want %q", pol.SchedulerName, tc.scheduler)
			}
			if strings.Contains(strings.Join(cfg.Warnings, "\n"), "#12634") {
				t.Fatalf("resolved scalar leaf %q must not warn #12634: %v", tc.child, cfg.Warnings)
			}
			if _, err := CompileConfig(tree); err != nil {
				t.Fatalf("strict compiler must accept resolved scalar leaf %q: %v", tc.child, err)
			}
		})
	}
}

// #14681 (D9-01): a container child (`match`/`then`) nested under a known
// scalar policy leaf must not be hoisted into the expanded policy leaves.
// Before the fix allDescendantsDeclared9792 accepted any declared head, so
// `scheduler-name work-hours { then deny; }` hoisted `then deny` beside the
// scheduler leaf; policyUnresolvedScalarLeafTails then saw only clean len-2
// scalar leaves while compilePolicy read `match`/`then` from the unexpanded
// node — the nested deny was compiled by nobody and the policy stayed
// permit, unpoisoned, with no strict error (SchemaValidate alone rejected
// it). The scheduler `work-hours` is defined so the scheduler-reference
// gate cannot mask the drop.
func nestedThenTree14681(t *testing.T, body string) *ConfigTree {
	t.Helper()
	text := `schedulers {
    scheduler work-hours {
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
                ` + body + `
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

func flatNestedThenTree14681(t *testing.T, tail string) *ConfigTree {
	t.Helper()
	tree := &ConfigTree{}
	commands := []string{
		"set schedulers scheduler work-hours daily start-time 08:30",
		"set schedulers scheduler work-hours daily stop-time 09:00",
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		"set security policies from-zone trust to-zone untrust policy p match source-address any",
		"set security policies from-zone trust to-zone untrust policy p match destination-address any",
		"set security policies from-zone trust to-zone untrust policy p match application any",
		"set security policies from-zone trust to-zone untrust policy p then permit",
		"set security policies from-zone trust to-zone untrust policy p " + tail,
	}
	for _, command := range commands {
		path, err := ParseSetCommand(command)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", command, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", command, err)
		}
	}
	return tree
}

func TestPolicyScalarLeafNestedThenOrMatchRejected12634(t *testing.T) {
	cases := []struct {
		name string
		body string
		flat bool
		tail string
		leaf string
	}{
		{name: "braced scheduler-name then deny", body: `scheduler-name work-hours { then deny; }`, leaf: "scheduler-name"},
		{name: "braced scheduler-name match leaf", body: `scheduler-name work-hours { match source-address 10.0.0.1/32; }`, leaf: "scheduler-name"},
		{name: "braced description then deny", body: `description d1 { then deny; }`, leaf: "description"},
		{name: "flat scheduler-name match", tail: `scheduler-name work-hours match source-address 10.0.0.1/32`, flat: true, leaf: "scheduler-name"},
		{name: "flat scheduler-name then deny", tail: `scheduler-name work-hours then deny`, flat: true, leaf: "scheduler-name"},
		{name: "flat description then deny", tail: `description d1 then deny`, flat: true, leaf: "description"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var tree *ConfigTree
			if tc.flat {
				tree = flatNestedThenTree14681(t, tc.tail)
			} else {
				tree = nestedThenTree14681(t, tc.body)
			}
			cfg, err := CompileConfigLenient(tree)
			if err != nil {
				t.Fatalf("lenient compile rejected policy: %v", err)
			}
			pol := policyPoisonPolicy11013(t, cfg)
			// The control `then permit` stays the compiled action; the
			// nested clause must surface as poison, never as a silent
			// permit-with-narrowing or permit-with-deny-dropped.
			if pol.Action != PolicyPermit {
				t.Fatalf("control permit action = %v, want permit", pol.Action)
			}
			if !pol.LenientContentDropped {
				t.Fatalf("nested container tail under scalar leaf %q was hoisted and dropped without poison", tc.leaf)
			}
			warnings := strings.Join(cfg.Warnings, "\n")
			for _, want := range []string{tc.leaf, "#12634"} {
				if !strings.Contains(warnings, want) {
					t.Errorf("lenient warning %q does not name %q", warnings, want)
				}
			}
			if _, err := CompileConfig(tree); err == nil || !strings.Contains(err.Error(), "#12634") {
				t.Fatalf("strict compiler must reject nested container tail under %q, got %v", tc.leaf, err)
			}
			if err := SchemaValidate(tree, nil); err == nil {
				t.Fatalf("strict schema must reject nested container tail under %q", tc.leaf)
			}
		})
	}
}

// #14681 control: a legitimately resolved description/scheduler run stays
// clean (also covered by TestKnownScalarLeafResolvedRunsStayClean12634) and
// a nested scalar tail under a scalar head still expands.
func TestPolicyScalarLeafNestedScalarRunStaysClean14681(t *testing.T) {
	tree := nestedThenTree14681(t, `description d1 scheduler-name work-hours;`)
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile rejected policy: %v", err)
	}
	pol := policyPoisonPolicy11013(t, cfg)
	if pol.LenientContentDropped {
		t.Fatalf("resolved scalar run must not poison: warnings=%v", cfg.Warnings)
	}
	if pol.SchedulerName != "work-hours" || pol.Description != "d1" {
		t.Fatalf("resolved run fields = scheduler %q description %q, want work-hours/d1", pol.SchedulerName, pol.Description)
	}
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("strict compiler must accept resolved scalar run: %v", err)
	}
}
