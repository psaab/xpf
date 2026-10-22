package config

import (
	"strings"
	"testing"
)

// #1746: equal-flow-target-policy knob tests. The policy selects the
// per-flow target reduction the userspace equal-flow publisher applies:
// "slowest" (the byte-unchanged default; "" maps here), "mean", or
// "ideal-share". It is only meaningful with equal-flow-enforcement
// (warn-not-strip otherwise), and "slowest"/"mean" carry a
// non-work-conserving aggregate-cost warning.

func compileEqualFlowPolicyLines(t *testing.T, lines []string) *Config {
	t.Helper()
	tree := &ConfigTree{}
	for _, line := range lines {
		path, err := ParseSetCommand(line)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", line, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", line, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}
	return cfg
}

func TestEqualFlowTargetPolicyCompileSetSyntax(t *testing.T) {
	cfg := compileEqualFlowPolicyLines(t, []string{
		"set class-of-service schedulers ef-sched transmit-rate 1g",
		"set class-of-service schedulers ef-sched transmit-rate exact",
		"set class-of-service schedulers ef-sched equal-flow-enforcement",
		"set class-of-service schedulers ef-sched equal-flow-target-policy mean",
		"set class-of-service schedulers plain-sched transmit-rate 1g",
		"set class-of-service schedulers plain-sched transmit-rate exact",
		"set class-of-service schedulers plain-sched equal-flow-enforcement",
		"set system dataplane-type userspace",
	})
	if got := cfg.ClassOfService.Schedulers["ef-sched"].EqualFlowTargetPolicy; got != "mean" {
		t.Fatalf("ef-sched EqualFlowTargetPolicy = %q, want mean", got)
	}
	// Unset policy stays "" (the byte-unchanged default that the
	// dataplane maps to "slowest").
	if got := cfg.ClassOfService.Schedulers["plain-sched"].EqualFlowTargetPolicy; got != "" {
		t.Fatalf("plain-sched EqualFlowTargetPolicy = %q, want empty default", got)
	}
}

// Dual-AST discipline: the compiler must handle the hierarchical shape
// (`equal-flow-target-policy mean;`) as well as the flat set form
// covered above — same `nodeVal` path as the scheduler `priority` leaf.
func TestEqualFlowTargetPolicyCompileHierarchical(t *testing.T) {
	p := NewParser(`class-of-service { schedulers { ef { transmit-rate 1g exact; equal-flow-enforcement; equal-flow-target-policy mean; } } }`)
	tree, errs := p.Parse()
	if len(errs) > 0 {
		t.Fatalf("parse errors: %v", errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}
	if got := cfg.ClassOfService.Schedulers["ef"].EqualFlowTargetPolicy; got != "mean" {
		t.Fatalf("hierarchical EqualFlowTargetPolicy = %q, want mean", got)
	}
}

func TestEqualFlowTargetPolicyStrictRejectsUnknownValue(t *testing.T) {
	// The schema enum validator catches bad values on the interactive
	// set path; validateClassOfServiceStrict must also reject them so
	// externally-assembled configs cannot smuggle an unknown policy to
	// the dataplane (which would silently parse it as "slowest").
	cfg := &ClassOfServiceConfig{
		Schedulers: map[string]*CoSScheduler{
			"bad": {
				Name:                  "bad",
				TransmitRateBytes:     125_000_000,
				TransmitRateExact:     true,
				EqualFlowEnforcement:  true,
				EqualFlowTargetPolicy: "bogus-policy",
			},
		},
	}
	err := validateClassOfServiceStrict(cfg)
	if err == nil {
		t.Fatal("expected strict validation error for unknown equal-flow-target-policy")
	}
	if !strings.Contains(err.Error(), "equal-flow-target-policy") {
		t.Fatalf("error missing knob name: %v", err)
	}
	for _, ok := range []string{"", "slowest", "mean", "ideal-share"} {
		cfg.Schedulers["bad"].EqualFlowTargetPolicy = ok
		if err := validateClassOfServiceStrict(cfg); err != nil {
			t.Fatalf("policy %q must pass strict validation, got %v", ok, err)
		}
	}
}

func TestEqualFlowTargetPolicyWarnsWithoutEnforcement(t *testing.T) {
	cfg := compileEqualFlowPolicyLines(t, []string{
		"set class-of-service schedulers inert-sched transmit-rate 1g",
		"set class-of-service schedulers inert-sched transmit-rate exact",
		"set class-of-service schedulers inert-sched equal-flow-target-policy mean",
		"set system dataplane-type userspace",
	})
	// Warn-not-strip: the value is preserved (harmless no-op at the
	// dataplane, which gates on equal-flow-enforcement).
	if got := cfg.ClassOfService.Schedulers["inert-sched"].EqualFlowTargetPolicy; got != "mean" {
		t.Fatalf("EqualFlowTargetPolicy = %q, want mean preserved (warn-not-strip)", got)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "equal-flow-target-policy") && strings.Contains(w, "no effect") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected no-effect warning for policy without enforcement, got %v", cfg.Warnings)
	}
}

func TestEqualFlowTargetPolicyCostWarning(t *testing.T) {
	// "mean" and "slowest" with enforcement are non-work-conserving:
	// the operator must see the aggregate-cost warning at commit.
	for _, policy := range []string{"mean", "slowest"} {
		cfg := compileEqualFlowPolicyLines(t, []string{
			"set class-of-service schedulers ef-sched transmit-rate 1g",
			"set class-of-service schedulers ef-sched transmit-rate exact",
			"set class-of-service schedulers ef-sched equal-flow-enforcement",
			"set class-of-service schedulers ef-sched equal-flow-target-policy " + policy,
			"set system dataplane-type userspace",
		})
		found := false
		for _, w := range cfg.Warnings {
			if strings.Contains(w, "non-work-conserving") {
				found = true
			}
		}
		if !found {
			t.Fatalf("policy %s: expected non-work-conserving cost warning, got %v", policy, cfg.Warnings)
		}
	}
	// Unset policy (the unchanged default) and "ideal-share" (the
	// documented no-op) must NOT add the cost warning — existing
	// equal-flow configs see no new commit noise.
	for _, lines := range [][]string{
		{
			"set class-of-service schedulers ef-sched transmit-rate 1g",
			"set class-of-service schedulers ef-sched transmit-rate exact",
			"set class-of-service schedulers ef-sched equal-flow-enforcement",
			"set system dataplane-type userspace",
		},
		{
			"set class-of-service schedulers ef-sched transmit-rate 1g",
			"set class-of-service schedulers ef-sched transmit-rate exact",
			"set class-of-service schedulers ef-sched equal-flow-enforcement",
			"set class-of-service schedulers ef-sched equal-flow-target-policy ideal-share",
			"set system dataplane-type userspace",
		},
	} {
		cfg := compileEqualFlowPolicyLines(t, lines)
		for _, w := range cfg.Warnings {
			if strings.Contains(w, "non-work-conserving") {
				t.Fatalf("unexpected cost warning for default/ideal-share config: %v", cfg.Warnings)
			}
		}
	}
}

func equalFlowPolicyFlatSchemaCheck(t *testing.T, cmd string) error {
	t.Helper()
	tree := &ConfigTree{}
	path, err := ParseSetCommand(cmd)
	if err != nil {
		t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
	}
	if err := tree.SetPath(path); err != nil {
		t.Fatalf("SetPath(%q): %v", cmd, err)
	}
	return SchemaValidate(tree)
}

func TestEqualFlowTargetPolicySchemaValidate(t *testing.T) {
	// Commit-check schema gate on the flat-set path (the same path
	// that validates `priority`): enum values pass, garbage is
	// rejected. (Hierarchical-form leaf VALUE validation is a
	// pre-existing gap shared by every enum leaf, e.g. `priority`;
	// the strict compile validator covers that shape.)
	for _, val := range []string{"slowest", "mean", "ideal-share"} {
		cmd := "set class-of-service schedulers be equal-flow-target-policy " + val
		if err := equalFlowPolicyFlatSchemaCheck(t, cmd); err != nil {
			t.Fatalf("expected %q to pass schema validation, got %v", cmd, err)
		}
	}
	err := equalFlowPolicyFlatSchemaCheck(t,
		"set class-of-service schedulers be equal-flow-target-policy bogus")
	if err == nil {
		t.Fatal("expected schema rejection for unknown equal-flow-target-policy value")
	}
	if !strings.Contains(err.Error(), "expected one of") {
		t.Fatalf("expected enum error, got %v", err)
	}
}

func TestEqualFlowTargetPolicyValueCompletion(t *testing.T) {
	results := CompleteSetPathWithValues(
		[]string{"class-of-service", "schedulers", "be", "equal-flow-target-policy"}, nil)
	for _, want := range []string{"slowest", "mean", "ideal-share"} {
		if !containsCompletionName(results, want) {
			t.Fatalf("expected %q in equal-flow-target-policy value completions, got %v",
				want, completionNames(results))
		}
	}
}
