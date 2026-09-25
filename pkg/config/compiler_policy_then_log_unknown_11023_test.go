package config

import (
	"strings"
	"testing"
)

// This is a fail-on-revert cell: if the #11023 poison is removed, the
// leniently compiled permit is publishable; if its prewalk diagnostic is
// removed, the unknown audit mode is silent again.
func TestUnknownSecurityPolicyThenLogModePoisonsLenientCompile11023(t *testing.T) {
	tree := buildPolicyThenTree(t,
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		"set security policies from-zone trust to-zone untrust policy p match source-address any",
		"set security policies from-zone trust to-zone untrust policy p match destination-address any",
		"set security policies from-zone trust to-zone untrust policy p match application any",
		"set security policies from-zone trust to-zone untrust policy p then permit",
		"set security policies from-zone trust to-zone untrust policy p then log session-init bogusmode",
	)

	if err := SchemaValidate(tree, nil); err == nil || !strings.Contains(err.Error(), "bogusmode") {
		t.Fatalf("strict schema validation must reject the unknown then-log mode, got %v", err)
	}

	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile rejected the persisted policy: %v", err)
	}
	pol := policyPoisonPolicy11013(t, cfg)
	if !pol.LenientContentDropped {
		t.Fatal("unknown then-log mode did not poison the policy; the incomplete permit could be published")
	}
	warnings := strings.Join(cfg.Warnings, "\n")
	for _, want := range []string{`policy "p"`, "bogusmode", "#11023"} {
		if !strings.Contains(warnings, want) {
			t.Fatalf("tolerant compile warning missing %q: %q", want, warnings)
		}
	}
}

func TestUnknownSecurityPolicyThenLogSelfTokenPoisonsLenientCompile11023(t *testing.T) {
	tree := buildPolicyThenTree(t,
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		"set security policies from-zone trust to-zone untrust policy p match source-address any",
		"set security policies from-zone trust to-zone untrust policy p match destination-address any",
		"set security policies from-zone trust to-zone untrust policy p match application any",
		"set security policies from-zone trust to-zone untrust policy p then permit",
		"set security policies from-zone trust to-zone untrust policy p then log log",
	)
	if err := SchemaValidate(tree, nil); err == nil {
		t.Fatal("strict schema validation must reject `log` as a then-log mode")
	}
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile rejected the persisted policy: %v", err)
	}
	if !policyPoisonPolicy11013(t, cfg).LenientContentDropped {
		t.Fatal("unknown self-named then-log mode did not poison the policy")
	}
}

func TestUnknownSecurityPolicyThenLogChildPoisonsLenientCompile11023(t *testing.T) {
	tree := policyPoisonTree11013(t,
		`then { permit; log { session-init; bogusmode; } }`)
	if err := SchemaValidate(tree, nil); err == nil || !strings.Contains(err.Error(), "bogusmode") {
		t.Fatalf("strict schema validation must reject the unknown then-log child, got %v", err)
	}
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile rejected the persisted policy: %v", err)
	}
	if !policyPoisonPolicy11013(t, cfg).LenientContentDropped {
		t.Fatal("unknown nested then-log child did not poison the policy")
	}
	warnings := strings.Join(cfg.Warnings, "\n")
	for _, want := range []string{`policy "p"`, "bogusmode", "#11023"} {
		if !strings.Contains(warnings, want) {
			t.Fatalf("tolerant compile warning missing %q: %q", want, warnings)
		}
	}
}

func TestCompactUnknownSecurityPolicyThenLogModePoisonsLenientCompile11023(t *testing.T) {
	tree := policyPoisonTree11013(t, "then { permit; }\nthen log bogusmode;")
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile rejected the persisted compact policy: %v", err)
	}
	if !policyPoisonPolicy11013(t, cfg).LenientContentDropped {
		t.Fatal("unknown compact then-log mode did not poison the policy")
	}
	warnings := strings.Join(cfg.Warnings, "\n")
	for _, want := range []string{`policy "p"`, "bogusmode", "#11023"} {
		if !strings.Contains(warnings, want) {
			t.Fatalf("tolerant compile warning missing %q: %q", want, warnings)
		}
	}
}

func TestKnownSecurityPolicyThenLogModesDoNotPoison11023(t *testing.T) {
	tree := buildPolicyThenTree(t,
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		"set security policies from-zone trust to-zone untrust policy p match source-address any",
		"set security policies from-zone trust to-zone untrust policy p match destination-address any",
		"set security policies from-zone trust to-zone untrust policy p match application any",
		"set security policies from-zone trust to-zone untrust policy p then permit",
		"set security policies from-zone trust to-zone untrust policy p then log session-init session-close",
	)

	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile rejected supported then-log modes: %v", err)
	}
	if pol := policyPoisonPolicy11013(t, cfg); pol.LenientContentDropped {
		t.Fatal("supported then-log modes unexpectedly poisoned the policy")
	}
}
