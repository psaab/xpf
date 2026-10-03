package config

import (
	"fmt"
	"strings"
	"testing"
)

func inertRewriteTree11811(t *testing.T, family, ruleName, lossPriority, codePoint string) *ConfigTree {
	t.Helper()
	return flatTreeFromSets(t,
		"set class-of-service forwarding-classes queue 3 voice",
		fmt.Sprintf("set class-of-service rewrite-rules %s %s forwarding-class voice loss-priority %s code-point %s",
			family, ruleName, lossPriority, codePoint),
		"set system dataplane-type userspace",
	)
}

func inertRewriteEntry11811(cfg *Config, family string) *CoSInertRewriteRuleEntry {
	if cfg == nil || cfg.ClassOfService == nil {
		return nil
	}
	if family == "inet-precedence" {
		rule := cfg.ClassOfService.INetPrecedenceRewriteRuleDefs["rw"]
		if rule != nil && len(rule.Entries) > 0 {
			return rule.Entries[0]
		}
		return nil
	}
	rule := cfg.ClassOfService.EXPRewriteRuleDefs["rw"]
	if rule != nil && len(rule.Entries) > 0 {
		return rule.Entries[0]
	}
	return nil
}

func TestCoSInertRewriteRulesCompileValidationModel11811(t *testing.T) {
	for _, family := range []string{"inet-precedence", "exp"} {
		t.Run(family, func(t *testing.T) {
			for _, tc := range []struct {
				raw  string
				want uint8
			}{{"0", 0}, {"7", 7}} {
				cfg, err := CompileConfig(inertRewriteTree11811(t, family, "rw", "low", tc.raw))
				if err != nil {
					t.Fatalf("CompileConfig(%s): %v", tc.raw, err)
				}
				entry := inertRewriteEntry11811(cfg, family)
				if entry == nil || entry.ForwardingClass != "voice" ||
					entry.LossPriority != "low" || entry.CodePoint != tc.want {
					t.Fatalf("%s rewrite entry for code-point %s = %+v, want voice/low/%d",
						family, tc.raw, entry, tc.want)
				}
			}
		})
	}
}

func TestCoSInertRewriteRulesLenientLossPriorityWarns11811(t *testing.T) {
	for _, family := range []string{"inet-precedence", "exp"} {
		t.Run(family, func(t *testing.T) {
			cfg, err := CompileConfigLenient(inertRewriteTree11811(t, family, "rw", "hgih", "5"))
			if err != nil {
				t.Fatalf("CompileConfigLenient rejected an inert rewrite loss-priority typo: %v", err)
			}
			warned := false
			for _, warning := range cfg.Warnings {
				if strings.Contains(warning, "loss-priority") && strings.Contains(warning, "hgih") {
					warned = true
					break
				}
			}
			if !warned {
				t.Fatalf("lenient compile produced no %s loss-priority warning: %v", family, cfg.Warnings)
			}
			entry := inertRewriteEntry11811(cfg, family)
			if entry == nil || entry.LossPriority != "hgih" {
				t.Fatalf("lenient %s rewrite entry = %+v, want the legacy entry retained", family, entry)
			}
		})
	}
}

func TestCoSInertRewriteRulesRejectInvalidCodePoints11811(t *testing.T) {
	for _, family := range []string{"inet-precedence", "exp"} {
		t.Run(family, func(t *testing.T) {
			tree := inertRewriteTree11811(t, family, "rw", "low", "9")
			if err := SchemaValidate(tree, nil); err != nil {
				t.Fatalf("SchemaValidate rejected the recognized rewrite grammar: %v", err)
			}
			_, err := CompileConfig(tree)
			if err == nil {
				t.Fatalf("CompileConfig accepted %s code-point 9; want the 0..7 rejection", family)
			}
			if !strings.Contains(err.Error(), "0..7") || !strings.Contains(err.Error(), family) {
				t.Fatalf("CompileConfig error = %v, want %s 0..7 diagnostic", err, family)
			}
		})
	}
}

func TestCoSInertRewriteRulesRejectLossPriorityTypos11811(t *testing.T) {
	for _, family := range []string{"inet-precedence", "exp"} {
		t.Run(family, func(t *testing.T) {
			tree := inertRewriteTree11811(t, family, "rw", "hgih", "5")
			if err := SchemaValidate(tree, nil); err != nil {
				t.Fatalf("SchemaValidate rejected the recognized rewrite grammar: %v", err)
			}
			_, err := CompileConfig(tree)
			if err == nil {
				t.Fatalf("CompileConfig accepted %s loss-priority hgih", family)
			}
			if !strings.Contains(err.Error(), "loss-priority") || !strings.Contains(err.Error(), "hgih") {
				t.Fatalf("CompileConfig error = %v, want loss-priority typo diagnostic", err)
			}
		})
	}
}

func TestCoSInertRewriteRulesLenientCodePointWarnsAndKeepsAdvisory11811(t *testing.T) {
	for _, family := range []string{"inet-precedence", "exp"} {
		t.Run(family, func(t *testing.T) {
			tree := inertRewriteTree11811(t, family, "rw", "low", "9")
			cfg, err := CompileConfigLenient(tree)
			if err != nil {
				t.Fatalf("CompileConfigLenient rejected invalid inert rewrite code-point: %v", err)
			}
			warned := false
			for _, warning := range cfg.Warnings {
				if strings.Contains(warning, "rewrite-rules "+family) &&
					strings.Contains(warning, "downgraded to warning on tolerant path") &&
					strings.Contains(warning, "0..7") {
					warned = true
					break
				}
			}
			if !warned {
				t.Fatalf("lenient compile produced no invalid-code-point warning: %v", cfg.Warnings)
			}
			if entry := inertRewriteEntry11811(cfg, family); entry != nil {
				t.Fatalf("invalid %s code-point must be omitted from the validation model, got %+v", family, entry)
			}
			if !hasWarningContaining(ValidateConfig(cfg), "rewrite-rules "+family+" is accepted for compatibility but inert") {
				t.Fatalf("the existing %s inert advisory disappeared: %v", family, ValidateConfig(cfg))
			}
		})
	}
}
