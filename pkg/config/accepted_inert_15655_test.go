package config

import (
	"strings"
	"testing"
)

// #15655 V12-01: `security alg pptp disable` must be modeled, not inert.
func TestPPTPDisableModeled15655(t *testing.T) {
	for _, lines := range [][]string{
		{"set security alg pptp disable"},
	} {
		cfg, err := CompileConfig(buildTree(t, lines))
		if err != nil {
			t.Fatalf("compile: %v", err)
		}
		if !cfg.Security.ALG.PPTPDisable {
			t.Fatalf("PPTPDisable not set; alg=%+v warnings=%v", cfg.Security.ALG, cfg.Warnings)
		}
		if cfg.Security.ALG.ALGDisabled("pptp") != true {
			t.Fatalf("ALGDisabled(pptp) = false")
		}
		found := false
		for _, p := range ALGModeledProtos() {
			if p == "pptp" {
				found = true
			}
		}
		if !found {
			t.Fatalf("pptp missing from ALGModeledProtos %v", ALGModeledProtos())
		}
		for _, p := range cfg.Security.ALG.UnsupportedProtos {
			if p == "pptp" {
				t.Fatalf("pptp still in UnsupportedProtos %v", cfg.Security.ALG.UnsupportedProtos)
			}
		}
		if strings.Contains(strings.Join(cfg.Warnings, "\n"), "pptp accepted but inert") {
			t.Fatalf("pptp still warned inert: %v", cfg.Warnings)
		}
		if got := ALGStatusText("pptp", true); got != ALGStatusDisabled {
			t.Fatalf("ALGStatusText(pptp,true)=%q want disabled", got)
		}
	}
	// Hierarchical spelling.
	tree, errs := NewParser("security { alg { pptp { disable; } } }").Parse()
	if len(errs) > 0 {
		t.Fatalf("parse: %v", errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile hier: %v", err)
	}
	if !cfg.Security.ALG.PPTPDisable {
		t.Fatalf("hierarchical pptp disable not set: %+v", cfg.Security.ALG)
	}
}

// #15655 V15-04: security user-identification must warn (not silent), and
// services warnings must be deduplicated and cover device-information /
// authentication-source without contradictory generic fallback.
func TestUserIdentificationWarnings15655(t *testing.T) {
	// security form — previously silent.
	cfg, err := CompileConfig(buildTree(t, []string{
		"set security user-identification active-directory-access domain-name corp.example",
	}))
	if err != nil {
		t.Fatalf("compile security user-id: %v", err)
	}
	joined := strings.Join(cfg.Warnings, "\n")
	if !strings.Contains(joined, "user-identification") || !strings.Contains(joined, "accepted-only") {
		t.Fatalf("security user-identification silent; warnings=%v", cfg.Warnings)
	}

	// services form: duplicate flat lines must warn once per stanza, and
	// device-information must be named, not fall back to generic.
	cfg2, err := CompileConfig(buildTree(t, []string{
		"set services user-identification active-directory-access domain-name corp.example",
		"set services user-identification active-directory-access domain-name other.example",
		"set services user-identification device-information",
	}))
	if err != nil {
		t.Fatalf("compile services user-id: %v", err)
	}
	count := 0
	for _, w := range cfg2.Warnings {
		if strings.Contains(w, "active-directory-access") {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("duplicate active-directory-access warnings: count=%d warnings=%v", count, cfg2.Warnings)
	}
	joined2 := strings.Join(cfg2.Warnings, "\n")
	if !strings.Contains(joined2, "device-information") {
		t.Fatalf("device-information not named; warnings=%v", cfg2.Warnings)
	}
	// Generic fallback must not coexist with specific stanza warnings.
	for _, w := range cfg2.Warnings {
		if w == "services user-identification configured but accepted-only — xpf does not implement identity-based policy mapping, so the stanza has no runtime effect (#10947)" {
			t.Fatalf("contradictory generic fallback alongside specific warnings: %v", cfg2.Warnings)
		}
	}
}

// #15655 V15-04: JIMS secrets must never survive redaction.
func TestJIMSRedaction15655(t *testing.T) {
	const leak1 = "LEAK-JIMS-CLIENT-SECRET-15655"
	const leak2 = "LEAK-JIMS-SHARED-SECRET-15655"
	tree := buildRedactTree(t, []string{
		"set services user-identification identity-management connection primary authentication client-secret " + leak1,
		"set services user-identification identity-management connection primary authentication shared-secret " + leak2,
		"set security user-identification authentication-source jims client-secret " + leak1,
	})
	out := tree.RedactedClone().Format()
	if strings.Contains(out, leak1) || strings.Contains(out, leak2) {
		t.Fatalf("JIMS secret leaked in redacted render:\n%s", out)
	}
	if !strings.Contains(out, SecretDataPlaceholder) {
		t.Fatalf("expected redaction placeholder in:\n%s", out)
	}
	// Compare path must also be clean.
	cmp := FormatCompareRedacted(&ConfigTree{}, tree)
	if strings.Contains(cmp, leak1) || strings.Contains(cmp, leak2) {
		t.Fatalf("JIMS secret leaked in compare:\n%s", cmp)
	}
}
