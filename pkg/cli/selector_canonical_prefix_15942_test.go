package cli

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #15942 H1-01: canonicalPrefix stepped into the first selector keyword,
// so an anchored deny/allow written against the base command
// (`^show security policies$`) never matched the selector-bearing
// spellings operators actually type (`… from-zone trust`). Any selector
// keyword stepped around an anchored deny, and a mandatory-selector
// command could never satisfy an anchored allow. The fix prices the
// selector-free base form alongside the full form.
func TestAnchoredDenySelectorForms15942(t *testing.T) {
	for _, tc := range []struct {
		deny   string
		line   string
		denied bool
		why    string
	}{
		{"^show security policies$", "show security policies", true, "positive control: bare base denied"},
		{"^show security policies$", "show security policies from-zone trust", true, "selector form must not step around the anchored base deny"},
		{"^show security policies$", "show security policies from-zone trust to-zone untrust", true, "chained selectors still price as the base"},
		{"^show security policies$", "show security policies policy-name allow-web", true, "typed-leaf selector (#15721) prices as the base"},
		{"^show security policies$", "show security policies brief", false, "plain subcommand keyword is not priced as the bare base"},
		{"^show security policies$", "show security zones", false, "negative control: sibling command untouched"},
		{"^clear dhcp client-identifier$", "clear dhcp client-identifier interface ge-0/0/0", true, "AcceptsArgs trailing words price as the base command"},
	} {
		rules, err := config.CompileLoginRegexes(config.LoginRegexPlainFamily, "", false, tc.deny, true)
		if err != nil {
			t.Fatalf("compile deny %q: %v", tc.deny, err)
		}
		err = evaluateCommandRegex(rules, "restricted", tc.line, "")
		if tc.denied && err == nil {
			t.Errorf("deny=%q line=%q: ALLOWED, want denied — %s", tc.deny, tc.line, tc.why)
		}
		if !tc.denied && err != nil {
			t.Errorf("deny=%q line=%q: denied (%v), want allowed — %s", tc.deny, tc.line, err, tc.why)
		}
	}
}

// Anchored allow side: a class allowed only `^show security policies$`
// must be able to run the mandatory-selector spellings (pre-fix the
// polluted prefix matched no allow and the allowlist refused them),
// while unrelated commands stay refused.
func TestAnchoredAllowSelectorForms15942(t *testing.T) {
	rules, err := config.CompileLoginRegexes(config.LoginRegexPlainFamily,
		"^show security policies$", true, "", false)
	if err != nil {
		t.Fatalf("compile allow: %v", err)
	}
	for _, line := range []string{
		"show security policies",
		"show security policies from-zone trust",
		"show security policies from-zone trust to-zone untrust",
	} {
		if err := evaluateCommandRegex(rules, "restricted", line, ""); err != nil {
			t.Errorf("allow=^show security policies$ line=%q: denied (%v), want allowed", line, err)
		}
	}
	if err := evaluateCommandRegex(rules, "restricted", "show security zones", ""); err == nil {
		t.Error("show security zones was ALLOWED under allowlist ^show security policies$, want refused")
	}
}

// True subcommand chains must not be truncated to a shorter base: an
// anchored deny on `show security flow` must not fire for the distinct
// `show security flow session` command, and an anchored deny on the
// session command must fire for its selector spellings.
func TestSelectorBaseKeepsSubcommandChains15942(t *testing.T) {
	rules, err := config.CompileLoginRegexes(config.LoginRegexPlainFamily, "", false, "^show security flow$", true)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if err := evaluateCommandRegex(rules, "restricted", "show security flow session", ""); err != nil {
		t.Errorf("show security flow session denied by ^show security flow$ (%v); subcommand chain truncated", err)
	}
	rules2, err := config.CompileLoginRegexes(config.LoginRegexPlainFamily, "", false, "^show security flow session$", true)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if err := evaluateCommandRegex(rules2, "restricted", "show security flow session", ""); err == nil {
		t.Error("show security flow session ALLOWED under its own anchored deny, want denied")
	}
}
