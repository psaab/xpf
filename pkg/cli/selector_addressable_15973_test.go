package cli

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// Fold of #15973 review (ledgers 15973-{codex,opus,glm}): the first
// canonicalForms cut dropped selector keywords from every form, so an
// anchored rule written against the DOCUMENTED selector spelling
// (`^show security screen ids-option$`, `^show firewall filter$`)
// matched nothing in either direction, the "full" form fabricated
// spellings aliasing real siblings (`show firewall effective`), and
// the #14687 rescue let pipe-filter text and full-form denials be
// overridden. Selector spellings are addressable forms again; the
// rescue may fire only when the base form is the sole deny verdict.

func eval15973(t *testing.T, allow, deny, line, pipeSuffix string) error {
	t.Helper()
	rules, err := config.CompileLoginRegexes(config.LoginRegexPlainFamily,
		allow, allow != "", deny, deny != "")
	if err != nil {
		t.Fatalf("compile allow=%q deny=%q: %v", allow, deny, err)
	}
	return evaluateCommandRegex(rules, "restricted", line, pipeSuffix)
}

func TestSelectorSpellingAddressable15973(t *testing.T) {
	for _, tc := range []struct {
		rules  string // "deny:..." or "allow:..."
		line   string
		pipe   string
		denied bool
		why    string
	}{
		// B1: anchored deny on the selector spelling must match.
		{"deny:^show security screen ids-option$", "show security screen ids-option foo", "", true, "selector-spelling deny (GLM B1)"},
		{"deny:^show firewall filter$", "show firewall filter FOO family inet", "", true, "selector-spelling deny (GLM B1)"},
		{"deny:^show security screen ids-option$", "show security screen ids-option foo detail", "", true, "selector-spelling deny covers detail child"},
		// B2: anchored allow on the selector spelling must satisfy.
		{"allow:^show security screen ids-option$", "show security screen ids-option foo", "", false, "selector-spelling allow (GLM B2)"},
		{"allow:^show firewall filter$", "show firewall filter FOO family inet", "", false, "selector-spelling allow (GLM B2)"},
		// Original H1-01 cells still hold.
		{"deny:^show security policies$", "show security policies from-zone trust", "", true, "anchored base deny reaches selector form"},
		{"deny:^show security policies$", "show security policies from-zone trust to-zone untrust", "", true, "anchored base deny reaches chained selectors"},
		{"allow:^show security policies$", "show security policies from-zone trust", "", false, "anchored base allow satisfies mandatory selector"},
		// B3: no fabricated forms aliasing real siblings.
		{"allow:^show firewall effective$", "show firewall filter FOO effective", "", true, "fabricated full form must not satisfy sibling allow (GLM B3)"},
		{"deny:^show firewall effective$", "show firewall filter FOO effective", "", false, "fabricated full form must not trigger sibling deny (GLM B3 mirror)"},
		// #14687 narrower command: base deny alone does not veto it…
		{"deny:^show security screen$", "show security screen ids-option prof1", "", false, "distinct narrower selector survives base-only deny"},
		// …but a deny on its full keyword form does (Opus exact check).
		{"deny:^show security screen$|^show security screen detail$", "show security screen ids-option prof1 detail", "", true, "full-form deny vetoes the rescue"},
		// Codex/9628: a deny on the executed pipe-less command is not rescued.
		{"deny:^show route table secret-vrf$", "show route table secret-vrf", "match .", true, "executed-command deny survives the rescue (Codex P1)"},
		// B4: pipe-filter text cannot affirm the rescue (GLM B4).
		{"allow+deny:interfaces|^show security screen$", "show security screen ids-option foo", "match interfaces", true, "pipe-smuggled allow must not rescue (GLM B4)"},
	} {
		allow, deny := "", ""
		switch {
		case len(tc.rules) > 11 && tc.rules[:11] == "allow+deny:":
			parts := tc.rules[11:]
			if i := indexFold15973(parts, "|^"); i >= 0 {
				allow, deny = parts[:i], parts[i+1:]
			}
		case len(tc.rules) > 5 && tc.rules[:5] == "deny:":
			deny = tc.rules[5:]
		case len(tc.rules) > 6 && tc.rules[:6] == "allow:":
			allow = tc.rules[6:]
		}
		err := eval15973(t, allow, deny, tc.line, tc.pipe)
		if tc.denied && err == nil {
			t.Errorf("rules=%q line=%q pipe=%q: ALLOWED, want denied — %s", tc.rules, tc.line, tc.pipe, tc.why)
		}
		if !tc.denied && err != nil {
			t.Errorf("rules=%q line=%q pipe=%q: denied (%v), want allowed — %s", tc.rules, tc.line, tc.pipe, err, tc.why)
		}
	}
}

func indexFold15973(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
