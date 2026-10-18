package cli

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #14686 through the real CLI gate (evaluateCommandRegex): a piped/arg form
// must not defeat an end-anchored deny via a wildcard allow measured on the
// longer piped string, and an allow phrase smuggled into pipe filter text
// must not satisfy the allowlist for a command that never matched it.
func TestPipedWildcardAndSmuggledAllowDoNotBypassAnchoredDeny14686(t *testing.T) {
	for _, tc := range []struct {
		allow, deny, line, pipe string
		wantDeny                bool
		why                     string
	}{
		{"^show.*", "(^show version$)|(^show log$)", "show version", "match .", true, "wildcard allow grows with pipe text, anchored deny cannot"},
		{"^show.*", "(^show version$)|(^show log$)", "show version", "except foo", true, "any pipe suffix"},
		{"^show.*", "(^show version$)|(^show log$)", "show route", "match .", false, "negative control: undenied piped command"},
		{"show interfaces", "", "show configuration", "except show interfaces", true, "allow phrase smuggled in pipe filter text"},
		{"show interfaces", "", "show interfaces", "match x", false, "genuinely allowed command, piped"},
		{"^show log 100$", "^show log$", "show log 100", "", false, "documented anchored exception (no pipe)"},
		{"^show log 100$", "^show log$", "show log 100", "match x", false, "documented anchored exception through a pipe: full piped form is the exception's command with output filter"},
		{"", "display set", "show configuration | display set", "", true, "control: pipe-text deny still bites"},
	} {
		t.Run(tc.line+"|"+tc.pipe, func(t *testing.T) {
			rules, err := config.CompileLoginRegexes(config.LoginRegexPlainFamily, tc.allow, tc.allow != "", tc.deny, tc.deny != "")
			if err != nil {
				t.Fatalf("CompileLoginRegexes: %v", err)
			}
			err = evaluateCommandRegex(rules, "restricted", tc.line, tc.pipe)
			if tc.wantDeny && err == nil {
				t.Fatalf("ALLOWED, want denied. %s", tc.why)
			}
			if !tc.wantDeny && err != nil {
				t.Fatalf("DENIED (%v), want allowed. %s", err, tc.why)
			}
		})
	}
}
