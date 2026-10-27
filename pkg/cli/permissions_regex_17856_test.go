package cli

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #17856 through the real CLI gate (evaluateCommandRegex): a deny
// alternation whose WINNING alternative matches only pipe text must veto
// the piped command even when a sibling alternative touches the command
// core (and loses there) and the class's allow matches the pipe-less
// core. #16780's guard asked whether the whole deny pattern ever matched
// the core, so the losing sibling disabled it.
func TestPipedWinningPipeDenyAltNotSaved17856(t *testing.T) {
	for _, tc := range []struct {
		allow, deny, line, pipe string
		wantDeny                bool
		why                     string
	}{
		{"^show", `^sh|display set`, "show configuration | display set", "", true, "winning display set alternative is pipe text; the ^sh sibling loses 2 < 4 everywhere"},
		{"^show", `^sh|display set`, "show configuration", "display set", true, "same denial through the split pipe suffix"},
		{"^show", `^sh| display set`, "show configuration", "display set", true, "spaced pipe alternative, split suffix spelling"},
		{"^show", `^sh|\| match`, "show route", "match 10.", true, "winning \\| match alternative is pipe text; Evaluate(full) denies (7 > 4)"},
		{"^show", `^sh|display set`, "show configuration system | display set", "", true, "subtree spelling under the same alternation"},
		{"^show log 100$", `^sh|display set`, "show log 100", "display set", true, "the anchored exception covers the core, not the denied display pipe; the ^sh sibling loses there 2 < 12"},
		{"^show configuration", `^sh|show configuration security \| display set`, "show configuration security", "display set", true, "anchored full-spelling pipe deny inside the alternation wins 41 > 18"},
		// Controls that must stay green (#14686/#9022/#9628/#16780).
		{"^show log 100$", "^show log$", "show log 100", "match x", false, "documented anchored exception through a benign pipe"},
		{"^show route table public-vrf$", "^show route table", "show route table public-vrf", "match 10.0", false, "public-vrf core exception through a pipe"},
		{"^show route table public-vrf$", `^show route table|display set`, "show route table public-vrf", "match 10.0", false, "exception survives a pipe alternative added to the deny: the winning alternative covers core text"},
		{"^show", "^sh", "show configuration | display set", "", false, "an alternation with no pipe winner loses the full form (2 < 4) and stays allowed"},
		{"^show", "display set", "show configuration", "match x", false, "negative control: a pipe the deny does not name"},
	} {
		t.Run(tc.line+" | "+tc.pipe+" allow="+tc.allow+" deny="+tc.deny, func(t *testing.T) {
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
