package cli

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #16780 through the real CLI gate (evaluateCommandRegex): a deny that
// matches only pipe/format text (`display set`, `| match`, an anchored
// full-spelling pipe deny) must veto the piped command even when the
// class's allow matches the pipe-less core. Before the fix the
// #14686 pipe-boundary "saved" arm overturned the full-form tier
// denial whenever a pipe-less form affirmed the core allow.
func TestPipedPipeOnlyDenyNotSaved16780(t *testing.T) {
	for _, tc := range []struct {
		allow, deny, line, pipe string
		wantDeny                bool
		why                     string
	}{
		{"^show", "display set", "show configuration | display set", "", true, "deny on pipe format text; allow matches the bare command"},
		{"^show", "display set", "show configuration", "display set", true, "same denial reached through the split pipe suffix"},
		{"^show", "display set", "show configuration system | display set", "", true, "subtree spelling under the same pipe-only deny"},
		{"^show", `\| match`, "show route", "match 10.", true, "deny on the pipe verb itself; Evaluate(full) denies (7 > 4)"},
		{"^show configuration", `show configuration security \| display set`, "show configuration security | display set", "", true, "full-spelling pipe deny out-measures the core allow (41 > 18)"},
		{"^show log 100$", "display set", "show log 100", "display set", true, "the anchored exception covers the core, not the denied pipe"},
		// Controls that must stay green (#14686/#9022/#9628).
		{"^show log 100$", "^show log$", "show log 100", "match x", false, "documented anchored exception through a benign pipe"},
		{"^show route table public-vrf$", "^show route table", "show route table public-vrf", "match 10.0", false, "public-vrf core exception through a pipe"},
		{"", "display set", "show configuration | display set", "", true, "positive control: deny-only class"},
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
