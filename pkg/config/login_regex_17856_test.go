package config

import (
	"strings"
	"testing"
)

// #17856: #16780's pipeOnlyDeny asked whether the WHOLE deny pattern ever
// matches the pipe-less core. One losing alternative that merely touches
// the core (`^sh` in `^sh|display set`, 2 characters against allow
// `^show`'s 4) therefore disabled the guard while a different, WINNING
// alternative (`display set`, 11 > 4 on the full form) matched only pipe
// text — the exact residual #16780 exists to close, reachable through
// every pipe-boundary save. The guard now judges per alternative: only
// the alternatives realizing the deny's winning extent on the full form
// decide whether the denial is pipe text.
func TestEvaluateFormsWithPipeWinningPipeDenyAltNotSaved17856(t *testing.T) {
	for _, tc := range []struct {
		name    string
		allow   string
		allowOn bool
		deny    string
		denyOn  bool
		forms   []string // forms[0]=full (piped), forms[1]=prefix, rest=more
		want    bool
		why     string
	}{
		{
			name:  "winning pipe alternative not rescued by core-touching sibling",
			allow: "^show", allowOn: true,
			deny: `^sh|display set`, denyOn: true,
			forms: []string{"show configuration | display set", "show configuration"},
			want:  false, why: "the ^sh sibling loses on the full form (2 < 4) and on the core; display set wins 11 > 4 on pipe text only",
		},
		{
			name:  "spaced winning pipe alternative with core-touching sibling",
			allow: "^show", allowOn: true,
			deny: `^sh| display set`, denyOn: true,
			forms: []string{"show configuration | display set", "show configuration"},
			want:  false, why: "same geometry with the pipe alternative spelled ' display set'",
		},
		{
			name:  "winning pipe-verb alternative with core-touching sibling",
			allow: "^show", allowOn: true,
			deny: `^sh|\| match`, denyOn: true,
			forms: []string{"show configuration | match x", "show configuration"},
			want:  false, why: "the \\| match alternative wins 7 > 4 on pipe text; the ^sh sibling loses 2 < 4",
		},
		{
			name:  "subtree spelling under the winning pipe alternative",
			allow: "^show", allowOn: true,
			deny: `^sh|display set`, denyOn: true,
			forms: []string{"show configuration system | display set", "show configuration", "show configuration system"},
			want:  false, why: "the subtree spelling's core allow must not rescue the pipe-text winner either",
		},
		{
			name:  "exception allow does not rescue its own denied pipe past a core-touching sibling",
			allow: "^show log 100$", allowOn: true,
			deny: `^sh|display set`, denyOn: true,
			forms: []string{"show log 100 | display set", "show log", "show log 100"},
			want:  false, why: "the ^show log 100$ exception covers the core; the winning display set alternative is pipe text, and the ^sh sibling loses on the core (2 < 12)",
		},
		{
			name:  "anchored full-spelling pipe deny inside an alternation",
			allow: "^show configuration", allowOn: true,
			deny: `^sh|show configuration security \| display set`, denyOn: true,
			forms: []string{"show configuration security | display set", "show configuration", "show configuration security"},
			want:  false, why: "the anchored alternative wins 41 > 18 and matches the core only with its pipe text; the ^sh sibling loses 2 < 18",
		},
		{
			name:  "grouped core-touching sibling still loses to the pipe winner",
			allow: "^show", allowOn: true,
			deny: `^(s|h)|display set`, denyOn: true,
			forms: []string{"show configuration | display set", "show configuration"},
			want:  false, why: "the ^(s|h) branches match 1 character of the core against allow's 4; display set wins 11 > 4 on pipe text only",
		},
		// Controls that must stay green (#14686/#9022/#9628/#16780).
		{
			name:  "documented anchored exception through a benign pipe stays allowed",
			allow: "^show log 100$", allowOn: true,
			deny: "^show log$", denyOn: true,
			forms: []string{"show log 100 | match x", "show log", "show log 100"},
			want:  true, why: "#9022 deny-with-exceptions geometry through a pipe",
		},
		{
			name:  "public-vrf exception through a pipe stays allowed",
			allow: "^show route table public-vrf$", allowOn: true,
			deny: "^show route table", denyOn: true,
			forms: []string{"show route table public-vrf | match 10.0", "show route table", "show route table public-vrf"},
			want:  true, why: "#9628 public-vrf: the winning alternative covers core text, so the exception saves still apply",
		},
		{
			name:  "public-vrf exception with a pipe alternative added stays allowed",
			allow: "^show route table public-vrf$", allowOn: true,
			deny: `^show route table|display set`, denyOn: true,
			forms: []string{"show route table public-vrf | match 10.0", "show route table", "show route table public-vrf"},
			want:  true, why: "the winning alternative (^show route table, 16) covers the truncated core, so the denial is core-explained and the exception saves run",
		},
		{
			name:  "alternation whose every alternative loses on the core stays allowed",
			allow: "^show", allowOn: true,
			deny: "^sh", denyOn: true,
			forms: []string{"show configuration | display set", "show configuration"},
			want:  true, why: "the deny loses the full form (2 < 4) and the core; no pipe winner exists",
		},
		{
			name:  "core anchored deny through a pipe still vetoes",
			allow: "^show", allowOn: true,
			deny: "^show version$", denyOn: true,
			forms: []string{"show version | match .", "show version", "show version"},
			want:  false, why: "deny matches the pipe-less core, so it is not pipe-only and still vetoes",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rules, err := CompileLoginRegexes(LoginRegexPlainFamily, tc.allow, tc.allowOn, tc.deny, tc.denyOn)
			if err != nil {
				t.Fatalf("CompileLoginRegexes: %v", err)
			}
			if !strings.Contains(tc.forms[0], "|") {
				t.Fatalf("forms[0] must carry a pipe: %q", tc.forms[0])
			}
			var d LoginRegexDecision
			if len(tc.forms) > 2 {
				d = rules.EvaluateFormsWithPipe(tc.forms[0], tc.forms[1], tc.forms[2:]...)
			} else {
				d = rules.EvaluateFormsWithPipe(tc.forms[0], tc.forms[1])
			}
			if d.Allowed != tc.want {
				t.Fatalf("EvaluateFormsWithPipe%q allow=%q deny=%q: allowed=%v (%s), want %v. %s",
					tc.forms, tc.allow, tc.deny, d.Allowed, d.Reason, tc.want, tc.why)
			}
		})
	}
}
