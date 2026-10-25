package config

import (
	"strings"
	"testing"
)

// #16780: the #14686 pipe-boundary "saved" arm overturned a full-form
// deny that matches only pipe/format text whenever an allow matched
// the pipe-less core. A deny on `display set` / `| match` therefore
// had no effect for any class whose allow covered the bare command,
// contrary to docs/system-login.md ("the pipe is matched as typed, so
// a deny on `display set` still sees it … a deny that wins on any
// spelling vetoes the command").
//
// The save exists only for the deny-with-exceptions geometry: a
// core-anchored exception allow that out-measures a vetoing deny on
// the command core (isCoreException). When the vetoing deny matches
// only pipe text there is no core deny for an exception to out-measure,
// so the full-form tier denial must stand.
func TestEvaluateFormsWithPipePipeOnlyDenyNotSaved16780(t *testing.T) {
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
			name:  "pipe-text deny display set not saved by core allow",
			allow: "^show", allowOn: true,
			deny: "display set", denyOn: true,
			forms: []string{"show configuration | display set", "show configuration", "show configuration"},
			want:  false, why: "deny matches only pipe text; ^show on the core must not save it",
		},
		{
			name:  "pipe-text deny match not saved by core allow",
			allow: "^show", allowOn: true,
			deny: `\| match`, denyOn: true,
			forms: []string{"show route | match 10.", "show route", "show route"},
			want:  false, why: "Evaluate(full) says deny wins (7 > 4); the pipe save must not overturn it",
		},
		{
			name:  "full-spelling pipe deny not saved by shorter core allow",
			allow: "^show configuration", allowOn: true,
			deny: `show configuration security \| display set`, denyOn: true,
			forms: []string{"show configuration security | display set", "show configuration", "show configuration security"},
			want:  false, why: "deny wins on the full spelling (41 > 18) and matches the core only with its pipe text",
		},
		{
			name:  "pipe-text deny on subtree spelling not saved",
			allow: "^show", allowOn: true,
			deny: "display set", denyOn: true,
			forms: []string{"show configuration system | display set", "show configuration", "show configuration system"},
			want:  false, why: "subtree command form affirming the core allow must not save a pipe-only deny",
		},
		{
			name:  "exception allow does not save its own denied pipe",
			allow: "^show log 100$", allowOn: true,
			deny: "display set", denyOn: true,
			forms: []string{"show log 100 | display set", "show log", "show log 100"},
			want:  false, why: "the ^show log 100$ exception covers the core, not the denied display pipe",
		},
		// Controls that must stay green (#14686/#9022/#9628).
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
			want:  true, why: "#9628 public-vrf: core exception out-measures the core deny",
		},
		{
			name:  "core anchored deny through a pipe still vetoes",
			allow: "^show", allowOn: true,
			deny: "^show version$", denyOn: true,
			forms: []string{"show version | match .", "show version", "show version"},
			want:  false, why: "deny matches the pipe-less core, so it is not pipe-only and still vetoes",
		},
		{
			name:  "deny-only pipe deny still bites",
			allow: "", allowOn: false,
			deny: "display set", denyOn: true,
			forms: []string{"show configuration | display set", "show configuration", "show configuration"},
			want:  false, why: "positive control: no allow to save with",
		},
		{
			name:  "undenied pipe still allowed",
			allow: "^show", allowOn: true,
			deny: "display set", denyOn: true,
			forms: []string{"show configuration | match x", "show configuration", "show configuration"},
			want:  true, why: "negative control: a pipe the deny does not name",
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
