package config

import (
	"strings"
	"testing"
)

// #14686: cross-form longest-match maximization + pipe/arg keyword smuggling.
//
// RED on the pooled max-per-side EvaluateForms:
//   - EvaluateForms("show version | match .","show version","show version")
//     allow ^show.* / deny (^show version$)|(^show log$) -> ALLOWED (22 > 12)
//   - EvaluateForms("show configuration | except show interfaces",...)
//     allow "show interfaces" (allowlist) -> ALLOWED via pipe text
//
// GREEN requires per-form evaluation: piped/arg forms of an anchored-deny
// command stay denied, and the documented ^show log 100$ exception survives.
func TestEvaluateFormsPipeAndArgDoNotDefeatAnchoredDeny14686(t *testing.T) {
	for _, tc := range []struct {
		name    string
		allow   string
		allowOn bool
		deny    string
		denyOn  bool
		forms   []string // forms[0]=full, forms[1]=prefix, rest=more
		want    bool
		why     string
	}{
		{
			name:  "piped wildcard does not outgrow anchored deny",
			allow: "^show.*", allowOn: true,
			deny: "(^show version$)|(^show log$)", denyOn: true,
			forms: []string{"show version | match .", "show version", "show version"},
			want:  false, why: "pipe inflates wildcard allow past anchored deny",
		},
		{
			name:  "arg-suffixed wildcard does not outgrow anchored deny",
			allow: "^show.*", allowOn: true,
			deny: "(^show version$)|(^show log$)", denyOn: true,
			forms: []string{"show log 100", "show log"},
			want:  false,
			why:   "argument form must not let ^show.* outgrow ^show log$ on the prefix form",
		},
		{
			name:  "unanchored allow smuggled in pipe text does not satisfy allowlist",
			allow: "show interfaces", allowOn: true,
			deny: "", denyOn: false,
			forms: []string{"show configuration | except show interfaces", "show configuration", "show configuration"},
			want:  false, why: "allow phrase inside user pipe text must not authorize show configuration",
		},
		{
			name:  "unanchored allow smuggled in pipe text with deny present",
			allow: "show interfaces", allowOn: true,
			deny: "request system reboot", denyOn: true,
			forms: []string{"show configuration | except show interfaces", "show configuration", "show configuration"},
			want:  false, why: "same smuggling, with an unrelated deny configured",
		},
		{
			name:  "documented anchored exception survives",
			allow: "^show log 100$", allowOn: true,
			deny: "^show log$", denyOn: true,
			forms: []string{"show log 100", "show log"},
			want:  true, why: "#9022 deny-with-exceptions idiom",
		},
		{
			name:  "anchored exception only for its exact arg",
			allow: "^show log 100$", allowOn: true,
			deny: "^show log$", denyOn: true,
			forms: []string{"show log 200", "show log"},
			want:  false, why: "show log 200 is not the allowed exception",
		},
		{
			name:  "bare anchored deny still denies",
			allow: "^show.*", allowOn: true,
			deny: "(^show version$)|(^show log$)", denyOn: true,
			forms: []string{"show version", "show version"},
			want:  false, why: "control: bare denied command",
		},
		{
			name:  "wildcard allow still allows undenied piped command",
			allow: "^show.*", allowOn: true,
			deny: "(^show version$)|(^show log$)", denyOn: true,
			forms: []string{"show route | match .", "show route", "show route"},
			want:  true, why: "negative control: unrelated piped show command",
		},
		{
			name:  "allowlist command itself still allowed piped",
			allow: "show interfaces", allowOn: true,
			deny: "", denyOn: false,
			forms: []string{"show interfaces | match x", "show interfaces", "show interfaces"},
			want:  true, why: "the genuinely allowed command, piped",
		},
		{
			name:  "identical patterns tier1 still allows",
			allow: "request system reboot", allowOn: true,
			deny: "request system reboot", denyOn: true,
			forms: []string{"request system reboot", "request system reboot"},
			want:  true, why: "Juniper tier 1",
		},
		{
			name:  "longer deny beats shorter allow same form",
			allow: "commit", allowOn: true,
			deny: "commit synchronize", denyOn: true,
			forms: []string{"commit synchronize", "commit synchronize"},
			want:  false, why: "tier 2 deny direction (#7172)",
		},
		{
			name:  "pipe deny still bites on piped form",
			allow: "", allowOn: false,
			deny: "display set", denyOn: true,
			forms: []string{"show configuration | display set", "show configuration", "show configuration"},
			want:  false, why: "#7172/#9628: deny on pipe text, command form alone would allow",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rules, err := CompileLoginRegexes(LoginRegexPlainFamily, tc.allow, tc.allowOn, tc.deny, tc.denyOn)
			if err != nil {
				t.Fatalf("CompileLoginRegexes: %v", err)
			}
			// Forms containing a pipe go through the pipe-marked entry,
			// exactly as evaluateCommandRegex dispatches them.
			hasPipe := strings.Contains(tc.forms[0], "|")
			var d LoginRegexDecision
			switch {
			case hasPipe && len(tc.forms) > 2:
				d = rules.EvaluateFormsWithPipe(tc.forms[0], tc.forms[1], tc.forms[2:]...)
			case hasPipe:
				d = rules.EvaluateFormsWithPipe(tc.forms[0], tc.forms[1])
			case len(tc.forms) > 2:
				d = rules.EvaluateForms(tc.forms[0], tc.forms[1], tc.forms[2:]...)
			default:
				d = rules.EvaluateForms(tc.forms[0], tc.forms[1])
			}
			if d.Allowed != tc.want {
				t.Fatalf("EvaluateForms%q allow=%q deny=%q: allowed=%v (%s), want %v. %s",
					tc.forms, tc.allow, tc.deny, d.Allowed, d.Reason, tc.want, tc.why)
			}
		})
	}
}
