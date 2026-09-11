package cli

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #9628: the gate spliced `| suffix` into the words it canonicalized against
// the OPERATIONAL tree. `|` is not a tree word, so a restricted class was
// refused nearly every piped command. It failed closed, so this is
// over-rejection, not a bypass. The fix must not become a bypass either: the
// refusal was also what kept `show version | match .` away from an anchored
// `^show version$`, and those rows are here too.
func TestPipedCommandsAuthorizeOnTheirCommand9628(t *testing.T) {
	for _, tc := range []struct {
		allow, deny, line, pipe string
		wantDeny                bool
		why                     string
	}{
		// The issue's acceptance: a class denying only `request system reboot`.
		{"", "request system reboot", "show route", "match 10.0.0", false, "a recognised filter after a bare command"},
		{"", "request system reboot", "show configuration | display set", "", false, "`display` is parsed in-line by the handler, so it arrives inside the line"},
		{"", "request system reboot", "show security policies", "match trust", false, "the issue's third row"},
		{"", "request system reboot", "show interfaces", "count", false, "unchanged: this resolved before the fix"},
		{"", "request system reboot", "show route table secret-vrf", "match 10.0.0", false, "a dynamic value followed by a pipe; #9505's one-value rule must not refuse it"},
		{"", "save", "show configuration", "save /tmp/x", true, "#7172: still denied"},
		{"", "display set", "show configuration | display set", "", true, "the pipe is still part of the matched string"},
		{"", "request system reboot", "show route", "frobnicate x", true, "an unknown pipe verb is refused"},
		{"", "request system reboot", "c", "match x", true, "an ambiguous command prefix still fails closed"},
		// The rows the splice used to hide. Each is an anchored deny that a
		// pipe must not step around.
		{"", "^show version$", "show version", "match .", true, "the pipe-less command is measured too"},
		{"", "^show route table secret-vrf$", "show route table secret-vrf", "match .", true, "a value-carrying anchored deny under a pipe"},
		{"", "^show configuration$", "show configuration | display set", "", true, "display set dumps what the anchored deny withholds"},
		{"", "^show version$", "show route", "match .", false, "negative control: an unrelated piped command"},
		// deny-with-exceptions still resolves by longest match through a pipe.
		{"^show route table public-vrf$", "^show route table", "show route table public-vrf", "match 10.0", false, "the exception covers its own piped form"},
		{"^show route table public-vrf$", "^show route table", "show route table secret-vrf", "match 10.0", true, "and not a different table"},
	} {
		t.Run(tc.line+" | "+tc.pipe+" deny="+tc.deny, func(t *testing.T) {
			rules, err := config.CompileLoginRegexes(config.LoginRegexPlainFamily, tc.allow, tc.allow != "", tc.deny, true)
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

// An unknown pipe is refused with a message naming the PIPE, so an operator
// does not go looking for a deny rule they never wrote, or for a problem with
// the command.
func TestUnknownPipeRefusalNamesThePipe9628(t *testing.T) {
	rules, err := config.CompileLoginRegexes(config.LoginRegexPlainFamily, "", false, "request system reboot", true)
	if err != nil {
		t.Fatal(err)
	}
	err = evaluateCommandRegex(rules, "restricted", "show route", "frobnicate x")
	if err == nil || !strings.Contains(err.Error(), `output pipe "frobnicate"`) {
		t.Fatalf("want a refusal naming the pipe, got %v", err)
	}
}
