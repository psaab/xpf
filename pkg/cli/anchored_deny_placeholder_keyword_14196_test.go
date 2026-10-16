package cli

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/diagcmd"
)

// #14196: A LITERAL PLACEHOLDER WORD DEFEATED AN ANCHORED TARGET DENY.
//
// `ping` declares Options with a `<host>` placeholder. Canonicalize marked
// that placeholder filled only on its unmatched-word arm, while
// resolveTreeWord resolved `<` (and `<host>`, `<h`, …) as a unique prefix
// of the `<host>` keyword. A surplus literal after a real target therefore
// canonicalized to a fake keyword:
//
//	deny="^ping 192.0.2.1$"  line="ping 192.0.2.1"      -> denied
//	deny="^ping 192.0.2.1$"  line="ping 192.0.2.1 <"    -> ALLOWED (pre-fix)
//
// The judged forms were the polluted full string `ping 192.0.2.1 <host>`
// and the keyword-only prefix `ping` — the denied target appears in
// neither — while the handler executed the denied target: the strict
// option parser rejects the surplus word, so nothing about the executed
// command carries it either. Appending the literal changed only the
// string the gate judged, which is the #8289/#9022 divergence in the
// placeholder-keyword costume. The canonicalizer now never resolves a
// placeholder name as a keyword, so the surplus word has no value slot
// and the gate fails closed.
func TestAnchoredDenySurvivesLiteralPlaceholder14196(t *testing.T) {
	for _, tc := range []struct {
		deny, line string
		wantDeny   bool
		why        string
	}{
		{"^ping 192.0.2.1$", "ping 192.0.2.1", true, "positive control: the bare denied command"},
		{"^ping 192.0.2.1$", "ping 192.0.2.1 <", true,
			"the reported shape: a surplus literal `<` must not launder the denied target into a fake <host> keyword"},
		{"^ping 192.0.2.1$", "ping 192.0.2.1 <host>", true, "the full literal placeholder name"},
		{"^ping 192.0.2.1$", "ping 192.0.2.1 <h", true, "a `<`-prefix spelling of the same fake keyword"},
		{"^ping 192.0.2.1$", "ping 192.0.2.1 count 5 <", true,
			"the surplus literal after a complete option list is still a surplus word"},
		{"^ping 192.0.2.1$", "ping 192.0.2.2 <", true,
			"deliberately refused too: the tree cannot say which command this is, so a restricted class fails closed (#9505's junk-word row)"},
		{"^ping 192.0.2.1$", "ping 192.0.2.2", false, "negative control: the deny stays narrow"},
		{"^ping 192.0.2.1$", "show version", false, "negative control: an unrelated command"},
		// The unanchored control the issue requires: it matched even on
		// the broken code (partial matching sees the target inside the
		// polluted string), and it must keep matching — the fix must not
		// be a change that merely makes every form refuse.
		{"ping 192.0.2.1", "ping 192.0.2.1 <", true, "unanchored control: matched before the fix and must still match"},
		{"ping 192.0.2.1", "ping 192.0.2.1", true, "unanchored control: the bare command"},
		{"ping 192.0.2.1", "ping 192.0.2.2", false, "unanchored negative control"},
	} {
		t.Run(tc.deny+" / "+tc.line, func(t *testing.T) {
			rules, err := config.CompileLoginRegexes(config.LoginRegexPlainFamily, "", false, tc.deny, true)
			if err != nil {
				t.Fatalf("CompileLoginRegexes: %v", err)
			}
			err = evaluateCommandRegex(rules, "restricted", tc.line, "")
			if tc.wantDeny && err == nil {
				t.Fatalf("deny=%q line=%q was ALLOWED, want denied.\n%s", tc.deny, tc.line, tc.why)
			}
			if !tc.wantDeny && err != nil {
				t.Fatalf("deny=%q line=%q was DENIED (%v), want allowed.\n%s", tc.deny, tc.line, err, tc.why)
			}
		})
	}
}

// The handler-side identity half of the decisive check: the surplus word
// never reaches the ping child as part of the target. The strict shared
// parser takes the FIRST word as the target and rejects the surplus as an
// unknown option, so the executed command is exactly the denied
// `ping 192.0.2.1` — which is why the gate, not the handler, is where the
// laundered string had to be refused.
func TestPingTargetIdentityWithLiteralPlaceholder14196(t *testing.T) {
	if _, err := diagcmd.ParsePingOptions([]string{"192.0.2.1", "<"}); err == nil {
		t.Fatal("ParsePingOptions accepted a surplus literal `<`: the handler would " +
			"run a command the gate never judged in that form")
	}
	parsed, err := diagcmd.ParsePingOptions([]string{"192.0.2.1"})
	if err != nil || parsed.Target != "192.0.2.1" {
		t.Fatalf("the denied command itself must still parse to its target: %+v err=%v", parsed, err)
	}
}
