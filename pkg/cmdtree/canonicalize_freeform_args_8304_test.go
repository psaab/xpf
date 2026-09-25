package cmdtree

import (
	"strings"
	"testing"
)

// #8304. Canonicalize's contract makes its bool non-advisory: a caller
// enforcing a login-class restriction MUST fail closed on anything but
// CanonicalOK, and evaluateCommandRegex (pkg/cli/permissions_regex.go) does
// exactly that. So a legal command the tree cannot resolve is not a cosmetic
// gap — every class carrying allow-commands or deny-commands is refused it.
//
// Measured at origin/master before this change, with resolving controls in the
// SAME run so the result is not vacuous:
//
//	show configuration security zones   -> CanonicalUnknown
//	show log messages                   -> CanonicalUnknown
//	show route / show security policies -> CanonicalOK
//
// The issue named three commands. Two are real and the class is wider than
// both: EVERY `show configuration <stanza> <deeper>` failed, and so did
// `show log 50` — the `[N]` form that node's own Desc advertises.

func canon(t *testing.T, cmd string) CanonicalizeResult {
	t.Helper()
	_, res := Canonicalize(OperationalTree, strings.Fields(cmd))
	return res
}

// The commands an operator is entitled to run must resolve.
func TestFreeFormArgCommandsResolve_8304(t *testing.T) {
	for _, cmd := range []string{
		// show log: filename, count, filename+count, and bare.
		"show log",
		"show log messages",
		"show log 50",
		"show log messages 50",
		// show configuration <stanza> <arbitrary depth>. Not one leaf: the
		// whole stanza set, at more than one depth.
		"show configuration security",
		"show configuration security zones",
		"show configuration security zones security-zone trust",
		"show configuration system services",
		"show configuration bridge-domains",
		"show configuration bridge-domains bd0",
		"show configuration interfaces ge-0/0/0",
		"show configuration firewall filter f1",
	} {
		if got := canon(t, cmd); got != CanonicalOK {
			t.Errorf("Canonicalize(%q) = %v, want CanonicalOK. A login class carrying "+
				"allow-commands/deny-commands is refused this command outright.", cmd, got)
		}
	}
}

// THE OVER-REACH CONTROLS, and they are the load-bearing half. A canonicalizer
// loosened until the target commands pass satisfies every cell above while
// resolving anything at all — which would silently widen what a deny regex is
// judged against.
//
// RED on over-reach: drop the AcceptsArgs opt-in and admit any trailing word
// after any node, and every case here starts returning CanonicalOK.
func TestUncanonicalCommandsStillFail_8304(t *testing.T) {
	for _, tc := range []struct{ cmd, why string }{
		{"show security policies zzz", "a node without AcceptsArgs stays strict"},
		{"zzz-not-a-command", "an unknown first word is not a command"},
		{"show zzz-not-a-subcommand", "an unknown second word is not a command"},
		// #8289's bypass: a leaf must not descend to its own siblings.
		{"show version configuration", "the #8289 sibling-descent bypass must stay closed"},
	} {
		if got := canon(t, tc.cmd); got == CanonicalOK {
			t.Errorf("Canonicalize(%q) resolved, want a refusal — %s", tc.cmd, tc.why)
		}
	}
}

// DELIBERATELY NOT A CONTROL: `show route zzz-not-a-thing`.
//
// It was in the list above on the first draft and it failed — measured on a
// clean worktree at origin/master, it resolves there too, so it is not a
// regression from AcceptsArgs and the EXPECTATION was wrong. `show route` has a
// `<destination>` PLACEHOLDER child, and findPlaceholder is the third
// pre-existing mechanism by which Canonicalize admits a non-keyword word: the
// unknown token is a destination, and resolving it is correct.
//
// Recorded rather than deleted silently, because "tighten the canonicalizer
// until this refuses" is a plausible-looking next step that would break
// `show route <prefix>` for every operator. The over-reach controls above are
// the ones where NO mechanism applies — no placeholder, no dynamic, no
// AcceptsArgs.

// The command the issue names THIRD must keep failing. It looks like a peer of
// the other two, but the CLI rejects it: parseClearSessionFilter's default arm
// sets `unknown session filter "all"` (pkg/cli/session_filter.go), so `all` is
// not a served command and refusing it is correct.
//
// Marking it would model a command the dispatcher declines — the mirror of the
// defect this fixes, and the property #8057's canonicalize-to-self check exists
// to protect: every entry in a command table is a real command.
func TestClearSessionAllStaysUnresolved_8304(t *testing.T) {
	if got := canon(t, "clear security flow session all"); got == CanonicalOK {
		t.Errorf("`clear security flow session all` resolved, but the CLI refuses it as "+
			"an unknown session filter; modelling it would claim a command that does "+
			"not exist (got %v)", got)
	}
	// The real filter form is the control: it must resolve, so the refusal
	// above is about `all` specifically and not about the subtree.
	if got := canon(t, "clear security flow session zone trust"); got != CanonicalOK {
		t.Errorf("a REAL session filter must still resolve, got %v", got)
	}
}
