package config

import (
	"strings"
	"testing"
)

// #2078: no-syn-check-in-tunnel, rst-invalidate-session and no-sequence-check
// remain accepted-only. #10703 wires no-syn-check and strict-syn-check into
// transit session-miss admission. These tests pin the advisory for the
// unenforced flags and ensure the two live selectors no longer get a stale
// warning.

// findTCPSessionAdvisory returns the single #2078 tcp-session advisory warning,
// or "" if none was emitted. It is keyed on the stable substrings the warning
// is built from, NOT on the per-knob token list (which the per-knob tests below
// assert separately), so the helper stays valid as knobs are added.
func findTCPSessionAdvisory(cfg *Config) string {
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "security flow tcp-session") &&
			strings.Contains(w, "accepted-only") &&
			strings.Contains(w, "#2078") {
			return w
		}
	}
	return ""
}

// Each knob, set in isolation, must produce the advisory AND the advisory must
// name that specific knob (so the warning is not a generic catch-all that would
// pass even if the knob were silently dropped). Driven through the production
// ParseSetCommand + SetPath + CompileConfig path (compileSetLines).
func TestTCPSessionAdvisory_PerKnob(t *testing.T) {
	cases := []struct {
		setLine string
		token   string // the exact knob name that must appear in the advisory
	}{
		{"set security flow tcp-session no-syn-check-in-tunnel", "no-syn-check-in-tunnel"},
		{"set security flow tcp-session rst-invalidate-session", "rst-invalidate-session"},
		{"set security flow tcp-session no-sequence-check", "no-sequence-check"},
	}
	for _, tc := range cases {
		t.Run(tc.token, func(t *testing.T) {
			cfg := compileSetLines(t, []string{tc.setLine})
			adv := findTCPSessionAdvisory(cfg)
			if adv == "" {
				t.Fatalf("%q did not emit the #2078 tcp-session advisory; warnings=%v",
					tc.setLine, cfg.Warnings)
			}
			if !strings.Contains(adv, tc.token) {
				t.Fatalf("advisory does not name knob %q: %q", tc.token, adv)
			}
		})
	}
}

// All three remaining accepted-only flags fold into one advisory.
func TestTCPSessionAdvisory_FoldsRemainingFlags(t *testing.T) {
	cfg := compileSetLines(t, []string{
		"set security flow tcp-session no-syn-check-in-tunnel",
		"set security flow tcp-session rst-invalidate-session",
		"set security flow tcp-session no-sequence-check",
	})

	count := 0
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "security flow tcp-session") &&
			strings.Contains(w, "accepted-only") {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("expected exactly one folded tcp-session advisory, got %d; warnings=%v",
			count, cfg.Warnings)
	}

	adv := findTCPSessionAdvisory(cfg)
	for _, token := range []string{
		"no-syn-check-in-tunnel", "rst-invalidate-session", "no-sequence-check",
	} {
		if !strings.Contains(adv, token) {
			t.Fatalf("folded advisory missing knob %q: %q", token, adv)
		}
	}
}

// #10703: no-syn-check is enforced by the dataplane, so its explicit opt-out
// must not receive the accepted-only warning reserved for inert flags.
func TestTCPNoSynCheckIsNotAdvisedAsInert10703(t *testing.T) {
	cfg := compileSetLines(t, []string{
		"set security flow tcp-session no-syn-check",
	})
	if cfg.Security.Flow.TCPSession == nil || !cfg.Security.Flow.TCPSession.NoSynCheck {
		t.Fatal("no-syn-check did not compile into typed config")
	}
	for _, warning := range cfg.Warnings {
		if strings.Contains(warning, "no-syn-check") && strings.Contains(warning, "accepted-only") {
			t.Fatalf("live no-syn-check selector still receives an inert warning: %q", warning)
		}
	}
}

// A tcp-session stanza with only established-timeout — the one leaf that IS
// wire-carried — and none of the unenforced presence flags must NOT emit this
// advisory: it proves the warning is gated on the actual knobs, not on the
// presence of the tcp-session node. The OTHER three timeout leaves are not
// enforced either and get their own advisory, keyed on #6539 rather than
// #2078; findTCPSessionAdvisory below requires "#2078", so the two families
// cannot satisfy each other's assertions.
func TestTCPSessionAdvisory_TimeoutsOnlyNoWarn(t *testing.T) {
	cfg := compileSetLines(t, []string{
		"set security flow tcp-session established-timeout 600",
	})
	if cfg.Security.Flow.TCPSession == nil {
		t.Fatal("TCPSession is nil; established-timeout did not compile")
	}
	if adv := findTCPSessionAdvisory(cfg); adv != "" {
		t.Fatalf("unexpected tcp-session advisory with only a timeout set: %q", adv)
	}
}

// No tcp-session stanza at all: no advisory, no nil-deref.
func TestTCPSessionAdvisory_AbsentNoWarn(t *testing.T) {
	cfg := compileSetLines(t, []string{
		"set security zones security-zone trust",
	})
	if adv := findTCPSessionAdvisory(cfg); adv != "" {
		t.Fatalf("unexpected tcp-session advisory with no tcp-session stanza: %q", adv)
	}
}
