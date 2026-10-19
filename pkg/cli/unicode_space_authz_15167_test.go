package cli

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
)

// #15167 (V47-S1): dispatchConfig gates the raw line with the config lexer
// (checkConfigRegex -> AuthorizeConfigMutation -> lexConfigMutationLine9938)
// but executes set/delete/deactivate/activate from strings.Fields tokens.
//
// The config lexer (pkg/config/lexer.go) only treats ASCII ' '/'\t'/'\n'/'\r'
// as whitespace and stops at a non-ASCII byte with TokenError, so the gate
// lexes only a PREFIX of the line (or, when a non-ASCII space follows the
// verb, sees only the verb and declines to gate). strings.Fields is
// unicode-aware, so the executor sees the full path. A restricted class
// could therefore mutate any path — including `system login class <self>` —
// by spelling the line with a Unicode space (NBSP U+00A0, EM SPACE U+2003,
// VT, FF, ...) after the verb or between path elements.
//
// Fix: the gate fails closed on a lexer error token (shared, in
// AuthorizeConfigMutation), and the local executor derives its path from
// the same config lexer (config.ParseConfigMutationLine) instead of
// strings.Fields, so executor and gate judge and act on identical tokens.
// Legitimate spellings — quoted elements, comments, tabs, and the ASCII
// control `set system services telnet` — are unchanged.

func unicodeSpaceStore15167(t *testing.T) *configstore.Store {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if err := store.LoadOverride(`
system {
    host-name unicode-space-test;
    services {
        ssh;
    }
    login {
        class limited {
            permissions all;
            deny-configuration "system login";
        }
        class telnet-op {
            permissions all;
            allow-configuration "system (services telnet|host-name)";
        }
    }
}
`); err != nil {
		t.Fatalf("LoadOverride: %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	// Commit leaves the store in configure mode with a fresh candidate.
	return store
}

// The probe's NBSP/EM cells (and the VT/FF/other Unicode-space spellings of
// the same mechanism) must be denied for every flat mutation verb, with the
// candidate unchanged. `limited` carries only deny-configuration
// "system login", so a lexer-prefix view (`set` alone, or `set system`
// alone) is ADMITTED by the pre-fix gate while strings.Fields executes the
// full denied path.
func TestDispatchConfigUnicodeSpaceDenied15167(t *testing.T) {
	cases := []struct {
		name string
		line string
	}{
		{"set NBSP after verb", "set\u00a0system login class limited permissions all"},
		{"set NBSP inside path", "set system\u00a0login class limited permissions all"},
		{"set EM SPACE after verb", "set\u2003system login class limited permissions all"},
		{"set EM SPACE inside path", "set system\u2003login class limited permissions all"},
		{"set VT after verb", "set\v system login class limited permissions all"},
		{"set FF after verb", "set\f system login class limited permissions all"},
		{"set NEL inside path", "set system\u0085login class limited permissions all"},
		{"set LINE SEP inside path", "set system\u2028login class limited permissions all"},
		{"delete NBSP after verb", "delete\u00a0system login class limited"},
		{"delete NBSP inside path", "delete system\u00a0login class limited"},
		{"deactivate NBSP after verb", "deactivate\u00a0system login class limited"},
		{"deactivate EM inside path", "deactivate system\u2003login class limited"},
		{"activate NBSP after verb", "activate\u00a0system login class limited"},
		{"activate NBSP inside path", "activate system\u00a0login class limited"},
		// Self-escalation spelling from the report: rewrite own class.
		{"set own class NBSP", "set\u00a0system login class limited permissions all"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := unicodeSpaceStore15167(t)
			c := &CLI{store: store, userClass: "limited"}
			before := store.ShowCandidateSet()
			err := c.dispatchConfig(tc.line)
			if err == nil {
				t.Fatalf("dispatchConfig(%q) was ALLOWED for deny-configuration \"system login\" (#15167); candidate:\n%s", tc.line, store.ShowCandidateSet())
			}
			if !strings.Contains(err.Error(), "denies") && !strings.Contains(err.Error(), "permission denied") {
				t.Fatalf("dispatchConfig(%q) refused for the wrong reason (want a deny-configuration refusal): %v", tc.line, err)
			}
			if after := store.ShowCandidateSet(); after != before {
				t.Fatalf("candidate changed despite refusal for %q:\nbefore:\n%s\nafter:\n%s", tc.line, before, after)
			}
		})
	}
}

// ASCII controls stay green: the same denied path in plain ASCII is denied
// (pre-existing behaviour), and the allowed path from the issue —
// `set system services telnet` — still succeeds for the restricted class.
func TestDispatchConfigUnicodeSpaceControls15167(t *testing.T) {
	t.Run("ascii denied set still denied", func(t *testing.T) {
		store := unicodeSpaceStore15167(t)
		c := &CLI{store: store, userClass: "limited"}
		before := store.ShowCandidateSet()
		if err := c.dispatchConfig("set system login class limited permissions all"); err == nil {
			t.Fatal("plain ASCII denied set was ALLOWED")
		}
		if after := store.ShowCandidateSet(); after != before {
			t.Fatalf("candidate changed on ASCII denied set:\n%s", after)
		}
	})

	t.Run("ascii allowed telnet still allowed", func(t *testing.T) {
		store := unicodeSpaceStore15167(t)
		c := &CLI{store: store, userClass: "telnet-op"}
		if err := c.dispatchConfig("set system services telnet"); err != nil {
			t.Fatalf("`set system services telnet` must stay allowed: %v", err)
		}
		if out := store.ShowCandidateSet(); !strings.Contains(out, "telnet") {
			t.Fatalf("allowed telnet set did not reach candidate:\n%s", out)
		}
	})

	t.Run("ascii allowed host-name still allowed", func(t *testing.T) {
		store := unicodeSpaceStore15167(t)
		c := &CLI{store: store, userClass: "telnet-op"}
		if err := c.dispatchConfig("set system host-name allowed-15167"); err != nil {
			t.Fatalf("allowed host-name set was refused: %v", err)
		}
		if out := store.ShowCandidateSet(); !strings.Contains(out, "allowed-15167") {
			t.Fatalf("allowed host-name set did not reach candidate:\n%s", out)
		}
	})

	// Legitimate lexer spellings the executor already honoured must keep
	// working through the lexer-derived executor: quoted element and tab.
	t.Run("quoted allowed path still allowed", func(t *testing.T) {
		store := unicodeSpaceStore15167(t)
		c := &CLI{store: store, userClass: "telnet-op"}
		if err := c.dispatchConfig(`set system "host-name" quoted-15167`); err != nil {
			t.Fatalf("quoted allowed set was refused: %v", err)
		}
		if out := store.ShowCandidateSet(); !strings.Contains(out, "quoted-15167") {
			t.Fatalf("quoted allowed set did not reach candidate:\n%s", out)
		}
	})

	t.Run("tab separated allowed still allowed", func(t *testing.T) {
		store := unicodeSpaceStore15167(t)
		c := &CLI{store: store, userClass: "telnet-op"}
		if err := c.dispatchConfig("set\tsystem\thost-name\ttab-15167"); err != nil {
			t.Fatalf("tab-separated allowed set was refused: %v", err)
		}
		if out := store.ShowCandidateSet(); !strings.Contains(out, "tab-15167") {
			t.Fatalf("tab-separated set did not reach candidate:\n%s", out)
		}
	})
}
