package cli

import (
	"io"
	"path/filepath"
	"strings"
	"testing"

	"github.com/chzyer/readline"
	"github.com/psaab/xpf/pkg/configstore"
)

// #14716: dispatchConfig stored the `edit` cursor as raw strings.Fields
// tokens. A decorated cursor — `edit /* interfaces */ "system"`,
// `edit "system"`, or `edit system /*` completed by `set */ ...` — was
// prepended verbatim by the gate (anchored denies missed, comment text
// satisfied allows) while execution re-joined the same raw tokens and
// the store lexer skipped the comment and unquoted the string, so the
// denied subtree was mutated. These cells drive the real dispatcher:
// edit, then a denied set, then assert both the refusal and that the
// candidate carries no trace of the denied mutation.

func cliWithDiscardReadline14716(t *testing.T, store *configstore.Store, class string) *CLI {
	t.Helper()
	rl, err := readline.NewEx(&readline.Config{Stdin: io.NopCloser(strings.NewReader("")), Stdout: io.Discard, Stderr: io.Discard})
	if err != nil {
		t.Fatalf("readline.NewEx: %v", err)
	}
	t.Cleanup(func() { rl.Close() })
	return &CLI{store: store, userClass: class, rl: rl}
}

func decoratedEditStore14716(t *testing.T) *configstore.Store {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if err := store.LoadOverride(`
system {
    host-name decorated-edit-test;
    login {
        class limited {
            permissions all;
            deny-configuration "^system root-authentication";
        }
        class ifaces {
            permissions all;
            allow-configuration "^interfaces";
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

func TestDispatchConfigDecoratedEditPathDenied14716(t *testing.T) {
	cases := []struct {
		name string
		edit string
		set  string
	}{
		{"quote only", `edit "system"`, "set root-authentication plain-text-password hunter2"},
		{"comment plus quote", `edit /* interfaces */ "system"`, "set root-authentication plain-text-password hunter2"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := decoratedEditStore14716(t)
			c := cliWithDiscardReadline14716(t, store, "limited")
			if err := c.dispatchConfig(tc.edit); err != nil {
				t.Fatalf("dispatchConfig(%q): %v", tc.edit, err)
			}
			err := c.dispatchConfig(tc.set)
			if err == nil {
				t.Fatalf("%q + %q was ALLOWED under deny-configuration ^system root-authentication (#14716)", tc.edit, tc.set)
			}
			if !strings.Contains(err.Error(), "denies") {
				t.Fatalf("%q + %q refused for the wrong reason (want a deny-configuration refusal): %v", tc.edit, tc.set, err)
			}
			if out := store.ShowCandidateSet(); strings.Contains(out, "plain-text-password") {
				t.Fatalf("the denied mutation reached the candidate:\n%s", out)
			}
		})
	}

	// Split-comment construction: the unterminated comment is refused at
	// `edit` time, so the cursor that would let `set */ ...` complete it
	// into `system root-authentication` can no longer be minted. Raw
	// cursors minted before the fix are covered at the gate in
	// pkg/config (TestAuthorizeConfigMutationDecoratedEditPath14716).
	t.Run("split comment refused at edit", func(t *testing.T) {
		store := decoratedEditStore14716(t)
		c := cliWithDiscardReadline14716(t, store, "limited")
		if err := c.dispatchConfig(`edit system /*`); err == nil {
			t.Fatal("`edit system /*` was accepted; an unterminated comment must be refused " +
				"so a later `set */ ...` cannot complete it into a denied path (#14716)")
		}
		if got := store.GetEditPath(); len(got) != 0 {
			t.Fatalf("edit path = %v, want empty after a refused edit", got)
		}
	})
}

func TestDispatchConfigDecoratedEditPathAllowNotSatisfiedByComment14716(t *testing.T) {
	store := decoratedEditStore14716(t)
	c := cliWithDiscardReadline14716(t, store, "ifaces")
	if err := c.dispatchConfig(`edit /* interfaces */ "system"`); err != nil {
		t.Fatalf("dispatchConfig(edit): %v", err)
	}
	err := c.dispatchConfig("set root-authentication plain-text-password hunter2")
	if err == nil {
		t.Fatal("comment text satisfied allow-configuration ^interfaces while the store " +
			"executed system root-authentication (#14716)")
	}
	if !strings.Contains(err.Error(), "denies") {
		t.Fatalf("refused for the wrong reason (want an allow/deny refusal): %v", err)
	}
	if out := store.ShowCandidateSet(); strings.Contains(out, "plain-text-password") {
		t.Fatalf("the denied mutation reached the candidate:\n%s", out)
	}

	// Control: a decorated cursor that lexes to interfaces, mutating
	// interfaces, is still permitted for the same class.
	store2 := decoratedEditStore14716(t)
	c2 := cliWithDiscardReadline14716(t, store2, "ifaces")
	if err := c2.dispatchConfig(`edit /* x */ "interfaces"`); err != nil {
		t.Fatalf("dispatchConfig(edit interfaces): %v", err)
	}
	if err := c2.dispatchConfig("set ge-0/0/0 description uplink"); err != nil {
		t.Fatalf("allowed interfaces mutation under decorated cursor was refused: %v", err)
	}
}
