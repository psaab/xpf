package cli

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
)

// #15082 A53-01: `top delete ...` / `up ... <cmd>` printed [edit],
// returned nil, and executed nothing — the trailing command was
// silently dropped while the cursor moved, so an operator's delete
// of a permit policy stayed in the candidate and committed.
// The prefixed form must execute the command at the target level
// and restore the cursor, or fail loudly.

func cliTopUp15082(t *testing.T, store *configstore.Store) *CLI {
	t.Helper()
	return cliWithDiscardReadline14716(t, store, "")
}

func topUpStore15082(t *testing.T) *configstore.Store {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	for _, line := range []string{
		"security policies from-zone trust to-zone untrust policy allow-all match source-address any",
		"security policies from-zone trust to-zone untrust policy allow-all match destination-address any",
		"security policies from-zone trust to-zone untrust policy allow-all match application any",
		"security policies from-zone trust to-zone untrust policy allow-all then permit",
		"system host-name keep15082",
	} {
		if err := store.SetFromInput(line); err != nil {
			t.Fatalf("SetFromInput(%q): %v", line, err)
		}
	}
	return store
}

func TestTopDeleteExecutesAndRestoresCursor15082(t *testing.T) {
	store := topUpStore15082(t)
	c := cliTopUp15082(t, store)
	// Cursor deep inside the policy being deleted.
	store.SetEditPath([]string{"security", "policies", "from-zone", "trust", "to-zone", "untrust"})
	var err error
	captureStdout(t, func() {
		err = c.dispatchConfig("top delete security policies from-zone trust to-zone untrust policy allow-all")
	})
	if err != nil {
		t.Fatalf("top delete ... = %v, want the delete executed at top (#15082)", err)
	}
	if out := store.ShowCandidateSet(); strings.Contains(out, "allow-all") {
		t.Fatalf("top delete left allow-all in the candidate; the trailing command was dropped (#15082):\n%s", out)
	}
	if got := store.GetEditPath(); len(got) != 6 || got[0] != "security" {
		t.Fatalf("edit path = %v, want the original cursor restored after top <cmd> (#15082)", got)
	}
}

func TestUpDeleteExecutesAndRestoresCursor15082(t *testing.T) {
	// #15237 A53-02: `up` is identity-aware — from inside
	// `policy allow-all` one up lands at the zone pair, so the
	// relative delete names the policy explicitly.
	for _, line := range []string{
		"up delete policy allow-all",
		"up 1 delete policy allow-all",
	} {
		store := topUpStore15082(t)
		c := cliTopUp15082(t, store)
		store.SetEditPath([]string{"security", "policies", "from-zone", "trust", "to-zone", "untrust", "policy", "allow-all"})
		var err error
		captureStdout(t, func() { err = c.dispatchConfig(line) })
		if err != nil {
			t.Fatalf("%q = %v, want the delete executed one level up (#15082)", line, err)
		}
		if out := store.ShowCandidateSet(); strings.Contains(out, "allow-all") {
			t.Fatalf("%q left allow-all in the candidate (#15082):\n%s", line, out)
		}
		if got := store.GetEditPath(); len(got) != 8 {
			t.Fatalf("%q: edit path = %v, want cursor restored (#15082)", line, got)
		}
	}
}

func TestTopUpBareNavigationUnchanged15082(t *testing.T) {
	store := topUpStore15082(t)
	c := cliTopUp15082(t, store)
	store.SetEditPath([]string{"security", "policies"})
	if err := c.dispatchConfig("up"); err != nil {
		t.Fatalf("bare up: %v", err)
	}
	if got := store.GetEditPath(); len(got) != 1 || got[0] != "security" {
		t.Fatalf("bare up: edit path = %v, want [security]", got)
	}
	if err := c.dispatchConfig("top"); err != nil {
		t.Fatalf("bare top: %v", err)
	}
	if got := store.GetEditPath(); len(got) != 0 {
		t.Fatalf("bare top: edit path = %v, want []", got)
	}
	// up with only a count is still navigation.
	store.SetEditPath([]string{"security", "policies", "from-zone"})
	if err := c.dispatchConfig("up 2"); err != nil {
		t.Fatalf("up 2: %v", err)
	}
	if got := store.GetEditPath(); len(got) != 1 || got[0] != "security" {
		t.Fatalf("up 2: edit path = %v, want [security]", got)
	}
	if out := store.ShowCandidateSet(); !strings.Contains(out, "allow-all") {
		t.Fatalf("bare navigation mutated the candidate:\n%s", out)
	}
}

func TestTopUpInvalidTrailingFailsClosed15082(t *testing.T) {
	for _, line := range []string{"top frobnicate x", "up 99 delete system host-name", "up x delete system host-name", "top up delete system host-name"} {
		store := topUpStore15082(t)
		c := cliTopUp15082(t, store)
		store.SetEditPath([]string{"security", "policies"})
		var err error
		captureStdout(t, func() { err = c.dispatchConfig(line) })
		if err == nil {
			t.Fatalf("%q returned nil; a prefixed command that cannot run must fail, never silently succeed (#15082)", line)
		}
		if got := store.GetEditPath(); len(got) != 2 {
			t.Fatalf("%q: edit path = %v, want cursor restored on error (#15082)", line, got)
		}
		if out := store.ShowCandidateSet(); !strings.Contains(out, "allow-all") || !strings.Contains(out, "keep15082") {
			t.Fatalf("%q mutated the candidate despite failing:\n%s", line, out)
		}
	}
}
