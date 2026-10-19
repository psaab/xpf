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

// #15759: a quoted value with interior (doubled) spaces must survive
// a top/up prefix — the old strings.Join(inner, " ") dispatch split
// it into separate tokens and stored a different value.
func TestTopUpQuotedValueSurvives15759(t *testing.T) {
	store := topUpStore15082(t)
	c := cliTopUp15082(t, store)
	store.SetEditPath([]string{"security", "policies"})
	var err error
	captureStdout(t, func() {
		err = c.dispatchConfig(`top set system host-name "lab router"`)
	})
	if err != nil {
		t.Fatalf("top set quoted host-name = %v (#15759)", err)
	}
	if out := store.ShowCandidateSet(); !strings.Contains(out, "lab router") {
		t.Fatalf("quoted host-name not stored as one value (#15759):\n%s", out)
	}
	if got := store.GetEditPath(); len(got) != 2 {
		t.Fatalf("edit path = %v, want cursor restored (#15759)", got)
	}
	// Doubled interior spaces are the discriminating case: a join
	// round-trip collapses them even when it re-quotes.
	store2 := topUpStore15082(t)
	c2 := cliTopUp15082(t, store2)
	store2.SetEditPath([]string{"interfaces", "ge-0/0/0"})
	captureStdout(t, func() {
		err = c2.dispatchConfig(`up set description "wan  uplink"`)
	})
	if err != nil {
		t.Fatalf("up set quoted description = %v (#15759)", err)
	}
	if out := store2.ShowCandidateSet(); !strings.Contains(out, "wan  uplink") {
		t.Fatalf("doubled-space description mangled by prefix (#15759):\n%s", out)
	}
}

// #15759: `top show | compare` must reach the compare renderer; the
// strict gate lexer stops at the pipe, so the old token re-join
// dispatched a bare `show` (whole candidate, no diff).
func TestTopShowComparePipeSurvives15759(t *testing.T) {
	store := topUpStore15082(t)
	c := cliTopUp15082(t, store)
	store.SetEditPath([]string{"security", "policies"})
	var err error
	out := captureStdout(t, func() {
		err = c.dispatchConfig("top show | compare")
	})
	if err != nil {
		t.Fatalf("top show | compare = %v (#15759)", err)
	}
	if !strings.Contains(out, "keep15082") {
		t.Fatalf("top show | compare diff missing staged change (#15759):\n%s", out)
	}
	if !strings.Contains(out, "[edit") {
		t.Fatalf("top show | compare did not render a diff — pipe lost, bare show ran (#15759):\n%s", out)
	}
	// display set pipe likewise: flat `set ...` lines, no tree braces.
	out = captureStdout(t, func() {
		err = c.dispatchConfig("top show | display set")
	})
	if err != nil {
		t.Fatalf("top show | display set = %v (#15759)", err)
	}
	if !strings.Contains(out, "set system host-name keep15082") {
		t.Fatalf("top show | display set missing flat set line (#15759):\n%s", out)
	}
	if got := store.GetEditPath(); len(got) != 2 {
		t.Fatalf("edit path = %v, want cursor restored (#15759)", got)
	}
}

// #15759: bracket lists under a prefix keep their grouping — the
// store lexer re-reads [ a b ] from the raw tail.
func TestTopBracketListSurvives15759(t *testing.T) {
	store := topUpStore15082(t)
	c := cliTopUp15082(t, store)
	store.SetEditPath([]string{"security", "policies"})
	var err error
	captureStdout(t, func() {
		err = c.dispatchConfig(`top set security zones security-zone trust interfaces [ ge-0/0/0 ge-0/0/1 ]`)
	})
	if err != nil {
		t.Fatalf("top set bracket list = %v (#15759)", err)
	}
	out := store.ShowCandidateSet()
	if !strings.Contains(out, "ge-0/0/0") || !strings.Contains(out, "ge-0/0/1") {
		t.Fatalf("bracket members not stored (#15759):\n%s", out)
	}
}
