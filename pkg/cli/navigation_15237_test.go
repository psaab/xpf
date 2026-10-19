package cli

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
)

// #15237 local surface: exit-as-up, cursor-relative completion, bare
// rename destination, and quoted-whitespace set. FAIL-ON-REVERT:
// restoring unconditional ExitConfigure / root completion /
// cursor-prefixed bare dst / Fields join turns each cell RED.

func navStore15237(t *testing.T) *configstore.Store {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	for _, line := range []string{
		"security zones security-zone trust",
		"security zones security-zone untrust",
		"security policies from-zone trust to-zone untrust policy deny-ssh match source-address any",
		"security policies from-zone trust to-zone untrust policy deny-ssh match destination-address any",
		"security policies from-zone trust to-zone untrust policy deny-ssh match application any",
		"security policies from-zone trust to-zone untrust policy deny-ssh then deny",
		"interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24",
	} {
		if err := store.SetFromInput(line); err != nil {
			t.Fatalf("seed %q: %v", line, err)
		}
	}
	return store
}

func TestLocalExitAtDepthActsAsUp15237(t *testing.T) {
	store := navStore15237(t)
	c := cliWithDiscardReadline14716(t, store, "")
	store.SetEditPath([]string{"security", "policies"})
	var err error
	captureStdout(t, func() { err = c.dispatchConfig("exit") })
	if err != nil {
		t.Fatalf("exit at depth: %v", err)
	}
	if !store.InConfigMode() {
		t.Fatal("exit at depth left configuration mode (#15237 A53-03)")
	}
	if got := store.GetEditPath(); strings.Join(got, " ") != "security" {
		t.Fatalf("edit path after exit = %v, want [security] (#15237 A53-03)", got)
	}
	// Top-level: dirty warning + release via the extracted helper.
	store.SetEditPath(nil)
	out := captureStdout(t, func() { err = c.exitConfigureTop() })
	if err != nil {
		t.Fatalf("exit at top: %v", err)
	}
	if !strings.Contains(out, "warning: uncommitted changes") {
		t.Fatalf("dirty top exit did not warn: %q (#15237 A53-03)", out)
	}
	if store.InConfigMode() {
		t.Fatal("top exit should leave configuration mode")
	}
}

func TestLocalUpPopsZoneIdentity15237(t *testing.T) {
	store := navStore15237(t)
	c := cliWithDiscardReadline14716(t, store, "")
	store.SetEditPath([]string{"security", "zones", "security-zone", "trust"})
	var err error
	captureStdout(t, func() { err = c.dispatchConfig("up") })
	if err != nil {
		t.Fatalf("up: %v", err)
	}
	if got := store.GetEditPath(); strings.Join(got, " ") != "security zones" {
		t.Fatalf("edit path after up = %v, want [security zones] (#15237 A53-02)", got)
	}
}

func TestLocalCompleteUnderSystemOffersHostName15237(t *testing.T) {
	store := navStore15237(t)
	c := cliWithDiscardReadline14716(t, store, "")
	store.SetEditPath([]string{"system"})
	cands := c.completeForHelp([]string{"set"}, "host")
	found := false
	for _, cand := range cands {
		if cand.name == "host-name" {
			found = true
		}
		if cand.name == "interfaces" {
			t.Fatalf("under [edit system], set host offered top-level interfaces (#15237 A53-06): %v", cands)
		}
	}
	if !found {
		t.Fatalf("under [edit system], set host candidates = %v, want host-name (#15237 A53-06)", cands)
	}
}

func TestLocalRenameBareDstInPlace15237(t *testing.T) {
	store := navStore15237(t)
	c := cliWithDiscardReadline14716(t, store, "")
	store.SetEditPath([]string{"security", "policies", "from-zone", "trust", "to-zone", "untrust"})
	var err error
	captureStdout(t, func() {
		err = c.dispatchConfig("rename policy deny-ssh to policy deny-ssh-v2")
	})
	if err != nil {
		t.Fatalf("rename bare dst: %v (#15237 A53-04)", err)
	}
	out := store.ShowCandidateSet()
	if !strings.Contains(out, "policy deny-ssh-v2") {
		t.Fatalf("renamed policy missing:\n%s", out)
	}
	for _, line := range strings.Split(out, "\n") {
		trimmed := strings.TrimSpace(strings.TrimPrefix(line, "set "))
		if strings.HasPrefix(trimmed, "policy deny-ssh-v2") {
			t.Fatalf("rename detached to root: %q (#15237 A53-04)\n%s", line, out)
		}
	}
	if _, err := store.CompileCandidate(); err != nil {
		t.Fatalf("renamed candidate fails compile: %v (#15237 A53-04)", err)
	}
}

func TestLocalSetQuotedWhitespacePreserved15237(t *testing.T) {
	store := navStore15237(t)
	c := cliWithDiscardReadline14716(t, store, "")
	var err error
	captureStdout(t, func() {
		err = c.dispatchConfig(`set system services ssh message "a  b"`)
	})
	if err != nil {
		// message may not be a schema leaf under ssh; fall back to description.
		captureStdout(t, func() {
			err = c.dispatchConfig(`set system description "a  b"`)
		})
	}
	if err != nil {
		t.Fatalf("set quoted value: %v", err)
	}
	out := store.ShowCandidate()
	if !strings.Contains(out, "a  b") {
		t.Fatalf("stored value lost doubled space (#15237 A53-07):\n%s", out)
	}
	if strings.Contains(out, `"a b"`) && !strings.Contains(out, "a  b") {
		t.Fatalf("stored value collapsed: %q", out)
	}
}
