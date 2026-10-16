package cli

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
)

// #14147: the on-box CLI gate lexed the line but dispatchConfig split
// it with strings.Fields before handleCopyRename/handleInsert, so the
// executor acted on endpoints the gate never adjudicated. These cells
// drive dispatchConfig (gate-free userClass, so the EXECUTOR split is
// what is measured) and assert the candidate lands on the lexed
// endpoints.

func splitStore14147(t *testing.T) *configstore.Store {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	for _, line := range []string{
		"set system services ssh",
		"set system services telnet",
		"set system host-name keep",
	} {
		if _, err := store.LoadSet(line); err != nil {
			t.Fatalf("LoadSet(%q): %v", line, err)
		}
	}
	return store
}

func TestCLICopyRenameActsOnLexedEndpoints14147(t *testing.T) {
	// Comment form: Fields would keep /*, to, */ as path tokens and
	// fail (or act on a junk path); the lexer strips them, so the
	// rename acts on ssh -> telnet2.
	store := splitStore14147(t)
	c := &CLI{store: store}
	if err := c.dispatchConfig(`rename system services /* to */ ssh to system services telnet2`); err != nil {
		t.Fatalf("dispatchConfig(comment rename): %v (#14147)", err)
	}
	if out := store.ShowCandidateSet(); !strings.Contains(out, "telnet2") {
		t.Fatalf("comment rename did not land on the lexed destination:\n%s", out)
	}

	// Quoted-"to" form: Fields split at the second bare `to` and
	// renamed ssh -> root-authentication. The lexed source is
	// [system services ssh to foo], which does not exist, so the
	// command must error and mutate nothing.
	store2 := splitStore14147(t)
	c2 := &CLI{store: store2}
	err := c2.dispatchConfig(`rename system services ssh "to" foo to system root-authentication`)
	if err == nil {
		t.Fatal("quoted-to rename acted on the Fields endpoints (ssh -> root-authentication); " +
			"the lexed source does not exist and must error (#14147)")
	}
	out := store2.ShowCandidateSet()
	if !strings.Contains(out, "system services ssh") || strings.Contains(out, "root-authentication") {
		t.Fatalf("quoted-to rename mutated the candidate via the Fields split:\n%s", out)
	}
}

func TestCLIInsertActsOnLexedElement14147(t *testing.T) {
	store := splitStore14147(t)
	c := &CLI{store: store}
	// Plain insert still works through the canonical parser.
	if err := c.dispatchConfig("insert system services ssh before telnet"); err != nil {
		t.Fatalf("dispatchConfig(insert): %v (#14147)", err)
	}
	out := store.ShowCandidateSet()
	sshIdx := strings.Index(out, "system services ssh")
	telnetIdx := strings.Index(out, "system services telnet")
	if sshIdx < 0 || telnetIdx < 0 || sshIdx > telnetIdx {
		t.Fatalf("insert did not order ssh before telnet:\n%s", out)
	}
}
