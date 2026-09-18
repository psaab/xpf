package cli

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestCLICommitJournalCarriesKernelIdentity10301(t *testing.T) {
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	c := &CLI{store: store, uid: 4242, username: "opsuser", userClass: "operator"}
	if err := store.SetFromInput("system host-name shell-attributed"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.runCommit("shell commit"); err != nil {
		t.Fatalf("shell commit: %v", err)
	}
	entries, err := store.ListCommitHistory(0)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) == 0 {
		t.Fatal("shell commit produced no history entry")
	}
	want := "source=local-shell;uid=4242;user=opsuser;class=operator;session=none"
	if entries[len(entries)-1].Principal != want {
		t.Fatalf("shell commit principal = %q, want %q", entries[len(entries)-1].Principal, want)
	}

	if err := store.SetFromInput("system host-name shell-confirmed"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.runCommitConfirmed(5); err != nil {
		t.Fatalf("shell commit confirmed: %v", err)
	}
	entries, err = store.ListCommitHistory(0)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) == 0 || entries[len(entries)-1].Principal != want {
		t.Fatalf("shell commit-confirmed principal = %q, want %q", entries[len(entries)-1].Principal, want)
	}
	if strings.Contains(entries[len(entries)-1].Principal, "shell-attributed") {
		t.Fatal("commit description leaked into principal")
	}
	if err := store.ConfirmCommit(); err != nil {
		t.Fatal(err)
	}
}
