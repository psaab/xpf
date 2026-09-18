package configstore

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestCommitJournalPrincipalEndToEnd10301 proves the already-authorized
// transport principal survives the handler/authority/store boundary and lands
// in the durable journal entry. The raw session token must not be persisted.
func TestCommitJournalPrincipalEndToEnd10301(t *testing.T) {
	const (
		session = "rest-config-0123456789abcdef0123456789abcdef"
		user    = "ops"
		class   = "super-user"
	)
	s := newTestStore(t)
	if err := s.EnterConfigureSession(session); err != nil {
		t.Fatal(err)
	}
	if err := s.SetFromInputAs(session, "system host-name attributed"); err != nil {
		t.Fatal(err)
	}
	_, gen, err := s.CompileCandidateGen()
	if err != nil {
		t.Fatal(err)
	}
	principal := FormatJournalPrincipal("peer-uid", 1001, user, class, session)
	authority, err := s.AuthorizeCommitAs(session, principal)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CommitWithDescriptionGenAs(authority, "attributed commit", gen); err != nil {
		t.Fatal(err)
	}

	entries, err := s.journal.Tail(0)
	if err != nil {
		t.Fatal(err)
	}
	var got *JournalEntry
	for _, entry := range entries {
		if entry.Action == "commit" {
			got = entry
		}
	}
	if got == nil {
		t.Fatalf("journal has no commit entry: %+v", entries)
	}
	if got.Principal != principal {
		t.Fatalf("commit principal = %q, want %q", got.Principal, principal)
	}
	if strings.Contains(got.Principal, session) {
		t.Fatalf("commit principal leaked raw session token: %q", got.Principal)
	}
	raw, err := os.ReadFile(filepath.Join(filepath.Dir(s.filePath), ".config.journal"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), session) {
		t.Fatalf("raw journal leaked session token %q: %s", session, raw)
	}
}

// TestDirectCommitJournalPrincipalIsExplicitUnknown10301 pins the honest
// fallback for callers that do not have a transport principal. It must not
// guess from the config-lock holder or process identity.
func TestDirectCommitJournalPrincipalIsExplicitUnknown10301(t *testing.T) {
	s := newTestStore(t)
	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	if err := s.SetFromInput("system host-name direct"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CommitWithDescription("direct caller"); err != nil {
		t.Fatal(err)
	}
	entries, err := s.journal.Tail(0)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) == 0 || entries[len(entries)-1].Principal != UnknownPrincipal {
		t.Fatalf("direct commit principal = %+v, want explicit %q", entries, UnknownPrincipal)
	}
}

// TestSystemJournalPrincipals10301 pins known autonomous sources and the
// explicit unknown wrapper used by direct legacy callers.
func TestSystemJournalPrincipals10301(t *testing.T) {
	s := newTestStore(t)
	s.LogSystemAction("reboot")
	s.LogSystemActionAs("halt", "source=peer-uid;user=ops;class=super-user;session=none")
	entries, err := s.journal.Tail(0)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("journal entries = %d, want 2", len(entries))
	}
	if entries[0].Principal != UnknownPrincipal {
		t.Errorf("direct system action principal = %q, want %q", entries[0].Principal, UnknownPrincipal)
	}
	if entries[1].Principal == UnknownPrincipal {
		t.Errorf("explicit system action principal was discarded: %q", entries[1].Principal)
	}
}
