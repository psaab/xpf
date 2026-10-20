package configstore

import (
	"path/filepath"
	"strings"
	"testing"
)

// #15942 H2-03 (store arm): path-scoped redacted renders redacted the
// whole tree before navigating (forDisplay), so a path naming a masked
// identity token (`snmp community <name>`) matched nothing and rendered
// "". ShowActiveRedacted / ShowRollbackRedactedPath now navigate first
// and mask only the matched subtree.
func TestShowRedactedPathSecretIdentity15942(t *testing.T) {
	s := newTestStoreAt(t, filepath.Join(t.TempDir(), "config"))
	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	for _, line := range []string{
		"snmp community public authorization read-only",
		"system host-name redacted-path-15942",
	} {
		if err := s.SetFromInput(line); err != nil {
			t.Fatalf("SetFromInput(%q): %v", line, err)
		}
	}
	if _, err := s.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	// Second commit so rollback slot 1 exists.
	if _, err := s.Commit(); err != nil {
		t.Fatalf("Commit slot: %v", err)
	}
	s.ExitConfigure()

	path := []string{"snmp", "community", "public"}
	out := s.ShowActiveRedacted(path)
	if out == "" {
		t.Fatalf("ShowActiveRedacted(%v) returned \"\"; the community subtree must render", path)
	}
	if strings.Contains(out, "public") {
		t.Errorf("scoped redacted render leaked the community name:\n%s", out)
	}
	if !strings.Contains(out, "read-only") {
		t.Errorf("scoped redacted render lost the subtree content:\n%s", out)
	}

	rb, err := s.ShowRollbackRedactedPath(1, path)
	if err != nil {
		t.Fatalf("ShowRollbackRedactedPath: %v", err)
	}
	if rb == "" {
		t.Fatalf("ShowRollbackRedactedPath(1, %v) returned \"\"; the community subtree must render", path)
	}
	if strings.Contains(rb, "public") {
		t.Errorf("scoped rollback render leaked the community name:\n%s", rb)
	}
}
