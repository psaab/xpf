package configstore

import (
	"path/filepath"
	"strings"
	"testing"
)

// #15657 V45-03: operational rollback compare diffs against ACTIVE.
//
// Fixture: commit host-a (active=A, history empty), commit host-b
// (active=B, history[1]=A). Then stage a dirty candidate host-c and
// ExitConfigure is NOT called yet — the candidate-vs-active answers
// differ observably, which is what makes the baseline distinguishable.

func newRollbackCompareStore15657(t *testing.T) *Store {
	t.Helper()
	s := newTestStoreAt(t, filepath.Join(t.TempDir(), "config"))
	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if err := s.SetFromInput("system host-name host-a-15657"); err != nil {
		t.Fatalf("Set host-a: %v", err)
	}
	if _, err := s.Commit(); err != nil {
		t.Fatalf("Commit A: %v", err)
	}
	if err := s.SetFromInput("system host-name host-b-15657"); err != nil {
		t.Fatalf("Set host-b: %v", err)
	}
	if _, err := s.Commit(); err != nil {
		t.Fatalf("Commit B: %v", err)
	}
	return s
}

func TestShowCompareRollbackActiveBaseline15657(t *testing.T) {
	s := newRollbackCompareStore15657(t)
	// Dirty candidate from "another session": host-c, never committed.
	if err := s.SetFromInput("system host-name host-c-15657"); err != nil {
		t.Fatalf("Set host-c: %v", err)
	}

	// Active baseline: rollback1(A) vs active(B) — mentions A and B,
	// never the dirty candidate C.
	diff, err := s.ShowCompareRollbackActive(1)
	if err != nil {
		t.Fatalf("ShowCompareRollbackActive(1) with dirty candidate: %v", err)
	}
	if !strings.Contains(diff, "host-a-15657") || !strings.Contains(diff, "host-b-15657") {
		t.Errorf("active-baseline diff should mention host-a and host-b:\n%s", diff)
	}
	if strings.Contains(diff, "host-c-15657") {
		t.Errorf("active-baseline diff leaked the dirty candidate:\n%s", diff)
	}

	// Candidate baseline (config-mode surface) still diffs vs C.
	cdiff, err := s.ShowCompareRollback(1)
	if err != nil {
		t.Fatalf("ShowCompareRollback(1): %v", err)
	}
	if !strings.Contains(cdiff, "host-c-15657") {
		t.Errorf("candidate-baseline diff should mention host-c:\n%s", cdiff)
	}

	// After ExitConfigure there is no candidate at all: the active
	// baseline still works, the candidate baseline refuses.
	s.ExitConfigure()
	diff, err = s.ShowCompareRollbackActive(1)
	if err != nil {
		t.Fatalf("ShowCompareRollbackActive(1) outside config mode: %v", err)
	}
	if !strings.Contains(diff, "host-a-15657") {
		t.Errorf("operational diff outside config mode lost rollback content:\n%s", diff)
	}
	if _, err := s.ShowCompareRollback(1); err == nil {
		t.Error("candidate-baseline compare outside config mode must still refuse")
	}

	// Redacted twin behaves identically outside config mode.
	rdiff, err := s.ShowCompareRollbackActiveRedacted(1)
	if err != nil {
		t.Fatalf("ShowCompareRollbackActiveRedacted(1): %v", err)
	}
	if !strings.Contains(rdiff, "host-a-15657") {
		t.Errorf("redacted operational diff lost rollback content:\n%s", rdiff)
	}
}

func TestRollbackZeroIsActive15657(t *testing.T) {
	s := newRollbackCompareStore15657(t)

	// Show rollback 0 renders the active config (host-b), not an error.
	out, err := s.ShowRollback(0)
	if err != nil {
		t.Fatalf("ShowRollback(0): %v", err)
	}
	if !strings.Contains(out, "host-b-15657") {
		t.Errorf("ShowRollback(0) should render active (host-b):\n%s", out)
	}
	if out, err := s.ShowRollbackRedacted(0); err != nil || !strings.Contains(out, "host-b-15657") {
		t.Errorf("ShowRollbackRedacted(0) = %q, %v; want active render", out, err)
	}

	// Operational compare 0: active vs active — no changes, and it
	// works outside configuration mode.
	s.ExitConfigure()
	if diff, err := s.ShowCompareRollbackActive(0); err != nil || diff != "[no changes]\n" {
		t.Errorf("ShowCompareRollbackActive(0) = %q, %v; want [no changes]", diff, err)
	}
	if diff, err := s.ShowCompareRollbackActiveRedacted(0); err != nil || diff != "[no changes]\n" {
		t.Errorf("ShowCompareRollbackActiveRedacted(0) = %q, %v; want [no changes]", diff, err)
	}

	// Config-mode compare rollback 0 == candidate-vs-active: with a
	// dirty candidate it shows the staged change.
	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if err := s.SetFromInput("system host-name host-c-15657"); err != nil {
		t.Fatalf("Set host-c: %v", err)
	}
	diff, err := s.ShowCompareRollback(0)
	if err != nil {
		t.Fatalf("ShowCompareRollback(0): %v", err)
	}
	if !strings.Contains(diff, "host-c-15657") {
		t.Errorf("compare rollback 0 should diff candidate vs active (host-c):\n%s", diff)
	}
	if diff, err := s.ShowCompareRollbackRedacted(0); err != nil || !strings.Contains(diff, "host-c-15657") {
		t.Errorf("ShowCompareRollbackRedacted(0) = %q, %v; want candidate diff", diff, err)
	}

	// Negative still fails through the history bounds.
	if _, err := s.ShowRollback(-1); err == nil {
		t.Error("ShowRollback(-1) must fail")
	}
}

func TestShowRollbackFormatsAndPath15657(t *testing.T) {
	s := newRollbackCompareStore15657(t)

	// Slot 1 is host-a; every format renders it, scoped by path.
	if out, err := s.ShowRollbackSet(1); err != nil || !strings.Contains(out, "set system host-name host-a-15657") {
		t.Errorf("ShowRollbackSet(1) = %q, %v", out, err)
	}
	if out, err := s.ShowRollbackJSON(1); err != nil || !strings.Contains(out, "host-a-15657") || !strings.Contains(out, "{") {
		t.Errorf("ShowRollbackJSON(1) = %q, %v", out, err)
	}
	if out, err := s.ShowRollbackXML(1); err != nil || !strings.Contains(out, "<configuration") || !strings.Contains(out, "host-a-15657") {
		t.Errorf("ShowRollbackXML(1) = %q, %v", out, err)
	}
	if out, err := s.ShowRollbackInheritance(1); err != nil || !strings.Contains(out, "host-a-15657") {
		t.Errorf("ShowRollbackInheritance(1) = %q, %v", out, err)
	}
	if out, err := s.ShowRollbackJSONRedactedPath(1, []string{"system"}); err != nil || !strings.Contains(out, "host-a-15657") {
		t.Errorf("ShowRollbackJSONRedactedPath(1, system) = %q, %v", out, err)
	}
	// Path scoping actually scopes: the system subtree has no security.
	if out, err := s.ShowRollbackPath(1, []string{"security"}); err != nil || strings.Contains(out, "host-name") {
		t.Errorf("ShowRollbackPath(1, security) = %q, %v; want no host-name", out, err)
	}
	// Rollback 0 in JSON is the active config.
	if out, err := s.ShowRollbackJSON(0); err != nil || !strings.Contains(out, "host-b-15657") {
		t.Errorf("ShowRollbackJSON(0) = %q, %v; want active host-b", out, err)
	}
}
