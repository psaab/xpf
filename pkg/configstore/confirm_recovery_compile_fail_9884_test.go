package configstore

import (
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// #9884: a Load whose active tree fails to compile skipped pending-confirm
// recovery entirely — recoverPendingConfirmLocked ran only on the success
// path — so the node sat with no compiled policy AND a stranded
// commit-confirmed record (no in-memory timer, record still on disk).

// brokenActiveTree9884 returns a tree that fails even the lenient Load
// compile: `apply-groups badgroup` references an undefined group (same
// trigger as TestLoadCommittedConfigCompileFailureFailsClosed).
func brokenActiveTree9884(t *testing.T) *config.ConfigTree {
	t.Helper()
	const broken = "apply-groups badgroup;\nsystem {\n  host-name box;\n}\n"
	tree, errs := config.NewParser(broken).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse broken config: %v", errs[0])
	}
	if _, err := config.CompileConfigLenient(tree); err == nil {
		t.Fatal("precondition: broken config compiled leniently; it must fail " +
			"to exercise the compile-fail Load path")
	}
	return tree
}

func prevTree9884(t *testing.T) *config.ConfigTree {
	t.Helper()
	const prev = "system {\n  host-name Base;\n}\n"
	tree, errs := config.NewParser(prev).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse prev config: %v", errs[0])
	}
	if _, err := config.CompileConfigLenient(tree); err != nil {
		t.Fatalf("precondition: prev config must compile leniently: %v", err)
	}
	return tree
}

// seedBrokenActiveWithConfirm9884 writes a compile-failing active.json plus a
// confirm.json guarding exactly that tree. GuardedHash is computed over the
// broken tree's canonical text — the binding the arm-time write would have
// produced when the text still compiled (in production the text is unchanged;
// a tightened validator or deleted group rejects it at boot).
func seedBrokenActiveWithConfirm9884(t *testing.T, path string, deadline time.Time) {
	t.Helper()
	s0 := newTestStoreAt(t, path)
	broken := brokenActiveTree9884(t)
	if err := s0.db.WriteActive(broken); err != nil {
		t.Fatalf("WriteActive: %v", err)
	}
	rec := &confirmRecord{
		Deadline:    deadline,
		PrevTree:    prevTree9884(t),
		FirstCommit: false,
		GuardedHash: guardedConfigHash(broken),
	}
	if err := s0.db.WriteConfirm(rec); err != nil {
		t.Fatalf("WriteConfirm: %v", err)
	}
}

// Expired window + compile-failing active tree: Load must still return the
// #1960 ErrConfigCompile fail-closed signal, but the recovery must run —
// roll back to prev (Base), persist it, clear the record.
func TestConfirmRecoveryCompileFailExpiredRollsBack_9884(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config")
	seedBrokenActiveWithConfirm9884(t, path, time.Now().Add(-2*time.Minute))

	s := newTestStoreAt(t, path)
	err := s.Load()
	if err == nil {
		t.Fatal("Load of compile-failing active.json with an expired confirm " +
			"record returned nil; want ErrConfigCompile (fail-closed signal)")
	}
	if !errors.Is(err, ErrConfigCompile) {
		t.Fatalf("Load error = %v; want ErrConfigCompile", err)
	}
	if errors.Is(err, ErrConfigDBUnreadable) {
		t.Fatalf("Load error wrongly tagged ErrConfigDBUnreadable (bytes were "+
			"fine): %v", err)
	}
	got := s.ActiveConfig()
	if got == nil {
		t.Fatal("ActiveConfig is nil after a compile-failing Load with an " +
			"expired window; want the rolled-back prev config (Base)")
	}
	if got.System.HostName != "Base" {
		t.Fatalf("active host-name = %q, want Base (expired window was not "+
			"rolled back — #9884)", got.System.HostName)
	}
	if s.IsConfirmPending() {
		t.Error("an expired window must NOT stay pending after Load")
	}
	if r, rerr := s.db.ReadConfirm(); rerr != nil || r != nil {
		t.Fatalf("confirm.json must be removed after recovery rollback: rec=%v err=%v", r, rerr)
	}
	if !s.EverCommitted() {
		t.Error("EverCommitted() == false after rollback to a committed prev; want true")
	}
	// The rollback healed the disk: a second restart is a clean load of Base.
	s2 := newTestStoreAt(t, path)
	if err := s2.Load(); err != nil {
		t.Fatalf("second Load: %v", err)
	}
	if s2.IsConfirmPending() {
		t.Error("second restart must not resurrect the resolved window")
	}
	got2 := s2.ActiveConfig()
	if got2 == nil {
		t.Fatal("second restart: ActiveConfig is nil; want Base")
	}
	if got2.System.HostName != "Base" {
		t.Fatalf("second restart: active host-name = %q, want Base", got2.System.HostName)
	}
}

// Live window + compile-failing active tree: Load must still return
// ErrConfigCompile with nothing promoted, but the window must be re-armed
// (in-memory timer restored), not stranded on disk with no timer.
//
// The window is PARTIALLY elapsed (2 minutes left of the nominal 10-minute
// window — 8 minutes of simulated downtime): the re-arm must restore the
// ORIGINAL deadline, not a fresh full window, and the re-armed callback must
// roll back to the ORIGINAL target. The fire is driven deterministically
// through the same seams as TestConfirmRecovery_WithinWindowReArmsOnLoad_4577
// (no sleeps; no exactness claimed about the sampled remaining duration).
func TestConfirmRecoveryCompileFailLiveRearms_9884(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config")
	deadline := time.Now().Add(2 * time.Minute)
	seedBrokenActiveWithConfirm9884(t, path, deadline)

	s := newTestStoreAt(t, path)
	err := s.Load()
	if err == nil {
		t.Fatal("Load of compile-failing active.json with a live confirm " +
			"record returned nil; want ErrConfigCompile (fail-closed signal)")
	}
	if !errors.Is(err, ErrConfigCompile) {
		t.Fatalf("Load error = %v; want ErrConfigCompile", err)
	}
	if s.ActiveConfig() != nil {
		t.Fatal("ActiveConfig() != nil after a compile-failing Load; want nil " +
			"(nothing promoted)")
	}
	if !s.EverCommitted() {
		t.Error("EverCommitted() == false after loading a committed DB; want true")
	}
	if !s.IsConfirmPending() {
		t.Fatal("live confirm window was NOT re-armed after a compile-failing " +
			"Load (timer lost, record stranded — #9884)")
	}
	if rec, rerr := s.db.ReadConfirm(); rerr != nil || rec == nil {
		t.Fatalf("confirm.json must be retained while the window is live: rec=%v err=%v", rec, rerr)
	}
	// The ORIGINAL window is restored — same deadline (the remaining ~2
	// minutes, not a fresh full window), same non-first rollback target —
	// not a fresh-full-window timer that merely looks pending.
	target, first, restored, ok := s.RecoveredConfirmWindow()
	if !ok {
		t.Fatal("recovered confirm window not reported after a compile-failing Load")
	}
	if !restored.Equal(deadline) {
		t.Fatalf("restored deadline = %v, want the original %v (a fresh full window "+
			"passes pending but re-arms the wrong duration)", restored, deadline)
	}
	if first {
		t.Error("restored window reports first-commit; want false (prev is the committed Base config)")
	}
	if target == nil {
		t.Fatal("restored rollback target is nil; want the compiled Base config")
	}
	if target.System.HostName != "Base" {
		t.Fatalf("restored rollback target host-name = %q, want Base", target.System.HostName)
	}
	// Stop the REAL timer now that pending-ness is proven: the deterministic
	// fire below invokes the callback directly, so nothing must remain armed
	// past this test.
	s.mu.Lock()
	if s.confirmTimer != nil {
		s.confirmTimer.Stop()
	}
	s.mu.Unlock()
	// Drive the re-armed callback deterministically: it must roll back to
	// the ORIGINAL target (Base) and resolve the window, proving the
	// restored callback is the real rollback and not a no-op.
	s.InvokeRollbackTimerForTesting(s.ConfirmGenForTesting())
	got := s.ActiveConfig()
	if got == nil {
		t.Fatal("ActiveConfig is nil after the re-armed callback fired; want Base")
	}
	if got.System.HostName != "Base" {
		t.Fatalf("re-armed callback rolled back to %q, want Base", got.System.HostName)
	}
	if s.IsConfirmPending() {
		t.Error("after the re-armed callback fires the window must be resolved")
	}
	if r, rerr := s.db.ReadConfirm(); rerr != nil || r != nil {
		t.Fatalf("confirm.json must be removed after the re-armed callback fires: rec=%v err=%v", r, rerr)
	}
}
