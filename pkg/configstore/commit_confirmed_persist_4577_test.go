package configstore

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// #4577: the commit-confirmed rollback deadline used to be an IN-MEMORY
// time.AfterFunc only — no confirm.json was persisted and Store.Load never
// re-armed it. A daemon crash/reboot INSIDE the confirm window therefore made
// the UNCONFIRMED config permanent, silently losing the auto-rollback safety
// hatch (the operator commits a management-stranding config relying on
// commit-confirmed to auto-revert, the daemon crashes, the box is stranded).
//
// These tests simulate a crash+restart by arming a commit-confirmed on one
// Store, then constructing a FRESH Store over the SAME .configdb and calling
// Load (the daemon boot path). The confirm state must survive.

// armed builds a Store at path, commits Base, then commit-confirmed Confirmed,
// leaving a pending window. Returns the store (its in-memory timer keeps
// running with `minutes`; harmless for the test).
func armedConfirmStore(t *testing.T, path string, minutes int) *Store {
	t.Helper()
	s := newTestStoreAt(t, path)
	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	if err := s.SetFromInput("system host-name Base"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := s.SetFromInput("system host-name Confirmed"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CommitConfirmed(minutes); err != nil {
		t.Fatalf("CommitConfirmed: %v", err)
	}
	if !s.IsConfirmPending() {
		t.Fatal("should have a pending confirm after CommitConfirmed")
	}
	// The confirm.json must exist after arming.
	if rec, err := s.db.ReadConfirm(); err != nil || rec == nil {
		t.Fatalf("CommitConfirmed must persist confirm.json: rec=%v err=%v", rec, err)
	}
	return s
}

// RED-on-revert (a): the confirm window expired during downtime. A fresh
// Store.Load MUST roll back to the pre-confirm config (Base) — the unconfirmed
// config (Confirmed) is NOT permanent. Before the fix Load ignored the
// (nonexistent) persisted state and left Confirmed active forever.
func TestConfirmRecovery_ExpiredRollsBackOnLoad_4577(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config")
	_ = armedConfirmStore(t, path, 10)

	// Force the persisted deadline into the past (simulate a downtime longer
	// than the window — the minutes granularity of the public API cannot go
	// sub-minute). In-package access to the DB is deliberate.
	s0 := newTestStoreAt(t, path)
	rec, err := s0.db.ReadConfirm()
	if err != nil || rec == nil {
		t.Fatalf("ReadConfirm: rec=%v err=%v", rec, err)
	}
	rec.Deadline = time.Now().Add(-2 * time.Minute)
	if err := s0.db.WriteConfirm(rec); err != nil {
		t.Fatalf("WriteConfirm (past deadline): %v", err)
	}

	// Crash+restart: a brand-new Store over the same .configdb.
	s := newTestStoreAt(t, path)
	if err := s.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}

	if s.IsConfirmPending() {
		t.Error("an expired confirm window must NOT stay pending after Load")
	}
	got := s.ActiveConfig()
	if got == nil {
		t.Fatal("ActiveConfig is nil after recovery rollback")
	}
	if got.System.HostName != "Base" {
		t.Fatalf("expired confirm window: active host-name = %q, want Base "+
			"(the unconfirmed config was NOT rolled back — #4577 regression)",
			got.System.HostName)
	}
	// The persisted state must be cleared once resolved.
	if r, err := s.db.ReadConfirm(); err != nil || r != nil {
		t.Fatalf("confirm.json must be removed after recovery rollback: rec=%v err=%v", r, err)
	}
	// A second restart must be a clean, non-pending load of the rolled-back
	// config (idempotent recovery).
	s2 := newTestStoreAt(t, path)
	if err := s2.Load(); err != nil {
		t.Fatalf("second Load: %v", err)
	}
	if s2.IsConfirmPending() {
		t.Error("second restart must not resurrect the resolved window")
	}
	if s2.ActiveConfig().System.HostName != "Base" {
		t.Fatalf("second restart: active host-name = %q, want Base", s2.ActiveConfig().System.HostName)
	}
}

// RED-on-revert (b): still within the window. A fresh Store.Load MUST re-arm
// the timer (a pending confirm is still tracked) and keep the unconfirmed
// config active until the re-armed timer fires — at which point it rolls back
// to the ORIGINAL pre-confirm target (Base).
func TestConfirmRecovery_WithinWindowReArmsOnLoad_4577(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config")
	_ = armedConfirmStore(t, path, 10) // 10-minute window, still open

	s := newTestStoreAt(t, path)
	if err := s.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}

	if !s.IsConfirmPending() {
		t.Fatal("a still-open confirm window must be re-armed (pending) after Load — #4577")
	}
	if got := s.ActiveConfig().System.HostName; got != "Confirmed" {
		t.Fatalf("within window: active host-name = %q, want Confirmed "+
			"(the unconfirmed config must stay active until the re-armed timer fires)", got)
	}
	// confirm.json is left in place while the window is open.
	if r, err := s.db.ReadConfirm(); err != nil || r == nil {
		t.Fatalf("confirm.json must remain while the window is open: rec=%v err=%v", r, err)
	}

	// Drive the re-armed timer deterministically: it must roll back to the
	// ORIGINAL rollback target (Base), proving the persisted target was
	// restored correctly.
	gen := s.ConfirmGenForTesting()
	s.InvokeRollbackTimerForTesting(gen)

	if got := s.ActiveConfig().System.HostName; got != "Base" {
		t.Fatalf("re-armed confirm timer rolled back to %q, want Base "+
			"(recovered rollback target wrong — #4577)", got)
	}
	if s.IsConfirmPending() {
		t.Error("after the re-armed timer fires the window must be resolved")
	}
	if r, err := s.db.ReadConfirm(); err != nil || r != nil {
		t.Fatalf("confirm.json must be removed after the re-armed timer fires: rec=%v err=%v", r, err)
	}
}

// When chrony reports an active clock-skew alarm, recovery must roll back
// instead of trusting that shifted deadline and re-arming it (#10875).
func TestConfirmRecovery_ClockSkewAlarmRollsBackAfterWallStep_10875(t *testing.T) {
	originalNow, originalBootID := confirmWallNow, confirmBootID
	if systemBootID := originalBootID(); systemBootID == "" {
		t.Fatal("the kernel boot-id source did not yield an identifier")
	}
	armWall := time.Date(2030, 4, 5, 6, 7, 8, 0, time.UTC)
	now := armWall
	bootID := "boot-before"
	confirmWallNow = func() time.Time { return now }
	confirmBootID = func() string { return bootID }
	t.Cleanup(func() {
		confirmWallNow = originalNow
		confirmBootID = originalBootID
	})

	for _, alarmActive := range []bool{true, false} {
		name := "alarm-clear"
		if alarmActive {
			name = "alarm-active"
		}
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config")
			now = armWall
			bootID = "boot-before"
			armed := armedConfirmStore(t, path, 10)
			t.Cleanup(func() {
				if armed.confirmTimer != nil {
					armed.confirmTimer.Stop()
				}
			})

			rec, err := armed.db.ReadConfirm()
			if err != nil || rec == nil {
				t.Fatalf("ReadConfirm: rec=%v err=%v", rec, err)
			}
			if !rec.ArmedAt.Equal(armWall) || rec.ArmedBootID != "boot-before" {
				t.Fatalf("arm anchor = (%v, %q), want (%v, boot-before)",
					rec.ArmedAt, rec.ArmedBootID, armWall)
			}

			// Model downtime while keeping the clock after the arm time. A
			// backward step before ArmedAt is covered separately below.
			now = armWall.Add(time.Minute)
			bootID = "boot-after"
			recovered := newTestStoreAt(t, path)
			recovered.SetConfirmRecoveryClockSkewCheck(func(*config.Config) bool {
				return alarmActive
			})
			if err := recovered.Load(); err != nil {
				t.Fatalf("Load: %v", err)
			}

			if alarmActive {
				if recovered.IsConfirmPending() {
					t.Fatal("active clock-skew alarm must not re-arm the shifted confirm deadline")
				}
				if got := recovered.ActiveConfig().System.HostName; got != "Base" {
					t.Fatalf("active config after skew recovery = %q, want rollback target Base", got)
				}
				if r, err := recovered.db.ReadConfirm(); err != nil || r != nil {
					t.Fatalf("confirm.json must be removed after alarm rollback: rec=%v err=%v", r, err)
				}
				return
			}

			if !recovered.IsConfirmPending() {
				t.Fatal("without a clock-skew alarm, a future deadline must still re-arm")
			}
			if got := recovered.ActiveConfig().System.HostName; got != "Confirmed" {
				t.Fatalf("active config without alarm = %q, want Confirmed", got)
			}
			if r, err := recovered.db.ReadConfirm(); err != nil || r == nil {
				t.Fatalf("confirm.json must remain while the window is re-armed: rec=%v err=%v", r, err)
			}
			if recovered.confirmTimer != nil {
				recovered.confirmTimer.Stop()
			}
		})
	}
}

// A standalone node has no cluster clock-skew alarm, so recovery must use
// the persisted arm time as conclusive evidence of a backward wall-clock step.
// Since elapsed downtime cannot be reconstructed, fail closed by rolling back
// rather than re-arming a timer beyond the original confirm window (#12167).
func TestConfirmRecovery_BackwardWallClockRollsBackStandalone_12167(t *testing.T) {
	originalNow, originalBootID := confirmWallNow, confirmBootID
	armWall := time.Date(2030, 4, 5, 6, 7, 8, 0, time.UTC)
	now := armWall
	bootID := "boot-before"
	confirmWallNow = func() time.Time { return now }
	confirmBootID = func() string { return bootID }
	t.Cleanup(func() {
		confirmWallNow = originalNow
		confirmBootID = originalBootID
	})

	path := filepath.Join(t.TempDir(), "config")
	armed := armedConfirmStore(t, path, 10)
	t.Cleanup(func() { armed.CancelConfirmTimerForTesting() })
	rec, err := armed.db.ReadConfirm()
	if err != nil || rec == nil {
		t.Fatalf("ReadConfirm: rec=%v err=%v", rec, err)
	}
	if !rec.ArmedAt.Equal(armWall) || !rec.Deadline.Equal(armWall.Add(10*time.Minute)) {
		t.Fatalf("persisted arm=(%v, %v), want (%v, %v)",
			rec.ArmedAt, rec.Deadline, armWall, armWall.Add(10*time.Minute))
	}

	// Reboot 30 days behind the arm time while the original deadline remains
	// apparently 30 days away. The daemon's standalone alarm callback is clear.
	now = armWall.Add(-30 * 24 * time.Hour)
	bootID = "boot-after"
	recovered := newTestStoreAt(t, path)
	recovered.SetConfirmRecoveryClockSkewCheck(func(*config.Config) bool { return false })
	if err := recovered.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	t.Cleanup(func() { recovered.CancelConfirmTimerForTesting() })

	if recovered.IsConfirmPending() {
		t.Fatal("backward wall clock with no trustworthy elapsed downtime must roll back, not re-arm")
	}
	if got := recovered.ActiveConfig().System.HostName; got != "Base" {
		t.Fatalf("active config after backward-clock recovery = %q, want rollback target Base", got)
	}
	if r, err := recovered.db.ReadConfirm(); err != nil || r != nil {
		t.Fatalf("confirm.json must be removed after backward-clock rollback: rec=%v err=%v", r, err)
	}
}

// A backward-clock rollback of a first commit must retain #12155's durable
// daemon teardown debt while applying the same fail-closed clock policy.
func TestConfirmRecovery_BackwardFirstCommitKeepsTeardownDebt_12167(t *testing.T) {
	originalNow, originalBootID := confirmWallNow, confirmBootID
	armWall := time.Date(2030, 4, 5, 6, 7, 8, 0, time.UTC)
	now := armWall
	bootID := "boot-before"
	confirmWallNow = func() time.Time { return now }
	confirmBootID = func() string { return bootID }
	t.Cleanup(func() {
		confirmWallNow = originalNow
		confirmBootID = originalBootID
	})

	path := filepath.Join(t.TempDir(), "config")
	armed := newTestStoreAt(t, path)
	if err := armed.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if err := armed.SetFromInput("system host-name FirstWindow"); err != nil {
		t.Fatalf("SetFromInput: %v", err)
	}
	if _, err := armed.CommitConfirmed(10); err != nil {
		t.Fatalf("CommitConfirmed: %v", err)
	}
	armed.ExitConfigure()
	t.Cleanup(func() { armed.CancelConfirmTimerForTesting() })

	rec, err := armed.db.ReadConfirm()
	if err != nil || rec == nil || !rec.FirstCommit {
		t.Fatalf("first commit record = %+v, err=%v; want FirstCommit=true", rec, err)
	}
	now = armWall.Add(-30 * 24 * time.Hour)
	bootID = "boot-after"
	recovered := newTestStoreAt(t, path)
	recovered.SetConfirmRecoveryClockSkewCheck(func(*config.Config) bool { return false })
	if err := recovered.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}

	if !recovered.FirstCommitTeardownOwed() {
		t.Fatal("backward-clock first-commit rollback lost #12155 teardown debt")
	}
	if _, committed, err := recovered.db.ReadActiveMeta(); err != nil || committed {
		t.Fatalf("rollback active marker committed=%v err=%v; want committed=false", committed, err)
	}
	configDB := filepath.Join(filepath.Dir(path), ".configdb")
	markerPath := firstCommitTeardownMarkerPath(configDB)
	if _, err := os.Stat(markerPath); err != nil {
		t.Fatalf("durable #12155 teardown marker missing: %v", err)
	}
	if _, err := os.Stat(filepath.Join(configDB, "confirm.json")); !os.IsNotExist(err) {
		t.Fatalf("confirm.json remains after durable teardown marker publication: %v", err)
	}
}

// The recovered timer is bounded by the persisted original window. A legacy
// record without an arm timestamp is still capped by the maximum accepted API
// window rather than by an arbitrarily distant wall-clock deadline.
func TestRecoveredConfirmDelayBounded_12167(t *testing.T) {
	arm := time.Date(2030, 4, 5, 6, 7, 8, 0, time.UTC)
	window := 10 * time.Minute
	maxWindow := time.Duration(MaxCommitConfirmedMinutes) * time.Minute

	tests := []struct {
		name     string
		deadline time.Time
		now      time.Time
		armedAt  time.Time
		want     time.Duration
	}{
		{
			name:     "persisted original window",
			deadline: arm.Add(window),
			now:      arm.Add(-30 * 24 * time.Hour),
			armedAt:  arm,
			want:     window,
		},
		{
			name:     "legacy record without arm timestamp",
			deadline: arm.Add(maxWindow + time.Minute),
			now:      arm,
			want:     maxWindow,
		},
		{
			name:     "normal remaining time",
			deadline: arm.Add(window),
			now:      arm.Add(time.Minute),
			armedAt:  arm,
			want:     window - time.Minute,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := recoveredConfirmDelay(tt.deadline, tt.now, tt.armedAt); got != tt.want {
				t.Fatalf("recoveredConfirmDelay() = %v, want %v", got, tt.want)
			}
		})
	}
}

// A normal confirm-within-window (explicit ConfirmCommit) must make the config
// permanent: confirm.json is removed, and a subsequent restart loads the
// confirmed config with NO pending window and NO rollback.
func TestConfirmRecovery_ExplicitConfirmIsPermanent_4577(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config")
	s0 := armedConfirmStore(t, path, 10)
	if err := s0.ConfirmCommit(); err != nil {
		t.Fatalf("ConfirmCommit: %v", err)
	}
	if r, err := s0.db.ReadConfirm(); err != nil || r != nil {
		t.Fatalf("ConfirmCommit must remove confirm.json: rec=%v err=%v", r, err)
	}

	s := newTestStoreAt(t, path)
	if err := s.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if s.IsConfirmPending() {
		t.Error("a confirmed config must NOT be pending after restart")
	}
	if got := s.ActiveConfig().System.HostName; got != "Confirmed" {
		t.Fatalf("confirmed config after restart: active host-name = %q, want Confirmed", got)
	}
}

// A bare `commit` during the window confirms the pending config (Junos
// semantics). confirm.json is removed and a restart must NOT roll back — the
// bare-commit config is permanent.
func TestConfirmRecovery_BareCommitConfirms_4577(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config")
	s0 := armedConfirmStore(t, path, 10)

	// Background/eventengine PLAIN commit during the window (reaches
	// CommitWithDescription directly, which calls clearPendingConfirmLocked).
	if err := s0.SetFromInput("system host-name Remediated"); err != nil {
		t.Fatal(err)
	}
	if _, err := s0.Commit(); err != nil {
		t.Fatalf("plain Commit during confirm window: %v", err)
	}
	if s0.IsConfirmPending() {
		t.Error("a plain commit must confirm (clear) the pending window")
	}
	if r, err := s0.db.ReadConfirm(); err != nil || r != nil {
		t.Fatalf("a plain commit must remove confirm.json: rec=%v err=%v", r, err)
	}

	s := newTestStoreAt(t, path)
	if err := s.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if s.IsConfirmPending() {
		t.Error("no pending window must survive a bare-commit confirmation")
	}
	if got := s.ActiveConfig().System.HostName; got != "Remediated" {
		t.Fatalf("bare-commit-confirmed config after restart: active host-name = %q, "+
			"want Remediated (the confirmed config must be permanent — not rolled back)", got)
	}
}
