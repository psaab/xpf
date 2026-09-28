package configstore

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #8566: a boot `ReadConfirm` failure must not silently discard the pending
// commit-confirmed rollback window.
//
// `recoverPendingConfirmLocked` logged a WARN and returned nil, so `Load`
// reported success and the box came up with no timer, no debt, and
// `ConfigPersistDegraded()` FALSE — /health 200 and
// `xpf_daemon_config_persist_degraded` 0. The still-UNCONFIRMED config was
// standing permanently with no rollback, which is the #4577 failure the record
// exists to prevent, and the only evidence was one log line.
//
// Every other way the store ends a boot unsafe raises degraded health. This one
// did not, so nothing alerted on it — which is why the operator-visible signal
// is part of the defect and not a nicety.
//
// What this change does and does not do:
//   - `Load` still SUCCEEDS. Refusing to boot on an unreadable transient
//     recovery file would turn a corrupt 200-byte file into an outage (#1960).
//   - the record is NOT deleted: a decrypt failure can be a transient
//     master-key problem, and the window may be readable on a later boot.
//   - no bounded retry is added. That is a startup-latency and error-taxonomy
//     change with its own design, deliberately not folded in here.
//
// `..._ClearsOnOperatorAction_8566` is the control that fails on the
// OVER-BROAD fix: a flag that latched forever would satisfy the first cell
// while pinning /health at 503 for the life of the process with no way out.

// armThenCorruptConfirm arms a window and then makes confirm.json unreadable,
// returning the store path and the still-active (unconfirmed) set.
func armThenCorruptConfirm(t *testing.T, withLegacyAPIAuth ...bool) (string, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config")
	s := newTestStoreAt(t, path)
	commitBaseline(t, s)
	stagePendingConfirmed(t, s, "eth1", "untrust")
	if len(withLegacyAPIAuth) > 0 && withLegacyAPIAuth[0] {
		// Add a legacy api-auth subtree directly to the persisted pending tree,
		// then refresh the rollback binding. This models the upgrade input while
		// keeping the fixture's generation-bound history internally consistent.
		active, err := s.db.ReadActive()
		if err != nil || active == nil {
			t.Fatalf("read pending active config: tree=%v err=%v", active, err)
		}
		addLegacyAPIAuthToActive10825(t, active)
		s.active = active
		if err := s.db.WriteActive(active); err != nil {
			t.Fatalf("write legacy pending active config: %v", err)
		}
		s.saveRollbackFiles()
		if s.rollbackPersistDegraded {
			t.Fatal("refresh rollback binding after fixture update")
		}
	}
	unconfirmed := s.ShowActiveSet()

	confirmFile := filepath.Join(filepath.Dir(path), ".configdb", "confirm.json")
	if _, err := os.Stat(confirmFile); err != nil {
		t.Fatalf("PREMISE: the armed record must exist at %s: %v", confirmFile, err)
	}
	if err := os.WriteFile(confirmFile, []byte("{not json"), 0o600); err != nil {
		t.Fatalf("corrupt confirm.json: %v", err)
	}
	return path, unconfirmed
}

func TestBootReadFailureIsReported_8566(t *testing.T) {
	path, unconfirmed := armThenCorruptConfirm(t)

	s2 := newTestStoreAt(t, path)
	if err := s2.Load(); err != nil {
		t.Fatalf("#8566: Load must still SUCCEED — an unreadable transient recovery file "+
			"must not brick the boot (#1960): %v", err)
	}
	// The window really is lost; this is the state being reported, not a
	// recovery. Asserting it keeps the cell honest about what the fix does.
	if s2.IsConfirmPending() {
		t.Fatal("PREMISE: the window cannot be restored from an unreadable record, so no " +
			"timer should be armed — if one is, this cell is measuring something else")
	}
	if got := s2.ShowActiveSet(); got != unconfirmed {
		t.Fatalf("PREMISE: the unconfirmed config is what stands.\nwant %s\ngot  %s", unconfirmed, got)
	}

	if !s2.ConfirmRecoveryReadFailed() {
		t.Fatal("#8566: the lost-window state must be recorded")
	}
	if !s2.ConfigPersistDegraded() {
		t.Fatal("#8566: the box must SAY so. ConfigPersistDegraded() drives /health 503 and " +
			"xpf_daemon_config_persist_degraded; while it reads false an operator whose " +
			"rollback safety net has just vanished sees a healthy firewall.")
	}
}

func TestBootReadFailureWithLegacyAPIAuthIsNonfatal_8566_10826(t *testing.T) {
	path, _ := armThenCorruptConfirm(t, true)
	confirmFile := filepath.Join(filepath.Dir(path), ".configdb", "confirm.json")

	s2 := newTestStoreAt(t, path)
	if err := s2.Load(); err != nil {
		t.Fatalf("#8566: unreadable confirm plus legacy active credentials must not make Load fatal: %v", err)
	}
	if !s2.ConfirmRecoveryReadFailed() || !s2.ConfigPersistDegraded() {
		t.Fatal("#8566: unreadable confirm record must remain a visible degraded boot")
	}
	if s2.IsConfirmPending() {
		t.Fatal("unreadable confirm record must not arm a timer")
	}
	if got, err := os.ReadFile(confirmFile); err != nil || string(got) != "{not json" {
		t.Fatalf("unreadable confirm record = %q, %v; want retained original bytes", got, err)
	}
	persisted, err := s2.db.ReadActive()
	if err != nil {
		t.Fatalf("read migrated active: %v", err)
	}
	formatted := persisted.Format()
	for _, secret := range []string{
		"correct-horse-battery",
		"machine-generated-key-alpha",
		"automation-key-secret-alpha",
	} {
		if strings.Contains(formatted, secret) {
			t.Fatalf("legacy api-auth credential %q remains cleartext after Load", secret)
		}
	}
	apiAuth := s2.ActiveConfig().System.Services.WebManagement.APIAuth
	if apiAuth == nil || len(apiAuth.Users) != 1 || len(apiAuth.APIKeys) != 1 || len(apiAuth.Keys) != 1 ||
		!config.VerifyAPIAuthSecret(apiAuth.Users[0].Password.Reveal(), "correct-horse-battery") ||
		!config.VerifyAPIAuthSecret(apiAuth.APIKeys[0].Reveal(), "machine-generated-key-alpha") ||
		!config.VerifyAPIAuthSecret(apiAuth.Keys[0].Secret.Reveal(), "automation-key-secret-alpha") {
		t.Fatal("legacy active credentials were not migrated to usable verifiers")
	}
}

// TestBootReadFailureClearsOnOperatorAction_8566 is the control that fails on
// the over-broad fix. The state is unhealable in itself — the window is gone —
// so it must clear when the operator arms a new window, or /health is pinned at
// 503 for the life of the process with no remedy.
func TestBootReadFailureClearsOnOperatorAction_8566(t *testing.T) {
	path, _ := armThenCorruptConfirm(t)

	s2 := newTestStoreAt(t, path)
	if err := s2.Load(); err != nil {
		t.Fatalf("boot Load: %v", err)
	}
	if !s2.ConfigPersistDegraded() {
		t.Fatal("PREMISE: the boot must have entered the degraded state this cell clears")
	}

	// The operator arms a fresh window. A readable record exists again.
	if err := s2.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	stagePendingConfirmed(t, s2, "eth2", "guest")
	if s2.ConfirmRecoveryReadFailed() {
		t.Fatal("#8566: arming a fresh window writes a readable record, so the lost-window " +
			"state is over and must clear")
	}
	if s2.ConfigPersistDegraded() {
		t.Fatal("#8566: /health must recover once a readable record exists — a flag that " +
			"latches forever reports the failure and then never stops, which is a different " +
			"defect wearing the same shape")
	}
}

// TestCleanBootIsNotDegraded_8566 is the vacuity control: an ordinary boot with
// a perfectly readable record must NOT report degraded. Without it, a fix that
// set the flag unconditionally would pass both cells above.
func TestCleanBootIsNotDegraded_8566(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config")
	s := newTestStoreAt(t, path)
	commitBaseline(t, s)
	stagePendingConfirmed(t, s, "eth1", "untrust")

	s2 := newTestStoreAt(t, path)
	if err := s2.Load(); err != nil {
		t.Fatalf("boot Load: %v", err)
	}
	if !s2.IsConfirmPending() {
		t.Fatal("PREMISE: a readable record must restore the window, or this control is vacuous")
	}
	if s2.ConfirmRecoveryReadFailed() || s2.ConfigPersistDegraded() {
		t.Fatal("#8566: a clean boot must not report a lost window")
	}
}
