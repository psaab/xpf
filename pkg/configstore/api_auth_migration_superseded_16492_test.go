package configstore

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// #16492: a #15273-deferred api-auth migration strands
// .configdb/api-auth-migration.json, so the next plain commit or HA config
// sync makes the following boot fatal (ErrConfigDBUnreadable).
//
// Mechanism on base: boot1 crosses the #10826 migration with legacy
// cleartext api-auth while confirm.json is unreadable, so the durable
// active rewrite is deferred and staging (Old=H1, New=H2) stays on disk.
// A plain Commit (or SyncApply) then writes a new generation H3 and
// rebinds the rollback sidecar to H3, but nothing retires staging. On
// boot2, apiAuthMigrationStagingConsistent sees sidecar H3 matching
// neither staged side and Load returns ErrConfigDBUnreadable — the
// documented remedy (commit, per ConfirmRecoveryReadFailed's contract)
// bricks every later boot until an operator deletes a file no message
// names.
//
// GREEN: a durable promotion whose sidecar binds the new disk generation
// exactly supersedes the staged transition. The promotion retires
// staging in-process; if that retirement is lost (crash / failed delete),
// boot2's Load retires it before the consistency gate. Controls: no
// intervening promotion (staging must survive so the deferred migration
// still completes), and a genuinely unrelated active generation with a
// stale sidecar (must stay fail-closed).

// bootDeferredMigration16492 replays the #16492 precondition and returns
// the store path plus the boot1 store: Load succeeded with the durable
// rewrite deferred, the hashed tree in memory, staging on disk, and the
// unreadable confirm record retained (the /health-503 lost-window state).
func bootDeferredMigration16492(t *testing.T) (string, *Store) {
	t.Helper()
	path, _, _, _ := seedMigrationUnreadableConfirm15273(t, time.Now().Add(10*time.Minute))

	// Persistent corruption (not the transient seam): confirm.json stays
	// unreadable on every later boot, so the deferral would repeat
	// forever and the only exit is a promotion — which is what bricks.
	confirmFile := filepath.Join(filepath.Dir(path), ".configdb", "confirm.json")
	if err := os.WriteFile(confirmFile, []byte("{garbage-not-json"), 0o600); err != nil {
		t.Fatalf("corrupt confirm.json persistently: %v", err)
	}

	s1 := newTestStoreAt(t, path)
	if err := s1.Load(); err != nil {
		t.Fatalf("#16492 boot1 Load: %v", err)
	}
	if !s1.ConfirmRecoveryReadFailed() {
		t.Fatal("#16492 boot1: unreadable confirm must leave the lost-window flag set")
	}
	if _, err := os.Stat(s1.apiAuthMigrationStagingPath()); err != nil {
		t.Fatalf("#16492 boot1: deferred migration must leave staging on disk: %v", err)
	}
	if got, err := s1.db.ReadActive(); err != nil || got == nil ||
		!strings.Contains(got.Format(), "correct-horse-battery") {
		t.Fatalf("#16492 boot1: active.json must keep the pre-migration generation: err=%v", err)
	}
	return path, s1
}

// assertBootsCleanAndHashed16492 loads a fresh store over path and asserts
// the boot is clean, staging is retired, and the durable active generation
// carries only hashed api-auth verifiers (no cleartext on disk).
func assertBootsCleanAndHashed16492(t *testing.T, path, via string) *Store {
	t.Helper()
	s := newTestStoreAt(t, path)
	if err := s.Load(); err != nil {
		t.Fatalf("#16492 %s: boot2 Load must be clean, got: %v", via, err)
	}
	if _, err := os.Stat(s.apiAuthMigrationStagingPath()); !os.IsNotExist(err) {
		t.Fatalf("#16492 %s: staging must be retired after boot2, stat err=%v", via, err)
	}
	persisted, err := s.db.ReadActive()
	if err != nil || persisted == nil {
		t.Fatalf("#16492 %s: read boot2 active: tree=%v err=%v", via, persisted, err)
	}
	text := persisted.Format()
	if strings.Contains(text, "correct-horse-battery") {
		t.Fatalf("#16492 %s: boot2 active.json still carries cleartext api-auth:\n%s", via, text)
	}
	if !strings.Contains(text, "$xpf-bcrypt$") {
		t.Fatalf("#16492 %s: boot2 active.json must carry hashed api-auth verifiers:\n%s", via, text)
	}
	return s
}

// Arm A: deferred boot1 -> plain Commit -> boot2 boots cleanly with
// api-auth hashed on disk. RED on base: boot2 Load returns
// ErrConfigDBUnreadable ("staged api-auth migration does not match
// active rollback generation").
func TestDeferredMigrationThenPlainCommitBootsClean16492(t *testing.T) {
	path, s1 := bootDeferredMigration16492(t)

	// The documented remedy: the operator commits in response to the
	// /health-503 alarm. The commit promotes the in-memory (hashed) tree
	// plus a fresh change to a new durable generation.
	if err := s1.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if err := s1.SetFromInput("interfaces eth2 unit 0 family inet address 10.2.0.1/24"); err != nil {
		t.Fatalf("SetFromInput iface: %v", err)
	}
	if err := s1.SetFromInput("security zones security-zone dmz interfaces eth2.0"); err != nil {
		t.Fatalf("SetFromInput zone: %v", err)
	}
	if _, err := s1.Commit(); err != nil {
		t.Fatalf("#16492 plain Commit after deferred boot: %v", err)
	}
	if _, err := os.Stat(s1.apiAuthMigrationStagingPath()); !os.IsNotExist(err) {
		t.Fatalf("#16492: plain commit must retire superseded staging, stat err=%v", err)
	}

	assertBootsCleanAndHashed16492(t, path, "plain commit")
}

// Arm SyncApply: deferred boot1 (on a secondary) -> HA config sync ->
// boot2 boots cleanly. RED on base with the same fatal Load error.
func TestDeferredMigrationThenSyncApplyBootsClean16492(t *testing.T) {
	path, s1 := bootDeferredMigration16492(t)

	synced := `system {
 host-name synced-secondary-16492;
 services {
  web-management {
   api-auth {
    expires 2099-01-01;
    user admin { password correct-horse-battery; }
    api-key machine-generated-key-alpha;
   }
  }
 }
}`
	if _, err := s1.SyncApply(synced, nil); err != nil {
		t.Fatalf("#16492 SyncApply after deferred boot: %v", err)
	}
	if _, err := os.Stat(s1.apiAuthMigrationStagingPath()); !os.IsNotExist(err) {
		t.Fatalf("#16492: SyncApply must retire superseded staging, stat err=%v", err)
	}

	assertBootsCleanAndHashed16492(t, path, "SyncApply")
}

// Control B: no intervening promotion — boot2 must still defer cleanly
// (staging retained, active.json untouched, no fatal), and boot3 after
// the operator finally commits must converge. This pins that the
// supersession check does not widen to "staging plus any later boot".
func TestDeferredMigrationWithoutPromotionStillDefers16492(t *testing.T) {
	path, _ := bootDeferredMigration16492(t)

	s2 := newTestStoreAt(t, path)
	if err := s2.Load(); err != nil {
		t.Fatalf("#16492 control B: boot2 without promotion must stay a clean deferred boot: %v", err)
	}
	if _, err := os.Stat(s2.apiAuthMigrationStagingPath()); err != nil {
		t.Fatalf("#16492 control B: staging must survive while no promotion superseded it: %v", err)
	}
	if got, err := s2.db.ReadActive(); err != nil || got == nil ||
		!strings.Contains(got.Format(), "correct-horse-battery") {
		t.Fatalf("#16492 control B: active.json must remain pre-migration until a promotion: err=%v", err)
	}
	if !s2.ConfirmRecoveryReadFailed() {
		t.Fatal("#16492 control B: lost-window flag must persist across deferred boots")
	}
}

// Control C: a readable confirm record means no deferral — the ordinary
// migration converges on boot1 and a later commit boots cleanly (the
// #15273 control shape; guards against the retirement hook disturbing
// the non-deferred path).
func TestReadableConfirmMigrationThenCommitBootsClean16492(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config")
	initial := newTestStoreAt(t, path)
	active := parseAuthMigrationTree10826(t, legacyAPIAuthConfig10826)
	previous := parseAuthMigrationTree10826(t, `system {
 services {
  web-management {
   api-auth {
    expires 2099-01-01;
    api-key rollback-key-alpha-123456;
   }
  }
 }
}`)
	if err := initial.db.WriteActive(active); err != nil {
		t.Fatalf("write active: %v", err)
	}
	if err := initial.db.WriteConfirm(&confirmRecord{
		Deadline:    time.Now().Add(10 * time.Minute),
		PrevTree:    previous,
		GuardedHash: guardedConfigHash(active),
	}); err != nil {
		t.Fatalf("write confirm: %v", err)
	}
	s1 := newTestStoreAt(t, path)
	if err := s1.Load(); err != nil {
		t.Fatalf("#16492 control C boot1 Load: %v", err)
	}
	defer s1.CancelConfirmTimerForTesting()
	if _, err := os.Stat(s1.apiAuthMigrationStagingPath()); !os.IsNotExist(err) {
		t.Fatalf("#16492 control C: non-deferred migration must converge staging on boot1, stat err=%v", err)
	}
	if err := s1.ConfirmCommit(); err != nil {
		t.Fatalf("#16492 control C ConfirmCommit: %v", err)
	}
	s2 := assertBootsCleanAndHashed16492(t, path, "control C")
	_ = s2
}

// Negative control: staging plus a genuinely UNRELATED active generation
// whose sidecar still binds the OLD generation (direct disk tamper, no
// Store promotion) must stay fail-closed. Supersession requires the
// sidecar and disk to agree with each other on a non-staged generation;
// tampering only active.json leaves them in disagreement.
func TestUnrelatedActiveWithStaleSidecarStaysFatal16492(t *testing.T) {
	path, s1 := bootDeferredMigration16492(t)

	unrelated := parseAuthMigrationTree10826(t, `system { host-name unrelated-active-16492; }`)
	if err := s1.db.WriteActive(unrelated); err != nil {
		t.Fatalf("tamper active.json directly: %v", err)
	}

	s2 := newTestStoreAt(t, path)
	if err := s2.Load(); !errors.Is(err, ErrConfigDBUnreadable) {
		t.Fatalf("#16492: unrelated active with stale sidecar must stay fatal, got: %v", err)
	} else if !strings.Contains(err.Error(), "api-auth-migration.json") {
		t.Fatalf("#16492: fatal error must name the staging file to repair, got: %v", err)
	}
	if _, err := os.Stat(s2.apiAuthMigrationStagingPath()); err != nil {
		t.Fatalf("#16492: fail-closed boot must preserve staging for repair: %v", err)
	}
}
