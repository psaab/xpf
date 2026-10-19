package configstore

import (
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// seedMigrationUnreadableConfirm15273 arms a commit-confirmed window whose
// active tree ALSO carries legacy plaintext api-auth (the pre-#10826 shape),
// then adds the legacy api-auth subtree to the persisted active tree exactly
// like armThenCorruptConfirm(t, true) does. It rewrites the confirm record
// with the caller's deadline so the live and expired cells share one seed.
// Returns the store path, the unconfirmed active set text, the PrevTree
// api-key, and the exact confirm.json bytes.
func seedMigrationUnreadableConfirm15273(t *testing.T, deadline time.Time) (string, string, string, []byte) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config")
	s := newTestStoreAt(t, path)
	commitBaseline(t, s)
	stagePendingConfirmed(t, s, "eth1", "untrust")
	active, err := s.db.ReadActive()
	if err != nil || active == nil {
		t.Fatalf("read pending active: tree=%v err=%v", active, err)
	}
	addLegacyAPIAuthToActive10825(t, active)
	s.active = active
	if err := s.db.WriteActive(active); err != nil {
		t.Fatalf("write legacy pending active: %v", err)
	}
	s.saveRollbackFiles()
	if s.rollbackPersistDegraded {
		t.Fatal("refresh rollback binding after fixture update")
	}
	rec, err := s.db.ReadConfirm()
	if err != nil || rec == nil {
		t.Fatalf("read armed record: rec=%v err=%v", rec, err)
	}
	const prevKey = "rollback-key-alpha-123456"
	rec.Deadline = deadline
	rec.PrevTree = parseAuthMigrationTree10826(t, `system {
 services {
  web-management {
   api-auth {
    expires 2099-01-01;
    api-key `+prevKey+`;
   }
  }
 }
}`)
	rec.GuardedHash = guardedConfigHash(active)
	if err := s.db.WriteConfirm(rec); err != nil {
		t.Fatalf("rewrite confirm record: %v", err)
	}
	s.CancelConfirmTimerForTesting()
	unconfirmed := s.ShowActiveSet()
	raw, err := os.ReadFile(filepath.Join(filepath.Dir(path), ".configdb", "confirm.json"))
	if err != nil {
		t.Fatalf("read confirm bytes: %v", err)
	}
	return path, unconfirmed, prevKey, raw
}

// installConfirmReadFault15273 installs the rbReadBoundedFile fault scoped to
// confirm.json (the #9887 seam) and returns its gate. Seams are restored via
// restoreRollbackSeams' t.Cleanup.
func installConfirmReadFault15273(t *testing.T) *atomic.Bool {
	t.Helper()
	restoreRollbackSeams(t)
	fail := &atomic.Bool{}
	fail.Store(true)
	inner := rbReadBoundedFile
	rbReadBoundedFile = func(p string, max int64) ([]byte, error) {
		if fail.Load() && filepath.Base(p) == "confirm.json" {
			return nil, errInjectedConfirmTransientRead
		}
		return inner(p, max)
	}
	return fail
}

// #15273 (C01-01): the #10826 api-auth boot migration rewrote active.json
// while confirm.json was unreadable, so the retained #8566 record was
// discarded as stale on the next boot and the unconfirmed config became
// permanent.
//
// RED on base: boot1 (corrupt record + legacy plaintext api-auth active)
// rewrites active.json to the hashed generation; boot2 restores the valid
// record, ReadConfirm now succeeds binding the OLD (pre-migration) hash,
// but active+raw hashes are both the migrated hash, so matchesActive fails
// and the record is stale-dropped instead of restored/rolled back.
//
// GREEN: boot1 defers the durable active rewrite (hashed tree in memory
// only), so boot2's record still binds the on-disk generation (and the
// staging OldHash->NewHash alias covers the boundary), the window is
// restored or rolled back, and only then does migration persist.
//
// Fault injection: the record's *bytes* stay valid on disk. The transient
// read fault is injected through rbReadBoundedFile scoped to confirm.json
// (the same seam #9887 uses) so boot1 hits ReadConfirm-error with
// confirm.json present, while boot2 reads the intact record. Corrupting
// bytes on disk cannot model this: ReadConfirm would keep failing on boot2.

func TestBootMigrationUnreadableConfirmRestoresLiveWindow15273(t *testing.T) {
	path, _, prevKey, origBytes := seedMigrationUnreadableConfirm15273(t, time.Now().Add(10*time.Minute))

	// Boot 1: transient confirm-read fault + legacy plaintext active.
	fail := installConfirmReadFault15273(t)
	s1 := newTestStoreAt(t, path)
	if err := s1.Load(); err != nil {
		t.Fatalf("#15273 boot1 Load: %v", err)
	}
	fail.Store(false)
	if !s1.ConfirmRecoveryReadFailed() {
		t.Fatal("#15273 boot1: unreadable confirm must remain degraded (#8566 signal)")
	}
	if got, err := s1.db.ReadActive(); err != nil || got == nil || !strings.Contains(got.Format(), "correct-horse-battery") {
		t.Fatalf("#15273 boot1: active.json must keep pre-migration generation while confirm is unreadable: err=%v", err)
	}
	if s1.ActiveConfig() == nil {
		t.Fatal("#15273 boot1: hashed in-memory config must be published")
	}
	wm := s1.ActiveConfig().System.Services.WebManagement
	if wm == nil || wm.APIAuth == nil || len(wm.APIAuth.Users) != 1 ||
		!config.VerifyAPIAuthSecret(wm.APIAuth.Users[0].Password.Reveal(), "correct-horse-battery") {
		t.Fatal("#15273 boot1: in-memory active must carry hashed verifiers")
	}
	if cur, err := os.ReadFile(filepath.Join(filepath.Dir(path), ".configdb", "confirm.json")); err != nil || string(cur) != string(origBytes) {
		t.Fatalf("#15273 boot1: confirm.json must be retained byte-for-byte: err=%v", err)
	}

	// Boot 2: fault cleared. Live window must be re-armed, not stale-dropped.
	s2 := newTestStoreAt(t, path)
	if err := s2.Load(); err != nil {
		t.Fatalf("#15273 boot2 Load: %v", err)
	}
	defer s2.CancelConfirmTimerForTesting()
	if !s2.IsConfirmPending() {
		t.Fatal("#15273 boot2: live commit-confirmed window was not restored (record stale-dropped, unconfirmed config permanent)")
	}
	// The unconfirmed stanza (eth1/untrust) must still stand while the
	// window is live; the api-auth secret itself is now rendered as its
	// hashed verifier, so compare the stanza, not the seed bytes.
	if got := s2.ShowActiveSet(); !strings.Contains(got, "untrust") || !strings.Contains(got, "eth1") {
		t.Fatalf("#15273 boot2: unconfirmed config must stand while window is live\ngot %s", got)
	}
	if rec, err := s2.db.ReadConfirm(); err != nil || rec == nil {
		t.Fatalf("#15273 boot2: confirm record must remain while window is live: rec=%v err=%v", rec, err)
	}
	_ = prevKey
}

func TestBootMigrationUnreadableConfirmRollsBackExpiredWindow15273(t *testing.T) {
	path, _, prevKey, _ := seedMigrationUnreadableConfirm15273(t, time.Now().Add(-time.Second))

	fail := installConfirmReadFault15273(t)
	s1 := newTestStoreAt(t, path)
	if err := s1.Load(); err != nil {
		t.Fatalf("#15273 expired boot1 Load: %v", err)
	}
	fail.Store(false)

	s2 := newTestStoreAt(t, path)
	if err := s2.Load(); err != nil {
		t.Fatalf("#15273 expired boot2 Load: %v", err)
	}
	defer s2.CancelConfirmTimerForTesting()
	if s2.IsConfirmPending() {
		t.Fatal("#15273 expired boot2: expired window must roll back, not re-arm")
	}
	got := s2.ActiveConfig()
	if got == nil || got.System.Services.WebManagement == nil || got.System.Services.WebManagement.APIAuth == nil {
		t.Fatalf("#15273 expired boot2: rolled-back config missing api-auth: %+v", got)
	}
	keys := got.System.Services.WebManagement.APIAuth.APIKeys
	if len(keys) != 1 || !config.VerifyAPIAuthSecret(keys[0].Reveal(), prevKey) {
		t.Fatal("#15273 expired boot2: did not roll back to the confirm record PrevTree")
	}
	if rec, err := s2.db.ReadConfirm(); err != nil || rec != nil {
		t.Fatalf("#15273 expired boot2: confirm record must be removed after rollback: rec=%v err=%v", rec, err)
	}
}

// Control: no confirm file at all — migration must still rewrite
// active.json durably on boot1 (the deferral must not widen).
func TestBootMigrationNoConfirmStillRewritesActive15273(t *testing.T) {
	s := newTestStore(t)
	if err := s.db.WriteActive(parseAuthMigrationTree10826(t, legacyAPIAuthConfig10826)); err != nil {
		t.Fatalf("write legacy active: %v", err)
	}
	if err := s.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	persisted, err := s.db.ReadActive()
	if err != nil || persisted == nil {
		t.Fatalf("read migrated active: %v", err)
	}
	if strings.Contains(persisted.Format(), "correct-horse-battery") || !strings.Contains(persisted.Format(), "$xpf-bcrypt$") {
		t.Fatalf("control: active.json must be migrated when no confirm record exists:\n%s", persisted.Format())
	}
}

// Control: readable live record — existing rebinding path still migrates
// active.json and restores the window (guards the #10826 cell).
func TestBootMigrationReadableConfirmStillRebinds15273(t *testing.T) {
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
	restarted := newTestStoreAt(t, path)
	if err := restarted.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	defer restarted.CancelConfirmTimerForTesting()
	if !restarted.IsConfirmPending() {
		t.Fatal("control: readable live window must be restored")
	}
	persisted, err := restarted.db.ReadActive()
	if err != nil || persisted == nil || strings.Contains(persisted.Format(), "correct-horse-battery") {
		t.Fatalf("control: readable path must still migrate active.json: err=%v", err)
	}
}
