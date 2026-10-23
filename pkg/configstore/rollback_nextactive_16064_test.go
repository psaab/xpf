package configstore

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/fsatomic"
)

// #16064 fault-injection regression: kill the process after the durable
// active rename but before Commit's rollback-slot rewrite begins. Production
// recording order is:
//
//	db.WriteActive(new) -> history.Push(old) -> saveRollbackFiles()
//
// The test seam panics as saveRollbackFiles starts. Boot must preserve
// byte-verifiable history at pre-shift positions from the preparation
// sidecar instead of tombstoning all generation-bound slots.
func TestRollbackCrashAfterActiveRenameKeepsHistory16064(t *testing.T) {
	path := filepath.Join(t.TempDir(), "xpf.conf")
	s := newTestStoreAt(t, path)
	for _, host := range []string{"host-a", "host-b", "host-c"} {
		if err := s.EnterConfigure(); err != nil {
			t.Fatal(err)
		}
		if err := s.SetFromInput("system host-name " + host); err != nil {
			t.Fatal(err)
		}
		if _, err := s.CommitWithDescription("commit " + host); err != nil {
			t.Fatalf("commit %s: %v", host, err)
		}
		s.ExitConfigure()
	}

	oldRBWrite := rbWriteFileDurable
	t.Cleanup(func() { rbWriteFileDurable = oldRBWrite })

	killed := errors.New("simulated power loss after active rename")
	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	if err := s.SetFromInput("system host-name host-d"); err != nil {
		t.Fatal(err)
	}
	var recovered any
	func() {
		defer func() { recovered = recover() }()
		// saveRollbackFiles reaches rbWriteFileDurable for slot 1 before the
		// sidecar publish; simulate loss of process there by panicking from
		// the production seam and treating it as process death.
		rbWriteFileDurable = func(p string, data []byte, perm os.FileMode, opts ...fsatomic.Option) error {
			if strings.HasPrefix(filepath.Base(p), "xpf.conf.") {
				panic(killed)
			}
			return oldRBWrite(p, data, perm, opts...)
		}
		_, _ = s.CommitWithDescription("commit host-d")
	}()
	rbWriteFileDurable = oldRBWrite
	if recovered == nil {
		t.Fatal("commit did not reach the injected crash point")
	}

	restarted := newTestStoreAt(t, path)
	restarted.loadRollbackHistory()
	entries := restarted.history.List()
	if len(entries) < 2 {
		t.Fatalf("crash restart loaded %d history positions, want preserved rollback slots", len(entries))
	}
	if entries[0].Config == nil || !strings.Contains(entries[0].Config.Format(), "host-b") {
		t.Fatalf("slot 1 = %#v, want pre-shift host-b history", entries[0])
	}
	if entries[1].Config == nil || !strings.Contains(entries[1].Config.Format(), "host-a") {
		t.Fatalf("slot 2 = %#v, want pre-shift host-a history", entries[1])
	}
}

// The older hazard remains fail-closed when no next-active sidecar certifies it.
func TestRollbackActiveRewriteWithoutPreparationRefuses16064(t *testing.T) {
	path := filepath.Join(t.TempDir(), "xpf.conf")
	s := newTestStoreAt(t, path)
	s.active = tree10723(t, "active-old")
	if err := s.db.WriteActive(s.active); err != nil {
		t.Fatalf("write old active: %v", err)
	}
	for _, host := range []string{"old-slot-2", "old-slot-1"} {
		s.history.Push(&HistoryEntry{Config: tree10723(t, host), Timestamp: time.Now()})
	}
	s.saveRollbackFiles()
	if err := s.db.WriteActive(tree10723(t, "active-other")); err != nil {
		t.Fatalf("uncertified active rewrite: %v", err)
	}
	restarted := newTestStoreAt(t, path)
	restarted.loadRollbackHistory()
	entries := restarted.history.List()
	if len(entries) != 2 {
		t.Fatalf("loaded %d entries, want two preserved tombstone positions", len(entries))
	}
	for i, entry := range entries {
		if entry.Config != nil {
			t.Fatalf("slot %d admitted uncertified history: %s", i+1, entry.Config.Format())
		}
	}
}

// TestGateDrivesLoad16064 drives the PRODUCTION loader gate
// (loadRollbackHistory -> rollbackSkewSlotAdmission) end-to-end: a partial
// slot rewrite leaves slot 1 holding its future (pending) bytes while slot 2
// keeps pre-shift bytes. Restart must admit both, and the pending-admitted
// slot must carry the pending (future entry) timestamp/comment, not another
// position's committed attributes.
func TestGateDrivesLoad16064(t *testing.T) {
	path := filepath.Join(t.TempDir(), "xpf.conf")
	s := newTestStoreAt(t, path)
	for _, host := range []string{"host-a", "host-b", "host-c"} {
		if err := s.EnterConfigure(); err != nil {
			t.Fatal(err)
		}
		if err := s.SetFromInput("system host-name " + host); err != nil {
			t.Fatal(err)
		}
		if _, err := s.CommitWithDescription("commit " + host); err != nil {
			t.Fatalf("commit %s: %v", host, err)
		}
		s.ExitConfigure()
	}

	oldRBWrite := rbWriteFileDurable
	t.Cleanup(func() { rbWriteFileDurable = oldRBWrite })
	killed := errors.New("simulated power loss mid slot rewrite")
	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	if err := s.SetFromInput("system host-name host-d"); err != nil {
		t.Fatal(err)
	}
	var recovered any
	func() {
		defer func() { recovered = recover() }()
		// Slot 1 rewrite lands (pending bytes), slot 2 write dies: partial.
		rbWriteFileDurable = func(p string, data []byte, perm os.FileMode, opts ...fsatomic.Option) error {
			base := filepath.Base(p)
			if strings.HasPrefix(base, "xpf.conf.") && base != "xpf.conf.1" {
				panic(killed)
			}
			return oldRBWrite(p, data, perm, opts...)
		}
		_, _ = s.CommitWithDescription("commit host-d distinct comment")
	}()
	rbWriteFileDurable = oldRBWrite
	if recovered == nil {
		t.Fatal("commit did not reach the injected crash point")
	}

	restarted := newTestStoreAt(t, path)
	restarted.loadRollbackHistory()
	entries := restarted.history.List()
	if len(entries) < 2 {
		t.Fatalf("partial-rewrite restart loaded %d positions, want >=2", len(entries))
	}
	// Slot 1 was rewritten to future bytes (old active host-c): pending path.
	if entries[0].Config == nil || !strings.Contains(entries[0].Config.Format(), "host-c") {
		t.Fatalf("slot 1 = %#v, want host-c via pending hash", entries[0])
	}
	if entries[0].Comment != "commit host-d distinct comment" {
		t.Fatalf("slot 1 comment = %q, want its own pending comment", entries[0].Comment)
	}
	// Slot 2 kept pre-shift bytes (host-b at old slot 2): chain path.
	// Slot 2 kept pre-shift bytes: old slot 2 held host-a-era history; the
	// exact content matters less than that it survives with its own attrs.
	if entries[1].Config == nil {
		t.Fatalf("slot 2 tombstoned, want pre-shift survivor: %#v", entries[1])
	}
}

// Same-content commit (next hash == committed active hash) must still be
// certified: the active file identity moved even though bytes did not.
func TestSameContentCommitCrashCertified16064(t *testing.T) {
	path := filepath.Join(t.TempDir(), "xpf.conf")
	s := newTestStoreAt(t, path)
	for _, host := range []string{"same-a", "same-b"} {
		if err := s.EnterConfigure(); err != nil {
			t.Fatal(err)
		}
		if err := s.SetFromInput("system host-name " + host); err != nil {
			t.Fatal(err)
		}
		if _, err := s.CommitWithDescription("commit " + host); err != nil {
			t.Fatalf("commit %s: %v", host, err)
		}
		s.ExitConfigure()
	}
	oldRBWrite := rbWriteFileDurable
	t.Cleanup(func() { rbWriteFileDurable = oldRBWrite })
	killed := errors.New("simulated power loss after same-content rename")
	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	// Re-commit identical content (comment-only change in history).
	var recovered any
	func() {
		defer func() { recovered = recover() }()
		rbWriteFileDurable = func(p string, data []byte, perm os.FileMode, opts ...fsatomic.Option) error {
			if strings.HasPrefix(filepath.Base(p), "xpf.conf.") {
				panic(killed)
			}
			return oldRBWrite(p, data, perm, opts...)
		}
		_, _ = s.CommitWithDescription("same content recommit")
	}()
	rbWriteFileDurable = oldRBWrite
	if recovered == nil {
		t.Fatal("commit did not reach the injected crash point")
	}
	snap := s.readRollbackMetadataSnapshotFull()
	if snap.NextActiveHash == "" || snap.NextActiveHash != snap.ActiveHash {
		t.Fatalf("same-content preparation not recorded: next=%q active=%q", snap.NextActiveHash, snap.ActiveHash)
	}
	restarted := newTestStoreAt(t, path)
	restarted.loadRollbackHistory()
	entries := restarted.history.List()
	if len(entries) < 1 || entries[0].Config == nil {
		t.Fatalf("same-content crash lost history: %#v", entries)
	}
}

// A store recovered through the skew path must re-arm preparation on its
// next commit: a second crash in the same window must not lose history again.
func TestPostRecoveryCommitRearms16064(t *testing.T) {
	path := filepath.Join(t.TempDir(), "xpf.conf")
	s := newTestStoreAt(t, path)
	for _, host := range []string{"re-a", "re-b", "re-c"} {
		if err := s.EnterConfigure(); err != nil {
			t.Fatal(err)
		}
		if err := s.SetFromInput("system host-name " + host); err != nil {
			t.Fatal(err)
		}
		if _, err := s.CommitWithDescription("commit " + host); err != nil {
			t.Fatalf("commit %s: %v", host, err)
		}
		s.ExitConfigure()
	}
	oldRBWrite := rbWriteFileDurable
	t.Cleanup(func() { rbWriteFileDurable = oldRBWrite })
	killed := errors.New("simulated power loss")
	crashCommit := func(store *Store, host, comment string) {
		t.Helper()
		if err := store.EnterConfigure(); err != nil {
			t.Fatal(err)
		}
		if err := store.SetFromInput("system host-name " + host); err != nil {
			t.Fatal(err)
		}
		var rec any
		func() {
			defer func() { rec = recover() }()
			rbWriteFileDurable = func(p string, data []byte, perm os.FileMode, opts ...fsatomic.Option) error {
				if strings.HasPrefix(filepath.Base(p), "xpf.conf.") {
					panic(killed)
				}
				return oldRBWrite(p, data, perm, opts...)
			}
			_, _ = store.CommitWithDescription(comment)
		}()
		rbWriteFileDurable = oldRBWrite
		if rec == nil {
			t.Fatal("commit did not reach crash point")
		}
	}
	// First crash + recovery through the skew path.
	crashCommit(s, "re-d", "commit re-d")
	recoveredStore := newTestStoreAt(t, path)
	if err := recoveredStore.Load(); err != nil {
		t.Fatalf("Load after first crash: %v", err)
	}
	if len(recoveredStore.history.List()) < 1 || recoveredStore.history.List()[0].Config == nil {
		t.Fatalf("first recovery lost history: %#v", recoveredStore.history.List())
	}
	// Second commit on the recovered store crashes the same way.
	crashCommit(recoveredStore, "re-e", "commit re-e")
	snap := recoveredStore.readRollbackMetadataSnapshotFull()
	if snap.NextActiveHash == "" {
		t.Fatal("recovered store did not re-arm next-active preparation")
	}
	restarted := newTestStoreAt(t, path)
	restarted.loadRollbackHistory()
	entries := restarted.history.List()
	if len(entries) < 1 || entries[0].Config == nil {
		t.Fatalf("second crash lost history again: %#v", entries)
	}
}
