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

func TestClassifyRollbackSlotBytes16064(t *testing.T) {
	committed := []string{"a", "b", "c"}
	pending := []string{"x", "a", "b"}
	cases := []struct {
		name        string
		pendingOK   bool
		genValid    bool
		preShift    bool
		consumed    bool
		pos         int
		hash        string
		wantAdmit   bool
		wantForward bool
	}{
		{"no pending", false, true, false, false, 1, "a", false, false},
		{"forward slot2", true, true, false, false, 1, "a", true, true},
		{"forward slot3", true, true, false, false, 2, "b", true, true},
		{"self wrong generation", true, false, false, false, 1, "b", false, false},
		{"self stepped past", true, true, true, false, 1, "b", false, false},
		{"self admitted", true, true, false, false, 1, "b", true, false},
		{"slot1 self stepped past", true, true, true, false, 0, "a", false, false},
		{"unknown", true, true, false, false, 1, "zzz", false, false},
		{"consumed blocks", true, true, false, true, 1, "a", false, false},
		{"pending mismatch", true, true, false, false, 1, "b", true, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			admit, forward := classifyRollbackSlotBytes(tc.pendingOK, tc.genValid, tc.preShift, tc.consumed,
				committed, pending, tc.pos, tc.hash)
			if admit != tc.wantAdmit || forward != tc.wantForward {
				t.Fatalf("classify = (%v,%v), want (%v,%v)", admit, forward, tc.wantAdmit, tc.wantForward)
			}
		})
	}
}
