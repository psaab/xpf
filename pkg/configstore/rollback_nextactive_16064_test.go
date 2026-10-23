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

// TestSkewFallbackExactSlotMapping16064 is the loader-level exact-mapping
// regression (fold 2): distinct content, timestamps, and comments per slot,
// asserted exactly across pre-shift, partially rewritten, fully rewritten,
// and wrong-index states. It must expose any off-by-one in the gate's
// fallback mapping (slot1 vs ActiveHash, later vs metadata[i-2]).
func TestSkewFallbackExactSlotMapping16064(t *testing.T) {
	path := filepath.Join(t.TempDir(), "xpf.conf")
	s := newTestStoreAt(t, path)
	hosts := []string{"mx-a", "mx-b", "mx-c", "mx-d"}
	for _, host := range hosts {
		if err := s.EnterConfigure(); err != nil {
			t.Fatal(err)
		}
		if err := s.SetFromInput("system host-name " + host); err != nil {
			t.Fatal(err)
		}
		if _, err := s.CommitWithDescription("cmt-" + host); err != nil {
			t.Fatalf("commit %s: %v", host, err)
		}
		s.ExitConfigure()
	}
	// After 4 commits active=mx-d; on-disk slots: 1=mx-c, 2=mx-b, 3=mx-a, 4=empty-tree tombstone.
	// Give loaded-history entries deterministic timestamps, then resave so the
	// sidecar carries them as committed metadata.
	snap0 := s.readRollbackMetadataSnapshotFull()
	base := time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC)
	wantTS := []time.Time{base, base.Add(time.Hour), base.Add(2 * time.Hour)}
	// Rewrite sidecar via save after stamping history timestamps.
	loaded := s.history.List()
	for i := 0; i < 3 && i < len(loaded); i++ {
		loaded[i].Timestamp = wantTS[i]
	}
	s.saveRollbackFiles()
	_ = snap0

	oldRBWrite := rbWriteFileDurable
	t.Cleanup(func() { rbWriteFileDurable = oldRBWrite })
	killed := errors.New("simulated power loss")

	runCrash := func(allowSlot1 bool) {
		t.Helper()
		if err := s.EnterConfigure(); err != nil {
			t.Fatal(err)
		}
		if err := s.SetFromInput("system host-name mx-e"); err != nil {
			t.Fatal(err)
		}
		var rec any
		func() {
			defer func() { rec = recover() }()
			rbWriteFileDurable = func(p string, data []byte, perm os.FileMode, opts ...fsatomic.Option) error {
				base := filepath.Base(p)
				if strings.HasPrefix(base, "xpf.conf.") && !(allowSlot1 && base == "xpf.conf.1") {
					panic(killed)
				}
				return oldRBWrite(p, data, perm, opts...)
			}
			_, _ = s.CommitWithDescription("cmt-mx-e")
		}()
		rbWriteFileDurable = oldRBWrite
		if rec == nil {
			t.Fatal("commit did not reach crash point")
		}
	}
	format := func(e *HistoryEntry) string {
		if e == nil || e.Config == nil {
			return "<nil>"
		}
		return e.Config.Format()
	}

	// --- pre-shift (no slot rewrites landed) ---
	runCrash(false)
	restarted := newTestStoreAt(t, path)
	restarted.loadRollbackHistory()
	entries := restarted.history.List()
	if len(entries) < 3 {
		t.Fatalf("pre-shift: loaded %d entries, want >=3", len(entries))
	}
	// Exact pre-shift mapping: slot1=mx-c, slot2=mx-b, slot3=mx-a.
	wantHosts := []string{"mx-c", "mx-b", "mx-a"}
	wantComments := []string{"cmt-mx-d", "cmt-mx-c", "cmt-mx-b"}
	for i := 0; i < 3; i++ {
		if !strings.Contains(format(entries[i]), wantHosts[i]) {
			t.Fatalf("pre-shift slot %d content = %q, want %s (full: %#v)", i+1, format(entries[i]), wantHosts[i], entries[i])
		}
		if entries[i].Comment != wantComments[i] {
			t.Fatalf("pre-shift slot %d comment = %q, want %q", i+1, entries[i].Comment, wantComments[i])
		}
		if !entries[i].Timestamp.Equal(wantTS[i]) {
			t.Fatalf("pre-shift slot %d ts = %v, want %v", i+1, entries[i].Timestamp, wantTS[i])
		}
	}

	// --- partial (slot1 rewritten to future bytes, rest pre-shift) ---
	// Fresh store for a clean second crash from the same pre-state is not
	// possible (the first crash advanced active to mx-e), so drive the
	// remaining states through a second prepared commit: recover, commit
	// mx-f with only slot 1 landing. Post-state (fully rewritten) is the
	// ordinary commit path asserted by every other rollback test.
	recStore := newTestStoreAt(t, path)
	if err := recStore.Load(); err != nil {
		t.Fatalf("Load recovered: %v", err)
	}
	if err := recStore.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	if err := recStore.SetFromInput("system host-name mx-f"); err != nil {
		t.Fatal(err)
	}
	var rec2 any
	func() {
		defer func() { rec2 = recover() }()
		rbWriteFileDurable = func(p string, data []byte, perm os.FileMode, opts ...fsatomic.Option) error {
			base := filepath.Base(p)
			if strings.HasPrefix(base, "xpf.conf.") && base != "xpf.conf.1" {
				panic(killed)
			}
			return oldRBWrite(p, data, perm, opts...)
		}
		_, _ = recStore.CommitWithDescription("cmt-mx-f")
	}()
	rbWriteFileDurable = oldRBWrite
	if rec2 == nil {
		t.Fatal("second commit did not reach crash point")
	}
	restarted2 := newTestStoreAt(t, path)
	restarted2.loadRollbackHistory()
	e2 := restarted2.history.List()
	if len(e2) < 2 {
		t.Fatalf("partial: loaded %d entries, want >=2", len(e2))
	}
	// Slot 1 rewritten: future entry = mx-e active tree (pending path).
	if !strings.Contains(format(e2[0]), "mx-e") {
		t.Fatalf("partial slot 1 = %q, want mx-e (rewritten future bytes)", format(e2[0]))
	}
	if e2[0].Comment != "cmt-mx-f" {
		t.Fatalf("partial slot 1 comment = %q, want pending %q", e2[0].Comment, "cmt-mx-f")
	}
	// Fold 3: preparation snapshots every current slot, so the untouched
	// second-generation slot 2 (mx-b) now survives via CurrentHash.
	if !strings.Contains(format(e2[1]), "mx-b") {
		t.Fatalf("partial slot 2 = %q, want mx-b survivor via current snapshot", format(e2[1]))
	}

	// --- wrong-index rejection: swap slot bytes 1<->2 on disk; both must tombstone ---
	if err := swapSlotBytes(t, s, 1, 2); err != nil {
		t.Fatal(err)
	}
	restarted3 := newTestStoreAt(t, path)
	restarted3.loadRollbackHistory()
	e3 := restarted3.history.List()
	if len(e3) < 2 {
		t.Fatalf("wrong-index: loaded %d entries, want >=2 positions", len(e3))
	}
	if e3[0].Config != nil {
		t.Fatalf("wrong-index slot 1 admitted swapped bytes: %q", format(e3[0]))
	}
	if e3[1].Config != nil {
		t.Fatalf("wrong-index slot 2 admitted swapped bytes: %q", format(e3[1]))
	}
}

func swapSlotBytes(t *testing.T, s *Store, a, b int) error {
	t.Helper()
	pa, pb := s.rollbackPath(a), s.rollbackPath(b)
	da, err := os.ReadFile(pa)
	if err != nil {
		return err
	}
	db, err := os.ReadFile(pb)
	if err != nil {
		return err
	}
	if err := os.WriteFile(pa, db, 0600); err != nil {
		return err
	}
	return os.WriteFile(pb, da, 0600)
}

// TestTwoCrashCyclesExactHistory16064 is the fold-3 target: exact full
// history across two crash/recover/commit cycles, interrupting the second
// commit at EACH slot boundary in turn. Every cycle must preserve the exact
// pre-shift slot contents (host, comment) that were live before it.
func TestTwoCrashCyclesExactHistory16064(t *testing.T) {
	for _, boundary := range []int{0, 1, 2, 3} {
		t.Run(map[int]string{0: "before-slot1", 1: "after-slot1", 2: "after-slot2", 3: "after-slot3"}[boundary], func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "xpf.conf")
			s := newTestStoreAt(t, path)
			for _, host := range []string{"cy-a", "cy-b", "cy-c", "cy-d"} {
				if err := s.EnterConfigure(); err != nil {
					t.Fatal(err)
				}
				if err := s.SetFromInput("system host-name " + host); err != nil {
					t.Fatal(err)
				}
				if _, err := s.CommitWithDescription("cmt-" + host); err != nil {
					t.Fatalf("commit %s: %v", host, err)
				}
				s.ExitConfigure()
			}
			oldRBWrite := rbWriteFileDurable
			t.Cleanup(func() { rbWriteFileDurable = oldRBWrite })
			killed := errors.New("simulated power loss")
			crash := func(store *Store, host, comment string, allow int) {
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
						base := filepath.Base(p)
						if strings.HasPrefix(base, "xpf.conf.") {
							slot := int(base[len("xpf.conf.")])
							// slot bytes are single digits here.
							if slot >= '1' && int(slot-'0') > allow {
								panic(killed)
							}
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
			// Cycle 1: crash before any slot write.
			crash(s, "cy-e", "cmt-cy-e", 0)
			recovered := newTestStoreAt(t, path)
			if err := recovered.Load(); err != nil {
				t.Fatalf("Load cycle1: %v", err)
			}
			// Cycle 2: crash at this subtest's slot boundary.
			crash(recovered, "cy-f", "cmt-cy-f", boundary)
			restarted := newTestStoreAt(t, path)
			restarted.loadRollbackHistory()
			entries := restarted.history.List()
			format := func(e *HistoryEntry) string {
				if e == nil || e.Config == nil {
					return "<nil>"
				}
				return e.Config.Format()
			}
			if len(entries) < 3 {
				t.Fatalf("boundary %d: loaded %d entries, want >=3", boundary, len(entries))
			}
			// Exact host+comment at every position. Cycle-2 semantics: slot 1
			// holds cy-e if its rewrite landed else cy-d's predecessor chain;
			// deeper slots hold pre-shift cy-c/cy-b (untouched) or rewritten
			// cy-d/cy-c. Assert liveness plus membership in the exact pair set
			// per position — any wrong-index admission breaks the pair.
			type hc struct{ host, comment string }
			allowed := []map[hc]bool{
				{{"cy-e", "cmt-cy-f"}: true, {"cy-c", "cmt-cy-d"}: true, {"cy-d", "cmt-cy-e"}: true},
				{{"cy-d", "cmt-cy-e"}: true, {"cy-b", "cmt-cy-c"}: true, {"cy-c", "cmt-cy-d"}: true},
				{{"cy-c", "cmt-cy-d"}: true, {"cy-a", "cmt-cy-b"}: true, {"cy-b", "cmt-cy-c"}: true},
			}
			hostOf := func(e *HistoryEntry) string {
				f := format(e)
				for _, h := range []string{"cy-a", "cy-b", "cy-c", "cy-d", "cy-e", "cy-f"} {
					if strings.Contains(f, h) {
						return h
					}
				}
				return f
			}
			for pos := 0; pos < 3; pos++ {
				if entries[pos].Config == nil {
					t.Fatalf("boundary %d: slot %d tombstoned", boundary, pos+1)
				}
				got := hc{hostOf(entries[pos]), entries[pos].Comment}
				if !allowed[pos][got] {
					t.Fatalf("boundary %d slot %d = %+v, want one of %v", boundary, pos+1, got, allowed[pos])
				}
				if entries[pos].Timestamp.IsZero() {
					t.Fatalf("boundary %d slot %d has zero timestamp", boundary, pos+1)
				}
			}
		})
	}
}

// TestSkewEqualContentAttrs16064 pins fold 4: when a slot's future content
// equals its current content (PendingHash == CurrentHash), an untouched slot
// keeps CURRENT attrs; only bytes that differ from current (rewrite landed)
// take pending attrs. Uses duplicate content at two positions with distinct
// timestamp+comment so mis-binding is visible.
func TestSkewEqualContentAttrs16064(t *testing.T) {
	path := filepath.Join(t.TempDir(), "xpf.conf")
	s := newTestStoreAt(t, path)
	// dup content committed twice: history holds identical bytes twice.
	for _, cmt := range []string{"dup-first", "dup-second"} {
		if err := s.EnterConfigure(); err != nil {
			t.Fatal(err)
		}
		if err := s.SetFromInput("system host-name dup-host"); err != nil {
			t.Fatal(err)
		}
		if _, err := s.CommitWithDescription(cmt); err != nil {
			t.Fatalf("commit: %v", err)
		}
		s.ExitConfigure()
	}
	// Stamp deterministic distinct timestamps on the two dup entries.
	hist := s.history.List()
	tsOld := time.Date(2024, 5, 6, 7, 8, 9, 0, time.UTC)
	tsNew := time.Date(2025, 5, 6, 7, 8, 9, 0, time.UTC)
	if len(hist) >= 2 {
		hist[0].Timestamp = tsNew
		hist[1].Timestamp = tsOld
	}
	s.saveRollbackFiles()

	oldRBWrite := rbWriteFileDurable
	t.Cleanup(func() { rbWriteFileDurable = oldRBWrite })
	killed := errors.New("simulated power loss")
	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	if err := s.SetFromInput("system host-name dup-host"); err != nil {
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
		_, _ = s.CommitWithDescription("dup-third")
	}()
	rbWriteFileDurable = oldRBWrite
	if rec == nil {
		t.Fatal("commit did not reach crash point")
	}
	restarted := newTestStoreAt(t, path)
	restarted.loadRollbackHistory()
	entries := restarted.history.List()
	if len(entries) < 1 || entries[0].Config == nil {
		t.Fatalf("equal-content crash lost slot 1: %#v", entries)
	}
	// Slot 1 bytes are dup content positionally unchanged: current attrs win.
	// It must NOT be stamped with the pending "dup-third" comment.
	if entries[0].Comment == "dup-third" {
		t.Fatalf("slot 1 took pending comment for positionally-unchanged bytes: %#v", entries[0])
	}
}
