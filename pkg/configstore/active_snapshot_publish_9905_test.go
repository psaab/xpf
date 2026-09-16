package configstore

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

// Active-snapshot publication coverage (#9905, review GPT-1/SPARK-F5).
//
// ActiveSnapshot is the lock-free warm-path probe behind the daemon's cached
// per-commit derivations: every compiled swap must publish exactly one
// immutable {gen, cfg} pair, or a cached derivation goes permanently stale.
// Coverage here is behavioral per promotion path, plus a structural test pinning
// the swap↔publish pairing itself (an 8th swap site fails loudly either way).
//
// The boot-recovery swaps (store_persist.go) have no behavioral cell: driving
// recoverPendingConfirmLocked needs on-disk confirm-record fixtures, and the
// structural test below already pins both sites' publish lines. The daemon
// rebuild test (TestHandleDeltaZoneMapRebuildsOnCommit9905) pins the commit
// path end to end.

func snapshotPublishStore9905(t *testing.T, host string) *Store {
	t.Helper()
	s := newTestStore(t)
	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	if err := s.SetFromInput("system host-name " + host); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Commit(); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestActiveSnapshotFreshStore9905(t *testing.T) {
	s := newTestStore(t)
	gen, cfg := s.ActiveSnapshot()
	if gen != 0 || cfg != nil {
		t.Fatalf("fresh store snapshot = (%d,%v), want (0,nil)", gen, cfg)
	}
}

func TestActiveSnapshotBumpsOnCommit9905(t *testing.T) {
	s := snapshotPublishStore9905(t, "a")
	g1, c1 := s.ActiveSnapshot()
	if g1 == 0 || c1 == nil || c1.System.HostName != "a" {
		t.Fatalf("post-commit snapshot = (%d,%v), want (nonzero,a)", g1, c1)
	}
	if c1 != s.ActiveConfig() {
		t.Fatal("snapshot cfg != ActiveConfig after commit")
	}
	// Still in config mode after commit: LoadSet/Commit directly.
	if err := s.SetFromInput("system host-name b"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Commit(); err != nil {
		t.Fatal(err)
	}
	g2, c2 := s.ActiveSnapshot()
	if g2 != g1+1 || c2 == nil || c2.System.HostName != "b" {
		t.Fatalf("second commit snapshot = (%d,%v), want (%d,b)", g2, c2, g1+1)
	}
	if c2 != s.ActiveConfig() {
		t.Fatal("snapshot cfg != ActiveConfig after second commit")
	}
}

func TestActiveSnapshotBumpsOnSyncApply9905(t *testing.T) {
	s := snapshotPublishStore9905(t, "a")
	g1, _ := s.ActiveSnapshot()
	content := "system {\n host-name synced;\n}\n"
	if _, err := s.SyncApply(content, nil); err != nil {
		t.Fatalf("SyncApply: %v", err)
	}
	g2, c2 := s.ActiveSnapshot()
	if g2 != g1+1 || c2 == nil || c2.System.HostName != "synced" {
		t.Fatalf("post-sync snapshot = (%d,%v), want (%d,synced)", g2, c2, g1+1)
	}
	if c2 != s.ActiveConfig() {
		t.Fatal("snapshot cfg != ActiveConfig after SyncApply")
	}
}

func TestActiveSnapshotBumpsOnRollback9905(t *testing.T) {
	s := newTestStore(t)
	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	if err := s.SetFromInput("system host-name A"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Commit(); err != nil {
		t.Fatal(err)
	}
	gBase, _ := s.ActiveSnapshot()
	if err := s.SetFromInput("system host-name B"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CommitConfirmed(1); err != nil {
		t.Fatal(err)
	}
	// The confirmed commit itself promotes (second bump).
	gConf, cConf := s.ActiveSnapshot()
	if gConf != gBase+1 || cConf == nil || cConf.System.HostName != "B" {
		t.Fatalf("post-confirmed snapshot = (%d,%v), want (%d,B)", gConf, cConf, gBase+1)
	}
	gen := s.ConfirmGenForTesting()
	prevCfg, ok := s.PromoteRollback(gen)
	if !ok {
		t.Fatal("PromoteRollback: ok=false, want true")
	}
	gAfter, cAfter := s.ActiveSnapshot()
	if gAfter != gConf+1 {
		t.Fatalf("post-rollback gen = %d, want %d", gAfter, gConf+1)
	}
	if cAfter != prevCfg || cAfter.System.HostName != "A" {
		t.Fatalf("post-rollback cfg = %v, want prevCfg (A)", cAfter)
	}
}

func TestActiveSnapshotConcurrentLoads9905(t *testing.T) {
	s := snapshotPublishStore9905(t, "a")
	g0, _ := s.ActiveSnapshot()
	const readers = 8
	const loads = 2000
	var maxSeen atomic.Uint64
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < readers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			var localMax uint64
			for j := 0; j < loads; j++ {
				gen, cfg := s.ActiveSnapshot()
				// Pair invariant: gen==0 ⟺ cfg==nil (fresh store only).
				if (gen == 0) != (cfg == nil) {
					t.Errorf("mixed pair (%d,%v): gen==0 must coincide with cfg==nil", gen, cfg)
					return
				}
				if gen > localMax {
					localMax = gen
				}
			}
			for {
				cur := maxSeen.Load()
				if localMax <= cur || maxSeen.CompareAndSwap(cur, localMax) {
					break
				}
			}
		}()
	}
	close(start)
	// Punctuated commits while readers hammer the snapshot.
	for _, host := range []string{"b1", "b2", "b3", "b4"} {
		if err := s.SetFromInput("system host-name " + host); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Commit(); err != nil {
			t.Fatal(err)
		}
	}
	wg.Wait()
	gFinal, cFinal := s.ActiveSnapshot()
	if gFinal != g0+4 || cFinal == nil || cFinal.System.HostName != "b4" {
		t.Fatalf("final snapshot = (%d,%v), want (%d,b4)", gFinal, cFinal, g0+4)
	}
	if maxSeen.Load() > gFinal {
		t.Fatalf("reader saw gen %d beyond final %d", maxSeen.Load(), gFinal)
	}
}

// TestActiveSnapshotPublishCoversEverySwap9905 is the structural backstop:
// every `s.compiled =` assignment in production store files must be
// immediately followed by a publishActiveLocked call. Verified by mutation
// (removing any one publish line fails this test naming the file:line).
func TestActiveSnapshotPublishCoversEverySwap9905(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	dir := filepath.Dir(thisFile)
	swapRE := regexp.MustCompile(`s\.compiled = [^=]`)
	files := []string{"store.go", "store_commit.go", "store_persist.go"}
	swaps := 0
	for _, name := range files {
		raw, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		lines := strings.Split(string(raw), "\n")
		for i, line := range lines {
			if !swapRE.MatchString(line) {
				continue
			}
			swaps++
			found := false
			for _, next := range lines[i+1:] {
				if strings.TrimSpace(next) == "" {
					continue
				}
				found = strings.Contains(next, "publishActiveLocked()")
				if !found {
					t.Errorf("%s:%d: compiled swap not followed by publish (next: %q)", name, i+1, strings.TrimSpace(next))
				}
				break
			}
			if !found {
				// find the line number for the message (already reported above
				// unless the swap is the last non-empty line of the file)
				if i+1 >= len(lines) {
					t.Errorf("%s:%d: compiled swap at EOF without publish", name, i+1)
				}
			}
		}
	}
	// Tripwire on the inventory itself: today there are exactly 7 production
	// swaps. An 8th swap WITH a publish still fails here until a human
	// extends the count — adding a promotion path must be a conscious,
	// reviewed act, not a silent drift.
	if swaps != 7 {
		t.Errorf("found %d compiled swaps, want exactly 7 (update the count + review when adding a promotion path)", swaps)
	}
}
