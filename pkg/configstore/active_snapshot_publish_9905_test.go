package configstore

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// Active-snapshot publication coverage (#9905, review GPT-1/SPARK-F5).
//
// ActiveSnapshot is the lock-free warm-path probe behind the daemon's cached
// per-commit derivations: every compiled swap must publish exactly one
// immutable {gen, cfg} pair, or a cached derivation goes permanently stale.
// Coverage here is behavioral per promotion path — commit, SyncApply,
// PromoteRollback (incl. the nil first-commit target), boot recovery
// (incl. the nil first-commit outcome) — plus a structural test pinning
// the swap↔publish pairing within store*.go production files (line and
// block comments excluded on both sides of the check). Swaps outside
// store*.go non-test files are out of this guard's sight by construction.
// way). The daemon rebuild test pins the commit path end to end, and the
// daemon withhold cell pins the (gen, nil) snapshot shape the daemon
// treats as transient.

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
	// snapshotAckTimeout bounds a collection stall (deadlock/bug) instead of
	// hanging to package timeout. Generous on purpose: it is a liveness
	// backstop, not a perf assertion — healthy rounds complete in milliseconds.
	const snapshotAckTimeout = 2 * time.Minute
	// committed pre-registers generation → hostname BEFORE each commit, so
	// every observable generation has an expectation: readers assert
	// version-correspondence (the observed cfg's hostname must equal the
	// hostname committed AT the observed generation). A split publication
	// (new gen, old cfg) fails. There is no "unknown, skip" hole.
	var mu sync.Mutex
	committed := map[uint64]string{g0: "a"}
	finalGen := g0 + 4
	type ack struct {
		reader int
		gen    uint64
	}
	// acks/errc/done are the writer-driven coordination: readers run until
	// done closes (no spin cap to exhaust, no early exit except through
	// errc), the writer releases one generation at a time and requires
	// every reader's ack before the next commit, and any reader error
	// fails fast via errc (t.Fatalf runs on the test goroutine). The
	// writer can never strand: it waits only for acks of the currently
	// published generation, which spinning readers must observe.
	acks := make(chan ack, readers*8)
	errc := make(chan string, readers)
	done := make(chan struct{})
	var wg sync.WaitGroup
	for r := range readers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var lastAcked uint64
			for {
				select {
				case <-done:
					return
				default:
				}
				gen, cfg := s.ActiveSnapshot()
				// Pair invariant: gen==0 ⟺ cfg==nil (fresh store only).
				if (gen == 0) != (cfg == nil) {
					errc <- "mixed pair: gen==0 must coincide with cfg==nil"
					return
				}
				if gen == 0 {
					continue
				}
				mu.Lock()
				want, known := committed[gen]
				mu.Unlock()
				if !known {
					errc <- "observed generation was never pre-registered"
					return
				}
				got := "<nil>"
				if cfg != nil {
					got = cfg.System.HostName
				}
				if got != want {
					errc <- "generation maps to wrong hostname"
					return
				}
				if gen > lastAcked {
					lastAcked = gen
					acks <- ack{reader: r, gen: gen}
				}
			}
		}()
	}
	for i, host := range []string{"b1", "b2", "b3", "b4"} {
		wantGen := g0 + 1 + uint64(i)
		mu.Lock()
		committed[wantGen] = host
		mu.Unlock()
		if err := s.SetFromInput("system host-name " + host); err != nil {
			close(done)
			t.Fatal(err)
		}
		if _, err := s.Commit(); err != nil {
			close(done)
			t.Fatal(err)
		}
		// Publication check: the commit must have advanced the snapshot.
		// Without it, a mutant that drops publication would leave readers
		// spinning on the old generation while the ack collection below
		// hangs to package timeout instead of failing cleanly here.
		if gen, _ := s.ActiveSnapshot(); gen != wantGen {
			close(done)
			t.Fatalf("post-commit snapshot gen = %d, want %d (publication missing?)", gen, wantGen)
		}
		// Every reader validates this generation before the next commit:
		// collect one ack ≥ wantGen per distinct reader. The snapshot
		// stays at wantGen until the next commit, so spinning readers
		// must observe and ack it — and every publication window is
		// provably sampled by every reader.
		seen := make(map[int]bool, readers)
		deadline := time.After(snapshotAckTimeout)
		for len(seen) < readers {
			select {
			case a := <-acks:
				if a.gen >= wantGen {
					seen[a.reader] = true
				}
			case err := <-errc:
				close(done)
				t.Fatalf("reader failure: %s", err)
			case <-deadline:
				close(done)
				t.Fatalf("timed out waiting for acks ≥ %d (liveness backstop, not a perf assertion)", wantGen)
			}
		}
	}
	close(done)
	wg.Wait()
	gFinal, cFinal := s.ActiveSnapshot()
	if gFinal != finalGen || cFinal == nil || cFinal.System.HostName != "b4" {
		t.Fatalf("final snapshot = (%d,%v), want (%d,b4)", gFinal, cFinal, finalGen)
	}
}

// TestActiveSnapshotPublishCoversEverySwap9905 is the structural backstop:
// every `s.compiled =` assignment in production store files must be
// immediately followed by a publishActiveLocked call. Verified by mutation
// (removing any one publish line fails this test naming the file:line; a
// comment merely mentioning the call does not satisfy it).
func TestActiveSnapshotPublishCoversEverySwap9905(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	dir := filepath.Dir(thisFile)
	// All production store files, not a hardcoded list: an 8th swap in a
	// NEW file must be pinned too, not evade both the check and the count.
	matches, err := filepath.Glob(filepath.Join(dir, "store*.go"))
	if err != nil {
		t.Fatal(err)
	}
	var files []string
	for _, path := range matches {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		files = append(files, filepath.Base(path))
	}
	for _, want := range []string{"store.go", "store_commit.go", "store_persist.go"} {
		known := false
		for _, name := range files {
			if name == want {
				known = true
				break
			}
		}
		if !known {
			t.Fatalf("glob missed known store file %s (glob covers: %v) — guard would be vacuous", want, files)
		}
	}
	swapRE := regexp.MustCompile(`s\.compiled = [^=]`)
	blockRE := regexp.MustCompile(`(?s)/\*.*?\*/`)
	stripBlocks := func(s string) string {
		// Blank block comments to newlines (never delete): line numbers
		// below a multi-line comment must keep matching the file.
		return blockRE.ReplaceAllStringFunc(s, func(m string) string {
			return strings.Repeat("\n", strings.Count(m, "\n"))
		})
	}
	swaps := 0
	for _, name := range files {
		raw, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		lines := strings.Split(stripBlocks(string(raw)), "\n")
		for i, line := range lines {
			// Code lines only: doc comments (including this test's own
			// description of the pattern) must not count as swaps.
			if strings.HasPrefix(strings.TrimSpace(line), "//") || !swapRE.MatchString(line) {
				continue
			}
			swaps++
			reported := false
			for _, next := range lines[i+1:] {
				if strings.TrimSpace(next) == "" {
					continue
				}
				// Strip line comments: a comment merely MENTIONING the
				// call must not satisfy the guard — only real code counts.
				// (No `//` appears inside string literals on these lines.)
				code, _, _ := strings.Cut(next, "//")
				if !strings.Contains(code, "s.publishActiveLocked()") {
					t.Errorf("%s:%d: compiled swap not followed by publish call (next code: %q)", name, i+1, strings.TrimSpace(code))
				}
				reported = true
				break
			}
			if !reported {
				t.Errorf("%s:%d: compiled swap with no following code line (EOF/blank tail)", name, i+1)
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

func TestActiveSnapshotRollbackToNil9905(t *testing.T) {
	// First-commit rollback: the prev target has no compiled config, so
	// the publication is (gen+1, nil) — the exact shape the daemon treats
	// as "no config, withhold" (see the daemon withhold cell).
	s := newTestStore(t)
	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	if err := s.SetFromInput("system host-name First"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CommitConfirmed(1); err != nil {
		t.Fatal(err)
	}
	gConf, _ := s.ActiveSnapshot()
	gen := s.ConfirmGenForTesting()
	prevCfg, ok := s.PromoteRollback(gen)
	if !ok {
		t.Fatal("PromoteRollback: ok=false, want true")
	}
	if prevCfg != nil {
		t.Fatalf("prevCfg = %v, want nil (first commit has no compiled target)", prevCfg)
	}
	gAfter, cAfter := s.ActiveSnapshot()
	if gAfter != gConf+1 || cAfter != nil {
		t.Fatalf("post-rollback snapshot = (%d,%v), want (%d,nil)", gAfter, cAfter, gConf+1)
	}
	if s.ActiveConfig() != nil {
		t.Fatal("ActiveConfig non-nil after nil rollback")
	}
}

func TestActiveSnapshotRecoveryRollback9905(t *testing.T) {
	// Expired-during-downtime recovery: Load publishes the loaded active
	// config (gen 1), then the recovery rollback publishes the prev
	// target (gen 2). The exact count pins BOTH Load-time publishes.
	path := filepath.Join(t.TempDir(), "config")
	_ = armedConfirmStore(t, path, 10)
	forceConfirmDeadlinePast(t, path)
	s := newTestStoreAt(t, path)
	if err := s.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	gen, cfg := s.ActiveSnapshot()
	if gen != 2 || cfg == nil || cfg.System.HostName != "Base" {
		t.Fatalf("post-recovery snapshot = (%d,%v), want (2,Base)", gen, cfg)
	}
	if cfg != s.ActiveConfig() {
		t.Fatal("snapshot cfg != ActiveConfig after recovery")
	}
}

func TestActiveSnapshotRecoveryFirstCommitNil9905(t *testing.T) {
	// First-commit variant: the rollback target is the empty bootstrap
	// tree, so recovery publishes (gen, nil) — the daemon withhold shape.
	path := filepath.Join(t.TempDir(), "config")
	s0 := newTestStoreAt(t, path)
	if err := s0.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	if err := s0.SetFromInput("system host-name First"); err != nil {
		t.Fatal(err)
	}
	if _, err := s0.CommitConfirmed(10); err != nil {
		t.Fatalf("CommitConfirmed: %v", err)
	}
	forceConfirmDeadlinePast(t, path)
	s := newTestStoreAt(t, path)
	if err := s.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	gen, cfg := s.ActiveSnapshot()
	if gen != 2 || cfg != nil {
		t.Fatalf("post-recovery snapshot = (%d,%v), want (2,nil)", gen, cfg)
	}
	if s.ActiveConfig() != nil {
		t.Fatal("ActiveConfig non-nil after nil recovery")
	}
}
