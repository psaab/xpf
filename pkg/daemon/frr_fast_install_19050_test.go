package daemon

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/frr"
	"golang.org/x/sync/semaphore"
)

// #19050 option B cells (design: #19050 issuecomment-6763838572 and the
// v2.1-v2.3 addenda). The frr.Manager half is pinned in
// pkg/frr/fast_install_19050_test.go.

func newFastDaemon19050(t *testing.T) (*Daemon, *frr.RecordingExecutor) {
	t.Helper()
	d, _ := newDemotion18701(t, false, 0)
	rec := &frr.RecordingExecutor{}
	d.frr = frr.NewForTest(filepath.Join(t.TempDir(), "frr.conf"), rec)
	t.Cleanup(d.frr.Stop)
	d.directSendGARPsFn = func(int) {}
	if d.applySem == nil {
		d.applySem = semaphore.NewWeighted(1)
	}
	d.directVIPMu.Lock()
	d.directVIPOwned = map[int]bool{}
	d.directVIPMu.Unlock()
	return d, rec
}

// TestDirectVIPEpochMovesOnlyOnRealEdges19050 (R4 B2): the epoch moves only
// on a real ownership edge, and only a promotion edge triggers the fast
// install. A safety-net re-add of an owned RG moves nothing.
func TestDirectVIPEpochMovesOnlyOnRealEdges19050(t *testing.T) {
	d, _ := newFastDaemon19050(t)
	var mu sync.Mutex
	var triggers []uint64
	d.frrFastInstallFn = func(rg int, epoch uint64) {
		mu.Lock()
		triggers = append(triggers, epoch)
		mu.Unlock()
	}
	d.applyDirectVIPOwnership(1, true, "test")
	d.applyDirectVIPOwnership(1, true, "safety-net")
	d.applyDirectVIPOwnership(1, true, "safety-net")
	if got := d.directVIPEpoch19050(1); got != 1 {
		t.Fatalf("epoch after one promotion and two re-adds = %d, want 1", got)
	}
	d.applyDirectVIPOwnership(1, false, "demote")
	d.applyDirectVIPOwnership(1, false, "safety-net")
	d.applyDirectVIPOwnership(1, true, "promote")
	if got := d.directVIPEpoch19050(1); got != 3 {
		t.Fatalf("epoch after promote/demote/promote = %d, want 3", got)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(triggers) != 2 || triggers[0] != 1 || triggers[1] != 3 {
		t.Fatalf("fast-install triggers = %v, want [1 3] (promotion edges only)", triggers)
	}
}

func baseInputs19050(t *testing.T, d *Daemon) fastInstallInputs19050 {
	t.Helper()
	primeRG1Primary(t, d)
	in := fastInstallInputs19050{
		rgID:     1,
		epoch:    d.bumpDirectVIPEpoch19050(1),
		cfg:      d.store.ActiveConfig(),
		writeGen: d.frr.UnconditionalWriteGeneration(),
		owners:   d.localOwnershipVector19050(),
	}
	if !d.fastInstallPrecheck19050(in) {
		t.Fatalf("premise: the unperturbed pre-check must pass (owners=%v)", in.owners)
	}
	return in
}

// TestFastInstallPrecheckTerms19050: every input of the render is fenced; each
// subtest perturbs exactly ONE term, so each term's mutant has a cell that
// goes red.
func TestFastInstallPrecheckTerms19050(t *testing.T) {
	t.Run("resetting", func(t *testing.T) { // C1 (R14)
		d, _ := newFastDaemon19050(t)
		in := baseInputs19050(t, d)
		d.resetting.Store(true)
		if d.fastInstallPrecheck19050(in) {
			t.Fatal("pre-check passed during a factory reset")
		}
	})
	t.Run("epoch", func(t *testing.T) {
		d, _ := newFastDaemon19050(t)
		in := baseInputs19050(t, d)
		d.bumpDirectVIPEpoch19050(1)
		if d.fastInstallPrecheck19050(in) {
			t.Fatal("pre-check passed after the RG's ownership epoch moved")
		}
	})
	t.Run("is-local-primary", func(t *testing.T) { // R4 B3: the render's own predicate
		d, _ := newFastDaemon19050(t)
		in := baseInputs19050(t, d)
		d.cluster.SetGroupStateForTesting(1, cluster.StateSecondary)
		in.owners = d.localOwnershipVector19050() // the vector agrees; only IsLocalPrimary catches it
		if d.fastInstallPrecheck19050(in) {
			t.Fatal("pre-check passed for an RG this node is not primary for")
		}
	})
	t.Run("active-config", func(t *testing.T) {
		d, _ := newFastDaemon19050(t)
		in := baseInputs19050(t, d)
		in.cfg = &config.Config{}
		if d.fastInstallPrecheck19050(in) {
			t.Fatal("pre-check passed against a config other than the active one")
		}
	})
	t.Run("unconditional-write-generation", func(t *testing.T) { // C1 belt
		d, _ := newFastDaemon19050(t)
		in := baseInputs19050(t, d)
		in.writeGen++
		if d.fastInstallPrecheck19050(in) {
			t.Fatal("pre-check passed after an unconditional FRR write")
		}
	})
	t.Run("ownership-vector", func(t *testing.T) {
		d, _ := newFastDaemon19050(t)
		in := baseInputs19050(t, d)
		other := -1 // another configured RG moves, whichever way it stood
		for rg := range in.owners {
			if rg != 1 {
				other = rg
				break
			}
		}
		if other < 0 {
			t.Fatalf("premise: the fixture needs a second RG, owners=%v", in.owners)
		}
		if in.owners[other] {
			d.cluster.SetGroupStateForTesting(other, cluster.StateSecondary)
		} else {
			d.cluster.SetGroupStateForTesting(other, cluster.StatePrimary)
		}
		if d.fastInstallPrecheck19050(in) {
			t.Fatal("pre-check passed after another RG's ownership changed")
		}
	})
}

// TestFastInstallFencedByFactoryResetInterleave19050 (C1, R14): a promotion
// triggers and renders; a factory reset then raises its flag (and would strip
// the managed section, making every owned static look missing) BEFORE the
// fast install reaches reloadMu. The pre-check must refuse it.
func TestFastInstallFencedByFactoryResetInterleave19050(t *testing.T) {
	d, rec := newFastDaemon19050(t)
	primeRG1Primary(t, d)
	epoch := d.bumpDirectVIPEpoch19050(1)
	if err := d.applySem.Acquire(context.Background(), 1); err != nil {
		t.Fatal(err)
	}
	out := make(chan frr.FastInstallOutcome, 1)
	go func() { out <- d.frrFastInstall19050(1, epoch) }()
	time.Sleep(50 * time.Millisecond) // the install passed its entry checks and waits for applySem
	d.resetting.Store(true)           // the reset raises its flag after the trigger
	d.applySem.Release(1)
	select {
	case got := <-out:
		if got != frr.FastSkipped {
			t.Fatalf("fast install outcome during a factory reset = %v, want skipped by the pre-check", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("fast install did not finish")
	}
	if len(rec.FastInstalls) != 0 {
		t.Fatalf("fast install ran during a factory reset: %q", rec.FastInstalls)
	}
}

// TestFastInstallDoesNotSupersedePendingReload19050 (R4 B4, N2): the fast
// path must not move frrApplySeq or the FRR unconditional write generation,
// or a pending demotion reload's current() turns false and it skips itself.
func TestFastInstallDoesNotSupersedePendingReload19050(t *testing.T) {
	d, _ := newFastDaemon19050(t)
	primeRG1Primary(t, d)
	seq, ugen := d.frrApplySeq.Load(), d.frr.UnconditionalWriteGeneration()
	epoch := d.bumpDirectVIPEpoch19050(1)
	if got := d.frrFastInstall19050(1, epoch); got != frr.FastNothingToDo && got != frr.FastInstalled {
		t.Fatalf("premise: the fast install must reach the FRR manager, got %v", got)
	}
	if d.frrApplySeq.Load() != seq || d.frr.UnconditionalWriteGeneration() != ugen {
		t.Fatalf("fast install moved the HA reload's currency tokens: frrApplySeq %d->%d unconditionalWriteGen %d->%d",
			seq, d.frrApplySeq.Load(), ugen, d.frr.UnconditionalWriteGeneration())
	}
}

// TestFastInstallLockOrderCanary19050 (N1, R14): an applier holding applySem
// and writing FRR (commit order: applySem -> reloadMu) completes while fast
// installs run (fast order: applySem released -> reloadMu -> cluster lock /
// epoch leaf). A cycle would hang here.
func TestFastInstallLockOrderCanary19050(t *testing.T) {
	d, _ := newFastDaemon19050(t)
	primeRG1Primary(t, d)
	done := make(chan struct{})
	go func() {
		defer close(done)
		var wg sync.WaitGroup
		for i := 0; i < 20; i++ {
			wg.Add(2)
			go func() {
				defer wg.Done()
				d.frrFastInstall19050(1, d.bumpDirectVIPEpoch19050(1))
			}()
			go func() {
				defer wg.Done()
				if err := d.applySem.Acquire(context.Background(), 1); err != nil {
					return
				}
				_ = d.frr.ApplyFullIfCurrent(&frr.FullConfig{}, func() bool { return true })
				d.applySem.Release(1)
			}()
		}
		wg.Wait()
	}()
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		t.Fatal("lock-order canary hung: fast install and an applySem-holding FRR writer deadlocked")
	}
}

// TestDirectVIPAddPrimitiveCensus19050 (C2, R14): every caller of the VIP-add
// PRIMITIVE (reconcileDirectVIPAddrs(_, true), reached through directAddVIPs)
// is classified. A new caller fails the census until it is classified: either
// it goes through the promotion hook, or it is shown not to consume the
// ownership edge.
func TestDirectVIPAddPrimitiveCensus19050(t *testing.T) {
	allow := map[string]string{
		"directAddVIPs":               "the primitive's own wrapper",
		"addDirectVIPs":               "the hook: applyDirectVIPOwnershipWith's add (test seam wrapper)",
		"reconcileAfterRethLinkCycle": "link-cycle re-add of an OWNED RG: writes neither directVIPOwned nor the epoch",
	}
	got := map[string]bool{}
	files, _ := filepath.Glob("*.go")
	sort.Strings(files)
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, f, src, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", f, err)
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				switch sel.Sel.Name {
				case "directAddVIPs":
				case "reconcileDirectVIPAddrs":
					if len(call.Args) != 2 {
						return true
					}
					if id, ok := call.Args[1].(*ast.Ident); !ok || id.Name != "true" {
						return true
					}
				default:
					return true
				}
				got[fn.Name.Name] = true
				if _, ok := allow[fn.Name.Name]; !ok {
					t.Errorf("%s: %s calls the VIP-add primitive %s outside the classified callers; route it through applyDirectVIPOwnershipWith or classify it in this census (#19050 C2)",
						fset.Position(call.Pos()), fn.Name.Name, sel.Sel.Name)
				}
				return true
			})
		}
	}
	for name := range allow {
		if !got[name] {
			t.Errorf("census allowlist entry %q no longer calls the primitive; the census rotted (update it)", name)
		}
	}
}
