package daemon

import (
	"context"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
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
		owners:   newOwnershipRecorder19050(d.cluster),
	}
	in.owners.IsLocalPrimary(1)
	d.assembleFRRConfigForActiveConfigOwned(in.cfg, nil, in.owners) // the render records its reads
	if !d.fastInstallPrecheck19050(in) {
		t.Fatalf("premise: the unperturbed pre-check must pass (reads=%v)", in.owners.reads)
	}
	return in
}

// baseABAInputs19050 is baseInputs19050 on the multi-RG fixture: RG1 primary
// (the trigger), RG2 secondary and read by the render (it owns reth1), RG0
// primary and read by the render (globalActive), RG3 owning nothing and so
// never read.
func baseABAInputs19050(t *testing.T) (*Daemon, *cluster.Manager, fastInstallInputs19050) {
	t.Helper()
	d, _, cm := newABADaemon19050(t)
	cm.SetGroupStateForTesting(1, cluster.StatePrimary)
	in := fastInstallInputs19050{
		rgID:     1,
		epoch:    d.bumpDirectVIPEpoch19050(1),
		cfg:      d.store.ActiveConfig(),
		writeGen: d.frr.UnconditionalWriteGeneration(),
		owners:   newOwnershipRecorder19050(cm),
	}
	in.owners.IsLocalPrimary(1)
	d.assembleFRRConfigForActiveConfigOwned(in.cfg, nil, in.owners)
	for _, rg := range []int{0, 1, 2} {
		if _, ok := in.owners.reads[rg]; !ok {
			t.Fatalf("premise: the render must read RG%d, reads=%v", rg, in.owners.reads)
		}
	}
	if _, ok := in.owners.reads[3]; ok {
		t.Fatalf("premise: the render must not read RG3, which owns nothing, reads=%v", in.owners.reads)
	}
	if !d.fastInstallPrecheck19050(in) {
		t.Fatalf("premise: the unperturbed pre-check must pass (reads=%v)", in.owners.reads)
	}
	return d, cm, in
}

// TestFastInstallPrecheckTerms19050: every input of the render is fenced; each
// subtest perturbs exactly ONE term, so each term's mutant has a cell that
// goes red. The mastership subtests cover the review's ABA (Codex P1-1): a
// contributing RG that moves and moves BACK reads the same boolean, so only
// its monotonic mastership generation shows the move.
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
		in.owners = newOwnershipRecorder19050(d.cluster)
		in.owners.IsLocalPrimary(1) // the recorded reads agree; only the primary term catches it
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
	t.Run("trigger-rg-mastership-aba", func(t *testing.T) { // Codex P1-1, the trigger RG itself
		d, _ := newFastDaemon19050(t)
		in := baseInputs19050(t, d)
		d.cluster.SetGroupStateForTesting(1, cluster.StateSecondary)
		d.cluster.SetGroupStateForTesting(1, cluster.StatePrimary)
		if d.fastInstallPrecheck19050(in) {
			t.Fatal("pre-check passed after the trigger RG went primary -> secondary -> primary")
		}
	})
	t.Run("other-rg-mastership", func(t *testing.T) {
		d, cm, in := baseABAInputs19050(t)
		cm.SetGroupStateForTesting(2, cluster.StatePrimary)
		if d.fastInstallPrecheck19050(in) {
			t.Fatal("pre-check passed after another contributing RG's ownership changed")
		}
	})
	t.Run("other-rg-mastership-aba", func(t *testing.T) { // Codex P1-1: the vector of booleans is blind to this
		d, cm, in := baseABAInputs19050(t)
		cm.SetGroupStateForTesting(2, cluster.StatePrimary)
		cm.SetGroupStateForTesting(2, cluster.StateSecondary) // and back: the boolean reads the same
		if cm.IsLocalPrimary(2) {
			t.Fatal("premise: RG2 must read secondary again")
		}
		if d.fastInstallPrecheck19050(in) {
			t.Fatal("pre-check passed after another contributing RG moved and moved back (ABA)")
		}
	})
	t.Run("rg0-mastership", func(t *testing.T) { // Codex on 11e4c6f47e: RG0 reaches statics via IS-IS
		d, cm, in := baseABAInputs19050(t)
		cm.SetGroupStateForTesting(0, cluster.StateSecondary)
		if d.fastInstallPrecheck19050(in) {
			t.Fatal("pre-check passed after RG0, which the render read, moved")
		}
	})
	t.Run("rg0-mastership-aba", func(t *testing.T) {
		d, cm, in := baseABAInputs19050(t)
		cm.SetGroupStateForTesting(0, cluster.StateSecondary)
		cm.SetGroupStateForTesting(0, cluster.StatePrimary)
		if d.fastInstallPrecheck19050(in) {
			t.Fatal("pre-check passed after RG0 moved and moved back (ABA)")
		}
	})
	t.Run("unread-rg-moves", func(t *testing.T) { // scope: RG3 owns nothing; the render never read it
		d, cm, in := baseABAInputs19050(t)
		cm.SetGroupStateForTesting(3, cluster.StateSecondary)
		if !d.fastInstallPrecheck19050(in) {
			t.Fatal("pre-check refused because RG3, which the render never read, moved")
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

// abaClusterSet19050 is a multi-RG cluster: reth0 (RG1, the WAN default),
// reth1 (RG2, a LAN static), and RG3, which owns nothing. reth1 carries a
// bandwidth so the render
// consults frrTunnelNameMapFn, which the ABA cell uses as a hook inside the
// render, AFTER the render has read RG ownership.
const abaClusterSet19050 = "" +
	"set chassis cluster cluster-id 1\n" +
	"set chassis cluster node 0\n" +
	"set chassis cluster reth-count 2\n" +
	"set chassis cluster redundancy-group 0 node 0 priority 200\n" +
	"set chassis cluster redundancy-group 0 node 1 priority 100\n" +
	"set chassis cluster redundancy-group 1 node 0 priority 200\n" +
	"set chassis cluster redundancy-group 1 node 1 priority 100\n" +
	"set chassis cluster redundancy-group 2 node 0 priority 200\n" +
	"set chassis cluster redundancy-group 2 node 1 priority 100\n" +
	"set chassis cluster redundancy-group 3 node 0 priority 200\n" +
	"set chassis cluster redundancy-group 3 node 1 priority 100\n" +
	"set chassis cluster authentication-key test-cluster-psk-6611\n" +
	"set chassis cluster control-interface em0\n" +
	"set chassis cluster peer-address 10.99.0.2\n" +
	"set interfaces em0 unit 0 family inet address 10.99.0.1/24\n" +
	"set interfaces ge-0/0/1 gigether-options redundant-parent reth1\n" +
	"set interfaces ge-0/0/2 gigether-options redundant-parent reth0\n" +
	"set interfaces reth0 redundant-ether-options redundancy-group 1\n" +
	"set interfaces reth0 unit 0 family inet address 172.16.50.8/24\n" +
	"set interfaces reth1 redundant-ether-options redundancy-group 2\n" +
	"set interfaces reth1 bandwidth 1g\n" +
	"set interfaces reth1 unit 0 family inet address 10.0.61.1/24\n" +
	"set routing-options static route 0.0.0.0/0 next-hop 172.16.50.1\n" +
	"set routing-options static route 198.51.100.0/24 next-hop 10.0.61.254\n"

const (
	abaRG1Line19050 = "ip route 0.0.0.0/0 172.16.50.1"
	abaRG2Line19050 = "ip route 198.51.100.0/24 10.0.61.254"
)

// newABADaemon19050 is a settled standby for RG1 and RG2: both secondary, and
// a managed section (written by a real conditional HA apply) with neither
// RETH static. RG0 stays primary.
func newABADaemon19050(t *testing.T) (*Daemon, *frr.RecordingExecutor, *cluster.Manager) {
	t.Helper()
	d, rec := newFastDaemon19050(t)
	d.store = fenceTestStore(t, abaClusterSet19050)
	cfg := d.store.ActiveConfig()
	cm := cluster.NewManager(0, 1)
	cm.UpdateConfig(cfg.Chassis.Cluster)
	for drained := true; drained; {
		select {
		case <-cm.Events():
		default:
			drained = false
		}
	}
	d.cluster = cm
	cm.SetGroupStateForTesting(0, cluster.StatePrimary)
	cm.SetGroupStateForTesting(1, cluster.StateSecondary)
	cm.SetGroupStateForTesting(2, cluster.StateSecondary)
	cm.SetGroupStateForTesting(3, cluster.StatePrimary)
	if err := d.frr.ApplyFullIfCurrent(d.assembleFRRConfig(cfg, nil), func() bool { return true }); err != nil {
		t.Fatalf("settled standby apply: %v", err)
	}
	return d, rec, cm
}

func fastInstalled19050(rec *frr.RecordingExecutor, prefix string) bool {
	for _, batch := range rec.FastInstalls {
		for _, l := range batch {
			if strings.HasPrefix(l, prefix) {
				return true
			}
		}
	}
	return false
}

// hookRender19050 runs fn once, inside the next render that consults
// frrTunnelNameMapFn (after that render read RG ownership).
func hookRender19050(t *testing.T, fn func()) *atomic.Bool {
	t.Helper()
	orig := frrTunnelNameMapFn
	var fired atomic.Bool
	frrTunnelNameMapFn = func(c *config.Config) map[string]string {
		if fired.CompareAndSwap(false, true) {
			fn()
		}
		return orig(c)
	}
	t.Cleanup(func() { frrTunnelNameMapFn = orig })
	return &fired
}

// runFastInstallAfter19050 starts the fast install for rg while the test holds
// applySem, so its inputs are captured first; then runs between() and
// releases applySem, so the render happens after between().
func runFastInstallAfter19050(t *testing.T, d *Daemon, rg int, epoch uint64, between func()) frr.FastInstallOutcome {
	t.Helper()
	if err := d.applySem.Acquire(context.Background(), 1); err != nil {
		t.Fatal(err)
	}
	out := make(chan frr.FastInstallOutcome, 1)
	go func() { out <- d.frrFastInstall19050(rg, epoch) }()
	time.Sleep(100 * time.Millisecond) // the install captured its inputs and waits for applySem
	between()
	d.applySem.Release(1)
	select {
	case got := <-out:
		return got
	case <-time.After(10 * time.Second):
		t.Fatal("fast install did not finish")
		return frr.FastRefused
	}
}

// TestFastInstallRefusesAnotherRGsABA19050 is review Codex P1-1's probe. RG1
// (A) promotes and triggers with RG2 (B) secondary. B promotes before the
// render, so the render includes B's static; during the render B demotes
// again and its HA reload completes (writing A's static, not B's). The
// ownership booleans now read exactly as at the capture, and A's epoch never
// moved, so a pre-check comparing them passes and the subtraction selects
// precisely B's now-removed line, which nothing would remove. B's line must
// never be fast-installed.
func TestFastInstallRefusesAnotherRGsABA19050(t *testing.T) {
	d, rec, cm := newABADaemon19050(t)
	cfg := d.store.ActiveConfig()
	cm.SetGroupStateForTesting(1, cluster.StatePrimary) // A promotes: the trigger
	epoch := d.bumpDirectVIPEpoch19050(1)
	var renderSawB bool
	fired := hookRender19050(t, func() {
		renderSawB = cm.IsLocalPrimary(2)
		cm.SetGroupStateForTesting(2, cluster.StateSecondary) // B demotes again
		// ... and B's demotion reload completes before the fast install
		// reaches reloadMu.
		if err := d.frr.ApplyFullIfCurrent(d.assembleFRRConfig(cfg, nil), func() bool { return true }); err != nil {
			t.Errorf("B's demotion reload: %v", err)
		}
	})
	got := runFastInstallAfter19050(t, d, 1, epoch, func() {
		cm.SetGroupStateForTesting(2, cluster.StatePrimary) // B promotes after the capture
	})
	if !fired.Load() || !renderSawB {
		t.Fatalf("premise: the render must run the hook (%v) and see B primary (%v)", fired.Load(), renderSawB)
	}
	if fastInstalled19050(rec, abaRG2Line19050) {
		t.Fatalf("outcome %v: B's static was fast-installed after B's own demotion reload removed it: %q", got, rec.FastInstalls)
	}
}

// TestFastInstallNotFencedByNonContributingRG19050: the positive control for
// the cell above, and the scope claim. With no ABA the install reaches FRR
// and installs A's line only. RG3 owns nothing and the render never reads its
// ownership, so RG3 moving during the render must not cost A its fast install.
// (RG0 IS read, through globalActive: see the IS-IS cell below.)
func TestFastInstallNotFencedByNonContributingRG19050(t *testing.T) {
	d, rec, cm := newABADaemon19050(t)
	cm.SetGroupStateForTesting(1, cluster.StatePrimary)
	epoch := d.bumpDirectVIPEpoch19050(1)
	hookRender19050(t, func() {
		cm.SetGroupStateForTesting(3, cluster.StateSecondary) // a net move, not an ABA
	})
	got := runFastInstallAfter19050(t, d, 1, epoch, func() {})
	if got != frr.FastInstalled || !fastInstalled19050(rec, abaRG1Line19050) {
		t.Fatalf("outcome %v installs %q, want A's default fast-installed", got, rec.FastInstalls)
	}
	if fastInstalled19050(rec, abaRG2Line19050) {
		t.Fatalf("B's static installed while B is secondary: %q", rec.FastInstalls)
	}
}

// TestFastInstallNeverCallsTransferReadiness19050 is review Codex P2-4's
// probe. GroupStates() runs the transfer-readiness callback, which in
// production can import routes and query FRR; the pre-check runs under the
// FRR manager's reloadMu, outside the fast install's own bound. Capturing and
// checking ownership must never invoke it.
func TestFastInstallNeverCallsTransferReadiness19050(t *testing.T) {
	d, _ := newFastDaemon19050(t)
	primeRG1Primary(t, d)
	release := make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	t.Cleanup(unblock)
	var calls atomic.Int32
	d.cluster.SetTransferReadinessFunc(func(int) (bool, []string) {
		calls.Add(1)
		<-release
		return true, nil
	})
	out := make(chan frr.FastInstallOutcome, 1)
	go func() { out <- d.frrFastInstall19050(1, d.bumpDirectVIPEpoch19050(1)) }()
	select {
	case got := <-out:
		if got != frr.FastInstalled && got != frr.FastNothingToDo {
			t.Fatalf("premise: the install must reach the FRR manager, got %v", got)
		}
	case <-time.After(5 * time.Second):
		unblock()
		t.Fatalf("the fast install blocked in the transfer-readiness callback (%d calls)", calls.Load())
	}
	if n := calls.Load(); n != 0 {
		t.Fatalf("the fast install invoked the transfer-readiness callback %d times", n)
	}
}

// isisRG0Config19050 is the review's lenient shape (Codex on 11e4c6f47e): a
// non-RETH IS-IS interface (ge-0/0/3, following RG0 through globalActive) and
// a preference-50 static via the RG1 RETH gateway. Strict commit rejects a
// static between Junos IS-IS 15/18 and FRR's fixed 115 (#17735); a lenient
// load keeps it, and the render withholds the static exactly while IS-IS has
// an interface, that is while RG0 is primary here. ge-0/0/3 carries a
// bandwidth so the render consults frrTunnelNameMapFn (the hook).
const isisRG0Config19050 = `chassis {
    cluster {
        cluster-id 1;
        node 0;
        reth-count 1;
        redundancy-group 0 {
            node 0 priority 200;
            node 1 priority 100;
        }
        redundancy-group 1 {
            node 0 priority 200;
            node 1 priority 100;
        }
        authentication-key test-cluster-psk-6611;
        control-interface em0;
        peer-address 10.99.0.2;
    }
}
interfaces {
    em0 {
        unit 0 {
            family inet {
                address 10.99.0.1/24;
            }
        }
    }
    ge-0/0/2 {
        gigether-options {
            redundant-parent reth0;
        }
    }
    ge-0/0/3 {
        bandwidth 1g;
        unit 0 {
            family inet {
                address 192.0.2.1/24;
            }
        }
    }
    reth0 {
        redundant-ether-options {
            redundancy-group 1;
        }
        unit 0 {
            family inet {
                address 172.16.50.8/24;
            }
        }
    }
}
routing-options {
    static {
        route 198.51.100.0/24 {
            next-hop 172.16.50.1;
            preference 50;
        }
    }
}
protocols {
    isis {
        net 49.0001.0100.0000.0001.00;
        interface ge-0/0/3;
    }
}
`

const isisGuardedLine19050 = "ip route 198.51.100.0/24 172.16.50.1 50"

// TestFastInstallFencesRG0ThroughISISDistanceGuard19050 is the review's
// interleaving (Codex on 11e4c6f47e). RG1 promotes and triggers with RG0
// secondary, so its fast render keeps the preference-50 static (IS-IS has no
// interface). During that render RG0 promotes and RG0's reload completes: IS-IS
// gains ge-0/0/3 and the reload withholds the static. RG0 owns no RETH, so a
// fence of RETH owners passes, and the fast install re-installs the static the
// authoritative render withheld, with nothing left to remove it.
func TestFastInstallFencesRG0ThroughISISDistanceGuard19050(t *testing.T) {
	d, rec := newFastDaemon19050(t)
	d.store = newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if _, err := d.store.SyncApply(isisRG0Config19050, nil); err != nil {
		t.Fatalf("lenient load: %v", err)
	}
	cfg := d.store.ActiveConfig()
	cm := cluster.NewManager(0, 1)
	cm.UpdateConfig(cfg.Chassis.Cluster)
	for drained := true; drained; {
		select {
		case <-cm.Events():
		default:
			drained = false
		}
	}
	d.cluster = cm
	cm.SetGroupStateForTesting(0, cluster.StateSecondary)
	cm.SetGroupStateForTesting(1, cluster.StateSecondary)
	if err := d.frr.ApplyFullIfCurrent(d.assembleFRRConfig(cfg, nil), func() bool { return true }); err != nil {
		t.Fatalf("settled apply: %v", err)
	}
	// Positive control on the render: with RG0 primary the guard withholds the
	// static, with RG0 secondary it renders.
	cm.SetGroupStateForTesting(1, cluster.StatePrimary)
	cm.SetGroupStateForTesting(0, cluster.StatePrimary)
	if lines := strings.Join(d.frr.RenderStaticLines(d.assembleFRRConfig(cfg, nil)), "|"); strings.Contains(lines, isisGuardedLine19050) {
		t.Fatalf("premise: with RG0 primary the IS-IS guard must withhold %q, got %q", isisGuardedLine19050, lines)
	}
	cm.SetGroupStateForTesting(0, cluster.StateSecondary)
	if lines := strings.Join(d.frr.RenderStaticLines(d.assembleFRRConfig(cfg, nil)), "|"); !strings.Contains(lines, isisGuardedLine19050) {
		t.Fatalf("premise: with RG0 secondary the static must render, got %q", lines)
	}
	epoch := d.bumpDirectVIPEpoch19050(1)
	var renderSawRG0Secondary bool
	fired := hookRender19050(t, func() {
		renderSawRG0Secondary = !cm.IsLocalPrimary(0)
		cm.SetGroupStateForTesting(0, cluster.StatePrimary) // RG0 promotes
		// ... and RG0's HA reload completes, withholding the static.
		if err := d.frr.ApplyFullIfCurrent(d.assembleFRRConfig(cfg, nil), func() bool { return true }); err != nil {
			t.Errorf("RG0's reload: %v", err)
		}
	})
	got := d.frrFastInstall19050(1, epoch)
	if !fired.Load() || !renderSawRG0Secondary {
		t.Fatalf("premise: the render must run the hook (%v) with RG0 secondary (%v)", fired.Load(), renderSawRG0Secondary)
	}
	if fastInstalled19050(rec, "ip route 198.51.100.0/24") {
		t.Fatalf("outcome %v: the static RG0's authoritative render withholds was fast-installed: %q", got, rec.FastInstalls)
	}
}

// TestMastershipGenerationKnown19050 pins the cluster property the recorder's
// LocalGroupPrimary relies on: a known group's mastership generation is never
// 0 and an unknown group's always is, so (primary, gen != 0) is exactly
// cluster.LocalGroupPrimary's (primary, known), read under one lock.
func TestMastershipGenerationKnown19050(t *testing.T) {
	d, _, cm := newABADaemon19050(t)
	_ = d
	for _, rg := range []int{0, 1, 2, 3, 7} {
		primary, gen := cm.LocalMastershipSnapshot(rg)
		p2, known := cm.LocalGroupPrimary(rg)
		if (gen != 0) != known || primary != p2 {
			t.Errorf("RG%d: snapshot (primary=%v gen=%d) disagrees with LocalGroupPrimary (primary=%v known=%v)", rg, primary, gen, p2, known)
		}
	}
	if _, known := cm.LocalGroupPrimary(7); known {
		t.Fatal("premise: RG7 must be unknown")
	}
}

// newFRRHADemotionState is a TEST helper: production builds the render state
// only through newFRRHADemotionStateFrom, called once from
// assembleFRRConfigOwned (TestFRRRenderOwnershipReadsCensus19050). Older cells
// still build it from a daemon's live cluster manager.
func newFRRHADemotionState(d *Daemon, cfg *config.Config) *frrHADemotionState {
	if d == nil || d.cluster == nil {
		return nil
	}
	return newFRRHADemotionStateFrom(d.cluster, cfg)
}

// ownershipAccessors19050 are the cluster-ownership reads the render could
// make. Outside the frrHAOwnership argument none may appear in render code.
var ownershipAccessors19050 = map[string]bool{
	"IsLocalPrimary": true, "LocalGroupPrimary": true, "IsLocalPrimaryAny": true,
	"GroupState": true, "GroupStates": true, "LocalMastershipSnapshot": true,
	"IsPeerPrimary": true, "LocalPriorities": true, "WithLocalMastershipSnapshot": true,
}

// renderOwnershipViolations19050 checks the package's non-test sources (file
// name -> content) for every way the FRR render could read cluster ownership
// other than through its frrHAOwnership argument, so that the #19050 fast
// install's recorder sees every ownership read its render makes:
//   - R1: frrHADemotionState is constructed (composite literal) only inside
//     newFRRHADemotionStateFrom;
//   - R2: newFRRHADemotionStateFrom is called only from
//     assembleFRRConfigOwned, with the identifier `own` as its ownership;
//   - R3: inside assembleFRRConfigOwned, `own` is assigned only from
//     d.cluster (the nil default);
//   - R4: following in-package calls by name (an over-approximation: a name
//     reaches every declaration with it) from the render's entry points, no
//     reachable function writes an ownership field (active, globalActive)
//     outside the constructor, touches .cluster other than in a nil check or
//     the R3 default, or calls an ownership accessor on anything but `own`.
//     The recorder's own methods are the recording path and are exempt.
func renderOwnershipViolations19050(srcs map[string]string) ([]string, error) {
	fset := token.NewFileSet()
	funcs := map[string][]*ast.FuncDecl{}
	var violations []string
	report := func(pos token.Pos, format string, args ...any) {
		violations = append(violations, fset.Position(pos).String()+": "+fmt.Sprintf(format, args...))
	}
	names := make([]string, 0, len(srcs))
	for name := range srcs {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		file, err := parser.ParseFile(fset, name, srcs[name], 0)
		if err != nil {
			return nil, err
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			funcs[fn.Name.Name] = append(funcs[fn.Name.Name], fn)
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				switch x := n.(type) {
				case *ast.CompositeLit: // R1
					t := x.Type
					if id, ok := t.(*ast.Ident); ok && id.Name == "frrHADemotionState" && fn.Name.Name != "newFRRHADemotionStateFrom" {
						report(x.Pos(), "R1: %s constructs frrHADemotionState; only newFRRHADemotionStateFrom may", fn.Name.Name)
					}
				case *ast.CallExpr: // R2
					if id, ok := x.Fun.(*ast.Ident); ok && id.Name == "newFRRHADemotionStateFrom" {
						if fn.Name.Name != "assembleFRRConfigOwned" {
							report(x.Pos(), "R2: %s calls newFRRHADemotionStateFrom; only assembleFRRConfigOwned may", fn.Name.Name)
						} else if arg, ok := x.Args[0].(*ast.Ident); !ok || arg.Name != "own" {
							report(x.Pos(), "R2: newFRRHADemotionStateFrom's ownership is not the `own` argument")
						}
					}
				}
				return true
			})
		}
	}
	roots := append(append([]*ast.FuncDecl(nil), funcs["assembleFRRConfigForActiveConfigOwned"]...), funcs["assembleFRRConfigOwned"]...)
	if len(funcs["assembleFRRConfigOwned"]) != 1 || len(funcs["assembleFRRConfigForActiveConfigOwned"]) != 1 || len(funcs["newFRRHADemotionStateFrom"]) != 1 {
		return nil, fmt.Errorf("census roots missing: the render entry points or the constructor were renamed")
	}
	recorderMethod := func(fn *ast.FuncDecl) bool {
		if fn.Recv == nil || len(fn.Recv.List) != 1 {
			return false
		}
		star, ok := fn.Recv.List[0].Type.(*ast.StarExpr)
		if !ok {
			return false
		}
		id, ok := star.X.(*ast.Ident)
		return ok && id.Name == "ownershipRecorder19050"
	}
	seen := map[*ast.FuncDecl]bool{}
	for queue := roots; len(queue) > 0; {
		fn := queue[0]
		queue = queue[1:]
		if seen[fn] || recorderMethod(fn) {
			continue
		}
		seen[fn] = true
		allowed := map[*ast.SelectorExpr]bool{} // nil checks and the R3 default
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.BinaryExpr:
				if x.Op == token.EQL || x.Op == token.NEQ {
					for _, pair := range [][2]ast.Expr{{x.X, x.Y}, {x.Y, x.X}} {
						if id, ok := pair[1].(*ast.Ident); ok && id.Name == "nil" {
							if sel, ok := pair[0].(*ast.SelectorExpr); ok {
								allowed[sel] = true
							}
						}
					}
				}
			case *ast.AssignStmt:
				for i, lhs := range x.Lhs {
					if id, ok := lhs.(*ast.Ident); ok && id.Name == "own" && fn.Name.Name == "assembleFRRConfigOwned" {
						sel, ok := x.Rhs[i].(*ast.SelectorExpr)
						if !ok || sel.Sel.Name != "cluster" {
							report(x.Pos(), "R3: `own` is assigned from something other than the d.cluster default")
						} else {
							allowed[sel] = true
						}
						continue
					}
					target := lhs
					if ix, ok := target.(*ast.IndexExpr); ok {
						target = ix.X
					}
					if sel, ok := target.(*ast.SelectorExpr); ok && (sel.Sel.Name == "active" || sel.Sel.Name == "globalActive") && fn.Name.Name != "newFRRHADemotionStateFrom" {
						report(x.Pos(), "R4: %s writes the ownership field %s outside the constructor", fn.Name.Name, sel.Sel.Name)
					}
				}
			case *ast.SelectorExpr:
				if x.Sel.Name == "cluster" && !allowed[x] {
					report(x.Pos(), "R4: %s (reachable from the render) touches .cluster", fn.Name.Name)
				}
			case *ast.CallExpr:
				name := ""
				switch f := x.Fun.(type) {
				case *ast.Ident:
					name = f.Name
				case *ast.SelectorExpr:
					name = f.Sel.Name
					if ownershipAccessors19050[name] {
						if id, ok := f.X.(*ast.Ident); !ok || id.Name != "own" {
							report(x.Pos(), "R4: %s (reachable from the render) calls %s outside frrHAOwnership", fn.Name.Name, name)
						}
					}
				}
				queue = append(queue, funcs[name]...)
			case *ast.Ident: // function values passed around
				queue = append(queue, funcs[x.Name]...)
			}
			return true
		})
	}
	if ctor := funcs["newFRRHADemotionStateFrom"][0]; !seen[ctor] {
		report(ctor.Pos(), "R2: the render no longer builds its state through newFRRHADemotionStateFrom")
	}
	return violations, nil
}

func daemonSources19050(t *testing.T) map[string]string {
	t.Helper()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		out[f] = string(b)
	}
	return out
}

// TestFRRRenderOwnershipReadsCensus19050: the fast install's fence is the set
// of ownership reads recorded during its render, so the render must read
// cluster ownership ONLY through its frrHAOwnership argument
// (renderOwnershipViolations19050 states the rules).
func TestFRRRenderOwnershipReadsCensus19050(t *testing.T) {
	v, err := renderOwnershipViolations19050(daemonSources19050(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range v {
		t.Error(line)
	}
}

// TestFRRRenderOwnershipCensusSeesBypasses19050: the census reports each
// bypass shape the review named (Codex on d80962db72) and its siblings,
// injected into the real sources. A census that cannot see them is a cell
// with the right name and no power.
func TestFRRRenderOwnershipCensusSeesBypasses19050(t *testing.T) {
	const ctor = "haState := newFRRHADemotionStateFrom(own, cfg)"
	const ret = "\treturn d.assembleFRRConfigOwned(cfg, overlay, current, peerCfg, own)"
	cases := []struct {
		name          string
		file, old, nw string
		extra         string // appended to daemon_ipmon.go
		want          string // the rule that must name it
	}{
		{"recorded-branch-calls-live-constructor", "daemon_ipmon.go", ctor,
			"haState := newFRRHADemotionStateFrom(d.cluster, cfg)", "", "R2: newFRRHADemotionStateFrom's ownership is not"},
		{"wrapper-reintroduced", "daemon_ipmon.go", ctor, "haState := newFRRHADemotionStateLive(d, cfg)",
			"\nfunc newFRRHADemotionStateLive(d *Daemon, cfg *config.Config) *frrHADemotionState {\n\treturn newFRRHADemotionStateFrom(d.cluster, cfg)\n}\n", "R2: newFRRHADemotionStateLive calls"},
		{"caller-precomputed-ownership", "daemon_ipmon.go", ret,
			"\tif d.cluster.IsLocalPrimary(1) {\n\t\toverlay = nil\n\t}\n" + ret, "", "R4: assembleFRRConfigForActiveConfigOwned (reachable from the render) calls IsLocalPrimary"},
		{"field-patched-after-construction", "daemon_ipmon.go", ctor,
			ctor + "\n\tif haState != nil {\n\t\thaState.globalActive = d.renderPrimaryAny19050()\n\t}", "\nfunc (d *Daemon) renderPrimaryAny19050() bool { return true }\n", "R4: assembleFRRConfigOwned writes the ownership field globalActive"},
		{"helper-reads-ownership", "daemon_ipmon.go", ret,
			"\t_ = d.renderOwnerHelper19050()\n" + ret,
			"\nfunc (d *Daemon) renderOwnerHelper19050() bool { return d.cluster.IsLocalPrimaryAny() }\n", "R4: renderOwnerHelper19050 (reachable from the render)"},
		{"accessor-through-another-variable", "daemon_ipmon.go", ret,
			"\tc := d.cluster\n\t_ = c\n" + ret, "", "R4: assembleFRRConfigForActiveConfigOwned (reachable from the render) touches .cluster"},
		{"literal-construction", "daemon_ipmon.go", ctor,
			"haState := &frrHADemotionState{active: map[int]bool{}}", "", "R1: assembleFRRConfigOwned constructs"},
		{"own-assigned-from-elsewhere", "daemon_ipmon.go", ctor,
			"own = d.store\n\t" + ctor, "", "R3:"},
	}
	base := daemonSources19050(t)
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srcs := map[string]string{}
			for k, v := range base {
				srcs[k] = v
			}
			if n := strings.Count(srcs[c.file], c.old); n != 1 {
				t.Fatalf("premise: anchor %q occurs %d times in %s", c.old, n, c.file)
			}
			srcs[c.file] = strings.Replace(srcs[c.file], c.old, c.nw, 1) + c.extra
			v, err := renderOwnershipViolations19050(srcs)
			if err != nil {
				t.Fatalf("census refused the injected source: %v", err)
			}
			if len(v) == 0 {
				t.Fatal("the census reported nothing for this bypass")
			}
			if all := strings.Join(v, "\n"); !strings.Contains(all, c.want) {
				t.Fatalf("no violation names %q; got:\n%s", c.want, all)
			}
		})
	}
}

// TestOwnershipRecorderFirstReadWins19050: an RG read twice at different
// states (it moved between the reads, so one render saw two ownerships) must
// fail the fence even when the second read matches the present. Recording the
// LAST read would pass it. An end-to-end render cannot stage a flip between
// two reads of one RG, so the recorder's rule is pinned here.
func TestOwnershipRecorderFirstReadWins19050(t *testing.T) {
	_, _, cm := newABADaemon19050(t)
	r := newOwnershipRecorder19050(cm)
	r.IsLocalPrimary(2) // secondary
	cm.SetGroupStateForTesting(2, cluster.StatePrimary)
	cm.SetGroupStateForTesting(2, cluster.StateSecondary)
	r.IsLocalPrimary(2) // secondary again, at a newer generation
	if r.current() {
		t.Fatal("an RG read at two generations passed the fence")
	}
	fresh := newOwnershipRecorder19050(cm)
	fresh.IsLocalPrimary(2)
	if !fresh.current() {
		t.Fatal("premise: an unmoved RG must pass the fence")
	}
}
