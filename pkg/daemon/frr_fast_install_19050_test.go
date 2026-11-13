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
	}
	in.mastership = d.contributingMastership19050(in.cfg, 1)
	if !d.fastInstallPrecheck19050(in) {
		t.Fatalf("premise: the unperturbed pre-check must pass (mastership=%v)", in.mastership)
	}
	return in
}

// baseABAInputs19050 is baseInputs19050 on the two-data-RG fixture: RG1
// primary (the trigger), RG2 secondary and CONTRIBUTING (it owns reth1, whose
// static the render reads), RG0 primary and not contributing.
func baseABAInputs19050(t *testing.T) (*Daemon, *cluster.Manager, fastInstallInputs19050) {
	t.Helper()
	d, _, cm := newABADaemon19050(t)
	cm.SetGroupStateForTesting(1, cluster.StatePrimary)
	in := fastInstallInputs19050{
		rgID:     1,
		epoch:    d.bumpDirectVIPEpoch19050(1),
		cfg:      d.store.ActiveConfig(),
		writeGen: d.frr.UnconditionalWriteGeneration(),
	}
	in.mastership = d.contributingMastership19050(in.cfg, 1)
	if _, ok := in.mastership[2]; !ok {
		t.Fatalf("premise: RG2 must be a contributing RG, snapshot=%v", in.mastership)
	}
	if !d.fastInstallPrecheck19050(in) {
		t.Fatalf("premise: the unperturbed pre-check must pass (mastership=%v)", in.mastership)
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
		in.mastership = d.contributingMastership19050(in.cfg, 1) // the snapshot agrees; only the primary term catches it
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
	t.Run("non-contributing-rg-moves", func(t *testing.T) { // scope: RG0 owns no RETH
		d, cm, in := baseABAInputs19050(t)
		cm.SetGroupStateForTesting(0, cluster.StateSecondary)
		if !d.fastInstallPrecheck19050(in) {
			t.Fatal("pre-check refused because RG0, which no static line depends on, moved")
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

// abaClusterSet19050 is a two-data-RG cluster: reth0 (RG1, the WAN default)
// and reth1 (RG2, a LAN static). reth1 carries a bandwidth so the render
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
// and installs A's line only. RG0 owns no RETH and the static render never
// reads it (staticHopActive), so RG0 moving during the render must not cost
// a takeover its fast install.
func TestFastInstallNotFencedByNonContributingRG19050(t *testing.T) {
	d, rec, cm := newABADaemon19050(t)
	cm.SetGroupStateForTesting(1, cluster.StatePrimary)
	epoch := d.bumpDirectVIPEpoch19050(1)
	hookRender19050(t, func() {
		cm.SetGroupStateForTesting(0, cluster.StateSecondary) // a net move, not an ABA
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
