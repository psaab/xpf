package daemon

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"golang.org/x/sync/semaphore"
)

// stubRoutingReconcile9693 replaces both retry-owner reconciles for one cell.
func stubRoutingReconcile9693(t *testing.T, policy func(*config.Config) error) *[]*config.Config {
	t.Helper()
	seen := &[]*config.Config{}
	prevPolicy, prevLeak := routingPolicyReconcileFn, routeLeakReconcileFn
	routingPolicyReconcileFn = func(_ *Daemon, cfg *config.Config) error {
		*seen = append(*seen, cfg)
		return policy(cfg)
	}
	routeLeakReconcileFn = func(*Daemon, *config.Config, []config.RouteOverlayEntry) error { return nil }
	t.Cleanup(func() { routingPolicyReconcileFn, routeLeakReconcileFn = prevPolicy, prevLeak })
	return seen
}

func daemonWithActiveConfig9693(t *testing.T) *Daemon {
	t.Helper()
	s := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if _, err := s.SyncApply("system {\n    host-name routing-9693;\n}\n", nil); err != nil {
		t.Fatalf("SyncApply: %v", err)
	}
	if cfg := s.ActiveConfig(); cfg == nil || cfg.System.HostName != "routing-9693" {
		t.Fatalf("precondition: active config not installed: %+v", cfg)
	}
	return &Daemon{applySem: semaphore.NewWeighted(1), store: s}
}

func TestRoutingReconcileDebtLatchesAndDischarges9693(t *testing.T) {
	d := &Daemon{}
	d.noteRoutingReconcileResult(nil, errors.New("apply next-table rules: boom"))
	if owed, failures, last := d.RoutingReconcileDebt(); !owed || failures != 1 || last == "" {
		t.Fatalf("a failed reconcile must latch the debt: owed=%v failures=%d last=%q", owed, failures, last)
	}
	d.noteRoutingReconcileResult(nil, nil)
	if owed, failures, _ := d.RoutingReconcileDebt(); owed || failures != 1 {
		t.Fatalf("a clean reconcile must discharge the debt and keep the failure count: owed=%v failures=%d", owed, failures)
	}
}

// TestRetryOwnerRunsOnlyWhileOwedAndUntilItSucceeds9693 is the cell the defect
// fails: before #9693 nothing re-ran a failed reconcile at all.
func TestRetryOwnerRunsOnlyWhileOwedAndUntilItSucceeds9693(t *testing.T) {
	d := daemonWithActiveConfig9693(t)
	attempts := 0
	seen := stubRoutingReconcile9693(t, func(*config.Config) error {
		attempts++
		if attempts == 1 {
			return errors.New("apply rib-group rules: transient")
		}
		return nil
	})
	ctx := context.Background()

	d.reassertRoutingReconcileOnce(ctx)
	if len(*seen) != 0 {
		t.Fatal("the retry owner ran a reconcile nobody owed")
	}

	d.noteRoutingReconcileResult(errors.New("apply PBR rules: transient"))
	d.reassertRoutingReconcileOnce(ctx)
	if owed, failures, _ := d.RoutingReconcileDebt(); !owed || failures != 2 || len(*seen) != 1 {
		t.Fatalf("a failing retry must keep the debt and count the failure: owed=%v failures=%d runs=%d", owed, failures, len(*seen))
	}
	d.reassertRoutingReconcileOnce(ctx)
	if owed, _, _ := d.RoutingReconcileDebt(); owed || len(*seen) != 2 {
		t.Fatalf("a succeeding retry must discharge the debt: owed=%v runs=%d", owed, len(*seen))
	}
	d.reassertRoutingReconcileOnce(ctx)
	if len(*seen) != 2 {
		t.Fatalf("the retry owner kept reconciling after the debt was discharged (runs=%d)", len(*seen))
	}
}

// TestRetryOwnerReconcilesTheActiveConfigUnderApplySem9693: the retry must use
// the ACTIVE config read inside applySem, and must wait for a commit holding it.
func TestRetryOwnerReconcilesTheActiveConfigUnderApplySem9693(t *testing.T) {
	d := daemonWithActiveConfig9693(t)
	seen := stubRoutingReconcile9693(t, func(*config.Config) error { return nil })
	d.noteRoutingReconcileResult(errors.New("route-leak snapshot republish: transient"))

	if !d.applySem.TryAcquire(1) {
		t.Fatal("precondition: applySem free")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	d.reassertRoutingReconcileOnce(ctx)
	if len(*seen) != 0 {
		t.Fatal("the retry owner reconciled while a commit held applySem")
	}
	d.applySem.Release(1)

	d.reassertRoutingReconcileOnce(context.Background())
	if len(*seen) != 1 || (*seen)[0] != d.store.ActiveConfig() {
		t.Fatalf("the retry owner must reconcile the active config (runs=%d)", len(*seen))
	}
}

// TestRetryOwnerRechecksTheDebtInsideApplySem9693: a commit that runs the same
// reconcile while the retry owner waits on applySem discharges the debt, and the
// retry owner must then reconcile nothing. Without the check inside the
// semaphore it would re-run a reconcile against a config the commit already
// converged.
func TestRetryOwnerRechecksTheDebtInsideApplySem9693(t *testing.T) {
	d := daemonWithActiveConfig9693(t)
	seen := stubRoutingReconcile9693(t, func(*config.Config) error { return nil })
	d.noteRoutingReconcileResult(errors.New("apply next-table rules: transient"))

	if !d.applySem.TryAcquire(1) {
		t.Fatal("precondition: applySem free")
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		d.reassertRoutingReconcileOnce(context.Background())
	}()
	// Give the retry owner time to pass the outer owed check and block on the
	// semaphore. If it has not got there yet, it sees the debt already
	// discharged and returns early, which still reconciles nothing, so the cell
	// cannot fail spuriously. It can only fail to reach the inner check.
	time.Sleep(50 * time.Millisecond)
	d.noteRoutingReconcileResult(nil) // the commit's own reconcile succeeded
	d.applySem.Release(1)
	<-done
	if len(*seen) != 0 {
		t.Fatalf("the retry owner reconciled after a commit discharged the debt while it waited (runs=%d)", len(*seen))
	}
}

// TestRetryOwnerRerunsTheRouteLeakRepublishToo9693: the retry owner must re-run
// the route-leak snapshot republish as well as the ip-rule reconcile, and a
// republish failure on its own must keep the debt. A wiring check cannot see
// this, because the seam definition names reconcileRouteLeakSnapshot even when
// the retry path stops calling the seam.
func TestRetryOwnerRerunsTheRouteLeakRepublishToo9693(t *testing.T) {
	d := daemonWithActiveConfig9693(t)
	stubRoutingReconcile9693(t, func(*config.Config) error { return nil })
	leakCalls := 0
	routeLeakReconcileFn = func(*Daemon, *config.Config, []config.RouteOverlayEntry) error {
		leakCalls++
		if leakCalls == 1 {
			return errors.New("route-leak snapshot republish: transient")
		}
		return nil
	}
	d.noteRoutingReconcileResult(errors.New("route-leak snapshot republish: transient"))
	d.reassertRoutingReconcileOnce(context.Background())
	if owed, _, _ := d.RoutingReconcileDebt(); leakCalls != 1 || !owed {
		t.Fatalf("the retry owner must re-run the republish and keep the debt when only the republish fails (calls=%d owed=%v)", leakCalls, owed)
	}
	d.reassertRoutingReconcileOnce(context.Background())
	if owed, _, _ := d.RoutingReconcileDebt(); leakCalls != 2 || owed {
		t.Fatalf("a successful republish retry must discharge the debt (calls=%d owed=%v)", leakCalls, owed)
	}
}

// TestRetryOwnerDoesNotQueueBehindACommitWhenNothingIsOwed9693: with nothing
// owed, the retry owner must return at once rather than wait for applySem. The
// re-check inside the semaphore would still stop it reconciling, but a tick
// that owes nothing would queue behind every commit.
func TestRetryOwnerDoesNotQueueBehindACommitWhenNothingIsOwed9693(t *testing.T) {
	d := daemonWithActiveConfig9693(t)
	seen := stubRoutingReconcile9693(t, func(*config.Config) error { return nil })
	if !d.applySem.TryAcquire(1) {
		t.Fatal("precondition: applySem free")
	}
	defer d.applySem.Release(1)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	start := time.Now()
	d.reassertRoutingReconcileOnce(ctx)
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("with nothing owed the retry owner waited %v on a commit's applySem", elapsed)
	}
	if len(*seen) != 0 {
		t.Fatalf("the retry owner reconciled with nothing owed (runs=%d)", len(*seen))
	}
}

// TestRoutingReconcileRetryOwnerIsWired9693 binds the wiring the cells above call
// directly: the apply latches the debt after the route-leak republish, Run starts
// the loop, applyRoutingRules shares applyPolicyRoutingRules, and the retry owner
// never re-runs the FRR apply.
func TestRoutingReconcileRetryOwnerIsWired9693(t *testing.T) {
	fset := token.NewFileSet()
	selectorsIn := func(file string) map[string][]token.Pos {
		f, err := parser.ParseFile(fset, file, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		out := map[string][]token.Pos{}
		ast.Inspect(f, func(n ast.Node) bool {
			if sel, ok := n.(*ast.SelectorExpr); ok {
				out[sel.Sel.Name] = append(out[sel.Sel.Name], sel.Pos())
			}
			return true
		})
		return out
	}
	apply := selectorsIn("daemon_apply.go")
	if len(apply["noteRoutingReconcileResult"]) == 0 || len(apply["reconcileRouteLeakSnapshot"]) == 0 ||
		apply["noteRoutingReconcileResult"][0] < apply["reconcileRouteLeakSnapshot"][0] {
		t.Error("the config apply must latch the routing reconcile debt after the route-leak republish")
	}
	if len(selectorsIn("daemon_run.go")["routingReconcileReassertLoop"]) == 0 {
		t.Error("Run must start routingReconcileReassertLoop")
	}
	if len(selectorsIn("daemon_apply_routing.go")["applyPolicyRoutingRules"]) == 0 {
		t.Error("applyRoutingRules must share applyPolicyRoutingRules with the retry owner")
	}
	retry := selectorsIn("routing_reconcile_debt_9693.go")
	for _, forbidden := range []string{"applyRoutingRules", "applyFRRConfig", "assembleFRRConfig"} {
		if len(retry[forbidden]) != 0 {
			t.Errorf("the routing reconcile retry owner must not call %s (FRR owns its own retry)", forbidden)
		}
	}
	if len(retry["applyPolicyRoutingRules"]) == 0 || len(retry["reconcileRouteLeakSnapshot"]) == 0 {
		t.Error("the retry owner must re-run both applyPolicyRoutingRules and reconcileRouteLeakSnapshot")
	}
}
