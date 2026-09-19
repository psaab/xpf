package daemon

import (
	"context"
	"errors"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/routing"
	"github.com/vishvananda/netlink"
	"golang.org/x/sync/semaphore"
	"golang.org/x/sys/unix"
)

// Day-2 tail for the #9819/#10421 VRF miss terminator (#10458).
//
// #10421 reasserts the managed pref-2000 rules at every apply boundary and
// retries failures through the #9693 debt owner. But the retry owner returns
// early when no debt is owed, so a post-success async delete — cleanup that
// lands after Apply returns with zero error debt — is never re-driven. The
// periodic tick must always reassert the VRF terminator (VRF-only when nothing
// is owed; full reconcile when debt exists), while policy/route-leak
// reconciles stay debt-gated and no-debt ticks never queue behind a commit.

const day2SfmixConfig10458 = "routing-instances {\n    sfmix {\n        instance-type virtual-router;\n    }\n}\n"

// day2TermOps10458 names the exported method set of the routing package's
// terminator surface so the fixture below can accept any fake.
type day2TermOps10458 interface {
	RuleDel(*netlink.Rule) error
	RuleAddL3mdevUnreachable(family, priority int) error
}

// day2Daemon10458 builds a tick-driving daemon with committed config text and
// a caller-supplied terminator fake. The VRF device survives (post-restart
// adoption state); the pref-2000 rules converge via ReconcileVRFs.
func day2Daemon10458[T day2TermOps10458](t *testing.T, term T, configText string) *Daemon {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "config.db"))
	if _, err := store.SyncApply(configText, nil); err != nil {
		t.Fatalf("SyncApply: %v", err)
	}
	ops := newReconcileFakeLinkOps()
	ops.links["vrf-sfmix"] = &netlink.Vrf{LinkAttrs: netlink.LinkAttrs{Name: "vrf-sfmix"}, Table: 488570}
	return &Daemon{
		applySem: semaphore.NewWeighted(1),
		store:    store,
		routing:  routing.NewManagerWithLinkAndTermOpsForTest(ops, term),
	}
}

// day2StatefulTerm10458 models kernel rule state: installs are idempotent
// (a duplicate add returns EEXIST, which the product ignores, mirroring the
// kernel's NLM_F_EXCL duplicate check), deletes remove.
type day2StatefulTerm10458 struct {
	mu        sync.Mutex
	installed map[int]bool
	addCalls  int // attempts, including EEXIST duplicates
	installs  int // absent -> present transitions
	delCalls  int
	invalid   int
}

func (f *day2StatefulTerm10458) RuleDel(rule *netlink.Rule) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.delCalls++
	if f.installed == nil {
		f.installed = map[int]bool{}
	}
	if rule != nil && (rule.Family == unix.AF_INET || rule.Family == unix.AF_INET6) {
		delete(f.installed, rule.Family)
	}
	return nil
}

func (f *day2StatefulTerm10458) RuleAddL3mdevUnreachable(family, priority int) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.addCalls++
	if f.installed == nil {
		f.installed = map[int]bool{}
	}
	if priority != 2000 || (family != unix.AF_INET && family != unix.AF_INET6) {
		f.invalid++
		return nil
	}
	if f.installed[family] {
		return unix.EEXIST
	}
	f.installed[family] = true
	f.installs++
	return nil
}

func (f *day2StatefulTerm10458) snapshot() (installed map[int]bool, addCalls, installs, invalid int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	installed = map[int]bool{}
	for fam := range f.installed {
		installed[fam] = true
	}
	return installed, f.addCalls, f.installs, f.invalid
}

func day2AssertExactlyOnePerFamily10458(t *testing.T, term *day2StatefulTerm10458, what string) {
	t.Helper()
	installed, _, _, invalid := term.snapshot()
	if invalid != 0 {
		t.Fatalf("%s: %d invalid terminator ops", what, invalid)
	}
	if len(installed) != 2 || !installed[unix.AF_INET] || !installed[unix.AF_INET6] {
		t.Fatalf("%s: installed families = %v, want exactly {AF_INET, AF_INET6}", what, installed)
	}
}

// TestDay2TailRestoresAsyncDeleteWithNoDebt10458 is the cell the defect fails:
// a green reassert with zero error debt, followed by a post-success async
// delete, must be restored by the next tick — not silently lost. The no-debt
// tick stays VRF-only: policy and route-leak reconciles must not run.
//
// RED-on-revert: the pre-#10458 tick returns early when nothing is owed, so
// the event sequence stops after del-4/del-6 and the exact-family assertion
// fails.
func TestDay2TailRestoresAsyncDeleteWithNoDebt10458(t *testing.T) {
	d, term, _ := startupApplyDaemon10421(t)
	spec := []routing.VRFSpec{{Name: "sfmix", TableID: 488570}}
	if err := d.routing.ReconcileVRFs(spec); err != nil {
		t.Fatalf("initial VRF reconcile: %v", err)
	}
	if owed, _, _ := d.RoutingReconcileDebt(); owed {
		t.Fatal("precondition: fresh daemon owes routing debt")
	}
	term.events = nil

	prevPolicy, prevLeak := routingPolicyReconcileFn, routeLeakReconcileFn
	t.Cleanup(func() { routingPolicyReconcileFn, routeLeakReconcileFn = prevPolicy, prevLeak })
	policyRuns, leakRuns := 0, 0
	routingPolicyReconcileFn = func(*Daemon, *config.Config) error { policyRuns++; return nil }
	routeLeakReconcileFn = func(*Daemon, *config.Config, []config.RouteOverlayEntry) error {
		leakRuns++
		return nil
	}

	// Post-success async delete with zero error debt: the #10458 window.
	_ = term.RuleDel(&netlink.Rule{Family: unix.AF_INET, Priority: 2000})
	_ = term.RuleDel(&netlink.Rule{Family: unix.AF_INET6, Priority: 2000})

	d.reassertRoutingReconcileOnce(context.Background())

	want := []string{"del-4", "del-6", "add-4", "add-6"}
	if !slices.Equal(term.events, want) {
		t.Fatalf("day-2 tail event sequence = %v, want %v", term.events, want)
	}
	if policyRuns != 0 || leakRuns != 0 {
		t.Fatalf("no-debt tick ran debt-gated reconciles: policy=%d leak=%d", policyRuns, leakRuns)
	}
	if owed, _, _ := d.RoutingReconcileDebt(); owed {
		t.Fatal("successful day-2 tail latched routing debt")
	}
}

// TestDay2TailNoDuplicateRulesAcrossTicks10458 proves repeated ticks and
// delete/recover cycles converge on exactly one rule per family — the
// unconditional reassert never accumulates duplicates (production dedups via
// the kernel's EEXIST, modeled by the stateful fake).
//
// RED-on-revert: the pre-#10458 tick never restores, so the first
// delete/recover cycle ends with zero installed families.
func TestDay2TailNoDuplicateRulesAcrossTicks10458(t *testing.T) {
	term := &day2StatefulTerm10458{}
	d := day2Daemon10458(t, term, day2SfmixConfig10458)
	spec := []routing.VRFSpec{{Name: "sfmix", TableID: 488570}}
	if err := d.routing.ReconcileVRFs(spec); err != nil {
		t.Fatalf("initial VRF reconcile: %v", err)
	}
	day2AssertExactlyOnePerFamily10458(t, term, "after initial reconcile")

	ctx := context.Background()
	for i := 0; i < 3; i++ {
		d.reassertRoutingReconcileOnce(ctx) // idle tick: must stay exactly one/family
		day2AssertExactlyOnePerFamily10458(t, term, "after idle tick")
		_ = term.RuleDel(&netlink.Rule{Family: unix.AF_INET, Priority: 2000})
		_ = term.RuleDel(&netlink.Rule{Family: unix.AF_INET6, Priority: 2000})
		if installed, _, _, _ := term.snapshot(); len(installed) != 0 {
			t.Fatalf("precondition: async delete left %v installed", installed)
		}
		d.reassertRoutingReconcileOnce(ctx) // recovery tick: must restore exactly one/family
		day2AssertExactlyOnePerFamily10458(t, term, "after recovery tick")
	}
	if owed, _, _ := d.RoutingReconcileDebt(); owed {
		t.Fatal("idle day-2 ticks latched routing debt")
	}
	_, _, installs, _ := term.snapshot()
	// Initial converge (2) plus one restore per cycle (3*2). Idle ticks hit
	// EEXIST and install nothing.
	if installs != 8 {
		t.Fatalf("absent->present installs = %d, want 8 (initial 2 + 3 restores)", installs)
	}
}

// TestDay2TailNoDesiredVRFIsNoOp10458 is the negative control for the new
// always-run path: a tick with no desired or owned VRF must not create a
// global pref-2000 rule. GREEN before and after; guards the ownership check.
func TestDay2TailNoDesiredVRFIsNoOp10458(t *testing.T) {
	term := &startupTerminator10421{}
	d := day2Daemon10458(t, term, "system {\n    host-name day2-10458;\n}\n")
	d.reassertRoutingReconcileOnce(context.Background())
	if len(term.events) != 0 {
		t.Fatalf("no-desired-VRF tick mutated global rules: %v", term.events)
	}
	if owed, _, _ := d.RoutingReconcileDebt(); owed {
		t.Fatal("no-desired-VRF tick latched routing debt")
	}
}

// TestDay2TailFailureLatchesRetryDebt10458 proves a day-2 tail failure joins
// the #9693 retry debt (like every other terminator failure) instead of being
// dropped, and the next owed tick runs the full reconcile and discharges.
//
// RED-on-revert: the pre-#10458 tick does nothing with no debt, so no debt is
// ever latched.
func TestDay2TailFailureLatchesRetryDebt10458(t *testing.T) {
	d, term, _ := startupApplyDaemon10421(t)
	spec := []routing.VRFSpec{{Name: "sfmix", TableID: 488570}}
	if err := d.routing.ReconcileVRFs(spec); err != nil {
		t.Fatalf("initial VRF reconcile: %v", err)
	}
	term.events = nil

	prevPolicy, prevLeak := routingPolicyReconcileFn, routeLeakReconcileFn
	t.Cleanup(func() { routingPolicyReconcileFn, routeLeakReconcileFn = prevPolicy, prevLeak })
	policyRuns, leakRuns := 0, 0
	routingPolicyReconcileFn = func(*Daemon, *config.Config) error { policyRuns++; return nil }
	routeLeakReconcileFn = func(*Daemon, *config.Config, []config.RouteOverlayEntry) error {
		leakRuns++
		return nil
	}

	injected := errors.New("injected day-2 terminator failure")
	term.failAfter = term.addCalls
	term.addErr = injected
	d.reassertRoutingReconcileOnce(context.Background())
	if owed, failures, last := d.RoutingReconcileDebt(); !owed || failures != 1 ||
		!strings.Contains(last, "VRF miss terminator") {
		t.Fatalf("day-2 tail failure did not latch retry debt: owed=%v failures=%d last=%q",
			owed, failures, last)
	}
	if policyRuns != 0 || leakRuns != 0 {
		t.Fatalf("failing no-debt tick ran debt-gated reconciles: policy=%d leak=%d", policyRuns, leakRuns)
	}

	term.addErr = nil
	d.reassertRoutingReconcileOnce(context.Background())
	if owed, _, last := d.RoutingReconcileDebt(); owed || last != "" {
		t.Fatalf("owed retry did not discharge debt: owed=%v last=%q", owed, last)
	}
	if policyRuns != 1 || leakRuns != 1 {
		t.Fatalf("owed retry runs = policy %d leak %d, want 1 each", policyRuns, leakRuns)
	}
	want := []string{"add-4", "add-6", "add-4", "add-6"}
	if !slices.Equal(term.events, want) {
		t.Fatalf("failure/retry event sequence = %v, want %v", term.events, want)
	}
}

// TestDay2TailSkipsBootstrap10458 protects the startup takeover boundary:
// bootstrap has a committed VRF in the store, but the periodic owner must not
// mutate global policy rules until the authorized bootstrap exit.
//
// RED-on-revert: removing the bootstrap gate lets this tick install both
// pref-2000 rules after bootstrap setup returns.
func TestDay2TailSkipsBootstrap10458(t *testing.T) {
	d, term := startupDaemon10421(t, false)
	spec := []routing.VRFSpec{{Name: "sfmix", TableID: 488570}}
	if err := d.routing.ReconcileVRFs(spec); err != nil {
		t.Fatalf("bootstrap VRF reconcile setup: %v", err)
	}
	term.events = nil
	d.bootstrapMode.Store(true)
	d.reassertRoutingReconcileOnce(context.Background())
	if len(term.events) != 0 {
		t.Fatalf("bootstrap day-2 tick mutated global rules: %v", term.events)
	}
}

// TestDay2TailCanceledContextSkipsMutation10458 ensures shutdown cancellation
// is observed before the no-debt TryAcquire fast path can reach netlink.
//
// RED-on-revert: removing the context guard allows a canceled idle tick to
// reassert both families.
func TestDay2TailCanceledContextSkipsMutation10458(t *testing.T) {
	d, term, _ := startupApplyDaemon10421(t)
	spec := []routing.VRFSpec{{Name: "sfmix", TableID: 488570}}
	if err := d.routing.ReconcileVRFs(spec); err != nil {
		t.Fatalf("initial VRF reconcile: %v", err)
	}
	term.events = nil
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	d.reassertRoutingReconcileOnce(ctx)
	if len(term.events) != 0 {
		t.Fatalf("canceled day-2 tick mutated global rules: %v", term.events)
	}
}
