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
	delErr    error
	invalid   int
}

func (f *day2StatefulTerm10458) RuleDel(rule *netlink.Rule) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.delCalls++
	if f.installed == nil {
		f.installed = map[int]bool{}
	}
	if f.delErr != nil {
		return f.delErr
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
func (f *day2StatefulTerm10458) flush(families ...int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, family := range families {
		delete(f.installed, family)
	}
}

// day2RuleList10458 exposes the terminator fake's current state through the
// same full-rule snapshot shape as the production RuleList probe.
func day2RuleList10458(term *day2StatefulTerm10458) func(int) ([]netlink.Rule, error) {
	return func(family int) ([]netlink.Rule, error) {
		installed, _, _, _ := term.snapshot()
		if installed[family] {
			return ruleListAtPriorities18005(family, 0, 1000, vrfMissTerminatorPriority16804, 32766), nil
		}
		return ruleListAtPriorities18005(family, 0, 1000, 32766), nil
	}
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

// TestDay2TailRestoresAsyncDeleteWithNoDebt10458 exercises a no-debt tick
// after an asynchronous canary deletion. The truthful canary read now
// escalates to the same policy/leak/DNS repair as a networkd flush.
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
	prevDNS, prevList := mgmtDNSRulesReconcileFn, terminatorFlushRuleListFn
	t.Cleanup(func() {
		routingPolicyReconcileFn, routeLeakReconcileFn = prevPolicy, prevLeak
		mgmtDNSRulesReconcileFn, terminatorFlushRuleListFn = prevDNS, prevList
	})
	policyRuns, leakRuns, dnsRuns := 0, 0, 0
	routingPolicyReconcileFn = func(*Daemon, *config.Config) error { policyRuns++; return nil }
	routeLeakReconcileFn = func(*Daemon, *config.Config, []config.RouteOverlayEntry) error {
		leakRuns++
		return nil
	}
	mgmtDNSRulesReconcileFn = func(*Daemon) error { dnsRuns++; return nil }
	terminatorFlushRuleListFn = func(family int) ([]netlink.Rule, error) {
		return ruleListAtPriorities18005(family, 0, 1000, 32766), nil
	}

	// Post-success async delete with zero generic routing debt.
	_ = term.RuleDel(&netlink.Rule{Family: unix.AF_INET, Priority: 2000})
	_ = term.RuleDel(&netlink.Rule{Family: unix.AF_INET6, Priority: 2000})

	d.reassertRoutingReconcileOnce(context.Background())

	want := []string{"del-4", "del-6", "add-4", "add-6"}
	if !slices.Equal(term.events, want) {
		t.Fatalf("day-2 tail event sequence = %v, want %v", term.events, want)
	}
	if policyRuns != 1 || leakRuns != 1 || dnsRuns != 1 {
		t.Fatalf("missing-canary tick runs = policy %d, leak %d, DNS %d; want one each",
			policyRuns, leakRuns, dnsRuns)
	}
	if owed, _, _ := d.RoutingReconcileDebt(); owed {
		t.Fatal("successful day-2 tail latched routing debt")
	}
}

// TestDay2TailNoDuplicateRulesAcrossTicks10458 proves repeated healthy ticks
// and asynchronous deletions converge on exactly one rule per family. The
// stateful RuleList probe keeps healthy ticks quiet and lets the recovery tick
// distinguish a real missing canary from an idempotent existing rule.
func TestDay2TailNoDuplicateRulesAcrossTicks10458(t *testing.T) {
	term := &day2StatefulTerm10458{}
	d := day2Daemon10458(t, term, day2SfmixConfig10458)
	spec := []routing.VRFSpec{{Name: "sfmix", TableID: 488570}}
	if err := d.routing.ReconcileVRFs(spec); err != nil {
		t.Fatalf("initial VRF reconcile: %v", err)
	}
	day2AssertExactlyOnePerFamily10458(t, term, "after initial reconcile")

	prevPolicy, prevLeak := routingPolicyReconcileFn, routeLeakReconcileFn
	prevDNS, prevList := mgmtDNSRulesReconcileFn, terminatorFlushRuleListFn
	t.Cleanup(func() {
		routingPolicyReconcileFn, routeLeakReconcileFn = prevPolicy, prevLeak
		mgmtDNSRulesReconcileFn, terminatorFlushRuleListFn = prevDNS, prevList
	})
	policyRuns, leakRuns, dnsRuns := 0, 0, 0
	routingPolicyReconcileFn = func(*Daemon, *config.Config) error { policyRuns++; return nil }
	routeLeakReconcileFn = func(*Daemon, *config.Config, []config.RouteOverlayEntry) error {
		leakRuns++
		return nil
	}
	mgmtDNSRulesReconcileFn = func(*Daemon) error { dnsRuns++; return nil }
	terminatorFlushRuleListFn = day2RuleList10458(term)

	ctx := context.Background()
	for range 3 {
		d.reassertRoutingReconcileOnce(ctx) // healthy tick stays quiet
		day2AssertExactlyOnePerFamily10458(t, term, "after idle tick")
		term.flush(unix.AF_INET, unix.AF_INET6)
		d.reassertRoutingReconcileOnce(ctx) // missing-canary tick restores all bands
		day2AssertExactlyOnePerFamily10458(t, term, "after recovery tick")
	}
	if owed, _, _ := d.RoutingReconcileDebt(); owed {
		t.Fatal("successful day-2 ticks latched routing debt")
	}
	if policyRuns != 3 || leakRuns != 3 || dnsRuns != 3 {
		t.Fatalf("recovery callbacks = policy %d, leak %d, DNS %d; want 3 each",
			policyRuns, leakRuns, dnsRuns)
	}
	_, _, installs, _ := term.snapshot()
	// Initial converge (2) plus one restore per cycle (3*2). Healthy ticks
	// hit EEXIST and install nothing.
	if installs != 8 {
		t.Fatalf("absent->present installs = %d, want 8 (initial 2 + 3 restores)", installs)
	}
}

// TestRoutingTickPendingRemovalDoesNotReinstall10458 covers the manager's
// remove-pending ownership state after the rule has disappeared. The
// conservative no-canary escalation may run bands once, but must not install
// a terminator or retain debt after removal converges.
func TestRoutingTickPendingRemovalDoesNotReinstall10458(t *testing.T) {
	term := &day2StatefulTerm10458{}
	d := day2Daemon10458(t, term, day2SfmixConfig10458)
	spec := []routing.VRFSpec{{Name: "sfmix", TableID: 488570}}
	if err := d.routing.ReconcileVRFs(spec); err != nil {
		t.Fatalf("initial VRF reconcile: %v", err)
	}
	if _, err := d.store.SyncApply("system {\n    host-name no-vrf-10458;\n}\n", nil); err != nil {
		t.Fatalf("SyncApply no-VRF config: %v", err)
	}
	injected := errors.New("injected terminator removal failure")
	term.mu.Lock()
	term.delErr = injected
	term.mu.Unlock()
	if err := d.routing.ReconcileVRFs(nil); !errors.Is(err, injected) {
		t.Fatalf("initial remove-pending setup error = %v, want %v", err, injected)
	}
	if !d.routing.VRFMissTerminatorNeedsReconcile() {
		t.Fatal("precondition: failed terminator removal did not retain pending ownership")
	}
	term.flush(unix.AF_INET, unix.AF_INET6)
	term.mu.Lock()
	term.delErr = nil
	term.mu.Unlock()

	prevPolicy, prevLeak := routingPolicyReconcileFn, routeLeakReconcileFn
	prevDNS, prevList := mgmtDNSRulesReconcileFn, terminatorFlushRuleListFn
	t.Cleanup(func() {
		routingPolicyReconcileFn, routeLeakReconcileFn = prevPolicy, prevLeak
		mgmtDNSRulesReconcileFn, terminatorFlushRuleListFn = prevDNS, prevList
	})
	calls := 0
	routingPolicyReconcileFn = func(*Daemon, *config.Config) error { calls++; return nil }
	routeLeakReconcileFn = func(*Daemon, *config.Config, []config.RouteOverlayEntry) error {
		calls++
		return nil
	}
	mgmtDNSRulesReconcileFn = func(*Daemon) error { calls++; return nil }
	listCalls := 0
	terminatorFlushRuleListFn = func(family int) ([]netlink.Rule, error) {
		listCalls++
		return day2RuleList10458(term)(family)
	}

	d.reassertRoutingReconcileOnce(context.Background())
	if calls != 3 {
		t.Fatalf("pending-removal flush tick recovery callbacks = %d, want 3", calls)
	}
	if d.routing.VRFMissTerminatorNeedsReconcile() {
		t.Fatal("successful tick did not discharge pending terminator removal")
	}
	if owed, _, last := d.RoutingReconcileDebt(); owed {
		t.Fatalf("successful pending removal retained routing debt: %q", last)
	}
	installed, addCalls, installs, invalid := term.snapshot()
	if len(installed) != 0 || addCalls != 2 || installs != 2 || invalid != 0 {
		t.Fatalf("pending removal reinstalled or corrupted canary: installed=%v adds=%d installs=%d invalid=%d",
			installed, addCalls, installs, invalid)
	}

	d.reassertRoutingReconcileOnce(context.Background())
	if calls != 3 || listCalls != 1 {
		t.Fatalf("converged no-VRF tick was not quiet: recovery=%d RuleList=%d", calls, listCalls)
	}
}

// TestRoutingTickKeepsGenericAndMgmtRouteDebtIndependent10458 proves each
// recovery domain keeps its own retry bit even when a canary flush forces
// both domains to run in the same tick.
func TestRoutingTickKeepsGenericAndMgmtRouteDebtIndependent10458(t *testing.T) {
	for _, tc := range []struct {
		name  string
		flush bool
	}{
		{name: "generic success leaves management debt", flush: true},
		{name: "management success leaves generic debt", flush: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			term := &day2StatefulTerm10458{}
			d := day2Daemon10458(t, term, day2SfmixConfig10458)
			spec := []routing.VRFSpec{{Name: "sfmix", TableID: 488570}}
			if err := d.routing.ReconcileVRFs(spec); err != nil {
				t.Fatalf("initial VRF reconcile: %v", err)
			}
			if tc.flush {
				term.flush(unix.AF_INET, unix.AF_INET6)
			}

			prevPolicy, prevLeak := routingPolicyReconcileFn, routeLeakReconcileFn
			prevDNS, prevList := mgmtDNSRulesReconcileFn, terminatorFlushRuleListFn
			prevMgmt := mgmtVRFRouteReconcileFn
			t.Cleanup(func() {
				routingPolicyReconcileFn, routeLeakReconcileFn = prevPolicy, prevLeak
				mgmtDNSRulesReconcileFn, terminatorFlushRuleListFn = prevDNS, prevList
				mgmtVRFRouteReconcileFn = prevMgmt
			})
			genericErr := errors.New("injected generic recovery failure")
			mgmtErr := errors.New("injected management-route recovery failure")
			policyRuns, leakRuns, dnsRuns, mgmtRuns := 0, 0, 0, 0
			routingPolicyReconcileFn = func(*Daemon, *config.Config) error {
				policyRuns++
				if !tc.flush && policyRuns == 1 {
					return genericErr
				}
				return nil
			}
			routeLeakReconcileFn = func(*Daemon, *config.Config, []config.RouteOverlayEntry) error {
				leakRuns++
				return nil
			}
			mgmtDNSRulesReconcileFn = func(*Daemon) error { dnsRuns++; return nil }
			terminatorFlushRuleListFn = day2RuleList10458(term)
			mgmtVRFRouteReconcileFn = func(*Daemon) error {
				mgmtRuns++
				if tc.flush && mgmtRuns == 1 {
					return mgmtErr
				}
				return nil
			}

			assertDebt := func(wantGeneric, wantMgmt bool) {
				t.Helper()
				d.routingDebt.mu.Lock()
				gotGeneric, gotMgmt := d.routingDebt.owed, d.routingDebt.mgmtRoutesOwed
				d.routingDebt.mu.Unlock()
				if gotGeneric != wantGeneric || gotMgmt != wantMgmt {
					t.Fatalf("generic/mgmt debt = %v/%v, want %v/%v",
						gotGeneric, gotMgmt, wantGeneric, wantMgmt)
				}
			}
			if tc.flush {
				d.noteMgmtRouteReconcileResult(mgmtErr)
			} else {
				d.noteRoutingReconcileResult(genericErr)
				d.noteMgmtRouteReconcileResult(mgmtErr)
			}

			d.reassertRoutingReconcileOnce(context.Background())
			if tc.flush {
				assertDebt(false, true)
				d.reassertRoutingReconcileOnce(context.Background())
				assertDebt(false, false)
				if policyRuns != 1 || leakRuns != 1 || dnsRuns != 1 || mgmtRuns != 2 {
					t.Fatalf("flush recovery runs = policy %d, leak %d, DNS %d, mgmt %d; want 1/1/1/2",
						policyRuns, leakRuns, dnsRuns, mgmtRuns)
				}
			} else {
				assertDebt(true, false)
				d.reassertRoutingReconcileOnce(context.Background())
				assertDebt(false, false)
				if policyRuns != 2 || leakRuns != 2 || dnsRuns != 2 || mgmtRuns != 1 {
					t.Fatalf("owed recovery runs = policy %d, leak %d, DNS %d, mgmt %d; want 2/2/2/1",
						policyRuns, leakRuns, dnsRuns, mgmtRuns)
				}
			}
		})
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
// the #9693 retry debt and the next owed tick retries the full reconcile.
func TestDay2TailFailureLatchesRetryDebt10458(t *testing.T) {
	d, term, _ := startupApplyDaemon10421(t)
	spec := []routing.VRFSpec{{Name: "sfmix", TableID: 488570}}
	if err := d.routing.ReconcileVRFs(spec); err != nil {
		t.Fatalf("initial VRF reconcile: %v", err)
	}
	term.events = nil

	prevPolicy, prevLeak := routingPolicyReconcileFn, routeLeakReconcileFn
	prevDNS, prevList := mgmtDNSRulesReconcileFn, terminatorFlushRuleListFn
	t.Cleanup(func() {
		routingPolicyReconcileFn, routeLeakReconcileFn = prevPolicy, prevLeak
		mgmtDNSRulesReconcileFn, terminatorFlushRuleListFn = prevDNS, prevList
	})
	policyRuns, leakRuns := 0, 0
	routingPolicyReconcileFn = func(*Daemon, *config.Config) error { policyRuns++; return nil }
	routeLeakReconcileFn = func(*Daemon, *config.Config, []config.RouteOverlayEntry) error {
		leakRuns++
		return nil
	}
	mgmtDNSRulesReconcileFn = func(*Daemon) error { return nil }
	terminatorFlushRuleListFn = func(family int) ([]netlink.Rule, error) {
		return ruleListAtPriorities18005(family, 0, 1000, vrfMissTerminatorPriority16804, 32766), nil
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
		t.Fatalf("owed retry runs = policy %d, leak %d, want 1 each", policyRuns, leakRuns)
	}
	want := []string{"add-4", "add-6", "add-4", "add-6"}
	if !slices.Equal(term.events, want) {
		t.Fatalf("failure/retry event sequence = %v, want %v", term.events, want)
	}
}

// TestDay2TailSkipsBootstrap10458 is the debt-free bootstrap negative control:
// the probe, terminator, and all recovery callbacks stay suppressed.
func TestDay2TailSkipsBootstrap10458(t *testing.T) {
	d, term := startupDaemon10421(t, false)
	spec := []routing.VRFSpec{{Name: "sfmix", TableID: 488570}}
	if err := d.routing.ReconcileVRFs(spec); err != nil {
		t.Fatalf("bootstrap VRF reconcile setup: %v", err)
	}
	term.events = nil
	d.bootstrapMode.Store(true)

	prevPolicy, prevLeak := routingPolicyReconcileFn, routeLeakReconcileFn
	prevDNS, prevList := mgmtDNSRulesReconcileFn, terminatorFlushRuleListFn
	prevVRF, prevMgmt := vrfMissTerminatorReconcileFn, mgmtVRFRouteReconcileFn
	t.Cleanup(func() {
		routingPolicyReconcileFn, routeLeakReconcileFn = prevPolicy, prevLeak
		mgmtDNSRulesReconcileFn, terminatorFlushRuleListFn = prevDNS, prevList
		vrfMissTerminatorReconcileFn, mgmtVRFRouteReconcileFn = prevVRF, prevMgmt
	})
	probes, vrfRuns, policyRuns, leakRuns, dnsRuns, mgmtRuns := 0, 0, 0, 0, 0, 0
	terminatorFlushRuleListFn = func(int) ([]netlink.Rule, error) { probes++; return nil, nil }
	vrfMissTerminatorReconcileFn = func(*Daemon) error { vrfRuns++; return nil }
	routingPolicyReconcileFn = func(*Daemon, *config.Config) error { policyRuns++; return nil }
	routeLeakReconcileFn = func(*Daemon, *config.Config, []config.RouteOverlayEntry) error {
		leakRuns++
		return nil
	}
	mgmtDNSRulesReconcileFn = func(*Daemon) error { dnsRuns++; return nil }
	mgmtVRFRouteReconcileFn = func(*Daemon) error { mgmtRuns++; return nil }

	d.reassertRoutingReconcileOnce(context.Background())
	if len(term.events) != 0 || probes+vrfRuns+policyRuns+leakRuns+dnsRuns+mgmtRuns != 0 {
		t.Fatalf("debt-free bootstrap tick performed work: term=%v probe=%d VRF=%d policy=%d leak=%d DNS=%d mgmt=%d",
			term.events, probes, vrfRuns, policyRuns, leakRuns, dnsRuns, mgmtRuns)
	}
}

// TestDay2TailRetriesDebtDuringBootstrap10458 preserves the existing debt
// retry contract: bootstrap suppresses the canary and terminator takeover, not
// generic or management-route recovery that was already owed.
func TestDay2TailRetriesDebtDuringBootstrap10458(t *testing.T) {
	d, term := startupDaemon10421(t, false)
	spec := []routing.VRFSpec{{Name: "sfmix", TableID: 488570}}
	if err := d.routing.ReconcileVRFs(spec); err != nil {
		t.Fatalf("bootstrap VRF reconcile setup: %v", err)
	}
	term.events = nil
	d.bootstrapMode.Store(true)

	prevPolicy, prevLeak := routingPolicyReconcileFn, routeLeakReconcileFn
	prevDNS, prevList := mgmtDNSRulesReconcileFn, terminatorFlushRuleListFn
	prevVRF, prevMgmt := vrfMissTerminatorReconcileFn, mgmtVRFRouteReconcileFn
	t.Cleanup(func() {
		routingPolicyReconcileFn, routeLeakReconcileFn = prevPolicy, prevLeak
		mgmtDNSRulesReconcileFn, terminatorFlushRuleListFn = prevDNS, prevList
		vrfMissTerminatorReconcileFn, mgmtVRFRouteReconcileFn = prevVRF, prevMgmt
	})
	probes, vrfRuns, policyRuns, leakRuns, dnsRuns, mgmtRuns := 0, 0, 0, 0, 0, 0
	terminatorFlushRuleListFn = func(int) ([]netlink.Rule, error) { probes++; return nil, nil }
	vrfMissTerminatorReconcileFn = func(*Daemon) error { vrfRuns++; return nil }
	routingPolicyReconcileFn = func(*Daemon, *config.Config) error { policyRuns++; return nil }
	routeLeakReconcileFn = func(*Daemon, *config.Config, []config.RouteOverlayEntry) error {
		leakRuns++
		return nil
	}
	mgmtDNSRulesReconcileFn = func(*Daemon) error { dnsRuns++; return nil }
	mgmtVRFRouteReconcileFn = func(*Daemon) error { mgmtRuns++; return nil }
	d.noteRoutingReconcileResult(errors.New("injected generic routing debt"))
	d.noteMgmtRouteReconcileResult(errors.New("injected management-route debt"))

	d.reassertRoutingReconcileOnce(context.Background())
	if probes != 0 || vrfRuns != 0 || len(term.events) != 0 {
		t.Fatalf("bootstrap debt retry touched the canary: probes=%d VRF=%d term=%v", probes, vrfRuns, term.events)
	}
	if policyRuns != 1 || leakRuns != 1 || dnsRuns != 1 || mgmtRuns != 1 {
		t.Fatalf("bootstrap debt retries = policy %d, leak %d, DNS %d, mgmt %d; want one each",
			policyRuns, leakRuns, dnsRuns, mgmtRuns)
	}
	if owed, _, last := d.RoutingReconcileDebt(); owed {
		t.Fatalf("successful bootstrap debt retries did not discharge: last=%q", last)
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
