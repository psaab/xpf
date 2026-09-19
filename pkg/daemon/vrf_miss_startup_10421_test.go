package daemon

import (
	"context"
	"errors"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	"github.com/psaab/xpf/pkg/routing"
	"github.com/vishvananda/netlink"
	"golang.org/x/sync/semaphore"
	"golang.org/x/sys/unix"
)

type startupTerminator10421 struct {
	events              []string
	addCalls            int
	networkdActivations int
	failAfter           int
	addErr              error
	delCalls            int
	failDelAfter        int
	delErr              error
}

type startupRuleOps10421 struct{}

func (startupRuleOps10421) RuleAdd(*netlink.Rule) error            { return nil }
func (startupRuleOps10421) RuleDel(*netlink.Rule) error            { return nil }
func (startupRuleOps10421) RuleList(int) ([]netlink.Rule, error)   { return nil, nil }
func (startupRuleOps10421) RuleAddDSCP(*netlink.Rule, uint8) error { return nil }

func (f *startupTerminator10421) RuleDel(rule *netlink.Rule) error {
	if rule == nil {
		f.events = append(f.events, "del-invalid")
		return nil
	}
	switch rule.Family {
	case unix.AF_INET:
		f.events = append(f.events, "del-4")
	case unix.AF_INET6:
		f.events = append(f.events, "del-6")
	default:
		f.events = append(f.events, "del-invalid")
	}
	f.delCalls++
	if f.delErr != nil && f.delCalls > f.failDelAfter {
		return f.delErr
	}
	return nil
}

func (f *startupTerminator10421) RuleAddL3mdevUnreachable(family, priority int) error {
	if priority != 2000 {
		f.events = append(f.events, "add-invalid")
		return nil
	}
	var event string
	switch family {
	case unix.AF_INET:
		event = "add-4"
	case unix.AF_INET6:
		event = "add-6"
	default:
		event = "add-invalid"
	}
	f.events = append(f.events, event)
	f.addCalls++
	if f.addErr != nil && f.addCalls > f.failAfter {
		return f.addErr
	}
	return nil
}

func startupApplyDaemon10421(t *testing.T) (*Daemon, *startupTerminator10421, *config.Config) {
	t.Helper()
	d, _ := minimalNetworkdDaemon(t, t.TempDir(), &dataplane.ApplyResult{})
	d.applySem = semaphore.NewWeighted(1)
	d.opts.NoDataplane = false
	d.buildRuntimeDataPlaneForTest = func(string) (dataplane.RuntimeDataPlane, error) {
		return &runtimeOnlyApplyTestDP{applyResult: &dataplane.ApplyResult{}}, nil
	}
	const text = "routing-instances {\n    sfmix {\n        instance-type virtual-router;\n    }\n}\n"
	if _, err := d.store.SyncApply(text, nil); err != nil {
		t.Fatalf("SyncApply: %v", err)
	}
	cfg := d.store.ActiveConfig()
	if cfg == nil || len(cfg.RoutingInstances) != 1 {
		t.Fatalf("precondition: committed VRF config missing: %+v", cfg)
	}

	// The VRF device survived the daemon restart, while the pref-2000 rules did
	// not. This is the exact locked-probe state before the full apply starts.
	ops := newReconcileFakeLinkOps()
	ops.links["vrf-sfmix"] = &netlink.Vrf{LinkAttrs: netlink.LinkAttrs{Name: "vrf-sfmix"}, Table: 488570}
	term := &startupTerminator10421{}
	d.routing = routing.NewManagerWithLinkTermAndRuleOpsForTest(ops, term, startupRuleOps10421{})
	// Model only the observed late deletion, after the real networkd.Apply call;
	// all other apply phases remain production code.
	d.afterNetworkdApplyForTest = func() {
		term.networkdActivations++
		_ = term.RuleDel(&netlink.Rule{Family: unix.AF_INET, Priority: 2000})
		_ = term.RuleDel(&netlink.Rule{Family: unix.AF_INET6, Priority: 2000})
	}
	return d, term, cfg
}

// startupDaemon10421 provides the bootstrap-only setup fixture. Bootstrap does
// not enter applyActiveConfig, so it must not reach the apply-boundary reassert.
func startupDaemon10421(t *testing.T, bootstrap bool) (*Daemon, *startupTerminator10421) {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "config.db"))
	const text = "routing-instances {\n    sfmix {\n        instance-type virtual-router;\n    }\n}\n"
	if _, err := store.SyncApply(text, nil); err != nil {
		t.Fatalf("SyncApply: %v", err)
	}
	ops := newReconcileFakeLinkOps()
	ops.links["vrf-sfmix"] = &netlink.Vrf{LinkAttrs: netlink.LinkAttrs{Name: "vrf-sfmix"}, Table: 488570}
	term := &startupTerminator10421{}
	d := &Daemon{
		applySem: semaphore.NewWeighted(1),
		store:    store,
		routing:  routing.NewManagerWithLinkAndTermOpsForTest(ops, term),
		opts:     Options{NoDataplane: false},
		buildRuntimeDataPlaneForTest: func(string) (dataplane.RuntimeDataPlane, error) {
			return &runtimeOnlyApplyTestDP{}, nil
		},
	}
	d.bootstrapMode.Store(bootstrap)
	return d, term
}

// TestStartupReassertsVRFMissTerminatorAfterActiveApply10421 drives the full
// applyConfigLocked pipeline: VRF reconcile emits both installs, networkd's
// activation seam removes both families, and the post-networkd boundary
// restores exactly one IPv4 and one IPv6 terminator.
//
// RED-on-revert: removing the post-networkd reassert leaves the sequence at
// add-4, add-6, del-4, del-6 and fails this exact-family assertion.
func TestStartupReassertsVRFMissTerminatorAfterActiveApply10421(t *testing.T) {
	d, term, cfg := startupApplyDaemon10421(t)
	if err := d.applyConfigLocked(context.Background(), cfg); err != nil {
		t.Fatalf("applyConfigLocked: %v", err)
	}
	want := []string{
		"add-4", "add-6", // VRF reconcile
		"del-4", "del-6", // networkd activation cleanup
		"add-4", "add-6", // immediate post-networkd reassert
		"add-4", "add-6", // end-of-core reassert
	}
	if len(term.events) != len(want) {
		t.Fatalf("startup event sequence = %v, want %v", term.events, want)
	}
	for i := range want {
		if term.events[i] != want[i] {
			t.Fatalf("startup event sequence = %v, want %v", term.events, want)
		}
	}
	if term.networkdActivations != 1 {
		t.Fatalf("networkd activation seam calls = %d, want 1", term.networkdActivations)
	}
}

// TestDay2ApplyReassertsVRFMissTerminator10421 proves the activation invariant
// is not a boot-only repair: a second committed apply sees the same simulated
// networkd deletion and restores both address families again.
//
// RED-on-revert: deleting the apply-boundary reassert makes the second exact
// family sequence stop after del-4/del-6.
func TestDay2ApplyReassertsVRFMissTerminator10421(t *testing.T) {
	d, term, cfg := startupApplyDaemon10421(t)
	d.beforeFinalVRFMissReassertForTest = func() {
		_ = term.RuleDel(&netlink.Rule{Family: unix.AF_INET, Priority: 2000})
		_ = term.RuleDel(&netlink.Rule{Family: unix.AF_INET6, Priority: 2000})
	}
	if err := d.applyConfigLocked(context.Background(), cfg); err != nil {
		t.Fatalf("first applyConfigLocked: %v", err)
	}
	term.events = nil
	term.networkdActivations = 0
	if err := d.applyConfigLocked(context.Background(), cfg); err != nil {
		t.Fatalf("second applyConfigLocked: %v", err)
	}
	want := []string{
		"add-4", "add-6", // VRF reconcile
		"del-4", "del-6", // networkd activation cleanup
		"add-4", "add-6", // immediate post-networkd reassert
		"del-4", "del-6", // late cleanup before core return
		"add-4", "add-6", // final core reassert
	}
	if len(term.events) != len(want) {
		t.Fatalf("day-2 event sequence = %v, want %v", term.events, want)
	}
	for i := range want {
		if term.events[i] != want[i] {
			t.Fatalf("day-2 event sequence = %v, want %v", term.events, want)
		}
	}
	if term.networkdActivations != 1 {
		t.Fatalf("day-2 networkd activation seam calls = %d, want 1", term.networkdActivations)
	}
}

// TestVRFMissTerminatorFailureFailsApply10421 pins the deferred error wiring:
// a post-networkd install failure must fail the apply and become #9693 retry
// debt, rather than being logged after the applied marker.
//
// RED-on-revert: joining the terminator failure into neither vrfErr nor the
// retry debt makes this test report a false successful apply.
func TestVRFMissTerminatorFailureFailsApply10421(t *testing.T) {
	d, term, cfg := startupApplyDaemon10421(t)
	injected := errors.New("injected VRF miss terminator failure")
	term.failAfter = 2 // initial reconcile succeeds; post-networkd reassert fails
	term.addErr = injected

	if err := d.applyConfigLocked(context.Background(), cfg); err == nil {
		t.Fatal("applyConfigLocked succeeded despite post-networkd terminator failure")
	} else if !strings.Contains(err.Error(), "reassert VRF miss terminator") || !errors.Is(err, injected) {
		t.Fatalf("apply error = %v, want reassert context and injected cause", err)
	}
	if owed, _, last := d.RoutingReconcileDebt(); !owed || !strings.Contains(last, "VRF miss terminator") {
		t.Fatalf("terminator failure did not latch routing retry debt: owed=%v last=%q", owed, last)
	}
}

// TestVRFMissTerminatorDebtLoopRetriesAndDischarges10421 proves that a
// latched terminator failure reaches the actual #9693 retry operation. A direct
// manager call would not catch deleting vrfMissTerminatorReconcileFn from the
// retry join.
func TestVRFMissTerminatorDebtLoopRetriesAndDischarges10421(t *testing.T) {
	d, term, _ := startupApplyDaemon10421(t)
	spec := []routing.VRFSpec{{Name: "sfmix", TableID: 488570}}
	if err := d.routing.ReconcileVRFs(spec); err != nil {
		t.Fatalf("initial VRF reconcile: %v", err)
	}
	term.events = nil
	prevPolicy, prevLeak := routingPolicyReconcileFn, routeLeakReconcileFn
	t.Cleanup(func() {
		routingPolicyReconcileFn, routeLeakReconcileFn = prevPolicy, prevLeak
	})
	routingPolicyReconcileFn = func(*Daemon, *config.Config) error { return nil }
	routeLeakReconcileFn = func(*Daemon, *config.Config, []config.RouteOverlayEntry) error {
		return nil
	}
	d.noteRoutingReconcileResult(errors.New("seed VRF terminator retry debt"))
	injected := errors.New("injected one-shot VRF terminator retry failure")
	term.failAfter = term.addCalls
	term.addErr = injected
	d.reassertRoutingReconcileOnce(context.Background())
	if owed, _, last := d.RoutingReconcileDebt(); !owed ||
		!strings.Contains(last, "VRF miss terminator") {
		t.Fatalf("failed retry did not preserve debt: owed=%v last=%q", owed, last)
	}
	if want := []string{"add-4", "add-6"}; !slices.Equal(term.events, want) {
		t.Fatalf("failed retry events = %v, want %v", term.events, want)
	}
	term.addErr = nil
	d.reassertRoutingReconcileOnce(context.Background())
	if owed, _, last := d.RoutingReconcileDebt(); owed || last != "" {
		t.Fatalf("successful retry did not discharge debt: owed=%v last=%q", owed, last)
	}
	want := []string{"add-4", "add-6", "add-4", "add-6"}
	if !slices.Equal(term.events, want) {
		t.Fatalf("retry events = %v, want %v", term.events, want)
	}
}

// TestStartupTailReassertsAfterSynchronousApply10421 models the real startup
// call site: cleanup occurs after applyActiveConfig returns, before the tail
// reassert, so the returned state is proven rather than inferred from the
// in-core activation seam.
func TestStartupTailReassertsAfterSynchronousApply10421(t *testing.T) {
	d, term, _ := startupApplyDaemon10421(t)
	d.afterActiveConfigApplyForTest = func() {
		_ = term.RuleDel(&netlink.Rule{Family: unix.AF_INET, Priority: 2000})
		_ = term.RuleDel(&netlink.Rule{Family: unix.AF_INET6, Priority: 2000})
	}
	if err := d.setupDataplaneAndInitialConfig(); err != nil {
		t.Fatalf("setupDataplaneAndInitialConfig: %v", err)
	}
	want := []string{
		"add-4", "add-6", // applyVRFReconcile
		"del-4", "del-6", // networkd activation cleanup
		"add-4", "add-6", // immediate post-networkd reassert
		"add-4", "add-6", // end-of-core reassert
		"del-4", "del-6", // post-apply asynchronous cleanup
		"add-4", "add-6", // startup-tail reassert
	}
	if len(term.events) != len(want) {
		t.Fatalf("startup-tail event sequence = %v, want %v", term.events, want)
	}
	for i := range want {
		if term.events[i] != want[i] {
			t.Fatalf("startup-tail event sequence = %v, want %v", term.events, want)
		}
	}
	if term.networkdActivations != 1 {
		t.Fatalf("networkd activation seam calls = %d, want 1", term.networkdActivations)
	}
}

// TestVRFMissTerminatorRemovalFailureRetriesDesiredAbsence10421 ensures a
// failed removal is not converted into a false no-op: #9693's retry owner must
// issue the delete operation again, not reinstall a rule that is no longer
// desired.
func TestVRFMissTerminatorRemovalFailureRetriesDesiredAbsence10421(t *testing.T) {
	d, term, _ := startupApplyDaemon10421(t)
	spec := []routing.VRFSpec{{Name: "sfmix", TableID: 488570}}
	if err := d.routing.ReconcileVRFs(spec); err != nil {
		t.Fatalf("initial VRF reconcile: %v", err)
	}
	injected := errors.New("injected VRF miss terminator removal failure")
	term.failDelAfter = 0
	term.delErr = injected
	if err := d.routing.ReconcileVRFs(nil); err == nil || !errors.Is(err, injected) {
		t.Fatalf("removal error = %v, want injected failure", err)
	}
	term.delErr = nil
	if err := vrfMissTerminatorReconcileFn(d); err != nil {
		t.Fatalf("retrying failed removal through #9693 owner: %v", err)
	}
	want := []string{"add-4", "add-6", "del-4", "del-6", "del-4", "del-6"}
	if len(term.events) != len(want) {
		t.Fatalf("removal event sequence = %v, want %v", term.events, want)
	}
	for i := range want {
		if term.events[i] != want[i] {
			t.Fatalf("removal event sequence = %v, want %v", term.events, want)
		}
	}
}

// TestVRFMissTerminatorNoDesiredVRFIsNoOp10421 protects the cfg-aware
// ownership guard: a manager with no desired or tracked VRF must not create
// a global pref-2000 rule merely because the apply pipeline is active.
func TestVRFMissTerminatorNoDesiredVRFIsNoOp10421(t *testing.T) {
	d, term, _ := startupApplyDaemon10421(t)
	if d.shouldReassertVRFMissTerminator(&config.Config{}) {
		t.Fatal("empty VRF config unexpectedly requested a terminator reassert")
	}
	if err := d.routing.ReassertVRFMissTerminator(); err != nil {
		t.Fatalf("reassert without desired VRF: %v", err)
	}
	if len(term.events) != 0 {
		t.Fatalf("no-desired VRF reassert mutated global rules: %v", term.events)
	}
}

// TestBootstrapDoesNotReassertVRFMissTerminator10421 is the negative control:
// bootstrap startup suppresses dataplane takeover and must not mutate global
// ip rules merely because a committed VRF exists.
func TestBootstrapDoesNotReassertVRFMissTerminator10421(t *testing.T) {
	d, term := startupDaemon10421(t, true)
	if err := d.setupDataplaneAndInitialConfig(); err != nil {
		t.Fatalf("setupDataplaneAndInitialConfig: %v", err)
	}
	if len(term.events) != 0 {
		t.Fatalf("bootstrap setup must not touch global rules, got %v", term.events)
	}
}
