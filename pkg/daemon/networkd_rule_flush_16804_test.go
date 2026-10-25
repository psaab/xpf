package daemon

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dhcp"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// #16804: systemd-networkd's default ManageForeignRoutingPolicyRules=yes
// deletes every xpf ip rule on `networkctl reconfigure` and on networkd
// restart. These cells pin the Go-side owners: the mgmt-DNS steering
// reconcile re-runs after the networkd activation (and after FRR), and
// the 30 s #9693 routing owner detects a between-commits flush via the
// terminator canary readback and restores the policy bands, the
// route-leak snapshot and the mgmt-DNS pairs without a commit.

// TestMgmtDNSReconcileRunsAfterNetworkdActivation16804 is the source-order
// pin for the acceptance "MGMT-DNS-RULES-INSTALL after
// NETWORKD-RECONFIGURE": the post-FRR applyMgmtDNSRules call (the one
// that lands after applyDataplaneAndHACore's networkd.Apply) must remain
// after the FRR call and after the dataplane core. FAIL-ON-REVERT:
// moving the post-FRR reconcile back before applyDataplaneAndHACore
// (or deleting it) leaves the 2500-2503 pairs flushed by the activation
// and this pin goes red.
func TestMgmtDNSReconcileRunsAfterNetworkdActivation16804(t *testing.T) {
	src := stripLineComments6791(readDaemonSource(t, "daemon_apply.go"))
	core := strings.Index(src, "core := d.applyDataplaneAndHACore(ctx, cfg)")
	frr := strings.Index(src, "frrErr := d.applyFRRFull(cfg, commitOverlay)")
	if core < 0 || frr < 0 || frr < core {
		t.Fatal("applyDataplaneAndHACore / applyFRRFull order not found")
	}
	// The reconcile after FRR is necessarily after the networkd
	// activation inside the dataplane core.
	second := strings.Index(src[frr:], "d.applyMgmtDNSRules()")
	if second < 0 {
		t.Fatal("no applyMgmtDNSRules after networkd activation + FRR (#16804)")
	}
	// And the routing-rule reconcile (next-table/rib-group/PBR) must
	// also land after the activation, as it already did pre-#16804.
	if strings.Index(src[frr:], "routingRuleErr := d.applyRoutingRules") < 0 {
		t.Fatal("no applyRoutingRules after networkd activation (#16804)")
	}
}
// TestApplyOrderMgmtDNSAfterNetworkdFlushDynamic16804 drives the real
// applyConfigLocked with the #10421 activation seam extended to the DNS
// bands: afterNetworkdApplyForTest records NETWORKD-RECONFIGURE, and the
// mgmt-DNS reconcile seam records MGMT-DNS-RULES-INSTALL on every
// applyMgmtDNSRules run. The acceptance order is dynamic, not source
// text: a post-activation install must be recorded after the
// reconfigure marker. FAIL-ON-REVERT: deleting the post-FRR reconcile
// leaves only the pre-activation install and this cell goes red.
func TestApplyOrderMgmtDNSAfterNetworkdFlushDynamic16804(t *testing.T) {
	d, term, cfg := startupApplyDaemon10421(t)

	var events []string
	prevDNS := mgmtDNSRulesApplyFn
	t.Cleanup(func() { mgmtDNSRulesApplyFn = prevDNS })
	mgmtDNSRulesApplyFn = func(*Daemon, []*dhcp.Lease, *config.Config) error {
		events = append(events, "MGMT-DNS-RULES-INSTALL")
		return nil
	}
	d.afterNetworkdApplyForTest = func() {
		term.networkdActivations++
		events = append(events, "NETWORKD-RECONFIGURE")
		_ = term.RuleDel(&netlink.Rule{Family: unix.AF_INET, Priority: 2000})
		_ = term.RuleDel(&netlink.Rule{Family: unix.AF_INET6, Priority: 2000})
	}

	if err := d.applyConfigLocked(context.Background(), cfg); err != nil {
		t.Fatalf("applyConfigLocked: %v", err)
	}
	reconf := slices.Index(events, "NETWORKD-RECONFIGURE")
	if reconf < 0 {
		t.Fatalf("no NETWORKD-RECONFIGURE recorded; events = %v", events)
	}
	post := slices.Index(events[reconf+1:], "MGMT-DNS-RULES-INSTALL")
	if post < 0 {
		t.Fatalf("no MGMT-DNS-RULES-INSTALL after NETWORKD-RECONFIGURE; events = %v", events)
	}
}


// TestRoutingTickRestoresAllRuleBandsAfterFlush16804 drives the real
// reassertRoutingReconcileOnce tick with a simulated networkd restart:
// the terminator is missing on readback while no routing debt is owed,
// so the tick must escalate to re-run the policy bands, the route-leak
// republish and the mgmt-DNS reconcile — without any commit — and latch
// no debt once they succeed. FAIL-ON-REVERT: reverting the tick to
// debt-gated-only leaves calls empty and this cell goes red (the
// restart arm had no owner until the next commit).
func TestRoutingTickRestoresAllRuleBandsAfterFlush16804(t *testing.T) {
	d, term, cfg := startupApplyDaemon10421(t)
	if err := d.applyConfigLocked(context.Background(), cfg); err != nil {
		t.Fatalf("applyConfigLocked: %v", err)
	}
	term.events = nil

	var calls []string
	prevPolicy, prevLeak := routingPolicyReconcileFn, routeLeakReconcileFn
	prevDNS, prevList := mgmtDNSRulesReconcileFn, terminatorFlushRuleListFn
	t.Cleanup(func() {
		routingPolicyReconcileFn, routeLeakReconcileFn = prevPolicy, prevLeak
		mgmtDNSRulesReconcileFn, terminatorFlushRuleListFn = prevDNS, prevList
	})
	routingPolicyReconcileFn = func(*Daemon, *config.Config) error {
		calls = append(calls, "policy")
		return nil
	}
	routeLeakReconcileFn = func(*Daemon, *config.Config, []config.RouteOverlayEntry) error {
		calls = append(calls, "leak")
		return nil
	}
	mgmtDNSRulesReconcileFn = func(*Daemon) error {
		calls = append(calls, "mgmtdns")
		return nil
	}
	// Simulate the restart flush: terminator absent from both families.
	terminatorFlushRuleListFn = func(family int) ([]int, error) {
		return []int{0, 1000, 32766}, nil
	}

	d.reassertRoutingReconcileOnce(context.Background())

	want := []string{"policy", "leak", "mgmtdns"}
	if !slices.Equal(calls, want) {
		t.Fatalf("flush tick calls = %v, want %v", calls, want)
	}
	if owed, _, last := d.RoutingReconcileDebt(); owed {
		t.Fatalf("successful flush restore must not latch debt: owed=%v last=%q", owed, last)
	}
	// The terminator itself was re-asserted first (existing always-on arm).
	if !slices.Contains(term.events, "add-4") || !slices.Contains(term.events, "add-6") {
		t.Fatalf("terminator re-assert missing on flush tick: %v", term.events)
	}
}

// TestRoutingTickNoFlushIsQuiet16804 is the negative control: with the
// terminator present on readback and no debt owed, the tick must NOT
// re-run the policy/mgmt-DNS reconciles (a healthy steady-state box
// would otherwise rewrite its rule bands every 30 s).
func TestRoutingTickNoFlushIsQuiet16804(t *testing.T) {
	d, _, cfg := startupApplyDaemon10421(t)
	if err := d.applyConfigLocked(context.Background(), cfg); err != nil {
		t.Fatalf("applyConfigLocked: %v", err)
	}

	calls := 0
	prevPolicy, prevLeak := routingPolicyReconcileFn, routeLeakReconcileFn
	prevDNS, prevList := mgmtDNSRulesReconcileFn, terminatorFlushRuleListFn
	t.Cleanup(func() {
		routingPolicyReconcileFn, routeLeakReconcileFn = prevPolicy, prevLeak
		mgmtDNSRulesReconcileFn, terminatorFlushRuleListFn = prevDNS, prevList
	})
	routingPolicyReconcileFn = func(*Daemon, *config.Config) error { calls++; return nil }
	routeLeakReconcileFn = func(*Daemon, *config.Config, []config.RouteOverlayEntry) error {
		calls++
		return nil
	}
	mgmtDNSRulesReconcileFn = func(*Daemon) error { calls++; return nil }
	terminatorFlushRuleListFn = func(family int) ([]int, error) {
		return []int{0, 1000, vrfMissTerminatorPriority16804, 32766}, nil
	}

	d.reassertRoutingReconcileOnce(context.Background())
	if calls != 0 {
		t.Fatalf("healthy tick ran %d band reconciles, want 0", calls)
	}
	if owed, _, _ := d.RoutingReconcileDebt(); owed {
		t.Fatal("healthy tick latched routing debt")
	}
}

// TestRoutingTickFlushRestoreFailureLatchesDebt16804: when the flush
// restore itself fails, the tick must latch ordinary routing debt so
// the next tick retries — the restart arm must not heal once and give up.
func TestRoutingTickFlushRestoreFailureLatchesDebt16804(t *testing.T) {
	d, _, cfg := startupApplyDaemon10421(t)
	if err := d.applyConfigLocked(context.Background(), cfg); err != nil {
		t.Fatalf("applyConfigLocked: %v", err)
	}

	injected := errors.New("injected flush-restore failure")
	prevPolicy, prevLeak := routingPolicyReconcileFn, routeLeakReconcileFn
	prevDNS, prevList := mgmtDNSRulesReconcileFn, terminatorFlushRuleListFn
	t.Cleanup(func() {
		routingPolicyReconcileFn, routeLeakReconcileFn = prevPolicy, prevLeak
		mgmtDNSRulesReconcileFn, terminatorFlushRuleListFn = prevDNS, prevList
	})
	routingPolicyReconcileFn = func(*Daemon, *config.Config) error { return injected }
	routeLeakReconcileFn = func(*Daemon, *config.Config, []config.RouteOverlayEntry) error {
		return nil
	}
	mgmtDNSRulesReconcileFn = func(*Daemon) error { return nil }
	terminatorFlushRuleListFn = func(family int) ([]int, error) {
		if family == unix.AF_INET {
			return []int{0, 1000}, nil // v4 terminator flushed
		}
		return []int{0, 1000, vrfMissTerminatorPriority16804}, nil
	}

	d.reassertRoutingReconcileOnce(context.Background())
	owed, _, last := d.RoutingReconcileDebt()
	if !owed || !strings.Contains(last, "injected flush-restore failure") {
		t.Fatalf("failed flush restore must latch debt: owed=%v last=%q", owed, last)
	}
}

// TestTerminatorFlushedProbe16804 unit-pins the canary: desired-but-
// missing in either family reports a flush; present in both does not;
// no desired VRF never probes.
func TestTerminatorFlushedProbe16804(t *testing.T) {
	d, _, _ := startupApplyDaemon10421(t)
	prev := terminatorFlushRuleListFn
	t.Cleanup(func() { terminatorFlushRuleListFn = prev })

	live := map[int][]int{
		unix.AF_INET:  {0, 1000, vrfMissTerminatorPriority16804, 32766},
		unix.AF_INET6: {0, 1000, vrfMissTerminatorPriority16804, 32766},
	}
	terminatorFlushRuleListFn = func(family int) ([]int, error) { return live[family], nil }
	flushed, err := terminatorFlushed16804(d)
	if err != nil || flushed {
		t.Fatalf("present terminator: flushed=%v err=%v, want false,nil", flushed, err)
	}

	live[unix.AF_INET6] = []int{0, 1000}
	flushed, err = terminatorFlushed16804(d)
	if err != nil || !flushed {
		t.Fatalf("v6 terminator missing: flushed=%v err=%v, want true,nil", flushed, err)
	}
}
