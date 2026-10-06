package daemon

import (
	"fmt"
	"net"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/routing"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// fakeRuleOps5642 is a minimal in-memory ip-rule table implementing the routing
// package's ruleOps surface (RuleAdd/RuleDel/RuleList) so a pkg/daemon test can
// drive applyRoutingRules' rib-group reconcile against a fake netlink handle via
// routing.NewManagerWithRuleOpsForTest — no root, no live kernel.
type fakeRuleOps5642 struct {
	rules map[int][]netlink.Rule
	dels  int
}

func newFakeRuleOps5642() *fakeRuleOps5642 {
	return &fakeRuleOps5642{rules: map[int][]netlink.Rule{
		unix.AF_INET:  {},
		unix.AF_INET6: {},
	}}
}

func (f *fakeRuleOps5642) RuleAdd(r *netlink.Rule) error {
	f.rules[r.Family] = append(f.rules[r.Family], *r)
	return nil
}

func (f *fakeRuleOps5642) RuleDel(r *netlink.Rule) error {
	f.dels++
	list := f.rules[r.Family]
	out := list[:0:0]
	for _, e := range list {
		if e.Priority == r.Priority {
			continue
		}
		out = append(out, e)
	}
	f.rules[r.Family] = out
	return nil
}

func (f *fakeRuleOps5642) RuleList(family int) ([]netlink.Rule, error) {
	return f.rules[family], nil
}

func (f *fakeRuleOps5642) hasPriority(family, prio int) bool {
	for _, r := range f.rules[family] {
		if r.Priority == prio {
			return true
		}
	}
	return false
}

// TestApplyRoutingRulesClearsRibGroupLeakOnZeroTransition is the #5642 (M34)
// fail-on-revert guard for part (a): when a config transition removes the FINAL
// rib-group (RoutingOptions.RibGroups becomes empty), applyRoutingRules must
// STILL run the rib-group reconcile so the previously-installed synthetic
// per-prefix leak ip-rule (`ip rule to <prefix> lookup <sourceTable>`, the
// #3876 leak band at priority 30000-30999) is deleted from the kernel.
//
// RED-on-revert: restoring the pre-fix `len(cfg.RoutingOptions.RibGroups) > 0`
// gate skips ApplyRibGroupRules entirely on the zero-transition, so the stale
// rule survives and this test fails. That stale rule would keep routing the
// deleted VRF's prefix into its table indefinitely — a route-leak that
// kernel-forwarded / local / route-based-IPsec plaintext could follow.
func TestApplyRoutingRulesClearsRibGroupLeakOnZeroTransition(t *testing.T) {
	// pkg/routing ribGroupLeakRulePriority (#3876 per-prefix leak band). Kept as
	// a literal because the constant is package-private to pkg/routing.
	const ribGroupLeakPrio = 30000

	ops := newFakeRuleOps5642()
	// Seed the stale C1 rib-group leak rule: `ip rule to 10.0.30.0/24 lookup 101`.
	_, dst, err := net.ParseCIDR("10.0.30.0/24")
	if err != nil {
		t.Fatalf("ParseCIDR: %v", err)
	}
	staleLeak := netlink.NewRule()
	staleLeak.Family = unix.AF_INET
	staleLeak.Priority = ribGroupLeakPrio
	staleLeak.Table = 101
	staleLeak.Dst = dst
	ops.rules[unix.AF_INET] = append(ops.rules[unix.AF_INET], *staleLeak)

	d := &Daemon{routing: routing.NewManagerWithRuleOpsForTest(ops)}

	// C2: the final rib-group has been removed. The instance still exists but
	// carries no interface-routes rib-group, and RoutingOptions.RibGroups is empty.
	cfg := &config.Config{}
	cfg.RoutingInstances = []*config.RoutingInstanceConfig{
		{Name: "dmz-vr", TableID: 101},
	}

	d.applyRoutingRules(cfg, nil)

	if ops.hasPriority(unix.AF_INET, ribGroupLeakPrio) {
		t.Fatalf("zero-transition must delete the stale rib-group leak ip-rule at "+
			"priority %d; rules=%v", ribGroupLeakPrio, ops.rules[unix.AF_INET])
	}
	if ops.dels == 0 {
		t.Fatal("expected a RuleDel for the stale rib-group leak rule; none issued")
	}
}

// TestApplyRoutingRulesNoRibGroupNoChurn pins the no-spurious-churn contract for
// a config that never carried a rib-group: with no rule in the scanned bands,
// the unconditional reconcile issues no RuleDel. Guards against a regression
// where the gate removal starts churning ip-rules on every plain commit.
func TestApplyRoutingRulesNoRibGroupNoChurn(t *testing.T) {
	ops := newFakeRuleOps5642()
	d := &Daemon{routing: routing.NewManagerWithRuleOpsForTest(ops)}

	cfg := &config.Config{}
	cfg.RoutingInstances = []*config.RoutingInstanceConfig{
		{Name: "dmz-vr", TableID: 101},
	}

	d.applyRoutingRules(cfg, nil)

	if ops.dels != 0 {
		t.Fatalf("a never-had-a-rib-group config must issue no RuleDel; got %d", ops.dels)
	}
}

// TestReconcileRouteLeakSnapshotRepublishesOnChange is the #5642 part-(b) guard:
// after applyRoutingRules reconciles the kernel ip-rule table, the daemon
// republishes the routes-only userspace snapshot so a stale inter-VRF leak
// (published by the earlier full dataplane apply from the pre-reconcile rule
// table) is rebuilt leak-free. A real publish (route set changed) MUST be
// followed by a FIB-generation bump so established flows re-resolve.
//
// RED-on-revert: reverting reconcileRouteLeakSnapshot to a no-op leaves the
// published snapshot stale and this test fails (publish/bump never fire).
func TestReconcileRouteLeakSnapshotRepublishesOnChange(t *testing.T) {
	dp := &fakeOverlayDP{}
	d := &Daemon{}
	d.setDataplane(dp) // #2114: publish through the cell

	d.reconcileRouteLeakSnapshot(&config.Config{}, nil)

	if len(dp.calls) != 2 || dp.calls[0] != "publish" || dp.calls[1] != "bump" {
		t.Fatalf("calls = %v, want [publish bump]", dp.calls)
	}
}

// TestReconcileRouteLeakSnapshotSkipsBumpOnDuplicate: an unchanged route set
// (PublishRouteOverlaySnapshot duplicate-skip → published=false) must NOT bump
// the FIB generation — a steady-state commit and a never-had-a-rib-group config
// publish nothing and churn nothing.
func TestReconcileRouteLeakSnapshotSkipsBumpOnDuplicate(t *testing.T) {
	dp := &fakeOverlayDP{publishSkipped: true}
	d := &Daemon{}
	d.setDataplane(dp) // #2114: publish through the cell

	d.reconcileRouteLeakSnapshot(&config.Config{}, nil)

	if len(dp.calls) != 1 || dp.calls[0] != "publish" {
		t.Fatalf("calls = %v, want exactly [publish]", dp.calls)
	}
	for _, c := range dp.calls {
		if c == "bump" {
			t.Fatalf("calls = %v: FIB generation bumped after a duplicate-skip", dp.calls)
		}
	}
}

// RuleAddDSCP satisfies ruleOps. These domains (probe pins / rib-group leaks /
// reconcile) never emit a DSCP selector, so a call here means a rule was routed
// down the wrong path — fail loudly rather than silently accepting it.
func (f *fakeRuleOps5642) RuleAddDSCP(*netlink.Rule, uint8) error {
	return fmt.Errorf("unexpected RuleAddDSCP: this domain emits no DSCP selectors")
}
