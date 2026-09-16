package daemon

import (
	"errors"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/networkd"
	"github.com/psaab/xpf/pkg/routing"
	"github.com/psaab/xpf/pkg/vrrp"
	"github.com/vishvananda/netlink"
)

// #5844: pkg/routing correctly RETURNS next-table / rib-group / PBR ip-rule
// reconcile failures, but applyRoutingRules used to LOG-and-DROP them. So a
// commit was acknowledged after a partial clear/add left stale-or-missing
// cross-VRF policy in the kernel — and the immediately-following userspace route
// snapshot (reconcileRouteLeakSnapshot) then canonized that partial live kernel
// state. The fix makes applyRoutingRules RETURN the joined error and threads it
// (routingRuleErr) into the tail commit-error join, fail-closed BUT complete
// (every rule type still runs, then the joined error surfaces).

// fakeRuleOps5844 is a minimal ruleOps double (RuleAdd/RuleDel/RuleList — all
// exported, so it structurally satisfies pkg/routing's unexported ruleOps and
// can back a routing.Manager via NewManagerWithRuleOpsForTest). A non-nil
// listErr makes every per-family RuleList dump fail, which each rule manager's
// clear() surfaces as a returned error — the partial-reconcile signal #5844
// must not drop. listCalls counts how many times RuleList ran so a test can
// prove all three rule types (next-table, rib-group, PBR) executed even after
// one failed (fail-closed but COMPLETE).
type fakeRuleOps5844 struct {
	listErr   error
	listCalls int
	addCalls  int
	delCalls  int
}

func (f *fakeRuleOps5844) RuleAdd(*netlink.Rule) error { f.addCalls++; return nil }
func (f *fakeRuleOps5844) RuleDel(*netlink.Rule) error { f.delCalls++; return nil }
func (f *fakeRuleOps5844) RuleList(int) ([]netlink.Rule, error) {
	f.listCalls++
	return nil, f.listErr
}

// TestApplyRoutingRulesFailsClosedAndComplete_5844 drives the REAL
// applyRoutingRules against a routing.Manager whose ip-rule ops fail, and
// asserts it (a) RETURNS the failure (fail-closed) and (b) STILL ran every rule
// type (complete — a single rule-type failure does not skip the others). frr is
// nil so the FRR block is a no-op and the ip-rule reconciles are isolated.
//
// FAIL-ON-REVERT: revert applyRoutingRules to its void, log-and-drop form and
// this test stops compiling (no error to assign) — the silent partial-reconcile
// acknowledgement #5844 describes.
func TestApplyRoutingRulesFailsClosedAndComplete_5844(t *testing.T) {
	injected := errors.New("injected: RuleList EPERM")
	fake := &fakeRuleOps5844{listErr: injected}
	d := &Daemon{routing: routing.NewManagerWithRuleOpsForTest(fake)}

	// A minimal config: no next-table routes / rib-groups / PBR filters. Each
	// rule manager's clear() still lists the kernel per family up front, so the
	// injected RuleList failure surfaces from all three even with empty desired
	// state — exactly the partial-reconcile window #5844 fails closed on.
	cfg := &config.Config{}

	err := d.applyRoutingRules(cfg, nil)
	if err == nil {
		t.Fatal("applyRoutingRules must return the ip-rule reconcile failure " +
			"(fail-closed); got nil — the dropped-from-commit-truth bug #5844 describes")
	}
	if !errors.Is(err, injected) {
		t.Fatalf("returned error must wrap the injected ip-rule failure, got %v", err)
	}
	// Complete: next-table + rib-group + PBR each ran clear() → RuleList per
	// family (AF_INET + AF_INET6). Six total proves all three rule types
	// executed even though the first already failed (not aborted-early).
	if fake.listCalls < 6 {
		t.Fatalf("expected all three rule types to run their clear() (>=6 RuleList "+
			"calls across next-table/rib-group/PBR × 2 families); got %d — a failure "+
			"aborted the reconcile early instead of completing it", fake.listCalls)
	}
}

// TestApplyRoutingRulesCleanSucceeds_5844 proves a clean ip-rule reconcile does
// NOT fail the commit: RuleList returns an empty kernel table, RuleAdd/RuleDel
// succeed, and an empty config desires nothing, so applyRoutingRules returns
// nil. Guards against a false failure from the new error threading.
func TestApplyRoutingRulesCleanSucceeds_5844(t *testing.T) {
	fake := &fakeRuleOps5844{} // listErr nil -> lists succeed (empty)
	d := &Daemon{routing: routing.NewManagerWithRuleOpsForTest(fake)}
	if err := d.applyRoutingRules(&config.Config{}, nil); err != nil {
		t.Fatalf("a clean ip-rule reconcile must not fail the commit, got %v", err)
	}
}

// TestApplyTailReconcilesSurfacesRoutingRuleError_5844 is the commit-level
// wiring proof: it drives the REAL applyTailReconciles with an injected
// routing-rule error (routingRuleErr, the new final operand) and asserts the
// returned commit error includes it — pinning the tail errors.Join wiring the
// direct applyRoutingRules test does not cover.
//
// FAIL-ON-REVERT: drop routingRuleErr from that join and this goes RED (the
// apply completes and returns nil despite the ip-rule reconcile having failed —
// the exact silent acknowledgement #5844 describes). The nft seams are stubbed
// to succeed so the injected routingRuleErr is the ONLY operand that can surface.
func TestApplyTailReconcilesSurfacesRoutingRuleError_5844(t *testing.T) {
	installFakeNetworkctl(t)

	origApply, origDelete := nftApplyPayload, nftDeleteTable
	nftApplyPayload = func(string) ([]byte, error) { return nil, nil }
	nftDeleteTable = func(string, string) ([]byte, error) { return nil, nil }
	defer func() { nftApplyPayload, nftDeleteTable = origApply, origDelete }()

	d := &Daemon{
		networkd: networkd.NewInDir(t.TempDir()),
		store:    newConfigStore(t, filepath.Join(t.TempDir(), "config.db")),
		vrrpMgr:  vrrp.NewManager(),
		opts:     Options{NoDataplane: true},
	}
	d.setDataplane(&runtimeOnlyApplyTestDP{}) // #2114: publish through the cell

	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"reth0": {Name: "reth0", Units: map[int]*config.InterfaceUnit{0: {Number: 0}}},
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"trust": {Name: "trust", Interfaces: []string{"reth0.0"}},
	}

	injected := errors.New("injected: next-table ip-rule reconcile failed")
	// routingRuleErr is the final applyTailReconciles operand; every other
	// deferred error is nil so it is the only thing that can surface.
	err := d.applyTailReconciles(cfg, nil, nil, nil, nil, nil, nil, injected, nil, nil, nil, nil)
	if err == nil {
		t.Fatal("applyTailReconciles must surface the routing-rule reconcile failure " +
			"(fail-closed); got nil")
	}
	if !errors.Is(err, injected) {
		t.Fatalf("returned commit error must include the routing-rule failure via the "+
			"tail errors.Join wiring, got %v", err)
	}
}

// TestApplyTailReconcilesSurfacesMgmtRouteError_5867 is the commit-level wiring
// proof for the #5867 management-VRF route reconcile error. #5867 moved the
// applyMgmtVRFRoutes call out of applyVRFReconcile (whose error early-aborts and
// would skip the dataplane apply) into applyConfigLocked as a deferred
// mgmtRouteErr, threaded as the FINAL applyTailReconciles operand and appended to
// the tail errors.Join. The root-fix tests (mgmtvrf_route_applied_5867_test.go)
// exercise applyMgmtVRFRoutesTo directly and therefore do NOT cover the join
// wiring — so, exactly like #5844's sibling test above, this drives the REAL
// applyTailReconciles with an injected error in the mgmtRouteErr slot and asserts
// the returned commit error includes it.
//
// FAIL-ON-REVERT: drop mgmtRouteErr from that errors.Join and this goes RED (the
// apply completes and returns nil despite the mgmt-VRF route reconcile having
// failed — a failed RouteReplace / stale-route-cleanup error silently dropped
// from commit truth, the fail-open #5867 closes). The nft seams are stubbed to
// succeed so the injected mgmtRouteErr is the ONLY operand that can surface.
func TestApplyTailReconcilesSurfacesMgmtRouteError_5867(t *testing.T) {
	installFakeNetworkctl(t)

	origApply, origDelete := nftApplyPayload, nftDeleteTable
	nftApplyPayload = func(string) ([]byte, error) { return nil, nil }
	nftDeleteTable = func(string, string) ([]byte, error) { return nil, nil }
	defer func() { nftApplyPayload, nftDeleteTable = origApply, origDelete }()

	d := &Daemon{
		networkd: networkd.NewInDir(t.TempDir()),
		store:    newConfigStore(t, filepath.Join(t.TempDir(), "config.db")),
		vrrpMgr:  vrrp.NewManager(),
		opts:     Options{NoDataplane: true},
	}
	d.setDataplane(&runtimeOnlyApplyTestDP{}) // #2114: publish through the cell

	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"reth0": {Name: "reth0", Units: map[int]*config.InterfaceUnit{0: {Number: 0}}},
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"trust": {Name: "trust", Interfaces: []string{"reth0.0"}},
	}

	injected := errors.New("injected: mgmt-VRF RouteReplace rejected")
	// mgmtRouteErr is the FINAL applyTailReconciles operand; every other deferred
	// error is nil so it is the only thing that can surface.
	err := d.applyTailReconciles(cfg, nil, nil, nil, nil, nil, nil, nil, injected, nil, nil, nil)
	if err == nil {
		t.Fatal("applyTailReconciles must surface the mgmt-VRF route reconcile failure " +
			"(fail-closed); got nil")
	}
	if !errors.Is(err, injected) {
		t.Fatalf("returned commit error must include the mgmt-VRF route failure via the "+
			"tail errors.Join wiring, got %v", err)
	}
}

// RuleAddDSCP satisfies ruleOps. These domains (probe pins / rib-group leaks /
// reconcile) never emit a DSCP selector, so a call here means a rule was routed
// down the wrong path — fail loudly rather than silently accepting it.
func (f *fakeRuleOps5844) RuleAddDSCP(*netlink.Rule, uint8) error {
	return fmt.Errorf("unexpected RuleAddDSCP: this domain emits no DSCP selectors")
}
