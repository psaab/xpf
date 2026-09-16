package daemon

// #5700 (daemon/routing M25): a VRF setup or (management) bind failure was
// recorded "managed" and then DISCARDED from commit truth — applyVRFReconcile
// returned nil for every genuine ReconcileVRFs failure (WARN-only) even though
// reconcileVRFs's partial-failure contract still records the VRF in the managed
// set (IsManagedVRF true), and the authoritative post-networkd management-VRF
// re-bind swallowed its failure at WARN too. The commit reported the VRF
// configured while it was NOT on the kernel, with no retry owner to reconcile it
// (false convergence).
//
// The fix surfaces the TWO load-bearing, transient-free swallow sites into
// commit truth, mirroring the #5310 ifaceErr / #5696 routeLeakErr / #5844
// routingRuleErr deferred-error joins:
//   - applyVRFReconcile now returns a deferred vrfErr for a ReconcileVRFs
//     (VRF-device setup) failure — threaded into the tail errors.Join — while
//     the #2926-C1 ctx-cancellation still aborts unchanged;
//   - rebindManagementVRFIfaces aggregates the authoritative post-networkd
//     management-VRF bind failures and returns them (joined into networkdErr).
// The routing-instance member binds (which run before tunnel/xfrmi creation) and
// the pre-networkd management bind (stripped by networkctl reconfigure) remain
// best-effort WARN — surfacing them would promote an EXPECTED transient absence
// into a false commit failure.
//
// FAIL-ON-REVERT: restore applyVRFReconcile's `return nil` (drop vrfErr) and
// TestApplyVRFReconcileSurfacesSetupFailure_5700 goes RED (ctxErr/vrfErr both
// nil despite the injected setup failure). Restore rebindManagementVRFIfaces'
// WARN-only swallow and TestRebindManagementVRFSurfacesBindFailure_5700 goes RED.
// Drop vrfErr from the tail errors.Join and
// TestApplyTailReconcilesSurfacesVRFError_5700 goes RED.

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/networkd"
	"github.com/psaab/xpf/pkg/routing"
	"github.com/psaab/xpf/pkg/vrrp"
	"github.com/vishvananda/netlink"
)

// mgmtIfaceConfig is a minimal config whose single management interface (fxp0)
// makes applyVRFReconcile add vrf-mgmt to the desired VRF set (mgmtIfaces
// detection keys on the fxp*/fab*/em* prefix).
func mgmtIfaceConfig() *config.Config {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"fxp0": {Name: "fxp0"},
	}
	return cfg
}

// TestApplyVRFReconcileSurfacesSetupFailure_5700 drives the REAL
// applyVRFReconcile against a routing.Manager whose vrf-mgmt LinkAdd fails and
// asserts it returns the failure as the DEFERRED vrfErr (not the ctx-abort
// ctxErr), so the caller threads it into commit truth.
func TestApplyVRFReconcileSurfacesSetupFailure_5700(t *testing.T) {
	ops := newReconcileFakeLinkOps()
	injected := errors.New("injected: vrf-mgmt LinkAdd EPERM")
	ops.addFail["vrf-mgmt"] = injected

	d := &Daemon{routing: routing.NewManagerWithLinkOpsForTest(ops)}
	ctxErr, vrfErr := d.applyVRFReconcile(context.Background(), mgmtIfaceConfig())

	if ctxErr != nil {
		t.Fatalf("ctxErr must be nil for a non-cancellation setup failure, got %v", ctxErr)
	}
	if vrfErr == nil {
		t.Fatal("applyVRFReconcile must return the VRF-device setup failure as vrfErr " +
			"(fail-closed); got nil — the swallowed false-convergence #5700 describes")
	}
	if !errors.Is(vrfErr, injected) {
		t.Fatalf("vrfErr must wrap the injected ReconcileVRFs failure, got %v", vrfErr)
	}
}

// TestApplyVRFReconcileToleratesSuccess_5700 is the positive control: a VRF
// setup that succeeds does not fabricate a commit failure. The pre-networkd
// management bind may WARN (fxp0 is not a live link in the fake) but must NOT
// surface — only the setup (ReconcileVRFs) is load-bearing here.
func TestApplyVRFReconcileToleratesSuccess_5700(t *testing.T) {
	ops := newReconcileFakeLinkOps()

	d := &Daemon{routing: routing.NewManagerWithLinkOpsForTest(ops)}
	ctxErr, vrfErr := d.applyVRFReconcile(context.Background(), mgmtIfaceConfig())

	if ctxErr != nil {
		t.Fatalf("ctxErr = %v, want nil on the success path", ctxErr)
	}
	if vrfErr != nil {
		t.Fatalf("vrfErr = %v, want nil: a successful VRF-device setup must not fail "+
			"the commit (and a best-effort pre-networkd bind must not surface)", vrfErr)
	}
}

// TestApplyVRFReconcileCtxCancelIsNotVRFError_5700 proves the #2926-C1 boundary
// is preserved: a pre-cancelled context returns via ctxErr (the abort path),
// NOT vrfErr — so the cancellation still funnels through the host-authorization
// closeout and is never misreported as a VRF setup failure.
func TestApplyVRFReconcileCtxCancelIsNotVRFError_5700(t *testing.T) {
	ops := newReconcileFakeLinkOps()
	ops.addFail["vrf-mgmt"] = errors.New("would fail if reached")

	d := &Daemon{routing: routing.NewManagerWithLinkOpsForTest(ops)}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	ctxErr, vrfErr := d.applyVRFReconcile(ctx, mgmtIfaceConfig())

	if !errors.Is(ctxErr, context.Canceled) {
		t.Fatalf("ctxErr = %v, want context.Canceled (the #2926-C1 abort)", ctxErr)
	}
	if vrfErr != nil {
		t.Fatalf("vrfErr = %v, want nil: a C1 cancellation must not run the reconcile "+
			"or manufacture a VRF setup error", vrfErr)
	}
}

// TestRebindManagementVRFSurfacesBindFailure_5700 drives the REAL
// rebindManagementVRFIfaces against a routing.Manager where the management
// interface exists but vrf-mgmt does not, so BindInterfaceToVRF fails, and
// asserts the aggregated error is RETURNED (so the caller joins it into
// networkdErr / commit truth) instead of being swallowed at WARN.
func TestRebindManagementVRFSurfacesBindFailure_5700(t *testing.T) {
	ops := newReconcileFakeLinkOps()
	// fxp0 exists; vrf-mgmt does NOT — a genuine bind failure (VRF device absent).
	ops.links["fxp0"] = &netlink.Device{LinkAttrs: netlink.LinkAttrs{Name: "fxp0", Index: 2}}

	d := &Daemon{routing: routing.NewManagerWithLinkOpsForTest(ops)}
	d.publishMgmtVRFIfaces(map[string]bool{"fxp0": true})

	err := d.rebindManagementVRFIfaces()
	if err == nil {
		t.Fatal("rebindManagementVRFIfaces must return the management-VRF bind failure " +
			"(fail-closed); got nil — the swallowed false-convergence #5700 describes")
	}
}

// TestRebindManagementVRFToleratesSuccess_5700 is the positive control: when
// both the interface and vrf-mgmt exist, the bind succeeds and no error surfaces.
func TestRebindManagementVRFToleratesSuccess_5700(t *testing.T) {
	ops := newReconcileFakeLinkOps()
	ops.links["fxp0"] = &netlink.Device{LinkAttrs: netlink.LinkAttrs{Name: "fxp0", Index: 2}}
	ops.links["vrf-mgmt"] = &netlink.Vrf{LinkAttrs: netlink.LinkAttrs{Name: "vrf-mgmt", Index: 9}, Table: 999}

	d := &Daemon{routing: routing.NewManagerWithLinkOpsForTest(ops)}
	d.publishMgmtVRFIfaces(map[string]bool{"fxp0": true})

	if err := d.rebindManagementVRFIfaces(); err != nil {
		t.Fatalf("a successful management-VRF re-bind must not fail the commit, got %v", err)
	}
}

// TestRebindManagementVRFNoSetIsNoop_5700 proves the empty/no-mgmt-VRF case is a
// clean no-op (nil), so a non-VRF config never fails the commit here.
func TestRebindManagementVRFNoSetIsNoop_5700(t *testing.T) {
	ops := newReconcileFakeLinkOps()
	d := &Daemon{routing: routing.NewManagerWithLinkOpsForTest(ops)}
	// No publishMgmtVRFIfaces -> mgmtVRFIfaceSet() is empty.
	if err := d.rebindManagementVRFIfaces(); err != nil {
		t.Fatalf("no management-VRF interface set must be a no-op, got %v", err)
	}
}

// TestApplyTailReconcilesSurfacesVRFError_5700 is the commit-level wiring proof:
// it drives the REAL applyTailReconciles with an injected VRF error (vrfErr) and
// asserts the returned commit error includes it — pinning the tail errors.Join
// wiring the direct applyVRFReconcile test does not cover. The nft seams are
// stubbed to succeed so the injected vrfErr is the only operand that can surface.
//
// FAIL-ON-REVERT: drop vrfErr from that join and this goes RED (the apply
// completes and returns nil despite the VRF reconcile having failed).
func TestApplyTailReconcilesSurfacesVRFError_5700(t *testing.T) {
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

	injected := errors.New("injected: VRF reconcile (vrf-mgmt create) failed")
	// vrfErr is the LAST operand of applyTailReconciles.
	err := d.applyTailReconciles(cfg, nil, nil, nil, nil, nil, nil, nil, nil, injected, nil, nil)
	if err == nil {
		t.Fatal("applyTailReconciles must surface the VRF reconcile failure " +
			"(fail-closed); got nil")
	}
	if !errors.Is(err, injected) {
		t.Fatalf("returned commit error must include the VRF failure via the tail "+
			"errors.Join wiring, got %v", err)
	}
}

// TestApplyVRFReconcileMemberBindStaysBestEffort_5700 pins the transient-vs-fatal
// boundary the #5700 fix deliberately draws (the gap the PR #5945 hostile review
// surfaced). The PRE-networkd routing-instance MEMBER bind
// (BindInterfaceToVRF(member, ri.Name)) runs BEFORE applyInterfaceReconcile
// creates the tunnel/xfrmi member devices, so a member that is a later-created
// tunnel is legitimately "not found" at that phase — an EXPECTED transient
// absence. It MUST stay best-effort (WARN) and NOT surface into commit truth;
// only the transient-free ReconcileVRFs device setup (vrfErr) and the
// post-networkd rebindManagementVRFIfaces (networkdErr) are load-bearing.
//
// Isolation: ReconcileVRFs SUCCEEDS (vrf-blue LinkAdd has no addFail, so the
// device-setup path cannot confound vrfErr) and no fxp*/fab*/em* interface is
// present (so the management desired-VRF and its pre-networkd bind never run).
// Only the RI member ge-0-0-5 is absent from the fake link table, so
// BindInterfaceToVRF's LinkByName(member) returns LinkNotFoundError and ONLY the
// member bind fails. applyVRFReconcile must still return vrfErr == nil.
//
// FAIL-ON-REVERT: add `vrfErr = errors.Join(vrfErr, err)` to the member-bind
// loop in applyVRFReconcile (surface the transient) and this goes RED — the test
// is load-bearing against a regression that promotes the expected member-bind
// transient into a false commit failure. The existing
// TestApplyVRFReconcileToleratesSuccess_5700 covers the pre-networkd MGMT bind's
// best-effort-ness; this covers the routing-instance MEMBER bind.
func TestApplyVRFReconcileMemberBindStaysBestEffort_5700(t *testing.T) {
	ops := newReconcileFakeLinkOps()

	d := &Daemon{routing: routing.NewManagerWithLinkOpsForTest(ops)}

	cfg := &config.Config{}
	cfg.RoutingInstances = []*config.RoutingInstanceConfig{
		{
			Name:         "blue",
			InstanceType: "vrf",                // non-forwarding -> reconciled + member-bound
			TableID:      100,                  // vrf-blue LinkAdd succeeds (no addFail)
			Interfaces:   []string{"ge-0/0/5"}, // ge-0-0-5: absent from ops.links -> bind fails
		},
	}

	ctxErr, vrfErr := d.applyVRFReconcile(context.Background(), cfg)
	if ctxErr != nil {
		t.Fatalf("ctxErr = %v, want nil (not a #2926-C1 cancellation)", ctxErr)
	}
	if vrfErr != nil {
		t.Fatalf("vrfErr = %v, want nil: a routing-instance MEMBER bind failure is "+
			"best-effort (an expected transient before tunnel/xfrmi member creation) and "+
			"must NOT surface into commit truth — only the ReconcileVRFs device setup does "+
			"(#5700)", vrfErr)
	}
}
