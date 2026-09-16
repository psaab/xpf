package daemon

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/networkd"
	"github.com/psaab/xpf/pkg/vrrp"
)

// #5696 (M19, a #5642 residual): reconcileRouteLeakSnapshot is a commit-tail
// reconcile with NO dirty-retry engine (unlike the ip-monitoring actuator).
// A route-publication or FIB-invalidation failure MUST fail the commit closed —
// a deferred error threaded into applyTailReconciles' tail errors.Join — rather
// than be logged-and-forgotten. Otherwise the userspace FIB keeps the exact
// stale inter-VRF leak #5642 removed while the commit reports success, with no
// owner to rediscover the inconsistency. Benign no-ops (duplicate-skip,
// helperless, clean success) stay successful commits.
//
// These tests reuse the fakeOverlayDP publish surface from daemon_ipmon_test.go.

// TestRouteLeakReconcileFailsCommitOnPublishError: a transient routes-only
// republish failure surfaces as a non-nil deferred error that wraps the cause.
//
// FAIL-ON-REVERT: revert the publish leg back to a bare `return` (swallowing the
// error) and reconcileRouteLeakSnapshot returns nil — this test goes RED. That
// is the exact "logged and forgotten" fail-open the issue describes.
func TestRouteLeakReconcileFailsCommitOnPublishError(t *testing.T) {
	sentinel := errors.New("apply_snapshot socket timeout")
	dp := &fakeOverlayDP{publishErr: sentinel}
	d := &Daemon{}
	d.setDataplane(dp)

	err := d.reconcileRouteLeakSnapshot(&config.Config{}, nil)
	if err == nil {
		t.Fatal("route-leak republish failure must fail the commit (deferred error); got nil")
	}
	if !errors.Is(err, sentinel) {
		t.Fatalf("returned error must wrap the publish failure; got %v", err)
	}
	// Publish failed → the helper does not have the new routes, so no bump.
	for _, c := range dp.calls {
		if c == "bump" {
			t.Fatalf("calls = %v: bumped FIB generation after a failed publish", dp.calls)
		}
	}
}

// TestRouteLeakReconcileFailsCommitOnBumpError: the publish succeeds (route set
// moved) but the FIB-generation invalidation fails, so established flows stay
// pinned to the stale leak route — the commit must still fail closed.
//
// FAIL-ON-REVERT: revert the bump leg back to a bare warn (no error return) and
// this test goes RED.
func TestRouteLeakReconcileFailsCommitOnBumpError(t *testing.T) {
	sentinel := errors.New("bump_fib_generation control socket timeout")
	dp := &fakeOverlayDP{bumpErr: sentinel}
	d := &Daemon{}
	d.setDataplane(dp)

	err := d.reconcileRouteLeakSnapshot(&config.Config{}, nil)
	if err == nil {
		t.Fatal("route-leak FIB-bump failure must fail the commit (deferred error); got nil")
	}
	if !errors.Is(err, sentinel) {
		t.Fatalf("returned error must wrap the bump failure; got %v", err)
	}
	if len(dp.calls) != 2 || dp.calls[0] != "publish" || dp.calls[1] != "bump" {
		t.Fatalf("calls = %v, want [publish bump]", dp.calls)
	}
}

// TestRouteLeakReconcileDuplicateSkipStaysSuccess: an unchanged route set
// (PublishRouteOverlaySnapshot duplicate-skip → published=false) is a benign
// no-op — nil error, and no FIB-generation bump churn.
func TestRouteLeakReconcileDuplicateSkipStaysSuccess(t *testing.T) {
	dp := &fakeOverlayDP{publishSkipped: true}
	d := &Daemon{}
	d.setDataplane(dp)

	if err := d.reconcileRouteLeakSnapshot(&config.Config{}, nil); err != nil {
		t.Fatalf("duplicate-skip must stay a successful commit; got %v", err)
	}
	for _, c := range dp.calls {
		if c == "bump" {
			t.Fatalf("calls = %v: bumped FIB generation on a duplicate-skip", dp.calls)
		}
	}
}

// TestRouteLeakReconcileSuccessStaysSuccess: a real publish followed by a
// confirmed bump is a clean, successful commit.
func TestRouteLeakReconcileSuccessStaysSuccess(t *testing.T) {
	dp := &fakeOverlayDP{}
	d := &Daemon{}
	d.setDataplane(dp)

	if err := d.reconcileRouteLeakSnapshot(&config.Config{}, nil); err != nil {
		t.Fatalf("clean republish+bump must be a successful commit; got %v", err)
	}
	if len(dp.calls) != 2 || dp.calls[0] != "publish" || dp.calls[1] != "bump" {
		t.Fatalf("calls = %v, want [publish bump]", dp.calls)
	}
}

// TestRouteLeakReconcileHelperlessStaysSuccess: with no routeOverlayPublisher
// (helperless dataplane) the kernel ip-rule reconcile is the only route-leak
// consumer and already ran — a benign no-op that keeps the commit successful.
func TestRouteLeakReconcileHelperlessStaysSuccess(t *testing.T) {
	d := &Daemon{} // d.dp is nil → not a routeOverlayPublisher
	if err := d.reconcileRouteLeakSnapshot(&config.Config{}, nil); err != nil {
		t.Fatalf("helperless reconcile must stay a successful commit; got %v", err)
	}
}

// TestApplyTailReconcilesSurfacesRouteLeakError is the commit-level wiring proof
// (#5696): it drives the REAL applyTailReconciles with an injected route-leak
// error in the routeLeakErr slot and asserts the returned commit error includes
// it via the tail errors.Join.
//
// FAIL-ON-REVERT: drop routeLeakErr from that join (or from the parameter list)
// and this test goes RED — the apply completes and returns nil despite the
// route-leak reconcile having failed. The nft seams are stubbed to succeed so
// the injected routeLeakErr is the ONLY operand that can surface.
func TestApplyTailReconcilesSurfacesRouteLeakError(t *testing.T) {
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

	injected := errors.New("injected: route-leak snapshot republish failed")
	err := d.applyTailReconciles(cfg, nil, nil, nil, nil, nil, injected, nil, nil, nil, nil, nil)
	if err == nil {
		t.Fatal("applyTailReconciles must surface the route-leak reconcile failure " +
			"(fail-closed); got nil")
	}
	if !errors.Is(err, injected) {
		t.Fatalf("returned commit error must include the route-leak failure via the "+
			"tail errors.Join wiring, got %v", err)
	}
}
