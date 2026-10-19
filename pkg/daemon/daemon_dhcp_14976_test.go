package daemon

import (
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/ipsec"

	"golang.org/x/sync/semaphore"
)

// mgmtIPsecCfg14976 returns config text whose shape takes the
// management-only branch of onDHCPAddressChange: fxp0.0 is DHCP-managed
// and is NOT security-zoned (so no dataplane recompile is required),
// and — when ipsec is true — an IPsec gateway dynamically bound to it
// (no local-address), so ipsec.HasDHCPBoundGateway gates the rebind.
func mgmtIPsecCfg14976(ipsecBound bool) string {
	text := "set interfaces fxp0 unit 0 family inet dhcp\n"
	if ipsecBound {
		text += "set security ike gateway gw1 address 203.0.113.1\n" +
			"set security ike gateway gw1 external-interface fxp0.0\n"
	}
	return text
}

// mgmtIPsecDaemon14976 seeds a store with config A (DHCP-bound gateway)
// and builds a daemon wired for the management-only lease path: a real
// (unused) IPsec manager so the nil guard passes, an injected swanctl
// seam recording the config it received, and the mgmt-route seam
// stubbed (real netlink would fail in CI and latch route debt).
func mgmtIPsecDaemon14976(t *testing.T) (*Daemon, *configstore.Store) {
	t.Helper()
	s := newConfigStore(t, filepath.Join(t.TempDir(), "config.db"))
	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if _, err := s.LoadSet(mgmtIPsecCfg14976(true)); err != nil {
		t.Fatalf("LoadSet(A): %v", err)
	}
	if _, err := s.Commit(); err != nil {
		t.Fatalf("Commit(A): %v", err)
	}
	d := &Daemon{
		applySem: semaphore.NewWeighted(1),
		store:    s,
		ipsec:    ipsec.New(),
	}
	d.mgmt.Store(&managementReconciler{})
	d.reconcileDNSFn = func(*config.Config, bool) error { return nil }
	// The recompile predicate (§dhcpLeaseChangeRequiresRecompile) stays
	// conservative (forces a full recompile) until the apply path has
	// published the management-VRF interface set; publish fxp0 so the
	// callback takes the management-only branch this suite exercises.
	mgmtSet := map[string]bool{"fxp0": true}
	d.mgmtVRFInterfaces.Store(&mgmtSet)
	return d, s
}

// commit14976 loads+commits additional set-lines on a store already in
// configure mode. LoadSet LAYERS onto the candidate (it does not replace
// it), so the gateway-removal commit carries an explicit delete.
func commit14976(t *testing.T, s *configstore.Store, text string) {
	t.Helper()
	if _, err := s.LoadSet(text); err != nil {
		t.Fatalf("LoadSet: %v", err)
	}
	if _, err := s.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
}

// removeGateway14976 is the commit-B text: the DHCP interface stays, the
// IPsec gateway binding is deleted (the operator action the stale
// snapshot would silently resurrect).
const removeGateway14976 = "delete security ike gateway gw1\n"

// TestMgmtOnlyLeaseRefreshUsesFreshSnapshotAndSerializesRoutes14976 is the
// D33-04 (#14976) regression. It drives the REAL production callback
// onDHCPAddressChange. A commit removing the DHCP-bound gateway lands
// between the callback's branch decision (which reads config A) and the
// management-only work — injected deterministically via the mgmt-route
// seam, which on the broken code runs unserialized BEFORE any semaphore,
// and on the fixed code runs under applySem before the snapshot re-read.
//
// RED on pre-fix code:
//   - the mgmt-route seam observes applySem FREE (routes reconciled
//     unserialized against a concurrent commit), and
//   - reapplyIPsecForLeaseChange receives the stale config A, so the
//     just-removed gateway (and its PSKs) would be resurrected into
//     swanctl by ipsecApplyForLeaseChange.
//
// GREEN after the fix: the route seam runs under applySem, the snapshot
// is re-read after acquiring, the gate sees config B (no DHCP-bound
// gateway), and no swanctl apply happens.
func TestMgmtOnlyLeaseRefreshUsesFreshSnapshotAndSerializesRoutes14976(t *testing.T) {
	d, s := mgmtIPsecDaemon14976(t)

	var routeUnderSem atomic.Bool
	var routeCalls atomic.Int32
	prevRoute := mgmtRouteRefreshFn
	t.Cleanup(func() { mgmtRouteRefreshFn = prevRoute })
	mgmtRouteRefreshFn = func(dd *Daemon) error {
		routeCalls.Add(1)
		if d.applySem.TryAcquire(1) {
			d.applySem.Release(1)
		} else {
			routeUnderSem.Store(true)
		}
		// Land commit B while the refresh holds (fixed) / has not yet
		// taken (broken) the semaphore: removes the DHCP-bound gateway.
		commit14976(t, s, removeGateway14976)
		return nil
	}
	var applied []*config.Config
	d.ipsecApply = func(cfg *config.Config) error {
		applied = append(applied, cfg)
		return nil
	}
	var webCalls atomic.Int32
	prevWeb := webMgmtRebindApply
	t.Cleanup(func() { webMgmtRebindApply = prevWeb })
	webMgmtRebindApply = func(*Daemon, *config.Config) error {
		webCalls.Add(1)
		return nil
	}

	done := make(chan struct{})
	go func() {
		d.onDHCPAddressChange()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("onDHCPAddressChange did not return — nested applySem take deadlocked?")
	}
	if webCalls.Load() != 0 {
		t.Fatalf("web-management rebind driven %d time(s); config B binds no DHCP web-management leg", webCalls.Load())
	}
	if !routeUnderSem.Load() {
		t.Fatal("management-VRF route reconcile ran WITHOUT applySem held — " +
			"it can interleave with a concurrent commit's applyMgmtVRFRoutes (#14976)")
	}
	if len(applied) != 0 {
		t.Fatalf("IPsec rebind applied %d time(s) against the stale pre-commit snapshot — "+
			"the just-removed DHCP-bound gateway would be resurrected into swanctl (#14976)", len(applied))
	}
}

// TestMgmtOnlyLeaseRefreshStillRebindsLiveGateway14976 is the adjacent
// legitimate-behaviour control: with NO intervening commit, a DHCP lease
// change on a DHCP-bound IPsec gateway must still re-render swanctl, and
// with the gateway removed up front it must stay a no-op.
func TestMgmtOnlyLeaseRefreshStillRebindsLiveGateway14976(t *testing.T) {
	d, _ := mgmtIPsecDaemon14976(t)

	prevRoute := mgmtRouteRefreshFn
	t.Cleanup(func() { mgmtRouteRefreshFn = prevRoute })
	mgmtRouteRefreshFn = func(*Daemon) error { return nil }

	var applied []*config.Config
	d.ipsecApply = func(cfg *config.Config) error {
		applied = append(applied, cfg)
		return nil
	}

	done := make(chan struct{})
	go func() {
		d.onDHCPAddressChange()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("onDHCPAddressChange did not return")
	}
	if len(applied) != 1 {
		t.Fatalf("live DHCP-bound gateway: IPsec rebind applied %d times, want 1", len(applied))
	}
}
