package vrrp

import (
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
)

// #2156 — UpdateInstances build-before-teardown for interface-index changes:
// a transient member-link or socket-open failure during rebind must NOT orphan
// the RG out of VRRP election. The old instance keeps running and is retried
// once the interface returns. VIP-set commits use updateVIPs in place (#10780).
// These tests drive the real UpdateInstances diff via injectable lifecycle
// seams (no real sockets, no live run() goroutine).

// newTestManagerNoNetwork returns a Manager whose lifecycle seams never touch
// the network or spawn goroutines, plus recorders for asserting the
// teardown/start ordering. The link-watcher seams are stubbed so a tracked
// interface doesn't start a real netlink subscription.
func newTestManagerNoNetwork() (*Manager, *lifecycleRecorder) {
	m := NewManager()
	rec := &lifecycleRecorder{}

	m.linkState = func(string) (bool, error) { return true, nil }
	m.subscribeLinks = func(ch chan<- netlink.LinkUpdate, done <-chan struct{}) error { return nil }
	// Stub the #2528 addr-watcher subscription so UpdateInstances never opens
	// a real netlink address socket. Returning nil leaves the watcher
	// subscribed-but-silent (no events), matching the link-watcher stub above.
	m.subscribeAddrs = func(ch chan<- netlink.AddrUpdate, done <-chan struct{}) error { return nil }
	// A VIP-family edit is covered by dedicated socket tests; the lifecycle
	// manager fixture must never open privileged raw sockets.
	m.ensureVIPFamilySockets = func(*vrrpInstance, []string) error { return nil }

	// resolveIface returns a synthetic interface; failures are injected via
	// openInstanceSocket so we exercise the socket-open arm of the bug.
	m.resolveIface = func(name string) (*net.Interface, error) {
		return &net.Interface{Name: name, Index: 1}, nil
	}
	m.openInstanceSocket = func(vi *vrrpInstance) error {
		rec.mu.Lock()
		defer rec.mu.Unlock()
		rec.openCalls++
		if rec.openShouldFail.Load() {
			return errSocketOpenFailed
		}
		return nil
	}
	m.runInstance = func(vi *vrrpInstance) {
		rec.mu.Lock()
		rec.runCalls++
		rec.lastRun = vi
		rec.mu.Unlock()
		// Mark the instance "started" so stop() (if ever called on it)
		// would not deadlock: close stopped on a goroutine the way run()
		// does. Tests that assert no-stop never reach here for the old vi.
		close(vi.stopped)
	}
	m.stopInstance = func(vi *vrrpInstance) {
		rec.mu.Lock()
		rec.stopCalls++
		rec.stopped = append(rec.stopped, vi)
		rec.mu.Unlock()
		// Mimic vi.stop()'s observable effect without touching sockets.
		select {
		case <-vi.stopCh:
		default:
			close(vi.stopCh)
		}
	}
	return m, rec
}

var errSocketOpenFailed = &socketOpenError{}

type socketOpenError struct{}

func (e *socketOpenError) Error() string { return "test: socket open failed" }

type lifecycleRecorder struct {
	mu             sync.Mutex
	openCalls      int
	runCalls       int
	stopCalls      int
	lastRun        *vrrpInstance
	stopped        []*vrrpInstance
	openShouldFail atomic.Bool
}

func (r *lifecycleRecorder) snapshot() (open, run, stop int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.openCalls, r.runCalls, r.stopCalls
}

// TestUpdateInstances_BuildBeforeTeardown_KeepsOldOnSocketFailure asserts the
// #2156 fix for an ifindex rebind: if the replacement socket fails to open,
// the ORIGINAL instance stays in m.instances unchanged — it is neither deleted
// (orphaned) nor stopped, and the failed replacement is never started.
func TestUpdateInstances_BuildBeforeTeardown_KeepsOldOnSocketFailure(t *testing.T) {
	m, rec := newTestManagerNoNetwork()
	defer stopManagerForTest(m)
	m.resolveIface = func(name string) (*net.Interface, error) {
		return &net.Interface{Name: name, Index: 2}, nil
	}

	key := instanceKey{iface: "reth0.50", groupID: 101} // RETH VRID for RG 1

	// Seed an established, "running" instance with the original VIP set.
	orig := newInstance(Instance{
		Interface:        "reth0.50",
		GroupID:          101,
		Priority:         200,
		Preempt:          true,
		VirtualAddresses: []string{"172.16.50.1/24"},
	}, &net.Interface{Name: "reth0.50", Index: 1}, m.eventCh, nil)
	m.mu.Lock()
	m.instances[key] = orig
	m.mu.Unlock()

	// RGVRRPReady is truthful before the failed update.
	if ready, _ := m.RGVRRPReady(1, true); !ready {
		t.Fatal("RGVRRPReady(1) should be true with the original instance present")
	}

	// Inject a socket-open failure, then simulate the member netdev being
	// recreated under the same name with a new ifindex.
	rec.openShouldFail.Store(true)
	desired := []*Instance{{
		Interface:        "reth0.50",
		GroupID:          101,
		Priority:         200,
		Preempt:           true,
		VirtualAddresses: []string{"172.16.50.1/24"},
	}}
	if err := m.UpdateInstances(desired); err != nil {
		t.Fatalf("UpdateInstances: %v", err)
	}

	// The original instance must still own the key (no orphan).
	m.mu.RLock()
	got, ok := m.instances[key]
	n := len(m.instances)
	m.mu.RUnlock()
	if !ok || got != orig {
		t.Fatalf("after failed restart: key not owned by original instance (ok=%v same=%v)", ok, got == orig)
	}
	if n != 1 {
		t.Fatalf("expected exactly 1 instance, got %d", n)
	}

	// The original must NOT have been stopped, and the failed replacement
	// must NOT have been started (no double-run, no orphan).
	open, run, stop := rec.snapshot()
	if open != 1 {
		t.Errorf("openInstanceSocket calls = %d, want 1 (the failed attempt)", open)
	}
	if run != 0 {
		t.Errorf("runInstance calls = %d, want 0 (replacement never started)", run)
	}
	if stop != 0 {
		t.Errorf("stopInstance calls = %d, want 0 (original kept running)", stop)
	}
	// The old instance remains registered with its prior config; because its
	// ifindex is stale, this assertion does not claim the old socket advertises.
	if got.cfg.VirtualAddresses[0] != "172.16.50.1/24" {
		t.Errorf("original VIP = %q, want 172.16.50.1/24 (unchanged)", got.cfg.VirtualAddresses[0])
	}

	// The stale socket is retained safely, but the RG is not ready until rebind.
	if ready, reasons := m.RGVRRPReady(1, true); ready {
		t.Fatal("RGVRRPReady(1) must be false while the retained instance may be bound to a stale ifindex")
	} else if len(reasons) == 0 || !strings.Contains(strings.Join(reasons, " "), "ifindex rebind failed") {
		t.Fatalf("stale-ifindex readiness reason missing: %v", reasons)
	}

	// A later transient probe error must not erase a previously observed,
	// unresolved rebind from RG readiness.
	m.resolveIface = func(string) (*net.Interface, error) {
		return nil, errSocketOpenFailed
	}
	if err := m.UpdateInstances(desired); err != nil {
		t.Fatalf("UpdateInstances after transient resolve failure: %v", err)
	}
	if ready, reasons := m.RGVRRPReady(1, true); ready ||
		!strings.Contains(strings.Join(reasons, " "), "ifindex rebind failed") {
		t.Fatalf("stale-ifindex readiness was cleared by a probe error: ready=%v reasons=%v",
			ready, reasons)
	}
}

// TestUpdateInstances_ReDriveRecoversOnLinkReturn asserts the bounded
// self-recovery (#2156 B1 at the manager layer): after a transient socket
// failure leaves the old ifindex-bound instance running, a subsequent reconcile
// after the replacement socket succeeds swaps it and stops the old instance.
func TestUpdateInstances_ReDriveRecoversOnLinkReturn(t *testing.T) {
	m, rec := newTestManagerNoNetwork()
	defer stopManagerForTest(m)
	m.resolveIface = func(name string) (*net.Interface, error) {
		return &net.Interface{Name: name, Index: 2}, nil
	}

	key := instanceKey{iface: "reth0.50", groupID: 101}
	orig := newInstance(Instance{
		Interface:        "reth0.50",
		GroupID:          101,
		Priority:         200,
		Preempt:          true,
		VirtualAddresses: []string{"172.16.50.1/24"},
	}, &net.Interface{Name: "reth0.50", Index: 1}, m.eventCh, nil)
	m.mu.Lock()
	m.instances[key] = orig
	m.mu.Unlock()

	desired := []*Instance{{
		Interface:        "reth0.50",
		GroupID:          101,
		Priority:         200,
		Preempt:          true,
		VirtualAddresses: []string{"172.16.50.1/24"},
	}}

	// Pass 1: socket fails — old ifindex-bound instance survives.
	rec.openShouldFail.Store(true)
	if err := m.UpdateInstances(desired); err != nil {
		t.Fatalf("UpdateInstances pass 1: %v", err)
	}
	m.mu.RLock()
	if m.instances[key] != orig {
		m.mu.RUnlock()
		t.Fatal("pass 1: original instance was orphaned")
	}
	m.mu.RUnlock()

	// Pass 2: replacement socket now opens. The re-drive rebinds the
	// unchanged config to the new ifindex and tears down the old instance.
	rec.openShouldFail.Store(false)
	if err := m.UpdateInstances(desired); err != nil {
		t.Fatalf("UpdateInstances pass 2: %v", err)
	}

	m.mu.RLock()
	got, ok := m.instances[key]
	n := len(m.instances)
	m.mu.RUnlock()
	if !ok {
		t.Fatal("pass 2: key missing after successful re-drive")
	}
	if got == orig {
		t.Fatal("pass 2: instance was not replaced")
	}
	if n != 1 {
		t.Fatalf("pass 2: expected exactly 1 instance, got %d", n)
	}
	if got.cfg.VirtualAddresses[0] != "172.16.50.1/24" {
		t.Errorf("pass 2: VIP = %q, want 172.16.50.1/24", got.cfg.VirtualAddresses[0])
	}

	// Ordering: exactly one stop (the old) and one run (the new), and the
	// old instance is the one that was stopped (build-before-teardown stops
	// only after the replacement is proven buildable).
	open, run, stop := rec.snapshot()
	if open != 2 {
		t.Errorf("openInstanceSocket calls = %d, want 2 (fail + success)", open)
	}
	if run != 1 {
		t.Errorf("runInstance calls = %d, want 1 (new instance started once)", run)
	}
	if stop != 1 {
		t.Errorf("stopInstance calls = %d, want 1 (old instance stopped once)", stop)
	}
	rec.mu.Lock()
	stoppedOld := len(rec.stopped) == 1 && rec.stopped[0] == orig
	startedNew := rec.lastRun == got
	rec.mu.Unlock()
	if !stoppedOld {
		t.Error("the stopped instance was not the original (teardown ordering wrong)")
	}
	if !startedNew {
		t.Error("the started instance was not the new replacement")
	}

	// RGVRRPReady remained truthful across both passes.
	if ready, _ := m.RGVRRPReady(1, true); !ready {
		t.Fatal("RGVRRPReady(1) should be true after recovery")
	}
}

// TestUpdateInstances_NewKeyFailureNoPhantom asserts that a brand-new key
// whose socket fails to open is simply not created (no phantom entry), and a
// retry creates it once the socket succeeds. This guards the symmetry of the
// build block for the new-key path.
func TestUpdateInstances_NewKeyFailureNoPhantom(t *testing.T) {
	m, rec := newTestManagerNoNetwork()
	defer stopManagerForTest(m)

	desired := []*Instance{{
		Interface:        "reth0.50",
		GroupID:          101,
		Priority:         200,
		Preempt:          true,
		VirtualAddresses: []string{"172.16.50.1/24"},
	}}

	rec.openShouldFail.Store(true)
	if err := m.UpdateInstances(desired); err != nil {
		t.Fatalf("UpdateInstances (fail): %v", err)
	}
	m.mu.RLock()
	n := len(m.instances)
	m.mu.RUnlock()
	if n != 0 {
		t.Fatalf("failed new-key build left %d phantom instance(s), want 0", n)
	}
	// Gate is not satisfied by a phantom — RG has RETH but no instance.
	if ready, _ := m.RGVRRPReady(1, true); ready {
		t.Fatal("RGVRRPReady(1) must be false when the only build attempt failed")
	}

	rec.openShouldFail.Store(false)
	if err := m.UpdateInstances(desired); err != nil {
		t.Fatalf("UpdateInstances (retry): %v", err)
	}
	m.mu.RLock()
	n = len(m.instances)
	m.mu.RUnlock()
	if n != 1 {
		t.Fatalf("retry created %d instance(s), want 1", n)
	}
	if ready, _ := m.RGVRRPReady(1, true); !ready {
		t.Fatal("RGVRRPReady(1) should be true after the retry created the instance")
	}
}

// TestUpdateInstances_PartialBuild_RGNotReady is the #5641 fail-on-revert
// pin. An RG commonly has SEVERAL desired RETH keys under ONE VRID: a
// VLAN-tagged reth yields one instance per sub-interface (reth0.50 + reth0.80),
// both GroupID 100+rgID, and reths can share the RG. When ONE key's build
// fails (resolve / socket / family capability) its VIP is dark even though the
// sibling instance for the same VRID is live and advertising. RGVRRPReady must
// report the RG NOT ready and name the un-built key — otherwise the cluster
// state machine releases the sync hold / preempts / claims ownership while a
// desired VIP never advertises.
//
// REVERT NEUTRALIZATION (firsthand parent-RED): in RGVRRPReady delete the
// m.unbuiltDesired scan — the `for key, reason := range m.unbuiltDesired { … }`
// loop through `if len(unready) > 0 { … return false, unready }`. RGVRRPReady
// then finds the built reth0.50 instance and returns (true, nil), so the
// `if ready` assertion below fires: a clean assertion failure, not a compile
// break. (Neutralizing `m.unbuiltDesired = unbuilt` at the end of
// UpdateInstances produces the identical RED.)
func TestUpdateInstances_PartialBuild_RGNotReady(t *testing.T) {
	m, _ := newTestManagerNoNetwork()
	defer stopManagerForTest(m)

	// Fail the socket for reth0.80 ONLY; reth0.50 builds normally. Both are
	// RETH keys (empty family) under VRID 101 → RG 1.
	m.openInstanceSocket = func(vi *vrrpInstance) error {
		if vi.cfg.Interface == "reth0.80" {
			return errSocketOpenFailed
		}
		return nil
	}

	desired := []*Instance{
		{
			Interface:        "reth0.50",
			GroupID:          101,
			Priority:         200,
			Preempt:          true,
			VirtualAddresses: []string{"172.16.50.8/24"},
		},
		{
			Interface:        "reth0.80",
			GroupID:          101,
			Priority:         200,
			Preempt:          true,
			VirtualAddresses: []string{"172.16.80.8/24"},
		},
	}
	if err := m.UpdateInstances(desired); err != nil {
		t.Fatalf("UpdateInstances: %v", err)
	}

	// Exactly one sibling built; the other is dark (no phantom placeholder).
	m.mu.RLock()
	_, has50 := m.instances[instanceKey{iface: "reth0.50", groupID: 101}]
	_, has80 := m.instances[instanceKey{iface: "reth0.80", groupID: 101}]
	n := len(m.instances)
	m.mu.RUnlock()
	if !has50 {
		t.Fatal("reth0.50 should have built")
	}
	if has80 {
		t.Fatal("reth0.80 build was injected to fail but an instance exists")
	}
	if n != 1 {
		t.Fatalf("expected exactly 1 live instance, got %d", n)
	}

	// THE PIN: a partially-built RG must report NOT ready, naming the un-built
	// key. Pre-fix this returned (true, nil) off the built reth0.50 sibling.
	ready, reasons := m.RGVRRPReady(1, true)
	if ready {
		t.Fatal("RGVRRPReady(1) must be FALSE while reth0.80's VIP is dark (partial build)")
	}
	if len(reasons) == 0 {
		t.Fatal("RGVRRPReady(1) must return a reason naming the un-built key")
	}
	joined := strings.Join(reasons, " ")
	if !strings.Contains(joined, "reth0.80") {
		t.Fatalf("readiness reasons must name the un-built key reth0.80, got: %v", reasons)
	}
	if strings.Contains(joined, "reth0.50") {
		t.Fatalf("readiness reasons wrongly named the BUILT sibling reth0.50: %v", reasons)
	}

	// Recovery: let reth0.80 build too. Every desired key now has a live
	// instance → the RG is ready with no reasons and the unbuilt record clears.
	m.openInstanceSocket = func(vi *vrrpInstance) error { return nil }
	if err := m.UpdateInstances(desired); err != nil {
		t.Fatalf("UpdateInstances (recovery): %v", err)
	}
	m.mu.RLock()
	n = len(m.instances)
	m.mu.RUnlock()
	if n != 2 {
		t.Fatalf("expected both instances after recovery, got %d", n)
	}
	if ready, reasons := m.RGVRRPReady(1, true); !ready || reasons != nil {
		t.Fatalf("RGVRRPReady(1) must be (true, nil) once every desired key built: ready=%v reasons=%v", ready, reasons)
	}
}

// seedRunningInstance installs an already-"running" instance for the given key
// bound to the supplied ifindex. The instance's stopped channel is left open
// so the stub stopInstance (which only records) does not block; the real run()
// goroutine is never started in these no-network tests.
func seedRunningInstance(m *Manager, key instanceKey, cfg Instance, ifindex int) *vrrpInstance {
	vi := newInstance(cfg, &net.Interface{Name: cfg.Interface, Index: ifindex}, m.eventCh, nil)
	m.mu.Lock()
	m.instances[key] = vi
	m.mu.Unlock()
	return vi
}

// TestUpdateInstances_IfindexChange_RestartsRebind asserts the #2294 fix: when
// a running instance's member interface keeps the SAME xpf config but its
// kernel ifindex changes (netdev delete+recreate / rename), the reconcile path
// detects the drift and restarts the instance — stopping the stale-bound old
// one and starting a fresh instance bound to the NEW ifindex. Without the fix
// the byte-identical config hits the "No change" continue and the instance
// keeps its socket bound to the dead ifindex → permanent VRRP silence. This
// test FAILS if the ifindex-drift detection is reverted (no restart occurs).
func TestUpdateInstances_IfindexChange_RestartsRebind(t *testing.T) {
	m, rec := newTestManagerNoNetwork()
	defer stopManagerForTest(m)

	// resolveIface returns whatever ifindex the test currently advertises.
	var liveIndex atomic.Int64
	liveIndex.Store(7)
	m.resolveIface = func(name string) (*net.Interface, error) {
		return &net.Interface{Name: name, Index: int(liveIndex.Load())}, nil
	}

	key := instanceKey{iface: "reth0.50", groupID: 101}
	cfg := Instance{
		Interface:        "reth0.50",
		GroupID:          101,
		Priority:         200,
		Preempt:          true,
		VirtualAddresses: []string{"172.16.50.1/24"},
	}
	orig := seedRunningInstance(m, key, cfg, 7) // bound to ifindex 7

	// The netdev was deleted+recreated under the same name → new ifindex 9,
	// while the desired config is byte-identical.
	liveIndex.Store(9)
	desired := []*Instance{{
		Interface:        "reth0.50",
		GroupID:          101,
		Priority:         200,
		Preempt:          true,
		VirtualAddresses: []string{"172.16.50.1/24"}, // UNCHANGED config
	}}
	if err := m.UpdateInstances(desired); err != nil {
		t.Fatalf("UpdateInstances: %v", err)
	}

	open, run, stop := rec.snapshot()
	if open != 1 || run != 1 || stop != 1 {
		t.Fatalf("ifindex drift must restart: open=%d run=%d stop=%d, want 1/1/1", open, run, stop)
	}

	m.mu.RLock()
	got, ok := m.instances[key]
	n := len(m.instances)
	m.mu.RUnlock()
	if !ok || n != 1 {
		t.Fatalf("expected exactly 1 instance for the key, ok=%v n=%d", ok, n)
	}
	if got == orig {
		t.Fatal("instance was not replaced — stale ifindex socket kept (bug)")
	}
	if got.iface.Index != 9 {
		t.Fatalf("replacement bound to ifindex %d, want 9 (new live ifindex)", got.iface.Index)
	}

	rec.mu.Lock()
	stoppedOld := len(rec.stopped) == 1 && rec.stopped[0] == orig
	rec.mu.Unlock()
	if !stoppedOld {
		t.Fatal("the stopped instance was not the original (build-before-teardown ordering wrong)")
	}

	// Restart must preserve the configured priority/preempt/VIPs.
	if got.cfg.Priority != 200 || !got.cfg.Preempt {
		t.Fatalf("restart lost config: priority=%d preempt=%v, want 200/true", got.cfg.Priority, got.cfg.Preempt)
	}
	if !vipsEqual(got.cfg.VirtualAddresses, cfg.VirtualAddresses) {
		t.Fatalf("restart lost VIPs: %v, want %v", got.cfg.VirtualAddresses, cfg.VirtualAddresses)
	}
}

// TestUpdateInstances_IfindexUnchanged_NoRestart asserts the idempotence half
// of #2294: a reconcile pass where the resolved ifindex matches the bound
// ifindex and the config is unchanged must NOT restart the instance (no socket
// churn, no spurious failover). This is the steady-state every-2s reconcile
// case; a regression here would restart-storm every RG.
func TestUpdateInstances_IfindexUnchanged_NoRestart(t *testing.T) {
	m, rec := newTestManagerNoNetwork()
	defer stopManagerForTest(m)

	// Live ifindex stays equal to the bound one.
	m.resolveIface = func(name string) (*net.Interface, error) {
		return &net.Interface{Name: name, Index: 5}, nil
	}

	key := instanceKey{iface: "reth0.50", groupID: 101}
	cfg := Instance{
		Interface:        "reth0.50",
		GroupID:          101,
		Priority:         200,
		Preempt:          true,
		VirtualAddresses: []string{"172.16.50.1/24"},
	}
	orig := seedRunningInstance(m, key, cfg, 5)

	desired := []*Instance{{
		Interface:        "reth0.50",
		GroupID:          101,
		Priority:         200,
		Preempt:          true,
		VirtualAddresses: []string{"172.16.50.1/24"},
	}}

	// Drive the reconcile several times — must remain a no-op every time.
	for i := 0; i < 3; i++ {
		if err := m.UpdateInstances(desired); err != nil {
			t.Fatalf("UpdateInstances pass %d: %v", i, err)
		}
	}

	open, run, stop := rec.snapshot()
	if open != 0 || run != 0 || stop != 0 {
		t.Fatalf("unchanged ifindex must NOT restart: open=%d run=%d stop=%d, want 0/0/0", open, run, stop)
	}
	m.mu.RLock()
	got := m.instances[key]
	m.mu.RUnlock()
	if got != orig {
		t.Fatal("instance was replaced despite unchanged ifindex+config (idempotence broken)")
	}
}

// TestUpdateInstances_IfindexUnchanged_PriorityOnlyStaysInPlace asserts that a
// priority-only delta with an UNCHANGED ifindex still takes the cheap in-place
// updateConfig path (no restart) — the #2294 ifindex check must not turn a
// priority bump into a socket-churning restart. Guards against over-triggering.
func TestUpdateInstances_IfindexUnchanged_PriorityOnlyStaysInPlace(t *testing.T) {
	m, rec := newTestManagerNoNetwork()
	defer stopManagerForTest(m)

	m.resolveIface = func(name string) (*net.Interface, error) {
		return &net.Interface{Name: name, Index: 5}, nil
	}

	key := instanceKey{iface: "reth0.50", groupID: 101}
	orig := seedRunningInstance(m, key, Instance{
		Interface:        "reth0.50",
		GroupID:          101,
		Priority:         200,
		Preempt:          true,
		VirtualAddresses: []string{"172.16.50.1/24"},
	}, 5)

	desired := []*Instance{{
		Interface:        "reth0.50",
		GroupID:          101,
		Priority:         150, // priority changed, VIPs + ifindex unchanged
		Preempt:          true,
		VirtualAddresses: []string{"172.16.50.1/24"},
	}}
	if err := m.UpdateInstances(desired); err != nil {
		t.Fatalf("UpdateInstances: %v", err)
	}

	open, run, stop := rec.snapshot()
	if open != 0 || run != 0 || stop != 0 {
		t.Fatalf("priority-only delta must stay in-place: open=%d run=%d stop=%d, want 0/0/0", open, run, stop)
	}
	m.mu.RLock()
	got := m.instances[key]
	m.mu.RUnlock()
	if got != orig {
		t.Fatal("priority-only delta replaced the instance (should be in-place)")
	}
	if got.cfg.Priority != 150 {
		t.Fatalf("in-place update did not apply priority: got %d, want 150", got.cfg.Priority)
	}
}

// TestUpdateInstances_AdvertiseIntervalOnlyAppliedInPlace is the #5087
// fail-on-revert pin for reth-advertise-interval. A commit that changes ONLY
// the advertise-interval (VIPs + ifindex + priority + preempt + tracking all
// unchanged) must NOT hit the no-change shortcut: the running instance's
// cfg.AdvertiseInterval must be updated in place so the advert timer re-arms to
// the new interval on its next fire.
//
// REVERT NEUTRALIZATION (firsthand-verified RED both ways):
//   - Drop `existing.cfg.AdvertiseInterval == inst.AdvertiseInterval` from the
//     no-change gate in UpdateInstances → an interval-only delta matches the
//     shortcut, `continue // No change` runs, updateConfig is never called, and
//     cfg.AdvertiseInterval stays 1000 → the assertions below fire.
//   - Drop `vi.cfg.AdvertiseInterval = cfg.AdvertiseInterval` from updateConfig
//     → the gate detects the change and takes the in-place arm, but the field
//     is never copied, so cfg.AdvertiseInterval stays 1000 → same RED.
//
// The advertInterval() assertion pins the run loop's actual timer source: the
// MASTER select re-arms via advertTimer.Reset(vi.advertInterval()), so proving
// advertInterval() now yields the new Duration proves the timer re-arms to the
// new interval — not merely that a struct field was written.
func TestUpdateInstances_AdvertiseIntervalOnlyAppliedInPlace(t *testing.T) {
	m, rec := newTestManagerNoNetwork()
	defer stopManagerForTest(m)

	m.resolveIface = func(name string) (*net.Interface, error) {
		return &net.Interface{Name: name, Index: 5}, nil
	}

	key := instanceKey{iface: "reth0.50", groupID: 101}
	orig := seedRunningInstance(m, key, Instance{
		Interface:         "reth0.50",
		GroupID:           101,
		Priority:          200,
		Preempt:           true,
		AdvertiseInterval: 1000, // day-1 interval (1s)
		GARPCount:         3,
		VirtualAddresses:  []string{"172.16.50.1/24"},
	}, 5)

	// Day-2 change: only reth-advertise-interval moves 1000ms → 30ms.
	desired := []*Instance{{
		Interface:         "reth0.50",
		GroupID:           101,
		Priority:          200,
		Preempt:           true,
		AdvertiseInterval: 30,
		GARPCount:         3,
		VirtualAddresses:  []string{"172.16.50.1/24"},
	}}
	if err := m.UpdateInstances(desired); err != nil {
		t.Fatalf("UpdateInstances: %v", err)
	}

	// The delta must take the cheap in-place path, not a socket-churning restart.
	open, run, stop := rec.snapshot()
	if open != 0 || run != 0 || stop != 0 {
		t.Fatalf("advertise-interval-only delta must stay in-place: open=%d run=%d stop=%d, want 0/0/0", open, run, stop)
	}
	m.mu.RLock()
	got := m.instances[key]
	m.mu.RUnlock()
	if got != orig {
		t.Fatal("advertise-interval-only delta replaced the instance (should be in-place)")
	}

	// THE PIN: the running instance picked up the new interval. RED if either
	// the no-change gate or the updateConfig copy is reverted.
	if got.cfg.AdvertiseInterval != 30 {
		t.Fatalf("in-place update did not apply advertise-interval: got %d, want 30", got.cfg.AdvertiseInterval)
	}
	// The advert timer re-arms to this Duration on its next fire (the run loop's
	// advertTimer.Reset(vi.advertInterval()) source).
	if iv := got.advertInterval(); iv != 30*time.Millisecond {
		t.Fatalf("advertInterval() = %v, want 30ms — advert timer would not re-arm to the new interval", iv)
	}
}

// TestUpdateInstances_GARPCountOnlyAppliedInPlace is the #5087 fail-on-revert
// pin for gratuitous-arp-count. A commit changing ONLY gratuitous-arp-count
// (everything else unchanged) must update the running instance's cfg.GARPCount
// in place so the NEXT failover's sendGARP burst uses the new count — sendGARP
// re-reads vi.cfg.GARPCount on every call.
//
// REVERT NEUTRALIZATION: identical to the advertise-interval pin — dropping
// `existing.cfg.GARPCount == inst.GARPCount` from the no-change gate makes a
// count-only delta hit the `continue // No change` shortcut, and dropping
// `vi.cfg.GARPCount = cfg.GARPCount` from updateConfig leaves the field stale
// after the in-place arm runs. Either way cfg.GARPCount stays 3 → RED.
func TestUpdateInstances_GARPCountOnlyAppliedInPlace(t *testing.T) {
	m, rec := newTestManagerNoNetwork()
	defer stopManagerForTest(m)

	m.resolveIface = func(name string) (*net.Interface, error) {
		return &net.Interface{Name: name, Index: 5}, nil
	}

	key := instanceKey{iface: "reth0.50", groupID: 101}
	orig := seedRunningInstance(m, key, Instance{
		Interface:         "reth0.50",
		GroupID:           101,
		Priority:          200,
		Preempt:           true,
		AdvertiseInterval: 30,
		GARPCount:         3, // day-1 default burst
		VirtualAddresses:  []string{"172.16.50.1/24"},
	}, 5)

	// Day-2 change: only gratuitous-arp-count moves 3 → 5.
	desired := []*Instance{{
		Interface:         "reth0.50",
		GroupID:           101,
		Priority:          200,
		Preempt:           true,
		AdvertiseInterval: 30,
		GARPCount:         5,
		VirtualAddresses:  []string{"172.16.50.1/24"},
	}}
	if err := m.UpdateInstances(desired); err != nil {
		t.Fatalf("UpdateInstances: %v", err)
	}

	open, run, stop := rec.snapshot()
	if open != 0 || run != 0 || stop != 0 {
		t.Fatalf("gratuitous-arp-count-only delta must stay in-place: open=%d run=%d stop=%d, want 0/0/0", open, run, stop)
	}
	m.mu.RLock()
	got := m.instances[key]
	m.mu.RUnlock()
	if got != orig {
		t.Fatal("gratuitous-arp-count-only delta replaced the instance (should be in-place)")
	}

	// THE PIN: the running instance picked up the new burst count. RED if either
	// the no-change gate or the updateConfig copy is reverted.
	if got.cfg.GARPCount != 5 {
		t.Fatalf("in-place update did not apply gratuitous-arp-count: got %d, want 5", got.cfg.GARPCount)
	}
}

// TestUpdateInstances_IfindexChange_TransientResolveFailKeepsOld asserts that a
// resolve failure during the reconcile does NOT churn the instance: the old
// (possibly stale-bound) instance is kept until the interface resolves again,
// matching the build-before-teardown tolerance (#2156) and avoiding dropping
// the RG out of election on a transient netlink hiccup.
func TestUpdateInstances_IfindexChange_TransientResolveFailKeepsOld(t *testing.T) {
	m, rec := newTestManagerNoNetwork()
	defer stopManagerForTest(m)

	resolveErr := atomic.Bool{}
	resolveErr.Store(true)
	m.resolveIface = func(name string) (*net.Interface, error) {
		if resolveErr.Load() {
			return nil, errSocketOpenFailed
		}
		return &net.Interface{Name: name, Index: 9}, nil
	}

	key := instanceKey{iface: "reth0.50", groupID: 101}
	cfg := Instance{
		Interface:        "reth0.50",
		GroupID:          101,
		Priority:         200,
		Preempt:          true,
		VirtualAddresses: []string{"172.16.50.1/24"},
	}
	orig := seedRunningInstance(m, key, cfg, 7)

	desired := []*Instance{{
		Interface:        "reth0.50",
		GroupID:          101,
		Priority:         200,
		Preempt:          true,
		VirtualAddresses: []string{"172.16.50.1/24"},
	}}

	// Pass 1: resolve fails — keep the old instance, no restart.
	if err := m.UpdateInstances(desired); err != nil {
		t.Fatalf("UpdateInstances pass 1: %v", err)
	}
	open, run, stop := rec.snapshot()
	if open != 0 || run != 0 || stop != 0 {
		t.Fatalf("resolve failure must keep old instance: open=%d run=%d stop=%d, want 0/0/0", open, run, stop)
	}
	m.mu.RLock()
	if m.instances[key] != orig {
		m.mu.RUnlock()
		t.Fatal("pass 1: old instance orphaned on transient resolve failure")
	}
	m.mu.RUnlock()

	// Pass 2: resolve returns the NEW ifindex — the drift restart fires.
	resolveErr.Store(false)
	if err := m.UpdateInstances(desired); err != nil {
		t.Fatalf("UpdateInstances pass 2: %v", err)
	}
	open, run, stop = rec.snapshot()
	if open != 1 || run != 1 || stop != 1 {
		t.Fatalf("pass 2 ifindex drift must restart: open=%d run=%d stop=%d, want 1/1/1", open, run, stop)
	}
	m.mu.RLock()
	got := m.instances[key]
	m.mu.RUnlock()
	if got == orig || got.iface.Index != 9 {
		t.Fatalf("pass 2: not rebound to new ifindex (same=%v index=%d)", got == orig, got.iface.Index)
	}
}
