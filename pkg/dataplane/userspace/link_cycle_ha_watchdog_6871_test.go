package userspace

import (
	"path/filepath"
	"testing"
)

// #6871 round 6: the SEVENTH producer of the worker-respawn class, and the one
// that shows why enumerating callers does not close the class.
//
// The three operator verbs (link_cycle_operator_verbs_6871_test.go) really are
// the complete set of DIRECT setters. But the daemon reaches the same
// worker-respawning helper handler by a second route it does not own: the HA
// watchdog heartbeat. daemon_ha_sync.go runs a 500ms goroutine, NOT serialized
// on the daemon's applySem, calling SetHAWatchdog -> Manager.UpdateHAWatchdog for
// every configured RG. On the first tick for an RG, on any Active-state change,
// and on the 3s backstop, that call publishes the full HA state over the control
// socket (syncHAStateLocked) — and syncHAStateLocked's tail is
// syncDesiredForwardingStateLocked, which sends set_forwarding_state.
//
// set_forwarding_state lands in the helper's handlers/forwarding.rs, which calls
// reconcile_status_bindings UNCONDITIONALLY -> afxdp.reconcile -> SPAWNS WORKER
// THREADS. So a heartbeat tick landing between PrepareLinkCycle and setDown
// restarts the workers the cycle just joined, into a NIC about to unmap their
// UMEM: the use-after-unmap #5103 exists to prevent.
//
// WHERE THE GATE LIVES, and why not at UpdateHAWatchdog. Only the
// set_forwarding_state half respawns. The update_ha_state half is a LIVENESS
// signal — Coordinator::update_ha_state is the only thing that refreshes the
// helper's per-RG forwarding lease, which is receipt-anchored, not
// value-anchored (ActiveUntil(max(watchdog, now) +
// HA_WATCHDOG_STALE_AFTER_SECS), 10s; now is sampled at receipt, so each active
// receipt mints a full lease — #10791), and is_forwarding_active consults it per
// packet. Suppressing it for the length of a 60s link-cycle lease would expire
// that lease and stop forwarding outright: an outage in place of a race.
// Gating the emitter also covers the two callers that were already safe (the
// status tick, via its own lease skip; the compile path, via applySem) and any
// future caller that publishes THROUGH syncDesiredForwardingStateLocked, which
// gating one caller would not. It is not a chokepoint for the request type:
// three other sites build a raw set_forwarding_state, one gated at its own entry
// (SetForwardingArmed) and two ungated but reachable only under applySem — see
// the emitter's own comment in manager_ha.go for the inventory and why the
// ungated pair has no runtime escape today.
//
// SCOPE OF THESE CELLS, stated rather than implied. They bind the gate at the
// emitter, over a real control socket, on the request stream — the observable
// that matters, since a gate that reported a refusal while still sending the
// request would leave the workers spawned. What they do NOT drive end-to-end is
// UpdateHAWatchdog -> ... -> syncDesiredForwardingStateLocked in one call: with
// no BPF maps, applyHelperStatusLocked returns "userspace_ctrl map not loaded"
// and syncHAStateLocked returns before its tail. A map-backed fixture would make
// these cells SKIP unprivileged instead of run, which is a worse trade — a guard
// that is green because it never executed. The reachability half is covered
// separately, and honestly, by
// TestHAWatchdogPublishesOverTheControlSocket_6871 below.
//
// THE GAP THAT LEAVES, named rather than left implicit (#6871 round 7). Because
// no cell reaches the tail, the tail LINE is unguarded: changing
// syncHAStateLocked's closing `return m.syncDesiredForwardingStateLocked()`
// (manager_ha.go) to `return nil` leaves pkg/dataplane/userspace AND pkg/daemon
// fully green. That was measured, not assumed. Its production effect is bounded
// and self-healing rather than an outage — the desired-forwarding decision is
// level-triggered, so the 1 Hz status tick re-evaluates the same delta within a
// second — but the composition genuinely has no test.
//
// It is left open deliberately: closing it needs applyHelperStatusLocked to
// succeed, which needs real ctrl and bindings BPF maps, which needs privileges
// this suite does not have. The two candidate fixes are both worse than the gap.
// A map-backed cell would SKIP unprivileged, adding a fourth entry to the
// three-leaf-cell privilege disclosure at
// TestUpdateRGActiveCannotReEnableCtrlDuringLinkCycle_6871
// (link_cycle_lease_6871_test.go) and buying a guard that does not run in the
// environment most people run the suite in. A production
// test seam threaded through applyHelperStatusLocked would put new indirection
// on the HA status path — the hot path this whole change exists to protect — to
// serve a test, and the seam itself would then be the unbound thing.

// newWatchdogTestManager builds a map-free manager whose UpdateHAWatchdog can run
// without a loaded BPF map: haWatchdogMapWrite is the production seam for
// exactly that (see manager.go), so the socket half is reachable while the
// Go-owned HA map write is stubbed.
func newWatchdogTestManager(t *testing.T) (*Manager, *leaseControlServer) {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "control.sock")
	m := newLinkCycleProcessOnlyManager(t, sock)
	srv := startLeaseControlServer(t, sock, ProcessStatus{
		PID:          7777,
		Workers:      2,
		Capabilities: UserspaceCapabilities{ForwardingSupported: true},
		Bindings:     []BindingStatus{{Slot: 1, Ifindex: 2, QueueID: 0, Ready: true}},
	})
	m.haWatchdogMapWrite = func(int, uint64) error { return nil }
	// ForwardingSupported makes desiredForwardingArmedLocked() true while
	// lastStatus.ForwardingArmed stays false, so there is a real delta for
	// syncDesiredForwardingStateLocked to publish. Without one it would return
	// early and the assertions below would hold for the wrong reason.
	m.lastStatus.Capabilities.ForwardingSupported = true
	m.lastStatus.ForwardingArmed = false
	return m, srv
}

// TestDesiredForwardingStateDeferredDuringLinkCycle_6871 is the discriminator.
//
// RED-on-revert: delete the `if m.linkCycleInFlight()` block from
// syncDesiredForwardingStateLocked (manager_ha.go) and this fails at
// "set_forwarding_state reached the helper DURING the link cycle".
func TestDesiredForwardingStateDeferredDuringLinkCycle_6871(t *testing.T) {
	skipLinkCycleRebindSleep(t)
	m, srv := newWatchdogTestManager(t)

	// POSITIVE CONTROL: with no cycle in flight this fixture really does publish
	// set_forwarding_state. Without it the assertion below could hold because the
	// delta never existed or the socket was never reached.
	m.mu.Lock()
	err := m.syncDesiredForwardingStateLocked()
	m.mu.Unlock()
	if err != nil {
		// applyHelperStatusLocked fails map-free; that is a fixture limit, not a
		// refusal, and it happens strictly AFTER the request is on the wire.
		t.Logf("syncDesiredForwardingStateLocked (control, no cycle): %v", err)
	}
	if n := countRequests(srv.requests(), "set_forwarding_state"); n != 1 {
		t.Fatalf("control: set_forwarding_state requests with NO cycle in flight = %d, "+
			"want 1. This fixture does not reach the control socket, so the during-cycle "+
			"assertion below would hold vacuously. Requests: %v", n, srv.requests())
	}
	before := countRequests(srv.requests(), "set_forwarding_state")

	// THE DISCRIMINATOR: same call, one link cycle in flight.
	if err := m.PrepareLinkCycle(); err != nil {
		t.Fatalf("PrepareLinkCycle: %v", err)
	}
	m.mu.Lock()
	deferErr := m.syncDesiredForwardingStateLocked()
	m.mu.Unlock()
	if deferErr != nil {
		t.Errorf("the deferral must return nil, not an error: callers log or propagate "+
			"errors, and nothing has FAILED here — the publish is postponed to the next "+
			"level-triggered pass. Got %v", deferErr)
	}
	if err := m.NotifyLinkCycle(); err != nil {
		t.Fatalf("NotifyLinkCycle: %v", err)
	}

	between := requestsBetween(t, srv.requests(), "stop_workers", "rebind")
	for _, r := range between {
		if r != "set_forwarding_state" {
			continue
		}
		t.Errorf("set_forwarding_state reached the helper DURING the link cycle: %v.\n"+
			"PrepareLinkCycle had joined every worker and the daemon has not taken the "+
			"NIC down yet. handlers/forwarding.rs calls reconcile_status_bindings "+
			"unconditionally, so this request SPAWNS WORKER THREADS into a NIC about to "+
			"unmap their UMEM. The ctrl gate cannot cover it: the spawn happens inside "+
			"the helper, before the status this manager applies. The 500ms HA watchdog "+
			"heartbeat reaches this emitter and is not serialized on applySem, so it "+
			"lands here on its own schedule (#6871). Full stream: %v",
			between, srv.requests())
		break
	}
	if n := countRequests(srv.requests(), "set_forwarding_state"); n != before {
		t.Errorf("set_forwarding_state count went %d -> %d across the deferred call; the "+
			"gate must turn the publish back BEFORE the control socket, not after",
			before, n)
	}
}

// TestDesiredForwardingStateResumesAfterLinkCycle_6871 is the over-reach guard.
//
// The deferral must be a DEFERRAL, not a drop. The decision is level-triggered on
// persistent state (desiredForwardingArmedLocked vs lastStatus.ForwardingArmed),
// so the first pass after the lease ends must publish the same delta — otherwise
// a helper that needed arming stays disarmed until something else happens to move
// that state, which on a quiet node may be never.
//
// It stays GREEN under the revert above (removing the gate only ever lets more
// through, so a test asserting the publish RESUMES cannot be satisfied by it),
// which is what makes it a control rather than a restatement.
func TestDesiredForwardingStateResumesAfterLinkCycle_6871(t *testing.T) {
	skipLinkCycleRebindSleep(t)
	m, srv := newWatchdogTestManager(t)

	if err := m.PrepareLinkCycle(); err != nil {
		t.Fatalf("PrepareLinkCycle: %v", err)
	}
	m.mu.Lock()
	_ = m.syncDesiredForwardingStateLocked()
	m.mu.Unlock()
	if err := m.NotifyLinkCycle(); err != nil {
		t.Fatalf("NotifyLinkCycle: %v", err)
	}

	before := countRequests(srv.requests(), "set_forwarding_state")
	m.mu.Lock()
	_ = m.syncDesiredForwardingStateLocked()
	m.mu.Unlock()
	if n := countRequests(srv.requests(), "set_forwarding_state"); n != before+1 {
		t.Errorf("set_forwarding_state requests after the cycle = %d, want %d. The "+
			"deferred publish was DROPPED rather than postponed: the helper stays in "+
			"whatever forwarding state it was left in, and nothing re-evaluates the "+
			"delta on a node where no other state changes. Requests: %v",
			n, before+1, srv.requests())
	}
}

// TestHAWatchdogPublishesOverTheControlSocket_6871 is the reachability half.
//
// It pins the claim the discriminator above depends on but cannot itself show:
// that the daemon's 500ms watchdog heartbeat is a control-socket caller at all,
// and therefore reaches syncHAStateLocked — whose tail is the emitter the
// discriminator gates. UpdateHAWatchdog's throttle fires unconditionally on the
// FIRST tick for an RG (no baseline yet), which is the case here.
//
// This does not run all the way through to set_forwarding_state, and that is a
// fixture limit rather than a claim: map-free, applyHelperStatusLocked fails with
// "userspace_ctrl map not loaded" and syncHAStateLocked returns just before its
// tail. Making it go further would require real BPF maps and would turn the cell
// into an unprivileged SKIP.
func TestHAWatchdogPublishesOverTheControlSocket_6871(t *testing.T) {
	m, srv := newWatchdogTestManager(t)

	if err := m.UpdateHAWatchdog(1, 1000); err != nil {
		// The error is applyHelperStatusLocked's map complaint, raised after the
		// request has already crossed the socket.
		t.Logf("UpdateHAWatchdog: %v", err)
	}
	if n := countRequests(srv.requests(), "update_ha_state"); n != 1 {
		t.Fatalf("update_ha_state requests = %d, want 1. The HA watchdog heartbeat is "+
			"supposed to be a control-socket caller — that is what puts it on the path to "+
			"syncDesiredForwardingStateLocked, and it runs every 500ms on a goroutine "+
			"with no applySem. Requests: %v", n, srv.requests())
	}
}

// TestHAWatchdogKeepsPublishingHAStateDuringLinkCycle_6871 is the over-reach
// guard for the placement decision, and the one that would catch a "gate the
// whole socket half of UpdateHAWatchdog" fix.
//
// update_ha_state is the ONLY refresh of the helper's per-RG forwarding lease,
// which is receipt-anchored: Coordinator::update_ha_state sets
// ActiveUntil(max(watchdog, now) + HA_WATCHDOG_STALE_AFTER_SECS) — 10s,
// userspace-dp/src/afxdp/mod.rs; now is sampled at receipt so each active receipt
// mints a full lease (#10791) — and is_forwarding_active consults it on every packet.
// The link-cycle lease TTL is
// 60s. Suppressing update_ha_state for the length of a cycle would therefore
// expire the helper's forwarding lease and stop forwarding for that RG: an
// OUTAGE, strictly worse than the respawn race being closed. Its handler
// (server/handlers/ha.rs) does call refresh_status, which can repair the WG/GRE
// auxiliary threads — but not reconcile_status_bindings or any other spawn of
// the AF_XDP PACKET workers whose UMEM the cycle unmaps, and after a successful
// stop_workers those records are cleared anyway. So there is nothing to gain by
// suppressing it (#6871 round 7: "reaches no worker spawn" was too absolute).
//
// It stays GREEN under the discriminator's revert (that revert removes a gate;
// this asserts traffic still flows).
func TestHAWatchdogKeepsPublishingHAStateDuringLinkCycle_6871(t *testing.T) {
	skipLinkCycleRebindSleep(t)
	m, srv := newWatchdogTestManager(t)

	if err := m.PrepareLinkCycle(); err != nil {
		t.Fatalf("PrepareLinkCycle: %v", err)
	}
	before := countRequests(srv.requests(), "update_ha_state")
	if err := m.UpdateHAWatchdog(1, 2000); err != nil {
		t.Logf("UpdateHAWatchdog during link cycle: %v", err)
	}
	if n := countRequests(srv.requests(), "update_ha_state"); n != before+1 {
		t.Errorf("update_ha_state requests during the link cycle = %d, want %d. The "+
			"watchdog's HA-state publish must NOT be gated on the link-cycle lease: it is "+
			"the only thing that refreshes the helper's 10s per-RG forwarding lease, and "+
			"the link-cycle lease runs to 60s, so suppressing it expires that lease and "+
			"stops forwarding for the RG. Only the set_forwarding_state half respawns "+
			"workers, and only that half is deferred (#6871). Requests: %v",
			n, before+1, srv.requests())
	}
}
