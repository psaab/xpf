package userspace

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
)

// #6871 round 7: bind the PRODUCTION ADAPTERS, not just the methods behind them.
//
// THE DEFECT CLASS. The daemon never touches *Manager. It holds a
// dataplane.RuntimeDataPlane and reaches the dataplane through two thin seams:
//
//	Daemon -> dp.Link() -> userspaceLinkController -> Manager.<method>
//	Daemon -> dp.HA()   -> userspaceHAController -> managerHAOps -> Manager.<method>
//
// Every one of those hops is a two-line forwarder, which is exactly why they
// attract tests that skip them: it is easier to call m.UpdateHAWatchdog(1, ts)
// than to build dp.HA() and call SetHAWatchdog(ctx, 1, ts), and the assertion
// reads the same either way. It is NOT the same. A suite that only ever calls
// the inner method leaves the forwarder completely unguarded, so replacing its
// body with `return nil` is invisible to the whole package while removing the
// behaviour from production entirely.
//
// This was measured, not reasoned about. Before this file existed, each of these
// edits left `go test ./pkg/dataplane/userspace/ ./pkg/daemon/` fully green:
//
//	managerHAOps.UpdateHAWatchdog      -> return nil     GREEN
//	userspaceHAController.SetHAWatchdog -> return nil    GREEN
//	userspaceLinkController.RenewLinkCycle -> {}         GREEN
//	userspaceLinkController.SetDeferWorkers -> {}        GREEN
//	managerHAOps.UpdateRGActive        -> return nil     GREEN
//	userspaceHAController.SetRGActive  -> return nil     GREEN
//	LegacyDataPlaneAdapter.PrepareLinkCycle -> return nil GREEN
//
// The first three are the #6871 ones and the worst: severing either watchdog
// link stops the daemon's 500ms heartbeat from ever refreshing the helper's
// per-RG forwarding lease (10s, HA_WATCHDOG_STALE_AFTER_SECS in
// userspace-dp/src/afxdp/mod.rs), so the lease expires and the redundancy group
// STOPS FORWARDING. Severing the renewal removes every production renewal of the
// link-cycle lease while leaving all of its tests green.
//
// Only two adapter methods were already bound — PrepareLinkCycle and
// NotifyLinkCycle — and only because the #5103/#6871 error-return work happened
// to drive them through Link().
//
// SO THE FIX IS THE WHOLE SURFACE, NOT THE THREE INSTANCES. Three of one defect
// class in one PR is a property of how the suite is written, not a coincidence,
// so this file drives EVERY method of the two production adapters through
// m.Link() / m.HA() — the same constructors the daemon uses, so severing those
// constructors is caught too — and asserts an observable only the real inner
// Manager can produce.
//
// FIXTURE NOTE, stated rather than implied. These cells are map-free, and the
// observables are chosen to suit that: a control-socket request, a manager
// field, the lease deadline, or the specific error a missing BPF map produces.
// A map-backed fixture would make them SKIP unprivileged rather than run, which
// is a guard that is green because it never executed — the same trade the rest
// of this fold refuses (see the fixture note in
// link_cycle_ha_watchdog_6871_test.go).

// newAdapterBindingManager builds a map-free manager with a live process handle,
// a real control socket, and the watchdog shim-map write stubbed, so the socket
// half of the HA path is reachable without privileges.
func newAdapterBindingManager(t *testing.T) (*Manager, *leaseControlServer) {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "control.sock")
	m := newLinkCycleProcessOnlyManager(t, sock)
	srv := startLeaseControlServer(t, sock, ProcessStatus{
		PID:          8888,
		Workers:      2,
		Capabilities: UserspaceCapabilities{ForwardingSupported: true},
		Bindings:     []BindingStatus{{Slot: 1, Ifindex: 2, QueueID: 0, Ready: true}},
	})
	m.haWatchdogMapWrite = func(int, uint64) error { return nil }
	return m, srv
}

// TestHAControllerWatchdogReachesTheManager_6871 is the B1 guard: the daemon's
// watchdog heartbeat must survive BOTH userspace hops.
//
// Production is Daemon -> userspaceHAController.SetHAWatchdog ->
// managerHAOps.UpdateHAWatchdog -> Manager.UpdateHAWatchdog. Every other
// watchdog test in this package calls the last of those directly, so the first
// two were load-bearing and unguarded.
//
// RED-on-revert: replace EITHER controllers.go body with `return nil` and this
// fails at "the watchdog never reached the helper". Both severances were
// confirmed green before this test existed.
//
// The observable is the update_ha_state request on the wire, not a manager
// field, and deliberately so: what production needs from this call is the
// helper's forwarding lease being refreshed, and only the IPC does that. A
// forwarder that updated m.haGroups but never sent would satisfy a field
// assertion and still expire the lease.
func TestHAControllerWatchdogReachesTheManager_6871(t *testing.T) {
	m, srv := newAdapterBindingManager(t)

	// The production seam, constructed the way the daemon constructs it.
	ha := m.HA()
	if err := ha.SetHAWatchdog(context.Background(), 1, 4242); err != nil {
		// Map-free, applyHelperStatusLocked complains AFTER the request has
		// already crossed the socket. That is a fixture limit, not a refusal.
		t.Logf("SetHAWatchdog: %v", err)
	}

	if n := countRequests(srv.requests(), "update_ha_state"); n != 1 {
		t.Fatalf("update_ha_state requests = %d, want 1: the receipt-anchored HA "+
			"lease refresh never reached the helper through the production adapter. "+
			"The daemon's 500ms heartbeat (daemon_ha_sync.go) is the ONLY refresh "+
			"lease — Coordinator::update_ha_state -> ActiveUntil(max(watchdog, now) + "+
			"HA_WATCHDOG_STALE_AFTER_SECS), 10s, receipt-anchored (#10791); each active "+
			"receipt mints a full lease — and is_forwarding_active consults it on every "+
			"packet. A severed hop here expires that lease and STOPS FORWARDING for "+
			"the redundancy group, while every test that calls Manager.UpdateHAWatchdog "+
			"directly stays green (#6871). Requests: %v", n, srv.requests())
	}
	m.mu.Lock()
	got := m.haGroups[1].WatchdogTimestamp
	m.mu.Unlock()
	if got != 4242 {
		t.Errorf("haGroups[1].WatchdogTimestamp = %d, want 4242: the timestamp the daemon "+
			"passed was not the one that reached the manager, so a forwarder is dropping or "+
			"rewriting its argument rather than merely being present", got)
	}
}

// TestHAControllerWatchdogPropagatesContextCancellation_6871 is the over-reach
// guard for the outer hop specifically.
//
// userspaceHAController.SetHAWatchdog checks ctx.Err() before forwarding, which
// is the one piece of behaviour that lives in the OUTER adapter and nowhere else
// — the manager method takes no context. Without this cell a "fix" that deleted
// the outer adapter and wired managerHAOps straight into the interface would
// still pass the cell above.
func TestHAControllerWatchdogPropagatesContextCancellation_6871(t *testing.T) {
	m, srv := newAdapterBindingManager(t)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := m.HA().SetHAWatchdog(ctx, 1, 4242); err == nil {
		t.Error("SetHAWatchdog on a cancelled context returned nil; the adapter's ctx.Err() " +
			"check is the only place this path honors cancellation")
	}
	if n := countRequests(srv.requests(), "update_ha_state"); n != 0 {
		t.Errorf("update_ha_state requests after a cancelled context = %d, want 0: the "+
			"refusal must happen BEFORE the control socket, not after. Requests: %v",
			n, srv.requests())
	}
}

// TestLinkControllerRenewReachesTheManager_6871 is the B2 guard.
//
// The daemon renews the link-cycle lease through rt.Link().RenewLinkCycle()
// (Daemon.renewLinkCycleLease). pkg/daemon's own renewal test uses a FAKE
// controller and this package's test calls m.RenewLinkCycle() directly, so the
// REAL adapter sat between two green tests with nothing on it: making its body a
// no-op removed every production renewal and neither side noticed.
//
// The assertion is the production-meaningful one — the lease OUTLIVES its TTL
// because the renewal landed — rather than a numeric comparison of deadlines. A
// severed adapter leaves the deadline where acquire put it, so the lease expires
// on schedule and linkCycleInFlight() goes false while the cycle is still
// running: precisely the window in which the 1 Hz tick respawns the AF_XDP
// workers into a NIC that is about to unmap their UMEM.
//
// RED-on-revert: make userspaceLinkController.RenewLinkCycle an empty body and
// this fails at "the lease expired on schedule".
func TestLinkControllerRenewReachesTheManager_6871(t *testing.T) {
	advance := fakeLinkCycleClock(t)
	m := New()

	m.acquireLinkCycleLease()
	if !m.linkCycleInFlight() {
		t.Fatal("the lease must be held immediately after acquire, or this test proves nothing")
	}

	// Spend most of the TTL, then renew THROUGH THE PRODUCTION ADAPTER.
	advance(linkCycleLeaseTTL - time.Second)
	m.Link().RenewLinkCycle()

	// Cross the original deadline. A renewal that landed pushed it out of reach.
	advance(2 * time.Second)
	if !m.linkCycleInFlight() {
		t.Fatalf("the lease expired on schedule despite a renewal through Link(): the "+
			"production adapter is not forwarding to Manager.RenewLinkCycle. The daemon "+
			"renews once per RETH member and twice more in the tail, which is what lets a "+
			"%s TTL bound ONE interval instead of a whole rethToPhys loop an operator can "+
			"take to 128 members. With the adapter severed there are no production renewals "+
			"at all, and every renewal test still passes because pkg/daemon uses a fake "+
			"controller and this package calls the manager method directly (#6871)",
			linkCycleLeaseTTL)
	}

	// And the renewal bought a full fresh TTL, not an arbitrary extension.
	advance(linkCycleLeaseTTL)
	if m.linkCycleInFlight() {
		t.Error("the lease survived a full TTL past its renewal; RenewLinkCycle must extend " +
			"by exactly one TTL from the renewal, not disable expiry")
	}
}

// TestLinkControllerRenewCannotOpenALease_6871 is the over-reach guard for B2.
//
// The renewal must never CREATE a lease from the 0 sentinel. If it could, the
// daemon's per-member loop — which runs on every RETH apply, the vast majority
// of which cycle no link at all — would suppress the 1 Hz reconcile with nothing
// obliged to release it.
//
// It stays GREEN under the revert above (a severed adapter creates nothing
// either), so it is a control rather than a restatement of the cell above.
func TestLinkControllerRenewCannotOpenALease_6871(t *testing.T) {
	fakeLinkCycleClock(t)
	m := New()

	m.Link().RenewLinkCycle()

	if m.linkCycleInFlight() {
		t.Error("RenewLinkCycle opened a lease with no cycle in flight. Nothing would ever " +
			"release it, so the status tick's reconcile would stay suppressed until the TTL " +
			"backstop fired — on every RETH apply, not just the ones that cycle a link")
	}
	if until := m.linkCycleLeaseUntil.Load(); until != 0 {
		t.Errorf("linkCycleLeaseUntil = %d, want the 0 sentinel: the renewal wrote a deadline "+
			"where there was no lease", until)
	}
}

// TestRuntimeAdaptersForwardToTheManager_6871 is the SWEEP.
//
// Codex's three findings were three instances of one class, so the fix is the
// class: every remaining method of the two production adapters, driven through
// m.Link() / m.HA() and checked against an observable only the real inner
// Manager produces. Four of these were measured unbound before this table
// existed (SetDeferWorkers, both halves of the RG-active path, and — new in this
// PR — the LegacyDataPlaneAdapter error return, covered separately below).
//
// PrepareLinkCycle and NotifyLinkCycle were ALREADY bound; they are here so the
// table is the complete surface rather than the subset that happened to be
// broken, and so a future method added to either interface has an obvious place
// to be answered for.
func TestRuntimeAdaptersForwardToTheManager_6871(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(*testing.T, *Manager)
		drive func(*testing.T, *Manager)
		check func(*testing.T, *Manager, *leaseControlServer)
	}{
		{
			name: "link/set_defer_workers",
			drive: func(t *testing.T, m *Manager) {
				m.Link().SetDeferWorkers(true)
			},
			check: func(t *testing.T, m *Manager, _ *leaseControlServer) {
				m.mu.Lock()
				defer m.mu.Unlock()
				if !m.deferWorkers {
					t.Error("deferWorkers is still false: the daemon's pre-MAC worker deferral " +
						"never reached the manager, so a RETH apply that must not spawn workers " +
						"yet would spawn them")
				}
			},
		},
		{
			name: "link/prepare_link_cycle",
			drive: func(t *testing.T, m *Manager) {
				if err := m.Link().PrepareLinkCycle(); err != nil {
					t.Fatalf("PrepareLinkCycle: %v", err)
				}
			},
			check: func(t *testing.T, _ *Manager, srv *leaseControlServer) {
				if n := countRequests(srv.requests(), "stop_workers"); n != 1 {
					t.Errorf("stop_workers requests = %d, want 1: the AF_XDP worker join never "+
						"reached the helper, so the link would cycle with workers still "+
						"touching UMEM. Requests: %v", n, srv.requests())
				}
			},
		},
		{
			name: "link/notify_link_cycle",
			setup: func(t *testing.T, _ *Manager) {
				skipLinkCycleRebindSleep(t)
			},
			drive: func(t *testing.T, m *Manager) {
				if err := m.Link().NotifyLinkCycle(); err != nil {
					t.Fatalf("NotifyLinkCycle: %v", err)
				}
			},
			check: func(t *testing.T, _ *Manager, srv *leaseControlServer) {
				if n := countRequests(srv.requests(), "rebind"); n != 1 {
					t.Errorf("rebind requests = %d, want 1: the inverse of stop_workers never "+
						"reached the helper, so the workers stay joined and the node forwards "+
						"nothing. Requests: %v", n, srv.requests())
				}
			},
		},
		{
			name: "ha/set_rg_active",
			drive: func(t *testing.T, m *Manager) {
				err := m.HA().SetRGActive(context.Background(), 1, true)
				// Map-free this MUST fail, and the specific failure is the
				// evidence: the rg_active BPF map write is the first thing
				// Manager.UpdateRGActive does, so its complaint can only have
				// come from the real manager.
				if err == nil {
					t.Error("SetRGActive returned nil with no rg_active map loaded. The real " +
						"Manager.UpdateRGActive writes that map FIRST and fails when it is " +
						"absent, so a nil here means the adapter answered on its own and the " +
						"kernel-visible RG ownership state was never written — the standby " +
						"would keep forwarding as if it still owned the group")
					return
				}
				if !strings.Contains(err.Error(), "rg_active") {
					t.Errorf("SetRGActive error = %q, want it to name rg_active: some other "+
						"layer refused before the manager's own map write was attempted", err)
				}
			},
			check: func(*testing.T, *Manager, *leaseControlServer) {},
		},
		{
			name: "ha/set_fabric_forwarding_fabric0",
			drive: func(t *testing.T, m *Manager) {
				err := m.HA().SetFabricForwarding(context.Background(), 0, dataplane.FabricFwdInfo{})
				assertFabricMapComplaint6871(t, err, "fabric0")
			},
			check: func(*testing.T, *Manager, *leaseControlServer) {},
		},
		{
			name: "ha/set_fabric_forwarding_fabric1",
			drive: func(t *testing.T, m *Manager) {
				err := m.HA().SetFabricForwarding(context.Background(), 1, dataplane.FabricFwdInfo{})
				assertFabricMapComplaint6871(t, err, "fabric1")
			},
			check: func(*testing.T, *Manager, *leaseControlServer) {},
		},
		{
			name: "ha/sync_fabric_state",
			setup: func(_ *testing.T, m *Manager) {
				m.lastSnapshot = &ConfigSnapshot{}
				m.fabricSnapshotBuilder = func(*config.Config) []FabricSnapshot {
					return []FabricSnapshot{{Name: "fab0"}}
				}
			},
			drive: func(t *testing.T, m *Manager) {
				if err := m.HA().SyncFabricState(context.Background()); err != nil {
					t.Fatalf("SyncFabricState: %v", err)
				}
			},
			check: func(t *testing.T, _ *Manager, srv *leaseControlServer) {
				if n := countRequests(srv.requests(), "update_fabrics"); n != 1 {
					t.Errorf("update_fabrics requests = %d, want 1: the freshly resolved fabric "+
						"peer MACs never reached the helper, so cross-chassis redirect keeps "+
						"using the stale set during exactly the HA window it exists to cover. "+
						"Requests: %v", n, srv.requests())
				}
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, srv := newAdapterBindingManager(t)
			if tc.setup != nil {
				tc.setup(t, m)
			}
			tc.drive(t, m)
			tc.check(t, m, srv)
		})
	}
}

// assertFabricMapComplaint6871 checks that a fabric-forwarding call reached the
// real manager. Map-free, Manager.bpfShim.UpdateFabricFwd{,1} fails with
// "fabric_fwd map not found", so that complaint is proof the adapter forwarded;
// a nil return means it answered on its own and the peer MAC the HA path needs
// was never written.
func assertFabricMapComplaint6871(t *testing.T, err error, slot string) {
	t.Helper()
	if err == nil {
		t.Errorf("SetFabricForwarding(%s) returned nil with no fabric_fwd map loaded; the "+
			"real manager writes that map and fails when it is absent, so the adapter is "+
			"not forwarding and cross-chassis redirect would silently keep a stale peer MAC",
			slot)
		return
	}
	if !strings.Contains(err.Error(), "fabric_fwd") {
		t.Errorf("SetFabricForwarding(%s) error = %q, want it to name fabric_fwd: some other "+
			"layer refused before the manager's own map write was attempted", slot, err)
	}
}

// TestLegacyAdapterPrepareLinkCycleSurfacesResolutionFailure_6871 binds the one
// adapter this PR CHANGED whose new behaviour nothing else reaches.
//
// #5103 rewrote LegacyDataPlaneAdapter.PrepareLinkCycle from a void method that
// swallowed a manager-resolution failure into one that returns it, and the
// method's own doc comment leans on that divergence: Link() resolves an absent
// manager to "nothing to join, proceed" (nil), while this one means "a manager
// was expected and could not be resolved" (error). Nothing bound the difference
// — reverting the body to `return nil` left both packages green — so the two
// readings could silently collapse back into one.
//
// A caller that cycled the link on a nil return here would do so with an unknown
// worker state, which is the #5103 use-after-unmap.
func TestLegacyAdapterPrepareLinkCycleSurfacesResolutionFailure_6871(t *testing.T) {
	a := NewLegacyDataPlaneAdapter(nil)

	err := a.PrepareLinkCycle()

	if err == nil {
		t.Fatal("PrepareLinkCycle on an adapter with no resolvable manager returned nil, i.e. " +
			"reported a successful AF_XDP worker join. #5103 made this an error precisely " +
			"because a nil here is indistinguishable from a real join to a caller that is " +
			"about to take the NIC down: it would cycle the link with the worker state " +
			"unknown. This is the opposite reading from Link(), whose nil means no userspace " +
			"dataplane is wired at all and there is genuinely nothing to join")
	}
}

// Compile-time restatement of what this file is for: the daemon consumes these
// two interfaces and nothing narrower, so the adapters above are the entire
// production surface and every method on them needs an answer in this file.
var (
	_ dataplane.LinkController = userspaceLinkController{}
	_ dataplane.HAController   = userspaceHAController{}
)
