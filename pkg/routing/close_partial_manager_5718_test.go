package routing

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
)

// closeGuardRuleOps is a do-nothing ruleOps: this test only drives Close, so
// no rule call is expected to run.
type closeGuardRuleOps struct{}

func (closeGuardRuleOps) RuleAdd(*netlink.Rule) error { return nil }
func (closeGuardRuleOps) RuleDel(*netlink.Rule) error { return nil }
func (closeGuardRuleOps) RuleList(int) ([]netlink.Rule, error) {
	return nil, nil
}

// closeGuardRouteLister is a do-nothing routeLister, same rationale.
type closeGuardRouteLister struct{}

func (closeGuardRouteLister) RouteListFiltered(int, *netlink.Route, uint64) ([]netlink.Route, error) {
	return nil, nil
}
func (closeGuardRouteLister) RouteList(netlink.Link, int) ([]netlink.Route, error) { return nil, nil }
func (closeGuardRouteLister) RouteListFilteredIter(int, *netlink.Route, uint64, func(netlink.Route) bool) error {
	return nil
}
func (closeGuardRouteLister) LinkByIndex(int) (netlink.Link, error)                { return nil, nil }
func (closeGuardRouteLister) LinkByName(string) (netlink.Link, error)              { return nil, nil }

// liveKeepalive is the observable state of a real keepalive goroutine planted
// in the tunnel domain.
type liveKeepalive struct {
	done  <-chan struct{}
	ticks atomic.Int64
	// sawDrain records that the goroutine observed its cancellation, so a
	// closed `done` cannot be satisfied by a goroutine that exited some other
	// way.
	sawDrain atomic.Bool
	// handleOpenAtDrain records whether the shared netlink handle was still
	// open at the moment the goroutine was cancelled. This is what binds the
	// #848 ORDERING: stopAll drains BEFORE Close touches the handle, so a
	// keepalive still in flight must never see a closed handle.
	handleOpenAtDrain atomic.Bool
}

// installLiveKeepalive wires a REAL running keepalive goroutine into the
// tunnel domain.
//
// The goroutine has the shape stopAllKeepalivesLocked depends on: it exits on
// ctx.Done and closes `done` on the way out, so `<-runner.done` returning is
// proof the goroutine actually left — not merely that cancel() was called.
//
// On cancellation it touches the shared netlink handle exactly as a real
// keepalive tick would, and records whether the handle was still usable. That
// read is race-free in BOTH orderings and deterministic in both, because
// stopAll blocks on `<-runner.done`:
//
//	drain-then-close: cancel -> this read -> close(done) -> Close() the handle
//	close-then-drain: Close() the handle -> cancel -> this read
//
// so the context and the done channel supply the happens-before edge either
// way, and the recorded answer differs between them.
func installLiveKeepalive(t *testing.T, m *Manager, name string) *liveKeepalive {
	t.Helper()
	handle := m.nlHandle
	return installLiveKeepaliveWatching(t, m, name, func() bool {
		if handle == nil {
			return true
		}
		socks, err := handle.GetSocketReceiveBufferSize()
		return err == nil && len(socks) > 0
	})
}

// installLiveKeepaliveWatching is installLiveKeepalive with an explicit
// "is the handle still usable?" probe, so a Manager with no netlink handle can
// still bind the #848 ordering through an injected release recorder.
func installLiveKeepaliveWatching(t *testing.T, m *Manager, name string, handleUsable func() bool) *liveKeepalive {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	doneCh := make(chan struct{})
	ka := &liveKeepalive{done: doneCh}

	go func() {
		defer close(doneCh)
		tk := time.NewTicker(200 * time.Microsecond)
		defer tk.Stop()
		for {
			select {
			case <-ctx.Done():
				ka.handleOpenAtDrain.Store(handleUsable())
				ka.sawDrain.Store(true)
				return
			case <-tk.C:
				ka.ticks.Add(1)
			}
		}
	}()
	// If the test fails before Close runs, do not leak the goroutine.
	t.Cleanup(cancel)

	m.tunnel.mu.Lock()
	if m.tunnel.keepalives == nil {
		m.tunnel.keepalives = make(map[string]*keepaliveRunner)
	}
	m.tunnel.keepalives[name] = &keepaliveRunner{
		cancel: cancel,
		done:   doneCh,
		state:  &KeepaliveState{RemoteAddr: "198.51.100.1", Interval: 1, MaxRetries: 3},
	}
	m.tunnel.mu.Unlock()

	// Prove it is genuinely running before Close is asked to stop it, so the
	// post-Close assertion is not satisfied by a goroutine that never started.
	deadline := time.Now().Add(2 * time.Second)
	for ka.ticks.Load() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("setup: the keepalive goroutine never ran")
		}
		time.Sleep(time.Millisecond)
	}
	return ka
}

// assertDrained checks that Close cancelled the runner AND waited for it.
func (ka *liveKeepalive) assertDrained(t *testing.T, what string) {
	t.Helper()
	select {
	case <-ka.done:
	default:
		t.Fatalf("%s: Close returned without draining the keepalive runner (goroutine still "+
			"running after %d ticks). stopAll must cancel it AND wait for it to exit before "+
			"the netlink handle is closed, or an in-flight tick uses the closed handle (#848)",
			what, ka.ticks.Load())
	}
	if !ka.sawDrain.Load() {
		t.Fatalf("%s: the keepalive goroutine's done channel closed without it observing "+
			"cancellation — it exited some other way, so nothing here proves stopAll ran",
			what)
	}
}

// TestCloseDrainsBeforeReleasingHandle_5718 is the CI-PORTABLE guard for
// Close's two obligations and, decisively, their ORDER (#5718 fold r3).
//
// The netlink-backed test below observes the same contract through a real
// *netlink.Handle and therefore SKIPS wherever netlink is unavailable. A
// skipped test reports PASS, which means it accepts every implementation in
// that environment — a mutation run against it yields a cell that looks green
// and proves nothing. So the binding guard is this one: it uses no netlink at
// all, and the handle-release step is an injected recorder.
//
// What is asserted:
//   - the keepalive runner is cancelled AND drained (its goroutine returned);
//   - the handle release ran exactly once;
//   - the release happened AFTER the drain (#848). Final state is identical
//     under either order, so the ordering is observed from inside the
//     keepalive goroutine at the moment it is cancelled: it records whether
//     the release had already fired. stopAll blocks on <-runner.done, so this
//     is deterministic and race-free in both orders —
//     drain-then-release gives cancel -> read -> close(done) -> release, and
//     release-then-drain gives release -> cancel -> read.
func TestCloseDrainsBeforeReleasingHandle_5718(t *testing.T) {
	m := NewManagerWithLinkOpsForTest(nil)
	if m.tunnel == nil {
		t.Fatal("setup: NewManagerWithLinkOpsForTest must wire the tunnel domain")
	}

	var releases atomic.Int64
	m.closeHandleFn = func() { releases.Add(1) }

	ka := installLiveKeepaliveWatching(t, m, "gr-order-5718", func() bool {
		return releases.Load() == 0
	})

	if err := m.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	ka.assertDrained(t, "link-ops Manager with an injected handle release")

	if got := releases.Load(); got != 1 {
		t.Fatalf("Close ran the handle release %d time(s); want exactly 1. A Close that "+
			"skips it leaks the netlink handle the Manager solely owns", got)
	}
	if !ka.handleOpenAtDrain.Load() {
		t.Fatal("Close released the netlink handle BEFORE draining the keepalive runner: " +
			"the still-running goroutine observed the release had already fired. stopAll " +
			"must drain first, or an in-flight keepalive tick touches a closed handle " +
			"(#848). Final state is identical under either order, so only the goroutine's " +
			"own view at cancellation time can tell them apart")
	}

	m.tunnel.mu.Lock()
	remaining := len(m.tunnel.keepalives)
	m.tunnel.mu.Unlock()
	if remaining != 0 {
		t.Fatalf("Close left %d keepalive runner(s) registered", remaining)
	}
}

// TestCloseReleasesLiveHandleAndKeepalives_5718 is the SUPPLEMENTARY,
// environment-gated check: the same contract against a real *netlink.Handle.
//
// It SKIPS where netlink handle construction is unavailable, so it must not be
// treated as the merge-gate guard and a mutation cell scored against it is
// UNKNOWN, not GREEN, whenever it skipped. TestCloseDrainsBeforeReleasingHandle
// above is the portable guard; this one adds that the real handle's sockets
// actually go away, which no fake can show.
//
// Both obligations are observed on live state rather than inferred from a nil
// error:
//
//   - the keepalive runner is drained. `<-runner.done` unblocking means the
//     goroutine returned; a Close that skipped stopAll leaves `done` open.
//   - the netlink handle is closed. netlink.Handle.Close() closes each socket
//     and nils the map, so GetSocketReceiveBufferSize reports one entry per
//     live socket before and none after. (A post-close LinkList is NOT an
//     observable — the library silently falls back to a package-level socket.)
//   - the ORDER: stopAll drains BEFORE the handle closes (#848), so an
//     in-flight keepalive tick can never use-after-close it. Final state alone
//     is identical under either order, so the ordering is observed from
//     INSIDE the keepalive goroutine at the moment it is cancelled.
//   - the IDENTITY: the handle that gets closed is the one the Manager was
//     using. Asserting on m.nlHandle after Close would be satisfied by
//     swapping in a fresh empty handle while leaking the original, so the
//     original pointer is captured up front and both checks run against it.
func TestCloseReleasesLiveHandleAndKeepalives_5718(t *testing.T) {
	m, err := New()
	if err != nil {
		t.Skipf("netlink handle unavailable in this environment: %v", err)
	}
	if m.nlHandle == nil {
		t.Fatal("setup: New() must own a netlink handle")
	}
	if m.tunnel == nil {
		t.Fatal("setup: New() must wire the tunnel domain")
	}
	// Capture the handle the Manager is actually using, before Close can
	// replace it.
	origHandle := m.nlHandle

	socketsBefore, err := origHandle.GetSocketReceiveBufferSize()
	if err != nil {
		t.Fatalf("setup: reading the handle's sockets: %v", err)
	}
	if len(socketsBefore) == 0 {
		t.Fatal("setup: the handle must own at least one live socket before Close")
	}

	ka := installLiveKeepalive(t, m, "gr-close-5718")

	if err := m.Close(); err != nil {
		t.Fatalf("Close on a fully wired Manager: %v", err)
	}

	// 1) The keepalive goroutine is gone, and it left by being cancelled.
	ka.assertDrained(t, "fully wired Manager")

	// 2) It was cancelled while the handle was still usable — the #848
	//    ordering. Under the reverse order (close the handle, then drain) the
	//    goroutine is still live when the sockets vanish, which is precisely
	//    the use-after-close this ordering exists to prevent.
	if !ka.handleOpenAtDrain.Load() {
		t.Fatal("Close closed the netlink handle BEFORE draining the keepalive runner: the " +
			"still-running goroutine observed a handle with no sockets. stopAll must drain " +
			"first, or an in-flight keepalive tick touches a closed handle (#848). Final " +
			"state is identical under either order, so only the goroutine's own view of the " +
			"handle at cancellation time can tell them apart")
	}

	// 3) The runner is removed from the map, not left as a cancelled corpse
	//    that GetKeepaliveState would still report.
	m.tunnel.mu.Lock()
	remaining := len(m.tunnel.keepalives)
	m.tunnel.mu.Unlock()
	if remaining != 0 {
		t.Fatalf("Close left %d keepalive runner(s) registered", remaining)
	}

	// 4) Close released the ORIGINAL handle rather than swapping in a fresh
	//    one. Both halves matter: the identity check catches the swap, and the
	//    socket check on the captured pointer catches the leak it would hide.
	if m.nlHandle != origHandle {
		t.Fatal("Close replaced m.nlHandle instead of closing it. A fresh handle satisfies " +
			"any socket-count assertion made against m.nlHandle after the fact while the " +
			"original's sockets stay open — the Manager is the sole owner and must release " +
			"the handle it was using")
	}
	socketsAfter, err := origHandle.GetSocketReceiveBufferSize()
	if err != nil {
		t.Fatalf("reading the handle's sockets after Close: %v", err)
	}
	if len(socketsAfter) != 0 {
		t.Fatalf("Close left %d of %d netlink socket(s) open on the handle the Manager was "+
			"using: the Manager is the sole owner and must release it",
			len(socketsAfter), len(socketsBefore))
	}
}

// TestClosePartialTestManagersDoesNotPanic_5718 is the #5718 A7-b02-C01
// fail-on-revert.
//
// The partial test-manager constructors in test_seams.go wire only the domains
// their callers exercise and leave the rest nil. Their doc comments told
// callers that Close nil-guards the unwired state, but Close guarded only
// nlHandle and called m.tunnel.stopAll() unconditionally. stopAll immediately
// takes t.mu (tunnel_keepalive_runner.go), which dereferences the nil
// *tunnelManager, so the documented `defer m.Close()` panicked the caller's
// test rather than cleaning up.
//
// A constructor this package exports must produce a Manager that is safe to
// Close, so this test drives Close on every partial constructor.
//
// Scope, stated plainly: the rule-ops and route-lister subtests bind ONE thing
// — that Close does not panic on a nil tunnel domain — and nothing else. A
// Manager with no tunnel and no handle has no live state to observe, so those
// two subtests also accept a `return nil` no-op. That no-op is caught by
// TestCloseDrainsBeforeReleasingHandle_5718, which does have live state; the
// suite binds both properties even though neither subtest binds both. Do not
// read these two as guarding that Close still does its work.
func TestClosePartialTestManagersDoesNotPanic_5718(t *testing.T) {
	t.Run("rule ops manager", func(t *testing.T) {
		m := NewManagerWithRuleOpsForTest(closeGuardRuleOps{})
		if m.tunnel != nil {
			t.Fatal("setup: NewManagerWithRuleOpsForTest is expected to leave the " +
				"tunnel domain nil — that unwired domain is what Close must guard")
		}
		if m.nlHandle != nil {
			t.Fatal("setup: NewManagerWithRuleOpsForTest is expected to leave nlHandle nil")
		}
		// Panics with a nil-pointer dereference in tunnelManager.stopAll
		// without the Close guard.
		if err := m.Close(); err != nil {
			t.Fatalf("Close on a rule-ops test manager: %v", err)
		}
	})

	t.Run("route lister manager", func(t *testing.T) {
		m := NewManagerWithRouteListerForTest(closeGuardRouteLister{})
		if m.tunnel != nil {
			t.Fatal("setup: NewManagerWithRouteListerForTest is expected to leave " +
				"the tunnel domain nil")
		}
		if m.nlHandle != nil {
			t.Fatal("setup: NewManagerWithRouteListerForTest is expected to leave nlHandle nil")
		}
		if err := m.Close(); err != nil {
			t.Fatalf("Close on a route-lister test manager: %v", err)
		}
	})

	t.Run("link ops manager still drains keepalives", func(t *testing.T) {
		// The link-ops constructor DOES populate tunnel, so the guard must not
		// turn Close into a no-op there: a live runner must still be cancelled
		// and drained (#848), on a Manager that has no netlink handle at all.
		m := NewManagerWithLinkOpsForTest(nil)
		if m.tunnel == nil {
			t.Fatal("setup: NewManagerWithLinkOpsForTest must wire the tunnel domain")
		}
		ka := installLiveKeepalive(t, m, "gr-linkops-5718")

		if err := m.Close(); err != nil {
			t.Fatalf("Close on a link-ops test manager: %v", err)
		}
		ka.assertDrained(t, "tunnel-wired partial Manager")
		m.tunnel.mu.Lock()
		remaining := len(m.tunnel.keepalives)
		m.tunnel.mu.Unlock()
		if remaining != 0 {
			t.Fatalf("Close left %d keepalive runner(s) registered", remaining)
		}
	})
}

// RuleAddDSCP satisfies ruleOps. These domains (probe pins / rib-group leaks /
// reconcile) never emit a DSCP selector, so a call here means a rule was routed
// down the wrong path — fail loudly rather than silently accepting it.
func (closeGuardRuleOps) RuleAddDSCP(*netlink.Rule, uint8) error {
	return fmt.Errorf("unexpected RuleAddDSCP: this domain emits no DSCP selectors")
}
