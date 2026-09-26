package vrrp

import (
	"net"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/cluster"
)

// #2081: ReconcileVIPs (called after programRethMAC link DOWN/UP changes the
// RETH virtual MAC) bumps garpEpoch to FORCE a fresh GARP, defeating the
// epoch dedup. But sendGARP has a SECOND gate — the 500ms time dampener
// (garpDampened) — which the epoch bump does NOT clear. If any routine GARP
// was emitted in the prior 500ms, the dampener silently dropped the critical
// post-MAC-change GARP, leaving peers with a stale ARP entry (blackhole until
// it ages out).
//
// The fix routes forced sends through garpSendAllowed(force=true), which
// bypasses the time dampener while preserving it for the normal periodic path
// AND preserving the per-epoch dedup for both paths.
//
// These tests exercise garpSendAllowed directly — the network-free decision
// seam used by sendGARP — so the suppression behaviour is verified without
// performing real ARP/NA I/O.

// TestGARPForcedBypassesDampener is the core #2081 regression: a forced send
// must proceed even when a routine GARP was emitted moments ago (well inside
// the 500ms window). This FAILS pre-fix, where the dampener applied to every
// send regardless of force.
func TestGARPForcedBypassesDampener(t *testing.T) {
	now := time.Now().UnixNano()

	vi := &vrrpInstance{}
	// Simulate the ReconcileVIPs sequence: a routine GARP just fired (e.g. a
	// becomeMaster burst 100ms ago for epoch 1), then programRethMAC changed
	// the MAC and ReconcileVIPs bumped the epoch to 2.
	vi.lastGARPEpoch.Store(1)
	vi.lastGARPTime.Store(now - (100 * time.Millisecond).Nanoseconds())
	vi.garpEpoch.Store(2)

	// Forced (ReconcileVIPs) path: MUST be allowed despite being only 100ms
	// after the prior burst — the MAC just changed, peers hold a stale entry.
	if !vi.garpSendAllowed(true, now) {
		t.Fatal("forced post-MAC-change GARP was suppressed within 500ms of a " +
			"prior burst — #2081 regression: stale ARP blackhole at peers")
	}
}

// TestGARPNormalStillDampenedWithinWindow proves the fix did NOT remove
// dampening globally: a NON-forced send within 500ms of a prior burst is
// still suppressed (storm control for rapid VRRP flaps is preserved).
func TestGARPNormalStillDampenedWithinWindow(t *testing.T) {
	now := time.Now().UnixNano()

	vi := &vrrpInstance{}
	// A routine GARP fired 100ms ago for the current epoch's predecessor;
	// a new transition bumped the epoch (so epoch dedup does NOT fire and we
	// isolate the dampener gate).
	vi.lastGARPEpoch.Store(1)
	vi.lastGARPTime.Store(now - (100 * time.Millisecond).Nanoseconds())
	vi.garpEpoch.Store(2)

	if vi.garpSendAllowed(false, now) {
		t.Fatal("normal periodic GARP within 500ms should remain dampened — " +
			"the dampener must survive the #2081 fix")
	}
}

// TestGARPNormalAllowedAfterWindow confirms the normal path resumes once the
// dampening window has elapsed (the dampener is a delay, not a permanent gate).
func TestGARPNormalAllowedAfterWindow(t *testing.T) {
	now := time.Now().UnixNano()

	vi := &vrrpInstance{}
	vi.lastGARPEpoch.Store(1)
	// Last burst was 600ms ago — outside the 500ms window.
	vi.lastGARPTime.Store(now - (600 * time.Millisecond).Nanoseconds())
	vi.garpEpoch.Store(2)

	if !vi.garpSendAllowed(false, now) {
		t.Fatal("normal GARP after the 500ms window should be allowed")
	}
}

// TestGARPForcedStillRespectsEpochDedup proves force bypasses ONLY the time
// dampener, not the per-epoch dedup. A forced caller that did NOT bump the
// epoch (lastGARPEpoch already equals garpEpoch) must still be deduplicated —
// otherwise a spurious double ReconcileVIPs would emit duplicate bursts.
func TestGARPForcedStillRespectsEpochDedup(t *testing.T) {
	now := time.Now().UnixNano()

	vi := &vrrpInstance{}
	// Epoch already satisfied: a GARP for epoch 2 was already completed.
	vi.garpEpoch.Store(2)
	vi.lastGARPEpoch.Store(2)
	// And no recent burst, so the dampener would not fire — isolate dedup.
	vi.lastGARPTime.Store(0)

	if vi.garpSendAllowed(true, now) {
		t.Fatal("forced send must still honour the per-epoch dedup; force only " +
			"bypasses the time dampener")
	}
}

// TestGARPReconcileSequenceAllowed reproduces the exact ReconcileVIPs ordering
// end-to-end at the decision seam: a fresh becomeMaster burst, then an epoch
// bump (as ReconcileVIPs does), then the forced send — which must proceed even
// though the becomeMaster burst is well inside the dampening window. This is
// the precise scenario #2081 describes.
func TestGARPReconcileSequenceAllowed(t *testing.T) {
	now := time.Now().UnixNano()

	vi := &vrrpInstance{}

	// 1. becomeMaster for epoch 1, non-forced: allowed (nothing sent yet).
	vi.garpEpoch.Store(1)
	if !vi.garpSendAllowed(false, now) {
		t.Fatal("initial becomeMaster GARP should be allowed")
	}
	// Record the completed burst as sendGARP would.
	vi.lastGARPEpoch.Store(1)
	vi.lastGARPTime.Store(now)

	// 2. A duplicate becomeMaster GARP for the same epoch is deduped.
	if vi.garpSendAllowed(false, now+(10*time.Millisecond).Nanoseconds()) {
		t.Fatal("duplicate GARP for the same epoch should be deduped")
	}

	// 3. programRethMAC changes the MAC; ReconcileVIPs bumps the epoch and
	//    forces a send only 50ms after the becomeMaster burst. Pre-fix the
	//    dampener swallowed this; post-fix the forced path emits it.
	vi.garpEpoch.Store(2)
	soon := now + (50 * time.Millisecond).Nanoseconds()
	if !vi.garpSendAllowed(true, soon) {
		t.Fatal("forced ReconcileVIPs GARP after a MAC change must be emitted " +
			"even 50ms after the becomeMaster burst (#2081)")
	}

	// 4. Sanity: the SAME state via the NON-forced path would have been
	//    dampened — proving force is exactly what unblocks it (non-tautological).
	if vi.garpSendAllowed(false, soon) {
		t.Fatal("control: non-forced send in the same state should be dampened, " +
			"confirming the forced path is what bypasses the dampener")
	}
}

// TestGARPForcedEpochZero covers force with no prior epoch bump (epoch==0):
// the epoch dedup only fires when epoch>0, so a forced send at epoch 0 must
// be allowed. ForceRGMaster/manual takeover can drive a send before any
// becomeMaster bump, so this combination is reachable.
func TestGARPForcedEpochZero(t *testing.T) {
	now := time.Now().UnixNano()
	vi := &vrrpInstance{}
	// epoch 0, never sent, but a routine burst fired 50ms ago.
	vi.lastGARPTime.Store(now - (50 * time.Millisecond).Nanoseconds())
	if !vi.garpSendAllowed(true, now) {
		t.Fatal("forced send at epoch 0 must be allowed (dedup only applies for epoch>0)")
	}
}

// TestGARPForcedBackwardClock covers the #1792 backward-wall-clock interaction
// with force: lastGARPTime is "in the future" relative to now. garpDampened
// already treats this as send-allowed, but force must also never be blocked by
// it. Belt-and-suspenders for the failover-blackhole class.
func TestGARPForcedBackwardClock(t *testing.T) {
	now := time.Now().UnixNano()
	vi := &vrrpInstance{}
	vi.lastGARPEpoch.Store(1)
	vi.garpEpoch.Store(2)
	// last burst stamped 3s in the "future" (wall clock stepped backward).
	vi.lastGARPTime.Store(now + (3 * time.Second).Nanoseconds())
	if !vi.garpSendAllowed(true, now) {
		t.Fatal("forced send must be allowed despite a backward wall-clock step (#1792 + #2081)")
	}
	// And the normal path is also allowed here (garpDampened clamps negatives).
	if !vi.garpSendAllowed(false, now) {
		t.Fatal("normal send should be allowed on a backward clock step (#1792)")
	}
}

// --- Caller-wiring tests (R2 Major): assert the call sites pass the correct
// force value, so an arg-swap (becomeMaster forces, ReconcileVIPs does not)
// is caught — not just the garpSendAllowed seam in isolation.
//
// sendGARP is driven directly with an EMPTY VirtualAddresses set: the send
// loop then performs no network I/O, but the gate decision and the
// lastGARPEpoch/lastGARPTime state-store still execute. Asserting state
// advancement therefore proves whether the gate admitted the burst for the
// given force value.

// masterInstanceNoVIPs builds a MASTER vrrpInstance with no VIPs (so sendGARP
// emits nothing on the wire) and an interface name that does not exist (so the
// addVIPs netlink lookup warns and returns without side effects).
func masterInstanceNoVIPs(t *testing.T) *vrrpInstance {
	t.Helper()
	vi := newInstance(Instance{
		Interface:        "xpf-test-nonexistent0",
		GroupID:          101,
		Priority:         200,
		VirtualAddresses: nil, // no VIPs -> sendGARP loop is a no-op
	}, &net.Interface{Name: "xpf-test-nonexistent0"}, make(chan VRRPEvent, 8), nil)
	vi.setState(StateMaster)
	return vi
}

// TestReconcileVIPsForcesGARPWithinDampenWindow is the end-to-end caller test
// for #2081: ReconcileVIPs must emit the post-MAC-change GARP even when a
// routine GARP fired moments ago. If the ReconcileVIPs call site silently
// passed force=false (the arg-swap regression), lastGARPEpoch would NOT
// advance and this fails.
func TestReconcileVIPsForcesGARPWithinDampenWindow(t *testing.T) {
	m := NewManager()
	vi := masterInstanceNoVIPs(t)
	// Simulate a routine becomeMaster GARP just completed for epoch 1, 100ms
	// ago — well inside the 500ms dampen window.
	vi.garpEpoch.Store(1)
	vi.lastGARPEpoch.Store(1)
	vi.lastGARPTime.Store(time.Now().Add(-100 * time.Millisecond).UnixNano())

	m.mu.Lock()
	m.instances = map[instanceKey]*vrrpInstance{
		{iface: vi.cfg.Interface, groupID: 101}: vi,
	}
	m.mu.Unlock()

	// programRethMAC changed the MAC; the daemon calls ReconcileVIPs.
	m.ReconcileVIPs()

	// ReconcileVIPs bumps the epoch (1 -> 2) and forces a send; the forced
	// send completes and records lastGARPEpoch = 2.
	if got := vi.garpEpoch.Load(); got != 2 {
		t.Fatalf("ReconcileVIPs should bump garpEpoch to 2, got %d", got)
	}
	if got := vi.lastGARPEpoch.Load(); got != 2 {
		t.Fatalf("forced ReconcileVIPs GARP was NOT emitted within the dampen "+
			"window: lastGARPEpoch = %d, want 2 (#2081 caller-wiring regression — "+
			"the call site must pass force=true)", got)
	}
}

// TestReconcileVIPsHonoursSuppression confirms ReconcileVIPs still respects
// strict-vip-ownership GARP suppression (force must not override suppressGARP).
func TestReconcileVIPsHonoursSuppression(t *testing.T) {
	m := NewManager()
	vi := masterInstanceNoVIPs(t)
	vi.garpEpoch.Store(1)
	vi.lastGARPEpoch.Store(1)
	vi.lastGARPTime.Store(time.Now().Add(-100 * time.Millisecond).UnixNano())
	vi.suppressGARP.Store(true)

	m.mu.Lock()
	m.instances = map[instanceKey]*vrrpInstance{
		{iface: vi.cfg.Interface, groupID: 101}: vi,
	}
	m.mu.Unlock()

	m.ReconcileVIPs()

	// Epoch is still bumped (the announce intent is recorded), but no send
	// happened, so lastGARPEpoch stays at the prior value.
	if got := vi.lastGARPEpoch.Load(); got != 1 {
		t.Fatalf("suppressed ReconcileVIPs should NOT emit a GARP: lastGARPEpoch = %d, want 1", got)
	}
}

// TestBecomeMasterGARPIsDampened is the inverse caller-wiring test: the
// becomeMaster GARP path must pass force=false, so a burst within 500ms of a
// prior one is dampened. If the call site were swapped to force=true, this
// burst would be emitted and lastGARPEpoch would advance — catching the
// reverse arg-swap. sendGARP(false) is invoked synchronously here (the
// production goroutine just wraps the same call).
func TestBecomeMasterGARPIsDampened(t *testing.T) {
	vi := masterInstanceNoVIPs(t)
	// A routine GARP completed 100ms ago for epoch 1 in this same tenure.
	vi.garpEpoch.Store(1)
	vi.lastGARPEpoch.Store(1)
	vi.lastGARPOwnerGen.Store(vi.ownerGen.Load())
	vi.lastGARPTime.Store(time.Now().Add(-100 * time.Millisecond).UnixNano())
	// A new transition bumps the epoch (mirrors becomeMaster) but does NOT
	// change the MAC, so the non-forced path must dampen it.
	vi.garpEpoch.Store(2)

	vi.sendGARP(false)

	if got := vi.lastGARPEpoch.Load(); got != 1 {
		t.Fatalf("non-forced becomeMaster-path GARP within 500ms should be "+
			"dampened (lastGARPEpoch unchanged): got %d, want 1 — if this is 2, "+
			"the becomeMaster call site is wrongly forcing", got)
	}
}

// TestSendGARPForcedAdvancesStateWithinWindow proves sendGARP(true) end-to-end
// (not just the seam) advances state within the dampen window, while
// sendGARP(false) in the identical state does not. This is the strongest
// single non-tautological assertion: same instance, same state, the ONLY
// difference is the force argument.
func TestSendGARPForcedAdvancesStateWithinWindow(t *testing.T) {
	mk := func() *vrrpInstance {
		vi := masterInstanceNoVIPs(t)
		vi.garpEpoch.Store(2)
		vi.lastGARPEpoch.Store(1)
		vi.lastGARPOwnerGen.Store(vi.ownerGen.Load())
		vi.lastGARPTime.Store(time.Now().Add(-100 * time.Millisecond).UnixNano())
		return vi
	}

	forced := mk()
	forced.sendGARP(true)
	if forced.lastGARPEpoch.Load() != 2 {
		t.Fatalf("sendGARP(true) within window should advance lastGARPEpoch to 2, got %d",
			forced.lastGARPEpoch.Load())
	}

	normal := mk()
	normal.sendGARP(false)
	if normal.lastGARPEpoch.Load() != 1 {
		t.Fatalf("sendGARP(false) within window should be dampened (lastGARPEpoch "+
			"stays 1), got %d", normal.lastGARPEpoch.Load())
	}
}

// TestBecomeMasterGARPAfterAbdicationBypassesDampener covers sub-500ms
// failback while an older burst is still in flight. The old completion must
// retain its captured owner generation; otherwise it re-arms the dampener for
// the new tenure and suppresses the corrective GARP.
func TestBecomeMasterGARPAfterAbdicationBypassesDampener(t *testing.T) {
	oldBurstFn, oldProbeFn := garpBurstFn, arpProbeFn
	var burstCalls int
	blocked := make(chan struct{})
	release := make(chan struct{})
	released := false
	sendStarted := false
	sendDone := make(chan struct{})
	unblock := func() {
		if !released {
			close(release)
			released = true
		}
	}
	t.Cleanup(func() {
		unblock()
		if sendStarted {
			<-sendDone
		}
		garpBurstFn, arpProbeFn = oldBurstFn, oldProbeFn
	})
	garpBurstFn = func(_ string, _ net.IP, _ int, _ cluster.BurstStillValid) error {
		burstCalls++
		if burstCalls == 2 {
			close(blocked)
			<-release
		}
		return nil
	}
	arpProbeFn = func(_ string, _, _ net.IP) error { return nil }

	vi := masterInstanceWithVIP(t, "10.0.0.100/24")
	vi.garpEpoch.Store(1)
	vi.sendGARP(false)
	if burstCalls != 1 {
		t.Fatalf("initial MASTER GARP emitted %d bursts, want 1", burstCalls)
	}

	// Stamp the prior burst as 150ms old. The second forced burst enters its
	// sender, then remains in flight across ownership loss and rapid failback.
	vi.lastGARPTime.Store(time.Now().Add(-150 * time.Millisecond).UnixNano())
	vi.garpEpoch.Store(2)
	go func() {
		defer close(sendDone)
		vi.sendGARP(true)
	}()
	sendStarted = true
	select {
	case <-blocked:
	case <-time.After(time.Second):
		t.Fatal("forced GARP did not reach the burst sender")
	}

	vi.setState(StateBackup) // peer takes mastership and advertises its MAC
	vi.setState(StateMaster) // this node fails back inside the 500ms window
	vi.garpEpoch.Store(3)
	unblock()
	<-sendDone

	// The old burst's completion wrote its captured owner generation. A normal
	// failback send must still emit a corrective burst within 500ms.
	vi.sendGARP(false)
	if burstCalls != 3 {
		t.Fatalf("GARP burst callbacks = %d, want 3 (initial, in-flight, failback)",
			burstCalls)
	}
	if got := vi.lastGARPEpoch.Load(); got != 3 {
		t.Fatalf("failback GARP completion epoch = %d, want 3", got)
	}
}
