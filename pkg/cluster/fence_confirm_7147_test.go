package cluster

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// #7147 — the `peer-fencing disable-rg-confirmed` policy at the Manager level.
//
// Two properties, and the suite is only meaningful if it holds BOTH:
//
//  1. ORDERING. The fence is sent and confirmed BEFORE this node claims the
//     redundancy groups. Without this the policy is decoration.
//  2. LIVENESS. Every way the confirmation can fail still results in a
//     takeover. Without this the policy is an outage generator, and it would be
//     a worse defect than the gap #7147 set out to close.

// confirmFenceManager returns a manager armed with the confirmed policy, primed
// so handlePeerTimeout runs its fence branch.
func confirmFenceManager(t *testing.T) *Manager {
	t.Helper()
	m := NewManager(0, 1)
	cfg := makeConfig(makeRG(0, false, map[int]int{0: 200, 1: 100}))
	cfg.PeerFencing = PeerFencingDisableRGConfirmed
	m.UpdateConfig(cfg)
	m.mu.Lock()
	m.peerAlive = true
	m.peerEverSeen = true
	// Force SECONDARY. UpdateConfig already elects this node primary (it has
	// the higher priority and no peer state is known), and from a
	// already-primary start NOTHING electSingleNode does is observable — the
	// ordering test below would then pass identically against the pre-#7147
	// fence-after-election shape. Starting secondary is what makes the
	// discriminator actually vary.
	for _, rg := range m.groups {
		rg.State = StateSecondary
	}
	m.mu.Unlock()
	return m
}

func rgState(t *testing.T, m *Manager, rgID int) NodeState {
	t.Helper()
	m.mu.RLock()
	defer m.mu.RUnlock()
	rg, ok := m.groups[rgID]
	if !ok {
		t.Fatalf("redundancy group %d missing", rgID)
	}
	return rg.State
}

// THE CORE CLAIM. Under `disable-rg-confirmed` the fence must be issued while
// this node still does NOT own the groups — that ordering is the entire
// difference between this policy and `disable-rg`.
//
// The assertion is made from INSIDE the confirm callback, sampling the real RG
// state at the moment the fence is issued. Asserting only the end state would
// pass just as happily with the pre-#7147 ordering (fence after election),
// because both orderings end with the node primary.
func TestConfirmedFenceRunsBeforeElection7147(t *testing.T) {
	m := confirmFenceManager(t)

	// Guard the discriminator: if the fixture were already primary, both
	// orderings would sample StatePrimary inside the callback and this test
	// would certify the shape it exists to reject.
	if got := rgState(t, m, 0); got == StatePrimary {
		t.Fatalf("fixture is already primary (%v); this test cannot distinguish the "+
			"orderings from that starting point", got)
	}

	var stateAtFence NodeState
	var called bool
	m.SetPeerFenceConfirmFunc(func(timeout time.Duration) (FenceAck, error) {
		called = true
		stateAtFence = rgState(t, m, 0)
		return FenceAck{Status: FenceAckOK, RGsFenced: 1, RGsTotal: 1}, nil
	})

	m.handlePeerTimeout()

	if !called {
		t.Fatal("the confirm function was never called under disable-rg-confirmed, so " +
			"nothing gated the takeover")
	}
	if stateAtFence == StatePrimary {
		t.Errorf("this node was ALREADY %v when the fence was issued; the fence must "+
			"precede the election or the policy gates nothing", stateAtFence)
	}
	if got := rgState(t, m, 0); got != StatePrimary {
		t.Errorf("after a CONFIRMED fence the node is %v, want primary — the takeover "+
			"must still happen", got)
	}
}

// LIVENESS, exhaustively. Every negative outcome must still end with the node
// primary. A gate that can withhold ownership converts peer loss into an
// outage, which is strictly worse than the unacknowledged fence it replaced.
func TestConfirmedFenceAlwaysFailsOpen7147(t *testing.T) {
	tests := []struct {
		name    string
		fn      func(time.Duration) (FenceAck, error)
		wantMsg string
	}{
		{
			name:    "no sync armed",
			fn:      nil,
			wantMsg: "Fence skipped: sync not available",
		},
		{
			name:    "peer not connected",
			fn:      func(time.Duration) (FenceAck, error) { return FenceAck{}, fmt.Errorf("peer not connected") },
			wantMsg: "Fence unconfirmed, took over anyway: peer not connected",
		},
		{
			name: "peer predates 7147",
			fn: func(time.Duration) (FenceAck, error) {
				return FenceAck{}, fmt.Errorf("peer does not support fence acknowledgement")
			},
			wantMsg: "Fence unconfirmed, took over anyway: peer does not support fence acknowledgement",
		},
		{
			name: "ack timed out",
			fn: func(d time.Duration) (FenceAck, error) {
				return FenceAck{}, fmt.Errorf("timed out after %s waiting for peer fence ack seq=1", d)
			},
			wantMsg: "Fence unconfirmed, took over anyway: timed out",
		},
		{
			name: "peer only partly fenced",
			fn: func(time.Duration) (FenceAck, error) {
				return FenceAck{Status: FenceAckPartial, RGsFenced: 1, RGsTotal: 3}, nil
			},
			wantMsg: "Fence NOT confirmed (peer disabled only 1/3 redundancy groups), took over anyway",
		},
		{
			name: "peer has no dataplane",
			fn: func(time.Duration) (FenceAck, error) {
				return FenceAck{Status: FenceAckUnavailable}, nil
			},
			wantMsg: "Fence NOT confirmed (peer has no dataplane (config-only mode)), took over anyway",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := confirmFenceManager(t)
			if tt.fn != nil {
				m.SetPeerFenceConfirmFunc(tt.fn)
			}

			done := make(chan struct{})
			go func() {
				m.handlePeerTimeout()
				close(done)
			}()
			select {
			case <-done:
			case <-time.After(30 * time.Second):
				t.Fatal("handlePeerTimeout never returned; the confirmed fence must " +
					"never block a takeover indefinitely")
			}

			if got := rgState(t, m, 0); got != StatePrimary {
				t.Errorf("node is %v after a FAILED confirmation, want primary — the "+
					"takeover must proceed anyway or peer loss becomes an outage", got)
			}

			// The operator asked for a guarantee and did not get it. That must
			// be visible, or a cluster failing open on every takeover looks
			// exactly like one that confirms every time.
			out := m.FormatInformation()
			if !strings.Contains(out, tt.wantMsg) {
				t.Errorf("`show chassis cluster information` does not report the "+
					"fail-open reason %q:\n%s", tt.wantMsg, out)
			}
			if strings.Contains(out, "Fence confirmed by peer") {
				t.Errorf("a FAILED confirmation was reported as confirmed:\n%s", out)
			}
		})
	}
}

// A successful confirmation must be reported as such, and must name what the
// peer actually disabled rather than merely that a message was sent.
func TestConfirmedFenceReportsWhatThePeerDisabled7147(t *testing.T) {
	m := confirmFenceManager(t)
	m.SetPeerFenceConfirmFunc(func(time.Duration) (FenceAck, error) {
		return FenceAck{Status: FenceAckOK, RGsFenced: 4, RGsTotal: 4}, nil
	})
	m.handlePeerTimeout()

	out := m.FormatInformation()
	want := "Fence confirmed by peer (peer disabled 4/4 redundancy groups)"
	if !strings.Contains(out, want) {
		t.Errorf("expected %q in:\n%s", want, out)
	}
	if !strings.Contains(out, "Action: disable-rg-confirmed") {
		t.Errorf("the armed policy is not reported:\n%s", out)
	}
}

// The bounded timeout must actually reach the sender. A gate that passed 0 (or
// forgot the argument) would either never wait or wait forever, and both look
// fine in an end-state assertion.
func TestConfirmedFencePassesTheBoundedTimeout7147(t *testing.T) {
	m := confirmFenceManager(t)
	var got time.Duration
	m.SetPeerFenceConfirmFunc(func(d time.Duration) (FenceAck, error) {
		got = d
		return FenceAck{Status: FenceAckOK}, nil
	})
	m.handlePeerTimeout()

	if got != FenceConfirmTimeout {
		t.Errorf("confirm fn received timeout %s, want FenceConfirmTimeout (%s)", got, FenceConfirmTimeout)
	}
	if got <= 0 {
		t.Error("the fence confirmation wait is unbounded or instant; neither is the " +
			"intended bounded fail-open policy")
	}
}

// `disable-rg` must be untouched by #7147: it uses the fire-and-forget sender,
// never the confirming one, so no already-deployed config changes behaviour.
func TestDisableRGPolicyIsUnaffectedBy7147(t *testing.T) {
	m := fenceInfoManager(t, PeerFencingDisableRG)
	confirmCalled := false
	bestEffortCalled := false
	m.SetPeerFenceConfirmFunc(func(time.Duration) (FenceAck, error) {
		confirmCalled = true
		return FenceAck{Status: FenceAckOK}, nil
	})
	m.SetPeerFenceFunc(func() error {
		bestEffortCalled = true
		return nil
	})

	m.handlePeerTimeout()

	if confirmCalled {
		t.Error("`disable-rg` used the CONFIRMING fence path. #7147 must not change " +
			"the behaviour of a policy value that operators already have deployed")
	}
	if !bestEffortCalled {
		t.Error("`disable-rg` no longer sends its best-effort fence")
	}
	if got := rgState(t, m, 0); got != StatePrimary {
		t.Errorf("node is %v, want primary", got)
	}
}

// Symmetrically: an UNCONFIGURED peer-fencing leaf must not send anything at
// all. Without this, the two policy tests above would both pass on an
// implementation that fenced unconditionally.
func TestNoFencingPolicySendsNoFence7147(t *testing.T) {
	m := fenceInfoManager(t, "")
	confirmCalled := false
	bestEffortCalled := false
	m.SetPeerFenceConfirmFunc(func(time.Duration) (FenceAck, error) {
		confirmCalled = true
		return FenceAck{Status: FenceAckOK}, nil
	})
	m.SetPeerFenceFunc(func() error {
		bestEffortCalled = true
		return nil
	})

	m.handlePeerTimeout()

	if confirmCalled || bestEffortCalled {
		t.Errorf("a node with no peer-fencing configured fenced its peer "+
			"(confirm=%v best_effort=%v)", confirmCalled, bestEffortCalled)
	}
	if got := rgState(t, m, 0); got != StatePrimary {
		t.Errorf("node is %v, want primary", got)
	}
}

// The confirmation counters must reach the operator surface. FenceAcksTimedOut
// is the number that says "you did not get the guarantee you selected", and it
// appears nowhere else — FencesSent counts the same on a confirmed and an
// unconfirmed takeover.
func TestConfirmationCountersAreRendered7147(t *testing.T) {
	m := confirmFenceManager(t)
	ss := &SessionSync{}
	ss.stats.FenceAcksReceived.Store(3)
	ss.stats.FenceAcksTimedOut.Store(2)
	ss.stats.FenceAcksSent.Store(1)
	m.SetSyncStats(ss)

	out := m.FormatInformation()
	want := "Confirmations: received 3, timed out 2, sent to peer 1"
	if !strings.Contains(out, want) {
		t.Errorf("expected %q in `show chassis cluster information`:\n%s", want, out)
	}
}

// The policy strings the runtime branches on must be values an operator can
// actually COMMIT. A constant that disagreed with the config schema's enum
// would compile, pass every test above (they all use the constant, so they
// agree with themselves by construction), and silently no-op in production —
// handlePeerTimeout would match neither arm and fence nothing.
//
// So this asserts the AGREEMENT by driving the real schema validator, rather
// than pinning the constants to literals. Pinning would only prove the
// constants equal whatever this test also hard-codes; it could not see the
// schema rejecting them. The near-miss rows are what stop the check passing on
// a validator loosened to a prefix match.
func TestPolicyConstantsAreCommittable7147(t *testing.T) {
	t.Parallel()

	commit := func(t *testing.T, value string) error {
		t.Helper()
		tree := &config.ConfigTree{}
		path, err := config.ParseSetCommand("set chassis cluster peer-fencing " + value)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", value, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", value, err)
		}
		return config.SchemaValidate(tree, nil)
	}

	for _, v := range []string{PeerFencingDisableRG, PeerFencingDisableRGConfirmed} {
		if err := commit(t, v); err != nil {
			t.Errorf("the runtime branches on peer-fencing %q but the config schema "+
				"REJECTS it (%v). handlePeerTimeout would match neither arm and fence "+
				"nothing, while every other test here still passed because they all use "+
				"this same constant.", v, err)
		}
	}

	// Guard the guard: if the schema accepted anything, the loop above would
	// pass no matter what the constants said.
	for _, v := range []string{"disable-rg-confirm", "shoot-the-other-node"} {
		if err := commit(t, v); err == nil {
			t.Errorf("the schema accepted peer-fencing %q; the acceptance check above "+
				"then proves nothing about the real constants", v)
		}
	}
}

// THE HAZARD THE FIRST DRAFT OF THIS SUITE COULD NOT SEE.
//
// `awaitPeerFenceLocked` releases m.mu across the wait. handlePeerTimeout sets
// peerAlive=false precisely to BYPASS electSingleNode's #7161 readiness gate
// (armed only when `controlInterface != "" && (peerAlive || !peerEverSeen)`),
// so a heartbeat landing inside that window re-arms the gate and the election
// declines to promote — after the peer has already been fenced dark. Peer dark
// plus local node passive is a total outage, produced by the very policy that
// exists to prevent split-brain. This cell covers the CONFIRMED arm of that
// window; the unconfirmed arm is #14158 (a heartbeat plus a failed fence must
// abort the takeover instead) — see fence_heartbeat_race_14158_test.go.
//
// Every other test in this file is STRUCTURALLY BLIND to it: confirmFenceManager
// builds its config with makeConfig, which never sets ControlInterface, so
// `m.controlInterface == ""` makes the gate arm unreachable and the window
// cannot change any outcome. This fixture arms the gate (ControlInterface set,
// a takeover hold running so the RG is not takeover-ready) and simulates the
// racing heartbeat from inside the confirm callback — the one place that is
// genuinely inside the window.
func TestConfirmedFencePromotesEvenIfAHeartbeatLandsInTheWindow7147(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(makeRG(0, false, map[int]int{0: 200, 1: 100}))
	cfg.PeerFencing = PeerFencingDisableRGConfirmed
	// Arm the election gates: without this the branch under test is dead code
	// and the test would pass against the unfixed implementation.
	cfg.ControlInterface = "em0"
	cfg.TakeoverHoldTime = int((30 * time.Second) / time.Millisecond)
	m.UpdateConfig(cfg)

	m.mu.Lock()
	m.peerAlive = true
	m.peerEverSeen = true
	for _, rg := range m.groups {
		rg.State = StateSecondary
		// Ready, but only just — so IsReadyForTakeover is false for the whole
		// takeover-hold window and readinessGateVerdictLocked would decline if
		// the gate were armed.
		rg.Ready = true
		rg.ReadySince = time.Now()
	}
	if m.controlInterface == "" {
		m.mu.Unlock()
		t.Fatal("fixture did not arm the readiness gate (controlInterface empty); " +
			"this test cannot observe the hazard it exists for")
	}
	if m.groups[0].IsReadyForTakeover(m.takeoverHoldTime) {
		m.mu.Unlock()
		t.Fatal("fixture RG is already takeover-ready, so the readiness gate would " +
			"permit promotion regardless and the test would pass either way")
	}
	m.mu.Unlock()

	m.SetPeerFenceConfirmFunc(func(time.Duration) (FenceAck, error) {
		// Inside the window: m.mu is released here, exactly as a blocked
		// handlePeerHeartbeat goroutine would find it. Take it and set
		// peerAlive, which is all handlePeerHeartbeat needs to do to re-arm
		// the gate.
		m.mu.Lock()
		m.peerAlive = true
		m.mu.Unlock()
		// The peer HAS been fenced: it reports every RG disabled.
		return FenceAck{Status: FenceAckOK, RGsFenced: 1, RGsTotal: 1}, nil
	})

	m.handlePeerTimeout()

	if got := rgState(t, m, 0); got != StatePrimary {
		t.Fatalf("node is %v after a CONFIRMED fence, want primary. A heartbeat that "+
			"landed while awaitPeerFenceLocked held m.mu open re-armed the #7161 "+
			"readiness gate, so electSingleNode declined to promote — while the peer "+
			"had already driven every RG to rg_active=false in response to our fence. "+
			"Peer dark, this node passive: no primary anywhere.", got)
	}
}
