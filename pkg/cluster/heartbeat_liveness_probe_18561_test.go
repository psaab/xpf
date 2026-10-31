package cluster

import (
	"testing"
	"time"
)

// #18561: a hard-killed peer (power loss, no FIN) leaves a half-open sync
// socket that still reads "connected", and its last sync frame is only about
// one heartbeat interval younger than its last heartbeat. The 2s recency
// window of syncSuppressesPeerTimeoutLocked therefore kept a dead peer alive
// for up to 2s past the heartbeat threshold (loss: declared 0.7-1.58 s after
// the kill at a 1.0 s threshold). The suppression now needs an inbound sync
// frame from AFTER a probe sent while the heartbeats were already late.
//
// The cells drive the real heartbeatReceiver.checkTimeout and
// handlePeerTimeout with a fake sync source. No sockets, no goroutines; the
// one-tick gap between the pre-arm tick and the timeout tick is modelled by
// backdating the probe stamp by one interval.

type fakeLivenessProber18561 struct {
	ackSupported bool
	lastRxMono   int64
	probes       int
}

func (f *fakeLivenessProber18561) IsConnected() bool { return true }
func (f *fakeLivenessProber18561) LastPeerReceiveAge() (time.Duration, bool) {
	if f.lastRxMono == 0 {
		return 0, false
	}
	return time.Duration(MonotonicNanos() - f.lastRxMono), true
}
func (f *fakeLivenessProber18561) PeerRecentlyActiveWithinSilenceWindow() bool { return true }
func (f *fakeLivenessProber18561) TransferChannelGen() uint64                  { return 0 }
func (f *fakeLivenessProber18561) PeerHeartbeatAckSupported() bool             { return f.ackSupported }
func (f *fakeLivenessProber18561) LastPeerReceiveMono() (int64, bool) {
	return f.lastRxMono, f.lastRxMono != 0
}
func (f *fakeLivenessProber18561) RequestLivenessProbe() { f.probes++ }

// seenPeer18561 is a steady-state receiver (past every boot/restart grace)
// at the runtime default 100ms x 5, with a seen, alive peer whose last
// heartbeat and last sync frame are both `lateBy` old.
func seenPeer18561(t *testing.T, src *fakeLivenessProber18561, lateBy time.Duration) (*Manager, *heartbeatReceiver) {
	t.Helper()
	m := NewManager(0, 1)
	r := newHeartbeatReceiver(m, nil, DefaultHeartbeatThreshold, DefaultHeartbeatInterval, nil)
	r.startedAt = time.Now().Add(-(heartbeatStartupGrace + time.Second))
	m.mu.Lock()
	m.peerAlive = true
	m.peerEverSeen = true
	m.hbReceiver = r
	m.mu.Unlock()
	m.setPeerSyncSourceForTesting(src)
	r.lastSeen.Store(MonotonicNanos() - lateBy.Nanoseconds())
	return m, r
}

// elapseOneTick18561 moves every past stamp (the outstanding probe, the
// last heartbeat, the last sync frame) one heartbeat interval into the
// past, i.e. the state on the next checkTimeout tick.
func elapseOneTick18561(m *Manager, r *heartbeatReceiver, src *fakeLivenessProber18561) {
	tick := DefaultHeartbeatInterval.Nanoseconds()
	m.mu.Lock()
	if m.hbLivenessProbeMono != 0 {
		m.hbLivenessProbeMono -= tick
	}
	m.mu.Unlock()
	r.lastSeen.Store(r.lastSeen.Load() - tick)
	if src.lastRxMono != 0 {
		src.lastRxMono -= tick
	}
}

const lateTick18561 = DefaultHeartbeatThreshold*DefaultHeartbeatInterval - DefaultHeartbeatInterval/2

// The defect cell: a dead peer is declared lost on the timeout tick, not
// held by its last sync frame. RED on revert (suppressed: the frame is far
// younger than 2s) and RED if the pre-arm is removed from checkTimeout (the
// timeout tick then sends the probe itself and must wait for it).
func TestDeadPeerDeclaredAtHeartbeatThreshold18561(t *testing.T) {
	src := &fakeLivenessProber18561{ackSupported: true}
	src.lastRxMono = MonotonicNanos() - lateTick18561.Nanoseconds()
	m, r := seenPeer18561(t, src, lateTick18561)

	r.checkTimeout() // late, not stale: pre-arm
	if !m.PeerAlive() || src.probes != 1 {
		t.Fatalf("pre-arm tick: alive=%v probes=%d, want alive and one probe", m.PeerAlive(), src.probes)
	}
	elapseOneTick18561(m, r, src)
	r.checkTimeout() // stale, no sync frame since the probe
	if m.PeerAlive() {
		t.Fatal("dead peer still alive on the timeout tick: the half-open sync socket's last frame " +
			"(older than the probe) must not suppress the heartbeat timeout")
	}
}

// A live peer whose UDP heartbeats stall but whose sync channel answers is
// still protected (the #1792/#17056 shape), and each suppressed tick sends
// the next probe.
func TestLivePeerAnsweringProbeStaysSuppressed18561(t *testing.T) {
	src := &fakeLivenessProber18561{ackSupported: true}
	src.lastRxMono = MonotonicNanos() - lateTick18561.Nanoseconds()
	m, r := seenPeer18561(t, src, lateTick18561)

	r.checkTimeout()
	src.lastRxMono = MonotonicNanos() // the heartbeat ack
	elapseOneTick18561(m, r, src)
	r.checkTimeout()
	if !m.PeerAlive() {
		t.Fatal("live peer that answered the probe was declared lost")
	}
	if src.probes != 2 {
		t.Fatalf("probes = %d, want 2: an answered probe must be followed by the next one", src.probes)
	}

	// It then dies: the next tick has nothing since the second probe.
	elapseOneTick18561(m, r, src)
	r.checkTimeout()
	if m.PeerAlive() {
		t.Fatal("peer that stopped answering was kept alive by an earlier answer")
	}
}

// A peer that never proved heartbeat-ack support keeps the recency-only
// rule: its sync traffic still suppresses. RED if the ack gate is dropped.
func TestPeerWithoutAckSupportKeepsRecencyRule18561(t *testing.T) {
	src := &fakeLivenessProber18561{ackSupported: false}
	src.lastRxMono = MonotonicNanos() - lateTick18561.Nanoseconds()
	m, r := seenPeer18561(t, src, lateTick18561)

	r.checkTimeout()
	elapseOneTick18561(m, r, src)
	r.checkTimeout()
	if !m.PeerAlive() {
		t.Fatal("peer without heartbeat-ack support lost the sync-recency suppression")
	}
	if src.probes != 0 {
		t.Fatalf("probes = %d, want 0 for a peer that cannot answer", src.probes)
	}
}

// A probe sent on the timeout tick itself (no pre-arm) is given
// minLivenessProbeAnswer before its silence counts; the 5s cap still ends
// an answered window.
func TestProbeAnswerFloorAndCap18561(t *testing.T) {
	src := &fakeLivenessProber18561{ackSupported: true}
	src.lastRxMono = MonotonicNanos() - time.Second.Nanoseconds()
	m := NewManager(0, 1)
	m.setPeerSyncSourceForTesting(src)
	now := MonotonicNanos()
	m.mu.Lock()
	defer m.mu.Unlock()
	if ok, _ := m.syncSuppressesPeerTimeoutLocked(now); !ok || src.probes != 1 {
		t.Fatalf("first suppressed tick: suppress=%v probes=%d, want true and one probe", ok, src.probes)
	}
	if ok, _ := m.syncSuppressesPeerTimeoutLocked(now + (minLivenessProbeAnswer / 2).Nanoseconds()); !ok {
		t.Fatal("probe younger than the answer floor already judged unanswered")
	}
	if ok, _ := m.syncSuppressesPeerTimeoutLocked(now + minLivenessProbeAnswer.Nanoseconds()); ok {
		t.Fatal("unanswered probe past the answer floor still suppressed")
	}

	m.resetSyncSuppressionLocked()
	src.lastRxMono = MonotonicNanos()
	m.hbSuppressStart = now - (maxSyncSuppressDuration + time.Second).Nanoseconds()
	if ok, _ := m.syncSuppressesPeerTimeoutLocked(now); ok {
		t.Fatal("the 5s continuous-suppression cap no longer ends the window")
	}
}
