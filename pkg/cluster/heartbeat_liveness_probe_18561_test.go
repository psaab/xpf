package cluster

import (
	"context"
	"net"
	"testing"
	"time"
)

// #18561: a hard-killed peer (power loss, no FIN) leaves a half-open sync
// socket that still reads "connected", and its last sync frame is only about
// one heartbeat interval younger than its last heartbeat. The 2s recency
// window of syncSuppressesPeerTimeoutLocked therefore kept a dead peer alive
// for up to 2s past the heartbeat threshold (loss: declared 0.7-1.58 s after
// the kill at a 1.0 s threshold). One sync liveness probe is now sent at the
// first missed heartbeat; if no sync frame newer than it has arrived by the
// timeout tick, the timeout fires.
//
// The cells drive the real heartbeatReceiver.checkTimeout and
// handlePeerTimeout with a fake sync source at the runtime default
// 100 ms x 5. No sockets, no goroutines: time is advanced by moving every past
// stamp (last heartbeat, last sync frame, probe) into the past.

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

type probeRig18561 struct {
	t   *testing.T
	m   *Manager
	r   *heartbeatReceiver
	src *fakeLivenessProber18561
}

// newProbeRig18561 is a steady-state receiver (past every boot/restart grace)
// at 100 ms x 5 with a seen, alive peer whose last heartbeat and last sync
// frame are both lateBy old.
func newProbeRig18561(t *testing.T, ack bool, lateBy time.Duration) *probeRig18561 {
	t.Helper()
	src := &fakeLivenessProber18561{ackSupported: ack}
	src.lastRxMono = MonotonicNanos() - lateBy.Nanoseconds()
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
	return &probeRig18561{t: t, m: m, r: r, src: src}
}

// elapse moves every past stamp d into the past.
func (g *probeRig18561) elapse(d time.Duration) {
	n := d.Nanoseconds()
	g.m.mu.Lock()
	if g.m.hbLivenessProbeMono != 0 {
		g.m.hbLivenessProbeMono -= n
	}
	g.m.mu.Unlock()
	g.r.lastSeen.Store(g.r.lastSeen.Load() - n)
	if g.src.lastRxMono != 0 {
		g.src.lastRxMono -= n
	}
}

const firstMiss18561 = 160 * time.Millisecond // > 1.5 intervals, not stale

// Timeout tick: the last heartbeat is older than threshold x interval.
const toStale18561 = DefaultHeartbeatThreshold*DefaultHeartbeatInterval + 20*time.Millisecond - firstMiss18561

// The defect cell: a dead peer is declared on the timeout tick, not held by
// its last sync frame. RED on revert (suppressed: the frame is far younger
// than 2s) and RED if the probe stops being judged.
func TestDeadPeerDeclaredAtHeartbeatThreshold18561(t *testing.T) {
	g := newProbeRig18561(t, true, firstMiss18561)
	g.r.checkTimeout() // first missed heartbeat: one probe
	if !g.m.PeerAlive() || g.src.probes != 1 {
		t.Fatalf("first-miss tick: alive=%v probes=%d, want alive and one probe", g.m.PeerAlive(), g.src.probes)
	}
	g.elapse(toStale18561)
	g.r.checkTimeout()
	if g.m.PeerAlive() {
		t.Fatal("dead peer still alive on the timeout tick: the half-open sync socket's last frame " +
			"(older than the probe) must not suppress the heartbeat timeout")
	}
	if _, sent, unanswered := g.m.LivenessProbeStats(); sent != 1 || unanswered != 1 {
		t.Fatalf("probe stats sent=%d unanswered=%d, want 1/1", sent, unanswered)
	}
}

// A live peer gets the whole window, (threshold - 1.5) intervals, for ONE
// round trip: an answer that arrives just before the timeout tick still
// counts (seat U: a per-tick round-trip rule failed slow but live peers).
// Once answered, the window keeps the recency rule with no further probes.
func TestSlowLivePeerAnsweringOnceStaysSuppressed18561(t *testing.T) {
	g := newProbeRig18561(t, true, firstMiss18561)
	g.r.checkTimeout()
	g.elapse(toStale18561 - 20*time.Millisecond)
	g.src.lastRxMono = MonotonicNanos() // the answer, late in the window
	g.elapse(20 * time.Millisecond)
	g.r.checkTimeout()
	if !g.m.PeerAlive() {
		t.Fatal("a live peer that answered within the window was declared lost")
	}
	// Further ticks with no new frame: the recency rule holds the window
	// (the frame is well under 2s old) and nothing is re-probed.
	for range 5 {
		g.elapse(DefaultHeartbeatInterval)
		g.r.checkTimeout()
	}
	if !g.m.PeerAlive() {
		t.Fatal("an answered window lost the recency rule")
	}
	if g.src.probes != 1 {
		t.Fatalf("probes = %d, want 1: an answered window must not be re-probed every tick", g.src.probes)
	}
}

// A peer that never proved heartbeat-ack support keeps the recency-only
// rule, although the probe still goes out (its answer is what latches the
// support). RED if the ack gate is dropped from the decision.
func TestPeerWithoutAckSupportKeepsRecencyRule18561(t *testing.T) {
	g := newProbeRig18561(t, false, firstMiss18561)
	g.r.checkTimeout()
	if g.src.probes != 1 {
		t.Fatalf("probes = %d, want 1: the probe must go out even before the ack latch arms", g.src.probes)
	}
	g.elapse(toStale18561)
	g.r.checkTimeout()
	if !g.m.PeerAlive() {
		t.Fatal("peer without heartbeat-ack support lost the sync-recency suppression")
	}
}

// After a window ends (an admitted heartbeat resets it), the next window
// starts from scratch: an old probe answered by frames since then must not
// count for the new window. RED if resetSyncSuppressionLocked keeps the
// probe stamp or the proven latch.
func TestNewWindowIgnoresEarlierProbe18561(t *testing.T) {
	g := newProbeRig18561(t, true, firstMiss18561)
	g.r.checkTimeout() // window 1: probe
	g.src.lastRxMono = MonotonicNanos()
	g.elapse(toStale18561)
	g.r.checkTimeout() // answered: proven
	// Heartbeats resume: the window ends.
	g.m.mu.Lock()
	g.m.notePeerHeartbeatRecoveredLocked()
	g.m.mu.Unlock()
	g.r.lastSeen.Store(MonotonicNanos())
	g.src.lastRxMono = MonotonicNanos()
	// The peer is then hard-killed: heartbeat and sync stop together.
	g.elapse(firstMiss18561)
	g.r.checkTimeout() // window 2: a NEW probe
	if g.src.probes != 2 {
		t.Fatalf("probes = %d, want 2: window 2 must send its own probe", g.src.probes)
	}
	g.elapse(toStale18561)
	g.r.checkTimeout()
	if g.m.PeerAlive() {
		t.Fatal("the dead peer was kept alive by the previous window's answered probe")
	}
}

// A probe sent on the timeout tick itself (no pre-arm) gets
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

// An installed sync connection sends one sync-level heartbeat, so the peer's
// HeartbeatAck latches peerHeartbeatAckEver even on a node that keeps
// receiving frames and so never reaches its read-deadline heartbeat (seat T:
// a 20 ms inbound cadence left the latch false and the probe rule idle).
// RED if the install-time heartbeat is removed.
func TestInstalledConnectionSendsLivenessHeartbeat18561(t *testing.T) {
	s := newAuthSync(t, nil)
	cli, srv := net.Pipe()
	if !s.beginSetup(srv, true) {
		t.Fatal("beginSetup should admit the first inbound connection")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.handleNewConnection(ctx, 0, srv, true)
	defer cli.Close()
	for i := 0; i < 32; i++ {
		_ = cli.SetReadDeadline(time.Now().Add(2 * time.Second))
		typ, _, err := readSyncFrameRaw(cli)
		if err != nil {
			t.Fatalf("frame %d: %v (no sync heartbeat seen)", i, err)
		}
		if typ == syncMsgHeartbeat {
			return
		}
	}
	t.Fatal("an installed connection sent no sync-level heartbeat")
}
