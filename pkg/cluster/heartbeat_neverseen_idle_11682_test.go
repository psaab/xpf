package cluster

import (
	"context"
	"fmt"
	"io"
	"net"
	"testing"
	"time"
)

// #11682: an idle sync-alive peer (heartbeat-ACK only, no session traffic)
// with dead UDP heartbeats was confirmed absent inside the stale ACK gap.
//
// An idle peer sends only a heartbeat/ACK per 10s sync read deadline, so a 2s
// receive proof is stale ~8s out of every 10s. checkTimeout ticks every
// heartbeat interval, so after the 30s startup grace the first tick inside a
// stale gap confirmed an alive-but-idle peer absent and the ready node
// promoted — dual-primary until dual-active resolution demoted one side.
//
// The never-seen probe must therefore use the 30s peer-silence window, not
// the 2s established-peer guard: every sample across the 10s ACK cycle must
// suppress absence confirmation, while a truly silent peer must still allow
// single-node promotion (below).

// TestColdBootIdleSyncAliveNeverConfirmedAbsent11682 walks one 10s idle ACK
// cycle past the startup grace with UDP heartbeats dead (lastSeen == 0) and
// requires every tick to hold: no absence confirmation, no ever-seen
// rewrite, and no promotion (a promotion here is dual-primary — the peer is
// alive). Fully hermetic: ages are injected monotonic nanos, no sleeps.
func TestColdBootIdleSyncAliveNeverConfirmedAbsent11682(t *testing.T) {
	// Receive ages across one 10s idle ACK cycle, worst stale gap last: an
	// ACK landed `age` ago and the next one is due at 10s.
	idleAges := []time.Duration{
		0,
		time.Second,
		2 * time.Second,
		3 * time.Second,
		5 * time.Second,
		8 * time.Second,
		9 * time.Second,
		9900 * time.Millisecond,
	}
	for _, age := range idleAges {
		m := coldBootManager(t)
		m.SetRGReady(0, true, nil)
		ss := NewSessionSync("127.0.0.1:0", "127.0.0.1:0", nil)
		ss.stats.Connected.Store(true)
		ss.lastPeerRxMono.Store(MonotonicNanos() - age.Nanoseconds())
		m.SetPeerNeverSeenSyncFreshFunc(func() bool {
			return ss.IsConnected() && ss.PeerRecentlyActiveWithinSilenceWindow()
		})

		r := newHeartbeatReceiver(m, nil, DefaultHeartbeatThreshold, DefaultHeartbeatInterval, nil)
		r.startedAt = time.Now().Add(-(heartbeatStartupGrace + time.Second))
		// r.lastSeen stays 0: UDP heartbeats dead, sync ACKs only.
		r.checkTimeout()

		if peerConfirmedAbsent(m) {
			t.Errorf("idle ACK age %v: alive peer confirmed absent inside the stale ACK gap", age)
		}
		if peerEverSeen(m) {
			t.Errorf("idle ACK age %v: never-seen peer incorrectly recorded as ever seen", age)
		}
		if m.IsLocalPrimary(0) {
			t.Errorf("idle ACK age %v: node promoted while the idle peer is alive (dual-primary)", age)
		}
	}
}

// TestColdBootIdleSyncAckCadenceHoldsNeverSeenPeer11682 runs an actual sync
// receiveLoop over a pipe. The peer answers the production heartbeat probes
// with heartbeat ACK frames at a controlled, accelerated cadence while the
// UDP receiver remains never-seen. It checks each heartbeat tick on the same
// manager after cold-boot grace, including ages beyond the scaled 2s/10s stale
// threshold but before the next ACK.
func TestColdBootIdleSyncAckCadenceHoldsNeverSeenPeer11682(t *testing.T) {
	const readDeadline = 50 * time.Millisecond
	legacyProbeWindow := readDeadline / 5 // 2s guard scaled against a 10s probe interval.
	m := coldBootManager(t)
	m.SetRGReady(0, true, nil)
	ss := NewSessionSync("127.0.0.1:0", "127.0.0.1:0", nil)
	ss.readDeadline = readDeadline
	ss.peerSilenceLimit = 4 * readDeadline
	localConn, peerConn := net.Pipe()
	ss.installConn(0, localConn)
	// Make the install's initial timestamp stale. Only a frame read by the
	// receive loop can re-establish the proof used below.
	ss.lastPeerRxMono.Store(MonotonicNanos() - time.Second.Nanoseconds())

	m.SetPeerNeverSeenSyncFreshFunc(func() bool {
		return ss.IsConnected() && ss.PeerRecentlyActiveWithinSilenceWindow()
	})
	r := newHeartbeatReceiver(m, nil, DefaultHeartbeatThreshold, DefaultHeartbeatInterval, nil)
	r.startedAt = time.Now().Add(-(heartbeatStartupGrace + time.Second))

	ctx, cancel := context.WithCancel(context.Background())
	receiveDone := make(chan struct{})
	go func() {
		ss.receiveLoop(ctx, localConn)
		close(receiveDone)
	}()
	peerDone := make(chan struct{})
	ackTimes := make(chan time.Time, 16)
	peerErr := make(chan error, 1)
	go func() {
		defer close(peerDone)
		hdr := make([]byte, syncHeaderSize)
		for {
			if _, err := io.ReadFull(peerConn, hdr); err != nil {
				return
			}
			if hdr[4] != syncMsgHeartbeat {
				select {
				case peerErr <- fmt.Errorf("unexpected sync message type %d, want heartbeat probe", hdr[4]):
				default:
				}
				return
			}
			if err := writeMsg(peerConn, syncMsgHeartbeatAck, nil); err != nil {
				select {
				case peerErr <- fmt.Errorf("write heartbeat ACK: %w", err):
				default:
				}
				return
			}
			ackTimes <- time.Now()
		}
	}()
	defer func() {
		cancel()
		_ = localConn.Close()
		_ = peerConn.Close()
		<-receiveDone
		<-peerDone
	}()

	select {
	case <-ackTimes:
	case err := <-peerErr:
		t.Fatalf("idle peer failed to answer sync probe: %v", err)
	case <-time.After(time.Second):
		t.Fatal("receive loop did not send a sync heartbeat probe")
	}
	ackDeadline := time.After(time.Second)
	for !ss.peerHeartbeatAckEver.Load() {
		select {
		case err := <-peerErr:
			t.Fatalf("idle peer failed to answer sync probe: %v", err)
		case <-ackDeadline:
			t.Fatal("receive loop did not process the idle peer's heartbeat ACK")
		case <-time.After(time.Millisecond):
		}
	}
	if age, ok := ss.LastPeerReceiveAge(); !ok || age > readDeadline {
		t.Fatalf("received heartbeat ACK did not refresh sync proof: age=%v received=%v", age, ok)
	}

	ticker := time.NewTicker(readDeadline / 10)
	defer ticker.Stop()
	runFor := 3 * readDeadline
	timer := time.NewTimer(runFor)
	defer timer.Stop()
	ackCount, tickCount := 1, 0
	crossedLegacyGap := false
	for {
		select {
		case <-ackTimes:
			ackCount++
		case err := <-peerErr:
			t.Fatalf("idle peer failed to answer sync probe: %v", err)
		case <-ticker.C:
			tickCount++
			r.checkTimeout()
			if age, ok := ss.LastPeerReceiveAge(); ok && age > legacyProbeWindow {
				crossedLegacyGap = true
			}
			if peerConfirmedAbsent(m) {
				t.Fatalf("idle ACK peer confirmed absent after %d heartbeat ticks", tickCount)
			}
			if peerEverSeen(m) {
				t.Fatal("never-seen heartbeat state was rewritten by sync ACK")
			}
			if m.IsLocalPrimary(0) {
				t.Fatalf("node promoted while the idle sync peer answered ACK probes (dual-primary)")
			}
		case <-timer.C:
			if !crossedLegacyGap {
				t.Fatal("test did not sample an ACK gap beyond the scaled 2s probe window")
			}
			if ackCount < 3 || tickCount < 10 {
				t.Fatalf("controlled cadence too short: received ACKs=%d heartbeat ticks=%d", ackCount, tickCount)
			}
			return
		}
	}
}

// TestColdBootTrulySilentSyncStillPromotes11682 pins the fix's other edge: a
// peer that is silent past the 30s silence window, sync-disconnected, or has
// never sent anything must NOT hold the never-seen path — single-node
// promotion must still happen. In particular there is no PeerHealthy-style
// legacy-true arm: a connected peer with zero inbound proves nothing.
func TestColdBootTrulySilentSyncStillPromotes11682(t *testing.T) {
	cases := []struct {
		name      string
		connected bool
		age       time.Duration
		everRx    bool
	}{
		{name: "silent past window", connected: true, age: 31 * time.Second, everRx: true},
		{name: "sync disconnected", connected: false, age: 0, everRx: true},
		{name: "connected never sent", connected: true, age: 0, everRx: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := coldBootManager(t)
			m.SetRGReady(0, true, nil)
			ss := NewSessionSync("127.0.0.1:0", "127.0.0.1:0", nil)
			ss.stats.Connected.Store(tc.connected)
			if tc.everRx {
				ss.lastPeerRxMono.Store(MonotonicNanos() - tc.age.Nanoseconds())
			}
			m.SetPeerNeverSeenSyncFreshFunc(func() bool {
				return ss.IsConnected() && ss.PeerRecentlyActiveWithinSilenceWindow()
			})

			r := newHeartbeatReceiver(m, nil, DefaultHeartbeatThreshold, DefaultHeartbeatInterval, nil)
			r.startedAt = time.Now().Add(-(heartbeatStartupGrace + time.Second))
			r.checkTimeout()

			if !peerConfirmedAbsent(m) || peerEverSeen(m) {
				t.Fatalf("truly silent peer produced wrong never-seen state: confirmedAbsent=%v everSeen=%v",
					peerConfirmedAbsent(m), peerEverSeen(m))
			}
			if !m.IsLocalPrimary(0) {
				t.Fatal("ready node did not promote for a truly silent peer")
			}
		})
	}
}

// TestPeerRecentlyActiveWithinSilenceWindow11682 keeps the probe window tied
// to the sync peer-silence policy, rather than the daemon's shorter
// established-peer heartbeat suppression window.
func TestPeerRecentlyActiveWithinSilenceWindow11682(t *testing.T) {
	ss := NewSessionSync("127.0.0.1:0", "127.0.0.1:0", nil)
	if ss.PeerRecentlyActiveWithinSilenceWindow() {
		t.Fatal("never-received peer reported recently active")
	}

	// A 10s-old ACK is stale under the daemon's former 2s probe but healthy
	// within the 30s sync peer-silence window.
	ss.lastPeerRxMono.Store(MonotonicNanos() - (10 * time.Second).Nanoseconds())
	if !ss.PeerRecentlyActiveWithinSilenceWindow() {
		t.Fatal("idle ACK 10s into the default 30s silence window reported stale")
	}

	ss.lastPeerRxMono.Store(MonotonicNanos() - (31 * time.Second).Nanoseconds())
	if ss.PeerRecentlyActiveWithinSilenceWindow() {
		t.Fatal("peer beyond the silence window reported recently active")
	}

	ss.peerSilenceLimit = 5 * time.Second
	ss.lastPeerRxMono.Store(MonotonicNanos() - (6 * time.Second).Nanoseconds())
	if ss.PeerRecentlyActiveWithinSilenceWindow() {
		t.Fatal("probe did not honor the session's configured silence window")
	}
}
