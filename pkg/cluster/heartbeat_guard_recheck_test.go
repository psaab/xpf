package cluster

import (
	"testing"
	"time"
)

// TestHandlePeerTimeout_FreshHeartbeatAbortsPeerLost17056 exercises the
// #2080 bug directly: a fresh peer heartbeat must abort the peer-lost
// transition. #17056: there is no longer a guard window — handlePeerTimeout
// decides under m.mu — so the cell pins the same outcome through the
// freshness seam the timeout path consults first: fresh heartbeat -> peer
// stays alive, peer groups preserved. (Renamed from
// TestHandlePeerTimeout_FreshHeartbeatDuringGuardWindow and
// TestHandlePeerTimeout_StaleAfterGuardStillMarksLost's sibling naming;
// the guard window those names invoked no longer exists. The stale
// control below is renamed likewise to
// TestHandlePeerTimeout_StaleHeartbeatStillMarksLost17056.)
func TestHandlePeerTimeout_FreshHeartbeatAbortsPeerLost17056(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(
		makeRG(0, false, map[int]int{0: 200, 1: 100}),
	)
	m.UpdateConfig(cfg)

	m.mu.Lock()
	m.peerAlive = true
	m.peerEverSeen = true
	m.peerNodeID = 1
	m.peerGroups = map[int]PeerGroupState{
		0: {GroupID: 0, Priority: 100, Weight: 255, State: StatePrimary},
	}
	m.peerHeartbeatFreshFn = func() bool { return true }
	m.mu.Unlock()

	m.handlePeerTimeout()

	if !m.PeerAlive() {
		t.Fatal("peer marked lost despite a fresh heartbeat (#2080)")
	}
	if got := len(m.PeerGroupStates()); got != 1 {
		t.Fatalf("peer groups = %d, want 1 — peer state must be preserved when the heartbeat is fresh", got)
	}
}

// TestHandlePeerTimeout_StaleHeartbeatStillMarksLost17056 is the negative
// control: when the heartbeat is genuinely stale (and no fresh sync source
// suppresses), the peer must still be marked lost. This guards against an
// over-eager abort that would break real failover. (Renamed from
// TestHandlePeerTimeout_StaleAfterGuardStillMarksLost, #17056.)
func TestHandlePeerTimeout_StaleHeartbeatStillMarksLost17056(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(
		makeRG(0, false, map[int]int{0: 200, 1: 100}),
	)
	m.UpdateConfig(cfg)

	m.mu.Lock()
	m.peerAlive = true
	m.peerEverSeen = true
	m.peerNodeID = 1
	m.peerGroups = map[int]PeerGroupState{
		0: {GroupID: 0, Priority: 100, Weight: 255, State: StatePrimary},
	}
	m.peerHeartbeatFreshFn = func() bool { return false }
	m.mu.Unlock()

	// No sync source published: nothing suppresses.
	m.handlePeerTimeout()

	if m.PeerAlive() {
		t.Fatal("peer should be marked lost when the heartbeat is genuinely stale")
	}
	if got := len(m.PeerGroupStates()); got != 0 {
		t.Fatalf("peer groups = %d, want 0 — peer state must be cleared on a real peer loss", got)
	}
}

// TestHandlePeerTimeout_NoReceiverNoSeamStillMarksLost pins the default
// behavior: with no receiver wired and no seam set, peerHeartbeatFreshLocked
// reports not-fresh, so the peer-lost transition proceeds exactly as it did
// before the re-check existed. This protects the many existing callers that
// drive handlePeerTimeout without a real heartbeat receiver.
func TestHandlePeerTimeout_NoReceiverNoSeamStillMarksLost(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(
		makeRG(0, false, map[int]int{0: 200, 1: 100}),
	)
	m.UpdateConfig(cfg)

	m.mu.Lock()
	m.peerAlive = true
	m.peerEverSeen = true
	m.peerGroups = map[int]PeerGroupState{
		0: {GroupID: 0, Priority: 100, Weight: 255, State: StatePrimary},
	}
	m.mu.Unlock()

	// No guard, no seam, no receiver.
	m.handlePeerTimeout()

	if m.PeerAlive() {
		t.Fatal("peer should be marked lost with no receiver/seam (default fall-through)")
	}
}

// TestPeerHeartbeatFresh_ReceiverBacked exercises the real receiver-backed
// freshness check (the production path that peerHeartbeatFreshLocked defers to
// when no seam is set), so the test seam used above is not the only thing
// validated.
func TestPeerHeartbeatFresh_ReceiverBacked(t *testing.T) {
	r := &heartbeatReceiver{
		threshold: DefaultHeartbeatThreshold,
		interval:  DefaultHeartbeatInterval,
	}

	// Never seen → not fresh.
	if r.peerHeartbeatFresh() {
		t.Fatal("receiver with lastSeen==0 must report not-fresh")
	}

	// A heartbeat that just landed → fresh.
	r.lastSeen.Store(MonotonicNanos())
	if !r.peerHeartbeatFresh() {
		t.Fatal("receiver with a just-stored lastSeen must report fresh")
	}

	// A heartbeat older than the timeout window → stale.
	timeout := time.Duration(r.threshold) * r.interval
	r.lastSeen.Store(MonotonicNanos() - (2 * timeout).Nanoseconds())
	if r.peerHeartbeatFresh() {
		t.Fatal("receiver with a lastSeen older than the timeout must report stale")
	}
}

// TestPeerHeartbeatFreshLocked_ReceiverWiring confirms peerHeartbeatFreshLocked
// defers to the live receiver when no seam is set — closing the seam-vs-real
// gap end to end (handlePeerTimeout → Manager helper → receiver).
func TestPeerHeartbeatFreshLocked_ReceiverWiring(t *testing.T) {
	m := NewManager(0, 1)

	m.mu.Lock()
	defer m.mu.Unlock()

	// No receiver, no seam → not fresh.
	if m.peerHeartbeatFreshLocked() {
		t.Fatal("no receiver and no seam must report not-fresh")
	}

	// Wire a receiver with a fresh heartbeat.
	m.hbReceiver = &heartbeatReceiver{
		threshold: DefaultHeartbeatThreshold,
		interval:  DefaultHeartbeatInterval,
	}
	m.hbReceiver.lastSeen.Store(MonotonicNanos())
	if !m.peerHeartbeatFreshLocked() {
		t.Fatal("receiver with a fresh heartbeat must report fresh through peerHeartbeatFreshLocked")
	}

	// Seam takes precedence over the receiver.
	m.peerHeartbeatFreshFn = func() bool { return false }
	if m.peerHeartbeatFreshLocked() {
		t.Fatal("seam must take precedence over the receiver")
	}
}

// #12165/#17056 interleaving cell. Pre-move, the daemon guard ran outside
// Manager.mu: a heartbeat admitted during the guard cleared the daemon
// stamp, then the guard could store a fresh stamp, so the second gap
// inherited an already-expired cap. That race is now unrepresentable:
// admission clears hbSuppressStart in the same critical section that marks
// the peer alive, and the suppression decision reads the stamp under the
// same lock. This cell drives the exact interleaving — suppression window
// open, heartbeat admitted, second gap — through the real Manager paths
// and asserts the second gap gets a fresh stamp, not the first gap's.
// FAIL-ON-REVERT: remove the admission clear
// (notePeerHeartbeatRecoveredLocked in handlePeerHeartbeat) and the second
// HandlePeerTimeout promotes instead of suppressing.
func TestHandlePeerTimeout_SuppressedGuardClearsLateHeartbeatStamp12165(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(
		makeRG(0, false, map[int]int{0: 200, 1: 100}),
	)
	m.UpdateConfig(cfg)
	m.SetRGReady(0, true, nil)

	peerPrimary := &HeartbeatPacket{
		NodeID:    1,
		ClusterID: 1,
		Groups: []HeartbeatGroup{{
			GroupID: 0, Priority: 100, Weight: 100, State: uint8(StatePrimary),
		}},
	}
	m.handlePeerHeartbeat(peerPrimary)
	m.SetFakePeerSyncSourceForTesting(true, 100*time.Millisecond, true, true)

	// Gap 1: suppression opens and stamps.
	m.handlePeerTimeout()
	if !m.PeerAlive() {
		t.Fatal("gap 1: fresh sync traffic must suppress peer loss")
	}
	first := m.HBSuppressStartForTesting()
	if first == 0 {
		t.Fatal("gap 1: hbSuppressStart = 0 after suppression began, want nonzero stamp")
	}

	// Backdate gap 1's stamp past the 5s cap while heartbeats recover
	// through real admission. Admission must clear it in-section.
	m.SetHBSuppressStartForTesting(MonotonicNanos() - (6 * time.Second).Nanoseconds())
	m.handlePeerHeartbeat(peerPrimary)
	if got := m.HBSuppressStartForTesting(); got != 0 {
		t.Fatalf("admission: hbSuppressStart = %d, want cleared (0) so the next gap re-arms", got)
	}

	// Gap 2 must suppress on its own fresh stamp, not inherit gap 1's
	// expired cap.
	m.handlePeerTimeout()
	if !m.PeerAlive() {
		t.Fatal("gap 2: stale first stamp caused premature peer loss (#12165)")
	}
	second := m.HBSuppressStartForTesting()
	if second == 0 || second <= first {
		t.Fatalf("gap 2: hbSuppressStart = %d, want a fresh stamp after %d", second, first)
	}

	// Gap 2's own cap expiry must stop suppressing.
	m.SetHBSuppressStartForTesting(MonotonicNanos() - (6 * time.Second).Nanoseconds())
	m.handlePeerTimeout()
	if m.PeerAlive() {
		t.Fatal("gap 2: suppression did not expire after its own 5s cap")
	}
}

// #17056 reconnect cell: a disconnect+reconnect on the SAME SessionSync
// object (no republish, no heartbeat admission in between) must reset the
// suppression cap stamp, so the post-reconnect gap gets a fresh 5s window
// instead of inheriting the prior connection's expired cap. This pins the
// per-connection reset the pre-move daemon did in
// onSessionSyncPeerConnected (hbSuppressStart.Store(0) on every connect);
// the moved policy provides it through the OnPeerReconnected binding
// SetPeerSyncSource installs, fired at the sync_conn.go /
// sync_bulkstart_recv.go OnPeerConnected dispatch points. Sub-tick: the
// backdated stamp is already past its cap, so without the reset the first
// post-reconnect timeout promotes immediately (cap expired early); with
// it, the timeout re-stamps and suppresses.
// FAIL-ON-REVERT: drop the OnPeerReconnected binding in SetPeerSyncSource
// (or its dispatch in sync_conn.go) and the post-reconnect timeout below
// marks the peer lost instead of suppressing.
func TestHandlePeerTimeout_ReconnectResetsSuppressionCap17056(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(
		makeRG(0, false, map[int]int{0: 200, 1: 100}),
	)
	m.UpdateConfig(cfg)
	m.SetRGReady(0, true, nil)

	peerPrimary := &HeartbeatPacket{
		NodeID:    1,
		ClusterID: 1,
		Groups: []HeartbeatGroup{{
			GroupID: 0, Priority: 100, Weight: 100, State: uint8(StatePrimary),
		}},
	}
	m.handlePeerHeartbeat(peerPrimary)

	// Real SessionSync (not the fake): the reconnect binding lives on the
	// real object and is installed by the real publish.
	ss := NewSessionSync("127.0.0.1:4785", "127.0.0.1:4785", nil)
	ss.SetConnectedForTesting(true)
	ss.SetPeerReceiveAgeForTesting(100*time.Millisecond, true)
	m.SetPeerSyncSource(ss)
	if ss.OnPeerReconnected == nil {
		t.Fatal("SetPeerSyncSource did not bind OnPeerReconnected (#17056)")
	}
	if ss.peerReconnectOwner != m {
		t.Fatal("SetPeerSyncSource did not record the reconnect-binding owner (#17056)")
	}

	// Gap on the first connection: suppression opens and stamps.
	m.handlePeerTimeout()
	if !m.PeerAlive() {
		t.Fatal("gap 1: fresh sync traffic must suppress peer loss")
	}
	if first := m.HBSuppressStartForTesting(); first == 0 {
		t.Fatal("gap 1: hbSuppressStart = 0 after suppression began, want nonzero stamp")
	}

	// Disconnect + reconnect on the same object, sub-tick, with NO
	// heartbeat admission in between (admission would clear the stamp on
	// its own and mask a missing reconnect reset). The stamp is backdated
	// past its 5s cap first, modelling a first connection whose
	// continuous-suppression window had already expired by reconnect time.
	m.SetHBSuppressStartForTesting(MonotonicNanos() - (6 * time.Second).Nanoseconds())
	ss.SetConnectedForTesting(false) // disconnect: no timeout runs while down
	ss.SetConnectedForTesting(true)  // reconnect on the same SessionSync
	ss.SetPeerReceiveAgeForTesting(100*time.Millisecond, true)
	// The per-connection dispatch point (sync_conn.go / sync_bulkstart_recv.go
	// in production) fires the bound reset.
	ss.OnPeerReconnected()
	if got := m.HBSuppressStartForTesting(); got != 0 {
		t.Fatalf("reconnect: hbSuppressStart = %d, want cleared (0) by the per-connection reset", got)
	}

	// First post-reconnect timeout must re-stamp fresh and suppress: the
	// cap must NOT be treated as already expired from the prior connection.
	m.handlePeerTimeout()
	if !m.PeerAlive() {
		t.Fatal("post-reconnect: prior connection's expired cap caused premature peer loss (#17056)")
	}
	second := m.HBSuppressStartForTesting()
	if second == 0 {
		t.Fatal("post-reconnect: hbSuppressStart = 0, want a fresh stamp for the new connection's window")
	}
	if age := time.Duration(MonotonicNanos() - second); age < 0 || age > time.Second {
		t.Fatalf("post-reconnect: fresh stamp age = %v, want within [0, 1s] (sub-tick reconnect)", age)
	}

	// The new connection's own cap still applies: backdate past 5s and the
	// next timeout must stop suppressing.
	m.SetHBSuppressStartForTesting(MonotonicNanos() - (6 * time.Second).Nanoseconds())
	m.handlePeerTimeout()
	if m.PeerAlive() {
		t.Fatal("post-reconnect: suppression did not expire after the new connection's own 5s cap")
	}

	// Unpublish clears only this Manager's binding.
	m.SetPeerSyncSource(nil)
	if ss.OnPeerReconnected != nil || ss.peerReconnectOwner != nil {
		t.Fatal("SetPeerSyncSource(nil) left the reconnect binding installed (#17056)")
	}
}

// Positive/control cells for the moved policy (#17056): the 2s recency
// window, the disconnect/quiet resets, and the silence-window never-seen
// proof are exercised directly against syncSuppressesPeerTimeoutLocked /
// peerSyncFreshLocked timing, unchanged from the daemon guard.
func TestSyncSuppressesPeerTimeoutLocked17056(t *testing.T) {
	now := MonotonicNanos()
	cases := []struct {
		name         string
		connected    bool
		age          time.Duration
		received     bool
		silenceFresh bool
		wantSuppress bool
	}{
		{"fresh sync suppresses", true, 100 * time.Millisecond, true, true, true},
		{"at 2s boundary suppresses", true, 2 * time.Second, true, true, true},
		{"past 2s does not suppress", true, 2*time.Second + time.Millisecond, true, true, false},
		{"never received does not suppress", true, 0, false, false, false},
		{"disconnected does not suppress", false, 100 * time.Millisecond, true, true, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := NewManager(0, 1)
			m.SetFakePeerSyncSourceForTesting(tc.connected, tc.age, tc.received, tc.silenceFresh)
			m.mu.Lock()
			got, _ := m.syncSuppressesPeerTimeoutLocked(now)
			m.mu.Unlock()
			if got != tc.wantSuppress {
				t.Fatalf("syncSuppressesPeerTimeoutLocked = %v, want %v", got, tc.wantSuppress)
			}
		})
	}

	// Disconnect and quiet both reset the stamp so a later window re-arms.
	m := NewManager(0, 1)
	m.SetFakePeerSyncSourceForTesting(true, 100*time.Millisecond, true, true)
	m.mu.Lock()
	if ok, _ := m.syncSuppressesPeerTimeoutLocked(now); !ok || m.hbSuppressStart == 0 {
		m.mu.Unlock()
		t.Fatal("fresh sync must suppress and stamp")
	}
	m.mu.Unlock()
	m.SetFakePeerSyncSourceForTesting(false, 100*time.Millisecond, true, true)
	// SetPeerSyncSource reset already cleared; re-stamp then check quiet reset:
	m.SetFakePeerSyncSourceForTesting(true, 100*time.Millisecond, true, true)
	m.mu.Lock()
	_, _ = m.syncSuppressesPeerTimeoutLocked(now)
	m.mu.Unlock()
	m.setPeerSyncSourceForTesting(&fakePeerSyncSource17056{connected: true, age: 3 * time.Second, received: true})
	m.mu.Lock()
	if ok, _ := m.syncSuppressesPeerTimeoutLocked(now); ok {
		m.mu.Unlock()
		t.Fatal("quiet sync must not suppress")
	}
	if m.hbSuppressStart != 0 {
		m.mu.Unlock()
		t.Fatal("quiet sync must reset hbSuppressStart to 0")
	}
	m.mu.Unlock()

	// Cap: a stamp older than 5s stops suppression even with fresh sync.
	m2 := NewManager(0, 1)
	m2.SetFakePeerSyncSourceForTesting(true, 100*time.Millisecond, true, true)
	m2.SetHBSuppressStartForTesting(now - (6 * time.Second).Nanoseconds())
	m2.mu.Lock()
	if ok, _ := m2.syncSuppressesPeerTimeoutLocked(now); ok {
		m2.mu.Unlock()
		t.Fatal("cap exceeded must not suppress")
	}
	m2.mu.Unlock()
}

// hbSuppressCapExceeded boundary semantics in the monotonic domain (#1792),
// moved with the policy from pkg/daemon.
func TestHBSuppressCapExceeded17056(t *testing.T) {
	const capDur = 5 * time.Second
	base := int64(2_000_000_000_000)
	cases := []struct {
		name       string
		start, now int64
		want       bool
	}{
		{"just started", base, base, false},
		{"within cap", base, base + (4 * time.Second).Nanoseconds(), false},
		{"exactly cap", base, base + capDur.Nanoseconds(), false},
		{"just past cap", base, base + capDur.Nanoseconds() + 1, true},
		{"negative elapsed tolerated", base, base - time.Second.Nanoseconds(), false},
	}
	for _, tc := range cases {
		if got := hbSuppressCapExceeded(tc.start, tc.now, capDur); got != tc.want {
			t.Errorf("%s: hbSuppressCapExceeded(%d, %d, %v) = %v, want %v", tc.name, tc.start, tc.now, capDur, got, tc.want)
		}
	}
}
