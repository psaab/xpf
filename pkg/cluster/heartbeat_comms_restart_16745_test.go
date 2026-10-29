package cluster

import (
	"testing"
	"time"
)

// #16745: a comms restart is StopHeartbeat followed by StartHeartbeat in the
// same Manager lifetime (stopClusterComms -> next epoch's startClusterComms,
// driven by a transport-endpoint commit or a #11448 reassert). StartHeartbeat
// used to pass restartSeed 0, so the replacement was a cold start:
//
//   - peer silent from the restart onward: the new receiver's lastSeen stays
//     0, every tick takes the never-seen arm, and handlePeerNeverSeen returns
//     on peerEverSeen — the peer is NEVER declared lost;
//   - peer heard once then lost: seenThenLostGrace() is the 30s cold-boot
//     grace, so takeover is up to 30s late (#9722's class, at the
//     Stop+Start site #9722 did not cover).
//
// StopHeartbeat now stashes the outgoing receiver's lastSeen/grace-end and
// StartHeartbeat seeds from it when peerEverSeen && peerAlive; the
// never-seen arm additionally routes a seen-and-alive Manager through
// handlePeerTimeout as defense in depth.
//
// Cells drive the real StartHeartbeat/StopHeartbeat sockets on loopback
// (SO_REUSEPORT allows the rebind, as in heartbeat_liveness_test.go), then
// drive the installed receiver's checkTimeout directly with backdated
// startedAt — no 40s sleeps.

// commsManager16745 builds a two-node-priority RG where the peer (node 1,
// priority 200) outranks local (node 0, priority 100), so while the peer is
// alive local stays secondary and after peer loss local promotes.
func commsManager16745(t *testing.T) *Manager {
	t.Helper()
	m := NewManager(0, 1)
	cfg := makeConfig(makeRG(1, false, map[int]int{0: 100, 1: 200}))
	cfg.ControlInterface = "em0"
	m.UpdateConfig(cfg)
	m.SetRGReady(1, true, nil)
	return m
}

// markPeerSeen16745 records a peer that was heard and owns RG1 as primary,
// with its last heartbeat `age` old on receiver r.
func markPeerSeen16745(m *Manager, r *heartbeatReceiver, age time.Duration) int64 {
	seed := MonotonicNanos() - age.Nanoseconds()
	r.lastSeen.Store(seed)
	m.mu.Lock()
	m.peerAlive = true
	m.peerEverSeen = true
	m.peerNodeID = 1
	m.peerGroups = map[int]PeerGroupState{
		1: {GroupID: 1, Priority: 200, Weight: 255, State: StatePrimary},
	}
	if rg, ok := m.groups[1]; ok {
		rg.State = StateSecondary
	}
	m.mu.Unlock()
	return seed
}

func installedReceiver16745(t *testing.T, m *Manager) *heartbeatReceiver {
	t.Helper()
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.hbReceiver == nil {
		t.Fatal("no receiver installed")
	}
	return m.hbReceiver
}

// DEFECT row (acceptance): Stop+Start with a peer silent from the restart
// onward flips to peerAlive=false / localPrimary=true within restart grace
// plus timeout. RED on pre-fix: the replacement has lastSeen==0 / no restart
// grace and stays peerAlive=true forever.
// CONTROL row included: a live peer heard after the restart stays alive.
func TestVA22CommsRestartSilentPeer16745(t *testing.T) {
	m := commsManager16745(t)
	if err := m.StartHeartbeat("127.0.0.1", "127.0.0.1", "", "em0"); err != nil {
		t.Fatalf("StartHeartbeat: %v", err)
	}
	old := installedReceiver16745(t, m)
	// Steady state: heard 10 minutes ago in wall terms is modelled by an
	// old-but-valid seed plus a startedAt long past the boot grace, so the
	// predecessor was NOT inside any grace at stop time.
	seed := markPeerSeen16745(m, old, 250*time.Millisecond)
	old.startedAt = time.Now().Add(-10 * time.Minute)

	// Comms restart: the production pair.
	m.StopHeartbeat()
	if err := m.StartHeartbeat("127.0.0.1", "127.0.0.1", "", "em0"); err != nil {
		t.Fatalf("restart StartHeartbeat: %v", err)
	}
	defer m.StopHeartbeat()

	nr := installedReceiver16745(t, m)
	if nr == old {
		t.Fatal("receiver was not replaced by the comms restart")
	}
	if got := nr.lastSeen.Load(); got != seed {
		t.Fatalf("#16745: replacement lastSeen = %d, want outgoing seed %d — the comms restart dropped the peer-liveness seed", got, seed)
	}
	if nr.seenGrace != heartbeatRestartGrace {
		t.Fatalf("#16745: replacement seenGrace = %v, want %v (restart grace, not cold-boot)", nr.seenGrace, heartbeatRestartGrace)
	}

	// Peer silent from the restart onward. Simulate restart-grace-plus
	// elapsed: backdate startedAt past the restart grace and age the seeded
	// lastSeen by the same span (real monotonic time did not pass while the
	// fixture was built), so it is stale by > threshold*interval.
	nr.lastSeen.Store(seed - (heartbeatRestartGrace + 500*time.Millisecond).Nanoseconds())
	nr.startedAt = time.Now().Add(-(heartbeatRestartGrace + 500*time.Millisecond))
	nr.checkTimeout()
	if m.PeerAlive() {
		t.Fatal("#16745 DEFECT: peer silent from a comms restart onward is still alive after restart grace + timeout — never declared lost")
	}
	if !m.IsLocalPrimary(1) {
		t.Fatal("#16745 DEFECT: local did not take over RG1 after the silent peer was declared lost")
	}
	if rgs, alive := m.PeerPrimaryRGs(); alive || len(rgs) != 0 {
		t.Fatalf("PeerPrimaryRGs = %v,%v after peer loss, want none,false", rgs, alive)
	}

	// CONTROL: a second manager whose peer resumes after the restart stays
	// alive past the same point.
	m2 := commsManager16745(t)
	if err := m2.StartHeartbeat("127.0.0.1", "127.0.0.1", "", "em0"); err != nil {
		t.Fatalf("control StartHeartbeat: %v", err)
	}
	old2 := installedReceiver16745(t, m2)
	markPeerSeen16745(m2, old2, 250*time.Millisecond)
	old2.startedAt = time.Now().Add(-10 * time.Minute)
	m2.StopHeartbeat()
	if err := m2.StartHeartbeat("127.0.0.1", "127.0.0.1", "", "em0"); err != nil {
		t.Fatalf("control restart StartHeartbeat: %v", err)
	}
	defer m2.StopHeartbeat()
	nr2 := installedReceiver16745(t, m2)
	nr2.lastSeen.Store(MonotonicNanos()) // peer heard again after restart
	nr2.startedAt = time.Now().Add(-(heartbeatRestartGrace + 500*time.Millisecond))
	nr2.checkTimeout()
	if !m2.PeerAlive() {
		t.Fatal("control: a peer heard after the comms restart was declared lost")
	}
}

// Second arm: peer heard once after the restart, then dies. The replacement
// must hold only heartbeatRestartGrace (5s), not the 30s cold-boot grace:
// past 5.5s with a stale lastSeen the peer is lost. RED on pre-fix: cold
// grace keeps peerAlive=true at 5.5s (declared lost up to 30s late).
func TestCommsRestartHeardOnceThenLostUsesRestartGrace16745(t *testing.T) {
	m := commsManager16745(t)
	if err := m.StartHeartbeat("127.0.0.1", "127.0.0.1", "", "em0"); err != nil {
		t.Fatalf("StartHeartbeat: %v", err)
	}
	old := installedReceiver16745(t, m)
	markPeerSeen16745(m, old, 250*time.Millisecond)
	old.startedAt = time.Now().Add(-10 * time.Minute)
	m.StopHeartbeat()
	if err := m.StartHeartbeat("127.0.0.1", "127.0.0.1", "", "em0"); err != nil {
		t.Fatalf("restart StartHeartbeat: %v", err)
	}
	defer m.StopHeartbeat()

	nr := installedReceiver16745(t, m)
	// Heard once just after the restart, then silent for 10s.
	nr.lastSeen.Store(MonotonicNanos() - staleAge9722.Nanoseconds())
	nr.startedAt = time.Now().Add(-(heartbeatRestartGrace + 500*time.Millisecond))
	if nr.startedAt.Before(time.Now().Add(-heartbeatStartupGrace)) {
		t.Fatal("fixture: must still be inside the cold-boot grace to prove the point")
	}
	nr.checkTimeout()
	if m.PeerAlive() {
		t.Fatal("#16745: peer heard once after a comms restart then lost is still alive past the 5s restart grace (held for the 30s cold-boot grace)")
	}
	if !m.IsLocalPrimary(1) {
		t.Fatal("#16745: local did not take over RG1 after the heard-once peer was declared lost")
	}
}

// Cold-boot cells unchanged (#4386/#11566): a fresh Manager's StartHeartbeat
// (no stash, peer never seen) keeps seenGrace==0, and a replacement for a
// receiver that never saw the peer leaves no seed for the next start.
func TestCommsRestartColdBootUnchanged16745(t *testing.T) {
	m := commsManager16745(t)
	if err := m.StartHeartbeat("127.0.0.1", "127.0.0.1", "", "em0"); err != nil {
		t.Fatalf("StartHeartbeat: %v", err)
	}
	r := installedReceiver16745(t, m)
	if r.seenGrace != 0 || r.lastSeen.Load() != 0 {
		t.Fatalf("cold start armed: seenGrace=%v lastSeen=%d, want 0/0", r.seenGrace, r.lastSeen.Load())
	}
	// Never-seen receiver inside grace -> past grace still confirms absent
	// via the never-seen arm, not peer loss.
	r.startedAt = time.Now().Add(-(heartbeatStartupGrace + time.Second))
	r.checkTimeout()
	if !peerConfirmedAbsent(m) || peerEverSeen(m) {
		t.Fatalf("cold-boot never-seen: confirmedAbsent=%v everSeen=%v, want true/false", peerConfirmedAbsent(m), peerEverSeen(m))
	}
	if m.PeerAlive() {
		t.Fatal("cold-boot never-seen must not mark peerAlive")
	}

	// Stop (never seen) then Start: no seed is stashed, cold start again.
	m.StopHeartbeat()
	if err := m.StartHeartbeat("127.0.0.1", "127.0.0.1", "", "em0"); err != nil {
		t.Fatalf("second StartHeartbeat: %v", err)
	}
	defer m.StopHeartbeat()
	r2 := installedReceiver16745(t, m)
	if r2.seenGrace != 0 || r2.lastSeen.Load() != 0 {
		t.Fatalf("start after a never-seen stop inherited a seed: seenGrace=%v lastSeen=%d, want cold start", r2.seenGrace, r2.lastSeen.Load())
	}
}

// Defense in depth: even if a replacement somehow starts unseeded
// (lastSeen==0) while the Manager has seen a live peer, the never-seen arm
// must declare the peer lost via handlePeerTimeout instead of returning on
// peerEverSeen forever. Also pins that a peer already lost is not
// re-confirmed absent and cold-boot managers are untouched.
func TestNeverSeenArmRoutesSeenAlivePeerToTimeout16745(t *testing.T) {
	m := commsManager16745(t)
	r := newHeartbeatReceiver(m, nil, DefaultHeartbeatThreshold, DefaultHeartbeatInterval, nil)
	m.mu.Lock()
	m.hbReceiver = r
	m.peerAlive = true
	m.peerEverSeen = true
	m.peerGroups = map[int]PeerGroupState{
		1: {GroupID: 1, Priority: 200, Weight: 255, State: StatePrimary},
	}
	m.mu.Unlock()
	// Unseeded receiver, well past the never-seen grace, peer silent.
	r.startedAt = time.Now().Add(-(heartbeatStartupGrace + time.Second))
	r.checkTimeout()
	if m.PeerAlive() {
		t.Fatal("#16745: never-seen arm left a seen-and-alive peer marked alive forever")
	}
	if !m.IsLocalPrimary(1) {
		t.Fatal("#16745: never-seen arm did not promote local after routing to peer timeout")
	}
	if peerConfirmedAbsent(m) {
		t.Fatal("seen-peer loss must not be recorded as cold-boot confirmed-absent")
	}
}

// #17764: a SECOND comms restart inside the same boot epoch must not drop
// the cold-boot floor the first restart inherited. Sequence: cold receiver
// starts at t=0 and hears its peer (protection until t0+30s); Stop+Start at
// ~t=1 installs a receiver with 5s own grace and inheritedHold t0+30;
// Stop+Start again at ~t=2 must install a receiver whose inheritedHold is
// still t0+30. Pre-fix, the second StopHeartbeat stashes only
// startedAt+seenThenLostGrace() (~t1+5s), so the floor drops ~23s early and
// checkTimeout past the second receiver's own 5s grace declares a live
// (but silent-since-restart) peer lost.
// Controls: expired inherited floor is not resurrected; never-seen second
// restart stays a cold start; a fresh peer heartbeat stays alive.
func TestSecondCommsRestartInheritsColdBootGrace17764(t *testing.T) {
	m := commsManager16745(t)
	if err := m.StartHeartbeat("127.0.0.1", "127.0.0.1", "", "em0"); err != nil {
		t.Fatalf("StartHeartbeat: %v", err)
	}
	r0 := installedReceiver16745(t, m)
	// Cold receiver: no seen grace, started now — inside the 30s boot grace.
	seed := markPeerSeen16745(m, r0, 250*time.Millisecond)
	floor := r0.startedAt.Add(heartbeatStartupGrace)
	if r0.seenGrace != 0 {
		t.Fatalf("fixture: cold receiver seenGrace = %v, want 0", r0.seenGrace)
	}

	// First comms restart (~1s into the epoch, by backdating not sleeping).
	m.StopHeartbeat()
	if err := m.StartHeartbeat("127.0.0.1", "127.0.0.1", "", "em0"); err != nil {
		t.Fatalf("first restart StartHeartbeat: %v", err)
	}
	r1 := installedReceiver16745(t, m)
	if r1 == r0 {
		t.Fatal("first restart did not replace the receiver")
	}
	if got := r1.lastSeen.Load(); got != seed {
		t.Fatalf("first restart lastSeen = %d, want %d", got, seed)
	}
	if r1.seenGrace != heartbeatRestartGrace {
		t.Fatalf("first restart seenGrace = %v, want %v", r1.seenGrace, heartbeatRestartGrace)
	}
	if !r1.inheritedHold.Equal(floor) {
		t.Fatalf("first restart inheritedHold = %v, want cold-boot floor %v", r1.inheritedHold, floor)
	}
	// Simulate ~1s elapsed since the first restart without sleeping: its
	// own 5s grace end is now far before the inherited floor.
	r1.startedAt = time.Now().Add(-time.Second)

	// Second comms restart — the defect site.
	m.StopHeartbeat()
	if err := m.StartHeartbeat("127.0.0.1", "127.0.0.1", "", "em0"); err != nil {
		t.Fatalf("second restart StartHeartbeat: %v", err)
	}
	defer m.StopHeartbeat()
	r2 := installedReceiver16745(t, m)
	if r2 == r1 || r2 == r0 {
		t.Fatal("second restart did not replace the receiver")
	}
	if got := r2.lastSeen.Load(); got != seed {
		t.Fatalf("#17764: second restart lastSeen = %d, want %d", got, seed)
	}
	if r2.seenGrace != heartbeatRestartGrace {
		t.Fatalf("#17764: second restart seenGrace = %v, want %v", r2.seenGrace, heartbeatRestartGrace)
	}
	if !r2.inheritedHold.Equal(floor) {
		t.Fatalf("#17764 DEFECT: second restart inheritedHold = %v, want original cold-boot floor %v — the second comms restart dropped the inherited grace", r2.inheritedHold, floor)
	}

	// Behavioural: past the second receiver's own 5s grace but still
	// inside the inherited floor, a peer silent since the restart (stale
	// lastSeen) must NOT be declared lost.
	r2.lastSeen.Store(MonotonicNanos() - staleAge9722.Nanoseconds())
	r2.startedAt = time.Now().Add(-(heartbeatRestartGrace + 500*time.Millisecond))
	r2.checkTimeout()
	if !m.PeerAlive() {
		t.Fatal("#17764 DEFECT: peer declared lost inside the inherited cold-boot floor after the second comms restart")
	}

	// CONTROL expired floor: once the inherited floor has passed, the same
	// stale peer IS declared lost (no resurrection, no permanent hold).
	r2.inheritedHold = time.Now().Add(-time.Millisecond)
	r2.checkTimeout()
	if m.PeerAlive() {
		t.Fatal("control: stale peer still alive after the inherited floor expired")
	}
	if !m.IsLocalPrimary(1) {
		t.Fatal("control: local did not take over after the inherited floor expired and the peer went stale")
	}

	// CONTROL never-seen: two restarts of a never-seen receiver stay cold.
	m2 := commsManager16745(t)
	if err := m2.StartHeartbeat("127.0.0.1", "127.0.0.1", "", "em0"); err != nil {
		t.Fatalf("control StartHeartbeat: %v", err)
	}
	m2.StopHeartbeat()
	if err := m2.StartHeartbeat("127.0.0.1", "127.0.0.1", "", "em0"); err != nil {
		t.Fatalf("control first restart: %v", err)
	}
	m2.StopHeartbeat()
	if err := m2.StartHeartbeat("127.0.0.1", "127.0.0.1", "", "em0"); err != nil {
		t.Fatalf("control second restart: %v", err)
	}
	defer m2.StopHeartbeat()
	rn := installedReceiver16745(t, m2)
	if rn.seenGrace != 0 || rn.lastSeen.Load() != 0 || !rn.inheritedHold.IsZero() {
		t.Fatalf("control never-seen: second restart armed seenGrace=%v lastSeen=%d inheritedHold=%v, want cold start", rn.seenGrace, rn.lastSeen.Load(), rn.inheritedHold)
	}

	// CONTROL resumed peer: heard after the second restart, stays alive
	// past its own restart grace.
	m3 := commsManager16745(t)
	if err := m3.StartHeartbeat("127.0.0.1", "127.0.0.1", "", "em0"); err != nil {
		t.Fatalf("control StartHeartbeat: %v", err)
	}
	c0 := installedReceiver16745(t, m3)
	markPeerSeen16745(m3, c0, 250*time.Millisecond)
	m3.StopHeartbeat()
	if err := m3.StartHeartbeat("127.0.0.1", "127.0.0.1", "", "em0"); err != nil {
		t.Fatalf("control first restart: %v", err)
	}
	m3.StopHeartbeat()
	if err := m3.StartHeartbeat("127.0.0.1", "127.0.0.1", "", "em0"); err != nil {
		t.Fatalf("control second restart: %v", err)
	}
	defer m3.StopHeartbeat()
	c2 := installedReceiver16745(t, m3)
	c2.lastSeen.Store(MonotonicNanos())
	c2.startedAt = time.Now().Add(-(heartbeatRestartGrace + 500*time.Millisecond))
	c2.inheritedHold = time.Now().Add(-time.Millisecond)
	c2.checkTimeout()
	if !m3.PeerAlive() {
		t.Fatal("control: a peer heard after the second restart was declared lost")
	}
}

// #17764: an ordinary heartbeat restart must also carry forward the
// predecessor's inherited boot floor, even when that receiver's own 5s
// restart grace has already expired.
func TestRestartHeartbeatKeepsInheritedBootGrace17764(t *testing.T) {
	m := commsManager16745(t)
	if err := m.StartHeartbeat("127.0.0.1", "127.0.0.1", "", "em0"); err != nil {
		t.Fatalf("StartHeartbeat: %v", err)
	}
	defer m.StopHeartbeat()

	r0 := installedReceiver16745(t, m)
	seed := markPeerSeen16745(m, r0, 250*time.Millisecond)
	floor := r0.startedAt.Add(heartbeatStartupGrace)
	// Model a first replacement receiver: it has a short own grace and an
	// inherited cold-boot floor that outlives that grace.
	r0.armRestart(seed, floor)
	r0.startedAt = time.Now().Add(-(heartbeatRestartGrace + 500*time.Millisecond))

	if !m.RestartHeartbeat() {
		t.Fatal("RestartHeartbeat returned false while running")
	}
	r1 := installedReceiver16745(t, m)
	if r1 == r0 {
		t.Fatal("RestartHeartbeat did not replace the receiver")
	}
	if !r1.inheritedHold.Equal(floor) {
		t.Fatalf("#17764 DEFECT: RestartHeartbeat inheritedHold = %v, want prior inherited cold-boot floor %v", r1.inheritedHold, floor)
	}

	// Past the replacement's own restart grace but inside the inherited
	// floor, a silent peer must remain protected.
	r1.lastSeen.Store(MonotonicNanos() - staleAge9722.Nanoseconds())
	r1.startedAt = time.Now().Add(-(heartbeatRestartGrace + 500*time.Millisecond))
	r1.checkTimeout()
	if !m.PeerAlive() {
		t.Fatal("#17764 DEFECT: RestartHeartbeat declared the peer lost inside the inherited cold-boot floor")
	}
}
