package cluster

import (
	"crypto/rand"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

const (
	beaconTestCluster = 42
	beaconTestNode    = 1
	beaconTestPSK     = "a-test-control-link-psk-10745"
	beaconTestPSKAlt  = "a-rotated-control-link-psk-10745"
)

func keyedBeaconManager(t *testing.T, signing, additional string) *Manager {
	t.Helper()
	m := NewManager(beaconTestNode, beaconTestCluster)
	m.UpdateConfig(&config.ClusterConfig{
		ControlLinkAuthKey:    config.Secret(signing),
		ControlLinkAuthKeyAlt: config.Secret(additional),
	})
	if len(m.controlLinkAcceptedKeys()) == 0 {
		t.Fatal("fixture broken: keyed manager accepted no keys")
	}
	return m
}

func beaconTestInstance(t *testing.T) [16]byte {
	t.Helper()
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		t.Fatalf("instance id: %v", err)
	}
	return id
}

func beaconManagerWarned(m *Manager) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return !m.lastDupNodeIDWarn.IsZero()
}

func beaconHistoryCount(m *Manager, substr string) int {
	n := 0
	for _, ev := range m.history.Events(EventRG) {
		if strings.Contains(ev.Message, substr) {
			n++
		}
	}
	return n
}

// TestDuplicateIdentityBeaconWarnsOnlyAfterAuth_10745 is the core #10745 cell:
// a live duplicate peer's signed beacon warns, while every unauthenticated or
// mismatched shape stays silent. The peer must remain absent throughout — the
// beacon is a warning, never liveness.
func TestDuplicateIdentityBeaconWarnsOnlyAfterAuth_10745(t *testing.T) {
	foreign := beaconTestInstance(t)
	now := time.Now()

	sign := func(t *testing.T, cluster, node int, key string, instance [16]byte, at time.Time) []byte {
		t.Helper()
		frame, err := marshalDuplicateIdentityBeacon(cluster, node, []byte(key), instance, at)
		if err != nil {
			t.Fatalf("sign: %v", err)
		}
		return frame
	}

	t.Run("signed_duplicate_warns_without_touching_peer_state", func(t *testing.T) {
		mgr := keyedBeaconManager(t, beaconTestPSK, "")
		w := newDuplicateIdentityWatcher(mgr, "em0", nil, nil, nil, time.Second, beaconTestInstance(t))
		w.handleBeacon(sign(t, beaconTestCluster, beaconTestNode, beaconTestPSK, foreign, now), now)
		if !beaconManagerWarned(mgr) {
			t.Fatal("a signed same-cluster/same-node beacon from a foreign sender did not warn")
		}
		mgr.mu.RLock()
		peerAlive, peerSeen := mgr.peerAlive, mgr.peerEverSeen
		peerNodeID := mgr.peerNodeID
		mgr.mu.RUnlock()
		if peerAlive || peerSeen || peerNodeID != 0 {
			t.Fatalf("beacon moved peer state: alive=%v everSeen=%v nodeID=%d — it must only warn",
				peerAlive, peerSeen, peerNodeID)
		}
		if got := beaconHistoryCount(mgr, "authenticated control-link beacon"); got != 1 {
			t.Fatalf("history entries = %d, want 1", got)
		}
	})

	t.Run("forged_unsigned_and_mismatched_shapes_stay_silent", func(t *testing.T) {
		mgr := keyedBeaconManager(t, beaconTestPSK, "")
		w := newDuplicateIdentityWatcher(mgr, "em0", nil, nil, nil, time.Second, beaconTestInstance(t))
		valid := sign(t, beaconTestCluster, beaconTestNode, beaconTestPSK, foreign, now)

		tampered := append([]byte(nil), valid...)
		tampered[10] ^= 0xff // node-id byte: breaks the MAC, not just the value

		cases := map[string][]byte{
			"wrong_psk":      sign(t, beaconTestCluster, beaconTestNode, "another-psk-entirely", foreign, now),
			"tampered":       tampered,
			"stale":          sign(t, beaconTestCluster, beaconTestNode, beaconTestPSK, foreign, now.Add(-time.Minute)),
			"far_future":     sign(t, beaconTestCluster, beaconTestNode, beaconTestPSK, foreign, now.Add(time.Hour)),
			"other_node":     sign(t, beaconTestCluster, beaconTestNode+1, beaconTestPSK, foreign, now),
			"other_cluster":  sign(t, beaconTestCluster+1, beaconTestNode, beaconTestPSK, foreign, now),
			"truncated":      valid[:duplicateIdentityBeaconLen-1],
			"garbage":        []byte("not a beacon at all, just udp payload"),
			"empty":          nil,
			"unsigned_shape": append([]byte(nil), valid[:51]...), // header+ids+nonce, MAC stripped
		}
		for name, frame := range cases {
			w.handleBeacon(frame, now)
			if beaconManagerWarned(mgr) {
				t.Fatalf("%s produced the duplicate warning without a valid fresh MAC", name)
			}
		}
		if got := beaconHistoryCount(mgr, "duplicate node-id"); got != 0 {
			t.Fatalf("history entries = %d, want 0 after all-silent shapes", got)
		}
	})

	t.Run("own_broadcast_loopback_does_not_warn", func(t *testing.T) {
		mgr := keyedBeaconManager(t, beaconTestPSK, "")
		self := beaconTestInstance(t)
		w := newDuplicateIdentityWatcher(mgr, "em0", nil, nil, nil, time.Second, self)
		// Linux delivers our own broadcast back to the wildcard listener; the
		// frame is VALID (we signed it) and must still not warn.
		w.handleBeacon(sign(t, beaconTestCluster, beaconTestNode, beaconTestPSK, self, now), now)
		if beaconManagerWarned(mgr) {
			t.Fatal("the watcher's own looped-back beacon warned as a duplicate — " +
				"every keyed heartbeat would self-report")
		}
	})

	t.Run("rotation_key_beacon_still_warns", func(t *testing.T) {
		mgr := keyedBeaconManager(t, beaconTestPSK, beaconTestPSKAlt)
		w := newDuplicateIdentityWatcher(mgr, "em0", nil, nil, nil, time.Second, beaconTestInstance(t))
		w.handleBeacon(sign(t, beaconTestCluster, beaconTestNode, beaconTestPSKAlt, foreign, now), now)
		if !beaconManagerWarned(mgr) {
			t.Fatal("a beacon signed with the accepted rotation key did not warn — " +
				"verifying against the signing key only reopens the #6630 outage window for this detector")
		}
	})

	t.Run("exact_replay_warns_once", func(t *testing.T) {
		mgr := keyedBeaconManager(t, beaconTestPSK, "")
		w := newDuplicateIdentityWatcher(mgr, "em0", nil, nil, nil, time.Second, beaconTestInstance(t))
		frame := sign(t, beaconTestCluster, beaconTestNode, beaconTestPSK, foreign, now)
		w.handleBeacon(frame, now)
		if !beaconManagerWarned(mgr) {
			t.Fatal("first delivery did not warn")
		}
		// Re-arm the limiter so a second warning COULD fire; the nonce cache
		// must still suppress this exact packet.
		mgr.mu.Lock()
		mgr.lastDupNodeIDWarn = time.Time{}
		mgr.mu.Unlock()
		w.handleBeacon(frame, now.Add(time.Second))
		if got := beaconHistoryCount(mgr, "authenticated control-link beacon"); got != 1 {
			t.Fatalf("replayed packet produced %d history entries, want 1 — the nonce cache is not suppressing replays", got)
		}
	})
}

// TestDuplicateIdentityBeaconSharesWarningBudget_10745 pins that the beacon and
// the heartbeat join point share one 30s duplicate-node-id budget: one
// misconfiguration, one warning stream.
func TestDuplicateIdentityBeaconSharesWarningBudget_10745(t *testing.T) {
	mgr := keyedBeaconManager(t, beaconTestPSK, "")
	mgr.NoteDuplicateNodeIDHeartbeat()
	mgr.NoteDuplicateNodeIDBeacon("em0")
	if got := beaconHistoryCount(mgr, "duplicate node-id"); got != 1 {
		t.Fatalf("history entries = %d after heartbeat+beacon warnings, want 1 (shared limiter)", got)
	}

	fresh := keyedBeaconManager(t, beaconTestPSK, "")
	fresh.NoteDuplicateNodeIDBeacon("em0")
	fresh.NoteDuplicateNodeIDHeartbeat()
	if got := beaconHistoryCount(fresh, "duplicate node-id"); got != 1 {
		t.Fatalf("history entries = %d after beacon+heartbeat warnings, want 1 (shared limiter)", got)
	}
}

// TestDuplicateIdentityBroadcastAddr_10745 pins the broadcast derivation,
// including the shapes that must skip the detector.
func TestDuplicateIdentityBroadcastAddr_10745(t *testing.T) {
	got, err := duplicateIdentityBroadcastAddr("lo", net.ParseIP("127.0.0.1"))
	if err != nil {
		t.Fatalf("lo/127.0.0.1: %v", err)
	}
	if want := "127.255.255.255:4786"; got.String() != want {
		t.Fatalf("broadcast = %s, want %s", got, want)
	}
	for name, tc := range map[string]struct {
		iface string
		ip    string
	}{
		"unknown_interface": {"xpf-no-such-iface-10745", "127.0.0.1"},
		"ipv6":              {"lo", "::1"},
		"unparsable":        {"lo", "not-an-ip"},
		"not_on_iface":      {"lo", "192.0.2.1"},
	} {
		if _, err := duplicateIdentityBroadcastAddr(tc.iface, net.ParseIP(tc.ip)); err == nil {
			t.Fatalf("%s: expected an error, got a broadcast address", name)
		}
	}
}

// TestDuplicateIdentityWatcherLiveSockets_10745 runs the real send/receive
// loops over loopback: the watcher's own beacons (delivered back to its
// listener) must not warn, while a second instance's signed beacon — the
// duplicate peer — must warn through the live readLoop. This proves the
// socket read/auth/self-exclusion path with frames that actually cross a
// socket; subnet-broadcast delivery itself is NOT covered here (README
// wire-proof gap) — unicast-to-self stands in for the broadcast address.
func TestDuplicateIdentityWatcherLiveSockets_10745(t *testing.T) {
	mgr := keyedBeaconManager(t, beaconTestPSK, "")
	listen, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listener: %v", err)
	}
	send, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		listen.Close()
		t.Fatalf("sender: %v", err)
	}
	// Unicast-to-self stands in for the subnet broadcast address so the test
	// does not depend on the host forwarding 127/8 broadcasts. That substitution
	// is exactly why this test cannot prove L2 broadcast delivery (see README).
	w := newDuplicateIdentityWatcher(mgr, "lo", listen, send,
		listen.LocalAddr().(*net.UDPAddr), 10*time.Millisecond, mgr.beaconSenderID())
	w.start()
	t.Cleanup(w.stop)

	// Phase 1: our own beacons arrive continuously and must stay silent.
	time.Sleep(150 * time.Millisecond)
	if beaconManagerWarned(mgr) {
		t.Fatal("live watcher warned on its own beacons within 150ms — self-exclusion is broken")
	}

	// Phase 2: a second instance with the same identity warns through the
	// live readLoop.
	peer, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("peer socket: %v", err)
	}
	t.Cleanup(func() { peer.Close() })
	frame, err := marshalDuplicateIdentityBeacon(beaconTestCluster, beaconTestNode,
		[]byte(beaconTestPSK), beaconTestInstance(t), time.Now())
	if err != nil {
		t.Fatalf("sign peer beacon: %v", err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for !beaconManagerWarned(mgr) && time.Now().Before(deadline) {
		if _, err := peer.WriteToUDP(frame, listen.LocalAddr().(*net.UDPAddr)); err != nil {
			t.Fatalf("send peer beacon: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
		// Fresh timestamp each attempt so the frame never ages out mid-loop.
		frame, err = marshalDuplicateIdentityBeacon(beaconTestCluster, beaconTestNode,
			[]byte(beaconTestPSK), beaconTestInstance(t), time.Now())
		if err != nil {
			t.Fatalf("re-sign peer beacon: %v", err)
		}
	}
	if !beaconManagerWarned(mgr) {
		t.Fatal("live watcher did not warn for a duplicate peer's signed beacon within 5s")
	}
	mgr.mu.RLock()
	peerAlive, peerSeen := mgr.peerAlive, mgr.peerEverSeen
	mgr.mu.RUnlock()
	if peerAlive || peerSeen {
		t.Fatalf("live beacon moved peer state: alive=%v everSeen=%v", peerAlive, peerSeen)
	}
}

// TestPrepareDuplicateIdentityWatcherIsBestEffort_10745 pins the skip matrix:
// anything the detector cannot use must yield a nil watcher, never an error,
// so heartbeat startup cannot fail because of it.
func TestPrepareDuplicateIdentityWatcherIsBestEffort_10745(t *testing.T) {
	if w := prepareDuplicateIdentityWatcher(nil, "lo", "127.0.0.1", "", time.Second); w != nil {
		w.stop()
		t.Fatal("nil manager produced a watcher")
	}
	unkeyed := NewManager(beaconTestNode, beaconTestCluster)
	if w := prepareDuplicateIdentityWatcher(unkeyed, "lo", "127.0.0.1", "", time.Second); w != nil {
		w.stop()
		t.Fatal("unkeyed manager produced a watcher — beacons cannot authenticate without the PSK")
	}
	keyed := keyedBeaconManager(t, beaconTestPSK, "")
	if w := prepareDuplicateIdentityWatcher(keyed, "", "127.0.0.1", "", time.Second); w != nil {
		w.stop()
		t.Fatal("empty interface produced a watcher")
	}
	if w := prepareDuplicateIdentityWatcher(keyed, "xpf-no-such-iface-10745", "127.0.0.1", "", time.Second); w != nil {
		w.stop()
		t.Fatal("unknown interface produced a watcher")
	}
	if w := prepareDuplicateIdentityWatcher(keyed, "lo", "::1", "", time.Second); w != nil {
		w.stop()
		t.Fatal("IPv6 control link produced an ARP-era IPv4 broadcast watcher")
	}
}

// TestHeartbeatTenureOwnsDuplicateIdentityWatcher_10745 pins the wiring: a
// keyed heartbeat owns a beacon watcher for exactly its tenure, and an
// unkeyed heartbeat starts fine without one. Deleting the startHeartbeat
// hookup reds the first half; making preparation fatal reds the second.
func TestHeartbeatTenureOwnsDuplicateIdentityWatcher_10745(t *testing.T) {
	keyed := keyedBeaconManager(t, beaconTestPSK, "")
	if err := keyed.StartHeartbeat("127.0.0.1", "127.0.0.1", "", "lo"); err != nil {
		t.Fatalf("keyed StartHeartbeat: %v", err)
	}
	keyed.mu.RLock()
	watcher := keyed.duplicateIdentityWatcher
	keyed.mu.RUnlock()
	if watcher == nil {
		keyed.StopHeartbeat()
		t.Fatal("keyed heartbeat owns no identity watcher — the #10745 hookup is missing")
	}
	keyed.StopHeartbeat()
	keyed.mu.RLock()
	still := keyed.duplicateIdentityWatcher
	keyed.mu.RUnlock()
	if still != nil {
		t.Fatal("StopHeartbeat left the identity watcher installed")
	}

	unkeyed := NewManager(beaconTestNode, beaconTestCluster)
	if err := unkeyed.StartHeartbeat("127.0.0.1", "127.0.0.1", "", "lo"); err != nil {
		t.Fatalf("unkeyed StartHeartbeat: %v", err)
	}
	t.Cleanup(unkeyed.StopHeartbeat)
	unkeyed.mu.RLock()
	bare := unkeyed.duplicateIdentityWatcher
	unkeyed.mu.RUnlock()
	if bare != nil {
		t.Fatal("unkeyed heartbeat installed an identity watcher it cannot authenticate")
	}
}

// TestDuplicateIdentityReplayDoesNotSurviveWatcherReplacement_10745 is the
// cross-tenure regression (review M1): replay memory lives on the Manager, so
// a captured still-fresh beacon replayed after a heartbeat restart cannot
// warn without the PSK. A per-watcher cache reds the replay half.
func TestDuplicateIdentityReplayDoesNotSurviveWatcherReplacement_10745(t *testing.T) {
	mgr := keyedBeaconManager(t, beaconTestPSK, "")
	now := time.Now()
	foreign := beaconTestInstance(t)
	if foreign == mgr.beaconSenderID() {
		t.Fatal("fixture collision: foreign instance equals the manager's stable ID")
	}
	frame, err := marshalDuplicateIdentityBeacon(beaconTestCluster, beaconTestNode,
		[]byte(beaconTestPSK), foreign, now)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	// Production shape: every watcher carries the manager's stable sender ID.
	first := newDuplicateIdentityWatcher(mgr, "em0", nil, nil, nil, time.Second, mgr.beaconSenderID())
	first.handleBeacon(frame, now)
	if got := beaconHistoryCount(mgr, "authenticated control-link beacon"); got != 1 {
		t.Fatalf("first-tenure delivery produced %d warnings, want 1", got)
	}

	// Simulate a heartbeat restart: same manager, key and stable sender ID;
	// only the watcher (and, under the old design, its cache) is replaced.
	second := newDuplicateIdentityWatcher(mgr, "em0", nil, nil, nil, time.Second, mgr.beaconSenderID())
	second.handleBeacon(frame, now.Add(time.Second))
	if got := beaconHistoryCount(mgr, "authenticated control-link beacon"); got != 1 {
		t.Fatalf("replay into the replacement watcher produced %d warnings, want 1 — "+
			"replay memory did not survive the restart", got)
	}

	// Positive control: a live duplicate in the current tenure still warns.
	mgr.mu.Lock()
	mgr.lastDupNodeIDWarn = time.Time{}
	mgr.mu.Unlock()
	live, err := marshalDuplicateIdentityBeacon(beaconTestCluster, beaconTestNode,
		[]byte(beaconTestPSK), beaconTestInstance(t), now.Add(time.Second))
	if err != nil {
		t.Fatalf("sign live beacon: %v", err)
	}
	second.handleBeacon(live, now.Add(time.Second))
	if got := beaconHistoryCount(mgr, "authenticated control-link beacon"); got != 2 {
		t.Fatalf("live duplicate in the current tenure produced %d warnings, want 2", got)
	}
}

// TestDuplicateIdentityReplayCacheIsBounded_10745 pins the BEACON-01 fix: a
// deterministic burst of unique correctly-signed matching beacons cannot grow
// the cache past its cap, and entries expire without any further traffic.
func TestDuplicateIdentityReplayCacheIsBounded_10745(t *testing.T) {
	mgr := keyedBeaconManager(t, beaconTestPSK, "")
	w := newDuplicateIdentityWatcher(mgr, "em0", nil, nil, nil, time.Second, beaconTestInstance(t))
	now := time.Now()
	foreign := beaconTestInstance(t)
	const burst = duplicateIdentityReplayCap + 1000
	for i := range burst {
		frame, err := marshalDuplicateIdentityBeacon(beaconTestCluster, beaconTestNode,
			[]byte(beaconTestPSK), foreign, now)
		if err != nil {
			t.Fatalf("sign beacon %d: %v", i, err)
		}
		w.handleBeacon(frame, now)
	}
	if got := mgr.beaconReplay.len(); got > duplicateIdentityReplayCap {
		t.Fatalf("cache holds %d entries after a %d-burst, want at most %d",
			got, burst, duplicateIdentityReplayCap)
	}
	// Traffic-independent expiry: sweep with no further packets reclaims all.
	mgr.beaconReplay.sweep(now.Add(10 * time.Minute))
	if got := mgr.beaconReplay.len(); got != 0 {
		t.Fatalf("cache holds %d entries after an idle sweep, want 0", got)
	}
}

// TestDuplicateIdentitySkewedFutureNonceOutlivesReceipt_10745 pins the
// BEACON-02 fix: a beacon stamped near the +30s future edge stays replayable
// by timestamp long after receipt+30s, so its nonce must suppress replays
// until the stamp itself expires — not until receipt+30s.
func TestDuplicateIdentitySkewedFutureNonceOutlivesReceipt_10745(t *testing.T) {
	mgr := keyedBeaconManager(t, beaconTestPSK, "")
	w := newDuplicateIdentityWatcher(mgr, "em0", nil, nil, nil, time.Second, beaconTestInstance(t))
	now := time.Now()
	frame, err := marshalDuplicateIdentityBeacon(beaconTestCluster, beaconTestNode,
		[]byte(beaconTestPSK), beaconTestInstance(t), now.Add(29*time.Second))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	w.handleBeacon(frame, now)
	if got := beaconHistoryCount(mgr, "authenticated control-link beacon"); got != 1 {
		t.Fatalf("first delivery produced %d warnings, want 1", got)
	}
	// Past receipt+30s, the stamp is still fresh (delta ~2s) — the exact
	// packet must still be recognised as a replay, not a new duplicate.
	mgr.mu.Lock()
	mgr.lastDupNodeIDWarn = time.Time{}
	mgr.mu.Unlock()
	w.handleBeacon(frame, now.Add(31*time.Second))
	if got := beaconHistoryCount(mgr, "authenticated control-link beacon"); got != 1 {
		t.Fatalf("replay of a still-fresh skewed beacon produced %d warnings, want 1", got)
	}
}

// TestDuplicateIdentityReadStepSurvivesTransientErrors_10745 pins the
// readLoop error policy (review Host P2): it is heartbeatReceiver.readLoop's,
// exactly — transient errors continue, only a closed stopCh ends the loop.
func TestDuplicateIdentityReadStepSurvivesTransientErrors_10745(t *testing.T) {
	mgr := keyedBeaconManager(t, beaconTestPSK, "")

	t.Run("closed_socket_stays_alive", func(t *testing.T) {
		conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatalf("socket: %v", err)
		}
		w := newDuplicateIdentityWatcher(mgr, "lo", conn, nil, nil, 5*time.Millisecond, beaconTestInstance(t))
		conn.Close() // every read now fails non-timeout, stopCh still open
		if _, alive := w.readStep(make([]byte, duplicateIdentityBeaconReadLen)); !alive {
			t.Fatal("a transient read error ended the loop — day-0 detection dies silently for the tenure")
		}
	})

	t.Run("closed_stopCh_ends_loop", func(t *testing.T) {
		conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatalf("socket: %v", err)
		}
		defer conn.Close()
		w := newDuplicateIdentityWatcher(mgr, "lo", conn, nil, nil, 5*time.Millisecond, beaconTestInstance(t))
		close(w.stopCh)
		if _, alive := w.readStep(make([]byte, duplicateIdentityBeaconReadLen)); alive {
			t.Fatal("a stopped watcher stayed alive")
		}
	})

	t.Run("timeout_stays_alive", func(t *testing.T) {
		conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatalf("socket: %v", err)
		}
		defer conn.Close()
		w := newDuplicateIdentityWatcher(mgr, "lo", conn, nil, nil, 5*time.Millisecond, beaconTestInstance(t))
		n, alive := w.readStep(make([]byte, duplicateIdentityBeaconReadLen))
		if !alive || n != 0 {
			t.Fatalf("timeout read returned n=%d alive=%v, want n=0 alive=true", n, alive)
		}
	})
}

// TestDuplicateIdentityFreshnessBoundaries_10745 pins the ±30s wall-clock
// window edges (review NV2): the documented time-sync prerequisite is that
// nodes hold wall-clock within 30s of each other, and acceptance matches it
// exactly on both sides.
func TestDuplicateIdentityFreshnessBoundaries_10745(t *testing.T) {
	mgr := keyedBeaconManager(t, beaconTestPSK, "")
	now := time.Now()
	instance := beaconTestInstance(t)
	signAt := func(t *testing.T, at time.Time) []byte {
		t.Helper()
		frame, err := marshalDuplicateIdentityBeacon(beaconTestCluster, beaconTestNode,
			[]byte(beaconTestPSK), instance, at)
		if err != nil {
			t.Fatalf("sign: %v", err)
		}
		return frame
	}
	accept := []time.Time{
		now.Add(-duplicateIdentityBeaconMaxAge),
		now.Add(-duplicateIdentityBeaconMaxAge + time.Second),
		now,
		now.Add(duplicateIdentityBeaconMaxAge - time.Second),
		now.Add(duplicateIdentityBeaconMaxAge),
	}
	for _, at := range accept {
		if _, _, _, _, _, ok := verifyDuplicateIdentityBeacon(signAt(t, at), mgr, now); !ok {
			t.Fatalf("beacon stamped %v from now was rejected, want accepted", at.Sub(now))
		}
	}
	reject := []time.Time{
		now.Add(-duplicateIdentityBeaconMaxAge - time.Nanosecond),
		now.Add(-2 * duplicateIdentityBeaconMaxAge),
		now.Add(duplicateIdentityBeaconMaxAge + time.Nanosecond),
		now.Add(2 * duplicateIdentityBeaconMaxAge),
	}
	for _, at := range reject {
		if _, _, _, _, _, ok := verifyDuplicateIdentityBeacon(signAt(t, at), mgr, now); ok {
			t.Fatalf("beacon stamped %v from now was accepted, want rejected", at.Sub(now))
		}
	}
}

// TestDuplicateIdentityOwnBeaconSurvivesWatcherReplacement_10745 pins the
// stable sender ID: a beacon this node signed but never received (sent just
// before a heartbeat restart) must still read as self in the replacement
// watcher — never as a foreign duplicate. A per-watcher random ID reds this:
// the replacement carries a fresh ID and the old own-beacon looks foreign.
func TestDuplicateIdentityOwnBeaconSurvivesWatcherReplacement_10745(t *testing.T) {
	mgr := keyedBeaconManager(t, beaconTestPSK, "")
	now := time.Now()
	own := mgr.beaconSenderID()
	if mgr.beaconSenderID() != own {
		t.Fatal("manager sender ID is not stable across calls")
	}
	// Signed with our own ID but NEVER delivered to the first watcher: the
	// send-then-restart-before-loopback shape.
	frame, err := marshalDuplicateIdentityBeacon(beaconTestCluster, beaconTestNode,
		[]byte(beaconTestPSK), own, now)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	replacement := newDuplicateIdentityWatcher(mgr, "em0", nil, nil, nil, time.Second, mgr.beaconSenderID())
	replacement.handleBeacon(frame, now.Add(time.Second))
	if beaconManagerWarned(mgr) {
		t.Fatal("the replacement watcher warned on this node's own in-flight beacon")
	}
	if got := mgr.beaconReplay.len(); got != 0 {
		t.Fatalf("own beacon recorded %d replay entries, want 0 (self is excluded before the cache)", got)
	}
}

// TestPrepareAssignsStableSenderID_10745 pins that production preparation
// hands every watcher the manager's stable ID rather than minting per-watcher
// randoms.
func TestPrepareAssignsStableSenderID_10745(t *testing.T) {
	mgr := keyedBeaconManager(t, beaconTestPSK, "")
	first := prepareDuplicateIdentityWatcher(mgr, "lo", "127.0.0.1", "", time.Second)
	if first == nil {
		t.Skip("lo/127.0.0.1 cannot prepare a watcher in this environment")
	}
	t.Cleanup(first.stop)
	second := prepareDuplicateIdentityWatcher(mgr, "lo", "127.0.0.1", "", time.Second)
	if second == nil {
		t.Fatal("second preparation failed while the first succeeded")
	}
	t.Cleanup(second.stop)
	if first.instance != mgr.beaconSenderID() || second.instance != mgr.beaconSenderID() {
		t.Fatal("prepared watchers do not carry the manager's stable sender ID")
	}
}
