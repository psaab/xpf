package daemon

import (
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/ipsec"
)

// #1792: the heartbeat-timeout suppression cap must be measured in the
// CLOCK_MONOTONIC domain. The helper takes injected timestamps, so these
// tests pin the boundary semantics that wall-clock steps used to break
// (backward step → suppression stuck on, blocking failover; forward step
// → suppression cut short).
func TestHBSuppressCapExceeded(t *testing.T) {
	const capDur = 5 * time.Second
	base := int64(2_000_000_000_000) // arbitrary monotonic reading

	cases := []struct {
		name  string
		start int64
		now   int64
		want  bool
	}{
		{"just started", base, base, false},
		{"within cap", base, base + (4 * time.Second).Nanoseconds(), false},
		{"exactly cap", base, base + capDur.Nanoseconds(), false},
		{"just past cap", base, base + capDur.Nanoseconds() + 1, true},
		// now < start cannot happen on a correct monotonic clock; the
		// equivalent wall-clock state (backward step after suppression
		// began) used to keep suppression alive for the step duration.
		// In the monotonic domain the helper simply reports not-exceeded
		// and the suppression window proceeds normally.
		{"negative elapsed tolerated", base, base - time.Second.Nanoseconds(), false},
	}
	for _, tc := range cases {
		if got := hbSuppressCapExceeded(tc.start, tc.now, capDur); got != tc.want {
			t.Errorf("%s: hbSuppressCapExceeded(%d, %d, %v) = %v, want %v",
				tc.name, tc.start, tc.now, capDur, got, tc.want)
		}
	}
}

// shouldSuppressPeerHeartbeatTimeout must reset its suppression-start
// state when session sync is unavailable, so a later suppression window
// re-arms from scratch instead of inheriting a stale cap start.
func TestShouldSuppressPeerHeartbeatTimeoutResetsWhenSyncUnavailable(t *testing.T) {
	d := &Daemon{}
	d.hbSuppressStart.Store(123)

	suppress, reason := d.shouldSuppressPeerHeartbeatTimeout()
	if suppress {
		t.Fatalf("suppress = true with nil session sync (reason %q)", reason)
	}
	if got := d.hbSuppressStart.Load(); got != 0 {
		t.Fatalf("hbSuppressStart = %d after sync-unavailable check, want reset to 0", got)
	}
}

// --- #15687: degraded constructor epochs must still launch the
// context-scoped loops and must record comms-restart debt. ---

// exhaustSyncAddressPolls15687 makes every sync-address poll and every
// SessionSync Start attempt fail instantly, so the constructor reaches
// its degraded branches without the production 30x2s waits.
func exhaustSyncAddressPolls15687(t *testing.T) {
	t.Helper()
	oldAttempts, oldDelay := syncAddressPollAttempts, syncAddressPollDelay
	oldFab1 := fab1AddressPollAttempts
	oldStartAttempts, oldStartDelay := sessionSyncStartAttempts, sessionSyncStartRetryDelay
	syncAddressPollAttempts, syncAddressPollDelay = 2, 0
	fab1AddressPollAttempts = 2
	sessionSyncStartAttempts, sessionSyncStartRetryDelay = 2, 0
	t.Cleanup(func() {
		syncAddressPollAttempts, syncAddressPollDelay = oldAttempts, oldDelay
		fab1AddressPollAttempts = oldFab1
		sessionSyncStartAttempts, sessionSyncStartRetryDelay = oldStartAttempts, oldStartDelay
	})
}

// TestStartClusterCommsLaunchesFabricForwardingWhenPrimarySyncUnaddressed
// is the #15687 acceptance regression for the primary-address leg.
//
// RED on pre-fix code: the constructor returned at `syncIP == ""`
// before startClusterSyncAuxLoops / publishFabricRefreshChansIfCurrent /
// startFabricForwardingLoops, so no refresh channels were published, no
// fabric pair was recorded, no IPsec loop (the startClusterSyncAuxLoops
// observable that requires no dataplane/session) was registered, and
// activeTransport().BindingChanged stayed false.
func TestStartClusterCommsLaunchesFabricForwardingWhenPrimarySyncUnaddressed(t *testing.T) {
	exhaustSyncAddressPolls15687(t)
	// "xpf-nonexistent-15687" never resolves, so the primary poll exhausts.
	d := newVRFBindingRetryDaemon12168(t, []string{
		"set chassis cluster cluster-id 1",
		"set chassis cluster node 0",
		"set chassis cluster authentication-key 15687-test",
		"set chassis cluster fabric-interface xpf-nonexistent-15687",
		"set chassis cluster fabric-peer-address 127.0.0.2",
		"set chassis cluster ipsec-session-synchronization",
	}, false)
	d.ipsec = ipsec.New()
	// startClusterSyncAuxLoops -> ensureIPsecSASyncLoop requires the live
	// comms context (published by beginClusterCommsEpoch) and d.ipsec;
	// the DHCP sibling stays off (no dhcpServer / no session), and the
	// configSync + persistent-NAT loops are plain commsCtx goroutines.

	d.startClusterComms(d.daemonCtx)
	waitVRFCommsConstructor12168(t, d)

	// Fabric forwarding loops started: their refresh channels were
	// published for this epoch and populateFabricFwd recorded the pair.
	ch0, ch1 := d.snapshotFabricRefreshChans()
	if ch0 == nil || ch1 == nil {
		t.Fatal("fabric refresh channels not published: startFabricForwardingLoops " +
			"was skipped when the primary sync address was unavailable (#15687)")
	}
	// populateFabricFwd runs on its own goroutine; wait for it to record
	// the fabric pair rather than racing its first instruction.
	deadline := time.Now().Add(5 * time.Second)
	var fabPeerSet bool
	for time.Now().Before(deadline) {
		d.fabricMu.RLock()
		fabPeerSet = d.fabricPeerIP != nil
		d.fabricMu.RUnlock()
		if fabPeerSet {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !fabPeerSet {
		t.Fatal("populateFabricFwd did not run: fabricPeerIP unset (#15687)")
	}
	// Aux loops started: the IPsec SA loop (the startClusterSyncAuxLoops
	// member observable without a dataplane) is registered.
	d.ipsecSASync.loopMu.Lock()
	auxStarted := d.ipsecSASync.loopCancel != nil
	d.ipsecSASync.loopMu.Unlock()
	if !auxStarted {
		t.Fatal("startClusterSyncAuxLoops was skipped when the primary sync " +
			"address was unavailable (#15687)")
	}
	// Transport debt: a later address arrival must restart comms via
	// step 20 (live key flagged vs freshly computed key unflagged).
	if !d.activeTransport().BindingChanged {
		t.Fatal("clusterTransportBindingChanged not marked: a sync address " +
			"arriving after the poll window would never restart startClusterComms (#15687)")
	}
	if got := d.getSessionSync(); got != nil {
		t.Fatalf("session sync published despite no sync address: %p", got)
	}
}

// TestStartClusterCommsRebuildsDualSessionSyncWhenFab1AddressArrivesLate
// is the #15687 acceptance regression for the fab1 leg.
//
// Epoch 1: fab0 (lo) resolves, fab1 (nonexistent) exhausts its poll, so
// the epoch builds a SINGLE SessionSync and latches
// syncPeerAddr1Disabled. The restart that the transport debt triggers
// (reconcileClusterTransportBinding, step 20's helper) must re-run the
// constructor; epoch 2 -- now with fab1 also on lo, modelling the late
// address arrival -- must publish a DUAL SessionSync and clear
// syncPeerAddr1Disabled.
//
// RED on pre-fix code: epoch 1 recorded no debt
// (activeTransport().BindingChanged stayed false), so
// reconcileClusterTransportBinding returned without restarting and the
// single-fabric SessionSync / disabled latch survived.
func TestStartClusterCommsRebuildsDualSessionSyncWhenFab1AddressArrivesLate(t *testing.T) {
	exhaustSyncAddressPolls15687(t)
	if resolveClusterInterfaceAddr("lo", "127.0.0.1", "") == "" {
		t.Skip("loopback has no usable IPv4 address")
	}
	cfgLines := func(fab1Iface string) []string {
		return []string{
			"set chassis cluster cluster-id 1",
			"set chassis cluster node 0",
			"set chassis cluster authentication-key 15687-test",
			"set chassis cluster fabric-interface lo",
			"set chassis cluster fabric-peer-address 127.0.0.2",
			"set chassis cluster fabric1-interface " + fab1Iface,
			"set chassis cluster fabric1-peer-address 127.0.0.3",
		}
	}
	d := newVRFBindingRetryDaemon12168(t, cfgLines("xpf-nonexistent-15687"), false)

	d.startClusterComms(d.daemonCtx)
	waitVRFCommsConstructor12168(t, d)

	ss1 := d.getSessionSync()
	if ss1 == nil {
		t.Fatal("epoch 1 published no session sync (fab0 on lo must start)")
	}
	if ss1.IsDualFabric() {
		t.Fatal("epoch 1 session sync is dual despite fab1 being unaddressed")
	}
	d.fabricMu.RLock()
	disabled1 := d.syncPeerAddr1Disabled
	d.fabricMu.RUnlock()
	if !disabled1 {
		t.Fatal("epoch 1 did not latch syncPeerAddr1Disabled for the missing fab1")
	}
	if !d.activeTransport().BindingChanged {
		t.Fatal("fab1 poll expiry recorded no transport debt: a late fab1 " +
			"address would never restart comms (#15687)")
	}

	// The address "arrives": the corrected config names lo for fab1.
	// Re-driving step 20's helper with the SAME daemon/store shape a
	// subsequent apply would present: swap the store's active config by
	// rebuilding the daemon's store is out of scope here, so drive the
	// restart through the helper against a fresh active config.
	d2cfg := testStoreWithSetConfig(t, cfgLines("lo"))
	d.store = d2cfg
	cfg := d.store.ActiveConfig()
	d.reconcileClusterTransportBinding(cfg, false)
	waitVRFCommsConstructor12168(t, d)

	ss2 := d.getSessionSync()
	if ss2 == nil {
		t.Fatal("epoch 2 published no session sync after the debt restart")
	}
	if ss2 == ss1 {
		t.Fatal("debt restart did not rebuild SessionSync (same object)")
	}
	if !ss2.IsDualFabric() {
		t.Fatal("epoch 2 session sync is not dual after fab1 address arrival (#15687)")
	}
	d.fabricMu.RLock()
	disabled2 := d.syncPeerAddr1Disabled
	peer1 := d.syncPeerAddr1
	d.fabricMu.RUnlock()
	if disabled2 {
		t.Fatal("syncPeerAddr1Disabled still latched after the dual rebuild (#15687)")
	}
	if peer1 != "127.0.0.3" {
		t.Fatalf("syncPeerAddr1 = %q, want 127.0.0.3 after dual rebuild", peer1)
	}
	if d.activeTransport().BindingChanged {
		t.Fatal("healthy dual epoch still carries transport debt")
	}
}
