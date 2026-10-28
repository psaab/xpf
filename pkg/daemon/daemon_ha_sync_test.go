package daemon

import (
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/ipsec"
)

// #1792/#17056: the heartbeat-timeout suppression cap tests moved with
// the policy to pkg/cluster (TestHBSuppressCapExceeded17056 and
// TestSyncSuppressesPeerTimeoutLocked17056 in
// pkg/cluster/heartbeat_guard_recheck_test.go, plus the #12165 cells).
// The daemon keeps only the wiring-level 12165 cell
// (daemon_ha_sync_12165_test.go).

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
		"set chassis cluster authentication-key 15687-test-cluster-psk",
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
// is the #15687 acceptance regression for the fab1 leg, narrowed by
// #16842: the debt no longer rides on BindingChanged (which the #11448
// reassert consumed every 30 s, churning the working epoch), so this
// test pins Fab1Debt instead and drives the late upgrade through the
// reassert tick's fab1-ready gate.
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
// single-fabric SessionSync / disabled latch survived. RED on the
// #16842 defect shape (debt on BindingChanged): the Fab1Debt assertions
// below fail and the reassert-stability cell in
// fab1_debt_churn_16842_test.go counts 5 restarts over 5 ticks.
func TestStartClusterCommsRebuildsDualSessionSyncWhenFab1AddressArrivesLate(t *testing.T) {
	exhaustSyncAddressPolls15687(t)
	if resolveClusterInterfaceAddr(nil, "lo", "127.0.0.1", "") == "" {
		t.Skip("loopback has no usable IPv4 address")
	}
	cfgLines := func(fab1Iface string) []string {
		return []string{
			"set chassis cluster cluster-id 1",
			"set chassis cluster node 0",
			"set chassis cluster authentication-key 15687-test-cluster-psk",
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
	if !d.activeTransport().Fab1Debt {
		t.Fatal("fab1 poll expiry recorded no fab1 debt: a late fab1 " +
			"address would never restart comms (#15687)")
	}
	if d.activeTransport().BindingChanged {
		t.Fatal("fab1 debt rode on BindingChanged: the #11448 reassert " +
			"would churn this working epoch every 30 s (#16842)")
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
	if d.activeTransport().BindingChanged || d.activeTransport().Fab1Debt {
		t.Fatal("healthy dual epoch still carries transport debt")
	}
}
