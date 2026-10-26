package daemon

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sync/semaphore"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/dataplane/userspace"
)

// commitConfirmedSnapshotGateDaemon10782 stages a multi-zone scoped global
// policy on an RG0 owner with config-sync enabled. The peer protocol and
// connectivity model the rolling-upgrade window guarded by #6650.
func commitConfirmedSnapshotGateDaemon10782(t *testing.T, peerVersion uint16, connected bool) (*Daemon, *configstore.Store, *int) {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "config"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	seed := func(step string) {
		t.Helper()
		if err := store.SetFromInput(step); err != nil {
			t.Fatalf("set %q: %v", step, err)
		}
	}
	for _, step := range []string{
		"system host-name OLD",
		"chassis cluster cluster-id 1",
		"chassis cluster authentication-key test-cluster-psk-10782",
		"chassis cluster control-interface em0",
		"chassis cluster peer-address 10.99.0.2",
		"interfaces em0 unit 0 family inet address 10.99.0.1/24",
		"chassis cluster node 0",
		"chassis cluster redundancy-group 0 node 0 priority 200",
		"chassis cluster redundancy-group 0 node 1 priority 100",
		"chassis cluster configuration-synchronize",
		"security zones security-zone dmz",
		"security zones security-zone trust",
		"security zones security-zone untrust",
	} {
		seed(step)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("commit baseline: %v", err)
	}
	for _, step := range []string{
		"security policies global policy multi-zone-deny match from-zone dmz",
		"security policies global policy multi-zone-deny match from-zone trust",
		"security policies global policy multi-zone-deny match to-zone untrust",
		"security policies global policy multi-zone-deny match source-address any",
		"security policies global policy multi-zone-deny match destination-address any",
		"security policies global policy multi-zone-deny match application any",
		"security policies global policy multi-zone-deny then deny",
	} {
		seed(step)
	}

	ss := cluster.NewSessionSync(":0", ":0", nil)
	ss.SetConnectedForTesting(connected)
	ss.SetPeerSnapshotProtocolVersionForTesting(peerVersion)
	d := &Daemon{
		applySem:    semaphore.NewWeighted(1),
		store:       store,
		cluster:     clusterOwningRG0(t),
		sessionSync: ss,
	}
	d.syncPeerConnected.Store(connected)
	if connected {
		d.syncPeerConnEpoch.Store(1)
	}
	d.applyBodyForTest = func(*config.Config) {}
	pushes := 0
	d.syncPeerForTest = func() { pushes++ }
	return d, store, &pushes
}

// nat64SnapshotGateDaemon16049 mirrors the 10782 harness but seeds a
// multi-RI NAT64 rule-set instead of the multi-zone global policy, so
// the #16049 v64 floor race cells exercise the same commit-confirmed
// machinery with the NAT64 shape.
func nat64SnapshotGateDaemon16049(t *testing.T, peerVersion uint16, connected bool) (*Daemon, *configstore.Store, *int) {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "config"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	seed := func(step string) {
		t.Helper()
		if err := store.SetFromInput(step); err != nil {
			t.Fatalf("set %q: %v", step, err)
		}
	}
	for _, step := range []string{
		"system host-name OLD",
		"chassis cluster cluster-id 1",
		"chassis cluster authentication-key test-cluster-psk-16049",
		"chassis cluster control-interface em0",
		"chassis cluster peer-address 10.99.0.2",
		"interfaces em0 unit 0 family inet address 10.99.0.1/24",
		"chassis cluster node 0",
		"chassis cluster redundancy-group 0 node 0 priority 200",
		"chassis cluster redundancy-group 0 node 1 priority 100",
		"chassis cluster configuration-synchronize",
		"routing-instances blue instance-type virtual-router",
		"routing-instances red instance-type virtual-router",
		"security nat source pool p64 address 100.64.0.1/32",
	} {
		seed(step)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("commit baseline: %v", err)
	}
	for _, step := range []string{
		"security nat nat64 rule-set rs1 prefix 64:ff9b::/96",
		"security nat nat64 rule-set rs1 source-pool p64",
		"security nat nat64 rule-set rs1 from routing-instance [ blue red ]",
	} {
		seed(step)
	}
	ss := cluster.NewSessionSync(":0", ":0", nil)
	ss.SetConnectedForTesting(connected)
	ss.SetPeerSnapshotProtocolVersionForTesting(peerVersion)
	d := &Daemon{
		applySem:    semaphore.NewWeighted(1),
		store:       store,
		cluster:     clusterOwningRG0(t),
		sessionSync: ss,
	}
	d.syncPeerConnected.Store(connected)
	if connected {
		d.syncPeerConnEpoch.Store(1)
	}
	d.applyBodyForTest = func(*config.Config) {}
	pushes := 0
	d.syncPeerForTest = func() { pushes++ }
	return d, store, &pushes
}

func TestCommitConfirmedUsesPeerSnapshotProtocolGate10782(t *testing.T) {
	t.Run("disconnected peer does not freeze commit", func(t *testing.T) {
		d, store, pushes := commitConfirmedSnapshotGateDaemon10782(t, 0, false)
		if _, err := d.commitConfirmedAndApply(t.Context(), configstore.InternalCommitter(), 1, peerSyncAlways); err != nil {
			t.Fatalf("commit confirmed with a disconnected peer must remain allowed: %v", err)
		}
		if got := len(store.ActiveConfig().Security.GlobalPolicies); got != 1 {
			t.Fatalf("disconnected-peer commit-confirmed promoted %d global policies; want 1", got)
		}
		if *pushes != 0 {
			t.Fatalf("commit-confirmed with a disconnected peer made %d peer-sync attempts; want none", *pushes)
		}
		if err := store.ConfirmCommitAs(""); err != nil {
			t.Fatalf("ConfirmCommitAs after offline promotion: %v", err)
		}
		if store.IsConfirmPending() {
			t.Fatal("ConfirmCommitAs did not clear the offline commit-confirmed timer")
		}
	})
	t.Run("connected pre-6650 peer refuses", func(t *testing.T) {
		d, store, pushes := commitConfirmedSnapshotGateDaemon10782(t, 0, true)
		_, err := d.commitConfirmedAndApply(t.Context(), configstore.InternalCommitter(), 1, peerSyncAlways)
		if !errors.Is(err, ErrPeerSnapshotProtocolIncompatible) {
			t.Fatalf("connected peer advertising no snapshot protocol must be refused; got %v", err)
		}
		if got := len(store.ActiveConfig().Security.GlobalPolicies); got != 0 {
			t.Fatalf("refused commit-confirmed promoted %d global policies; want none", got)
		}
		if *pushes != 0 {
			t.Fatalf("refused commit-confirmed pushed %d configs; want none", *pushes)
		}
	})
}

// FAIL-ON-REVERT: removing the reconnect protocol gate lets the pre-v4 row
// queue the offline commit and claim the per-epoch marker.

func TestOfflineCommitConfirmedDefersUntilPeerCanRepresentSnapshot10782(t *testing.T) {
	d, store, pushes := commitConfirmedSnapshotGateDaemon10782(t, 0, false)
	if _, err := d.commitConfirmedAndApply(t.Context(), configstore.InternalCommitter(), 1, peerSyncAlways); err != nil {
		t.Fatalf("offline commit-confirmed should promote locally: %v", err)
	}
	if err := store.ConfirmCommitAs(""); err != nil {
		t.Fatalf("ConfirmCommitAs after offline promotion: %v", err)
	}

	d.configSyncPushForTest = func() { *pushes++ }
	ss := d.getSessionSync()
	ss.SetPeerSnapshotProtocolVersionForTesting(3)
	ss.SetConnectedForTesting(true)
	d.syncPeerConnected.Store(true)
	d.syncPeerConnEpoch.Add(1)
	d.reconcileConfigSyncToPeer("test-reconnect-pre-v4")
	if *pushes != 0 {
		t.Fatalf("pre-v4 reconnect queued %d configs; want none", *pushes)
	}
	d.configSyncMu.Lock()
	marked := d.configSyncHasPushed
	d.configSyncMu.Unlock()
	if marked {
		t.Fatal("rejected pre-v4 reconnect claimed the config-sync push marker")
	}
	if alarm := d.peerSnapshotProtocolDeferredAlarm(); !strings.Contains(alarm, "Config sync deferred") {
		t.Fatalf("pre-v4 reconnect did not retain an operator-visible alarm: %q", alarm)
	}
	foundDeferredEvent := false
	for _, event := range d.cluster.EventHistoryFor(cluster.EventConfigSync) {
		if strings.Contains(event.Message, "Config sync deferred") {
			foundDeferredEvent = true
			break
		}
	}
	if !foundDeferredEvent {
		t.Fatal("pre-v4 reconnect did not record a Config Sync cluster event")
	}

	ss.SetPeerSnapshotProtocolVersionForTesting(userspace.MinProtocolMultiZoneScopedPolicy)
	d.syncPeerConnEpoch.Add(1)
	d.reconcileConfigSyncToPeer("test-reconnect-v4")
	if *pushes != 1 {
		t.Fatalf("v4 reconnect queued %d configs; want one", *pushes)
	}
	d.configSyncMu.Lock()
	marked = d.configSyncHasPushed &&
		d.configSyncPushedEpoch == d.syncPeerConnEpoch.Load() &&
		d.configSyncPushedGen != 0
	d.configSyncMu.Unlock()
	if !marked {
		t.Fatal("v4 reconnect did not claim the config-sync marker after queueing")
	}
	if alarm := d.peerSnapshotProtocolDeferredAlarm(); alarm != "" {
		t.Fatalf("successful v4 reconnect did not clear the deferral alarm: %q", alarm)
	}
}

// FAIL-ON-REVERT: skipping authorization revalidation lets the v4 preflight
// token push the promoted config to the pre-v4 replacement peer.

func TestCommitConfirmedPeerProtocolRevalidatedAfterApply10782(t *testing.T) {
	d, store, pushes := commitConfirmedSnapshotGateDaemon10782(t,
		userspace.MinProtocolMultiZoneScopedPolicy, true)
	ss := d.getSessionSync()
	d.applyBodyForTest = func(*config.Config) {
		// Model v4 disconnecting and a pre-v4 process reconnecting after
		// preflight but before commit-confirmed reaches the queue boundary.
		ss.SetConnectedForTesting(false)
		d.syncPeerConnected.Store(false)
		ss.SetPeerSnapshotProtocolVersionForTesting(0)
		d.syncPeerConnEpoch.Add(1)
		ss.SetPeerSnapshotProtocolVersionForTesting(3)
		ss.SetConnectedForTesting(true)
		d.syncPeerConnected.Store(true)
	}
	_, err := d.commitConfirmedAndApply(t.Context(), configstore.InternalCommitter(), 1, peerSyncAlways)
	if !errors.Is(err, ErrPeerSnapshotProtocolIncompatible) {
		t.Fatalf("preflight authorization survived a v4→pre-v4 reconnect: %v", err)
	}
	if got := len(store.ActiveConfig().Security.GlobalPolicies); got != 1 {
		t.Fatalf("commit-confirmed did not retain its local promotion after the queue deferral; policies=%d", got)
	}
	if !store.ActiveApplied() {
		t.Fatal("successful local apply lost its applied marker because the peer authorization became stale")
	}
	if *pushes != 0 {
		t.Fatalf("stale preflight authorization pushed %d configs to the new peer; want none", *pushes)
	}
	d.configSyncMu.Lock()
	marked := d.configSyncHasPushed
	d.configSyncMu.Unlock()
	if marked {
		t.Fatal("stale preflight authorization claimed the config-sync marker")
	}
	if alarm := d.peerSnapshotProtocolDeferredAlarm(); !strings.Contains(alarm, "Config sync deferred") {
		t.Fatalf("stale preflight authorization did not raise the deferral alarm: %q", alarm)
	}
	if err := store.ConfirmCommitAs(""); err != nil {
		t.Fatalf("ConfirmCommitAs after queue-boundary deferral: %v", err)
	}
}

// TestCommitConfirmedUsesPeerSnapshotProtocolGate10782 proves the second
// generation-bound commit path refuses the exact multi-zone shape a pre-v4
// connected peer narrows. The store remains unpromoted and no peer push occurs.
//
// RED-on-revert: removing peerSnapshotProtocolCommitPreflight from
// commitConfirmedAndApply makes the incompatible-peer row promote and push,
// failing its error, active-state, and push-count assertions.
func TestCommitConfirmedPeerSnapshotProtocolFloor10782(t *testing.T) {
	t.Run("connected pre-v4 peer refuses before promotion", func(t *testing.T) {
		d, store, pushes := commitConfirmedSnapshotGateDaemon10782(t, 3, true)
		_, err := d.commitConfirmedAndApply(t.Context(), configstore.InternalCommitter(), 1, peerSyncAlways)
		if !errors.Is(err, ErrPeerSnapshotProtocolIncompatible) {
			t.Fatalf("commit confirmed with a connected pre-v4 peer must be refused by #6650; got %v", err)
		}
		if got := len(store.ActiveConfig().Security.GlobalPolicies); got != 0 {
			t.Fatalf("refused commit-confirmed promoted %d global policies; want none", got)
		}
		if store.IsConfirmPending() {
			t.Fatal("refused commit-confirmed armed a rollback timer")
		}
		if *pushes != 0 {
			t.Fatalf("refused commit-confirmed pushed %d configs to the peer; want none", *pushes)
		}
	})

	t.Run("connected capable peer remains allowed", func(t *testing.T) {
		d, store, pushes := commitConfirmedSnapshotGateDaemon10782(t,
			userspace.MinProtocolMultiZoneScopedPolicy, true)
		_, err := d.commitConfirmedAndApply(t.Context(), configstore.InternalCommitter(), 1, peerSyncAlways)
		if err != nil {
			t.Fatalf("commit confirmed with a peer at the feature floor must succeed: %v", err)
		}
		if got := len(store.ActiveConfig().Security.GlobalPolicies); got != 1 {
			t.Fatalf("capable peer commit-confirmed promoted %d global policies; want 1", got)
		}
		if *pushes != 1 {
			t.Fatalf("successful commit-confirmed pushed %d configs to the peer; want 1", *pushes)
		}
		if err := store.ConfirmCommit(); err != nil {
			t.Fatalf("clear test confirm timer: %v", err)
		}
	})

}

// #16049 NAT64-specific race cells (mirrors of the 10782 multi-zone
// cells, with the NAT64 multi-RI shape and the v64 floor):
//
//  1. Connected v63 peer refuses at commit preflight before promotion.
//  2. Peer downgrades v64 -> v63 BETWEEN preflight and queue write:
//     authorization revalidation withholds the push, retains the
//     deferral alarm, and does not claim the push marker.
func TestCommitConfirmedNAT64PeerSnapshotProtocolFloor16049(t *testing.T) {
	t.Run("connected v63 peer refuses before promotion", func(t *testing.T) {
		d, store, pushes := nat64SnapshotGateDaemon16049(t, 63, true)
		_, err := d.commitConfirmedAndApply(t.Context(), configstore.InternalCommitter(), 1, peerSyncAlways)
		if !errors.Is(err, ErrPeerSnapshotProtocolIncompatible) {
			t.Fatalf("commit confirmed with a connected v63 peer must be refused by #16049; got %v", err)
		}
		if got := len(store.ActiveConfig().Security.NAT.NAT64); got != 0 {
			t.Fatalf("refused commit-confirmed promoted %d NAT64 rule-sets; want none", got)
		}
		if store.IsConfirmPending() {
			t.Fatal("refused commit-confirmed armed a rollback timer")
		}
		if *pushes != 0 {
			t.Fatalf("refused commit-confirmed pushed %d configs to the peer; want none", *pushes)
		}
	})

	t.Run("connected v64 peer remains allowed", func(t *testing.T) {
		d, store, pushes := nat64SnapshotGateDaemon16049(t,
			uint16(userspace.MinProtocolNAT64RoutingInstanceList), true)
		_, err := d.commitConfirmedAndApply(t.Context(), configstore.InternalCommitter(), 1, peerSyncAlways)
		if err != nil {
			t.Fatalf("commit confirmed with a v64 peer must succeed: %v", err)
		}
		if got := len(store.ActiveConfig().Security.NAT.NAT64); got != 1 {
			t.Fatalf("capable peer commit-confirmed promoted %d NAT64 rule-sets; want 1", got)
		}
		if *pushes != 1 {
			t.Fatalf("successful commit-confirmed pushed %d configs to the peer; want 1", *pushes)
		}
		if err := store.ConfirmCommit(); err != nil {
			t.Fatalf("clear test confirm timer: %v", err)
		}
	})

	t.Run("v64 to v63 downgrade between preflight and queue withholds", func(t *testing.T) {
		d, store, pushes := nat64SnapshotGateDaemon16049(t,
			uint16(userspace.MinProtocolNAT64RoutingInstanceList), true)
		ss := d.getSessionSync()
		d.applyBodyForTest = func(*config.Config) {
			// Model v64 disconnecting and a v63 process reconnecting
			// after preflight but before the queue boundary.
			ss.SetConnectedForTesting(false)
			d.syncPeerConnected.Store(false)
			ss.SetPeerSnapshotProtocolVersionForTesting(0)
			d.syncPeerConnEpoch.Add(1)
			ss.SetPeerSnapshotProtocolVersionForTesting(63)
			ss.SetConnectedForTesting(true)
			d.syncPeerConnected.Store(true)
		}
		_, err := d.commitConfirmedAndApply(t.Context(), configstore.InternalCommitter(), 1, peerSyncAlways)
		if !errors.Is(err, ErrPeerSnapshotProtocolIncompatible) {
			t.Fatalf("preflight authorization survived a v64->v63 reconnect: %v", err)
		}
		if got := len(store.ActiveConfig().Security.NAT.NAT64); got != 1 {
			t.Fatalf("commit-confirmed did not retain its local promotion after the queue deferral; NAT64=%d", got)
		}
		if *pushes != 0 {
			t.Fatalf("stale preflight authorization pushed %d configs to the v63 peer; want none", *pushes)
		}
		d.configSyncMu.Lock()
		marked := d.configSyncHasPushed
		d.configSyncMu.Unlock()
		if marked {
			t.Fatal("stale preflight authorization claimed the config-sync marker")
		}
		if alarm := d.peerSnapshotProtocolDeferredAlarm(); !strings.Contains(alarm, "Config sync deferred") {
			t.Fatalf("stale preflight authorization did not raise the deferral alarm: %q", alarm)
		}
		if err := store.ConfirmCommitAs(""); err != nil {
			t.Fatalf("ConfirmCommitAs after queue-boundary deferral: %v", err)
		}
	})
}
