package daemon

import (
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
)

// The #6428 decomposition moved every session-sync wiring assignment out of
// startClusterComms and into focused builders. Measured at that point, the
// wiring was entirely UNBOUND: `go tool cover -func` reported 0.0% statement
// coverage for all ten builders that live inside the sync-constructor
// goroutine, and nilling all 30 wiring assignments at once left
// ./pkg/daemon/ and ./pkg/cluster/ fully green. The existing tests that call
// startClusterComms deliberately configure it to early-return before the
// constructor goroutine (no committed cluster config / no control+fabric
// endpoints), so no test reached the wiring at all.
//
// That is the failure mode where a test binds a FUNCTION when the property is
// the WIRING: every callback body below is reachable through its own unit
// test, but nothing asserted that startClusterComms actually INSTALLS them.
// Deleting an installation was silently green.
//
// These tests bind the wiring itself. They assert only that each builder
// installs each handle — never what the handle does — so they stay valid when
// a callback's behaviour changes, and they red the moment an installation is
// dropped. One subtest per field, so a red NAMES the dropped assignment
// instead of failing a single compound assertion.
//
// Not covered here: the ten d.cluster.Set*() hooks installed by
// wireClusterPeerFailoverHooks and wireClusterFenceCallbacks. cluster.Manager
// exposes no getter for any of them, so binding those needs an observation
// seam in pkg/cluster — out of scope for a pure-code-motion change, and
// recorded in the PR body as still-unbound.

func newWiringTestDaemon() *Daemon {
	return &Daemon{
		cluster:                    newClusterManager(true),
		localFailoverCommitTimeout: 2 * time.Second,
	}
}

func newWiringTestSessionSync() *cluster.SessionSync {
	return cluster.NewSessionSync("127.0.0.1:4785", "127.0.0.1:4785", nil)
}

func TestWireSessionSyncConfigCallbacksInstallsHandles_6428(t *testing.T) {
	d := newWiringTestDaemon()
	ss := newWiringTestSessionSync()
	d.wireSessionSyncConfigCallbacks(ss)

	// NOTE: compare each func field to nil DIRECTLY. Collecting them into a
	// table of `any` boxes a typed nil func into a non-nil interface, so
	// `got == nil` is false even for an uninstalled handle — the first draft of
	// this test did exactly that and 14 of its 17 unwire mutations stayed
	// green. The mutation matrix is what caught it.
	if ss.OnConfigReceived == nil {
		t.Error("wireSessionSyncConfigCallbacks did not install ss.OnConfigReceived")
	}
	if ss.OnConfigApplyHealth == nil {
		t.Error("wireSessionSyncConfigCallbacks did not install ss.OnConfigApplyHealth")
	}
}

func TestWireSessionSyncPeerCallbacksInstallsHandles_6428(t *testing.T) {
	d := newWiringTestDaemon()
	ss := newWiringTestSessionSync()
	d.wireSessionSyncPeerCallbacks(ss)

	if ss.OnPeerConnected == nil {
		t.Error("wireSessionSyncPeerCallbacks did not install ss.OnPeerConnected")
	}
	if ss.OnBulkSyncReceived == nil {
		t.Error("wireSessionSyncPeerCallbacks did not install ss.OnBulkSyncReceived")
	}
	if ss.OnBulkSyncAckReceived == nil {
		t.Error("wireSessionSyncPeerCallbacks did not install ss.OnBulkSyncAckReceived")
	}
	if ss.OnSessionInventoryBulkReceived == nil {
		t.Error("wireSessionSyncPeerCallbacks did not install ss.OnSessionInventoryBulkReceived")
	}

	if ss.OnForwardSessionInstalled == nil {
		t.Error("wireSessionSyncPeerCallbacks did not install ss.OnForwardSessionInstalled")
	}
	// #6031: cold prime must be framed from table truth. Its own tests call the
	// producer (userspaceBulkSnapshot) directly, so the INSTALLATION was
	// revertible with a green suite until #7261.
	if ss.BulkSnapshotSource == nil {
		t.Error("wireSessionSyncPeerCallbacks did not install ss.BulkSnapshotSource")
	}
	if ss.OnPeerDisconnected == nil {
		t.Error("wireSessionSyncPeerCallbacks did not install ss.OnPeerDisconnected")
	}
}

func TestWireSessionSyncFailoverCallbacksInstallsHandles_6428(t *testing.T) {
	d := newWiringTestDaemon()
	ss := newWiringTestSessionSync()
	d.wireSessionSyncFailoverCallbacks(ss)

	if ss.OnRemoteFailover == nil {
		t.Error("wireSessionSyncFailoverCallbacks did not install ss.OnRemoteFailover")
	}
	if ss.OnRemoteFailoverBatch == nil {
		t.Error("wireSessionSyncFailoverCallbacks did not install ss.OnRemoteFailoverBatch")
	}
	if ss.OnRemoteFailoverCommit == nil {
		t.Error("wireSessionSyncFailoverCallbacks did not install ss.OnRemoteFailoverCommit")
	}
	if ss.OnRemoteFailoverCommitBatch == nil {
		t.Error("wireSessionSyncFailoverCallbacks did not install ss.OnRemoteFailoverCommitBatch")
	}
	// #5640: the applied-ack must wait on real local actuation. An unwired
	// WaitFailoverApplied silently reverts that gate to "ack immediately",
	// reopening the two-owner window.
	if ss.WaitFailoverApplied == nil {
		t.Error("wireSessionSyncFailoverCallbacks did not install ss.WaitFailoverApplied")
	}
	if ss.WaitFailoverAppliedBatch == nil {
		t.Error("wireSessionSyncFailoverCallbacks did not install ss.WaitFailoverAppliedBatch")
	}
}

func TestWireClusterFenceCallbacksInstallsHandle_6428(t *testing.T) {
	d := newWiringTestDaemon()
	ss := newWiringTestSessionSync()
	d.wireClusterFenceCallbacks(t.Context(), ss)

	if ss.OnFenceReceived == nil {
		t.Error("wireClusterFenceCallbacks did not install ss.OnFenceReceived")
	}
}

// TestWireSessionSyncTransportRefsRecordsPeerAddrs_6428 binds the two daemon
// fields the transport-refs builder publishes for gRPC peer dialing. The
// fab1 address is recorded ONLY when dual-fabric is in play (syncLocal1
// non-empty), so both arms are asserted: a builder that unconditionally
// recorded syncPeerAddr1 would leave a stale peer address on a single-fabric
// node.
func TestWireSessionSyncTransportRefsRecordsPeerAddrs_6428(t *testing.T) {
	cc := &config.ClusterConfig{Fabric1PeerAddress: "10.99.1.2"}

	t.Run("single fabric", func(t *testing.T) {
		d := newWiringTestDaemon()
		ss := newWiringTestSessionSync()
		d.wireSessionSyncTransportRefs(ss, cc, "control-link", "10.99.0.2", "")
		if d.syncPeerAddr != "10.99.0.2" {
			t.Errorf("syncPeerAddr = %q, want %q", d.syncPeerAddr, "10.99.0.2")
		}
		if d.syncPeerAddr1 != "" {
			t.Errorf("syncPeerAddr1 = %q, want empty on a single-fabric node", d.syncPeerAddr1)
		}
	})

	t.Run("dual fabric", func(t *testing.T) {
		d := newWiringTestDaemon()
		ss := newWiringTestSessionSync()
		d.wireSessionSyncTransportRefs(ss, cc, "fabric", "10.99.0.2", "10.99.1.1:4785")
		if d.syncPeerAddr != "10.99.0.2" {
			t.Errorf("syncPeerAddr = %q, want %q", d.syncPeerAddr, "10.99.0.2")
		}
		if d.syncPeerAddr1 != "10.99.1.2" {
			t.Errorf("syncPeerAddr1 = %q, want %q", d.syncPeerAddr1, "10.99.1.2")
		}
	})
}
