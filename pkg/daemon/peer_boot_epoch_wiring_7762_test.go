package daemon

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/vrrp"
)

// #7762: startClusterComms must WIRE the peer-boot-epoch callback, not merely
// leave SessionSync able to accept one.
//
// This is the half a cluster-package cell cannot reach. Those cells construct a
// SessionSync and assign PeerBootEpochFn by hand, which proves the CLASSIFIER
// consumes the signal — it says nothing about whether the daemon ever supplies
// it. With the assignment deleted from startClusterComms the field is nil, the
// classifier takes its "not wired" arm, and every cluster-package cell still
// passes while the fix does nothing in production.
//
// RED on revert: delete `ss.PeerBootEpochFn = ...` from startClusterComms.
//
// The wait condition IS the asserted property (#7350). startClusterComms
// publishes the SessionSync BEFORE it wires it, so polling on getSessionSync()
// and then asserting the field is a window, not a test.
func TestStartClusterCommsWiresPeerBootEpochFn_7762(t *testing.T) {
	store := newConfigStore(t, filepath.Join(t.TempDir(), "config.db"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	// Fabric transport rather than a sync endpoint, for the reason
	// TestStartClusterCommsWiresBulkSnapshotSource7259 documents: it reaches the
	// same wiring block without touching the pre-existing StartHeartbeat race.
	for _, line := range []string{
		"chassis cluster cluster-id 1",
		"chassis cluster node 0",
		"chassis cluster fabric-interface lo",
		"chassis cluster fabric-peer-address 127.0.0.2",
		"chassis cluster redundancy-group 0 node 0 priority 200",
		"chassis cluster redundancy-group 0 node 1 priority 100",
		"chassis cluster authentication-key test-cluster-psk-7762",
		"security zones security-zone lan",
		"security zones security-zone wan",
	} {
		if err := store.SetFromInput(line); err != nil {
			t.Fatalf("set %q: %v", line, err)
		}
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}

	d := &Daemon{
		store:    store,
		opts:     Options{NoDataplane: true},
		cluster:  newClusterManager(true),
		vrrpMgr:  vrrp.NewManager(),
		rgStates: make(map[int]*rgStateMachine),
	}
	// The predicates are wired only when a runtime is published, and both
	// boot-epoch callbacks are assigned in the same block.
	d.setDataplane(&wiringExporterDP{})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d.startClusterComms(ctx)
	t.Cleanup(d.stopClusterComms)

	var ss *cluster.SessionSync
	published := false
	for deadline := time.Now().Add(15 * time.Second); time.Now().Before(deadline); {
		if cand := d.getSessionSync(); cand != nil {
			published = true
			if cand.PeerBootEpochFn != nil &&
				cand.LocalBootEpochFn != nil &&
				cand.LocalProcessTokenFn != nil {
				ss = cand
				break
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	if ss == nil {
		if published {
			t.Fatal("SessionSync was published but one of PeerBootEpochFn or " +
				"LocalBootEpochFn was never wired — peer incarnation attribution " +
				"would silently fall back to the legacy path")
		}
		t.Fatal("SessionSync was never published")
	}

	// The callback must answer from the cluster Manager rather than being any
	// non-nil function. A fresh Manager has seen no peer heartbeat, so the
	// honest answer is the UNLATCHED one — which is also the state the
	// classifier must treat as "cannot tell yet" rather than as "no reboot".
	epoch, latched := ss.PeerBootEpochFn()
	if latched {
		t.Errorf("a Manager that has received no peer heartbeat must report the epoch "+
			"UNLATCHED; latched=true here would mean the callback is answering from "+
			"something other than the heartbeat state (got epoch=%d)", epoch)
	}
	if epoch != 0 {
		t.Errorf("unlatched floor must be 0, got %d", epoch)
	}

	token := ss.LocalProcessTokenFn()
	if token == 0 {
		t.Fatal("wired local process token must be non-zero")
	}
}
