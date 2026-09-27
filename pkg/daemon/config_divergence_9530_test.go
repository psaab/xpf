package daemon

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"golang.org/x/sync/semaphore"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
)

// #9530: the daemon half of the partition-commit divergence alarm. The store
// cells (pkg/configstore/unshared_commit_divergence_9530_test.go) pin the mark
// and the classification; these pin what the daemon feeds the store and what it
// raises.

var clusterLines9530 = []string{
	"chassis cluster cluster-id 1",
	"chassis cluster authentication-key test-cluster-psk-6611",
	"chassis cluster node 0",
	"chassis cluster configuration-synchronize",
}

// markPartitionCommit9530 commits on store while the peer is unreachable, so the
// active config is marked unshared.
func markPartitionCommit9530(t *testing.T, store *configstore.Store) {
	t.Helper()
	store.SetPeerReachableFn(func() bool { return false })
	commitHostName(t, store, "partition-commit")
}

func winnerText9530(t *testing.T) string {
	t.Helper()
	return renderSyncedConfigText(t, append(append([]string{}, clusterLines9530...), "system host-name winner")...)
}

// The reconcile push counts as sharing the marked commit only when the peer reads
// RG0 secondary. In the dual-active heal window the peer is still primary and
// rejects the push, so the mark must survive it.
func TestReconcilePushSharesTheCommitOnlyWhenThePeerReadsSecondary_9530(t *testing.T) {
	for _, tc := range []struct {
		name           string
		peerSecondary  bool
		wantDivergence bool
	}{
		{"peer still reads primary", false, true},
		{"peer reads secondary", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, pushes := newReconcileDaemon(t, true /*primary*/, 60*time.Second)
			markPartitionCommit9530(t, d.store)
			d.configPeerStateForTest = func() (bool, bool) { return true, tc.peerSecondary }
			d.syncPeerConnEpoch.Add(1)
			d.reconcileConfigSyncToPeer("heal")
			if got := pushes.Load(); got != 1 {
				t.Fatalf("setup: the reconciler pushed %d times, want 1", got)
			}

			d.store.SetClusterReadOnly(true)
			if _, err := d.store.SyncApply(winnerText9530(t), nil); err != nil {
				t.Fatalf("SyncApply: %v", err)
			}
			_, _, got := d.store.ConfigSyncDivergence()
			if got != tc.wantDivergence {
				t.Errorf("after a push while the %s, the sync that replaced the partition commit reported divergence=%v, want %v",
					tc.name, got, tc.wantDivergence)
			}
		})
	}
}

// A heal sync that discards the partition commit raises one cluster event, and a
// converged re-push does not raise another.
func TestHealSyncRaisesTheDivergenceEventOnce_9530(t *testing.T) {
	store := newConfigSyncStore(t, "c0-host")
	markPartitionCommit9530(t, store)
	store.SetClusterReadOnly(true)
	d := &Daemon{
		cluster:          newClusterManager(false /*secondary*/),
		store:            store,
		applySem:         semaphore.NewWeighted(1),
		applyBodyForTest: func(*config.Config) {},
	}
	winner := winnerText9530(t)

	if err := d.handleConfigSync(winner); err != nil {
		t.Fatalf("heal sync: %v", err)
	}
	events := func() []string {
		var out []string
		for _, ev := range d.cluster.EventHistoryFor(cluster.EventConfigSync) {
			if s := fmt.Sprintf("%+v", ev); strings.Contains(s, "never held") {
				out = append(out, s)
			}
		}
		return out
	}
	if got := events(); len(got) != 1 {
		t.Fatalf("#9530: the heal sync discarded the partition commit and raised %d divergence events, want 1: %v", len(got), got)
	}
	if got := events()[0]; !strings.Contains(got, "rollback 1") {
		t.Errorf("the divergence event does not name the rollback slot that holds the discarded commit: %s", got)
	}

	if err := d.handleConfigSync(winner); err != nil {
		t.Fatalf("converged re-push: %v", err)
	}
	d.reportConfigSyncDivergence()
	if got := events(); len(got) != 1 {
		t.Errorf("a converged re-push raised the divergence again: %d events", len(got))
	}
}

// Standalone and reachable nodes never raise it.
func TestHealthySyncRaisesNoDivergenceEvent_9530(t *testing.T) {
	store := newConfigSyncStore(t, "c0-host")
	store.SetPeerReachableFn(func() bool { return true })
	commitHostName(t, store, "routine-commit")
	store.SetClusterReadOnly(true)
	d := &Daemon{
		cluster:          newClusterManager(false),
		store:            store,
		applySem:         semaphore.NewWeighted(1),
		applyBodyForTest: func(*config.Config) {},
	}
	if err := d.handleConfigSync(winnerText9530(t)); err != nil {
		t.Fatalf("sync: %v", err)
	}
	for _, ev := range d.cluster.EventHistoryFor(cluster.EventConfigSync) {
		if s := fmt.Sprintf("%+v", ev); strings.Contains(s, "never held") {
			t.Errorf("a routine failover sync raised a divergence event: %s", s)
		}
	}
}

// The production predicate: a peer whose heartbeat was never seen is unreachable
// even with a session-sync connection up, and a daemon with no cluster manager
// has no peer.
func TestConfigPeerReachableNeedsALivePeer_9530(t *testing.T) {
	d := &Daemon{cluster: newClusterManager(true)}
	d.syncPeerConnected.Store(true)
	if d.configPeerReachable() {
		t.Errorf("a peer whose heartbeat was never seen read as reachable, so a partition commit would not be marked")
	}
	standalone := &Daemon{}
	standalone.syncPeerConnected.Store(true)
	if standalone.configPeerReachable() {
		t.Errorf("a daemon with no cluster manager reported a reachable peer")
	}
}
