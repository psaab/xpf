package daemon

import (
	"errors"
	"path/filepath"
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
		"chassis cluster node 0",
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
	d.applyBodyForTest = func(*config.Config) {}
	pushes := 0
	d.syncPeerForTest = func() { pushes++ }
	return d, store, &pushes
}

// TestCommitConfirmedUsesPeerSnapshotProtocolGate10782 proves the second
// generation-bound commit path refuses the exact multi-zone shape a pre-v4
// connected peer narrows. The store remains unpromoted and no peer push occurs.
//
// RED-on-revert: removing peerSnapshotProtocolCommitPreflight from
// commitConfirmedAndApply makes the incompatible-peer row promote and push,
// failing its error, active-state, and push-count assertions.
func TestCommitConfirmedUsesPeerSnapshotProtocolGate10782(t *testing.T) {
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

	t.Run("disconnected peer does not freeze commit", func(t *testing.T) {
		d, store, pushes := commitConfirmedSnapshotGateDaemon10782(t, 0, false)
		if _, err := d.commitConfirmedAndApply(t.Context(), configstore.InternalCommitter(), 1, peerSyncNever); err != nil {
			t.Fatalf("commit confirmed with a disconnected peer must remain allowed: %v", err)
		}
		if got := len(store.ActiveConfig().Security.GlobalPolicies); got != 1 {
			t.Fatalf("disconnected-peer commit-confirmed promoted %d global policies; want 1", got)
		}
		if *pushes != 0 {
			t.Fatalf("commit-confirmed with a disconnected peer made %d peer-sync attempts; want none", *pushes)
		}
		if err := store.ConfirmCommit(); err != nil {
			t.Fatalf("clear test confirm timer: %v", err)
		}
	})
}
