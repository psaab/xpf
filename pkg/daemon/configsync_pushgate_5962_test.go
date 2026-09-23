package daemon

// configsync_pushgate_5962_test.go — binds the PUSH-TIME half of the #5962
// attempt-time/push-time authority split.
//
// #5962 is about a decision taken twice: commitAndApplyOperator resolves
// rg0ConfigSyncAuthority BEFORE store.Commit, and the push site
// (syncConfigToPeer) re-checks it at the moment of the push. The two checks can
// disagree, and which one is load-bearing depends on the DIRECTION ownership
// moves:
//
//   - PROMOTION inside the window (non-authority at attempt, authority at push):
//     the frozen attempt-time `false` wins and the push is skipped. The push-time
//     re-check cannot recover it — a gate can only narrow, never widen — so this
//     direction is a genuine defect, fixed by resolving the policy at the push.
//   - DEMOTION inside the window (authority at attempt, non-authority at push):
//     the attempt-time `true` reaches the push site and THIS gate stops it. It is
//     the only thing that stops it: production leaves d.syncPeerForTest nil, so
//     the single commit-path push route is
//     applyAndSyncCommitted -> pushCommittedConfigToPeer -> syncConfigToPeer,
//     and a node that lost RG0 in the window would otherwise overwrite the config
//     of the node that now owns it.
//
// That makes the demotion direction safe BECAUSE of the gate below — and the
// gate was entirely unbound: deleting `if !rg0ConfigSyncAuthority(d.cluster) {
// return }` from syncConfigToPeer left `go vet` clean and the whole pkg/daemon
// suite green (exit 0, zero failures). A silent deletion is exactly the revert
// that turns the safe direction into a live one, so it is pinned here.
//
// The tests deliberately drive the PRODUCTION route, not the d.syncPeerForTest
// seam: that seam short-circuits pushCommittedConfigToPeer and never reaches
// syncConfigToPeer, so a cell written against it cannot observe this gate at all.
//
// FAIL-ON-REVERT: removing the RG0 re-check from syncConfigToPeer turns
// "non-authority must not reach the push" RED while the authority control stays
// GREEN.

import (
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/cluster"
)

// newPushGateDaemon wires a Daemon that can reach the real push body without a
// live TCP peer.
//
// A non-nil *cluster.SessionSync clears the transport-presence guards in
// syncConfigToPeer and pushConfigToPeer. Nothing is written to a socket: a
// zero-value SessionSync has no active connection, so QueueConfig no-ops. The
// observable is the #5863 reconcile marker, which pushConfigToPeer stamps via
// markConfigSyncPushed AFTER it has committed to pushing — so the marker is set
// if and only if control reached the push body.
func newPushGateDaemon(t *testing.T, cl *cluster.Manager) *Daemon {
	t.Helper()
	d := &Daemon{
		cluster:   cl,
		store:     newConfigSyncStore(t, "pushgate-host"),
		startTime: time.Now().Add(-60 * time.Second),
	}
	d.sessionSync = &cluster.SessionSync{}
	d.configSyncPushForTest = func() {}
	// The production route sees this test-only hook as an in-process transport
	// and still runs the push-time RG0 authority gate before invoking it.
	d.syncPeerConnected.Store(true)
	d.syncPeerConnEpoch.Add(1)
	return d
}

// reachedPush reports whether control reached pushConfigToPeer's push body.
func reachedPush(d *Daemon) bool {
	d.configSyncMu.Lock()
	defer d.configSyncMu.Unlock()
	return d.configSyncHasPushed
}

// TestSyncConfigToPeerGatesOnRG0AuthorityAtPushTime pins the push-time gate that
// makes the #5962 DEMOTION direction safe.
func TestSyncConfigToPeerGatesOnRG0AuthorityAtPushTime(t *testing.T) {
	t.Run("non-authority: must not reach the push", func(t *testing.T) {
		d := newPushGateDaemon(t, clusterNotOwningRG0(t))

		d.syncConfigToPeer()

		if reachedPush(d) {
			t.Fatal("a node that is NOT the RG0 config authority reached the config " +
				"push body. syncConfigToPeer's rg0ConfigSyncAuthority re-check is the " +
				"only thing standing between an attempt-time `true` and a push FROM a " +
				"node demoted mid-commit TOWARD the node that now owns the config — " +
				"which would overwrite the authority's config with a stale tree (#5962)")
		}
	})

	// Control: the same fixture on an OWNER must reach the push. Without this,
	// the cell above passes for the wrong reason — a store with config-sync
	// disabled, an empty active config, or a nil session sync would each return
	// early on their own and leave the marker unset with the gate gone.
	t.Run("authority: reaches the push (control)", func(t *testing.T) {
		d := newPushGateDaemon(t, clusterOwningRG0(t))

		d.syncConfigToPeer()

		if !reachedPush(d) {
			t.Fatal("the RG0 config authority did not reach the config push body; the " +
				"fixture never gets past the transport/config-sync preconditions, so the " +
				"non-authority cell above would pass even with the gate removed")
		}
	})
}
