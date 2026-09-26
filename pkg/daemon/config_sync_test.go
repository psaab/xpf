package daemon

import (
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
)

// newClusterManager creates a cluster.Manager where node 0 is primary or
// secondary for RG0. For secondary: uses non-preempt + control-interface
// (cluster mode) so electSingleNode() defers to peer heartbeat timeout,
// keeping the node secondary without a peer.
func newClusterManager(primary bool) *cluster.Manager {
	m := cluster.NewManager(0, 1)
	cfg := &config.ClusterConfig{
		RethCount: 1,
		RedundancyGroups: []*config.RedundancyGroup{{
			ID:             0,
			NodePriorities: map[int]int{0: 200},
			Preempt:        primary, // preempt=true → immediate primary; false → deferred
		}},
	}
	if !primary {
		// Setting ControlInterface makes this a "cluster mode" manager.
		// Combined with Preempt=false + no peer ever seen, electSingleNode()
		// keeps the node in StateSecondary.
		cfg.ControlInterface = "control0"
	}
	m.UpdateConfig(cfg)
	return m
}

// TestHandleConfigSync_RejectsWhenPrimary verifies that the RG0 primary
// rejects incoming config sync (prevents secondary from overwriting).
//
// The returned ERROR is load-bearing, not incidental. `configApplyLoop`
// advances the config high-water (`recordAppliedConfigGen`) ONLY on a nil
// `OnConfigReceived` return (M-2/#4151), so a short-circuit that returned nil
// here would advance `lastAppliedConfigGen` past a config this node never
// applied — the primary's re-push of that same generation would then be
// dropped by `shouldApplyConfigGen` as stale and the node would sit silently
// diverged. Asserting only "it did not panic on the nil store" cannot see that:
// verified by mutation at `daemon_ha_sync.go`'s rejection arm — replacing
// `return errConfigSyncRejectedPrimary` with `return nil` left the pre-#6419
// form of this test GREEN.
//
// The `err == nil` check below is NOT redundant with the `errors.Is`. Go
// defines `errors.Is(nil, nil)` as true (`errors/wrap.go`: `if err == nil ||
// target == nil { return err == target }`), so mutating the production sentinel
// itself to a nil `error` makes the handler return nil AND satisfies
// `errors.Is` — the #6419 form of this test was still vacuous against that
// mutation. Checking non-nil first closes it.
//
// #6419: this rejection is also half of the reason the "reuse the authority's
// own config-generation namespace" shortcut cannot close the active/active
// reverse direction — see the `stampInstallGenV4` comment and
// docs/session-sync-architecture.md. Each counter is live in exactly one role
// (`configGenCounter` on the authority, `lastAppliedConfigGen` off it), which
// is why the shortcut cannot be written role-free.
func TestHandleConfigSync_RejectsWhenPrimary(t *testing.T) {
	d := &Daemon{
		cluster: newClusterManager(true),
	}
	// Reaching the assertion at all proves the short-circuit fired: without the
	// guard, the call falls through and panics on this Daemon's nil dependencies
	// (`applySem` is dereferenced before the nil store is ever reached). The
	// assertions then prove it short-circuited as a REJECTION, not a silent
	// success.
	err := d.handleConfigSync("set system host-name bad-config")
	if err == nil {
		t.Fatal("RG0 primary must REJECT a peer config push with a NON-NIL error " +
			"so configApplyLoop leaves the config high-water pinned (M-2/#4151); got nil")
	}
	if !errors.Is(err, errConfigSyncRejectedPrimary) {
		t.Fatalf("RG0 primary rejection must be errConfigSyncRejectedPrimary; got err = %v", err)
	}
}

// TestConfigReceivedWiringPropagatesRejection binds the production WIRING, not
// the handler it calls.
//
// TestHandleConfigSync_RejectsWhenPrimary invokes `d.handleConfigSync` directly,
// but nothing in production does. `configApplyLoop` calls
// `SessionSync.OnConfigReceived`, and the only thing that ever populates that
// field is the assignment in `wireSessionSyncConfigCallbacks`. A closure that
// called the handler and then returned nil regardless would keep every direct
// handler test green while `configApplyLoop` recorded the config as APPLIED —
// exactly the silent-divergence outcome those tests exist to prevent.
//
// Verified: rewriting that closure's tail to `_ = d.handleConfigSync(configText);
// return nil` left the ENTIRE pkg/daemon suite green before this test existed.
// This test reds on that mutation and on deletion of the assignment itself.
func TestConfigReceivedWiringPropagatesRejection(t *testing.T) {
	d := &Daemon{
		cluster: newClusterManager(true),
	}
	ss := cluster.NewSessionSync(":0", "10.0.0.2:4785", nil)

	d.wireSessionSyncConfigCallbacks(ss)

	if ss.OnConfigReceived == nil {
		t.Fatal("wireSessionSyncConfigCallbacks must install OnConfigReceived — " +
			"configApplyLoop has no other source for it")
	}

	// Drive the callback the way configApplyLoop does. This node is RG0 primary,
	// so the handler rejects; the wiring must hand that rejection back unchanged,
	// because configApplyLoop advances lastAppliedConfigGen on a nil return.
	err := ss.OnConfigReceived("set system host-name bad-config")
	if err == nil {
		t.Fatal("OnConfigReceived must PROPAGATE the RG0-primary rejection; it returned nil, " +
			"so configApplyLoop would record an un-applied config as applied and the peer's " +
			"re-push of that generation would then be dropped as stale (M-2/#4151)")
	}
	if !errors.Is(err, errConfigSyncRejectedPrimary) {
		t.Fatalf("OnConfigReceived must propagate errConfigSyncRejectedPrimary unchanged; got err = %v", err)
	}
}

// TestHandleConfigSync_AcceptsWhenSecondary verifies that a secondary node
// proceeds past the authority guard. We expect a store error (nil store)
// which confirms the guard passed and the function tried to apply config.
func TestHandleConfigSync_AcceptsWhenSecondary(t *testing.T) {
	d := &Daemon{
		cluster: newClusterManager(false),
	}
	// Secondary should pass the guard and try SyncApply → panic on nil store.
	// Recover from the expected nil pointer to confirm the guard passed.
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic from nil store (guard should have passed)")
		}
	}()
	d.handleConfigSync("set system host-name good-config")
}

// TestHandleConfigSync_AcceptsWhenNoCluster verifies that standalone mode
// (no cluster manager) accepts incoming config sync.
func TestHandleConfigSync_AcceptsWhenNoCluster(t *testing.T) {
	d := &Daemon{}
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic from nil store (guard should have passed)")
		}
	}()
	d.handleConfigSync("set system host-name standalone")
}

func TestHandleConfigSync_SkipsWhenConfigAlreadyMatchesActive(t *testing.T) {
	store := newConfigStore(t, filepath.Join(t.TempDir(), "config"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if err := store.SetFromInput("system host-name sync-test"); err != nil {
		t.Fatalf("SetFromInput: %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	// #4957: the converged shortcut now requires the active config to have been
	// APPLIED, not merely to match by text (a promoted-but-unapplied synced config
	// must NOT read as converged). This test commits directly through the store,
	// bypassing the daemon apply path that stamps the marker, so establish it
	// explicitly to represent an already-applied active config.
	store.MarkActiveApplied()
	active := store.ShowActive()
	historyLen := len(store.ListHistory())

	d := &Daemon{
		cluster: newClusterManager(false),
		store:   store,
	}

	d.handleConfigSync(active + "\n")

	if got := store.ShowActive(); got != active {
		t.Fatalf("active config changed on identical sync:\nwant:\n%s\n\ngot:\n%s", active, got)
	}
	if got := store.ActiveConfig(); got == nil || got.System.HostName != "sync-test" {
		t.Fatalf("expected unchanged compiled config, got %#v", got)
	}
	if got := len(store.ListHistory()); got != historyLen {
		t.Fatalf("expected identical config sync to skip history mutation, want %d entries got %d", historyLen, got)
	}
}

// TestConfigSyncPeerConnectUsesRG0Reconciler verifies reconnect push behavior
// through the production reconciler rather than a test-only replica of the
// removed callback logic.
func TestConfigSyncPeerConnectUsesRG0Reconciler(t *testing.T) {
	for _, tc := range []struct {
		name     string
		primary  bool
		wantPush int64
	}{
		{name: "RG0 primary pushes", primary: true, wantPush: 1},
		{name: "secondary does not push", primary: false, wantPush: 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, pushes := newReconcileDaemon(t, tc.primary, 60*time.Second)
			d.reconcileConfigSyncToPeer("peer-connect")
			if got := pushes.Load(); got != tc.wantPush {
				t.Fatalf("peer-connect reconciler push count = %d, want %d", got, tc.wantPush)
			}
		})
	}
}
