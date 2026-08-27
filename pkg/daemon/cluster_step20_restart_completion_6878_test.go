package daemon

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/networkd"
	"github.com/psaab/xpf/pkg/vrrp"
)

// #6878: the three #5078 subtests bind the step-20 DECISION correctly, but two
// things beside them were unobservable in that harness. Both escapes below were
// MEASURED against the pre-fix tree, not reasoned.
//
// Escape 1 — a store-derived keyed check is invisible. The #5078 fixture's
// store deliberately holds NO committed cluster config, so a suppression check
// reading the auth key from d.store.ActiveConfig() instead of the candidate cfg
// sees nothing and the package stays green. A real commit promotes the new
// config BEFORE apply (store_commit.go -> daemon_apply.go), so in production
// that spelling would see the key and suppress the restart: the same #5078
// deadlock, different spelling, no red.
//
// Escape 2 — the subtests prove teardown, not restart. All three observe
// clusterCommsGen, which stopClusterComms bumps FIRST. Measured: deleting
// d.startClusterComms(d.daemonCtx) from step 20 left the whole pkg/daemon
// package green (0 named failures). A build that tears comms down on every
// endpoint change and never brings them back up passes the suite, while every
// endpoint move silently leaves the cluster with no session-sync.
//
// Both escapes share one root: the fixture had no committed cluster stanza.
// This harness fixes that root rather than adding assertions to the #5078
// subtests, which are correct as they stand and are deliberately left alone.
//
//   - The store holds a COMMITTED, KEYED cluster config. That is what makes a
//     store-derived keyed check visible: it would now see the key.
//   - The start is observed through startClusterCommsFn, so restart COMPLETION
//     is bound without standing up heartbeat/sync sockets. Counting invocations
//     rather than watching clusterCommsGen is the whole point — the generation
//     cannot distinguish "restarted" from "torn down and abandoned".
func TestStep20RestartsCommsToCompletion_6878(t *testing.T) {
	installFakeNetworkctl(t)

	// The transport the daemon believes is already live.
	baseTransport := func() *config.Config {
		cfg := &config.Config{}
		cfg.Chassis.Cluster = &config.ClusterConfig{
			ClusterID:         1,
			NodeID:            0,
			ControlInterface:  "em0",
			PeerAddress:       "10.99.0.2",
			FabricInterface:   "fab0",
			FabricPeerAddress: "10.99.1.2",
		}
		return cfg
	}

	newDaemon := func(t *testing.T) (*Daemon, *int) {
		t.Helper()
		store := newConfigStore(t, filepath.Join(t.TempDir(), "config.db"))
		if err := store.EnterConfigure(); err != nil {
			t.Fatalf("EnterConfigure: %v", err)
		}
		// A committed cluster config that CARRIES AN AUTH KEY. Escape 1 is
		// invisible without this: a store-derived keyed check needs a key in
		// the store to read.
		for _, line := range []string{
			"chassis cluster cluster-id 1",
			"chassis cluster node 0",
			"chassis cluster authentication-key committed-psk-6878",
		} {
			if err := store.SetFromInput(line); err != nil {
				t.Fatalf("SetFromInput(%q): %v", line, err)
			}
		}
		if _, err := store.Commit(); err != nil {
			t.Fatalf("commit keyed cluster config: %v", err)
		}
		active := store.ActiveConfig()
		if active == nil || active.Chassis.Cluster == nil {
			t.Fatal("fixture broken: the store must hold a committed cluster config, " +
				"or a store-derived keyed check stays invisible exactly as it was " +
				"before this test")
		}
		if active.Chassis.Cluster.ControlLinkAuthKey == "" {
			t.Fatal("fixture broken: the committed cluster config must carry an auth " +
				"key, or Escape 1 is not covered")
		}

		starts := 0
		d := &Daemon{
			store:     store,
			networkd:  networkd.NewInDir(t.TempDir()),
			vrrpMgr:   vrrp.NewManager(),
			cluster:   cluster.NewManager(0, 1),
			daemonCtx: context.Background(),
			opts:      Options{NoDataplane: true},
		}
		d.startClusterCommsFn = func(context.Context) { starts++ }
		d.activeClusterTransport = clusterTransportFromConfig(baseTransport())
		return d, &starts
	}

	t.Run("endpoint_change_restarts_comms_to_COMPLETION", func(t *testing.T) {
		// The load-bearing cell. clusterCommsGen cannot tell a completed
		// restart from a teardown, so this counts the start itself.
		d, starts := newDaemon(t)
		moved := baseTransport()
		moved.Chassis.Cluster.PeerAddress = "10.99.0.9"

		_ = d.applyTailReconciles(moved, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)

		if *starts != 1 {
			t.Fatalf("step 20 started cluster comms %d times, want exactly 1 — a "+
				"teardown that never comes back up leaves every endpoint move with "+
				"no session-sync, and clusterCommsGen cannot see it because "+
				"stopClusterComms bumps the generation first", *starts)
		}
	})

	t.Run("key_commit_still_does_not_restart_with_a_KEYED_store", func(t *testing.T) {
		// Escape 1. The #5078 subtest asserts this against a store holding no
		// cluster config; here the store holds a KEYED one, so a suppression
		// check derived from d.store.ActiveConfig() is now observable.
		d, starts := newDaemon(t)
		keyed := baseTransport()
		keyed.Chassis.Cluster.ControlLinkAuthKey = config.Secret("a-real-cluster-psk-6878")

		_ = d.applyTailReconciles(keyed, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)

		if *starts != 0 {
			t.Fatalf("committing an authentication key restarted cluster comms "+
				"(%d starts): that drops the established session-sync connection at "+
				"the moment the primary becomes keyed, and it is the ONLY path by "+
				"which the key reaches a config read-only secondary (#5078)", *starts)
		}
	})

	t.Run("no_transport_change_does_not_restart", func(t *testing.T) {
		// Negative control on the other axis: step 20 must not fire when
		// nothing moved. Without this, a step 20 that restarted on EVERY apply
		// would satisfy the completion cell above.
		d, starts := newDaemon(t)

		_ = d.applyTailReconciles(baseTransport(), nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)

		if *starts != 0 {
			t.Fatalf("an unchanged transport restarted cluster comms (%d starts) — "+
				"step 20 fires on every apply, which would make the completion "+
				"assertion above pass for the wrong reason", *starts)
		}
	})
}
