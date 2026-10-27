package daemon

import (
	"context"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/configstore"
)

// #17030 (finding R4-Q31-05): the #8965 peer-sync control-endpoint refusal
// branch in syncAndApplyWithAncestry was pasted from the #6192 identity
// branch (7f7713fa8e) and changed only in its predicate. Its slog.Error named
// a node-id/cluster-id identity change and a restart to re-key the HA
// manager, and reconcileManagementAfterPromotion received the reason
// "peer-synced identity change refused" — the wrong cause and the wrong
// remediation for a refusal whose own preflight error
// (controlEndpointMoveRefusal8965 / controlEndpointDeleteRefusal9178)
// prescribes setting the new control-link peer address on BOTH nodes and
// restarting xpfd on both, or taking the cluster down / configuring a
// fabric fallback first.
//
// These cells drive the real peer-sync path (promoteReconcileEnv +
// syncAndApply) so the branch's observable log text and reason are pinned,
// not a copy of the strings. Class U: hermetic — the management listener is
// a fake registry listener, the cluster manager is constructed in-memory
// with SetHeartbeatEndpointForTesting (no sockets), and all config stores
// live in t.TempDir(). No netlink, nftables, daemon, or exec reach.
//
// FAIL-ON-REVERT: restore the identity text/reason in the #8965 branch of
// syncAndApplyWithAncestry and the move cell below reds (the log names
// "node-id/cluster-id", "re-key the HA manager", and neither peer address);
// the identity control cell stays GREEN, proving the two branches are
// distinguished rather than one shared string renamed everywhere.

// peerSyncClusterLines17030 is a clustered stanza whose identity matches a
// manager keyed (node 0, cluster 1), so the topology and identity backstops
// pass and the control-endpoint gate is the one that can refuse. peerAddr is
// the candidate's control-link peer address; control-interface keeps the
// strict control-link pair complete so the candidate compiles as a valid
// clustered config.
func peerSyncClusterLines17030(peerAddr string) string {
	return "set chassis cluster cluster-id 1\n" +
		"set chassis cluster node 0\n" +
		"set chassis cluster authentication-key peer-sync-17030-psk\n" +
		"set chassis cluster control-interface em0\n" +
		"set chassis cluster peer-address " + peerAddr + "\n" +
		"set chassis cluster redundancy-group 1 node 0 priority 200\n"
}

// syncPeerText17030 commits text in a throwaway peer store and returns
// ShowActive() — exactly what pushConfigToPeer sends and SyncApply promotes.
func syncPeerText17030(t *testing.T, name, text string) string {
	t.Helper()
	peerStore, err := configstore.New(filepath.Join(t.TempDir(), name))
	if err != nil {
		t.Fatalf("configstore.New (peer): %v", err)
	}
	mgmtAuthCommit(t, peerStore, text)
	return peerStore.ShowActive()
}

func TestPeerSyncControlEndpointRefusalNamesControlLink17030(t *testing.T) {
	const (
		oldSecret = "OLD-17030-secret"
		newSecret = "NEW-17030-secret"
		running   = "10.99.170.1"
		moved     = "10.99.170.2"
	)
	e := newPromoteReconcileEnv(t)

	// Local active: clustered (cluster-id 1 / node 0), OLD credential, and
	// the candidate's own control endpoint — so only the peer-address move
	// distinguishes the peer text.
	mgmtAuthCommit(t, e.store, mgmtAuthConfigFor("ge-0/0/0", oldSecret)+peerSyncClusterLines17030(running))
	if act := e.store.ActiveConfig(); act == nil || act.Chassis.Cluster == nil {
		t.Fatal("setup: the local active config must compile a chassis-cluster stanza, or " +
			"the control-endpoint backstop is unreachable and this guard proves nothing")
	}
	if err := e.d.reconcileWebManagement(e.store.ActiveConfig()); err != nil {
		t.Fatalf("setup reconcile: %v", err)
	}
	if !e.liveSecretMatches(t, oldSecret) {
		t.Fatal("setup: the old credential must be live before the sync")
	}

	// Running HA manager: same identity as the candidate (so the identity
	// gate passes), heartbeat already on `running` (so a candidate naming
	// `moved` is a live control-endpoint move for the #8965 gate).
	mgr := cluster.NewManager(0, 1)
	mgr.SetHeartbeatEndpointForTesting("10.99.170.254", running, "em0")
	e.d.cluster = mgr

	peerText := syncPeerText17030(t, "peer-17030.conf",
		mgmtAuthConfigFor("ge-0/0/0", newSecret)+peerSyncClusterLines17030(moved))

	logs, restore := captureSlog(t)
	_, err := e.d.syncAndApply(context.Background(), peerText, nil)
	restore()
	if err == nil {
		t.Fatal("setup: the control-endpoint backstop must reject a peer-synced control-link " +
			"peer-address move; without that rejection this test exercises the ordinary apply path")
	}
	// The returned error is the preflight's own text: it must name both
	// control-link addresses (the acceptance's "names the control-link peer
	// address") and the both-nodes procedure.
	for _, want := range []string{running, moved, "BOTH nodes"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("control-endpoint refusal error must contain %q; got %v", want, err)
		}
	}

	// The branch log must name ITS OWN cause and remediation — the
	// control-endpoint move — not the identity gate's.
	out := logs.String()
	if !strings.Contains(out, "peer-synced control-endpoint") {
		t.Errorf("the #8965 peer-sync branch must log its own control-endpoint cause; logs:\n%s", out)
	}
	if !strings.Contains(out, "control-link") {
		t.Errorf("the #8965 peer-sync branch log must name the control link; logs:\n%s", out)
	}
	for _, bad := range []string{"node-id/cluster-id", "re-key the HA manager", "peer-synced identity change refused"} {
		if strings.Contains(out, bad) {
			t.Errorf("the #8965 peer-sync branch still carries the identity gate's text %q; logs:\n%s", bad, out)
		}
	}

	// #6720 is preserved: SyncApply promoted the peer config before the
	// backstop returned, so its credential revocation is live policy and
	// the management reconcile must still have run.
	if e.liveSecretMatches(t, oldSecret) {
		t.Fatalf("the listener still authenticates %q after the control-endpoint backstop refused "+
			"the apply; the promoted config's revocation is live policy (#6720)", oldSecret)
	}
	if !e.liveSecretMatches(t, newSecret) {
		t.Fatal("the listener must honour the promoted config's credential")
	}
}

// TestPeerSyncIdentityRefusalKeepsIdentityText17030 is the positive control:
// the sibling identity branch must KEEP its (correct) identity text and
// reason, so the fix distinguishes the two branches rather than renaming a
// shared string. It mirrors the #6720 identity guard's fixture (cluster-id
// 1 -> 2) and additionally pins the branch log.
func TestPeerSyncIdentityRefusalKeepsIdentityText17030(t *testing.T) {
	const oldSecret, newSecret = "OLD-17030-id-secret", "NEW-17030-id-secret"
	e := newPromoteReconcileEnv(t)

	clusterLines := func(clusterID int) string {
		// control-interface + peer-address keep the strict #16746
		// control-link pair complete; the running manager has no recorded
		// heartbeat endpoint, so the #8965 gate no-ops (have=="") and the
		// identity gate is the one that refuses.
		return "set chassis cluster cluster-id " + strconv.Itoa(clusterID) + "\n" +
			"set chassis cluster node 0\n" +
			"set chassis cluster authentication-key identity-17030-psk\n" +
			"set chassis cluster control-interface em0\n" +
			"set chassis cluster peer-address 10.99.170.1\n" +
			"set chassis cluster redundancy-group 1 node 0 priority 200\n"
	}
	mgmtAuthCommit(t, e.store, mgmtAuthConfigFor("ge-0/0/0", oldSecret)+clusterLines(1))
	if act := e.store.ActiveConfig(); act == nil || act.Chassis.Cluster == nil {
		t.Fatal("setup: the local active config must compile a chassis-cluster stanza")
	}
	if err := e.d.reconcileWebManagement(e.store.ActiveConfig()); err != nil {
		t.Fatalf("setup reconcile: %v", err)
	}
	if !e.liveSecretMatches(t, oldSecret) {
		t.Fatal("setup: the old credential must be live before the sync")
	}
	e.d.cluster = cluster.NewManager(0, 1)

	peerText := syncPeerText17030(t, "peer-17030-id.conf",
		mgmtAuthConfigFor("ge-0/0/0", newSecret)+clusterLines(2))

	logs, restore := captureSlog(t)
	_, err := e.d.syncAndApply(context.Background(), peerText, nil)
	restore()
	if err == nil {
		t.Fatal("setup: the identity backstop must reject a peer-synced cluster-id change")
	}
	if !strings.Contains(err.Error(), "restart") {
		t.Fatalf("setup: expected the identity backstop's restart-required error, got %v", err)
	}
	out := logs.String()
	if !strings.Contains(out, "node-id/cluster-id") || (!strings.Contains(out, "peer-synced identity change refused") && !strings.Contains(out, "identity change")) {
		t.Errorf("the identity branch must keep naming the identity cause; logs:\n%s", out)
	}
	if strings.Contains(out, "peer-synced control-endpoint move refused") {
		t.Errorf("the identity branch must not borrow the control-endpoint reason; logs:\n%s", out)
	}
	if e.liveSecretMatches(t, oldSecret) {
		t.Fatalf("the listener still authenticates %q after the identity backstop refused the apply (#6720)", oldSecret)
	}
	if !e.liveSecretMatches(t, newSecret) {
		t.Fatal("the listener must honour the promoted config's credential")
	}
}
