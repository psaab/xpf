package daemon

import (
	"context"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sync/semaphore"

	"github.com/psaab/xpf/pkg/api"
	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
)

// #6718 / #6720 — a path that PROMOTES a config to active must reach the
// management reconcile even when it deliberately never enters applyConfigLocked.
//
// reconcileWebManagement's contract is already written in the tree: it runs
// early in the apply "so a committed authentication tightening/revocation or
// bind change is live even on an apply that returns early". That is stated for
// an apply that ABORTS PARTWAY, and it had an unstated precondition —
// applyConfigLocked is its only caller. Two paths return BEFORE entering it,
// and each leaves a superseded credential authenticating against the live
// listener.
//
// The two guards below must fail INDEPENDENTLY. They share an invariant, a fix
// shape and a helper, which is exactly the setup in which one guard ends up
// wearing two names: each drives its OWN trigger path (a first-commit rollback
// timeout vs a peer push carrying a topology transition), so removing one call
// site reds one test and leaves the other green.

// promoteReconcileEnv wires a daemon whose management listener is LIVE and
// currently honouring `secret` on an off-box bind — the precondition both
// defects need, because a listener that never started makes reconcileTo a no-op
// on `m.srv == nil` and every assertion below would pass vacuously.
type promoteReconcileEnv struct {
	d     *Daemon
	store *configstore.Store
	m     *managementReconciler
}

func newPromoteReconcileEnv(t *testing.T) *promoteReconcileEnv {
	t.Helper()
	mgmtAuthIfaceAddrs(t)
	s, err := configstore.New(filepath.Join(t.TempDir(), "xpf.conf"))
	if err != nil {
		t.Fatalf("configstore.New: %v", err)
	}
	d := &Daemon{applySem: semaphore.NewWeighted(1), store: s}
	reg := newFakeReg()
	m := newManagementReconciler(d, api.Config{ListenFunc: reg.listen})
	d.mgmt.Store(m)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if err := m.start(ctx); err != nil {
		t.Fatalf("mgmt start: %v", err)
	}
	return &promoteReconcileEnv{d: d, store: s, m: m}
}

// liveSecret returns the api-auth password the LIVE listener currently accepts
// for `webadmin`, or "" when it accepts none.
func (e *promoteReconcileEnv) liveSecret(t *testing.T) string {
	t.Helper()
	e.m.mu.Lock()
	srv := e.m.srv
	e.m.mu.Unlock()
	if srv == nil {
		t.Fatal("setup: the management server must be live, or every assertion here is vacuous")
	}
	auth := srv.LiveAuth()
	if auth == nil {
		return ""
	}
	return auth.Users["webadmin"]
}
func (e *promoteReconcileEnv) liveSecretMatches(t *testing.T, expected string) bool {
	t.Helper()
	e.m.mu.Lock()
	srv := e.m.srv
	e.m.mu.Unlock()
	if srv == nil {
		t.Fatal("setup: the management server must be live, or every assertion here is vacuous")
	}
	return mgmtAuthSecretMatches(t, srv.LiveAuth(), expected)
}

// TestFirstCommitRollbackDropsTheAbandonedCredential6718 is the #6718 guard.
//
// A first `commit confirmed` on a fresh store enables a credentialed off-box
// bind; the operator never confirms; the timer fires. PromoteRollback returns
// prevCfg == nil, the store is back to the empty tree and marked
// never-committed — and before #6718 the listener stayed bound where the
// abandoned commit put it, with its credential still authenticating, authorised
// by a config the box has formally abandoned.
//
// The reverted endpoint is the generic one and that is the point: with the empty
// tree active there is no web-management stanza, so the desired state IS the
// --api-addr flag default with no credential. Keeping the management LIFELINE —
// the reason this branch skips the apply — is not the same as keeping the
// abandoned commit's off-box bind and secret.
//
// FAIL-ON-REVERT: delete the reconcileManagementAfterPromotion call from the
// prevCfg == nil branch of executeConfirmedRollback. This test reds; the #6720
// test below stays GREEN.
func TestFirstCommitRollbackDropsTheAbandonedCredential6718(t *testing.T) {
	const abandoned = "ABANDONED-first-commit-secret"
	e := newPromoteReconcileEnv(t)

	// A fresh store starts with no credential at all.
	if got := e.liveSecret(t); got != "" {
		t.Fatalf("setup: a fresh store must authorise no credential, got %q", got)
	}

	// The FIRST commit, unconfirmed, enables the credentialed off-box bind.
	if err := e.store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if _, err := e.store.LoadSet(mgmtAuthConfigFor("ge-0/0/0", abandoned)); err != nil {
		t.Fatalf("LoadSet: %v", err)
	}
	if _, err := e.store.CommitConfirmed(1); err != nil {
		t.Fatalf("CommitConfirmed: %v", err)
	}
	e.store.ExitConfigure()

	// Stand in for the apply that the real commit path runs: the listener is now
	// where the abandoned commit put it. This is the state #6718 describes, so
	// establishing it is setup, not the property under test.
	if err := e.d.reconcileWebManagement(e.store.ActiveConfig()); err != nil {
		t.Fatalf("setup reconcile: %v", err)
	}
	if !e.liveSecretMatches(t, abandoned) {
		t.Fatal("setup: the abandoned commit's credential must be live before the timeout")
	}

	// The operator never confirms. Fire the timer through the production
	// executor, not by calling the branch directly.
	e.d.applyBodyForTest = func(_ *config.Config) {}
	e.store.SetRollbackExecutor(e.d.executeConfirmedRollback)
	e.store.InvokeRollbackTimerForTesting(e.store.ConfirmGenForTesting())

	if !e.d.inBootstrap() {
		t.Fatal("setup: the first-commit timeout must take the prevCfg == nil branch " +
			"(bootstrap mode); if it did not, this test is not exercising #6718 at all")
	}
	if e.store.EverCommitted() {
		t.Fatal("setup: the store must read never-committed after a first-commit rollback")
	}

	if e.liveSecretMatches(t, abandoned) {
		t.Fatal("the listener still authenticates the ABANDONED commit's credential after " +
			"the first-commit-confirmed timeout. The store has reverted to the empty tree " +
			"and marked itself never-committed, so that credential is authorised by a " +
			"config the box has formally abandoned — and under #5561 it still yields a " +
			"full-power principal (#6718)")
	}
	if got := e.liveSecret(t); got != "" {
		t.Fatalf("the reverted endpoint must carry NO credential — the empty active config "+
			"names no api-auth — got %q", got)
	}
}

// TestPeerSyncBackstopStillReconcilesManagement6720 is the #6720 guard.
//
// SyncApply promotes the peer config FIRST; the topology backstop then refuses
// the live apply and returns before applyConfigLocked. The backstop is right to
// refuse to arm the dataplane — the HA runtime is boot-only — but that
// constraint does not apply to the AUTHORIZATION reconcile, and skipping it left
// the listener honouring a credential the now-active config had revoked.
//
// FAIL-ON-REVERT: delete the reconcileManagementAfterPromotion call from the
// topology backstop in syncAndApply. This test reds; the #6718 test above stays
// GREEN.
func TestPeerSyncBackstopStillReconcilesManagement6720(t *testing.T) {
	const oldSecret, newSecret = "OLD-peer-secret", "NEW-peer-secret"
	e := newPromoteReconcileEnv(t)
	d := e.d

	// Active config carries the OLD credential, reconciled live.
	mgmtAuthCommit(t, e.store, mgmtAuthConfigFor("ge-0/0/0", oldSecret))
	if err := e.d.reconcileWebManagement(e.store.ActiveConfig()); err != nil {
		t.Fatalf("setup reconcile: %v", err)
	}
	if !e.liveSecretMatches(t, oldSecret) {
		t.Fatal("setup: the old credential must be live before the sync")
	}

	// The peer pushes a config that BOTH revokes the old credential and carries
	// a topology transition. This daemon HAS an HA runtime and the pushed config
	// is standalone, so clusterTopologyCommitPreflight rejects the live apply —
	// the "removing `chassis cluster` cannot tear down the HA runtime" direction.
	//
	// That direction is used deliberately: it needs no chassis stanza to survive
	// the peer-text round trip, so the fixture cannot pass for the wrong reason
	// if the cluster block fails to compile. The backstop's code path — promote,
	// then return before applyConfigLocked — is identical in both directions.
	d.cluster = cluster.NewManager(0, 1)

	// Build the peer text the way a PEER actually produces it: commit the new
	// config in its own store and render it with ShowActive(), which is exactly
	// what pushConfigToPeer sends (daemon_ha_sync.go). Deriving it from the local
	// candidate instead does not work — the candidate render did not carry the
	// changed secret, so SyncApply promoted a config identical to the active one
	// and the test passed its setup while proving nothing.
	peerStore, err := configstore.New(filepath.Join(t.TempDir(), "peer.conf"))
	if err != nil {
		t.Fatalf("configstore.New (peer): %v", err)
	}
	mgmtAuthCommit(t, peerStore, mgmtAuthConfigFor("ge-0/0/0", newSecret))
	peerText := peerStore.ShowActive()

	_, err = e.d.syncAndApply(context.Background(), peerText, nil)
	if err == nil {
		t.Fatal("setup: the topology backstop must reject a peer-synced topology transition " +
			"on a daemon whose HA runtime cannot be torn down live; without that rejection " +
			"this test exercises the ordinary apply path and proves nothing about #6720")
	}
	if !strings.Contains(err.Error(), "restart") {
		t.Fatalf("setup: expected the topology backstop's restart-required error, got %v", err)
	}

	// The promotion happened regardless — that is the backstop's deliberate
	// design (the store converges with the peer). So the credential it revoked
	// must be gone from the live listener.
	if e.liveSecretMatches(t, oldSecret) {
		t.Fatalf("the listener still authenticates %q, a credential the now-ACTIVE peer "+
			"config revoked. SyncApply promoted that config before the backstop returned, "+
			"so the revocation is live policy; the backstop's constraint is the boot-only "+
			"HA runtime, which has nothing to do with the authorization reconcile (#6720)", oldSecret)
	}
	if !e.liveSecretMatches(t, newSecret) {
		t.Fatal("the listener must honour the promoted config's credential")
	}
}

// TestPeerSyncIdentityBackstopStillReconcilesManagement6720 covers the SECOND
// #6720 call site. The identity backstop is a separate `return nil, err` before
// applyConfigLocked, so it is a separate claim and owes its own guard — a fix
// applied to the topology branch alone would leave this one silently open, and
// the topology test above cannot see it.
//
// Here both sides are clustered (so the topology backstop passes) and the peer's
// cluster-id differs from the running manager's, which is what
// clusterIdentityCommitPreflight refuses: the boot-constructed HA manager cannot
// be re-keyed live.
//
// FAIL-ON-REVERT: delete the reconcileManagementAfterPromotion call from the
// identity backstop. This test reds; the other two stay GREEN.
func TestPeerSyncIdentityBackstopStillReconcilesManagement6720(t *testing.T) {
	const oldSecret, newSecret = "OLD-identity-secret", "NEW-identity-secret"
	e := newPromoteReconcileEnv(t)

	clusterLines := func(clusterID int) string {
		return "set chassis cluster cluster-id " + strconv.Itoa(clusterID) + "\n" +
			"set chassis cluster node 0\n" +
			"set chassis cluster authentication-key identity-6720-psk\n" +
			"set chassis cluster redundancy-group 1 node 0 priority 200\n"
	}

	// Local active: clustered, cluster-id 1, OLD credential.
	mgmtAuthCommit(t, e.store, mgmtAuthConfigFor("ge-0/0/0", oldSecret)+clusterLines(1))
	// A hard precondition, NOT a t.Skip. A skip here would silently disable the
	// only guard on the identity call site the moment the chassis stanza stopped
	// compiling from this fixture — a green indistinguishable from a healthy one.
	if act := e.store.ActiveConfig(); act == nil || act.Chassis.Cluster == nil {
		t.Fatal("setup: the local active config must compile a chassis-cluster stanza, or " +
			"the identity backstop is unreachable and this guard proves nothing")
	}
	if err := e.d.reconcileWebManagement(e.store.ActiveConfig()); err != nil {
		t.Fatalf("setup reconcile: %v", err)
	}
	if !e.liveSecretMatches(t, oldSecret) {
		t.Fatal("setup: the old credential must be live before the sync")
	}

	// Running HA manager is keyed to cluster-id 1; the peer pushes cluster-id 2.
	e.d.cluster = cluster.NewManager(0, 1)

	peerStore, err := configstore.New(filepath.Join(t.TempDir(), "peer-identity.conf"))
	if err != nil {
		t.Fatalf("configstore.New (peer): %v", err)
	}
	mgmtAuthCommit(t, peerStore, mgmtAuthConfigFor("ge-0/0/0", newSecret)+clusterLines(2))
	peerText := peerStore.ShowActive()

	_, err = e.d.syncAndApply(context.Background(), peerText, nil)
	if err == nil {
		t.Fatal("setup: the identity backstop must reject a peer-synced cluster-id change; " +
			"without that rejection this test exercises the ordinary apply path")
	}
	if !strings.Contains(err.Error(), "restart") {
		t.Fatalf("setup: expected the identity backstop's restart-required error, got %v", err)
	}

	if e.liveSecretMatches(t, oldSecret) {
		t.Fatalf("the listener still authenticates %q after the IDENTITY backstop refused the "+
			"apply. SyncApply promoted the peer config first, so its revocation is live "+
			"policy; the backstop's constraint is re-keying the boot-constructed HA manager, "+
			"which has nothing to do with the authorization reconcile (#6720)", oldSecret)
	}
	if !e.liveSecretMatches(t, newSecret) {
		t.Fatal("the listener must honour the promoted config's credential")
	}
}
