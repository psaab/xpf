package daemon

import (
	"context"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/sync/semaphore"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
)

type peerSyncRefusalCase18622 struct {
	name           string
	activeCluster  string
	refusedCluster string
	wantError      string
	fabric         bool
}

var peerSyncRefusalCases18622 = []peerSyncRefusalCase18622{
	{
		name:           "8965-peer-address",
		activeCluster:  peerSyncClusterLines17030("10.99.170.1"),
		refusedCluster: peerSyncClusterLines17030("10.99.170.2"),
		wantError:      "changing the chassis cluster control-link peer address from",
	},
	{
		name:           "8987-control-interface",
		activeCluster:  peerSyncClusterLines17030("10.99.170.1"),
		refusedCluster: strings.Replace(peerSyncClusterLines17030("10.99.170.1"), "control-interface em0", "control-interface em1", 1),
		wantError:      "changing the chassis cluster control-link interface from",
	},
	{
		name:           "9121-config-sync-endpoint",
		activeCluster:  "set chassis cluster cluster-id 1\n" +
			"set chassis cluster node 0\n" +
			"set chassis cluster authentication-key peer-sync-18622-psk\n" +
			"set chassis cluster fabric-interface fab0\n" +
			"set chassis cluster fabric-peer-address 10.99.13.2\n" +
			"set chassis cluster no-private-rg-election\n" +
			"set chassis cluster redundancy-group 1 node 0 priority 200\n",
		refusedCluster: "set chassis cluster cluster-id 1\n" +
			"set chassis cluster node 0\n" +
			"set chassis cluster authentication-key peer-sync-18622-psk\n" +
			"set chassis cluster fabric-interface fab0\n" +
			"set chassis cluster fabric-peer-address 10.99.14.2\n" +
			"set chassis cluster no-private-rg-election\n" +
			"set chassis cluster redundancy-group 1 node 0 priority 200\n",
		wantError: "changing the chassis cluster config-sync endpoint from",
		fabric:    true,
	},
}

// Every peer text also rotates the web-management credential. The gate must
// refuse the whole candidate, not reconcile an authorization change from text
// that never became active.
func peerSyncText18622(check peerSyncRefusalCase18622) string {
	return mgmtAuthConfigFor("ge-0/0/0", "peer-sync-18622-secret") + check.activeCluster
}

func peerSyncPeerText18622(t *testing.T, check peerSyncRefusalCase18622, extra string) string {
	t.Helper()
	peerStore, err := configstore.New(filepath.Join(t.TempDir(), "peer.conf"))
	if err != nil {
		t.Fatalf("configstore.New(peer): %v", err)
	}
	refusedText := mgmtAuthConfigFor("ge-0/0/0", "peer-sync-18622-new-secret") + check.refusedCluster + extra
	mgmtAuthCommit(t, peerStore, refusedText)
	return peerStore.ShowActive()
}

func newPeerSyncRefusalFixture18622(t *testing.T, check peerSyncRefusalCase18622) (*Daemon, *configstore.Store, *config.Config, string, string) {
	t.Helper()
	store, err := configstore.New(filepath.Join(t.TempDir(), "active.conf"))
	if err != nil {
		t.Fatalf("configstore.New(active): %v", err)
	}
	mgmtAuthCommit(t, store, peerSyncText18622(check))
	before := store.ActiveTree().Format()
	activeCfg := store.ActiveConfig()

	peerText := peerSyncPeerText18622(t, check, "")
	mgr := cluster.NewManager(0, 1)
	if !check.fabric {
		mgr.SetHeartbeatEndpointForTesting("10.99.170.254", "10.99.170.1", "em0")
	}
	d := &Daemon{store: store, applySem: semaphore.NewWeighted(1), cluster: mgr}
	d.activeClusterTransport = clusterTransportFromConfig(activeCfg)
	return d, store, activeCfg, before, peerText
}

func requirePeerSyncRefused18622(t *testing.T, check peerSyncRefusalCase18622, err error, what string) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), check.wantError) {
		t.Fatalf("%s must be refused by the %s gate, got %v", what, check.name, err)
	}
}

// The per-check subtests make each gate independently live: a push with only
// that check's transport change must nack, and it must continue to nack after
// both the identical retry and a later changed-content push.
//
// FAIL-ON-REVERT: neutering any one pre-promotion check reds that check's first
// push assertion; putting it back after promotion reds the active-unchanged
// assertions even if the later retry happens to nack for another reason.

func TestPeerSyncRefusalRetriesRemainRefused18622(t *testing.T) {
	for _, check := range peerSyncRefusalCases18622 {
		t.Run(check.name, func(t *testing.T) {
			d, store, _, before, peerText := newPeerSyncRefusalFixture18622(t, check)

			_, err := d.syncAndApplyForTest(context.Background(), peerText, nil)
			requirePeerSyncRefused18622(t, check, err, "the first peer push")
			requireActiveUnchanged18606(t, store, before, "the first refused peer push")

			_, err = d.syncAndApplyForTest(context.Background(), peerText, nil)
			requirePeerSyncRefused18622(t, check, err, "the identical re-push after nack")
			requireActiveUnchanged18606(t, store, before, "the identical re-push")

			laterText := peerSyncPeerText18622(t, check, "set system host-name later-push-18622\n")
			_, err = d.syncAndApplyForTest(context.Background(), laterText, nil)
			requirePeerSyncRefused18622(t, check, err, "a later push carrying the same topology change")
			requireActiveUnchanged18606(t, store, before, "a later peer push carrying the refused change")
		})
	}
}

// FAIL-ON-REVERT: restoring the after-promotion check order for any row makes
// its named background-apply subtest apply the refused endpoint/interface
// rather than the old active config. Each subtest reaches the real #9811
// reassert operation and captures what reaches applyConfigLocked.
func TestPeerSyncBackgroundApplySeesUnchangedConfig18622(t *testing.T) {
	for _, check := range peerSyncRefusalCases18622 {
		t.Run(check.name, func(t *testing.T) {
			d, store, activeCfg, before, peerText := newPeerSyncRefusalFixture18622(t, check)
			_, err := d.syncAndApplyForTest(context.Background(), peerText, nil)
			requirePeerSyncRefused18622(t, check, err, "the peer push before a background apply")

			var applied *config.Config
			d.applyBodyForTest = func(cfg *config.Config) { applied = cfg }
			if err := configApplyReassertFn(d); err != nil {
				t.Fatalf("the #9811 background retry apply: %v", err)
			}
			if applied == nil {
				t.Fatal("precondition: the #9811 retry did not reach applyConfigLocked")
			}
			if !reflect.DeepEqual(applied, activeCfg) {
				t.Fatalf("background retry did not apply the unchanged active config after %s refusal", check.name)
			}
			if after := store.ActiveTree().Format(); after != before {
				t.Fatalf("background retry observed a promoted refused config for %s:\n--- before\n%s\n--- after\n%s", check.name, before, after)
			}
		})
	}
}
