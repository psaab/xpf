package daemon

import (
	"context"
	"path/filepath"
	"sync"
	"testing"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/networkd"
	"github.com/psaab/xpf/pkg/vrrp"
)

// clusteredStore7066 commits a cluster stanza that yields a NON-ZERO
// clusterTransportKey while starting no comms goroutines.
//
// The non-zero part is load-bearing and is why this does not reuse the #6290
// fixture. clusterTransportFromConfig reads ControlInterface / PeerAddress /
// the fabric fields, and that fixture sets NONE of them — so its key is the
// zero value, and a value assertion written against it would be
// zero-equals-zero and pass with the publish deleted. That is the defect this
// file exists to bind, reproduced in the test for it.
//
// control-interface ALONE is what gives a non-zero key for free: the heartbeat
// is gated on ControlInterface AND PeerAddress, and clusterSyncTransport falls
// back to the (empty) fabric pair when either is missing, so neither goroutine
// starts.
func clusteredStore7066(t *testing.T) *configstore.Store {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "config.db"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	for _, line := range []string{
		"chassis cluster cluster-id 1",
		"chassis cluster node 0",
		"chassis cluster authentication-key test-cluster-psk-7066",
		"chassis cluster control-interface em0",
	} {
		if err := store.SetFromInput(line); err != nil {
			t.Fatalf("set %q: %v", line, err)
		}
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("commit clustered active: %v", err)
	}
	return store
}

// #7067: TestActiveClusterTransportIsMutexGuarded_6290 stays green when the
// publish is DELETED OUTRIGHT — measured, collected=1 in both cells. With no
// write there is no concurrent access, so the race detector has nothing to
// report and the probe passes whether the access is correctly guarded or absent.
//
// That is inherent to any probe whose only assertion is the race detector: it
// binds HOW an access is synchronized, never THAT the access happens. Binding
// the write's existence needs a value assertion, which is this.
//
// TestSetActiveTransportDropsStaleEpoch does not cover it — that calls
// setActiveTransportIfCurrent directly and never goes through startClusterComms,
// so it binds the epoch gate rather than the call site.
func TestStartClusterCommsPublishesTheTransport_7067(t *testing.T) {
	store := clusteredStore7066(t)
	active := store.ActiveConfig()
	want := clusterTransportFromConfig(active)

	// PREMISE. Without this the assertion below is zero == zero and passes
	// against a build with the publish removed — which is exactly how the
	// existing race probe fails to bind it.
	if want == (clusterTransportKey{}) {
		t.Fatalf("premise broken: this fixture's transport key is the ZERO value, so the "+
			"assertion below cannot tell a publish from no publish at all. Give the cluster "+
			"stanza a control-interface. key=%+v", want)
	}

	d := &Daemon{store: store, opts: Options{NoDataplane: true}}
	if got := d.activeTransport(); got != (clusterTransportKey{}) {
		t.Fatalf("premise broken: the daemon already holds a transport key before "+
			"startClusterComms runs (%+v), so a passing assertion would not be evidence "+
			"that the publish happened", got)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d.startClusterComms(ctx)

	if got := d.activeTransport(); got != want {
		t.Errorf("startClusterComms did not publish the transport key.\n got %+v\nwant %+v\n"+
			"Step 20 compares the next commit's transport against this field to decide "+
			"whether to restart comms; unpublished it stays zero, the `active != zero` guard "+
			"never passes, and a genuine endpoint change silently does not restart comms. "+
			"The #6290 race probe cannot see this — with no write there is no concurrent "+
			"access for the detector to report", got, want)
	}
}

// #7066: the OTHER half of #6869's production delta — daemon_apply_tail.go's
// step 20 replacing six direct d.activeClusterTransport reads with one guarded
// d.activeTransport() snapshot — is unbound. Measured: revert that file to
// master's shape and the whole `go test -race ./pkg/daemon/` suite stays green,
// 0 DATA RACE.
//
// It cannot fail there because the #6290 probe's reader is the ACCESSOR, and no
// test drives applyTailReconciles concurrently with startClusterComms. The other
// step-20 drivers (cluster_transport_key_5078_test.go) are single-goroutine and
// seed the field with a direct write. So the pair the reverted tree races —
// step 20's read against startClusterComms' write — is never executed
// concurrently by anything.
//
// This drives that actual pair. The transport does not change between the
// committed active and the config passed to the tail, so step 20 READS and
// decides not to restart: the read is what is under test, and a restart storm
// would make the cell about something else.
func TestStepTwentyReadsTheTransportUnderTheLock_7066(t *testing.T) {
	installFakeNetworkctl(t)
	store := clusteredStore7066(t)
	cfg := store.ActiveConfig()

	d := &Daemon{
		store:     store,
		networkd:  networkd.NewInDir(t.TempDir()),
		vrrpMgr:   vrrp.NewManager(),
		cluster:   cluster.NewManager(0, 1),
		daemonCtx: context.Background(),
		opts:      Options{NoDataplane: true},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// PREMISE: step 20 must actually reach the read. If the tail returned before
	// it, this would be a race test over code that never runs.
	d.startClusterComms(ctx)
	if d.activeTransport() == (clusterTransportKey{}) {
		t.Fatal("premise broken: no transport published, so step 20's `active != zero` " +
			"branch is not exercised and this cell races nothing")
	}

	const iterations = 60
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			d.startClusterComms(ctx)
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			// The tail returns reconcile errors in this stripped-down harness;
			// the access under test is step 20's read, which it performs
			// regardless.
			_ = d.applyTailReconciles(cfg, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)
		}
	}()
	wg.Wait()
}
