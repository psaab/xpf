package daemon

import (
	"sync"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/ra"
)

// refusedClusterRATarget17693 retains a node-local RA config in the store while
// making the rollback target fail the existing dataplane preflight.
func refusedClusterRATarget17693(t *testing.T) string {
	t.Helper()
	tree := &config.ConfigTree{}
	for _, line := range []string{
		"set system host-name refused-target",
		"set chassis cluster cluster-id 1",
		"set chassis cluster authentication-key test-cluster-psk-6611",
		"set chassis cluster node 0",
		"set chassis cluster control-interface em0",
		"set chassis cluster peer-address 10.99.0.2",
		"set chassis cluster redundancy-group 1 node 0 priority 200",
		"set chassis cluster redundancy-group 1 node 1 priority 100",
		"set interfaces em0 unit 0 family inet address 10.99.0.1/24",
		"set interfaces reth0 vlan-tagging",
		"set interfaces reth0 redundant-ether-options redundancy-group 1",
		"set interfaces reth0 unit 50 vlan-id 50",
		"set interfaces ge-0/0/0 gigether-options redundant-parent reth0",
		"set interfaces ge-7/0/0 gigether-options redundant-parent reth0",
		"set interfaces ge-0/0/9 unit 0 family inet6 address 2001:db8:99::1/64",
		"set protocols router-advertisement interface ge-0/0/9.0 prefix 2001:db8:99::/64",
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		"set security policies from-zone trust to-zone gone policy bad1 match source-address any",
		"set security policies from-zone trust to-zone gone policy bad1 match destination-address any",
		"set security policies from-zone trust to-zone gone policy bad1 match application any",
		"set security policies from-zone trust to-zone gone policy bad1 then permit",
	} {
		path, err := config.ParseSetCommand(line)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", line, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", line, err)
		}
	}
	return tree.Format()
}

// #17693: the refused-target bootstrap retains an unusable clustered config in
// ActiveConfig. Its periodic cluster RA pass must not recreate node-local
// senders after bootstrap withdrew them; an authorized exit re-enables reconcile.
func TestRefusedTargetBootstrapSuppressesClusterRA17693(t *testing.T) {
	h := newDaemon9615(t)
	h.d.ra = ra.New()
	t.Cleanup(func() { _ = h.d.ra.Clear() })

	armWindowOver9615(t, h.s, refusedClusterRATarget17693(t))
	h.s.InvokeRollbackTimerForTesting(h.s.ConfirmGenForTesting())
	if cfg := h.s.ActiveConfig(); cfg == nil || cfg.Chassis.Cluster == nil {
		t.Fatal("premise: refused rollback target must retain the cluster config")
	}
	if !h.d.inBootstrap() || !h.d.bootstrapFromRefusedRollback.Load() {
		t.Fatal("premise: refused-target rollback must remain in bootstrap")
	}
	if got := h.d.ra.Status(); len(got) != 0 {
		t.Fatalf("RA senders after refused-target bootstrap withdrawal = %+v, want none", got)
	}

	h.d.reconcileClusterRAServices("periodic-after-refused-bootstrap")
	if got := h.d.ra.Status(); len(got) != 0 {
		t.Fatalf("periodic cluster reconcile recreated node-local RA in bootstrap: %+v", got)
	}

	h.d.exitBootstrapMode("authorized correction control")
	h.d.reconcileClusterRAServices("after-authorized-bootstrap-exit")
	if got := h.d.ra.Status(); len(got) == 0 {
		t.Fatal("cluster RA reconcile remained suppressed after authorized bootstrap exit")
	}
}

// #17693: a cluster reconcile already inside raReconcileMu must finish before
// bootstrap's final Withdraw; after that boundary, waiting periodic passes see
// bootstrap mode and cannot re-add the abandoned node-local sender.
func TestBootstrapRAWithdrawalSerializesWithInFlightReconcile17693(t *testing.T) {
	store := raClusterStore(t, "2001:db8:1::/64")
	if err := store.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	if _, err := store.LoadSet(
		"set interfaces ge-0/0/9 unit 0 family inet6 address 2001:db8:99::1/64\n" +
			"set protocols router-advertisement interface ge-0/0/9.0 prefix 2001:db8:99::/64\n"); err != nil {
		t.Fatalf("LoadSet node-local RA: %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit node-local RA: %v", err)
	}
	store.ExitConfigure()

	d := &Daemon{store: store, ra: ra.New(), rgStates: make(map[int]*rgStateMachine)}
	d.applyBodyForTest = func(*config.Config) {}
	started := make(chan struct{})
	release := make(chan struct{})
	var startedOnce, releaseOnce sync.Once
	d.raApplyFn = func(configs []*config.RAInterfaceConfig) error {
		startedOnce.Do(func() { close(started) })
		<-release
		return d.ra.Apply(configs)
	}
	var wg sync.WaitGroup
	reconcileDone := make(chan struct{})
	rollbackDone := make(chan error, 1)
	wg.Add(2)
	go func() {
		defer wg.Done()
		d.reconcileClusterRAServices("in-flight-bootstrap-race")
		close(reconcileDone)
	}()
	goRollback := func() {
		go func() {
			defer wg.Done()
			rollbackDone <- d.enterBootstrapMode()
		}()
	}
	t.Cleanup(func() {
		releaseOnce.Do(func() { close(release) })
		done := make(chan struct{})
		go func() { wg.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Error("in-flight RA or bootstrap teardown did not complete")
		}
		_ = d.ra.Clear()
	})

	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("cluster reconcile did not reach the blocked RA applier")
	}
	goRollback()
	deadline := time.After(2 * time.Second)
	for !d.inBootstrap() {
		select {
		case <-deadline:
			t.Fatal("bootstrap rollback did not set bootstrap mode")
		case <-time.After(time.Millisecond):
		}
	}
	select {
	case err := <-rollbackDone:
		t.Fatalf("bootstrap withdrawal crossed the in-flight RA reconcile boundary: %v", err)
	case <-time.After(20 * time.Millisecond):
	}

	releaseOnce.Do(func() { close(release) })
	select {
	case <-reconcileDone:
	case <-time.After(2 * time.Second):
		t.Fatal("in-flight RA reconcile did not finish after release")
	}
	select {
	case err := <-rollbackDone:
		if err != nil {
			t.Fatalf("enter bootstrap mode: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("bootstrap teardown did not finish after RA reconcile")
	}
	if got := d.ra.Status(); len(got) != 0 {
		t.Fatalf("in-flight reconcile left RA senders after bootstrap withdrawal: %+v", got)
	}
	d.reconcileClusterRAServices("periodic-after-in-flight-bootstrap")
	if got := d.ra.Status(); len(got) != 0 {
		t.Fatalf("waiting periodic pass recreated RA in bootstrap: %+v", got)
	}
}
