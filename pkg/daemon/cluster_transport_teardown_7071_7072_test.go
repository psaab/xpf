package daemon

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/networkd"
	"github.com/psaab/xpf/pkg/vrrp"
)

// #7072 is REFUTED, and this is the cell that refutes it.
//
// The issue asked for `stopClusterComms` to clear `activeClusterTransport`,
// on the premise that the stale value is unreachable — "the only
// stopClusterComms call site is step 20's, immediately followed by a start".
// There is a SECOND: bootstrap.go's rollback teardown stops comms and RETURNS.
//
// On that path the stale field is the ONLY memory of which transport comms were
// using, and step 20's `active != zero && newTransport != active` needs it to
// notice a corrected commit. Measured both ways with a counting
// startClusterCommsFn:
//
//	field retained (today):  restarts=1  -> comms recover
//	field cleared:           restarts=0  -> comms stay down
//
// This test is the retained side. It FAILS on the naive fix, which is the whole
// reason it exists: the first version of this file asserted the cleared
// behaviour as correct, and that assertion was a probe keyed to the repair
// rather than to the property.
//
// The fixture must reach step 20, which is gated on `d.cluster != nil` — an
// earlier draft omitted the cluster manager and measured restarts=0 in BOTH
// arms, which looks exactly like a confirmed regression and is not.
func TestBootstrapRollbackThenCorrectedCommitRecovers_7072(t *testing.T) {
	store := clusteredStore7066(t)
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
	d.startClusterComms(ctx)
	if d.activeTransport() == (clusterTransportKey{}) {
		t.Fatal("premise: comms must publish a NON-ZERO transport, or step 20's " +
			"`active != zero` conjunct is false for a reason unrelated to teardown")
	}

	// The bootstrap-rollback shape: stop, and do NOT start.
	d.stopClusterComms()

	restarts := 0
	d.startClusterCommsFn = func(context.Context) { restarts++ }

	moved := store.ActiveConfig()
	moved.Chassis.Cluster.PeerAddress = "10.99.0.9"
	_ = d.applyTailReconciles(moved, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)

	if restarts != 1 {
		t.Errorf("a corrected commit after a bootstrap rollback did not restart comms "+
			"(restarts=%d, activeTransport=%+v).\nThis is what clearing "+
			"activeClusterTransport in stopClusterComms costs: step 20's first conjunct "+
			"becomes false, and the only other production startClusterComms call site is "+
			"the daemon_run.go boot path — so the node holds a valid cluster config with "+
			"no heartbeat, no session sync and no fabric refresh until the process "+
			"restarts (#7072)", restarts, d.activeTransport())
	}
}

// #7072, the other direction: a node that has NEVER started comms must not have
// step 20 act for it.
//
// `active != zero` is not a redundant "have we started" convenience. The boot
// applyConfig runs BEFORE daemon_run.go:405's startClusterComms — which is
// deliberately positioned after the event fanout to avoid an HA startup race —
// so step 20 runs during boot with the field still zero. Relaxing the guard to
// just `newTransport != active`, the obvious repair once the field is cleared,
// reintroduces that race with a truth table that looks perfect.
//
// Together with the cell above this brackets the guard: it must act after comms
// have run, and must not before.
func TestStepTwentyIgnoresANeverStartedNode_7072(t *testing.T) {
	store := clusteredStore7066(t)
	d := &Daemon{
		store:     store,
		networkd:  networkd.NewInDir(t.TempDir()),
		vrrpMgr:   vrrp.NewManager(),
		cluster:   cluster.NewManager(0, 1),
		daemonCtx: context.Background(),
		opts:      Options{NoDataplane: true},
	}
	if d.activeTransport() != (clusterTransportKey{}) {
		t.Fatalf("premise: a never-started node must hold a ZERO transport, got %+v",
			d.activeTransport())
	}

	restarts := 0
	d.startClusterCommsFn = func(context.Context) { restarts++ }

	cfg := store.ActiveConfig()
	cfg.Chassis.Cluster.PeerAddress = "10.99.0.9"
	_ = d.applyTailReconciles(cfg, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)

	if restarts != 0 {
		t.Errorf("step 20 acted for a node whose comms have never started "+
			"(restarts=%d). The boot applyConfig runs before startClusterComms, so this "+
			"would fire inside the HA startup window daemon_run.go:405 is positioned "+
			"after (#7072)", restarts)
	}
}

// #7071 CALL-SITE guard — and it exists because my first attempt at binding
// this was measured GREEN under the revert.
//
// `TestSupersededEpochPublishIsRefused_7071` below asserts that
// setActiveTransportIfCurrent REFUSES a superseded epoch. That is true with the
// fix and true without it: the gate is unchanged either way. Reverting the call
// site to `d.setActiveTransportIfCurrent(...)` with the result discarded left
// the whole pkg/daemon suite green — 2192 collected, 0 named failures. The test
// was adjacent to the property, not on it.
//
// The property is that the CALL SITE consumes the bool, and it cannot be driven
// behaviourally without a seam: the drop needs the epoch to advance between
// `beginClusterCommsEpoch` and the publish on the next line, a window no test
// can schedule. Rather than add a production seam whose only consumer is a test,
// this asserts the call site's SHAPE — the same instrument
// `TestDaemonPassesRethBeforeCycleHook_5103` uses for "programRethMemberMAC has
// exactly one call site and its result is assigned back", and
// `TestCompileRoutesPublishThroughFailClosedHelper4959` uses for "this publish
// goes through the fail-closed helper".
//
// Comments are stripped before matching. A source-scanning guard that reads its
// own explanatory prose is satisfied by the sentence describing the thing it is
// meant to find.
func TestStartClusterCommsConsumesTheDropSignal_7071(t *testing.T) {
	src, err := os.ReadFile("daemon_ha_sync.go")
	if err != nil {
		t.Fatalf("read daemon_ha_sync.go: %v", err)
	}
	const fn = "func (d *Daemon) startClusterComms("
	start := strings.Index(string(src), fn)
	if start < 0 {
		t.Fatalf("startClusterComms not found — this guard is scanning for a name that " +
			"no longer exists, which is not evidence that the call site is correct")
	}
	rest := string(src)[start+len(fn):]
	if end := strings.Index(rest, "\nfunc "); end >= 0 {
		rest = rest[:end]
	}
	var code []string
	for _, line := range strings.Split(rest, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "//") {
			continue
		}
		code = append(code, line)
	}
	body := strings.Join(code, "\n")

	// Non-vacuity: the call must be in there at all. Without this the shape
	// assertion below would pass for free on a body that never publishes.
	if !strings.Contains(body, "setActiveTransportIfCurrent(") {
		t.Fatalf("startClusterComms no longer calls setActiveTransportIfCurrent at all, " +
			"so the transport is never published and step 20's `active != zero` guard " +
			"never passes")
	}
	if !strings.Contains(body, "if !d.setActiveTransportIfCurrent(") {
		t.Errorf("startClusterComms DISCARDS setActiveTransportIfCurrent's drop signal.\n"+
			"Both sibling publishers gate on theirs (publishSessionSyncIfCurrent, "+
			"publishFabricRefreshChansIfCurrent). A false return means this epoch was "+
			"superseded, so everything below wires a DEAD epoch onto `commsCtx` — whose "+
			"cancel the newer epoch has already overwritten in clusterCommsCancel, so "+
			"nothing can cancel those goroutines and they outlive the epoch that spawned "+
			"them.\nbody:\n%s", body)
	}
	if !strings.Contains(body, "commsCancel()") {
		t.Errorf("the drop path does not cancel its own sub-context. Returning without " +
			"it leaks the context — nothing else holds that cancel, since the field now " +
			"names the newer epoch's — and cancelling here is safe precisely because " +
			"nothing has been launched on it yet")
	}
}

// #7071: startClusterComms must CONSUME the drop signal from
// setActiveTransportIfCurrent, as both sibling publishers already do.
//
// A false return means this epoch was superseded between the epoch opening and
// the publish, so everything below would wire a DEAD epoch. The wasted work is
// the smaller half. The goroutines are the larger one: they capture `commsCtx`,
// whose cancel the NEWER epoch has already overwritten in `clusterCommsCancel`,
// so nothing can cancel them — stopClusterComms would call the newer epoch's
// cancel — and they survive until the daemon context dies.
//
// Driving the race directly would be a timing test. This instead constructs the
// superseded state deterministically: open an epoch, advance the generation
// behind it, and assert the publish is refused. That is the exact condition the
// call site now returns on, and it is the property that makes the early return
// correct rather than arbitrary.
func TestSupersededEpochPublishIsRefused_7071(t *testing.T) {
	store := clusteredStore7066(t)
	d := &Daemon{store: store, opts: Options{NoDataplane: true}}
	want := clusterTransportFromConfig(store.ActiveConfig())
	if want == (clusterTransportKey{}) {
		t.Fatal("premise: a zero transport key cannot distinguish a refused publish " +
			"from an accepted one — both leave the field zero")
	}

	_, staleGen, staleCancel := d.beginClusterCommsEpoch(context.Background())
	defer staleCancel()

	// A newer epoch opens behind the first one — exactly what a concurrent
	// restart does between the two lines at the call site.
	_, newGen, newCancel := d.beginClusterCommsEpoch(context.Background())
	defer newCancel()
	if newGen == staleGen {
		t.Fatalf("premise: beginClusterCommsEpoch must advance the generation "+
			"(stale=%d new=%d)", staleGen, newGen)
	}

	if d.setActiveTransportIfCurrent(staleGen, want) {
		t.Error("the superseded epoch's publish was ACCEPTED. The call site returns " +
			"early on false, so accepting here would let a dead epoch wire the VRF " +
			"resolve, the HA watchdog, the heartbeat goroutine and the session-sync " +
			"constructor onto a context nothing can cancel")
	}
	if got := d.activeTransport(); got != (clusterTransportKey{}) {
		t.Errorf("a refused publish still wrote the field: %+v", got)
	}

	// And the live epoch's publish is still accepted — without this the test
	// passes against a setActiveTransportIfCurrent that refuses everything.
	if !d.setActiveTransportIfCurrent(newGen, want) {
		t.Error("the CURRENT epoch's publish was refused; the gate must drop only " +
			"superseded epochs")
	}
}

// #7901: the row the #7072 pair does not cover — a corrected commit whose
// transport key is IDENTICAL.
//
// The existing two cells bracket step 20's `active != zero` conjunct: it must
// act after comms have run, and must not before. Neither exercises the recovery
// disjunct, because both move the transport or never start comms at all. So the
// measured defect fell exactly between them:
//
//	corrected commit, key DIFFERS:    restarts=1  -> comms recover
//	corrected commit, key IDENTICAL:  restarts=0  -> comms stay DOWN
//
// The fixture commits a change that is NOT a transport change and asserts the
// key is identical as a precondition, so a repair that merely widened the key
// comparison cannot pass it.
func TestStepTwentyRestartsWhenATeardownOwesOne_7901(t *testing.T) {
	store := clusteredStore7066(t)
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
	d.startClusterComms(ctx)
	if d.activeTransport() == (clusterTransportKey{}) {
		t.Fatal("premise: comms must publish a NON-ZERO transport, or step 20's " +
			"`active != zero` conjunct is false for a reason unrelated to teardown")
	}
	started := d.activeTransport()

	// The bootstrap-rollback shape: stop, mark the owed restart, do NOT start.
	d.stopClusterComms()
	d.markClusterCommsRestartNeeded()

	restarts := 0
	d.startClusterCommsFn = func(context.Context) { restarts++ }

	corrected := store.ActiveConfig()
	corrected.Chassis.Cluster.HeartbeatInterval = 250
	if got := clusterTransportFromConfig(corrected); got != started {
		t.Fatalf("premise: this fixture must leave the transport key IDENTICAL "+
			"(started=%+v corrected=%+v); otherwise it re-tests the key-moved row "+
			"the #7072 cell already covers", started, got)
	}
	_ = d.applyTailReconciles(corrected, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)

	if restarts != 1 {
		t.Errorf("comms stayed DOWN after a corrected commit with an identical "+
			"transport key (restarts=%d). Recovery must not depend on the correction "+
			"happening to move an endpoint: bootstrap.go's rollback teardown is a "+
			"stop-without-start and the only other production startClusterComms site "+
			"is the daemon_run.go boot path, so the node holds a valid cluster config "+
			"with no heartbeat, no session sync and no fabric refresh until the "+
			"process restarts (#7901)", restarts)
	}

	// The recovery is ONE-SHOT. A second apply must not restart again: the flag
	// is consumed, not read. Without this the cell above passes equally for a
	// live "are comms down?" predicate, which fires on every apply and breaks
	// #5078 (a key commit must not restart comms) and #6878 (an unchanged
	// transport must not restart) — measured, three cells across those two.
	_ = d.applyTailReconciles(corrected, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)
	if restarts != 1 {
		t.Errorf("a SECOND apply restarted comms again (restarts=%d, want 1). The "+
			"owed restart must be consumed, not re-read: a live down-predicate fires "+
			"on every apply and reintroduces #5078/#6878 (#7901)", restarts)
	}
}
