package daemon

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	"github.com/psaab/xpf/pkg/vrrp"
)

// #7259 — the #6031 fix depends on ONE assignment that nothing asserts.
//
// The two halves are independently useless: pkg/cluster consults
// SessionSync.BulkSnapshotSource and fails closed when it errors, and pkg/daemon
// can build the table-truth snapshot. The residual only closes because
// startClusterComms joins them:
//
//	ss.BulkSnapshotSource = d.userspaceBulkSnapshot
//
// Delete that line and every #6031 test still passes — they all call
// userspaceBulkSnapshot{,WithConfig} directly, or set BulkSnapshotSource
// themselves. Meanwhile doBulkSync takes its `src == nil` branch, falls through
// to BulkSync(), and frames the window from the BPF display mirror the helper's
// transit forward install never publishes to. Since #5085 the receiver DELETES
// every eligible session absent from the window, so the standby's live
// peer-owned transit sessions go again — with a green suite.

// wiringExporterDP is a RuntimeDataPlane whose live surface is the table-truth
// export plus the two accessors SessionSync.SetRuntime reaches. The nil embed
// panics if the wiring path touches anything else, which keeps the fake honest.
type wiringExporterDP struct {
	dataplane.RuntimeDataPlane
	exporter *recordingExporter
}

func (d *wiringExporterDP) ExportOwnerRGSessionsPagedStream(rgIDs []int, sink dpuserspace.OwnerRGExportPageSink) (dpuserspace.ProcessStatus, int, error) {
	return d.exporter.ExportOwnerRGSessionsPagedStream(rgIDs, sink)
}

func (d *wiringExporterDP) Mode() dpuserspace.DataplaneMode { return dpuserspace.ModeUserspaceStrict }

// HA returns a no-op controller (#7350).
//
// The embedded dataplane.RuntimeDataPlane is NIL, so before this the promoted
// HA() dispatched into a nil interface. startClusterComms launches the HA
// watchdog heartbeat, whose goroutine calls rt.HA().SetHAWatchdog on a ticker,
// so this fixture carried a latent SIGSEGV that fired roughly half a second in.
//
// Nothing noticed because the test used to reach its assertion within
// milliseconds and tear the daemon down before the first tick. The moment the
// test WAITED for anything — which is exactly what #7350's fix requires — the
// panic became reachable, and a panic takes the whole package binary down
// rather than failing one test.
//
// A no-op is the honest double here: this test is about wiring, not about what
// the watchdog writes, and returning a controller that records nothing keeps
// the goroutine harmless without pretending to model it.
func (d *wiringExporterDP) HA() dataplane.HAController { return noopHAController7350{} }

type noopHAController7350 struct{}

func (noopHAController7350) SetRGActive(context.Context, int, bool) error     { return nil }
func (noopHAController7350) SetHAWatchdog(context.Context, int, uint64) error { return nil }
func (noopHAController7350) SetFabricForwarding(context.Context, dataplane.FabricID, dataplane.FabricFwdInfo) error {
	return nil
}
func (noopHAController7350) SyncFabricState(context.Context) error { return nil }

// Sessions/Telemetry are reached by SessionSync.SetRuntime. nil is the
// "no store wired" case the sync layer already guards for — this test is about
// the SOURCE, not about the store walk it exists to replace.
func (d *wiringExporterDP) Sessions() dataplane.SessionStore { return nil }

func (d *wiringExporterDP) Telemetry() dataplane.Telemetry { return nil }

// TestStartClusterCommsWiresBulkSnapshotSource7259 drives the REAL
// startClusterComms and then INVOKES the source it published.
//
// Asserting `BulkSnapshotSource != nil` alone would pass with any function
// assigned to the field, so the round trip is the load-bearing part: an
// export-capable runtime is published, the wired source is called, and the
// session that came out of ExportOwnerRGSessions must be in the snapshot. That
// identifies the wired function as the table-truth resolver rather than merely
// as "something".
//
// RED-on-revert: delete `ss.BulkSnapshotSource = d.userspaceBulkSnapshot` from
// startClusterComms and the nil assertion fires; assign a different producer and
// the round-trip assertion fires.
func TestStartClusterCommsWiresBulkSnapshotSource7259(t *testing.T) {
	store := newConfigStore(t, filepath.Join(t.TempDir(), "config.db"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	// A clustered active whose sync endpoint RESOLVES: lo carries 127.0.0.1/8,
	// which selectClusterBindAddr matches against the 127.0.0.2 peer, so the
	// sync constructor goroutine gets past its address retry loop and reaches
	// the callback-wiring block.
	//
	// The endpoint is the FABRIC transport, not control-link, deliberately.
	// startClusterComms starts the heartbeat only when control-interface AND
	// peer-address are both set, and cluster.Manager.StartHeartbeat reads
	// m.hbSender/m.hbReceiver OUTSIDE m.mu while StopHeartbeat nils them under
	// it (#7257) — a PRE-EXISTING race this test has no business exposing. The
	// sync constructor takes the `syncIface == ""` fall-back to
	// fabric-interface/fabric-peer-address and reaches the identical wiring.
	// TestActiveClusterTransportIsMutexGuarded_6290 avoids the same hazard by
	// configuring no sync endpoint at all.
	for _, line := range []string{
		"chassis cluster cluster-id 1",
		"chassis cluster node 0",
		"chassis cluster fabric-interface lo",
		"chassis cluster fabric-peer-address 127.0.0.2",
		"chassis cluster redundancy-group 0 node 0 priority 200",
		"chassis cluster redundancy-group 0 node 1 priority 100",
		"chassis cluster authentication-key test-cluster-psk-7259",
		"security zones security-zone lan",
		"security zones security-zone wan",
	} {
		if err := store.SetFromInput(line); err != nil {
			t.Fatalf("set %q: %v", line, err)
		}
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}

	// The delta the helper's table-truth export will hand back. OwnerRGID 0
	// matches the single configured redundancy group this node is primary for,
	// so the snapshot's eligibility filter admits it.
	exported := transitDelta6031(39906)
	exported.OwnerRGID = 0
	exporter := &recordingExporter{deltas: []dpuserspace.SessionDeltaInfo{exported}}

	d := &Daemon{
		store:    store,
		opts:     Options{NoDataplane: true},
		cluster:  newClusterManager(true),
		vrrpMgr:  vrrp.NewManager(),
		rgStates: make(map[int]*rgStateMachine),
	}
	// Publish the export-capable runtime BEFORE comms start: startClusterComms
	// wires the ownership predicates (IsPrimaryFn / IsPrimaryForRGFn) only when
	// a runtime is published, and the snapshot's eligibility filter consults
	// them.
	d.setDataplane(&wiringExporterDP{exporter: exporter})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d.startClusterComms(ctx)
	t.Cleanup(d.stopClusterComms)

	// #7350: WAIT FOR THE ASSERTED PROPERTY, NOT A PROXY FOR IT.
	//
	// startClusterComms publishes the SessionSync BEFORE it wires it —
	// deliberately, because publishSessionSyncIfCurrent is the generation check
	// that drops a superseded constructor's object before it touches cluster
	// state (the Order contract at daemon_ha_comms_wiring.go:128). So
	// getSessionSync() goes non-nil several wiring calls before
	// BulkSnapshotSource is assigned in wireSessionSyncPeerCallbacks.
	//
	// This loop used to exit on the OBJECT and then immediately assert the
	// FIELD, with nothing ordering the two. It lost 1 run in 5 under
	// full-suite scheduling pressure and passed 3/3 under a -run filter — the
	// signature of a window, not of a defect in what it was testing. Any
	// future change that adds wiring between the publish and this field widens
	// it again, which is why the wait condition itself has to be the property.
	//
	// NOT fixable by wiring before publishing: that inverts the deliberate
	// order above.
	//
	// The two waited-for states are tracked separately so a failure says WHICH
	// one was reached. "Never published" and "published but never wired" are
	// different defects, and collapsing them would send the next reader to the
	// wrong half of startClusterComms.
	var ss *cluster.SessionSync
	published := false
	for deadline := time.Now().Add(15 * time.Second); time.Now().Before(deadline); {
		if cand := d.getSessionSync(); cand != nil {
			published = true
			if cand.BulkSnapshotSource != nil {
				ss = cand
				break
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	if ss == nil && !published {
		t.Fatal("setup: startClusterComms never published a SessionSync")
	}
	// The deadline path MUST fail with the #7259 message rather than fall
	// through. A wait-for-the-field rewrite that let a never-wired field time
	// out into a PASS would silently convert this regression guard into a
	// no-op — the #7259 property must stay bound, not become a timeout.
	if ss == nil {
		t.Fatal("#7259: startClusterComms published a SessionSync with NO BulkSnapshotSource — " +
			"doBulkSync takes its src==nil branch and frames the cold-prime window from the " +
			"BPF display mirror, which is blind to transit sessions, so the standby's live " +
			"peer-owned sessions are reconciled away (#6031 regressed, silently)")
	}

	snap, err := ss.BulkSnapshotSource()
	if err != nil {
		t.Fatalf("wired BulkSnapshotSource() error = %v", err)
	}
	if exporter.calls != 1 {
		t.Fatalf("export_owner_rg_sessions calls = %d, want 1 — the function wired into "+
			"BulkSnapshotSource is not the table-truth resolver", exporter.calls)
	}
	cfg := store.ActiveConfig()
	if cfg == nil {
		t.Fatal("setup: no active config")
	}
	if !hasV4(t, snap, cfg, exported) {
		t.Fatalf("the wired source returned %d v4 entries and none is the exported session — "+
			"the field carries some other producer", len(snap.V4))
	}
}
