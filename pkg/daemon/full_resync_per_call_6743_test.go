package daemon

import (
	"context"
	"sync/atomic"
	"testing"

	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// #2114 / #6743 r2 B8: handleEventStreamFullResync must resolve its session
// exporter from the cell ON EVERY CALL.
//
// WHAT WAS UNBOUND, measured at 710a87569 with BUILD_RC=0: replacing the
// per-call `exporter, ok := d.dataplane().(userspaceSessionExporter)`
// (daemon_ha_userspace_stream.go) with a latch that captures the FIRST
// published backend and reuses it forever left pkg/daemon FULL_RC=0. No
// assertion fired.
//
// WHY IT MATTERS HERE SPECIFICALLY. This is the pre-#2114 capture shape,
// on the path that pushes a FULL session export into cluster session-sync.
// A full resync is requested when the helper's replay buffer was trimmed
// past our last ack, i.e. exactly when the standby's session table is
// already known to be behind. The commit-confirmed rollback calls
// Teardown() and deliberately leaves the object in the cell so a corrected
// commit can re-arm — see the "A torn-down backend can still be published"
// note in pkg/daemon/README.md — so after a rollback and a corrected
// re-arm the cell holds a DIFFERENT backend. A latch would keep exporting
// from the torn-down one: the standby is handed the retired backend's
// session view as its catch-up state, and the divergence the resync exists
// to repair is instead written in.
//
// HOW THE PROPERTY IS MADE OBSERVABLE. With a steady cell a latch and a
// per-call resolution return the same object, so nothing distinguishes
// them. The test therefore REPUBLISHES between two calls and asserts on
// which backend each call reached. That is an identity assertion, not a
// count: a guard that only counted exports would pass under the latch
// (two calls, two exports — both from the wrong backend).

// resyncExporterDP is a publishable backend that records whether its
// ExportOwnerRGSessionsPaged was called, and with which RG set.
type resyncExporterDP struct {
	runtimeOnlyApplyTestDP
	name    string
	exports atomic.Int64
	lastRGs atomic.Value // []int
}

func newResyncExporterDP(name string) *resyncExporterDP {
	return &resyncExporterDP{name: name}
}

func (r *resyncExporterDP) ExportOwnerRGSessionsPagedStream(rgIDs []int, sink dpuserspace.OwnerRGExportPageSink) (
	dpuserspace.ProcessStatus, int, error,
) {
	r.exports.Add(1)
	r.lastRGs.Store(append([]int(nil), rgIDs...))
	return dpuserspace.ProcessStatus{}, 0, nil
}

var _ userspaceSessionExporter = (*resyncExporterDP)(nil)

// TestFullResyncResolvesTheExporterPerCall is the fail-on-revert guard.
//
// RED-on-revert: replace the per-call
// `exporter, ok := d.dataplane().(userspaceSessionExporter)` in
// handleEventStreamFullResync with a latch over the first published
// backend.
func TestFullResyncResolvesTheExporterPerCall(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	d := &Daemon{
		cluster: clusterManagerPrimaryForRGs(0, 1),
		store: testStoreWithSetConfig(t, []string{
			"set system dataplane-type userspace",
			"set chassis cluster cluster-id 1",
			"set chassis cluster control-interface em0",
			"set chassis cluster peer-address 10.99.0.2",
			"set chassis cluster authentication-key test-cluster-psk-6743",
			"set chassis cluster node 0",
			"set chassis cluster redundancy-group 0 node 0 priority 200",
			"set chassis cluster redundancy-group 1 node 0 priority 200",
		}),
	}
	d.sessionSync = connectedSyncPairForDrainTest(t, ctx)

	// CONTROLS on the gates handleEventStreamFullResync takes before it
	// ever reaches the exporter resolution. Without these a green run could
	// mean "the export never happened" rather than "the export used the
	// right backend".
	if !d.cluster.IsLocalPrimaryAny() {
		t.Fatal("test setup: node must be primary for some RG or the export is unreachable")
	}
	cfg := d.store.ActiveConfig()
	if cfg == nil {
		t.Fatal("test setup: ActiveConfig() is nil, the export is unreachable")
	}
	if len(d.primaryOwnerRGIDs(cfg)) == 0 {
		t.Fatal("test setup: no primary-owned RGs, so exportUserspaceOwnerRGSessionsWithConfig " +
			"returns early and the exporter is never called")
	}

	first := newResyncExporterDP("A")
	d.setDataplane(first)

	if ok := d.handleEventStreamFullResync(); !ok {
		t.Fatal("first full resync reported failure: the export path did not complete, so " +
			"this test cannot observe which backend it used")
	}
	if got := first.exports.Load(); got != 1 {
		t.Fatalf("first backend's ExportOwnerRGSessionsPaged calls = %d, want 1 — the first "+
			"resync did not reach the exporter at all, so the republication below "+
			"distinguishes nothing", got)
	}

	// The corrected re-arm after a commit-confirmed rollback: a DIFFERENT
	// backend is published while the daemon keeps running.
	second := newResyncExporterDP("B")
	d.setDataplane(second)

	if ok := d.handleEventStreamFullResync(); !ok {
		t.Fatal("second full resync reported failure")
	}

	// THE PROPERTY.
	if got := second.exports.Load(); got != 1 {
		t.Fatalf("the CURRENTLY published backend's ExportOwnerRGSessionsPaged calls = %d, "+
			"want 1: handleEventStreamFullResync latched its exporter instead of "+
			"resolving the #2114 cell per call, so a full resync after a rollback and "+
			"re-arm exports the standby's catch-up state from a torn-down backend "+
			"(#6743 r2-B8)", got)
	}
	if got := first.exports.Load(); got != 1 {
		t.Fatalf("the SUPERSEDED backend's ExportOwnerRGSessionsPaged calls = %d, want it to "+
			"stay 1: the second resync dispatched into a backend the daemon had already "+
			"replaced", got)
	}
}

// TestFullResyncDeclinesOnADisownedCell is the fail-closed half, in a
// SEPARATE body: after setDataplane(nil) the resync must report failure so
// the caller retries, rather than succeeding against a retired backend or
// silently reporting a completed export that never happened.
//
// A latch would make this arm succeed — it would still hold backend A —
// which is the same defect seen from the other side, and it is asserted
// separately so it is observed running under the mutation rather than
// sitting behind the guard above's t.Fatal.
func TestFullResyncDeclinesOnADisownedCell(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	d := &Daemon{
		cluster: clusterManagerPrimaryForRGs(0),
		store: testStoreWithSetConfig(t, []string{
			"set system dataplane-type userspace",
			"set chassis cluster cluster-id 1",
			"set chassis cluster control-interface em0",
			"set chassis cluster peer-address 10.99.0.2",
			"set chassis cluster authentication-key test-cluster-psk-6743",
			"set chassis cluster node 0",
			"set chassis cluster redundancy-group 0 node 0 priority 200",
		}),
	}
	d.sessionSync = connectedSyncPairForDrainTest(t, ctx)

	backend := newResyncExporterDP("A")
	d.setDataplane(backend)
	if ok := d.handleEventStreamFullResync(); !ok {
		t.Fatal("control: the resync must succeed while a backend IS published, or the " +
			"decline below proves nothing")
	}
	if got := backend.exports.Load(); got != 1 {
		t.Fatalf("control: exports = %d, want 1", got)
	}

	d.setDataplane(nil)

	if ok := d.handleEventStreamFullResync(); ok {
		t.Fatal("full resync reported SUCCESS on a disowned cell: the caller will not " +
			"retry, so the standby is left behind with no further resync attempt")
	}
	if got := backend.exports.Load(); got != 1 {
		t.Fatalf("the disowned backend's ExportOwnerRGSessionsPaged calls = %d, want it to "+
			"stay 1: the resync dispatched into a backend the daemon no longer publishes", got)
	}
}
