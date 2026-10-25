package daemon

import (
	"errors"
	"testing"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// recordingExporter captures the arguments the cold-prime snapshot passes to
// ExportOwnerRGSessionsPaged so the test can assert on them, and can be made to
// fail.
type recordingExporter struct {
	deltas   []dpuserspace.SessionDeltaInfo
	err      error
	calls    int
	gotRGIDs []int
}

func (r *recordingExporter) ExportOwnerRGSessionsPagedStream(rgIDs []int, sink dpuserspace.OwnerRGExportPageSink) (dpuserspace.ProcessStatus, int, error) {
	r.calls++
	r.gotRGIDs = append([]int(nil), rgIDs...)
	if r.err != nil {
		return dpuserspace.ProcessStatus{}, 0, r.err
	}
	if len(r.deltas) > 0 {
		if err := sink.OnOwnerRGExportPage(append([]dpuserspace.SessionDeltaInfo(nil), r.deltas...)); err != nil {
			return dpuserspace.ProcessStatus{}, 0, err
		}
	}
	return dpuserspace.ProcessStatus{}, len(r.deltas), nil
}

func snapshot6031Daemon() (*Daemon, *cluster.SessionSync, *config.Config) {
	ss := &cluster.SessionSync{
		IsPrimaryFn:      func() bool { return true },
		IsPrimaryForRGFn: func(rgID int) bool { return rgID == 1 },
	}
	d := &Daemon{sessionSync: ss}
	cfg := &config.Config{}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"lan": {Name: "lan"},
		"wan": {Name: "wan"},
	}
	return d, ss, cfg
}

func transitDelta6031(srcPort uint16) dpuserspace.SessionDeltaInfo {
	return dpuserspace.SessionDeltaInfo{
		Event:         "open",
		AddrFamily:    dataplane.AFInet,
		Protocol:      6,
		SrcIP:         "10.0.61.102",
		DstIP:         "172.16.80.200",
		SrcPort:       srcPort,
		DstPort:       5201,
		IngressZone:   "lan",
		EgressZone:    "wan",
		OwnerRGID:     1,
		EgressIfindex: 12,
	}
}

// hasV4 reports whether snap frames the session the given delta converts to.
// The expected key is derived through the PRODUCTION converter rather than
// hand-built: SessionKey ports are stored in network byte order, so a hand-built
// host-order comparison silently never matches and every assertion would pass or
// fail for the wrong reason.
func hasV4(t *testing.T, snap cluster.BulkSnapshot, cfg *config.Config, delta dpuserspace.SessionDeltaInfo) bool {
	t.Helper()
	want, _, ok := userspaceSessionFromDeltaV4(delta, buildZoneIDs(cfg))
	if !ok {
		t.Fatalf("fixture: delta %+v does not convert; the assertion would be vacuous", delta)
	}
	for _, e := range snap.V4 {
		if e.Key == want {
			return true
		}
	}
	return false
}

// TestUserspaceBulkSnapshotGathersUnboundedTableTruth6031 pins the two
// properties the cold-prime window depends on:
//
//   - the set comes from the helper's in-process SessionTable, filtered to the
//     RGs this node is primary for, NOT from the BPF conntrack display mirror
//     BulkSync walks; and
//   - the window is COMPLETE. Since #5085 every eligible session missing from
//     it is DELETED on the peer, so a truncated window silently destroys
//     sessions N+1..end.
//
// #9344 changed HOW the second property is held, and this cell changed with it.
// It used to assert `max == 0` on the exporter call, because unbounded was the
// only complete request the daemon could make. The cap knob is now gone from
// this interface entirely — completeness is decided in the Manager, which knows
// the helper's paging contract and pages or falls back accordingly — so the
// assertion here is STRUCTURAL: there is no cap to get wrong at this layer.
// The behavioural half moved to the Manager, where
// TestOwnerRGExportPagesUntilTheHelperSaysNoMore9344 and its siblings drive it;
// asserting `max == 0` here after the change would have been asserting a
// parameter that no longer exists.
func TestUserspaceBulkSnapshotGathersUnboundedTableTruth6031(t *testing.T) {
	d, ss, cfg := snapshot6031Daemon()
	exporter := &recordingExporter{deltas: []dpuserspace.SessionDeltaInfo{transitDelta6031(39906)}}

	snap, err := d.userspaceBulkSnapshotWithConfig(exporter, ss, cfg, []int{1})
	if err != nil {
		t.Fatalf("userspaceBulkSnapshotWithConfig() error = %v", err)
	}
	if exporter.calls != 1 {
		t.Fatalf("ExportOwnerRGSessionsPaged calls = %d, want 1", exporter.calls)
	}
	if len(exporter.gotRGIDs) != 1 || exporter.gotRGIDs[0] != 1 {
		t.Fatalf("ExportOwnerRGSessionsPaged rgIDs = %v, want [1]", exporter.gotRGIDs)
	}
	if !hasV4(t, snap, cfg, transitDelta6031(39906)) {
		t.Fatalf("snapshot must carry the exported transit session; got V4 = %+v", snap.V4)
	}
}

// TestUserspaceBulkSnapshotAppliesTheIncrementalFilter6031 pins that the bulk
// window and the incremental delta stream admit ONE set.
//
// Both run through walkUserspaceSessionDeltas, so a session the incremental path
// refuses to sync (a host-bound local_delivery session, whose node-local
// ifindexes and addresses are meaningless on the peer) must not appear in the
// window either — and, symmetrically, a session it DOES sync must appear, or the
// peer deletes the copy the delta stream gave it.
//
// RED-on-revert: build the snapshot from the raw deltas without the filter and
// the local_delivery session lands in the window.
func TestUserspaceBulkSnapshotAppliesTheIncrementalFilter6031(t *testing.T) {
	d, ss, cfg := snapshot6031Daemon()

	syncable := transitDelta6031(39906)
	hostBound := transitDelta6031(51000)
	hostBound.Disposition = "local_delivery"
	// A session owned by an RG this node is NOT primary for: the incremental
	// path filters it out, so the window must not claim it either.
	foreignRG := transitDelta6031(39907)
	foreignRG.OwnerRGID = 7

	exporter := &recordingExporter{deltas: []dpuserspace.SessionDeltaInfo{syncable, hostBound, foreignRG}}

	snap, err := d.userspaceBulkSnapshotWithConfig(exporter, ss, cfg, []int{1})
	if err != nil {
		t.Fatalf("userspaceBulkSnapshotWithConfig() error = %v", err)
	}
	if !hasV4(t, snap, cfg, syncable) {
		t.Fatal("a syncable transit session must be in the window; omitting it makes the peer DELETE its copy")
	}
	if hasV4(t, snap, cfg, hostBound) {
		t.Fatal("a local_delivery session must be filtered out of the window, exactly as the incremental path filters it")
	}
	if hasV4(t, snap, cfg, foreignRG) {
		t.Fatal("a session owned by an RG this node is not primary for must be filtered out of the window")
	}
}

// TestUserspaceBulkSnapshotRetractsAClosedSession6031 pins the close handling.
// The export drains the same per-binding delta buffers the incremental path
// reads, so an exported open and a later close for the same key can arrive in
// ONE batch. Framing the already-closed session would resurrect it on the peer,
// which then holds a session the primary no longer has — the stale-permit shape
// #5085 exists to prevent.
//
// RED-on-revert: make snapshotDeltaSink.deleteV4 a no-op and the closed session
// stays in the window.
func TestUserspaceBulkSnapshotRetractsAClosedSession6031(t *testing.T) {
	d, ss, cfg := snapshot6031Daemon()

	open := transitDelta6031(39906)
	closed := transitDelta6031(39906)
	closed.Event = "close"
	survivor := transitDelta6031(39908)

	exporter := &recordingExporter{deltas: []dpuserspace.SessionDeltaInfo{open, closed, survivor}}

	snap, err := d.userspaceBulkSnapshotWithConfig(exporter, ss, cfg, []int{1})
	if err != nil {
		t.Fatalf("userspaceBulkSnapshotWithConfig() error = %v", err)
	}
	if hasV4(t, snap, cfg, open) {
		t.Fatal("a session closed within the exported batch must be retracted from the window, not framed as live")
	}
	if !hasV4(t, snap, cfg, survivor) {
		t.Fatal("the retraction must remove only the closed key")
	}
}

// TestUserspaceBulkSnapshotPropagatesExportFailure6031 pins fail-closed at the
// daemon boundary. An export failure must surface as an error, never as an empty
// snapshot: an empty snapshot is an ASSERTION that this node owns nothing, and
// doBulkSync would frame it as authoritative, making the peer delete every
// session it holds for our RGs.
//
// RED-on-revert: swallow the error and return the empty snapshot; the error
// assertion fires.
func TestUserspaceBulkSnapshotPropagatesExportFailure6031(t *testing.T) {
	d, ss, cfg := snapshot6031Daemon()
	boom := errors.New("helper control socket timed out")
	exporter := &recordingExporter{err: boom}

	snap, err := d.userspaceBulkSnapshotWithConfig(exporter, ss, cfg, []int{1})
	if err == nil {
		t.Fatalf("#6031: a failed export must be an ERROR, not an empty authoritative snapshot; got %+v", snap)
	}
	if !errors.Is(err, boom) {
		t.Fatalf("error = %v, want it to wrap %v", err, boom)
	}
}

// TestUserspaceBulkSnapshotRequiresAnExporter6031 pins the same fail-closed
// direction for the resolution path: with no session sync, no active config, or
// a dataplane that cannot export table truth, userspaceBulkSnapshot must error
// rather than hand doBulkSync an empty window.
func TestUserspaceBulkSnapshotRequiresAnExporter6031(t *testing.T) {
	d, ss, cfg := snapshot6031Daemon()

	if _, err := d.userspaceBulkSnapshotWithConfig(nil, ss, cfg, []int{1}); err == nil {
		t.Fatal("a nil exporter must error, not yield an empty authoritative snapshot")
	}
	exporter := &recordingExporter{}
	if _, err := d.userspaceBulkSnapshotWithConfig(exporter, nil, cfg, []int{1}); err == nil {
		t.Fatal("a nil session sync must error, not yield an empty authoritative snapshot")
	}
	if _, err := d.userspaceBulkSnapshotWithConfig(exporter, ss, nil, []int{1}); err == nil {
		t.Fatal("a nil active config must error, not yield an empty authoritative snapshot")
	}
	if exporter.calls != 0 {
		t.Fatalf("no export should be attempted when a precondition fails; calls = %d", exporter.calls)
	}
}
