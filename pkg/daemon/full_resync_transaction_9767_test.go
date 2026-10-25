package daemon

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// #9766 / #9767: the FullResync export is one transaction. Its frame is
// acknowledged only if the whole export reached the send queue, and the
// fallback loop's drain cannot queue a delta in the middle of it.
// resyncDeltaExporterDP is a publishable backend whose owner-RG export returns
// fixed deltas. during, when set, runs inside the export after its snapshot.
type resyncDeltaExporterDP struct {
	runtimeOnlyApplyTestDP
	deltas     []dpuserspace.SessionDeltaInfo
	during     func()
	exports    atomic.Int64
	exported   chan struct{}
	exportOnce sync.Once
}

func (r *resyncDeltaExporterDP) ExportOwnerRGSessionsPagedStream(rgIDs []int, sink dpuserspace.OwnerRGExportPageSink) (
	dpuserspace.ProcessStatus, int, error,
) {
	r.exports.Add(1)
	if r.exported != nil {
		r.exportOnce.Do(func() { close(r.exported) })
	}
	if r.during != nil {
		r.during()
	}
	if len(r.deltas) > 0 {
		if err := sink.OnOwnerRGExportPage(append([]dpuserspace.SessionDeltaInfo(nil), r.deltas...)); err != nil {
			return dpuserspace.ProcessStatus{}, 0, err
		}
	}
	return dpuserspace.ProcessStatus{}, len(r.deltas), nil
}

var _ userspaceSessionExporter = (*resyncDeltaExporterDP)(nil)

// transitOpen9767 is a transit session on RG 1, which the fixture's node owns.
func transitOpen9767() dpuserspace.SessionDeltaInfo {
	return dpuserspace.SessionDeltaInfo{
		Event:         "open",
		AddrFamily:    dataplane.AFInet,
		Protocol:      6,
		SrcIP:         "10.0.61.102",
		DstIP:         "172.16.80.200",
		SrcPort:       39906,
		DstPort:       5201,
		IngressZone:   "lan",
		EgressZone:    "wan",
		OwnerRGID:     1,
		EgressIfindex: 12,
		TXIfindex:     11,
		TXVLANID:      80,
		NeighborMAC:   "aa:bb:cc:dd:ee:ff",
		SrcMAC:        "02:bf:72:00:50:08",
	}
}

// transitOpenV6_9767 is transitOpen9767's IPv6 twin.
func transitOpenV6_9767() dpuserspace.SessionDeltaInfo {
	delta := transitOpen9767()
	delta.AddrFamily = dataplane.AFInet6
	delta.SrcIP = "2001:559:8585:bf01::102"
	delta.DstIP = "2001:559:8585:80::200"
	return delta
}

// resyncFixture9767 is a node primary for RG 0 and RG 1 whose session sync
// reads connected but has no writer, so its send queue holds exactly what the
// FullResync queued.
func resyncFixture9767(t *testing.T, deltas ...dpuserspace.SessionDeltaInfo) (*Daemon, *cluster.SessionSync, *resyncDeltaExporterDP) {
	t.Helper()
	d := &Daemon{
		cluster: clusterManagerPrimaryForRGs(0, 1),
		store: testStoreWithSetConfig(t, []string{
			"set system dataplane-type userspace",
			"set chassis cluster cluster-id 1",
			"set chassis cluster authentication-key test-cluster-psk-9767",
			"set chassis cluster node 0",
			"set chassis cluster redundancy-group 0 node 0 priority 200",
			"set chassis cluster redundancy-group 1 node 0 priority 200",
			"set security zones security-zone lan",
			"set security zones security-zone wan",
		}),
		fullResyncInstallWaitForTest: 50 * time.Millisecond,
	}
	ss := cluster.NewSessionSync("127.0.0.1:0", "127.0.0.1:1", nil)
	ss.IsPrimaryFn = func() bool { return true }
	ss.IsPrimaryForRGFn = func(rgID int) bool { return rgID == 0 || rgID == 1 }
	ss.SetConnectedForTesting(true)
	d.sessionSync = ss
	exporter := &resyncDeltaExporterDP{deltas: deltas}
	d.setDataplane(exporter)
	if cfg := d.store.ActiveConfig(); cfg == nil || len(d.primaryOwnerRGIDs(cfg)) == 0 {
		t.Fatal("setup: the node owns no configured RG, so the FullResync never reaches the export")
	}
	return d, ss, exporter
}

// queuedTypes9767 empties the send queue and returns its message types in order.
func queuedTypes9767(ss *cluster.SessionSync) []string {
	var types []string
	for {
		typ, ok := ss.TakeQueuedMessageTypeForTesting(0)
		if !ok {
			return types
		}
		types = append(types, typ)
	}
}

func TestFullResyncIsNotAcknowledgedWhenAnInstallMissesTheSendQueue_9767(t *testing.T) {
	for _, tc := range []struct {
		name  string
		delta dpuserspace.SessionDeltaInfo
		want  string
	}{
		{"v4", transitOpen9767(), "session_v4"},
		{"v6", transitOpenV6_9767(), "session_v6"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, ss, exporter := resyncFixture9767(t, tc.delta)
			ss.FillSendQueueForTesting()

			if d.handleEventStreamFullResync() {
				t.Fatal("#9767: the export's install found the send queue full for its whole wait and was " +
					"dropped, yet the FullResync reported success. The frame is acknowledged, the helper trims " +
					"past the barrier, and the standby never receives the session")
			}
			if got := exporter.exports.Load(); got != 1 {
				t.Fatalf("control: exports = %d, want 1; the decline must come from admission, not from a "+
					"gate before the export", got)
			}

			queuedTypes9767(ss)
			d.fullResyncRetryAt.Store(0) // the backoff passes
			if !d.handleEventStreamFullResync() {
				t.Fatal("control: with room in the send queue the same resync must be acknowledged")
			}
			if got := queuedTypes9767(ss); len(got) != 1 || got[0] != tc.want {
				t.Fatalf("control: the acknowledged resync queued %v, want [%s]", got, tc.want)
			}
		})
	}
}

func TestFullResyncIsNotAcknowledgedWhenTheSchemaGateWithholdsTheBatch_9767(t *testing.T) {
	d, ss, exporter := resyncFixture9767(t, transitOpen9767())
	local := localSessionDeltaSchemaFingerprint()
	mismatched := local + 1
	if mismatched == 0 {
		mismatched = 2
	}
	d.recordUserspaceDeltaSchema(mismatched)

	if d.handleEventStreamFullResync() {
		t.Fatal("#9767: the #7194 schema gate withheld the whole export, yet the FullResync reported " +
			"success, so the frame is acknowledged with nothing sent")
	}
	if got := exporter.exports.Load(); got != 1 {
		t.Fatalf("control: exports = %d, want 1", got)
	}
	if got := queuedTypes9767(ss); len(got) != 0 {
		t.Fatalf("control: the withheld batch queued %v", got)
	}

	d.recordUserspaceDeltaSchema(local)
	d.fullResyncRetryAt.Store(0)
	if !d.handleEventStreamFullResync() {
		t.Fatal("control: with a matching schema the resync must be acknowledged")
	}
}

func TestFullResyncRetryInsideTheBackoffDoesNotReExport_9767(t *testing.T) {
	d, ss, exporter := resyncFixture9767(t, transitOpen9767())
	ss.FillSendQueueForTesting()
	if d.handleEventStreamFullResync() {
		t.Fatal("setup: the incomplete admission must decline")
	}
	queuedTypes9767(ss)

	for i := 0; i < 3; i++ {
		if d.handleEventStreamFullResync() {
			t.Fatal("#9767: a retry inside the backoff reported success without exporting")
		}
	}
	if got := exporter.exports.Load(); got != 1 {
		t.Fatalf("#9767: %d exports, want 1. The event stream retries a withheld FullResync on every later "+
			"frame and every 100 ms ACK tick, and each retry inside the backoff re-ran the synchronous "+
			"helper export", got)
	}

	d.fullResyncRetryAt.Store(0) // the backoff passes
	if !d.handleEventStreamFullResync() {
		t.Fatal("control: after the backoff, with room in the queue, the retry must be acknowledged")
	}
	if got := exporter.exports.Load(); got != 2 {
		t.Fatalf("control: exports = %d after the backoff, want 2", got)
	}
}

func TestFullResyncPacesAnExportLargerThanTheFreeQueue_9767(t *testing.T) {
	v4b := transitOpen9767()
	v4b.SrcPort = 39907
	for _, tc := range []struct {
		name   string
		deltas []dpuserspace.SessionDeltaInfo
		want   []string
	}{
		{"v4", []dpuserspace.SessionDeltaInfo{transitOpen9767(), v4b}, []string{"session_v4", "session_v4"}},
		{"v6", []dpuserspace.SessionDeltaInfo{transitOpenV6_9767()}, []string{"session_v6"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, ss, exporter := resyncFixture9767(t, tc.deltas...)
			d.fullResyncInstallWaitForTest = 5 * time.Second
			fillers := ss.FillSendQueueForTesting()

			// The writer frees room only after the export has taken its snapshot,
			// so the export's FIRST install meets a full queue, and a lossy
			// enqueue drops it at once. Each family gets its own subtest: once
			// the writer is running, a later install finds room either way.
			exported := make(chan struct{})
			exporter.during = func() { close(exported) }
			var got []string
			writerDone := make(chan struct{})
			go func() {
				defer close(writerDone)
				<-exported
				time.Sleep(100 * time.Millisecond)
				for {
					typ, ok := ss.TakeQueuedMessageTypeForTesting(time.Second)
					if !ok {
						return
					}
					got = append(got, typ)
				}
			}()

			if !d.handleEventStreamFullResync() {
				t.Fatal("#9767: the writer freed room within the install wait, so the whole export must go " +
					"through, paced; the resync was declined instead")
			}
			<-writerDone
			if len(got) != fillers+len(tc.want) {
				t.Fatalf("the writer saw %d messages, want %d fillers and then %v", len(got), fillers, tc.want)
			}
			for i, typ := range got {
				want := "filler"
				if i >= fillers {
					want = tc.want[i-fillers]
				}
				if typ != want {
					t.Fatalf("send-queue message %d = %q, want %q: the export must follow what was queued "+
						"before it, in order", i, typ, want)
				}
			}
		})
	}
}

// A stalled link costs the event-stream reader one install wait, not one per
// session: after the first install times out, the rest of the export is queued
// without waiting.
func TestFullResyncStalledLinkCostsOneWait_9767(t *testing.T) {
	deltas := []dpuserspace.SessionDeltaInfo{
		transitOpen9767(), transitOpen9767(), transitOpen9767(), transitOpen9767(), transitOpen9767(),
	}
	deltas[1].SrcPort, deltas[2].SrcPort, deltas[3].SrcPort, deltas[4].SrcPort = 40001, 40002, 40003, 40004
	d, ss, _ := resyncFixture9767(t, deltas...)
	const wait = 300 * time.Millisecond
	d.fullResyncInstallWaitForTest = wait
	ss.FillSendQueueForTesting()

	start := time.Now()
	if d.handleEventStreamFullResync() {
		t.Fatal("control: an export into a send queue that never drains must decline")
	}
	if elapsed := time.Since(start); elapsed >= 3*wait {
		t.Fatalf("#9767: an export of %d sessions into a stalled send queue held the event-stream reader for "+
			"%v, about one %v wait per session. After the first install times out the rest must be queued "+
			"without waiting, or a stalled link stops the reader for the whole table", len(deltas), elapsed, wait)
	}
}

func TestFullResyncHoldsTheDeltaDrainOffItsExportAndQueueing_9766(t *testing.T) {
	open := transitOpen9767()
	d, ss, exporter := resyncFixture9767(t, open)
	closed := open
	closed.Event = "close"
	drainer := &fakeUserspaceDeltaDrainer{batches: [][]dpuserspace.SessionDeltaInfo{{closed}}}
	cfg := d.store.ActiveConfig()

	// The fallback loop's reconciliation drain fires while the export sits
	// between its snapshot and its queueing, and drains the close of the
	// session the snapshot still holds open.
	drained := make(chan struct{})
	exporter.during = func() {
		go func() {
			defer close(drained)
			_, _ = d.drainUserspaceSessionDeltasLocked(drainer, cfg)
		}()
		select {
		case <-drained:
		case <-time.After(300 * time.Millisecond):
		}
	}

	if !d.handleEventStreamFullResync() {
		t.Fatal("control: the resync must be acknowledged, or the order below says nothing")
	}
	select {
	case <-drained:
	case <-time.After(5 * time.Second):
		t.Fatal("the drain never finished: the FullResync did not release the delta lock")
	}
	got := queuedTypes9767(ss)
	if len(got) != 2 || got[0] != "session_v4" || got[1] != "delete_v4" {
		t.Fatalf("#9766: the peer is sent %v, want [session_v4 delete_v4]. The close drained during the "+
			"export went out ahead of the export's stale install, whose fresher generation resurrects the "+
			"closed session on the standby", got)
	}
}

// Every drain the fallback loop runs goes through a locked helper; an unlocked
// drain could queue (or discard) a delta in the middle of a FullResync's
// export. #16627: the connected arm discards instead of queueing, so the
// locked calls are one discard + one queueing drain.
func TestFallbackLoopDrainsUnderTheDeltaLock_9766(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "daemon_ha_userspace_stream.go", nil, 0)
	if err != nil {
		t.Fatalf("parse daemon_ha_userspace_stream.go: %v", err)
	}
	found := false
	locked, discard, unlocked := 0, 0, 0
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "eventStreamFallbackLoop" {
			continue
		}
		found = true
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
				switch sel.Sel.Name {
				case "drainUserspaceSessionDeltasLocked":
					locked++
				case "discardUserspaceSessionDeltasLocked":
					discard++
				case "drainUserspaceSessionDeltasWithConfig", "drainUserspaceSessionDeltasWithConfigLocked":
					unlocked++
				}
			}
			return true
		})
	}
	if !found {
		t.Fatal("eventStreamFallbackLoop is not in daemon_ha_userspace_stream.go")
	}
	if locked != 1 || discard != 1 || unlocked != 0 {
		t.Fatalf("#9766/#16627: eventStreamFallbackLoop drains %d times through drainUserspaceSessionDeltasLocked, "+
			"%d times through discardUserspaceSessionDeltasLocked and %d times through an unlocked drain, want 1, 1 and 0",
			locked, discard, unlocked)
	}
}

// The queue helper is deliberately named Locked: a future producer must opt
// into the ordering domain explicitly rather than silently reopening #9766.
// The handler-specific bracket check below makes lock ownership structural;
// a scheduler cannot make a test seam look serialized after Lock/Unlock removal.
func TestUserspaceDeltaQueueCallsitesUseLockedHelper_9766(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "daemon_ha_userspace_stream.go", nil, 0)
	if err != nil {
		t.Fatalf("parse daemon_ha_userspace_stream.go: %v", err)
	}
	locked, old := 0, 0
	handlerFound := false
	handlerQueue := 0
	var lockPos, queuePos, unlockPos token.Pos
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		switch sel.Sel.Name {
		case "queueUserspaceSessionDeltasLocked":
			locked++
		case "queueUserspaceSessionDeltas":
			old++
		}
		return true
	})
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "handleEventStreamDelta" {
			continue
		}
		handlerFound = true
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if sel.Sel.Name == "queueUserspaceSessionDeltasLocked" {
				handlerQueue++
				queuePos = call.Pos()
				return true
			}
			receiver, ok := sel.X.(*ast.SelectorExpr)
			if !ok || receiver.Sel.Name != "userspaceDeltaSyncMu" {
				return true
			}
			switch sel.Sel.Name {
			case "Lock":
				lockPos = call.Pos()
			case "Unlock":
				unlockPos = call.Pos()
			}
			return true
		})
	}
	if !handlerFound {
		t.Fatal("handleEventStreamDelta is not in daemon_ha_userspace_stream.go")
	}
	if locked != 3 || old != 0 {
		t.Fatalf("#9766: queue helper callsites = locked:%d old:%d, want locked:3 old:0 "+
			"(handler, drain success path, and the #15217 drain status-error path — all under userspaceDeltaSyncMu)",
			locked, old)
	}
	if handlerQueue != 1 || lockPos == 0 || queuePos == 0 || unlockPos == 0 ||
		!(lockPos < queuePos && queuePos < unlockPos) {
		t.Fatalf("#9766: handleEventStreamDelta mutex bracket = lock:%v queue:%v unlock:%v calls:%d, want one lock < queue < unlock",
			lockPos, queuePos, unlockPos, handlerQueue)
	}
}

// --- #16627: discard only at/below the applied watermark ---

type discardDrainer16627 struct {
	batches [][]dpuserspace.SessionDeltaInfo
	status  dpuserspace.ProcessStatus
	err     error
	calls   int
}

func (f *discardDrainer16627) DrainSessionDeltas(uint32) ([]dpuserspace.SessionDeltaInfo, dpuserspace.ProcessStatus, error) {
	f.calls++
	if len(f.batches) == 0 {
		return nil, f.status, f.err
	}
	b := f.batches[0]
	f.batches = f.batches[1:]
	return b, f.status, f.err
}

// TestDiscardOnlyCoveredByAppliedWatermark16627: covered deltas
// (StreamSeq <= applied) are discarded; StreamSeq 0 and ahead-of-
// watermark deltas queue. Fail-on-revert: discard-all fails the queue
// assertions; queue-all fails the discarded count.
func TestDiscardOnlyCoveredByAppliedWatermark16627(t *testing.T) {
	d, ss, _ := resyncFixture9767(t)
	cfg := d.store.ActiveConfig()
	covered := transitOpen9767()
	covered.StreamSeq = 2
	unsequenced := transitOpen9767()
	unsequenced.SrcPort = 41001 // distinct key so both installs queue
	ahead := transitOpen9767()
	ahead.SrcPort = 41002
	ahead.StreamSeq = 99
	drainer := &discardDrainer16627{batches: [][]dpuserspace.SessionDeltaInfo{{covered, unsequenced, ahead}}}
	discarded, err := d.discardUserspaceSessionDeltasLocked(drainer, cfg, 3)
	if err != nil {
		t.Fatalf("discard drain: %v", err)
	}
	if discarded != 1 {
		t.Fatalf("#16627: discarded = %d, want 1 (only the covered delta)", discarded)
	}
	if types := queuedTypes9767(ss); len(types) != 2 {
		t.Fatalf("#16627: queued types = %v, want 2 installs (unsequenced + ahead-of-watermark must queue, not discard)", types)
	}
}

// TestDiscardRecordsSchemaOnlyOnValidStatus16627: the schema
// fingerprint is recorded only when err == nil.
func TestDiscardRecordsSchemaOnlyOnValidStatus16627(t *testing.T) {
	foreign := localSessionDeltaSchemaFingerprint() + 1

	// Valid status: recorded.
	d, _, _ := resyncFixture9767(t)
	drainer := &discardDrainer16627{status: dpuserspace.ProcessStatus{SessionDeltaSchemaFingerprint: foreign}}
	if _, err := d.discardUserspaceSessionDeltasLocked(drainer, d.store.ActiveConfig(), 10); err != nil {
		t.Fatalf("valid-status discard: %v", err)
	}
	if got := d.userspaceDeltaSchemaFP.Load(); got != foreign {
		t.Fatalf("#16627: valid status must record the fingerprint, got %d want %d", got, foreign)
	}

	// Error status: NOT recorded, error propagates, covered still discarded.
	d2, ss2, _ := resyncFixture9767(t)
	covered := transitOpen9767()
	covered.StreamSeq = 1
	wantErr := errors.New("status apply failed 16627")
	drainer2 := &discardDrainer16627{
		batches: [][]dpuserspace.SessionDeltaInfo{{covered}},
		status:  dpuserspace.ProcessStatus{SessionDeltaSchemaFingerprint: foreign},
		err:     wantErr,
	}
	discarded, err := d2.discardUserspaceSessionDeltasLocked(drainer2, d2.store.ActiveConfig(), 10)
	if !errors.Is(err, wantErr) {
		t.Fatalf("#16627: discard error = %v, want propagated status error", err)
	}
	if discarded != 1 {
		t.Fatalf("#16627: discarded on error batch = %d, want 1", discarded)
	}
	if got := d2.userspaceDeltaSchemaFP.Load(); got != 0 {
		t.Fatalf("#16627: error status must NOT record the fingerprint, got %d", got)
	}
	if got := d2.UserspaceDeltaDrainStatusErrorCount(); got != 1 {
		t.Fatalf("#16627: status-error count = %d, want 1", got)
	}
	_ = ss2
}
