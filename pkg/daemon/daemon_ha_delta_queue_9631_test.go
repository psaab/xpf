package daemon

import (
	"context"
	"encoding/binary"
	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestHandleEventStreamDeltaPeerDownIsHandled9631 is the #9631 RED-on-base
// guard: while the HA sync peer is down, every session delta on a primary is
// "not ready" (handleEventStreamDelta returns false), so each one queues in
// the 4096-capped pendingCallbackFrames queue until it fills and the stream
// closes to force a replay — which reconnects, replays, fills again and
// closes again for the whole outage on a fixed 100ms backoff.
//
// A reconnect runs an authoritative bulk sync (handleNewConnection cold-prime
// in pkg/cluster/sync_conn.go drives doBulkSync, whose receiver upserts every
// session and prunes what we no longer own), so deltas produced during the
// outage are superseded by it. They must be treated as handled (dropped and
// counted) rather than not-ready.
func TestHandleEventStreamDeltaPeerDownIsHandled9631(t *testing.T) {
	d := &Daemon{
		cluster:     newClusterManager(true),
		sessionSync: &cluster.SessionSync{},
	}
	if !d.cluster.IsLocalPrimaryAny() {
		t.Fatal("test setup: node must be primary so the delta reaches the sync-connected gate")
	}
	if ss := d.getSessionSync(); ss == nil || ss.IsConnected() {
		t.Fatal("test setup: session sync must exist and be disconnected (peer down)")
	}
	delta := dpuserspace.SessionDeltaInfo{
		AddrFamily: dataplane.AFInet,
		Protocol:   6,
		SrcIP:      "10.0.1.102",
		DstIP:      "172.16.80.200",
		SrcPort:    12345,
		DstPort:    443,
	}
	// More than pendingCallbackFramesLimit (4096): on base every iteration
	// returns false, which is what fills the queue and storms the stream.
	const deltas = 5000
	for i := 0; i < deltas; i++ {
		if !d.handleEventStreamDelta(dpuserspace.EventTypeSessionOpen, delta) {
			t.Fatalf("delta %d/%d while peer down returned not-ready: "+
				"it queues toward the 4096-cap close/replay storm instead of being dropped as handled",
				i+1, deltas)
		}
	}
}

// TestHandleEventStreamFullResyncPeerDownIsHandled9631 is the #9631 barrier
// co-flip guard: a barrier that answers not-ready while the peer is down
// head-blocks flushPendingCallbackFrames, so one mid-outage barrier re-arms
// the exact storm the delta shed removes. It must be shed (handled) with a
// latched repayment debt instead: the export it asks for cannot deliver
// while disconnected, so repayOwedFullResyncIfDue runs it post-reconnect.
func TestHandleEventStreamFullResyncPeerDownIsHandled9631(t *testing.T) {
	d := &Daemon{
		cluster:     newClusterManager(true),
		sessionSync: &cluster.SessionSync{},
	}
	if !d.cluster.IsLocalPrimaryAny() {
		t.Fatal("test setup: node must be primary so the barrier reaches the sync-connected gate")
	}
	if ss := d.getSessionSync(); ss == nil || ss.IsConnected() {
		t.Fatal("test setup: session sync must exist and be disconnected (peer down)")
	}
	if !d.handleEventStreamFullResync() {
		t.Fatal("FullResync while peer down returned not-ready: it wedges the queue head instead of being shed with a repayment debt")
	}
	if got := d.UserspaceFullResyncPeerDownDroppedCount(); got != 1 {
		t.Fatalf("FullResync peer-down shed count = %d, want 1", got)
	}
	if !d.userspaceFullResyncOwedWhileDown.Load() {
		t.Fatal("shed barrier must latch the owed-repayment debt")
	}
}

// peerDownDaemon9631 builds a primary daemon with a disconnected sync peer
// and a committed (minimal) config so close deltas reach the queue path.
func peerDownDaemon9631(t *testing.T) *Daemon {
	t.Helper()
	d := &Daemon{
		cluster:     newClusterManager(true),
		sessionSync: &cluster.SessionSync{},
		store:       newConfigStore(t, t.TempDir()+"/config.db"),
	}
	if !d.cluster.IsLocalPrimaryAny() {
		t.Fatal("test setup: node must be primary so deltas reach the sync-connected gate")
	}
	if ss := d.getSessionSync(); ss == nil || ss.IsConnected() {
		t.Fatal("test setup: session sync must exist and be disconnected (peer down)")
	}
	if _, err := d.store.SyncApply("system {\n    host-name node-a;\n}\n", nil); err != nil {
		t.Fatalf("SyncApply: %v", err)
	}
	return d
}

// TestPeerDownDropCountersExact9631 pins the #9631 counting discipline:
// opens/updates while down are shed and counted exactly; closes are NOT shed
// (they fall through to the queue path and journal for replay).
func TestPeerDownDropCountersExact9631(t *testing.T) {
	d := peerDownDaemon9631(t)
	delta := dpuserspace.SessionDeltaInfo{
		AddrFamily: dataplane.AFInet,
		Protocol:   6,
		SrcIP:      "10.0.1.102",
		DstIP:      "172.16.80.200",
		SrcPort:    12345,
		DstPort:    443,
	}
	const opens = 5000
	for i := range opens {
		if !d.handleEventStreamDelta(dpuserspace.EventTypeSessionOpen, delta) {
			t.Fatalf("open delta %d/%d while peer down returned not-ready", i+1, opens)
		}
	}
	if got := d.UserspaceDeltaPeerDownDroppedCount(); got != opens {
		t.Fatalf("peer-down dropped count = %d, want %d", got, opens)
	}
	for i := range 100 {
		if !d.handleEventStreamDelta(dpuserspace.EventTypeSessionClose, delta) {
			t.Fatalf("close delta %d/100 while peer down returned not-ready", i+1)
		}
	}
	if got := d.UserspaceDeltaPeerDownDroppedCount(); got != opens {
		t.Fatalf("peer-down dropped count moved on closes = %d, want %d (closes journal, not shed)", got, opens)
	}
}

// TestPeerDownFallsThroughWithoutConfig9631 covers the cfg-nil-down window: no
// active config means nothing is convertible, but the outage must still shed
// (never queue toward the storm) and count.
func TestPeerDownFallsThroughWithoutConfig9631(t *testing.T) {
	d := &Daemon{
		cluster:     newClusterManager(true),
		sessionSync: &cluster.SessionSync{},
		store:       newConfigStore(t, t.TempDir()+"/config.db"),
	}
	if cfg := d.store.ActiveConfig(); cfg != nil {
		t.Fatal("test setup: store must have no active config for the cfg-nil window")
	}
	delta := dpuserspace.SessionDeltaInfo{
		AddrFamily: dataplane.AFInet,
		Protocol:   6,
		SrcIP:      "10.0.1.102",
		DstIP:      "172.16.80.200",
		SrcPort:    12345,
		DstPort:    443,
	}
	for _, typ := range []uint8{dpuserspace.EventTypeSessionOpen, dpuserspace.EventTypeSessionUpdate, dpuserspace.EventTypeSessionClose} {
		if !d.handleEventStreamDelta(typ, delta) {
			t.Fatalf("delta type %d while peer down with no config returned not-ready", typ)
		}
	}
	if got := d.UserspaceDeltaPeerDownDroppedCount(); got != 2 {
		t.Fatalf("peer-down dropped count = %d, want 2 (open+update shed, close unshed)", got)
	}
}

// TestPeerDownToleratesNilStore9631 proves the peer-down path never touches a
// nil store: ActiveConfig is not nil-safe, so the handler must guard before
// loading config. Must return handled, never panic.
func TestPeerDownToleratesNilStore9631(t *testing.T) {
	d := &Daemon{
		cluster:     newClusterManager(true),
		sessionSync: &cluster.SessionSync{},
	}
	delta := dpuserspace.SessionDeltaInfo{
		AddrFamily: dataplane.AFInet,
		Protocol:   6,
		SrcIP:      "10.0.1.102",
		DstIP:      "172.16.80.200",
		SrcPort:    12345,
		DstPort:    443,
	}
	for _, typ := range []uint8{dpuserspace.EventTypeSessionOpen, dpuserspace.EventTypeSessionUpdate, dpuserspace.EventTypeSessionClose} {
		if !d.handleEventStreamDelta(typ, delta) {
			t.Fatalf("delta type %d while peer down with nil store returned not-ready", typ)
		}
	}
	if got := d.UserspaceDeltaPeerDownDroppedCount(); got != 2 {
		t.Fatalf("peer-down dropped count = %d, want 2 (open+update shed, close unshed)", got)
	}
}

// TestPeerDownSameKeyReopenCounters9631 drives the gen-0 race shape at the
// routing level: same 5-tuple opens, closes, and reopens while down. Every
// frame must be handled; exactly the two opens shed.
func TestPeerDownSameKeyReopenCounters9631(t *testing.T) {
	d := peerDownDaemon9631(t)
	delta := dpuserspace.SessionDeltaInfo{
		AddrFamily: dataplane.AFInet,
		Protocol:   6,
		SrcIP:      "10.0.1.102",
		DstIP:      "172.16.80.200",
		SrcPort:    12345,
		DstPort:    443,
	}
	seq := []uint8{dpuserspace.EventTypeSessionOpen, dpuserspace.EventTypeSessionClose, dpuserspace.EventTypeSessionOpen}
	for i, typ := range seq {
		if !d.handleEventStreamDelta(typ, delta) {
			t.Fatalf("frame %d (type %d) of same-key reopen while peer down returned not-ready", i, typ)
		}
	}
	if got := d.UserspaceDeltaPeerDownDroppedCount(); got != 2 {
		t.Fatalf("peer-down dropped count = %d, want 2 (both opens shed, close unshed)", got)
	}
}

// TestPeerDownClosesJournalPastCap9631 proves closes-while-down journal for
// replay instead of blackholing: past the 10000-entry journal cap the oldest
// entry is evicted, DeletesDropped advances, and nothing reaches the wire.
func TestPeerDownClosesJournalPastCap9631(t *testing.T) {
	d := peerDownDaemon9631(t)
	ss := d.getSessionSync()
	ss.IsPrimaryFn = func() bool { return true }
	delta := dpuserspace.SessionDeltaInfo{
		AddrFamily:    dataplane.AFInet,
		Protocol:      6,
		SrcIP:         "10.0.1.102",
		DstIP:         "172.16.80.200",
		SrcPort:       12345,
		DstPort:       443,
		IngressZoneID: 1,
		EgressZoneID:  1,
	}
	const closes = 10001
	for i := range closes {
		if !d.handleEventStreamDelta(dpuserspace.EventTypeSessionClose, delta) {
			t.Fatalf("close %d/%d while peer down returned not-ready", i+1, closes)
		}
	}
	stats := ss.Stats()
	if stats.DeletesDropped != 1 {
		t.Fatalf("DeletesDropped = %d, want 1 (10001 closes against the 10000 journal cap must evict exactly one)", stats.DeletesDropped)
	}
	if stats.DeletesSent != 0 {
		t.Fatalf("DeletesSent = %d, want 0 (nothing reaches the wire while down)", stats.DeletesSent)
	}
}

// resyncFixture9631 mirrors resyncFixture9767 but leaves the peer
// DISCONNECTED: a node primary for RGs 0-1 with a committed cluster config,
// an install-wait-shortened daemon, and a fixed-delta exporter backend.
func resyncFixture9631(t *testing.T, deltas ...dpuserspace.SessionDeltaInfo) (*Daemon, *cluster.SessionSync, *resyncDeltaExporterDP) {
	t.Helper()
	d := &Daemon{
		cluster: clusterManagerPrimaryForRGs(0, 1),
		store: testStoreWithSetConfig(t, []string{
			"set system dataplane-type userspace",
			"set chassis cluster cluster-id 1",
			"set chassis cluster authentication-key test-cluster-psk-9631",
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
	d.sessionSync = ss
	exporter := &resyncDeltaExporterDP{deltas: deltas}
	d.setDataplane(exporter)
	if cfg := d.store.ActiveConfig(); cfg == nil || len(d.primaryOwnerRGIDs(cfg)) == 0 {
		t.Fatal("setup: the node owns no configured RG, so the FullResync never reaches the export")
	}
	if ss.IsConnected() {
		t.Fatal("test setup: session sync must start disconnected (peer down)")
	}
	return d, ss, exporter
}

// regression needs. The embedded interface supplies the unused SessionStore
// methods; SessionSync still executes its production decoders, generation
// guards, and apply path against these concrete Put/Delete methods.
type orderingSessionStore9631 struct {
	dataplane.SessionStore
	mu sync.Mutex
	v4 map[dataplane.SessionKey]dataplane.SessionValue
}

func newOrderingSessionStore9631() *orderingSessionStore9631 {
	return &orderingSessionStore9631{
		v4: make(map[dataplane.SessionKey]dataplane.SessionValue),
	}
}

func (s *orderingSessionStore9631) PutClusterSyncedV4(
	key dataplane.SessionKey, val dataplane.SessionValue,
) error {
	s.mu.Lock()
	s.v4[key] = val
	s.mu.Unlock()
	return nil
}

func (s *orderingSessionStore9631) DeleteWithCompanionsV4(
	key dataplane.SessionKey, _ dataplane.DeleteReason, _ bool,
) error {
	s.mu.Lock()
	delete(s.v4, key)
	s.mu.Unlock()
	return nil
}

func (s *orderingSessionStore9631) hasV4(key dataplane.SessionKey) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.v4[key]
	return ok
}

// writeEventFrame9631 writes the actual EventStream frame format to a helper
// Unix connection. The test uses a real Start/accept/readLoop close and reopen,
// not the callback function directly.
func writeEventFrame9631(t *testing.T, conn net.Conn, typ uint8, seq uint64, payload []byte) {
	t.Helper()
	frame := make([]byte, dpuserspace.EventFrameHeaderSize+len(payload))
	binary.LittleEndian.PutUint32(frame[0:4], uint32(len(payload)))
	frame[4] = typ
	binary.LittleEndian.PutUint64(frame[8:16], seq)
	copy(frame[dpuserspace.EventFrameHeaderSize:], payload)
	if n, err := conn.Write(frame); err != nil || n != len(frame) {
		t.Fatalf("write event frame: n=%d len=%d err=%v", n, len(frame), err)
	}
}

func sessionClosePayload9631(delta dpuserspace.SessionDeltaInfo) []byte {
	src := net.ParseIP(delta.SrcIP).To4()
	dst := net.ParseIP(delta.DstIP).To4()
	payload := make([]byte, 6+8+5+4)
	payload[0] = 4
	payload[1] = delta.Protocol
	binary.LittleEndian.PutUint16(payload[2:4], delta.SrcPort)
	binary.LittleEndian.PutUint16(payload[4:6], delta.DstPort)
	copy(payload[6:10], src)
	copy(payload[10:14], dst)
	binary.LittleEndian.PutUint32(payload[14:18], uint32(int32(delta.OwnerRGID)))
	binary.LittleEndian.PutUint16(payload[19:21], config.StableZoneID(delta.IngressZone))
	binary.LittleEndian.PutUint16(payload[21:23], config.StableZoneID(delta.EgressZone))
	return payload
}

func waitEventStreamConnected9631(t *testing.T, es *dpuserspace.EventStream, want bool) {
	t.Helper()
	timeout := time.NewTimer(5 * time.Second)
	defer timeout.Stop()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for {
		if es.IsConnected() == want {
			return
		}
		select {
		case <-timeout.C:
			t.Fatalf("event stream connected=%t, want %t", es.IsConnected(), want)
		case <-tick.C:
		}
	}
}

// TestPeerDownDaemonAdmissionStampsGenerationOnReopen9631 binds the daemon
// callback to the cluster QueueSessionV4 path. It isolates one admitted,
// zone-resolved key, exercises an open/close/reopen while disconnected, then
// forces a connected close into the journal and asserts a nonzero delete
// generation. If the daemon early-drops down-state opens, the final close has
// no sender-side install stamp and this cell fails.
func TestPeerDownDaemonAdmissionStampsGenerationOnReopen9631(t *testing.T) {
	live := transitOpen9767()
	d, ss, _ := resyncFixture9631(t)
	zoneIDs := buildZoneIDs(d.store.ActiveConfig())
	key, _, ok := userspaceSessionFromDeltaV4(live, zoneIDs)
	if !ok {
		t.Fatal("setup: admitted live delta did not convert")
	}
	for i, typ := range []uint8{
		dpuserspace.EventTypeSessionOpen,
		dpuserspace.EventTypeSessionClose,
		dpuserspace.EventTypeSessionOpen,
	} {
		if !d.handleEventStreamDelta(typ, live) {
			t.Fatalf("down-phase frame %d (%s) returned not-ready", i, userspaceSessionEventName(typ))
		}
	}
	if got := d.UserspaceDeltaPeerDownDroppedCount(); got != 2 {
		t.Fatalf("down-phase open shed count = %d, want 2", got)
	}
	if stamp := ss.SentInstallGenerationV4ForTesting(key); stamp == 0 {
		t.Fatal("admitted down-phase reopen did not stamp QueueSessionV4 generation")
	}

	ss.SetConnectedForTesting(true)
	ss.FillSendQueueForTesting()
	if !d.handleEventStreamDelta(dpuserspace.EventTypeSessionClose, live) {
		t.Fatal("connected close returned not-ready")
	}
	gen, ok := ss.DeleteJournalGenerationV4ForTesting(key)
	if !ok || gen == 0 {
		t.Fatalf("connected close journal generation = %d/%t, want nonzero (daemon down-phase QueueSessionV4 stamp missing)", gen, ok)
	}
}

// TestPeerDownRepaySerializesWithReopenedStreamClose9631 is the deterministic
// #9766 regression. It drives the real EventStream accept/read loops through
// an actual helper close and reconnect, then starts repayment. The export
// snapshot is held while the reopened close enters the callback's queue
// boundary; blocking joins make that reader participation observable before
// the exporter is released. The post-repayment TryLock probe is the
// deterministic lock-use guard: it proves the callback held the mutex and
// kills a removed or conditionally skipped lock. FIFO/types are a separate
// order proof once lock use is established, and the AST companion remains
// defense in depth. The queued bytes are applied to a real SessionSync
// receiver path, and its concrete store must end absent.
func TestPeerDownRepaySerializesWithReopenedStreamClose9631(t *testing.T) {
	live := transitOpen9767()
	d, ss, exporter := resyncFixture9631(t, live)
	if !d.handleEventStreamFullResync() {
		t.Fatal("setup: FullResync while peer down must shed")
	}

	receiverStore := newOrderingSessionStore9631()
	receiver := cluster.NewSessionSync("127.0.0.1:0", "127.0.0.1:1", nil)
	receiver.SetRuntimeDomains(receiverStore, nil)

	socketPath := filepath.Join(t.TempDir(), "events.sock")
	es := dpuserspace.NewEventStream(socketPath)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	exportEntered := make(chan struct{})
	allowExport := make(chan struct{})
	exporter.during = func() {
		close(exportEntered)
		<-allowExport
	}
	deltaArrived := make(chan struct{})
	deltaAtLockBoundary := make(chan struct{})
	deltaLockAcquired := make(chan struct{})
	deltaQueued := make(chan struct{})
	allowLockAttempt := make(chan struct{})
	repaymentReleased := make(chan struct{})
	var lockOwnershipViolation atomic.Bool
	d.userspaceDeltaBeforeLockForTest = func() {
		close(deltaArrived)
		<-allowLockAttempt
		// The callback has now passed the arrival gate and is immediately
		// before the production mutex Lock. Join this handoff before
		// releasing the exporter so reader participation is observable.
		close(deltaAtLockBoundary)
	}
	d.userspaceDeltaAfterLockForTest = func() {
		<-repaymentReleased
		// TryLock must fail while the callback owns the production mutex.
		// This catches a removed Lock and an if-peerDown-wrapped Lock
		// without depending on scheduler timing.
		if d.userspaceDeltaSyncMu.TryLock() {
			d.userspaceDeltaSyncMu.Unlock()
			lockOwnershipViolation.Store(true)
		}
		close(deltaLockAcquired)
	}
	d.userspaceDeltaAfterQueueForTest = func() { close(deltaQueued) }

	if err := es.Start(ctx); err != nil {
		t.Fatalf("start event stream: %v", err)
	}
	defer es.Close()
	d.installEventStreamCallbacks(es)

	first, err := net.Dial("unix", socketPath)
	if err != nil {
		t.Fatalf("dial first helper connection: %v", err)
	}
	waitEventStreamConnected9631(t, es, true)
	if err := first.Close(); err != nil {
		t.Fatalf("close first helper connection: %v", err)
	}
	waitEventStreamConnected9631(t, es, false)

	reopened, err := net.Dial("unix", socketPath)
	if err != nil {
		t.Fatalf("dial reopened helper connection: %v", err)
	}
	defer reopened.Close()
	waitEventStreamConnected9631(t, es, true)

	ss.SetConnectedForTesting(true)

	repayDone := make(chan struct{})
	go func() {
		d.repayOwedFullResyncIfDue()
		close(repayDone)
	}()
	<-exportEntered // the live snapshot is now held inside the repayment export

	writeEventFrame9631(t, reopened, dpuserspace.EventTypeSessionClose, 1, sessionClosePayload9631(live))
	<-deltaArrived
	if d.userspaceDeltaSyncMu.TryLock() {
		d.userspaceDeltaSyncMu.Unlock()
		lockOwnershipViolation.Store(true)
	}
	close(allowLockAttempt)
	<-deltaAtLockBoundary

	close(allowExport)
	<-repayDone
	close(repaymentReleased)
	<-deltaLockAcquired
	<-deltaQueued
	if lockOwnershipViolation.Load() {
		t.Fatal("delta callback did not execute while the repayment-held mutex was owned")
	}

	types, err := ss.ApplyQueuedMessagesForTesting(receiver)
	if err != nil {
		t.Fatalf("apply queued messages to receiver: %v", err)
	}
	if len(types) != 2 || types[0] != "session_v4" || types[1] != "delete_v4" {
		t.Fatalf("receiver wire order = %v, want [session_v4 delete_v4]", types)
	}
	key, _, ok := userspaceSessionFromDeltaV4(live, buildZoneIDs(d.store.ActiveConfig()))
	if !ok {
		t.Fatal("setup: live export delta did not convert")
	}
	if receiverStore.hasV4(key) {
		t.Fatal("receiver retained the closed session: repayment install resurrected after stream close")
	}
}

// TestPeerDownRepayOrderingAdverseControl9631 is the opposite-order control
// for the #9766 regression. A close that is queued before repayment has
// stamped an install produces a gen-0 delete; the later live snapshot install
// therefore wins, leaving the session present. The ordering regression above
// must prevent this schedule when the close arrives during repayment export.
func TestPeerDownRepayOrderingAdverseControl9631(t *testing.T) {
	live := transitOpen9767()
	d, ss, _ := resyncFixture9631(t, live)
	if !d.handleEventStreamFullResync() {
		t.Fatal("setup: FullResync while peer down must shed")
	}
	ss.SetConnectedForTesting(true)
	if !d.handleEventStreamDelta(dpuserspace.EventTypeSessionClose, live) {
		t.Fatal("adverse-order close returned not-ready")
	}
	d.repayOwedFullResyncIfDue()

	receiverStore := newOrderingSessionStore9631()
	receiver := cluster.NewSessionSync("127.0.0.1:0", "127.0.0.1:1", nil)
	receiver.SetRuntimeDomains(receiverStore, nil)
	types, err := ss.ApplyQueuedMessagesForTesting(receiver)
	if err != nil {
		t.Fatalf("apply adverse-order messages to receiver: %v", err)
	}
	if len(types) != 2 || types[0] != "delete_v4" || types[1] != "session_v4" {
		t.Fatalf("adverse-order wire = %v, want [delete_v4 session_v4]", types)
	}
	key, _, ok := userspaceSessionFromDeltaV4(live, buildZoneIDs(d.store.ActiveConfig()))
	if !ok {
		t.Fatal("setup: live export delta did not convert")
	}
	if !receiverStore.hasV4(key) {
		t.Fatal("adverse-order control did not leave the newer repayment install present")
	}

}

// TestPeerDownOwedFullResyncRepaidOnReconnect9631 proves the #9631 barrier
// debt is durable and repaid: shed while down, then one repayment export on
// reconnect delivers the live session and clears the debt.
func TestPeerDownOwedFullResyncRepaidOnReconnect9631(t *testing.T) {
	d, ss, exporter := resyncFixture9631(t, transitOpen9767())
	if !d.handleEventStreamFullResync() {
		t.Fatal("FullResync while peer down returned not-ready: it must shed with a repayment debt")
	}
	if !d.userspaceFullResyncOwedWhileDown.Load() {
		t.Fatal("shed barrier must latch the owed-repayment debt")
	}
	ss.SetConnectedForTesting(true)
	d.repayOwedFullResyncIfDue()
	if d.userspaceFullResyncOwedWhileDown.Load() {
		t.Fatal("repayment after reconnect must clear the debt")
	}
	if got := exporter.exports.Load(); got != 1 {
		t.Fatalf("exporter ran %d times, want 1 (exactly one repayment export)", got)
	}
	var types []string
	for {
		typ, ok := ss.TakeQueuedMessageTypeForTesting(0)
		if !ok {
			break
		}
		types = append(types, typ)
	}
	if len(types) != 1 || types[0] != "session_v4" {
		t.Fatalf("send queue holds %v, want [session_v4] (the repaid live session)", types)
	}
}

// TestPeerDownOwedFullResyncKeptWhenExportFails9631 proves a failed repayment
// keeps the debt armed for the next tick instead of dropping it: with the
// send queue full the paced install misses, the export fails, and the debt
// survives.
func TestPeerDownOwedFullResyncKeptWhenExportFails9631(t *testing.T) {
	d, ss, exporter := resyncFixture9631(t, transitOpen9767())
	if !d.handleEventStreamFullResync() {
		t.Fatal("setup: FullResync while peer down must shed")
	}
	ss.SetConnectedForTesting(true)
	ss.FillSendQueueForTesting()
	d.repayOwedFullResyncIfDue()
	if !d.userspaceFullResyncOwedWhileDown.Load() {
		t.Fatal("failed repayment must keep the debt armed for the next tick")
	}
	if got := exporter.exports.Load(); got != 1 {
		t.Fatalf("exporter ran %d times, want 1 (the attempt ran and missed)", got)
	}
}

// TestPeerDownBarrierInterleavedWithDeltasAllHandled9631 is the #9631
// acceptance shape with barriers: 5000 deltas with a wire barrier every
// 1000, all handled while down. Every-true plus the userspace pins (true
// implies zero enqueue) proves no queue growth and no close-to-replay.
func TestPeerDownBarrierInterleavedWithDeltasAllHandled9631(t *testing.T) {
	d := peerDownDaemon9631(t)
	delta := dpuserspace.SessionDeltaInfo{
		AddrFamily: dataplane.AFInet,
		Protocol:   6,
		SrcIP:      "10.0.1.102",
		DstIP:      "172.16.80.200",
		SrcPort:    12345,
		DstPort:    443,
	}
	const opens = 5000
	for i := range opens {
		if !d.handleEventStreamDelta(dpuserspace.EventTypeSessionOpen, delta) {
			t.Fatalf("open delta %d/%d while peer down returned not-ready", i+1, opens)
		}
		if (i+1)%1000 == 0 && !d.handleEventStreamFullResync() {
			t.Fatalf("barrier %d/5 interleaved while peer down returned not-ready", (i+1)/1000)
		}
	}
	if got := d.UserspaceDeltaPeerDownDroppedCount(); got != opens {
		t.Fatalf("peer-down dropped count = %d, want %d", got, opens)
	}
	if got := d.UserspaceFullResyncPeerDownDroppedCount(); got != 5 {
		t.Fatalf("FullResync peer-down shed count = %d, want 5", got)
	}
}

// TestPeerDownFreshShedSurvivesRepay9631 proves the owed-debt consume is
// race-safe: a barrier shed concurrently with a successful repayment export
// (peer flap window) must survive the success instead of being erased by a
// clear-after-success. The 9767 exporter's during hook runs inside the export
// synchronously, so the interleaving is deterministic, not timing-based.
func TestPeerDownFreshShedSurvivesRepay9631(t *testing.T) {
	d, ss, exporter := resyncFixture9631(t, transitOpen9767())
	if !d.handleEventStreamFullResync() {
		t.Fatal("setup: FullResync while peer down must shed")
	}
	ss.SetConnectedForTesting(true)
	exporter.during = func() {
		// Simulate a barrier shed in the flap window mid-export: it arms
		// fresh debt that the in-flight success must not erase.
		d.userspaceFullResyncOwedWhileDown.Store(true)
	}
	d.repayOwedFullResyncIfDue()
	if !d.userspaceFullResyncOwedWhileDown.Load() {
		t.Fatal("fresh debt shed during a successful repayment was erased: consume must claim-before-attempt so concurrent arms survive")
	}
	if got := exporter.exports.Load(); got != 1 {
		t.Fatalf("exporter ran %d times, want 1 (the repayment ran to success)", got)
	}
}

// TestPeerDownShedsWithoutWarnChurn9631 proves the #9631 acceptance clause
// "visible as a counter, not an ERROR per cycle": 5000 shed opens + 5 shed
// barriers while down emit exactly two bounded WARNs (one dampened drop arm
// plus one once-per-debt-episode barrier arm) and zero ERRORs — no
// per-barrier/per-delta churn.
func TestPeerDownShedsWithoutWarnChurn9631(t *testing.T) {
	d := peerDownDaemon9631(t)
	delta := dpuserspace.SessionDeltaInfo{
		AddrFamily: dataplane.AFInet,
		Protocol:   6,
		SrcIP:      "10.0.1.102",
		DstIP:      "172.16.80.200",
		SrcPort:    12345,
		DstPort:    443,
	}
	out := captureDaemonWarn(t, func() {
		for i := range 5000 {
			if !d.handleEventStreamDelta(dpuserspace.EventTypeSessionOpen, delta) {
				t.Fatalf("open delta %d/5000 while peer down returned not-ready", i+1)
			}
			// Churn is the observable here (IsHandled owns the bool).
			if (i+1)%1000 == 0 {
				d.handleEventStreamFullResync()
			}
		}
	})
	if warns := strings.Count(out, "level=WARN"); warns != 2 {
		t.Fatalf("WARN lines during 5000-shed outage = %d, want exactly 2 (drop + debt episode)", warns)
	}
	if strings.Contains(out, "level=ERROR") {
		t.Fatal("ERROR emitted during shed outage: outage must be counter-visible, not log churn")
	}
	if !strings.Contains(out, "shedding opens/updates while sync peer down") ||
		!strings.Contains(out, "shedding full resync while sync peer down") {
		t.Fatal("bounded WARNs must identify both the drop and full-resync debt arms")
	}
}

// TestPeerDownOwedRepayIndependentOfHelperStream9631 pins that repayment is
// gated on HA sync connectivity, never helper-stream state: the fixture wires
// no EventStream at all, yet with the sync peer connected the owed export
// runs and clears. This is what makes the once-per-tick fallback-hook
// placement (both arms) correct, and it guards any future stream-gating of
// repay (which would strand the debt whenever the helper stream is down).
func TestPeerDownOwedRepayIndependentOfHelperStream9631(t *testing.T) {
	d, ss, exporter := resyncFixture9631(t, transitOpen9767())
	if !d.handleEventStreamFullResync() {
		t.Fatal("setup: FullResync while peer down must shed")
	}
	ss.SetConnectedForTesting(true)
	// No EventStream is wired on this fixture by construction; repay must
	// not care — HA sync connectivity is its only connectivity gate.
	d.repayOwedFullResyncIfDue()
	if d.userspaceFullResyncOwedWhileDown.Load() {
		t.Fatal("repayment with sync connected but no helper stream must clear the debt")
	}
	if got := exporter.exports.Load(); got != 1 {
		t.Fatalf("exporter ran %d times, want 1 (the repayment export)", got)
	}
}

// TestPeerDownFallbackLoopRepaysWithoutHelperOrDrainer9631 binds the
// production fallback hook itself. The exporter deliberately implements
// neither userspaceEventStreamProvider nor userspaceSessionDeltaDrainer, so
// only the repay call above the helper/drainer branches can clear the debt.
// Its exported signal is entry-only; cancellation and loop join below prove
// the export returned and its queued frame is visible before assertions.
func TestPeerDownFallbackLoopRepaysWithoutHelperOrDrainer9631(t *testing.T) {
	d, ss, exporter := resyncFixture9631(t, transitOpen9767())
	if !d.handleEventStreamFullResync() {
		t.Fatal("setup: FullResync while peer down must shed")
	}
	if !d.userspaceFullResyncOwedWhileDown.Load() {
		t.Fatal("setup: debt must be armed before entering fallback loop")
	}
	exported := make(chan struct{})
	exporter.exported = exported
	ss.SetConnectedForTesting(true)

	ctx, cancel := context.WithCancel(context.Background())
	loopDone := make(chan struct{})
	go func() {
		d.eventStreamFallbackLoop(ctx, nil)
		close(loopDone)
	}()
	select {
	case <-exported:
	case <-time.After(5 * time.Second):
		cancel()
		<-loopDone
		t.Fatal("fallback loop did not repay debt without a helper stream or drainer")
	}
	// The exporter closes exported on entry, before its snapshot is returned
	// and queued. Join the loop before checking debt, export count, or frames.
	cancel()
	<-loopDone
	got := queuedTypes9767(ss)
	if len(got) != 1 || got[0] != "session_v4" {
		t.Fatalf("fallback-loop queued types = %v, want [session_v4]", got)
	}
	if d.userspaceFullResyncOwedWhileDown.Load() {
		t.Fatal("fallback-loop repayment left debt armed after successful export")
	}
	if got := exporter.exports.Load(); got != 1 {
		t.Fatalf("fallback-loop exporter runs = %d, want 1", got)
	}

}

// TestPeerDownRepayRetainsDebtWhenDemoted9631 pins the handled-but-not-
// exported repayment outcome. Scope: ownership is changed to secondary before
// repayment's initial connected/primary gate; this does not drive a demotion
// after that gate and before export (the post-claim TOCTOU window is not
// deterministic here). The callback is intentionally handled as an ignored
// non-primary request, but the debt must remain for a later promotion rather
// than being reported as repaid.
func TestPeerDownRepayRetainsDebtWhenDemoted9631(t *testing.T) {
	d, ss, exporter := resyncFixture9631(t, transitOpen9767())
	if !d.handleEventStreamFullResync() {
		t.Fatal("setup: FullResync while peer down must shed")
	}
	d.cluster.SetGroupStateForTesting(0, cluster.StateSecondary)
	d.cluster.SetGroupStateForTesting(1, cluster.StateSecondary)
	ss.SetConnectedForTesting(true)
	d.repayOwedFullResyncIfDue()
	if !d.userspaceFullResyncOwedWhileDown.Load() {
		t.Fatal("demotion handled the repayment callback without exporting; debt must remain armed")
	}
	if got := exporter.exports.Load(); got != 0 {
		t.Fatalf("demoted repayment exporter runs = %d, want 0", got)
	}
}

// TestFullResyncAttemptShedWithoutCountingRepay9631 pins the two-result
// FullResync split: repayment's own peer-down retry is handled (the event
// stream must advance) but not exported or counted as a fresh user barrier.
func TestFullResyncAttemptShedWithoutCountingRepay9631(t *testing.T) {
	d, ss, _ := resyncFixture9631(t)
	handled, exported := d.fullResyncAttempt(false)
	if !handled || exported {
		t.Fatalf("repayment peer-down attempt = handled:%t exported:%t, want true/false", handled, exported)
	}
	if !d.userspaceFullResyncOwedWhileDown.Load() {
		t.Fatal("a peer-down repayment flap must re-arm debt")
	}
	if got := d.UserspaceFullResyncPeerDownDroppedCount(); got != 0 {
		t.Fatalf("repayment self-shed count = %d, want 0", got)
	}
	if ss.IsConnected() {
		t.Fatal("test setup: session sync unexpectedly connected")
	}
}

// TestFullResyncConnectedNilStoreFailsClosed9631 covers the connected
// config-store gap. It must return not-ready rather than panic or claim a
// FullResync was exported.
func TestFullResyncConnectedNilStoreFailsClosed9631(t *testing.T) {
	d := &Daemon{
		cluster:     newClusterManager(true),
		sessionSync: cluster.NewSessionSync("127.0.0.1:0", "127.0.0.1:1", nil),
	}
	d.setDataplane(&resyncDeltaExporterDP{deltas: []dpuserspace.SessionDeltaInfo{transitOpen9767()}})
	d.sessionSync.SetConnectedForTesting(true)
	if d.handleEventStreamFullResync() {
		t.Fatal("connected FullResync with nil config store was handled without export")
	}
}

// TestUserspaceWarnThrottlePreservesMonotonicOrdering9631 uses full Time
// values, including a backwards monotonic step, to ensure the dampener does
// not emit warning churn after wall-clock rollback.
func TestUserspaceWarnThrottlePreservesMonotonicOrdering9631(t *testing.T) {
	var throttle userspaceWarnThrottle
	now := time.Now()
	if emit, suppressed := throttle.shouldLog(now, time.Minute); !emit || suppressed != 0 {
		t.Fatalf("first warning = emit:%t suppressed:%d, want true/0", emit, suppressed)
	}
	if emit, _ := throttle.shouldLog(now.Add(time.Second), time.Minute); emit {
		t.Fatal("warning inside the monotonic interval was emitted")
	}
	if emit, _ := throttle.shouldLog(now.Add(-time.Hour), time.Minute); emit {
		t.Fatal("backward monotonic time step emitted a warning")
	}
	if emit, suppressed := throttle.shouldLog(now.Add(2*time.Minute), time.Minute); !emit || suppressed != 2 {
		t.Fatalf("post-interval warning = emit:%t suppressed:%d, want true/2", emit, suppressed)
	}
}
