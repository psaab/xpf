package cluster

import (
	"context"
	"encoding/binary"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
)

// TestColdPrimeOwedWhenRuntimeWiredAfterConnect is the #82 startup-race repro.
//
// The daemon starts session sync (ss.Start -> accept/dial goroutines) BEFORE it
// wires the runtime (ss.SetRuntime), so a peer that connects inside that window
// drives the cold-prime bulk against a SessionSync whose session store is still
// nil. BulkSync returns "session store not ready" without touching the
// connection (no disconnect), the needColdPrime obligation stays armed, and
// nothing re-drives it while the connection stays up: the reconnect consumer
// lives in installConn and the survivor re-drive lives in handleDisconnect.
//
// The incremental sweep cannot cover for it. StartSyncSweep seeds lastSweepTime
// to "now", and the sweep only queues sessions with Created >= threshold, so
// every session that existed before the sweep started is invisible to it
// forever. Those are exactly the sessions the cold-prime bulk exists to
// replicate, and they are also the only thing that drives the peer's
// authoritative reconcileStaleSessions window.
//
// RED at the pre-fix HEAD: BulkSyncs stays 0 across every post-wire sweep tick
// and the pre-existing session never reaches the standby.
func TestColdPrimeOwedWhenRuntimeWiredAfterConnect(t *testing.T) {
	const zone = uint16(2)
	// Created=0 — a session that already existed when the daemon came up, i.e.
	// strictly older than any sweep threshold.
	preExisting := dataplane.SessionKey{SrcIP: [4]byte{10, 0, 7, 1}, DstIP: [4]byte{10, 0, 8, 1}, Protocol: 6, SrcPort: 1200, DstPort: 80}

	primDP := &mockSweepDP{
		v4sessions: map[dataplane.SessionKey]dataplane.SessionValue{
			preExisting: {IsReverse: 0, IngressZone: zone, Created: 0},
		},
		sessionCounter: 1,
	}

	// Runtime NOT wired: this is the state of `ss` between ss.Start() and
	// ss.SetRuntime(rt) in startClusterComms.
	prim := NewSessionSync(":0", "10.0.0.2:4785", nil)
	if prim.sessions != nil {
		t.Fatal("precondition: session store must be nil before the runtime is wired")
	}

	cap := newBulkCaptureConn()
	ctx, cancel := context.WithCancel(context.Background())
	defer func() {
		cancel()
		cap.Close()
	}()

	// The peer connects inside the wiring window. Unkeyed, so the handshake is
	// a no-op and handleNewConnection runs the real cold-prime path.
	prim.handleNewConnection(ctx, 0, cap, true)

	if got := prim.stats.BulkSyncs.Load(); got != 0 {
		t.Fatalf("precondition: bulk must have failed with a nil session store, got %d completed bulks", got)
	}
	if !prim.needColdPrime.Load() {
		t.Fatal("precondition: the failed cold prime must leave the obligation armed")
	}
	// sendClockSync already wrote a clock frame; assert only that no bulk
	// window opened.
	if starts, ends := countBulkMarkers(t, cap.bytes()); starts != 0 || ends != 0 {
		t.Fatalf("precondition: no bulk window should have opened, got starts=%d ends=%d", starts, ends)
	}

	// The dataplane becomes ready and the daemon wires it, exactly as
	// startClusterComms does after Start returns.
	prim.SetRuntime(primDP)
	prim.IsPrimaryFn = func() bool { return true }
	// StartSyncSweep seeds the threshold to "now" — the pre-existing session is
	// already older than this, so the incremental path can never carry it.
	prim.lastSweepTime = monotonicSeconds()

	// The connection stays up. Tick the sweep as the 1s loop would.
	for i := 0; i < 3; i++ {
		prim.syncSweep()
	}

	if got := prim.stats.BulkSyncs.Load(); got != 1 {
		t.Fatalf("#82: expected exactly one authoritative bulk after the runtime was wired, got %d (none means no path re-drives the owed prime while the connection stays up)", got)
	}
	// #9626: the obligation is discharged by the peer's BulkAck, not by the
	// write. It is still owed here, and the ack for this bulk clears it.
	epoch, _, ok := prim.PendingBulkAck()
	if !ok || !prim.needColdPrime.Load() {
		t.Fatalf("#82/#9626: after the re-drive, want a pending ack and a still-owed obligation, got pending=%v owed=%v",
			ok, prim.needColdPrime.Load())
	}
	prim.handleMessage(cap, syncMsgBulkAck, epochPayload9626(epoch))
	if prim.needColdPrime.Load() {
		t.Error("#82: the cold-prime obligation is still armed after the peer acknowledged the re-driven bulk")
	}

	standbyDP := &mockSweepDP{
		v4sessions:     map[dataplane.SessionKey]dataplane.SessionValue{},
		sessionCounter: 1,
	}
	standby := NewSessionSync(":0", "10.0.0.1:4785", standbyDP)
	standby.IsPrimaryFn = func() bool { return false }
	standby.IsPrimaryForRGFn = func(int) bool { return false }
	standby.SetZoneRGMap(map[uint16]int{zone: 2})

	starts, ends := replayBulkFrames(t, standby, cap.bytes())
	if starts != 1 || ends != 1 {
		t.Fatalf("#82: expected exactly one BulkStart/BulkEnd window on the wire, got starts=%d ends=%d", starts, ends)
	}
	if _, ok := standbyDP.v4sessions[preExisting]; !ok {
		t.Fatal("#82: the session that existed before startup was never replicated to the standby")
	}
}

// countBulkMarkers counts BulkStart/BulkEnd frames in a captured stream without
// replaying them into a standby.
func countBulkMarkers(t *testing.T, buf []byte) (starts, ends int) {
	t.Helper()
	for len(buf) > 0 {
		if len(buf) < syncHeaderSize {
			t.Fatalf("truncated frame header: %d bytes left", len(buf))
		}
		typ := buf[4]
		n := binary.LittleEndian.Uint32(buf[8:12])
		buf = buf[syncHeaderSize:]
		if uint32(len(buf)) < n {
			t.Fatalf("truncated payload: want %d, have %d", n, len(buf))
		}
		buf = buf[n:]
		switch typ {
		case syncMsgBulkStart:
			starts++
		case syncMsgBulkEnd:
			ends++
		}
	}
	return starts, ends
}
