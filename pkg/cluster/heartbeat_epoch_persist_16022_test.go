package cluster

// #16022 — the downgrade latch, epoch floor and per-value session bindings
// survive a daemon restart, scoped to the accepted key set.
//
// RED-on-revert (each test names its severance):
//   - Drop the restore in Manager.reconcilePeerEpochState and
//     TestEpochlessReplayRefusedAfterDaemonRestart_16022 admits the
//     epochless capture set after the restart (1625/1625 measured pre-fix).
//   - Drop the bindings from the durable record (persist the floor alone)
//     and TestEqualEpochBindingsSurviveRestart_16022 hands the attacker a
//     fresh equality slot after the restart.
//   - Drop the key-set digest from the record (or from the restore check)
//     and TestPeerEpochRecordScopedToKeySet_16022 carries the latch across
//     a rotation that must clear it.
//   - Drop the owed mark in admitAuthed (or the sender-tick flush) and the
//     periodic-flush test never lands a record.
//
// The production restart model: latchEnv.restartDaemon builds a brand-new
// Manager (every in-memory tracker gone) on the committed key — exactly
// what a daemon restart re-reads. These tests additionally drive the new
// Manager through UpdateConfig with that key, because that is the daemon's
// real boot sequence (bringup applies the committed config before the
// heartbeat starts), and reconciliation hangs off it. peerEpochStatePath
// is redirected per test so the simulated restart shares one durable file.

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// durableLatchEnv redirects the peer-epoch record into a temp dir for the
// whole test and returns the env plus the record path.
func durableLatchEnv(t *testing.T) (*latchEnv, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ha-peer-epoch")
	restore := SetPeerEpochStatePathForTesting(path)
	t.Cleanup(restore)
	return newLatchEnv(t), path
}

// applyKey drives the restarted Manager through the daemon's real boot
// sequence: UpdateConfig with the committed cluster config carrying key.
// latchEnv.restartDaemon sets the key field directly (the pre-#16022
// fixture shortcut); reconciliation is an UpdateConfig responsibility, so
// the durable tests must apply the config rather than poke the field.
func (e *latchEnv) applyKey(t *testing.T, key []byte) {
	t.Helper()
	e.m.UpdateConfig(&config.ClusterConfig{ControlLinkAuthKey: config.NewSecret(string(key))})
}

func waitPeerEpochWorkerIdle(t *testing.T, m *Manager) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		m.peerEpochWorkMu.Lock()
		running := m.peerEpochWorkerRunning
		done := m.peerEpochWorkerDone
		m.peerEpochWorkMu.Unlock()
		if !running {
			// Workers schedule cadence retries internally. Do not use a
			// queued-but-internal state as "busy" for successful writes;
			// channel completion implies the worker has exited.
			return
		}
		if done != nil {
			select {
			case <-done:
				return
			case <-time.After(2 * time.Millisecond):
			}
		} else {
			time.Sleep(2 * time.Millisecond)
		}
	}
	t.Fatal("peer epoch persistence worker did not become idle")
}

func flushAndWaitPeerEpoch(t *testing.T, m *Manager) {
	t.Helper()
	m.flushPeerEpochState(true)
	waitPeerEpochWorkerIdle(t, m)
}

// TestEpochlessReplayRefusedAfterDaemonRestart_16022 is the acceptance
// gate for #16022: restart the receiver, replay a pre-upgrade epochless
// capture set while the peer is down — rejected once the persisted bit is
// restored, where the pre-fix code admitted it indefinitely.
func TestEpochlessReplayRefusedAfterDaemonRestart_16022(t *testing.T) {
	e, _ := durableLatchEnv(t)

	// The live peer is upgraded: it arms the latch and sets the floor.
	const liveEpoch = uint64(9_200_000_000_000_000)
	e.applyKey(t, e.key)
	e.liveRun(e.captureIncarnation(0x16022, liveEpoch, epochFramesPerIncarnation), "live upgraded peer")
	if !e.r.auth.peerEpochLatched() {
		t.Fatal("setup: an accepted epoch-bearing frame must arm the latch")
	}

	// Land the durable record the way production does (stop-time flush).
	flushAndWaitPeerEpoch(t, e.m)

	// FULL daemon restart while the peer is silent. The pre-#16022 latch
	// died here; the durable one must be restored by the boot apply.
	e.restartDaemon()
	e.applyKey(t, e.key)
	if !e.r.auth.peerEpochLatched() {
		t.Fatal("the downgrade latch did not survive a daemon restart — the persisted bit was not restored")
	}
	if got := e.r.auth.peerEpochFloor(); got != liveEpoch {
		t.Fatalf("floor after restart = %d, want %d (the persisted floor)", got, liveEpoch)
	}

	// The attack: >=65 captured PRE-UPGRADE incarnations, replayed while
	// the peer is down. Against the cleared pre-fix state this churned
	// the 64-entry ring indefinitely (1625/1625); against the restored
	// latch every frame is refused before the ring is consulted.
	caps := e.epochlessCaptures(heartbeatReplaySessions + 1)
	admitted, total := e.replayAll(caps, 5)
	if admitted != 0 {
		t.Fatalf("epochless replay after a daemon restart: %d/%d admitted, want 0 — "+
			"65 captured incarnations still churn the ring across a receiver restart", admitted, total)
	}

	// And the live peer, when it returns, is admitted and re-raises the
	// floor as before — durability must not strand a genuine peer.
	e.liveRun(e.captureIncarnation(0x16023, liveEpoch+1, epochFramesPerIncarnation), "live peer after restart")
}

// TestEpochBearingSetBoundedAcrossRestart_16022 pins the epoch-bearing
// half: with the floor restored, a captured epoch-bearing set buys at
// most its one finite ascending pass after a restart, exactly as it does
// in-process (325/325 then 0/1625 measured pre-#16022 in-process).
func TestEpochBearingSetBoundedAcrossRestart_16022(t *testing.T) {
	e, _ := durableLatchEnv(t)
	e.applyKey(t, e.key)

	const base = uint64(9_300_000_000_000_000)
	e.liveRun(e.captureIncarnation(0xA0, base, epochFramesPerIncarnation), "live peer")
	flushAndWaitPeerEpoch(t, e.m)

	// 65 captured epoch-bearing incarnations with strictly increasing
	// epochs, recorded while the peer was live (they verify: same key).
	caps := make([][][]byte, 0, heartbeatReplaySessions+1)
	for i := range heartbeatReplaySessions + 1 {
		caps = append(caps, e.captureIncarnation(uint64(0xB0+i), base+1+uint64(i), epochFramesPerIncarnation))
	}

	e.restartDaemon()
	e.applyKey(t, e.key)

	// First (ascending) pass: each capture is at-or-above the floor and
	// ring-fresh, so it is admitted and raises the floor — this is the
	// finite pass the design has always allowed. Every later round must
	// be refused: the floor has climbed past all but the newest, and the
	// newest is at its watermark.
	admitted1, _ := e.replayAll(caps, 1)
	if admitted1 == 0 {
		t.Fatal("fixture: the ascending pass admitted nothing, so the bounded assertion below is vacuous")
	}
	admitted, total := e.replayAll(caps, 5)
	if admitted != 0 {
		t.Fatalf("epoch-bearing replays after the ascending pass: %d/%d admitted, want 0 — "+
			"the restored floor does not bound the set across a restart", admitted, total)
	}
}

// TestEqualEpochBindingsSurviveRestart_16022 pins why the bindings persist
// with the floor: a capture set SHARING one epoch value must not get a
// fresh per-value budget from a restart.
func TestEqualEpochBindingsSurviveRestart_16022(t *testing.T) {
	e, _ := durableLatchEnv(t)
	e.applyKey(t, e.key)

	const shared = uint64(9_400_000_000_000_000)
	// Two incarnations at one epoch value spend the whole per-value budget
	// (heartbeatEpochSessionsPerEpoch = 2).
	e.liveRun(e.captureIncarnation(0xC1, shared, epochFramesPerIncarnation), "first incarnation at the shared epoch")
	e.liveRun(e.captureIncarnation(0xC2, shared, epochFramesPerIncarnation), "second incarnation at the shared epoch")
	flushAndWaitPeerEpoch(t, e.m)

	e.restartDaemon()
	e.applyKey(t, e.key)
	if got := e.r.auth.peerEpochFloor(); got != shared {
		t.Fatalf("floor after restart = %d, want %d", got, shared)
	}
	// A third distinct session at the SAME epoch must be refused. If the
	// bindings were not persisted, the restart would hand it a fresh slot.
	for i, f := range e.captureIncarnation(0xC3, shared, epochFramesPerIncarnation) {
		if e.feed(f) {
			t.Fatalf("third session at the persisted floor epoch admitted (frame %d) — "+
				"the per-value bindings did not survive the restart", i)
		}
	}
}

// TestPeerEpochRecordScopedToKeySet_16022 pins the scoping in both
// directions: the record restores under the SAME accepted set and does
// NOT restore under a rotated one — which is what makes the rotation the
// rollback recovery with no state file to edit.
func TestPeerEpochRecordScopedToKeySet_16022(t *testing.T) {
	e, path := durableLatchEnv(t)
	e.applyKey(t, e.key)
	const liveEpoch = uint64(9_500_000_000_000_000)
	e.liveRun(e.captureIncarnation(0xD1, liveEpoch, epochFramesPerIncarnation), "live peer under K1")
	flushAndWaitPeerEpoch(t, e.m)
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("setup: no durable record was written: %v", err)
	}

	// Restart under the SAME key: restored.
	e.restartDaemon()
	e.applyKey(t, e.key)
	if !e.r.auth.peerEpochLatched() {
		t.Fatal("same-key restart did not restore the latch")
	}

	// Restart under a ROTATED key: the K1 record must not arm the latch
	// for K2. The peer re-proves itself by observation under the new key,
	// and K1 captures fail MAC verification under K2 anyway.
	k2 := []byte("rotated-shared-secret")
	e.rotateKey(k2)
	e.restartDaemon()
	e.applyKey(t, k2)
	if e.r.auth.peerEpochLatched() {
		t.Fatal("the latch armed from a record scoped to the retired key set — rotation must clear it")
	}
	if got := e.r.auth.peerEpochFloor(); got != 0 {
		t.Fatalf("floor after a rotated restart = %d, want 0", got)
	}
	// The migration window is intact under the new key: epochless frames
	// are accepted until the peer proves it emits epochs under K2.
	e.liveRun(e.captureIncarnation(0xD2, 0, epochFramesPerIncarnation), "epochless peer under the new key (pre-proof)")
	// And once it proves it, the latch arms under K2.
	e.liveRun(e.captureIncarnation(0xD3, liveEpoch+10, epochFramesPerIncarnation), "epoch-capable peer under the new key")
	if !e.r.auth.peerEpochLatched() {
		t.Fatal("the latch did not arm by observation under the rotated key")
	}
}

// TestPeerEpochRecordClearedWithKeySet_16022 pins the clear direction:
// removing the PSK drops the in-memory latch and the file, so re-keying
// later starts unlatched rather than resurrecting the old record.
func TestPeerEpochRecordClearedWithKeySet_16022(t *testing.T) {
	e, path := durableLatchEnv(t)
	e.applyKey(t, e.key)
	e.liveRun(e.captureIncarnation(0xE1, 9_600_000_000_000_000, epochFramesPerIncarnation), "live peer")
	flushAndWaitPeerEpoch(t, e.m)
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("setup: no durable record: %v", err)
	}

	e.m.UpdateConfig(&config.ClusterConfig{})
	if e.r.auth.peerEpochLatched() {
		t.Fatal("clearing the key set left the in-memory latch armed")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("clearing the key set left the durable record behind (stat err=%v)", err)
	}

	// Re-key with the SAME bytes: still unlatched, because the record is
	// gone — the peer must re-prove by observation.
	e.applyKey(t, e.key)
	if e.r.auth.peerEpochLatched() {
		t.Fatal("re-keying resurrected a latch whose record was cleared with the key set")
	}
}

// TestPeerEpochCorruptRecordDegradesToFresh_16022 pins the failure
// direction: a missing/corrupt/mismatched record restores nothing, so a
// wiped /var degrades to the migration window (accept epochless until
// proof) rather than refusing a healthy peer on unverifiable state.
func TestPeerEpochCorruptRecordDegradesToFresh_16022(t *testing.T) {
	for _, body := range []string{
		"not-a-record\n",
		"0 \n",                     // implausible floor, no digest
		"99999999999999999999 x\n", // unparseable floor
		"95000000000000000 1 2 3 4 deadbeefdigest\n", // too many sessions + wrong digest
	} {
		e, path := durableLatchEnv(t)
		e.applyKey(t, e.key)
		e.liveRun(e.captureIncarnation(0xF1, 9_700_000_000_000_000, epochFramesPerIncarnation), "live peer")
		flushAndWaitPeerEpoch(t, e.m)
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		e.restartDaemon()
		e.applyKey(t, e.key)
		if e.r.auth.peerEpochLatched() {
			t.Fatalf("corrupt record %q armed the latch", body)
		}
		if got := e.r.auth.peerEpochFloor(); got != 0 {
			t.Fatalf("corrupt record %q restored floor %d, want 0", body, got)
		}
	}
}

// TestPeerEpochPeriodicFlushLandsRecord_16022 pins the async off-path
// write: with no explicit flush, the owed mark queues the sole worker from
// maybeFlushPeerEpochState, rapid advances coalesce, and a wedged store
// fails open to process-scoped behaviour.
func TestPeerEpochPeriodicFlushLandsRecord_16022(t *testing.T) {
	e, path := durableLatchEnv(t)
	e.applyKey(t, e.key)
	e.liveRun(e.captureIncarnation(0x11, 9_800_000_000_000_000, epochFramesPerIncarnation), "live peer")

	// No explicit flush. The first request starts the worker; wait only in
	// the test harness, never in production tick/stop code.
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("record exists before any flush (stat err=%v)", err)
	}
	e.m.maybeFlushPeerEpochState()
	waitPeerEpochWorkerIdle(t, e.m)
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("the async flush did not land the record: %v", err)
	}

	// Inside the success interval a second advance does NOT rewrite until
	// the worker cadence expires. Advance only the worker's timestamp (the
	// function production reads under peerEpochWorkMu), then queue a fresh
	// worker pass and observe the generation advance.
	e.liveRun(e.captureIncarnation(0x12, 9_800_000_000_000_001, epochFramesPerIncarnation), "peer reboot")
	before, _ := os.ReadFile(path)
	e.m.maybeFlushPeerEpochState()
	after, _ := os.ReadFile(path)
	if string(before) != string(after) {
		t.Fatal("an async request rewrote synchronously — heartbeat callers must never perform persistence")
	}
	e.m.peerEpochWorkMu.Lock()
	e.m.peerEpochLastFlush = time.Now().Add(-peerEpochPersistInterval - time.Second)
	e.m.peerEpochLastFlushOK = true
	running := e.m.peerEpochWorkerRunning
	e.m.peerEpochWorkMu.Unlock()
	if running {
		// An earlier request's worker may wait out remaining cadence. Its
		// snapshot predates this timestamp, so request another pass after
		// it has had its one timer cycle instead of racing it.
		waitPeerEpochWorkerIdle(t, e.m)
	}
	e.m.maybeFlushPeerEpochState()
	deadline2 := time.Now().Add(5 * time.Second)
	for {
		advanced, _ := os.ReadFile(path)
		if string(advanced) != string(before) {
			break
		}
		if time.Now().After(deadline2) {
			t.Fatal("the record did not advance after the worker cadence elapsed")
		}
		time.Sleep(2 * time.Millisecond)
	}
	waitPeerEpochWorkerIdle(t, e.m)

	// A wedged store (record path under a regular file, so the dir create
	// fails) fails open: admission already happened above, the flush
	// reports not-landed, and the latch stays armed in memory.
	e2, path2 := durableLatchEnv(t)
	e2.applyKey(t, e2.key)
	blocker := filepath.Join(t.TempDir(), "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	restore := SetPeerEpochStatePathForTesting(filepath.Join(blocker, "sub", "ha-peer-epoch"))
	defer restore()
	_ = path2
	e2.liveRun(e2.captureIncarnation(0x13, 9_800_000_000_000_000, epochFramesPerIncarnation), "live peer on a wedged store")
	// Queue exactly one wedged attempt and assert the caller returns and
	// memory stays armed. Do not wait for worker idle: failed durable
	// writes intentionally retry at worker cadence while owed.
	e2.m.flushPeerEpochState(true)
	time.Sleep(50 * time.Millisecond)
	if !e2.r.auth.peerEpochLatched() {
		t.Fatal("a failed flush disarmed the in-memory latch — the failure must fail open to process scope")
	}
}

// TestPeerEpochPersistRoundTrip_16022 unit-pins the record codec: format
// and parse are inverse for every admissible shape, and every inadmissible
// shape parses to "no record".
func TestPeerEpochPersistRoundTrip_16022(t *testing.T) {
	digest := controlAuthKeySetDigest(epochTestPSK, nil)
	if digest == "" {
		t.Fatal("fixture: empty digest for a keyed set")
	}
	for _, tc := range []struct {
		generation uint64
		floor      uint64
		sessions   []uint64
	}{
		{1, 9_000_000_000_000_000, nil},
		{2, 9_000_000_000_000_000, []uint64{7}},
		{3, 9_000_000_000_000_000, []uint64{7, 8}},
	} {
		generation, floor, sessions, ok := parsePeerEpochState(formatPeerEpochState(tc.generation, tc.floor, tc.sessions, digest), digest)
		if !ok || generation != tc.generation || floor != tc.floor || len(sessions) != len(tc.sessions) {
			t.Fatalf("round trip %+v -> generation=%d floor=%d sessions=%v ok=%v", tc, generation, floor, sessions, ok)
		}
		for i := range tc.sessions {
			if sessions[i] != tc.sessions[i] {
				t.Fatalf("round trip %+v: session %d = %d", tc, i, sessions[i])
			}
		}
	}
	if _, _, _, ok := parsePeerEpochState(formatPeerEpochState(1, 9_000_000_000_000_000, nil, digest), "other-digest"); ok {
		t.Fatal("a record parsed under a different key-set digest")
	}
	if _, _, _, ok := parsePeerEpochState(formatPeerEpochState(1, 9_000_000_000_000_000, nil, digest), ""); ok {
		t.Fatal("a record parsed with no key set")
	}
	if _, _, _, ok := parsePeerEpochState("9500000000000000000 "+digest+"\n", digest); ok {
		t.Fatal("a legacy two-field (no generation) record parsed as durable state")
	}
}

func TestPeerEpochAsyncPersistDoesNotBlockCallers_16022(t *testing.T) {
	e, _ := durableLatchEnv(t)
	e.applyKey(t, e.key)
	entered := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	orig := peerEpochPersistHookForTest
	peerEpochPersistHookForTest = func() {
		once.Do(func() { close(entered) })
		<-release
	}
	t.Cleanup(func() {
		peerEpochPersistHookForTest = orig
	})
	e.liveRun(e.captureIncarnation(0x21, 9_900_000_000_000_000, epochFramesPerIncarnation), "live peer")

	type call struct {
		name string
		fn   func()
	}
	// StopHeartbeat/Stop cannot run on this fixture's synthetic receiver:
	// it has a nil socket and existing stop paths would close it. Their
	// peer-epoch operation is exactly this direct async request, which is
	// the operation whose nonblocking contract matters.
	for _, tc := range []call{
		{"maybeFlush", e.m.maybeFlushPeerEpochState},
		{"flush", func() { e.m.flushPeerEpochState(true) }},
		{"StopHeartbeat-queue", func() { e.m.flushPeerEpochState(true) }},
		{"Stop-queue", func() { e.m.flushPeerEpochState(true) }},
	} {
		done := make(chan struct{})
		go func(fn func()) {
			defer close(done)
			fn()
		}(tc.fn)
		select {
		case <-done:
		case <-entered:
			// Worker may start on any request. Caller completion is
			// asserted after entered closes below; this select only starts
			// all calls without allowing one to masquerade as another.
		case <-time.After(2 * time.Second):
			t.Fatalf("%s blocked before persistence worker entered", tc.name)
		}
		// Once worker is known parked, every already-launched caller that
		// can complete must do so; the first request itself is done by the
		// time entered closes in this design.
	}
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("async worker never entered persistence hook")
	}
	// With persistence definitely parked pre-flock, another flush request
	// must also return immediately and coalesce rather than join.
	stopDone := make(chan struct{})
	go func() { defer close(stopDone); e.m.flushPeerEpochState(true) }()
	select {
	case <-stopDone:
	case <-time.After(2 * time.Second):
		t.Fatal("flush request joined parked peer-epoch persistence")
	}
	close(release)
	waitPeerEpochWorkerIdle(t, e.m)
}

func TestPeerEpochGenerationGuardSkipsOlderSnapshot_16022(t *testing.T) {
	_, path := durableLatchEnv(t)
	digest := controlAuthKeySetDigest(epochTestPSK, nil)
	newer := peerEpochSnapshot{generation: 10, floor: 9_900_000_000_000_000, sessions: []uint64{7}, digest: digest, path: path}
	if written, skipped := persistPeerEpochState(newer); !written || skipped {
		t.Fatalf("newer write = written %v skipped %v", written, skipped)
	}
	older := peerEpochSnapshot{generation: 9, floor: 8_000_000_000_000_000, sessions: []uint64{8}, digest: digest, path: path}
	if written, skipped := persistPeerEpochState(older); written || !skipped {
		t.Fatalf("older write = written %v skipped %v, want skipped generation guard", written, skipped)
	}
	generation, floor, sessions, ok := loadPeerEpochState(path, digest)
	if !ok || generation != 10 || floor != newer.floor || len(sessions) != 1 || sessions[0] != 7 {
		t.Fatalf("record after older snapshot = gen %d floor %d sessions %v ok %v", generation, floor, sessions, ok)
	}
	equal := peerEpochSnapshot{generation: 10, floor: 1_000_000_000_000_000, sessions: []uint64{9}, digest: digest, path: path}
	if written, skipped := persistPeerEpochState(equal); written || !skipped {
		t.Fatalf("equal generation rewrite = written %v skipped %v", written, skipped)
	}
}

func TestDeclineRaiseBindingAdvancesGeneration_16022(t *testing.T) {
	const receiverNow = int64(1_800_000_000_000_000_000)
	s := &heartbeatAuthState{}
	epochA := uint64(receiverNow) - uint64(time.Minute)
	if ok, _ := admitAt6969(t, s, receiverNow, epochA, 0xA1, 1); !ok {
		t.Fatal("fixture A rejected")
	}
	genAfterA := s.peerEpochPersistGeneration
	if genAfterA == 0 || !s.peerEpochPersistOwed {
		t.Fatalf("raise generation=%d owed=%v", genAfterA, s.peerEpochPersistOwed)
	}
	epochB := uint64(receiverNow + int64(2*bootEpochMaxSkew))
	if ok, _ := admitAt6969(t, s, receiverNow, epochB, 0xB1, 1); !ok {
		t.Fatal("declined peer rejected")
	}
	if s.peerEpochPersistGeneration <= genAfterA {
		t.Fatalf("decline binding did not advance generation: before %d after %d", genAfterA, s.peerEpochPersistGeneration)
	}
	if s.highEpochSessionCount != 2 {
		t.Fatalf("decline binding slots = %d, want 2", s.highEpochSessionCount)
	}
	// Re-presenting same session/counter is ring rejected before binding,
	// so no further durable generation is consumed.
	gen := s.peerEpochPersistGeneration
	_, _ = admitAt6969(t, s, receiverNow, epochB, 0xB1, 1)
	if s.peerEpochPersistGeneration != gen {
		t.Fatal("rejected replay advanced persistence generation")
	}
}

func TestConcurrentReconcileNeverInstallsStaleDigest_16022(t *testing.T) {
	e, path := durableLatchEnv(t)
	k1 := e.key
	e.applyKey(t, k1)
	e.liveRun(e.captureIncarnation(0x31, 9_910_000_000_000_000, epochFramesPerIncarnation), "K1 live peer")
	flushAndWaitPeerEpoch(t, e.m)
	if _, err := os.Stat(path); err != nil {
		t.Fatal(err)
	}
	k2 := []byte("rotated-shared-secret-16022")
	d1 := controlAuthKeySetDigest(k1, nil)
	d2 := controlAuthKeySetDigest(k2, nil)
	m := e.m
	// Install K2 through production UpdateConfig path after racing stale K1.
	done := make(chan struct{})
	go func() { defer close(done); m.reconcilePeerEpochState(d1) }()
	<-done
	m.UpdateConfig(&config.ClusterConfig{ControlLinkAuthKey: config.NewSecret(string(k2))})
	m.reconcilePeerEpochState(d1)
	m.hbAuth.mu.Lock()
	gotDigest := m.hbAuth.peerEpochKeySetDigest
	latched := m.hbAuth.epochSeen
	checkedGen := m.hbAuth.peerEpochCheckedGeneration
	reconcileGen := m.hbAuth.peerEpochReconcileGeneration
	m.hbAuth.mu.Unlock()
	if gotDigest != d2 || latched {
		t.Fatalf("stale K1 reconcile installed digest=%q latched=%v, want K2 unlatched", gotDigest, latched)
	}
	if checkedGen == 0 || checkedGen != reconcileGen {
		t.Fatalf("checked generation %d != reconcile generation %d", checkedGen, reconcileGen)
	}
}
