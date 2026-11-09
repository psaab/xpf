package cluster

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/fsatomic"
)

// #6669 fold round 10 — the floor's replacement claim was false FOR EQUAL
// EPOCHS, and two of the recovery claims around it were unconditional when the
// behaviour is not.
//
// The claim was: "sustained ring churn needs heartbeatReplaySessions+1 sessions
// at or above the floor, and one incarnation emits exactly one session, so
// epoch-bearing captures buy only a finite ascending pass." The step that fails
// is DISTINCT SESSIONS => DISTINCT EPOCHS. `epoch == highEpoch` fell through to
// the ring, so any number of sessions sharing ONE valid epoch were all admitted
// AT the floor and churned the ring exactly as epochless frames do.
//
// The measurement that produced the claim could not see it: the corpus in
// heartbeat_epoch_test.go hard-codes strictly increasing epochs (1000+i), so it
// held constant the very variable the defect lives in.
//
// The fix binds the floor to a BOUNDED SET of sessions
// (heartbeatAuthState.highEpochSessions, heartbeatEpochSessionsPerEpoch slots,
// reset by a raise). Round 10 shipped that set as a singleton, which refused a
// legitimate successor incarnation on every heartbeat — see
// TestEqualEpochSuccessorIsAdmitted_6669. These tests pin the closed hole, the
// live-peer path it must not break, and both doors out of a poisoned floor.

// TestEqualEpochsCannotChurnTheRing_6669 is the fail-on-revert gate for the
// equal-epoch replay hole.
//
// RED-on-revert: delete the `epoch == s.highEpoch &&
// !s.epochSessionAdmissible(session)` rejection in admitAuthed (or move
// it AFTER the s.replay.admit call, which is the same ordering bug the floor
// itself has to avoid) and both subtests go back to sustained admits.
func TestEqualEpochsCannotChurnTheRing_6669(t *testing.T) {
	// ALL captures share ONE epoch. This is what a sender with a clock at or
	// before the Unix epoch emits: bootEpochSeed returns the literal 1 for every
	// incarnation, and a store that never completes never raises it.
	t.Run("all_captures_share_one_epoch", func(t *testing.T) {
		e := newEpochEnv(t)
		const n = heartbeatReplaySessions + 1
		const shared = uint64(1_700_000_000_000_000_000)

		caps := make([][][]byte, 0, n)
		for i := 0; i < n; i++ {
			frames := e.captureIncarnation(uint64(0x7000+i), shared, epochFramesPerIncarnation)
			for _, f := range frames {
				e.feed(f)
			}
			caps = append(caps, frames)
		}

		admitted, total := e.replayAll(caps, 5)
		if admitted != 0 {
			t.Fatalf("%d/%d equal-epoch replays admitted, want 0 — %d captured sessions sharing "+
				"one epoch churn the ring exactly as epochless frames do, so the floor buys "+
				"nothing against them", admitted, total, n)
		}
		if got := e.r.auth.peerEpochFloor(); got != shared {
			t.Fatalf("floor = %d, want %d", got, shared)
		}
	})

	// EQUAL MAXIMUM. The sharpest shape: the captures ascend normally — so the
	// ascending pass the claim describes really happens — but the TOP value is
	// shared by heartbeatReplaySessions+1 distinct sessions. Ascending epochs
	// alone (the corpus the original measurement used) cannot reach this.
	t.Run("equal_maximum_epoch_across_many_sessions", func(t *testing.T) {
		e := newEpochEnv(t)
		const ascending = 4
		const atMax = heartbeatReplaySessions + 1
		const base = uint64(1_700_000_000_000_000_000)
		maxEpoch := base + ascending // strictly above every ascending value

		caps := make([][][]byte, 0, ascending+atMax)
		for i := 0; i < ascending; i++ {
			frames := e.captureIncarnation(uint64(0x8000+i), base+uint64(i), epochFramesPerIncarnation)
			e.liveRun(frames, "ascending capture")
			caps = append(caps, frames)
		}
		for i := 0; i < atMax; i++ {
			frames := e.captureIncarnation(uint64(0x9000+i), maxEpoch, epochFramesPerIncarnation)
			for _, f := range frames {
				e.feed(f)
			}
			caps = append(caps, frames)
		}

		admitted, total := e.replayAll(caps, 5)
		if admitted != 0 {
			t.Fatalf("%d/%d replays admitted, want 0 — %d sessions sharing the MAXIMUM epoch "+
				"sustain the churn even though every capture below them is ordered",
				admitted, total, atMax)
		}
		if got := e.r.auth.peerEpochFloor(); got != maxEpoch {
			t.Fatalf("floor = %d, want %d (a replay must never move the floor)", got, maxEpoch)
		}
		if got := e.m.HeartbeatStats().EpochSessionCollision; got == 0 {
			t.Fatal("EpochSessionCollision stayed 0; the operator cannot see the regime that " +
				"produces equal epochs")
		}
	})
}

// TestFloorRebindsToTheRaisingIncarnation_6669 is the negative control, and it
// must pass both WITH and WITHOUT the session binding.
//
// Rejecting at equality is only safe because the LIVE peer keeps its session
// for the life of its incarnation (Manager.heartbeatNonce, #6169 Stage 0) while
// its epoch only ever rises. A guard that rejected every frame at the floor
// would make the test above pass and take the cluster down; this is what
// separates the two.
func TestFloorRebindsToTheRaisingIncarnation_6669(t *testing.T) {
	e := newEpochEnv(t)
	const liveSession = uint64(0xC0FE)
	epoch := uint64(time.Now().Add(-time.Hour).UnixNano())

	// A long run at ONE epoch from ONE session: every frame admitted. This is
	// the ordinary case — a peer emits many heartbeats per second, all carrying
	// the epoch it published at boot.
	for c := 1; c <= 50; c++ {
		if !e.feed(marshalHeartbeatAuthEpoch(samplePkt(), e.key, liveSession, uint64(c), epoch)) {
			t.Fatalf("frame %d from the live peer at its OWN bound floor was rejected; the peer "+
				"is declared dead in ~500ms and the cluster goes dual-master", c)
		}
	}
	// Refinement raises the peer's epoch mid-incarnation: the session does not
	// change, and the floor must follow.
	raised := epoch + 1
	if !e.feed(marshalHeartbeatAuthEpoch(samplePkt(), e.key, liveSession, 51, raised)) {
		t.Fatal("the live peer's mid-incarnation epoch raise was rejected")
	}
	if got := e.r.auth.peerEpochFloor(); got != raised {
		t.Fatalf("floor = %d after the raise, want %d", got, raised)
	}
	// And it keeps being admitted at the new floor.
	if !e.feed(marshalHeartbeatAuthEpoch(samplePkt(), e.key, liveSession, 52, raised)) {
		t.Fatal("the live peer was rejected at the floor it had just raised — the binding did " +
			"not follow the raise")
	}
	if got := e.m.HeartbeatStats().EpochSessionCollision; got != 0 {
		t.Fatalf("EpochSessionCollision = %d on a purely legitimate run, want 0", got)
	}
}

// TestPoisonedFloorStillRecoversByRaise_6669 pins BOTH doors out of a poisoned
// floor (#6711), which is the shape the equal-epoch bound changed.
//
// While equality fell through to the ring unconditionally, the only statement
// was "a regressed sender that has climbed back to exactly the floor is
// admitted". Round 10 replaced that with a singleton binding, which shut the
// equality door completely — the archived frame had bound its own session, so
// the live peer at exactly the floor was refused. The bound is now
// heartbeatEpochSessionsPerEpoch rather than one, so BOTH doors are open and
// each has a different shape:
//
//   - AT the floor, while a slot is free. Narrow (one exact value) and finite
//     (the slots do not refill), but it is the door a legitimate successor
//     incarnation that republished its predecessor's epoch comes through.
//   - STRICTLY past the floor. One nanosecond of wall clock rather than an
//     exact value, and never exhausted, so it is the wider of the two.
func TestPoisonedFloorStillRecoversByRaise_6669(t *testing.T) {
	e := newEpochEnv(t)
	const archivedSession, liveSession = uint64(0xAAAA), uint64(0xBBBB)
	floor := uint64(time.Now().Add(-time.Hour).UnixNano())

	// An archived frame from a retired incarnation raises and binds the floor.
	if !e.feed(marshalHeartbeatAuthEpoch(samplePkt(), e.key, archivedSession, 1, floor)) {
		t.Fatal("the archived frame was refused; the #6711 premise is not reachable")
	}

	// The regressed live peer sits below it — pre-existing #6711, unchanged.
	if e.feed(marshalHeartbeatAuthEpoch(samplePkt(), e.key, liveSession, 1, floor-1000)) {
		t.Fatal("a frame BELOW the floor was admitted")
	}
	// AT it under its own session: admitted, because a slot is free. This is the
	// door a successor incarnation needs, and shutting it is what made a healthy
	// node refused on every heartbeat.
	if !e.feed(marshalHeartbeatAuthEpoch(samplePkt(), e.key, liveSession, 2, floor)) {
		t.Fatal("the live peer was refused AT the floor with a slot free; a successor " +
			"incarnation that republished its predecessor's epoch is locked out")
	}
	// But the door is FINITE. With the slots spent, a further session at the
	// same value is refused however many times it asks — that is what keeps a
	// shared-epoch capture set from churning the ring.
	for c := 1; c <= 20; c++ {
		if e.feed(marshalHeartbeatAuthEpoch(samplePkt(), e.key, 0xCCCC, uint64(c), floor)) {
			t.Fatalf("frame %d from a third session was admitted at one epoch value; the "+
				"equal-epoch churn is open", c)
		}
	}

	// One nanosecond past: admitted, and the floor rebinds to the live peer.
	if !e.feed(marshalHeartbeatAuthEpoch(samplePkt(), e.key, liveSession, 3, floor+1)) {
		t.Fatal("the live peer was refused ONE NANOSECOND past the floor — recovery by raise " +
			"is broken, and #6711 becomes unrecoverable rather than merely slow")
	}
	if got := e.r.auth.peerEpochFloor(); got != floor+1 {
		t.Fatalf("floor = %d, want %d", got, floor+1)
	}
	if !e.feed(marshalHeartbeatAuthEpoch(samplePkt(), e.key, liveSession, 4, floor+1)) {
		t.Fatal("the live peer was refused at the floor it had just raised")
	}
}

// TestOverlappingRefineRequestIsCoalesced_6669 is the fail-on-revert gate for
// the dropped recovery request.
//
// startBootEpochRefine used to DROP a refine requested while one was in flight.
// The in-flight worker's locked read can already be complete, so an update that
// lands behind it is invisible to that pass — and the caller who lost the CAS is
// the one asking for the re-read. Dropping it left this node below its peer's
// floor until some later heartbeat start, which nothing bounds (#6724).
//
// The schedule below is that exact shape, driven deterministically through the
// epochFlock seam: pass 1 is held at the lock, a refresh is requested and lost,
// and the update the request exists to pick up lands only AFTER pass 1 has read
// the file — so nothing but a SECOND pass can see it.
//
// RED-on-revert: restore the `if !CAS(false, true) { return }` early return in
// startBootEpochRefine (dropping the bootEpochRefinePending store) and this
// times out waiting for pass 2.
func TestOverlappingRefineRequestIsCoalesced_6669(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ha-boot-epoch")
	m := keyedEpochManager(t, path)

	var passes atomic.Int64
	entered := make(chan int, 8)
	releasePass1 := make(chan struct{})
	releasePass2 := make(chan struct{})
	origFlock := epochFlock
	epochFlock = func(fd int, how int) error {
		switch passes.Add(1) {
		case 1:
			entered <- 1
			<-releasePass1
		case 2:
			entered <- 2
			<-releasePass2
		}
		return origFlock(fd, how)
	}
	t.Cleanup(func() { epochFlock = origFlock })

	// UNPARK ON THE FAILURE PATH TOO: t.Fatalf runs runtime.Goexit and skips the
	// explicit release(s) below, which would leave the parked worker in the seam
	// for the rest of the package run, reading vars a later test assigns.
	var p1Once, p2Once sync.Once
	unparkPass1 := func() { p1Once.Do(func() { close(releasePass1) }) }
	unparkPass2 := func() { p2Once.Do(func() { close(releasePass2) }) }
	t.Cleanup(func() {
		unparkPass1()
		unparkPass2()
	})

	m.initHeartbeatEpochState()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("pass 1 never reached the lock")
	}
	// ANCHORED ON THE PARKED WORKER, NOT ON A PRE-EXISTENCE BASELINE. Sampling
	// before initHeartbeatEpochState counts whatever this package still has in
	// flight from EARLIER tests, and if one of those exits before the check the
	// delta reads one lower — observed once under concurrent-process stress as
	// "0 package goroutines ... want exactly 1", never reproduced in isolation
	// at -count=500. Every comparison below is instead between two samples taken
	// while pass 1 is deterministically parked, so background drift before the
	// park cannot reach them and the property asserted — that these requests add
	// no goroutine — is the one actually measured.
	goParked := clusterGoroutines()

	// The request that must not be lost, made while pass 1 is in flight.
	m.refreshBootEpoch()

	// OWNERSHIP, ASSERTED DIRECTLY — and NOT redundant with the assertions that
	// follow, however much it may look it.
	//
	// Everything below checks CONSEQUENCES of coalescing: that a second pass
	// happens at all, and that the epoch chains from the raised file. Those do
	// catch a concurrent second worker today — measured, three ways — but they
	// catch it INCIDENTALLY. The epoch assertion turns on
	// epochOrderable(n+1, now); bootEpochMaxSkew is exactly 60*60*1e9 and this
	// test raises the file by exactly time.Hour, so whether it fires depends on
	// the wall clock advancing past the published epoch between the raise and
	// the worker's read. That is a scheduler-timing boundary. The day someone
	// widens the skew constant or loosens that assertion, the concurrency
	// detection vanishes silently from a test still named IsCoalesced. The third
	// variant is caught only by the race detector, which is not present in every
	// leg someone might run.
	//
	// This line is the only one that names the invariant the running/pending bit
	// design exists for: the request COALESCES ONTO THE RUNNING WORKER. A
	// request that spawned its own, concurrently or redundantly, adds a
	// goroutine here and is caught on an ownership statement rather than on
	// arithmetic. Keep both.
	//
	// "ONE WORKER MEANS ONE GOROUTINE" IS TRUE AT THIS CHECKPOINT, NOT IN
	// GENERAL, and an earlier revision of this comment stated it as a flat
	// production invariant. It is not one: releaseBootEpochRefine drops the
	// in-flight bit BEFORE the outgoing goroutine's deferred handle-clear runs
	// (see startBootEpochRefine's defer and its CAS), so a legitimate successor
	// can overlap a retiring predecessor for those few instructions and two
	// goroutines is correct. What makes the count exact HERE is the seam: pass 1
	// is deterministically parked inside epochFlock across both reads, so no
	// worker is retiring while they are taken. Anyone reusing this assertion
	// outside such a checkpoint needs to re-establish that first.
	if got := clusterGoroutines(); got != goParked {
		t.Fatalf("package goroutines went %d -> %d across the overlapping request, want no "+
			"change: the request did not coalesce onto the worker already running, it "+
			"spawned another. The flock still serialises their writes, so the epoch "+
			"assertions further down can miss this — see the comment above",
			goParked, got)
	}

	unparkPass1()

	// Pass 1 runs to completion. Pass 2 must exist at all — that is the fix.
	select {
	case n := <-entered:
		if n != 2 {
			t.Fatalf("expected pass 2, got pass %d", n)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("only %d refine pass(es) ran: the overlapping request was DROPPED, so an "+
			"update landing after pass 1's read is never picked up and this node stays "+
			"below its peer's floor", passes.Load())
	}

	// NOW another incarnation raises the file — after pass 1's read, so only
	// pass 2 can carry it. This is what the dropped request cost.
	raised := m.heartbeatBootEpoch() + uint64(time.Hour)
	if err := os.WriteFile(path, []byte(strconv.FormatUint(raised, 10)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	unparkPass2()
	waitBootEpochIdle(t, m)

	if got := m.heartbeatBootEpoch(); got <= raised {
		t.Fatalf("published epoch = %d, want > %d — the coalesced pass ran but did not chain "+
			"from the value another incarnation left in the file", got, raised)
	}
}

// TestLateRefineRequestIsReclaimed_6669 is the fail-on-revert gate for the
// RE-CLAIM half of the coalescing fix, which nothing else binds.
//
// TestOverlappingRefineRequestIsCoalesced_6669 covers the request that lands
// while the worker is still inside its pass — the worker's own pending check
// sees it and `continue`s. The release CAS covers the OTHER window: a request
// that loses the claim (so it queues rather than spawning a worker) and
// publishes the bit AFTER that check has already run. Nobody else will serve it
// — the setter saw a worker in flight and returned — so without the re-claim it
// is stranded with no worker running, and this node stays below its peer's
// floor until some later heartbeat start that nothing bounds (#6724).
//
// The window is a few instructions wide in production, so hammering does not
// reach it: 3000 rounds x 4 concurrent refreshBootEpoch never landed in it.
// It is driven deterministically through the epochRefineBeforeRelease seam.
//
// This is the half where the request lands BEFORE the release CAS, so the CAS
// fails and the worker picks it up.
// TestLateRefineRequestCannotBeStranded_6669 drives the half where it lands
// after, which is what needs claim and release to move ONE word.
//
// RED-on-revert: make releaseBootEpochRefine release unconditionally (drop the
// `st&bootEpochPendingBit` branch and the CAS retry, storing 0 and returning
// false) and the second pass never runs.
func TestLateRefineRequestIsReclaimed_6669(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ha-boot-epoch")
	m := keyedEpochManager(t, path)

	var passes atomic.Int64
	entered := make(chan int, 8)
	origFlock := epochFlock
	epochFlock = func(fd int, how int) error {
		if n := passes.Add(1); n >= 2 {
			entered <- int(n)
		}
		return origFlock(fd, how)
	}
	t.Cleanup(func() { epochFlock = origFlock })

	atRelease := make(chan struct{})
	releaseWorker := make(chan struct{})
	var once sync.Once
	origHook := epochRefineBeforeRelease
	epochRefineBeforeRelease = func() {
		once.Do(func() {
			close(atRelease)
			<-releaseWorker
		})
	}
	t.Cleanup(func() { epochRefineBeforeRelease = origHook })

	// UNPARK ON THE FAILURE PATH TOO: t.Fatalf runs runtime.Goexit and skips the
	// explicit release(s) below, which would leave the parked worker in the seam
	// for the rest of the package run, reading vars a later test assigns.
	var unparkOnce sync.Once
	unparkWorker := func() { unparkOnce.Do(func() { close(releaseWorker) }) }
	t.Cleanup(unparkWorker)

	m.initHeartbeatEpochState()
	select {
	case <-atRelease:
	case <-time.After(5 * time.Second):
		t.Fatal("the refine worker never reached its release point")
	}

	// Pass 1 is COMPLETE (it has read, written and checked pending) but the
	// in-flight bit is still held, so this request loses the claim and queues —
	// too late for the check that just ran.
	if m.bootEpochRefine.Load()&bootEpochRefiningBit == 0 {
		t.Fatal("the worker released the in-flight bit before the seam; the window this " +
			"test drives is not the one the release CAS covers")
	}
	m.refreshBootEpoch()
	if m.bootEpochRefine.Load()&bootEpochPendingBit == 0 {
		t.Fatal("the request did not queue: it either spawned a second worker or was dropped")
	}

	// Another incarnation raises the file. Pass 1 has already read AND written,
	// so only a second pass can carry it — which is exactly what the queued
	// request is for.
	raised := m.heartbeatBootEpoch() + uint64(time.Hour)
	if err := os.WriteFile(path, []byte(strconv.FormatUint(raised, 10)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	unparkWorker()

	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatalf("only %d refine pass(es) ran: a request that queued AFTER the worker's own "+
			"pending check was STRANDED with no worker to serve it", passes.Load())
	}
	waitBootEpochIdle(t, m)

	// EXACTLY TWO, not "at least two". The select above takes any second entry,
	// so an implementation that queues the request correctly AND ALSO spawns a
	// redundant extra worker satisfies it — the pending bit is set, the follow-up
	// runs, and the surplus pass is invisible. The re-claim is supposed to cost
	// ONE extra pass; a count that only has a floor cannot tell "re-claimed" from
	// "re-claimed and duplicated".
	if got := passes.Load(); got != 2 {
		t.Fatalf("%d locked refine passes ran for the initial resolve plus ONE queued "+
			"request, want exactly 2: the request was re-claimed, but something also ran "+
			"a surplus pass, so the slot is not serialising what it claims to", got)
	}

	if got := m.heartbeatBootEpoch(); got <= raised {
		t.Fatalf("published epoch = %d, want > %d — the re-claimed pass ran but did not chain "+
			"from the value another incarnation left in the file", got, raised)
	}
}

// TestThirdRequestCoalescesOntoTheLateReclaim_6669 is the THIRD element, and it
// is the only one that tests the attempt to RE-ARM a decision already made.
//
// Two requests can only show the pending bit being SET. The order that nothing
// else reaches is:
//
//  1. pass 1 has already run its pending check and is parked immediately before
//     its release CAS (the epochRefineBeforeRelease seam sits between the two);
//  2. request 2 lands there and establishes the late reclaim — it sets pending
//     against a worker that has already looked;
//  3. request 3 arrives AFTER that decision and must FOLD INTO it.
//
// WHAT THIS ADDS, STATED EXACTLY, because it is narrower than "the branch is
// untested". Mutating the already-pending branch to re-arm a full-loop worker
// (`return true` instead of `return false`) was measured against the whole
// package at 20 runs each:
//
//   - TestOverlappingRefineRequestIsCoalesced_6669      GREEN
//   - TestLateRefineRequestIsReclaimed_6669             GREEN
//   - TestLateRefineRequestCannotBeStranded_6669        GREEN
//   - TestInitHeartbeatEpochStateNeverBlocks_6169       GREEN
//   - TestCoalescingDoesNotRatchetOnAHealthyNode_6669   RED (:794)
//   - this test                                        RED
//
// So the already-pending branch is NOT unguarded — the twenty-request test
// reaches it and its exact pass count catches the re-arm. What that test cannot
// distinguish is the ORDER: its twenty requests all arrive EARLY, while the
// worker is still inside its pass and has not yet run its own pending check, so
// the follow-up is served by that check. Here the worker is parked PAST the
// check, so the owed follow-up can only be served by its release CAS failing and
// the loop re-reading the word. That is a different path to the same coalesce,
// and this is the only test that drives a request into it.
//
// The two mutations are also not interchangeable: making the busy path claim
// UNCONDITIONALLY is caught by the twenty-request test as well, but through the
// early order. Neither mutation is caught by any of the four GREEN tests above,
// which is the coverage this file was missing.
//
// STATED EXACTLY, so neither wrong reading survives: what is new here is THE
// COMPOSITION OF THE ALREADY-COVERED PENDING COALESCE WITH THE ALREADY-COVERED
// LATE RELEASE-CAS RETRY — not unique protection against the mutation above.
// Delete the twenty-request test because "this one covers the branch" and the
// early order goes unguarded; delete this one as "redundant" and the
// composition does.
//
// RED-on-revert: in claimBootEpochRefine, make the `st&bootEpochPendingBit != 0`
// branch return true instead of false, so a third request re-arms a worker
// rather than coalescing.
func TestThirdRequestCoalescesOntoTheLateReclaim_6669(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ha-boot-epoch")
	m := keyedEpochManager(t, path)

	var passes atomic.Int64
	var gid1, gid2 atomic.Uint64
	inPass2 := make(chan struct{})
	releasePass2 := make(chan struct{})
	var pass2Once sync.Once
	origFlock := epochFlock
	epochFlock = func(fd int, how int) error {
		switch passes.Add(1) {
		case 1:
			gid1.Store(currentGoroutineID())
		case 2:
			// Recorded BEFORE parking, so the test can read it while pass 2 is
			// held. Park the FOLLOW-UP too, so who runs it is observable at all:
			// without this, everything from the unpark to waitBootEpochIdle is
			// unseen.
			gid2.Store(currentGoroutineID())
			pass2Once.Do(func() {
				close(inPass2)
				<-releasePass2
			})
		}
		return origFlock(fd, how)
	}
	t.Cleanup(func() { epochFlock = origFlock })

	// Park pass 1 between its pending check and its release CAS.
	atRelease := make(chan struct{})
	releaseWorker := make(chan struct{})
	var once sync.Once
	origHook := epochRefineBeforeRelease
	epochRefineBeforeRelease = func() {
		once.Do(func() {
			close(atRelease)
			<-releaseWorker
		})
	}
	t.Cleanup(func() { epochRefineBeforeRelease = origHook })

	// Unpark on the failure path too; t.Fatalf skips the explicit call below.
	var unparkOnce, unparkPass2Once sync.Once
	unparkWorker := func() { unparkOnce.Do(func() { close(releaseWorker) }) }
	unparkPass2 := func() { unparkPass2Once.Do(func() { close(releasePass2) }) }
	t.Cleanup(func() {
		unparkWorker()
		unparkPass2()
	})

	m.initHeartbeatEpochState()
	select {
	case <-atRelease:
	case <-time.After(5 * time.Second):
		t.Fatal("the refine worker never reached its release point")
	}
	if got, want := m.bootEpochRefine.Load(), bootEpochRefiningBit; got != want {
		t.Fatalf("refine word = %#x with pass 1 parked before release, want %#x; the schedule "+
			"this test needs did not happen", got, want)
	}
	// ANCHORED ON THE PARKED WORKER, NOT ON A PRE-EXISTENCE BASELINE. Sampling
	// before initHeartbeatEpochState counts whatever this package still has in
	// flight from EARLIER tests, and if one of those exits before the check the
	// delta reads one lower — observed once under concurrent-process stress as
	// "0 package goroutines ... want exactly 1", never reproduced in isolation
	// at -count=500. Every comparison below is instead between two samples taken
	// while pass 1 is deterministically parked, so background drift before the
	// park cannot reach them and the property asserted — that these requests add
	// no goroutine — is the one actually measured.
	goParked := clusterGoroutines()
	// The worker's own exit handle, used below to prove the SAME worker serves
	// the follow-up rather than handing it to a successor.
	w1 := m.bootEpochWorker.Load()
	if w1 == nil {
		t.Fatal("no refine worker handle published with pass 1 in flight")
	}

	// STEP 2 — the late reclaim decision. This is where every other test stops.
	m.refreshBootEpoch()
	if got, want := m.bootEpochRefine.Load(), bootEpochRefiningBit|bootEpochPendingBit; got != want {
		t.Fatalf("refine word = %#x after the LATE request, want %#x: it did not queue against "+
			"a worker that had already run its pending check", got, want)
	}

	// STEP 3 — the request this test exists for. Pending is ALREADY set, so this
	// one must fold into the follow-up that is already owed rather than arming a
	// second. A bit is not a queue: two owed requests are still one pass.
	m.refreshBootEpoch()
	if got, want := m.bootEpochRefine.Load(), bootEpochRefiningBit|bootEpochPendingBit; got != want {
		t.Fatalf("refine word = %#x after a request arriving on an ALREADY-PENDING word, want "+
			"%#x", got, want)
	}
	if got := clusterGoroutines(); got != goParked {
		t.Fatalf("package goroutines went %d -> %d across the third request, want no change: "+
			"it re-armed a worker instead of coalescing onto the follow-up already owed",
			goParked, got)
	}

	unparkWorker()

	// THE FOLLOW-UP MUST RUN ON THE SAME GOROUTINE. Every count above is taken
	// BEFORE the unpark, so without an observation here the window from this
	// point to waitBootEpochIdle is unseen and a HAND-OFF satisfies the test:
	// worker 1 consumes pending, exits, and a successor runs the follow-up,
	// leaving exactly two passes, a settled word and both goroutine counts
	// untouched. releaseBootEpochRefine's contract is stronger than that — it
	// serves the follow-up with the in-flight bit STILL HELD, which is precisely
	// what keeps a second worker from spawning at all.
	//
	// THE GOROUTINE ID IS THE PROPERTY; THE HANDLE POINTER IS A PROXY FOR IT,
	// and an earlier revision of this comment claimed the proxy proved it. A
	// successor that INHERITS the predecessor's handle — same pointer, in-flight
	// bit held continuously, cleanup transferred — passes the pointer comparison
	// and the goroutine COUNT while a different goroutine serves pass 2:
	// measured 200/200 green. It is wrong in the other direction too, since a
	// healthy worker that rotated its handle per pass would fail it. Both checks
	// are kept, but for what each actually says: the ids below bind the worker,
	// the pointer below that binds the HANDLE against rotation or republication.
	select {
	case <-inPass2:
	case <-time.After(5 * time.Second):
		t.Fatalf("the coalesced follow-up never reached the file lock (refine word = %#x)",
			m.bootEpochRefine.Load())
	}
	g1, g2 := gid1.Load(), gid2.Load()
	if g1 == 0 || g2 == 0 {
		t.Fatalf("goroutine ids not captured (pass 1 = %d, pass 2 = %d); the assertion below "+
			"would pass vacuously", g1, g2)
	}
	if g1 != g2 {
		t.Fatalf("the follow-up is running on goroutine %d but pass 1 ran on %d: the owed pass "+
			"was HANDED OFF to a successor instead of being served by the worker that still "+
			"holds the in-flight bit, which is what keeps a second worker from spawning at "+
			"all", g2, g1)
	}
	if m.bootEpochWorker.Load() != w1 {
		t.Fatal("the published worker handle changed while one worker was still serving its " +
			"own follow-up: a handle is published per CLAIMED WORKER, not per pass, and " +
			"rotating it would release a joiner holding the old one early")
	}
	if got := clusterGoroutines(); got != goParked {
		t.Fatalf("package goroutines went %d -> %d by the time the follow-up ran, want no "+
			"change", goParked, got)
	}
	unparkPass2()
	waitBootEpochIdle(t, m)

	// EXACTLY 2. Pass 1 plus ONE follow-up serving BOTH late requests. Three
	// would mean the third request armed a pass of its own.
	if got := passes.Load(); got != 2 {
		t.Fatalf("%d locked refine passes ran for the initial resolve plus TWO late requests, "+
			"want exactly 2: the second late request did not coalesce onto the follow-up "+
			"the first had already made owed", got)
	}
	// AND THE HANDLE IS RETIRED. Nothing above requires it: the word is 0 and
	// worker.done is closed, so deleting the CompareAndSwap in the worker's exit
	// defer leaves a stale handle published and every other assertion here still
	// passes. joinBootEpochRefine short-circuits on a nil handle, so a stale one
	// makes a later join wait on a worker that has already gone.
	//
	// THIS DEPENDS ON THE ORDER OF THOSE TWO STATEMENTS, which is why the exit
	// defer carries a matching note. waitBootEpochIdle returns once done is
	// closed, and only because the CAS runs BEFORE the close is the handle
	// guaranteed retired by then. Swap them and this assertion becomes
	// intermittently red with nothing naming the cause — it would be reported as
	// a flake in this test rather than as a reordering in the worker.
	if got := m.bootEpochWorker.Load(); got != nil {
		t.Fatal("a worker handle is still published after the worker exited: the exit defer's " +
			"CompareAndSwap did not retire it, so the next join selects on a channel belonging " +
			"to a worker that is already gone")
	}
	if got := m.bootEpochRefine.Load(); got != 0 {
		t.Fatalf("refine word settled at %#x, want 0", got)
	}
}

// TestRetiringWorkerDoesNotEraseASuccessor_6669 is the fail-on-revert gate for
// the handle retire being a COMPARE-AND-SWAP rather than a Store.
//
// The retirement assertion in TestThirdRequestCoalescesOntoTheLateReclaim_6669
// catches DELETING the clear, but not degrading it: replacing
// CompareAndSwap(worker, nil) with an unconditional Store(nil) passes it 200/200,
// because that fixture never has a successor published while the outgoing worker
// is retiring. Only this ordering distinguishes them:
//
//  1. the outgoing worker drops the in-flight bit (releaseBootEpochRefine
//     returns false) — the slot is now FREE;
//  2. a successor claims it and publishes its OWN handle;
//  3. the outgoing worker runs its exit defer.
//
// At step 3 a CAS compares against a handle that is no longer current and does
// nothing, leaving the successor published. A Store(nil) ERASES the live
// successor — after which Manager.Stop loads nil, joins nothing, and returns
// while a refine worker is still writing the state file. That is the hazard the
// comparison exists for, and it is invisible without a successor in the window.
//
// The window is a few instructions wide and closes on its own, so hammering
// cannot land in it; epochRefineWorkerBeforeExit makes it deterministic.
//
// RED-on-revert: change the exit defer's CompareAndSwap(worker, nil) to
// m.bootEpochWorker.Store(nil).
func TestRetiringWorkerDoesNotEraseASuccessor_6669(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ha-boot-epoch")
	m := keyedEpochManager(t, path)

	// Park the SUCCESSOR inside its pass, so it is still live and published
	// while the outgoing worker retires.
	var passes atomic.Int64
	inPass2 := make(chan struct{})
	releasePass2 := make(chan struct{})
	var pass2Once sync.Once
	origFlock := epochFlock
	epochFlock = func(fd int, how int) error {
		if passes.Add(1) == 2 {
			pass2Once.Do(func() {
				close(inPass2)
				<-releasePass2
			})
		}
		return origFlock(fd, how)
	}
	t.Cleanup(func() { epochFlock = origFlock })

	// Park the OUTGOING worker between dropping the in-flight bit and clearing
	// its handle — the window a Store would misuse.
	atExit := make(chan struct{})
	releaseExit := make(chan struct{})
	var exitOnce sync.Once
	origExit := epochRefineWorkerBeforeExit
	epochRefineWorkerBeforeExit = func() {
		exitOnce.Do(func() {
			close(atExit)
			<-releaseExit
		})
	}
	t.Cleanup(func() { epochRefineWorkerBeforeExit = origExit })

	var unparkExitOnce, unparkPass2Once sync.Once
	unparkExit := func() { unparkExitOnce.Do(func() { close(releaseExit) }) }
	unparkPass2 := func() { unparkPass2Once.Do(func() { close(releasePass2) }) }
	t.Cleanup(func() {
		unparkExit()
		unparkPass2()
	})

	m.initHeartbeatEpochState()
	select {
	case <-atExit:
	case <-time.After(5 * time.Second):
		t.Fatal("the first refine worker never reached its exit seam")
	}
	w1 := m.bootEpochWorker.Load()
	if w1 == nil {
		t.Fatal("no handle published for the outgoing worker")
	}
	if got := m.bootEpochRefine.Load(); got != 0 {
		t.Fatalf("refine word = %#x at the exit seam, want 0: the in-flight bit must already "+
			"be dropped or a successor cannot claim, and the window under test never opens",
			got)
	}

	// STEP 2 — a successor claims the free slot and publishes its own handle,
	// while the outgoing worker is still parked before its clear.
	go m.refreshBootEpoch()
	select {
	case <-inPass2:
	case <-time.After(5 * time.Second):
		t.Fatal("the successor never reached the file lock")
	}
	w2 := m.bootEpochWorker.Load()
	if w2 == nil || w2 == w1 {
		t.Fatalf("successor handle = %p, outgoing = %p: the successor did not publish a "+
			"handle of its own, so this test cannot tell a CAS from a Store", w2, w1)
	}

	// STEP 3 — let the outgoing worker run its exit defer, and join it.
	unparkExit()
	select {
	case <-w1.done:
	case <-time.After(5 * time.Second):
		t.Fatal("the outgoing worker never finished retiring")
	}

	// THE ASSERTION. A CAS against a handle that is no longer current does
	// nothing. A Store(nil) erases the live successor.
	if got := m.bootEpochWorker.Load(); got != w2 {
		t.Fatalf("published handle = %p after the outgoing worker retired, want the LIVE "+
			"successor %p: the retire is not a compare-and-swap, so it erased a worker that "+
			"is still running. Manager.Stop then loads nil, joins nothing, and returns while "+
			"that worker is still writing the state file", got, w2)
	}

	unparkPass2()
	waitBootEpochIdle(t, m)
	if got := m.bootEpochWorker.Load(); got != nil {
		t.Fatalf("handle = %p after every worker exited, want nil", got)
	}
}

// TestLateRefineRequestCannotBeStranded_6669 is the fail-on-revert gate for the
// PACKED refine word, and it is the one window the re-claim step above does not
// cover.
//
// TestLateRefineRequestIsReclaimed_6669 lands the request BEFORE the worker's
// release, so the release notices it. This lands it AFTER: with the in-flight
// flag and the pending bit as two separate atomics, a requester could observe
// "a worker is in flight", lose the race while the worker ran all the way out,
// and only then store the pending bit — against a worker that no longer exists:
//
//	R: CAS(refining, false->true) FAILS   (worker still in flight)
//	W: clears pending; releases refining; re-claims pending -> nothing;
//	   returns.                              <-- no worker left
//	R: Store(pending, true)                  <-- nobody will serve it
//
// Nothing in production observes that bit, so the cost was a node silently
// parked below its peer's floor until some later heartbeat start, which nothing
// bounds (#6724). With claim and release as CASes on ONE word, R's publish is
// conditional on the observation still holding: it fails against the word the
// worker left and R takes the idle slot itself.
//
// THIS TEST IS DETERMINISTIC, not a stress loop. The window is a few
// instructions wide and 3000 rounds x 4 concurrent refreshBootEpoch never
// reached it, so the schedule is imposed through two seams —
// epochRefineBeforeRelease parks the worker at its exit, epochRefineAfterLostClaim
// parks the requester between observing the worker and publishing its request —
// and the worker is JOINED (not polled) before the requester is let go, so
// "the worker has gone" is a fact and not a timing hope. Every step below is
// ordered by a channel handoff.
//
// RED-on-revert: restore the two separate atomics (bootEpochRefining /
// bootEpochRefinePending) with the plain Store on the request path, and the
// second pass never runs.
func TestLateRefineRequestCannotBeStranded_6669(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ha-boot-epoch")
	m := keyedEpochManager(t, path)

	var passes atomic.Int64
	origFlock := epochFlock
	epochFlock = func(fd int, how int) error {
		passes.Add(1)
		return origFlock(fd, how)
	}
	t.Cleanup(func() { epochFlock = origFlock })

	// Park the worker at its exit, with the in-flight slot still held.
	atRelease := make(chan struct{})
	releaseWorker := make(chan struct{})
	var releaseOnce sync.Once
	origRelease := epochRefineBeforeRelease
	epochRefineBeforeRelease = func() {
		releaseOnce.Do(func() {
			close(atRelease)
			<-releaseWorker
		})
	}
	t.Cleanup(func() { epochRefineBeforeRelease = origRelease })

	// Park the requester between observing that worker and publishing its
	// request against that observation.
	lostClaim := make(chan struct{})
	resumeRequester := make(chan struct{})
	var lostOnce sync.Once
	origLost := epochRefineAfterLostClaim
	epochRefineAfterLostClaim = func() {
		lostOnce.Do(func() {
			close(lostClaim)
			<-resumeRequester
		})
	}
	t.Cleanup(func() { epochRefineAfterLostClaim = origLost })

	// UNPARK ON THE FAILURE PATH TOO, and this test is the one where it matters
	// most. Its assertions fire while the REQUESTER is parked inside
	// claimBootEpochRefine — which is to say, while it holds bootEpochRefineMu.
	// t.Fatalf runs runtime.Goexit and skips the explicit closes below, so
	// without these cleanups that goroutine keeps the mutex for the life of the
	// process and EVERY later test in the package that starts or stops a refine
	// worker blocks on it: one assertion failure turns into a package-wide
	// `panic: test timed out` naming an unrelated test. The two unparks stay
	// SEPARATE because the body deliberately releases the worker first and the
	// requester later; these only backstop whichever the failure path skipped.
	var unparkWorkerOnce, unparkRequesterOnce sync.Once
	unparkWorker := func() { unparkWorkerOnce.Do(func() { close(releaseWorker) }) }
	unparkRequester := func() { unparkRequesterOnce.Do(func() { close(resumeRequester) }) }
	t.Cleanup(func() {
		unparkWorker()
		unparkRequester()
	})

	m.initHeartbeatEpochState()
	select {
	case <-atRelease:
	case <-time.After(5 * time.Second):
		t.Fatal("the refine worker never reached its release point")
	}

	requested := make(chan struct{})
	go func() {
		defer close(requested)
		m.refreshBootEpoch()
	}()
	select {
	case <-lostClaim:
	case <-time.After(5 * time.Second):
		t.Fatalf("the requester never observed a worker in flight (refine word = %#x); the "+
			"window this test drives is not the one it reached", m.bootEpochRefine.Load())
	}

	// Let the worker run ALL the way out — past its release and past anything
	// that could still re-claim — while the requester is still parked. The join
	// is on the worker goroutine itself, so this is not a poll on a flag that
	// clears a few instructions early.
	unparkWorker()
	if !m.joinBootEpochRefine(5 * time.Second) {
		t.Fatal("the in-flight refine worker never exited")
	}
	if passes.Load() != 1 {
		t.Fatalf("%d refine pass(es) ran before the request was published, want 1", passes.Load())
	}

	// Another incarnation raises the file. Pass 1 has already read AND written,
	// so only a second pass can carry it — and the request for that second pass
	// is the one about to be published into a word with no worker in it.
	raised := m.heartbeatBootEpoch() + uint64(time.Hour)
	if err := os.WriteFile(path, []byte(strconv.FormatUint(raised, 10)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	unparkRequester()
	select {
	case <-requested:
	case <-time.After(5 * time.Second):
		t.Fatal("refreshBootEpoch never returned")
	}

	deadline := time.Now().Add(5 * time.Second)
	for passes.Load() < 2 {
		if time.Now().After(deadline) {
			t.Fatalf("only %d refine pass(es) ran: the request was published AFTER the worker "+
				"had gone and was STRANDED with nothing to serve it (refine word = %#x). "+
				"This node stays below its peer's floor until some later heartbeat start, "+
				"which nothing bounds (#6724).", passes.Load(), m.bootEpochRefine.Load())
		}
		time.Sleep(time.Millisecond)
	}
	waitBootEpochIdle(t, m)

	if got := m.bootEpochRefine.Load(); got != 0 {
		t.Fatalf("refine word settled at %#x, want 0 — a bit was left set with no worker", got)
	}
	if got := m.heartbeatBootEpoch(); got <= raised {
		t.Fatalf("published epoch = %d, want > %d — the re-taken pass ran but did not chain "+
			"from the value another incarnation left in the file", got, raised)
	}
}

// TestCoalescingDoesNotRatchetOnAHealthyNode_6669 is the negative control for
// the coalescing loop: many overlapping requests must collapse into ONE extra
// pass, and that extra pass must still be idempotent.
//
// A worker that re-ran unconditionally would ratchet the epoch by one on every
// heartbeat start, which is exactly what refineBootEpoch's `prev == lastWrote`
// shortcut exists to prevent. Coalescing adds passes, so it is the change most
// able to break that.
//
// THE OVERLAP IS IMPOSED, not hoped for. An earlier revision of this test fired
// twenty refreshBootEpoch calls with no seam and asserted only that neither the
// epoch nor the file moved — which twenty strictly SEQUENTIAL workers satisfy
// just as well, so it said nothing about coalescing at all and would have passed
// against a pending bit that did not exist. The worker is now parked inside its
// first locked pass while every request lands, so all twenty provably arrive
// while it is in flight; the word is asserted to be exactly
// {refining|pending} at that point (one follow-up owed, not twenty, and no
// second worker), and the LOCKED PASS COUNT is asserted to be exactly 2
// afterwards.
func TestCoalescingDoesNotRatchetOnAHealthyNode_6669(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ha-boot-epoch")
	m := keyedEpochManager(t, path)

	// Park pass 1 inside its lock, and count every locked pass.
	var passes atomic.Int64
	inPass1 := make(chan struct{})
	releaseWorker := make(chan struct{})
	var once sync.Once
	origFlock := epochFlock
	epochFlock = func(fd int, how int) error {
		if passes.Add(1) == 1 {
			once.Do(func() {
				close(inPass1)
				<-releaseWorker
			})
		}
		return origFlock(fd, how)
	}
	t.Cleanup(func() { epochFlock = origFlock })

	// UNPARK ON THE FAILURE PATH TOO. t.Fatalf runs runtime.Goexit, which skips
	// the explicit close below but still runs cleanups; without this, a failing
	// assertion returns with pass 1 parked in the seam FOREVER, and that escaped
	// worker goes on to read epochRefineBeforeRelease in releaseBootEpochRefine
	// while a later test assigns it — the same cross-test race awaitFirstRefine
	// exists to stop, reintroduced on the failure path.
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(releaseWorker) }) }
	t.Cleanup(release)

	m.initHeartbeatEpochState()
	// Published synchronously, ahead of any I/O — so this is the value the
	// passes below must leave alone.
	first := m.heartbeatBootEpoch()
	if first == 0 {
		t.Fatal("no epoch published")
	}
	select {
	case <-inPass1:
	case <-time.After(5 * time.Second):
		t.Fatal("the first refine worker never reached the file lock")
	}

	// Pile requests on. Every one of them lands while pass 1 is in flight.
	for i := 0; i < 20; i++ {
		m.refreshBootEpoch()
	}
	if got, want := m.bootEpochRefine.Load(), bootEpochRefiningBit|bootEpochPendingBit; got != want {
		t.Fatalf("refine word = %#x after 20 overlapping requests, want %#x: they did not "+
			"coalesce onto the in-flight worker as a single owed follow-up", got, want)
	}

	release()
	waitBootEpochIdle(t, m)

	if got := passes.Load(); got != 2 {
		t.Fatalf("%d locked refine passes ran for the initial resolve plus 20 overlapping "+
			"requests, want exactly 2 (the initial pass and ONE coalesced follow-up)", got)
	}
	if got := m.heartbeatBootEpoch(); got != first {
		t.Fatalf("published epoch moved from %d to %d under coalesced refreshes; a healthy "+
			"node must not ratchet", first, got)
	}
	if got := readPersistedEpoch(t, path); got != first {
		t.Fatalf("state file holds %d after the coalesced passes, want the published %d",
			got, first)
	}
}

// TestPostRenameSyncKeepsTheWatermark_6669 is the fail-on-revert gate for the
// durability-error misclassification.
//
// refineBootEpoch assumed every WriteFileDurable error meant the file had not
// moved. fsatomic documents otherwise: a *PostRenameSyncError is a
// directory-fsync failure AFTER a successful rename, so the new content is
// VISIBLE (#5185) and only its durability is unknown. Returning the old
// watermark there made the next pass fail to recognise its own value, chain
// from it, and rewrite epoch+1 — ratcheting on EVERY pass for as long as the
// fsync kept failing.
//
// RED-on-revert: delete the errors.As(*fsatomic.PostRenameSyncError) branch in
// refineBootEpoch and the file climbs by one per pass here.
func TestPostRenameSyncKeepsTheWatermark_6669(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ha-boot-epoch")
	restore := fsatomic.SetAfterRenameSyncDirForTesting(func(string) error {
		return errors.New("injected post-rename directory fsync failure")
	})
	t.Cleanup(restore)

	var published atomic.Uint64
	published.Store(uint64(time.Now().UnixNano()))

	var wrote uint64
	const passes = 5
	seen := make([]uint64, 0, passes)
	for i := 0; i < passes; i++ {
		wrote = refineBootEpoch(path, &published, wrote)
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("pass %d: the post-rename content must be VISIBLE, so the file must "+
				"exist: %v", i, err)
		}
		n, perr := strconv.ParseUint(string(data[:len(data)-1]), 10, 64)
		if perr != nil {
			t.Fatalf("pass %d: parse %q: %v", i, data, perr)
		}
		seen = append(seen, n)
	}

	for i, got := range seen {
		if got != seen[0] {
			t.Fatalf("pass %d left %d in the file, want %d — a post-rename fsync failure is "+
				"being read as 'nothing was written', so every pass chains from its own "+
				"value and ratchets (%v)", i, got, seen[0], seen)
		}
	}
	if wrote != seen[0] {
		t.Fatalf("watermark = %d, want %d: the pass DID move the file and must say so", wrote, seen[0])
	}
	if got := published.Load(); got != seen[0] {
		t.Fatalf("published = %d, want %d", got, seen[0])
	}
}

// TestRefineRecoveryNeedsTheRaisingEpochInTheFile_6669 is a CHARACTERIZATION,
// not a fix. It states the two conditions the re-runnable-refinement recovery
// claim actually carries, both of which were left unsaid.
//
// Manager.refreshBootEpoch bounds "an incarnation stranded below its peer's
// floor is pinned there for the life of the process". It does so by re-reading
// the FILE, so it recovers only what the file can express.
//
// CONDITION 1 — the floor-raising epoch must have REACHED the file. Refinement
// publishes the raised value before persisting it, deliberately: a node that
// read a predecessor's higher value must still order itself above it even when
// it cannot write (that is the backward-clock-step case persistence exists
// for). The cost is that A can EMIT `b+1` while the file still reads `b`. B
// then has no signal at all — it wrote `b`, the file says `b` — so every
// restart returns at the `prev == lastWrote` shortcut and B stays below the
// peer's floor for its process lifetime. No amount of restarting helps, because
// the information is not in the only channel B reads.
//
// CONDITION 2 — A must be GONE. While both run, each pass raises above the
// other and the file ratchets, so they leapfrog and alternately strand each
// other. TestConcurrentIncarnationsAreOrderedByLockAcquisition_6669 shows the
// recovery working; it makes A exit first, and that is load-bearing.
//
// THE TWO DO NOT NEED THE SAME MISSING STATE, and an earlier revision of this
// comment (and of README.md) said they did. Only CONDITION 2 does: separating
// "a concurrent newer incarnation wrote it" from "a predecessor wrote it after a
// backward clock step" needs a writer identity in the file or a lifetime-held
// liveness lock, which is where the leapfrog lives. CONDITION 1 needs neither —
// the code already does the right thing on a RETRY (A's published value is
// already b+1, so nothing ratchets and the WriteFileDurable is simply
// re-attempted; once b+1 lands, B's next refresh reads it and raises to b+2).
// What is missing there is only a TRIGGER for that retry, which is the "no
// periodic re-check" half of #6724 and a materially smaller change. See
// withEpochFileLock, whose comment is the accurate statement of both.
func TestRefineRecoveryNeedsTheRaisingEpochInTheFile_6669(t *testing.T) {
	t.Run("a_failed_write_strands_the_peer_across_every_restart", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "ha-boot-epoch")
		mB := keyedEpochManager(t, path)

		mB.initHeartbeatEpochState()
		awaitFirstRefine(t, mB, "B's first refine")
		b := mB.heartbeatBootEpoch()
		if got := readPersistedEpoch(t, path); got != b {
			t.Fatalf("persisted %d after B's refine, want %d", got, b)
		}

		// A is older and delayed. Its write FAILS — but it has already read `b`,
		// so it raises and emits `b+1` regardless. The store refuses the write
		// through fsatomic's rename seam, not a 0555 chmod, which cannot refuse
		// uid 0 (#19049).
		clearFault := refuseDurableWritesInto19049(t, dir)
		var pubA atomic.Uint64
		pubA.Store(b - uint64(time.Second))
		refineBootEpoch(path, &pubA, 0)
		epochA := pubA.Load()
		clearFault()
		if epochA <= b {
			t.Fatalf("A published %d, which does not exceed B's %d — the schedule this test "+
				"describes did not happen, so the assertions below prove nothing", epochA, b)
		}
		if got := readPersistedEpoch(t, path); got != b {
			t.Fatalf("the file holds %d, want B's %d — A's write was supposed to FAIL, so this "+
				"subtest is exercising the wrong path", got, b)
		}

		// The peer latches A's value and refuses B.
		var peer heartbeatAuthState
		if ok, _ := peer.admitAuthed(true, epochA, 0xA669, 1); !ok {
			t.Fatal("the peer refused A")
		}
		if ok, _ := peer.admitAuthed(true, b, 0xB669, 1); ok {
			t.Fatal("the peer admitted B; the mis-ordering premise is not reachable")
		}

		// A exits. B restarts refinement repeatedly and STAYS STRANDED — the
		// documented recovery does not apply, because the value that raised the
		// floor is not in the file.
		for i := 0; i < 5; i++ {
			mB.initHeartbeatEpochState()
			waitBootEpochIdle(t, mB)
		}
		if got := mB.heartbeatBootEpoch(); got > epochA {
			t.Fatalf("B recovered to %d, above A's %d. If that is now genuinely reachable the "+
				"recovery claim can be stated unconditionally and this characterization "+
				"should be replaced by a fix-gate.", got, epochA)
		}
		if ok, _ := peer.admitAuthed(true, mB.heartbeatBootEpoch(), 0xB66A, 2); ok {
			t.Fatal("the peer admitted B after all; see above")
		}
	})

	t.Run("two_live_incarnations_leapfrog_and_ratchet_the_file", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "ha-boot-epoch")
		now := uint64(time.Now().UnixNano())
		var pubA, pubB atomic.Uint64
		pubA.Store(now - uint64(time.Second))
		pubB.Store(now)

		var wroteA, wroteB uint64
		wroteB = refineBootEpoch(path, &pubB, wroteB)
		start := readPersistedEpoch(t, path)

		const rounds = 4
		for i := 0; i < rounds; i++ {
			wroteA = refineBootEpoch(path, &pubA, wroteA)
			if pubA.Load() <= pubB.Load() {
				t.Fatalf("round %d: A at %d did not overtake B at %d", i, pubA.Load(), pubB.Load())
			}
			wroteB = refineBootEpoch(path, &pubB, wroteB)
			if pubB.Load() <= pubA.Load() {
				t.Fatalf("round %d: B at %d did not overtake A at %d", i, pubB.Load(), pubA.Load())
			}
		}

		end := readPersistedEpoch(t, path)
		if end <= start {
			t.Fatalf("the file did not ratchet (%d -> %d); the leapfrog this documents is not "+
				"reachable and the condition can be dropped from the recovery claim", start, end)
		}
	})
}
