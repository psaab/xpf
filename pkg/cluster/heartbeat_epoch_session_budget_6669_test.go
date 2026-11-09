package cluster

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// #6669 fold round 11 — round 10 bound the floor to EXACTLY ONE session per
// epoch value, and that refuses a healthy node rather than an attacker.
//
// Round 10's stated bound was "durable only under the dead-clock AND dead-store
// pair, which is precisely the regime in which the sender publishes no order at
// all". It is false. refineBootEpoch chains with `if next := prev + 1; next >
// epoch`, which is a pure function of the FILE, so a store that READS but cannot
// WRITE hands every successive incarnation the identical value — on a perfectly
// healthy, advancing clock, with different seeds and different sessions.
// Refinement, offered by that text as the escape, is the equal-epoch GENERATOR
// whenever persist fails.
//
// The bound is now heartbeatEpochSessionsPerEpoch slots rather than one. These
// tests pin the successor case that must be admitted and the two properties the
// slots must keep: they are spent at most once per epoch value, and nothing an
// attacker can produce refills them.

// epochUnwritableStore points bootEpochPath at a directory whose state file
// READS but cannot be WRITTEN, holding a value ahead of `now` but inside
// bootEpochMaxSkew.
//
// That is one ordinary appliance fault (a full or read-only /var) plus one
// ordinary clock event (an RTC that ran fast, corrected back by NTP under an
// hour). Neither is a dead clock and neither is a dead store: the `.lock`
// already exists so withEpochFileLock takes it and os.ReadFile succeeds, and
// only WriteFileDurable fails — its rename is refused (refuseDurableWritesInto19049).
// The refusal used to be a 0555 chmod of the directory, which cannot refuse
// uid 0, so as uid 0 the "unwritable" store took every write (#19049). It
// returns the state path and the value in the file.
func epochUnwritableStore(t *testing.T, lead time.Duration) (string, uint64) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "ha-boot-epoch")

	fileVal := uint64(time.Now().Add(lead).UnixNano())
	if err := os.WriteFile(path, []byte(strconv.FormatUint(fileVal, 10)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	lock, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	lock.Close()
	refuseDurableWritesInto19049(t, dir)

	orig := bootEpochPath
	bootEpochPath = path
	t.Cleanup(func() { bootEpochPath = orig })
	return path, fileVal
}

// startedIncarnation is one daemon incarnation resolved through the PRODUCTION
// entry point — Manager.initHeartbeatEpochState, which is what StartHeartbeat
// calls — joined on its first refine.
func startedIncarnation(t *testing.T, what string) *Manager {
	t.Helper()
	m := NewManager(0, 42)
	m.mu.Lock()
	m.controlAuthKey = []byte("cluster-shared-secret")
	m.mu.Unlock()
	m.initHeartbeatEpochState()
	awaitFirstRefine(t, m, what)
	return m
}

// TestEqualEpochSuccessorIsAdmitted_6669 is the fail-on-revert gate for round
// 10's regression.
//
// RED-on-revert: restore the singleton form of the equality check in
// admitAuthed —
//
//	if epoch == s.highEpoch && session != s.highEpochSession { ... }
//
// (equivalently, set heartbeatEpochSessionsPerEpoch to 1) and the successor
// subtest goes to 0/40 admitted, which at the shipped 200ms interval and
// threshold 5 declares a healthy node dead in 1s and takes over its RGs while it
// still holds them.
func TestEqualEpochSuccessorIsAdmitted_6669(t *testing.T) {
	// THE REACHABLE REGIME, end to end: two incarnations over a store that
	// cannot advance, real signed frames through the real readLoop gate.
	t.Run("successor_of_an_unwritable_store_is_admitted", func(t *testing.T) {
		path, fileVal := epochUnwritableStore(t, 30*time.Minute)

		mA := startedIncarnation(t, "incarnation A")
		mB := startedIncarnation(t, "incarnation B")
		sessionA, _ := mA.heartbeatNonce()
		sessionB, _ := mB.heartbeatNonce()
		epochA, epochB := mA.heartbeatBootEpoch(), mB.heartbeatBootEpoch()

		// The premise, asserted rather than assumed — if any of it stops
		// holding, the subtest below proves nothing.
		if got := readPersistedEpoch(t, path); got != fileVal {
			t.Fatalf("the file moved to %d, want %d: the persist was supposed to FAIL, so "+
				"this subtest is exercising the wrong path", got, fileVal)
		}
		if epochA != epochB {
			t.Fatalf("the two incarnations published %d and %d: equal epochs from an "+
				"unadvanced file is the whole premise", epochA, epochB)
		}
		if epochA != fileVal+1 {
			t.Fatalf("published %d, want file+1 = %d: the chain is not the generator this "+
				"test says it is", epochA, fileVal+1)
		}
		if sessionA == sessionB {
			t.Fatal("both incarnations drew the same session; not a two-incarnation probe")
		}

		e := newEpochEnv(t)
		e.liveRun(framesFor(e, sessionA, epochA, 1, 10), "incarnation A")

		// B is the SUCCESSOR: a healthy node, one restart later, publishing the
		// value its predecessor published because the file did not move.
		admitted := 0
		const frames = 40
		for c := 1; c <= frames; c++ {
			if e.feed(marshalHeartbeatAuthEpoch(samplePkt(), e.key, sessionB, uint64(c), epochB)) {
				admitted++
			}
		}
		if admitted != frames {
			t.Fatalf("the successor incarnation was admitted %d/%d (collisions=%d) — a healthy "+
				"node with a correct, advancing clock is refused on every heartbeat and is "+
				"declared dead in 1s", admitted, frames, e.m.HeartbeatStats().EpochSessionCollision)
		}
	})

	// THE PROPERTY THE BOUND EXISTS FOR, kept: the slots are spent at most once
	// per epoch value, so a capture set sharing one epoch buys a finite pass and
	// nothing sustained.
	t.Run("a_shared_epoch_capture_set_spends_the_slots_once", func(t *testing.T) {
		e := newEpochEnv(t)
		const n = heartbeatReplaySessions + 1
		const shared = uint64(1_700_000_000_000_000_000)

		sessions := make([]uint64, n)
		for i := range sessions {
			sessions[i] = uint64(0xE000 + i)
		}
		distinct := map[uint64]bool{}
		for _, s := range sessions {
			for _, f := range framesFor(e, s, shared, 1, epochFramesPerIncarnation) {
				if e.feed(f) {
					distinct[s] = true
				}
			}
		}
		if len(distinct) != heartbeatEpochSessionsPerEpoch {
			t.Fatalf("%d distinct sessions were admitted at ONE epoch value, want exactly %d — "+
				"the per-value budget is not what the security argument spends",
				len(distinct), heartbeatEpochSessionsPerEpoch)
		}

		// NOTHING SUSTAINED. Replaying the whole capture set five more times
		// admits nothing, and the floor never moves.
		//
		// WHAT THIS DOES NOT MODEL, stated because an earlier revision of this
		// comment claimed it did: the rounds below are silent but
		// INSTANTANEOUS — no wall-clock interval elapses and no clock is
		// injected — so they are not "aging out a staleness-based rebind" and
		// could not detect one. Nothing to age out exists today:
		// epochSessionAdmissible is a pure predicate over highEpochSessions,
		// bindEpochSession is its only mutator, and neither reads a clock, so
		// the budget is refilled by a floor RAISE and by nothing else (see the
		// a_raise_resets_the_slots subtest). A future time-based refill would
		// need its own gate and would escape this one.
		//
		// WHICH GATE refused what is asserted, not just the total, because
		// 0-admitted is the FAILURE DEFAULT here: malformed frames, a wrong key,
		// or a drifted floor would all produce it. The split is exact and the
		// two halves are different mechanisms:
		//
		//   - the sessions NOT in the bound set are refused by the EPOCH budget
		//     (EpochSessionCollision), which is the property under test;
		//   - the heartbeatEpochSessionsPerEpoch sessions that ARE bound clear
		//     the epoch gate and are refused by the RING, on their own stale
		//     counters. Those must NOT show up as collisions — if they did, the
		//     binding would have been dropped and the budget would be refilling.
		const rounds = 5
		bound := heartbeatEpochSessionsPerEpoch
		wantCollisions := uint64(rounds * (n - bound) * epochFramesPerIncarnation)
		wantRingRefused := rounds * bound * epochFramesPerIncarnation

		collisionsBefore := e.m.HeartbeatStats().EpochSessionCollision
		sustained, replayed := 0, 0
		for r := 0; r < rounds; r++ {
			for _, s := range sessions {
				for _, f := range framesFor(e, s, shared, 1, epochFramesPerIncarnation) {
					replayed++
					if e.feed(f) {
						sustained++
					}
				}
			}
		}
		if sustained != 0 {
			t.Fatalf("%d frames admitted across %d replay rounds, want 0 — a shared-epoch "+
				"capture set is sustaining forged peer liveness", sustained, rounds)
		}
		gotCollisions := e.m.HeartbeatStats().EpochSessionCollision - collisionsBefore
		if gotCollisions != wantCollisions {
			t.Fatalf("the epoch budget refused %d of the %d replayed frames, want %d "+
				"(%d unbound sessions x %d frames x %d rounds). 0 admitted does not "+
				"establish that the per-value BUDGET is what held unless the budget is "+
				"what did the refusing", gotCollisions, replayed, wantCollisions,
				n-bound, epochFramesPerIncarnation, rounds)
		}
		if got := replayed - int(gotCollisions); got != wantRingRefused {
			t.Fatalf("%d frames reached the ring, want %d (the %d BOUND sessions' own stale "+
				"counters). A bound session refused by the epoch gate instead would mean the "+
				"binding was dropped between rounds, i.e. the budget refilled", got,
				wantRingRefused, bound)
		}
		if got := e.r.auth.peerEpochFloor(); got != shared {
			t.Fatalf("floor = %d, want %d (a replay must never move the floor)", got, shared)
		}
	})

	// A RAISE RESETS THE SLOTS, and only a raise does. The budget is per epoch
	// VALUE: carrying spent slots forward would refuse the live peer at the
	// value it just raised to, and carrying unspent ones forward would let one
	// value's budget be spent at the next.
	t.Run("a_raise_resets_the_slots", func(t *testing.T) {
		e := newEpochEnv(t)
		base := uint64(time.Now().Add(-time.Hour).UnixNano())

		// Spend the whole budget at `base`.
		for i := 0; i < heartbeatEpochSessionsPerEpoch; i++ {
			if !e.feed(marshalHeartbeatAuthEpoch(samplePkt(), e.key, uint64(0xF100+i), 1, base)) {
				t.Fatalf("session %d was refused at an epoch with a free slot", i)
			}
		}
		if e.feed(marshalHeartbeatAuthEpoch(samplePkt(), e.key, 0xF1FF, 1, base)) {
			t.Fatal("a session beyond the budget was admitted at one epoch value")
		}

		// A raise: the raising session binds alone, and the budget is fresh.
		if !e.feed(marshalHeartbeatAuthEpoch(samplePkt(), e.key, 0xF200, 1, base+1)) {
			t.Fatal("the raise was refused")
		}
		// The RAISING session must keep being admitted at the value it just
		// raised to. Carrying the old value's spent slots forward instead of
		// resetting locks out the very peer that raised the floor — the live
		// peer, on every subsequent heartbeat.
		if !e.feed(marshalHeartbeatAuthEpoch(samplePkt(), e.key, 0xF200, 2, base+1)) {
			t.Fatal("the session that RAISED the floor was refused at its own new value; the " +
				"slots did not reset, so a live peer is declared dead in 1s")
		}
		for i := 1; i < heartbeatEpochSessionsPerEpoch; i++ {
			if !e.feed(marshalHeartbeatAuthEpoch(samplePkt(), e.key, uint64(0xF200+i), 1, base+1)) {
				t.Fatalf("session %d was refused at the raised value; the raise did not reset "+
					"the slots", i)
			}
		}
		if e.feed(marshalHeartbeatAuthEpoch(samplePkt(), e.key, 0xF2FF, 1, base+1)) {
			t.Fatal("a session beyond the budget was admitted at the raised value")
		}
		// And the sessions bound at the OLD value are below the floor now.
		if e.feed(marshalHeartbeatAuthEpoch(samplePkt(), e.key, 0xF100, 2, base)) {
			t.Fatal("a session bound at the previous floor was admitted below the new one")
		}
	})

	// A FRAME THE RING REFUSES MUST NOT SPEND A SLOT. The admissibility test
	// runs before s.replay.admit (it has to — admit RECORDS a never-seen session
	// as a side effect), but the BINDING is recorded after it. Reachable: a
	// session admitted at a lower value keeps its ring watermark while the raise
	// drops it from the bound set, so its stale counters arrive at the current
	// floor with a slot free.
	t.Run("a_ring_refused_frame_does_not_spend_a_slot", func(t *testing.T) {
		e := newEpochEnv(t)
		base := uint64(time.Now().Add(-time.Hour).UnixNano())
		const stale, live, successor = uint64(0xD001), uint64(0xD002), uint64(0xD003)

		// stale lands in the ring at a LOWER value, watermark 5.
		if !e.feed(marshalHeartbeatAuthEpoch(samplePkt(), e.key, stale, 5, base)) {
			t.Fatal("the first frame was refused")
		}
		// live raises: the slots reset to {live}, so stale is no longer bound
		// but is still in the ring.
		if !e.feed(marshalHeartbeatAuthEpoch(samplePkt(), e.key, live, 1, base+1)) {
			t.Fatal("the raise was refused")
		}
		// stale replays an OLD counter at the CURRENT floor. A slot is free, so
		// it clears the epoch gate; the RING is what refuses it.
		for c := 1; c <= 4; c++ {
			if e.feed(marshalHeartbeatAuthEpoch(samplePkt(), e.key, stale, uint64(c), base+1)) {
				t.Fatalf("a replayed counter (%d, watermark 5) was admitted", c)
			}
		}
		if got := e.m.HeartbeatStats().EpochSessionCollision; got != 0 {
			t.Fatalf("EpochSessionCollision = %d: those frames were refused by the EPOCH gate, "+
				"so the ring never got to rule on them and this subtest proves nothing", got)
		}
		// The slot they did not spend is still there for a real successor.
		if !e.feed(marshalHeartbeatAuthEpoch(samplePkt(), e.key, successor, 1, base+1)) {
			t.Fatal("the successor was refused: frames the RING rejected spent the slot, so a " +
				"replay with stale counters can exhaust the budget a live incarnation needs")
		}
	})
}

// TestEqualEpochBoundStillStrandsTheNextSuccessor_6669 is a CHARACTERIZATION,
// not a fix. It is the residual the bound leaves, stated executably so the
// comments on highEpochSessions and in README.md cannot drift off it.
//
// heartbeatEpochSessionsPerEpoch slots buy heartbeatEpochSessionsPerEpoch-1
// restarts inside the window; they do not remove it. The incarnation past the
// last slot is refused, and it is refused for its WHOLE PROCESS LIFETIME:
// bootEpoch is set once under bootEpochOnce, and re-refinement lands on the same
// prev+1 every pass because prev+1 > prev+1 is false. Recovery needs the wall
// clock to climb past prev+1 AND another restart — up to however far the file
// leads the clock, at most bootEpochMaxSkew.
//
// Closing it needs the sender to stop republishing one value, and ENTROPY IS NOT
// WHAT IS MISSING — an earlier revision of this comment said the degenerate case
// (a clock at or before the Unix epoch with no chainable file) had "nothing to
// draw on". It has 64 crypto-random bits already: every Manager draws an
// incarnation session id from crypto/rand at its first signed send
// (randomSessionID, via Manager.heartbeatNonce), with no dependence on the clock
// or on the file, and already carries it in every frame.
//
// What blocks using it is that the EPOCH is an ordering value, not an identity:
// the receiver compares it with < and >, so folding random bits in produces a
// successor that can land BELOW its predecessor, which admitAuthed refuses
// outright — trading a bounded stranding for an unbounded one. Distinctness
// would have to come from something MONOTONE the sender can produce without the
// file, and that is what the degenerate case does not have. A receiver-side
// bound is needed either way; see highEpochSessions.
func TestEqualEpochBoundStillStrandsTheNextSuccessor_6669(t *testing.T) {
	_, fileVal := epochUnwritableStore(t, 30*time.Minute)

	const incarnations = heartbeatEpochSessionsPerEpoch + 1
	e := newEpochEnv(t)
	var last *Manager
	for i := 0; i < incarnations; i++ {
		m := startedIncarnation(t, "incarnation")
		session, _ := m.heartbeatNonce()
		epoch := m.heartbeatBootEpoch()
		if epoch != fileVal+1 {
			t.Fatalf("incarnation %d published %d, want %d: every one of them must republish "+
				"the same chained value or this test proves nothing", i, epoch, fileVal+1)
		}
		admitted := e.feed(marshalHeartbeatAuthEpoch(samplePkt(), e.key, session, 1, epoch))
		want := i < heartbeatEpochSessionsPerEpoch
		if admitted != want {
			t.Fatalf("incarnation %d: admitted=%v, want %v (slots = %d)",
				i, admitted, want, heartbeatEpochSessionsPerEpoch)
		}
		last = m
	}

	// The stranded incarnation cannot lift itself out in-process: re-refinement
	// reads the same unadvanced file and lands on the same value.
	stuck := last.heartbeatBootEpoch()
	for i := 0; i < 10; i++ {
		last.initHeartbeatEpochState()
		waitBootEpochIdle(t, last)
	}
	if got := last.heartbeatBootEpoch(); got != stuck {
		t.Fatalf("the stranded incarnation's epoch moved from %d to %d under re-refinement. "+
			"If that is now genuinely reachable, this residual is smaller than documented and "+
			"highEpochSessions/README.md should be corrected to say so.", stuck, got)
	}
	session, _ := last.heartbeatNonce()
	if e.feed(marshalHeartbeatAuthEpoch(samplePkt(), e.key, session, 2, stuck)) {
		t.Fatal("the stranded incarnation was admitted after re-refinement; see above")
	}
}

// framesFor builds counters lo..hi of one incarnation's signed heartbeats.
func framesFor(e *epochEnv, session, epoch uint64, lo, hi int) [][]byte {
	e.t.Helper()
	frames := make([][]byte, 0, hi-lo+1)
	for c := lo; c <= hi; c++ {
		frames = append(frames, marshalHeartbeatAuthEpoch(samplePkt(), e.key, session, uint64(c), epoch))
	}
	return frames
}
