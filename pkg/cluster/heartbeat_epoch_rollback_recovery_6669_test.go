package cluster

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

// #6669 fold — what the documented rollback recovery actually recovers from.
//
// pkg/cluster/README.md told operators that `systemctl restart xpfd` on the
// refusing node recovers from a peer rollback, unqualified. It does not, and
// the gap matters precisely against the attacker #6169 exists to stop.
//
// TestArchivedEpochReplayReArmsLatchAfterRestart_6169 is the executable
// statement of residual 5.
//
// In this fixture's IN-MEMORY model the restart clears the floor, the latch
// and the ring TOGETHER, and arming the latch needs only an authenticated,
// orderable, ring-fresh epoch frame. Against that empty state a single
// ARCHIVED frame — captured while the peer still ran an epoch-capable build —
// satisfies all three: highEpoch is 0 so nothing is below the floor, and an
// empty ring calls its session never-seen. It re-arms the latch and the
// legitimately rolled-back peer is refused again.
//
// This is a CHARACTERIZATION test: it pins the in-memory behaviour the code
// deliberately does not change (see the arming site in admitAuthed for why a
// freshness test was rejected), so that the documentation and the operator
// warning cannot drift back to claiming a bare restart is enough. Since
// #16022 the latch is ALSO durable (key-set-scoped, off the accept path);
// that does not close the re-arm — a replayed archived frame re-arms a
// restored latch identically — it only means the restart no longer clears
// it in the first place. The durable gates are in
// heartbeat_epoch_persist_16022_test.go.
func TestArchivedEpochReplayReArmsLatchAfterRestart_6169(t *testing.T) {
	e := newLatchEnv(t)

	// 1. The peer runs an epoch-capable build. The attacker records it.
	const peerEpoch = uint64(9_500_000_000_000_000)
	archived := e.captureIncarnation(0x6690, peerEpoch, epochFramesPerIncarnation)
	e.liveRun(archived, "peer on an epoch-capable build")
	if !e.r.auth.peerEpochLatched() {
		t.Fatal("setup: an accepted epoch-bearing frame must arm the latch")
	}

	// 2. The peer is legitimately rolled back to a pre-#6169 build: fresh
	//    session, fresh counter, no epoch. Refused, as designed.
	rolledBack := e.captureIncarnation(0x66FF, 0, epochFramesPerIncarnation)
	for i, f := range rolledBack {
		if e.feed(f) {
			t.Fatalf("setup: rolled-back frame %d admitted; the latch is not engaging", i)
		}
	}

	// 3. The operator performs the recovery the README USED to document,
	//    unqualified: restart xpfd here, with no rotation first.
	e.restartDaemon()
	if e.r.auth.peerEpochLatched() {
		t.Fatal("a daemon restart must disarm the latch")
	}
	if got := e.r.auth.peerEpochFloor(); got != 0 {
		t.Fatalf("floor after a daemon restart = %d, want 0", got)
	}

	// 4. The attacker replays ONE archived frame into that empty state.
	if !e.feed(archived[0]) {
		t.Fatal("an archived epoch frame was refused by a freshly restarted receiver; if this " +
			"now fails, the re-arm is closed and README residual 5 plus the arming-site comment " +
			"in admitAuthed are stale")
	}
	if !e.r.auth.peerEpochLatched() {
		t.Fatal("the replayed archived frame did not re-arm the latch; README residual 5 and the " +
			"arming-site comment in admitAuthed are stale and must be updated")
	}

	// 5. So the restart did NOT recover: the genuine rolled-back peer is refused
	//    again, and one replay per restart sustains that indefinitely.
	for i, f := range e.captureIncarnation(0x6701, 0, epochFramesPerIncarnation) {
		if e.feed(f) {
			t.Fatalf("rolled-back frame %d admitted after the re-arm (frame %d)", i, i)
		}
	}

	// 6. So a bare restart is not the recovery. WHICH ordering of rotation and
	//    restart is — and what the wrong one costs — is proved separately, in
	//    TestRollbackRecoveryOrderingIsRotateThenRestart_6169. Doing it here, in
	//    a flow that has already restarted twice, is how the previous revision
	//    ended up asserting "rotation first" over a body that restarted first.
}

// rolledBackPeerRefusedUnderArchive builds the state both recovery orderings
// start from, so neither has to be inferred from the other's leftovers:
//
//   - the peer ran an epoch-capable build, so the downgrade latch is ARMED;
//   - an on-link attacker holds an archived epoch-bearing frame from that
//     period, signed under the CURRENT PSK;
//   - the peer has since been legitimately rolled back to a pre-#6169 build and
//     its genuine epoch-less frames are being refused.
//
// It returns the env and the attacker's archived frame.
func rolledBackPeerRefusedUnderArchive(t *testing.T, session uint64) (*latchEnv, []byte) {
	t.Helper()
	e := newLatchEnv(t)

	const peerEpoch = uint64(9_500_000_000_000_000)
	archived := e.captureIncarnation(session, peerEpoch, epochFramesPerIncarnation)
	e.liveRun(archived, "peer on an epoch-capable build")
	if !e.r.auth.peerEpochLatched() {
		t.Fatal("setup: an accepted epoch-bearing frame must arm the latch")
	}

	for i, f := range e.captureIncarnation(session+1, 0, epochFramesPerIncarnation) {
		if e.feed(f) {
			t.Fatalf("setup: rolled-back frame %d admitted; the latch is not engaging", i)
		}
	}
	return e, archived[0]
}

// TestRollbackRecoveryOrderingIsRotateThenRestart_6169 pins the ORDER the
// operator warning and pkg/cluster/README.md both prescribe, by executing both
// orderings end to end.
//
// The two steps do different jobs and neither substitutes for the other:
// rotation retires the attacker's PRE-ROTATION archive (those frames fail
// verifyHeartbeatMAC under the new key) but does NOT clear the in-memory latch;
// a restart clears the latch but does NOT retire the archive. So the order is
// the whole content of the advice, and a test that asserts one ordering in a
// comment while executing the other proves neither.
//
// WHAT RECOVERY DOES NOT COVER is asserted too, in the first subtest. Rotation
// retires captures taken BEFORE it and nothing else, so the epoch-less frames
// the attacker records from the rolled-back peer AFTER the rotation still verify
// under the new key — and against the cleared latch the restart produces, they
// are admitted. An earlier revision of this test generated exactly those frames,
// used them only to prove that rotation alone does not recover, and then threw
// them away before the restart, which is the step that makes them usable. That
// left "there is nothing left to re-arm it" reading as though the recovery were
// complete. It is not; see TestRotationDoesNotRetirePostRotationCaptures_6669
// for the same property stated as the reason a durable latch has real value, and
// the epochSeen field comment for why it is nonetheless declined.
//
// RED-on-revert: swap the two operations inside either subtest.
func TestRollbackRecoveryOrderingIsRotateThenRestart_6169(t *testing.T) {
	rotated := []byte("rotated-cluster-shared-secret")

	t.Run("rotate_then_restart_recovers", func(t *testing.T) {
		e, archived := rolledBackPeerRefusedUnderArchive(t, 0x6710)

		// ROTATE FIRST. The archive dies with the old key — but rotation alone
		// is not the recovery: the latch is in memory and rotation does not
		// touch it, so the rolled-back peer is still refused under the new key.
		e.rotateKey(rotated)
		if !e.r.auth.peerEpochLatched() {
			t.Fatal("a PSK rotation must not, by itself, clear the downgrade latch — if it did, " +
				"the restart in the documented recovery would be pointless")
		}
		postRotation := e.captureIncarnation(0x6712, 0, epochFramesPerIncarnation)
		for i, f := range postRotation {
			if e.feed(f) {
				t.Fatalf("re-keyed rolled-back frame %d admitted before the restart; rotation "+
					"alone cannot be the recovery", i)
			}
		}

		// THEN RESTART. The latch clears, and the PRE-rotation archive is dead.
		e.restartDaemon()
		if e.r.auth.peerEpochLatched() {
			t.Fatal("a daemon restart must disarm the latch")
		}
		if e.feed(archived) {
			t.Fatal("an archived frame still verified after a PSK rotation — rotation is the " +
				"only thing that retires the attacker's capture, so this must fail")
		}
		if e.r.auth.peerEpochLatched() {
			t.Fatal("a frame that failed MAC verification must not arm the latch")
		}

		// BUT THE POST-ROTATION CAPTURES SURVIVE BOTH STEPS. They were signed
		// with the key still in force, so rotation cannot retire them, and in
		// this in-memory fixture the restart is what makes them usable by
		// clearing the latch that was refusing them. (#16022's durable latch
		// refuses them in production; this fixture models the in-memory
		// lifecycle only.)
		admitted := feedCount(e, postRotation)
		if admitted != epochFramesPerIncarnation {
			t.Fatalf("post-rotation epoch-less captures after the restart: %d/%d admitted, "+
				"want %d. If this now fails the durable-latch pricing in the epochSeen field "+
				"comment and README residual 5 are stale — the residual they accept is closed.",
				admitted, epochFramesPerIncarnation, epochFramesPerIncarnation)
		}

		// The rolled-back peer, re-keyed with the operator, is accepted again —
		// and stays accepted while the attacker keeps replaying.
		e.liveRun(e.captureIncarnation(0x6713, 0, epochFramesPerIncarnation),
			"rolled-back peer after rotating the PSK and restarting")
		if e.feed(archived) {
			t.Fatal("the retired archive verified on a later attempt")
		}
		e.liveRun(e.captureIncarnation(0x6714, 0, epochFramesPerIncarnation),
			"rolled-back peer after a further replay attempt")
	})

	t.Run("restart_then_rotate_costs_a_second_restart", func(t *testing.T) {
		e, archived := rolledBackPeerRefusedUnderArchive(t, 0x6720)

		// RESTART FIRST — the wrong order. The latch clears, and the archive is
		// still valid because the key has not changed yet, so one replay lands
		// in the window and re-arms it.
		e.restartDaemon()
		if e.r.auth.peerEpochLatched() {
			t.Fatal("a daemon restart must disarm the latch")
		}
		if !e.feed(archived) {
			t.Fatal("the archived frame was refused by a freshly restarted receiver under the " +
				"UNROTATED key; if this now fails, the re-arm is closed and README residual 5 " +
				"plus the arming-site comment in admitAuthed are stale")
		}
		if !e.r.auth.peerEpochLatched() {
			t.Fatal("the replayed archived frame did not re-arm the latch")
		}

		// NOW rotate. It retires the archive, but the latch it already re-armed
		// is in memory and rotation does not clear it — a floor and a latch are
		// per-peer state, not key material. The rolled-back peer stays refused.
		e.rotateKey(rotated)
		if !e.r.auth.peerEpochLatched() {
			t.Fatal("rotating the PSK must not clear a latch that is already armed; if it did, " +
				"the ordering advice would be unnecessary")
		}
		for i, f := range e.captureIncarnation(0x6722, 0, epochFramesPerIncarnation) {
			if e.feed(f) {
				t.Fatalf("re-keyed rolled-back frame %d admitted while the re-armed latch is "+
					"engaged", i)
			}
		}

		// A SECOND restart is what recovers — the cost of the wrong order.
		e.restartDaemon()
		if e.feed(archived) {
			t.Fatal("the archived frame verified after the rotation; it must be dead by now")
		}
		e.liveRun(e.captureIncarnation(0x6723, 0, epochFramesPerIncarnation),
			"rolled-back peer after the SECOND restart")
	})
}

// TestEpochDowngradeWarningNamesTheCompleteRecovery_6169 is the fail-on-revert
// gate for the OPERATOR-facing half.
//
// The warning is the only place an operator learns what to do, and it used to
// say "restart xpfd on THIS node to clear the latch" — advice that loops
// forever while an archived frame is being replayed. It must name the PSK
// rotation, and name it FIRST.
//
// RED-on-revert: restore the old single-sentence recovery in
// Manager.NoteEpochDowngradeHeartbeat and this fails.
func TestEpochDowngradeWarningNamesTheCompleteRecovery_6169(t *testing.T) {
	var buf bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
	t.Cleanup(func() { slog.SetDefault(old) })

	NewManager(0, 42).NoteEpochDowngradeHeartbeat()

	out := buf.String()
	if out == "" {
		t.Fatal("NoteEpochDowngradeHeartbeat logged nothing; the refusal must be operator-visible")
	}
	for _, want := range []string{
		"rotate the control-link PSK",
		"BOTH nodes",
		"restart",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("the epoch-downgrade warning does not mention %q.\n"+
				"An operator told only to restart will loop: a replayed archived epoch frame "+
				"re-arms the latch against the empty post-restart state, and only rotating the "+
				"PSK retires that capture.\n--- log ---\n%s", want, out)
		}
	}
	// The ORDER is the load-bearing part: rotate, then restart.
	if strings.Index(out, "rotate the control-link PSK") > strings.Index(out, "then restart") {
		t.Fatalf("the warning puts the restart before the rotation; restarting first leaves a "+
			"window for the replay to land\n--- log ---\n%s", out)
	}
}
