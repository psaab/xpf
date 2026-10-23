package cluster

import (
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// #6169 — the DOWNGRADE LATCH.
//
// The boot-epoch floor only ever sees frames that CARRY an epoch. An attacker's
// captured incarnations are, by construction, mostly from BEFORE the upgrade
// and therefore carry none, so a receiver that accepts epochless frames forever
// never consults the floor at all. Measured on the first cut of this change,
// with the floor latched at a live peer's epoch: 975/975 epochless replays
// admitted.
//
// The latch closes that: once the peer has proved it emits epochs, an epochless
// frame from it is refused. The latch lives on Manager.hbAuth so routine
// restarts preserve it. Since #16022 the latch, floor and bound sessions are
// also persisted across daemon restarts, scoped to the accepted key set —
// see heartbeat_epoch_persist_16022_test.go for the durability gates. The
// tests in THIS file that restart the daemon use the legacy fixture model
// (restartDaemon sets the committed key directly, without an UpdateConfig
// apply, and peerEpochStatePath is not redirected), so they exercise the
// in-memory lifecycle only; the durable lifecycle is pinned separately.

// heldEpochLock takes the REAL advisory lock the persist path needs, for tests
// that wedge the store rather than simulating a wedge, and returns a
// once-guarded release.
//
// EVERY CALLER PAIRS IT WITH A CLEANUP that releases AND drains, because the
// body's own release is on the happy path only: t.Fatalf runs runtime.Goexit
// and skips the rest of the body, so an assertion firing while the lock is held
// would otherwise leave a refine worker parked on it for the whole remaining
// package run — where it goes on to read the package-var seams a later test
// assigns, which is the cross-test race awaitFirstRefine exists to stop. The
// pair must be one cleanup and in that order: t.Cleanup is LIFO, so a
// separately registered drain would run BEFORE the release and simply wait out
// its budget.
func heldEpochLock(t *testing.T, path string) func() {
	t.Helper()
	lockFile, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	// Registered FIRST so it runs LAST — after every release/drain below.
	t.Cleanup(func() { lockFile.Close() })
	if err := unix.Flock(int(lockFile.Fd()), unix.LOCK_EX); err != nil {
		t.Fatalf("could not take the lock the test needs to hold: %v", err)
	}
	var once sync.Once
	return func() {
		once.Do(func() { _ = unix.Flock(int(lockFile.Fd()), unix.LOCK_UN) })
	}
}

// latchEnv is an epochEnv plus the ability to model a FULL receiver daemon
// restart (a brand-new Manager, so every in-memory tracker is gone).
type latchEnv struct {
	*epochEnv
}

func newLatchEnv(t *testing.T) *latchEnv {
	t.Helper()
	return &latchEnv{epochEnv: newEpochEnv(t)}
}

// restartDaemon models a FULL receiver daemon restart. Unlike a heartbeat
// restart or a VRF rebind — which preserve Manager.hbAuth (#5086/#6642) — this
// discards every in-memory tracker, including the downgrade latch.
func (e *latchEnv) restartDaemon() {
	// The restarted daemon re-reads the COMMITTED PSK, so it comes up on
	// whatever rotateKey last installed — not on the original key.
	e.m = epochGateManagerWithKey(e.key)
	e.r = newHeartbeatReceiver(e.m, nil, DefaultHeartbeatThreshold, DefaultHeartbeatInterval, nil)
	e.m.mu.Lock()
	e.m.hbReceiver = e.r
	e.m.mu.Unlock()
}

// epochlessCaptures builds n distinct PRE-UPGRADE (epochless) incarnations —
// what an on-link sniffer holds from before the cluster was upgraded.
func (e *latchEnv) epochlessCaptures(n int) [][][]byte {
	caps := make([][][]byte, 0, n)
	for i := 0; i < n; i++ {
		caps = append(caps, e.captureIncarnation(uint64(0x9000+i), 0, epochFramesPerIncarnation))
	}
	return caps
}

// TestHeartbeatEpochlessReplayRefusedOnceLatched_6169 is the fail-on-revert
// gate for the finding that the epoch floor alone closes almost nothing.
//
// RED-on-revert: the fix is the `if s.epochSeen { return false }` branch in
// heartbeatAuthState.admitAuthed. Delete it and the epochless replays are
// admitted again (975/975 on the pre-fix code), because they never reach the
// floor comparison at all.
func TestHeartbeatEpochlessReplayRefusedOnceLatched_6169(t *testing.T) {
	e := newLatchEnv(t)

	// The live peer is upgraded: it signs a boot epoch, and the receiver both
	// latches and records a floor from real traffic.
	live := e.captureIncarnation(0x11E0, 9_000_000_000_000_000, epochFramesPerIncarnation)
	e.liveRun(live, "live upgraded incarnation")
	if !e.r.auth.peerEpochLatched() {
		t.Fatal("an accepted epoch-bearing frame must arm the downgrade latch")
	}

	// The attacker replays a ringful-and-then-some of PRE-UPGRADE, epochless
	// captures — more than heartbeatReplaySessions, so the FIFO ring alone is
	// churnable and would admit every one of them.
	caps := e.epochlessCaptures(heartbeatReplaySessions + 8)
	admitted, total := e.replayAll(caps, 3)
	if admitted != 0 {
		t.Fatalf("epochless replay: %d/%d admitted, want 0 — a pre-upgrade capture set "+
			"still bypasses the boot-epoch floor entirely", admitted, total)
	}

	// NEGATIVE CONTROL (passes with and without the latch): the live peer keeps
	// working, and a genuine reboot into a higher epoch is still admitted.
	next := marshalHeartbeatAuthEpoch(samplePkt(), e.key, 0x11E0,
		uint64(len(live)+1), 9_000_000_000_000_000)
	if !e.feed(next) {
		t.Fatal("the live peer's next genuine frame was rejected")
	}
	rebooted := e.captureIncarnation(0x11E1, 9_000_000_000_000_001, epochFramesPerIncarnation)
	e.liveRun(rebooted, "genuine peer reboot")
}

// TestHeartbeatEpochLatchScopeIsTheProcess_6169 pins the IN-MEMORY
// durability contract, in both directions, so the boundary is deliberate
// rather than discovered. (The durable across-restart contract is pinned
// in heartbeat_epoch_persist_16022_test.go, which redirects the record
// file and drives the restart through UpdateConfig.)
//
// The latch survives the restarts that happen routinely — a heartbeat restart,
// a DHCP-triggered VRF rebind, an HA comms restart — because the state lives on
// Manager.hbAuth (#5086/#6642). In this fixture's model (no UpdateConfig
// apply, no redirected record) a full daemon restart clears it, and a live
// peer re-arms it with its next heartbeat.
//
// An earlier revision persisted the floor to disk to cover the daemon-restart
// case too. Review priced that: it made a deliberate rollback require deleting
// a state file, opened a crash window between accepting a frame and committing
// the floor, needed cross-process locking, and let an in-range-but-wrong epoch
// lock a peer out across reboots. #16022 answers that pricing with a
// key-set-scoped record written off the accept path — see the epochSeen field
// comment.
//
// The window an IN-MEMORY-ONLY latch leaves is NOT "covered operationally by
// PSK rotation", which this comment used to say. A rotation retires captures
// taken BEFORE it and nothing else; captures taken under the CURRENT key
// survive both the rotation and the restart (TestRotationDoesNotRetirePost
// RotationCaptures_6669, and the post-rotation replay in
// TestRollbackRecoveryOrderingIsRotateThenRestart_6169). That is the window
// #16022's durable record closes; this test pins only the in-memory half.
func TestHeartbeatEpochLatchScopeIsTheProcess_6169(t *testing.T) {
	e := newLatchEnv(t)
	const liveEpoch = uint64(9_100_000_000_000_000)
	e.liveRun(e.captureIncarnation(0x22E0, liveEpoch, epochFramesPerIncarnation), "live upgraded incarnation")

	// A ROUTINE heartbeat restart (VRF rebind / comms restart) must NOT clear
	// the latch or the floor — this is the case that matters day to day.
	e.restartHeartbeat()
	if !e.r.auth.peerEpochLatched() {
		t.Fatal("a heartbeat restart must not clear the downgrade latch (#5086/#6642 anchoring)")
	}
	if got := e.r.auth.peerEpochFloor(); got != liveEpoch {
		t.Fatalf("floor after a heartbeat restart = %d, want %d", got, liveEpoch)
	}
	admitted, total := e.replayAll(e.epochlessCaptures(heartbeatReplaySessions+8), 3)
	if admitted != 0 {
		t.Fatalf("epochless replay after a heartbeat restart: %d/%d admitted, want 0", admitted, total)
	}

	// A FULL daemon restart clears it. Documented, and the reason rollback
	// recovery is "rotate the PSK, then restart xpfd" rather than deleting a
	// state file. (The rotation is the half that retires an attacker's archive;
	// see TestRollbackRecoveryOrderingIsRotateThenRestart_6169. Nothing is being
	// replayed here, so the restart alone is enough for this assertion.)
	e.restartDaemon()
	if e.r.auth.peerEpochLatched() {
		t.Fatal("a full daemon restart is documented to clear the latch; it did not")
	}

	// And the live peer re-arms it on its very next heartbeat — one interval.
	if !e.feed(marshalHeartbeatAuthEpoch(samplePkt(), e.key, 0x22E1, 1, liveEpoch+1)) {
		t.Fatal("the live peer's first post-restart frame must be accepted")
	}
	if !e.r.auth.peerEpochLatched() {
		t.Fatal("one genuine epoch-bearing heartbeat must re-arm the latch")
	}
	admitted, total = e.replayAll(e.epochlessCaptures(heartbeatReplaySessions+8), 3)
	if admitted != 0 {
		t.Fatalf("epochless replay after re-arming: %d/%d admitted, want 0", admitted, total)
	}
	// The floor came back with it, so retired incarnations stay rejected.
	for i, f := range e.captureIncarnation(0x22DF, liveEpoch-1, epochFramesPerIncarnation) {
		if e.feed(f) {
			t.Fatalf("retired-epoch frame %d admitted after re-arming", i)
		}
	}
}

// TestHeartbeatEpochUpgradeWindowStillAccepts_6169 is the migration gate. The
// latch must be armed by OBSERVATION, never by local build version: until the
// peer has proved it emits epochs, its epochless frames must be accepted or a
// rolling upgrade splits the cluster — which is worse than the replay this
// closes. This must pass in every world.
func TestHeartbeatEpochUpgradeWindowStillAccepts_6169(t *testing.T) {
	e := newLatchEnv(t)

	if e.r.auth.peerEpochLatched() {
		t.Fatal("a receiver that has never seen an epoch must not be latched")
	}
	// The peer is still on a pre-#6169 build for a good while.
	for i := 0; i < 5; i++ {
		frames := e.captureIncarnation(uint64(0x3300+i), 0, epochFramesPerIncarnation)
		e.liveRun(frames, "not-yet-upgraded peer")
	}
	if e.r.auth.peerEpochLatched() {
		t.Fatal("epochless traffic must never arm the latch")
	}
	// The peer is upgraded mid-flight and starts signing epochs. Accepted, and
	// only now does the latch arm.
	e.liveRun(e.captureIncarnation(0x33FF, 9_200_000_000_000_000, epochFramesPerIncarnation), "peer after upgrade")
	if !e.r.auth.peerEpochLatched() {
		t.Fatal("the latch must arm once the peer proves it emits epochs")
	}
}

// TestHeartbeatEpochRollbackRefusedThenRecovered_6169 states, in executable
// form, exactly what happens when a peer is rolled back to a pre-#6169 build —
// the one legitimate trigger the latch cannot distinguish from an attack.
//
// The peer IS refused; that is the deliberate trade, and the same one #4107's
// sticky peerAuthSeen already makes for the auth trailer. In this fixture's
// in-memory model, recovery is ROTATE THE CONTROL-LINK PSK ON BOTH NODES, THEN
// `systemctl restart xpfd` on the refusing node — operations operators already
// perform, with no state file to hand-edit. (Since #16022 the latch is durable,
// so production recovery is the rotation ALONE — it clears the key-set-scoped
// record on the next apply; see
// TestPeerEpochRecordScopedToKeySet_16022. This test pins the in-memory half.)
//
// THE ROTATION IS NOT OPTIONAL AND ITS POSITION IS NOT COSMETIC. A bare restart
// clears the in-memory latch, the floor and the ring together, so a single
// ARCHIVED epoch-bearing frame replayed into that empty state re-arms the latch
// and the rolled-back peer is refused again — one replay per restart,
// indefinitely. Rotation is what retires the archive. This test covers only
// the no-attacker case, where the restart alone is enough; the ordering itself
// is proved in TestRollbackRecoveryOrderingIsRotateThenRestart_6169 and the
// re-arm in TestArchivedEpochReplayReArmsLatchAfterRestart_6169.
func TestHeartbeatEpochRollbackRefusedThenRecovered_6169(t *testing.T) {
	e := newLatchEnv(t)
	e.liveRun(e.captureIncarnation(0x44E0, 9_300_000_000_000_000, epochFramesPerIncarnation), "peer on an epoch-capable build")

	// Operator rolls the peer back: fresh session, fresh counter, no epoch.
	// Refused — indistinguishable on the wire from a replayed capture.
	rolledBack := e.captureIncarnation(0x44FF, 0, epochFramesPerIncarnation)
	for i, f := range rolledBack {
		if e.feed(f) {
			t.Fatalf("rolled-back peer frame %d was admitted — the latch is not engaging", i)
		}
	}
	if got := e.m.HeartbeatStats().EpochDowngradeRejected; got != uint64(len(rolledBack)) {
		t.Fatalf("EpochDowngradeRejected = %d, want %d — the operator must be able to SEE the refusal",
			got, len(rolledBack))
	}

	// Documented recovery, second half: restart xpfd on the refusing node. No
	// file to delete. The first half — rotating the control-link PSK — is not
	// exercised here because no archived frame is being replayed in this
	// scenario; with one, the restart alone is defeated
	// (TestRollbackRecoveryOrderingIsRotateThenRestart_6169).
	e.restartDaemon()
	if e.r.auth.peerEpochLatched() {
		t.Fatal("a daemon restart must disarm the latch")
	}
	e.liveRun(rolledBack, "rolled-back peer after restarting xpfd on the refusing node")
}

// TestHeartbeatEpochImplausibleValueCannotLockOut_6169 pins the one-way-door
// guard. An epoch outside the plausibility band must never become the floor —
// latching, say, MaxUint64 would reject every subsequent genuine frame forever.
//
// It does NOT arm the downgrade latch either, and that is the deliberate half:
// the frame is REFUSED, and the refusal returns before the arming site. Arming
// on it would make the refusal a one-way door — a peer whose only observed
// epochs were out of range would then have its epoch-less frames refused too,
// with nothing this receiver can order to let it back in. The assertions below
// pin both: no floor, no latch, and the genuine peer still accepted afterwards.
func TestHeartbeatEpochImplausibleValueCannotLockOut_6169(t *testing.T) {
	e := newLatchEnv(t)

	// A frame carrying an epoch the floor cannot ORDER is REFUSED, not
	// admitted-and-ignored: a frame outside the comparable range would be
	// governed by the bounded ring alone, which is the epochless bypass in
	// miniature.
	for _, bad := range []uint64{
		math.MaxUint64,
		epochPlausibleMax,
		uint64(time.Now().UnixNano()) + bootEpochMaxSkew*2, // plausible year, but far ahead of us
	} {
		if e.feed(marshalHeartbeatAuthEpoch(samplePkt(), e.key, 0x55E0, 1, bad)) {
			t.Fatalf("a frame with an unorderable epoch (%d) was admitted", bad)
		}
	}
	if got := e.r.auth.peerEpochFloor(); got != 0 {
		t.Fatalf("floor = %d, want 0 — an unorderable epoch must never be latched as the floor", got)
	}
	if e.r.auth.peerEpochLatched() {
		t.Fatal("a REFUSED frame must not arm the latch")
	}
	// The genuine peer with an ordinary epoch is still accepted the moment it
	// comes back into range — the refusal must not be a one-way door.
	e.liveRun(e.captureIncarnation(0x55E1, 9_400_000_000_000_000, epochFramesPerIncarnation), "genuine peer after an unorderable epoch")
}

// TestHeartbeatEpochlessAdmitsAreCounted_6169 pins the OBSERVABILITY guard.
//
// Until the peer has proved it emits epochs, an epochless frame is admitted on
// the bounded ring alone — which is the mechanism that stops working past
// heartbeatReplaySessions captures. That residual must be VISIBLE: an operator
// who has upgraded both nodes otherwise has no way to tell whether the cluster
// is still accepting pre-upgrade-shaped frames, and the documentation would be
// the only defence.
//
// The guard asserts the COUNT, not merely that the code path exists.
func TestHeartbeatEpochlessAdmitsAreCounted_6169(t *testing.T) {
	e := newLatchEnv(t)

	if got := e.r.auth.epochlessAdmitted.Load(); got != 0 {
		t.Fatalf("epochlessAdmitted starts at %d, want 0", got)
	}
	// A not-yet-upgraded peer: every admitted frame must be counted.
	const n = 7
	e.liveRun(e.captureIncarnation(0x88E0, 0, n), "not-yet-upgraded peer")
	if got := e.r.auth.epochlessAdmitted.Load(); got != n {
		t.Fatalf("epochlessAdmitted = %d after %d admitted epochless frames, want %d", got, n, n)
	}

	// An epoch-bearing frame must NOT be counted as epochless exposure.
	e.liveRun(e.captureIncarnation(0x88E1, 9_600_000_000_000_000, 3), "upgraded peer")
	if got := e.r.auth.epochlessAdmitted.Load(); got != n {
		t.Fatalf("epochlessAdmitted = %d after epoch-bearing frames, want it unchanged at %d", got, n)
	}

	// Once latched, epochless frames are REFUSED — counted separately, and the
	// exposure meter must not climb.
	before := e.r.auth.epochDowngradeRejected.Load()
	const rejects = 4
	for i := 0; i < rejects; i++ {
		if e.feed(marshalHeartbeatAuthEpoch(samplePkt(), e.key, uint64(0x88F0+i), 1, 0)) {
			t.Fatal("epochless frame admitted after the latch armed")
		}
	}
	if got := e.r.auth.epochDowngradeRejected.Load(); got != before+rejects {
		t.Fatalf("epochDowngradeRejected = %d, want %d", got, before+rejects)
	}
	if got := e.r.auth.epochlessAdmitted.Load(); got != n {
		t.Fatalf("epochlessAdmitted climbed to %d on REFUSED frames, want %d", got, n)
	}

	// And it reaches the operator surface.
	e.m.mu.Lock()
	e.m.hbReceiver = e.r
	e.m.mu.Unlock()
	st := e.m.HeartbeatStats()
	if st.EpochlessAdmitted != n {
		t.Fatalf("HeartbeatStats.EpochlessAdmitted = %d, want %d", st.EpochlessAdmitted, n)
	}
	if st.EpochDowngradeRejected != before+rejects {
		t.Fatalf("HeartbeatStats.EpochDowngradeRejected = %d, want %d", st.EpochDowngradeRejected, before+rejects)
	}
}

// TestHeartbeatEpochLatchLayersOverPeerAuthSeen_6169 states how the #6169 epoch
// latch composes with the #4107 peerAuthSeen latch. They are LAYERED, not
// duplicative, and neither subsumes the other:
//
//   - peerAuthSeen latches "the peer proved it holds the PSK" and refuses
//     UNSIGNED frames from then on.
//   - epochSeen latches "the peer proved it runs an epoch-capable build" and
//     refuses SIGNED-BUT-EPOCHLESS frames from then on.
//
// An attacker's replayed pre-upgrade capture is genuinely signed (it was
// captured off a keyed cluster), so it passes the first gate and is stopped only
// by the second — which is exactly why the epoch latch was needed. An unsigned
// frame never reaches the epoch gate at all: readLoop only calls admitAuthed
// when the MAC verified.
//
// The remaining open path is a cluster with NO key configured, where neither
// mechanism exists because there is no MAC to verify and the epoch marker is
// key-derived. That is #6624's domain — an unkeyed chassis cluster is refused at
// commit — and is out of scope here.
func TestHeartbeatEpochLatchLayersOverPeerAuthSeen_6169(t *testing.T) {
	e := newLatchEnv(t)

	// A signed, epoch-bearing frame arms BOTH latches.
	e.liveRun(e.captureIncarnation(0x99E0, 9_700_000_000_000_000, 3), "signed peer with an epoch")
	if !e.r.auth.peerAuthenticated() {
		t.Fatal("#4107: an accepted signed frame must arm peerAuthSeen")
	}
	if !e.r.auth.peerEpochLatched() {
		t.Fatal("#6169: an accepted epoch-bearing frame must arm epochSeen")
	}

	// UNSIGNED frame -> stopped by the #4107 gate, before admitAuthed runs.
	unsigned := MarshalHeartbeat(samplePkt())
	if _, _, present := heartbeatAuthTrailer(unsigned); present {
		t.Fatal("test frame unexpectedly carries an auth trailer")
	}
	if e.feed(unsigned) {
		t.Fatal("#4107: an unsigned frame must be refused once the peer has authenticated")
	}

	// SIGNED but epochless -> passes #4107 (the MAC verifies), stopped by #6169.
	signedEpochless := MarshalHeartbeatAuth(samplePkt(), e.key, 0x99E1, 1)
	if !verifyHeartbeatMAC(signedEpochless, e.key) {
		t.Fatal("test frame should verify")
	}
	if e.feed(signedEpochless) {
		t.Fatal("#6169: a signed but epochless frame must be refused once the epoch latch armed")
	}
}

// TestHeartbeatUnorderableEpochNeverArmsLatch_6169 makes the corrected
// admitAuthed comment executable.
//
// An earlier revision of this change ADMITTED an unorderable epoch without
// latching it; the comment above admitAuthed still described that behaviour
// after the code changed to REFUSE. Both halves are pinned here so the comment
// cannot drift from the code again:
//
//   - a frame whose epoch cannot be ordered is refused and does NOT arm the
//     latch, and
//   - the second-order consequence is the SAFE direction — because the latch
//     never armed, a peer that is later rolled back to a pre-#6169 build is
//     still accepted. Refusing an unorderable epoch never strands a peer.
func TestHeartbeatUnorderableEpochNeverArmsLatch_6169(t *testing.T) {
	e := newLatchEnv(t)

	// A peer whose clock runs years ahead: refused outright.
	farAhead := uint64(time.Now().UnixNano()) + bootEpochMaxSkew*3
	for i := 0; i < 5; i++ {
		if e.feed(marshalHeartbeatAuthEpoch(samplePkt(), e.key, 0xCC01, uint64(i+1), farAhead)) {
			t.Fatalf("frame %d with a far-future epoch was admitted", i)
		}
	}
	if e.r.auth.peerEpochLatched() {
		t.Fatal("a refused frame must never arm the downgrade latch")
	}
	if got := e.r.auth.peerEpochFloor(); got != 0 {
		t.Fatalf("floor = %d, want 0", got)
	}
	// A restart does not inherit a bogus latch either.
	e.restartDaemon()
	if e.r.auth.peerEpochLatched() {
		t.Fatal("a refused frame must not leave a latch behind")
	}

	// The safe direction: that peer, rolled back to a pre-#6169 build, is still
	// accepted — the latch never armed on it.
	e.liveRun(e.captureIncarnation(0xCC02, 0, epochFramesPerIncarnation), "peer rolled back after a far-future epoch")
}

// TestHeldFlockCannotCauseFalsePeerDeath_6169 reproduces, link by link, the
// exact chain a tie-break review measured against an earlier revision of this
// change:
//
//	held the real flock            -> StartHeartbeat returned after 2.0076s, bootEpoch 0
//	bootEpoch 0 => epochless frame -> heartbeatFrameEpoch: present=false
//	latched peer rejects them      -> fresh-nonce valid-MAC frames ALL rejected
//	rejection => declared dead     -> PeerAlive() false after 500ms
//
// A local, recoverable storage stall became a peer-declared death in 500ms — an
// availability regression on exactly the path this change exists to protect,
// and caused by the change itself.
//
// The chain is broken at LINK 1: the boot epoch is published synchronously from
// the wall clock before any file is touched, so a held lock (or a hung fsync,
// or an unwritable state dir) cannot make this node emit an epochless frame.
// The remaining links are asserted anyway, because the property that matters is
// the end of the chain, not the beginning.
//
// RED-on-revert: gate publication on the worker again (store bootEpoch only
// after refineBootEpoch) and link 1 fails immediately.
func TestHeldFlockCannotCauseFalsePeerDeath_6169(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ha-boot-epoch")
	orig := bootEpochPath
	bootEpochPath = path
	t.Cleanup(func() { bootEpochPath = orig })

	// Hold the REAL advisory lock the persist path takes, for the whole test.
	releaseLock := heldEpochLock(t, path)

	// LINK 1 — the sender still has an epoch, immediately, with the lock held.
	sender := NewManager(0, 42)
	// Release AND drain on the FAILURE path too — the explicit release below is
	// on the happy path only, and t.Fatalf skips it. One cleanup, in this order:
	// t.Cleanup is LIFO, so a separate drain would run before the release.
	t.Cleanup(func() {
		releaseLock()
		sender.joinBootEpochRefine(5 * time.Second)
	})
	start := time.Now()
	epoch := sender.heartbeatBootEpoch()
	elapsed := time.Since(start)
	if epoch == 0 {
		t.Fatal("LINK 1: bootEpoch is 0 while the persist lock is held — a storage stall " +
			"makes this node emit epochless frames, which a latched peer rejects")
	}
	if elapsed > time.Second {
		t.Fatalf("LINK 1: heartbeatBootEpoch blocked for %v on a held lock; it must not do I/O", elapsed)
	}

	// LINK 2 — the frames it emits carry that epoch.
	key := []byte("cluster-shared-secret")
	frame := marshalHeartbeatAuthEpoch(samplePkt(), key, 0xDD01, 1, epoch)
	got, present := heartbeatFrameEpoch(frame, key)
	if !present || got != epoch {
		t.Fatalf("LINK 2: frame epoch = (%d,%v), want (%d,true)", got, present, epoch)
	}

	// LINK 3 — a LATCHED peer accepts them.
	e := newLatchEnv(t)
	e.liveRun(e.captureIncarnation(0xDD00, epoch-1000, epochFramesPerIncarnation), "arming the peer's latch")
	if !e.r.auth.peerEpochLatched() {
		t.Fatal("test setup: the receiver should be latched")
	}
	for c := 1; c <= 5; c++ {
		f := marshalHeartbeatAuthEpoch(samplePkt(), e.key, 0xDD01, uint64(c), epoch)
		if !e.feed(f) {
			t.Fatalf("LINK 3: a latched peer REJECTED frame %d from a node whose storage is stalled", c)
		}
	}

	// LINK 4 — and therefore never declares it dead.
	e.r.checkTimeout()
	if !e.m.PeerAlive() {
		t.Fatal("LINK 4: peer declared DEAD while its heartbeats were being accepted")
	}

	// The lock is still held, so nothing above depended on the persist landing.
	if _, err := os.Stat(path); err == nil {
		t.Fatal("the epoch was persisted despite the lock being held; the lock is not exclusive")
	}

	// Release and drain the worker before the test ends, so its write cannot
	// race t.TempDir() cleanup. This also demonstrates the self-heal the
	// tie-break observed: the persist completes once the lock frees.
	releaseLock()
	awaitFirstRefine(t, sender, "the persist worker after the lock was released")
	if sender.heartbeatBootEpoch() == 0 {
		t.Fatal("the epoch went back to 0 after the persist completed")
	}
}

// TestInBoundFarFutureEpochLockoutIsBounded_6169 answers whether MAJOR 4
// survives the removal of the durable floor. It does, in reduced form, and this
// pins the reduced shape so it is a known cost rather than a discovery.
//
//   - An epoch BEYOND the forward bound is refused and never latched, so it
//     cannot lock anything out (TestHeartbeatUnorderableEpochNeverArmsLatch).
//   - An epoch INSIDE the bound IS latched, and a repaired peer returning to
//     real time then sits below that floor. That is the residual.
//
// Two things bound it, and the second is what the durable version lacked:
//  1. the slack IS the lockout, and it is one hour (bootEpochMaxSkew), so the
//     peer's own wall-clock seed climbs past the floor within that window; and
//  2. the floor is in memory, so `systemctl restart xpfd` on the refusing node
//     clears it immediately — with a durable floor this needed deleting a state
//     file, which is what made it a MAJOR. Subject to the same caveat as the
//     latch: a replayed archived frame can re-raise a cleared floor exactly as
//     it re-arms a cleared latch (README residual 5), so with an attacker
//     present the restart must follow a PSK rotation.
func TestInBoundFarFutureEpochLockoutIsBounded_6169(t *testing.T) {
	e := newLatchEnv(t)
	now := uint64(time.Now().UnixNano())

	// A peer whose clock is ahead, but INSIDE the skew allowance: latched.
	inBound := now + bootEpochMaxSkew/2
	if !epochOrderable(inBound, int64(now)) {
		t.Fatal("test setup: the value must be inside the bound")
	}
	e.liveRun(e.captureIncarnation(0xEE01, inBound, epochFramesPerIncarnation), "peer with a clock inside the skew allowance")
	if got := e.r.auth.peerEpochFloor(); got != inBound {
		t.Fatalf("floor = %d, want %d", got, inBound)
	}

	// The peer is repaired and comes back at real time: BELOW the floor, refused.
	repaired := e.captureIncarnation(0xEE02, now, epochFramesPerIncarnation)
	for i, f := range repaired {
		if e.feed(f) {
			t.Fatalf("repaired peer frame %d admitted; expected refusal below the latched floor", i)
		}
	}

	// BOUND 1 — the lockout cannot exceed the slack. Once the peer's own
	// wall-clock seed passes the floor it is accepted again with no operator
	// action at all.
	e.liveRun(e.captureIncarnation(0xEE03, inBound+1, epochFramesPerIncarnation), "peer once its clock passes the floor")

	// BOUND 2 — and in this in-memory model a restart clears it outright.
	// (Since #16022 the durable record persists it in production; the
	// rotation, not the restart, is now the clearing operation — see
	// TestPeerEpochRecordScopedToKeySet_16022.)
	e2 := newLatchEnv(t)
	e2.liveRun(e2.captureIncarnation(0xEE04, now+bootEpochMaxSkew/2, epochFramesPerIncarnation), "peer with a clock inside the allowance")
	e2.restartDaemon()
	if got := e2.r.auth.peerEpochFloor(); got != 0 {
		t.Fatalf("floor = %d after a daemon restart, want 0 — the lockout must be clearable by a restart", got)
	}
	e2.liveRun(e2.captureIncarnation(0xEE05, now, epochFramesPerIncarnation), "repaired peer after restarting xpfd")
}

// TestReceiverRestartWindowIsOneHeartbeat_6169 measures what the IN-MEMORY
// floor costs at a receiver daemon restart, rather than asserting it.
// (Since #16022 the durable record closes this window in production; this
// fixture models the in-memory lifecycle only — see the file header.)
//
// The claim being checked: the window is bounded by the peer's next genuine
// heartbeat — roughly one interval — after which the floor re-establishes above
// any captured older epoch. It holds, with one honest qualification: a replay
// landing INSIDE the window is admitted (and can even set a low floor), but the
// live peer's next frame carries a strictly higher epoch, which repairs the
// floor and re-arms the latch. Sustained exposure therefore additionally
// requires the genuine peer to be ABSENT.
//
// SCOPE — THIS IS A MONOTONIC-SENDER RESULT, and the qualifier is load-bearing.
// An earlier revision of this comment generalised it to "the genuine frame
// always dominates", which is FALSE. Everything below assumes the live peer's
// next epoch is HIGHER than the replayed one; that is what makes it dominate.
// When the peer's own epoch has REGRESSED (#6711 — a backward clock step larger
// than bootEpochMaxSkew), the archived frame carries the HIGHER value, the floor
// rises above the live peer, and no genuine frame repairs it. That case is
// measured separately in TestArchivedEpochPoisonsAFreshFloor_6711; do not read
// this test as covering it.
func TestReceiverRestartWindowIsOneHeartbeat_6169(t *testing.T) {
	e := newLatchEnv(t)
	const liveEpoch = uint64(9_500_000_000_000_000)
	e.liveRun(e.captureIncarnation(0xFF01, liveEpoch, epochFramesPerIncarnation), "live upgraded peer")

	// The attacker's pre-upgrade, epochless captures.
	caps := e.epochlessCaptures(heartbeatReplaySessions + 8)

	// Daemon restart: the window opens.
	e.restartDaemon()
	if e.r.auth.peerEpochLatched() {
		t.Fatal("a daemon restart should clear the latch")
	}
	// Inside the window a replay IS admitted — stated, not hidden.
	if !e.feed(caps[0][0]) {
		t.Fatal("expected the documented in-window admission")
	}

	// The genuine peer's very next heartbeat closes it: one frame, one interval.
	if !e.feed(marshalHeartbeatAuthEpoch(samplePkt(), e.key, 0xFF02, 1, liveEpoch+1)) {
		t.Fatal("the live peer's first post-restart frame must be accepted")
	}
	if !e.r.auth.peerEpochLatched() {
		t.Fatal("one genuine epoch-bearing heartbeat must re-arm the latch")
	}

	// From here the whole capture set is refused again.
	admitted, total := e.replayAll(caps, 3)
	if admitted != 0 {
		t.Fatalf("after re-arming: %d/%d replays admitted, want 0", admitted, total)
	}
	// And a retired incarnation is below the re-established floor.
	for i, f := range e.captureIncarnation(0xFF03, liveEpoch-1, epochFramesPerIncarnation) {
		if e.feed(f) {
			t.Fatalf("retired-epoch frame %d admitted after re-arming", i)
		}
	}
}

// TestInitHeartbeatEpochStateNeverBlocks_6169 is the guard for the relocated
// form of the storage-hang failure.
//
// StartHeartbeat calls StopHeartbeat() FIRST, then initHeartbeatEpochState().
// While that second call waited on the refine worker, a wedged store stalled a
// node whose heartbeat was already STOPPED — measured at 2.005s / 2.012s /
// 2.011s against a dead-peer threshold of 500ms (code default) or 1s (shipped
// 200ms interval). The peer cannot tell "emits epoch-less frames" from "emits
// no frames at all"; both end in a healthy node declared dead. Every routine
// VRF rebind and HA comms restart would have paid it.
//
// The wait bought nothing once emission moved ahead of all I/O, so it is gone.
//
// RED-on-revert: reinstate a `select { case <-m.bootEpochReady: case
// <-time.After(...) }` in initHeartbeatEpochState.
func TestInitHeartbeatEpochStateNeverBlocks_6169(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ha-boot-epoch")
	orig := bootEpochPath
	bootEpochPath = path
	t.Cleanup(func() { bootEpochPath = orig })

	// Wedge the store by holding the lock the refine worker needs.
	releaseLock := heldEpochLock(t, path)

	m := NewManager(0, 42)
	m.mu.Lock()
	m.controlAuthKey = []byte("cluster-shared-secret") // keyed, so the epoch path engages
	m.mu.Unlock()
	// Release AND drain on the FAILURE path too — the explicit release below is
	// on the happy path only, and t.Fatalf skips it. One cleanup, in this order:
	// t.Cleanup is LIFO, so a separate drain would run before the release.
	t.Cleanup(func() {
		releaseLock()
		m.joinBootEpochRefine(5 * time.Second)
	})

	// Three calls, as three routine restarts would make.
	const budget = 250 * time.Millisecond // well under the 500ms dead-peer floor
	for i := 0; i < 3; i++ {
		start := time.Now()
		m.initHeartbeatEpochState()
		if elapsed := time.Since(start); elapsed > budget {
			t.Fatalf("initHeartbeatEpochState blocked %v on call %d with the store wedged; "+
				"StartHeartbeat has already STOPPED the heartbeat by this point, so this is a "+
				"self-inflicted peer-death window", elapsed, i)
		}
	}
	// And the epoch is advertised throughout, despite the wedge.
	if m.heartbeatBootEpoch() == 0 {
		t.Fatal("no epoch advertised while the store is wedged")
	}

	// Release and drain so the worker cannot race t.TempDir cleanup.
	//
	// bootEpochReady IS NOT A FULL DRAIN, and treating it as one left this test
	// leaking a worker into the rest of the package. It is closed when the FIRST
	// attempt finishes, by contract (see startBootEpochRefine); the second and
	// third calls above go through refreshBootEpoch, whose requests are COALESCED
	// onto the running worker rather than dropped, so passes are still owed after
	// it closes. The escaped worker then read epochNowNanos while a later test
	// (senderIncarnationAt, TestArchivedEpochPoisonsAFreshFloor_6711) overrode
	// it: a data race that failed `go test -race ./pkg/cluster/` 20 times out of
	// 20 when those two tests ran together, and intermittently in the full suite.
	// awaitFirstRefine waits for ready AND drains, which is the actual join.
	releaseLock()
	awaitFirstRefine(t, m, "the refine worker after the lock was released")
}

// TestStartHeartbeatReturnsWithAUsableEpoch_6169 answers the question deleting
// the wait raises: removing a bound is exactly the kind of fix that trades a
// stall for a RACE, so this pins that StartHeartbeat cannot return before the
// epoch is usable — and pins it under the wedged store, where the old wait
// existed.
//
// The ordering that makes it safe: initHeartbeatEpochState calls
// heartbeatBootEpoch, whose sync.Once body stores the wall-clock seed BEFORE it
// spawns the refinement worker. sync.Once.Do does not return until that body
// completes, so publication happens-before StartHeartbeat proceeds. Nothing in
// that path touches the filesystem.
//
// RED-on-revert: move the bootEpoch.Store into the worker goroutine and the
// epoch is 0 when StartHeartbeat returns.
func TestStartHeartbeatReturnsWithAUsableEpoch_6169(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ha-boot-epoch")
	orig := bootEpochPath
	bootEpochPath = path
	t.Cleanup(func() { bootEpochPath = orig })

	// Wedge the store for the whole of StartHeartbeat.
	releaseLock := heldEpochLock(t, path)

	m := NewManager(0, 42)
	m.mu.Lock()
	m.controlAuthKey = []byte("cluster-shared-secret")
	m.mu.Unlock()
	t.Cleanup(m.StopHeartbeat)
	// Release AND drain on the FAILURE path too — the explicit release below is
	// on the happy path only, and t.Fatalf skips it. One cleanup, in this order:
	// t.Cleanup is LIFO, so a separate drain would run before the release.
	t.Cleanup(func() {
		releaseLock()
		m.joinBootEpochRefine(5 * time.Second)
	})

	start := time.Now()
	if err := m.StartHeartbeat("127.0.0.1", "127.0.0.1", "", "em0"); err != nil {
		t.Fatalf("StartHeartbeat: %v", err)
	}
	elapsed := time.Since(start)

	// No stall...
	if elapsed > 500*time.Millisecond {
		t.Fatalf("StartHeartbeat took %v with the store wedged; the heartbeat is down for that whole window", elapsed)
	}
	// ...and no race: the epoch is usable the instant it returns.
	epoch := m.heartbeatBootEpoch()
	if epoch == 0 {
		t.Fatal("StartHeartbeat returned with no usable epoch — deleting the wait traded a stall for a race")
	}
	if !epochOrderable(epoch, time.Now().UnixNano()) {
		t.Fatalf("epoch %d is not orderable, so a peer would refuse it", epoch)
	}
	// And a frame built right now carries it, so a latched peer accepts us.
	key := m.controlLinkAuthKey()
	frame := marshalHeartbeatAuthEpoch(m.buildHeartbeat(), key, 1, 1, m.heartbeatBootEpoch())
	if _, present := heartbeatFrameEpoch(frame, key); !present {
		t.Fatal("the first frame after StartHeartbeat carries no epoch")
	}

	// Release and drain so the worker cannot outlive t.TempDir — or the seams a
	// LATER test installs. bootEpochReady alone is not that drain; see
	// awaitFirstRefine.
	releaseLock()
	awaitFirstRefine(t, m, "the refinement worker after the lock was released")
}

// TestBackwardClockStepDoesNotKillALatchedPeer_6169 is the fail-on-revert gate
// for the clock-step false-peer-death.
//
// epochOrderable was applied to EVERY epoch-bearing frame, including one
// carrying the already-accepted epoch from the already-latched incarnation. A
// backward wall-clock step beyond bootEpochMaxSkew therefore made the live
// peer's ordinary frames fail the forward bound and be rejected BEFORE the
// monotonic lastSeen update — a healthy peer declared dead in ~500ms, and a
// spurious dual-master. That is wall-clock sensitivity on the accept path,
// which #1792's CLOCK_MONOTONIC lastSeen exists specifically to keep out.
//
// The forward bound now gates only RAISING the floor.
//
// RED-on-revert: restore the unconditional `if !epochOrderable(epoch, now)`
// ahead of the floor comparison in admitAuthed.
func TestBackwardClockStepDoesNotKillALatchedPeer_6169(t *testing.T) {
	e := newLatchEnv(t)

	// The peer's clock is well ahead of ours — or equivalently, ours has since
	// stepped back. Either way its epoch is beyond the forward bound relative to
	// our clock RIGHT NOW.
	stepped := uint64(time.Now().UnixNano()) + bootEpochMaxSkew*3
	if epochWithinForwardBound(stepped, time.Now().UnixNano()) {
		t.Fatal("test setup: the epoch must be beyond the forward bound")
	}

	// It was latched earlier, when the clocks still agreed. Model that directly:
	// the floor holds this incarnation's epoch AND is bound to the session that
	// raised it. Both halves, because the real raise path sets both — a floor
	// with an unbound session is a state admitAuthed cannot reach, and
	// modelling only the epoch would test the peer against a DIFFERENT
	// incarnation than the one this test says is already latched.
	const liveSession = uint64(0x7701)
	e.r.auth.mu.Lock()
	e.r.auth.highEpoch = stepped
	e.r.auth.bindEpochSession(liveSession, true)
	e.r.auth.epochSeen = true
	e.r.auth.mu.Unlock()

	// The live peer keeps sending frames carrying that SAME epoch. Every one
	// must be accepted: it is the incarnation we already latched, and nothing
	// about it is newer or unordered.
	for c := 1; c <= 10; c++ {
		f := marshalHeartbeatAuthEpoch(samplePkt(), e.key, liveSession, uint64(c), stepped)
		if !e.feed(f) {
			t.Fatalf("frame %d from the ALREADY-LATCHED incarnation was rejected after a clock "+
				"step; the peer is declared dead in ~500ms and the cluster goes dual-master", c)
		}
	}
	// Liveness was refreshed, so checkTimeout keeps the peer alive.
	e.r.checkTimeout()
	if !e.m.PeerAlive() {
		t.Fatal("healthy peer declared dead after a backward clock step")
	}

	// The one-way door is still shut: a HIGHER out-of-bound epoch must not be
	// LATCHED, because raising the floor is the irreversible operation.
	//
	// #6969 F5 re-decided the frame's DISPOSITION here, and only that. This
	// case's own message already said the bound "must still gate raising", and
	// that is what is asserted below and still holds: the floor is pinned. What
	// changed is that the frame is no longer REJECTED — rejecting it dropped it
	// before the monotonic lastSeen update, so a peer that restarts while this
	// receiver's clock is slow was declared dead in ~500ms and the cluster went
	// dual-master over a clock fault on THIS node. The receiver has an
	// established floor here, which is exactly the condition under which the
	// decline applies; a FRESH receiver still refuses outright.
	higher := stepped + 1
	if !e.feed(marshalHeartbeatAuthEpoch(samplePkt(), e.key, 0x7702, 1, higher)) {
		t.Fatal("an out-of-bound HIGHER epoch was REJECTED by an already-latched receiver. " +
			"The frame must be admitted with the RAISE declined: the floor is the " +
			"irreversible operation, liveness is not (#6969 F5)")
	}
	if got := e.r.auth.peerEpochFloor(); got != stepped {
		t.Fatalf("floor moved to %d, want it pinned at %d", got, stepped)
	}
}

// senderIncarnationAt models the SENDER half at a PINNED wall clock: publish
// the seed that clock produces, then run the real refineBootEpoch against the
// real persisted file. It returns the epoch this incarnation would advertise
// and the value left in the file afterwards.
//
// Both clocks are pinned to the SAME instant deliberately. bootEpochSeed() and
// refineBootEpoch's judgment sample are separate reads of the wall clock in
// production; modelling them as one instant is what lets the test state a
// single "this node's clock reads X" premise.
func senderIncarnationAt(t *testing.T, path string, clock int64) (published, persisted uint64) {
	t.Helper()
	restore := epochNowNanos
	epochNowNanos = func() int64 { return clock }
	defer func() { epochNowNanos = restore }()

	var pub atomic.Uint64
	pub.Store(uint64(clock)) // what bootEpochSeed() returns at this instant
	refineBootEpoch(path, &pub, 0)

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read persisted epoch: %v", err)
	}
	n, err := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
	if err != nil {
		t.Fatalf("parse persisted epoch %q: %v", data, err)
	}
	return pub.Load(), n
}

// TestArchivedEpochPoisonsAFreshFloor_6711 measures the #6711 residual in the
// shape that actually determines recovery, and it is the counterexample to
// three claims this package used to make in the unqualified form:
//
//   - "a captured high-epoch frame cannot push the floor above the live peer"
//     (admitAuthed's doc, both copies);
//   - "the genuine frame always dominates" (README residual 1, and the scope
//     note on TestReceiverRestartWindowIsOneHeartbeat_6169);
//   - "declining costs a lockout that any restart on either node clears"
//     (heartbeat_epoch_test.go's chaining rationale).
//
// All three hold only while the SENDER IS MONOTONIC. The sender is not
// monotonic across a backward clock step larger than bootEpochMaxSkew: the
// persisted term of the seed is bounded, so refineBootEpoch declines to chain
// from the intact higher value AND durably overwrites it with the lower one.
// From then on the peer's archived frames carry a HIGHER epoch than the peer
// itself does, and one of them is enough to raise a floor the live peer is
// then refused at.
//
// "REFUSED AT", NOT "CAN NEVER CLIMB BACK OVER" — an earlier revision of this
// header said never, and the body does not test never. What it asserts is a
// restart ONE SECOND later, which is a lower bound on the lockout, not its
// duration. The production doc has this right: a clock that stays two hours
// slow reads past the archived floor two real hours later, and the epoch it
// then publishes is admitted on the RAISE path and rebinds the floor (see
// refineBootEpoch's decline branch and
// TestPoisonedFloorStillRecoversByRaise_6669). The lockout is bounded by how
// long the published reading stays below the floor — which can be arbitrarily
// long, and is not forever.
//
// The widening this pins, over the plain #6711 sequence, is the ARCHIVED FRAME
// ARRIVING FIRST at a receiver with FRESH state. The floor is then poisoned by
// a CAPTURE rather than by the sender's own live traffic, so the documented
// escape — restart the receiver, the floor is in memory — is defeated at one
// re-injection per restart, exactly as residual 5 defeats the restart recovery
// for the LATCH.
//
// REWRITTEN AGAINST THE #6711 FIX. The header used to end: "THIS PINS TODAY'S
// BEHAVIOUR, NOT THE DESIRED BEHAVIOUR. A real #6711 fix changes it, and this
// test is then expected to fail and be rewritten against the new semantics —
// deliberately, so the change is visible rather than silent." That fix has now
// landed, and this is that rewrite rather than a deletion, because everything
// the sequence pinned EXCEPT the overwrite is still true and still worth
// guarding.
//
// What changed: incarnation B no longer DESTROYS the intact predecessor. It
// still declines to chain from it (chaining across a step that large is the
// unrecoverable direction), so B still publishes the lower value and is still
// refused — the lockout while the clock is wrong is unchanged, and the archived-
// frame poisoning below is untouched. What the preserved file buys is the exit:
// the leg at the end shows a restart AFTER the clock is corrected chaining back
// above the floor immediately, which before the fix was impossible because the
// value it needed had been overwritten.
func TestArchivedEpochPoisonsAFreshFloor_6711(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ha-boot-epoch")

	// T is a correct present-day clock; the regressed incarnation runs 2h behind,
	// which is beyond bootEpochMaxSkew (1h) and far above epochClockSaneFloor.
	tNow := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC).UnixNano()
	back := tNow - int64(2*time.Hour)
	if uint64(back) < epochClockSaneFloor {
		t.Fatal("test setup: the regressed clock must still be credible")
	}
	if uint64(tNow) <= uint64(back)+bootEpochMaxSkew {
		t.Fatal("test setup: the step must exceed bootEpochMaxSkew")
	}

	// --- SENDER 1: incarnation A at the correct time. Publishes and persists T.
	epochA, fileA := senderIncarnationAt(t, path, tNow)
	if epochA != uint64(tNow) || fileA != uint64(tNow) {
		t.Fatalf("A: published=%d persisted=%d, want both %d", epochA, fileA, tNow)
	}

	// --- SENDER 2: incarnation B starts 2h behind with the file INTACT.
	// It declines to chain from the correct T and publishes the LOWER value —
	// unchanged by the #6711 fix, because chaining across a step that large
	// would strand this node ABOVE the range its peer accepts, which is the
	// unrecoverable direction.
	//
	// What the fix changes is the file: the intact higher value is PRESERVED,
	// not overwritten. Before the fix the overwrite is what made the regression
	// survive a sender restart even after the clock was corrected.
	epochB, fileB := senderIncarnationAt(t, path, back)
	if epochB != uint64(back) {
		t.Fatalf("B: published=%d, want %d — refinement must decline to chain from the intact T", epochB, back)
	}
	if fileB != uint64(tNow) {
		t.Fatalf("B: persisted=%d, want the PRESERVED intact value %d — overwriting it with the "+
			"stepped-back seed is what makes a single backward clock step outlive every restart (#6711)",
			fileB, tNow)
	}

	// --- SENDER 3: restarting B while the clock is still wrong does NOT recover.
	epochB2, _ := senderIncarnationAt(t, path, back+int64(time.Second))
	if epochB2 >= uint64(tNow) {
		t.Fatalf("a sender restart at the same wrong clock published %d, which already clears floor %d; "+
			"the premise of this test is that it does not", epochB2, tNow)
	}

	// --- RECEIVER: fresh process state, and the attacker's ARCHIVED A frame
	// (epoch T) arrives BEFORE any live traffic.
	e := newLatchEnv(t)
	archived := e.captureIncarnation(0xA711, uint64(tNow), epochFramesPerIncarnation)
	if !e.feed(archived[0]) {
		t.Fatal("the archived frame was refused against fresh state; the premise of the sequence is that it is admitted")
	}
	if got := e.r.auth.peerEpochFloor(); got != uint64(tNow) {
		t.Fatalf("floor = %d after ONE archived frame, want %d", got, tNow)
	}

	// The LIVE peer is now below a floor it never emitted. Every frame refused.
	if admitted := feedCount(e, e.captureIncarnation(0xB711, epochB, epochFramesPerIncarnation)); admitted != 0 {
		t.Fatalf("live peer: %d/%d frames admitted, want 0 — the archived frame must have locked it out",
			admitted, epochFramesPerIncarnation)
	}
	// And its next genuine incarnation too, so this is not a within-incarnation
	// artefact: a sender restart is not the escape.
	if admitted := feedCount(e, e.captureIncarnation(0xB712, epochB2, epochFramesPerIncarnation)); admitted != 0 {
		t.Fatalf("live peer after a SENDER restart: %d/%d frames admitted, want 0",
			admitted, epochFramesPerIncarnation)
	}

	// --- THE WIDENING: a RECEIVER restart clears the floor, as documented...
	e.restartDaemon()
	if got := e.r.auth.peerEpochFloor(); got != 0 {
		t.Fatalf("floor = %d after a receiver daemon restart, want 0", got)
	}
	// ...and the live peer WOULD be accepted in that window — the escape is real
	// only while the attacker is not re-injecting. Assert it, so the next clause
	// is a genuine contrast rather than a restatement.
	if !e.feed(marshalHeartbeatAuthEpoch(samplePkt(), e.key, 0xB713, 1, epochB2)) {
		t.Fatal("the live peer must be accepted against a genuinely cleared floor")
	}

	// ...but one re-injected archived frame re-poisons it, at one per restart.
	e.restartDaemon()
	if !e.feed(archived[1]) {
		t.Fatal("the archived frame was refused after the receiver restart")
	}
	if got := e.r.auth.peerEpochFloor(); got != uint64(tNow) {
		t.Fatalf("floor = %d after re-injection, want %d", got, tNow)
	}
	if admitted := feedCount(e, e.captureIncarnation(0xB714, epochB2, epochFramesPerIncarnation)); admitted != 0 {
		t.Fatalf("live peer after receiver restart + re-injection: %d/%d admitted, want 0 — "+
			"the restart escape must be defeated", admitted, epochFramesPerIncarnation)
	}

	// --- THE EXIT THE #6711 FIX BUYS: correct the clock and restart the sender.
	// The preserved predecessor is still on disk, so refinement chains from it
	// and publishes STRICTLY ABOVE the poisoned floor — admitted on the raise
	// path, which rebinds the floor to the live incarnation.
	//
	// Before the fix this leg was impossible: incarnation B had overwritten the
	// file with the stepped-back value, so a corrected-clock restart published
	// only its own wall clock, which sits AT the floor rather than above it, and
	// the equality door is finite (heartbeatEpochSessionsPerEpoch, no refill).
	epochC, fileC := senderIncarnationAt(t, path, tNow+int64(time.Second))
	if epochC <= uint64(tNow) {
		t.Fatalf("after the clock was corrected the sender published %d, which does not clear the "+
			"poisoned floor %d; recovery depends on chaining from the preserved predecessor (#6711)",
			epochC, tNow)
	}
	if fileC <= uint64(tNow) {
		t.Fatalf("the corrected incarnation persisted %d, want a value above %d so the NEXT restart "+
			"keeps climbing", fileC, tNow)
	}
	e.restartDaemon()
	if !e.feed(archived[2]) {
		t.Fatal("the archived frame was refused after the receiver restart")
	}
	if admitted := feedCount(e, e.captureIncarnation(0xB715, epochC, epochFramesPerIncarnation)); admitted == 0 {
		t.Fatalf("the corrected sender (epoch %d) was refused against the archived floor %d even "+
			"though it is strictly above it — the raise path is the documented exit and must work",
			epochC, tNow)
	}
}

// feedCount feeds every frame and reports how many were admitted.
func feedCount(e *latchEnv, frames [][]byte) int {
	e.t.Helper()
	admitted := 0
	for _, f := range frames {
		if e.feed(f) {
			admitted++
		}
	}
	return admitted
}

// TestRotationDoesNotRetirePostRotationCaptures_6669 is the counterexample to
// "a durable latch buys nothing the mandatory PSK rotation has not already
// bought" — a claim the epochSeen field comment and README used to make.
//
// A PSK rotation retires every frame captured BEFORE it, because those frames
// fail verifyHeartbeatMAC under the new key. It cannot retire a frame captured
// AFTER it: that frame was signed with the key still in force, so it still
// verifies. The whole run below happens under ONE key, which IS the post-
// rotation key — modelling "the rotation already happened, and everything here
// came after it".
//
// The sequence needs the peer to have run a build that SIGNS but emits no
// epoch while holding the current key — rollback, replacement under the same
// identity and key, or a partial upgrade. That precondition is what #16022's
// durable latch now refuses across the restart below; in this fixture's
// in-memory model (no UpdateConfig apply, no redirected record) the restart
// still clears the latch, so the captures are admitted — the pre-#16022
// behaviour this test was written to pin. The durable refusal is pinned in
// TestEpochlessReplayRefusedAfterDaemonRestart_16022.
//
// This pins the IN-MEMORY behaviour and the argument that rested on it, not
// the durable one.
func TestRotationDoesNotRetirePostRotationCaptures_6669(t *testing.T) {
	e := newLatchEnv(t)

	// Post-rotation, the epoch-capable peer arms the latch under the new key.
	const liveEpoch = uint64(9_600_000_000_000_000)
	e.liveRun(e.captureIncarnation(0xC669, liveEpoch, epochFramesPerIncarnation),
		"epoch-capable peer under the post-rotation key")
	if !e.r.auth.peerEpochLatched() {
		t.Fatal("an accepted epoch-bearing frame must arm the latch")
	}

	// The peer is rolled back under the SAME key to a signing-but-epochless
	// build. Those frames are refused — and the attacker records them. This is
	// the capture the rotation cannot retire, because it postdates the rotation.
	postRotationCaptures := e.captureIncarnation(0xC66A, 0, epochFramesPerIncarnation)
	if admitted := feedCount(e, postRotationCaptures); admitted != 0 {
		t.Fatalf("rolled-back peer while latched: %d/%d admitted, want 0", admitted, epochFramesPerIncarnation)
	}

	// The peer goes silent and this daemon restarts: in this in-memory
	// fixture the latch clears. (#16022's durable record, restored through
	// UpdateConfig in production, would still be armed for this key and
	// would refuse the captures below — pinned in
	// TestEpochlessReplayRefusedAfterDaemonRestart_16022.)
	e.restartDaemon()
	if e.r.auth.peerEpochLatched() {
		t.Fatal("a daemon restart must clear the in-memory latch")
	}

	// The post-rotation captures are admitted against the empty in-memory
	// state. A durable, PSK-scoped latch would still be armed for this key
	// and would refuse them — that is the benefit the rotation argument
	// wrongly claimed was already bought, and the one #16022 now takes.
	admitted := feedCount(e, postRotationCaptures)
	if admitted != epochFramesPerIncarnation {
		t.Fatalf("post-rotation epoch-less captures after a restart: %d/%d admitted, want %d — "+
			"the rotation cannot retire a capture taken after it",
			admitted, epochFramesPerIncarnation, epochFramesPerIncarnation)
	}
}
