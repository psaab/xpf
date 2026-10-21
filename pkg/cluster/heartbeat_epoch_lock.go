package cluster

// Cross-process locking for the HA boot-epoch state file.
//
// Split out of heartbeat_epoch.go (#6826): the acquisition policy is a
// self-contained concern — how long to wait for a lock another PROCESS holds,
// and which errno means "wait" versus "give up" — and it is the part a reader
// chasing a startup delay needs, without the epoch chaining and wire-format
// reasoning around it.

import (
	"log/slog"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

// withEpochFileLock serializes a read-modify-write of an epoch state file
// across PROCESSES, not merely within one.
//
// Within a process the one file this guards has a single writer at a time
// (Manager.startBootEpochRefine admits one refine worker), but two overlapping
// daemon incarnations could interleave read-modify-write, and an interleaved one
// can lose the update the other just made. An advisory lock on a sidecar file is
// cheaper than reasoning about whether the race is reachable.
//
// WHY OVERLAPPING INCARNATIONS ARE POSSIBLE — corrected in #8233. An earlier
// revision of this comment said the primary gRPC listener sets SO_REUSEPORT
// (pkg/grpcapi/server.go) so a second xpfd does not fail on a port collision.
// That is wrong twice over, and the second half is the trap: server.go DOES set
// SO_REUSEPORT — on the FABRIC listener, RunFabricListener — so a reader who
// greps the file finds the option and concludes the correction is the error. The
// PRIMARY management listener is a plain net.Listen("tcp", s.addr) with no
// ListenConfig and no Control hook, and a second xpfd's bind on it DOES fail
// with EADDRINUSE.
//
// What let the second daemon survive was supervisePrimaryListener treating every
// bind failure as transient — log, back off, retry forever — while Run returned
// nil, so the daemon came up with a permanently dead management listener. #8233
// bounds the EADDRINUSE retry and then exits.
//
// THE CONCLUSION IS UNCHANGED and this lock is still required. #8233 reduces how
// often two incarnations overlap; it does not make it unreachable — a supervisor
// that ignores the exit code can still start a second daemon, and nothing helps a
// node already in that state. See #7501's live-sibling refiner, which TOLERATES
// it, and which this lock complements rather than duplicates.
//
// IT DOES NOT ORDER INCARNATIONS, and an earlier revision of this comment said
// it did ("publish epochs that are not strictly ordered — which is precisely the
// property the whole mechanism rests on"). It serializes by LOCK ACQUISITION,
// and there is no happens-before edge from daemon start, or from survivorship,
// to that acquisition. heartbeatBootEpoch publishes the wall-clock seed and
// starts emitting BEFORE its worker reaches this function, deliberately (a
// storage fault must not take a healthy node off the air), so the two orders are
// independent. Older incarnation A publishes `a` and is delayed; newer B
// publishes `b > a`, locks first, persists `b`; A locks second, reads `b`,
// raises itself to `b+1` and persists that. The peer then latches `b+1` from the
// OLDER incarnation and refuses the NEWER one at `b`.
//
// That mis-ordering is not closed here, and it cannot be with this file alone:
// refinement only ever matters when the persisted value exceeds our own seed,
// and "a predecessor wrote it after a backward clock step" and "a concurrent
// newer incarnation wrote it" produce the identical file. Separating them needs
// state this design does not keep — a lifetime-held liveness lock, or a writer
// identity in the file — i.e. a larger change than the epoch itself. What IS
// closed is the unrecoverable half: refinement is re-runnable
// (Manager.refreshBootEpoch), so the stranded incarnation raises itself above
// the file again at its next heartbeat (re)start instead of being pinned below
// the floor for the life of the process by a one-shot sync.Once. Between the
// mis-ordering and that next start this node IS refused. #6724 closed the
// half of that gap which was a MISSING TRIGGER rather than missing state —
// Manager.retryOwedBootEpochPersist re-runs refinement from the sender loop
// when, and only when, a pass could not persist — and the mis-ordering itself
// is tracked as #7501. See
// TestConcurrentIncarnationsAreOrderedByLockAcquisition_6669.
//
// THAT RECOVERY CARRIES TWO CONDITIONS, and stating it flat overstates it. The
// re-run reads the FILE, so it can only recover what the file expresses:
//
//   - THE FLOOR-RAISING EPOCH MUST HAVE REACHED THE FILE. refineBootEpoch
//     publishes a raise BEFORE persisting it, deliberately — a node that has
//     read a predecessor's higher value must still order itself above that
//     value even when it cannot write, which is the backward-clock-step case
//     persistence exists for. So A can EMIT `b+1` while the file still reads
//     `b`. B then has no signal at all: it wrote `b`, the file says `b`, and
//     every restart returns at refineBootEpoch's `prev == lastWrote` shortcut.
//     B stays below the peer's floor for its whole process lifetime, however
//     many times it restarts, because the information is not in the only
//     channel it reads.
//   - THE OTHER INCARNATION MUST BE GONE. While both run, each pass raises
//     above the other and rewrites the file, so they leapfrog indefinitely and
//     alternately strand each other while the file ratchets. The test above
//     makes A exit before B re-refines, and that step is load-bearing.
//
// Both are characterized in
// TestRefineRecoveryNeedsTheRaisingEpochInTheFile_6669, and they are tracked
// with the mis-ordering — but they do NOT both need the same missing state, and
// an earlier revision of this comment said they did.
//
// CONDITION 2 does: separating "a concurrent newer incarnation wrote it" from
// "a predecessor wrote it after a backward clock step" needs a writer identity
// or a lifetime-held liveness lock, which is where the leapfrog lives.
//
// CONDITION 1 needs neither, and is CLOSED (#6724). It needed A to RETRY ITS
// FAILED PERSIST, and the code already did the right thing on a retry: A's
// published value is already b+1, so `next := prev+1` is not > epoch, nothing
// ratchets, and the WriteFileDurable is simply re-attempted. Once b+1 reaches
// the file, B's next refreshBootEpoch reads it, raises to b+2 and is admitted.
// What was missing was only a TRIGGER for that retry, which is a materially
// smaller change than a writer identity: refineBootEpochReporting now reports
// whether a persist is OWED, and Manager.retryOwedBootEpochPersist re-runs
// refinement from the heartbeat sender loop while one is. The gate is
// load-bearing in the other direction too — an UNCONDITIONAL periodic refine
// would make the leapfrog below continuous, so both nodes would be refused for
// part of every period instead of one being refused until its next restart.
//
// Fails CLOSED: if the lock cannot be taken, the read-modify-write is SKIPPED
// rather than run unlocked. A lock whose failure path executes the critical
// section anyway is not a lock — it reinstates the very race it exists to
// prevent, exactly when the guard cannot fire.
//
// WHY DECLINING IS RIGHT, not merely cheap. Proceeding unlocked does not trade
// correctness for liveness; it trades a TRANSIENT liveness risk for a DURABLE
// one. A raced read-modify-write can leave a lower epoch in the file than an
// overlapping incarnation already emitted. That value is read back as `prev` on
// the next boot, and it is exactly the term that matters after a backward clock
// step — the one case persistence exists for. The epoch then produced can sit
// BELOW the peer's latched floor, where admitAuthed refuses it: the same
// false-peer-death the fail-open was supposed to avoid, moved one restart later
// and made durable rather than transient. Corrupting the state whose only job is
// surviving a clock step is not a safe way to fail.
//
// What declining costs is bounded and transient by comparison: the wall-clock
// epoch is already published and already on the wire (see
// Manager.heartbeatBootEpoch), so only backward-clock-step protection is lost,
// and only until the next resolve succeeds.
//
// The old justification — "a node that cannot lock must not be a node that
// cannot heartbeat" — was a SENDER-liveness argument applied to a call site that
// is not on the heartbeat path at all. This runs on refineBootEpoch's worker,
// off both the send loop and the receive loop, so declining it cannot stop this
// node emitting anything. It also matches its siblings: MkdirAllDurable failure
// already declines and WriteFileDurable failure already declines, so lock
// failure was the only branch of three that proceeded.
func withEpochFileLock(path string, fn func()) {
	// #16050: 0600 (not 0644) and asserted on use — a readable lock file lets
	// any local user flock it on an O_RDONLY fd and block epoch persists.
	// The parent (/var/lib/xpf) mode is owned by the durable-state creators
	// (MkdirAllDurable in refineBootEpoch); only the lock file is tightened
	// here, before the flock, and a chmod failure declines like an open
	// failure rather than proceeding on a world-flockable lock.
	f, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		slog.Warn("cluster: HA epoch state lock unavailable; SKIPPING the persist "+
			"(the wall-clock epoch is already in use; only backward-clock-step "+
			"protection is lost)", "path", path, "err", err)
		return
	}
	if err := f.Chmod(0o600); err != nil {
		slog.Warn("cluster: HA epoch state lock tighten to 0600 failed; SKIPPING the persist "+
			"(the wall-clock epoch is already in use; only backward-clock-step "+
			"protection is lost)", "path", path, "err", err)
		return
	}
	defer f.Close()
	if err := acquireEpochFileLock(int(f.Fd()), path); err != nil {
		slog.Warn("cluster: HA epoch state lock failed; SKIPPING the persist "+
			"(the wall-clock epoch is already in use; only backward-clock-step "+
			"protection is lost)", "path", path, "err", err)
		return
	}
	defer func() { _ = unix.Flock(int(f.Fd()), unix.LOCK_UN) }()
	fn()
}

// bootEpochLockAcquireBudget bounds how long withEpochFileLock waits for a lock
// another PROCESS holds before declining the persist.
//
// It exists because a returned Manager.Stop does NOT imply this lock is free —
// see the invariant at joinBootEpochRefine — and restart is the documented
// recovery path for this subsystem, so the incoming process is exactly the
// party positioned to meet the outgoing one's lock. Sized to cover an ordinary
// durable write plus fsync on a healthy store while staying far below anything
// an operator would experience as a hang.
const bootEpochLockAcquireBudget = 3 * time.Second

// bootEpochLockRetryInterval is the poll gap inside that budget. flock(2) has no
// timed variant, so a bounded wait is a non-blocking attempt in a loop.
const bootEpochLockRetryInterval = 25 * time.Millisecond

// acquireEpochFileLock takes the epoch flock with a BOUNDED wait.
//
// WHY NOT A BLOCKING LOCK_EX, which is what this used to do. The lock is
// cross-process, and the process most likely to be holding it is an outgoing
// xpfd whose Manager.Stop has already returned: Stop joins the refinement
// worker with a bounded budget and, on timeout, warns and returns while the
// worker is still inside its callback holding LOCK_EX. A blocking acquisition
// here parks the INCOMING process's refinement worker for as long as that
// outgoing worker takes — which, if it is wedged on a dead disk, is the
// unbounded wait this entire file exists to avoid.
//
// WHY DECLINING IS THE RIGHT FAILURE. Its two siblings already decline:
// MkdirAllDurable failure declines and WriteFileDurable failure declines. What
// declining costs is bounded and transient — the wall-clock epoch is already
// published and already on the wire, so only backward-clock-step protection is
// lost, and only until the next resolve succeeds. What blocking costs is a
// refinement worker parked forever behind another process's wedged fsync.
//
// The bound is not a guess about the other process's health. It is a statement
// that this node's epoch refinement is not worth waiting on another node's
// store for, which is the same trade every other branch in this file makes.
func acquireEpochFileLock(fd int, path string) error {
	deadline := time.Now().Add(bootEpochLockAcquireBudget)
	var lastErr error
	for attempt := 0; ; attempt++ {
		lastErr = epochFlock(fd, unix.LOCK_EX|unix.LOCK_NB)
		if lastErr == nil {
			if attempt > 0 {
				slog.Info("cluster: HA epoch state lock acquired after contention "+
					"(another process — most likely an outgoing xpfd whose refinement "+
					"worker outlived its Stop — held it)",
					"path", path, "attempts", attempt+1)
			}
			return nil
		}
		// EWOULDBLOCK is CONTENTION, not failure: someone else holds it and may
		// release it. Every other errno is a real failure and is returned
		// immediately rather than retried until the budget expires — retrying
		// ENOLCK for three seconds would turn a fast, correct decline into a
		// slow one.
		if lastErr != unix.EWOULDBLOCK {
			return lastErr
		}
		if !time.Now().Before(deadline) {
			slog.Warn("cluster: HA epoch state lock still held by another process after "+
				"the acquire budget; DECLINING the persist rather than parking this "+
				"node's refinement worker behind it (a returned Manager.Stop does not "+
				"imply the previous holder released it — see joinBootEpochRefine)",
				"path", path, "waited", bootEpochLockAcquireBudget)
			return lastErr
		}
		time.Sleep(bootEpochLockRetryInterval)
	}
}
