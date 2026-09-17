package cluster

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"

	"github.com/psaab/xpf/pkg/fsatomic"
)

// --- #6169 across-reboot heartbeat anti-replay (boot epoch) ----------------
//
// #5477/#6167 gave the receiver a bounded set (heartbeatReplaySessions = 64) of
// per-session high-water counters. That raises an on-link replay attacker's
// cost but is NOT an absolute bar: ring eviction is FIFO and is triggered by
// ANY never-seen session INCLUDING a replayed one, so an attacker holding
// heartbeatReplaySessions+1 captured authenticated sessions can churn the ring
// by replay alone and sustain forged peer liveness indefinitely (measured: 64
// recordings -> 0/640 replays admitted; 65 -> 650/650 admitted).
//
// The fix needs an order the receiver can compare across peer incarnations.
// Session ids are random and unordered, so the frame must carry one: a
// per-daemon-incarnation BOOT EPOCH that increases across daemon restarts and
// reboots. The receiver keeps the highest epoch it has ever accepted and rejects
// anything below it in O(1) state, BEFORE the session ring is touched, so a
// frame the floor rejects never churns the ring (the bypass that closed the
// earlier attempt in #6370).
//
// IT IS NOT A TOTAL ORDER, AND THE FLOOR IS NOT "RETIRED INCARNATIONS CAN NEVER
// REPLAY". An earlier revision of this comment said both. Two things break it,
// and they are separate:
//
//   - The SEED "INCREASES", it does not "STRICTLY INCREASE ACROSS RESTARTS". It
//     is max(persisted+1, wall clock), and the persisted term is BOUNDED: a
//     value more than bootEpochMaxSkew ahead of `now` is not chained from (see
//     refineBootEpoch). A backward clock step larger than that bound regresses
//     this node's epoch even with the file perfectly intact. Since #6711 the
//     file is PRESERVED rather than overwritten when the persisted value could
//     be an intact predecessor (bootEpochPreserveMaxSkew), so the regression
//     lasts only until the clock is corrected instead of outliving every
//     restart. README residuals 3 and 5.
//   - The floor is a HIGH-WATER MARK, not a statement about which incarnation is
//     live. Once a sender has regressed, the highest epoch on the wire is a
//     RETIRED incarnation's, so an archived frame from it is admitted — it
//     raises the floor, refreshes liveness and applies its stale election state
//     — and the genuine current incarnation is refused. That is not a failure in
//     the safe direction; both halves go the wrong way at once. Measured in
//     TestArchivedEpochPoisonsAFreshFloor_6711, which also shows one re-injection
//     per receiver restart sustaining it.
//
// What the floor DOES buy is that an attacker cannot keep a retired incarnation
// admitted indefinitely: sustained ring churn needs heartbeatReplaySessions+1
// sessions the floor ADMITS, and the floor admits at most
// heartbeatEpochSessionsPerEpoch of them per epoch VALUE. Measured on 65
// captured epoch-bearing incarnations: 325/325 admitted on the ascending pass,
// then 0/1625 across five further rounds.
//
// THE PER-VALUE BOUND IS THE LOAD-BEARING HALF, AND IT TOOK A SECOND MECHANISM.
// The natural argument is "one incarnation emits exactly one session
// (Manager.heartbeatNonce, #6169 Stage 0), so distinct sessions are distinct
// incarnations, so they carry distinct epochs and all but the newest sit below
// the floor". The first two steps hold; the third does not. One session per
// process does NOT imply one epoch per process, and the comparison against the
// floor alone let equality through to the ring — so 65 captured incarnations
// SHARING one valid epoch churned it exactly as epochless frames do (measured
// 1625/1625 before heartbeatAuthState.highEpochSessions existed).
//
// Equal epochs are reachable rather than contrived, and the reachable path runs
// straight through THIS FILE: refineBootEpoch chains to prev+1, which is a pure
// function of the persisted value, so whenever the persist half cannot advance
// the file — an ordinary unwritable /var — every successive incarnation
// republishes the identical epoch on a healthy, advancing clock. (bootEpochSeed
// also returns the literal 1 for every incarnation of a node whose clock reads
// at or before the Unix epoch, which is the degenerate case.) The floor
// therefore admits a BOUNDED SET of sessions at one value and refuses the rest;
// see highEpochSessions for why the bound is neither one nor unbounded, what it
// still costs, and the sender-side alternative that was declined.
//
// The bound is then over DISTINCT EPOCH VALUES rather than over incarnations,
// and it is finite for the same reason either way: the floor is monotone, so an
// attacker walks up their captures once and every value is spent behind them.
//
// TWO PROPERTIES MAKE THAT ACTUALLY CLOSE THE ATTACK, and both are easy to get
// wrong:
//
//  1. A frame that carries NO epoch must not be a free bypass. The attacker's
//     captures are, by construction, mostly from BEFORE the upgrade — i.e.
//     epochless. If the receiver accepts epochless frames forever, the attacker
//     replays those and the floor is never consulted at all. Measured on the
//     first cut of this change: with the floor latched at a live peer's epoch,
//     975/975 epochless replays were still admitted. The fix is the DOWNGRADE
//     LATCH (see heartbeatAuthState.admitAuthed). It is process-scoped: a
//     durable floor was built, priced against rollback/crash/lock costs, and
//     removed — see the epochSeen field comment.
//
//  2. The sender must therefore ALWAYS advertise an epoch once it runs a build
//     that can. If a storage fault made a healthy node emit epochless frames, a
//     latched peer would refuse a LIVE node — a split-brain the latch itself
//     created. So persistence failures degrade MONOTONICITY (fall back to the
//     wall clock, which is still monotonic unless the clock steps backwards),
//     never EMISSION. The invariant that buys is crisp, and is exactly what the
//     latch leans on:
//
//     a keyed heartbeat carries no epoch  <=>  the peer runs a pre-#6169 build.
//
// The epoch rides INSIDE the signed span; see marshalHeartbeatAuthEpoch.

const (
	// bootEpochLabel domain-separates the boot-epoch section marker from every
	// other use of the control-link PSK. Versioned so a future section layout
	// change gets a distinct, non-colliding marker for free.
	bootEpochLabel = "xpf-ha-boot-epoch-v1"

	// heartbeatEpochMarkerSize is the length of the key-derived section marker.
	//
	// The marker is HMAC(PSK, bootEpochLabel)[:8], NOT a fixed ASCII magic. A
	// fixed magic would be matchable by ordinary body bytes: the section is
	// read at a SINGLE FIXED OFFSET back from the fixed-size auth trailer
	// (len-68, one index — there is no search loop and nothing unbounded), so
	// the bytes it lands on are the tail of the version section — a stable,
	// build-specific string. A colliding software-version string would collide
	// on EVERY frame of that build, deterministically, and because the receiver
	// LATCHES the high-water epoch, a bogus body-derived epoch would sit far
	// above a genuine wall-clock-seeded one and lock the peer out. A key-derived
	// marker removes that class entirely: it is a PRF value an attacker cannot
	// compute without the PSK, and an archived legacy body collides only at
	// ~2^-64 per frame. epochUsableAsFloor is the belt-and-braces second line.
	heartbeatEpochMarkerSize = 8

	// heartbeatEpochFieldSize is the little-endian uint64 epoch itself.
	heartbeatEpochFieldSize = 8

	// heartbeatEpochSectionSize is the whole optional section: marker + epoch.
	heartbeatEpochSectionSize = heartbeatEpochMarkerSize + heartbeatEpochFieldSize

	// epochPlausibleMax is 2200-01-01T00:00:00Z in nanoseconds — see
	// epochUsableAsFloor. A literal because time.Date is not a constant
	// expression; a test pins it against time.Date so it cannot drift.
	epochPlausibleMax uint64 = 7258118400_000000000

	// bootEpochMaxSkew is how far AHEAD of the receiver's own wall clock a peer
	// epoch may be and still be ordered against the floor. A peer epoch beyond
	// it is a broken clock or corrupt state, never a real incarnation.
	//
	// THE SLACK IS ITSELF THE WORST-CASE LOCKOUT, which is why it is an hour
	// and not a year. A bad epoch INSIDE the bound is latched, and a repaired
	// peer returning to real time then sits below the floor. A year of slack
	// bought nothing over an hour (it only has to exceed real inter-node clock
	// skew, which is milliseconds under NTP and minutes without it) and cost a
	// year-long lockout.
	//
	// THE LOCKOUT IS BOUNDED IN WALL-CLOCK TIME, NOT SELF-HEALING FOR THE
	// RUNNING SENDER (#6669 r18, Codex finding 6). An earlier revision of this
	// comment called it "a self-limiting window instead of one that needs
	// intervention", and README.md said the peer's seed "climbs past it
	// unattended". BOTH WERE FALSE, and falsely reassuring: the rejected
	// sender resolved its epoch ONCE, at boot, and caches it for the life of
	// the process (bootEpochOnce). Waiting does not change the value it emits,
	// so a peer latched out at T+30m stays out however long anyone waits — an
	// operator watching a wedged peer for a recovery that cannot arrive.
	//
	// What the hour actually bounds is how far a NEW incarnation has to climb:
	// the next sender restart on that peer seeds from a wall clock that has
	// moved on, and the receiver admits it on the raise path. So the recovery
	// is A SENDER RESTART (or a receiver restart, which clears the in-memory
	// floor outright) — never the passage of time alone.
	// Pinned by TestRunningSenderDoesNotRecoverByWaiting_6669.
	bootEpochMaxSkew uint64 = 60 * 60 * 1_000_000_000

	// bootEpochPreserveMaxSkew is how far ahead of our own clock a persisted
	// epoch may be and still be treated as POSSIBLY an intact predecessor
	// rather than garbage (#6711). Inside this band refineBootEpoch declines to
	// chain from it — unchanged — but also declines to OVERWRITE it, so a
	// backward clock step cannot destroy the value that keeps this node
	// acceptable to its peer.
	//
	// It is deliberately much larger than bootEpochMaxSkew and much smaller
	// than the absolute plausibility band. bootEpochMaxSkew (one hour) answers
	// "how far ahead may a value be and still be CHAINED FROM", which has to
	// stay tight because chaining is what strands a node above its peer's
	// range. This one answers a different question — "could a real backward
	// clock step explain this value" — and the events that produce one are a VM
	// restored from an old snapshot, a timezone or DST error, a manual `date`,
	// or an NTP correction after a long unsynchronised run. Thirty days covers
	// those with room to spare while remaining ~2000x short of the year-2200
	// absolute bound, so a genuinely corrupt far-future value is still healed
	// rather than preserved forever.
	bootEpochPreserveMaxSkew uint64 = 30 * 24 * 60 * 60 * 1_000_000_000

	// epochClockSaneFloor is 2020-01-01T00:00:00Z in nanoseconds: the point
	// below which the LOCAL clock is obviously unset rather than merely wrong.
	//
	// The forward bound is only applied when our own clock is above this. An
	// appliance whose RTC is dead boots at (or near) the Unix epoch and syncs
	// NTP some seconds later; during that window a healthy peer's epoch is
	// ~56 years "ahead" of us, and a naive forward bound would make us refuse
	// our peer at exactly the moment cold-boot split-brain is most likely (the
	// same hazard heartbeatStartupGrace exists for). Falling back to the
	// absolute bound alone there is permissive, never locking.
	epochClockSaneFloor uint64 = 1577836800_000000000
)

// bootEpochPath is where this node's own boot epoch is persisted. /var/lib/xpf
// is the persistent runtime-state root xpf already uses for durable identity
// counters (SNMPv3 engineBoots, the config DB). Overridden in tests.
//
// There is deliberately NO peer-side floor file; see the DURABILITY note on
// heartbeatAuthState.epochSeen for why the receiver latch is process-scoped.
var bootEpochPath = "/var/lib/xpf/ha-boot-epoch"

// bootEpochStopJoinBudget is how long Manager.Stop waits for an in-flight
// refine worker before giving up on it.
//
// Two seconds is chosen against the shutdown path, not against the store: the
// worker's only blocking calls are a flock and an fsync, which cost
// microseconds on a healthy store and are unbounded on a wedged one, so the
// budget never bites in the case it is not needed and bounds the case it is.
// Stop runs immediately after VRRP priority-0 and before the session-sync stop
// (its own 5s), inside the unit's TimeoutStopSec=20.
const bootEpochStopJoinBudget = 2 * time.Second

// bootEpochPersistRetryInterval is how often the #6724 trigger re-attempts a
// persist that a previous refine pass could not complete.
//
// 30s is chosen against what the retry is racing, not against the fault: a peer
// that latched a raise this node emitted but could not persist refuses a
// concurrent incarnation until the value reaches the file. The pre-#6724 bound
// on that was "until the next heartbeat (re)start", which is event-driven and
// unbounded — a daemon can run for days without one. Anything in the tens of
// seconds converts an unbounded wait into a bounded one; shorter buys nothing,
// because the faults that make a persist fail (a full or read-only filesystem,
// a wedged store) do not clear in milliseconds, and each attempt takes the
// epoch file lock.
//
// A var, not a const, for the same reason bootEpochPath and epochFlock are:
// the WIRING test drives a real heartbeatSender loop, and at the production
// interval the retry cadence is 150 ticks — thirty seconds of wall clock the
// test would have to spend to observe one retry. Never reassigned in
// production.
var bootEpochPersistRetryInterval = 30 * time.Second

// epochFlock is the lock withEpochFileLock takes. A var for the same reason
// epochNowNanos is one: the SECOND of its two failure branches is otherwise
// unreachable from a test. Failing the open is easy (point the lock path
// through a regular file), but flock(2) on a successfully opened regular file
// does not fail on Linux, so a mutation that runs the critical section unlocked
// on the flock error alone stayed green — the guard was scoped to one of the two
// paths it claims. Production never replaces it.
var epochFlock = unix.Flock

// epochNowNanos is the wall clock every CLOCK-DEPENDENT epoch check samples:
// refineBootEpoch validating persisted state at load, and admitAuthed
// applying the forward bound on the raise path. A var so a test can PIN an
// instant — epochWithinForwardBound is relative to this sample and abstains
// entirely below epochClockSaneFloor, so its boundaries only exist for one
// specific `now` and cannot be hit reliably with the real clock.
//
// The ACCEPT-PATH sample was added late, and its absence had a cost worth
// recording: with the real clock, `now` is always well above
// epochClockSaneFloor, so the forward bound always engages and absorbs every
// fixture the absolute band (epochUsableAsFloor) also catches. That made the
// absolute band deletable with the suite green — ordered belts, the outer one
// swallowing the inner one's whole tested range — even though the band is the
// only filter that survives an uncredible clock. See
// TestUncredibleClockLeavesOnlyTheAbsoluteBand_6669.
//
// Production never replaces it.
var epochNowNanos = func() int64 { return time.Now().UnixNano() }

// epochRefineBeforeRelease is a test seam on the refine worker's exit path, for
// the same reason epochFlock is one: the branch behind it is otherwise
// unreachable from a test.
//
// It runs in releaseBootEpochRefine between the pending check and the CAS that
// releases the in-flight bit. That window is the ONLY one in which a requester
// both loses the claim (so it queues rather than spawning) and publishes its
// request too late for the check that just ran — i.e. the window the release
// CAS has to detect. It is nanoseconds wide in production, so hammering does
// not reach it; without the seam the release can be reduced to a plain store
// with the suite green.
//
// No-op by default and never set outside tests.
var epochRefineBeforeRelease = func() {}

// epochRefineWorkerBeforeExit is a test seam in the ONE window that makes the
// handle retire a CompareAndSwap rather than a Store: after
// releaseBootEpochRefine has dropped the in-flight bit, and before this worker's
// deferred clear runs. The slot is free in there, so a successor can claim it
// and publish its own handle — and a retire written as Store(nil) would erase
// that live successor, after which Stop observes nil and joins nothing.
//
// The window is a few instructions wide and closes on its own, so no amount of
// hammering lands a successor inside it; the seam is what makes
// TestRetiringWorkerDoesNotEraseASuccessor_6669 deterministic. Production cost
// is one call to an empty func on a path that runs once per worker.
var epochRefineWorkerBeforeExit = func() {}

// epochRefineAfterLostClaim is the OTHER side of that same window, and it is a
// seam for the same reason: the interleaving cannot be scheduled from a test
// without one.
//
// It runs in claimBootEpochRefine after the caller has observed a worker in
// flight and before it publishes its request against that observation. Holding
// a requester here while the worker runs all the way out lands the request
// exactly where a torn (two-atomic) pair would strand it, which is what
// TestLateRefineRequestCannotBeStranded_6669 drives.
//
// No-op by default and never set outside tests.
var epochRefineAfterLostClaim = func() {}

// epochUsableAsFloor bounds what the receiver is willing to LATCH as its
// high-water epoch.
//
// The floor is a ONE-WAY DOOR: once raised it rejects everything below it, so a
// bogus far-future value locks the peer out permanently. The epoch is
// nanoseconds-since-the-Unix-epoch by construction (bootEpochSeed), so anything
// at or past the year 2200 is not a timestamp any healthy sender produces:
//
//	now (2026)          ~1.79e18 ns   ->  0.25x the bound
//	year 2200 (bound)    7.26e18 ns
//	MaxUint64            1.84e19 ns   ->  2.5x the bound  (== year 2554)
//
// MaxUint64 is ~528 years out, so it is unreachable by ordinary operation — but
// it IS reachable through a corrupted or hand-edited persist file, which is the
// only path that ever puts an arbitrary uint64 in this field. refineBootEpoch
// refuses to chain from such a value, and this is the receiver-side backstop for
// a peer running a build that does not.
//
// The bound is deliberately ONE-SIDED. A LOW epoch is permissive, not locking —
// it sits below any real floor and is simply rejected, or becomes a low floor
// that admits everything. Bounding below would reject an appliance whose RTC
// died, turning a cosmetic fault into a refused peer. And the bound is absolute
// rather than relative to the receiver's own clock, so a receiver whose own
// clock is wrong does not start refusing a healthy peer.
//
// A frame whose epoch fails this test is REJECTED, and because the rejection
// returns before the arming site it does NOT arm the downgrade latch either.
// Admitting it and merely declining to latch would recreate the epochless
// bypass in miniature — a frame the floor cannot order is governed by the
// bounded ring alone. Leaving the latch unarmed is the deliberate half: a peer
// that only ever emitted out-of-range epochs has proved nothing this receiver
// can act on, and refusing to latch on it is what keeps the refusal from
// becoming a one-way door once that peer comes back into range.
func epochUsableAsFloor(epoch uint64) bool {
	return epoch > 0 && epoch < epochPlausibleMax
}

// epochOrderable reports whether a peer epoch may be compared against, and
// latched as, the anti-replay floor. nowNanos is the receiver's own wall clock.
//
// It is epochUsableAsFloor plus a FORWARD bound. The absolute bound alone
// catches garbage, but leaves a single-fault path open: a peer whose clock (or
// persisted state) runs far ahead — yet still lands before year 2200 — would
// latch a floor its own corrected incarnations can never climb back above, and
// nothing would ever accept that peer again. Bounding how far ahead of US an
// epoch may be stops the LATCH, which is the unrecoverable half, so a peer that
// is corrected (or whose state is repaired) is accepted again the moment it
// comes back into range.
//
// THE RECEIVER DOES NOT CALL THIS; it applies the two halves separately, and
// the split is the point. admitAuthed runs epochUsableAsFloor on EVERY
// frame (clock-independent, so a 0 or beyond-year-2200 value is refused
// outright) but epochWithinForwardBound only on the RAISE path, epoch >
// highEpoch. So a frame at epoch == highEpoch that is beyond the forward bound
// is ADMITTED, not rejected — deliberately, because re-testing an
// already-accepted epoch after a backward clock step is what declared a healthy
// peer dead and went dual-master. See epochWithinForwardBound. (Equality has a
// separate gate of its own — it is admitted only from a session within the
// per-value bound, see heartbeatAuthState.highEpochSessions — but that gate is
// clock-INDEPENDENT, so it does not reintroduce the wall-clock sensitivity this
// split exists to keep off the accept path.)
//
// The combined predicate is for callers validating a value they are about to
// TRUST as a starting point rather than merely order against a floor — today
// that is refineBootEpoch chaining from persisted state. There, both halves
// apply: an unorderable value is ignored, never chained from.
func epochOrderable(epoch uint64, nowNanos int64) bool {
	return epochUsableAsFloor(epoch) && epochWithinForwardBound(epoch, nowNanos)
}

// epochWithinForwardBound is the CLOCK-DEPENDENT half of epochOrderable, split
// out because it must gate only the one operation that is irreversible.
//
// Raising the floor is a one-way door, so a far-future value must not be
// latched. But re-testing an epoch that has ALREADY been accepted is a
// different thing entirely, and doing it was a defect: a backward wall-clock
// step beyond bootEpochMaxSkew made every subsequent frame from the
// already-latched incarnation fail this bound and be rejected BEFORE the
// monotonic lastSeen update, so a healthy peer was declared dead in ~500ms and
// the cluster went dual-master. That is wall-clock sensitivity on the accept
// path, which is exactly what #1792's CLOCK_MONOTONIC lastSeen exists to keep
// out. admitAuthed therefore applies this ONLY when epoch > highEpoch.
//
// It is skipped entirely when our own clock is not credible
// (epochClockSaneFloor): an appliance with a dead RTC boots near the Unix epoch
// and syncs NTP seconds later, and during that window a healthy peer's epoch is
// ~56 years "ahead", so applying the bound would refuse the peer at exactly the
// moment cold-boot split-brain is most likely.
//
// THAT SKIP IS THE EXACT PRECONDITION ON SELF-HEALING, and it is a real
// residual rather than an oversight. refineBootEpoch validates persisted state
// with this predicate, so a persisted epoch that is wrong-but-below-year-2200
// is only rejected — and the file only healed — when the LOCAL clock is
// credible at the moment refinement loads it. On an appliance whose RTC is dead
// and whose xpfd starts before NTP, the FIRST pass of every boot is made against
// an uncredible clock and chains from the bad value; a correctly clocked peer
// then refuses this node's epoch on its raise path, which is asymmetric
// visibility, not mutual isolation.
//
// Refinement is RE-RUN at each later heartbeat start (Manager.refreshBootEpoch),
// so once NTP has corrected the clock the NEXT StartHeartbeat — a VRF rebind,
// an HA comms restart — does RE-VALIDATE the file. It does NOT heal it, and an
// earlier revision of this comment said it did. Re-validation and healing are
// different things and only the first is new here:
//
// refineBootEpoch ends by persisting published.Load(), and published is monotone
// non-decreasing — the sole store is gated on next > epoch. This residual's
// premise is that the FIRST pass already chained from the corrupt value, so
// published is by then bad+1. Every later pass therefore writes bad+1 back, or
// returns without writing (prev == lastWrote, a read error, a MkdirAll failure).
// No path can LOWER the file, and lowering is exactly what healing would mean
// here — contrast heartbeat_epoch.go's first-pass DECLINE ("ignoring it heals
// the file"), which heals precisely because published is still the sane
// wall-clock seed at that point.
//
// What actually clears it is a daemon restart with a credible clock. On the box
// this residual describes — a dead RTC, xpfd starting before time sync — that
// does not happen either: the first pass of EVERY boot chains again and the
// value ratchets +1 per boot. Re-running refinement bounds a different failure
// (an incarnation stranded BELOW its peer's floor climbs back, rather than being
// pinned by sync.Once for the life of the process); it does not bound this one.
//
// It cannot be closed COMPLETELY here, and the qualifier matters — an earlier
// revision of this comment said "cannot be closed" flat, which is too strong.
//
// What is genuinely impossible is a DISCRIMINATOR. Under a dead RTC a
// legitimate previous epoch and a corrupt future one are indistinguishable:
// both sit implausibly far "ahead" of a 1970 clock — a legitimate present-day
// value by ~56 years, the year-2191 fixture the tests use by ~222 — and nothing
// on this node separates them, because the forward bound that WOULD
// discriminate is precisely what is skipped below epochClockSaneFloor. What is
// missing is a trustworthy REFERENCE, not a magnitude gap. Healing after the
// fact would mean LOWERING a published epoch mid-incarnation, the one direction
// the whole design refuses.
//
// What IS available is a partial NARROWING, and it was considered and declined
// rather than missed: epochPlausibleMax is an arbitrary horizon, so lowering it
// (say to 2100) would reject the year-2191 fixture while still carrying every
// present-day value across an uncredible clock. It does not create a
// discriminator — any corrupt value below the new horizon still passes — it
// only moves the boundary, so the residual survives in the same shape with a
// smaller window.
//
// It is declined because the horizon is not free space; it is a hard cliff on
// the whole mechanism, in BOTH time and clock-fault magnitude:
//
//   - epochUsableAsFloor is applied to every frame, and a value at or past the
//     horizon is REJECTED, not merely unlatched. So a node whose clock reads
//     past the horizon is refused outright by its peer — a healthy peer
//     declared dead, which is the dual-master failure the equal-epoch
//     relaxation above exists to avoid. Lowering the horizon makes a FORWARD
//     clock fault (a wrong RTC, a bogus NTP source) that much easier to land
//     there.
//   - The trade is therefore: narrow a fault whose worst outcome is ASYMMETRIC
//     VISIBILITY (this node's epoch is refused on the peer's raise path; the
//     peer is still seen here) by widening one whose outcome is MUTUAL
//     REFUSAL. That is the wrong direction, and it is the same asymmetry the
//     absolute bound is deliberately one-sided for.
//
// So the absolute year-2200 band stays, applied unconditionally, as the only
// filter that survives an uncredible clock. The residual is stated in
// pkg/cluster/README.md under "Honest residuals"; the operational close is a
// working RTC or ordering xpfd after time synchronization.
func epochWithinForwardBound(epoch uint64, nowNanos int64) bool {
	if nowNanos > 0 && uint64(nowNanos) >= epochClockSaneFloor {
		if epoch > uint64(nowNanos)+bootEpochMaxSkew {
			return false
		}
	}
	return true
}

// heartbeatEpochMarker derives this cluster's boot-epoch section marker from
// the control-link PSK. Both nodes hold the same PSK (#6624 makes it mandatory
// for a chassis cluster), so both derive the same marker.
func heartbeatEpochMarker(authKey []byte) []byte {
	mac := hmac.New(sha256.New, authKey)
	mac.Write([]byte(bootEpochLabel))
	return mac.Sum(nil)[:heartbeatEpochMarkerSize]
}

// heartbeatFrameEpoch reads the boot epoch out of a heartbeat frame.
//
// CALLER CONTRACT: only call this on a frame whose auth trailer has ALREADY
// been located and whose HMAC has ALREADY verified. Only a verified frame
// authorises treating len-heartbeatAuthTrailerSize as the end of the signed
// body; the keyless / unverified path must never consult the marker, or an
// attacker could steer the epoch by appending bytes.
//
// Returns present=false for a frame from a peer running a pre-#6169 build.
func heartbeatFrameEpoch(data, authKey []byte) (epoch uint64, present bool) {
	if len(authKey) == 0 || len(data) < heartbeatAuthTrailerSize {
		return 0, false
	}
	bodyEnd := len(data) - heartbeatAuthTrailerSize
	// Never index into (or before) the fixed header: a canonical zero-RG body is
	// 13 bytes, so a short legacy frame must read as "no epoch" rather than
	// slicing out of range.
	if bodyEnd < heartbeatHeaderSize+heartbeatEpochSectionSize {
		return 0, false
	}
	markerAt := bodyEnd - heartbeatEpochSectionSize
	if !hmac.Equal(data[markerAt:markerAt+heartbeatEpochMarkerSize], heartbeatEpochMarker(authKey)) {
		return 0, false
	}
	return binary.LittleEndian.Uint64(data[markerAt+heartbeatEpochMarkerSize : bodyEnd]), true
}

// initHeartbeatEpochState starts this node's boot-epoch resolution, and is
// called from StartHeartbeat. It MUST NOT BLOCK.
//
// It used to wait up to two seconds for the persisted value, back when
// the epoch was only published after that read completed. Once emission moved
// ahead of all I/O (Manager.heartbeatBootEpoch) the wait stopped buying
// anything — and it was actively harmful: StartHeartbeat calls StopHeartbeat
// first, so the wait stalled a node with its heartbeat already STOPPED, and the
// channel it waited on is closed by the refine worker, which under a wedged
// store never returns. Measured on the wedged store: 2.005s / 2.012s / 2.011s,
// three of three paying the full bound, against a dead-peer threshold of 500ms
// at the code default and 1s at the shipped 200ms interval. That is the same
// false-peer-death this change exists to remove, relocated from "emits
// epoch-less frames" to "emits no frames at all" — which a peer cannot tell
// apart. Every routine VRF rebind and HA comms restart would have paid it.
//
// So there is no wait: kick the resolve and return. The wall-clock epoch is
// already published by the time this returns, and the persisted refinement
// lands whenever storage allows.
func (m *Manager) initHeartbeatEpochState() {
	if m == nil {
		return
	}
	// The epoch is only meaningful when frames are signed — the section marker
	// is key-derived, so an unkeyed cluster cannot carry one, and an unkeyed
	// node must not touch /var/lib/xpf for a mechanism it cannot use. A cluster
	// keyed LATER still resolves off the send path.
	if len(m.controlLinkAuthKey()) == 0 {
		return
	}
	// A SECOND and later heartbeat start RE-RUNS the refinement rather than
	// returning the value resolved at boot. Refinement is not a one-shot fact
	// about this incarnation: the file is shared state, and another incarnation
	// (or this node's own earlier one, under the withEpochFileLock ordering
	// hazard) can raise it above what we published, which parks us below the
	// peer's floor. sync.Once made that permanent for the life of the process;
	// re-running it here makes it recoverable at the next heartbeat (re)start —
	// StartHeartbeat, a DHCP-triggered VRF rebind, or the HA comms restart.
	// StartHeartbeat holds hbStartMu, so these two branches never interleave.
	if m.bootEpoch.Load() != 0 {
		m.refreshBootEpoch()
		return
	}
	m.heartbeatBootEpoch()
}

// bootEpochSeed is the wall-clock value an incarnation advertises before any
// I/O. Factored out so tests drive the SAME seed production uses rather than
// restating it — a restated seed is free to drift from the shipped one.
//
// 0 is the reserved "no epoch" sentinel, so it is never returned; that is only
// reachable with a clock at the Unix epoch.
func bootEpochSeed() uint64 {
	now := time.Now().UnixNano()
	if now > 0 {
		return uint64(now)
	}
	return 1
}

// heartbeatBootEpoch returns this daemon incarnation's boot epoch. It NEVER
// returns 0 for a node that has called it, and it NEVER performs I/O.
//
// This ordering is the whole answer to "a storage fault must not take a healthy
// node off the air". The epoch a peer needs is just a value that increases
// across this node's incarnations, and the wall clock supplies that WHILE IT
// ADVANCES MONOTONICALLY — which is the only case persistence is not needed for,
// and is why persistence is the refinement rather than the source. So the
// wall-clock value is published SYNCHRONOUSLY, with no file access, and every
// frame carries it from the very first send.
//
// Persistence is a REFINEMENT, not a prerequisite. Its only job is to survive a
// backward clock step, so it runs on a worker: read the previous value and, if
// it would be higher than what we published, raise. Raising mid-incarnation is
// safe — the receiver's floor simply moves up, and our own earlier frames
// become unreplayable, which is the direction we want.
//
// Consequently a hung disk, a blocking flock, or a wedged fsync cannot stop
// this node emitting a valid epoch, and cannot make a latched peer see it as
// epoch-less (and therefore dead).
//
// THE REMAINING REGRESSION IS NOT A DOUBLE FAULT, and an earlier revision of
// this comment said it was ("storage that never completes AND a clock that
// stepped backwards"). Storage failure is one way in; a SINGLE backward clock
// step larger than bootEpochMaxSkew is another, with the file perfectly intact
// and every write succeeding, because refineBootEpoch declines to chain from a
// persisted value that far ahead of `now`. A sender restart does not recover
// while the wrong clock still reads below the peer's floor. That is #6711;
// README residual 3.
//
// The #6711 fix narrows it to exactly that window. Refinement no longer
// OVERWRITES a persisted value that could be an intact predecessor
// (bootEpochPreserveMaxSkew), so correcting the clock and restarting chains from
// it and clears the floor at once. Before the fix the value that recovery needed
// had already been destroyed, and the node stayed refused until wall time
// climbed back past the old floor on its own.
func (m *Manager) heartbeatBootEpoch() uint64 {
	if m == nil {
		return 0
	}
	m.bootEpochOnce.Do(func() {
		// Publish immediately, before any I/O can be attempted.
		m.bootEpoch.Store(bootEpochSeed())

		// bootEpochReady is closed when the FIRST refine attempt finishes.
		// Nothing in production waits on it — that wait was removed, see
		// initHeartbeatEpochState.
		//
		// IT IS NOT A JOIN, and an earlier revision of this comment offered it
		// to tests as one ("tests use it to join the worker"). The worker closes
		// it from INSIDE its loop and then calls releaseBootEpochRefine — which
		// reads a package-var test seam — and may run further coalesced passes
		// before it returns. A test that stops here returns with that worker
		// still live, and the next test's seam assignment races it: exactly the
		// data race the -race repro in awaitFirstRefine's comment reports. The
		// join is joinBootEpochRefine, or waitBootEpochIdle/awaitFirstRefine in
		// tests, which wait for the whole word AND the goroutine.
		m.startBootEpochRefine(m.bootEpochReady)
	})
	return m.bootEpoch.Load()
}

// LocalBootEpoch returns this daemon's immutable ordered process identity
// epoch without starting heartbeat persistence. The heartbeat startup path
// publishes bootEpoch before session-sync starts; a zero value means that
// path has not published an epoch yet, so the sender relies on its token.
func (m *Manager) LocalBootEpoch() uint64 {
	if m == nil {
		return 0
	}
	m.localIdentityEpochOnce.Do(func() {
		m.localIdentityEpoch.Store(m.bootEpoch.Load())
	})
	return m.localIdentityEpoch.Load()
}

// refreshBootEpoch re-runs the persistence refinement for an incarnation that
// has already published, and is what keeps a lost ordering race recoverable.
//
// The published epoch is resolved against a SHARED file, so it can be correct
// when it is resolved and stale afterwards: another incarnation that acquires
// withEpochFileLock later raises the file above us and parks us below the peer's
// floor (see withEpochFileLock's ordering note). Behind the boot-time sync.Once
// alone, that state lasted for the life of the process — the peer refused this
// node until a full daemon restart, even after the other incarnation exited.
//
// Re-running refinement lifts us back above the file. It is NOT a fix for the
// mis-ordering itself; it bounds how long one costs us. It raises only when the
// file has moved above us and is a no-op otherwise, so a routine restart on a
// healthy node neither ratchets the epoch nor rewrites anything meaningful.
//
// ABOVE THE FILE, WHICH IS NOT THE SAME AS ABOVE THE PEER'S FLOOR. If the epoch
// that raised that floor never landed in the file — the other incarnation
// published it and its write failed — no number of re-runs sees it, and this
// node stays refused for its whole process lifetime. See withEpochFileLock for
// that condition and the leapfrog one beside it.
func (m *Manager) refreshBootEpoch() {
	if m == nil || m.bootEpoch.Load() == 0 {
		// Nothing published yet: heartbeatBootEpoch owns the first resolve.
		return
	}
	m.startBootEpochRefine(nil)
}

// bootEpochRefineWorker is one refine worker's exit handle: done is closed by
// that worker as its very last act. It is reached through an atomic.Pointer
// rather than a mutex-guarded field because BOTH readers must make progress
// while bootEpochRefineMu is held — Manager.joinBootEpochRefine exists to be
// bounded, and the worker's own exit defer must never block — and that mutex is
// held across claimBootEpochRefine's epochRefineAfterLostClaim seam, where a
// requester can be parked indefinitely. Guarding it deadlocked the join, the
// worker and the requester against each other in three goroutines.
type bootEpochRefineWorker struct {
	done chan struct{}
}

// The two bits of Manager.bootEpochRefine. Only three states are reachable —
// 0, {refining}, {refining|pending} — because the pending bit is only ever set
// while the in-flight bit is held, and the release drops both together. A bare
// {pending} would be a request with no worker, which is the state this word
// exists to make unrepresentable.
const (
	bootEpochRefiningBit uint32 = 1 << 0
	bootEpochPendingBit  uint32 = 1 << 1
)

// claimBootEpochRefine takes the in-flight slot for the CALLER, or hands the
// request to the worker already holding it. It reports whether the caller now
// owns the slot and must spawn the worker. It never blocks.
//
// THE PAIR MOVES AS ONE WORD, and that is what closes a lost wakeup rather than
// saving a cache line. With the in-flight flag and the pending bit as separate
// atomics, this sequence stranded a request with nobody to serve it:
//
//	R: CAS(refining, false->true) FAILS   (worker still in flight)
//	W: clears pending; releases refining; re-claims pending -> nothing;
//	   returns.                              <-- no worker left
//	R: Store(pending, true)                  <-- nobody will serve it
//
// R's observation ("a worker is in flight") had gone stale by the time it acted
// on it, and a plain Store cannot notice. Here the observation and the action
// are ONE CompareAndSwap on the pair: if the worker released the slot in
// between, the CAS fails against the word the worker left, and the retry sees
// an idle slot and takes it — spawning the pass itself instead of queuing it
// onto a worker that has gone. Symmetrically, releaseBootEpochRefine's release
// only succeeds while the pending bit is still clear.
//
// The window it closes is a few instructions wide and was not reachable by
// hammering (3000 rounds x 4 concurrent refreshBootEpoch never landed in it),
// so it is driven deterministically through the epochRefineAfterLostClaim seam
// — see TestLateRefineRequestCannotBeStranded_6669. What it cost when it did
// land was not a diagnosable failure: nothing in production observes the
// stranded bit, so an operator would have seen only a node that stayed below
// its peer's floor until some later heartbeat start, which nothing bounds
// (#6724) and which may never come.
//
// COALESCING IS PRESERVED: pending is a BIT, not a queue, so any number of
// requests arriving during one pass collapse into a single follow-up, and a
// caller that must not block still cannot build a backlog of fsync-ing workers.
func (m *Manager) claimBootEpochRefine() bool {
	for {
		st := m.bootEpochRefine.Load()
		if st&bootEpochRefiningBit == 0 {
			// Idle. Take the slot; preserve any pending bit so a follow-up
			// already owed is served rather than dropped.
			if m.bootEpochRefine.CompareAndSwap(st, st|bootEpochRefiningBit) {
				return true
			}
			continue
		}
		epochRefineAfterLostClaim()
		if st&bootEpochPendingBit != 0 {
			// A follow-up is already owed. Coalesce onto it.
			return false
		}
		if m.bootEpochRefine.CompareAndSwap(st, st|bootEpochPendingBit) {
			return false
		}
		// The word moved under us — the worker either took a pass or released
		// the slot. Re-read and decide again against what it actually left.
	}
}

// releaseBootEpochRefine ends one pass. It reports whether another pass is
// owed; when it returns false the in-flight slot has been released and the
// worker must return without doing any further REFINEMENT or touching the
// epoch state — m.bootEpoch, m.bootEpochWrote and the state file are all off
// limits from here, because a successor may already own the slot.
//
// "WITHOUT TOUCHING MANAGER STATE AGAIN" is what this said, and the round-14
// exit handle made it false: the worker's outermost defer still runs
// m.bootEpochWorker.CompareAndSwap(worker, nil) after this returns. That is
// deliberate and is not a refinement — it is the worker publishing its own
// death, and the CAS is what keeps an outgoing worker from clearing a
// SUCCESSOR's handle in exactly the window this function opens by dropping the
// in-flight bit before the goroutine has returned. See startBootEpochRefine.
//
// s.mu is not involved: the whole protocol is the one word. The release CAS
// carries the pending bit's value at the instant of release, so a request that
// lands between the check and the CAS fails the CAS rather than being lost —
// the mirror of claimBootEpochRefine's retry.
func (m *Manager) releaseBootEpochRefine() bool {
	for {
		st := m.bootEpochRefine.Load()
		if st&bootEpochPendingBit != 0 {
			// Serve it here, with the in-flight bit still held, so no second
			// worker spawns.
			if m.bootEpochRefine.CompareAndSwap(st, st&^bootEpochPendingBit) {
				return true
			}
			continue
		}
		epochRefineBeforeRelease()
		if m.bootEpochRefine.CompareAndSwap(st, st&^bootEpochRefiningBit) {
			return false
		}
		// A request arrived in that window. It is still in the word; loop and
		// pick it up.
	}
}

// joinBootEpochRefine waits for an in-flight refine worker to exit, up to
// budget. It reports whether the worker was joined.
//
// THE INVARIANT, STATED SO IT CANNOT DRIFT (#6826). A join that returns FALSE
// means the worker is STILL RUNNING, and that worker may be inside
// withEpochFileLock holding a CROSS-PROCESS flock: the lock is taken before the
// callback and released by a defer after it, and nothing cancels the callback.
// So:
//
//	a returned Manager.Stop does NOT imply the epoch flock is released.
//
// It is stated rather than fixed because the alternatives are worse. Releasing
// the lock on the timeout path would mean interrupting a durable write and an
// fsync at an arbitrary point, which is how a torn epoch file gets written.
// Making the budget cover the worst-case callback is not possible — the
// worst case is a wedged fsync, and bounding that is what this whole file
// exists to avoid.
//
// What closes the hole is the OTHER side: acquireEpochFileLock waits a bounded
// time for a contended lock and then declines the persist, so an incoming
// process meeting an outgoing one's still-held lock degrades to "no
// backward-clock-step protection this pass" instead of parking behind it.
// TestStopReturnsWhileEpochFlockIsStillHeld6826 pins this direction, and
// TestIncomingProcessDeclinesRatherThanBlocking6826 pins the other.
//
// THE BOUND IS THE POINT. The worker's blocking calls are a flock and an fsync,
// and this whole file exists because those can wedge indefinitely without that
// being allowed to stall the HA path (see heartbeatBootEpoch, and the 2s wait
// initHeartbeatEpochState had to lose). An unbounded join in Manager.Stop would
// reintroduce exactly that: a shutdown parked behind a dead disk, on the path
// that has just sent VRRP priority-0 and still has to stop session sync. So the
// wait is bounded and the timeout is reported rather than hidden.
//
// IT SPAWNS NOTHING, and that is what keeps a BOUNDED WAIT from becoming an
// UNBOUNDED LEAK. The obvious shape is a helper goroutine —
// `go func() { wg.Wait(); close(done) }()` — selected against a timer, and the
// timeout then returns only the CALLER: nothing cancels a WaitGroup.Wait, so
// the helper stays parked for as long as the worker does, which over a wedged
// store is forever.
//
// IN PRODUCTION THAT IS EXACTLY ONE GOROUTINE, and an earlier revision of this
// comment overstated it as "this is not called once". The call topology is
// once-per-process and each link was checked: cluster.NewManager runs at one
// site (pkg/daemon/daemon_run_bringup.go) and the manager is never rebuilt live
// — a day-2 node-id/cluster-id or topology change is REFUSED at commit and
// requires a process restart (pkg/daemon/cluster_topology_preflight.go) — while
// the only production Stop is in runShutdownSequence
// (pkg/daemon/daemon_run_shutdown.go), reached from two mutually exclusive
// returns in a Run that itself runs once (cmd/xpfd/main.go). So the leak was
// one parked goroutine in a process that is already exiting, which is not on
// its own worth a design change.
//
// WHAT MADE IT WORTH FIXING is that the shape is repeated where the joins ARE
// repeated — waitBootEpochIdle and keyedEpochManager join on every epoch test,
// and N timed-out joins left N permanent goroutines (measured: 8 calls, 8
// parked waiters) — and that the replacement is strictly SMALLER than what it
// replaced: a WaitGroup plus a goroutine per call become one pointer the worker
// publishes. A join is then a select on a channel somebody else closes, and a
// timeout costs nothing at all.
//
// IT ALSO TAKES NO LOCK, and that is not a micro-optimisation — reading the
// handle under bootEpochRefineMu DEADLOCKED this function outright. That mutex
// is held across claimBootEpochRefine, which contains the
// epochRefineAfterLostClaim seam, so a requester parked at that seam holds it
// for an unbounded time. A join is exactly the operation that must make
// progress anyway (its whole purpose is to be bounded), and so is the worker's
// own exit. Both therefore go through an atomic.Pointer:
// startBootEpochRefine still PUBLISHES under bootEpochRefineMu, which is what
// keeps Stop's refuse-then-join ordering airtight, but nothing has to take the
// lock to observe or clear it.
//
// "THE WORKER", singular, is exact rather than approximate: bootEpochRefiningBit
// admits one at a time, so the current worker IS every worker. The one seam is
// that a worker releases that bit slightly before its exit channel closes, so a
// successor can be spawned and publish its own handle while the outgoing one is
// still returning — a join taken in that window follows the outgoing worker.
// Neither caller can reach it: Stop sets bootEpochStopped first, and
// waitBootEpochIdle waits for the whole word to reach 0 (no worker in flight and
// none owed) before it joins.
//
// WHAT THE TIMEOUT LEAVES BEHIND is one worker goroutine, parked in the flock or
// the fsync this bound exists for. It CAN still hold a lock a caller waits on,
// and an earlier revision of this comment said it could not: withEpochFileLock
// holds the state file's advisory lock across the whole read-modify-write
// callback, so another INCARNATION's refine blocks behind it until this one
// unwedges. Nothing in THIS process waits on it — the refine slot is the only
// in-process serialization and it is a CAS word, not a lock — which is
// presumably what the claim meant, but the flock is a real cross-process one and
// the withEpochFileLock rationale is written around exactly that.
//
// THE TIMEOUT PATH MUST NOT RELEASE IT, and the exposure is smaller than "the
// next process blocks" suggests. Releasing is not merely awkward but WRONG: the
// descriptor is a local in withEpochFileLock, on the wedged worker's stack, and
// dropping the lock while that worker is still inside its read-modify-write
// would let another incarnation interleave with a write in progress — trading a
// delay for the torn update the lock exists to prevent. It does not need
// releasing, because an flock dies with the open file description: the kernel
// drops it when the process exits, SIGKILL included. Under the documented
// restart recovery (systemd Type=simple, TimeoutStopSec=20) the old unit is
// reaped — SIGTERM, then SIGKILL at 20 s — BEFORE the new one starts, so a
// restart never contends for this lock at all. What can contend is two
// CONCURRENTLY RUNNING incarnations, which is the overlap withEpochFileLock was
// written for (NOT an SO_REUSEPORT one — see that function's comment for the
// #8233 correction; the primary listener sets no socket options and the second
// bind does fail) (see
// TestConcurrentIncarnationsAreOrderedByLockAcquisition_6669), and there the
// blocked party is the other node's refine WORKER, whose failure this file
// already treats as survivable: it declines the persist and keeps the
// wall-clock epoch already on the wire. Beyond it the
// worker touches only m.bootEpoch and m.bootEpochWrote (both atomic) and the
// state file (written through fsatomic, so a concurrent reader sees the old or
// the new value and never a torn one). It cannot resurrect the heartbeat or
// re-enter election.
func (m *Manager) joinBootEpochRefine(budget time.Duration) bool {
	w := m.bootEpochWorker.Load()
	if w == nil {
		return true
	}
	timer := time.NewTimer(budget)
	defer timer.Stop()
	select {
	case <-w.done:
		return true
	case <-timer.C:
		return false
	}
}

// startBootEpochRefine runs one refinement on a worker. ready, when non-nil, is
// closed once that attempt finishes.
//
// ONE AT A TIME, BUT COALESCED. Overlapping refines would be safe on the file
// (withEpochFileLock serializes them) but they race on the persist watermark,
// whose whole job is to tell "the file holds what I wrote" from "the file moved
// under me". So exactly one worker runs — and a request that arrives while it
// is in flight sets the pending bit, which that worker serves as another pass
// before it exits.
//
// AN EARLIER REVISION DROPPED SUCH A REQUEST, and the drop silently discarded
// precisely the request that was needed. The in-flight worker's locked READ can
// already be complete, so an update landing behind it is invisible to that
// pass:
//
//   - B's worker finishes its read of file `b`, releases the lock, and is
//     descheduled before storing its watermark and clearing the in-flight bit;
//   - A locks next, persists `b+1` and emits it; the peer raises its floor and
//     refuses B at `b`;
//   - B's next StartHeartbeat loses the claim and returns WITHOUT queuing;
//   - B's old worker resumes, records the stale watermark `b`, and clears the
//     bit without re-reading.
//
// B is then below the peer's floor until some LATER heartbeat start, which
// nothing bounds (#6724) and which may never come. Coalescing turns "the
// request is lost" into "the request costs one extra pass", and the claim/
// release pair on ONE word (claimBootEpochRefine) is what makes that hold for
// EVERY request rather than for every request but one.
func (m *Manager) startBootEpochRefine(ready chan struct{}) {
	// Claim the slot and publish the worker's exit handle under one lock. A
	// concurrent Manager.Stop therefore either sees that handle and joins it,
	// or refuses the spawn outright — it can never miss a worker that starts
	// behind its own check. The lock is never held across I/O (the claim is a
	// CAS loop), so this still cannot block a heartbeat start.
	m.bootEpochRefineMu.Lock()
	claimed := false
	if !m.bootEpochStopped {
		claimed = m.claimBootEpochRefine()
	}
	var worker *bootEpochRefineWorker
	if claimed {
		worker = &bootEpochRefineWorker{done: make(chan struct{})}
		// Published under the lock so Stop cannot set bootEpochStopped between
		// the claim and the publish and then join a worker it never saw.
		m.bootEpochWorker.Store(worker)
	}
	m.bootEpochRefineMu.Unlock()

	if !claimed {
		// Either the request was handed to a worker already running, or the
		// manager is stopped and no refinement will run at all. Signal anyway:
		// a caller joining `ready` must never block because someone else got
		// there first. Only heartbeatBootEpoch passes a non-nil channel and
		// only from inside bootEpochOnce, so this cannot double-close.
		if ready != nil {
			close(ready)
		}
		return
	}
	// Read bootEpochPath on THIS goroutine: it is a package var tests
	// override, and a worker reading it later would race the next test.
	path := bootEpochPath
	go func() {
		// Registered FIRST so it runs LAST: a joiner selecting on this channel
		// must not be released while any other deferred action is still to run.
		//
		// The handle is cleared with a CAS and NOT under bootEpochRefineMu: that
		// mutex is held across the epochRefineAfterLostClaim seam by a requester
		// that may be parked there indefinitely, and this exit path must not be
		// able to wait on anything. The CAS also has the right semantics on its
		// own — the in-flight bit is dropped inside releaseBootEpochRefine,
		// before this defer runs, so a successor may already have published its
		// own handle, and it must not be cleared by this one.
		// THESE TWO STATEMENTS ARE ORDERED, AND THE ORDER IS LOAD-BEARING. The
		// CAS runs FIRST so that "done is closed" implies "the handle is already
		// retired": every observer released by done therefore sees a retired
		// handle, which is what lets waitBootEpochIdle's caller assert
		// bootEpochWorker is nil straight after it returns (see the retirement
		// assertion in TestThirdRequestCoalescesOntoTheLateReclaim_6669).
		//
		// Swapping them does not fail any test, because the window it opens is
		// a couple of instructions and an observer has to land inside it.
		// Closing it mechanically would need a seam BETWEEN these two lines,
		// which is production surface bought for a hazard that this comment and
		// the one at the assertion already address. So it is bound by comment on
		// both ends rather than by a test, deliberately, and that is the reason
		// not to reorder them.
		//
		// RE-MEASURED at 50698ade7 (#6669 r18): `go test -count=1 -v
		// ./pkg/cluster/` with the two statements swapped reports 584 top-level
		// PASS / 732 including subtests, 0 failures. An earlier revision of this
		// comment recorded "219 passes, 0 failures"; that number was taken when
		// the package was a third of its current size, so it had stopped
		// describing any run a reader could reproduce while still reading as a
		// live measurement. A COUNT in a comment goes stale as the guarded
		// surface grows — the reproducible part is the command and the SHA, so
		// re-measure rather than trusting the digits.
		defer func() {
			m.bootEpochWorker.CompareAndSwap(worker, nil)
			close(worker.done)
		}()
		// `ready` keeps its documented meaning — closed when the FIRST attempt
		// finishes — rather than being deferred to the end of a coalesced run.
		// The deferred close covers the paths that leave the loop early.
		signalled := false
		defer func() {
			if ready != nil && !signalled {
				close(ready)
			}
		}()
		for {
			gotWrote, owed := refineBootEpochReporting(path, &m.bootEpoch, m.bootEpochWrote.Load())
			m.bootEpochWrote.Store(gotWrote)
			// #6724: record the retry trigger AFTER the watermark, so an
			// observer that sees the flag also sees the watermark the pass
			// produced.
			m.bootEpochPersistOwed.Store(owed)
			if ready != nil && !signalled {
				signalled = true
				close(ready)
			}
			if !m.releaseBootEpochRefine() {
				epochRefineWorkerBeforeExit()
				return
			}
		}
	}()
}

// bootEpochPersistRetryTicks is how many heartbeat sender ticks pass between
// two #6724 persist retries, derived from the send interval so the RATE is
// what is configured, not the tick count.
//
// A TICK COUNT, not a deadline. Every clock this package could compare against
// is the wall clock, and a backward step in it is the exact fault the boot
// epoch exists to survive — a deadline would suspend retries for the duration
// of the very step that makes them matter. Ticks are monotonic by
// construction. The counter lives on the sender, so it resets on a heartbeat
// restart, which is harmless: a restart already runs a full refine.
func bootEpochPersistRetryTicks(interval time.Duration) int {
	if interval <= 0 {
		return 1
	}
	if n := int(bootEpochPersistRetryInterval / interval); n > 1 {
		return n
	}
	return 1
}

// retryOwedBootEpochPersist re-runs refinement when, and ONLY when, a previous
// pass left a persist owed (#6724).
//
// THE GATE IS THE WHOLE DESIGN, and an unconditional periodic refine — the
// obvious simpler thing — is worse rather than merely more expensive. While two
// incarnations overlap, each refine pass raises above the other and rewrites
// the file, so they leapfrog; running that on a timer would make the leapfrog
// CONTINUOUS, and each node would be refused by the peer for part of every
// period instead of one node being refused until its next heartbeat restart.
// Alternating refusal is worse for HA than a stable one: it is what makes a
// peer fail over repeatedly. Gating on an owed persist makes this a no-op in
// exactly that case — two healthy incarnations both persist successfully, so
// neither ever owes anything — while still closing the case the trigger exists
// for, where a pass could not write at all.
//
// It cannot fix the mis-ordering itself. Separating "a concurrent newer
// incarnation wrote it" from "a predecessor wrote it after a backward clock
// step" needs a writer identity or a lifetime-held liveness lock, which is
// larger than the epoch — see withEpochFileLock and #7501.
func (m *Manager) retryOwedBootEpochPersist() {
	if !m.bootEpochPersistOwed.Load() {
		return
	}
	// refreshBootEpoch coalesces onto a running worker and never blocks, so
	// this cannot stall the send loop it is called from.
	m.refreshBootEpoch()
}

// refineBootEpoch is the off-path half of heartbeatBootEpoch: consult the
// persisted previous epoch, raise the published value if a backward clock step
// means the wall clock alone would not have exceeded it, and record the result.
//
// Every failure here is survivable and is logged rather than propagated: the
// wall-clock epoch published synchronously is already valid and already on the
// wire.
//
// IT IS RE-RUNNABLE, and lastWrote is what makes re-running idempotent.
// Refinement raises when the persisted value is at or above what we published —
// that is how a backward clock step is carried across a restart — but after a
// successful persist the file holds OUR OWN value, so a second pass would meet
// that same condition and ratchet the epoch by one every time it ran.
// lastWrote is the epoch this incarnation last persisted (0 for a first pass),
// and a file still holding exactly that is left alone. The returned value is the
// new watermark.
//
// A failure path returns lastWrote unchanged, since a pass that did not write
// did not move the file either — WITH ONE EXCEPTION, and getting it wrong
// ratcheted the file on every pass. fsatomic.WriteFileDurable reports a
// post-rename directory-fsync failure as a typed *PostRenameSyncError, and at
// that point the new content is already VISIBLE (#5185); only its durability is
// unknown. That pass DID move the file, so it returns the value it wrote.
// refineBootEpoch is the value-only form, kept because it is what the epoch
// tests drive. Production uses refineBootEpochReporting, which additionally
// reports whether a persist is still OWED — see that function.
func refineBootEpoch(path string, published *atomic.Uint64, lastWrote uint64) (wrote uint64) {
	wrote, _ = refineBootEpochReporting(path, published, lastWrote)
	return wrote
}

// refineBootEpochReporting is refineBootEpoch plus the #6724 retry signal.
//
// persistOwed is true when this pass ended with the published epoch NOT known
// to be on disk because something FAILED or was SKIPPED — the directory create,
// the lock, the read, or the write. It is deliberately false for every pass
// that DECLINED to write on purpose (the #6711 preserve branch, the heal
// branch, and the `prev == lastWrote` no-op), because those are decisions, not
// faults, and retrying them forever would be a busy loop over a file this node
// has already decided not to touch.
//
// WHY THE SIGNAL CANNOT BE DERIVED FROM published != wrote AT THE CALL SITE,
// which is the obvious cheaper thing: the #6711 preserve branch also ends with
// published (this incarnation's wall-clock seed) != wrote (0, nothing written),
// and it ends that way FOREVER by design. A caller comparing those two would
// retry a preserved file on every period for the life of the process, which is
// exactly the state #7499 created on purpose. Only this function knows which
// branch it took.
func refineBootEpochReporting(path string, published *atomic.Uint64, lastWrote uint64) (wrote uint64, persistOwed bool) {
	wrote = lastWrote
	if err := fsatomic.MkdirAllDurable(filepath.Dir(path), 0o755); err != nil {
		slog.Warn("cluster: HA boot-epoch state dir create failed; this incarnation's epoch is NOT durable "+
			"(a backward clock step across the next restart could regress it)", "path", path, "err", err)
		return wrote, true
	}
	// `ran` distinguishes "the lock could not be taken, so the critical section
	// never executed" from "it ran and decided not to write" (#6724).
	// withEpochFileLock reports nothing itself, and giving it a return value
	// would churn every one of its callers for a fact the caller can observe
	// here for free.
	// #7501: this process's identity, resolved ONCE outside the lock. Reading
	// /proc inside the critical section would put an unbounded read in a place
	// the fail-closed rule is trying to keep short, and the answer cannot change
	// during a pass.
	self := currentEpochOwnerCached()
	ran := false
	withEpochFileLock(path, func() {
		ran = true
		var prev uint64
		if data, err := os.ReadFile(path); err == nil {
			// ONE clock sample, taken AFTER the read RETURNS and shared by the
			// load check and the candidate check below.
			//
			// Two properties, and they pull in opposite directions if you only
			// think about one of them:
			//
			//   - ONE sample, not two. Two samples could straddle the forward
			//     bound and validate `prev` against a different instant than the
			//     value actually derived from it.
			//   - AFTER the read, not before. The clock-credibility gate
			//     (epochClockSaneFloor) is what decides whether the forward
			//     bound applies at all, so the sample must describe the clock as
			//     it is when the value is JUDGED, not as it was when the read
			//     was issued. Sampling first reopened the exact hole this
			//     function exists to close on an appliance with a dead RTC:
			//     xpfd starts near 1970, the sample captures that uncredible
			//     instant, the read stalls (a cold or busy disk is the ordinary
			//     case here, not a contrived one), NTP corrects the clock to the
			//     present before the read returns, and a corrupt-but-below-2200
			//     value is then judged against the stale 1970 sample — so the
			//     forward bound is skipped and the bad successor is published by
			//     a node whose clock was, by the time it mattered, perfectly
			//     good. Sampling here shrinks that window to the microseconds
			//     between the read returning and the comparison, and there is no
			//     I/O left inside it.
			//
			// Only the read path needs a sample: the non-existent-file and
			// read-error paths never consult the clock.
			now := epochNowNanos()
			n, perr := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
			switch {
			case perr != nil:
				slog.Warn("cluster: HA boot-epoch state unreadable; keeping the wall-clock epoch", "path", path)
			// VALIDATE THE VALUE THIS NODE WOULD PUBLISH, not merely the one on
			// disk. The chained epoch is prev+1, so testing prev alone left a
			// one-value escape at each bound: a persisted epochPlausibleMax-1
			// passes the load check and then publishes exactly
			// epochPlausibleMax, which every receiver refuses because
			// epochUsableAsFloor is a strict `<`; a persisted value exactly at
			// now+bootEpochMaxSkew likewise publishes one nanosecond past the
			// bound. Not overflow — ordering. n+1 cannot overflow here: the
			// first disjunct short-circuits unless n < epochPlausibleMax.
			// #6711: SEPARATE "this value is garbage" from "this value could be
			// an intact predecessor that OUR clock has stepped back behind".
			// Both fail epochOrderable, and the old code treated them
			// identically — declining to chain AND then durably overwriting the
			// file with this incarnation's lower wall-clock seed. That
			// overwrite is what turns a single backward clock step into a
			// lockout that SURVIVES RESTARTS: the good predecessor is gone, so
			// every later boot re-publishes from the same bad clock instead of
			// chaining back above the peer's floor. #6711 reproduced exactly
			// that, with the file perfectly intact.
			//
			// Preserving costs nothing when the value really was written by a
			// clock running ahead: this node still declines to chain and still
			// publishes the same wall-clock seed, bit-identically to before.
			// The ONLY thing that changes is that the file is left alone, so a
			// later boot with a corrected clock can chain from it again.
			//
			// The band has to be bounded, and epochUsableAsFloor is far too wide
			// for it — that predicate admits anything before year 2200, so it
			// would preserve a year-2191 value no clock ever produced.
			// bootEpochPreserveMaxSkew is the "could a real backward step
			// explain this" window instead: a VM restored from an old snapshot,
			// a timezone or DST error, a manual `date`, an NTP correction. A
			// value beyond it is garbage and still gets healed.
			//
			// This is the same reasoning the read-error branch below already
			// applies — "overwriting unknown state is not a safe way to fail".
			// This branch is unknown state too; it only looked decided because
			// the bytes parsed.
			case (!epochOrderable(n, now) || !epochOrderable(n+1, now)) &&
				epochUsableAsFloor(n) && epochUsableAsFloor(n+1) &&
				n <= uint64(now)+bootEpochPreserveMaxSkew:
				slog.Warn("cluster: HA boot-epoch state is ahead of this node's clock by more than "+
					"the chaining bound; keeping the wall-clock epoch and PRESERVING the persisted "+
					"value — it may be an intact predecessor this node's clock has stepped back "+
					"behind, and overwriting it would make the lockout survive restarts (#6711)",
					"path", path, "value", n, "now", now)
				return
			case !epochOrderable(n, now) || !epochOrderable(n+1, now):
				// Corrupt, hand-edited, or written while this node's clock ran
				// ahead. Chaining from it would push this node toward MaxUint64,
				// where the NEXT boot regresses, and would strand it above the
				// range its peer accepts. Ignoring it heals the file.
				//
				// NOT ONLY those, though — and the residual is #6711. An INTACT
				// value written by a correctly-clocked earlier incarnation lands
				// here too if THIS incarnation's clock has stepped back by more
				// than bootEpochMaxSkew while still sitting above
				// epochClockSaneFloor. The peer latched the earlier value, so
				// declining to chain leaves this node below its floor. Both
				// branches are lockouts; this one is RECOVERABLE and chaining is
				// not, which is why it is still the right way round. Recoverable
				// is narrower than "ends at the next restart", which an earlier
				// revision of this comment claimed: restarting THIS node
				// re-publishes from the same bad clock (the file now holds the
				// lower value), so it stays below the floor FOR AS LONG AS THE
				// PUBLISHED READING REMAINS BELOW IT. That is the operative
				// condition, not "while the clock is wrong" — a clock that stays
				// two hours slow still reads past the floor two real hours later,
				// and a restart then publishes a value STRICTLY ABOVE it, which
				// the peer admits on the raise path and which rebinds the floor
				// to this incarnation. THE RAISE PATH IS THE ONE TO RELY ON, and
				// not because equality is shut: a frame landing exactly ON the
				// floor is admitted while a slot is free
				// (heartbeatEpochSessionsPerEpoch, per value, no refill), so that
				// door is real but finite. The raise is the wider one — a
				// nanosecond of wall clock past the floor, rather than hitting
				// one exact value — and it cannot be exhausted. Measured in
				// TestPoisonedFloorStillRecoversByRaise_6669.
				//
				// What recovers it sooner still is fixing the clock, or a
				// receiver restart paired with a PSK rotation — see the
				// "Recovery is narrower" paragraph in README.md. Chaining, by
				// contrast, ends at no restart at all: it strands this node
				// permanently above the range its peer will ever accept.
				// Carrying an intact predecessor across a larger backward step
				// needs a change to persistence semantics, so it is tracked
				// there rather than papered over here.
				slog.Warn("cluster: HA boot-epoch state cannot be chained from (it, or the epoch derived "+
					"from it, is out of range); ignoring it and keeping the wall-clock epoch",
					"path", path, "value", n)
			default:
				prev = n
			}
		} else if !os.IsNotExist(err) {
			// ABORT rather than fall through to the write. Falling through left
			// prev=0 and then durably replaced a possibly-HIGHER persisted value
			// with this incarnation's (possibly lower) wall-clock seed — the
			// exact durable regression withEpochFileLock's own rationale says
			// must never happen, and the one that makes a peer which latched the
			// higher value refuse this node indefinitely. The sibling branches
			// already decided this: MkdirAllDurable failure returns, and lock
			// failure skips. A transient read error is unknown state, and
			// overwriting unknown state is not a safe way to fail.
			slog.Warn("cluster: HA boot-epoch state read error; keeping the wall-clock epoch "+
				"and NOT overwriting the persisted value", "path", path, "err", err)
			// #6724: unknown state, not a decision — worth re-reading later.
			persistOwed = true
			return
		}

		epoch := published.Load()
		if prev == lastWrote && prev != 0 {
			// The file still holds exactly what THIS incarnation last persisted,
			// so there is nothing to chain from and nothing to write. Without
			// this, every re-run would meet the raise condition below (prev >=
			// epoch, because prev IS epoch) and ratchet the epoch by one.
			return
		}
		if next := prev + 1; next > epoch {
			// Either the clock stepped backwards — the wall-clock seed did not
			// clear the previous incarnation — or another incarnation raised the
			// file above us while we were running (withEpochFileLock's ordering
			// note).
			//
			// #7501: those two are not the same, and raising is only right for
			// the first. If the value belongs to a LIVE sibling incarnation,
			// raising above it makes THIS process — which may be the one about
			// to exit — the peer's floor, and the survivor is refused for the
			// life of its process. Decline instead: the sibling's value is
			// already higher, already on the wire, and already what the peer
			// will latch, so leaving it alone is both correct and a no-op.
			//
			// Fails to RAISE on every uncertainty (no sidecar, unparseable
			// sidecar, unreadable /proc, a different boot), because that is the
			// pre-#7501 behaviour and the guard may only ever subtract an
			// action. Failing the other way would let one stale sidecar pin
			// this node below its peer's floor durably, which is a worse
			// version of the lockout this closes.
			if owner, ok := readEpochOwner(path); ok && !sameEpochOwner(owner, self) && epochOwnerAlive(owner) {
				slog.Warn("cluster: HA boot-epoch state was written by a LIVE sibling "+
					"incarnation; NOT raising above it (raising would make this process "+
					"the peer's floor and get the survivor refused — #7501)",
					"path", path, "persisted", prev, "published", epoch,
					"owner_pid", owner.pid)
				// Not a fault: a decision, so no persist is owed. The sibling's
				// value stands and this incarnation keeps its own lower epoch,
				// which the peer accepts because the sibling's is the floor.
				return
			}
			epoch = next
			published.Store(epoch)
		}
		// #7501: record WHO is writing, so a later refiner can tell a live
		// sibling's value from a predecessor's. Best-effort and deliberately
		// BEFORE the epoch write: a sidecar naming us while the epoch write
		// then fails is harmless (a refiner finds our identity beside a value
		// we did not write, and the worst it does is decline to raise above a
		// value that is not ours — the safe direction), whereas an epoch
		// written with a STALE sidecar from a previous owner would attribute
		// our value to someone else, which is the unsafe direction.
		if self.ok {
			if err := writeEpochOwner(path, self.owner); err != nil {
				slog.Warn("cluster: HA boot-epoch owner sidecar write failed; a concurrent "+
					"incarnation cannot tell this value from a predecessor's (#7501). The "+
					"epoch itself is unaffected.", "path", path, "err", err)
			}
		}
		if err := fsatomic.WriteFileDurable(path, []byte(strconv.FormatUint(epoch, 10)+"\n"), 0o644); err != nil {
			// NOT EVERY WRITE ERROR MEANS THE FILE DID NOT MOVE. A
			// *PostRenameSyncError is a directory-fsync failure AFTER a
			// successful rename (#5185): the new content is already VISIBLE in
			// the namespace — a later pass, or a restart, reads it — and only
			// its durability across power loss is unknown. Treating that as
			// "nothing was written" left the watermark stale, so the next pass
			// read our OWN value, could not recognise it (prev != lastWrote),
			// chained from it, and rewrote epoch+1 — ratcheting the file by one
			// on EVERY pass for as long as the fsync kept failing. Record the
			// watermark from what the file now holds, and warn about the
			// durability rather than about a write that in fact landed.
			var postRename *fsatomic.PostRenameSyncError
			if errors.As(err, &postRename) {
				slog.Warn("cluster: HA boot-epoch state persisted but its durability is UNKNOWN "+
					"(the post-rename directory fsync failed; the value IS visible to the next read, "+
					"but a power loss could lose it)", "path", path, "epoch", epoch, "err", err)
				wrote = epoch
				return
			}
			slog.Warn("cluster: HA boot-epoch state persist failed; this incarnation's epoch is NOT durable "+
				"(a backward clock step across the next restart could regress it)", "path", path, "err", err)
			// #6724: the raise this pass published (if any) is on the wire but
			// not on disk. Until it lands, a peer that latched it can refuse a
			// concurrent incarnation that has no other way to learn of it.
			persistOwed = true
			return
		}
		wrote = epoch
	})
	if !ran {
		// The lock was unavailable, so the read-modify-write was skipped
		// entirely (withEpochFileLock fails CLOSED). Nothing was decided.
		persistOwed = true
	}
	return wrote, persistOwed
}
