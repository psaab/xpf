package cluster

// Unkeyed-authority grace (#16016, converged design v5).
//
// A cluster with no control-link PSK accepts unauthenticated heartbeat and
// session-sync authority (legacy dual-accept). That posture is needed only
// for first-keying: a not-yet-keyed secondary's only writer is config-sync
// over the pre-key connection. It is a provisioning-time event, not a
// steady-state need, so this file bounds it with a persisted 72-hour grace.
//
// Two clocks, by design:
//
//   - The persisted record exists only for restart recovery:
//     "v2 <earliestWallUnixNano> <highWaterWallUnixNano> <elapsedMonoNanos>".
//     Every touch ratchets highWater = max(highWater, wallNow) and elapsed to
//     the greatest wall-derived or in-process monotonic elapsed observation.
//     Boot remaining is min(grace-elapsed, earliest+grace-max(now, highWater)).
//     A rollback plus repeated restarts therefore cannot refund observed time.
//     A legacy v1 record lacks monotonic history and fails closed at boot.
//     A future-dated earliest is clamped down to now (shorten, never extend).
// Postures: file absent -> fresh stamp (day-0/reimage; wiping /var/lib/xpf
// is root-equivalent and indistinguishable from re-provisioning). File
// present but corrupt/unparseable -> expired-at-boot (presence is evidence
// of a prior in-grace node; corruption is not absence). Persist failure ->
// the in-process monotonic deadline still arms and expires; the failure is
// logged once and status names it. Nothing on the wire can create, move, or
// delete the anchor: post-grace config frames never reach SyncApply, and
// within-grace frames cannot touch this file. Only a local key commit
// deletes the record (UpdateConfig), which also arms the recovery hold; a
// later local key-clear re-stamps fresh, mirroring #15262 delete-on-clear.
//
// There is deliberately NO implicit re-anchoring: "loaded record expired ∧
// this process just booted" is true identically for a wrong-RTC fresh
// migration and a routine post-expiry restart, so any predicate that
// re-anchored one would re-open the vulnerability on every restart. The
// operator acts are local-only: key the cluster, or the audited
// `request chassis cluster failover force-primary ...` recovery path.

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/fsatomic"
)

// writeFrameLocked is the common post-install write choke point. Callers hold
// s.writeMu, preserving the existing per-stream serialization. encoded, when
// non-nil, is an already-framed wire message and avoids re-encoding/copying.
func (s *SessionSync) writeFrameLocked(conn net.Conn, msgType uint8, payload, encoded []byte) error {
	if s.unkeyedAuthorityExpired() {
		ac, authenticated := conn.(*authConn)
		if !authenticated || !ac.writeAuthed() {
			s.noteUnkeyedAuthorityRefusal(conn, "frame write")
			return errUnkeyedAuthorityGraceEnded
		}
	}
	if encoded != nil {
		return writeFull(conn, encoded)
	}
	return writeMsg(conn, msgType, payload)
}

// unkeyedAuthorityGrace is the window during which an unkeyed cluster keeps
// today's dual-accept posture. 72h is >= 2x any rolling upgrade and >= one
// maintenance window plus change-approval lead time; longer only extends
// exposure of the original vulnerability. A var so tests can shrink it.
var unkeyedAuthorityGrace = 72 * time.Hour

// unkeyedAuthorityGraceStatePath is where the persisted anchor lives.
// /var/lib/xpf is the persistent runtime-state root already used for the HA
// boot epoch and the fabric rollout-grace anchor.
var unkeyedAuthorityGraceStatePath = "/var/lib/xpf/unkeyed-authority-grace"

// unkeyedAuthorityNow is the wall clock the persisted record is stamped and
// compared with. A var so tests can pin an instant across a simulated
// restart (two Managers) without sleeping; production never replaces it.
var unkeyedAuthorityNow = func() time.Time { return time.Now() }

// unkeyedAuthorityMonoNow is the monotonic clock for the in-process
// deadline. A var so tests can advance the deadline deterministically.
var unkeyedAuthorityMonoNow = func() int64 { return MonotonicNanos() }
var unkeyedAuthorityPersist = persistUnkeyedAuthorityRecord

// SetUnkeyedAuthorityPersistForTesting injects an anchor write failure.
func SetUnkeyedAuthorityPersistForTesting(fn func(string, time.Time, time.Time, time.Duration) error) func() {
	original := unkeyedAuthorityPersist
	unkeyedAuthorityPersist = fn
	return func() { unkeyedAuthorityPersist = original }
}

const unkeyedAuthorityExpiredReason = "unkeyed authority grace expired (#16016); key the cluster"

// unkeyedGraceState is the Manager-side anchor state. The atomics are the
// hot-path posture words read by the frame gate, the write choke point, the
// connection seams and the election holds; the mutex-guarded fields are the
// bookkeeping behind them.
type unkeyedGraceState struct {
	// expired is the SessionSync-visible posture word: true once this
	// process has observed the grace expired (monotonic deadline passed,
	// or a corrupt/expired record loaded at boot).
	expired atomic.Bool
	// peerKeyClearPending denies unauthenticated authority during a peer
	// key-clear transition. Keyed transitions set it before publishing
	// keyConfigured=false; a missing/expired anchor sets it before persistence.
	peerKeyClearPending atomic.Bool
	// armedGen mirrors Manager.peerProofGen at the anchor-delete
	// (expired->keyed) transition; the recovery hold clears only when the
	// generation advances past it.
	armedGen atomic.Uint64
	// recoveryHold is true between the anchor-delete transition and the
	// first fresh authenticated heartbeat proof.
	recoveryHold  atomic.Bool
	keyConfigured atomic.Bool

	mu                          sync.Mutex
	anchorMono                  int64         // process-local monotonic accounting origin
	deadlineMono                atomic.Int64  // monotonic deadline; 0 = unarmed
	elapsedBase                 time.Duration // persisted elapsed floor at process start
	elapsedFloor                time.Duration // greatest elapsed observation, persisted
	earliestWall                time.Time     // persisted earliest wall stamp
	highWaterWall               time.Time     // persisted high-water wall stamp
	corrupt                     bool          // record present but unparseable at load
	loaded                      bool          // the persisted record has been read this process
	notPersisted                bool          // a persist failed; status suffix names it
	postRenameDurabilityUnknown bool          // replacement is visible but parent-dir durability was not confirmed
	persistFailureLogged        bool          // suppress repeated errors in one failure episode
	lastLogRung                 int           // highest notice rung already logged (0..4)
	lastPostExpiryLogMono       int64
}

// loadUnkeyedAuthorityRecord reads the persisted record. present=false means
// the file is absent (fresh stamp). corrupt=true means present but
// unparseable/legacy (expired-at-boot). A future-dated earliest is clamped
// down to now, and the clamped value is what later touches persist.
func loadUnkeyedAuthorityRecord(path string, now time.Time) (earliest, highWater time.Time, elapsed time.Duration, present, corrupt, clamped bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return time.Time{}, time.Time{}, 0, false, false, false
		}
		// An unreadable-but-present file is not absence.
		return time.Time{}, time.Time{}, 0, true, true, false
	}
	fields := strings.Fields(strings.TrimSpace(string(data)))
	if len(fields) != 4 || fields[0] != "v2" {
		// v1 has no persisted monotonic history. Granting any wall-derived
		// remainder could refund elapsed time hidden by a rollback/restart.
		return time.Time{}, time.Time{}, 0, true, true, false
	}
	e, err1 := strconv.ParseInt(fields[1], 10, 64)
	h, err2 := strconv.ParseInt(fields[2], 10, 64)
	n, err3 := strconv.ParseInt(fields[3], 10, 64)
	if err1 != nil || err2 != nil || err3 != nil || e <= 0 || h < e || n < 0 {
		return time.Time{}, time.Time{}, 0, true, true, false
	}
	earliest = time.Unix(0, e).UTC()
	highWater = time.Unix(0, h).UTC()
	elapsed = time.Duration(n)
	if earliest.After(now) {
		earliest = now // clamp down: shorten, never extend
		clamped = true
	}
	if highWater.Before(earliest) {
		highWater = earliest
	}
	return earliest, highWater, elapsed, true, false, clamped
}

// persistUnkeyedAuthorityRecord durably writes the record. Best-effort: the
// caller records/report failures but never fails config apply or boot.
func persistUnkeyedAuthorityRecord(path string, earliest, highWater time.Time, elapsed time.Duration) error {
	if earliest.IsZero() {
		return errors.New("empty unkeyed-authority grace anchor")
	}
	if highWater.Before(earliest) {
		highWater = earliest
	}
	if elapsed < 0 {
		return errors.New("negative unkeyed-authority elapsed floor")
	}
	if err := fsatomic.MkdirAllDurable(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	body := fmt.Sprintf("v2 %d %d %d\n", earliest.UnixNano(), highWater.UnixNano(), elapsed.Nanoseconds())
	if err := fsatomic.WriteFileDurable(path, []byte(body), 0o644); err != nil {
		return err
	}
	return nil
}

// persistUnkeyedAuthorityLocked is called with unkeyedGrace.mu held.
func (m *Manager) persistUnkeyedAuthorityLocked() {
	st := &m.unkeyedGrace
	err := unkeyedAuthorityPersist(unkeyedAuthorityGraceStatePath, st.earliestWall, st.highWaterWall, st.elapsedFloor)
	if err == nil {
		st.notPersisted = false
		st.postRenameDurabilityUnknown = false
		st.persistFailureLogged = false
		return
	}
	st.notPersisted = true
	var postRename *fsatomic.PostRenameSyncError
	st.postRenameDurabilityUnknown = errors.As(err, &postRename)
	if !st.persistFailureLogged {
		st.persistFailureLogged = true
		slog.Error("cluster: unkeyed-authority grace anchor persist failed; "+
			"the in-process deadline still expires but a restart may re-open grace (#16016)",
			"path", unkeyedAuthorityGraceStatePath, "err", err)
	}
}

// deleteUnkeyedAuthorityRecord removes the persisted anchor. Called when the
// accepted-key set becomes non-empty (local key commit). Best-effort like
// the persist: removing a missing file is success.
func deleteUnkeyedAuthorityRecord(path string) {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		slog.Warn("cluster: unkeyed-authority grace anchor delete failed (#16016)",
			"path", path, "err", err)
	}
}

// clusterAuthorityTransportConfigured is shared by config updates and the
// pre-listener boot belt. Fabric-only deployments carry session/config
// authority too, even when they declare no redundancy groups.
func clusterAuthorityTransportConfigured(cfg *config.ClusterConfig) bool {
	return cfg != nil && (cfg.ControlInterface != "" || cfg.PeerAddress != "" ||
		cfg.FabricInterface != "" || cfg.FabricPeerAddress != "" ||
		cfg.Fabric1Interface != "" || cfg.Fabric1PeerAddress != "" ||
		len(cfg.RedundancyGroups) > 0)
}

// touchUnkeyedAuthorityLocked observes the unkeyed posture once. Caller
// holds m.mu (via UpdateConfig) or the construction path before publication.
// clusterEnabled gates stamping: a standalone node with no cluster config
// never arms a cluster-authority window.
func (m *Manager) touchUnkeyedAuthorityLocked(clusterEnabled bool) {
	if m == nil || !clusterEnabled {
		return
	}
	st := &m.unkeyedGrace
	now := unkeyedAuthorityNow().UTC()
	mono := unkeyedAuthorityMonoNow()
	loadedExpired := false
	stamped := false
	changed := false
	st.mu.Lock()
	if !st.loaded {
		st.loaded = true
		earliest, highWater, elapsed, present, corrupt, clamped := loadUnkeyedAuthorityRecord(
			unkeyedAuthorityGraceStatePath, now)
		switch {
		case corrupt:
			st.corrupt = true
			loadedExpired = true
			slog.Error("cluster: unkeyed-authority grace anchor is corrupt or legacy; "+
				"treating the grace as expired at boot (#16016); key the cluster to recover",
				"path", unkeyedAuthorityGraceStatePath)
		case present:
			st.earliestWall = earliest
			st.highWaterWall = highWater
			st.elapsedFloor = elapsed
			effectiveWall := now
			if highWater.After(effectiveWall) {
				effectiveWall = highWater
			}
			if wallElapsed := unkeyedElapsedFromWall(earliest, effectiveWall); wallElapsed > st.elapsedFloor {
				st.elapsedFloor = wallElapsed
				changed = true
			}
			st.elapsedBase = st.elapsedFloor
			remaining := unkeyedAuthorityGrace - st.elapsedFloor
			if wallRemaining := earliest.Add(unkeyedAuthorityGrace).Sub(effectiveWall); wallRemaining < remaining {
				remaining = wallRemaining
			}
			if remaining <= 0 {
				loadedExpired = true
			}
			changed = changed || clamped
		}
	}
	if st.corrupt {
		st.mu.Unlock()
		if loadedExpired {
			m.markUnkeyedAuthorityExpired(time.Time{})
		}
		return
	}
	if st.anchorMono == 0 {
		st.anchorMono = mono
		st.elapsedBase = st.elapsedFloor
		remaining := unkeyedAuthorityGrace - st.elapsedFloor
		if !st.earliestWall.IsZero() {
			effectiveWall := now
			if st.highWaterWall.After(effectiveWall) {
				effectiveWall = st.highWaterWall
			}
			if wallRemaining := st.earliestWall.Add(unkeyedAuthorityGrace).Sub(effectiveWall); wallRemaining < remaining {
				remaining = wallRemaining
			}
		}
		if remaining < 0 {
			remaining = 0
		}
		st.deadlineMono.Store(mono + remaining.Nanoseconds())
		if st.earliestWall.IsZero() {
			st.earliestWall = now
			st.highWaterWall = now
			st.elapsedBase = 0
			st.elapsedFloor = 0
			m.persistUnkeyedAuthorityLocked()
			stamped = true
		}
	}
	if !st.earliestWall.IsZero() {
		wallNow := unkeyedAuthorityNow().UTC()
		if wallNow.After(st.highWaterWall) {
			st.highWaterWall = wallNow
			changed = true
		}
		monotonicElapsed := st.elapsedBase + time.Duration(mono-st.anchorMono)
		wallElapsed := unkeyedElapsedFromWall(st.earliestWall, maxAuthorityWall(wallNow, st.highWaterWall))
		nextElapsed := st.elapsedFloor
		if monotonicElapsed > nextElapsed {
			nextElapsed = monotonicElapsed
		}
		if wallElapsed > nextElapsed {
			nextElapsed = wallElapsed
		}
		nextElapsed = capUnkeyedElapsed(nextElapsed)
		if nextElapsed > st.elapsedFloor {
			st.elapsedFloor = nextElapsed
			changed = true
		}
	}
	if deadline := st.deadlineMono.Load(); deadline != 0 && mono >= deadline {
		loadedExpired = true
	}
	var noticeRung int
	var noticeExpiry time.Time
	if changed {
		m.persistUnkeyedAuthorityLocked()
	}
	if !loadedExpired {
		noticeRung, noticeExpiry = m.logUnkeyedGraceLadderLocked()
	}
	expiry := time.Time{}
	if !st.earliestWall.IsZero() {
		expiry = st.earliestWall.Add(unkeyedAuthorityGrace)
	}
	st.mu.Unlock()
	if stamped {
		slog.Warn("cluster: unkeyed-authority grace stamped; unauthenticated control authority "+
			"remains accepted until the grace expires (#16016)", "expires", expiry.Format(time.RFC3339))
		m.notifyUnkeyedGraceAlarm("stamped", true, expiry)
	}
	if loadedExpired {
		m.markUnkeyedAuthorityExpired(expiry)
	} else if noticeRung != 0 && !stamped {
		m.notifyUnkeyedGraceAlarm(unkeyedGraceNoticeName(noticeRung), true, noticeExpiry)
	}
}

func maxAuthorityWall(a, b time.Time) time.Time {
	if b.After(a) {
		return b
	}
	return a
}

func capUnkeyedElapsed(elapsed time.Duration) time.Duration {
	if elapsed < 0 {
		return 0
	}
	if elapsed > unkeyedAuthorityGrace {
		return unkeyedAuthorityGrace
	}
	return elapsed
}

func unkeyedElapsedFromWall(earliest, effectiveWall time.Time) time.Duration {
	if earliest.IsZero() || !effectiveWall.After(earliest) {
		return 0
	}
	return capUnkeyedElapsed(effectiveWall.Sub(earliest))
}

// logUnkeyedGraceLadderLocked emits the once-per-rung notice ladder using the
// monotonic deadline, so a wall-clock step cannot move an in-process notice.
// Caller holds st.mu.
func (m *Manager) logUnkeyedGraceLadderLocked() (int, time.Time) {
	st := &m.unkeyedGrace
	if st.earliestWall.IsZero() || st.corrupt {
		return 0, time.Time{}
	}
	expiry := st.earliestWall.Add(unkeyedAuthorityGrace)
	nowMono := unkeyedAuthorityMonoNow()
	deadline := st.deadlineMono.Load()
	remaining := deadline - nowMono
	if st.expired.Load() || remaining <= 0 {
		if st.lastLogRung < 4 {
			st.lastLogRung = 4
			st.lastPostExpiryLogMono = nowMono
			slog.Error("cluster: unkeyed authority grace expired; unauthenticated control authority is refused (#16016); " +
				"expired at " + expiry.Format(time.RFC3339) + "; a clock step can cause this — re-arm deliberately or key the cluster")
			return 4, expiry
		}
		if nowMono-st.lastPostExpiryLogMono >= int64(24*time.Hour) {
			st.lastPostExpiryLogMono = nowMono
			slog.Error("cluster: unkeyed authority remains expired; unauthenticated control authority is refused (#16016)",
				"expired_at", expiry.Format(time.RFC3339))
			return 5, expiry
		}
		return 0, expiry
	}
	rung := 1
	if remaining <= int64(time.Hour) {
		rung = 3
	} else if remaining <= int64(24*time.Hour) {
		rung = 2
	}
	if rung <= st.lastLogRung {
		return 0, expiry
	}
	st.lastLogRung = rung
	switch rung {
	case 2:
		slog.Error("cluster: unkeyed-authority grace expires within 24h; key the cluster now (#16016)",
			"expires", expiry.Format(time.RFC3339))
	case 3:
		slog.Error("cluster: unkeyed-authority grace expires within 1h; key the cluster now (#16016)",
			"expires", expiry.Format(time.RFC3339))
	}
	return rung, expiry
}

func unkeyedGraceNoticeName(rung int) string {
	switch rung {
	case 1:
		return "stamped"
	case 2:
		return "t-24h"
	case 3:
		return "t-1h"
	case 4:
		return "expired"
	case 5:
		return "daily-expired"
	default:
		return ""
	}
}

func (m *Manager) notifyUnkeyedGraceAlarm(rung string, raised bool, expiry time.Time) {
	if hook := m.unkeyedGraceAlarmHookFn(); hook != nil {
		// Keep the transition ordered and synchronous. Boot rungs can be
		// generated before the daemon's event reader exists, and the daemon
		// hook latches them until its sink is ready; a goroutine per rung could
		// reorder the FIFO or be lost during shutdown.
		hook(rung, raised, expiry)
	}
}

// noteUnkeyedKeyedLocked handles a local accepted-set transition. A normal
// in-grace key commit removes the obsolete anchor. Expired debt is retained
// until an authenticated heartbeat has installed peer state.
// Caller holds m.mu.
func (m *Manager) noteUnkeyedKeyedLocked() {
	st := &m.unkeyedGrace
	wasKeyed := st.keyConfigured.Swap(true)
	if wasKeyed && st.recoveryHold.Load() {
		return
	}
	wasExpired := m.loadUnkeyedAnchorForKeyedStateLocked()
	st.mu.Lock()
	if wasExpired {
		if st.earliestWall.IsZero() && !st.corrupt {
			now := unkeyedAuthorityNow().UTC()
			st.earliestWall = now.Add(-unkeyedAuthorityGrace)
			st.highWaterWall = now
		}
		if !st.earliestWall.IsZero() {
			expiry := st.earliestWall.Add(unkeyedAuthorityGrace)
			changed := st.highWaterWall.Before(expiry) || st.elapsedFloor < unkeyedAuthorityGrace
			st.highWaterWall = maxAuthorityWall(st.highWaterWall, expiry)
			st.elapsedFloor = unkeyedAuthorityGrace
			if changed || st.notPersisted {
				m.persistUnkeyedAuthorityLocked()
			}
		}
		st.anchorMono = 0
		st.deadlineMono.Store(0)
		st.mu.Unlock()
		st.expired.Store(true)
		st.armedGen.Store(m.peerProofGen.Load())
		st.recoveryHold.Store(true)
		slog.Warn("cluster: recovery hold armed after keying an expired unkeyed cluster (#16016); " +
			"takeover stays suppressed until the first authenticated peer heartbeat")
		if !wasKeyed {
			m.notifyUnkeyedGraceAlarm("cleared", false, time.Time{})
		}
		return
	}
	st.anchorMono = 0
	st.deadlineMono.Store(0)
	st.elapsedBase = 0
	st.elapsedFloor = 0
	st.earliestWall = time.Time{}
	st.highWaterWall = time.Time{}
	st.corrupt = false
	st.notPersisted = false
	st.persistFailureLogged = false
	st.lastLogRung = 0
	st.lastPostExpiryLogMono = 0
	deleteUnkeyedAuthorityRecord(unkeyedAuthorityGraceStatePath)
	st.mu.Unlock()
	st.expired.Store(false)
	if !wasKeyed {
		st.recoveryHold.Store(false)
	}
}

// restoreUnkeyedKeyedStateLocked preserves expired-anchor recovery debt when
// boot or peer configuration establishes a key without a local key commit.
// Caller holds m.mu.
func (m *Manager) restoreUnkeyedKeyedStateLocked() {
	st := &m.unkeyedGrace
	st.keyConfigured.Store(true)
	if m.loadUnkeyedAnchorForKeyedStateLocked() {
		st.expired.Store(true)
		st.recoveryHold.Store(true)
		st.armedGen.Store(m.peerProofGen.Load())
		slog.Warn("cluster: restored unkeyed-authority recovery hold from expired anchor (#16016); " +
			"takeover stays suppressed until the first authenticated peer heartbeat")
	}
}

// loadUnkeyedAnchorForKeyedStateLocked loads the on-disk evidence if needed
// and reports whether its wall/elapsed cutoff or the in-process deadline has
// expired. Caller holds m.mu.
func (m *Manager) loadUnkeyedAnchorForKeyedStateLocked() bool {
	st := &m.unkeyedGrace
	now := unkeyedAuthorityNow().UTC()
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.expired.Load() {
		if st.notPersisted && !st.earliestWall.IsZero() {
			m.persistUnkeyedAuthorityLocked()
		}
		return true
	}
	expired := st.expired.Load()
	changed := false
	if deadline := st.deadlineMono.Load(); deadline != 0 && unkeyedAuthorityMonoNow() >= deadline {
		expired = true
	}
	if !st.loaded {
		st.loaded = true
		earliest, highWater, elapsed, present, corrupt, _ := loadUnkeyedAuthorityRecord(
			unkeyedAuthorityGraceStatePath, now)
		if corrupt {
			st.corrupt = true
			expired = true
		} else if present {
			st.earliestWall = earliest
			st.highWaterWall = highWater
			st.elapsedFloor = elapsed
			st.elapsedBase = elapsed
		}
	}
	if st.corrupt {
		return true
	}
	if !st.earliestWall.IsZero() {
		effectiveWall := maxAuthorityWall(now, st.highWaterWall)
		wallElapsed := unkeyedElapsedFromWall(st.earliestWall, effectiveWall)
		if wallElapsed > st.elapsedFloor {
			st.elapsedFloor = wallElapsed
			changed = true
		}
		if effectiveWall.After(st.highWaterWall) {
			st.highWaterWall = effectiveWall
			changed = true
		}
		if st.elapsedFloor >= unkeyedAuthorityGrace ||
			!effectiveWall.Before(st.earliestWall.Add(unkeyedAuthorityGrace)) {
			expired = true
		}
	}
	if expired {
		if !st.earliestWall.IsZero() {
			expiry := st.earliestWall.Add(unkeyedAuthorityGrace)
			if st.highWaterWall.Before(expiry) {
				st.highWaterWall = expiry
				changed = true
			}
			if st.elapsedFloor < unkeyedAuthorityGrace {
				st.elapsedFloor = unkeyedAuthorityGrace
				changed = true
			}
			if changed || st.notPersisted {
				m.persistUnkeyedAuthorityLocked()
			}
		}
		st.expired.Store(true)
	}
	return expired
}

// noteUnkeyedKeyClearedLocked is the only transition that may deliberately
// replace an existing anchor with a fresh local key-clear grace window.
// Caller holds m.mu.
func (m *Manager) noteUnkeyedKeyClearedLocked() {
	st := &m.unkeyedGrace
	st.keyConfigured.Store(false)
	st.mu.Lock()
	st.anchorMono = 0
	st.deadlineMono.Store(0)
	st.elapsedBase = 0
	st.elapsedFloor = 0
	st.earliestWall = time.Time{}
	st.highWaterWall = time.Time{}
	st.corrupt = false
	st.notPersisted = false
	st.persistFailureLogged = false
	st.lastLogRung = 0
	st.lastPostExpiryLogMono = 0
	deleteUnkeyedAuthorityRecord(unkeyedAuthorityGraceStatePath)
	st.mu.Unlock()
	st.expired.Store(false)
	st.recoveryHold.Store(false)
	for _, rg := range m.groups {
		rg.forcedPrimary = false
	}
}

// closePeerKeyClearWithoutGraceLocked restores an existing anchor without
// creating one. Clearing a key that was previously configured after restart is
// fail-closed because the keyed interval is not measured by the grace clocks.
// Caller holds m.mu.
func (m *Manager) closePeerKeyClearWithoutGraceLocked(clusterEnabled, wasKeyConfigured bool) {
	if m == nil || !clusterEnabled {
		return
	}
	st := &m.unkeyedGrace
	now := unkeyedAuthorityNow().UTC()
	mono := unkeyedAuthorityMonoNow()
	expired := st.expired.Load()
	expiry := time.Time{}
	st.mu.Lock()
	changed := false
	if !st.loaded {
		st.loaded = true
		earliest, highWater, elapsed, present, corrupt, clamped := loadUnkeyedAuthorityRecord(
			unkeyedAuthorityGraceStatePath, now)
		switch {
		case corrupt:
			st.corrupt = true
			expired = true
			slog.Error("cluster: peer key-clear found a corrupt or legacy unkeyed-authority anchor; "+
				"failing closed (#16016)", "path", unkeyedAuthorityGraceStatePath)
		case present:
			st.earliestWall = earliest
			st.highWaterWall = highWater
			st.elapsedFloor = elapsed
			st.elapsedBase = elapsed
			changed = clamped
		}
	}
	if wasKeyConfigured && st.deadlineMono.Load() == 0 {
		if st.corrupt {
			expired = true
		} else if st.earliestWall.IsZero() {
			st.earliestWall = now.Add(-unkeyedAuthorityGrace)
			st.highWaterWall = now
			st.elapsedBase = unkeyedAuthorityGrace
			st.elapsedFloor = unkeyedAuthorityGrace
			st.anchorMono = mono
			st.deadlineMono.Store(mono)
			expiry = now
			changed = true
			expired = true
		} else {
			expiry = st.earliestWall.Add(unkeyedAuthorityGrace)
			if st.highWaterWall.Before(expiry) {
				st.highWaterWall = expiry
				changed = true
			}
			if st.elapsedFloor < unkeyedAuthorityGrace {
				st.elapsedFloor = unkeyedAuthorityGrace
				changed = true
			}
			expired = true
		}
	} else if st.corrupt {
		expired = true
	} else if st.earliestWall.IsZero() {
		// No anchor means a peer frame cannot establish a fresh provisioning
		// window. Persist a cutoff at "now", so a restart cannot interpret the
		// missing file as day-zero provisioning.
		st.earliestWall = now.Add(-unkeyedAuthorityGrace)
		st.highWaterWall = now
		st.elapsedBase = unkeyedAuthorityGrace
		st.elapsedFloor = unkeyedAuthorityGrace
		st.anchorMono = mono
		st.deadlineMono.Store(mono)
		expiry = now
		changed = true
		expired = true
	} else {
		expiry = st.earliestWall.Add(unkeyedAuthorityGrace)
		effectiveWall := maxAuthorityWall(now, st.highWaterWall)
		wallElapsed := unkeyedElapsedFromWall(st.earliestWall, effectiveWall)
		if wallElapsed > st.elapsedFloor {
			st.elapsedFloor = wallElapsed
			changed = true
		}
		deadline := st.deadlineMono.Load()
		if deadline == 0 {
			st.anchorMono = mono
			st.elapsedBase = st.elapsedFloor
			remaining := unkeyedAuthorityGrace - st.elapsedFloor
			if wallRemaining := expiry.Sub(effectiveWall); wallRemaining < remaining {
				remaining = wallRemaining
			}
			if remaining < 0 {
				remaining = 0
			}
			deadline = mono + remaining.Nanoseconds()
			st.deadlineMono.Store(deadline)
		}
		if now.After(st.highWaterWall) {
			st.highWaterWall = now
			changed = true
		}
		if st.elapsedFloor >= unkeyedAuthorityGrace || !effectiveWall.Before(expiry) || mono >= deadline {
			expired = true
		}
	}
	// A peer update that discovers a missing, corrupt, or expired cutoff must
	// deny authority before the durable sentinel write. Key-clear transitions
	// publish this earlier, before exposing the empty-key posture; this also
	// covers already-unkeyed peers whose first observed config has no anchor.
	if expired {
		st.peerKeyClearPending.Store(true)
	}
	if changed {
		m.persistUnkeyedAuthorityLocked()
	}

	st.mu.Unlock()
	if expired {
		m.markUnkeyedAuthorityExpired(expiry)
	}
}

// UnkeyedAuthorityExpired reports whether the unkeyed-authority grace has
// expired for this process. The hot path is an atomic posture read plus a
// monotonic deadline comparison; the wall-clock record is never consulted
// after boot.
func (m *Manager) UnkeyedAuthorityExpired() bool {
	if m == nil {
		return false
	}
	st := &m.unkeyedGrace
	if st.peerKeyClearPending.Load() {
		return true
	}
	if st.keyConfigured.Load() {
		return false
	}
	if st.expired.Load() {
		return true
	}
	deadline := st.deadlineMono.Load()
	if deadline != 0 && unkeyedAuthorityMonoNow() >= deadline {
		m.markUnkeyedAuthorityExpired(m.UnkeyedGraceExpiry())
	}
	return st.expired.Load()
}

func (m *Manager) markUnkeyedAuthorityExpired(expiry time.Time) {
	if m == nil {
		return
	}
	st := &m.unkeyedGrace
	if st.keyConfigured.Load() || !st.expired.CompareAndSwap(false, true) {
		return
	}
	st.mu.Lock()
	if expiry.IsZero() && !st.earliestWall.IsZero() {
		expiry = st.earliestWall.Add(unkeyedAuthorityGrace)
	}
	if !expiry.IsZero() {
		changed := st.highWaterWall.Before(expiry) || st.elapsedFloor < unkeyedAuthorityGrace
		if st.highWaterWall.Before(expiry) {
			st.highWaterWall = expiry
		}
		if st.elapsedFloor < unkeyedAuthorityGrace {
			st.elapsedFloor = unkeyedAuthorityGrace
		}
		if changed || st.notPersisted {
			m.persistUnkeyedAuthorityLocked()
		}
	}
	st.lastLogRung = 4
	st.lastPostExpiryLogMono = unkeyedAuthorityMonoNow()
	st.mu.Unlock()
	suffix := ""
	if !expiry.IsZero() {
		suffix = " expired at " + expiry.Format(time.RFC3339)
	}
	slog.Error("cluster: unkeyed authority grace expired; unauthenticated control authority is refused (#16016);" +
		suffix + "; a clock step can cause this — key the cluster to recover")
	m.notifyUnkeyedGraceAlarm("expired", true, expiry)
}

// checkUnkeyedGraceNotices runs from the existing one-second session-auth
// sweep so the pre-expiry warning ladder does not add a timer or a goroutine.
func (m *Manager) checkUnkeyedGraceNotices() {
	if m == nil {
		return
	}
	st := &m.unkeyedGrace
	now := unkeyedAuthorityNow().UTC()
	mono := unkeyedAuthorityMonoNow()
	expired := false
	changed := false
	st.mu.Lock()
	if st.keyConfigured.Load() {
		st.mu.Unlock()
		return
	}
	if st.expired.Load() {
		rung, expiry := m.logUnkeyedGraceLadderLocked()
		st.mu.Unlock()
		if rung != 0 {
			m.notifyUnkeyedGraceAlarm(unkeyedGraceNoticeName(rung), true, expiry)
		}
		return
	}
	if !st.loaded {
		st.loaded = true
		earliest, highWater, elapsed, present, corrupt, clamped := loadUnkeyedAuthorityRecord(
			unkeyedAuthorityGraceStatePath, now)
		if corrupt {
			st.corrupt = true
			expired = true
		} else if present {
			st.earliestWall = earliest
			st.highWaterWall = highWater
			st.elapsedFloor = elapsed
			effectiveWall := maxAuthorityWall(now, highWater)
			if wallElapsed := unkeyedElapsedFromWall(earliest, effectiveWall); wallElapsed > st.elapsedFloor {
				st.elapsedFloor = wallElapsed
				changed = true
			}
			st.elapsedBase = st.elapsedFloor
			changed = changed || clamped
		}
	}
	if !st.earliestWall.IsZero() {
		if st.anchorMono == 0 {
			st.anchorMono = mono
			st.elapsedBase = st.elapsedFloor
			effectiveWall := maxAuthorityWall(now, st.highWaterWall)
			remaining := unkeyedAuthorityGrace - st.elapsedFloor
			if wallRemaining := st.earliestWall.Add(unkeyedAuthorityGrace).Sub(effectiveWall); wallRemaining < remaining {
				remaining = wallRemaining
			}
			if remaining < 0 {
				remaining = 0
			}
			st.deadlineMono.Store(mono + remaining.Nanoseconds())
		}
		wallNow := unkeyedAuthorityNow().UTC()
		if wallNow.After(st.highWaterWall) {
			st.highWaterWall = wallNow
			changed = true
		}
		monotonicElapsed := st.elapsedBase + time.Duration(mono-st.anchorMono)
		wallElapsed := unkeyedElapsedFromWall(st.earliestWall, maxAuthorityWall(wallNow, st.highWaterWall))
		nextElapsed := st.elapsedFloor
		if monotonicElapsed > nextElapsed {
			nextElapsed = monotonicElapsed
		}
		if wallElapsed > nextElapsed {
			nextElapsed = wallElapsed
		}
		nextElapsed = capUnkeyedElapsed(nextElapsed)
		if nextElapsed > st.elapsedFloor {
			st.elapsedFloor = nextElapsed
			changed = true
		}
		if deadline := st.deadlineMono.Load(); deadline != 0 && mono >= deadline {
			expired = true
		}
	}
	expiry := time.Time{}
	if !st.earliestWall.IsZero() {
		expiry = st.earliestWall.Add(unkeyedAuthorityGrace)
	}
	if changed {
		m.persistUnkeyedAuthorityLocked()
	}
	st.mu.Unlock()
	if expired {
		m.markUnkeyedAuthorityExpired(expiry)
		return
	}
	m.UnkeyedAuthorityExpired()
	st.mu.Lock()
	rung, rungExpiry := m.logUnkeyedGraceLadderLocked()
	st.mu.Unlock()
	if rung != 0 {
		m.notifyUnkeyedGraceAlarm(unkeyedGraceNoticeName(rung), true, rungExpiry)
	}
}

// RestartUnkeyedAuthorityGrace is the audited local operator act for an
// expired or corrupt wall-clock anchor. It cannot extend an active window,
// and does not alter redundancy-group roles.
func (m *Manager) RestartUnkeyedAuthorityGrace(operator string) (time.Time, error) {
	if m == nil {
		return time.Time{}, fmt.Errorf("cluster not configured")
	}
	operator = strings.TrimSpace(operator)
	if operator == "" {
		return time.Time{}, fmt.Errorf("unkeyed-grace restart requires a local operator identity")
	}

	m.mu.Lock()
	if len(m.controlAuthKey) > 0 || len(m.controlAuthKeyAlt) > 0 {
		m.mu.Unlock()
		return time.Time{}, fmt.Errorf("unkeyed-grace restart requires an unkeyed cluster")
	}
	if !m.UnkeyedAuthorityExpired() {
		m.mu.Unlock()
		return time.Time{}, fmt.Errorf("unkeyed-grace restart is available only after the grace expires (#16016)")
	}

	st := &m.unkeyedGrace
	now := unkeyedAuthorityNow().UTC()
	mono := unkeyedAuthorityMonoNow()
	reason := "operator explicitly re-armed an expired or corrupt anchor after a clock step"
	st.mu.Lock()
	if st.earliestWall.IsZero() && !st.corrupt {
		st.mu.Unlock()
		m.mu.Unlock()
		return time.Time{}, fmt.Errorf("unkeyed-grace restart requires an existing expired or corrupt anchor")
	}
	deleteUnkeyedAuthorityRecord(unkeyedAuthorityGraceStatePath)
	st.anchorMono = mono
	st.deadlineMono.Store(mono + unkeyedAuthorityGrace.Nanoseconds())
	st.elapsedBase = 0
	st.elapsedFloor = 0
	st.earliestWall = now
	st.highWaterWall = now
	st.corrupt = false
	st.loaded = true
	st.notPersisted = false
	st.persistFailureLogged = false
	st.lastLogRung = 0
	st.lastPostExpiryLogMono = 0
	m.persistUnkeyedAuthorityLocked()
	st.expired.Store(false)
	st.keyConfigured.Store(false)
	st.recoveryHold.Store(false)
	rung, expiry := m.logUnkeyedGraceLadderLocked()
	st.mu.Unlock()
	message := fmt.Sprintf(
		"unkeyed-grace restart operator=%s node=%d at=%s reason=%q expires=%s",
		operator, m.nodeID, now.Format(time.RFC3339Nano), reason,
		expiry.UTC().Format(time.RFC3339))
	if m.history != nil {
		m.history.Record(EventRG, -1, message)
	}
	alarmHook := m.unkeyedGraceAlarmHookFn()
	auditHook := m.unkeyedRecoveryAuditHook()
	nodeID := m.nodeID
	m.mu.Unlock()

	if alarmHook != nil {
		alarmHook("cleared", false, expiry)
		if rung != 0 {
			alarmHook(unkeyedGraceNoticeName(rung), true, expiry)
		}
	}
	if auditHook != nil {
		auditHook("unkeyed-grace-restart", operator, -1, nodeID, now, reason)
	}
	slog.Warn("cluster: operator restarted expired unkeyed-authority grace (#16016)",
		"operator", operator, "node", nodeID, "time", now.Format(time.RFC3339Nano),
		"expires", expiry.Format(time.RFC3339), "reason", reason)
	return expiry, nil
}

// UnkeyedGraceExpiry returns the wall-clock expiry of the current anchor,
// or zero when no anchor is stamped (keyed, disabled, or not yet observed).
func (m *Manager) UnkeyedGraceExpiry() time.Time {
	if m == nil {
		return time.Time{}
	}
	st := &m.unkeyedGrace
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.earliestWall.IsZero() {
		return time.Time{}
	}
	return st.earliestWall.Add(unkeyedAuthorityGrace)
}

// UnkeyedGraceAnchorCorrupt reports whether the persisted anchor was present
// but unparseable at load (expired-at-boot posture).
func (m *Manager) UnkeyedGraceAnchorCorrupt() bool {
	if m == nil {
		return false
	}
	st := &m.unkeyedGrace
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.corrupt
}

// UnkeyedGraceNotPersisted reports whether the anchor could not be persisted
// (in-process deadline still enforces; a restart re-opens grace).
func (m *Manager) UnkeyedGraceNotPersisted() bool {
	notPersisted, _ := m.unkeyedGracePersistenceState()
	return notPersisted
}

func (m *Manager) unkeyedGracePersistenceState() (notPersisted, postRenameDurabilityUnknown bool) {
	if m == nil {
		return false, false
	}
	st := &m.unkeyedGrace
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.notPersisted, st.postRenameDurabilityUnknown
}

// RecoveryHoldActive reports whether takeover remains suppressed after
// expired->keyed recovery. Only the post-heartbeat proof publisher clears it,
// after the peer's election state has been installed.
func (m *Manager) RecoveryHoldActive() bool {
	return m != nil && m.unkeyedGrace.recoveryHold.Load()
}

// PeerProofGeneration returns the current fresh-proof generation. It is
// incremented ONLY at the end of admitFrame's authenticated arm, after
// handlePeerHeartbeat has installed the peer's RG/election claims from the
// verified frame — never from sync transport proof.
func (m *Manager) PeerProofGeneration() uint64 {
	if m == nil {
		return 0
	}
	return m.peerProofGen.Load()
}

// publishFreshHeartbeatProof runs only after an authenticated heartbeat has
// committed its peer state. The accepted-key generation captured before MAC
// verification must still match while Manager.mu is held; otherwise an
// interposed key transition makes this proof stale. The hold is released for
// election under Manager.mu; persisted evidence is removed only after normal
// election is reevaluated.
func (m *Manager) publishFreshHeartbeatProof(keySnapshotGeneration uint64) {
	if m == nil {
		return
	}
	st := &m.unkeyedGrace
	m.mu.Lock()
	if m.controlLinkKeyGeneration != keySnapshotGeneration {
		m.mu.Unlock()
		return
	}
	gen := m.peerProofGen.Add(1)
	if !st.keyConfigured.Load() || !st.recoveryHold.Load() || gen <= st.armedGen.Load() ||
		!st.recoveryHold.CompareAndSwap(true, false) {
		m.mu.Unlock()
		return
	}
	for rgID, rg := range m.groups {
		// A fresh authenticated peer-primary claim supersedes the local
		// break-glass pin before normal election resolves the two claims. A
		// proof that the peer is not primary leaves the operator's pin active.
		if peer, ok := m.peerGroups[rgID]; ok && peer.State == StatePrimary {
			rg.forcedPrimary = false
		}
	}
	if m.peerAlive {
		m.runElection()
	} else {
		m.electSingleNode()
	}
	st.mu.Lock()
	deleteUnkeyedAuthorityRecord(unkeyedAuthorityGraceStatePath)
	st.anchorMono = 0
	st.deadlineMono.Store(0)
	st.elapsedBase = 0
	st.elapsedFloor = 0
	st.earliestWall = time.Time{}
	st.highWaterWall = time.Time{}
	st.corrupt = false
	st.notPersisted = false
	st.persistFailureLogged = false
	st.lastLogRung = 0
	st.lastPostExpiryLogMono = 0
	st.mu.Unlock()
	st.expired.Store(false)
	m.mu.Unlock()
}

// electionHoldActiveLocked reports whether election acquisition is held:
// either the unkeyed-expired hold (accepted set empty ∧ grace expired) or
// the recovery hold. Cheap; safe under m.mu (atomics only).
func (m *Manager) electionHoldActiveLocked() bool {
	if m.UnkeyedAuthorityExpired() && !m.unkeyedGrace.keyConfigured.Load() {
		return true
	}
	return m.RecoveryHoldActive()
}

// StampUnkeyedAuthorityAnchor is the boot-pinning belt called by
// Daemon.startClusterComms before listeners open. It receives the same
// compiled cluster config as UpdateConfig, including fabric-only transports.
func (m *Manager) StampUnkeyedAuthorityAnchor(cfg *config.ClusterConfig) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.controlAuthKey) > 0 || len(m.controlAuthKeyAlt) > 0 {
		return
	}
	m.touchUnkeyedAuthorityLocked(clusterAuthorityTransportConfigured(cfg))
}

// SetUnkeyedGraceAlarmHook installs the per-rung notice and expiry transition
// callback, wired at Manager construction like SetPeerClockAlarmHook. The
// daemon forwards each event to syslog in the RT_SYSTEM shape.
func (m *Manager) SetUnkeyedGraceAlarmHook(fn func(rung string, raised bool, expiry time.Time)) {
	if m == nil {
		return
	}
	m.unkeyedAlarmMu.Lock()
	defer m.unkeyedAlarmMu.Unlock()
	m.unkeyedAlarmHook = fn
}

func (m *Manager) unkeyedGraceAlarmHookFn() func(string, bool, time.Time) {
	if m == nil {
		return nil
	}
	m.unkeyedAlarmMu.Lock()
	defer m.unkeyedAlarmMu.Unlock()
	return m.unkeyedAlarmHook
}

// SetUnkeyedRecoveryAuditHook installs the syslog audit sink for the
// local-only force-primary break-glass action.
func (m *Manager) SetUnkeyedRecoveryAuditHook(fn func(action, operator string, rgID, nodeID int, at time.Time, reason string)) {
	if m == nil {
		return
	}
	m.unkeyedAlarmMu.Lock()
	defer m.unkeyedAlarmMu.Unlock()
	m.unkeyedAuditHook = fn
}

func (m *Manager) unkeyedRecoveryAuditHook() func(string, string, int, int, time.Time, string) {
	if m == nil {
		return nil
	}
	m.unkeyedAlarmMu.Lock()
	defer m.unkeyedAlarmMu.Unlock()
	return m.unkeyedAuditHook
}

// SetUnkeyedAuthorityGraceStatePathForTesting redirects the persisted anchor
// file and returns a restore function. Test-only, mirroring
// SetFabricAuthGraceStatePathForTesting.
func SetUnkeyedAuthorityGraceStatePathForTesting(path string) func() {
	orig := unkeyedAuthorityGraceStatePath
	unkeyedAuthorityGraceStatePath = path
	return func() { unkeyedAuthorityGraceStatePath = orig }
}

// SetUnkeyedAuthorityClocksForTesting pins the wall and monotonic clocks and
// returns a restore function. Test-only.
func SetUnkeyedAuthorityClocksForTesting(wall func() time.Time, mono func() int64) func() {
	ow, om := unkeyedAuthorityNow, unkeyedAuthorityMonoNow
	if wall != nil {
		unkeyedAuthorityNow = wall
	}
	if mono != nil {
		unkeyedAuthorityMonoNow = mono
	}
	return func() { unkeyedAuthorityNow, unkeyedAuthorityMonoNow = ow, om }
}
