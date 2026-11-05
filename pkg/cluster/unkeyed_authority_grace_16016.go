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
//   - In-process authority is a set-once CLOCK_MONOTONIC deadline. The first
//     observation of (cluster enabled ∧ accepted set empty) arms it; expiry
//     fires at anchorMono+grace regardless of wall-clock steps, and no
//     in-process event ever moves it.
//   - The persisted record exists only for restart recovery:
//     "v1 <earliestWallUnixNano> <highWaterWallUnixNano>". Every touch
//     ratchets highWater = max(highWater, wallNow); expiry-by-wall is
//     max(wallNow, highWater) >= earliest+grace, so a rollback+restart
//     cannot refund observed time. A future-dated earliest is clamped down
//     to now (shorten, never extend).
//
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
func SetUnkeyedAuthorityPersistForTesting(fn func(string, time.Time, time.Time) error) func() {
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
	// armedGen mirrors Manager.peerProofGen at the anchor-delete
	// (expired->keyed) transition; the recovery hold clears only when the
	// generation advances past it.
	armedGen atomic.Uint64
	// recoveryHold is true between the anchor-delete transition and the
	// first fresh authenticated heartbeat proof.
	recoveryHold  atomic.Bool
	keyConfigured atomic.Bool

	mu                    sync.Mutex
	anchorMono            int64        // set-once monotonic anchor; 0 = unarmed
	deadlineMono          atomic.Int64 // anchorMono + grace; 0 = unarmed
	earliestWall          time.Time    // persisted earliest wall stamp
	highWaterWall         time.Time    // persisted high-water wall stamp
	corrupt               bool         // record present but unparseable at load
	loaded                bool         // the persisted record has been read this process
	notPersisted          bool         // a persist failed; status suffix names it
	persistFailureLogged  bool         // suppress repeated errors in one failure episode
	lastLogRung           int          // highest notice rung already logged (0..4)
	lastPostExpiryLogMono int64
}

// loadUnkeyedAuthorityRecord reads the persisted record. present=false means
// the file is absent (fresh stamp). corrupt=true means present but
// unparseable (expired-at-boot). A future-dated earliest is clamped down to
// now here, and the clamped value is what later touches persist.
func loadUnkeyedAuthorityRecord(path string, now time.Time) (earliest, highWater time.Time, present, corrupt, clamped bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return time.Time{}, time.Time{}, false, false, false
		}
		// An unreadable-but-present file is not absence.
		return time.Time{}, time.Time{}, true, true, false
	}
	fields := strings.Fields(strings.TrimSpace(string(data)))
	if len(fields) != 3 || fields[0] != "v1" {
		return time.Time{}, time.Time{}, true, true, false
	}
	e, err1 := strconv.ParseInt(fields[1], 10, 64)
	h, err2 := strconv.ParseInt(fields[2], 10, 64)
	if err1 != nil || err2 != nil || e <= 0 || h < e {
		return time.Time{}, time.Time{}, true, true, false
	}
	earliest = time.Unix(0, e).UTC()
	highWater = time.Unix(0, h).UTC()
	if earliest.After(now) {
		earliest = now // clamp down: shorten, never extend
		clamped = true
	}
	if highWater.Before(earliest) {
		highWater = earliest
	}
	return earliest, highWater, true, false, clamped
}

// persistUnkeyedAuthorityRecord durably writes the record. Best-effort: the
// caller records/report failures but never fails config apply or boot.
func persistUnkeyedAuthorityRecord(path string, earliest, highWater time.Time) error {
	if earliest.IsZero() {
		return errors.New("empty unkeyed-authority grace anchor")
	}
	if highWater.Before(earliest) {
		highWater = earliest
	}
	if err := fsatomic.MkdirAllDurable(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	body := fmt.Sprintf("v1 %d %d\n", earliest.UnixNano(), highWater.UnixNano())
	if err := fsatomic.WriteFileDurable(path, []byte(body), 0o644); err != nil {
		var postRename *fsatomic.PostRenameSyncError
		if errors.As(err, &postRename) {
			return nil // visible to the next read; durability unknown only
		}
		return err
	}
	return nil
}

// persistUnkeyedAuthorityLocked is called with unkeyedGrace.mu held.
func (m *Manager) persistUnkeyedAuthorityLocked() {
	st := &m.unkeyedGrace
	err := unkeyedAuthorityPersist(unkeyedAuthorityGraceStatePath, st.earliestWall, st.highWaterWall)
	if err == nil {
		st.notPersisted = false
		st.persistFailureLogged = false
		return
	}
	st.notPersisted = true
	if !st.persistFailureLogged {
		st.persistFailureLogged = true
		slog.Error("cluster: unkeyed-authority grace anchor persist failed; "+
			"the in-process deadline still expires but a restart re-opens grace (#16016)",
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
	now := unkeyedAuthorityNow()
	mono := unkeyedAuthorityMonoNow()
	loadedExpired := false
	remainingOnBoot := unkeyedAuthorityGrace
	clamped := false
	st.mu.Lock()
	if !st.loaded {
		st.loaded = true
		earliest, highWater, present, corrupt, clampOnLoad := loadUnkeyedAuthorityRecord(unkeyedAuthorityGraceStatePath, now)
		switch {
		case corrupt:
			st.corrupt = true
			loadedExpired = true
			slog.Error("cluster: unkeyed-authority grace anchor is corrupt; "+
				"treating the grace as expired at boot (#16016); key the cluster to recover",
				"path", unkeyedAuthorityGraceStatePath)
		case present:
			st.earliestWall = earliest
			if highWater.After(now) {
				// Expiry-by-wall uses max(wallNow, highWater) across restarts.
				now = highWater
			}
			st.highWaterWall = highWater
			expiry := earliest.Add(unkeyedAuthorityGrace)
			if !now.Before(expiry) {
				loadedExpired = true
				remainingOnBoot = 0
			} else {
				remainingOnBoot = expiry.Sub(now)
			}
			clamped = clampOnLoad
		}
	}
	if !st.earliestWall.IsZero() && st.anchorMono == 0 {
		wall := unkeyedAuthorityNow()
		if st.highWaterWall.After(wall) {
			wall = st.highWaterWall
		}
		expiry := st.earliestWall.Add(unkeyedAuthorityGrace)
		if !wall.Before(expiry) {
			loadedExpired = true
			remainingOnBoot = 0
		} else {
			remainingOnBoot = expiry.Sub(wall)
		}
	}
	if st.corrupt {
		st.mu.Unlock()
		if loadedExpired {
			m.markUnkeyedAuthorityExpired(time.Time{})
		}
		return
	}
	// Set-once monotonic arm. A restored, already-expired wall record stays
	// expired; the fresh monotonic deadline is irrelevant because the atomic
	// expired word is sticky until a local key commit clears the record.
	if st.anchorMono == 0 {
		st.anchorMono = mono
		st.deadlineMono.Store(mono + remainingOnBoot.Nanoseconds())
		if st.earliestWall.IsZero() {
			st.earliestWall = now
			st.highWaterWall = now
			m.persistUnkeyedAuthorityLocked()
			slog.Warn("cluster: unkeyed-authority grace stamped; unauthenticated control authority "+
				"remains accepted until the grace expires (#16016)",
				"expires", st.earliestWall.Add(unkeyedAuthorityGrace).Format(time.RFC3339))
		}
	}
	if clamped {
		m.persistUnkeyedAuthorityLocked()
	}
	// High-water ratchet on every touch. In-process expiry is MONOTONIC only:
	// a forward wall step cannot accelerate it, and a backward step cannot
	// extend it. The wall record is consulted only when a process starts.
	if wallNow := unkeyedAuthorityNow(); wallNow.After(st.highWaterWall) {
		st.highWaterWall = wallNow
		m.persistUnkeyedAuthorityLocked()
	}
	if deadline := st.deadlineMono.Load(); deadline != 0 && mono >= deadline {
		loadedExpired = true
	}
	var noticeRung int
	var noticeExpiry time.Time
	if !loadedExpired {
		noticeRung, noticeExpiry = m.logUnkeyedGraceLadderLocked()
	}
	expiry := time.Time{}
	if !st.earliestWall.IsZero() {
		expiry = st.earliestWall.Add(unkeyedAuthorityGrace)
	}
	st.mu.Unlock()
	if loadedExpired {
		m.markUnkeyedAuthorityExpired(expiry)
	} else if noticeRung != 0 {
		m.notifyUnkeyedGraceAlarm(unkeyedGraceNoticeName(noticeRung), true, noticeExpiry)
	}

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
		go hook(rung, raised, expiry)
	}
}

// noteUnkeyedKeyedLocked handles the accepted-set-nonempty transition:
// delete the persisted record, clear the in-process anchor, and — only when
// transitioning out of the expired posture — arm the recovery hold at the
// current proof generation. Caller holds m.mu.
func (m *Manager) noteUnkeyedKeyedLocked() {
	st := &m.unkeyedGrace
	wasKeyed := st.keyConfigured.Swap(true)
	wasExpired := false
	if !wasKeyed {
		wasExpired = st.expired.Load()
		if deadline := st.deadlineMono.Load(); deadline != 0 && unkeyedAuthorityMonoNow() >= deadline {
			wasExpired = true
		}
		if !wasExpired && st.deadlineMono.Load() == 0 {
			earliest, highWater, present, corrupt, _ := loadUnkeyedAuthorityRecord(
				unkeyedAuthorityGraceStatePath, unkeyedAuthorityNow())
			if present && corrupt {
				wasExpired = true
			} else if present {
				now := unkeyedAuthorityNow()
				if highWater.After(now) {
					now = highWater
				}
				wasExpired = !now.Before(earliest.Add(unkeyedAuthorityGrace))
			}
		}
	}

	// Serialize deletion with the one-second high-water sweep: a write that
	// started before this transition must finish before the anchor is removed.
	st.mu.Lock()
	st.anchorMono = 0
	st.deadlineMono.Store(0)
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
	if !wasKeyed && wasExpired {
		st.armedGen.Store(m.peerProofGen.Load())
		st.recoveryHold.Store(true)
		slog.Warn("cluster: recovery hold armed after keying an expired unkeyed cluster (#16016); " +
			"takeover stays suppressed until the first authenticated peer heartbeat")
		m.notifyUnkeyedGraceAlarm("cleared", false, time.Time{})
	} else if !wasKeyed {
		st.recoveryHold.Store(false)
	}
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
// creating one. If a peer key-clear leaves no local cutoff (for example, a
// local key commit deleted it earlier), it persists an already-expired
// sentinel instead of reopening unauthenticated authority. Caller holds m.mu.
func (m *Manager) closePeerKeyClearWithoutGraceLocked(clusterEnabled bool) {
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
		earliest, highWater, present, corrupt, clamped := loadUnkeyedAuthorityRecord(
			unkeyedAuthorityGraceStatePath, now)
		switch {
		case corrupt:
			st.corrupt = true
			expired = true
			slog.Error("cluster: peer key-clear found a corrupt unkeyed-authority anchor; "+
				"failing closed (#16016)", "path", unkeyedAuthorityGraceStatePath)
		case present:
			st.earliestWall = earliest
			st.highWaterWall = highWater
			changed = clamped
		}
	}
	if st.corrupt {
		expired = true
	} else if st.earliestWall.IsZero() {
		// No anchor means a peer frame cannot establish a fresh provisioning
		// window. Persist a cutoff at "now", so a restart cannot interpret the
		// missing file as day-zero provisioning.
		st.earliestWall = now.Add(-unkeyedAuthorityGrace)
		st.highWaterWall = now
		st.anchorMono = mono
		st.deadlineMono.Store(mono)
		expiry = now
		changed = true
		expired = true
	} else {
		expiry = st.earliestWall.Add(unkeyedAuthorityGrace)
		deadline := st.deadlineMono.Load()
		if deadline == 0 {
			effectiveWall := now
			if st.highWaterWall.After(effectiveWall) {
				effectiveWall = st.highWaterWall
			}
			remaining := expiry.Sub(effectiveWall)
			if remaining < 0 {
				remaining = 0
			}
			st.anchorMono = mono
			deadline = mono + remaining.Nanoseconds()
			st.deadlineMono.Store(deadline)
		}
		if mono >= deadline {
			expired = true
		}
		if now.After(st.highWaterWall) {
			st.highWaterWall = now
			changed = true
		}
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
		if st.highWaterWall.Before(expiry) {
			st.highWaterWall = expiry
		}
		m.persistUnkeyedAuthorityLocked()
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
	st.mu.Lock()
	if !st.loaded {
		st.loaded = true
		earliest, highWater, present, corrupt, clamped := loadUnkeyedAuthorityRecord(
			unkeyedAuthorityGraceStatePath, unkeyedAuthorityNow())
		if corrupt {
			st.corrupt = true
			st.expired.Store(true)
		} else if present {
			st.earliestWall = earliest
			st.highWaterWall = highWater
			effectiveWall := unkeyedAuthorityNow()
			if highWater.After(effectiveWall) {
				effectiveWall = highWater
			}
			if !effectiveWall.Before(earliest.Add(unkeyedAuthorityGrace)) {
				st.expired.Store(true)
			}
			if clamped {
				m.persistUnkeyedAuthorityLocked()
			}
		}
	}
	if !st.earliestWall.IsZero() {
		if now := unkeyedAuthorityNow(); now.After(st.highWaterWall) {
			st.highWaterWall = now
			m.persistUnkeyedAuthorityLocked()
		}
	}
	keyConfigured := st.keyConfigured.Load()
	if !keyConfigured && st.anchorMono == 0 && !st.earliestWall.IsZero() {
		mono := unkeyedAuthorityMonoNow()
		effectiveWall := unkeyedAuthorityNow()
		if st.highWaterWall.After(effectiveWall) {
			effectiveWall = st.highWaterWall
		}
		remaining := st.earliestWall.Add(unkeyedAuthorityGrace).Sub(effectiveWall)
		if remaining < 0 {
			remaining = 0
		}
		st.anchorMono = mono
		st.deadlineMono.Store(mono + remaining.Nanoseconds())
	}
	st.mu.Unlock()
	if keyConfigured {
		return
	}
	m.UnkeyedAuthorityExpired()
	st.mu.Lock()
	rung, expiry := m.logUnkeyedGraceLadderLocked()
	st.mu.Unlock()
	if rung != 0 {
		m.notifyUnkeyedGraceAlarm(unkeyedGraceNoticeName(rung), true, expiry)
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
	if m == nil {
		return false
	}
	st := &m.unkeyedGrace
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.notPersisted
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
// committed its peer state. Clearing the recovery hold and reevaluating under
// one manager lock prevents election from observing an empty peer posture.
func (m *Manager) publishFreshHeartbeatProof() {
	if m == nil {
		return
	}
	gen := m.peerProofGen.Add(1)
	st := &m.unkeyedGrace
	if !st.recoveryHold.Load() || gen <= st.armedGen.Load() || !st.recoveryHold.CompareAndSwap(true, false) {
		return
	}
	m.mu.Lock()
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
