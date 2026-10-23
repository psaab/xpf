package cluster

// Durable receiver anti-replay state: the downgrade latch, the epoch floor
// and its per-value session bindings, persisted across daemon restarts
// (#16022).
//
// WHY THIS EXISTS. The latch ("the peer has proved it emits boot epochs")
// and the floor (the highest epoch ever accepted) lived only on
// Manager.hbAuth. A full daemon restart cleared both, and the 64-entry
// session ring is all that remained. An attacker holding >=65 captured
// sender incarnations — 65 peer restarts' worth, each now a distinct
// per-daemon-incarnation session — replayed after a receiver restart while
// the peer was down churns that ring indefinitely: every replayed session
// is never-seen, is admitted, and evicts the oldest watermark. Archived
// epochless frames therefore sustained forged peer liveness and delayed
// takeover for as long as the replay ran. The epoch-bearing steady state
// was already bounded (the floor is checked before the ring and the
// per-value session budget is finite); only the restart-cleared state was
// not.
//
// WHAT PERSISTS. Alongside this node's own ha-boot-epoch file: the
// accepted-key-SET-scoped record
//
//	ha-peer-epoch: <floor> <session>... <digest>\n
//
// where digest is controlAuthKeySetDigest over the accepted key set (the
// #15262 fabric-grace construction: HMAC-keyed, domain-tagged, never the
// key). The file holds the latch bit implicitly — a record exists only if
// an epoch-bearing frame was accepted under that key set — the floor, and
// the sessions bound at that floor. Persisting the BOUND SESSIONS, not
// just the floor, is load-bearing: without them a restart with the floor
// restored would hand the attacker heartbeatEpochSessionsPerEpoch fresh
// equality slots per restart, and 65 captures sharing one epoch would
// churn again across restarts.
//
// WHAT A KEY-SET CHANGE DOES. The record is scoped to the accepted key
// SET digest, so a rotation (signing key changed, or the additional key
// added/retired) stops matching: the latch and floor do not carry over,
// the next accepted epoch-bearing frame under the new set re-arms and
// re-persists, and captures under the retired key fail MAC verification
// anyway. Clearing the key set clears both the in-memory latch/floor and
// the file, so re-keying from scratch starts unlatched — the migration
// window (accept epochless until the peer proves it emits epochs) is
// preserved for a genuinely new keying, which is the same scoping the
// #15262 grace anchor uses. This is also what makes a deliberate peer
// rollback recoverable without a state-file edit: rotate the PSK on both
// nodes (which retires every capture taken under the old key), and the
// refusing node's next config apply clears the durable latch with the key
// set; the restart that used to be required is no longer the mechanism,
// though it remains harmless.
//
// ENGAGING THE RATIONALE THAT REMOVED THE DURABLE LATCH. The epochSeen
// field comment priced a durable latch and declined it on three costs.
// This design answers each in shape, not by ignoring it:
//
//   - "A durable write on the accept path, with no good failure policy."
//     The write does NOT land before the frame is accepted, and is not on
//     the accept path at all. admitAuthed only notes, under its existing
//     lock and with no I/O, that the durable record is behind; a periodic
//     sender-tick flush (peerEpochPersistInterval) plus a stop-time flush
//     write it later. The failure policy is therefore decidable: a failed
//     or wedged write degrades to exactly the pre-#16022 process-scoped
//     behaviour — the in-memory latch and floor are untouched, admission
//     never waits on storage, and the flush retries on the next tick. The
//     residual window is bounded and stated: a crash inside one flush
//     interval loses at most that interval's latch/floor advance, and a
//     same-key epochless capture taken inside it replays after the crash
//     until the peer's next genuine frame re-arms. That is strictly
//     narrower than the pre-#16022 window, which every daemon restart
//     opened in full.
//   - "Cross-process locking on that path." Locking is off the accept
//     path entirely. The flush takes the same sidecar flock discipline as
//     the sender's own boot-epoch file (withEpochFileLock: bounded
//     acquire, fail-closed skip), so two overlapping daemon incarnations
//     serialize their flushes instead of interleaving a read-modify-write;
//     a lock that cannot be taken skips the flush and leaves the in-memory
//     state authoritative.
//   - "It strictly worsens the legitimate rollback." A bare restart no
//     longer clears the latch — that is the point of the fix — but the
//     recovery procedure does not become "delete the right file": because
//     the record is key-set-scoped, the already-documented recovery
//     (rotate the PSK on both nodes) clears it as a side effect of the
//     config apply, with no file to hand-edit. The no-attacker rollback
//     now needs the rotation, which the operator warning already prescribed
//     first, rather than the rotation plus a restart.
//
// WHAT DOES NOT PERSIST, DELIBERATELY. The session ring itself (64
// watermarks). With latch+floor+sessions restored, a replayed
// epoch-bearing set is bounded exactly as it is in-process — at most
// heartbeatEpochSessionsPerEpoch sessions at the floor value, each usable
// for one ascending pass before its watermark closes — and epochless
// captures are refused by the restored latch. Persisting the ring would
// buy nothing beyond that and would put 64 session ids on disk for no
// property. A restart therefore still admits one finite ascending pass of
// an epoch-bearing capture set; it no longer admits the unbounded
// epochless churn, and it no longer forgets that the peer emits epochs.

import (
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/psaab/xpf/pkg/fsatomic"
)

// peerEpochStatePath is where the receiver's durable latch/floor record
// lives, alongside ha-boot-epoch (bootEpochPath) and the #15262 fabric
// grace anchor. A package var so tests can redirect it, mirroring
// bootEpochPath.
var peerEpochStatePath = "/var/lib/xpf/ha-peer-epoch"

// peerEpochPersistInterval bounds how stale the durable record may be:
// the sender-tick flush re-writes it at most this often, and only when
// admitAuthed has marked it behind. Ten seconds is chosen against the
// crash window it defines, not against the heartbeat cadence — the write
// is one small durable file, off the accept path, and a shorter interval
// would buy a narrower crash window at the cost of an fsync every few
// heartbeats for the life of the daemon.
const peerEpochPersistInterval = 10 * time.Second

// peerEpochPersistRetryInterval is the sender-tick retry cadence after a
// failed flush (unwritable dir, contended lock). Shorter than the success
// cadence because a failed write means the durable record is NOT advancing
// while the in-memory one is; the retry is one bounded lock attempt plus
// one small write, and only runs while a persist is owed.
const peerEpochPersistRetryInterval = time.Second

// peerEpochPersistDue reports whether the durable record is behind the
// in-memory latch/floor AND the interval gate allows a write now. It is
// the sender tick's only question, and it is cheap: two atomic loads and,
// on the not-due path, nothing else.
//
// lastFlush is stamped on ATTEMPT, not on success — a store that fails
// every write must not be retried at heartbeat rate (5-10 Hz of flock
// attempts against a wedged /var). A failed attempt therefore backs off to
// peerEpochPersistRetryInterval; a successful one to
// peerEpochPersistInterval.
func peerEpochPersistDue(dirty bool, lastFlush, now time.Time, lastOK bool) bool {
	if !dirty {
		return false
	}
	if lastFlush.IsZero() {
		return true
	}
	gap := peerEpochPersistInterval
	if !lastOK {
		gap = peerEpochPersistRetryInterval
	}
	return !now.Before(lastFlush.Add(gap))
}

// formatPeerEpochState renders the durable record: floor, then the
// sessions bound at that floor, then the accepted-key-set digest, one
// line. The digest is last so the variable-length session list needs no
// count field; parsing takes the final field as the digest and every
// field between the floor and it as a session.
func formatPeerEpochState(floor uint64, sessions []uint64, digest string) string {
	var b strings.Builder
	b.WriteString(strconv.FormatUint(floor, 10))
	for _, s := range sessions {
		b.WriteByte(' ')
		b.WriteString(strconv.FormatUint(s, 10))
	}
	b.WriteByte(' ')
	b.WriteString(digest)
	b.WriteByte('\n')
	return b.String()
}

// parsePeerEpochState parses one durable record for digest. ok=false means
// "no usable record for this key set": missing, corrupt, implausible
// floor, too many sessions, or written under a different key set. Every
// one of those degrades to the pre-#16022 fresh state (latch clear, floor
// 0), which is the migration-safe direction: a node that cannot prove the
// peer emits epochs under THIS key set must accept epochless frames until
// it can, or a wiped /var would refuse a healthy pre-upgrade peer forever.
func parsePeerEpochState(body, digest string) (floor uint64, sessions []uint64, ok bool) {
	if digest == "" {
		return 0, nil, false
	}
	fields := strings.Fields(strings.TrimSpace(body))
	if len(fields) < 2 || fields[len(fields)-1] != digest {
		return 0, nil, false
	}
	floor, err := strconv.ParseUint(fields[0], 10, 64)
	if err != nil || !epochUsableAsFloor(floor) {
		return 0, nil, false
	}
	if len(fields)-2 > heartbeatEpochSessionsPerEpoch {
		return 0, nil, false
	}
	for _, f := range fields[1 : len(fields)-1] {
		s, err := strconv.ParseUint(f, 10, 64)
		if err != nil {
			return 0, nil, false
		}
		sessions = append(sessions, s)
	}
	return floor, sessions, true
}

// loadPeerEpochState reads the durable record for digest. A missing file
// is the normal first-boot case, not an error worth logging.
func loadPeerEpochState(path, digest string) (floor uint64, sessions []uint64, ok bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, nil, false
	}
	return parsePeerEpochState(string(data), digest)
}

// persistPeerEpochState durably records floor/sessions for digest.
// Best-effort and off the accept path: a failure is logged and otherwise
// ignored, because the in-memory latch/floor remain authoritative and the
// next tick retries. A post-rename fsync failure means the record IS
// visible to the next read, so it is not reported as a failure to persist
// (the same posture as persistFabricAuthGraceAnchor).
//
// The write runs under the boot-epoch file lock for path, so two
// overlapping daemon incarnations serialize instead of interleaving;
// withEpochFileLock declines (skips fn) when the lock cannot be taken, in
// which case this reports false and the caller keeps the persist owed.
func persistPeerEpochState(path string, floor uint64, sessions []uint64, digest string) bool {
	if digest == "" || !epochUsableAsFloor(floor) {
		return false
	}
	wrote := false
	withEpochFileLock(path, func() {
		if err := fsatomic.MkdirAllDurable(filepath.Dir(path), 0o755); err != nil {
			slog.Warn("cluster: peer epoch state dir create failed; the downgrade latch stays process-scoped until a later flush (#16022)",
				"path", path, "err", err)
			return
		}
		body := formatPeerEpochState(floor, sessions, digest)
		if err := fsatomic.WriteFileDurable(path, []byte(body), 0o644); err != nil {
			var postRename *fsatomic.PostRenameSyncError
			if errors.As(err, &postRename) {
				slog.Warn("cluster: peer epoch state persisted but its durability is UNKNOWN "+
					"(the post-rename directory fsync failed; the value IS visible to the next read) (#16022)",
					"path", path, "err", err)
				wrote = true
				return
			}
			slog.Warn("cluster: peer epoch state persist failed; the downgrade latch stays process-scoped until a later flush (#16022)",
				"path", path, "err", err)
			return
		}
		wrote = true
	})
	return wrote
}

// clearPeerEpochState removes the durable record. Called when the accepted
// key set is cleared: with no key there is no digest to scope a record to,
// and a later re-keying under a different key must not resurrect a latch
// armed under the old one. A missing file is success (already clear).
func clearPeerEpochState(path string) {
	withEpochFileLock(path, func() {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			slog.Warn("cluster: peer epoch state clear failed; a later re-keying may restore a stale latch until the first flush overwrites it (#16022)",
				"path", path, "err", err)
		}
	})
}

// peerEpochBoundSessionsLocked returns the sessions bound at the current
// floor, in binding order. s.mu must be held.
func (s *heartbeatAuthState) peerEpochBoundSessionsLocked() []uint64 {
	out := make([]uint64, s.highEpochSessionCount)
	copy(out, s.highEpochSessions[:s.highEpochSessionCount])
	return out
}

// restorePeerEpochLocked installs a durable latch/floor/bindings record
// (#16022). Called under s.mu only when this process has not yet
// reconciled (peerEpochPersistChecked false), so it can never clobber a
// floor the live peer has already raised in this process: reconciliation
// runs at UpdateConfig/StartHeartbeat, before the receiver admits frames.
// A record at or below the in-memory floor leaves the bindings alone —
// they belong to the higher value.
func (s *heartbeatAuthState) restorePeerEpochLocked(floor uint64, sessions []uint64) {
	s.epochSeen = true
	if floor > s.highEpoch {
		s.highEpoch = floor
		s.highEpochSessionCount = 0
		for _, sess := range sessions {
			if s.highEpochSessionCount < len(s.highEpochSessions) {
				s.highEpochSessions[s.highEpochSessionCount] = sess
				s.highEpochSessionCount++
			}
		}
	}
}

// clearPeerEpochLocked drops the latch, floor and bindings in memory
// (#16022: the accepted key set was cleared or replaced, so the restored
// record no longer scopes to the live keys). The durable file is handled
// by the caller (UpdateConfig), which owns the key-set transition.
func (s *heartbeatAuthState) clearPeerEpochLocked() {
	s.epochSeen = false
	s.highEpoch = 0
	s.highEpochSessionCount = 0
	s.peerEpochPersistOwed = false
}

// reconcilePeerEpochState restores the durable latch/floor for digest
// (#16022). s.hbAuth.mu must NOT be held. Called from UpdateConfig (key-set
// reconciliation) and from StartHeartbeat (a fixture or embedder that set
// the key without UpdateConfig). It is idempotent per digest: once checked,
// a later call with the same digest returns without touching the file, so a
// live floor raised in this process is never clobbered by a stale record.
// A different digest drops the in-memory state first — it was armed under
// keys this node no longer accepts.
func (m *Manager) reconcilePeerEpochState(digest string) {
	if m == nil {
		return
	}
	s := &m.hbAuth
	s.mu.Lock()
	if s.peerEpochPersistChecked && s.peerEpochKeySetDigest == digest {
		s.mu.Unlock()
		return
	}
	if s.peerEpochKeySetDigest != "" && s.peerEpochKeySetDigest != digest {
		s.clearPeerEpochLocked()
	}
	s.peerEpochKeySetDigest = digest
	s.peerEpochPersistChecked = true
	// Capture whether the latch was already armed, so a record matching
	// the live floor does not replace live bindings with stale ones.
	curSeen := s.epochSeen
	s.mu.Unlock()
	floor, sessions, ok := loadPeerEpochState(peerEpochStatePath, digest)
	if !ok {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	// Re-check under the lock: a concurrent reconcile for the same digest
	// may have already restored, or live frames may have advanced the
	// state past the record. Restore only into a state the record
	// dominates or matches; never lower a live floor.
	if s.highEpoch > floor {
		return
	}
	if s.highEpoch == floor && (curSeen || s.epochSeen) {
		return
	}
	s.restorePeerEpochLocked(floor, sessions)
}

// flushPeerEpochState writes the durable latch/floor record when it is
// behind (#16022). force bypasses the interval gate (stop-time flush).
// It never blocks admission: the snapshot is taken under hbAuth.mu, the
// lock is released, and the file write happens afterwards. If the state
// advanced during the write, peerEpochPersistOwed is left set so a later
// tick writes the newer record.
func (m *Manager) flushPeerEpochState(force bool) {
	if m == nil {
		return
	}
	m.peerEpochFlushMu.Lock()
	defer m.peerEpochFlushMu.Unlock()
	now := time.Now()
	s := &m.hbAuth
	s.mu.Lock()
	digest := s.peerEpochKeySetDigest
	owed := s.peerEpochPersistOwed
	checked := s.peerEpochPersistChecked
	floor := s.highEpoch
	seen := s.epochSeen
	sessions := s.peerEpochBoundSessionsLocked()
	s.mu.Unlock()
	if digest == "" || !checked {
		return
	}
	if !seen {
		// Nothing has ever armed the latch under this key set; there is no
		// record to write. (A cleared key set is handled by UpdateConfig,
		// which removes the file; this is the never-armed case.)
		if floor != 0 {
			slog.Warn("cluster: peer epoch flush skipped for an unarmed latch with a non-zero floor; the durable record is left as-is (#16022)",
				"floor", floor)
		}
		s.mu.Lock()
		s.peerEpochPersistOwed = false
		s.mu.Unlock()
		return
	}
	if !force && !peerEpochPersistDue(owed, m.peerEpochLastFlush, now, m.peerEpochLastFlushOK) {
		return
	}
	m.peerEpochLastFlush = now
	if !persistPeerEpochState(peerEpochStatePath, floor, sessions, digest) {
		m.peerEpochLastFlushOK = false
		return
	}
	m.peerEpochLastFlushOK = true
	s.mu.Lock()
	// Clear owed only if the state has not advanced past the snapshot.
	if s.highEpoch == floor && s.highEpochSessionCount == len(sessions) {
		same := true
		for i, sess := range sessions {
			if s.highEpochSessions[i] != sess {
				same = false
				break
			}
		}
		if same {
			s.peerEpochPersistOwed = false
		}
	}
	s.mu.Unlock()
}

// maybeFlushPeerEpochState is the sender tick's flush trigger (#16022).
// Cheap when nothing is owed: one lock, two field reads.
func (m *Manager) maybeFlushPeerEpochState() {
	if m == nil {
		return
	}
	s := &m.hbAuth
	s.mu.Lock()
	owed := s.peerEpochPersistOwed
	s.mu.Unlock()
	if owed {
		m.flushPeerEpochState(false)
	}
}

// SetPeerEpochStatePathForTesting redirects the durable peer-epoch record
// file (#16022) to path and returns a restore function. Test-only,
// mirroring SetFabricAuthGraceStatePathForTesting; not for production
// callers. It exists so a simulated restart (a second Manager over the
// same path) can prove the persisted latch/floor is honoured.
func SetPeerEpochStatePathForTesting(path string) func() {
	orig := peerEpochStatePath
	peerEpochStatePath = path
	return func() { peerEpochStatePath = orig }
}
