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
//	ha-peer-epoch: <generation> <floor> <session>... <digest>\n
//
// Generation is a process-local sequence that is re-seeded above any
// persisted value on reconcile and advances on every in-memory state
// advance, binding at an unchanged floor included. Within a live process it
// orders every snapshot; during final durable writes, the sidecar flock holds
// for a read/check/write cycle so an older overlapping process cannot stamp
// a stale snapshot over a newer record.
//
// The digest is controlAuthKeySetDigest over the accepted key set (the
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
//     the accept, heartbeat-send, or shutdown path at all. admitAuthed only
//     bumps a generation and requests persistence under its existing lock;
//     one coalescing worker per Manager owns every later read/check/write.
//     Sender ticks request a flush and reap it only with a nonblocking
//     check; heartbeat and Manager teardown request a final flush and do
//     NOT join the worker, so flock/fsync latency up to and beyond the 3s
//     lock budget can never stall heartbeats or shutdown. Failure degrades
//     to exactly the pre-#16022 process-scoped behaviour — the in-memory
//     latch and floor are untouched, admission never waits on storage, and
//     the worker retries at most once per second. The residual window is a
//     crash or SIGKILL before the latest queued generation lands: that
//     interval's latch/floor advance may be lost, after which the peer's
//     next genuine frame re-arms. A clean heartbeat/Manager stop does not
//     guarantee durable landing; it only queues the best available final
//     snapshot. That is strictly narrower than the pre-#16022 window, which
//     every daemon restart opened in full.
//   - "Cross-process locking on that path." Locking is on the persistence
//     worker only. Final writes use the same sidecar flock discipline as
//     the sender's own boot-epoch file, and the flock covers a complete
//     read/generation-check/write cycle. Two overlapping daemon
//     incarnations serialize there; an older manager that somehow obtains
//     the lock after a newer record exists sees the higher generation and
//     skips rather than overwriting it. A contended or otherwise failed
//     lock leaves the in-memory state authoritative and the request owed.
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

// peerEpochPersistInterval bounds how stale the durable record may be.
// It is retained as the successful-write cadence: a generation advance
// does not request a filesystem attempt until this much time has elapsed
// since the last attempt. Ten seconds defines the worst ordinary backlog
// handed to the asynchronous worker, not heartbeat latency — requests
// only bump coalescing state and never wait for this interval or the I/O.
const peerEpochPersistInterval = 10 * time.Second

// peerEpochPersistRetryInterval is the worker's minimum spacing after a
// failed persistence attempt. A wedged store is retried at most once per
// second by the dedicated worker, never from a heartbeat send/stop path.
const peerEpochPersistRetryInterval = time.Second

// peerEpochPersistHookForTest, when non-nil, is invoked once per durable
// write attempt after that attempt's snapshot has been frozen and before
// the sidecar flock is acquired. Tests use it to prove heartbeat/Stop calls
// return while even the pre-lock portion of persistence is parked. The
// worker waits for the hook's function to return; requesters do not.
// Production never replaces it.
var peerEpochPersistHookForTest func()

// peerEpochPersistDue reports whether a due request may hand work to the
// asynchronous persistence worker now. lastAttempt is stamped before each
// worker attempt, not on success — a store that fails every write must not
// be retried at heartbeat rate. A failed attempt backs off to
// peerEpochPersistRetryInterval; a successful one to peerEpochPersistInterval.
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

type peerEpochSnapshot struct {
	generation uint64
	floor      uint64
	sessions   []uint64
	digest     string
	path       string
}

// formatPeerEpochState renders one durable record: generation, floor, the
// sessions bound at that floor, then the accepted-key-set digest. The digest
// is last so the variable-length session list needs no count field; parsing
// takes the final field as digest and every field between floor and it as a
// bound session.
func formatPeerEpochState(generation, floor uint64, sessions []uint64, digest string) string {
	var b strings.Builder
	b.WriteString(strconv.FormatUint(generation, 10))
	b.WriteByte(' ')
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
func parsePeerEpochState(body, digest string) (generation, floor uint64, sessions []uint64, ok bool) {
	if digest == "" {
		return 0, 0, nil, false
	}
	fields := strings.Fields(strings.TrimSpace(body))
	if len(fields) < 3 || fields[len(fields)-1] != digest {
		return 0, 0, nil, false
	}
	generation, err := strconv.ParseUint(fields[0], 10, 64)
	if err != nil || generation == 0 {
		return 0, 0, nil, false
	}
	floor, err = strconv.ParseUint(fields[1], 10, 64)
	if err != nil || !epochUsableAsFloor(floor) {
		return 0, 0, nil, false
	}
	if len(fields)-3 > heartbeatEpochSessionsPerEpoch {
		return 0, 0, nil, false
	}
	for _, f := range fields[2 : len(fields)-1] {
		s, err := strconv.ParseUint(f, 10, 64)
		if err != nil {
			return 0, 0, nil, false
		}
		sessions = append(sessions, s)
	}
	return generation, floor, sessions, true
}

// loadPeerEpochState reads the durable record for digest. A missing file
// is the normal first-boot case, not an error worth logging.
func loadPeerEpochState(path, digest string) (generation, floor uint64, sessions []uint64, ok bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, 0, nil, false
	}
	return parsePeerEpochState(string(data), digest)
}

// persistPeerEpochState writes snapshot only if its generation is newer
// than the record currently on disk. The sidecar flock covers the entire
// read/check/write cycle: a competing process is either before us (we read
// its generation and win only if ours is higher) or after us (it reads ours
// under its subsequent lock and skips if older). withEpochFileLock is
// fail-closed — fn does not run when the bounded flock cannot be acquired —
// so a contended lock reports skipped, not success.
func persistPeerEpochState(snapshot peerEpochSnapshot) (written, skippedNewer bool) {
	if snapshot.digest == "" || snapshot.generation == 0 || !epochUsableAsFloor(snapshot.floor) {
		return false, false
	}
	if hook := peerEpochPersistHookForTest; hook != nil {
		hook()
	}
	withEpochFileLock(snapshot.path, func() {
		if generation, _, _, ok := loadPeerEpochState(snapshot.path, snapshot.digest); ok && generation >= snapshot.generation {
			skippedNewer = true
			return
		}
		if err := fsatomic.MkdirAllDurable(filepath.Dir(snapshot.path), 0o755); err != nil {
			slog.Warn("cluster: peer epoch state dir create failed; the downgrade latch stays process-scoped until the async worker retries (#16022)",
				"path", snapshot.path, "err", err)
			return
		}
		body := formatPeerEpochState(snapshot.generation, snapshot.floor, snapshot.sessions, snapshot.digest)
		if err := fsatomic.WriteFileDurable(snapshot.path, []byte(body), 0o644); err != nil {
			var postRename *fsatomic.PostRenameSyncError
			if errors.As(err, &postRename) {
				slog.Warn("cluster: peer epoch state persisted but its durability is UNKNOWN "+
					"(the post-rename directory fsync failed; the value IS visible to the next read) (#16022)",
					"path", snapshot.path, "err", err)
				written = true
				return
			}
			slog.Warn("cluster: peer epoch state persist failed; the downgrade latch stays process-scoped until the async worker retries (#16022)",
				"path", snapshot.path, "err", err)
			return
		}
		written = true
	})
	return written, skippedNewer
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
// by the caller (UpdateConfig), which owns the key-set transition. The
// generation is deliberately preserved: it must remain monotonic within
// this process so a pre-clear snapshot cannot later look new.
func (s *heartbeatAuthState) clearPeerEpochLocked() {
	s.epochSeen = false
	s.highEpoch = 0
	s.highEpochSessionCount = 0
	s.peerEpochPersistOwed = false
}

// reconcilePeerEpochState restores the durable latch/floor for digest.
// hbAuth.mu must NOT be held on entry. The outer Manager serialization in
// reconcilePeerEpochStateSerialized is held for the complete marker/load/
// install cycle: marking checked before reading would let a concurrent
// StartHeartbeat admit against an unrestored (or stale-key) latch, while
// reading before installing without that serialization would let an older
// reconcile overwrite a newer key-set generation. The generation check
// below therefore runs again after peerEpochReconcileMu is acquired.
func (m *Manager) reconcilePeerEpochState(digest string) {
	if m == nil {
		return
	}
	m.peerEpochReconcileMu.Lock()
	defer m.peerEpochReconcileMu.Unlock()
	// Generation guard at entry: a digest that was current when a racing
	// call was queued may no longer be the Manager's accepted digest by
	// the time serialization is acquired. controlAuthKeySetDigest is
	// maintained as part of UpdateConfig, which may already hold m.mu at
	// this call site; do not take m.mu here (Go's RWMutex cannot upgrade
	// a caller-held write lock). The field is only replaced under m.mu
	// and digest strings are immutable, so this read is race-free for the
	// stale-vs-current decision; the authoritative check remains the
	// hbAuth reconcile generation re-check inside the serialized cycle.
	current := m.controlAuthKeySetDigest
	if current != "" && current != digest {
		s := &m.hbAuth
		s.mu.Lock()
		if s.peerEpochKeySetDigest == digest {
			s.clearPeerEpochLocked()
			s.peerEpochPersistChecked = false
			s.peerEpochCheckedGeneration = 0
		}
		s.mu.Unlock()
		return
	}
	m.reconcilePeerEpochStateSerialized(digest)
}

func (m *Manager) reconcilePeerEpochStateSerialized(digest string) {
	s := &m.hbAuth
	s.mu.Lock()
	gen := s.peerEpochReconcileGeneration
	if s.peerEpochPersistChecked && s.peerEpochKeySetDigest == digest &&
		s.peerEpochCheckedGeneration == gen && gen != 0 {
		s.mu.Unlock()
		return
	}
	if s.peerEpochKeySetDigest != "" && s.peerEpochKeySetDigest != digest {
		s.clearPeerEpochLocked()
	}
	s.peerEpochKeySetDigest = digest
	// Do not mark checked yet. The file read below is outside hbAuth.mu,
	// but still inside peerEpochReconcileMu, so no other reconcile can
	// install a competing key set. admit paths see checked=false and the
	// flush refuses to overwrite before the restore decision.
	s.peerEpochPersistChecked = false
	s.peerEpochCheckedGeneration = 0
	curSeen := s.epochSeen
	s.mu.Unlock()

	generation, floor, sessions, ok := loadPeerEpochState(peerEpochStatePath, digest)
	if generation == ^uint64(0) {
		// Refuse to manufacture generation 0 after overflow. This is
		// unreachable under realistic increments; preserving checked=false
		// below is rejected at install time instead.
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	// Generation re-check after acquiring the serialization: UpdateConfig
	// bumps peerEpochReconcileGeneration under hbAuth.mu before releasing
	// the key-update critical section, and reconcile holds the outer Mu for
	// its whole cycle, so by the time we are here any concurrent key-set
	// transition has either completed (and its reconcile follows ours) or
	// not yet started. If the digest changed while the outer lock was
	// somehow unavailable to an internal caller, leave unchecked/owed so
	// the newer reconcile wins rather than installing this stale record.
	if s.peerEpochKeySetDigest != digest || s.peerEpochReconcileGeneration != gen || generation == ^uint64(0) {
		return
	}
	if generation > s.peerEpochPersistGeneration {
		s.peerEpochPersistGeneration = generation
	}
	s.peerEpochPersistChecked = true
	s.peerEpochCheckedGeneration = gen
	if !ok || s.highEpoch > floor {
		return
	}
	if s.highEpoch == floor && (curSeen || s.epochSeen) {
		return
	}
	s.restorePeerEpochLocked(floor, sessions)
}

func (m *Manager) peerEpochSnapshotLocked() (peerEpochSnapshot, bool) {
	s := &m.hbAuth
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.peerEpochPersistChecked || s.peerEpochKeySetDigest == "" {
		return peerEpochSnapshot{}, false
	}
	if !s.epochSeen {
		if s.highEpoch != 0 {
			slog.Warn("cluster: peer epoch snapshot skipped for an unarmed latch with a non-zero floor; the durable record is left as-is (#16022)",
				"floor", s.highEpoch)
		}
		s.peerEpochPersistOwed = false
		return peerEpochSnapshot{}, false
	}
	if s.peerEpochPersistGeneration == 0 {
		s.peerEpochPersistGeneration = 1
	}
	return peerEpochSnapshot{
		generation: s.peerEpochPersistGeneration,
		floor:      s.highEpoch,
		sessions:   s.peerEpochBoundSessionsLocked(),
		digest:     s.peerEpochKeySetDigest,
		path:       peerEpochStatePath,
	}, true
}

// requestPeerEpochPersist coalesces advances into the sole worker. It
// performs no I/O, allocation-heavy snapshot, filesystem call, or wait on
// a running worker. Repeated requests while queued are one request.
func (m *Manager) requestPeerEpochPersist(flushNow bool) {
	if m == nil {
		return
	}
	m.peerEpochWorkMu.Lock()
	if flushNow {
		m.peerEpochFlushNow = true
	}
	m.peerEpochPersistRequested = true
	if m.peerEpochWorkerRunning {
		m.peerEpochWorkMu.Unlock()
		return
	}
	m.peerEpochWorkerRunning = true
	done := make(chan struct{}, 1)
	m.peerEpochWorkerDone = done
	m.peerEpochWorkMu.Unlock()
	go m.peerEpochPersistWorker(done)
}

func (m *Manager) peerEpochReapDone() bool {
	if m == nil {
		return true
	}
	m.peerEpochWorkMu.Lock()
	if !m.peerEpochWorkerRunning {
		m.peerEpochWorkMu.Unlock()
		return true
	}
	done := m.peerEpochWorkerDone
	m.peerEpochWorkMu.Unlock()
	if done == nil {
		return false
	}
	select {
	case <-done:
		return true
	default:
		return false
	}
}

// maybeFlushPeerEpochState queues a persistence request if one is owed.
// It is safe on heartbeat tick paths: its only operations are short locks,
// a nonblocking channel reap and, when starting the sole worker, one
// goroutine launch. It never performs or joins filesystem I/O.
func (m *Manager) maybeFlushPeerEpochState() {
	if m == nil {
		return
	}
	m.peerEpochReapDone()
	s := &m.hbAuth
	s.mu.Lock()
	owed := s.peerEpochPersistOwed
	checked := s.peerEpochPersistChecked
	s.mu.Unlock()
	if owed && checked {
		m.requestPeerEpochPersist(false)
	}
}

// flushPeerEpochState requests a final async write. Despite its historical
// name, it never joins or performs persistence. Stop paths call this and
// return while the worker is parked in (or before) filesystem I/O.
func (m *Manager) flushPeerEpochState(force bool) {
	if m == nil {
		return
	}
	m.peerEpochReapDone()
	if force {
		m.requestPeerEpochPersist(true)
		return
	}
	m.maybeFlushPeerEpochState()
}

func (m *Manager) peerEpochPersistWorker(done chan struct{}) {
	defer func() {
		m.peerEpochWorkMu.Lock()
		m.peerEpochWorkerRunning = false
		m.peerEpochWorkerDone = nil
		m.peerEpochPersistRequested = false
		m.peerEpochWorkMu.Unlock()
		done <- struct{}{}
	}()
	for {
		m.peerEpochWorkMu.Lock()
		force := m.peerEpochFlushNow
		m.peerEpochFlushNow = false
		requested := m.peerEpochPersistRequested
		m.peerEpochPersistRequested = false
		last, lastOK := m.peerEpochLastFlush, m.peerEpochLastFlushOK
		m.peerEpochWorkMu.Unlock()
		if !requested {
			return
		}
		if !force {
			if remaining := peerEpochRemaining(last, lastOK, time.Now()); remaining > 0 {
				timer := time.NewTimer(remaining)
				<-timer.C
			}
		}

		snapshot, ok := m.peerEpochSnapshotLocked()
		if !ok {
			continue
		}
		m.peerEpochWorkMu.Lock()
		m.peerEpochLastFlush = time.Now()
		m.peerEpochWorkMu.Unlock()

		written, skipped := persistPeerEpochState(snapshot)
		m.peerEpochWorkMu.Lock()
		m.peerEpochLastFlushOK = written || skipped
		m.peerEpochWorkMu.Unlock()
		if written || skipped {
			s := &m.hbAuth
			s.mu.Lock()
			if s.peerEpochKeySetDigest == snapshot.digest && s.peerEpochPersistGeneration == snapshot.generation {
				s.peerEpochPersistOwed = false
			}
			s.mu.Unlock()
		}

		// Coalesce work that arrived during I/O. A new generation is always
		// another request. An unchanged failed generation gets a scheduled
		// retry inside this worker invocation: lastFlushOK is now false, so
		// the next cycle waits peerEpochPersistRetryInterval rather than
		// spinning. If that retry also fails, the following cycle repeats
		// at the same worker-owned cadence while requests remain owed; no
		// heartbeat or stop caller ever waits for it.
		s := &m.hbAuth
		s.mu.Lock()
		owed := s.peerEpochPersistOwed
		checked := s.peerEpochPersistChecked
		advanced := s.peerEpochPersistGeneration != snapshot.generation || s.peerEpochKeySetDigest != snapshot.digest
		s.mu.Unlock()
		m.peerEpochWorkMu.Lock()
		if owed && checked && (advanced || !written) {
			m.peerEpochPersistRequested = true
		}
		if !m.peerEpochPersistRequested {
			m.peerEpochWorkMu.Unlock()
			return
		}
		m.peerEpochWorkMu.Unlock()
	}
}

func peerEpochRemaining(last time.Time, lastOK bool, now time.Time) time.Duration {
	if last.IsZero() {
		return 0
	}
	gap := peerEpochPersistInterval
	if !lastOK {
		gap = peerEpochPersistRetryInterval
	}
	d := last.Add(gap).Sub(now)
	if d < 0 {
		return 0
	}
	return d
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
