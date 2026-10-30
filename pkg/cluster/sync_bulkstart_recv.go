package cluster

import (
	"encoding/binary"
	"log/slog"
	"net"
	"time"

	"github.com/psaab/xpf/pkg/dataplane"
)

// handleBulkStart is the BulkStart receive handler, extracted verbatim
// from handleMessage LAST (#16168), preserving the ORDER MATTERS
// sequence at the top of the original arm statement-for-statement:
// both incarnation records land before the generation reset below.
func (s *SessionSync) handleBulkStart(conn net.Conn, payload []byte) bool {
	var epoch uint64
	if len(payload) >= 8 {
		epoch = binary.LittleEndian.Uint64(payload[:8])
	}
	// #5084: the peer's boot incarnation, when it sent one. Recorded on the
	// CONNECTION so every config payload arriving on it is stamped with the
	// incarnation that primed it, and compared against the receiver-wide
	// current incarnation to decide a namespace switch.
	//
	// ORDER MATTERS: both records land BEFORE resetRecvGen below. Reversing
	// them opens a window in which the high-waters are already zeroed while
	// the current incarnation is still the DEAD one, so a prior-boot payload
	// dequeued by configApplyLoop in that window passes the fence and
	// records its (large) generation — the exact defect this exists to
	// close. In this order there is no such window.
	//
	// Not covered by a test, and deliberately called out rather than left
	// implied: binding it would mean interleaving the apply-loop goroutine
	// between two adjacent statements here, which no deterministic fixture
	// in this package can do. A mutation moving both records after the
	// reset leaves the whole suite green.
	inc := parseBootIncarnation(payload)
	s.noteConnBootIncarnation(conn, inc)
	// #6910: capture the PRIOR incarnation before the note overwrites it —
	// distinguishing a first prime (zero -> X) from a reboot (X -> Y)
	// requires the old value, and notePeerBootIncarnation's bool does not
	// carry it.
	priorInc := s.PeerBootIncarnation()
	switched := s.notePeerBootIncarnation(inc)
	// #2198 F2: the peer is re-priming its authoritative live set. Reset
	// our stored generations so a rebooted peer's bulk (whose genCounter
	// restarted lower) is accepted by the install guard instead of being
	// refused as stale (stale-RETAIN, the inverse of #2170).
	zoneSnap := s.snapshotZoneOwnership()
	s.bulkMu.Lock()
	// #8966: GUARD THE START THE WAY THE END IS GUARDED.
	//
	// `BulkEnd` at the bottom of this function refuses an epoch that does
	// not match the in-progress one. `BulkStart` compared nothing: it
	// assigned `bulkRecvEpoch` unconditionally and reset the accumulators,
	// so a delayed or reordered BulkStart carrying a LOWER epoch -- the
	// ordinary case with two fabric streams -- discarded the newer bulk's
	// accumulated receive set, after which the newer BulkEnd was rejected
	// as mismatched. Two handlers disagreeing about which epoch is
	// authoritative, and only one of them checking.
	//
	// THE #2198 F2 RATIONALE ABOVE IS TRUE AND COVERS A DIFFERENT CASE. A
	// rebooted peer legitimately restarts its genCounter lower, and
	// refusing that bulk would strand the standby. But the code could not
	// tell "the peer rebooted and is re-priming" from "an older BulkStart
	// arrived late on the other stream", and applied the reboot treatment
	// to both.
	//
	// `switched` -- already computed above for #6910's fabric preference --
	// is exactly that discriminator, so the information was in hand and
	// simply not consulted by the code that needed it. Across an
	// incarnation change, keep accept-and-reset: that IS the #2198 case.
	// Within one incarnation, a BulkStart must be strictly newer.
	//
	// #9174 V015: the same question is asked BETWEEN bulks, where the
	// original guard could not reach. See bulkStartStaleLocked.
	if s.bulkStartStaleLocked(epoch, inc, switched) {
		inProgress := s.bulkRecvEpoch
		active := s.bulkInProgress
		v4, v6 := len(s.bulkRecvV4), len(s.bulkRecvV6)
		s.bulkMu.Unlock()
		slog.Warn("cluster sync: ignoring stale BulkStart within the same boot incarnation",
			"in_progress_epoch", inProgress, "got_epoch", epoch,
			"bulk_in_progress", active,
			"accumulated_v4", v4, "accumulated_v6", v6,
			"peer_incarnation", inc)
		return false
	}
	s.bulkInProgress = true
	s.bulkRecvSerial++
	if s.bulkRecvSerial == 0 {
		s.bulkRecvSerial++
	}
	s.inventoryActive = s.inventoryPending
	s.inventoryActiveGeneration = s.inventoryPendingGeneration
	if !s.inventoryActive {
		s.inventoryActiveGeneration = 0
	}
	s.bulkRecvEpoch = epoch
	// #9174 V013: remember WHICH BOOT started this bulk, so its end marker
	// can be matched on more than the epoch. Recorded on the accepted path
	// only, beside the epoch it belongs to.
	s.bulkRecvIncarnation = inc
	// #9716: and WHICH CONNECTION carried it. Its BulkEnd is accepted only
	// there; see the BulkEnd arm.
	s.bulkRecvConn = conn
	s.bulkRecvStartedAt = s.bulkRecvNow()
	s.bulkRecvInvalid = false
	s.bulkRecvV4 = make(map[dataplane.SessionKey]struct{})
	s.bulkRecvV6 = make(map[dataplane.SessionKeyV6]struct{})
	s.bulkInstallFailedV4 = make(map[dataplane.SessionKey]struct{})
	s.bulkInstallFailedV6 = make(map[dataplane.SessionKeyV6]struct{})
	s.bulkZoneSnapshot = zoneSnap
	s.bulkMu.Unlock()
	// The generation reset moves to the ACCEPTED path only. It is the
	// #2198 F2 remedy for a re-priming peer. A DIFFERENT known boot
	// incarnation, or an un-incarnated legacy BulkStart, has no comparable
	// generation namespace and therefore gets the historical full reset.
	// A SAME known incarnation still reclaims live high-waters from the
	// previous authoritative window while retaining delete tombstones for
	// post-fence stale rows.
	//
	// It stays OUTSIDE `bulkMu`, where it has always been. `resetRecvGen`
	// takes `recvGenMu`, and pulling it inside would add a bulkMu ->
	// recvGenMu edge to the lock graph as a side effect of a correctness
	// fix -- a change nothing here needs and nobody would look for.
	if !inc.known() || (switched && priorInc.known()) {
		s.resetRecvGen()
	} else {
		s.reclaimRecvLiveGen()
	}
	// #9177 V052: the bulk TELEMETRY belongs on the accepted path too, and
	// it used to run above the accept. A REFUSED BulkStart -- the reordered
	// one #8966's own text calls "the ordinary case" with two fabric
	// streams -- re-stamped BulkSyncStartTime and zeroed BulkSyncEndTime on
	// its way to being rejected. `show chassis cluster information` then
	// read "Bulk sync in progress since ..." indefinitely, because the
	// BulkEnd that would set an end time belongs to a bulk that was never
	// accepted; and while that pair read open, every subsequent INCREMENTAL
	// install was counted as bulk traffic (the session handlers now key
	// that count on bulkInProgress, #15254, but the pair is still what
	// status renders).
	//
	// This is a statement-ORDERING defect, not an epoch-validation one: the
	// accept itself is correct. The #8966 author moved `resetRecvGen` below
	// the accept for exactly this reason and left these three where they
	// were, which is why they now sit beside it. The abandoned-accept twin
	// (#15254: accepted, then every fabric drops) is closed at the other
	// edge: handleDisconnect stamps an end when it clears a live window.
	s.stats.BulkSyncStartTime.Store(time.Now().UnixNano())
	s.stats.BulkSyncEndTime.Store(0)
	s.stats.BulkSyncSessions.Store(0)
	// #6910: ACT on the switch, do not merely report it. Until now
	// `switched` reached only this log line, so a reboot whose replacement
	// primed on the alternate fabric left the corpse installed, stamped
	// current, and winning fab0 preference in preferredFabricLocked — the
	// consequence the issue is actually about.
	//
	// This is peer-supplied evidence, not a local inference: the boot id on
	// the wire changed, which only a new peer boot produces. installConn
	// deliberately refuses to guess from slot occupancy; here there is
	// nothing to guess.
	//
	// Scoped to the connection that PRIMED. A replacement that never primes
	// carries no boot id (connBootIncarnation is zero for it, fail-open by
	// design), so this cannot reach that case — see the LIMIT comment in
	// installConn and #7762.
	//
	// GUARDED ON THE PRIOR VALUE BEING KNOWN, and this is not a nicety.
	// notePeerBootIncarnation reports `switched` for zero -> X as well as
	// for X -> Y, because both change the recorded incarnation. Only the
	// second is a REBOOT; the first is simply the first incarnated prime
	// this SessionSync has seen. Acting on it would advance the incarnation
	// and evict the peer's OTHER fabric — a healthy connection from the same
	// boot — which is the routine second-fabric case #5718's tests exist to
	// protect. So the remedy needs "we knew a DIFFERENT boot before", which
	// `switched` alone does not say.
	// #9636: this switch is one of TWO reboot classifiers, and
	// classifyPrimeLocked reconciles it with installConn's epoch arm. It
	// also settles an epoch retirement on a prime whose boot id did not
	// change, so it runs for every accepted BulkStart, not only a switch.
	s.mu.Lock()
	pc := s.classifyPrimeLocked(conn, switched, priorInc.known())
	s.mu.Unlock()
	if pc.announce && s.OnPeerConnected != nil {
		// No install classified this reboot, so the new process's
		// OnPeerConnected comes from here.
		slog.Info("cluster sync: scheduling OnPeerConnected callback for a peer reboot classified by its boot id",
			"remote", connRemoteAddrString(conn))
		s.dispatchPeerEvent(s.OnPeerConnected)
	}
	if pc.announce && s.OnPeerReconnected != nil {
		// #17056: same per-connection reset as the install dispatch in
		// handleNewConnection — this BulkStart announces a reboot the
		// install did not, so without firing here a reconnect classified
		// only by its boot id would keep the prior connection's stamp.
		go s.OnPeerReconnected()
	}
	if pc.retired && !pc.announce {
		// The connection's install already dispatched OnPeerConnected.
		// Its capability callback may have reconciled before this switch
		// and been rejected by the incarnation generation change, so
		// trigger one fresh pass against the restored per-connection state.
		if cb := s.OnPeerCapabilitiesChanged; cb != nil {
			go cb()
		}
	}
	slog.Info("cluster sync: bulk transfer starting", "epoch", epoch,
		"peer_boot_incarnation", inc.String(), "incarnation_switched", switched,
		"retired_incarnation", pc.retired, "reboot_already_retired", pc.consumed,
		"evicted_stale_incarnation_conn", pc.evicted,
		"local", connLocalAddrString(conn), "remote", connRemoteAddrString(conn))
	// #5084: a peer that primes without an incarnation gets today's
	// generation-only ordering (fail open). Warn ONCE per connection, not
	// per frame — a silent fallback is how a half-upgraded cluster hides,
	// and the CLAUDE.md logging rule forbids the per-frame version.
	if !inc.known() {
		s.warnUnincarnatedPrimeOnce(conn)
	}
	return true
}
