package userspace

// Session-table mutation entry points for the userspace dataplane: the
// dataplane.DataPlane install/delete/batch/clear verbs, the #5305
// transactional cluster-synced install (BPF pre-image snapshot + rollback on
// mirror failure), the chunked authoritative helper deletes, and the bulk
// event-stream session export. Each writes the BPF mirror and mirrors the
// change to the authoritative Rust helper.

import (
	"errors"
	"fmt"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/psaab/xpf/pkg/dataplane"
)

// ExportAllSessionsViaEventStream tells the Rust helper to push all current
// sessions through the event stream as Open events. The Go daemon receives
// them via handleEventStreamDelta and queues them to the peer automatically.
// This replaces the old BulkSync path that iterated BPF maps from Go.
func (m *Manager) ExportAllSessionsViaEventStream() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.proc == nil || m.proc.Process == nil {
		return errors.New("userspace dataplane helper not running")
	}
	var status ProcessStatus
	if err := m.requestLocked(ControlRequest{Type: "export_all_sessions"}, &status); err != nil {
		return err
	}
	return m.applyHelperStatusLocked(&status)
}

func (m *Manager) SetSessionV4(key dataplane.SessionKey, val dataplane.SessionValue) error {
	if err := m.bpfShim.SetSessionV4(key, val); err != nil {
		return err
	}
	if !shouldMirrorUserspaceSession(val.IsReverse) {
		return nil
	}
	m.mirrorSessionV4(key, val)
	return nil
}

// mirrorSessionV4 mirrors a locally installed forward session to the Rust
// helper. ONE upsert, not two (#8015).
//
// It used to send the forward AND an explicitly built `is_reverse=1` companion
// (#310, "the Rust worker must have the companion before RG activation"). That
// second request was redundant: `upsert_synced_session`
// (`userspace-dp/src/afxdp/ha/session_import.rs`) calls
// `synthesized_synced_reverse_entry` for EVERY non-reverse import — a total
// function, `Some` on every forward — and publishes both halves through
// `publish_shared_session`, which is why the #5674 aggregate ENTRY cap is sized
// at 2x the logical session ceiling. So a single forward upsert already leaves
// a complete pair, and it leaves a BETTER one: the helper resolves the
// companion's egress/FIB, fabric/tunnel and owner-RG against live node-local
// state, where this side could only copy the forward's (#5698). Synthesis also
// happens AT IMPORT, which is strictly earlier than this pre-install, so #310's
// invariant is satisfied by the request that remains.
//
// What the second request added was a failure mode. If the helper REFUSED the
// forward (a semantic refusal such as `RejectedCapacity`, not a transport
// failure — those abort the batch) the explicit reverse still went out and
// published alone: a reverse-only entry with no forward, which no later forward
// delete removes because `delete_synced_session_gen` derives the companion from
// the STORED forward and there is none. Sending one request removes that state
// rather than reporting it; the helper additionally REFUSES a standalone
// `is_reverse=1` upsert now, so the shape cannot be reintroduced from any
// sender.
//
// With one request the #5007 single-snapshot build and the #5698 contiguous
// transmit are both vacuous — there is no second half to resolve against a
// different `m.lastSnapshot` or to be interleaved away from — so this takes the
// ordinary per-request path. The mirror stays best-effort: the IPC error is
// dropped because the periodic session sync reconciles a transient miss, and a
// single request can no longer half-apply.
func (m *Manager) mirrorSessionV4(key dataplane.SessionKey, val dataplane.SessionValue) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.proc == nil {
		return
	}
	_ = m.syncSessionV4Locked("upsert", key, &val)
}

func (m *Manager) SetClusterSyncedSessionV4(key dataplane.SessionKey, val dataplane.SessionValue) error {
	installVal := val
	// The peer owns this row: strip every node-local field before it reaches
	// this node's maps or the helper. Single-sourced in
	// dataplane.SessionValue.ScrubNodeLocal (#7097) — this site kept its own
	// copy of the list and it silently stopped covering the #4983 ingress
	// identity when #6928 added it to the ABI. THIS is the site production
	// reaches: the session_store.go fallback runs only when the dataplane does
	// not implement clusterSyncedSessionInstaller, which the userspace manager
	// does.
	installVal.ScrubNodeLocal()
	// The helper already synthesizes the correct reverse companion from the
	// forward cluster-synced entry using local forwarding and HA state. An
	// explicit reverse cluster update can overwrite that locally-derived
	// companion with peer NAT/FIB metadata, so only mirror forward entries. A
	// reverse entry is never mirrored, so there is no mirror failure to
	// compensate: write the BPF mirror and return.
	if !shouldMirrorUserspaceSession(val.IsReverse) {
		return m.bpfShim.SetSessionV4(key, installVal)
	}
	// Forward entry: make the install transactional (#5305). Capture the
	// pre-image of the BPF session entry BEFORE writing it, then mirror to the
	// helper. On mirror failure RESTORE the pre-image (rewrite the prior value,
	// or DELETE the key if it was absent) so a failed cluster-synced install
	// leaves the BPF map exactly as it was. Otherwise the pinned map holds a
	// session the helper never received — a split truth the GC and fallback
	// bulk export would propagate as if the install had succeeded, producing
	// nondeterministic HA session ownership after takeover.
	//
	// snapshot + write + mirror + compensate run under m.mu so the sequence is
	// atomic w.r.t. any other m.mu-holding path; the per-peer receiver apply
	// loop is single-threaded (pkg/cluster/sync_conn.go installClusterSyncedV4),
	// so no concurrent install of the SAME key races. syncSessionV4Locked drops
	// m.mu only for the socket send and reacquires it before returning, so the
	// compensate that follows still observes our own BPF write.
	m.mu.Lock()
	defer m.mu.Unlock()
	prior, hadPrior, err := m.snapshotBPFSessionV4Locked(key)
	if err != nil {
		// The pre-image could not be read; refuse the install rather than write
		// an entry that could not later be rolled back on a mirror failure.
		return fmt.Errorf("snapshot synced v4 session pre-image: %w", err)
	}
	if err := m.bpfShim.SetSessionV4(key, installVal); err != nil {
		return err
	}
	if err := m.syncSessionV4Locked("upsert", key, &installVal); err != nil {
		m.noteSyncedMirrorFailureLocked(err)
		compErr := m.restoreBPFSessionV4Locked(key, prior, hadPrior)
		return errors.Join(
			fmt.Errorf("mirror synced v4 session to userspace helper: %w", err),
			compErr,
		)
	}
	// A successful mirror proves the helper session socket is healthy again;
	// clear any sticky failure so the standby regains takeover-readiness
	// without waiting for a helper restart (#5247).
	m.recordSessionMirrorSuccessLocked()
	return nil
}

// bpfSessionReadAbsent reports whether a bpfShim session GET error means the
// key is ABSENT rather than a hard read failure. The transactional snapshot
// (#5305) treats an absent pre-image as existed=false with a nil error so a
// later mirror-failure rollback DELETES the freshly-installed key; any OTHER
// read error is surfaced so the install is refused rather than leaving an
// entry that could not be rolled back (the fail-safe direction).
//
// It accepts the SAME key-absent error set as the Layer-1
// dataplane.sessionNotFound predicate — ebpf.ErrKeyNotExist OR unix.ENOENT,
// via the shared dataplane.IsKeyNotFound helper — so the two transaction
// layers agree on what "key absent" means (#6194). With the production cilium
// bpfShim the two sentinels never diverge (a missing lookup yields
// ErrKeyNotExist, not bare ENOENT), so this is a consistency fix, not a live
// bug; sharing one predicate removes the latent skew.
func bpfSessionReadAbsent(err error) bool {
	return dataplane.IsKeyNotFound(err)
}

// snapshotBPFSessionV4Locked reads the current BPF-mirror value for key so a
// failed cluster-synced install can be rolled back to it (#5305). Returns
// (value, existed, err); a missing key is existed=false with a nil error.
// Named "Locked" for the m.mu convention of the compensation sequence — it
// touches only the independently-locked bpfShim map, not m.mu directly.
func (m *Manager) snapshotBPFSessionV4Locked(key dataplane.SessionKey) (dataplane.SessionValue, bool, error) {
	val, err := m.bpfShim.GetSessionV4(key)
	if err != nil {
		if bpfSessionReadAbsent(err) {
			return dataplane.SessionValue{}, false, nil
		}
		return dataplane.SessionValue{}, false, err
	}
	return val, true, nil
}

// restoreBPFSessionV4Locked reverts the BPF session entry for key to the
// pre-install snapshot: rewrite the prior value, or delete the key if it was
// absent (#5305). Deleting an already-absent key is treated as success.
func (m *Manager) restoreBPFSessionV4Locked(key dataplane.SessionKey, prior dataplane.SessionValue, hadPrior bool) error {
	if hadPrior {
		if err := m.bpfShim.SetSessionV4(key, prior); err != nil {
			return fmt.Errorf("restore synced v4 session pre-image: %w", err)
		}
		return nil
	}
	if err := m.bpfShim.DeleteSession(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("remove orphan synced v4 session: %w", err)
	}
	return nil
}

func (m *Manager) SetSessionV6(key dataplane.SessionKeyV6, val dataplane.SessionValueV6) error {
	if err := m.bpfShim.SetSessionV6(key, val); err != nil {
		return err
	}
	if !shouldMirrorUserspaceSession(val.IsReverse) {
		return nil
	}
	m.mirrorSessionV6(key, val)
	return nil
}

// mirrorSessionV6 is the IPv6 analogue of mirrorSessionV4 — see that method
// for why the explicit reverse companion is gone (#8015).
func (m *Manager) mirrorSessionV6(key dataplane.SessionKeyV6, val dataplane.SessionValueV6) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.proc == nil {
		return
	}
	_ = m.syncSessionV6Locked("upsert", key, &val)
}

func (m *Manager) SetClusterSyncedSessionV6(key dataplane.SessionKeyV6, val dataplane.SessionValueV6) error {
	installVal := val
	// The peer owns this row: strip every node-local field before it reaches
	// this node's maps or the helper. Single-sourced in
	// dataplane.SessionValue.ScrubNodeLocal (#7097) — this site kept its own
	// copy of the list and it silently stopped covering the #4983 ingress
	// identity when #6928 added it to the ABI. THIS is the site production
	// reaches: the session_store.go fallback runs only when the dataplane does
	// not implement clusterSyncedSessionInstaller, which the userspace manager
	// does.
	installVal.ScrubNodeLocal()
	// Reverse entries are never mirrored (see SetClusterSyncedSessionV4): write
	// the BPF mirror and return — no mirror failure to compensate.
	if !shouldMirrorUserspaceSession(val.IsReverse) {
		return m.bpfShim.SetSessionV6(key, installVal)
	}
	// Forward entry: transactional install (#5305) — the IPv6 analogue of
	// SetClusterSyncedSessionV4. Snapshot the BPF pre-image, write, mirror, and
	// restore the pre-image on mirror failure so a failed install never leaves
	// an orphan split-truth BPF entry the helper never received.
	m.mu.Lock()
	defer m.mu.Unlock()
	prior, hadPrior, err := m.snapshotBPFSessionV6Locked(key)
	if err != nil {
		return fmt.Errorf("snapshot synced v6 session pre-image: %w", err)
	}
	if err := m.bpfShim.SetSessionV6(key, installVal); err != nil {
		return err
	}
	if err := m.syncSessionV6Locked("upsert", key, &installVal); err != nil {
		m.noteSyncedMirrorFailureLocked(err)
		compErr := m.restoreBPFSessionV6Locked(key, prior, hadPrior)
		return errors.Join(
			fmt.Errorf("mirror synced v6 session to userspace helper: %w", err),
			compErr,
		)
	}
	// A successful mirror proves the helper session socket is healthy again;
	// clear any sticky failure so the standby regains takeover-readiness
	// without waiting for a helper restart (#5247).
	m.recordSessionMirrorSuccessLocked()
	return nil
}

// snapshotBPFSessionV6Locked is the IPv6 sibling of snapshotBPFSessionV4Locked
// (#5305).
func (m *Manager) snapshotBPFSessionV6Locked(key dataplane.SessionKeyV6) (dataplane.SessionValueV6, bool, error) {
	val, err := m.bpfShim.GetSessionV6(key)
	if err != nil {
		if bpfSessionReadAbsent(err) {
			return dataplane.SessionValueV6{}, false, nil
		}
		return dataplane.SessionValueV6{}, false, err
	}
	return val, true, nil
}

// restoreBPFSessionV6Locked is the IPv6 sibling of restoreBPFSessionV4Locked
// (#5305).
func (m *Manager) restoreBPFSessionV6Locked(key dataplane.SessionKeyV6, prior dataplane.SessionValueV6, hadPrior bool) error {
	if hadPrior {
		if err := m.bpfShim.SetSessionV6(key, prior); err != nil {
			return fmt.Errorf("restore synced v6 session pre-image: %w", err)
		}
		return nil
	}
	if err := m.bpfShim.DeleteSessionV6(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("remove orphan synced v6 session: %w", err)
	}
	return nil
}

func shouldMirrorUserspaceSession(isReverse uint8) bool {
	return isReverse == 0
}

// deleteScopeVal returns the minimal SessionValue that carries ONLY a routing
// domain onto a "delete" sync request, or nil when there is no domain to name.
//
// #9146: a delete built with a nil value carries routing_domain 0, which the
// helper reads as WIRE_ABSENT and resolves by PROBING every routing instance for
// the bare 5-tuple. When two tenants hold that tuple the probe is ambiguous and
// the helper REFUSES the delete (#8636). Naming the domain the session was
// installed under makes the exact delete land, so the probe never runs.
//
// It is deliberately minimal rather than the whole value: a delete needs the key
// and the domain, and forwarding a full value would put zone/NAT/ifindex fields
// on a request that has no use for them.
func deleteScopeVal(routingDomain uint32) *dataplane.SessionValue {
	if routingDomain == 0 {
		return nil
	}
	return &dataplane.SessionValue{RoutingDomain: routingDomain}
}

// deleteScopeValV6 is the IPv6 analogue of deleteScopeVal (#9146/#9364).
//
// #9146 wrote its V6 scope inline in syncDeleteV6Locked; #9364 needs the same
// derivation from a second call site, and two copies of "nil at 0, else a
// domain-only value" is the drift the one-formula rule exists to prevent.
func deleteScopeValV6(routingDomain uint32) *dataplane.SessionValueV6 {
	if routingDomain == 0 {
		return nil
	}
	return &dataplane.SessionValueV6{RoutingDomain: routingDomain}
}

func (m *Manager) DeleteSession(key dataplane.SessionKey) error {
	// Look up the session value BEFORE deleting from the BPF map so we
	// can retrieve the ReverseKey for the pre-installed companion (#351).
	val, valErr := m.bpfShim.GetSessionV4(key)

	if err := m.bpfShim.DeleteSession(key); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	// #9146: the value is already in hand — it was fetched above for the
	// ReverseKey — and its routing domain used to be discarded here, so the
	// delete went out naming a bare 5-tuple while the INSTALL that created the
	// row had named its domain. Measured on the wire:
	//
	//	upsert tenant A: 10.0.0.5:1234->10.0.0.9:443/6 routing_domain=100007
	//	upsert tenant B: 10.0.0.5:1234->10.0.0.9:443/6 routing_domain=100008
	//	DELETE         : 10.0.0.5:1234->10.0.0.9:443/6 routing_domain=0
	//
	// The standby keys synced sessions BY domain, so it holds both tenants'
	// rows; a bare delete then matches two and the helper refuses it
	// (#8636 ambiguous-routing-domain). #8636's acceptance for refusing — "a
	// refused delete leaks for ONE PACKET, not until idle timeout", because
	// #8356 re-derives zone policy on the established-session hit path — was
	// written for the operator `clear security flow session` caller. It does not
	// transfer to a STANDBY, where a synced session receives no packets and
	// nothing re-judges it: it leaks until its idle timeout and is then promoted
	// on failover.
	m.syncDeleteV4Locked(key, val, valErr == nil)
	return nil
}

// syncDeleteV4Locked sends the helper deletes for a removed v4 session: the
// forward key, and the reverse companion SetSessionV4 pre-installed. Both name
// the session's routing domain when one is known.
//
// It is a named function rather than four lines inside DeleteSession so the
// scope derivation can be DRIVEN by a cell. DeleteSession itself reads and
// writes real BPF maps, so a cell for it skips wherever CAP_BPF is unavailable —
// and a skipping cell scores a mutation as survived, which is the reading that
// argues for deleting a guard doing its job.
func (m *Manager) syncDeleteV4Locked(key dataplane.SessionKey, val dataplane.SessionValue, haveVal bool) {
	m.syncDeleteV4LockedMarked(key, val, haveVal, false)
}

// syncDeleteV4LockedMarked is syncDeleteV4Locked with the #9714 peer mark set on
// both helper requests (the key and its reverse companion). It reports whether the
// helper REFUSED the marked delete of the key; a refused key keeps its reverse
// companion, so that request is not sent.
func (m *Manager) syncDeleteV4LockedMarked(key dataplane.SessionKey, val dataplane.SessionValue, haveVal, peer bool) bool {
	if m.proc == nil {
		return false
	}
	scope := (*dataplane.SessionValue)(nil)
	if haveVal {
		scope = deleteScopeVal(val.RoutingDomain)
	}
	req := m.buildSessionSyncRequestV4("delete", key, scope)
	req.PeerDelete = peer
	if err := m.syncSessionRequestLocked(req); peer && peerDeleteRefused(err) {
		return true
	}
	// The reverse companion is the same flow in the same tenant, so it carries
	// the same domain.
	if haveVal && val.ReverseKey.Protocol != 0 {
		reverse := m.buildSessionSyncRequestV4("delete", val.ReverseKey, scope)
		reverse.PeerDelete = peer
		_ = m.syncSessionRequestLocked(reverse)
	}
	return false
}

func (m *Manager) DeleteSessionV6(key dataplane.SessionKeyV6) error {
	// Look up the session value BEFORE deleting from the BPF map so we
	// can retrieve the ReverseKey for the pre-installed companion (#351).
	val, valErr := m.bpfShim.GetSessionV6(key)

	if err := m.bpfShim.DeleteSessionV6(key); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	// #9146: same as DeleteSession — name the domain the row was installed
	// under instead of sending a bare tuple the standby has to guess at.
	m.syncDeleteV6Locked(key, val, valErr == nil)
	return nil
}

// syncDeleteV6Locked is the IPv6 analogue of syncDeleteV4Locked (#9146).
func (m *Manager) syncDeleteV6Locked(key dataplane.SessionKeyV6, val dataplane.SessionValueV6, haveVal bool) {
	m.syncDeleteV6LockedMarked(key, val, haveVal, false)
}

// syncDeleteV6LockedMarked is the IPv6 analogue of syncDeleteV4LockedMarked (#9714).
func (m *Manager) syncDeleteV6LockedMarked(key dataplane.SessionKeyV6, val dataplane.SessionValueV6, haveVal, peer bool) bool {
	if m.proc == nil {
		return false
	}
	scope := (*dataplane.SessionValueV6)(nil)
	if haveVal {
		scope = deleteScopeValV6(val.RoutingDomain)
	}
	req := m.buildSessionSyncRequestV6("delete", key, scope)
	req.PeerDelete = peer
	if err := m.syncSessionRequestLocked(req); peer && peerDeleteRefused(err) {
		return true
	}
	if haveVal && val.ReverseKey.Protocol != 0 {
		reverse := m.buildSessionSyncRequestV6("delete", val.ReverseKey, scope)
		reverse.PeerDelete = peer
		_ = m.syncSessionRequestLocked(reverse)
	}
	return false
}

// DeletePeerSyncedSession deletes a session on behalf of the PEER (#9714). The
// helper answers FIRST, marked so it can refuse the delete for a live local session
// whose owner RG is locally active; a refused delete keeps the BPF mirror row and
// reports true. The mirror row may already be gone (the store calls this when its
// lookup found nothing), and the helper is asked all the same: before this, the
// failed mirror delete returned before the helper was contacted, so a helper-only
// stale session was never retracted.
func (m *Manager) DeletePeerSyncedSession(key dataplane.SessionKey) (bool, error) {
	val, valErr := m.bpfShim.GetSessionV4(key)
	m.mu.Lock()
	refused := m.syncDeleteV4LockedMarked(key, val, valErr == nil, true)
	m.mu.Unlock()
	if refused {
		return true, nil
	}
	if err := m.bpfShim.DeleteSession(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return false, err
	}
	return false, nil
}

// DeletePeerSyncedSessionV6 is the IPv6 analogue of DeletePeerSyncedSession (#9714).
func (m *Manager) DeletePeerSyncedSessionV6(key dataplane.SessionKeyV6) (bool, error) {
	val, valErr := m.bpfShim.GetSessionV6(key)
	m.mu.Lock()
	refused := m.syncDeleteV6LockedMarked(key, val, valErr == nil, true)
	m.mu.Unlock()
	if refused {
		return true, nil
	}
	if err := m.bpfShim.DeleteSessionV6(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return false, err
	}
	return false, nil
}

// sessionHelperDeleteChunk bounds how many per-session helper "delete" IPCs the
// batch/clear session paths transmit under a single control-socket unlock so a
// large clear stays cooperative and cannot monopolize the shared control socket
// (#5096). syncSessionRequestsLocked drops and reacquires m.mu once per chunk,
// giving a concurrent snapshot publish a window between chunks, and takes
// m.sessionMu once per REQUEST so live session installs can interleave INSIDE a
// chunk. A chunk this large deliberately stays interleavable: holding
// m.sessionMu across 256 round trips would starve live session installs for
// minutes (#5380).
const sessionHelperDeleteChunk = 256

// BatchDeleteSessions deletes a batch of IPv4 sessions from the BPF mirror AND
// issues an authoritative "delete" to the Rust helper for every key (#5096).
//
// The LegacyDataPlaneAdapter embeds the bpfShim as its dataplane.DataPlane, so
// without this method Go promotion would dispatch a batch delete to the mirror
// map ONLY — leaving the helper, which owns packet lookup/lifetime, forwarding
// under the just-revoked decision until it re-publishes the mirror ~10s later.
// The singular DeleteSession already routes per-session deletes to the helper;
// this does the same for the batch path used by policy invalidation and the
// cluster-stale sweep. The bpf mirror's delete count is returned unchanged so
// caller count semantics are preserved.
func (m *Manager) BatchDeleteSessions(keys []dataplane.SessionKey) (int, error) {
	deleted, err := m.bpfShim.BatchDeleteSessions(keys)
	// Attempt the helper delete for every key regardless of the mirror result:
	// a batch where a key vanished concurrently returns ErrKeyNotExist with a
	// partial count, and the helper delete of an already-absent key is a no-op,
	// so skipping on error would strand the still-present helper sessions.
	//
	// The batch path (policy invalidation, cluster-stale sweep) keeps the
	// #5096 best-effort contract — the periodic session sync and GC delta
	// reconcile a transient helper miss — so the helper IPC error is
	// intentionally discarded here. The operator clear-all path propagates it
	// instead (ClearAllSessions, #5881).
	_ = m.deleteHelperSessionsV4(keys)
	return deleted, err
}

// BatchDeleteSessionsScoped is the #9364 domain-carrying batch delete.
//
// The BPF mirror has no domain axis (#7160), so it takes the bare keys exactly as
// before; the domain matters only on the HELPER wire, where a bare 5-tuple is
// resolved by probing every routing instance and REFUSED when two tenants match
// (#8636). This is the highest-volume delete path on a running box — the
// conntrack GC retires sessions through it continuously — so it was the half of
// #9146 that mattered more and the half that was left bare.
func (m *Manager) BatchDeleteSessionsScoped(scoped []dataplane.ScopedSessionKey) (int, error) {
	deleted, err := m.bpfShim.BatchDeleteSessions(bareKeysV4(scoped))
	// Same best-effort contract as BatchDeleteSessions below: attempt the helper
	// delete regardless of the mirror result, and discard the helper IPC error.
	_ = m.deleteHelperSessionsScopedV4(scoped)
	return deleted, err
}

// BatchDeleteSessionsScopedV6 is the IPv6 analogue (#9364).
func (m *Manager) BatchDeleteSessionsScopedV6(scoped []dataplane.ScopedSessionKeyV6) (int, error) {
	deleted, err := m.bpfShim.BatchDeleteSessionsV6(bareKeysV6(scoped))
	_ = m.deleteHelperSessionsScopedV6(scoped)
	return deleted, err
}

// peerDeleteRefusedLocalOwned is the helper's in-band answer to a #9714 peer delete
// it refused: SYNCED_DELETE_REFUSED_PREFIX plus the reason
// (userspace-dp/src/server/handlers/sync_session.rs).
const peerDeleteRefusedLocalOwned = "synced-delete-refused:peer-delete-local-owned"

// peerDeleteRefused reports whether err is the helper's refusal of a peer delete.
// requestSessionSyncLocked returns an in-band answer verbatim and wraps every
// transport failure as errSessionHelperUnreachable, so a transport error never
// reads as a refusal.
func peerDeleteRefused(err error) bool {
	return err != nil && err.Error() == peerDeleteRefusedLocalOwned
}

// BatchDeletePeerSyncedSessionsScoped is BatchDeleteSessionsScoped for deletes made
// on behalf of the PEER (#9714). The helper answers FIRST: every request is marked
// PeerDelete, and a key the helper refuses (a live local session whose owner RG is
// locally active) is returned in refused and keeps its BPF mirror row. The other
// keys' mirror rows go one at a time, so a row already gone does not strand the
// rest. As with the unmarked batch, the helper IPC error itself is best-effort.
func (m *Manager) BatchDeletePeerSyncedSessionsScoped(scoped []dataplane.ScopedSessionKey) (int, []dataplane.ScopedSessionKey, error) {
	var refused []dataplane.ScopedSessionKey
	_ = m.deleteHelperSessionsScopedV4Marked(scoped, true, &refused)
	deleted, err := deleteUnrefusedMirrorRows(scoped, refused, func(sk dataplane.ScopedSessionKey) error {
		return m.bpfShim.DeleteSession(sk.Key)
	})
	return deleted, refused, err
}

// BatchDeletePeerSyncedSessionsScopedV6 is the IPv6 analogue (#9714).
func (m *Manager) BatchDeletePeerSyncedSessionsScopedV6(scoped []dataplane.ScopedSessionKeyV6) (int, []dataplane.ScopedSessionKeyV6, error) {
	var refused []dataplane.ScopedSessionKeyV6
	_ = m.deleteHelperSessionsScopedV6Marked(scoped, true, &refused)
	deleted, err := deleteUnrefusedMirrorRows(scoped, refused, func(sk dataplane.ScopedSessionKeyV6) error {
		return m.bpfShim.DeleteSessionV6(sk.Key)
	})
	return deleted, refused, err
}

// deleteUnrefusedMirrorRows deletes the BPF mirror row of every key the helper did
// not refuse (#9714). A refused key is a live local session the helper kept, so its
// row stays. Rows go one at a time, and a row that is already gone is not an error,
// so one missing row does not strand the rest.
func deleteUnrefusedMirrorRows[K comparable](keys, refused []K, del func(K) error) (int, error) {
	kept := make(map[K]struct{}, len(refused))
	for _, key := range refused {
		kept[key] = struct{}{}
	}
	deleted := 0
	var firstErr error
	for _, key := range keys {
		if _, ok := kept[key]; ok {
			continue
		}
		switch err := del(key); {
		case err == nil:
			deleted++
		case errors.Is(err, ebpf.ErrKeyNotExist):
		case firstErr == nil:
			firstErr = err
		}
	}
	return deleted, firstErr
}

func bareKeysV4(scoped []dataplane.ScopedSessionKey) []dataplane.SessionKey {
	keys := make([]dataplane.SessionKey, 0, len(scoped))
	for _, sk := range scoped {
		keys = append(keys, sk.Key)
	}
	return keys
}

func bareKeysV6(scoped []dataplane.ScopedSessionKeyV6) []dataplane.SessionKeyV6 {
	keys := make([]dataplane.SessionKeyV6, 0, len(scoped))
	for _, sk := range scoped {
		keys = append(keys, sk.Key)
	}
	return keys
}

// BatchDeleteSessionsV6 is the IPv6 analogue of BatchDeleteSessions (#5096).
func (m *Manager) BatchDeleteSessionsV6(keys []dataplane.SessionKeyV6) (int, error) {
	deleted, err := m.bpfShim.BatchDeleteSessionsV6(keys)
	_ = m.deleteHelperSessionsV6(keys)
	return deleted, err
}

// ClearAllSessions clears the BPF mirror AND issues an authoritative "delete" to
// the Rust helper for every session so an operator `clear security flow session
// all` actually stops forwarding under revoked decisions (#5096). The helper
// exposes no bulk-clear verb (only the per-session "delete" the singular path
// uses), so every mirror key — forward AND reverse conntrack entries — must be
// deleted on the helper too.
//
// The keys are NOT snapshotted here. Enumerating the full v4+v6 mirror into
// wrapper-owned slices while the shim's own clear snapshots them AGAIN (plus the
// dynamic-DNAT key lists) stacked ~1 GB of duplicate key slices in RSS on a
// max-loaded 10M/family table — enough for the recovery command to stall or
// OOM-kill the daemon (#5304). Instead the shim's ClearAllSessionsChunked drives
// a per-chunk callback: it collects a bounded chunk, deletes it from the mirror,
// and hands that same bounded chunk here for deletion on the helper, so neither
// side ever holds more than one chunk of keys. deleteHelperSessions{V4,V6} keeps
// the #5096 chunked-transmission behaviour (sessionHelperDeleteChunk).
//
// The Rust helper is AUTHORITATIVE in userspace mode — it owns packet
// lookup/forwarding while the BPF mirror is a read model. A helper-delete IPC
// failure therefore means a session the operator asked to revoke may still be
// forwarding, even though the mirror was emptied. Losing that error (as the
// pre-#5881 void callbacks did) let `clear security flow session all` report
// success while sessions lived on — a security bug. So the first helper-delete
// error is captured across chunks and, when the mirror clear itself succeeded,
// surfaced as ClearAllSessions's returned error. The bpf mirror's partial
// (v4, v6) counts are still returned alongside the error, matching the #5882
// non-atomic clear-all reporting contract, so a caller learns what the mirror
// side revoked while also learning the authoritative revocation is unconfirmed.
// A mirror-side error still takes precedence and is returned as before.
//
// #5380 residual: the per-chunk callbacks skip the helper delete once a
// transport failure is recorded, so a full clear-all under a hung helper pays
// ~one round-trip deadline total rather than one per 4096-key mirror chunk.
// See the helperDown guard below.
func (m *Manager) ClearAllSessions() (int, int, error) {
	var helperErr error
	recordHelperErr := func(err error) {
		if err != nil && helperErr == nil {
			helperErr = err
		}
	}
	// Fast-fail the WHOLE clear-all once the helper transport is down, not just
	// the 256-request loop inside a single deleteHelperSessions call (#5380
	// only aborted that inner loop). ClearAllSessionsChunked invokes these
	// callbacks ONCE PER sessionClearSnapshotChunk (4096-key) mirror chunk, and
	// the callbacks return void, so an inner abort does not propagate up: the
	// shim keeps handing every remaining chunk to a hung helper. A max table is
	// ~10M keys / 4096 ≈ 2440 chunks per family, so without this guard a
	// clear-all under a hung helper still pays ~one round-trip deadline PER
	// chunk (~2 h/family) even though each chunk's own delete already
	// fast-fails. Once a TRANSPORT failure has been recorded, skip the helper
	// delete for the remaining chunks so the clear-all pays ~one deadline
	// total. Only errSessionHelperUnreachable (a hung/unreachable helper) trips
	// the skip; an application-level rejection (helper alive, resp.OK=false) is
	// NOT wrapped as the sentinel, so a live helper that refuses one delete
	// keeps clearing the rest of the batch (#5881). The BPF mirror still clears
	// fully — the shim deletes each chunk BEFORE invoking the callback — and
	// helperErr stays set, so the #5881 error-propagation and #5882
	// partial-count contracts are unchanged.
	helperDown := func() bool { return errors.Is(helperErr, errSessionHelperUnreachable) }
	v4, v6, mirrorErr := m.bpfShim.ClearAllSessionsChunked(
		func(keys []dataplane.SessionKey) {
			if helperDown() {
				return
			}
			recordHelperErr(m.deleteHelperSessionsV4(keys))
		},
		func(keys []dataplane.SessionKeyV6) {
			if helperDown() {
				return
			}
			recordHelperErr(m.deleteHelperSessionsV6(keys))
		},
	)
	if mirrorErr != nil {
		return v4, v6, mirrorErr
	}
	if helperErr != nil {
		return v4, v6, fmt.Errorf("clear-all: authoritative helper session revocation failed: %w", helperErr)
	}
	return v4, v6, nil
}

// deleteHelperSessionsV4 tells the Rust helper to delete every key so the batch
// and clear session paths converge the helper's authoritative session table
// with the BPF mirror (#5096). Requests are transmitted in bounded chunks (see
// sessionHelperDeleteChunk) so a large clear does not monopolize the shared
// control socket. A "delete" request built with a nil value carries only the
// 5-tuple, so no snapshot read happens under m.mu.
//
// It returns the FIRST helper IPC error across all chunks (nil if all
// succeeded, or if there is no live helper). The best-effort batch callers
// discard it; ClearAllSessions propagates it so a failed authoritative
// revocation is reported rather than reported as success (#5881).
func (m *Manager) deleteHelperSessionsV4(keys []dataplane.SessionKey) error {
	// #9364: the BARE form, kept for the callers that genuinely have no value —
	// ClearAllSessions, which is exactly the caller #8636's ambiguous-delete
	// refusal was designed for. It maps onto the scoped implementation with
	// domain 0 rather than duplicating the chunking, so the #5380 fast-fail and
	// the #5448 contract cannot drift between the two forms.
	scoped := make([]dataplane.ScopedSessionKey, 0, len(keys))
	for _, k := range keys {
		scoped = append(scoped, dataplane.ScopedSessionKey{Key: k})
	}
	return m.deleteHelperSessionsScopedV4(scoped)
}

// deleteHelperSessionsScopedV4 is the #9364 domain-carrying helper delete.
func (m *Manager) deleteHelperSessionsScopedV4(keys []dataplane.ScopedSessionKey) error {
	return m.deleteHelperSessionsScopedV4Marked(keys, false, nil)
}

// deleteHelperSessionsScopedV4Marked is deleteHelperSessionsScopedV4 with the
// #9714 peer mark set on every request it builds.
// refused, when non-nil, collects the keys the helper refused as peer deletes.
func (m *Manager) deleteHelperSessionsScopedV4Marked(keys []dataplane.ScopedSessionKey, peer bool, refused *[]dataplane.ScopedSessionKey) error {
	if len(keys) == 0 {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.proc == nil {
		return nil
	}
	var firstErr error
	for start := 0; start < len(keys); start += sessionHelperDeleteChunk {
		end := start + sessionHelperDeleteChunk
		if end > len(keys) {
			end = len(keys)
		}
		reqs := make([]SessionSyncRequest, 0, end-start)
		for i := start; i < end; i++ {
			// #9364: name the domain the row was installed under, so the
			// helper does not have to probe for it and cannot refuse the delete
			// as ambiguous. deleteScopeVal returns nil at domain 0, which is the
			// pre-#9364 bare request, bit-identical.
			req := m.buildSessionSyncRequestV4(
				"delete", keys[i].Key, deleteScopeVal(keys[i].RoutingDomain))
			req.PeerDelete = peer
			reqs = append(reqs, req)
		}
		// #9714: every request's outcome, not only the first error, so a key the
		// helper refused as a peer delete is known by name. A refusal answers the
		// request; it is not a failure of it.
		var err error
		for i, outcome := range m.syncSessionRequestOutcomesLocked(reqs...) {
			switch {
			case outcome == nil:
			case peer && refused != nil && peerDeleteRefused(outcome):
				*refused = append(*refused, keys[start+i])
			case err == nil:
				err = outcome
			}
		}
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			// Helper unreachable/hung: stop chunking. Every remaining chunk
			// would fast-fail identically, so a large clear (10M keys ≈ 40K
			// chunks) does not spend one round-trip deadline PER chunk (#5380).
			if errors.Is(err, errSessionHelperUnreachable) {
				break
			}
		}
	}
	return firstErr
}

// deleteHelperSessionsV6 is the IPv6 analogue of deleteHelperSessionsV4 (#5096).
func (m *Manager) deleteHelperSessionsV6(keys []dataplane.SessionKeyV6) error {
	// #9364: the BARE form — see deleteHelperSessionsV4.
	scoped := make([]dataplane.ScopedSessionKeyV6, 0, len(keys))
	for _, k := range keys {
		scoped = append(scoped, dataplane.ScopedSessionKeyV6{Key: k})
	}
	return m.deleteHelperSessionsScopedV6(scoped)
}

// deleteHelperSessionsScopedV6 is the IPv6 analogue of
// deleteHelperSessionsScopedV4 (#9364).
func (m *Manager) deleteHelperSessionsScopedV6(keys []dataplane.ScopedSessionKeyV6) error {
	return m.deleteHelperSessionsScopedV6Marked(keys, false, nil)
}

// deleteHelperSessionsScopedV6Marked is the IPv6 analogue of
// deleteHelperSessionsScopedV4Marked (#9714).
func (m *Manager) deleteHelperSessionsScopedV6Marked(keys []dataplane.ScopedSessionKeyV6, peer bool, refused *[]dataplane.ScopedSessionKeyV6) error {
	if len(keys) == 0 {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.proc == nil {
		return nil
	}
	var firstErr error
	for start := 0; start < len(keys); start += sessionHelperDeleteChunk {
		end := start + sessionHelperDeleteChunk
		if end > len(keys) {
			end = len(keys)
		}
		reqs := make([]SessionSyncRequest, 0, end-start)
		for i := start; i < end; i++ {
			// #9364: name the domain — see the V4 twin.
			req := m.buildSessionSyncRequestV6(
				"delete", keys[i].Key, deleteScopeValV6(keys[i].RoutingDomain))
			req.PeerDelete = peer
			reqs = append(reqs, req)
		}
		// #9714: every request's outcome, not only the first error, so a key the
		// helper refused as a peer delete is known by name. A refusal answers the
		// request; it is not a failure of it.
		var err error
		for i, outcome := range m.syncSessionRequestOutcomesLocked(reqs...) {
			switch {
			case outcome == nil:
			case peer && refused != nil && peerDeleteRefused(outcome):
				*refused = append(*refused, keys[start+i])
			case err == nil:
				err = outcome
			}
		}
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			// Helper unreachable/hung: stop chunking (see deleteHelperSessionsV4).
			if errors.Is(err, errSessionHelperUnreachable) {
				break
			}
		}
	}
	return firstErr
}

// ErrSessionCountersUnsupported reports that the running helper does not
// implement the #7919 `session_counters` verb.
//
// THIS IS NOT "ZERO". An older helper answers an unknown verb with
// `unknown request type <verb>` (server/handlers/mod.rs), and a caller that
// treated that as an empty result would record "no worker holds this session"
// — which is one of the two states the query exists to distinguish, and would
// manufacture exactly the evidence it is meant to gather. In a rolling upgrade
// the two nodes run different binaries, so this path is reachable in normal
// operation, not just in test.
var ErrSessionCountersUnsupported = errors.New("helper does not support the session_counters verb")

// unknownVerbPrefix is the helper's wording for an unimplemented verb. Matching
// on text is unpleasant and it is the ONLY signal an already-released helper
// gives — that binary cannot be changed retroactively. The current helper's
// exact wording is pinned by a test on the Rust side so a reword breaks the
// build rather than silently turning "unsupported" into a generic error.
const unknownVerbPrefix = "unknown request type"

// QuerySessionCounters asks the helper what EACH worker's own session table
// holds for one 5-tuple (#7919).
//
// READ-ONLY and DIAGNOSTIC-ONLY. It broadcasts a command to every worker and
// waits (bounded, helper-side) for their replies, so it must never be issued on
// a poll: the control socket is shared with the status poll, HA sync, session
// installs and snapshot sync, and a caller above ~1 Hz starves session installs
// during bulk sync.
func (m *Manager) QuerySessionCounters(q SessionCounterQuery) ([]SessionCounterRow, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	resp, err := m.requestDetailedLocked(ControlRequest{
		Type:                "session_counters",
		SuppressStatus:      true,
		SessionCounterQuery: &q,
	})
	return sessionCountersFromResponse(resp, err)
}

// sessionCountersFromResponse turns one control exchange into the caller's
// answer. EXTRACTED from QuerySessionCounters rather than left inline because
// the request path has no test seam, and an inline choice cannot be bound by a
// test — the classification below is the whole contract of this verb on the Go
// side, and it must be exercisable without a live helper.
//
// The distinction it enforces: an UNSUPPORTED verb is an error, never an empty
// result. Returning `nil, nil` for an old helper would tell the caller that no
// worker holds the session, which is one of the two states the query exists to
// separate — the failure would look exactly like a finding.
func sessionCountersFromResponse(resp ControlResponse, err error) ([]SessionCounterRow, error) {
	if err != nil {
		if isUnknownVerbError(err) {
			return nil, ErrSessionCountersUnsupported
		}
		return nil, err
	}
	return resp.SessionCounters, nil
}

// isUnknownVerbError reports whether the helper refused the verb because it does
// not implement it, as opposed to failing while executing it. The two must not
// be conflated: the first means "ask a newer helper", the second means the
// answer is genuinely unavailable and retrying will not help.
func isUnknownVerbError(err error) bool {
	return err != nil && strings.Contains(err.Error(), unknownVerbPrefix)
}
