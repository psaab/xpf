use super::*;

/// #4800: calls to [`publish_shared_session`] — one per session published
/// into the cross-worker shared maps, i.e. one per new transit flow (plus
/// its reverse companion) and one per promote / HA import / tunnel install.
///
/// This is the DENOMINATOR for the publish leg of the new-flow-install
/// serialization question. On its own a publish rate says nothing; paired
/// with `SHARED_SESSION_PUBLISH_LOCK_CONTENDED` it says whether the publish
/// mutexes are where new flows queue up.
pub(crate) static SHARED_SESSION_PUBLISHES: AtomicU64 = AtomicU64::new(0);
// Isolate the probe from other tests' `CounterExempt` publishers.
#[cfg(test)]
std::thread_local! {
    static NAT_AMBIGUITY_LOCK_ACQUISITIONS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
pub(crate) struct NatAmbiguityLockStats {
    pub(crate) acquisitions: u64,
}

#[cfg(test)]
pub(crate) fn reset_nat_ambiguity_lock_stats() {
    NAT_AMBIGUITY_LOCK_ACQUISITIONS.with(|count| count.set(0));
}

#[cfg(test)]
pub(crate) fn nat_ambiguity_lock_stats() -> NatAmbiguityLockStats {
    NatAmbiguityLockStats {
        acquisitions: NAT_AMBIGUITY_LOCK_ACQUISITIONS.with(std::cell::Cell::get),
    }
}

#[cfg(test)]
fn lock_nat_ambiguities_for_publish(
    indexes: &SharedSessionOwnerRgIndexes,
) -> MutexGuard<'_, SharedNatAmbiguityIndex> {
    NAT_AMBIGUITY_LOCK_ACQUISITIONS.with(|count| count.set(count.get() + 1));
    lock_shared_recover(&indexes.nat_ambiguities)
}

#[cfg(not(test))]
fn lock_nat_ambiguities_for_publish(
    indexes: &SharedSessionOwnerRgIndexes,
) -> MutexGuard<'_, SharedNatAmbiguityIndex> {
    lock_shared_recover(&indexes.nat_ambiguities)
}

// #14383: publish-side lock for the forward-wire ambiguity index. Mirrors
// `lock_nat_ambiguities_for_publish` (plain recovering lock); no lock-count
// test seam is wired for the wire index.
fn lock_wire_ambiguities_for_publish(
    indexes: &SharedSessionOwnerRgIndexes,
) -> MutexGuard<'_, SharedNatAmbiguityIndex> {
    lock_shared_recover(&indexes.wire_ambiguities)
}

/// #8486: the largest `owner_rg_id` this helper will FILE into the owner-RG
/// indexes.
///
/// `metadata.owner_rg_id` arrives from the peer as a raw `i32` and was filed
/// for every positive value. A peer sending N distinct positive ids created N
/// buckets in `OwnerRgSessionIndex`, and nothing shrinks that allocation
/// afterwards. That is mild on its own -- but the authoritative un-file,
/// `remove_owner_rg_index_key_from_every_bucket_locked`, uses `HashMap::retain`,
/// which is O(CAPACITY) and visits empty slots, so removing N keys filed under
/// N distinct ids is Theta(N^2) of outer-capacity work on the session-control
/// thread.
///
/// 15 mirrors the Go strict bound (`compiler_validate_strict_chassis.go` limits
/// redundancy-group ids to 0..15). The Go side downgrades that to a WARNING on
/// the tolerant load / peer-sync path (`compiler_uniformgates_cluster_zone.go`),
/// which is exactly why the helper needs its own: it is the last line and it
/// did not hold one.
pub(crate) const MAX_FILEABLE_OWNER_RG_ID: i32 = 15;

/// #8486: owner-RG filings declined because the id was out of range. Nonzero
/// means a peer is sending ids this cluster's own strict validator would
/// reject -- worth seeing, and it is deliberately a counter rather than a log
/// so a burst cannot flood the journal.
pub(crate) static OWNER_RG_FILINGS_DECLINED: AtomicU64 = AtomicU64::new(0);

/// #8486: whether `owner_rg_id` may be FILED into an owner-RG index.
///
/// Deliberately narrower than the predicate the REMOVE path uses, and the
/// asymmetry is the point: removal stays `> 0` so anything that was ever filed
/// can always be un-filed, including under a future tightening of this bound.
/// A symmetric bound would strand entries filed under the old one, turning a
/// hardening change into a leak.
///
/// Declining to FILE rather than refusing the IMPORT is also deliberate. The
/// tolerant peer-sync path exists because a peer may legitimately be running an
/// older or looser config, and refusing the session would decline a takeover
/// this node is otherwise fit for -- trading a bounded memory cost for a
/// blackhole on failover. The session is kept and remains usable; only the
/// index entry is skipped.
pub(crate) fn is_fileable_owner_rg(owner_rg_id: i32) -> bool {
    if owner_rg_id <= 0 {
        return false;
    }
    if owner_rg_id > MAX_FILEABLE_OWNER_RG_ID {
        OWNER_RG_FILINGS_DECLINED.fetch_add(1, Ordering::Relaxed);
        return false;
    }
    true
}

/// #4800: shared-map mutex acquisitions taken by [`publish_shared_session`]
/// (1 for `shared_sessions`, plus `shared_nat_sessions` and
/// `shared_forward_wire_sessions` on a forward entry), and the subset that
/// found the mutex already held by another worker.
///
/// Scoped to the publish path deliberately: `remove_shared_session`, the HA
/// promote/demote prewarm, and the read-side lookups take the same mutexes
/// through the uncounted [`lock_shared_recover`], so folding them in would
/// blur exactly the attribution this pair exists to provide.
///
/// COST, stated honestly: the LOCK is unchanged — `try_lock()` on an
/// uncontended mutex is the same single CAS `lock()` already performed — but
/// the acquisition counter is bumped UNCONDITIONALLY, so the uncontended path
/// is not free. One forward `publish_shared_session` goes from 3 atomic
/// read-modify-writes (three `lock()` CASes) to 7: the call counter, plus one
/// relaxed increment and one CAS for each of the three maps. All relaxed, no
/// timing, no allocation, on the cold new-flow-install path — but "unchanged"
/// would be false.
pub(crate) static SHARED_SESSION_PUBLISH_LOCK_ACQUISITIONS: AtomicU64 = AtomicU64::new(0);
pub(crate) static SHARED_SESSION_PUBLISH_LOCK_CONTENDED: AtomicU64 = AtomicU64::new(0);

/// #2402: total shared-session / owner-RG-index mutex poison recoveries
/// across every site in this module (HA promotion prewarm, demotion,
/// publish, remove, lookups, owner-RG index maintenance). Each recovery
/// means a worker thread panicked while holding one of the shared-session
/// mutexes; the map still holds every committed insert, so the HA
/// promotion/demotion path proceeds with the EXISTING sessions instead of
/// silently treating the table as empty (which dropped all synced sessions
/// at failover — the #2402 bug). Mirrors the worker-command-queue policy
/// (`worker_queue::lock_recover`, #1807). Each recovery also emits a sparse
/// journald line so operators see that a worker panicked (the root cause);
/// the counter is kept for tests and future status wiring.
pub(crate) static SHARED_SESSION_POISON_RECOVERIES: AtomicU64 = AtomicU64::new(0);

/// Lock a shared-session (or owner-RG index) mutex, RECOVERING and
/// clearing poison instead of swallowing it.
///
/// Policy (#2402, mirrors `worker_queue::lock_recover` #1807): a panic
/// that poisoned the mutex already happened and was contained (#925
/// worker supervisor). The guarded map still holds the committed prefix
/// of every completed insert, so the correct recovery is to keep using
/// that data — NOT to skip the operation (`if let Ok`) or substitute an
/// empty table (`.lock().map(..).unwrap_or_default()`). On the HA
/// promotion path the latter silently dropped every active synced session
/// at the exact moment of failover. `clear_poison` restores the fast
/// unpoisoned path for subsequent locks so the Poisoned arm stays cold.
#[inline]
pub(in crate::afxdp) fn lock_shared_recover<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    match m.lock() {
        Ok(guard) => guard,
        Err(poisoned) => {
            m.clear_poison();
            SHARED_SESSION_POISON_RECOVERIES.fetch_add(1, Ordering::Relaxed);
            eprintln!(
                "xpf-ha: shared session mutex poisoned by a prior worker panic; recovering existing sessions and clearing poison"
            );
            poisoned.into_inner()
        }
    }
}

/// #4800: [`lock_shared_recover`] with contention accounting, used ONLY by
/// [`publish_shared_session`].
///
/// `try_lock()` first — a single CAS on an uncontended mutex, exactly what
/// `lock()` already did, so the LOCK ITSELF costs what it always did. The
/// acquisition counter above it is unconditional, so an uncontended
/// acquisition is 2 relaxed atomic RMWs where it used to be 1 (see
/// [`SHARED_SESSION_PUBLISH_LOCK_ACQUISITIONS`] for the per-publish total).
/// A failed CAS means another worker holds the map and this new-flow install
/// is about to serialize behind it: bump the contended counter, then block as
/// before — the block was going to happen anyway. Poison
/// policy is inherited unchanged by delegating to [`lock_shared_recover`]
/// for the blocking arm, and reproduced for the try-lock Poisoned arm
/// (which `try_lock` reports only when the mutex is FREE).
#[inline]
fn lock_shared_publish<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    SHARED_SESSION_PUBLISH_LOCK_ACQUISITIONS.fetch_add(1, Ordering::Relaxed);
    match m.try_lock() {
        Ok(guard) => return guard,
        Err(TryLockError::Poisoned(poisoned)) => {
            m.clear_poison();
            SHARED_SESSION_POISON_RECOVERIES.fetch_add(1, Ordering::Relaxed);
            eprintln!(
                "xpf-ha: shared session mutex poisoned by a prior worker panic; recovering existing sessions and clearing poison"
            );
            return poisoned.into_inner();
        }
        Err(TryLockError::WouldBlock) => {}
    }
    SHARED_SESSION_PUBLISH_LOCK_CONTENDED.fetch_add(1, Ordering::Relaxed);
    lock_shared_recover(m)
}

/// #1760 W3': cumulative count of shared-map NAT reverse-key displacement
/// events — a `publish_shared_session` insert into `shared_nat_sessions`
/// (reverse-wire or reverse-canonical slot) displaced an entry whose
/// FORWARD key differs from the one being published. Two distinct forward
/// NAT sessions mapping onto one reply tuple K is the #1758/#1760 latent
/// 1:N collision. This is the single choke point every transit forward
/// NAT session passes through — normal installs, `MissingNeighborSeed`
/// installs (which are NOT replicated to sibling workers and therefore
/// invisible to the per-worker `nat_reverse_key_collisions` counter),
/// promotes, HA sync imports, and tunnel-local installs — so zero here is
/// a much stronger "no collision while this process was up" signal than
/// the per-worker counter alone. Same-session republish (promote, RG
/// migration, HA re-sync) displaces an entry with the SAME forward key
/// and is not counted; nor is the entry's own canonical/wire alias.
/// Event count, not a pair census: a standing collision against a live
/// session whose K was already removed (post-winner-expiry) is not
/// observable at this choke point — see
/// docs/research/1760-reverse-key-v2/plan.md §2.3. Surfaced as
/// `xpf_userspace_session_nat_reverse_key_shared_displacements_total`.
pub(crate) static NAT_REVERSE_KEY_SHARED_DISPLACEMENTS: AtomicU64 = AtomicU64::new(0);

/// #1760 W3' detection helper: count a shared-map displacement when the
/// displaced entry belongs to a DIFFERENT forward session. Shared by the
/// reverse-wire and reverse-canonical insert sites in
/// `publish_shared_session`.
///
/// Alias exclusion (Codex code-r1 F1): HA session sync deliberately
/// publishes a fabric-redirect session TWICE — canonical forward key plus
/// a NAT-translated forward-WIRE alias key carrying the same value
/// (`pkg/daemon/daemon_ha_userspace.go` `userspaceForwardWireAliasFromDeltaV4`,
/// queued under `delta.FabricRedirect && !delta.FabricIngress`). Both
/// forms derive the same reverse key K, so on a standby the pair would
/// displace each other at K every sync sweep — a same-logical-session
/// republish, not a 1:N collision. `forward_wire_key` is idempotent
/// (rewrites replace src/dst with the rewrite targets), so the alias
/// relation is exactly "one key is the other's forward-wire form".
/// Genuine colliding sessions keep counting: their CANONICAL keys are
/// not each other's wire forms (each wire form is the shared external
/// tuple, not the peer's internal tuple), and NAT-vs-different-NAT or
/// NAT-vs-no-NAT pairs whose keys ARE wire-related still count because
/// the alias test also requires an identical NatDecision (the HA alias
/// carries the same session value as its canonical form).
/// Known accepted under-count:
/// on a standby, a genuine collision involving a wire-FORM synced entry
/// is excluded by this test — the session's OWNER node still counts the
/// canonical-vs-canonical displacement in its own shared map.
#[inline]
fn record_shared_nat_displacement(
    displaced: Option<&SyncedSessionEntry>,
    entry: &SyncedSessionEntry,
) {
    let Some(existing) = displaced else {
        return;
    };
    if existing.key == entry.key {
        return;
    }
    // Wire-alias relation: same logical session under its translated key.
    // Three conditions, ALL required (each one alone is insufficient):
    // - NAT equality: the HA alias is queued with the SAME session value
    //   as its canonical form, so its NatDecision is identical. Keeps
    //   genuine NAT-vs-different-NAT (and NAT-vs-no-NAT direct)
    //   collisions counted even though their keys are wire-related
    //   (Codex code-r2: DNAT client->VIP=>backend vs direct
    //   client->backend is a REAL collision).
    // - Wire-related keys (forward_wire_key is idempotent).
    // - At least one side has a SYNC-DERIVED origin (peer-synced OR
    //   `SharedPromote`): the wire-alias only ever enters via HA session
    //   sync (`userspaceForwardWireAliasFromDeltaV4`) and, at failover,
    //   may be locally PROMOTED to `SharedPromote`
    //   (`maybe_promote_synced_session` republishes promoted hits —
    //   Codex code-r4). Neither origin is ever assigned to a session
    //   created by local packets, so the owner-side genuine corner stays
    //   counted where a LOCAL flow's source already equals the SNAT
    //   external address (identical NAT, wire-related keys, two real
    //   sessions — Codex code-r3). Accepted residual (documented above):
    //   such a pathological ext-IP-sourced local flow colliding with a
    //   sync-derived wire-form entry is excluded.
    let sync_derived = |origin: SessionOrigin| {
        origin.is_peer_synced() || matches!(origin, SessionOrigin::SharedPromote)
    };
    if existing.decision.nat == entry.decision.nat
        && (sync_derived(existing.origin) || sync_derived(entry.origin))
        && (existing.key == forward_wire_key(&entry.key, entry.decision.nat)
            || entry.key == forward_wire_key(&existing.key, existing.decision.nat))
    {
        return;
    }
    NAT_REVERSE_KEY_SHARED_DISPLACEMENTS.fetch_add(1, Ordering::Relaxed);
}

/// #1760 W1: last-warn timestamp for the journald reverse-key-collision
/// warn. Process-global so the ≤1 line/min bound holds regardless of
/// worker count (AGY r1 F4).
static NAT_REVERSE_KEY_WARN_LAST_NS: AtomicU64 = AtomicU64::new(0);

/// #1760 W1: minimum interval between journald collision warns.
const NAT_REVERSE_KEY_WARN_INTERVAL_NS: u64 = 60_000_000_000;

/// #1760 W1: claim the process-global collision-warn slot. Returns true
/// when the caller won and may emit the warn; false when inside the 60s
/// window or another worker won the race. Same load → window-check → CAS
/// shape as the coordinator warm-sweep throttle
/// (`coordinator/mod.rs` `last_warm_sweep_ns`): a lost CAS means another
/// thread claimed this slot concurrently, which is exactly the
/// "already warned" outcome we want.
pub(crate) fn try_claim_nat_reverse_key_warn(now_ns: u64) -> bool {
    let last = NAT_REVERSE_KEY_WARN_LAST_NS.load(Ordering::Acquire);
    if now_ns.saturating_sub(last) < NAT_REVERSE_KEY_WARN_INTERVAL_NS {
        return false;
    }
    NAT_REVERSE_KEY_WARN_LAST_NS
        .compare_exchange(last, now_ns, Ordering::AcqRel, Ordering::Acquire)
        .is_ok()
}

pub(in crate::afxdp) fn demote_shared_owner_rgs(
    shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_nat_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_forward_wire_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_owner_rg_indexes: &SharedSessionOwnerRgIndexes,
    forwarding: &ForwardingState,
    dynamic_neighbors: &Arc<ShardedNeighborMap>,
    owner_rgs: &[i32],
) {
    if owner_rgs.is_empty() {
        return;
    }
    let mut demoted_entries = Vec::new();
    {
        let mut sessions = lock_shared_recover(shared_sessions);
        for key in owner_rg_session_keys(&shared_owner_rg_indexes.sessions, owner_rgs) {
            if let Some(entry) = sessions.get_mut(&key) {
                // Preserve every transient-local provenance in each alias:
                // later materialization must never make a local seed HA-exportable.
                if entry.origin.is_local_tun_origin() || entry.origin.is_transient_local_seed() {
                    continue;
                }
                let previous = entry.clone();
                entry.origin = SessionOrigin::SyncImport;
                demoted_entries.push((previous, entry.clone()));
            }
        }
    }
    for (previous, entry) in demoted_entries {
        refresh_reverse_prewarm_owner_rg_indexes(
            &shared_owner_rg_indexes.reverse_prewarm_sessions,
            forwarding,
            dynamic_neighbors,
            Some(&previous),
            Some(&entry),
        );
    }
    {
        let mut sessions = lock_shared_recover(shared_nat_sessions);
        for key in owner_rg_session_keys(&shared_owner_rg_indexes.nat_sessions, owner_rgs) {
            if let Some(entry) = sessions.get_mut(&key) {
                if entry.origin.is_local_tun_origin() || entry.origin.is_transient_local_seed() {
                    continue;
                }
                entry.origin = SessionOrigin::SyncImport;
            }
        }
    }
    {
        let mut sessions = lock_shared_recover(shared_forward_wire_sessions);
        for key in owner_rg_session_keys(&shared_owner_rg_indexes.forward_wire_sessions, owner_rgs)
        {
            if let Some(entry) = sessions.get_mut(&key) {
                if entry.origin.is_local_tun_origin() || entry.origin.is_transient_local_seed() {
                    continue;
                }
                entry.origin = SessionOrigin::SyncImport;
            }
        }
    }
}

pub(in crate::afxdp) fn synced_replica_entry(entry: &SyncedSessionEntry) -> SyncedSessionEntry {
    let mut replica = entry.clone();
    replica.origin = entry.origin.worker_replica_origin();
    replica
}

/// Union the forward owner-RG session keys with the narrower
/// reverse-prewarm keys, deduplicated, preserving order: every `forward`
/// key first (in its original order), then each `reverse` key not already
/// present, in first-seen order.
///
/// #4069: membership is tested against a hash set built once (O(M)), so the
/// merge is O(N+M) — N reverse keys, M forward keys. The prior inline
/// `forward.contains(&key)` re-scanned the growing forward Vec once per
/// reverse key, i.e. O(N·M). This merge runs on the RG-activation prewarm,
/// which is on the failover critical path (~60ms/~130ms budget); on a busy
/// cluster with thousands of synced sessions the quadratic scan measurably
/// slowed how quickly a newly-primary node fully forwarded. The result set
/// (and its order) is identical to the old dedup — only the membership data
/// structure changed.
pub(in crate::afxdp) fn merge_owner_rg_candidate_keys(
    mut forward: Vec<SessionKey>,
    reverse: Vec<SessionKey>,
) -> Vec<SessionKey> {
    // Seed the membership set with the forward keys (O(M)), then probe each
    // reverse key in O(1). `insert` returns true only for a not-yet-seen
    // key, which is exactly the old `!forward.contains(&key)` predicate and
    // also folds out duplicates within `reverse` itself.
    let mut seen: FastSet<SessionKey> = forward.iter().cloned().collect();
    for key in reverse {
        if seen.insert(key.clone()) {
            forward.push(key);
        }
    }
    forward
}

/// Pre-warm reverse companions in shared session maps at RG activation.
///
/// With deterministic reverse companions (#310), the Go sync path already
/// pre-installs reverse entries via UpsertSynced. This function still runs
/// at activation to re-resolve egress with local forwarding state.
///
/// #8612: the parenthetical that used to sit here — "the pre-installed
/// entries carry the peer's interface indices/MACs" — described the
/// pre-#7097 world and has been false since that scrub. They carry ZERO
/// there: `ScrubNodeLocal` zeroes `FibIfindex`, `FibVlanID`, the MACs and
/// the ingress pair on every peer-owned row. The re-resolution is therefore
/// not a correction of the peer's numbering, it is the ONLY source of that
/// numbering — which is why the re-resolve must run and cannot be skipped as
/// an optimisation.
///
/// The one field that now survives is `FibGen` under
/// `LogFlagUserspaceTunnelEndpoint`, because there it is a
/// `StableTunnelEndpointID` (a fold of the interface NAME, identical on both
/// nodes) rather than a node-local number. That is the identity this
/// re-resolution has nothing to rebuild from if it is erased in transit.
///
/// Use the union of the shared owner-RG session index and the narrower
/// reverse-prewarm index here. Activation is infrequent, and locally promoted
/// sessions can exist in the shared table without appearing in the
/// reverse-prewarm subset, while split-RG reverse companions can still resolve
/// to an activated RG even when the forward entry's current owner RG is
/// different. Both cases need their forward entries restored to worker
/// SessionTables and, when applicable, their reverse companions synthesized
/// again on activation.
pub(in crate::afxdp) fn prewarm_reverse_synced_sessions_for_owner_rgs(
    shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_nat_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_forward_wire_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_owner_rg_indexes: &SharedSessionOwnerRgIndexes,
    worker_commands: &[Arc<Mutex<VecDeque<WorkerCommand>>>],
    session_map: SteeringMap<'_>,
    forwarding: &ForwardingState,
    ha_state: &BTreeMap<i32, HAGroupRuntime>,
    dynamic_neighbors: &Arc<ShardedNeighborMap>,
    owner_rgs: &[i32],
    now_secs: u64,
) {
    if owner_rgs.is_empty() {
        return;
    }
    let publish_session_map = session_map.fd >= 0;
    let owner_rg_set: std::collections::BTreeSet<i32> = owner_rgs.iter().copied().collect();
    // #4069: dedup the forward and reverse-prewarm key sets in O(N+M) via a
    // hash set (see merge_owner_rg_candidate_keys) instead of the former
    // O(N·M) `Vec::contains` scan on this failover-critical prewarm path.
    let candidate_keys = merge_owner_rg_candidate_keys(
        owner_rg_session_keys_serialized(
            shared_sessions,
            &shared_owner_rg_indexes.sessions,
            owner_rgs,
        ),
        owner_rg_session_keys_serialized(
            shared_sessions,
            &shared_owner_rg_indexes.reverse_prewarm_sessions,
            owner_rgs,
        ),
    );
    // #2402: acquire the shared-session guard with poison RECOVERY. The
    // prior `.lock().map(..).unwrap_or_default()` swallowed a poisoned
    // lock into EMPTY (forward_entries, reverse_entries) — so if a worker
    // had panicked while holding this mutex, RG activation proceeded as if
    // there were NO sessions to promote and silently dropped every active
    // synced session at the exact moment of failover. Recover the existing
    // map and compute from it instead.
    let (forward_entries, reverse_entries) = {
        let sessions = lock_shared_recover(shared_sessions);
        let mut forward_entries = Vec::new();
        let mut reverse_entries = Vec::new();
        for key in candidate_keys {
            let Some(entry) = sessions.get(&key) else {
                continue;
            };
            if entry.metadata.is_reverse {
                continue;
            }
            // #10612 (M4): fence stale replays at prewarm ingress. A pre-purge
            // snapshot lingering in shared must not be BPF-published or fanned
            // out after the purge deleted it. Checked here (before reverse
            // synthesis) so a stale forward suppresses both halves.
            if crate::afxdp::session_glue::synced_entry_is_stale_replay(
                entry.origin,
                &entry.metadata,
                forwarding,
            ) {
                crate::afxdp::session_glue::note_stale_replay_fence_drop();
                continue;
            }
            let allow_reverse_prewarm = entry.origin.is_peer_synced()
                || matches!(entry.origin, SessionOrigin::SharedPromote);
            let Some(reverse) = synthesized_synced_reverse_entry(
                forwarding,
                ha_state,
                dynamic_neighbors,
                entry,
                now_secs,
            ) else {
                // Collect forward entry even if reverse can't be synthesized,
                // as long as the forward session belongs to an activated RG.
                if owner_rg_set.contains(&entry.metadata.owner_rg_id) {
                    forward_entries.push(entry.clone());
                }
                continue;
            };
            if owner_rg_set.contains(&entry.metadata.owner_rg_id)
                || owner_rg_set.contains(&reverse.metadata.owner_rg_id)
            {
                forward_entries.push(entry.clone());
                if allow_reverse_prewarm {
                    reverse_entries.push(reverse);
                }
            }
        }
        (forward_entries, reverse_entries)
    };
    if forward_entries.is_empty() && reverse_entries.is_empty() {
        return;
    }
    // Push forward entries to workers so their local SessionTables have
    // the promoted sessions. Without this, workers only have reverse
    // sessions and incoming traffic on existing flows misses the forward
    // session lookup.
    //
    // Also publish forward sessions to the USERSPACE_SESSIONS BPF map
    // synchronously (#475). Without this, there is a window between RG
    // activation and the workers processing UpsertSynced where the XDP
    // shim has no REDIRECT entry for forward flows. Packets arrive as
    // session misses and can resolve to HAInactive if the worker hasn't
    // yet applied the HA state update.
    let mut fwd_publish_errors = 0u32;
    for forward in &forward_entries {
        if publish_session_map
            && publish_session_map_entry_for_session(
                session_map,
                &forward.key,
                forward.decision,
                &forward.metadata,
                forwarding.has_routing_domains,
            )
            .is_err()
        {
            fwd_publish_errors += 1;
            // #1789: fold the activation-prewarm forward publish failures
            // into the global publish-error total. Semantically identical
            // to every other counted site (a USERSPACE_SESSIONS publish
            // that returned Err); the local fwd_publish_errors count is
            // kept only for the existing one-shot eprintln below, so this
            // is one increment per failure, not a double count.
            SESSION_PUBLISH_ERRORS_SHARED.fetch_add(1, Ordering::Relaxed);
        }
        for commands in worker_commands {
            // #1807: recover-and-push — `if let Ok` silently DROPPED the
            // activation-prewarm UpsertSynced for a poisoned worker queue.
            let mut pending = worker_queue::lock_recover(commands);
            worker_queue::push_bounded(&mut pending, WorkerCommand::UpsertSynced(forward.clone()));
        }
    }
    if fwd_publish_errors > 0 {
        eprintln!(
            "xpf-ha: prewarm forward BPF publish: {} errors out of {} entries",
            fwd_publish_errors,
            forward_entries.len()
        );
    }
    for reverse in reverse_entries {
        publish_shared_session(
            shared_sessions,
            shared_nat_sessions,
            shared_forward_wire_sessions,
            shared_owner_rg_indexes,
            &reverse,
        );
        if publish_session_map {
            // #1789: the reverse-prewarm publish in the same activation
            // path was still swallowed with `let _ =`; count it like the
            // forward loop above.
            if publish_session_map_entry_for_session(
                session_map,
                &reverse.key,
                reverse.decision,
                &reverse.metadata,
                forwarding.has_routing_domains,
            )
            .is_err()
            {
                SESSION_PUBLISH_ERRORS_SHARED.fetch_add(1, Ordering::Relaxed);
            }
        }
        for commands in worker_commands {
            // #1807: recover-and-push — `if let Ok` silently DROPPED the
            // reverse-prewarm UpsertSynced for a poisoned worker queue.
            let mut pending = worker_queue::lock_recover(commands);
            worker_queue::push_bounded(&mut pending, WorkerCommand::UpsertSynced(reverse.clone()));
        }
    }
}

/// Republish USERSPACE_SESSIONS BPF map entries for ALL shared sessions
/// belonging to the given owner RGs.
///
/// Called during RG activation (#475) to close the gap where sessions
/// exist in the shared table (received via sync) but their BPF map entries
/// were deleted during the previous demotion cycle. The `reverse_prewarm`
/// index only covers sessions added via `upsert_synced_session` — locally
/// originated sessions that were demoted then re-synced may not appear
/// there. This function uses the comprehensive `sessions` owner-RG index
/// to ensure no session is missed.
pub(in crate::afxdp) fn republish_bpf_session_entries_for_owner_rgs(
    shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_owner_rg_indexes: &SharedSessionOwnerRgIndexes,
    session_map: SteeringMap<'_>,
    owner_rgs: &[i32],
    // #9517: this republishes peer-synced sessions on RG activation, which is
    // exactly where PASS_TO_KERNEL rows come from.
    // #10612 (N1): takes forwarding (not just the domains bool) to fence
    // stale-zone rows: a shared-transient stale row must not be BPF-resurrected.
    forwarding: &ForwardingState,
) -> u32 {
    if owner_rgs.is_empty() {
        return 0;
    }
    let keys = owner_rg_session_keys_serialized(
        shared_sessions,
        &shared_owner_rg_indexes.sessions,
        owner_rgs,
    );
    // Collect entries under the lock, then release before BPF syscalls
    // to avoid blocking concurrent session insert/remove/lookup.
    let entries: Vec<_> = {
        // #2402: recover a poisoned lock instead of returning 0 — a prior
        // worker panic must not void the activation BPF-map republish.
        let sessions = lock_shared_recover(shared_sessions);
        keys.iter()
            .filter_map(|key| {
                sessions
                    .get(key)
                    .map(|e| (e.key.clone(), e.decision, e.metadata.clone(), e.origin))
            })
            .collect()
    };
    let mut published = 0u32;
    let mut errors = 0u32;
    for (key, decision, metadata, origin) in &entries {
        // #10612 (N1): skip stale-zone rows (fence BEFORE the BPF publish,
        // mirroring prewarm). BPF-only gap: narrow race, heals on demotion.
        if crate::afxdp::session_glue::synced_entry_is_stale_replay(*origin, metadata, forwarding) {
            crate::afxdp::session_glue::note_stale_replay_fence_drop();
            continue;
        }
        if publish_session_map_entry_for_session(
            session_map,
            key,
            *decision,
            metadata,
            forwarding.has_routing_domains,
        )
        .is_ok()
        {
            published += 1;
        } else {
            errors += 1;
            // #1789: feed the activation-republish failures into the same
            // always-on total as every other USERSPACE_SESSIONS publish site.
            SESSION_PUBLISH_ERRORS_SHARED.fetch_add(1, Ordering::Relaxed);
        }
    }
    if errors > 0 {
        eprintln!(
            "xpf-ha: republish_bpf_session_entries: {} errors out of {} attempted",
            errors,
            published + errors
        );
    }
    published
}

pub(in crate::afxdp) fn publish_shared_session(
    shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_nat_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_forward_wire_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_owner_rg_indexes: &SharedSessionOwnerRgIndexes,
    entry: &SyncedSessionEntry,
) {
    // #4800: in test builds only, hold the shared side of the counter lock for
    // the whole publish, so a reading test excludes this mover without the
    // caller having to opt in — no caller can be forgotten the way a
    // hand-maintained inventory was.
    //
    // NOT a closure proof: `SHARED_SESSION_PUBLISHES` and both lock counters
    // are `pub(crate)` and a direct `fetch_add` from anywhere in the crate
    // bypasses this entirely. See `afxdp::counter_test_lock`.
    #[cfg(test)]
    let _counter_guard = super::counter_test_lock::counter_mover_guard();
    // #4800: every new transit flow passes through here, so this counter is
    // the publish-leg new-flow rate AND the denominator for the lock
    // contention counted by `lock_shared_publish` below.
    SHARED_SESSION_PUBLISHES.fetch_add(1, Ordering::Relaxed);
    {
        // #2402: recover poison so a peer-sync / promote publish is never
        // silently dropped because a worker panicked under this lock.
        let mut sessions = lock_shared_publish(shared_sessions);
        let previous_owner_rg = sessions
            .insert(entry.key.clone(), entry.clone())
            .map(|existing| existing.metadata.owner_rg_id);
        lock_shared_recover(&shared_owner_rg_indexes.bare_tuple_sessions).insert(&entry.key);
        update_owner_rg_index(
            &shared_owner_rg_indexes.sessions,
            &entry.key,
            previous_owner_rg,
            entry.metadata.owner_rg_id,
        );
    }
    if !entry.metadata.is_reverse {
        // Record the lookup identity before publishing aliases, then keep this
        // lock across the NAT-map writes so readers cannot see an unindexed
        // alias. Read-side checks drop the map lock before acquiring this one,
        // avoiding an inverse nested lock order.
        let reverse_wire = reverse_session_key(&entry.key, entry.decision.nat);
        let reverse_canonical = reverse_canonical_key(&entry.key, entry.decision.nat);
        let mut ambiguities = lock_nat_ambiguities_for_publish(shared_owner_rg_indexes);
        ambiguities.observe(
            crate::session::reverse_match_key(&reverse_wire),
            entry.key.clone(),
        );
        // #15104: the canonical alias is a distinct ambiguity key when it
        // differs from the wire alias. Track its owner so removal can
        // forget it once no live forward entry maps to it; its ambiguous
        // verdict remains driven by the displacement mark below.
        if reverse_canonical != reverse_wire {
            ambiguities.track_owner(
                crate::session::reverse_match_key(&reverse_canonical),
                entry.key.clone(),
            );
        }
        let mut sessions = lock_shared_publish(shared_nat_sessions);
        let displaced = sessions.insert(reverse_wire.clone(), entry.clone());
        record_shared_nat_displacement(displaced.as_ref(), entry);
        let wire_displaced = displaced
            .as_ref()
            .is_some_and(|existing| existing.key != entry.key);
        let previous_owner_rg = displaced.map(|existing| existing.metadata.owner_rg_id);
        update_owner_rg_index(
            &shared_owner_rg_indexes.nat_sessions,
            &reverse_wire,
            previous_owner_rg,
            entry.metadata.owner_rg_id,
        );
        let canonical_displaced = if reverse_canonical != reverse_wire {
            let displaced = sessions.insert(reverse_canonical.clone(), entry.clone());
            record_shared_nat_displacement(displaced.as_ref(), entry);
            let ambiguous = displaced
                .as_ref()
                .is_some_and(|existing| existing.key != entry.key);
            let previous_owner_rg = displaced.map(|existing| existing.metadata.owner_rg_id);
            update_owner_rg_index(
                &shared_owner_rg_indexes.nat_sessions,
                &reverse_canonical,
                previous_owner_rg,
                entry.metadata.owner_rg_id,
            );
            ambiguous
        } else {
            false
        };
        drop(sessions);
        if wire_displaced {
            ambiguities.mark(crate::session::reverse_match_key(&reverse_wire));
        }
        if canonical_displaced {
            ambiguities.mark(reverse_canonical);
        }
    }
    if !entry.metadata.is_reverse {
        let wire_key = forward_wire_key(&entry.key, entry.decision.nat);
        if wire_key != entry.key {
            // #14383: record the wire-key owner BEFORE the map write (same
            // order as the NAT publish) so a reader can never observe a
            // wire alias whose owner has not been recorded. A publish that
            // displaces a DIFFERENT forward session marks the key
            // ambiguous; the shared wire lookup then fails closed.
            let mut wire_ambiguities =
                lock_wire_ambiguities_for_publish(shared_owner_rg_indexes);
            wire_ambiguities.observe(wire_key.clone(), entry.key.clone());
            // #15106: record the live owner in the per-wire-key multiset so a
            // later removal resolves survivors in O(1) instead of scanning
            // `shared_sessions`.
            wire_ambiguities.observe_wire_owner(wire_key.clone(), entry.key.clone());
            let mut sessions = lock_shared_publish(shared_forward_wire_sessions);
            let displaced = sessions.insert(wire_key.clone(), entry.clone());
            let wire_displaced = displaced
                .as_ref()
                .is_some_and(|existing| existing.key != entry.key);
            let previous_owner_rg = displaced.map(|existing| existing.metadata.owner_rg_id);
            update_owner_rg_index(
                &shared_owner_rg_indexes.forward_wire_sessions,
                &wire_key,
                previous_owner_rg,
                entry.metadata.owner_rg_id,
            );
            drop(sessions);
            if wire_displaced {
                wire_ambiguities.mark(wire_key.clone());
            }
        }
    }
}

/// Update policy identity in every shared alias without replacing the entry.
/// A policy rename must not reset HA generation, counters, or liveness.
pub(in crate::afxdp) fn restamp_shared_policy_entries(
    shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_nat_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_forward_wire_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    entries: &[crate::session::PolicyRebindEntry],
) {
    fn apply(stored: &mut SyncedSessionEntry, entry: &crate::session::PolicyRebindEntry) {
        stored.metadata.policy_id = entry.metadata.policy_id;
        stored.metadata.policy_counter_idx = entry.metadata.policy_counter_idx;
        stored.metadata.policy_counter = entry.metadata.policy_counter.clone();
        stored.metadata.ingress_zone = entry.metadata.ingress_zone;
        stored.metadata.ingress_zone_check = entry.metadata.ingress_zone_check;
        stored.metadata.egress_zone = entry.metadata.egress_zone;
        stored.metadata.egress_zone_check = entry.metadata.egress_zone_check;
        stored.metadata.log_session_init = entry.metadata.log_session_init;
        stored.metadata.log_session_close = entry.metadata.log_session_close;
    }

    // Hold each alias map lock once for the complete pair. This prevents a
    // concurrent reader from observing one half restamped while the other
    // still carries the old policy identity within any one map.
    {
        let mut sessions = lock_shared_recover(shared_sessions);
        for entry in entries {
            if let Some(stored) = sessions.get_mut(&entry.key) {
                apply(stored, entry);
            }
        }
    }
    {
        let mut sessions = lock_shared_recover(shared_nat_sessions);
        for entry in entries {
            if entry.metadata.is_reverse {
                continue;
            }
            let reverse_wire = reverse_session_key(&entry.key, entry.decision.nat);
            let aliases = [
                reverse_wire.clone(),
                reverse_canonical_key(&entry.key, entry.decision.nat),
            ];
            for alias in aliases {
                if let Some(stored) = sessions.get_mut(&alias)
                    && stored.key == entry.key
                {
                    apply(stored, entry);
                }
            }
        }
    }
    {
        let mut sessions = lock_shared_recover(shared_forward_wire_sessions);
        for entry in entries {
            if entry.metadata.is_reverse {
                continue;
            }
            let wire_key = forward_wire_key(&entry.key, entry.decision.nat);
            if wire_key != entry.key
                && let Some(stored) = sessions.get_mut(&wire_key)
                && stored.key == entry.key
            {
                apply(stored, entry);
            }
        }
    }
}

/// #9679: remove `alias` from a single-value shared alias map only while it
/// still names `owner`.
///
/// The NAT reverse-alias and forward-wire maps hold ONE entry per alias key, and
/// `publish_shared_session` overwrites a colliding session's alias (counted by
/// `record_shared_nat_displacement`). Deriving the removed session's alias keys
/// and deleting whatever sits there therefore deleted the SURVIVOR's alias
/// whenever the removed session had been displaced. A worker with no local copy
/// of the survivor then missed both lookups and sent its replies to new-flow
/// adjudication.
fn remove_shared_alias_owned_by(
    aliases: &mut FastMap<SessionKey, SyncedSessionEntry>,
    alias: &SessionKey,
    owner: &SessionKey,
) -> Option<SyncedSessionEntry> {
    if aliases
        .get(alias)
        .is_some_and(|stored| &stored.key == owner)
    {
        aliases.remove(alias)
    } else {
        None
    }
}

/// The outcome of a conditional shared-session removal (#9714 review round 2,
/// finding 3).
pub(in crate::afxdp) enum SharedRemoval {
    /// The predicate accepted, and this is the entry that was removed — the SAME
    /// one the predicate saw, under the same lock hold.
    Removed(Box<SyncedSessionEntry>),
    /// An entry was present and the predicate DECLINED it. Nothing was mutated:
    /// not the shared maps, not the aliases, and not the reverse-prewarm filing.
    Declined,
    /// No entry at the key.
    Absent,
}

pub(in crate::afxdp) fn remove_shared_session(
    shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_nat_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_forward_wire_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_owner_rg_indexes: &SharedSessionOwnerRgIndexes,
    key: &SessionKey,
) {
    let _ = remove_shared_session_if(
        shared_sessions,
        shared_nat_sessions,
        shared_forward_wire_sessions,
        shared_owner_rg_indexes,
        key,
        |_| true,
    );
}

/// `remove_shared_session` with the removal CONDITIONAL on a predicate evaluated
/// under the SAME lock hold that performs it (#9714 review round 2, finding 3).
///
/// The delete path used to clone the entry, release the lock, decide, and only then
/// call the unconditional remove — so a local replacement published in that window
/// was destroyed on a decision taken about a DIFFERENT entry. Deciding inside the
/// removal's own lock hold closes the window without needing an identity token: the
/// entry the predicate sees IS the entry removed. A stamp would validate a token and
/// then trust it, which leaves the same window one step further along.
///
/// The review prescribed "an incarnation/generation comparison". That identity does
/// not exist: `generation` is 0 for local-origin entries and `session_id` is 0 for
/// local-origin publishes, and local entries are exactly the population this guard
/// protects. So the goal is reached by the route that exists rather than the one
/// prescribed.
pub(in crate::afxdp) fn remove_shared_session_if(
    shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_nat_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_forward_wire_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_owner_rg_indexes: &SharedSessionOwnerRgIndexes,
    key: &SessionKey,
    accept: impl FnOnce(&SyncedSessionEntry) -> bool,
) -> SharedRemoval {
    // #7209: un-file this key from the reverse-prewarm index HERE, so that
    // EVERY removal path is covered rather than only the coordinator's delete
    // verb. `purge_translated_synced_hit` (session_glue/promote.rs) and the
    // LocalDelivery replacement after `take_synced_local` (session/lookup.rs)
    // both remove a peer-synced forward entry through this function and neither
    // calls `refresh_reverse_prewarm_owner_rg_indexes`. A later coordinator
    // delete then finds no stored entry and refreshes with `(None, None)`, so
    // before this the filing survived for the life of the process with no
    // session behind it — the same unbounded strand #7209 set out to close,
    // reached by a different door.
    //
    // Unconditional, and BEFORE the `remove` below: correctness does not depend
    // on the entry still being present. A key with no entry must not be filed
    // either — the activation prewarm looks the key up and skips it, so such a
    // filing is pure scan cost on the failover critical path.
    //
    // Needs no `forwarding`, which is what allows it to live here at all. While
    // the un-file was derived from the FIB it could only be done where a
    // `ForwardingState` was in scope, and it could not be authoritative anyway.
    // #9714 r2 F3: the un-file MOVED to after the decision — see the block near the
    // end of this function. It stays unconditional for the ABSENT and REMOVED cases,
    // which is what #7209 above requires; it is skipped only on a DECLINE, where the
    // entry remains LIVE and un-filing it would strand a session that still exists
    // (the activation prewarm skips a key it cannot find).
    //
    // The removal takes `shared_sessions` then the prewarm index. Publish paths
    // release `shared_sessions` before refreshing the prewarm index, and
    // production callers hold neither lock across this call. This nested
    // order makes removal atomic against the publish-then-file sequence;
    // #13672's regression pins the interleaving.
    //
    // #2402: recover poison so a delete-sync removal is never silently
    // skipped (leaving a stale entry that would mis-route after failover)
    // because a worker panicked under the shared-session lock.
    let mut sessions = lock_shared_recover(shared_sessions);
    if let Some(candidate) = sessions.get(key)
        && !accept(candidate)
    {
        return SharedRemoval::Declined;
    }
    let removed_entry = sessions.remove(key);
    if let Some(entry) = removed_entry.as_ref() {
        lock_shared_recover(&shared_owner_rg_indexes.bare_tuple_sessions).remove(&entry.key);
        remove_owner_rg_index_entry(
            &shared_owner_rg_indexes.sessions,
            entry.metadata.owner_rg_id,
            key,
        );
        if !entry.metadata.is_reverse {
            let mut nat_sessions = lock_shared_recover(shared_nat_sessions);
            let reverse_wire = reverse_session_key(&entry.key, entry.decision.nat);
            // #9679: each alias is deleted only while it still names this session.
            // The reverse order, where this session displaced the survivor at
            // publish, already lost the survivor's alias there (#1760); nothing at
            // removal can bring it back.
            if let Some(removed) =
                remove_shared_alias_owned_by(&mut nat_sessions, &reverse_wire, &entry.key)
            {
                remove_owner_rg_index_entry(
                    &shared_owner_rg_indexes.nat_sessions,
                    removed.metadata.owner_rg_id,
                    &reverse_wire,
                );
            }
            let reverse_canonical = reverse_canonical_key(&entry.key, entry.decision.nat);
            if reverse_canonical != reverse_wire
                && let Some(removed) =
                    remove_shared_alias_owned_by(&mut nat_sessions, &reverse_canonical, &entry.key)
            {
                remove_owner_rg_index_entry(
                    &shared_owner_rg_indexes.nat_sessions,
                    removed.metadata.owner_rg_id,
                    &reverse_canonical,
                );
            }
            drop(nat_sessions);
            // #15104: forget this entry's NAT ambiguity claims. The owner
            // multiset drops the alias record only when no surviving
            // forward entry maps to it, so a displaced survivor keeps its
            // (ambiguous) record and a sole survivor is restored to
            // unique. This runs for every forward removal, NAT'd or not:
            // publish observes the reverse alias unconditionally.
            {
                let mut ambiguities =
                    lock_shared_recover(&shared_owner_rg_indexes.nat_ambiguities);
                ambiguities.forget_owner(
                    &crate::session::reverse_match_key(&reverse_wire),
                    &entry.key,
                );
                if reverse_canonical != reverse_wire {
                    ambiguities.forget_owner(
                        &crate::session::reverse_match_key(&reverse_canonical),
                        &entry.key,
                    );
                }
            }
            {
                let wire_key = forward_wire_key(&entry.key, entry.decision.nat);
                if wire_key != entry.key {
                    // #14383: after this removal, re-resolve the wire key
                    // against the survivors. The wire map holds one entry per
                    // key, so an ambiguous key may currently name the removed
                    // entry, the survivor, or nothing (the survivor was
                    // displaced at publish). Exactly one survivor: restore
                    // its alias and reset the ambiguity record to it, so the
                    // shared wire lookup resolves again. No survivor: drop
                    // the alias and the record. Two or more survivors: the
                    // key stays ambiguous and unresolvable.
                    //
                    // #15106 (A71-03): the #14383 code re-resolved survivors
                    // by scanning every row of `shared_sessions` while holding
                    // its mutex — the #11299 shape, O(table) per NAT'd removal.
                    // The per-wire-key owner multiset maintained in
                    // `publish_shared_session` now answers in O(1). The roster
                    // is only trusted when it actually recorded the removed
                    // owner and the index is not saturated; the legacy scan
                    // below stays as a fail-closed-compatible fallback for
                    // unrecorded/saturated state (e.g. a session seeded by a
                    // bare map insert), reseeding the roster from its result.
                    let mut forward_wire_sessions =
                        lock_shared_recover(shared_forward_wire_sessions);
                    let mut wire_ambiguities =
                        lock_shared_recover(&shared_owner_rg_indexes.wire_ambiguities);
                    let roster_before = wire_ambiguities.wire_owner_count(&wire_key);
                    let remaining =
                        wire_ambiguities.remove_wire_owner(&wire_key, &entry.key);
                    let roster_trusted = wire_ambiguities.wire_owners_trusted()
                        && roster_before > 0
                        && remaining == roster_before - 1;
                    // Verdict: 0 = drop alias + forget, 1 = restore the sole
                    // survivor, 2+ = stay ambiguous (existing semantics).
                    let (survivor_key, survivor_count) = if roster_trusted {
                        let first = if remaining == 1 {
                            wire_ambiguities.wire_first_owner(&wire_key)
                        } else {
                            None
                        };
                        (first, remaining)
                    } else {
                        // Legacy fallback: scan at most 2 survivors (same
                        // filter/take as pre-#15106), then reseed the roster
                        // so later removals take the O(1) path.
                        let mut survivors = sessions
                            .values()
                            .filter(|candidate| {
                                !candidate.metadata.is_reverse
                                    && candidate.key != entry.key
                                    && forward_wire_key(&candidate.key, candidate.decision.nat)
                                        == wire_key
                            })
                            .take(2);
                        let survivor = survivors.next().cloned();
                        let still_ambiguous = survivors.next().is_some();
                        let count = match (&survivor, still_ambiguous) {
                            (Some(_), true) => 2,
                            (Some(_), false) => 1,
                            (None, _) => 0,
                        };
                        // Reseed only when the scan could name every survivor
                        // (count < 2); an ambiguous pair leaves the roster as
                        // found so the next removal rescans rather than
                        // trusting a partial roster.
                        if count < 2 {
                            let owners: Vec<SessionKey> = match &survivor {
                                Some(s) => vec![s.key.clone()],
                                None => Vec::new(),
                            };
                            wire_ambiguities.reset_wire_owners(wire_key.clone(), &owners);
                        }
                        (survivor.map(|s| s.key), count)
                    };
                    let still_ambiguous = survivor_count >= 2;
                    match survivor_key {
                        Some(survivor_key) if !still_ambiguous => {
                            // Fetch the full surviving entry by key from
                            // `shared_sessions` (still held) instead of
                            // scanning its values.
                            match sessions.get(&survivor_key).cloned() {
                                Some(survivor) => {
                                    let previous_owner_rg = forward_wire_sessions
                                        .insert(wire_key.clone(), survivor.clone())
                                        .map(|existing| existing.metadata.owner_rg_id);
                                    update_owner_rg_index(
                                        &shared_owner_rg_indexes.forward_wire_sessions,
                                        &wire_key,
                                        previous_owner_rg,
                                        survivor.metadata.owner_rg_id,
                                    );
                                    wire_ambiguities.reset_to_owner(
                                        wire_key.clone(),
                                        survivor.key.clone(),
                                    );
                                }
                                None => {
                                    // Roster named an owner no longer in
                                    // `shared_sessions`: fail closed — drop
                                    // only the removed entry's own alias and
                                    // forget the wire record (#9679).
                                    if let Some(removed) = remove_shared_alias_owned_by(
                                        &mut forward_wire_sessions,
                                        &wire_key,
                                        &entry.key,
                                    ) {
                                        remove_owner_rg_index_entry(
                                            &shared_owner_rg_indexes.forward_wire_sessions,
                                            removed.metadata.owner_rg_id,
                                            &wire_key,
                                        );
                                    }
                                    wire_ambiguities.forget(&wire_key);
                                }
                            }
                        }
                        _ => {
                            // No survivor, or still ambiguous: only the
                            // removed entry's own alias may be deleted
                            // (#9679 ownership discipline).
                            if let Some(removed) = remove_shared_alias_owned_by(
                                &mut forward_wire_sessions,
                                &wire_key,
                                &entry.key,
                            ) {
                                remove_owner_rg_index_entry(
                                    &shared_owner_rg_indexes.forward_wire_sessions,
                                    removed.metadata.owner_rg_id,
                                    &wire_key,
                                );
                            }
                            if !still_ambiguous {
                                wire_ambiguities.forget(&wire_key);
                            }
                        }
                    }
                }
            }
        }
    }
    // Keep `shared_sessions` held through the prewarm un-file. If this lock is
    // dropped first, a concurrent publisher can install a replacement and file
    // it in `reverse_prewarm_sessions` before this unconditional cleanup runs;
    // the cleanup would then erase the live replacement's only candidate filing
    // (#13672 D11-06). Publishers serialize their shared-map write on this lock
    // and file the prewarm index afterward, so this order leaves their filing
    // intact.
    {
        let mut index = lock_shared_recover(&shared_owner_rg_indexes.reverse_prewarm_sessions);
        remove_owner_rg_index_key_from_every_bucket_locked(&mut index, key);
    }
    match removed_entry {
        Some(entry) => SharedRemoval::Removed(Box::new(entry)),
        None => SharedRemoval::Absent,
    }
}

pub(in crate::afxdp) fn owner_rg_session_keys(
    index: &Arc<Mutex<OwnerRgSessionIndex>>,
    owner_rgs: &[i32],
) -> Vec<SessionKey> {
    let mut keys = FastSet::default();
    {
        // #2402: recover poison so the owner-RG index is not silently
        // emptied (which hides every session from promotion/demotion).
        let index = lock_shared_recover(index);
        for owner_rg_id in owner_rgs {
            if let Some(entries) = index.get(owner_rg_id) {
                keys.extend(entries.iter().cloned());
            }
        }
    }
    keys.into_iter().collect()
}

pub(in crate::afxdp) fn owner_rg_session_keys_serialized(
    sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    index: &Arc<Mutex<OwnerRgSessionIndex>>,
    owner_rgs: &[i32],
) -> Vec<SessionKey> {
    // #2402: hold the shared-session lock (recovering poison) to serialize
    // against concurrent insert/remove while the index is read.
    let _sessions = lock_shared_recover(sessions);
    owner_rg_session_keys(index, owner_rgs)
}

/// Maintain the reverse-prewarm owner-RG index across one entry transition:
/// `(Some, None)` is a delete, `(None, Some)` an insert, `(Some, Some)` a
/// replace of the same key.
///
/// #7209: THE INDEX IS ADD-ONLY WHILE THE ENTRY IS LIVE. Un-filing happens
/// exactly once, when the entry is authoritatively REMOVED — and that is done
/// by `remove_shared_session`, not here, so that every removal path is covered
/// rather than only the coordinator's delete verb.
///
/// An entry's buckets are `reverse_prewarm_owner_rg_candidates`: the RG named
/// by its own metadata (which travels with the entry, so it cannot drift) and
/// the RG that owns the egress interface a reply to `key.src_ip` would leave
/// by — read out of the FIB, and therefore a property of WHEN the question is
/// asked. So a refresh can only ever compute the buckets the FIB can name
/// *right now*, which is a strict SUBSET of the truth whenever the FIB is
/// momentarily blind to the reply path: a RETH member down with the route not
/// yet re-homed, or `stop_inner` having emptied `forwarding` between a failed
/// reconcile and its retry.
///
/// THE TWO DIRECTIONS ARE NOT SYMMETRIC, which is the whole design.
///
///   * An EXTRA bucket costs one re-synthesis that
///     `prewarm_reverse_synced_sessions_for_owner_rgs` then discards — it
///     re-derives the reverse companion under live tables and re-checks
///     `owner_rg_set.contains(..)` before keeping anything. The consumer
///     absorbs over-filing by construction.
///   * A MISSING bucket is never checked, because the key never enters the
///     candidate set at all. The session is simply not pre-resolved when that
///     RG activates.
///
/// So over-filing degrades a scan and under-filing drops reply traffic at a
/// failover. Anything this function cannot re-derive, it must not remove.
///
/// HISTORY, because the shape here is the second attempt and the first one
/// shipped. Originally the removal half recomputed the PREVIOUS entry's
/// candidate set against the CURRENT forwarding, which stranded a key
/// permanently whenever a route moved between RGs during the entry's life —
/// the index is only READ, never rebuilt, by the activation prewarm, so
/// nothing ever named that bucket again. PR #8479 fixed that by making every
/// refresh un-file from EVERY bucket and re-file `candidates(next)`, which
/// removed the strand and introduced the inverse defect above: a refresh
/// landing in a blind-FIB window narrowed the filing and nothing restored it.
/// Splitting the two — add-only here, authoritative un-file at removal — is
/// what gets both, and it is why the un-file no longer needs `forwarding` at
/// all and could therefore move to the one place every removal goes through.
pub(in crate::afxdp) fn refresh_reverse_prewarm_owner_rg_indexes(
    index: &Arc<Mutex<OwnerRgSessionIndex>>,
    forwarding: &ForwardingState,
    dynamic_neighbors: &Arc<ShardedNeighborMap>,
    previous_entry: Option<&SyncedSessionEntry>,
    next_entry: Option<&SyncedSessionEntry>,
) {
    let Some(next_entry) = next_entry else {
        // A removal. Un-file authoritatively — the entry is gone, so no bucket
        // it holds can still be wanted, and no FIB lookup is needed to know
        // that. `remove_shared_session` already does this for every removal
        // path; keeping it here too makes the coordinator's delete verb
        // self-contained and the operation is idempotent.
        if let Some(previous_entry) = previous_entry {
            // #2402: recover poison so index maintenance is not skipped after
            // a prior worker panic.
            let mut index = lock_shared_recover(index);
            remove_owner_rg_index_key_from_every_bucket_locked(&mut index, &previous_entry.key);
        }
        return;
    };
    // The entry is live: ADD what the FIB can name now, remove nothing.
    // `previous_entry` is deliberately unused on this arm — its buckets were
    // filed by an earlier call that could see a FIB this one may not.
    let next_owner_rgs =
        reverse_prewarm_owner_rg_candidates(forwarding, dynamic_neighbors, next_entry);
    let mut index = lock_shared_recover(index);
    for owner_rg_id in next_owner_rgs {
        index
            .entry(owner_rg_id)
            .or_insert_with(FastSet::default)
            .insert(next_entry.key.clone());
    }
}

/// #7209: drop `key` from every owner-RG bucket, pruning buckets it emptied.
///
/// Needs no `forwarding`, which is the point: an authoritative un-file must not
/// depend on a table that may be unable to name the buckets the key is in.
///
/// The `retain` predicate also drops buckets that were ALREADY empty. That is
/// not a behaviour change: `remove_owner_rg_index_entry_locked` has always
/// pruned on emptying, so an empty bucket is unreachable state, and
/// `owner_rg_session_keys` reads through `get`, for which an empty set and an
/// absent one are indistinguishable.
///
/// COST, stated honestly. `HashMap::retain` is O(CAPACITY), not O(len), so this
/// walks the whole allocation and the pruning does not shrink its high-water
/// capacity. Capacity is bounded by the number of DISTINCT owner-RG ids ever
/// filed, which on a real chassis cluster is single digits — but the helper
/// does not enforce that: `metadata.owner_rg_id` arrives from the peer as a raw
/// `i32` and every positive value is filed. A peer sending N distinct ids
/// therefore inflates this walk. That is a bound worth enforcing at the import
/// boundary rather than assuming here; it is not enforced today. Runs once per
/// authoritative removal (never per refresh) on the control thread, and
/// allocates nothing.
fn remove_owner_rg_index_key_from_every_bucket_locked(
    index: &mut OwnerRgSessionIndex,
    key: &SessionKey,
) {
    index.retain(|_, keys| {
        keys.remove(key);
        !keys.is_empty()
    });
}

/// #7209: test-only view of the candidate set, so a cell can assert which
/// arrangement its fixture is actually in rather than assuming it.
#[cfg(test)]
pub(in crate::afxdp) fn reverse_prewarm_owner_rg_candidates_for_test(
    forwarding: &ForwardingState,
    dynamic_neighbors: &Arc<ShardedNeighborMap>,
    entry: &SyncedSessionEntry,
) -> FastSet<i32> {
    reverse_prewarm_owner_rg_candidates(forwarding, dynamic_neighbors, entry)
}

fn reverse_prewarm_owner_rg_candidates(
    forwarding: &ForwardingState,
    dynamic_neighbors: &Arc<ShardedNeighborMap>,
    entry: &SyncedSessionEntry,
) -> FastSet<i32> {
    let mut owner_rgs = FastSet::default();
    if entry.metadata.is_reverse || !entry.origin.is_peer_synced() {
        return owner_rgs;
    }
    // #8486: PEER-SUPPLIED, so it is bounded here. `reverse_owner_rg_id` below
    // is derived from THIS node's own forwarding state and needs no bound.
    if is_fileable_owner_rg(entry.metadata.owner_rg_id) {
        owner_rgs.insert(entry.metadata.owner_rg_id);
    }
    // #12086 R1-F2: derive the reply target's native table exactly as
    // `synthesized_synced_reverse_entry` does. A forward PBR install stamp is
    // directional and can name a table with no route to the reply target.
    // Keep an Unresolvable native table in the add-only index as a best-effort
    // default-table candidate: over-filing is discarded by the activation
    // consumer, while under-filing omits the reverse owner RG entirely (#7209).
    let reverse_table = match super::forwarding::native_route_table_for_flow_target(
        forwarding,
        entry.key.routing_domain,
        entry.metadata.ingress_ifindex as i32,
        entry.metadata.ingress_vlan_id,
        None,
        entry.key.src_ip,
    ) {
        super::forwarding::NativeRouteTable::Default
        | super::forwarding::NativeRouteTable::Unresolvable { .. } => None,
        super::forwarding::NativeRouteTable::Table { table, .. } => Some(table),
    };
    let reverse_table = reverse_table.as_deref();
    let reverse_resolution =
        super::interface_nat_local_resolution(forwarding, entry.key.src_ip, reverse_table)
            .unwrap_or_else(|| {
                super::forwarding::lookup_forwarding_resolution_in_table_with_dynamic(
                    forwarding,
                    dynamic_neighbors,
                    entry.key.src_ip,
                    reverse_table,
                )
                .resolution
            });
    let reverse_owner_rg_id = owner_rg_for_resolution(forwarding, reverse_resolution);
    if reverse_owner_rg_id > 0 {
        owner_rgs.insert(reverse_owner_rg_id);
    }
    owner_rgs
}

fn update_owner_rg_index(
    index: &Arc<Mutex<OwnerRgSessionIndex>>,
    key: &SessionKey,
    previous_owner_rg: Option<i32>,
    owner_rg_id: i32,
) {
    if let Some(previous_owner_rg) = previous_owner_rg
        && previous_owner_rg != owner_rg_id
    {
        remove_owner_rg_index_entry(index, previous_owner_rg, key);
    }
    // #8486: the bound is here, on the FILING, not on the import.
    if !is_fileable_owner_rg(owner_rg_id) {
        return;
    }
    // #2402: recover poison (owner-RG index maintenance).
    let mut index = lock_shared_recover(index);
    index
        .entry(owner_rg_id)
        .or_insert_with(FastSet::default)
        .insert(key.clone());
}

fn remove_owner_rg_index_entry(
    index: &Arc<Mutex<OwnerRgSessionIndex>>,
    owner_rg_id: i32,
    key: &SessionKey,
) {
    if owner_rg_id <= 0 {
        return;
    }
    // #2402: recover poison (owner-RG index maintenance).
    let mut index = lock_shared_recover(index);
    remove_owner_rg_index_entry_locked(&mut index, owner_rg_id, key);
}

fn remove_owner_rg_index_entry_locked(
    index: &mut OwnerRgSessionIndex,
    owner_rg_id: i32,
    key: &SessionKey,
) {
    if let Some(keys) = index.get_mut(&owner_rg_id) {
        keys.remove(key);
        if keys.is_empty() {
            index.remove(&owner_rg_id);
        }
    }
}
