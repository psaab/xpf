use super::*;
use std::sync::atomic::AtomicU64;
use std::sync::{MutexGuard, TryLockError};

/// #4800: calls to [`publish_shared_session`] — one per session published
/// into the cross-worker shared maps, i.e. one per new transit flow (plus
/// its reverse companion) and one per promote / HA import / tunnel install.
///
/// This is the DENOMINATOR for the publish leg of the new-flow-install
/// serialization question. On its own a publish rate says nothing; paired
/// with `SHARED_SESSION_PUBLISH_LOCK_CONTENDED` it says whether the publish
/// mutexes are where new flows queue up.
pub(crate) static SHARED_SESSION_PUBLISHES: AtomicU64 = AtomicU64::new(0);

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
pub(super) fn lock_shared_recover<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
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

pub(super) fn demote_shared_owner_rgs(
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
                entry.origin = SessionOrigin::SyncImport;
            }
        }
    }
    {
        let mut sessions = lock_shared_recover(shared_forward_wire_sessions);
        for key in owner_rg_session_keys(&shared_owner_rg_indexes.forward_wire_sessions, owner_rgs)
        {
            if let Some(entry) = sessions.get_mut(&key) {
                entry.origin = SessionOrigin::SyncImport;
            }
        }
    }
}

pub(super) fn synced_replica_entry(entry: &SyncedSessionEntry) -> SyncedSessionEntry {
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
pub(super) fn merge_owner_rg_candidate_keys(
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
pub(super) fn prewarm_reverse_synced_sessions_for_owner_rgs(
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
pub(super) fn republish_bpf_session_entries_for_owner_rgs(
    shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_owner_rg_indexes: &SharedSessionOwnerRgIndexes,
    session_map: SteeringMap<'_>,
    owner_rgs: &[i32],
    // #9517: this republishes peer-synced sessions on RG activation, which is
    // exactly where PASS_TO_KERNEL rows come from.
    has_routing_domains: bool,
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
                    .map(|e| (e.key.clone(), e.decision, e.metadata.clone()))
            })
            .collect()
    };
    let mut published = 0u32;
    let mut errors = 0u32;
    for (key, decision, metadata) in &entries {
        if publish_session_map_entry_for_session(
            session_map,
            key,
            *decision,
            metadata,
            has_routing_domains,
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

pub(super) fn lookup_shared_session(
    shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    key: &SessionKey,
) -> Option<SyncedSessionEntry> {
    // #2402: recover poison so a prior worker panic does not turn every
    // shared-session lookup into a spurious miss.
    lock_shared_recover(shared_sessions).get(key).cloned()
}

pub(super) fn lookup_shared_forward_nat_match(
    shared_nat_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    reply_key: &SessionKey,
) -> Option<SyncedSessionEntry> {
    // #2402: recover poison (see lookup_shared_session).
    let map = lock_shared_recover(shared_nat_sessions);
    // #7160 (#2387): the shared NAT map is published under BOTH reverse keys —
    // `reverse_session_key` (which PRESERVES the routing domain) and
    // `reverse_canonical_key` (which zeroes it, being a reverse-MATCH key).
    // Probe in that order so a reply that resolved the flow's own domain
    // demuxes to its own tenant's entry, and a reply that arrived in another
    // domain still resolves through the domain-agnostic entry. This is the
    // same preference `find_forward_nat_match` applies to the local 1:N
    // bucket, expressed as two probes because this map is 1:1.
    //
    // A domain-0 reply key makes the second probe identical to the first;
    // `reverse_match_key` returns the key unchanged in that case, so a
    // deployment with no routing-instance interface membership pays one
    // lookup, exactly as before.
    if let Some(exact) = map.get(reply_key).cloned() {
        return Some(exact);
    }
    let probe = crate::session::reverse_match_key(reply_key);
    if probe == *reply_key {
        return None;
    }
    map.get(&probe).cloned()
}

pub(super) fn lookup_shared_forward_wire_match(
    shared_forward_wire_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    wire_key: &SessionKey,
) -> Option<SyncedSessionEntry> {
    // #2402: recover poison (see lookup_shared_session).
    lock_shared_recover(shared_forward_wire_sessions).get(wire_key).cloned()
}

#[derive(Clone, Debug)]
pub(super) enum ResolvedSessionKey {
    QueryKey,
    Canonical(SessionKey),
}

impl ResolvedSessionKey {
    pub(super) fn as_ref<'a>(&'a self, query_key: &'a SessionKey) -> &'a SessionKey {
        match self {
            Self::QueryKey => query_key,
            Self::Canonical(key) => key,
        }
    }
}

#[derive(Clone, Debug)]
pub(super) struct ResolvedSessionLookup {
    pub(super) key: ResolvedSessionKey,
    pub(super) lookup: SessionLookup,
    pub(super) shared_entry: Option<SyncedSessionEntry>,
    pub(super) origin: SessionOrigin,
}

impl ResolvedSessionLookup {
    pub(super) fn local_query(lookup: SessionLookup, origin: SessionOrigin) -> Self {
        Self {
            key: ResolvedSessionKey::QueryKey,
            lookup,
            shared_entry: None,
            origin,
        }
    }

    pub(super) fn local(key: SessionKey, lookup: SessionLookup, origin: SessionOrigin) -> Self {
        Self {
            key: ResolvedSessionKey::Canonical(key),
            lookup,
            shared_entry: None,
            origin,
        }
    }

    pub(super) fn shared(entry: SyncedSessionEntry) -> Self {
        let origin = entry.origin;
        Self {
            key: ResolvedSessionKey::Canonical(entry.key.clone()),
            lookup: SessionLookup {
                decision: entry.decision,
                metadata: entry.metadata.clone(),
            },
            shared_entry: Some(entry),
            origin,
        }
    }
}

#[derive(Clone, Debug)]
pub(super) struct ResolvedFlowSessionDecision {
    pub(super) key: SessionKey,
    pub(super) decision: SessionDecision,
    pub(super) metadata: SessionMetadata,
    pub(super) origin: SessionOrigin,
    pub(super) created: bool,
    /// #1861 §5.4: true when a session install was ATTEMPTED for this
    /// decision and refused (max_sessions) — distinct from "no install
    /// required" (hit paths, DNS fast-path), which stays false. The
    /// flow-cache population gate keys off this so a sessionless
    /// decision is never cached (caching it would suppress the
    /// per-packet reply repair until cache invalidation; Codex #1861
    /// r1 C1).
    pub(super) install_failed: bool,
}

// Fabric-ingress SNAT-only forward entries are standby-side wire placeholders
// in the split-RG topology: they should not win lookups over the real shared
// session and should not synthesize a competing local reverse session.
pub(super) fn is_fabric_wire_placeholder(
    fabric_ingress: bool,
    is_reverse: bool,
    decision: SessionDecision,
) -> bool {
    fabric_ingress
        && !is_reverse
        && decision.nat.rewrite_src.is_some()
        && decision.nat.rewrite_dst.is_none()
}

pub(super) fn lookup_session_across_scopes(
    sessions: &mut SessionTable,
    shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_forward_wire_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    key: &SessionKey,
    now_ns: u64,
    tcp_flags: u8,
) -> Option<ResolvedSessionLookup> {
    if let Some((lookup, origin)) = sessions.lookup_with_origin(key, now_ns, tcp_flags) {
        if is_fabric_wire_placeholder(
            lookup.metadata.fabric_ingress,
            lookup.metadata.is_reverse,
            lookup.decision,
        ) && let Some(shared) =
            lookup_shared_forward_wire_match(shared_forward_wire_sessions, key)
        {
            return Some(ResolvedSessionLookup::shared(shared));
        }
        return Some(ResolvedSessionLookup::local_query(lookup, origin));
    }
    if let Some((matched, origin)) = sessions.find_forward_wire_match_with_origin(key) {
        let lookup = SessionLookup {
            decision: matched.decision,
            metadata: matched.metadata,
        };
        if is_fabric_wire_placeholder(
            lookup.metadata.fabric_ingress,
            lookup.metadata.is_reverse,
            lookup.decision,
        ) && let Some(shared) =
            lookup_shared_forward_wire_match(shared_forward_wire_sessions, key)
        {
            return Some(ResolvedSessionLookup::shared(shared));
        }
        return Some(ResolvedSessionLookup::local(matched.key, lookup, origin));
    }
    lookup_shared_session(shared_sessions, key)
        .map(ResolvedSessionLookup::shared)
        .or_else(|| {
            lookup_shared_forward_wire_match(shared_forward_wire_sessions, key)
                .map(ResolvedSessionLookup::shared)
        })
}

/// #7169: what the caller knows about where the packet being matched actually
/// ARRIVED, so a reverse-canonical match can be revalidated against it.
///
/// The reverse-canonical index is keyed on a session's PRE-NAT reply tuple, so a
/// match means only "this 5-tuple equals a live session's private-side reply
/// tuple". Nothing about that establishes the packet came from where the reply
/// was expected — and on the main path a match installs a reverse session
/// carrying the original flow's zone pair, which then takes the established fast
/// path with no policy evaluation. Tuple equality alone was deciding both.
///
/// Three states, deliberately, with no variant that silently means "skip":
/// a lookup miss must not fail open into the same hole.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ReverseIngress {
    /// The zone the packet actually arrived in. A match is accepted only if the
    /// forward session EGRESSED to this zone — a reply must come back from
    /// where the flow went.
    ///
    /// Zone, not ifindex, on purpose: a zone can legitimately span interfaces,
    /// so a reply may arrive on a different member (LAG, ECMP, a route change)
    /// and still be the same flow. Ifindex equality would reject those. Zone is
    /// also the granularity policy is written against, which is what the
    /// synthesized session's metadata gets wrong.
    Zone(u16),
    /// The arrival interface has no zone mapping, so there is nothing to
    /// revalidate against. Fails CLOSED: no reverse match is synthesized.
    /// Distinct from `Unconstrained` precisely so an unmapped ifindex cannot
    /// reach the same outcome as a deliberate exemption.
    Unzoned,
    /// The caller asserts no ingress constraint, and owes a reason at the call
    /// site. Two hold today:
    ///
    /// * the ICMP embedded-error rewriters, which use the match only to recover
    ///   a pre-NAT tuple and install NO session — and where an error may
    ///   legitimately originate off-path (an intermediate router), so
    ///   constraining the arrival zone would break PMTUD;
    /// * a FABRIC-ingress packet, which arrives on the fabric link from the
    ///   peer node rather than in its logical ingress zone, so its arrival zone
    ///   is structurally not the flow's.
    Unconstrained,
}

/// Apply the #7169 ingress revalidation to a candidate match.
fn revalidate_reverse_ingress(
    m: ForwardSessionMatch,
    ingress: ReverseIngress,
) -> Option<ForwardSessionMatch> {
    match ingress {
        ReverseIngress::Unconstrained => Some(m),
        ReverseIngress::Unzoned => None,
        // The reply must arrive from the zone the forward flow egressed to.
        // On mismatch this returns NO MATCH rather than dropping: the packet
        // then falls through to ordinary policy evaluation IN THE ZONE IT
        // ACTUALLY ARRIVED IN, which is the correct adjudication. Dropping here
        // would substitute one unconsidered verdict for another.
        ReverseIngress::Zone(z) if m.metadata.egress_zone == z => Some(m),
        ReverseIngress::Zone(_) => None,
    }
}

pub(super) fn lookup_forward_nat_across_scopes(
    sessions: &SessionTable,
    shared_nat_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    reply_key: &SessionKey,
    ingress: ReverseIngress,
) -> Option<ForwardSessionMatch> {
    let m = lookup_forward_nat_across_scopes_inner(sessions, shared_nat_sessions, reply_key)?;
    revalidate_reverse_ingress(m, ingress)
}

fn lookup_forward_nat_across_scopes_inner(
    sessions: &SessionTable,
    shared_nat_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    reply_key: &SessionKey,
) -> Option<ForwardSessionMatch> {
    if let Some(local) = sessions.find_forward_nat_match(reply_key) {
        if is_fabric_wire_placeholder(
            local.metadata.fabric_ingress,
            local.metadata.is_reverse,
            local.decision,
        ) {
            return lookup_shared_forward_nat_match(shared_nat_sessions, reply_key).map(|entry| {
                ForwardSessionMatch {
                    key: entry.key,
                    decision: entry.decision,
                    metadata: entry.metadata,
                }
            });
        }
        return Some(local);
    }
    lookup_shared_forward_nat_match(shared_nat_sessions, reply_key).map(|entry| {
        ForwardSessionMatch {
            key: entry.key,
            decision: entry.decision,
            metadata: entry.metadata,
        }
    })
}

pub(super) fn build_reverse_session_from_forward_match(
    forwarding: &ForwardingState,
    ha_state: &BTreeMap<i32, HAGroupRuntime>,
    dynamic_neighbors: &Arc<ShardedNeighborMap>,
    forward_match: ForwardSessionMatch,
    now_secs: u64,
    ha_startup_grace_until_secs: u64,
) -> SessionLookup {
    let requires_fabric_return = forward_match.metadata.fabric_ingress
        || forward_match.decision.resolution.disposition == ForwardingDisposition::FabricRedirect;
    let resolution = reverse_resolution_for_session(
        forwarding,
        ha_state,
        dynamic_neighbors,
        forward_match.key.src_ip,
        forward_match.metadata.ingress_zone,
        requires_fabric_return,
        now_secs,
        forward_match.decision.resolution.tunnel_endpoint_id != 0
            && now_secs <= ha_startup_grace_until_secs,
    );
    let metadata = SessionMetadata {
        // #7169: this zone pair comes from the STORED forward session, i.e.
        // from where the ORIGINAL flow went — not from where this packet
        // arrived. That is safe only because the caller now revalidates the
        // arrival zone against `metadata.egress_zone` before a match is
        // returned (see `ReverseIngress`), so by the time this runs the two are
        // necessarily equal. Remove that check and this line silently
        // adjudicates a packet in a zone it never arrived in.
        ingress_zone: forward_match.metadata.egress_zone,
        egress_zone: forward_match.metadata.ingress_zone,
        // #7917: DELIBERATELY 0, and not to be "fixed" by inheriting
        // `forward_match.metadata.ingress_ifindex`.
        //
        // A synthesized reverse companion must not take the forward
        // direction's ingress identity: the forward flow's ingress is a
        // PREDICTION of where a reply will arrive, not an OBSERVATION of where
        // it did. 0 means "unobserved", which is truthful; inheriting would
        // make the row confidently wrong, which #6928 refused on the grounds
        // that a wrong interface is strictly worse than none.
        //
        // #7169 was filed listing this zero as part of the defect. It is not.
        // The defect was that nothing checked the ARRIVAL against the session
        // being synthesized, which is a different repair — and the tempting one
        // makes the record worse while leaving the hole open.
        ingress_ifindex: 0,
        ingress_vlan_id: 0,
        // Reverse companions are owned by the RG that currently owns the
        // client-side egress resolution, not necessarily the RG that owned the
        // original forward session. This matters during failback when a second
        // RG comes up later and stale reverse entries must be repointed away
        // from prior FabricRedirect results.
        owner_rg_id: owner_rg_for_resolution(forwarding, resolution),
        fabric_ingress: forward_match.metadata.fabric_ingress,
        is_reverse: true,
        // #4565: inherit the forward session's NAT64 reverse info (original v6
        // src/dst) so a peer-PROMOTED NAT64 session's synthesized reverse
        // companion can translate the server's v4 reply back to IPv6 after
        // failover. `build_nat64_forwarded_frame`'s reverse (v4->v6) branch
        // hard-requires this — without it the frame builder returns None and the
        // reply is dropped. `None` for every non-NAT64 forward session (the
        // forward metadata carries `None`), bit-identical to the prior behavior.
        nat64_reverse: forward_match.metadata.nat64_reverse,
        // #2508: inherit the forward session's per-policy log selection so
        // the reverse companion's close delta carries a consistent gate.
        log_session_init: forward_match.metadata.log_session_init,
        log_session_close: forward_match.metadata.log_session_close,
        // #3056: inherit the admitting policy ID from the forward session so a
        // materialized reverse companion attributes the same policy in its
        // BPF-compat conntrack row.
        policy_id: forward_match.metadata.policy_id,
        // #5153: inherit the forward session's per-application idle timeout so
        // the reverse companion ages on the admitting app's window, not the
        // global timeout. Both halves of one stateful flow share the same
        // application, so the app's `inactivity-timeout` governs either
        // direction. `companion_keeps_alive` (expire.rs) uses the companion's
        // OWN `expires_after_ns` — derived from this field via
        // `session_timeout_ns` — to decide whether to keep the idle-crossed
        // forward half alive; hardcoding `None` here made the reverse
        // companion's window fall back to the global timeout (e.g. 300s),
        // extending a 30s app timeout toward the global one. `None` for every
        // forward session with no per-app override (the forward metadata
        // carries `None`), bit-identical to the prior behavior. Residual of
        // #3227/#3301/#4380.
        inactivity_timeout_ns: forward_match.metadata.inactivity_timeout_ns,
        // #3073: inherit the admitting rule's hit-counter handle from the
        // forward session so a materialized reverse companion's reply traffic
        // counts against the same policy. #3322: inherit the reorder-stable
        // bound handle too so the reply counts against the admitting rule
        // even after a live policy reorder.
        policy_counter_idx: forward_match.metadata.policy_counter_idx,
        policy_counter: forward_match.metadata.policy_counter.clone(),
    };
    let decision = SessionDecision {
        resolution: redirect_session_resolution_for_metadata(forwarding, resolution, &metadata),
        nat: forward_match.decision.nat.reverse(
            forward_match.key.src_ip,
            forward_match.key.dst_ip,
            forward_match.key.src_port,
            forward_match.key.dst_port,
        ),
    };
    SessionLookup { decision, metadata }
}

pub(super) fn synthesized_synced_reverse_entry(
    forwarding: &ForwardingState,
    ha_state: &BTreeMap<i32, HAGroupRuntime>,
    dynamic_neighbors: &Arc<ShardedNeighborMap>,
    entry: &SyncedSessionEntry,
    now_secs: u64,
) -> Option<SyncedSessionEntry> {
    if entry.metadata.is_reverse {
        return None;
    }
    let reverse_key = reverse_session_key(&entry.key, entry.decision.nat);
    let reverse = build_reverse_session_from_forward_match(
        forwarding,
        ha_state,
        dynamic_neighbors,
        ForwardSessionMatch {
            key: entry.key.clone(),
            decision: entry.decision,
            metadata: entry.metadata.clone(),
        },
        now_secs,
        0,
    );
    let metadata = reverse.metadata;
    Some(SyncedSessionEntry {
        key: reverse_key,
        decision: reverse.decision,
        metadata,
        origin: SessionOrigin::SyncImport,
        protocol: entry.protocol,
        tcp_flags: entry.tcp_flags,
        // #2170: the reverse companion inherits the forward entry's install
        // generation so a delete refusal is consistent across both halves.
        generation: entry.generation,
        session_id: 0,
        // #9412: the reverse half carries the SAME close class as the forward
        // import. With 0, every close-state Update (and the takeover prewarm)
        // re-installed the reverse copy on the established window, and
        // `companion_keeps_alive` then held the closing forward alive with it.
        tcp_close_class: entry.tcp_close_class,
    })
}

pub(super) fn reverse_resolution_for_session(
    forwarding: &ForwardingState,
    ha_state: &BTreeMap<i32, HAGroupRuntime>,
    dynamic_neighbors: &Arc<ShardedNeighborMap>,
    target_ip: IpAddr,
    ingress_zone: u16,
    fabric_ingress: bool,
    now_secs: u64,
    allow_unseeded_tunnel_local: bool,
) -> ForwardingResolution {
    let resolved =
        super::interface_nat_local_resolution(forwarding, target_ip).unwrap_or_else(|| {
            lookup_forwarding_resolution_with_dynamic(forwarding, dynamic_neighbors, target_ip)
        });
    let owner_rg_id = owner_rg_for_resolution(forwarding, resolved);
    if fabric_ingress
        && owner_rg_id > 0
        && !matches!(
            ha_state.get(&owner_rg_id),
            Some(group) if group.is_forwarding_active(now_secs)
        )
        && let Some(redirect) =
            super::forwarding::resolve_zone_encoded_fabric_redirect_by_id(forwarding, ingress_zone)
    {
        return redirect;
    }
    let enforced = enforce_ha_resolution_snapshot(forwarding, ha_state, now_secs, resolved);
    if allow_unseeded_tunnel_local
        && enforced.disposition == ForwardingDisposition::HAInactive
        && owner_rg_is_unseeded(forwarding, ha_state, resolved)
    {
        return resolved;
    }
    enforced
}

pub(super) fn install_reverse_session_from_forward_match(
    sessions: &mut SessionTable,
    session_map: SteeringMap<'_>,
    shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_nat_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_forward_wire_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_owner_rg_indexes: &SharedSessionOwnerRgIndexes,
    peer_worker_commands: &[Arc<Mutex<VecDeque<WorkerCommand>>>],
    forwarding: &ForwardingState,
    ha_state: &BTreeMap<i32, HAGroupRuntime>,
    dynamic_neighbors: &Arc<ShardedNeighborMap>,
    reverse_key: &SessionKey,
    forward_match: ForwardSessionMatch,
    now_ns: u64,
    now_secs: u64,
    ha_startup_grace_until_secs: u64,
    protocol: u8,
    tcp_flags: u8,
) -> (SessionLookup, bool) {
    let reverse = build_reverse_session_from_forward_match(
        forwarding,
        ha_state,
        dynamic_neighbors,
        forward_match,
        now_secs,
        ha_startup_grace_until_secs,
    );
    // #1861 §5.4: the synthesized decision is returned EVEN when the
    // install fails (max_sessions) so the reply keeps forwarding — but
    // the caller must know the outcome: `created` telemetry and the
    // flow-cache eligibility gate both key off it. Caching a decision
    // with no backing session would suppress this repair until cache
    // invalidation (Codex #1861 r1 C1).
    let installed = sessions.install_with_protocol_with_origin(
        reverse_key.clone(),
        reverse.decision,
        reverse.metadata.clone(),
        SessionOrigin::ReverseFlow,
        now_ns,
        protocol,
        tcp_flags,
    );
    if installed {
        // #1789: count failed reverse-install publishes (was `let _ =`).
        // No binding context in this shared-ops path — shared counter.
        if publish_live_session_entry(session_map, reverse_key, reverse.decision.nat, true).is_err()
        {
            SESSION_PUBLISH_ERRORS_SHARED.fetch_add(1, Ordering::Relaxed);
        }
        let reverse_entry = SyncedSessionEntry {
            key: reverse_key.clone(),
            decision: reverse.decision,
            metadata: reverse.metadata.clone(),
            origin: SessionOrigin::ReverseFlow,
            protocol,
            tcp_flags,
            // Local reverse-flow learning: no peer install generation (#2170).
            generation: 0,
            session_id: 0,
            tcp_close_class: 0,
        };
        publish_shared_session(
            shared_sessions,
            shared_nat_sessions,
            shared_forward_wire_sessions,
            shared_owner_rg_indexes,
            &reverse_entry,
        );
        replicate_session_upsert(peer_worker_commands, &reverse_entry);
    }
    (reverse, installed)
}

pub(super) fn publish_shared_session(
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
        update_owner_rg_index(
            &shared_owner_rg_indexes.sessions,
            &entry.key,
            previous_owner_rg,
            entry.metadata.owner_rg_id,
        );
    }
    if !entry.metadata.is_reverse {
        let mut sessions = lock_shared_publish(shared_nat_sessions);
        let reverse_wire = reverse_session_key(&entry.key, entry.decision.nat);
        let displaced = sessions.insert(reverse_wire.clone(), entry.clone());
        record_shared_nat_displacement(displaced.as_ref(), entry);
        let previous_owner_rg = displaced.map(|existing| existing.metadata.owner_rg_id);
        update_owner_rg_index(
            &shared_owner_rg_indexes.nat_sessions,
            &reverse_wire,
            previous_owner_rg,
            entry.metadata.owner_rg_id,
        );
        let reverse_canonical = reverse_canonical_key(&entry.key, entry.decision.nat);
        if reverse_canonical != reverse_wire {
            let displaced = sessions.insert(reverse_canonical.clone(), entry.clone());
            record_shared_nat_displacement(displaced.as_ref(), entry);
            let previous_owner_rg = displaced.map(|existing| existing.metadata.owner_rg_id);
            update_owner_rg_index(
                &shared_owner_rg_indexes.nat_sessions,
                &reverse_canonical,
                previous_owner_rg,
                entry.metadata.owner_rg_id,
            );
        }
    }
    if !entry.metadata.is_reverse {
        let mut sessions = lock_shared_publish(shared_forward_wire_sessions);
        let wire_key = forward_wire_key(&entry.key, entry.decision.nat);
        if wire_key != entry.key {
            let previous_owner_rg = sessions
                .insert(wire_key.clone(), entry.clone())
                .map(|existing| existing.metadata.owner_rg_id);
            update_owner_rg_index(
                &shared_owner_rg_indexes.forward_wire_sessions,
                &wire_key,
                previous_owner_rg,
                entry.metadata.owner_rg_id,
            );
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
    if aliases.get(alias).is_some_and(|stored| &stored.key == owner) {
        aliases.remove(alias)
    } else {
        None
    }
}

pub(super) fn remove_shared_session(
    shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_nat_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_forward_wire_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_owner_rg_indexes: &SharedSessionOwnerRgIndexes,
    key: &SessionKey,
) {
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
    {
        let mut index = lock_shared_recover(&shared_owner_rg_indexes.reverse_prewarm_sessions);
        remove_owner_rg_index_key_from_every_bucket_locked(&mut index, key);
    }
    // #2402: recover poison so a delete-sync removal is never silently
    // skipped (leaving a stale entry that would mis-route after failover)
    // because a worker panicked under the shared-session lock.
    let mut sessions = lock_shared_recover(shared_sessions);
    if let Some(entry) = sessions.remove(key) {
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
            {
                let mut forward_wire_sessions =
                    lock_shared_recover(shared_forward_wire_sessions);
                let wire_key = forward_wire_key(&entry.key, entry.decision.nat);
                if wire_key != entry.key
                    && let Some(removed) = remove_shared_alias_owned_by(
                        &mut forward_wire_sessions,
                        &wire_key,
                        &entry.key,
                    )
                {
                    remove_owner_rg_index_entry(
                        &shared_owner_rg_indexes.forward_wire_sessions,
                        removed.metadata.owner_rg_id,
                        &wire_key,
                    );
                }
            }
        }
    }
}

pub(super) fn owner_rg_session_keys(
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

pub(super) fn owner_rg_session_keys_serialized(
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
pub(super) fn refresh_reverse_prewarm_owner_rg_indexes(
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
pub(super) fn reverse_prewarm_owner_rg_candidates_for_test(
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
    let reverse_resolution = super::interface_nat_local_resolution(forwarding, entry.key.src_ip)
        .unwrap_or_else(|| {
            lookup_forwarding_resolution_with_dynamic(
                forwarding,
                dynamic_neighbors,
                entry.key.src_ip,
            )
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
