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
// #18663: pauses a publisher between primary insertion and alias filing so
// the evidence lookup's primary-lock serialization is deterministic in tests.
#[cfg(test)]
std::thread_local! {
    pub(in crate::afxdp) static SHARED_ALIAS_PRIMARY_LOCK_HOOK_18663:
        std::cell::RefCell<Option<Box<dyn FnOnce()>>> = std::cell::RefCell::new(None);
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

/// Visit every reverse identity that can vouch for a primary row. Forward
/// rows publish the same wire and canonical aliases as `shared_nat_sessions`;
/// reverse rows contribute their NAT-derived opposite tuple.
fn visit_shared_served_aliases(
    entry: &SyncedSessionEntry,
    mut visit: impl FnMut(&SessionKey),
) {
    if entry.metadata.is_reverse {
        let reverse = reverse_session_key(&entry.key, entry.decision.nat);
        visit(&reverse);
        return;
    }
    let reverse_wire = reverse_session_key(&entry.key, entry.decision.nat);
    let reverse_canonical = reverse_canonical_key(&entry.key, entry.decision.nat);
    visit(&reverse_wire);
    if reverse_canonical != reverse_wire {
        visit(&reverse_canonical);
    }
}

fn update_shared_served_aliases(
    aliases: &mut SharedServedAliasIndex,
    entry: &SyncedSessionEntry,
    insert: bool,
) {
    visit_shared_served_aliases(entry, |alias| {
        if insert {
            aliases.insert(alias, &entry.key);
        } else {
            aliases.remove(alias, &entry.key);
        }
    });
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
        // #16223: monotonic handshake stage at the single publish
        // choke point — a republication of the same incarnation
        // (install-time publish, HA resend, barrier replay) must not
        // regress a stage this node already advanced (the ct-slice
        // maintenance restamps Established once a worker's pair
        // completes). A different session_id is a new incarnation
        // and takes the incoming stage as-is.
        let mut entry_owned;
        let entry = if let Some(previous) = sessions.get(&entry.key) {
            let same = entry.session_id == 0
                || previous.session_id == 0
                || entry.session_id == previous.session_id;
            let rank = crate::session::TcpHandshakeState::stage_rank;
            // #16217: reverse-packet evidence is monotonic per
            // incarnation too — a republication carrying a smaller
            // (or zero) count must not erase observed reverse service.
            // The forward-wire alias slot below applies the SAME
            // merge: the alias is a republication of this forward
            // row under the NAT'd tuple, and an install-time
            // (HandshakePending) republication must not regress an
            // Established alias the cache-hit restamp advanced
            // (Codex alias-republish regression).
            let keep_stage =
                same && rank(entry.tcp_handshake_state) < rank(previous.tcp_handshake_state);
            let keep_rev = same && entry.rev_packets < previous.rev_packets;
            let keep_fwd = same && entry.fwd_packets < previous.fwd_packets;
            // #18742: same-incarnation republication must not erase packet
            // recency advanced by the serving sibling's ct-slice.
            let keep_sibling_last_seen =
                same && entry.sibling_last_seen_ns < previous.sibling_last_seen_ns;
            if keep_stage || keep_rev || keep_fwd || keep_sibling_last_seen {
                entry_owned = entry.clone();
                if keep_stage {
                    entry_owned.tcp_handshake_state = previous.tcp_handshake_state;
                }
                if keep_rev {
                    entry_owned.rev_packets = previous.rev_packets;
                }
                if keep_fwd {
                    entry_owned.fwd_packets = previous.fwd_packets;
                }
                if keep_sibling_last_seen {
                    entry_owned.sibling_last_seen_ns = previous.sibling_last_seen_ns;
                }
                &entry_owned
            } else {
                entry
            }
        } else {
            entry
        };
        let previous = sessions.insert(entry.key.clone(), entry.clone());
        let previous_owner_rg = previous
            .as_ref()
            .map(|existing| existing.metadata.owner_rg_id);
        {
        #[cfg(test)]
        SHARED_ALIAS_PRIMARY_LOCK_HOOK_18663.with(|hook| {
            if let Some(hook) = hook.borrow_mut().take() {
                hook();
            }
        });
            // Lock order is shared primary -> served aliases. Evidence readers
            // use the same order and keep the primary lock while resolving an
            // alias, making replacement/displacement visible atomically.
            let mut served_aliases =
                lock_shared_recover(&shared_owner_rg_indexes.served_aliases);
            if let Some(previous) = previous.as_ref() {
                update_shared_served_aliases(&mut served_aliases, previous, false);
            }
            update_shared_served_aliases(&mut served_aliases, entry, true);
        }
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
            // #18658: LOCK ORDER — the forward-wire MAP before
            // `wire_ambiguities`, never the reverse. That is the order
            // `remove_shared_session_if` takes them in (both inside
            // `shared_sessions`). This publish used to take the index first,
            // so a publish holding `wire_ambiguities` and waiting for the map
            // could deadlock against a removal holding the map and waiting for
            // the index. Every worker and the coordinator then queued behind
            // them, permanently (tcp and loss, master 0050ac4172).
            //
            // #14383 still holds: a reader can never observe a wire alias
            // whose owner is unrecorded. The owner is recorded below, after
            // both locks are taken and before the alias is inserted, and
            // readers (`lookup_shared_forward_wire_match`) read the map first,
            // so none can reach the alias before this publish releases the
            // map. A publish that displaces a DIFFERENT forward session marks
            // the key ambiguous; the shared wire lookup then fails closed.
            let mut sessions = lock_shared_publish(shared_forward_wire_sessions);
            #[cfg(test)]
            super::wire_lock_order_18658_tests::publish_between_wire_locks(
                &wire_key,
                shared_forward_wire_sessions,
                &shared_owner_rg_indexes.wire_ambiguities,
            );
            let mut wire_ambiguities =
                lock_wire_ambiguities_for_publish(shared_owner_rg_indexes);
            wire_ambiguities.observe(wire_key.clone(), entry.key.clone());
            // #15106: record the live owner in the per-wire-key multiset so a
            // later removal resolves survivors in O(1) instead of scanning
            // `shared_sessions`.
            wire_ambiguities.observe_wire_owner(wire_key.clone(), entry.key.clone());
            // #16217 (Codex alias-republish regression): the alias
            // slot must keep a monotonic handshake stage + packet
            // counts exactly like the canonical row above. The
            // cache-hit restamp advances this slot to Established
            // on the completing packet; a later install-time /
            // barrier republication of the same incarnation
            // (HandshakePending, zero counts) must not regress it,
            // or the adoption gate reads w=2 again at failover.
            let mut alias_owned;
            let entry = if let Some(previous) = sessions.get(&wire_key) {
                let same_incarnation = previous.key == entry.key
                    && (entry.session_id == 0
                        || previous.session_id == 0
                        || entry.session_id == previous.session_id);
                let rank = crate::session::TcpHandshakeState::stage_rank;
                let keep_stage = same_incarnation
                    && rank(entry.tcp_handshake_state) < rank(previous.tcp_handshake_state);
                let keep_rev = same_incarnation && entry.rev_packets < previous.rev_packets;
                let keep_fwd = same_incarnation && entry.fwd_packets < previous.fwd_packets;
                if keep_stage || keep_rev || keep_fwd {
                    alias_owned = entry.clone();
                    if keep_stage {
                        alias_owned.tcp_handshake_state = previous.tcp_handshake_state;
                    }
                    if keep_rev {
                        alias_owned.rev_packets = previous.rev_packets;
                    }
                    if keep_fwd {
                        alias_owned.fwd_packets = previous.fwd_packets;
                    }
                    &alias_owned
                } else {
                    entry
                }
            } else {
                entry
            };
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
        {
            let mut served_aliases =
                lock_shared_recover(&shared_owner_rg_indexes.served_aliases);
            update_shared_served_aliases(&mut served_aliases, entry, false);
        }
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
                    // #15106/#16561: the per-wire-key owner multiset in
                    // `publish_shared_session` answers in O(1); the scan
                    // below is only the fail-closed fallback for
                    // unrecorded/at-ceiling state, reseeding the roster.
                    // #18658: the forward-wire map before `wire_ambiguities`,
                    // the one order every path takes them in (see
                    // `publish_shared_session`).
                    #[cfg(test)]
                    super::wire_lock_order_18658_tests::removal_before_wire_locks(&wire_key);
                    let mut forward_wire_sessions =
                        lock_shared_recover(shared_forward_wire_sessions);
                    #[cfg(test)]
                    super::wire_lock_order_18658_tests::removal_between_wire_locks(
                        &wire_key,
                        shared_forward_wire_sessions,
                        &shared_owner_rg_indexes.wire_ambiguities,
                    );
                    let mut wire_ambiguities =
                        lock_shared_recover(&shared_owner_rg_indexes.wire_ambiguities);
                    let roster_before = wire_ambiguities.wire_owner_count(&wire_key);
                    let remaining =
                        wire_ambiguities.remove_wire_owner(&wire_key, &entry.key);
                    // #16561: trust the roster on its own live state,
                    // not the alias saturation (see types/session_index.rs).
                    let roster_trusted = wire_ambiguities.wire_roster_trusted_for_removal()
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
                        // #16561: counted (operator-visible O(table) work).
                        SHARED_WIRE_FALLBACK_SCANS.fetch_add(1, Ordering::Relaxed);
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

#[cfg(test)]
mod handshake_monotonic_16223_tests {
    use super::*;
    use crate::session::SessionOrigin;
    use std::net::{IpAddr, Ipv4Addr};

    fn key(src_port: u16) -> SessionKey {
        SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: crate::ip_proto::PROTO_TCP,
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
            src_port,
            dst_port: 5211,
            discriminator: Default::default(),
            routing_domain: 0,
        }
    }

    fn entry(key: &SessionKey, wire: u8, session_id: u64, reverse: bool) -> SyncedSessionEntry {
        let mut metadata = crate::session::SessionMetadata { forward_wire_alias_origin: false,
            ingress_zone: 1,
            egress_zone: 2,
            ingress_zone_check: 0,
            egress_zone_check: 0,
            ingress_ifindex: 0,
            ingress_vlan_id: 0,
            forward_ingress_vlan_id: None,
            owner_rg_id: 1,
            fabric_ingress: false,
            is_reverse: reverse,
            nat64_reverse: None,
            log_session_init: false,
            log_session_close: false,
            policy_id: 0,
            inactivity_timeout_ns: None,
            policy_counter_idx: 0,
            policy_counter: None,
            nat_scope_ifindex: None,
        };
        metadata.is_reverse = reverse;
        SyncedSessionEntry { sibling_last_seen_ns: 0, key: key.clone(),
        decision: crate::session::SessionDecision {
            resolution: crate::afxdp::ForwardingResolution {
                disposition: crate::afxdp::ForwardingDisposition::ForwardCandidate,
                local_ifindex: 0,
                egress_ifindex: 12,
                tx_ifindex: 12,
                tunnel_endpoint_id: 0,
                next_hop: None,
                neighbor_mac: None,
                src_mac: None,
                tx_vlan_id: 0,
                source_ifindex: 0,
                route_mtu: 0,
                transport_route_mtu: 0,
            },
            nat: crate::nat::NatDecision {
                rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
                ..crate::nat::NatDecision::default()
            },
            install_table_domain: 0,
            install_table_check: 0,
        },
        metadata,
        persistent_lease_hold: None,
        source_nat_static: None,
        leak_incarnation: 0,
        origin: SessionOrigin::ForwardFlow,
        protocol: crate::ip_proto::PROTO_TCP,
        tcp_flags: 0,
        generation: 0,
        session_id,
        tcp_close_class: 0, tcp_handshake_state: wire, rev_packets: 0u64, fwd_packets: 0, pptp_call_ids: 0, }
    }

    fn maps() -> (
        Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
        Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
        Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
        SharedSessionOwnerRgIndexes,
    ) {
        (
            Arc::new(Mutex::new(FastMap::default())),
            Arc::new(Mutex::new(FastMap::default())),
            Arc::new(Mutex::new(FastMap::default())),
            SharedSessionOwnerRgIndexes::default(),
        )
    }

    fn nat_decision() -> crate::nat::NatDecision {
        crate::nat::NatDecision {
            rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
            ..crate::nat::NatDecision::default()
        }
    }

    fn wire(
        shared: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
        key: &SessionKey,
    ) -> u8 {
        lock_shared_recover(shared)
            .get(key)
            .map(|e| e.tcp_handshake_state)
            .unwrap_or(0)
    }

    #[test]
    fn publish_never_regresses_handshake_stage_16223() {
        let (shared, nat_map, wire_map, indexes) = maps();
        let forward = key(43001);
        let reverse = crate::session::reverse_session_key(&forward, nat_decision());
        let opening = crate::session::TcpHandshakeState::Opening.to_wire();
        let established = crate::session::TcpHandshakeState::Established.to_wire();
        // Install-time publishes: forward Opening, reverse pending.
        publish_shared_session(&shared, &nat_map, &wire_map, &indexes, &entry(&forward, opening, 77, false));
        publish_shared_session(&shared, &nat_map, &wire_map, &indexes, &entry(&reverse, 3, 77, true));
        // Serving maintenance advances both stored rows.
        restamp_shared_handshakes_established(&shared, &[(forward.clone(), nat_decision())]);
        assert_eq!(wire(&shared, &forward), established, "forward advanced");
        assert_eq!(wire(&shared, &reverse), established, "derived reverse advanced");
        // A stale Opening republication (same incarnation) must not regress.
        publish_shared_session(&shared, &nat_map, &wire_map, &indexes, &entry(&forward, opening, 77, false));
        assert_eq!(wire(&shared, &forward), established, "#16223: republication regressed forward");
        publish_shared_session(&shared, &nat_map, &wire_map, &indexes, &entry(&reverse, opening, 77, true));
        assert_eq!(wire(&shared, &reverse), established, "#16223: republication regressed reverse");
        // A new incarnation takes the incoming stage as-is.
        publish_shared_session(&shared, &nat_map, &wire_map, &indexes, &entry(&forward, opening, 78, false));
        assert_eq!(wire(&shared, &forward), opening, "new incarnation must not inherit stage");
    }

    #[test]
    fn forward_wire_alias_restamp_advances_wire_key_16217() {
        let (shared, nat_map, wire_map, indexes) = maps();
        let forward = key(43002);
        let pending = crate::session::TcpHandshakeState::HandshakePending.to_wire();
        let established = crate::session::TcpHandshakeState::Established.to_wire();
        let nat = nat_decision();
        let wire_key = crate::session::forward_wire_key(&forward, nat);
        assert_ne!(wire_key, forward, "SNAT fixture must produce a distinct wire key");
        publish_shared_session(&shared, &nat_map, &wire_map, &indexes, &entry(&forward, pending, 79, false));
        assert_eq!(wire(&shared, &forward), pending);
        // Canonical restamp is the caller's job (`restamp_shared_handshakes_established`
        // in the ct-slice); the wrapper owns only the alias slot.
        crate::afxdp::shared_ops::restamp_shared_handshakes_established(
            &shared,
            &[(forward.clone(), nat)],
        );
        crate::afxdp::shared_ops::restamp_shared_forward_wire_established(
            &shared,
            &wire_map,
            &[(forward.clone(), nat)],
        );
        assert_eq!(wire(&shared, &forward), established, "canonical advanced");
        assert_eq!(wire(&wire_map, &wire_key), established, "wire alias advanced");
        let aliased = lock_shared_recover(&wire_map)
            .get(&wire_key)
            .cloned()
            .expect("wire alias row present");
        assert_eq!(aliased.key, forward, "alias row retains the canonical key");
        assert!(!aliased.metadata.is_reverse, "alias stays a forward entry");
        assert!(
            crate::afxdp::shared_ops::lookup_shared_established_for_wire(
                &shared,
                &wire_map,
                &indexes,
                &wire_key,
            )
            .is_some(),
            "established wire alias must be adoptable"
        );
    }

    fn rev_of(
        shared: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
        key: &SessionKey,
    ) -> u64 {
        lock_shared_recover(shared)
            .get(key)
            .map(|e| e.rev_packets)
            .unwrap_or(0)
    }

    /// #16217 (fail-closed evidence, change 2): a synthesized reverse
    /// companion's mere EXISTENCE in the shared maps must NOT count
    /// as completion evidence — only an actual reverse packet count
    /// > 0 on a row does. The old implementation set
    /// `rev_packets_any = 1` for any reverse row present.
    ///
    /// MUTATION: restore the existence-based arm in
    /// `shared_completion_evidence` and the zero-count case below
    /// yields evidence, failing the first assertion.
    #[test]
    fn completion_evidence_requires_actual_reverse_count_16217() {
        let (shared, nat_map, wire_map, indexes) = maps();
        let forward = key(43011);
        let reverse = crate::session::reverse_session_key(&forward, nat_decision());
        let pending = crate::session::TcpHandshakeState::HandshakePending.to_wire();
        // Forward + synthesized reverse companion, both rev_packets=0
        // (the `entry` fixture publishes 0, as every synthesizer does).
        publish_shared_session(&shared, &nat_map, &wire_map, &indexes, &entry(&forward, pending, 81, false));
        publish_shared_session(&shared, &nat_map, &wire_map, &indexes, &entry(&reverse, pending, 81, true));
        assert_eq!(rev_of(&shared, &reverse), 0, "premise: companion carries no count");
        let ev = crate::afxdp::shared_ops::shared_completion_evidence(&shared, &wire_map, &forward);
        assert_eq!(
            ev.rev_packets_any, 0,
            "#16217: synthesized companion existence must not be evidence"
        );
        assert!(
            !ev.served_and_completed(),
            "#16217: zero-count evidence must not complete"
        );
        // Actual reverse service: the serving worker stamps its real
        // count onto the shared rows -> evidence appears.
        crate::afxdp::shared_ops::restamp_shared_rev_packets(
            &shared,
            &forward,
            nat_decision(),
            7,
        );
        assert_eq!(rev_of(&shared, &forward), 7);
        assert_eq!(rev_of(&shared, &reverse), 7);
        let ev = crate::afxdp::shared_ops::shared_completion_evidence(&shared, &wire_map, &forward);
        assert_eq!(ev.rev_packets_any, 7, "#16217: actual count must be evidence");
        assert!(ev.served_and_completed());
        // A republication carrying 0 must not erase the observed count.
        publish_shared_session(&shared, &nat_map, &wire_map, &indexes, &entry(&forward, pending, 81, false));
        assert_eq!(rev_of(&shared, &forward), 7, "#16217: republication must not regress the count");
        // The forward-wire alias slot alone (rev count on the wire
        // map's forward row) also vouches.
        let (shared2, nat2, wire2, idx2) = maps();
        publish_shared_session(&shared2, &nat2, &wire2, &idx2, &entry(&forward, pending, 82, false));
        let wire_key = crate::session::forward_wire_key(&forward, nat_decision());
        {
            let mut w = lock_shared_recover(&wire2);
            let row = w.get_mut(&wire_key).expect("wire alias row");
            row.rev_packets = 3;
        }
        let ev = crate::afxdp::shared_ops::shared_completion_evidence(&shared2, &wire2, &forward);
        assert_eq!(ev.rev_packets_any, 3, "#16217: wire-map count must be evidence");
    }

    /// #16217 (lock order, change 3): `restamp_shared_forward_wire_established`
    /// and `shared_completion_evidence` must agree on ONE lock order
    /// (shared_sessions then forward_wire) while both hold both maps.
    /// Run the two concurrently on disjoint tuples: any AB-BA pairing
    /// deadlocks (test harness timeout) or panics on poison; the
    /// unified order completes with correct contents.
    ///
    /// MUTATION: restore the nested sessions-lock inside the
    /// wire-held loop of the restamp and this races the evidence
    /// reader's sessions->wire acquisition.
    #[test]
    fn restamp_and_evidence_share_one_lock_order_16217() {
        use std::sync::atomic::{AtomicBool, Ordering};
        let (shared, nat_map, wire_map, indexes) = maps();
        let nat = nat_decision();
        let established = crate::session::TcpHandshakeState::Established.to_wire();
        // Seed 32 tuples through the real publish path.
        let mut forwards = Vec::new();
        for i in 0..32u16 {
            let f = key(43100 + i);
            publish_shared_session(
                &shared,
                &nat_map,
                &wire_map,
                &indexes,
                &entry(&f, crate::session::TcpHandshakeState::HandshakePending.to_wire(), 83, false),
            );
            forwards.push(f);
        }
        let stop = Arc::new(AtomicBool::new(false));
        let reader = {
            let shared = shared.clone();
            let wire_map = wire_map.clone();
            let stop = stop.clone();
            let forwards = forwards.clone();
            std::thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    for f in &forwards {
                        let _ = crate::afxdp::shared_ops::shared_completion_evidence(
                            &shared, &wire_map, f,
                        );
                    }
                }
            })
        };
        for _ in 0..200 {
            for f in &forwards {
                crate::afxdp::shared_ops::restamp_shared_forward_wire_established(
                    &shared,
                    &wire_map,
                    &[(f.clone(), nat)],
                );
            }
        }
        stop.store(true, Ordering::Relaxed);
        reader.join().expect("evidence reader must not deadlock/panic");
        for f in &forwards {
            let wire_key = crate::session::forward_wire_key(f, nat);
            assert_eq!(
                wire(&wire_map, &wire_key),
                established,
                "#16217: alias must be Established after concurrent restamps"
            );
        }
    }

    fn lookup(
        shared: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
        wire_map: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
        indexes: &SharedSessionOwnerRgIndexes,
        wire_key: &SessionKey,
    ) -> Option<SyncedSessionEntry> {
        crate::afxdp::shared_ops::lookup_shared_established_for_wire(
            shared, wire_map, indexes, wire_key,
        )
    }

    /// #16217 (DECISION arm): a HandshakePending forward row qualifies
    /// as Established-for-adoption when the canonical tuple shows
    /// completed-handshake evidence — actual reverse count > 0 on a
    /// synced row (incl. the reverse companion) AND forward count > 0.
    /// Zero-count rows never qualify (fail-closed per FZFixWire6).
    ///
    /// MUTATION: drop the HandshakePending arm and the evidenced case
    /// below returns None.
    #[test]
    fn pending_row_adopts_on_scoped_completion_evidence_16217() {
        let (shared, nat_map, wire_map, indexes) = maps();
        let forward = key(43201);
        let reverse = crate::session::reverse_session_key(&forward, nat_decision());
        let wire_key = crate::session::forward_wire_key(&forward, nat_decision());
        let pending = crate::session::TcpHandshakeState::HandshakePending.to_wire();
        // Canonical SyncImport row stuck at w=2, zero counts.
        let mut fwd = entry(&forward, pending, 91, false);
        fwd.origin = SessionOrigin::SyncImport;
        publish_shared_session(&shared, &nat_map, &wire_map, &indexes, &fwd);
        publish_shared_session(&shared, &nat_map, &wire_map, &indexes, &entry(&reverse, pending, 91, true));
        assert!(
            lookup(&shared, &wire_map, &indexes, &wire_key).is_none(),
            "premise: pending + zero counts must not adopt"
        );
        // Forward traffic alone (no reverse service) must not adopt.
        crate::afxdp::shared_ops::restamp_shared_packet_counts(
            &shared, &wire_map, &forward, nat_decision(), 0, 0, 12, 0,
        );
        assert!(
            lookup(&shared, &wire_map, &indexes, &wire_key).is_none(),
            "forward-only counts must not adopt"
        );
        // Completed-handshake evidence: reverse count lands on the
        // reverse companion row; forward count already > 0.
        crate::afxdp::shared_ops::restamp_shared_packet_counts(
            &shared, &wire_map, &forward, nat_decision(), 0, 0, 12, 5,
        );
        let found = lookup(&shared, &wire_map, &indexes, &wire_key)
            .expect("pending + rev>0 + fwd>0 must adopt as Established-for-adoption");
        assert_eq!(found.key, forward);
        assert_eq!(found.session_id, 91);
    }

    /// #16217 (ct-slice count stamp): the maintenance sequence the
    /// ct-slice runs for a collected pair — stage restamp, then the
    /// collected row's ACTUAL fwd+rev counts, then the alias
    /// restamp — must leave the shared rows adoptable by the scoped
    /// gate even when the stage already read Established (so (a)
    /// passed) but the counts still read import-time (0,0): the
    /// counts are the only thing the peer-facing export/adoption
    /// consumers can see. Here the canonical row starts pending
    /// with zero counts; after the sequence the gate must hit and
    /// the counts must read (12,5) on canonical AND alias.
    ///
    /// MUTATION: drop the `restamp_shared_packet_counts` leg of the
    /// ct-slice sequence (or the counts leg of this sequence) and
    /// the counts stay (0,0); the gate still hits on stage alone,
    /// which is exactly why the count assertions are the pin.
    #[test]
    fn ct_slice_sequence_stamps_counts_for_pending_row_16217() {
        let (shared, nat_map, wire_map, indexes) = maps();
        let forward = key(43211);
        let wire_key = crate::session::forward_wire_key(&forward, nat_decision());
        let pending = crate::session::TcpHandshakeState::HandshakePending.to_wire();
        let established = crate::session::TcpHandshakeState::Established.to_wire();
        let mut fwd = entry(&forward, pending, 96, false);
        fwd.origin = SessionOrigin::SyncImport;
        publish_shared_session(&shared, &nat_map, &wire_map, &indexes, &fwd);
        assert!(
            lookup(&shared, &wire_map, &indexes, &wire_key).is_none(),
            "premise: pending + zero counts must not adopt"
        );
        // The ct-slice sequence for one collected pair.
        crate::afxdp::shared_ops::restamp_shared_handshakes_established(
            &shared,
            &[(forward.clone(), nat_decision())],
        );
        crate::afxdp::shared_ops::restamp_shared_packet_counts(
            &shared, &wire_map, &forward, nat_decision(), 0, 0, 12, 5,
        );
        crate::afxdp::shared_ops::restamp_shared_forward_wire_established(
            &shared,
            &wire_map,
            &[(forward.clone(), nat_decision())],
        );
        assert_eq!(wire(&shared, &forward), established, "canonical stage must advance");
        assert_eq!(wire(&wire_map, &wire_key), established, "alias stage must advance");
        let canonical = lock_shared_recover(&shared).get(&forward).cloned().expect("canonical row");
        assert_eq!(canonical.fwd_packets, 12, "#16217: canonical fwd count must be stamped");
        assert_eq!(canonical.rev_packets, 5, "#16217: canonical rev count must be stamped");
        let aliased = lock_shared_recover(&wire_map).get(&wire_key).cloned().expect("alias row");
        assert_eq!(aliased.fwd_packets, 12, "#16217: alias fwd count must be stamped");
        assert_eq!(aliased.rev_packets, 5, "#16217: alias rev count must be stamped");
        assert!(
            lookup(&shared, &wire_map, &indexes, &wire_key).is_some(),
            "#16217: promoted + counted row must be adoptable"
        );
    }

    /// #16217 (scope): the evidence scan compares the FULL scoped key.
    /// Identical 5-tuple evidence in routing_domain 7 must not
    /// qualify the domain-0 pending row (Codex cross-VRF finding).
    ///
    /// MUTATION: compare `bare_tuple()` in the scoped scan and the
    /// cross-VRF case below wrongly adopts.
    #[test]
    fn pending_adoption_evidence_is_scope_exact_16217() {
        let (shared, nat_map, wire_map, indexes) = maps();
        let forward = key(43202);
        let wire_key = crate::session::forward_wire_key(&forward, nat_decision());
        let pending = crate::session::TcpHandshakeState::HandshakePending.to_wire();
        let mut fwd = entry(&forward, pending, 92, false);
        fwd.origin = SessionOrigin::SyncImport;
        publish_shared_session(&shared, &nat_map, &wire_map, &indexes, &fwd);
        // Same 5-tuple, different VRF, carrying both counts.
        let mut other = entry(&forward, pending, 93, false);
        other.key.routing_domain = 7;
        other.rev_packets = 9;
        other.fwd_packets = 9;
        publish_shared_session(&shared, &nat_map, &wire_map, &indexes, &other);
        // The scoped scan for the domain-0 key sees nothing.
        let ev = crate::afxdp::shared_ops::shared_scoped_completion_evidence(
            &shared, &wire_map, &forward, nat_decision(),
        );
        assert_eq!(ev.rev_packets, 0, "cross-VRF rev count must not leak");
        assert_eq!(ev.fwd_packets, 0, "cross-VRF fwd count must not leak");
        assert!(
            lookup(&shared, &wire_map, &indexes, &wire_key).is_none(),
            "cross-VRF evidence must not qualify the pending row"
        );
        // Same-scope evidence (restamp keys on the exact key) qualifies.
        crate::afxdp::shared_ops::restamp_shared_packet_counts(
            &shared, &wire_map, &forward, nat_decision(), 0, 0, 3, 2,
        );
        assert!(
            lookup(&shared, &wire_map, &indexes, &wire_key).is_some(),
            "same-scope evidence must qualify"
        );
    }

    /// #16217 (Codex alias-republish regression): the forward-wire
    /// alias slot keeps a monotonic stage + counts like the canonical
    /// row. An install-time HandshakePending republication must not
    /// regress an Established alias (nor erase its counts); a new
    /// incarnation takes the incoming stage as-is.
    ///
    /// MUTATION: drop the alias merge in `publish_shared_session` and
    /// the alias reads HandshakePending after republication.
    #[test]
    fn alias_republish_never_regresses_stage_16217() {
        let (shared, nat_map, wire_map, indexes) = maps();
        let forward = key(43203);
        let nat = nat_decision();
        let wire_key = crate::session::forward_wire_key(&forward, nat);
        let pending = crate::session::TcpHandshakeState::HandshakePending.to_wire();
        let established = crate::session::TcpHandshakeState::Established.to_wire();
        publish_shared_session(&shared, &nat_map, &wire_map, &indexes, &entry(&forward, pending, 94, false));
        // Cache-hit restamps advance canonical + alias and stamp counts.
        crate::afxdp::shared_ops::restamp_shared_handshakes_established(
            &shared,
            &[(forward.clone(), nat)],
        );
        crate::afxdp::shared_ops::restamp_shared_forward_wire_established(
            &shared,
            &wire_map,
            &[(forward.clone(), nat)],
        );
        crate::afxdp::shared_ops::restamp_shared_packet_counts(
            &shared, &wire_map, &forward, nat, 0, 0, 8, 4,
        );
        assert_eq!(wire(&wire_map, &wire_key), established, "premise: alias Established");
        // Stale republication of the same incarnation must not regress.
        publish_shared_session(&shared, &nat_map, &wire_map, &indexes, &entry(&forward, pending, 94, false));
        assert_eq!(wire(&wire_map, &wire_key), established, "alias stage regressed on republication");
        assert_eq!(wire(&shared, &forward), established, "canonical stage regressed on republication");
        let aliased = lock_shared_recover(&wire_map)
            .get(&wire_key)
            .cloned()
            .expect("alias row present");
        assert_eq!(aliased.rev_packets, 4, "alias rev count erased on republication");
        assert_eq!(aliased.fwd_packets, 8, "alias fwd count erased on republication");
        // A new incarnation takes the incoming stage as-is.
        publish_shared_session(&shared, &nat_map, &wire_map, &indexes, &entry(&forward, pending, 95, false));
        assert_eq!(wire(&wire_map, &wire_key), pending, "new incarnation must not inherit alias stage");
    }

    /// #16217 (fold B2): `shared_completion_evidence` (ct-slice
    /// promotion + bulk-export stamp input) must be scope-exact like
    /// the adoption arm: identical 5-tuple reverse counts in
    /// routing_domain 7 (or under another discriminator) must NOT
    /// leak into the domain-0 key's evidence; same-scope counts must
    /// still vouch (no over-scoping regression).
    ///
    /// MUTATION: restore the bare-tuple full-map scan and the
    /// cross-VRF count below wrongly completes the domain-0 key.
    #[test]
    fn completion_evidence_is_scope_exact_16217() {
        let (shared, nat_map, wire_map, indexes) = maps();
        let forward = key(43311);
        let reverse = crate::session::reverse_session_key(&forward, nat_decision());
        let pending = crate::session::TcpHandshakeState::HandshakePending.to_wire();
        publish_shared_session(&shared, &nat_map, &wire_map, &indexes, &entry(&forward, pending, 97, false));
        publish_shared_session(&shared, &nat_map, &wire_map, &indexes, &entry(&reverse, pending, 97, true));
        // Cross-VRF sibling: same 5-tuple, domain 7, real counts.
        let mut other = entry(&forward, pending, 98, false);
        other.key.routing_domain = 7;
        other.rev_packets = 9;
        other.fwd_packets = 9;
        publish_shared_session(&shared, &nat_map, &wire_map, &indexes, &other);
        let mut other_rev = entry(&reverse, pending, 98, true);
        other_rev.key.routing_domain = 7;
        other_rev.rev_packets = 9;
        publish_shared_session(&shared, &nat_map, &wire_map, &indexes, &other_rev);
        let ev = crate::afxdp::shared_ops::shared_completion_evidence(&shared, &wire_map, &forward);
        assert_eq!(
            ev.rev_packets_any, 0,
            "#16217 B2: cross-VRF rev count must not leak into scoped evidence"
        );
        assert!(
            !ev.served_and_completed(),
            "#16217 B2: cross-VRF evidence must not complete the domain-0 key"
        );
        // Same-scope evidence still vouches.
        crate::afxdp::shared_ops::restamp_shared_rev_packets(
            &shared,
            &forward,
            nat_decision(),
            4,
        );
        let ev = crate::afxdp::shared_ops::shared_completion_evidence(&shared, &wire_map, &forward);
        assert_eq!(ev.rev_packets_any, 4, "#16217 B2: same-scope count must still vouch");
        assert!(ev.served_and_completed());
    }

    /// #16217 (fold B5): `shared_scoped_completion_evidence` must
    /// find counts on rows stored under the forward-wire alias key
    /// (direct wire-keyed row) — NAT'd reverse-companion orientation
    /// included — via keyed gets, and must still refuse cross-VRF
    /// rows. This pins the orientation set the keyed replacement
    /// covers beyond canonical/reverse.
    ///
    /// MUTATION: drop the wire-key gets and the wire-stored counts
    /// below read (0,0).
    #[test]
    fn scoped_evidence_finds_wire_keyed_rows_16217() {
        let (shared, nat_map, wire_map, indexes) = maps();
        let forward = key(43312);
        let wire_key = crate::session::forward_wire_key(&forward, nat_decision());
        let pending = crate::session::TcpHandshakeState::HandshakePending.to_wire();
        assert_ne!(wire_key, forward, "SNAT fixture must produce a distinct wire key");
        publish_shared_session(&shared, &nat_map, &wire_map, &indexes, &entry(&forward, pending, 99, false));
        // A row stored DIRECTLY under the wire tuple (as the alias
        // slot can hold after a NAT'd publish) carrying real counts.
        {
            let mut w = lock_shared_recover(&wire_map);
            let mut row = entry(&forward, pending, 99, false);
            row.key = wire_key.clone();
            row.rev_packets = 6;
            row.fwd_packets = 11;
            w.insert(wire_key.clone(), row);
        }
        let ev = crate::afxdp::shared_ops::shared_scoped_completion_evidence(
            &shared, &wire_map, &forward, nat_decision(),
        );
        assert_eq!(ev.rev_packets, 6, "#16217 B5: wire-keyed rev count must be found by keyed get");
        assert_eq!(ev.fwd_packets, 11, "#16217 B5: wire-keyed fwd count must be found by keyed get");
    }

    /// #18742 escalation: a serving sibling's packet timestamp must survive
    /// an ordinary same-incarnation republication, then remain visible when
    /// the completed local row crosses its short idle window.
    #[test]
    fn same_id_republication_preserves_sibling_stamp_for_crossed_expiry_18742() {
        use crate::session::{
            ExpireHaContext, NodeServedEvidence, SessionInstall, SessionOrigin, SessionTable,
            TcpHandshakeState,
        };

        const SEC: u64 = 1_000_000_000;
        let (shared, nat_map, wire_map, indexes) = maps();
        let key = key(43313);
        let t0 = 1_000 * SEC;
        let wire = TcpHandshakeState::Established.to_wire();
        let template = entry(&key, wire, 0, false);
        let mut table = SessionTable::new();
        let mut metadata = template.metadata.clone();
        metadata.inactivity_timeout_ns = Some(5 * SEC);
        assert!(table.upsert_synced_with_origin(
            SessionInstall {
                key: key.clone(),
                decision: template.decision,
                metadata: metadata.clone(),
                source_nat_static: None,
                origin: SessionOrigin::ForwardFlow,
                now_ns: t0,
                protocol: template.protocol,
                tcp_flags: 0,
                session_id: 0,
                tcp_close_class: 0,
                tcp_handshake_state: wire,
                persistent_lease_hold: None,
                fwd_packets: 0,
                rev_packets: 0,
            },
            false,
        ));
        let session_id = table.session_id_for(&key);
        assert_ne!(session_id, 0, "premise: A has a stable local incarnation");
        assert_eq!(
            table.timeout_secs_for(&key),
            5,
            "premise: A has the configured 5 s established window"
        );

        let mut source = entry(&key, wire, session_id, false);
        source.fwd_packets = 50;
        source.rev_packets = 50;
        publish_shared_session(&shared, &nat_map, &wire_map, &indexes, &source);

        // B serves a packet after the previous evidence pass; its next
        // production pass stamps the packet timestamp onto the shared row.
        let sibling_packet_seen = t0 + 1_000_000;
        let source_namespace = ((session_id >> 48) as u16).wrapping_add(1);
        crate::afxdp::shared_ops::restamp_shared_packet_counts(
            &shared,
            &wire_map,
            &key,
            source.decision.nat,
            source_namespace,
            sibling_packet_seen,
            51,
            50,
        );
        let stamped = lock_shared_recover(&shared)
            .get(&key)
            .expect("shared row")
            .sibling_last_seen_ns;
        assert_eq!(stamped, sibling_packet_seen, "premise: B's packet was stamped");

        // `synced_entry_for` intentionally constructs a fresh publication with
        // sibling_last_seen_ns=0. The same-ID publish must retain B's stamp.
        let republished = entry(&key, wire, session_id, false);
        publish_shared_session(&shared, &nat_map, &wire_map, &indexes, &republished);
        let after_republication = lock_shared_recover(&shared)
            .get(&key)
            .expect("republished shared row")
            .sibling_last_seen_ns;
        assert_eq!(
            after_republication, sibling_packet_seen,
            "#18742: same-incarnation publication erased B's sibling packet timestamp"
        );

        let node_served = |candidate: &SessionKey| {
            let sessions = lock_shared_recover(&shared);
            let Some(row) = sessions.get(candidate) else {
                return NodeServedEvidence::default();
            };
            NodeServedEvidence {
                handshake_wire: row.tcp_handshake_state,
                shared_established: row.tcp_handshake_state == wire,
                shared_incarnation: Some((row.session_id, row.generation)),
                shared_evidence_max_cadence_ns: Some(10 * SEC),
                shared_served: Some(row.fwd_packets.saturating_add(row.rev_packets)),
                shared_sibling_last_seen_ns: (row.sibling_last_seen_ns != 0)
                    .then_some(row.sibling_last_seen_ns),
                ..NodeServedEvidence::default()
            }
        };
        let forwards = |_: i32| true;
        let epoch = |_: i32| 0u32;
        let ha = ExpireHaContext {
            node_active: true,
            forwards_rg: &forwards,
            epoch_of: &epoch,
            ceiling_mult: crate::session::STALE_SYNCED_CEILING_MULT,
            ceiling_abs_ns: crate::session::STALE_SYNCED_CEILING_ABS_NS,
            node_served: &node_served,
        };
        let _ = table.expire_stale_entries_ha(t0 + 12 * SEC, Some(&ha));
        assert_eq!(
            table.timeout_secs_for(&key),
            5,
            "#18742: A must retain its crossed row after B's stamp is re-published"
        );
        assert!(
            table.last_pop_stats().kept_alive_by_companion > 0,
            "anti-vacuity: A's retention must use the republished sibling stamp"
        );
    }
}
