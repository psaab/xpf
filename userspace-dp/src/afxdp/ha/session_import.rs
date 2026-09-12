use crate::afxdp::*;

/// The outcome of a helper-side synced delete (#9714 review round 2, finding 7).
///
/// This replaces a `bool` in which a stale-generation REJECTION and a successful
/// APPLY were the SAME value, `false`; only the peer refusal was distinguishable.
/// Peer deletes currently carry generation 0, so the collision is latent — but it is
/// latent in the direction that matters. A rejected delete reported as applied
/// licenses the caller to destroy the mirror and DNAT rows of a session the helper
/// still holds, and the mirror cannot be rebuilt afterwards: the refresh path writes
/// with `BPF_EXIST` precisely so it will not recreate a deleted entry. The moment a
/// generation-aware helper-originated delete exists, the conflation goes live.
///
/// Three states, because "I did it", "I declined" and "I declined for a DIFFERENT
/// reason" are three different answers to the caller, and only the first of them
/// permits any further teardown.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SyncedDeleteOutcome {
    /// The entry named by the key was removed.
    Applied,
    /// Refused: a PEER delete named a live LOCAL session whose owner redundancy
    /// group is locally forwarding-active — a dual-primary split.
    RefusedLocalOwned,
    /// Refused: the stored entry's install generation is strictly NEWER than the
    /// delete's, so this is a stale delete arriving after a same-key replacement
    /// the helper has already mirrored (#2170).
    RefusedStaleGeneration,
}

impl SyncedDeleteOutcome {
    /// Whether this is the #9714 ownership refusal specifically, which the handler
    /// answers in-band with its own token so the Go side keeps its mirror and DNAT
    /// rows. A stale-generation refusal is NOT that: it means the helper already
    /// holds something newer, so the Go side has nothing to preserve.
    pub(crate) fn is_refused_local_owned(self) -> bool {
        matches!(self, Self::RefusedLocalOwned)
    }
}

/// The outcome of an HA synced-session import (#6785).
///
/// `upsert_synced_session` used to return `()`. It has three SEMANTIC refusal
/// paths — a stale generation (#2170), the aggregate import cap (#5674), and a
/// translated-tuple reservation refusal (#6600) — and each one `return`ed
/// silently after bumping a counter. The control handler therefore answered
/// `ok = true`, so Go's `SetClusterSyncedSessionV4`/`V6` reported success and
/// LEFT its BPF mirror row in place for a session the helper had refused. That
/// is exactly the split truth #5305's transactional install exists to prevent —
/// its rollback machinery was already built and simply never reached, because
/// the only failure it could observe was an IPC error.
///
/// Reporting the refusal is therefore the whole fix on the helper side: the Go
/// compensation already exists.
///
/// The distinction between `Rejected*` and an IPC/transport failure matters on
/// the Go side and must not be collapsed. A transport failure means the session
/// socket is unhealthy and gates takeover-readiness (#5247); a semantic refusal
/// is an EXPECTED answer from a healthy helper (the peer sent something stale,
/// or this node is at its own ceiling) and marking the mirror unhealthy for it
/// would block failover on a node that is working correctly. Go discriminates on
/// the `SYNCED_IMPORT_REFUSED_PREFIX` token below.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncedImportOutcome {
    /// The entry was published (new key, or a replace of an existing one).
    Applied,
    /// #2170: a strictly-older generation than the stored entry.
    RejectedStaleGeneration,
    /// #5674: the aggregate synced-import entry ceiling is full.
    RejectedCapacity,
    /// #6600: the translated NAT tuple could not be reserved for this import.
    RejectedReserve,
    /// #8015: the request carried `is_reverse=true` with no forward of its own.
    ///
    /// A reverse entry is DERIVED state, never standalone authority. Every
    /// legitimate reverse companion in this map is produced HERE, by
    /// `synthesized_synced_reverse_entry` riding with the forward it was
    /// derived from — so an entry arriving pre-flagged is either a redundant
    /// duplicate of one this node will build better (it resolves egress/FIB,
    /// fabric/tunnel and owner-RG against live node-local state, #5698) or, if
    /// its forward was refused, a permit with nothing to anchor it.
    ///
    /// The unanchored case is the reason this refuses rather than deduplicates.
    /// `delete_synced_session_gen` derives the companion to remove from the
    /// STORED FORWARD; with no stored forward, a later delete of that forward
    /// finds nothing and the reverse survives it, idling out only when
    /// `reap_expired_sessions` collects it. Refusing at the door is what makes
    /// that state unreachable instead of merely counted.
    ///
    /// No shipped daemon can produce this: #8015 also removed the one sender
    /// (`mirrorSessionPairV4`/`V6`'s explicit companion pre-install), and the
    /// peer path never reached here — Go's `SetClusterSyncedSessionV4`/`V6`
    /// early-return on a reverse and write only the BPF mirror. So the refusal
    /// gets no counter of its own: a metric that can only ever read zero says
    /// nothing, and the typed outcome already reaches the caller as
    /// `synced-import-refused:standalone-reverse`.
    RejectedStandaloneReverse,
    /// #7160 (#2387): this node runs routing instances, and the request named
    /// no ingress identity to resolve the session's routing DOMAIN from.
    ///
    /// Refused rather than imported at domain 0, which is NOT a neutral
    /// default here: domain 0 is the DEFAULT ROUTING INSTANCE, so importing a
    /// tenant's session under it files that session in another tenant's
    /// identity space. The reverse-match path then reaches it — a reply that
    /// resolved its own domain falls back to the domain-agnostic probe
    /// (`lookup_shared_forward_nat_match`) and can match a session that was
    /// only keyed at 0 because its domain was unknown. That is the HA half of
    /// the very collision #7160 closes, and no single-instance test can see
    /// it, because there every key is legitimately 0.
    ///
    /// The cost of refusing is bounded and visible: the session is not taken
    /// over, so after a failover its flow re-adjudicates through policy
    /// instead of being adopted under a domain nothing verified.
    RejectedUnknownRoutingDomain,
}

/// The machine-readable prefix every semantic refusal carries in the control
/// response's `error` field. Go matches on THIS, not on the human-readable
/// remainder, so the sentence can be reworded without silently reclassifying a
/// refusal as a transport failure.
pub const SYNCED_IMPORT_REFUSED_PREFIX: &str = "synced-import-refused:";

/// #8636: the refusal prefix for a DELETE the helper cannot disambiguate.
///
/// Deliberately distinct from `SYNCED_IMPORT_REFUSED_PREFIX`. An import refusal
/// means "this node declined to take a session"; a delete refusal means "this
/// node kept one it was asked to remove". They need different operator
/// responses and different alert thresholds, and folding them onto one token
/// would make a cross-tenant guard firing look like an import problem.
pub const SYNCED_DELETE_REFUSED_PREFIX: &str = "synced-delete-refused:";

impl SyncedImportOutcome {
    /// The stable reason token, or `None` when the import applied.
    pub fn refusal_reason(self) -> Option<&'static str> {
        match self {
            SyncedImportOutcome::Applied => None,
            SyncedImportOutcome::RejectedStaleGeneration => Some("stale-generation"),
            SyncedImportOutcome::RejectedCapacity => Some("capacity"),
            SyncedImportOutcome::RejectedReserve => Some("reserve"),
            SyncedImportOutcome::RejectedStandaloneReverse => Some("standalone-reverse"),
            SyncedImportOutcome::RejectedUnknownRoutingDomain => Some("unknown-routing-domain"),
        }
    }
}

// #7209: this whole block moved from `impl Coordinator` to the SESSION DOMAIN
// handle. Nothing in it needed the coordinator — the reference set is exactly
// `sessions`, `forwarding`, `bpf_maps`, `workers`, `ha.rg_runtime` and
// `dynamic_neighbors_ref`, every one of which is already shared state — and the
// type system had already proved the subgraph `&self`-only, since
// `upsert_synced_session(&self)` compiled.
//
// The one substantive change is the FORWARDING source: these reads were
// `Coordinator::forwarding`, the owned field, and are now the PUBLISHED
// `RuntimeView` — the same state the packet workers hold. See
// `session_domain.rs` for why that is the more correct source rather than a
// concession, and why the two cannot diverge in production.
impl crate::afxdp::ha::SessionDomain {
    /// #5674: this appliance's aggregate synced-session ENTRY ceiling. The
    /// LOGICAL ceiling is `worker_count * DEFAULT_MAX_SESSIONS` (each worker
    /// table caps locally-created sessions at `DEFAULT_MAX_SESSIONS`), but the
    /// shared `synced` map holds TWO entries per admitted forward logical
    /// session: the forward key AND a synthesized reverse companion.
    /// `synthesized_synced_reverse_entry` returns `Some` for EVERY non-reverse
    /// import, and `upsert_synced_session` publishes both into `sessions.synced`
    /// via `publish_shared_session`. So the ENTRY cap must be 2× the logical
    /// ceiling. A symmetric HA pair holds up to `N = worker_count *
    /// DEFAULT_MAX_SESSIONS` logical sessions, which arrive here as 2N entries
    /// and EXACTLY fit this 2N cap — a legitimate full-peer failover import
    /// always fits, and only a peer EXCEEDING its own logical ceiling (a
    /// malicious/compromised peer) is rejected. Sizing the cap to the LOGICAL
    /// ceiling (the pre-fix bug) while counting ENTRIES rejected ~half of a
    /// legitimate symmetric-peer import above ~50% peer load — a 2× shortfall,
    /// not the "±1 pair overshoot" the old comment claimed. Bounds the shared
    /// `synced` map so a peer cannot drive this node past its aggregate session
    /// ceiling via the uncapped sync-import fan-out. Zero when no workers are
    /// registered (early boot / teardown) — the caller treats a zero ceiling as
    /// "bound disabled" so a transient window never rejects legitimate imports.
    /// Visible to `ha::tests` (#6819 §7) so the PRODUCTION arithmetic below can
    /// be asserted directly. Both admission tests set
    /// `synced_import_cap_override`, which returns from the `#[cfg(test)]`
    /// branch BEFORE this function's production expression is ever evaluated —
    /// a test-only seam shadowing the real formula. With only those tests,
    /// deleting the trailing `.saturating_mul(2)` here leaves every cap
    /// assertion green.
    /// #7209: the cap over an EXPLICIT records snapshot.
    ///
    /// Takes the MAP, not a count. `upsert_synced_session` must derive the cap
    /// from the same snapshot it uses for the reservation gate and the fan-out
    /// — once `sync_session` runs off the `ServerState` mutex, three
    /// independent `records()` loads inside one import can straddle a teardown
    /// and disagree: a cap sized for live workers, a gate that then sees none
    /// and skips the reservation, a fan-out that finds some again.
    ///
    /// The `.len()` lives HERE rather than at the call site deliberately. An
    /// earlier revision took a `worker_count: usize`, which moved the
    /// worker-count SOURCING into `upsert_synced_session` where no cap test
    /// could see it — the three assertions in
    /// `synced_import_cap_production_formula_is_twice_the_logical_ceiling`
    /// register N workers and would have stayed green with the live path
    /// reading anything at all. Keeping the map as the parameter keeps the
    /// sourcing inside the one function those assertions drive.
    pub(in crate::afxdp) fn synced_import_cap_for(
        &self,
        records: &std::collections::BTreeMap<u32, std::sync::Arc<crate::afxdp::coordinator::WorkerRuntimeRecord>>,
    ) -> usize {
        #[cfg(test)]
        {
            // #7209: the override is read through the SHARED cell, so a test
            // that sets it on the `Coordinator` reaches this handle.
            let override_cap = self
                .synced_import_cap_override
                .load(std::sync::atomic::Ordering::Relaxed);
            if override_cap != 0 {
                // The override expresses a LOGICAL session ceiling; double it to
                // the ENTRY cap (fwd + synthesized reverse per logical session),
                // matching the production formula below so tests exercise the
                // real arithmetic.
                return override_cap.saturating_mul(2);
            }
        }
        records
            .len()
            .saturating_mul(crate::session::default_max_sessions())
            .saturating_mul(2)
    }

    /// #6600: take this node's reservation on a peer-synced forward entry's
    /// translated NAT identity. Returns false when the node cannot own it.
    ///
    /// The zone pair is resolved through the SAME helper the worker-side upsert
    /// uses, so the coordinator and the workers cannot land on different
    /// allocators — a coordinator that reserved elsewhere would report success
    /// while the port the session actually names stayed free.
    ///
    /// The NAT64 twin is taken second and ROLLED BACK on failure of neither
    /// half being enough on its own: a NAT64 decision carries both a v4 pool
    /// source (source-NAT allocator) and a translated `(pool v4, port)` (the
    /// per-prefix allocator), so a session can be admissible to one and not the
    /// other. Leaving a half-taken reservation behind would be a leak no worker
    /// ever releases, because no session gets published to reap.

    fn reserve_synced_translation(&self, entry: &SyncedSessionEntry) -> bool {
        let now_ns = monotonic_nanos();
        // #7209: ONE load of the published view, bound for the whole call. Two
        // loads inside one import can straddle a publish and resolve the
        // session's zones against one generation and its NAT against another —
        // the pairing defect #6592 closed, reintroduced at a different layer.
        let view = self.runtime_view();
        let forwarding = view.forwarding();

        let zones = crate::afxdp::session_glue::synced_source_nat_zone_pair(
            forwarding,
            &entry.metadata,
        );
        // #7209: count the degraded path. Bumped HERE, on the coordinator's
        // once-per-import pre-publish reservation, and deliberately NOT at the
        // worker-side twin in `commands/upsert_synced.rs`: that one runs on
        // EVERY worker for the same entry (the command is fanned out to each
        // queue), so counting there would multiply one degraded import by the
        // worker count and make the metric a function of `--workers` rather
        // than of what happened.
        //
        // Counted only when the unresolved pair actually COST something. The
        // reservation early-returns for a reverse session and for one with no
        // source-NAT rewrite (`reserve_synced_source_nat_allocation_with_holder`
        // returns on `is_reverse` and on `rewrite_src == None`), so for those
        // the zone pair is never consulted and nothing is degraded. Counting
        // them would make the metric a function of how much non-NAT traffic the
        // peer syncs rather than of what was lost — an operator watching it
        // would see it climb on a healthy cluster and learn to ignore it.
        if zones.is_none()
            && !entry.metadata.is_reverse
            && entry.decision.nat.rewrite_src.is_some()
        {
            self.sessions
                .synced_import_zone_unresolved
                .fetch_add(1, Ordering::Relaxed);
        }
        if !crate::nat::reserve_synced_source_nat_allocation_untracked(
            &forwarding.iface_nat_allocators,
            &forwarding.source_nat_rules,
            &entry.key,
            entry.decision.nat,
            entry.metadata.is_reverse,
            zones,
            now_ns,
        ) {
            return false;
        }
        if !crate::nat64::reserve_synced_nat64_allocation(
            &forwarding.nat64,
            &entry.key,
            entry.decision.nat,
            entry.metadata.is_reverse,
            now_ns,
        ) {
            crate::nat::release_source_nat_allocation(
                &forwarding.iface_nat_allocators,
                &forwarding.source_nat_rules,
                &entry.key,
                entry.decision.nat,
                entry.metadata.is_reverse,
                now_ns,
            );
            return false;
        }
        true
    }

    /// Publish one synced session row to the kernel session map, or record that
    /// there was no map to publish into (#7209).
    ///
    /// This exists to split a conjunction that conflated two very different
    /// reasons for not publishing. The call sites read
    ///
    /// ```ignore
    /// if synced_entry_allows_local_replace(..) && let Some(fd) = ..session_map_fd
    /// ```
    ///
    /// where the FIRST operand failing is a deliberate ownership decision — the
    /// peer owns the redundancy group, so this node must NOT take the redirect,
    /// and not publishing is the correct outcome — while the SECOND failing is a
    /// gap: the entry is recorded in the shared map and answered to Go as
    /// installed, but no kernel row exists. Counting "did not publish" across
    /// both would fire continuously on healthy peer-owned imports and report
    /// nothing; only the second is reportable, and it is only separable once the
    /// `&&` is split.
    ///
    /// WHEN THE MAP IS ABSENT. `bpf_maps.session_map_fd` is `None` before the
    /// first successful reconcile and again between `Coordinator::stop_inner`
    /// (which sets it to `None`) and `reconcile::bringup` (which re-sets it). An
    /// HA standby that receives bulk session sync before its first snapshot
    /// apply — the ordinary failover-preparation sequence — lands here for every
    /// session in the batch.
    ///
    /// THIS IS NOT A LOSS TODAY, and the counter is not an alarm. Every
    /// `reconcile` replays the shared synced map once the new map is up, so an
    /// entry recorded while the fd was absent is published by the next
    /// reconcile.
    ///
    /// CORRECTED (#8157 / PR #8171). This paragraph used to say `teardown::tear_down`
    /// captures the whole map via `snapshot_shared_session_entries()` before
    /// the teardown, and that the remaining capture-to-replay window is closed
    /// by the snapshot-wide `ServerState` mutex. That was true when written and
    /// is not now: `replay_preserved_sessions` (`reconcile/bringup.rs`, which cites
    /// #8157) derives
    /// the replay set from the LIVE shared map at replay time — after every
    /// arrival the reconcile could race — so the window is closed by
    /// construction rather than by the lock. The historical shape is recorded
    /// because the mutex-based reasoning it supported still appears elsewhere,
    /// and because #7209 PROPOSES to remove that mutex for `sync_session` —
    /// which has not happened: `sync_session` still dispatches under it.
    ///
    /// Why this counter landed FIRST, in the past tense the correction above
    /// requires: BEFORE #8157/#8171, an import arriving in the capture-to-replay
    /// window would have been recorded, acked to Go as installed, never
    /// published and never replayed, with no signal anywhere. The replay now
    /// reads the live map, so that particular loss is closed by construction.
    /// The counter remains worth having because the absent-fd publish skip is
    /// still reachable on its own (a standby taking bulk sync before its first
    /// apply), and it makes those benign occurrences visible rather than
    /// asserted from a reading of the lock graph.
    fn publish_synced_entry_or_note_unpublished(
        &self,
        key: &SessionKey,
        nat: NatDecision,
        is_reverse: bool,
    ) {
        // #7209: the loaded set is bound to `maps` for the whole publish, so the
        // descriptor cannot be closed between this check and the write below.
        // The `Arc` is the lifetime guarantee; re-loading per read would not be.
        let maps = self.bpf_maps.load();
        let Some(session_map_fd) = maps.session_map_fd.as_ref() else {
            self.sessions
                .synced_import_unpublished
                .fetch_add(1, Ordering::Relaxed);
            return;
        };
        // #1789: a failed HA-upsert publish silently loses synced state (the
        // shim takes the NO_SESSION degraded path). No binding context here, so
        // bump the shared counter. Distinct from the absent-map arm above: this
        // one HAD a map and the kernel refused the write.
        if publish_live_session_entry(session_map_fd.fd, key, nat, is_reverse).is_err() {
            SESSION_PUBLISH_ERRORS_SHARED.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn upsert_synced_session(&self, entry: SyncedSessionEntry) -> SyncedImportOutcome {
        // #8015: refuse a STANDALONE reverse. This runs before every other
        // decision below because none of them apply to an entry that must not
        // be imported at all — and because the cap gate deliberately skips
        // reverse keys (`!entry.metadata.is_reverse`), which is what let the
        // old lone-reverse publish past a full map as the documented "+1
        // orphan".
        //
        // The reverse companion of every forward imported here is built by
        // `synthesized_synced_reverse_entry` a few lines down and published
        // with its forward, so nothing this function admits ever needs a
        // caller-supplied reverse. See `RejectedStandaloneReverse` for why the
        // unanchored case cannot be cleaned up after the fact.
        if entry.metadata.is_reverse {
            return SyncedImportOutcome::RejectedStandaloneReverse;
        }
        // #7209: ONE load of the published view, bound for the whole call. Two
        // loads inside one import can straddle a publish and resolve the
        // session's zones against one generation and its NAT against another —
        // the pairing defect #6592 closed, reintroduced at a different layer.
        let view = self.runtime_view();
        let forwarding = view.forwarding();

        // #7209: ONE snapshot of the worker set for this whole import.
        //
        // Three decisions below ask about the workers — the admission cap, the
        // no-worker reservation gate, and the command fan-out — and they must
        // agree with each other. They used to, for free: every mutator of the
        // record map needed `&mut Coordinator`, which the snapshot-wide
        // `ServerState` mutex made impossible to obtain while this ran. Once
        // `sync_session` dispatches off that mutex, three separate loads can
        // straddle a reconcile's teardown and disagree — a cap sized for live
        // workers, a gate that then sees none (skipping the reservation), and a
        // fan-out that finds some again (queueing a command for a session with
        // no reservation). Or the reverse: reserve, then fan out to nobody,
        // leaving an `Untracked` reservation with no worker to release it.
        // Pinning the snapshot here makes the import internally consistent
        // whatever the reconcile does, which is the property the mutex was
        // providing incidentally.
        let worker_records = Arc::clone(&self.workers.load());
        let now_secs = monotonic_nanos() / 1_000_000_000;
        let ha_state = self.rg_runtime.load();
        // #5154: read the stored entry AND the map length under ONE RECOVERED
        // critical section. Both reads feed a REFUSAL decision (the #2170
        // generation guard and the #5674 admission bound), and every write
        // below commits through `lock_shared_recover`. Reading with
        // `.lock().ok()` / `.lock().map(..).unwrap_or(0)` applied the OPPOSITE
        // poison policy to the validation half: after a contained worker panic
        // (#925 supervisor) poisoned this mutex, the stored entry read as None
        // and the length read as 0, so BOTH guards silently evaluated
        // "no previous entry, empty map" and fell through — while the
        // recovering write then committed the very install they exist to
        // refuse. A stale-generation import regressed the stored generation and
        // an over-ceiling import bypassed the aggregate bound, on a code path
        // the system is explicitly designed to SURVIVE. Recovering here (the
        // #2402 / #1807 module policy, `lock_shared_recover`: keep the
        // committed map, clear the poison, count + log the recovery) makes
        // validation and mutation agree. Refusing the WRITE on poison instead
        // is not a coherent alternative: `lock_shared_recover` CLEARS poison,
        // so the poisoned window closes the instant any other shared-session
        // path (publish, lookup, remove, prewarm) touches this mutex — a
        // refuse-on-poison write would fire or not fire depending on which
        // thread locked first, and would wedge HA session sync after a panic
        // the supervisor already contained. Folding the two reads into one
        // guard also removes a real TOCTOU: they were separate locks, so the
        // ceiling could be evaluated against a map that changed (including one
        // that had gained this very key) between them.
        let (previous_entry, synced_len) = {
            let sessions = lock_shared_recover(&self.sessions.synced);
            (sessions.get(&entry.key).cloned(), sessions.len())
        };
        // #2170 install-side guard (SMR C3): refuse a strictly-older-
        // generation install so the per-key stored generation never
        // regresses (closes the delayed-stale-install variant on the
        // helper). Only acts when BOTH the stored and incoming generations
        // are non-zero — local-origin entries (generation 0) and legacy
        // peers fall back to today's unconditional upsert.
        if let Some(previous) = previous_entry.as_ref()
            && previous.generation != 0
            && entry.generation != 0
            && entry.generation < previous.generation
        {
            self.sessions
                .install_stale_ignored
                .fetch_add(1, Ordering::Relaxed);
            return SyncedImportOutcome::RejectedStaleGeneration;
        }
        // #5674: aggregate synced-import admission bound. Locally-created
        // sessions are capped per worker at `DEFAULT_MAX_SESSIONS`
        // (`install_with_protocol_with_origin`), but peer-synced sessions were
        // imported with NO cap and fanned out to EVERY worker command queue +
        // table below, so a peer under session-table pressure — or a
        // malicious/compromised peer — could drive this node past its own
        // aggregate session ceiling and multiply that state across all workers
        // (the availability/DoS root of #5674). Bound the SHARED synced map
        // (the single fan-out choke point) at this appliance's OWN aggregate
        // ENTRY ceiling, `2 * worker_count * DEFAULT_MAX_SESSIONS`
        // (`synced_import_cap`). The 2× is load-bearing: each admitted forward
        // logical session publishes TWO keys into `sessions.synced` — the
        // forward key and a synthesized reverse companion — so K admitted
        // forwards occupy 2K entries. With the entry cap at 2N (N = the logical
        // ceiling), a NEW forward is rejected exactly when 2K >= 2N ⇔ K >= N:
        // a full symmetric-peer set (N logical → 2N entries) EXACTLY fits and
        // only a peer EXCEEDING its own logical ceiling is rejected.
        //
        // #8015 CLOSED THE "+1 ORPHAN" CORNER THIS GATE USED TO DOCUMENT. The
        // gate keys on `!entry.metadata.is_reverse`, so a lone `is_reverse=1`
        // import used to skip it and publish as a bounded orphan with no
        // matching forward whenever the map was AT the cap and its own forward
        // was cap-rejected. #6413 assessed that as self-inflicted and low-harm,
        // which it was — the tuple and the decision were the FORWARD's own, so
        // it admitted the reply direction of a flow this node had itself just
        // adjudicated — but it could OUTLIVE its forward:
        // `delete_synced_session_gen` derives the companion to remove from the
        // STORED forward, and after a refusal there is no stored forward, so a
        // later delete of that forward removed nothing and the reverse idled
        // out on its own.
        //
        // The standalone-reverse refusal at the top of this function removes
        // that shape at its root, and #8015 removed its only sender as well
        // (`mirrorSessionPairV4`/`V6`'s explicit companion pre-install). The
        // peer path never reached here in the first place: Go's
        // `SetClusterSyncedSessionV4`/`V6` early-return on
        // `!shouldMirrorUserspaceSession(val.IsReverse)` and write ONLY the BPF
        // mirror, so only FORWARD peer imports transit the helper, which then
        // synthesizes their companion locally.
        //
        // The `!entry.metadata.is_reverse` conditions in the rest of this
        // function are therefore redundant with that early return. They stay as
        // belt-and-suspenders — the same posture as the #2170 delete-side
        // generation guard, whose own comment records that nothing reaches it
        // today — so that weakening or moving the early return degrades to the
        // previous behaviour rather than to an unguarded publish.
        //
        // Drop-NEWEST: reject a NEW forward key at/above
        // the ceiling (never enqueue it to any worker), but ALWAYS allow a
        // REPLACE of an existing synced key (`previous_entry.is_some()` — it
        // does not grow the map) so an in-flight synced session keeps
        // refreshing. Never evict an existing synced session to make room; that
        // would drop a legitimate failover session. A zero ceiling (no workers
        // registered yet — early boot / teardown) disables the bound so a
        // transient window never rejects legitimate imports.
        if previous_entry.is_none() && !entry.metadata.is_reverse {
            let synced_cap = self.synced_import_cap_for(&worker_records);
            if synced_cap != 0 && synced_len >= synced_cap {
                self.sessions
                    .import_cap_drops
                    .fetch_add(1, Ordering::Relaxed);
                return SyncedImportOutcome::RejectedCapacity;
            }
        }
        let reverse_entry = if !entry.metadata.is_reverse {
            synthesized_synced_reverse_entry(
                forwarding,
                ha_state.as_ref(),
                &self.dynamic_neighbors,
                &entry,
                now_secs,
            )
        } else {
            None
        };
        // #6600: RESERVE THE TRANSLATED NAT PORT BEFORE PUBLISHING.
        //
        // The publish below makes the entry visible on every packet-path lookup
        // surface at once (`synced`, `nat`, `forward_wire`), and
        // `materialize_shared_session_hit` forwards on `replica.decision`
        // — including `decision.nat` — without reserving anything. The
        // reservation used to happen ONLY inside the worker-local upsert, which
        // is driven by a command enqueued AFTER this publish; a worker that
        // sampled an empty queue just before that push proceeds straight into
        // `poll_binding` with the entry already live. In that window a local
        // flow can allocate the same port, and `reserve_flow` REFUSES to steal
        // it — correctly — after which the imported session went on advertising
        // a translation this node does not own, with the refusal returned by
        // nothing and counted by nothing.
        //
        // Taking the reservation here closes the window at its source rather
        // than trying to observe it afterwards. It is also the only thing that
        // COULD make the refusal reachable by the import outcome at all: the
        // worker-side reserve runs long after the control RPC has answered, so
        // propagating from there was never possible.
        //
        // `Untracked` contributes no holder bit, so the per-worker reservations
        // that follow are absorbed rather than doubled — `reserve_flow` finds
        // the identical `(flow, translated)` already live and takes its
        // idempotent early return, OR-ing each worker's bit in — and the last
        // worker's release still empties the mask and frees the port.
        //
        // Skipped when NO worker is registered: nothing polls, so there is no
        // racing local allocation to guard against, and an `Untracked`
        // reservation that no worker ever adopts has no one to release it. Same
        // shape as the zero-ceiling carve-out above, and for the same reason.
        // #9678: decide LOCAL OWNERSHIP before anything below touches the
        // allocator or the shared maps.
        //
        // The worker refuses a peer upsert that would replace a locally-owned
        // session while that session's owner RG is locally forwarding-active
        // (`upsert_synced_with_origin` + `synced_entry_allows_local_replace` in
        // `handle_upsert_synced`). The reservation below ran first, and
        // `reserve_flow` retires an incumbent `live_by_flow` record holding a
        // DIFFERENT translated tuple. So a same-flow peer upsert evicted the live
        // local allocation T1, reserved an `Untracked` T2, and the worker then
        // kept forwarding on T1 with no allocator record behind it: T1 could be
        // handed to another flow. Every refusal inside the reserve also happened
        // after that unlink, so even a `RejectedReserve` import had freed T1.
        //
        // Skipping only the reservation would still publish the peer's decision
        // into the shared maps, which is the #6600 shape: a shared entry naming a
        // port this node does not hold. So the whole import stops here, before
        // the reservation, the shared publish and the worker fan-out, using the
        // same predicate the worker applies. That mirrors the worker's refusal,
        // which is silent too, and it is why this reports `Applied` rather than
        // a new refusal the control plane would surface as a peer error. Once
        // the RG is no longer locally active, the next sync of this flow imports
        // normally.
        if entry.origin.is_peer_synced()
            && previous_entry
                .as_ref()
                .is_some_and(|previous| !previous.origin.is_peer_synced())
            && !synced_entry_allows_local_replace(
                ha_state.as_ref(),
                entry.metadata.owner_rg_id,
                now_secs,
            )
        {
            return SyncedImportOutcome::Applied;
        }
        if entry.origin.is_peer_synced()
            && !entry.metadata.is_reverse
            && !worker_records.is_empty()
            && !self.reserve_synced_translation(&entry)
        {
            self.sessions
                .import_reserve_refused
                .fetch_add(1, Ordering::Relaxed);
            return SyncedImportOutcome::RejectedReserve;
        }
        publish_shared_session(
            &self.sessions.synced,
            &self.sessions.nat,
            &self.sessions.forward_wire,
            &self.sessions.owner_rg_indexes,
            &entry,
        );
        // #4393: publish the reverse-SNAT `dnat_table` BPF-map entry for a
        // peer-synced forward SNAT session. The active node populates this
        // steering map from the worker poll path when it forwards the first
        // SNAT'd packet (`poll_descriptor`), but the standby never forwards
        // that packet — it imports the pre-computed NAT decision here. Without
        // this publish the standby has no `dnat_table` entry, so after failover
        // the shim does not steer an inbound embedded-ICMP error (PMTUD
        // Too-Big / traceroute Time-Exceeded) whose quoted inner packet carries
        // the SNAT pool `(addr, port)` into the helper's slow path — the error
        // is passed to the kernel (no NAT state) instead of reverse-NAT'd back
        // to the original client, so the client never learns the PMTU (TCP
        // stalls on large packets) and traceroute breaks. Mirrors the primary's
        // `publish_dnat_table_entry` call site exactly (forward entry only; a
        // reverse companion carries no SNAT source rewrite). Published
        // unconditionally (NOT gated on `synced_entry_allows_local_replace`,
        // unlike the forward session-map publish below): the `dnat_table` is a
        // passive reverse-NAT steering map that must be ready the instant this
        // node becomes active, and inbound SNAT-return traffic does not reach
        // the standby anyway, so an early entry is inert until failover. The
        // matching release is `delete_synced_session_gen`'s teardown, plus the
        // #9514 holder migration below when a same-key replacement moves the
        // row. The
        // process-global `dnat_table` map is a single shared object, so this
        // once-per-synced-session publish (not per worker) mirrors the primary.
        if !entry.metadata.is_reverse {
            // #7209: hold the loaded set across the publish — `DnatTableFds`
            // carries RAW descriptors, so the guard must outlive the call that
            // uses them.
            let maps = self.bpf_maps.load();
            let dnat_fds = DnatTableFds {
                v4: maps.dnat_table_fd.as_ref().map(|fd| fd.fd),
                v6: maps.dnat_table_v6_fd.as_ref().map(|fd| fd.fd),
            };
            if !publish_dnat_table_entry(&dnat_fds, &entry.key, entry.decision.nat) {
                // #4393/#2244: a failed publish (map at capacity / kernel
                // resource exhaustion) silently loses the reverse-NAT steering
                // entry. Count it via the shared static (no per-binding context
                // here) so `dnat_publish_errors_total` stays honest.
                DNAT_PUBLISH_ERRORS_SHARED.fetch_add(1, Ordering::Relaxed);
            }
            // #9514: MIGRATE the steering hold on a same-key replacement that
            // MOVES the row. A hold is `(key, nat)`-shaped and
            // `release_dnat_steering_holder` drops only the pair it is given,
            // while the final teardown (`delete_synced_session_gen`) names the
            // STORED -- newest -- decision. So a replacement from SNAT tuple A
            // to B, left alone, strands `(key, A)`: the delete releases only B,
            // and every later session on row A then has its map delete refused,
            // because the stranded hold keeps the row non-empty. Measured
            // through this function before the fix (see docs/log/9514.md).
            //
            // Released THROUGH `delete_dnat_table_entry`, never with a raw map
            // delete: the row is shared (#6745), so this drops only THIS key's
            // hold and deletes the row only if that was the last one.
            //
            // Gated on the row CHANGING. A same-row refresh re-acquires the hold
            // idempotently in the publish above; releasing it here would drop
            // the hold of a session that is still live and delete its row.
            if let Some(previous) = previous_entry.as_ref()
                && crate::afxdp::checksum::dnat_steering_key(&previous.key, previous.decision.nat)
                    != crate::afxdp::checksum::dnat_steering_key(&entry.key, entry.decision.nat)
            {
                delete_dnat_table_entry(&dnat_fds, &previous.key, previous.decision.nat);
            }
        }
        // Keep the immediate BPF publish aligned with the worker-side
        // ownership guard so XSK redirect state cannot get ahead of what
        // the local SessionTable would actually accept.
        if synced_entry_allows_local_replace(
            ha_state.as_ref(),
            entry.metadata.owner_rg_id,
            now_secs,
        ) {
            self.publish_synced_entry_or_note_unpublished(
                &entry.key,
                entry.decision.nat,
                entry.metadata.is_reverse,
            );
        }
        refresh_reverse_prewarm_owner_rg_indexes(
            &self.sessions.owner_rg_indexes.reverse_prewarm_sessions,
            forwarding,
            &self.dynamic_neighbors,
            previous_entry.as_ref(),
            Some(&entry),
        );
        if let Some(reverse) = &reverse_entry {
            publish_shared_session(
                &self.sessions.synced,
                &self.sessions.nat,
                &self.sessions.forward_wire,
                &self.sessions.owner_rg_indexes,
                reverse,
            );
            if synced_entry_allows_local_replace(
                ha_state.as_ref(),
                reverse.metadata.owner_rg_id,
                now_secs,
            ) {
                // #1789: same accounting for the synthesized reverse entry
                // (was `let _ =`); #7209 folds it into the same authority.
                self.publish_synced_entry_or_note_unpublished(
                    &reverse.key,
                    reverse.decision.nat,
                    true,
                );
            }
        }
        // #6242: fan out to each worker's command queue via its runtime record.
        for rec in worker_records.values() {
            // #1790/#1807: recover-and-push instead of silently skipping a
            // poisoned queue (same policy as update_ha_state).
            let mut pending = worker_queue::lock_recover(&rec.handle.commands);
            // #6929: bounded. A drop here is an HA upsert the worker will
            // never see; the counter is what makes that visible instead of
            // silent.
            worker_queue::push_bounded(&mut pending, WorkerCommand::UpsertSynced(entry.clone()));
            if let Some(reverse) = &reverse_entry {
                worker_queue::push_bounded(
                    &mut pending,
                    WorkerCommand::UpsertSynced(reverse.clone()),
                );
            }
        }
        SyncedImportOutcome::Applied
    }

    /// #8636: does the shared synced map hold an entry under EXACTLY this key?
    ///
    /// The ambiguity probe for the domain-scoped delete. It exists because a
    /// delete built from a bare 5-tuple resolves routing domain 0 ("the sender
    /// did not state one"), and the handler must then decide between the
    /// domains that could hold it. Counting matches is what lets it refuse an
    /// ambiguous delete instead of deleting in every domain and tearing down
    /// another tenant's live session.
    ///
    /// Reads through `lock_shared_recover` for the same reason
    /// `delete_synced_session_gen` does (#5154): with `.lock().ok()` a poisoned
    /// mutex reads as None, and an ambiguity check that silently answers "no
    /// matches" would resolve to "delete nothing" — quiet, and indistinguishable
    /// from a clean miss.
    pub fn synced_session_contains(&self, key: &SessionKey) -> bool {
        lock_shared_recover(&self.sessions.synced).contains_key(key)
    }

    pub fn delete_synced_session(&self, key: SessionKey) {
        // Helper-local deletes (tunnel-remap purge, GC) are authoritative and
        // carry no peer install generation — apply unconditionally.
        self.delete_synced_session_gen(key, 0);
    }

    /// #9714: a delete sent on behalf of the PEER (`SessionSyncRequest.peer_delete`:
    /// the Go cluster-stale apply and the #6368 install rollback). It is refused for
    /// a key this node holds as a LOCAL session whose owner redundancy group is
    /// locally forwarding-active: under a dual-primary split both nodes forward the
    /// flow, and the peer closing its copy must not remove this node's kernel,
    /// DNAT and shared rows or send `DeleteSynced` to the sibling replicas. This is
    /// the process-wide mirror of the worker's #9048 refusal
    /// (`handle_delete_synced`), with the same predicate, so it fires only in a
    /// dual-primary split. Otherwise, and for every authoritative delete, it
    /// behaves exactly as `delete_synced_session`.
    ///
    /// Returns the OUTCOME. The handler answers a refusal in-band, so the Go side
    /// keeps its own mirror and DNAT rows for the flow the helper kept.
    pub fn delete_peer_synced_session(&self, key: SessionKey) -> SyncedDeleteOutcome {
        self.delete_synced_session_gen_marked(key, 0, true)
    }

    /// #2170 delete-side guard (belt-and-suspenders for any helper-side delete
    /// that carries a peer install generation): refuse to remove a stored
    /// entry whose generation is strictly NEWER than the delete's, so a stale
    /// delete cannot kill a same-key replacement the helper already mirrored.
    /// The authoritative guard lives in the Go cluster apply layer
    /// (deleteClusterSynced*) — that short-circuits both the BPF map delete and
    /// this helper path, so the cluster-delete path never reaches here with a
    /// non-zero delete_gen today; the seam exists for future helper-originated
    /// generation-aware deletes. A delete_gen of 0, or a stored generation of
    /// 0, falls back to unconditional delete (rolling-upgrade safe).
    pub fn delete_synced_session_gen(&self, key: SessionKey, delete_gen: u64) {
        let _ = self.delete_synced_session_gen_marked(key, delete_gen, false);
    }

    fn delete_synced_session_gen_marked(
        &self,
        key: SessionKey,
        delete_gen: u64,
        peer_delete: bool,
    ) -> SyncedDeleteOutcome {
        // #7209: ONE load of the published view, bound for the whole call. Two
        // loads inside one import can straddle a publish and resolve the
        // session's zones against one generation and its NAT against another —
        // the pairing defect #6592 closed, reintroduced at a different layer.
        let view = self.runtime_view();
        let forwarding = view.forwarding();

        // #5154: RECOVER the poison on this read (same policy as the write
        // below, which reaches the map through `remove_shared_session` ->
        // `lock_shared_recover`). With `.lock().ok()` a poisoned mutex read as
        // None, so the delete-side generation guard never evaluated — and the
        // recovering `remove_shared_session` then deleted the entry anyway.
        // That is a stale delete killing a NEWER same-key replacement the
        // helper had already mirrored: exactly the outcome this guard exists
        // to prevent, reachable via a contained worker panic.
        let removed_entry = lock_shared_recover(&self.sessions.synced)
            .get(&key)
            .cloned();
        if let Some(entry) = removed_entry.as_ref()
            && entry.generation != 0
            && delete_gen != 0
            && delete_gen < entry.generation
        {
            self.sessions
                .delete_stale_ignored
                .fetch_add(1, Ordering::Relaxed);
            return SyncedDeleteOutcome::RefusedStaleGeneration;
        }
        // #9714: refuse a PEER delete of a live local session whose owner RG is
        // locally active, before any kernel, DNAT or shared delete and before the
        // worker fan-out. Nothing below runs, so no sibling replica is dropped.
        //
        // #9714 F4: the predicate is the INSTALL side's
        // `synced_entry_allows_local_replace`, NOT `owner_rg_is_locally_active`.
        // The latter hard-requires `owner_rg_id > 0`, so owner 0 — which means
        // UNKNOWN rather than "no RG" — fell straight through to the delete,
        // while the install side already refused to clobber such an entry
        // whenever ANY redundancy group is forwarding-active. A delete guard
        // weaker than the install guard it mirrors is the #9714 defect through a
        // second door: the peer tears down what the peer could not have
        // installed. The same fail-open sat on BOTH delete guards (here and the
        // worker's #9048 refusal in `handle_delete_synced`); both move together,
        // so the two verbs keep agreeing by construction rather than by comment.
        if peer_delete
            && let Some(entry) = removed_entry.as_ref()
            && !entry.origin.is_peer_synced()
            && !synced_entry_allows_local_replace(
                self.rg_runtime.load().as_ref(),
                entry.metadata.owner_rg_id,
                monotonic_nanos() / 1_000_000_000,
            )
        {
            PEER_DELETE_REFUSED_LOCAL_OWNED.fetch_add(1, Ordering::Relaxed);
            return SyncedDeleteOutcome::RefusedLocalOwned;
        }
        let reverse_key = removed_entry.as_ref().and_then(|entry| {
            if entry.metadata.is_reverse {
                None
            } else {
                Some(reverse_session_key(&entry.key, entry.decision.nat))
            }
        });
        if let Some(entry) = removed_entry.as_ref() {
            let maps = self.bpf_maps.load();
            if let Some(session_map_fd) = maps.session_map_fd.as_ref() {
                delete_session_map_entry_for_removed_session(
                    session_map_fd.fd,
                    &entry.key,
                    entry.decision,
                    &entry.metadata,
                );
            }
            // #4393: release the reverse-SNAT `dnat_table` entry published for
            // this peer-synced forward SNAT session at `upsert_synced_session`
            // so it does not leak (the maps are non-LRU HASH with
            // `max_entries = MAX_SESSIONS`; every un-deleted entry burns a slot
            // until publishes start failing) or steer a stale inbound ICMP
            // error after the session is gone. Keyed on the SAME
            // `dnat_v4_key_bytes` / `dnat_v6_key_bytes` helpers the publish path
            // used, so it byte-matches the insert key; a non-SNAT / reverse
            // entry is a no-op.
            if !entry.metadata.is_reverse {
                // #7209: same as the publish twin — the guard must outlive the
                // call that uses the raw descriptors.
                let maps = self.bpf_maps.load();
                let dnat_fds = DnatTableFds {
                    v4: maps.dnat_table_fd.as_ref().map(|fd| fd.fd),
                    v6: maps.dnat_table_v6_fd.as_ref().map(|fd| fd.fd),
                };
                delete_dnat_table_entry(&dnat_fds, &entry.key, entry.decision.nat);
            }
        }
        // #9714 review round 2, finding 3: re-ask the decision UNDER THE LOCK, of the
        // entry actually being removed.
        //
        // The early returns above still short-circuit a delete that will be refused,
        // so no teardown is done for one. What they cannot do is bind their verdict
        // to THIS removal: the entry was read at the top of this function and the
        // lock released in the same statement, so a local replacement published in
        // the window between would be destroyed on a decision taken about a
        // different entry. Asking again inside the removal's own lock hold closes
        // that window without an identity token — the entry the predicate sees IS
        // the one removed.
        let now_secs = monotonic_nanos() / 1_000_000_000;
        let rg_runtime = self.rg_runtime.load();
        let removal = remove_shared_session_if(
            &self.sessions.synced,
            &self.sessions.nat,
            &self.sessions.forward_wire,
            &self.sessions.owner_rg_indexes,
            &key,
            |current| {
                // #2170: a stale delete must not remove a NEWER same-key entry.
                if current.generation != 0
                    && delete_gen != 0
                    && delete_gen < current.generation
                {
                    return false;
                }
                // #9714: nor may a peer delete remove a live LOCAL session whose
                // owner RG is not free to be replaced.
                !(peer_delete
                    && !current.origin.is_peer_synced()
                    && !synced_entry_allows_local_replace(
                        rg_runtime.as_ref(),
                        current.metadata.owner_rg_id,
                        now_secs,
                    ))
            },
        );
        refresh_reverse_prewarm_owner_rg_indexes(
            &self.sessions.owner_rg_indexes.reverse_prewarm_sessions,
            forwarding,
            &self.dynamic_neighbors,
            removed_entry.as_ref(),
            None,
        );
        // The reverse companion goes only if the FORWARD actually went. If the
        // predicate declined — a replacement appeared between the decision and the
        // removal — the flow is still live, and tearing down its reverse half would
        // leave a forward session that can no longer match its own replies: worse
        // than either outcome the decision was choosing between.
        if let Some(reverse_key) = &reverse_key
            && !matches!(removal, SharedRemoval::Declined)
        {
            remove_shared_session(
                &self.sessions.synced,
                &self.sessions.nat,
                &self.sessions.forward_wire,
                &self.sessions.owner_rg_indexes,
                reverse_key,
            );
        }
        // #6242: fan out to each worker's command queue via its runtime record.
        //
        // #6979 F4: a DROPPED `DeleteSynced` is a permanently stranded NAT
        // reservation, so the drop is repaired here instead of discarded.
        //
        // `push_bounded` returns false when the queue is at
        // `MAX_PENDING_WORKER_COMMANDS`, and that return was ignored. Shared
        // authority was already removed above, so the key is gone from replay
        // and no later reconcile re-delivers the command; the worker that never
        // received it keeps its holder bit set, and because that worker is
        // ALIVE neither reclaim sweep can see it — `retire_dead_worker_holders`
        // selects on the panic `dead` flag (#8069) and `retire_all_worker_holders`
        // runs only at generation teardown (#7092). The port is then held for
        // the life of the allocator.
        //
        // MEASURED, because the issue predicted otherwise. #6979's own closing
        // note expects the holder-set to bound F4 to "that worker's bit is
        // cleared". It does — for the route the finding NAMES, a worker that
        // STOPS. The unbounded route is a worker that stays ALIVE and never
        // receives the command at all. Probe at the parent of this change:
        // queue-drop delta 1, pool port still occupied, `dead` false,
        // dead-worker sweep freed 0.
        //
        // Releasing on the worker's behalf cannot OVER-release. The command was
        // dropped, so that worker will never run this teardown itself; and
        // `release_flow` no-ops unless `live_by_flow[flow].translated` equals
        // this exact tuple, so a worker whose own `UpsertSynced` is still queued
        // (no reservation taken yet) is untouched. The direction-of-error rule
        // at `PortAllocator::drop_holder_locked` is satisfied: this clears the
        // bit of a worker that provably cannot forward this flow again.
        //
        // NOT repaired here, deliberately: the same dropped command also means
        // that worker never removes its LOCAL session-table and BPF map entries
        // for the key. Shared authority governs which sessions exist and the
        // process-wide session-map delete already ran above, so the NAT
        // reservation is the part with no other owner. The wider signal is
        // `WORKER_COMMAND_QUEUE_DROPS`.
        for (worker_id, rec) in self.workers.load().iter() {
            // #1790/#1807: recover-and-push instead of silently skipping a
            // poisoned queue (same policy as update_ha_state).
            let mut pending = worker_queue::lock_recover(&rec.handle.commands);
            let queued =
                worker_queue::push_bounded(&mut pending, WorkerCommand::DeleteSynced(key.clone()));
            if let Some(reverse_key) = &reverse_key {
                worker_queue::push_bounded(
                    &mut pending,
                    WorkerCommand::DeleteSynced(reverse_key.clone()),
                );
            }
            // Release the command queue before touching allocator mutexes: the
            // two are unrelated locks and holding both would invent an ordering.
            drop(pending);
            // Only the FORWARD key carries a NAT reservation. The reverse
            // companion's teardown is a no-op by contract —
            // `release_source_nat_allocation_with_mode` returns immediately on
            // `is_reverse` — so repairing its drop would call a function that
            // does nothing and count a repair that did not happen. Measured:
            // repairing both made the counter read 2 for one stranded
            // reservation, which is exactly the kind of number an operator
            // would later have to explain.
            if let Some(entry) = removed_entry.as_ref()
                && !queued
            {
                self.release_dropped_delete_for_worker(entry, &key, *worker_id);
            }
        }
        SyncedDeleteOutcome::Applied
    }

    /// #6979 F4: run the NAT teardown a worker will never run itself, because
    /// its `DeleteSynced` was dropped by a full command queue.
    ///
    /// Byte-for-byte the call the worker makes when it processes the command,
    /// with that worker's id as the holder — so the holder mask empties on the
    /// same last-release rule and the port is returned exactly once.
    fn release_dropped_delete_for_worker(
        &self,
        entry: &SyncedSessionEntry,
        key: &SessionKey,
        worker_id: u32,
    ) {
        // #7209: ONE load of the published view, bound for the whole call. Two
        // loads inside one import can straddle a publish and resolve the
        // session's zones against one generation and its NAT against another —
        // the pairing defect #6592 closed, reintroduced at a different layer.
        let view = self.runtime_view();
        let forwarding = view.forwarding();
        self.sessions
            .delete_dropped_released
            .fetch_add(1, Ordering::Relaxed);
        crate::nat::release_source_nat_allocation_for_worker(
            &forwarding.iface_nat_allocators,
            &forwarding.source_nat_rules,
            key,
            entry.decision.nat,
            entry.metadata.is_reverse,
            crate::afxdp::wg::counters::monotonic_now_ns(),
            worker_id,
        );
    }

    /// #4054 test seam: install a qualifying LOCAL forward session (owner-RG 0
    /// so the RG-active gate is bypassed, `ForwardCandidate` disposition, local
    /// `ForwardFlow` origin so it is not skipped as peer-synced) so a dispatcher
    /// test can drive a non-empty bulk export against a backpressured event
    /// stream. `idx` gives each call a distinct 5-tuple.
    #[cfg(test)]
    pub(crate) fn test_install_local_forward_session(&self, idx: u16) {
        use std::net::{IpAddr, Ipv4Addr};
        let key = SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
            src_port: 40000 + idx,
            dst_port: 5201,
                    discriminator: Default::default(),
                    routing_domain: 0,
        };
        let resolution = ForwardingResolution {
            disposition: ForwardingDisposition::ForwardCandidate,
            local_ifindex: 0,
            egress_ifindex: 12,
            tx_ifindex: 12,
            tunnel_endpoint_id: 0,
            next_hop: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 50, 1))),
            neighbor_mac: Some([0, 1, 2, 3, 4, 5]),
            src_mac: Some([6, 7, 8, 9, 10, 11]),
            tx_vlan_id: 0,
        };
        let metadata = SessionMetadata {
            ingress_zone: 1,
            egress_zone: 3,
            ingress_ifindex: 0,
            ingress_vlan_id: 0,
            owner_rg_id: 0,
            fabric_ingress: false,
            is_reverse: false,
            nat64_reverse: None,
            log_session_init: false,
            log_session_close: false,
            policy_id: 0,
            inactivity_timeout_ns: None,
            policy_counter_idx: 0,
            policy_counter: None,
        };
        let _ = self.upsert_synced_session(SyncedSessionEntry {
            key,
            decision: SessionDecision {
                resolution,
                nat: NatDecision::default(),
            },
            metadata,
            origin: SessionOrigin::ForwardFlow,
            protocol: PROTO_TCP,
            tcp_flags: 0,
            generation: 0,
            session_id: 0,
            tcp_close_class: 0,
        });
    }
}
