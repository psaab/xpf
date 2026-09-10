// Install flow + capacity limits (#2005 pure code-motion split of
// session/mod.rs). The session-creation paths and their pre-flight
// admission live here: the #1861 capacity preflight/counter accessors
// (can_admit, note_admission_refused, admission_refused,
// note_install_partial, install_partial, create_drops,
// set_max_sessions_for_test), the new-flow installs (install_with_protocol,
// install_with_protocol_with_origin, upsert_synced,
// upsert_synced_with_origin), and the delta-emit / delete / owner-RG
// demotion helpers (emit_open_delta_with_origin,
// emit_close_delta_with_origin, delete, demote_owner_rg). Bodies are
// byte-for-byte identical; only the file boundary changed.
//
// No visibility was widened in this file: every moved method keeps its
// original `pub` / `pub(crate)` visibility (callable crate-wide off the
// pub(crate) SessionTable type). (The one widening in the overall split
// is `push_to_wheel` in expire.rs, not any method here.) The private
// helpers/structs these methods touch — remove_entry, next_epoch,
// index_forward_nat_key, push_delta, entry_by_key_mut,
// session_timeout_ns, SessionRecord/SessionEntry — live in the parent
// mod.rs and are visible to this descendant; push_to_wheel (in
// expire.rs) and owner_rg_session_keys (in lookup.rs) are reached via
// their existing pub/pub(in crate::session) visibility.
//
// The #1752/#1855 in-place-refresh contract (update_session,
// refresh_for_ha_transition, and the secondary-index re-assert helpers)
// stays in mod.rs — these installs build fresh records (remove_entry +
// insert), they are not the in-place-refresh path.

use super::*;

impl SessionTable {
    /// #1861 §5.1: pre-flight admission for an install group of `needed`
    /// new entries within ONE descriptor iteration. The table is
    /// per-worker, single-threaded, and `&mut`-exclusive during packet
    /// processing (GC and worker commands run between poll phases), so a
    /// passing preflight guarantees the subsequent `needed` installs
    /// cannot fail the `max_sessions` cap — the only install failure
    /// mode. Conservative on purpose: charges a full slot per entry even
    /// when the key already exists (a replacement would not grow the
    /// table). That matches `install_with_protocol_with_origin`'s own cap
    /// check, which also refuses replacements at cap; crediting
    /// replacements here would let the preflight pass while the install
    /// itself fails, violating the post-preflight infallibility contract.
    #[inline]
    pub fn can_admit(&self, needed: usize) -> bool {
        self.len().saturating_add(needed) <= self.max_sessions
    }

    /// #1861 §5.1: counted preflight refusal (one per refused flow).
    pub fn note_admission_refused(&mut self) {
        self.admission_refused = self.admission_refused.saturating_add(1);
    }

    /// #1861: cumulative pair-admission preflight refusals.
    pub fn admission_refused(&self) -> u64 {
        self.admission_refused
    }

    /// #1861 §5.2: counted impossible-by-construction release residual —
    /// an install failed after a passing preflight. Call sites pair this
    /// with `debug_assert!(false, ...)` per the #1855 contract.
    pub fn note_install_partial(&mut self) {
        self.install_partial = self.install_partial.saturating_add(1);
    }

    /// #1861: cumulative post-preflight partial-install residuals.
    pub fn install_partial(&self) -> u64 {
        self.install_partial
    }

    /// #1861: cumulative at-cap install refusals from
    /// `install_with_protocol_with_origin` (previously write-only —
    /// at-cap drops were operator-invisible).
    pub fn create_drops(&self) -> u64 {
        self.create_drops
    }

    /// #1861 tests: shrink the cap so at-cap interleavings can be rigged
    /// without inserting 131k entries.
    #[cfg(test)]
    pub(crate) fn set_max_sessions_for_test(&mut self, n: usize) {
        self.max_sessions = n;
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub fn install_with_protocol(
        &mut self,
        key: SessionKey,
        decision: SessionDecision,
        metadata: SessionMetadata,
        now_ns: u64,
        protocol: u8,
        tcp_flags: u8,
    ) -> bool {
        self.install_with_protocol_with_origin(
            key,
            decision,
            metadata,
            SessionOrigin::ForwardFlow,
            now_ns,
            protocol,
            tcp_flags,
        )
    }

    // NOTE: this fn stays positional (NOT context-struct) per the
    // #1357 plan v3.1 rollback criterion. Empirical codegen showed
    // the struct destructuring prelude added ~30% standalone-copy
    // instructions (274 -> 357), exceeding the plan's 10% gate. The
    // 7 non-inlined production callers (forwarding, poll_descriptor,
    // session_glue, shared_ops) are on the session-install hot path
    // and cannot absorb that overhead.
    pub fn install_with_protocol_with_origin(
        &mut self,
        key: SessionKey,
        decision: SessionDecision,
        metadata: SessionMetadata,
        origin: SessionOrigin,
        now_ns: u64,
        protocol: u8,
        tcp_flags: u8,
    ) -> bool {
        if self.len() >= self.max_sessions {
            self.create_drops = self.create_drops.saturating_add(1);
            return false;
        }
        // remove_entry's three debug_assert!s catch invariant
        // violations in tests:
        //   - stale-handle guard (entries.get returned None for a
        //     handle in key_to_handle)
        //   - PRIMARY-KEY GUARD (record.key != lookup key)
        //   - no_index_points_at (a secondary index still points
        //     at the freed handle after cleanup)
        // The first two guards restore the prior key_to_handle
        // mapping internally before returning None. In release we
        // proceed to insert the new record — the guard already
        // restored the prior mapping; the subsequent
        // self.key_to_handle.insert(...) overwrites it cleanly.
        let _previous = self.remove_entry(&key);
        let epoch = self.next_epoch();
        // #4915: allocate the STABLE, node-unique session id for this fresh
        // install. Threaded onto the entry (write-once) and the Open delta so a
        // session's SESSION_CREATE and SESSION_CLOSE RT_FLOW records share one
        // correlatable id, and a reused 5-tuple gets a distinct id.
        let session_id = self.alloc_session_id();
        let record = SessionRecord {
            key: key.clone(),
            entry: SessionEntry {
                decision,
                metadata: metadata.clone(),
                origin,
                install_epoch: epoch,
                last_seen_ns: now_ns,
                // #2465: stamp the creation instant once at install. Never
                // re-stamped, so the close delta reports the true session age.
                created_ns: now_ns,
                // #3152: a TCP session created by a bare SYN (SYN set, ACK
                // clear) starts OPENING (`established=false`); every other
                // first packet (non-TCP, or a TCP mid-stream pickup such as a
                // SYN-ACK or data segment) starts ESTABLISHED, preserving the
                // pre-#3152 full-established-timeout behaviour. Computed once
                // here and reused for the initial timeout selection.
                established: !(matches!(protocol, PROTO_TCP) && is_initial_syn(tcp_flags)),
                // #6752: a fresh install has seen no SYN-ACK, so nothing is pending.
                handshake_pending: false,
                // #7212: no static input-filter verdict has been derived for
                // this ENTRY yet. The forward install's own first packet was
                // adjudicated by the session-MISS path, but this constructor
                // also builds the REVERSE companion, whose ingress is
                // explicitly unobserved at install (the same reason
                // `SessionMetadata::ingress_ifindex` is `0` for it, #4983) —
                // stamping a live generation there would claim a filter had
                // judged a direction no filter has seen. Uniformly
                // `UNVALIDATED`, so the first packet of each direction derives
                // its own verdict against the interface it actually arrived on.
                filter_revalidated: FilterRevalidationStamp::UNVALIDATED,
                // #8356: UNVALIDATED at install, matching `filter_revalidated`
                // beside it. The session exists because the session-MISS path
                // just evaluated zone policy, so a live stamp would be TRUE —
                // but it would also have to be true for every caller of this
                // constructor, and the transient-local-seed origins do not all
                // carry a fresh policy verdict. `0` is the fail-closed default
                // and costs nothing measurable: a generation bump invalidates
                // every flow-cache entry, and in steady state the packet that
                // would pay for the re-derivation is served by the flow cache
                // this install populates, not by the session-hit path.
                policy_revalidated_gen: 0,
                expires_after_ns: session_timeout_ns(
                    protocol,
                    tcp_flags,
                    // #3152: OPENING half-open sessions take the short opening
                    // window; mirror the `established` seed computed above.
                    !(matches!(protocol, PROTO_TCP) && is_initial_syn(tcp_flags)),
                    &self.timeouts,
                    // #3227: per-application idle timeout override (None = global).
                    metadata.inactivity_timeout_ns,
                    // #3527: the ingress zone's `syn-flood timeout` override of
                    // the half-open window (None = global). Only consulted on
                    // the OPENING branch, so a bare-SYN session in a screened
                    // zone reaps on the operator's window.
                    self.opening_override_for(metadata.ingress_zone),
                ),
                closing: matches!(protocol, PROTO_TCP) && is_closing(tcp_flags),
                reset: matches!(protocol, PROTO_TCP) && has_rst(tcp_flags),
                // #7342: a fresh install has seen exactly one packet, so at most
                // one direction can have FINed and the companion's is unknown.
                // A session installed BY a closing packet is therefore CLOSING,
                // never TIME_WAIT — which is also the window it reaped on before
                // the state existed.
                fin_own: matches!(protocol, PROTO_TCP) && has_fin(tcp_flags),
                fin_peer: false,
                wheel_tick: 0,
                // #2120: a freshly-installed entry has never been HELD and
                // has not yet been self-healed. 0 is the never-self-healed
                // default; the first forwarding pass after any RG activation
                // that bumped the epoch will see current_epoch != 0 and fire
                // the self-heal (see session/expire.rs). The HOLD branch
                // does NOT write seen_rg_epoch, so it stays 0 throughout the
                // held lifetime — exactly what keeps the self-heal edge
                // intact under the old-map/new-epoch read skew.
                seen_rg_epoch: 0,
                first_held_ns: 0,
                // #2501: a fresh entry has forwarded no packets yet.
                counters: SessionCounters::default(),
                // #2749: seed the cumulative TCP control bits with the trigger
                // packet's flags (typically the SYN) so even a flow that closes
                // before any further forward packet is accounted reports a
                // non-empty tcpControlBits. The forward ToS is unknown until the
                // first packet is accounted on its forwarding pass.
                observed_tos: 0,
                observed_tcp_flags: tcp_flags,
                // #4915: the stable id allocated above, write-once for the life
                // of the entry.
                session_id,
            },
        };
        // #6297: route every slab insert through `insert_record` so the
        // live-extent high-watermark (the budgeted refresh walk's bound) is
        // advanced to cover this new slot.
        let raw = self.insert_record(record);
        let handle: u32 = raw.try_into().expect("slab handle exceeds u32");
        self.key_to_handle.insert(key.clone(), handle);
        self.index_forward_nat_key(&key, handle, decision, &metadata);
        // #965: schedule the new entry for expiration check.
        self.push_to_wheel(&key, now_ns);
        // #3122: SEPARATE the per-IP COUNT gate from the HA Open-delta
        // gate. The count must follow the session's PRESENCE in the table
        // regardless of origin (a forward, non-seed session consumes a
        // per-IP slot whether it was locally admitted or imported from the
        // HA peer) — otherwise a peer-synced session is invisible to the
        // limit and a client can exceed its cap after failover (#3122
        // limit bypass). The Open delta, by contrast, must NOT re-emit for
        // a peer-synced session (that would echo the peer's own session
        // back to it — a sync loop), so it keeps the `!is_peer_synced()`
        // gate. The two were one condition before #3122; they are now two.
        let counted = !metadata.is_reverse && !origin.is_transient_local_seed();
        if counted {
            // #2134/#3122: fresh-install count choke point. Capture the
            // Copy IPs before `key` is moved into the delta below. The
            // function returned `false` early at `len() >= max_sessions`
            // before any state change, so this only runs on a real
            // install.
            self.session_limit_inc(key.src_ip, key.dst_ip);
        }
        if counted && !origin.is_peer_synced() {
            self.push_delta(SessionDelta {
                kind: SessionDeltaKind::Open,
                key,
                decision,
                metadata,
                origin,
                fabric_redirect_sync: false,
                // #2465: an Open delta carries the install instant. The
                // SESSION_CREATE RT_FLOW frame does not report a duration, so
                // these are informational here, but keeping them consistent
                // with the entry avoids a 0/unknown asymmetry.
                created_ns: now_ns,
                last_seen_ns: now_ns,
                // #2501: a freshly-installed session has forwarded no
                // packets yet (the trigger packet is accounted on its own
                // forwarding pass).
                counters: SessionCounters::default(),
                // #2749: mirror the entry's seed flags on the Open delta
                // (informational — Open deltas have no flowexport consumer).
                observed_tos: 0,
                observed_tcp_flags: tcp_flags,
                // #4915: the stable session id assigned above, so the
                // SESSION_CREATE RT_FLOW frame carries the id its eventual
                // SESSION_CLOSE will.
                session_id,
                bulk_resync: false,
                // #9412: a session installed BY a closing packet is already closing.
                tcp_close_class: if matches!(protocol, PROTO_TCP) && is_closing(tcp_flags) {
                    TcpCloseClass::from_packet(tcp_flags).to_wire()
                } else {
                    0
                },
            });
        }
        true
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub fn upsert_synced(
        &mut self,
        key: SessionKey,
        decision: SessionDecision,
        metadata: SessionMetadata,
        now_ns: u64,
        protocol: u8,
        tcp_flags: u8,
        allow_replace_local: bool,
    ) -> bool {
        self.upsert_synced_with_origin(
            SessionInstall {
                key,
                decision,
                metadata,
                origin: SessionOrigin::SyncImport,
                now_ns,
                protocol,
                tcp_flags,
                // #5212: this legacy convenience wrapper carries no wire id, so
                // the receiver allocs a fresh node-local one (the real HA path
                // threads the peer's id via `handle_upsert_synced`).
                session_id: 0,
                // #9412: nor a close class; the real HA path threads it the same way.
                tcp_close_class: 0,
            },
            allow_replace_local,
        )
    }

    #[inline]
    pub fn upsert_synced_with_origin(
        &mut self,
        req: SessionInstall,
        allow_replace_local: bool,
    ) -> bool {
        let SessionInstall {
            key,
            decision,
            metadata,
            origin,
            now_ns,
            protocol,
            tcp_flags,
            session_id: wire_session_id,
            tcp_close_class: wire_close_class,
        } = req;
        // #9412: the close class the owning node stated. `None` (0, or a class
        // this build does not know) imports exactly as before.
        let wire_close = if matches!(protocol, PROTO_TCP) {
            TcpCloseClass::from_wire(wire_close_class)
        } else {
            None
        };
        // Reject peer data that would clobber a locally-owned session
        // unless explicitly allowed (e.g. during HA activation).
        if matches!(self.entry_by_key(&key), Some(existing) if !existing.origin.is_peer_synced())
            && !allow_replace_local
        {
            return false;
        }
        // Same guard semantics as install_with_protocol_with_origin:
        // remove_entry has 3 debug_assert!s (stale-handle,
        // primary-key, no_index_points_at) that catch invariant
        // violations in tests. The first two restore the prior
        // key_to_handle mapping internally before returning None.
        let _previous = self.remove_entry(&key);
        let epoch = self.next_epoch();
        // #5212 (completes the #4915 follow-up): ADOPT the originating node's
        // session id when it rides the HA session-sync wire, so a session that
        // opens on the primary and closes on the standby after a failover
        // carries the SAME RT_FLOW id on both nodes (cross-node log/event
        // correlation). The id is a metadata-only stamp (RT_FLOW correlation +
        // the show-session mirror id) — NEVER a lookup key or slab handle — so
        // adopting it verbatim cannot affect forwarding/security/memory. Since
        // #6311 it is also globally COLLISION-FREE: the namespace is
        // `node_bit<<15 | worker_id` in the high 16 bits
        // (`set_session_id_namespace`), so an adopted id carries the ORIGINATING
        // node's bit and can never equal an id this node mints. That is exactly
        // why `next_session_id` is deliberately NOT reconciled against an
        // adopted id here — the two live in disjoint namespaces, so a later
        // local alloc cannot re-hand-out an adopted value. Before the node bit,
        // both nodes ran the same worker set with counters that both start at 1,
        // so an adopted `(w<<48)|c` collided with the importing node's own
        // worker-`w` id — guaranteed in active/active early after boot.
        //
        // A peer that predates the node bit (mixed-base) mints ids in the
        // un-bitted low half, which is the pre-#6311 posture: no NEW collision,
        // just the old one until both nodes are upgraded. A zero wire id (a
        // legacy peer that predates the field, or a locally-generated upsert
        // such as a tunnel replica) falls back to a FRESH node-local id via
        // `alloc_session_id()` — the pre-#5212 behavior (rolling-upgrade safe).
        // 0 is never a real id (the allocator starts its counter at 1), so the
        // sentinel is unambiguous.
        let session_id = if wire_session_id != 0 {
            wire_session_id
        } else {
            self.alloc_session_id()
        };
        let record = SessionRecord {
            key: key.clone(),
            entry: SessionEntry {
                decision,
                metadata: metadata.clone(),
                origin,
                install_epoch: epoch,
                last_seen_ns: now_ns,
                // #2465: a re-imported synced entry stamps its creation instant
                // to the import time. The peer's original creation time is not
                // carried on the HA session-sync delta, so this best-effort
                // stamp is the local re-import time; the local close that
                // follows reports age from here.
                created_ns: now_ns,
                // #3152: a peer-synced entry is imported as ESTABLISHED, NOT
                // re-derived as OPENING from the carried `tcp_flags`. The
                // short opening window is a FORWARDING-NODE protection against
                // a locally-received bare-SYN flood; the standby never
                // receives that flood directly (it receives synced sessions),
                // so it must not apply the short window.
                //
                // #9412 CORRECTION. This comment used to continue "Crucially, the
                // synced `tcp_flags` are the install-time flags (the opening SYN
                // for a SYN-created flow) and are not guaranteed to be
                // re-published as the primary's handshake completes". That reads
                // as though the sync path carries real flags that #3152 chooses
                // not to trust, and it is what sent an external review down the
                // "the import re-derives close-state from the carried
                // `tcp_flags`" path. It does not. The production import
                // constructor hardcodes `tcp_flags: 0`
                // (`server/helpers/session_sync.rs`), so on a peer-synced entry
                // there is nothing to derive FROM: the `closing`, `reset` and
                // `fin_own` bits derived from `tcp_flags` below are ALWAYS false.
                // Before #9412 that meant a session closing on the primary
                // imported as open and reaped on the ESTABLISHED window (300 s).
                // #9412 carries close state on its OWN wire field,
                // `tcp_close_class`, which is applied below. It never rides
                // `tcp_flags`, and `tcp_flags_zero_on_sync_path_9412_tests.rs`
                // pins the hard zero so that stays true.
                //
                // #3152's CONCLUSION is unaffected and its reasoning still
                // stands on its own: were the flags ever carried, deriving
                // OPENING from them could misclassify a LIVE established flow on
                // the standby and reap its synced copy at the short stale-synced
                // ceiling (`STALE_SYNCED_CEILING_MULT × opening`), breaking failover
                // for any flow older than that ceiling. Importing as
                // ESTABLISHED preserves the exact pre-#3152 standby behaviour
                // (full established timeout + #2120 standby retention). The
                // half-open table-exhaustion mitigation still holds end to end:
                // the primary (the flood target) reaps its half-opens at
                // `tcp_opening_ns` and emits a Close delta (session/expire.rs)
                // that propagates to the standby, so the standby copy is
                // removed promptly without needing its own OPENING window. The
                // `established` field is node-local and never crosses the HA
                // wire, so this is a pure import-side decision (no wire change).
                established: true,
                // #6752: a mid-stream pickup is seeded ESTABLISHED with no handshake
                // to wait for — pending must stay false or it would be held on the
                // opening window forever.
                handshake_pending: false,
                // #7212: a peer-synced import carries NO locally-derived
                // input-filter verdict — the peer adjudicated it against the
                // peer's own interfaces. `UNVALIDATED` makes the first packet
                // this node forwards on the session re-derive the verdict
                // against THIS node's filter state. That is the failover fence:
                // a standby still holding a pre-commit view cannot cold-serve a
                // flow the primary revoked, because the promoted copy
                // revalidates before it forwards.
                filter_revalidated: FilterRevalidationStamp::UNVALIDATED,
                // #8356: the peer adjudicated this flow against the PEER's
                // zone policy. `0` makes the first packet this node forwards
                // re-derive against THIS node's policy — the same failover fence
                // `filter_revalidated` gets, for the verdict #7323 accepted as a
                // residual and this issue closes.
                policy_revalidated_gen: 0,
                // #9412: a peer-stated close class puts the copy on its close
                // window, through the same formula the owning node used. Without
                // one, it imports ESTABLISHED exactly as before (#3152).
                expires_after_ns: match wire_close {
                    Some(class) => tcp_close_window_ns(class, &self.timeouts),
                    None => session_timeout_ns(
                        protocol,
                        tcp_flags,
                        // #3152: imported ESTABLISHED (see above).
                        true,
                        &self.timeouts,
                        // #3227: per-application idle timeout override (None = global).
                        metadata.inactivity_timeout_ns,
                        // #3527: a peer-synced session is imported ESTABLISHED, so
                        // the OPENING branch is never taken and the per-zone
                        // half-open override is irrelevant here. Passing `None`
                        // (rather than re-deriving from this node's config) makes
                        // explicit that the override never crosses the HA wire — it
                        // is re-derived per node and only governs locally-received
                        // bare-SYN floods (§11.1 of the #3315 plan).
                        None,
                    ),
                },
                closing: wire_close.is_some() || (matches!(protocol, PROTO_TCP) && is_closing(tcp_flags)),
                reset: matches!(wire_close, Some(TcpCloseClass::Reset))
                    || (matches!(protocol, PROTO_TCP) && has_rst(tcp_flags)),
                // #7342: a fresh install has seen exactly one packet, so at most
                // one direction can have FINed and the companion's is unknown.
                // A session installed BY a closing packet is therefore CLOSING,
                // never TIME_WAIT — which is also the window it reaped on before
                // the state existed.
                //
                // #9412: TIME_WAIT is a statement about BOTH directions, so a
                // peer-stated TIME_WAIT sets both FIN bits. CLOSING sets NEITHER:
                // the wire does not say which direction FINed, and guessing would
                // misclassify the other side's later FIN. `tcp_close_class` still
                // reads CLOSING, because `closing` is set and neither `reset` nor
                // both FIN bits are.
                fin_own: matches!(wire_close, Some(TcpCloseClass::TimeWait))
                    || (matches!(protocol, PROTO_TCP) && has_fin(tcp_flags)),
                fin_peer: matches!(wire_close, Some(TcpCloseClass::TimeWait)),
                wheel_tick: 0,
                // #2120: a re-imported synced entry leaves the held world
                // with a fresh `last_seen_ns`, so it carries no carried-over
                // hold clock. `seen_rg_epoch` resets to the never-self-healed
                // default (the next SELF-HEAL pass, if this node forwards the
                // RG, records the live epoch; HOLD never writes it).
                // `upsert_synced` first `remove_entry`s any prior entry, so
                // this is the canonical re-import refresh that the §6.4
                // contract clears `first_held_ns` on.
                seen_rg_epoch: 0,
                first_held_ns: 0,
                // #2501: a fresh entry has forwarded no packets yet.
                counters: SessionCounters::default(),
                // #2749: a re-imported synced entry observes its own ToS / TCP
                // flags once local traffic forwards through it (the peer's
                // observed values are not carried on the HA session-sync delta).
                // Seed with the trigger flags, ToS unknown until first forward.
                observed_tos: 0,
                observed_tcp_flags: tcp_flags,
                // #4915: fresh node-local id allocated above.
                session_id,
            },
        };
        // #6297: route every slab insert through `insert_record` so the
        // live-extent high-watermark (the budgeted refresh walk's bound) is
        // advanced to cover this new slot.
        let raw = self.insert_record(record);
        let handle: u32 = raw.try_into().expect("slab handle exceeds u32");
        let index_key = key.clone();
        self.key_to_handle.insert(key, handle);
        self.index_forward_nat_key(&index_key, handle, decision, &metadata);
        // #965: schedule the synced entry for expiration check.
        self.push_to_wheel(&index_key, now_ns);
        // #3122: a peer-synced session counts toward the per-IP limit the
        // moment it is imported — it occupies a real slot on this node and
        // will be in the table when this node becomes active. Same
        // PRESENCE-based counted-class gate as the fresh-install path
        // (forward, non-seed), but ORIGIN-agnostic (a SyncImport is never
        // a seed; only the reverse direction is excluded so a session is
        // counted once on its forward key). The matching decrement fires
        // in `remove_entry` (now origin-agnostic too). Because failover
        // promotes a synced entry IN PLACE (`update_session`, no
        // remove+reinstall) and the promote site no longer re-increments,
        // there is no double-count across import -> promote.
        if !metadata.is_reverse && !origin.is_transient_local_seed() {
            self.session_limit_inc(index_key.src_ip, index_key.dst_ip);
        }
        true
    }

    pub fn emit_open_delta_with_origin(
        &mut self,
        key: SessionKey,
        decision: SessionDecision,
        metadata: SessionMetadata,
        origin: SessionOrigin,
        fabric_redirect_sync: bool,
    ) {
        if metadata.is_reverse {
            return;
        }
        // #5212: this is the owner-RG bulk/cold-sync export path (a live local
        // session re-announced as an Open delta so a freshly-connected or
        // failed-back peer picks it up). Unlike the #2465 timestamps/counters,
        // the STABLE session id IS recoverable — the entry is still live in this
        // table — so look it up by key and carry it on the wire, letting the
        // peer adopt the same id it will emit its own RT_FLOW records under
        // (`session_id_for` returns 0 if the key is somehow absent, the safe
        // fallback-to-local-alloc sentinel). BOTH legs of this owner-RG export
        // carry the id since #6312: the binary event-stream frame's trailing u64
        // (`encode_session_open`) and the JSON `SessionDeltaInfo`
        // (`rt_flow_session_id`, populated by `afxdp::session_delta_info`).
        let session_id = self.session_id_for(&key);
        // #9412: the live entry's close class, so this re-export also restores a
        // close-state Update the incremental stream dropped.
        let tcp_close_class = self.close_class_wire_for(&key);
        self.push_delta(SessionDelta {
            tcp_close_class,
            kind: SessionDeltaKind::Open,
            key,
            decision,
            metadata,
            origin,
            fabric_redirect_sync,
            // #2465: an explicit Open-delta emit (no entry in hand). The
            // SESSION_CREATE frame reports no duration, so 0/unknown is fine.
            created_ns: 0,
            last_seen_ns: 0,
            // #2501: an open carries no volume yet.
            counters: SessionCounters::default(),
            // #2749: explicit Open-delta emit, no entry in hand.
            observed_tos: 0,
            observed_tcp_flags: 0,
            // #5212: the stable id of the exported entry (0 if absent), so the
            // peer adopts it rather than minting a fresh node-local id.
            session_id,
            // #8593: the ONLY producer of bulk-export deltas. Its sole production
            // caller is the worker loop's chunked owner-RG export
            // (`chunked_drain_as_you_export!`); the other caller is a
            // `#[cfg(test)]` fixture. A drop of one of these must not arm the
            // loss-of-sync latch that TRIGGERS that export.
            bulk_resync: true,
        });
    }

    pub fn emit_close_delta_with_origin(
        &mut self,
        key: SessionKey,
        decision: SessionDecision,
        metadata: SessionMetadata,
        origin: SessionOrigin,
    ) {
        if metadata.is_reverse {
            return;
        }
        // #2465: this explicit-close API (clear-session / NAT-remap delete
        // glue) does not carry the originating entry's creation instant — the
        // caller has typically already removed the entry. Emit 0/unknown so the
        // exporter falls back to the packet-count estimate. The dominant close
        // path (idle/age expiry in session/expire.rs) carries real timestamps.
        self.push_delta(SessionDelta {
            kind: SessionDeltaKind::Close,
            key,
            decision,
            metadata,
            origin,
            fabric_redirect_sync: false,
            created_ns: 0,
            last_seen_ns: 0,
            // #2501: the entry was already removed by the explicit-close
            // caller, so its counters are no longer in hand — emit 0 (the
            // same fallback as the timestamps above). The dominant close
            // path (idle/age expiry) harvests the real counters.
            counters: SessionCounters::default(),
            // #2749: the entry was already removed by the explicit-close
            // caller, so its observed ToS / TCP flags are no longer in hand —
            // emit 0 (the dominant idle/age close path harvests the real
            // values off the expiring entry).
            observed_tos: 0,
            observed_tcp_flags: 0,
            // #4915: the entry was already removed by the explicit-close caller,
            // so its stable id is no longer in hand — 0 keeps the "unknown"
            // sentinel. The dominant idle/age close path (session/expire.rs)
            // carries the real id off the expiring entry.
            session_id: 0,
            bulk_resync: false,
            tcp_close_class: 0,
        });
    }

    pub fn delete(&mut self, key: &SessionKey) {
        self.remove_entry(key);
    }

    pub fn demote_owner_rg(&mut self, owner_rg_id: i32) -> Vec<crate::session::SessionKey> {
        if owner_rg_id <= 0 {
            return Vec::new();
        }
        let mut demoted_keys = Vec::new();
        for key in self.owner_rg_session_keys(&[owner_rg_id]) {
            let Some(entry) = self.entry_by_key_mut(&key) else {
                continue;
            };
            // #3122: an in-place demote local→synced is now (almost)
            // COUNT-NEUTRAL. Before #3122 the per-IP count tracked LOCAL
            // ownership, so a demote un-counted the session; now it tracks
            // table PRESENCE (local AND synced count alike), and a demoted
            // session is still present, so its slot must remain charged.
            // The matching decrement fires once, later, in `remove_entry`.
            //
            // The ONE exception is a transient seed (`MissingNeighborSeed`):
            // it is uncounted while a seed (presence predicate excludes
            // seeds) but the flip turns it into a `SyncImport` (a counted
            // forward session). Snapshot the pre-flip counted-class, flip,
            // then increment iff the flip ADDED the entry to the counted
            // class — otherwise the later `remove_entry` decrement would
            // underflow this IP (or wrongly debit another session's slot).
            // A normal local entry's counted-class is unchanged by the flip
            // (count-neutral); a reverse entry is uncounted before and
            // after.
            let old_origin = entry.origin;
            let is_reverse = entry.metadata.is_reverse;
            let will_flip = !old_origin.is_peer_synced();
            if will_flip {
                entry.origin = SessionOrigin::SyncImport;
            }
            // Borrow on `entry` ends here so the &mut self count helper can
            // run. `SyncImport` is never a transient seed, so the post-flip
            // counted-class is simply `!is_reverse`.
            let old_counted = !is_reverse && !old_origin.is_transient_local_seed();
            let new_counted = will_flip && !is_reverse;
            if new_counted && !old_counted {
                self.session_limit_inc(key.src_ip, key.dst_ip);
            }
            demoted_keys.push(key);
        }
        demoted_keys
    }
}
