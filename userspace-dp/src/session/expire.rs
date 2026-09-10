// Timer-wheel sweeps + eviction (#2005 pure code-motion split of
// session/mod.rs). The bucketed-wheel GC (#965) machinery — wheel
// cursor initialization, the throttled per-entry wheel scheduling, and
// the per-tick bucket drain / lazy-delete expiry pass — lives here.
// Bodies are byte-for-byte identical to the prior in-`mod.rs` form;
// `push_to_wheel` was widened from a module-private `fn` to
// `pub(in crate::session)` because the in-place-refresh contract that
// stays in `mod.rs` (and the install/lookup submodules) call it across
// the submodule boundary into `expire`.
// The `SessionWheel` machinery itself remains in
// `wheel.rs`; this file holds the `SessionTable` methods that drive it.

use super::wheel::{WHEEL_TICK_NS, WheelEntry, bucket_for_tick, target_tick_for};
use super::*;

impl SessionTable {
    /// #965: stats from the most-recent `expire_stale_entries` call.
    /// Used by tests to validate K-bounds and entry classification.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn last_pop_stats(&self) -> WheelPopStats {
        self.last_pop_stats
    }

    /// #965: lazily initialize the wheel cursor to the first observed
    /// `now_ns`. SessionTable::new() does not have a `now_ns`, so we
    /// must initialize on the first call to any method that takes one.
    /// Without this, `now_tick = now_ns / TICK_NS` can be billions
    /// (monotonic time) and the pop loop would walk billions of empty
    /// buckets on the first GC.
    #[inline]
    fn wheel_observe(&mut self, now_ns: u64) {
        if !self.wheel.initialized {
            self.wheel.cursor_tick = now_ns / WHEEL_TICK_NS;
            self.wheel.initialized = true;
        }
    }

    /// #965: schedule (or re-schedule) `key` for an expiration check
    /// at the tick implied by its `last_seen_ns + expires_after_ns`.
    /// Throttled: only pushes when the canonical wheel tick changes,
    /// so per-second touches within the same tick produce zero new
    /// wheel entries.
    ///
    /// MUST be called only AFTER `last_seen_ns` / `expires_after_ns`
    /// have been written and the `&mut` borrow on `self.entries` has
    /// dropped — otherwise the borrow checker will reject the
    /// `self.wheel.buckets[bucket].push_back(...)` line because it
    /// aliases `self` through both `self.entries` and `self.wheel`.
    #[inline]
    pub(in crate::session) fn push_to_wheel(&mut self, key: &SessionKey, now_ns: u64) {
        self.wheel_observe(now_ns);
        let new_tick = match self.entry_by_key_mut(key) {
            Some(entry) => {
                let nt = target_tick_for(
                    now_ns,
                    entry.last_seen_ns.saturating_add(entry.expires_after_ns),
                );
                if nt != entry.wheel_tick {
                    entry.wheel_tick = nt;
                    Some(nt)
                } else {
                    None
                }
            }
            None => return,
        };
        if let Some(tick) = new_tick {
            let bucket = bucket_for_tick(tick);
            self.wheel.buckets[bucket].push_back(WheelEntry {
                key: key.clone(),
                scheduled_tick: tick,
            });
        }
    }

    /// #965: GC pass over the timer wheel.
    ///
    /// Replaces the prior O(N) scan over all sessions with a wheel
    /// pop. For each tick that has elapsed since the last call (up to
    /// `now_ns / WHEEL_TICK_NS`), drain the bucket at the current
    /// cursor and process its entries via the lazy-delete discriminator:
    ///
    ///   1. Entry gone (HashMap miss) → drop.
    ///   2. Stale duplicate (`wheel_tick != scheduled_tick`) → drop.
    ///   3. Expired (`now > last_seen + expires_after`) → remove,
    ///      emit delta + ExpiredSession.
    ///   4. Still alive → re-bucket at the new absolute target tick.
    ///
    /// See docs/pr/965-session-gc-timer-wheel/plan.md for the full
    /// algorithm and complexity analysis.
    pub fn expire_stale_entries(&mut self, now_ns: u64) -> Vec<ExpiredSession> {
        self.expire_stale_entries_ha(now_ns, None)
    }

    /// #2120: HA-aware expiry pass. The standby must NOT age peer-synced
    /// sessions for an RG it does not currently forward — otherwise it
    /// silently reaps long-lived flows and breaks them on failover (#131
    /// reintroduced by the eBPF→userspace migration that moved expiry
    /// into this Rust wheel with no standby gate).
    ///
    /// When `ha` is `Some`, the Case-3 (idle-crossed) arm makes a
    /// three-way SELF-HEAL / HOLD / AGE decision before `remove_entry`:
    ///
    /// 1. **SELF-HEAL** (edge): the entry is peer-synced, this node now
    ///    FORWARDS its RG, but the entry's recorded epoch predates the
    ///    activation (`RefreshOwnerRGS` may not have landed yet) — fires
    ///    once, re-stamps `last_seen_ns`, re-buckets, records the new
    ///    epoch. `first_held_ns` is left UNTOUCHED so a flapping RG
    ///    cannot reset the leak ceiling.
    /// 2. **HOLD**: this node does NOT forward the session (standby /
    ///    demotion window) and it is peer-synced or this node forwards
    ///    something (`peer_synced || node_active`, the "in a cluster"
    ///    guard that excludes standalone). Held unless it has been held
    ///    past the stale-synced ceiling, in which case it is reaped
    ///    (bounded lost-delete leak).
    /// 3. **AGE**: normal `remove_entry` (active-node-owned, or
    ///    standalone, or ceiling-exceeded held entry).
    ///
    /// When `ha` is `None` (standalone / tests), behavior is identical to
    /// the pre-#2120 unconditional wheel: every idle-crossed entry ages.
    pub fn expire_stale_entries_ha(
        &mut self,
        now_ns: u64,
        ha: Option<&ExpireHaContext<'_>>,
    ) -> Vec<ExpiredSession> {
        // Reset per-call stats BEFORE the gc-interval gate so that a
        // gated no-op call returns zeroed stats rather than leftovers
        // from a prior call (Codex impl-review round-2 non-blocking note).
        self.last_pop_stats = WheelPopStats::default();
        if self.last_gc_ns != 0 && now_ns.saturating_sub(self.last_gc_ns) < SESSION_GC_INTERVAL_NS {
            return Vec::new();
        }
        self.last_gc_ns = now_ns;

        // #7699: age out PPTP call associations in the same sweep the sessions
        // use, because the hazard they carry is on the same clock.
        //
        // The association must expire whether or not a Call-Disconnect-Notify
        // ever arrives: a lost notify, a restarted peer or a control channel
        // torn down mid-call otherwise leaves an association that re-pairs a
        // REUSED 16-bit call id onto a dead handle. That is a MIS-ATTRIBUTION —
        // call B's traffic resolving to call A's session — not a memory leak.
        //
        // PLACEMENT IS LOAD-BEARING and it was wrong when this landed: this sat
        // ABOVE the gc-interval gate, so it ran on EVERY call rather than once
        // per interval. `expire_stale_entries_ha` is called from the worker poll
        // loop and the gate is what makes it periodic — above it, this scanned
        // the whole association map at poll frequency, which is precisely the
        // per-poll work this tree exists to avoid. Below the gate it runs once
        // per `SESSION_GC_INTERVAL_NS` like the session expiry it rides on.
        self.pptp
            .expire_idle(now_ns, crate::session::pptp::ASSOCIATION_IDLE_TIMEOUT_NS);

        self.wheel_observe(now_ns);
        let now_tick = now_ns / WHEEL_TICK_NS;
        let mut expired_entries: Vec<ExpiredSession> = Vec::new();
        while self.wheel.cursor_tick < now_tick {
            let bucket_idx = bucket_for_tick(self.wheel.cursor_tick);
            // Drain the bucket allocation-free: snapshot the length
            // before iterating, then `pop_front` exactly that many
            // times. Re-pushes targeting THIS bucket land at the back
            // of the VecDeque and are not popped during this BUCKET
            // drain (re-pushes into LATER buckets the outer loop
            // visits will be popped within the same call — by design).
            let due_count = self.wheel.buckets[bucket_idx].len();
            for _ in 0..due_count {
                let WheelEntry {
                    key,
                    scheduled_tick,
                } = self.wheel.buckets[bucket_idx]
                    .pop_front()
                    .expect("len snapshot bounds the iteration");
                self.last_pop_stats.scanned += 1;
                // Case 1: entry already removed elsewhere — drop hint.
                let Some(entry) = self.entry_by_key(&key) else {
                    self.last_pop_stats.dropped_gone += 1;
                    continue;
                };
                // Case 2: stale duplicate — entry's canonical wheel_tick
                // has advanced past this scheduled_tick, so the new tick
                // already has its own wheel entry. Drop.
                if entry.wheel_tick != scheduled_tick {
                    self.last_pop_stats.dropped_stale += 1;
                    continue;
                }
                // Case 3 vs 4: canonical entry. Match today's strict `>`
                // expiration semantics.
                if now_ns.saturating_sub(entry.last_seen_ns) > entry.expires_after_ns {
                    // #2120: the standby retention gate. Decide SELF-HEAL /
                    // HOLD / AGE before remove_entry. Snapshot the Copy
                    // fields we need so the immutable `entry` borrow can be
                    // dropped before any `&mut self` mutation below.
                    let e_origin = entry.origin;
                    let e_owner_rg = entry.metadata.owner_rg_id;
                    let e_is_reverse = entry.metadata.is_reverse;
                    let e_fabric_ingress = entry.metadata.fabric_ingress;
                    let e_last_seen_ns = entry.last_seen_ns;
                    let e_expires_after_ns = entry.expires_after_ns;
                    let e_first_held_ns = entry.first_held_ns;
                    let e_seen_rg_epoch = entry.seen_rg_epoch;
                    // #4380: the entry's OWN nat decision recovers its
                    // forward↔reverse companion key (`reverse_session_key`,
                    // its own inverse) for the idle-companion retention check
                    // just below. Snapshot it (Copy) before the immutable
                    // `entry` borrow is dropped.
                    let e_nat = entry.decision.nat;
                    // #4380: the companion idle-retention probe applies ONLY to
                    // the owner-side idle-expiry path — the `Age` HA decision or
                    // the `ha == None` standalone path (both start eligible). The
                    // two DELIBERATE-reap HA arms below (ReapStaleSynced,
                    // AgedOwnerRgZeroActiveNode) clear this: they are bounded
                    // reaps (the stale-synced lost-primary-delete leak ceiling,
                    // and the known active/active owner_rg<=0 residual) whose
                    // stats are ALSO already bumped in-arm, so letting the probe
                    // keep the entry there would both override the ceiling and
                    // miscount. On the standby the HOLD arm already retains BOTH
                    // halves (it `continue`s before this point), so the probe is
                    // redundant there regardless.
                    let mut companion_eligible = true;
                    if let Some(ha) = ha {
                        match self.standby_gate_decision(
                            ha,
                            now_ns,
                            e_origin,
                            e_owner_rg,
                            e_is_reverse,
                            e_fabric_ingress,
                            e_last_seen_ns,
                            e_expires_after_ns,
                            e_first_held_ns,
                            e_seen_rg_epoch,
                        ) {
                            StandbyGateDecision::SelfHeal { new_epoch } => {
                                // Re-stamp last_seen so the entry ages from a
                                // full timeout now that this node forwards it,
                                // record the new epoch (edge consumed), and
                                // re-bucket. first_held_ns is deliberately NOT
                                // cleared here — only a genuine departure from
                                // the held world (real-traffic / promotion
                                // refresh, re-import) clears it, so a flapping
                                // RG cannot reset the ceiling.
                                //
                                // The entry was just read by key immediately
                                // above (Case 3) with no intervening mutation,
                                // so the matching mutable lookup is a hard
                                // invariant — `expect` (matching the Case-4 /
                                // AGE arm) so an invariant violation surfaces
                                // loudly instead of silently skipping the
                                // re-stamp and leaving the entry mis-counted.
                                let em = self
                                    .entry_by_key_mut(&key)
                                    .expect("SELF-HEAL: entry was just read via entry_by_key in Case 3; no concurrent mutation");
                                em.last_seen_ns = now_ns;
                                em.seen_rg_epoch = new_epoch;
                                self.last_pop_stats.healed_on_promote += 1;
                                self.rebucket_alive_entry(&key, now_ns);
                                continue;
                            }
                            StandbyGateDecision::Hold => {
                                // Same hard invariant as the SELF-HEAL /
                                // Case-4 arms: the entry was just read by key
                                // in Case 3 with no intervening mutation, so
                                // `expect` (not `if let Some`) makes an
                                // invariant break loud instead of silently
                                // skipping the hold-clock stamp and the
                                // re-bucket.
                                let em = self
                                    .entry_by_key_mut(&key)
                                    .expect("HOLD: entry was just read via entry_by_key in Case 3; no concurrent mutation");
                                if em.first_held_ns == 0 {
                                    em.first_held_ns = now_ns;
                                }
                                // #2120 (Codex MAJOR): do NOT stamp
                                // seen_rg_epoch here. The worker reads the
                                // HA map (loop_body:491) and the rg_epochs
                                // counter (epoch_of) separately, so a HOLD
                                // can observe an OLD map (forwards_here =
                                // false) together with a NEW (already
                                // bumped) epoch. Stamping that new epoch
                                // would make the NEXT pass — which sees the
                                // new ACTIVE map — find current_epoch ==
                                // seen_rg_epoch and SKIP the self-heal,
                                // aging the very synced session this gate
                                // exists to preserve. Leaving seen_rg_epoch
                                // at its install/refresh value guarantees
                                // the first forwarding pass after ANY
                                // activation that bumped the epoch fires the
                                // self-heal (current != seen); the self-heal
                                // arm then records the epoch so it does not
                                // re-fire perpetually.
                                self.last_pop_stats.held_standby += 1;
                                self.rebucket_alive_entry(&key, now_ns);
                                continue;
                            }
                            StandbyGateDecision::ReapStaleSynced => {
                                self.last_pop_stats.reaped_stale_synced += 1;
                                // #4380: a deliberate bounded reap (leak
                                // ceiling) — the companion probe must NOT keep
                                // this entry alive past the ceiling.
                                companion_eligible = false;
                                // fall through to remove_entry below
                            }
                            StandbyGateDecision::AgedOwnerRgZeroActiveNode => {
                                self.last_pop_stats.aged_owner_rg_zero_active_node += 1;
                                // #4380: a deliberate reap of the known
                                // active/active owner_rg<=0 residual — the
                                // companion probe must NOT override it.
                                companion_eligible = false;
                                // fall through to remove_entry below
                            }
                            StandbyGateDecision::Age => {
                                // fall through to remove_entry below
                            }
                        }
                    }
                    // #4380: Junos single-session idle semantics. Forward and
                    // reverse are two independent entries that age
                    // independently — the read path re-stamps `last_seen_ns`
                    // only on the ONE entry a packet's wire tuple resolves
                    // (touch/touch_if_stale/lookup), and `account_packet` folds
                    // both directions' COUNTERS onto the forward entry without
                    // touching either `last_seen_ns`. So a flow active on only
                    // one direction (a one-way UDP feed, or a download whose
                    // forward ACKs have gone quiet) would reap its quiet half
                    // mid-flow — leaving a half-open session and, under NAT, a
                    // later packet re-creating a session with a DIFFERENT
                    // translation while the surviving half still maps the old
                    // one. Before reaping this idle-crossed half, probe its
                    // companion: if the companion is itself still within its
                    // idle window (the whole flow is active), re-stamp THIS
                    // half from the companion and keep both alive, so the HA
                    // Close delta + RT_FLOW harvest fire only when the WHOLE
                    // flow goes idle. Off the hot path: one extra
                    // `key_to_handle` probe per idle-crossed entry, in the GC
                    // pass only. Gated to the owner-side Age / no-HA path
                    // (`companion_eligible`): the deliberate stale-synced /
                    // aged-owner reaps do not consult it.
                    if companion_eligible && self.companion_keeps_alive(&key, e_nat, now_ns) {
                        self.last_pop_stats.kept_alive_by_companion += 1;
                        continue;
                    }
                    if let Some(removed) = self.remove_entry(&key) {
                        self.last_pop_stats.expired += 1;
                        let decision = removed.decision;
                        let metadata = removed.metadata;
                        if key.protocol == PROTO_TCP {
                            debug_log!(
                                "SESS_EXPIRE: proto=TCP {}:{} -> {}:{} closing={} age_ns={} timeout_ns={} rev={} origin={} nat=({:?},{:?})",
                                key.src_ip,
                                key.src_port,
                                key.dst_ip,
                                key.dst_port,
                                removed.closing,
                                now_ns.saturating_sub(removed.last_seen_ns),
                                removed.expires_after_ns,
                                metadata.is_reverse,
                                removed.origin.as_str(),
                                decision.nat.rewrite_src,
                                decision.nat.rewrite_dst,
                            );
                        }
                        if !metadata.is_reverse
                            && !removed.origin.is_peer_synced()
                            && !removed.origin.is_transient_local_seed()
                        {
                            self.push_delta(SessionDelta {
                                kind: SessionDeltaKind::Close,
                                key: key.clone(),
                                decision,
                                metadata: metadata.clone(),
                                origin: removed.origin,
                                fabric_redirect_sync: false,
                                // #2465: carry the real creation/last-seen
                                // instants from the expiring entry so the
                                // RT_FLOW close frame reports a true StartTime.
                                created_ns: removed.created_ns,
                                last_seen_ns: removed.last_seen_ns,
                                // #2501: harvest the per-direction byte/packet
                                // counters off the entry BEFORE it is dropped
                                // (remove_entry has already returned it). These
                                // populate the reserved volume slots on the
                                // SESSION_CLOSE RT_FLOW frame so NetFlow/IPFIX
                                // reports real volume instead of 0.
                                counters: removed.counters,
                                // #2749: harvest the observed forward ToS +
                                // cumulative TCP control bits off the expiring
                                // entry so the SESSION_CLOSE RT_FLOW frame
                                // carries real NetFlow/IPFIX class-of-service
                                // and TCP-flags values.
                                observed_tos: removed.observed_tos,
                                observed_tcp_flags: removed.observed_tcp_flags,
                                // #4915: harvest the stable session id off the
                                // expiring entry so the SESSION_CLOSE RT_FLOW
                                // frame carries the SAME id this session's
                                // SESSION_CREATE did — the correlatable key.
                                session_id: removed.session_id,
                                bulk_resync: false,
                                tcp_close_class: 0,
                            });
                        }
                        expired_entries.push(ExpiredSession {
                            key,
                            decision,
                            metadata,
                            origin: removed.origin,
                        });
                    }
                } else {
                    // Case 4: still alive — long-timeout (>= 256s) case
                    // or a session re-scheduled to exactly this tick.
                    // Re-bucket at the new absolute target tick. The
                    // entry was just read by key immediately above with
                    // no intervening mutation, so the matching mutable
                    // lookup is a hard invariant — use
                    // `expect` instead of `if let Some` so an invariant
                    // violation surfaces loudly instead of silently
                    // pushing a stale-tick wheel entry (Copilot review).
                    let new_target_tick = target_tick_for(
                        now_ns,
                        entry.last_seen_ns.saturating_add(entry.expires_after_ns),
                    );
                    let new_bucket = bucket_for_tick(new_target_tick);
                    let entry_mut = self
                        .entry_by_key_mut(&key)
                        .expect("entry was just read via entry_by_key; no concurrent mutation");
                    entry_mut.wheel_tick = new_target_tick;
                    self.wheel.buckets[new_bucket].push_back(WheelEntry {
                        key,
                        scheduled_tick: new_target_tick,
                    });
                    self.last_pop_stats.re_bucketed += 1;
                }
            }
            self.wheel.cursor_tick = self.wheel.cursor_tick.saturating_add(1);
        }
        let expired = expired_entries.len() as u64;
        self.expired = self.expired.saturating_add(expired);
        expired_entries
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub fn expire_stale(&mut self, now_ns: u64) -> u64 {
        self.expire_stale_entries(now_ns).len() as u64
    }

    /// #2120: re-bucket an entry the expire pass decided to keep alive
    /// (SELF-HEAL or HOLD) so it is re-examined on a future tick.
    ///
    /// For a SELF-HEAL re-stamp, `last_seen_ns` is now fresh, so the
    /// entry schedules to its natural full-timeout tick (FAR_FUTURE for
    /// long timeouts, exactly like Case-4).
    ///
    /// For a HOLD (no re-stamp, expiration already at/before `now`) we
    /// schedule the entry at exactly the CURRENT tick (`now_tick`). The
    /// drain loop runs `while cursor_tick < now_tick`, so a WheelEntry
    /// placed at `now_tick` is NOT re-drained during THIS call (the loop
    /// terminates at `now_tick`); the NEXT expire pass (with an advanced
    /// `now_ns`) drains it. This is the only safe re-bucket target for a
    /// still-due entry: the wheel has only WHEEL_BUCKETS physical buckets,
    /// so scheduling at any tick the cursor has not yet passed
    /// (`< now_tick`) collides with a bucket the cursor re-visits within
    /// this call — re-draining (and re-holding) the entry repeatedly under
    /// a multi-tick jump. Scheduling at `now_tick` re-examines a held
    /// entry every interval (re-checking the self-heal edge + the ceiling)
    /// without any in-call re-drain. Self-healed entries (fresh
    /// `last_seen`) schedule to their natural expiration tick, exactly
    /// like Case-4 (FAR_FUTURE for long timeouts).
    fn rebucket_alive_entry(&mut self, key: &SessionKey, now_ns: u64) {
        let Some(entry) = self.entry_by_key(key) else {
            return;
        };
        let natural_expiration = entry.last_seen_ns.saturating_add(entry.expires_after_ns);
        // Held entries (past expiration) clamp to `now_ns` so
        // `target_tick_for` yields `now_tick` (delta 0). Self-healed
        // entries keep their future natural expiration.
        let expiration_for_schedule = natural_expiration.max(now_ns);
        let new_target_tick = target_tick_for(now_ns, expiration_for_schedule);
        let new_bucket = bucket_for_tick(new_target_tick);
        let Some(entry_mut) = self.entry_by_key_mut(key) else {
            return;
        };
        entry_mut.wheel_tick = new_target_tick;
        self.wheel.buckets[new_bucket].push_back(WheelEntry {
            key: key.clone(),
            scheduled_tick: new_target_tick,
        });
        self.last_pop_stats.re_bucketed += 1;
    }

    /// #4380: keep an idle-crossed entry alive if its forward↔reverse
    /// companion is still active, implementing Junos single-session idle
    /// semantics (idle time is measured from the last activity in EITHER
    /// direction). Returns `true` when the entry was kept (re-stamped +
    /// re-bucketed); the caller then skips `remove_entry`.
    ///
    /// The companion key is recovered exactly as `account_packet` and
    /// `propagate_tcp_state_to_companion` hop reverse↔forward:
    /// `reverse_session_key(key, entry_nat)` where `key` is the entry's OWN
    /// canonical key and `entry_nat` its OWN nat decision (the transform is
    /// its own inverse given the reversed decision, so it works from either
    /// half). "Still active" uses the SAME predicate the wheel applies for
    /// expiry (`now - last_seen <= expires_after`, the exact complement of the
    /// Case-3 strict-`>` expiry test) so a genuinely idle session — both halves
    /// quiet past the timeout — still reaps: when this half crosses, the
    /// companion has crossed too, the probe fails, and the caller removes.
    ///
    /// This only DELAYS a reap; it never manufactures freshness. The re-stamp
    /// copies the companion's REAL `last_seen_ns` (not `now_ns`), so once the
    /// companion also stops receiving packets both halves' timestamps freeze,
    /// both cross the timeout, and the flow reaps within one timeout window of
    /// its last activity in either direction (bounded, terminating).
    fn companion_keeps_alive(
        &mut self,
        key: &SessionKey,
        entry_nat: NatDecision,
        now_ns: u64,
    ) -> bool {
        let companion_key = reverse_session_key(key, entry_nat);
        let companion_last_seen = match self.entry_by_key(&companion_key) {
            Some(companion) => {
                // #6752: never extend a half whose companion is still waiting on
                // the handshake-completing segment. The probe is otherwise
                // handshake-agnostic, and that is precisely how a SYN-ACK the
                // client never ACKed held BOTH halves for ~300s: the reverse
                // half was on its fresh established window, so this probe kept
                // re-stamping the forward half off it. Refusing here is the
                // second half of the fix — the effective-class change in
                // `lookup` keeps the reverse half short, and this keeps the
                // probe from undoing it.
                //
                // Checking the COMPANION alone is sufficient because the bit is
                // set and cleared on both halves together
                // (`promote_from_reverse` plus
                // `propagate_tcp_state_to_companion`).
                if companion.handshake_pending {
                    return false;
                }
                // Companion still within ITS idle window (complement of the
                // Case-3 `> expires_after` expiry test) → the whole flow is
                // active; keep this half. Otherwise fall through: both halves
                // are idle, this one reaps normally.
                if now_ns.saturating_sub(companion.last_seen_ns) > companion.expires_after_ns {
                    return false;
                }
                companion.last_seen_ns
            }
            // No companion (single-entry flow, e.g. a FabricRedirect half with
            // no local reverse, or a half already independently reaped) → no
            // retention; reap normally. Same fail-open posture as
            // `account_packet`'s reverse hop.
            None => return false,
        };
        // Re-stamp THIS half from the companion's real last activity so the
        // whole session ages from the last packet in either direction (and the
        // HA session-sync of `last_seen_ns` carries the true idle to the peer),
        // then re-bucket so the GC re-examines it at the companion-derived tick.
        let Some(em) = self.entry_by_key_mut(key) else {
            return false;
        };
        em.last_seen_ns = companion_last_seen;
        self.rebucket_alive_entry(key, now_ns);
        true
    }

    /// #2120: the standby retention decision for an idle-crossed entry.
    /// Pure (reads only the passed snapshot + the HA context closures),
    /// so it can be unit-tested in isolation and called from the expire
    /// pass while the entry borrow is already dropped.
    #[allow(clippy::too_many_arguments)]
    fn standby_gate_decision(
        &self,
        ha: &ExpireHaContext<'_>,
        now_ns: u64,
        origin: SessionOrigin,
        owner_rg_id: i32,
        is_reverse: bool,
        fabric_ingress: bool,
        last_seen_ns: u64,
        expires_after_ns: u64,
        first_held_ns: u64,
        seen_rg_epoch: u32,
    ) -> StandbyGateDecision {
        // Fabric-ingress sessions age normally — they are not held
        // standby state (matches the existing fabric-skip convention).
        if fabric_ingress {
            return StandbyGateDecision::Age;
        }
        let peer_synced = origin.is_peer_synced();
        // forwards_here: does THIS node forward this session right now?
        // (rg > 0 → per-RG predicate; rg <= 0 → node-level.)
        let forwards_here = (ha.forwards_rg)(owner_rg_id);
        let current_epoch = (ha.epoch_of)(owner_rg_id);

        // (1) SELF-HEAL edge: peer-synced, this node now forwards the RG,
        //     but the recorded epoch predates the activation. Fire once;
        //     the re-stamp + epoch record make the next pass AGE-eligible.
        if peer_synced && forwards_here && current_epoch != seen_rg_epoch {
            return StandbyGateDecision::SelfHeal {
                new_epoch: current_epoch,
            };
        }

        // (2) HOLD: this node does not forward the session, and it is
        //     peer-synced OR this node forwards something (the "real
        //     cluster node" guard — a standalone node forwards nothing and
        //     holds nothing). Reverse-flow synced entries are held too;
        //     they back the same flow as their forward partner and must
        //     survive to failover identically.
        if !forwards_here && (peer_synced || ha.node_active) {
            // owner_rg_id <= 0 active/active residual: a node-level
            // standby entry (owner_rg_id == 0) on a node that IS active
            // for some other RG is AGED (node_active true ⇒ forwards_here
            // true ⇒ this branch is not reached). The case that lands here
            // for owner_rg_id <= 0 is a whole-node-standby (node_active
            // false) — held. So an aged owner_rg_id<=0-on-active-node is
            // observed separately below, not here.
            let _ = (is_reverse, last_seen_ns);
            // Measure the hold duration from when the entry FIRST entered
            // the held state. On the very first hold observation
            // `first_held_ns` is still 0 (the HOLD branch below stamps it
            // to `now_ns`), so the held duration is 0 — a long-idle synced
            // session that has only just crossed its idle timeout is held,
            // NOT instantly reaped from its stale `last_seen_ns`.
            let held_since = if first_held_ns != 0 {
                first_held_ns
            } else {
                now_ns
            };
            let held_ns = now_ns.saturating_sub(held_since);
            if held_ns > ha.stale_ceiling_ns(expires_after_ns) {
                return StandbyGateDecision::ReapStaleSynced;
            }
            // NOTE: Hold deliberately carries NO epoch — the caller must
            // NOT stamp seen_rg_epoch on a hold (see the Hold arm + the
            // Codex old-map/new-epoch race note there).
            return StandbyGateDecision::Hold;
        }

        // (3) AGE. Distinguish the known active/active owner_rg_id<=0
        //     under-retention residual (peer-synced node-level entry on an
        //     otherwise-active node) so it is observable, not silent.
        if peer_synced && owner_rg_id <= 0 && ha.node_active {
            return StandbyGateDecision::AgedOwnerRgZeroActiveNode;
        }
        StandbyGateDecision::Age
    }
}

/// #2120: outcome of the standby retention gate for one idle-crossed
/// entry. See `SessionTable::standby_gate_decision`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StandbyGateDecision {
    /// Keep alive, re-stamp `last_seen_ns`, record `new_epoch`; this node
    /// has just started forwarding the RG (promotion self-heal edge).
    SelfHeal { new_epoch: u32 },
    /// Keep alive without re-stamping `last_seen_ns`; this node does not
    /// forward the session. Arms `first_held_ns`. Deliberately carries NO
    /// epoch: stamping `seen_rg_epoch` on a hold would poison the
    /// self-heal edge under the old-map/new-epoch read skew (Codex MAJOR).
    Hold,
    /// Reap a held entry that crossed the stale-synced ceiling (bounded
    /// lost-primary-delete leak).
    ReapStaleSynced,
    /// Reap the known active/active `owner_rg_id <= 0` residual on an
    /// otherwise-active node (observability-tagged AGE).
    AgedOwnerRgZeroActiveNode,
    /// Normal expiry (active-node-owned, standalone, or fabric-ingress).
    Age,
}
