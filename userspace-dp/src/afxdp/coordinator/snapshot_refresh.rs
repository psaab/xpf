//! #1890: runtime-snapshot refresh, split out of `coordinator/mod.rs`
//! (pure code motion). Owns the armed/disarmed snapshot-apply legs
//! (`refresh_runtime_snapshot{,_disarmed,_inner}`) — preflight policy
//! validation, manager-neighbor key rotation, the #1873 tunnel-remap
//! purge, the forwarding-state swap, the CoS owner/lease-map + fabric
//! publish (#5166: BEFORE the `ha.runtime` worker-visible store, so a
//! live worker never sees new queue config without its CoS owners), the
//! WG/GRE aux-thread reconcile or disarmed stop (after the forwarding
//! store), and the neighbor-warm pass — plus `refresh_fabric_links`
//! (the SyncFabricState path). The shared purge/log free helpers it
//! calls (`tunnel_remap_purge_ids`, `log_wg_endpoint_set_transition`)
//! stay in mod.rs: `reconcile/snapshot.rs` and tests outside this
//! module reference them at coordinator scope.
//!
//! # Publish ordering — the `RuntimeView` store is the single worker-visible gate
//! The `RuntimeView` is stored LAST so it acts as the one release-store that
//! publishes everything committed before it.
//!
//! - **validation ↔ forwarding (#6291 / #6592) — no longer an ordering
//!   problem.** The two used to be independent `ArcSwap`s, and coherence
//!   depended on the coordinator storing them in one order and every worker
//!   loading them in the opposite one. That can only ever exclude ONE of the
//!   two torn orientations: #6291 excluded `(old validation, new forwarding)`
//!   and left the mirror `(new validation, old forwarding)` reachable, which
//!   is not drop-only — once Go writes the new generation to `userspace_ctrl`
//!   the shim stamps NEW, and a worker holding the old forwarding classifies
//!   those packets `Valid` and forwards them under the STALE tables. #6592
//!   publishes both halves in ONE `Arc` (`types/runtime_view.rs`), so a worker
//!   observes whichever view was published as a unit and BOTH orientations are
//!   structurally impossible. Every publish site goes through the single choke
//!   point `Coordinator::publish_runtime_view` (or
//!   `republish_runtime_validation` for a validation-only change), which builds
//!   the view from `self.validation` at the store. That choke point is enforced
//!   by TYPES: `RuntimeViewChannel` / `RuntimeViewReader` hide the `ArcSwap`, so
//!   `publish` is the only mutation and consumers cannot obtain a writer, and
//!   `RuntimeView` has private fields and no `Clone`, so a loaded view can be
//!   neither mutated nor copied-and-tweaked.
//! - **CoS maps ↔ forwarding (#5166) — still an ordering pair.** The CoS
//!   owner/live/lease/backlog/vtime maps + `ha.fabrics` are stored BEFORE the
//!   `RuntimeView`; the worker reads the view FIRST, then the CoS maps.
//!   Observing a new view implies observing the matching CoS maps. Do NOT move
//!   these stores after the view store, and do NOT move the worker's view load
//!   after its CoS loads.
//!
//! Holding an OLD view remains possible and is SAFE — new-stamped packets
//! mismatch the old validation and DROP, the intended fail-closed behaviour.
//! #6592 closes INCOHERENT pairs, not stale coherent ones; nothing forces a
//! refresh.
//!
//! Both invariants are RED-on-revert guarded. The #6592 pairing: producer side
//! by the `#[cfg(test)] runtime_view_at_publish` seam captured immediately
//! above the view store (`coordinator/tests.rs`), consumer side by
//! `snapshot_refresh_runtime_view_pair_is_atomic_6592`
//! (`worker/loop_body/mod.rs`), which drives the worker refresh with a
//! coordinator publish injected between the two halves and asserts the
//! observed pair is coherent — splitting the refresh back into two loads goes
//! RED in EITHER order. The #5166 ordering: by
//! `refresh_runtime_snapshot_publishes_cos_owner_map_before_forwarding`.
//!
//! Coverage is uneven across the publications riding this gate: only the CoS
//! owner map (#5166) has an individual ordering assertion. The other
//! pre-view publications — CoS owner-live, root leases, exact backlogs, queue
//! leases, vtime floors, and `ha.fabrics` — are held in place by comment alone,
//! and the #5166 seam captures only the owner map so it does not prove its own
//! placement the way the #6592 seam does. Tracked as #6593.
//!
//! The rule is site-wide, not refresh-local: the worker's STARTUP SEED
//! (`worker/loop_body/setup.rs`) takes its pair from ONE view load, and
//! `Coordinator::stop_inner`'s teardown publishes the default pair through the
//! same choke point. Teardown runs after every worker thread has been joined,
//! so it has no live readers — it uses the choke point for uniformity, so that
//! no site in the tree contradicts this section.
use super::*;
use crate::afxdp::forwarding_build::build_forwarding_state_with_preparsed_policy_and_previous;

impl super::Coordinator {
    /// Refresh fabric link info from updated snapshots. Called when the
    /// Go daemon's refreshFabricFwd resolves a peer MAC that wasn't
    /// available at initial snapshot build time.
    ///
    /// This updates both the coordinator's local forwarding state and the
    /// shared Arc-backed state used by workers, so refreshed fabric links
    /// become visible to workers as soon as the new values are published.
    pub fn refresh_fabric_links(&mut self, snapshots: &[crate::FabricSnapshot]) {
        let (new_fabrics, new_skips) = resolve_fabric_links_from_snapshots(
            snapshots,
            &self.forwarding.egress,
            &self.neighbors.dynamic,
        );
        // Mirror the pre-#3773 gate: only REPLACE the fabric set when at least
        // one link resolved this pass, so an all-unresolved refresh keeps the
        // working set (from a prior SyncFabricState) instead of wiping it.
        let replace = !new_fabrics.is_empty();
        // #5686: when this pass resolves nothing (replace=false) we PRESERVE the
        // working fabric set — but first drop any preserved link SUPERSEDED by a
        // same-parent peer REPLACEMENT in the incoming snapshots. Otherwise the
        // stale old peer stays a valid `resolve_fabric_redirect` target while the
        // replacement peer is still unresolved (M01), and fabric-forwarded
        // traffic is sent to a peer that is no longer current. Once the stale
        // link is dropped, redirect for that parent yields no target during the
        // resolution window and the packet takes its normal non-fabric
        // disposition (safe). When replace=true the freshly-resolved
        // `new_fabrics` is built entirely from the current snapshots, so no
        // stale peer can survive there — the prune is only needed on the
        // preserve path.
        let superseded_removed = if replace {
            false
        } else {
            let before = self.forwarding.fabrics.len();
            self.forwarding
                .fabrics
                .retain(|link| !fabric_link_superseded_by_snapshots(link, snapshots));
            before != self.forwarding.fabrics.len()
        };
        // #3773 (M13): the skip list is pruned against whichever fabric set is
        // FINAL — a link kept from the prior resolved set is not reported as
        // "skipped" for the operator even if THIS pass could not re-resolve it
        // (its counter already bumped inside the resolver; the pruning only
        // governs the named status/log surface, not the cumulative atomics).
        let final_parents: Vec<i32> = if replace {
            new_fabrics.iter().map(|f| f.parent_ifindex).collect()
        } else {
            self.forwarding
                .fabrics
                .iter()
                .map(|f| f.parent_ifindex)
                .collect()
        };
        let pruned: Vec<FabricLinkSkip> = new_skips
            .into_iter()
            .filter(|s| !final_parents.contains(&s.parent_ifindex))
            .collect();
        log_fabric_skip_transition("fabric-refresh", &self.forwarding.fabric_skips, &pruned);
        let skips_changed = self.forwarding.fabric_skips != pruned;
        if replace {
            self.forwarding.fabrics = new_fabrics.clone();
            self.forwarding.fabric_skips = pruned;
            self.ha.fabrics.store(Arc::new(new_fabrics));
            // Also update the worker-visible view so workers see the new
            // fabric links for fabric redirect resolution. Without this,
            // workers use the snapshot's forwarding state which may have empty
            // fabrics if the peer MAC wasn't resolved at snapshot time.
            // #6592: through the choke point, so this fabric-only publish
            // carries the current validation.
            self.publish_runtime_view();
        } else if skips_changed || superseded_removed {
            // Nothing resolved this pass. Publish either because the skip
            // diagnostics changed or because #5686 pruned a stale (superseded)
            // link out of the preserved working set.
            self.forwarding.fabric_skips = pruned;
            if superseded_removed {
                // #5686: the pruned fabric set must also reach the worker
                // fast-path Arc (`shared_fabrics` / `self.ha.fabrics`). The
                // worker overwrites its forwarding.fabrics from that Arc ONLY
                // when it is non-empty, so a stale non-empty `ha.fabrics` would
                // re-add the superseded link the `RuntimeView` store just
                // removed. Store both so the stale peer is gone from every
                // reader.
                self.ha
                    .fabrics
                    .store(Arc::new(self.forwarding.fabrics.clone()));
            }
            self.publish_runtime_view();
        }
    }

    pub fn refresh_runtime_snapshot(
        &mut self,
        snapshot: &crate::ConfigSnapshot,
    ) -> Result<(), crate::policy::SnapshotIntegrityError> {
        let policy_state = self.prepare_snapshot_policy_state(snapshot)?;
        self.refresh_runtime_snapshot_with_policy_state(snapshot, policy_state)
    }

    pub(crate) fn refresh_runtime_snapshot_with_policy_state(
        &mut self,
        snapshot: &crate::ConfigSnapshot,
        policy_state: crate::policy::PreparedPolicyState,
    ) -> Result<(), crate::policy::SnapshotIntegrityError> {
        self.refresh_runtime_snapshot_inner(snapshot, true, policy_state)
    }

    /// #1866 (PR-review Codex r2): runtime-snapshot refresh for a
    /// DISARMED helper (`should_run_afxdp` false). Identical to
    /// `refresh_runtime_snapshot` EXCEPT it never spawns WG control
    /// threads — a disarmed helper must not transiently bind WG listen
    /// ports or emit handshake initiations; instead any existing
    /// entries are stopped (mirrors `reconcile_status_bindings →
    /// stop()`). Forwarding/validation state still refreshes so a
    /// later arming starts from current state.
    pub fn refresh_runtime_snapshot_disarmed(
        &mut self,
        snapshot: &crate::ConfigSnapshot,
    ) -> Result<(), crate::policy::SnapshotIntegrityError> {
        let policy_state = self.prepare_snapshot_policy_state(snapshot)?;
        self.refresh_runtime_snapshot_disarmed_with_policy_state(snapshot, policy_state)
    }

    pub(crate) fn refresh_runtime_snapshot_disarmed_with_policy_state(
        &mut self,
        snapshot: &crate::ConfigSnapshot,
        policy_state: crate::policy::PreparedPolicyState,
    ) -> Result<(), crate::policy::SnapshotIntegrityError> {
        self.refresh_runtime_snapshot_inner(snapshot, false, policy_state)
    }

    pub(crate) fn prepare_snapshot_policy_state(
        &self,
        snapshot: &crate::ConfigSnapshot,
    ) -> Result<crate::policy::PreparedPolicyState, crate::policy::SnapshotIntegrityError> {
        crate::policy::PreparedPolicyState::parse_snapshot(snapshot, &self.policy_counters)
    }
    #[cfg(test)]
    pub(crate) fn policy_parse_calls_for_test(&self) -> usize {
        self.policy_counters.parse_calls_for_test()
    }

    #[cfg(test)]
    pub(crate) fn reset_policy_parse_calls_for_test(&self) {
        self.policy_counters.reset_parse_calls_for_test();
    }


    /// #3766: same-plan runtime-snapshot refresh, now a FALLIBLE ATOMIC
    /// SWAP. The previous implementation mutated `self.validation` (H2)
    /// and rotated/deleted the dynamic neighbor-manager keys (H3) BEFORE
    /// the fallible `build_forwarding_state`, then swallowed a build
    /// error with a bare `return` — so an invalid same-plan snapshot
    /// that passed the POLICY preflight but failed a non-policy
    /// integrity check (invalid interface address, CoS queue, NAT64 /
    /// NPTv6 rule, ...) left the live table SPLIT-BRAIN (validation at
    /// the new generation, forwarding + old neighbor keys deleted)
    /// while the handler still reported `ok=true` (M1) and persisted
    /// the rejected snapshot as the boot baseline.
    ///
    /// The fix mirrors the full-reconcile invariant (#2484
    /// `build_reconcile_forwarding`): build the new forwarding state
    /// FIRST; only AFTER the build succeeds do we bump `self.validation`,
    /// rotate the neighbor-manager keys, swap the forwarding table, and
    /// publish to the worker-visible Arcs. On ANY integrity error no
    /// forwarding / validation / worker-visible state is mutated (a LATE
    /// build failure — NAT64/NPTv6/filter — may leave orphaned NAT-counter
    /// registrations; the prepared-policy guard rolls back candidate-only
    /// rule IDs, while the live policy continues to reference its old counters.
    /// NAT residue is benign and self-heals on the next successful apply) and
    /// the error is
    /// returned to the control-plane handler, which reports `ok=false` and
    /// does NOT persist the snapshot — the prior good state stays live and
    /// consistent (no split-brain, no neighbor blackhole).
    fn refresh_runtime_snapshot_inner(
        &mut self,
        snapshot: &crate::ConfigSnapshot,
        spawn_wg: bool,
        mut policy_state: crate::policy::PreparedPolicyState,
    ) -> Result<(), crate::policy::SnapshotIntegrityError> {

        // Preserve existing fabric links — they are resolved separately
        // via refresh_fabric_links (SyncFabricState) and the snapshot
        // may not include them if the peer MAC wasn't resolved at
        // snapshot build time. Always keep the better-resolved set.
        //
        // #5686: but DROP any preserved link SUPERSEDED by a same-parent peer
        // REPLACEMENT in this snapshot. If the snapshot names a new peer for a
        // parent whose old peer is still resolved, keeping the old link would
        // leave the STALE peer a valid `resolve_fabric_redirect` target while
        // the replacement peer is still unresolved (its neighbor MAC not yet
        // learned, so `populate_fabrics` skipped it and it is absent from the
        // new build). Once dropped, redirect for that parent yields no target
        // during the resolution window and the packet takes its normal
        // non-fabric disposition (safe). A snapshot that still names the SAME
        // peer (steady state) or omits the parent (fabric removed) does not
        // supersede, so the working link survives as before.
        let preserved_fabrics: Vec<FabricLink> = self
            .forwarding
            .fabrics
            .iter()
            .copied()
            .filter(|link| !fabric_link_superseded_by_snapshots(link, &snapshot.fabrics))
            .collect();
        // #3773 (M13): capture the prior fabric-skip set so the post-merge
        // transition log fires only when the named skip set actually changes.
        let old_fabric_skips = self.forwarding.fabric_skips.clone();
        // The prepared policy state came through the failure-atomic policy
        // preflight above. Passing it into the full forwarding build reuses
        // that parse while keeping all other build checks in their original
        // order.
        let new_forwarding = match build_forwarding_state_with_preparsed_policy_and_previous(
            snapshot,
            &self.policy_counters,
            &self.nat_counters,
            Some(&self.forwarding),
            policy_state.take_state(),
        ) {
            Ok(fwd) => fwd,
            Err(err) => {
                eprintln!(
                    "xpf-userspace-dp: snapshot integrity error during runtime-snapshot refresh: {} — keeping previous forwarding state",
                    err
                );
                return Err(err);
            }
        };
        policy_state.commit();

        // #3766: the build succeeded. From here on every step is
        // infallible; this is the atomic commit to the new generation.
        // The neighbor-manager key rotation + stale-entry removal (H3)
        // and the validation bump (H2) run ONLY now, so a rejected
        // snapshot can never have deleted a live neighbor key or
        // published a newer config generation against the old table.
        let next_manager_keys = snapshot
            .neighbors
            .iter()
            .filter_map(|neigh| {
                if neigh.ifindex <= 0
                    || !neighbor_state_usable_str(&neigh.state)
                    || neigh.mac.is_empty()
                    || parse_mac_str(&neigh.mac).is_none()
                {
                    return None;
                }
                let ip = neigh.ip.parse::<IpAddr>().ok()?;
                if crate::afxdp::forwarding::is_connected_v4_directed_broadcast(
                    &new_forwarding,
                    neigh.ifindex,
                    ip,
                ) {
                    return None;
                }
                Some((neigh.ifindex, ip))
            })
            .collect::<FastSet<_>>();
        let old_manager_keys = if let Ok(mut manager_keys) = self.neighbors.manager_keys.lock() {
            let old = manager_keys.iter().copied().collect::<Vec<_>>();
            *manager_keys = next_manager_keys;
            old
        } else {
            Vec::new()
        };
        // #949: bulk-remove stale manager keys atomically vs readers.
        self.neighbors.dynamic.with_all_shards(|bulk| {
            for key in &old_manager_keys {
                bulk.remove(key);
            }
        });
        // #1873 R-D (Codex code r3): captured BEFORE the overwrite —
        // gates the new-appearance purge arm below. False only when no
        // coordinator apply has ever installed a snapshot (disarmed
        // helper pre-first-arm), where boot-time synced sessions must
        // not be purged as "new appearances" against a default state.
        let prior_snapshot_installed = self.validation.snapshot_installed;
        self.validation = ValidationState {
            snapshot_installed: true,
            config_generation: snapshot.generation,
            fib_generation: snapshot.fib_generation,
        };
        // #1866 D3: WG endpoint-set transition log at the Rust apply
        // boundary. Rare (only when the set actually changes); pairs
        // with the Go publish-boundary log to pin which layer dropped
        // or retained an endpoint in one journal capture.
        log_wg_endpoint_set_transition("snapshot-refresh", &self.forwarding, &new_forwarding);
        // #1873 R-D: compute the remap purge set BEFORE the swap, and
        // PURGE before any store (Codex code-review r1). The worker
        // loop reads the forwarding Arc, drains commands, THEN runs the
        // RX sweep — so a worker that observes the new state in
        // iteration N drains these DeleteSynced commands in the same
        // iteration before processing a single packet with it. The
        // purge is CLEANUP (shared maps, worker tables, HA delete
        // propagation), not the correctness boundary: a stale session
        // that escapes any purge window can never mis-encapsulate,
        // because re-resolution and the encap builders refuse an id
        // whose owning netdev ifindex differs from the one stored in
        // the session's resolution (Codex code-review r2 — the r1
        // rotation-barrier approach was unsound: workers can hold
        // private fabric-overlay Arc clones, and a barrier timeout was
        // fail-open).
        // New-appearance purging is gated on a previously-installed
        // snapshot (Codex code r3): a DISARMED helper stores synced
        // sessions before its first coordinator apply (reconcile never
        // ran — `self.forwarding` is still default), so a same-plan
        // disarmed refresh would otherwise see every configured id as
        // "new" and wipe those boot-time entries.
        let tunnel_purge_ids =
            tunnel_remap_purge_ids(&self.forwarding, &new_forwarding, prior_snapshot_installed);
        // #8138: `self.forwarding` is still the live PREVIOUS state here (the
        // swap is the next line), so unlike the reconcile caller it is not
        // defaulted. `new_forwarding` is passed anyway, for one reason: the
        // allocators are the SAME objects either way (`Arc::clone` carryover),
        // and taking the argument from the same expression at both call sites
        // removes the chance of one drifting to the state that frees nothing.
        self.purge_remapped_tunnel_sessions(&tunnel_purge_ids, &new_forwarding);
        self.forwarding = new_forwarding;
        self.set_ipsec_tunnel_rows_from_snapshot(snapshot);
        // #6832 fold r5: the refresh's commit point for the #3651 per-zone
        // counters. Unlike the full reconcile there is no worker bring-up after
        // this swap — a same-plan refresh keeps the live workers — so the swap
        // itself IS the commit and the destructive prune is safe here. The
        // additive get-or-create already ran inside the build; see
        // `forwarding_build::commit_zone_counter_prune` for why the two halves
        // are split.
        crate::afxdp::forwarding_build::commit_zone_counter_prune(&self.forwarding, snapshot);
        // #7010: the policy / NAT hit-counter prune, moved down from above the
        // swap to sit beside the zone one. BEHAVIOUR-NEUTRAL on this path —
        // nothing between the old position and here can return, so the prune
        // already ran only on a committed refresh — but leaving it above the
        // swap left two counter families pruning at two different points in one
        // function, which is the shape that let the reconcile path drift.
        crate::afxdp::forwarding_build::commit_rule_counter_prune(
            &self.policy_counters,
            &self.nat_counters,
            snapshot,
        );
        if self.forwarding.fabrics.is_empty() && !preserved_fabrics.is_empty() {
            self.forwarding.fabrics = preserved_fabrics;
        } else if !preserved_fabrics.is_empty() {
            // Merge: for each preserved fabric, if the new snapshot
            // doesn't have a matching parent_ifindex, keep the old one.
            for old in &preserved_fabrics {
                if !self
                    .forwarding
                    .fabrics
                    .iter()
                    .any(|f| f.parent_ifindex == old.parent_ifindex)
                {
                    self.forwarding.fabrics.push(*old);
                }
            }
        }
        // #3773 (M13): the new build's `populate_fabrics` recorded its skips in
        // `self.forwarding.fabric_skips`. After the preserved-fabric merge
        // above, prune any skip whose parent is now present in the final
        // fabric set (a link kept from the prior resolved set is not reported
        // as skipped), then log the transition against the prior skip set —
        // once per change, not per route-churn `bump_fib`.
        let final_parents: Vec<i32> = self
            .forwarding
            .fabrics
            .iter()
            .map(|f| f.parent_ifindex)
            .collect();
        self.forwarding
            .fabric_skips
            .retain(|s| !final_parents.contains(&s.parent_ifindex));
        log_fabric_skip_transition(
            "snapshot-refresh",
            &old_fabric_skips,
            &self.forwarding.fabric_skips,
        );
        // #5166: publish the derived CoS owner/live/lease/backlog/vtime
        // maps AND the fabric-link set BEFORE making the new
        // ForwardingState worker-visible. A live worker refreshes its
        // per-tick view in a FIXED order — it loads the `RuntimeView`
        // first, then the CoS map Arcs (worker/loop_body/mod.rs), and
        // rebuilds `cos_fast_interfaces` from whichever CoS maps it holds.
        // With the pre-#5166 order (forwarding published first, CoS maps
        // refreshed after), a worker could observe the new queue config
        // while the CoS owner/lease maps still reflect the OLD generation
        // for a tick: a newly added queue would have NO owner (transient
        // class blackhole), an unchanged queue would meter at the stale
        // rate, and per-worker leases could over-admit across N workers.
        // `refresh_cos_owner_worker_map_from_identities` builds the maps
        // off `self.forwarding` — already the new state since the swap
        // above — so storing them first makes the invariant hold: because
        // the worker loads the view then CoS in the same tick and the
        // coordinator now stores CoS then the view, any worker that
        // observes the new forwarding is guaranteed by ArcSwap acquire/
        // release ordering to also observe the matching CoS maps. The
        // reverse window (new CoS maps visible while a worker still reads
        // the old view) is benign: added queues are not classified
        // to until forwarding rotates, and a removed queue merely loses a
        // dying CoS entry for one tick. Pure reordering of coordinator-side
        // stores — no new hot-path cost, no worker-side lock. The full
        // reconcile path (reconcile/bringup.rs) already refreshes the CoS
        // maps before spawning workers, so this brings the in-place refresh
        // in line with that atomic-publish discipline.
        self.refresh_cos_owner_worker_map_from_identities();
        self.ha
            .fabrics
            .store(Arc::new(self.forwarding.fabrics.clone()));
        // #5166 test seam: capture the CoS owner map at the instant just
        // before the new forwarding becomes worker-visible. With the
        // CoS-before-view order above it already reflects the new
        // generation; reverting the order captures the stale map, so the
        // ordering regression test goes RED. Absent from release builds.
        #[cfg(test)]
        {
            self.cos_owner_at_forwarding_publish =
                Some(self.cos.owner_worker_by_queue.load().as_ref().clone());
        }
        // #6592: ONE worker-visible store carrying BOTH halves. `self.validation`
        // was assigned above (the atomic commit to the new generation) and
        // `self.forwarding` is the new table, so the view this publishes is the
        // new generation's coherent pair. A worker observes that pair as a unit
        // — it cannot hold this refresh's validation with the previous
        // forwarding, nor the reverse. Both torn orientations (#6291 and its
        // mirror #6592) are structurally impossible, so no store/load ordering
        // discipline is needed between these two values any more; the #5166
        // CoS-then-view order above still is, and this store is still the gate
        // it rides.
        //
        // The `#[cfg(test)] runtime_view_at_publish` seam inside
        // `store_runtime_view` records the intended pair + the previous view
        // for the RED-on-revert test.
        self.publish_runtime_view();
        // #9506 S5: rotate reinject authority at the same committed
        // snapshot boundary as the worker-visible runtime view.
        if let Some(slow_path) = self.slow_path.as_ref() {
            let queue_epochs: Vec<(u16, u64)> = snapshot
                .queue_epochs
                .iter()
                .map(|entry| (entry.queue, entry.epoch))
                .collect();
            slow_path.publish_reinject_epochs(snapshot.permit_epoch, &queue_epochs);
        }
        // #1432 S2a (Copilot C1): reconcile WG control threads on every
        // runtime-snapshot refresh, not just initial bring-up, so a
        // same-plan apply that adds/removes/changes a WG endpoint starts,
        // stops, or restarts the matching UDP/TUN control thread.
        // #1866 (Codex code-r2): NEVER on a disarmed helper — not even
        // transiently (the control loop binds + may emit an initiation
        // before its first stop check); stop anything present instead.
        //
        // #5166: still runs AFTER the forwarding store above — a fresh
        // WG/GRE control thread's first `load_full()` must see the new
        // forwarding state (the store-to-join window is covered by the
        // thread-side rotation gate, tunnel.rs endpoint_attachment_valid).
        if spawn_wg {
            self.spawn_wg_control_threads();
            // #1881: reconcile GRE local-origin threads on every armed
            // runtime-snapshot refresh — tunnel interfaces are excluded
            // from the binding plan, so tunnel add/remove/reattach
            // commits reach ONLY this path.
            self.reconcile_local_tunnel_sources();
        } else {
            self.stop_all_wg_control_threads("disarmed");
            // #1881: a disarmed helper must not hold GRE TUN reader
            // fds either (mirrors the WG rule; in practice a no-op —
            // reconcile_status_bindings → stop() already cleared them).
            self.stop_all_local_tunnel_sources("disarmed");
        }
        // #1636 option C: proactively warm configured next-hops so the
        // neighbor cache is hot before the first user flow. Non-forced:
        // the 1s snapshot-level rate-limit coalesces config storms.
        self.queue_warm_pass(false);
        Ok(())
    }
}
