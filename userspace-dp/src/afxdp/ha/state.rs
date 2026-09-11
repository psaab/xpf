use crate::afxdp::*;

impl crate::afxdp::Coordinator {
    pub fn update_ha_state(&self, groups: &[HAGroupStatus]) -> Result<(), String> {
        let previous = self.ha.rg_runtime.load();
        let now_secs = monotonic_nanos() / 1_000_000_000;
        let mut state = BTreeMap::new();
        for group in groups {
            // Treat every active HA state update as a lease refresh. Packet-time
            // HA now consults a single applied lease state: active-until
            // or inactive.
            let lease = if group.active {
                HAGroupRuntime::active_lease_until(group.watchdog_timestamp, now_secs)
            } else {
                HAForwardingLease::Inactive
            };
            state.insert(
                group.rg_id,
                HAGroupRuntime {
                    active: group.active,
                    watchdog_timestamp: group.watchdog_timestamp,
                    lease,
                },
            );
        }
        let demoted_rgs = demoted_owner_rgs(previous.as_ref(), &state);
        let activated_rgs = activated_owner_rgs(previous.as_ref(), &state);
        // Debug: log state comparison for RGs 0-2
        for rg_id in 0..=2i32 {
            let prev_active = previous.get(&rg_id).map(|r| r.active);
            let curr_active = state.get(&rg_id).map(|r| r.active);
            if prev_active != curr_active {
                eprintln!(
                    "xpf-ha: RG{} state changed: {:?} -> {:?} (demoted={:?} activated={:?})",
                    rg_id, prev_active, curr_active, demoted_rgs, activated_rgs
                );
            }
        }
        // #2120 (MANDATORY): bump rg_epochs for every demoted AND
        // activated RG, plus the node-level rg_epochs[0] on ANY
        // activation, BEFORE publishing the new rg_runtime. This makes
        // the standby-retention self-heal edge airtight: a worker that
        // observes the active rg_runtime (ArcSwap acquire) is guaranteed
        // to also observe the bumped epoch (the Release store below is
        // ordered before the runtime publish), so the expire pass never
        // sees new-rg + old-epoch (the "AGE a session this node now
        // forwards" hole). The flow-cache invalidation these bumps also
        // drive is unaffected by the earlier timing — workers re-stamp on
        // the next lookup. The node-level rg_epochs[0] edge lets the
        // self-heal fire for owner_rg_id==0 fabric/reverse entries.
        //
        // These bumps replace the previously-after-store demote loop and
        // the handle_activated_rgs activation loop (removed below) so each
        // RG is incremented exactly once per transition.
        for rg_id in &demoted_rgs {
            let idx = *rg_id as usize;
            if idx > 0 && idx < MAX_RG_EPOCHS {
                self.rg_epochs[idx].fetch_add(1, Ordering::Release);
            }
        }
        for rg_id in &activated_rgs {
            let idx = *rg_id as usize;
            if idx > 0 && idx < MAX_RG_EPOCHS {
                self.rg_epochs[idx].fetch_add(1, Ordering::Release);
            }
        }
        if !activated_rgs.is_empty() {
            // Node-level "started forwarding something" edge so the
            // standby self-heal can release HELD owner_rg_id==0 entries.
            self.rg_epochs[0].fetch_add(1, Ordering::Release);
        }
        self.ha.rg_runtime.store(Arc::new(state));
        if !demoted_rgs.is_empty() {
            // #6242: fan out demote commands via each worker's runtime record.
            for rec in self.workers.records().values() {
                // #1790/#1807: recover from a poisoned worker command mutex
                // instead of early-returning. The new HA state was already
                // published via rg_runtime.store above, so an Err here would
                // make a retry diff against the demoted state (empty
                // demoted_rgs) and permanently skip the remaining workers'
                // demote commands, demote_shared_owner_rgs, and the
                // rg_epochs bumps. lock_recover applies the uniform
                // committed-prefix + clear_poison policy (worker_queue.rs).
                let mut pending = worker_queue::lock_recover(&rec.handle.commands);
                worker_queue::push_bounded(
                    &mut pending,
                    WorkerCommand::DemoteOwnerRGS {
                        owner_rgs: demoted_rgs.clone(),
                    },
                );
                // #941 Work item C: vacate V_min slots on demotion.
                // Stale-low slot values would cause peer workers to
                // throttle unnecessarily until the first post-settle
                // publish from this worker after re-promotion.
                worker_queue::push_bounded(&mut pending, WorkerCommand::VacateAllSharedExactSlots);
            }
            demote_shared_owner_rgs(
                &self.sessions.synced,
                &self.sessions.nat,
                &self.sessions.forward_wire,
                &self.sessions.owner_rg_indexes,
                &self.forwarding,
                self.dynamic_neighbors_ref(),
                &demoted_rgs,
            );
            // #2120: the demote rg_epochs bump moved BEFORE rg_runtime.store
            // above (epoch-before-publish ordering). O(1) flow-cache
            // invalidation is preserved — only the timing changed.
            // Record cache flush timestamp for observability (#312).
            self.last_cache_flush_at.store(now_secs, Ordering::Relaxed);
        }
        if !activated_rgs.is_empty() {
            eprintln!(
                "xpf-ha: RG activation detected: {:?}, workers={}, shared_sessions={}",
                activated_rgs,
                self.workers.records().len(),
                // #6653 sweep: log-only, but the same non-recovering pattern —
                // a poisoned mutex reported shared_sessions=0 in the RG
                // activation line, which is the single most misleading number
                // to get wrong during a failover post-mortem.
                lock_shared_recover(&self.sessions.synced).len(),
            );
            self.handle_activated_rgs(&activated_rgs, now_secs);
        }
        Ok(())
    }

    fn handle_activated_rgs(&self, activated_rgs: &[i32], now_secs: u64) {
        if activated_rgs.is_empty() {
            return;
        }
        // #2120: the activated rg_epochs bump (and the node-level
        // rg_epochs[0] edge) moved to update_ha_state BEFORE
        // rg_runtime.store, so it is NOT repeated here — a double
        // increment would still invalidate correctly but is avoided for
        // clarity and to keep each transition a single epoch step.

        let worker_commands = self
            .workers
            .records()
            .values()
            .map(|rec| rec.handle.commands.clone())
            .collect::<Vec<_>>();
        for commands in &worker_commands {
            // #1790/#1807: uniform poison recovery (worker_queue.rs).
            let mut pending = worker_queue::lock_recover(commands);
            worker_queue::push_bounded(
                &mut pending,
                WorkerCommand::RefreshOwnerRGS {
                    owner_rgs: activated_rgs.to_vec(),
                },
            );
        }
        let current = self.ha.rg_runtime.load();
        // #7209: hold the loaded set for as long as the raw fd is used below —
        // the `Arc` is what keeps the descriptor open across a concurrent
        // teardown, so extracting the raw `fd` and dropping the guard would
        // reintroduce the use-after-close this publish exists to prevent.
        let maps = self.bpf_maps.load();
        let session_map = SteeringMap {
            fd: maps.session_map_fd.as_ref().map(|fd| fd.fd).unwrap_or(-1),
            owners: &maps.session_map_owners,
        };

        // RG activation is still allowed to be a narrow ownership transition,
        // but split-RG continuity depends on rewarming the derived reverse
        // entries and restoring any redirect aliases that were removed during
        // demotion. This is not the old worker-wide HA refresh scan.
        prewarm_reverse_synced_sessions_for_owner_rgs(
            &self.sessions.synced,
            &self.sessions.nat,
            &self.sessions.forward_wire,
            &self.sessions.owner_rg_indexes,
            &worker_commands,
            session_map,
            &self.forwarding,
            current.as_ref(),
            self.dynamic_neighbors_ref(),
            activated_rgs,
            now_secs,
        );
        if session_map.fd >= 0 {
            let republished = republish_bpf_session_entries_for_owner_rgs(
                &self.sessions.synced,
                &self.sessions.owner_rg_indexes,
                session_map,
                activated_rgs,
                self.forwarding.has_routing_domains,
            );
            if republished > 0 {
                eprintln!(
                    "xpf-ha: republished {} USERSPACE_SESSIONS entries for activated RGs {:?}",
                    republished, activated_rgs
                );
            }
        }
        // #1636 option C: an RG just became forwarding-active on this
        // node. Repopulate the kernel neighbor cache for the now-active
        // next-hops (entries may have aged to NUD_FAILED while this node
        // was standby). Clears the per-key rate-limit and fires a forced
        // warm pass so this does not wait for the next snapshot apply.
        // queue_warm_pass re-checks each next-hop's RG via the freshly
        // stored rg_runtime, so standby RGs are not warmed.
        self.on_rg_promote_active();
    }

    pub fn ha_groups(&self) -> Vec<HAGroupStatus> {
        let now_secs = monotonic_nanos() / 1_000_000_000;
        self.ha.rg_runtime
            .load()
            .iter()
            .map(|(rg_id, runtime)| {
                let (lease_state, lease_until) = match runtime.lease {
                    HAForwardingLease::Inactive => ("inactive".to_string(), 0),
                    HAForwardingLease::ActiveUntil(until) => ("active".to_string(), until),
                };
                HAGroupStatus {
                    rg_id: *rg_id,
                    active: runtime.active,
                    watchdog_timestamp: runtime.watchdog_timestamp,
                    forwarding_active: runtime.is_forwarding_active(now_secs),
                    lease_state,
                    lease_until,
                }
            })
            .collect()
    }

    /// Returns the monotonic timestamp (secs) of the last HA flow cache flush.
    pub fn last_cache_flush_at(&self) -> u64 {
        self.last_cache_flush_at.load(Ordering::Relaxed)
    }
}
