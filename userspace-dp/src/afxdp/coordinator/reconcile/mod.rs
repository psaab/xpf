//! #1328 Phase 2: per-phase decomposition of `Coordinator::reconcile`.
//!
//! Pure code motion of the previous 506-LOC `reconcile()` body in
//! `coordinator/mod.rs` into four phase modules. The orchestrator
//! itself lives in [`reconcile`](Coordinator::reconcile) below; each
//! phase helper is a free `pub(super) fn` defined in its own module.
//!
//! Side-effect ordering and `last_reconcile_stage` writes are
//! preserved verbatim. See
//! `docs/pr/1328-coordinator-reconcile-split/plan.md` §"Hidden
//! invariants" for the load-bearing inventory.
use super::*;
// Bring afxdp scope so types like SyncedSessionEntry / SlowPathReinjector
// / OwnedFd / DnatTableFds / BindingStatus / ConfigSnapshot are usable in
// the orchestrator and the PreservedReconcileState/ReconcileSnapshotFds
// definitions below.
use super::super::*;

pub(super) mod bringup;
pub(super) mod reset;
pub(super) mod snapshot;
pub(crate) mod stage;
pub(super) mod teardown;

pub(crate) use stage::{MandatoryPin, ReconcileStage, WorkerBindShortfall};

/// #3789: the outcome of a full-`reconcile` that aborted in one of the
/// PRE-TEARDOWN legs (policy preflight, mandatory-map preflight, or the
/// `build_reconcile_forwarding` integrity build). Before this change
/// `reconcile` returned `()` and the control-socket `apply_snapshot`
/// handler could not tell an aborted reconcile from a successful one — so
/// on the non-same-plan full-apply leg and the same-plan
/// `needs_reconcile` leg it stored the rejected snapshot as the boot
/// baseline, set `persist_state`, and acked `ok=true` (the M1 class #3766
/// fixed for the same-plan *refresh* leg). Returning the failure lets the
/// handler mirror #3766: report `ok=false`, restore the prior snapshot +
/// status fields, and NOT persist.
///
/// The `Integrity` and `MapSetup` variants are raised ONLY by a
/// pre-teardown early return, where #2440/#2484 keep the prior workers +
/// forwarding + published generation fully live. For those, the handler
/// restore is a status/bookkeeping rollback, not a forwarding recovery —
/// the data plane never moved.
///
/// #4952: `WorkerSpawn` is the exception — it is raised AFTER `tear_down`
/// has already stopped the old workers, so the data plane HAS moved (a
/// queue set is left with no XSK-bound worker). There is no prior-state
/// restore that brings the torn-down workers back; the handler still fails
/// closed (report `ok=false`, do NOT persist the broken snapshot as the
/// boot baseline) and recovery is a retry / last-good reconcile.
#[derive(Debug)]
pub(crate) enum ReconcileError {
    /// A snapshot integrity fault surfaced by the top-of-reconcile policy
    /// preflight or by the pre-teardown forwarding build
    /// (`build_reconcile_forwarding`: invalid interface address, CoS
    /// queue, NAT64 / NPTv6 / filter rule, ...).
    Integrity(crate::policy::SnapshotIntegrityError),
    /// A mandatory BPF map pin was missing or its FD failed to open
    /// (`preflight_map_fds`), or `apply_snapshot` returned `None`
    /// (defensively unreachable post-#2484). #6244: carries the TYPED
    /// [`ReconcileStage`] failure identity (was the cloned stage `String`);
    /// its `Display` renders the identical control-plane error text.
    MapSetup(ReconcileStage),
    /// #4952: a worker thread failed to spawn on the POST-TEARDOWN
    /// destructive path (`bring_up_workers` -> `spawn_supervised_worker` ->
    /// `pthread_create` EAGAIN/ENOMEM under resource exhaustion). Unlike the
    /// two pre-teardown variants above, `tear_down` has already stopped the
    /// old workers, so the affected queue set has NO XSK-bound worker and
    /// forwarding is DOWN. Surfaced so the control handler fails closed and
    /// does NOT persist the broken snapshot as the boot baseline. #6244:
    /// carries the preserved typed [`ReconcileStage::SpawnWorkerFailed`]
    /// identity (was its stage `String`).
    WorkerSpawn(ReconcileStage),
    /// #5143: a worker SPAWNED successfully on the POST-TEARDOWN path but its
    /// IN-THREAD XSK/UMEM bind did not bring up its full planned binding set
    /// (a partial/empty bind), or it never reported startup readiness within
    /// the bounded barrier deadline. #4952's spawn-error propagation does NOT
    /// catch this — the spawn SUCCEEDED; the failure is inside the worker
    /// thread's setup, where a live heartbeat over an incomplete binding set
    /// used to satisfy the supervisor (the #5143 silent forwarding outage).
    /// Like `WorkerSpawn` this is raised AFTER teardown (the queue set has no
    /// XSK-bound worker), so the handler fails closed and does NOT persist the
    /// broken snapshot. #6244: carries the preserved typed
    /// [`ReconcileStage::WorkerBindIncomplete`] identity (was its stage
    /// `String`).
    WorkerBindIncomplete(ReconcileStage),
}

impl std::fmt::Display for ReconcileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReconcileError::Integrity(err) => write!(f, "{err}"),
            ReconcileError::MapSetup(stage) => write!(f, "map setup failed ({stage})"),
            ReconcileError::WorkerSpawn(stage) => write!(f, "worker spawn failed ({stage})"),
            ReconcileError::WorkerBindIncomplete(stage) => {
                write!(f, "worker bind incomplete ({stage})")
            }
        }
    }
}

/// State preserved across `stop_inner(false)` that the later phases
/// need to consume. `had_live_workers` lives entirely inside
/// `teardown.rs` (it gates the 500ms mlx5 quiesce sleep alongside the
/// `will_rebind` flag, which is not needed outside teardown).
pub(in crate::afxdp) struct PreservedReconcileState {
    pub(super) slow_path: Option<Arc<SlowPathReinjector>>,
    /// #1873 R-D (AGY code r3): the tunnel-owner map (id -> logical
    /// interface name) captured BEFORE `stop_inner(false)` resets
    /// `coord.forwarding` to default. The remap purge diff in
    /// `apply_snapshot` MUST run against this — diffing the
    /// post-teardown empty state makes every purge arm inert across a
    /// reconcile boundary.
    pub(super) tunnel_owners: Vec<(u16, String)>,
    /// Captured before `stop_inner` resets `coord.validation`: gates
    /// the new-appearance purge arm so only the GENUINE first apply of
    /// the helper's life skips it (not every post-teardown apply).
    pub(super) snapshot_was_installed: bool,
}

/// Owned BPF map FDs returned by [`snapshot::apply_snapshot`] and
/// consumed by [`bringup::bring_up_workers`], which stores them on
/// `self.bpf_maps` after the per-worker spawn loop runs.
pub(in crate::afxdp) struct ReconcileSnapshotFds {
    pub(super) map_fd: OwnedFd,
    pub(super) heartbeat_map_fd: OwnedFd,
    pub(super) session_map_fd: OwnedFd,
    pub(super) conntrack_v4_fd: Option<OwnedFd>,
    pub(super) conntrack_v6_fd: Option<OwnedFd>,
    pub(super) dnat_table_fd: Option<OwnedFd>,
    pub(super) dnat_table_v6_fd: Option<OwnedFd>,
    pub(super) dnat_fds: DnatTableFds,
    /// #2484: the fully-built forwarding state, produced in the
    /// pre-teardown preflight so a snapshot INTEGRITY fault aborts the
    /// reconcile BEFORE `tear_down` stops the workers and resets
    /// `coord.forwarding` / `coord.validation`. `apply_snapshot` REUSES
    /// this rather than rebuilding — the build reads `Some(&coord.forwarding)`
    /// as the "previous" arg, which teardown defaults to empty, so it MUST
    /// happen before teardown. Building once also avoids re-inserting
    /// per-rule counter handles into the live counter stores twice.
    pub(super) forwarding: ForwardingState,
}

impl Coordinator {
    /// #5171: run the PRE-TEARDOWN snapshot-integrity legs — policy-state
    /// preflight, mandatory + present-optional BPF map-pin openability, and
    /// the full forwarding build — WITHOUT any teardown, worker spawn,
    /// binding mutation, FD retention, or `last_reconcile_stage` write.
    ///
    /// These are the SAME integrity checks `reconcile` runs before it
    /// touches any live state (its policy preflight, `preflight_map_fds`,
    /// and `build_reconcile_forwarding` legs): the policy leg shares
    /// `snapshot::preflight_policy_state` verbatim, the map leg opens the
    /// same pins through the same `OwnedFd::open_bpf_map`, and the build leg
    /// invokes the same `build_forwarding_state_with_policy_counters_and_previous`.
    /// So a snapshot this method rejects is exactly one `reconcile` would
    /// reject (a parity test locks it). The three legs run in `reconcile`'s
    /// order, so a snapshot failing multiple legs reports the same first
    /// error either path.
    ///
    /// This exists for the DEFERRED-activation apply path (RETH MAC
    /// pending), which SKIPS worker bring-up entirely and therefore never
    /// reaches `reconcile` — yet still ACKs + persists the snapshot as the
    /// boot baseline. Before #5171 that path did so WITHOUT any of these
    /// checks, so a non-buildable config (bad interface address / CoS queue
    /// / NAT64 / NPTv6 rule, or a MISSING/UNOPENABLE mandatory map pin) was
    /// acked `ok=true` and persisted, only to fail-OPEN at the later
    /// deferred bring-up (re-apply/rebind failures are warning-only). The
    /// defer handler calls this to prove the snapshot is fully buildable
    /// with all mandatory resources BEFORE ack/persist, failing closed on
    /// error. It runs the integrity VALIDATION only — it does NOT activate
    /// workers (the defer semantics — skip the spawn — are preserved).
    ///
    /// Side-effect-free by construction: the map-pin leg opens each pin then
    /// drops the FD; the build leg uses SCRATCH policy + NAT counter stores
    /// (no `Arc` handle leak into the live stores on a rejected snapshot) AND
    /// passes `previous = None` so it never carries over — hence never mutates
    /// — the live `self.forwarding` zone-counter store (a `Clone`-shares-Arc
    /// store whose carry-over `reconcile(retain)` would otherwise prune the
    /// published per-zone totals; see `validate_forwarding_buildable`, rev-5605
    /// fold); `WgEngine::new` (invoked inside the build) is a pure constructor.
    /// Verdict parity with `reconcile` is preserved: no fallible integrity leg
    /// reads `previous` for its accept/reject decision. A `None` snapshot
    /// (config-cleared / shutdown) is trivially buildable — an intentional
    /// teardown — matching `reconcile`'s `no_snapshot` leg.
    pub(crate) fn validate_snapshot_buildable(
        &self,
        snapshot: Option<&ConfigSnapshot>,
    ) -> Result<(), ReconcileError> {
        let Some(snapshot) = snapshot else {
            return Ok(());
        };
        // Leg 1: policy-state preflight (#1606/#3402) — shared with reconcile.
        snapshot::preflight_policy_state(snapshot).map_err(ReconcileError::Integrity)?;
        // Leg 2: mandatory + present-optional BPF map-pin openability (#2440).
        snapshot::validate_map_pins(snapshot)?;
        // Leg 3: full forwarding-build integrity (#2484) — the non-policy
        // faults (invalid interface address, CoS queue, NPTv6 rule, ...)
        // reachable only inside the full build. `previous = None` inside
        // (rev-5605 fold) so the discarded build never prunes the live
        // zone-counter store; verdict parity with reconcile is preserved.
        snapshot::validate_forwarding_buildable(snapshot)
    }

    /// Reconcile the coordinator state against an optional config
    /// `snapshot`.
    ///
    /// Phases (preserved verbatim from pre-#1328 monolithic body):
    /// 1. Teardown: preserve synced sessions + healthy slow path,
    ///    stop workers, 500ms quiesce if workers were live AND a rebind
    ///    follows (snapshot-apply path only — #2522).
    /// 2. Reset: zero per-binding counter fields.
    /// 3. Snapshot apply (only if `snapshot.is_some()`): install
    ///    validation/forwarding state, re-arm slow path, open BPF
    ///    map FDs. Returns early on missing pin / open failure with
    ///    `last_reconcile_stage` + per-binding `last_error` set.
    /// 4. Bringup: build worker plans, replay preserved synced
    ///    sessions, per-worker spawn loop (#925 panic-slot inline),
    ///    start neighbor monitor + local tunnel sources.
    /// 5. Final `refresh_bindings(bindings)` so the operator-visible
    ///    `BindingStatus` snapshot reflects the just-spawned workers.
    ///
    /// The `no_snapshot` (config-cleared / shutdown) path returns after
    /// phase 2 but ALSO runs `refresh_bindings(bindings)` before
    /// returning (#2515) — phase 1 stopped every worker, so the refresh
    /// routes each now-workerless slot through `zero_unbound_slot`
    /// (clearing the bind-mode / socket / capacity fields that the phase
    /// 2 counter reset leaves untouched) and rebuilds the CoS owner map
    /// empty. Without it, status commands report torn-down slots as if
    /// still bound and the CoS owner->worker map keeps stale entries.
    pub fn reconcile(
        &mut self,
        snapshot: Option<&ConfigSnapshot>,
        bindings: &mut [BindingStatus],
        ring_entries: usize,
    ) -> Result<(), ReconcileError> {
        self.reconcile_calls += 1;
        self.last_reconcile_stage = ReconcileStage::Start;
        // #1606 (AGY r2 finding 4.2): policy-integrity preflight
        // BEFORE tear_down. If the snapshot has duplicate / zero /
        // unknown book IDs, reject WITHOUT tearing down the
        // existing workers. Workers keep running on the previous
        // good config until a valid snapshot arrives.
        //
        // Uses a scratch counter store (Codex r1 F2) so we don't
        // leak Arc<PolicyRuleCounter> entries on rejected snapshots.
        if let Some(snap) = snapshot {
            // #5171: the policy-state preflight is now shared verbatim with
            // the `validate_snapshot_buildable` deferred-apply gate
            // (`snapshot::preflight_policy_state`) so the deferred-activation
            // apply and this full reconcile can never drift on which
            // snapshots pass the policy check. Same #1606 scratch counter
            // store + #3402 snapshot-zone resolution as before.
            if let Err(err) = snapshot::preflight_policy_state(snap) {
                eprintln!(
                    "xpf-userspace-dp: snapshot integrity error during reconcile preflight: {} — keeping previous workers + forwarding state",
                    err
                );
                self.last_reconcile_stage =
                    ReconcileStage::SnapshotIntegrityErrorDetail(err.to_string());
                // #3789: surface the reject so the control handler fails
                // closed instead of persisting the rejected snapshot.
                return Err(ReconcileError::Integrity(err));
            }
        }
        // #2440 fail-open partial-apply fix: open the mandatory BPF map
        // FDs (xsk/heartbeat/sessions) — the real correctness boundary —
        // BEFORE `tear_down` stops the running workers and BEFORE
        // `apply_snapshot` publishes a newer forwarding generation. If
        // any mandatory pin is missing or its FD fails to open, abort
        // HERE: the prior workers keep running and the prior forwarding
        // generation stays published. Previously the FD open happened
        // AFTER teardown + publish, so a snapshot with an unopenable
        // required pin tore down the workers, published a newer
        // `snapshot_installed` generation, then aborted bring-up —
        // leaving the helper advertising a data-plane view backed by no
        // workers (fail-open on a security appliance).
        //
        // `preflight_map_fds` only opens FDs and writes
        // `last_reconcile_stage` / per-binding `last_error` on failure;
        // it mutates no published state, so returning here is safe.
        let preflight_fds = if let Some(snap) = snapshot {
            let mut fds = match snapshot::preflight_map_fds(self, snap, bindings) {
                Some(fds) => fds,
                None => {
                    // last_reconcile_stage + per-binding last_error set
                    // inside preflight_map_fds. No teardown, no publish.
                    // #3789: surface the reject (missing / unopenable
                    // mandatory pin) so the handler fails closed.
                    return Err(ReconcileError::MapSetup(self.last_reconcile_stage.clone()));
                }
            };
            // #2484 fail-open partial-apply fix (completes the #2440/#2444
            // trilogy): build the full forwarding state HERE, BEFORE
            // `tear_down`. The top-of-reconcile policy preflight above only
            // parses policy/address-book state, so snapshot INTEGRITY faults
            // reachable only inside the full build (e.g. Nptv6UnparseableRule,
            // NPTv6 overlap / unresolvable-zone faults; NAT64 is fail-scoped
            // per #3888 and no longer aborts) used to surface inside
            // `apply_snapshot` — AFTER teardown stopped the workers and reset
            // `coord.validation` and republished the default view, stranding the helper
            // with no forwarding and no workers (residual fail-open). Building
            // here aborts on such a fault with the prior generation + workers
            // still live, mirroring the map-FD hoist #2440 added.
            //
            // This is the SAME call `apply_snapshot` made; the result is
            // stashed on `fds.forwarding` and reused there (build-once), so we
            // do NOT pay a second build on the success path nor re-insert
            // per-rule counter handles into the live stores twice. The build
            // reads `Some(&self.forwarding)` as its "previous" arg, which
            // `tear_down` defaults to empty — another reason it MUST run
            // before teardown.
            match snapshot::build_reconcile_forwarding(self, snap) {
                Ok(forwarding) => fds.forwarding = forwarding,
                Err(err) => {
                    // last_reconcile_stage = "snapshot_integrity_error" set
                    // inside build_reconcile_forwarding. No teardown, no
                    // publish: prior generation + workers stay live.
                    // #3789: surface the integrity error so the control
                    // handler fails closed on the full-reconcile legs
                    // instead of persisting the rejected snapshot.
                    return Err(ReconcileError::Integrity(err));
                }
            }
            Some(fds)
        } else {
            None
        };
        // #2522: only the snapshot-apply path rebinds the XSK on the
        // (possibly) same queue set, so only it needs the mlx5 EBUSY
        // quiesce. A `None`-snapshot teardown (config cleared / shutdown
        // reconcile) returns at `no_snapshot` below without ever
        // rebinding — pass `will_rebind = false` so it skips the 500ms
        // stall.
        let will_rebind = snapshot.is_some();
        let mut preserved = teardown::tear_down(self, will_rebind);
        reset::reset_binding_counters(bindings);
        let Some(snapshot) = snapshot else {
            self.policy_counters.reconcile_rules(&[]);
            // #2218: no snapshot -> no active NAT rules -> drop all counters.
            self.nat_counters.reconcile_ids(&[]);
            // #2515: the no_snapshot teardown stopped every worker
            // (`stop_inner` emptied `workers.live` and cleared the CoS
            // owner maps), but `reset_binding_counters` only zeroes the
            // counter scalars + `bound`/`xsk_registered`/`socket_fd` — it
            // leaves `xsk_bind_mode`, `socket_ifindex`/`queue_id`/
            // `bind_flags`, `zero_copy`, and the `flow_cache_capacity`/
            // `active_flow_count` gauges at their pre-teardown values.
            // Without the refresh below, status commands keep reporting
            // those slots as if still bound, and the rebuilt CoS
            // owner->worker map is never emptied. `refresh_bindings`
            // routes every now-workerless slot through `zero_unbound_slot`
            // (clearing exactly those residual fields) and rebuilds the
            // CoS owner map empty — the same tail the snapshot-apply path
            // runs at the end of `reconcile`. Run it BEFORE setting the
            // stage so the operator-visible state is consistent on return.
            self.refresh_bindings(bindings);
            self.last_reconcile_stage = ReconcileStage::NoSnapshot;
            // #3789: a config-cleared / shutdown teardown is a successful
            // reconcile (the caller intentionally passed no snapshot).
            return Ok(());
        };
        // SAFETY: preflight_fds is Some whenever snapshot is Some (both
        // gated on the same `snapshot` Option above).
        let fds = preflight_fds.expect("preflight_map_fds ran for a Some snapshot");
        // #2484: `apply_snapshot` no longer rebuilds the forwarding state
        // or rejects on an integrity fault — that build (and its integrity
        // check) was hoisted into the pre-teardown preflight above
        // (`build_reconcile_forwarding`), so by the time we reach here the
        // build has already succeeded and `apply_snapshot` reuses
        // `fds.forwarding`. The `Option` return is retained for signature
        // stability; the `else` arm is now defensively unreachable.
        let Some((fds, tunnel_purge_ids)) = snapshot::apply_snapshot(
            self,
            snapshot,
            preserved.slow_path,
            &preserved.tunnel_owners,
            preserved.snapshot_was_installed,
            fds,
            crate::slowpath::set_if_mtu,
        ) else {
            // #2484: defensively unreachable — the build already succeeded
            // in the pre-teardown preflight and apply_snapshot reuses it.
            // #3789: still surface a reject rather than a false ok if it
            // ever fires (teardown already ran here, so this is a
            // fail-closed backstop, not a prior-state restore).
            return Err(ReconcileError::MapSetup(self.last_reconcile_stage.clone()));
        };
        let bringup_result = bringup::bring_up_workers(
            self,
            snapshot,
            bindings,
            fds,
            ring_entries,
            &tunnel_purge_ids,
        );
        // Reflect the real per-binding state either way — a partial spawn
        // (some workers up, then a spawn aborted the rest) still needs the
        // refresh so status shows which slots came up and which did not.
        self.refresh_bindings(bindings);
        // #6832 fold r5: THIS is the reconcile's commit point for the #3651
        // per-zone counters, and it is deliberately AFTER `bring_up_workers`
        // rather than inside the build. The destructive prune drops the blocks
        // for zones this snapshot no longer configures, and those blocks hold
        // cumulative totals in a store every generation's handle shares. A
        // build that succeeded but whose workers then failed to come up has NOT
        // been committed — the `WorkerSpawn` arm below leaves `coord.forwarding`
        // published, so `show security zones` keeps reporting from this store
        // while nothing is forwarding. Pruning at build time destroyed the
        // removed zone's totals for exactly that configuration (measured: live
        // {100,200} + candidate {100,300} + forced spawn failure took the
        // visible rows to [100]). The additive get-or-create stays at build
        // time — see `forwarding_build::commit_zone_counter_prune`.
        if bringup_result.is_ok() {
            crate::afxdp::forwarding_build::commit_zone_counter_prune(&self.forwarding, snapshot);
            // #7010: the policy / NAT hit-counter prune shares this commit
            // point, for the reason on `commit_rule_counter_prune`.
            crate::afxdp::forwarding_build::commit_rule_counter_prune(
                &self.policy_counters,
                &self.nat_counters,
                snapshot,
            );
        }
        // #4952 / #5143: a POST-TEARDOWN worker-bringup failure fails the
        // reconcile closed. `bring_up_workers` returned the specific failure —
        // a worker thread that failed to SPAWN (#4952) or a worker that
        // spawned but bound an INCOMPLETE queue set / never reported readiness
        // (#5143). Surface each as its own `ReconcileError` variant so the
        // control handler reports ok=false and does NOT persist this broken
        // snapshot as the boot baseline (the old workers are already torn down
        // — there is no forwarding to restore, only fail-closed bookkeeping +
        // a retry/last-good path).
        bringup_result.map_err(|err| match err {
            bringup::WorkerBringUpError::Spawn(stage) => ReconcileError::WorkerSpawn(stage),
            bringup::WorkerBringUpError::BindIncomplete(stage) => {
                ReconcileError::WorkerBindIncomplete(stage)
            }
        })
    }
}
