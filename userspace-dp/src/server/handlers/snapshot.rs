// #1345: per-verb handlers for apply_snapshot and bump_fib_generation.
// Both verbs pivot on request.snapshot. Bodies are byte-identical
// to handlers.rs lines 53-131 (apply_snapshot) and 209-225
// (bump_fib_generation) modulo the per-handler parameter-passing
// substitution described in docs/pr/1345-server-handlers-split/plan.md.

use super::super::helpers::{
    reconcile_status_bindings, refresh_status, replan_queues,
    same_plan_apply_needs_binding_reconcile, should_run_afxdp, snapshot_binding_plan_key,
};
use super::super::ServerState;
use crate::{
    ConfigSnapshot, ControlResponse, CONFIG_SNAPSHOT_PROTOCOL_VERSION,
    SNAPSHOT_CONTENT_CONFLICT_PREFIX,
};

pub(super) fn apply(
    guard: &mut ServerState,
    snapshot: Option<ConfigSnapshot>,
    response: &mut ControlResponse,
    persist_state: &mut bool,
) {
    let Some(snapshot) = snapshot else {
        response.ok = false;
        response.error = "missing snapshot".to_string();
        return;
    };
    if snapshot.version != CONFIG_SNAPSHOT_PROTOCOL_VERSION {
        response.ok = false;
        response.error = format!(
            "unsupported snapshot protocol version {} (want {})",
            snapshot.version, CONFIG_SNAPSHOT_PROTOCOL_VERSION
        );
        return;
    }
    // #5169: monotonicity gate for the FULL apply_snapshot path, mirroring the
    // #3767 H5 rollback guard on `bump_fib` below. Flow-cache validation is
    // EQUALITY based on the (config_generation, fib_generation) PAIR — an entry
    // is a HIT only when its stamped pair equals the currently-published pair
    // (afxdp/flow_cache.rs `lookup`; see `stale_config_generation_causes_miss`).
    // So re-publishing a pair that a later apply already superseded makes the
    // cache entries that later generation logically invalidated MATCH again,
    // reviving a stale permit decision (a lazily-unevicted cached ALLOW) after
    // the config/route that authorized it was withdrawn — a fail-OPEN.
    //
    // The Go control plane assigns config_generation from a monotone commit
    // counter (`Manager.bumpGeneration`, only ever ++, never resets) and
    // fib_generation from the monotone shim FIB counter (`readFIBGeneration`,
    // only ever ++). A full apply strictly advances config (fib carried
    // forward), a route-only overlay advances fib with config reused (that path
    // is `bump_fib`). So the guard REFUSES only a STRICTLY-LESS (superseded)
    // pair — one whose config rolls back (`generation < cur`) OR whose fib rolls
    // back under a reused config (`generation == cur && fib_generation <
    // cur_fib`) — and ADMITS everything else:
    //   * a config advance (any fib — a strictly greater config was, by the
    //     global monotonicity this guard enforces, never published, so no cache
    //     entry can equality-match it),
    //   * a same-config fib advance (the route-only overlay), and
    //   * an EXACT-EQUAL re-apply (`generation == cur && fib_generation ==
    //     cur_fib`).
    // Exact-equal is admitted because it revives NOTHING: an equal pair
    // equality-matches only the CURRENT published pair, whose cache entries are
    // already valid, so re-publishing it changes no validity. The revival
    // fail-open requires re-publishing a SUPERSEDED (strictly-less) pair, which
    // the `<` refusal still catches. Admitting exact-equal also restores the
    // #4036 "timeout-but-landed" IDEMPOTENT RETRY: the republish Go paths
    // (UpdatePolicyScheduleState, PublishRouteOverlaySnapshot,
    // retryDeferredWorkerArmLocked) commit `m.generation` only on Go-observed
    // success and do NOT consult `lastStatus.LastSnapshotGeneration`, so a
    // timeout-but-landed apply of gen G leaves `m.generation` at G-1 and the
    // retry re-sends gen G — which must be ACKed ok when it carries the SAME
    // content, not fail-closed into a non-converging loop. This mirrors
    // `bump_fib`, which refuses a STRICTLY-less fib and admits an equal one
    // (`Coordinator::bump_fib_generation`, `<` not `<=`). An earlier revision
    // of this comment also listed Compile; that was wrong (#9520): Compile
    // bumps the generation inline at build time and never reuses one.
    //
    // #9520: "the SAME content" is CHECKED, not assumed — see the content
    // identity gate after the rollback refusal below. The retry REBUILDS its
    // content (routes, scheduler bits), and the equal pair used to be admitted
    // on the claim that it "revives nothing". That holds only for equal
    // CONTENT: flow-cache entries are stamped with the pair, and session policy
    // stamps and the #8356 re-derivation with the config generation alone, so
    // new content under a reused generation leaves every decision made for the
    // old content fresh.
    //
    // Compare against the last PUBLISHED pair in `guard.status`, not the afxdp
    // ValidationState: config_generation has no coordinator accessor (only fib
    // does), and a disarmed apply advances `guard.status` but NOT
    // ValidationState — `guard.status` is the authoritative published pair the
    // armed flow-cache's ValidationState is derived from, so guard and cache
    // agree. Gate on a prior published snapshot: the first apply
    // (`guard.snapshot` == None) has no baseline and no cache entries to revive,
    // so it always applies (matching `bump_fib` admitting the first bump against
    // generation 0). Refuse fail-CLOSED before ANY guard mutation / preflight /
    // side effect, mirroring the #3766/#3789 capture-restore legs below.
    if guard.snapshot.is_some() {
        let cur_generation = guard.status.last_snapshot_generation;
        let cur_fib_generation = guard.status.last_fib_generation;
        let monotonic = snapshot.generation > cur_generation
            || (snapshot.generation == cur_generation
                && snapshot.fib_generation >= cur_fib_generation);
        if !monotonic {
            response.ok = false;
            response.error = format!(
                "snapshot generation rollback rejected: ({}, {}) < current ({}, {})",
                snapshot.generation,
                snapshot.fib_generation,
                cur_generation,
                cur_fib_generation
            );
            eprintln!(
                "CTRL_REQ: apply_snapshot rejected (generation rollback): ({}, {}) < current ({}, {})",
                snapshot.generation,
                snapshot.fib_generation,
                cur_generation,
                cur_fib_generation
            );
            return;
        }
        // #9520: content identity for a REUSED generation. Every Go full apply
        // puts new content on a generation no earlier successful apply used
        // (Compile bumps inline, the republish paths send m.generation + 1, the
        // deferred sync publishes m.lastSnapshot at a generation assigned by
        // m.generation++), so a same-generation apply is only ever a retry of
        // an attempt that landed without Go observing it. Refuse it when its
        // digest differs from the installed snapshot's, at ANY fib: a
        // (G, F' > F) apply passes the gate above as a fib advance, but the
        // session policy stamp is generation-only, so different content there
        // is as unsafe as at (G, F). The refusal precedes every mutation, and
        // its prefix proves to Go that this helper HOLDS the generation, which
        // is what lets Go advance past it instead of re-sending it forever. An
        // identical, non-empty digest (the #4036 retry) falls through and is
        // ACKed.
        if snapshot.generation == cur_generation {
            let installed_digest = guard
                .snapshot
                .as_ref()
                .map_or("", |installed| installed.content_digest.as_str());
            // An EMPTY digest never proves identity: two applies without one
            // compare equal as strings whatever their content, which is the
            // content-blind admission this gate closes. `update_fabrics` and
            // `update_neighbors` clear the installed digest when they change
            // enforced content, so an empty one also means the installed
            // snapshot vouches for no full apply. Go stamps every apply_snapshot,
            // so a real Go retry never trips this arm.
            if installed_digest.is_empty() || installed_digest != snapshot.content_digest {
                response.ok = false;
                response.error = format!(
                    "{} generation {} is installed with content digest {:?}; this apply carries {:?}",
                    SNAPSHOT_CONTENT_CONFLICT_PREFIX,
                    cur_generation,
                    installed_digest,
                    snapshot.content_digest
                );
                eprintln!(
                    "CTRL_REQ: apply_snapshot rejected (content conflict): {}",
                    response.error
                );
                return;
            }
        }
    }
    // #1606 (AGY r2 finding 4.1): preflight policy-state validation
    // BEFORE any guard.status mutation. If the snapshot has
    // duplicate / zero / unknown book IDs, reject WITHOUT touching
    // any guard fields. The existing snapshot + workers stay
    // running on the previous good config.
    //
    // Uses a scratch counter store so we don't leak Arc entries on
    // rejected snapshots.
    {
        let preflight_counters = crate::policy::PolicyCounterStore::default();
        // #3402: resolve policy zones against the INCOMING snapshot's own zones,
        // NOT the live forwarding table (empty on a fresh boot, stale on a
        // new-zone apply) — populate_zones(snapshot) runs only later inside
        // build_forwarding_state. Using the live table here would flag every
        // concrete-zone policy as UnresolvableZoneReference and reject the whole
        // boot snapshot.
        let preflight_zones = crate::policy::zone_name_to_id_from_snapshot(&snapshot.zones);
        if let Err(err) = crate::policy::parse_policy_state_with_counters(
            &snapshot.default_policy,
            &snapshot.policies,
            &preflight_zones,
            &snapshot.address_books,
            &preflight_counters,
        ) {
            response.ok = false;
            response.error = format!("snapshot integrity error: {}", err);
            eprintln!(
                "CTRL_REQ: apply_snapshot rejected (integrity preflight): {}",
                err
            );
            return;
        }
    }
    eprintln!(
        "CTRL_REQ: apply_snapshot generation={} fib_generation={} forwarding_armed_before={}",
        snapshot.generation, snapshot.fib_generation, guard.status.forwarding_armed
    );
    // #3766: capture the prior status-reporting fields BEFORE the bump
    // so the same-plan refresh leg can restore them if the fallible
    // forwarding build rejects the snapshot (fail closed — a rejected
    // snapshot must not advance the reported generation/capabilities
    // against the still-live prior forwarding table).
    let prev_last_snapshot_generation = guard.status.last_snapshot_generation;
    let prev_last_fib_generation = guard.status.last_fib_generation;
    let prev_last_snapshot_at = guard.status.last_snapshot_at;
    guard.status.last_snapshot_generation = snapshot.generation;
    guard.status.last_fib_generation = snapshot.fib_generation;
    guard.status.last_snapshot_at = Some(snapshot.generated_at);
    let prev_capabilities =
        std::mem::replace(&mut guard.status.capabilities, snapshot.capabilities.clone());
    let existing_bindings = guard.status.bindings.clone();
    let previous_defer_workers = guard
        .snapshot
        .as_ref()
        .is_some_and(|prev| prev.defer_workers);
    let same_plan = guard.snapshot.as_ref().is_some_and(|prev| {
        let prev_key = snapshot_binding_plan_key(prev);
        let next_key = snapshot_binding_plan_key(&snapshot);
        let same = prev_key == next_key;
        if !same {
            eprintln!(
                "CTRL_REQ: binding plan changed prev_key={} next_key={}",
                prev_key, next_key
            );
        }
        same
    });
    if same_plan {
        let needs_reconcile = same_plan_apply_needs_binding_reconcile(
            guard,
            previous_defer_workers,
            snapshot.defer_workers,
        );
        if needs_reconcile {
            eprintln!("CTRL_REQ: same-plan apply_snapshot reconciling deferred bindings");
            // #3789: the deferred-binding reconcile runs the FALLIBLE
            // pre-teardown build (build_reconcile_forwarding). A snapshot
            // that passed the policy preflight above can still fail a
            // non-policy integrity check (invalid interface address, CoS
            // queue, NAT64 / NPTv6 rule, ...) or a mandatory-map open.
            // Per #2440/#2484 the reconcile aborts BEFORE teardown, so the
            // prior workers + forwarding + generation stay live. Mirror the
            // same-plan refresh leg (#3766): install the new snapshot for
            // the reconcile, but on failure restore the prior snapshot +
            // status fields, report ok=false, and do NOT persist — a
            // rejected snapshot must never become the boot baseline nor be
            // acked ok=true.
            let prev_snapshot = std::mem::replace(&mut guard.snapshot, Some(snapshot));
            if let Err(err) = reconcile_status_bindings(guard) {
                guard.snapshot = prev_snapshot;
                guard.status.last_snapshot_generation = prev_last_snapshot_generation;
                guard.status.last_fib_generation = prev_last_fib_generation;
                guard.status.last_snapshot_at = prev_last_snapshot_at;
                guard.status.capabilities = prev_capabilities;
                response.ok = false;
                // #4952 / #5143: distinguish the POST-TEARDOWN worker-bringup
                // failures (old workers gone, dataplane down — refresh status
                // to the real per-binding state) from the pre-teardown
                // integrity faults (prior workers still live). Both
                // post-teardown classes — a worker that failed to SPAWN
                // (#4952) and a worker that spawned but bound an INCOMPLETE
                // queue set / never reported readiness (#5143) — fail closed
                // the SAME way: refresh status, do NOT persist. Only the
                // message differs from the pre-teardown integrity faults.
                if let crate::afxdp::ReconcileError::WorkerSpawn(stage)
                | crate::afxdp::ReconcileError::WorkerBindIncomplete(stage) = &err
                {
                    // Distinct verb per class (the #4952 tests pin "worker
                    // spawn failed"); both fail closed identically.
                    let verb = if matches!(err, crate::afxdp::ReconcileError::WorkerBindIncomplete(_))
                    {
                        "worker bind incomplete"
                    } else {
                        "worker spawn failed"
                    };
                    response.error = format!(
                        "{verb} after teardown ({stage}); dataplane down — snapshot not persisted"
                    );
                    refresh_status(guard);
                    eprintln!(
                        "CTRL_REQ: same-plan apply_snapshot rejected (post-teardown worker bring-up failure): {stage} — dataplane down, NOT persisting"
                    );
                } else {
                    response.error = format!("snapshot integrity error: {}", err);
                    eprintln!(
                        "CTRL_REQ: same-plan apply_snapshot rejected (integrity build): {} — keeping previous state",
                        err
                    );
                }
                return;
            }
        } else {
            // #1866 (PR-review Codex r1 F1 + r2): refresh_runtime_snapshot
            // reconciles WG control threads for the running case
            // (Copilot C1, #1432) — but a DISARMED helper must not
            // spawn/bind them even transiently (the control loop binds
            // and may emit a handshake initiation before its first
            // stop check). The disarmed variant refreshes the same
            // forwarding/validation state with the WG spawn pass
            // replaced by a stop, mirroring reconcile_status_bindings.
            // #3766: the same-plan refresh is a FALLIBLE ATOMIC SWAP.
            // A snapshot that passed the policy preflight above can
            // still fail the full forwarding build (invalid interface
            // address, CoS queue, NAT64 / NPTv6 rule, ...). On that
            // error the coordinator left the prior good state fully
            // intact (build-first / atomic-swap), so the handler MUST
            // fail closed too: report ok=false, keep the previously
            // stored snapshot as the boot baseline, and do NOT set
            // persist_state. Advancing guard.snapshot / status
            // generation / persisted state here would report a
            // rejected snapshot as the running config.
            let refresh_result = if should_run_afxdp(&guard.status) {
                guard.afxdp.refresh_runtime_snapshot(&snapshot)
            } else {
                guard.afxdp.refresh_runtime_snapshot_disarmed(&snapshot)
            };
            if let Err(err) = refresh_result {
                // Restore the status reporting fields bumped at the top
                // of `apply` so `show`/status never advertise the
                // rejected snapshot's generation against the still-live
                // prior forwarding table.
                guard.status.last_snapshot_generation = prev_last_snapshot_generation;
                guard.status.last_fib_generation = prev_last_fib_generation;
                guard.status.last_snapshot_at = prev_last_snapshot_at;
                guard.status.capabilities = prev_capabilities;
                response.ok = false;
                response.error = format!("snapshot integrity error: {}", err);
                eprintln!(
                    "CTRL_REQ: same-plan apply_snapshot rejected (integrity build): {} — keeping previous state",
                    err
                );
                return;
            }
            guard.snapshot = Some(snapshot);
        }
        refresh_status(guard);
        *persist_state = true;
    } else {
        let defer_workers = snapshot.defer_workers;
        if defer_workers {
            // #5171: a deferred-activation apply (RETH MAC pending) still
            // ACKs + PERSISTS the snapshot as the boot baseline, but before
            // this change it did so WITHOUT running the mandatory-map +
            // forwarding integrity build that the non-defer reconcile path
            // runs (reconcile_status_bindings -> afxdp.reconcile). So a
            // NON-buildable config — bad interface address / CoS queue /
            // NAT64 / NPTv6 rule, or a MISSING/UNOPENABLE mandatory BPF map
            // pin — was acked ok=true and persisted as the boot baseline,
            // only to fail-OPEN at the later deferred bring-up (whose
            // re-apply/rebind failures are warning-only). The disarmed defer
            // apply cannot borrow reconcile_status_bindings for this: with
            // forwarding not yet armed (arming follows the deferred worker
            // bring-up) it takes the disarmed STOP path (afxdp.stop() +
            // Ok(())) — a teardown with no integrity build; and when armed it
            // would spawn workers, violating the defer contract. So run the
            // SAME pre-teardown integrity legs directly (policy preflight +
            // mandatory-map openability + full forwarding build), BEFORE the
            // side-effecting tunnel/WG prunes and the guard.snapshot swap,
            // and fail CLOSED on error. This adds integrity VALIDATION, not
            // activation — the worker spawn stays deferred below.
            if let Err(err) = guard.afxdp.validate_snapshot_buildable(Some(&snapshot)) {
                // Mirror the #3766/#3789 same-plan capture-restore legs:
                // restore the status-reporting fields bumped at the top of
                // `apply`, report ok=false, and do NOT persist. Validation
                // runs BEFORE the guard.snapshot swap and BEFORE any prune,
                // so the prior snapshot stays the boot baseline untouched and
                // nothing was side-effected on the rejected snapshot — only
                // the status generation/capabilities bump is unwound here.
                guard.status.last_snapshot_generation = prev_last_snapshot_generation;
                guard.status.last_fib_generation = prev_last_fib_generation;
                guard.status.last_snapshot_at = prev_last_snapshot_at;
                guard.status.capabilities = prev_capabilities;
                response.ok = false;
                response.error = format!("snapshot integrity error: {}", err);
                eprintln!(
                    "CTRL_REQ: apply_snapshot defer_workers rejected (integrity build): {} — keeping previous state",
                    err
                );
                return;
            }
            // #1866 Change 2b (D4): the defer branch stores the snapshot
            // WITHOUT reconciling, leaving the coordinator's forwarding
            // (and so its WG desired set) stale until the deferred
            // bring-up. A WG endpoint REMOVED by this apply must still
            // release its control thread + UDP port NOW — narrow
            // prune-only reconcile against the new snapshot (no spawn,
            // no forwarding mutation).
            guard.afxdp.prune_wg_control_threads_for_snapshot(&snapshot);
            // #1881: same removal propagation for GRE local-origin
            // threads — a removed/mode-flipped tunnel's thread must
            // release its TUN reader fd NOW, not at the deferred
            // bring-up (the Go side is deleting the netdev).
            guard
                .afxdp
                .prune_local_tunnel_sources_for_snapshot(&snapshot);
        }
        let prev_snapshot = std::mem::replace(&mut guard.snapshot, Some(snapshot));
        let replanned = replan_queues(
            guard.snapshot.as_ref(),
            guard.status.workers,
            &existing_bindings,
            // #6749: new slots inherit the box's current arm state rather than
            // coming up unarmed and disabling every other binding with them.
            guard.status.forwarding_armed,
        );
        guard.status.bindings = replanned;
        if defer_workers {
            eprintln!(
                "CTRL_REQ: apply_snapshot defer_workers=true — skipping worker spawn (RETH MAC pending)"
            );
        } else if let Err(err) = reconcile_status_bindings(guard) {
            if let crate::afxdp::ReconcileError::WorkerSpawn(stage)
            | crate::afxdp::ReconcileError::WorkerBindIncomplete(stage) = &err
            {
                // #4952 / #5143: POST-TEARDOWN worker-bringup failure — a
                // worker that failed to SPAWN (#4952) or one that spawned but
                // bound an INCOMPLETE queue set / never reported readiness
                // (#5143). Unlike the pre-teardown integrity/map faults below
                // — where the old workers + forwarding stayed live and
                // restoring the prior bindings is truthful — here tear_down
                // already stopped the old workers and the new bring-up did not
                // produce a full XSK-bound worker set, so this queue set has NO
                // XSK-bound worker: the data plane is DOWN. Fail closed so the
                // broken snapshot is NOT persisted as the boot baseline. Roll
                // the in-memory baseline back to the prior good snapshot +
                // status generation (a retry / forwarding toggle then
                // reconciles last-good), but DO NOT restore existing_bindings —
                // refresh_status must report the REAL post-teardown per-binding
                // state, not the pre-teardown workers that no longer exist.
                guard.snapshot = prev_snapshot;
                guard.status.last_snapshot_generation = prev_last_snapshot_generation;
                guard.status.last_fib_generation = prev_last_fib_generation;
                guard.status.last_snapshot_at = prev_last_snapshot_at;
                guard.status.capabilities = prev_capabilities;
                response.ok = false;
                // Distinct verb per class (the #4952/#6140 tests pin "worker
                // spawn failed"); both fail closed identically.
                let verb =
                    if matches!(err, crate::afxdp::ReconcileError::WorkerBindIncomplete(_)) {
                        "worker bind incomplete"
                    } else {
                        "worker spawn failed"
                    };
                response.error = format!(
                    "{verb} after teardown ({stage}); dataplane down — snapshot not persisted"
                );
                refresh_status(guard);
                eprintln!(
                    "CTRL_REQ: apply_snapshot rejected (post-teardown worker bring-up failure): {stage} — dataplane down, NOT persisting"
                );
                return;
            }
            // #3789: full-reconcile leg fail-closed (the #2484 domain, out
            // of #3766's same-plan-refresh scope). reconcile_status_bindings
            // ran the fallible pre-teardown build; on a non-policy integrity
            // failure — or a missing / unopenable mandatory map pin — the
            // reconcile aborted BEFORE teardown (#2440/#2484), so the prior
            // workers + forwarding + generation are still live. Restore the
            // prior snapshot, bindings, and status-reporting fields, report
            // ok=false, and do NOT persist — the rejected snapshot must not
            // become the boot baseline nor be acked ok=true.
            guard.snapshot = prev_snapshot;
            guard.status.bindings = existing_bindings;
            guard.status.last_snapshot_generation = prev_last_snapshot_generation;
            guard.status.last_fib_generation = prev_last_fib_generation;
            guard.status.last_snapshot_at = prev_last_snapshot_at;
            guard.status.capabilities = prev_capabilities;
            response.ok = false;
            response.error = format!("snapshot integrity error: {}", err);
            eprintln!(
                "CTRL_REQ: apply_snapshot rejected (integrity build): {} — keeping previous state",
                err
            );
            return;
        }
        refresh_status(guard);
        *persist_state = true;
    }
}

pub(super) fn bump_fib(
    guard: &mut ServerState,
    snapshot: Option<&ConfigSnapshot>,
    response: &mut ControlResponse,
    persist_state: &mut bool,
) {
    // Lightweight FIB generation bump without a full snapshot.
    // Updates the generation counter so workers invalidate stale
    // flow cache entries, without the cost of rebuilding and
    // transmitting the entire config snapshot.
    let Some(snapshot) = snapshot else {
        response.ok = false;
        response.error = "missing snapshot".to_string();
        return;
    };
    // #3767 H4: version gate, mirroring `apply` above. bump_fib mutates
    // dataplane validation state (status + stored snapshot + worker FIB
    // generation), so a mixed-version / corrupt client (which serializes
    // version=0) must be rejected BEFORE any mutation, exactly as a full
    // apply_snapshot is. The Go `Manager.BumpFIBGeneration` now stamps the
    // bump snapshot with the protocol version so a legitimate bump passes.
    if snapshot.version != CONFIG_SNAPSHOT_PROTOCOL_VERSION {
        response.ok = false;
        response.error = format!(
            "unsupported snapshot protocol version {} (want {})",
            snapshot.version, CONFIG_SNAPSHOT_PROTOCOL_VERSION
        );
        return;
    }
    // #3767 H5: refuse a generation ROLLBACK. Flow-cache validation is
    // equality based, so publishing a strictly-lower fib_generation would
    // revive cache entries a prior bump already invalidated (see
    // Coordinator::bump_fib_generation). The coordinator owns the
    // monotonicity invariant and leaves its validation state untouched on
    // refusal; fail closed here too — do NOT advance the reported status /
    // stored snapshot and do NOT persist.
    if !guard.afxdp.bump_fib_generation(snapshot.fib_generation) {
        response.ok = false;
        response.error = format!(
            "fib generation rollback rejected: {} < current {}",
            snapshot.fib_generation,
            guard.afxdp.fib_generation()
        );
        return;
    }
    guard.status.last_fib_generation = snapshot.fib_generation;
    if let Some(ref mut snap) = guard.snapshot {
        snap.fib_generation = snapshot.fib_generation;
    }
    refresh_status(guard);
    // #3767 M2: persist the accepted bump. Previously bump_fib mutated
    // guard.status.last_fib_generation and guard.snapshot.fib_generation in
    // RAM only (no persist_state), so a route-only overlay bump to gen N left
    // the on-disk state at gen N-1 — a helper/host restart then booted from a
    // stale FIB generation the control plane already considered applied.
    *persist_state = true;
}
