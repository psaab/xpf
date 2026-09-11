//! #1328 Phase 2 — snapshot apply phase.
//!
//! Originally pure code motion from the middle of the pre-#1328
//! monolithic `Coordinator::reconcile` body: install
//! validation/forwarding state, re-arm slow path, publish HA-fabrics
//! snapshot, then open the required BPF map FDs.
//!
//! #2440 ordering invariant: the mandatory BPF map FDs
//! (xsk/heartbeat/sessions) — the real correctness boundary — are now
//! opened by [`preflight_map_fds`], which the orchestrator
//! (`reconcile/mod.rs`) runs BEFORE worker teardown and BEFORE any
//! publish. `apply_snapshot` therefore receives the already-secured
//! FDs and only runs once bring-up is guaranteed possible. A
//! mandatory-FD failure aborts in the preflight WITHOUT tearing down
//! the prior workers or publishing a newer forwarding generation, so a
//! snapshot whose required pins are missing/unopenable can never strand
//! the helper advertising a data-plane view backed by no workers
//! (fail-open partial apply). On any missing-pin or open-failure
//! `preflight_map_fds` sets `last_reconcile_stage` plus
//! per-registered-binding `last_error` (matching the pre-#1328 messages
//! verbatim) and returns `None`; the orchestrator bails before
//! `tear_down`.
use super::ReconcileSnapshotFds;
// Re-use afxdp scope (coordinator/mod.rs uses the same pattern).
use super::super::super::*;
use super::super::Coordinator;
use crate::protocol::snapshot::MapPins;
use std::collections::BTreeMap;
use std::sync::Arc;

/// #6243: every snapshot BPF map FD opened by [`open_snapshot_maps`], held
/// together until the whole seven-pin contract succeeds. The three mandatory
/// FDs (xsk/heartbeat/sessions) are always present; the four optional FDs are
/// `Some` only when their pin was configured (present + openable). The
/// activated caller ([`preflight_map_fds`]) destructures this into a
/// [`ReconcileSnapshotFds`] and KEEPS the FDs; the deferred caller
/// ([`validate_map_pins`]) DROPS it (RAII). That keep-vs-drop is the ONLY
/// difference between the two callers — no `mode` parameter is needed.
struct OpenedSnapshotMaps {
    xsk: OwnedFd,
    heartbeat: OwnedFd,
    sessions: OwnedFd,
    conntrack_v4: Option<OwnedFd>,
    conntrack_v6: Option<OwnedFd>,
    dnat_table: Option<OwnedFd>,
    dnat_table_v6: Option<OwnedFd>,
}

/// #6243: a fault opening the seven snapshot map pins, produced by the single
/// shared [`open_snapshot_maps`]. It carries enough identity to reproduce BOTH
/// operator-visible artifacts the two callers used to build independently:
///
/// - [`stage`](MapPinFault::stage) — the typed #6244 [`ReconcileStage`]
///   (`MissingPin` / `OpenMapFailed`) whose `Display` renders the byte-identical
///   `missing_{token}_pin` / `open_{token}_map_failed:{err}` operator string.
///   Both callers set this (the activated path onto `last_reconcile_stage`, the
///   deferred path wrapped in `ReconcileError::MapSetup`).
/// - [`binding_error`](MapPinFault::binding_error) — the verbatim per-binding
///   `last_error` string the activated path stamps onto every registered
///   binding. Its label root DIVERGES from the stage token for the xsk pin
///   (stage token `xsk`, binding label `XSK`); this type carries the label
///   explicitly so that byte-parity trap lives in exactly one place.
enum MapPinFault {
    /// A mandatory pin (xsk/heartbeat/sessions) was empty. An empty mandatory
    /// pin is always fatal (feature-absent is not an option for a mandatory
    /// pin, unlike the optional pins).
    MissingRequired {
        pin: MandatoryPin,
        /// The per-binding label root — uppercase `XSK`, lowercase
        /// `heartbeat`/`session` — DISTINCT from the lowercase stage token.
        binding_label: &'static str,
    },
    /// A pin (mandatory OR a PRESENT optional) failed to open. `map` is the
    /// lowercase `OpenMapFailed { map }` stage token; `binding_label` is the
    /// per-binding label root (they differ only for xsk). `err` is the opened
    /// error rendered to `String` once, so `stage()` and `binding_error()`
    /// render byte-identically from the same text.
    Open {
        map: &'static str,
        binding_label: &'static str,
        err: String,
    },
}

impl MapPinFault {
    /// Build the typed #6244 [`ReconcileStage`] — the ONLY place both callers
    /// derive the failure identity. Inherits #6244's byte-identical `Display`.
    fn stage(&self) -> ReconcileStage {
        match self {
            MapPinFault::MissingRequired { pin, .. } => ReconcileStage::MissingPin(*pin),
            MapPinFault::Open { map, err, .. } => ReconcileStage::OpenMapFailed {
                map,
                err: err.clone(),
            },
        }
    }

    /// The verbatim per-binding `last_error` string (test-locked in
    /// `coordinator/tests.rs`): `missing {label} map pin path` for an empty
    /// mandatory pin, `open {label} map: {err}` for an open failure. The
    /// uppercase `XSK` label root is preserved here (vs the lowercase `xsk`
    /// stage token) — the #6243 byte-parity trap.
    fn binding_error(&self) -> String {
        match self {
            MapPinFault::MissingRequired { binding_label, .. } => {
                format!("missing {binding_label} map pin path")
            }
            MapPinFault::Open {
                binding_label, err, ..
            } => format!("open {binding_label} map: {err}"),
        }
    }
}

/// #6243: THE single opener for the seven snapshot BPF map pins — the shared
/// source of truth both the activated reconcile ([`preflight_map_fds`]) and the
/// deferred-apply validation ([`validate_map_pins`]) route through, so they can
/// never drift on which snapshots pass the map-pin gate or how a fault is
/// classified.
///
/// PURE: it opens FDs and returns them (or a typed [`MapPinFault`]); it mutates
/// no coordinator/binding state and writes no `last_reconcile_stage`. The
/// side-effect stamping is a cold adapter on the activated caller.
///
/// Canonical order (fixes the two pre-#6243 divergences, both normalizing the
/// deferred path toward the activated SSOT, both still fail-closed):
///
/// 1. TWO-PASS mandatory precedence: check ALL THREE mandatory pins for
///    emptiness first (xsk -> heartbeat -> session), THEN open the three in the
///    same order. A multi-fault snapshot (an earlier mandatory pin
///    present-but-unopenable + a later one empty) therefore reports the SAME
///    stage from both callers. The old one-pass deferred walk
///    (check-empty-then-open per pin) instead reported the earlier pin's open
///    failure where the activated two-pass reported the later pin's emptiness.
/// 2. FD RETENTION: every opened FD is held in [`OpenedSnapshotMaps`] until the
///    WHOLE contract succeeds. The old deferred walk dropped each FD
///    immediately, so under FD-table pressure a later open could succeed where
///    the activated path (holding all earlier FDs simultaneously) failed.
///    Holding them here gives the deferred path the identical low-FD failure.
///
/// Requiredness (#2444): the 3 mandatory pins are fatal if empty; the 4
/// optional pins (conntrack v4/v6, dnat tables) are silent-absent if empty but
/// FATAL if present-but-unopenable. On any mandatory fault or present-optional
/// open failure it returns `Err` (never a partial `Ok`), so the caller aborts
/// BEFORE teardown/publish (#2440).
///
/// RAII single-close: `OwnedFd` is the non-`Clone` sole owner of its fd and
/// closes it on `Drop`, so a later open failure drops every earlier-opened FD
/// exactly once — enforced STRUCTURALLY by ownership, not a runtime assertion.
fn open_snapshot_maps(pins: &MapPins) -> Result<OpenedSnapshotMaps, MapPinFault> {
    // Pass 1: all mandatory pins must be non-empty (xsk -> heartbeat ->
    // session). Checking all three for emptiness BEFORE opening any is the
    // canonical two-pass precedence.
    if pins.xsk.is_empty() {
        return Err(MapPinFault::MissingRequired {
            pin: MandatoryPin::Xsk,
            binding_label: "XSK",
        });
    }
    if pins.heartbeat.is_empty() {
        return Err(MapPinFault::MissingRequired {
            pin: MandatoryPin::Heartbeat,
            binding_label: "heartbeat",
        });
    }
    if pins.sessions.is_empty() {
        return Err(MapPinFault::MissingRequired {
            pin: MandatoryPin::Session,
            binding_label: "session",
        });
    }
    // Pass 2: open the three mandatory pins in the same order. Each opened FD
    // is held in a local; if a later open fails, `?` returns Err and the
    // earlier FDs drop (RAII single-close).
    let xsk = OwnedFd::open_bpf_map(&pins.xsk).map_err(|err| MapPinFault::Open {
        map: "xsk",
        binding_label: "XSK",
        err: err.to_string(),
    })?;
    let heartbeat = OwnedFd::open_bpf_map(&pins.heartbeat).map_err(|err| MapPinFault::Open {
        map: "heartbeat",
        binding_label: "heartbeat",
        err: err.to_string(),
    })?;
    let sessions = OwnedFd::open_bpf_map(&pins.sessions).map_err(|err| MapPinFault::Open {
        map: "session",
        binding_label: "session",
        err: err.to_string(),
    })?;
    // Optional pins (#2444 empty-vs-present discipline): an empty pin is a
    // genuinely-absent feature (`Ok(None)`, the common case); a present pin
    // that fails to open is fatal, exactly like a mandatory pin. All earlier
    // FDs stay held across these opens.
    let conntrack_v4 = open_optional_snapshot_map(&pins.conntrack_v4, "conntrack_v4")?;
    let conntrack_v6 = open_optional_snapshot_map(&pins.conntrack_v6, "conntrack_v6")?;
    let dnat_table = open_optional_snapshot_map(&pins.dnat_table, "dnat_table")?;
    let dnat_table_v6 = open_optional_snapshot_map(&pins.dnat_table_v6, "dnat_table_v6")?;
    Ok(OpenedSnapshotMaps {
        xsk,
        heartbeat,
        sessions,
        conntrack_v4,
        conntrack_v6,
        dnat_table,
        dnat_table_v6,
    })
}

/// #6243: open one OPTIONAL snapshot map pin with the #2444 empty-vs-present
/// discipline, folded out of the two former list-walks so both callers share
/// it. Empty pin -> `Ok(None)` (feature absent, no gating). Present pin -> open;
/// an open failure is fatal (`Err(MapPinFault::Open)`, the same fail-closed path
/// as a mandatory pin). The optional pins reuse ONE `&'static str` as both the
/// stage token and the per-binding label (only xsk's two forms diverge).
fn open_optional_snapshot_map(
    pin: &str,
    name: &'static str,
) -> Result<Option<OwnedFd>, MapPinFault> {
    if pin.is_empty() {
        return Ok(None);
    }
    OwnedFd::open_bpf_map(pin)
        .map(Some)
        .map_err(|err| MapPinFault::Open {
            map: name,
            binding_label: name,
            err: err.to_string(),
        })
}

/// #2440: open the mandatory + optional BPF map FDs and surface any
/// missing-pin / open-failure BEFORE the orchestrator tears down the
/// current workers or `apply_snapshot` publishes a newer forwarding
/// generation. The mandatory map open (xsk/heartbeat/sessions) is the
/// real correctness boundary: if any of the three is missing or fails
/// to open, this returns `None` after setting `last_reconcile_stage` +
/// per-registered-binding `last_error` (verbatim pre-#1328 messages),
/// and the orchestrator aborts WITHOUT teardown or publish — the prior
/// generation stays published and the prior workers keep running.
///
/// The optional maps (conntrack v4/v6, dnat tables) are configured
/// per-feature: an EMPTY pin means the feature is absent (silent `None`,
/// the common case), but a PRESENT pin is the signal the feature IS
/// configured, so a present pin that fails to open is fatal — it aborts
/// the reconcile via the same fail-closed path as a mandatory map (#2444,
/// codex review-033 033-23). This prevents the helper from running
/// degraded (lost session zone/iface visibility; broken embedded-ICMP NAT
/// reversal → PMTUD/traceroute breakage) with no readiness signal.
pub(super) fn preflight_map_fds(
    coord: &mut Coordinator,
    snapshot: &ConfigSnapshot,
    bindings: &mut [BindingStatus],
) -> Option<ReconcileSnapshotFds> {
    // #6243: open all seven pins through the shared `open_snapshot_maps` (the
    // SSOT both this activated path and the deferred `validate_map_pins` route
    // through). On a fault this is the COLD ADAPTER — the only activated-
    // specific behavior — that stamps `last_reconcile_stage` (from the typed
    // #6244 stage) plus every registered binding's `last_error` (verbatim
    // pre-#1328 message), then aborts before teardown/publish. On success it
    // KEEPS the opened FDs (the deferred caller drops them).
    let maps = match open_snapshot_maps(&snapshot.map_pins) {
        Ok(maps) => maps,
        Err(fault) => {
            coord.last_reconcile_stage = fault.stage();
            let binding_error = fault.binding_error();
            for binding in bindings.iter_mut() {
                if binding.registered {
                    binding.last_error = binding_error.clone();
                }
            }
            return None;
        }
    };
    // Derive the raw dnat fd ints from the retained `OwnedFd`s (still owned by
    // `maps` at this point) BEFORE moving the FDs into the returned bundle.
    let dnat_fds = DnatTableFds {
        v4: maps.dnat_table.as_ref().map(|f| f.fd),
        v6: maps.dnat_table_v6.as_ref().map(|f| f.fd),
    };
    Some(ReconcileSnapshotFds {
        map_fd: maps.xsk,
        heartbeat_map_fd: maps.heartbeat,
        session_map_fd: maps.sessions,
        conntrack_v4_fd: maps.conntrack_v4,
        conntrack_v6_fd: maps.conntrack_v6,
        dnat_table_fd: maps.dnat_table,
        dnat_table_v6_fd: maps.dnat_table_v6,
        dnat_fds,
        // #2484: filled in by `build_reconcile_forwarding`, which the
        // orchestrator runs right after this (still before teardown). A
        // default placeholder until then; the orchestrator never reads it
        // before assigning the real build result.
        forwarding: ForwardingState::default(),
    })
}

/// #2484: build the full forwarding state for `snapshot` BEFORE the
/// orchestrator tears down the running workers. This is the SAME call
/// `apply_snapshot` previously made internally — hoisted ahead of
/// `tear_down` so a snapshot INTEGRITY fault (Nptv6UnparseableRule,
/// NPTv6 overlap / address-book / unresolvable-zone integrity faults
/// reachable only inside the full build, NOT caught by the
/// top-of-reconcile policy preflight; NAT64 is fail-scoped per #3888 and
/// no longer aborts) aborts the reconcile while the prior generation +
/// workers are still live, instead of surfacing post-teardown.
///
/// On success returns the built `ForwardingState` for the orchestrator to
/// stash on `ReconcileSnapshotFds::forwarding` (build-once, reused by
/// `apply_snapshot`). On an integrity error sets
/// `coord.last_reconcile_stage = "snapshot_integrity_error"` (matching the
/// descriptive-stage pattern) and returns `Err(SnapshotIntegrityError)`
/// (#3789: was `Err(())`); the orchestrator aborts WITHOUT teardown or
/// publish and wraps the error in `ReconcileError::Integrity` for the
/// control-plane handler.
///
/// MUST run before `tear_down`: it reads `Some(&coord.forwarding)` as the
/// build's "previous" arg (WG engine reuse, NAT counter carry-over, cold-
/// path slot map carry-over), which `stop_inner(false)` defaults to empty.
pub(super) fn build_reconcile_forwarding(
    coord: &mut Coordinator,
    snapshot: &ConfigSnapshot,
) -> Result<ForwardingState, crate::policy::SnapshotIntegrityError> {
    match build_forwarding_state_with_policy_counters_and_previous(
        snapshot,
        &coord.policy_counters,
        &coord.nat_counters,
        Some(&coord.forwarding),
    ) {
        Ok(fwd) => Ok(fwd),
        Err(err) => {
            coord.last_reconcile_stage = ReconcileStage::SnapshotIntegrityError;
            eprintln!(
                "xpf-userspace-dp: snapshot integrity error during reconcile preflight: {} — keeping previous forwarding state + workers",
                err
            );
            // #3789: return the concrete integrity error (was `()`) so the
            // orchestrator can surface it to the control-plane handler,
            // which fails closed instead of persisting the rejected
            // snapshot.
            Err(err)
        }
    }
}

/// #5171: the #1606/#3402 policy-state preflight, factored out so BOTH
/// `Coordinator::reconcile`'s pre-teardown leg AND the
/// `Coordinator::validate_snapshot_buildable` deferred-apply gate parse the
/// policy state through the identical path — the two can never drift on
/// which snapshots pass the policy check.
///
/// Resolves policy zones against the INCOMING snapshot's own zones
/// (`zone_name_to_id_from_snapshot`), NOT `self.forwarding.zone_name_to_id`
/// (the live table is empty on a fresh boot / HA standby first sync and
/// stale on a new-zone apply; `populate_zones(snapshot)` runs only later in
/// `build_forwarding_state`). Validating against the live table would flag
/// every concrete-zone policy as `UnresolvableZoneReference` and reject the
/// whole snapshot. Parses into a SCRATCH counter store (#1606 Codex r1 F2)
/// so a rejected snapshot leaks no `Arc<PolicyRuleCounter>` handles into any
/// live store. The parsed state is discarded — this is a preflight, the real
/// parse happens later inside `build_forwarding_state`.
pub(super) fn preflight_policy_state(
    snapshot: &ConfigSnapshot,
) -> Result<(), crate::policy::SnapshotIntegrityError> {
    let preflight_counters = crate::policy::PolicyCounterStore::default();
    let preflight_zones = crate::policy::zone_name_to_id_from_snapshot(&snapshot.zones);
    crate::policy::parse_policy_state_with_counters(
        &snapshot.default_policy,
        &snapshot.policies,
        &preflight_zones,
        &snapshot.address_books,
        &preflight_counters,
    )
    .map(|_| ())
}

/// #5171/#6243: side-effect-free validation that every MANDATORY BPF map pin
/// (xsk/heartbeat/sessions) is present and openable, and every PRESENT optional
/// pin (conntrack v4/v6, dnat tables) is openable.
///
/// #6243: this now routes through the SAME [`open_snapshot_maps`] the activated
/// [`preflight_map_fds`] uses, then DROPS the returned bundle (`.map(|_| ())`)
/// — RAII closes every opened FD — and maps the typed [`MapPinFault`] to the
/// same `ReconcileStage` via `fault.stage()`, wrapped in
/// `ReconcileError::MapSetup`. It keeps NO FDs, mutates no `bindings`, and
/// writes no `last_reconcile_stage`; openability is the only signal a
/// validate-only path needs. Sharing the opener closes two pre-#6243
/// divergences (both fail-closed, both normalized toward the activated SSOT):
///
/// - the deferred walk was ONE-pass (empty-then-open per pin) while activated
///   was TWO-pass, so a multi-fault snapshot could report a DIFFERENT stage
///   from each path; the shared two-pass order makes them identical.
/// - the deferred walk dropped each FD immediately, so under FD-table pressure
///   it could PASS where activated (retaining all seven FDs) FAILED; the shared
///   bundle now holds every opened FD until the whole contract succeeds, so the
///   deferred path catches the low-FD case too.
///
/// A MISSING/UNOPENABLE mandatory (or present-optional) pin is the #5171
/// headline fail-open a deferred apply must reject before ack/persist.
pub(super) fn validate_map_pins(snapshot: &ConfigSnapshot) -> Result<(), super::ReconcileError> {
    open_snapshot_maps(&snapshot.map_pins)
        // Drop the retained FD bundle (RAII single-close) — the deferred gate
        // only needs the Ok/Err verdict, never the FDs.
        .map(|_| ())
        .map_err(|fault| super::ReconcileError::MapSetup(fault.stage()))
}

/// #5171: side-effect-free forwarding-build integrity validation. Runs the
/// SAME `build_forwarding_state_with_policy_counters_and_previous` build
/// that `build_reconcile_forwarding` runs — so the two paths reject the
/// identical non-buildable snapshots (invalid interface address, CoS queue,
/// NPTv6 rule, ...) with no drift — but with SCRATCH policy + NAT counter
/// stores so a rejected snapshot leaks no per-rule counter handles into the
/// LIVE stores. The built state is discarded; only its Ok/Err verdict is
/// returned. `WgEngine::new` (invoked inside the build for a WG endpoint) is
/// a pure constructor — no socket bind, no thread spawn — so the discarded
/// build has no observable side effect.
///
/// `previous = None` is DELIBERATE (rev-5605 review fold): the real
/// `build_reconcile_forwarding` passes `Some(&coord.forwarding)` for
/// carry-over (NAT/source-NAT allocator reuse, cold-path slot retention,
/// zone-counter totals). But `ForwardingState::zone_counter_store` is a
/// `Clone`-shares-the-inner-`Arc<Mutex>` store, so handing a VALIDATION build
/// the live state hands it the live map, and the build writes to it.
///
/// **The harm this prevents changed shape in the #6832 r5 fold, and the
/// conclusion survived the change — read the current reason, not the old one.**
/// Until r5 the build ran `state.zone_counter_store.reconcile(&configured)`, an
/// in-place `retain` under the shared lock, so a validation build with
/// `Some(&coord.forwarding)` would have PRUNED the live published store,
/// dropping cumulative per-zone totals for any zone absent from the candidate
/// and silently resetting `show security zones` / REST / Prometheus. That
/// specific harm is gone: the destructive prune now lives in
/// `forwarding_build::commit_zone_counter_prune`, which only an APPLY path
/// calls at its commit point, and which this validation gate never invokes.
///
/// What remains is the ADDITIVE half, and it is still a reason not to relax
/// this. `attach_zone_counters` get-or-creates a block per SLOT-ASSIGNED zone
/// (`ZoneCounterSlotMap::build` skips zone id 0 and stops at
/// `ZONE_COUNTER_ASSIGNABLE_SLOTS`, so it is a subset of the configured set).
/// With `Some(&coord.forwarding)` every validation build — including one whose
/// deferred apply never happens — would leave a zero-valued block per
/// candidate-only zone in the live map: the #6995 residue class, invisible to
/// the sparse `snapshot()` and evicted only by the next committed prune.
/// `None` gives the discarded build FRESH stores, so it touches no live state
/// at all, which is the stronger and simpler guarantee.
///
/// #5716 NARROWED this, it did NOT subsume it. A build that REJECTS the
/// snapshot touches the store not at all. A validation build that ACCEPTS
/// still runs `attach_zone_counters` and would still write to the live store —
/// and "accepted" is the common case here, since this gate exists to admit
/// deferred applies. `previous = None` therefore remains load-bearing; do not
/// relax it, and do not relax it on the grounds that the prune moved.
///
/// Verdict PARITY with reconcile is preserved: NONE
/// of the fallible integrity legs (duplicate-zone-id, tunnel TTL, interface
/// address, egress, route family/preference, neighbor family, NPTv6, filter
/// unresolvable-token, CoS queue-id) reads `previous` for its accept/reject
/// decision — every one faults on snapshot CONTENT only; `previous` feeds
/// carry-over exclusively, which is irrelevant for a discarded build.
pub(super) fn validate_forwarding_buildable(
    snapshot: &ConfigSnapshot,
) -> Result<(), super::ReconcileError> {
    build_forwarding_state_with_policy_counters_and_previous(
        snapshot,
        &crate::policy::PolicyCounterStore::default(),
        &crate::nat::NatCounterStore::default(),
        None,
    )
    .map(|_| ())
    .map_err(super::ReconcileError::Integrity)
}

/// #5801 day-2 slow-path MTU reconcile decision, extracted from
/// [`apply_snapshot`] so the "reprogram the preserved TUN vs. skip" logic is
/// unit-testable without constructing a full [`Coordinator`].
///
/// The reinjector is preserved across snapshot reconciles, so a config MTU
/// change committed after startup must reprogram the RUNNING TUN — otherwise
/// the accepted snapshot advertises a jumbo MTU while the live TUN stays at its
/// startup ceiling and reinjected frames above it drop persistently until xpfd
/// restart. When `desired_mtu` differs from the reinjector's LIVE MTU this
/// calls [`SlowPathReinjector::reconcile_mtu`] to reprogram the live device and
/// converge `mtu()`/`live_mtu`/enqueue admission.
///
/// #6097: the trigger compares `desired_mtu` against `slow_path.status().live_mtu`
/// — the MTU the TUN is ACTUALLY programmed with — NOT `slow_path.mtu()` (the
/// creation-desired value). The two diverge after a STARTUP `SIOCSIFMTU` failure:
/// the worker records `mtu()` at the creation-desired jumbo value (e.g. 9000)
/// while `live_mtu` falls back to 1500 and `degraded` is set. Comparing against
/// `mtu()` there would see `desired == mtu()` and SKIP forever, so the transient
/// startup failure would never self-heal via reconcile (only on a config CHANGE
/// or an xpfd restart). Comparing against `live_mtu` makes a degraded live TUN
/// retry the program on the next reconcile whose desired still equals the
/// creation MTU.
///
/// `last_acted` dedups the attempt to once per distinct desired value (as the
/// old warn-only path did) so a steady-state reconcile loop does not re-issue
/// `SIOCSIFMTU` every tick — critical now that the trigger reads `live_mtu`:
/// when a program PERSISTENTLY fails, `live_mtu` never converges to `desired`,
/// so the `desired != live_mtu` guard alone would retry on every reconcile. The
/// `desired == *last_acted` short-circuit is what bounds a degraded interface to
/// one attempt per distinct desired value; the next DISTINCT desired retries.
/// `programmer` is the `SIOCSIFMTU` seam (`set_if_mtu` in production; injectable
/// in tests). Returns true when a reprogram was attempted this call.
pub(super) fn reconcile_preserved_slow_path_mtu(
    slow_path: &SlowPathReinjector,
    desired_mtu: i32,
    last_acted: &mut i32,
    programmer: impl FnOnce(&str, i32) -> Result<(), String>,
) -> bool {
    if desired_mtu == slow_path.status().live_mtu || desired_mtu == *last_acted {
        return false;
    }
    let live = slow_path.reconcile_mtu(desired_mtu, programmer);
    if live == desired_mtu {
        eprintln!(
            "xpf-ha: slow-path TUN MTU reconciled to {desired_mtu} after a day-2 \
             config change (#5801); reinjected frames up to {desired_mtu} bytes \
             are now accepted."
        );
    }
    // A failed SIOCSIFMTU already logged + marked the path degraded inside
    // reconcile_mtu, which kept the old live MTU. Record the attempted value so
    // a steady-state reconcile loop does not re-issue the ioctl; the next
    // DISTINCT desired value retries.
    *last_acted = desired_mtu;
    true
}

/// `mtu_programmer` is the `SIOCSIFMTU` seam used by the day-2 preserved-TUN MTU
/// reconcile (#5801). Production passes `crate::slowpath::set_if_mtu`; the #6097
/// wiring test injects a deterministic closure so it can assert the preserved
/// reinjector actually reprograms on an MTU delta (a real ioctl is
/// privilege-gated and non-deterministic under `cargo test`). Elevating the
/// previously-hardcoded seam to a parameter is what lets a thin harness bind the
/// `apply_snapshot` CALL SITE — reverting the seam call to the old warn-only
/// block turns that test red.
pub(super) fn apply_snapshot(
    coord: &mut Coordinator,
    snapshot: &ConfigSnapshot,
    preserved_slow_path: Option<Arc<SlowPathReinjector>>,
    prior_tunnel_owners: &[(u16, String)],
    snapshot_was_installed: bool,
    fds: ReconcileSnapshotFds,
    mtu_programmer: impl FnOnce(&str, i32) -> Result<(), String>,
) -> Option<(ReconcileSnapshotFds, Vec<u16>)> {
    // #2484: the forwarding state was already built in the pre-teardown
    // preflight (`build_reconcile_forwarding`) and stashed on
    // `fds.forwarding`. REUSE it here rather than rebuilding — build-once,
    // and (critically) the integrity check that this build performs now
    // happens BEFORE `tear_down`, so an integrity-faulted snapshot aborts
    // the reconcile while the prior generation + workers are still live
    // instead of stranding the helper post-teardown. By the time control
    // reaches `apply_snapshot` the build has already succeeded; there is no
    // longer an integrity Err arm here.
    //
    // The previous #1606 preflight policy-build (and the #2440 Copilot
    // follow-up that stamped `last_reconcile_stage` on its Err arm) moved
    // into `build_reconcile_forwarding` in the orchestrator's pre-teardown
    // stage.
    let mut fds = fds;
    let new_forwarding = std::mem::take(&mut fds.forwarding);

    coord.validation = ValidationState {
        snapshot_installed: true,
        config_generation: snapshot.generation,
        fib_generation: snapshot.fib_generation,
    };
    // #7010: the destructive prune of the policy / NAT hit counters USED to be
    // here, above `bring_up_workers`. It moved to
    // `Coordinator::commit_rule_counter_prune`, which each apply path calls at
    // ITS OWN commit point — the same split #6832 made for the per-zone
    // counters, and for the same measured reason: a build can succeed and the
    // apply still be rejected by a worker spawn failure (#4952) or an
    // incomplete queue bind (#5143), and pruning here destroyed the removed
    // rules' cumulative hit counts for a configuration that never forwarded a
    // packet. Worse than the zone case, which is why it needed its own issue:
    // `stop_inner` defaults `coord.forwarding` and takes the zone store's
    // publisher with it, but `policy_counters` and `nat_counters` are
    // Coordinator fields it never touches — so BOTH bring-up failure arms leaked
    // here, and `nat_rule_counters()` kept serving from the pruned store.
    // #1866 D3: WG endpoint-set transition log at the reconcile apply
    // boundary (mirrors refresh_runtime_snapshot).
    super::super::log_wg_endpoint_set_transition("reconcile", &coord.forwarding, &new_forwarding);
    // #3773 (M13): fabric-skip transition log at the reconcile apply boundary
    // (mirrors the WG log). `coord.forwarding` was defaulted by
    // `stop_inner(false)`, so this names the reconcile build's skipped fabric
    // links; the cumulative malformed/unresolved atomics quantify them.
    super::super::log_fabric_skip_transition(
        "reconcile",
        &coord.forwarding.fabric_skips,
        &new_forwarding.fabric_skips,
    );
    // #1873 R-D: the purge diff runs against the tunnel-owner map
    // captured BEFORE teardown (AGY code r3) — stop_inner(false) has
    // already defaulted coord.forwarding, so diffing the live state
    // here would make every purge arm inert across a reconcile
    // boundary while the preserved shared maps still hold the old
    // entries. The purge is cleanup, not the correctness boundary —
    // re-resolution and the encap builders refuse an id whose owning
    // netdev ifindex differs from the session's stored one (Codex
    // code-review r2; replaces the unsound r1 defer + rotation-barrier
    // design). New-appearance purging is gated on the GENUINE first
    // apply of the helper's life (flag captured before teardown).
    let tunnel_purge_ids = super::super::tunnel_remap_purge_ids_from_owners(
        prior_tunnel_owners,
        &new_forwarding,
        snapshot_was_installed,
    );
    // #8138: release against `new_forwarding`, NOT `coord.forwarding` —
    // `stop_inner(false)` has already defaulted the latter (see the comment
    // above), so it holds no allocators and freeing against it would free
    // nothing. The allocators are carried across the rebuild by `Arc::clone`,
    // so `new_forwarding` names the objects the reservation was taken against.
    coord.purge_remapped_tunnel_sessions(&tunnel_purge_ids, &new_forwarding);
    // #8157: the purge ids travel to the BRINGUP replay instead of being
    // applied to a Vec here. The replay now derives its entries from the live
    // shared map at replay time (see `replay_preserved_sessions`), so the
    // filter has to run there, against that set, using this same predicate —
    // the purged ids AND their derived reverse companions, so the replay
    // cannot resurrect them whole or as half-dead pairs (code r3; companion
    // semantics per AGY code r4).
    //
    // The purge above has already removed them from the live map, so for every
    // entry that existed before it the filter is redundant. It is retained for
    // the one case it still covers: an entry for a purged tunnel that lands in
    // the shared map AFTER this line. That cannot happen today (the
    // snapshot-wide ServerState mutex excludes sync_session for the whole
    // reconcile) and is exactly what #7209 makes reachable, which is why the
    // filter must move rather than be dropped as dead.
    coord.forwarding = new_forwarding;
    // #6592: ONE worker-visible store carrying both halves. `coord.validation`
    // was assigned at the head of this function and `coord.forwarding` is the
    // reconciled table, so this publishes the new generation's coherent pair
    // through the single choke point — see `types/runtime_view.rs`.
    coord.publish_runtime_view();
    coord.slow_path = if let Some(slow_path) = preserved_slow_path {
        // #5801: the preserved reinjector kept the MTU its TUN was created
        // with. A day-2 config MTU change updates the accepted snapshot but
        // NOT the live TUN unless we reprogram it here — otherwise reinjected
        // frames above the startup ceiling drop persistently until xpfd
        // restart. Reprogram the live TUN (and the reinjector's mtu()/
        // live_mtu/admission) to converge, instead of only warning (#2408).
        // First-boot jumbo configs still hit the else branch below.
        reconcile_preserved_slow_path_mtu(
            &slow_path,
            snapshot.slow_path_mtu(),
            &mut coord.last_slow_path_mtu_reconciled,
            mtu_programmer,
        );
        coord.last_slow_path_status = slow_path.status();
        Some(slow_path)
    } else {
        // #2408: size the slow-path TUN to the largest configured
        // data-interface MTU so reinjected jumbo frames are not dropped on
        // the TUN egress (default kernel TUN MTU is 1500).
        match SlowPathReinjector::new(DEFAULT_SLOW_PATH_TUN, snapshot.slow_path_mtu()) {
            Ok(reinjector) => {
                coord.last_slow_path_status = reinjector.status();
                Some(Arc::new(reinjector))
            }
            Err(err) => {
                coord.last_slow_path_status = SlowPathStatus {
                    last_error: err,
                    ..SlowPathStatus::default()
                };
                None
            }
        }
    };
    coord
        .local_tunnel_deliveries
        .store(Arc::new(BTreeMap::new()));
    coord
        .ha
        .fabrics
        .store(Arc::new(coord.forwarding.fabrics.clone()));
    // #2440: the mandatory + optional map FDs were already opened by
    // `preflight_map_fds` BEFORE teardown/publish. By the time we get
    // here bring-up is guaranteed possible, so the publish above is
    // never stranded behind an FD-open failure. Hand the secured FDs to
    // the bring-up phase.
    Some((fds, tunnel_purge_ids))
}

#[cfg(test)]
mod slow_path_mtu_tests {
    use super::*;
    use crate::protocol::snapshot::{ConfigSnapshot, InterfaceSnapshot};
    use crate::slowpath::SlowPathReinjector;

    /// A device name ≥ `IFNAMSIZ` (16) so the reinjector worker's `open_tun`
    /// fails at `IfReq::new` BEFORE any TUN/ioctl syscall and early-returns
    /// WITHOUT writing `live_mtu`/`degraded`. That makes the reinjector's MTU
    /// state driven solely by `force_mtu_state_for_test` / `reconcile_mtu` on the
    /// test thread — no privilege dependence and no race with a worker that (as
    /// root) would otherwise program the real device and clobber the fixture.
    const OVERSIZE_TUN_NAME: &str = "xpf-usp-6097-oversize-name";

    /// #5801 fail-on-revert (WIRING): a day-2 snapshot MTU increase over a
    /// PRESERVED reinjector must reprogram the live TUN through
    /// `reconcile_preserved_slow_path_mtu` — the seam `apply_snapshot` calls in
    /// place of the old warn-only branch. A SUCCEEDING programmer is injected so
    /// no real `SIOCSIFMTU` is issued (unit tests run without CAP_NET_ADMIN);
    /// the assertions are on the reinjector's converged state, which drives
    /// enqueue admission. If the reconcile is reverted to warn-only, `mtu()`
    /// stays at the 1500 startup ceiling and every assertion below fails.
    #[test]
    fn day2_mtu_increase_reprograms_preserved_reinjector() {
        // Constructing the reinjector spawns a worker that tries to open the
        // TUN; whether that open succeeds is irrelevant here — the reconcile
        // path uses the injected programmer and asserts on mtu()/live_mtu,
        // which are set synchronously and read lock-free.
        let reinjector =
            SlowPathReinjector::new_without_worker(1500);
        assert_eq!(reinjector.mtu(), 1500, "reinjector starts at the 1500 ceiling");

        let mut last_acted = 0i32;
        let acted =
            reconcile_preserved_slow_path_mtu(&reinjector, 9000, &mut last_acted, |_n, _m| Ok(()));
        assert!(acted, "a day-2 MTU rise must trigger a live-TUN reconcile");
        assert_eq!(
            reinjector.mtu(),
            9000,
            "the preserved reinjector's live MTU is reprogrammed to the new ceiling"
        );
        assert_eq!(
            reinjector.status().live_mtu,
            9000,
            "enqueue admission (live_mtu) converges to the new ceiling"
        );
        assert!(
            !reinjector.status().degraded,
            "a successful reconcile is not degraded"
        );
        assert_eq!(last_acted, 9000, "the attempted value is recorded for dedup");

        // A steady-state re-apply with the SAME desired value must NOT re-issue
        // the ioctl (the programmer panics if invoked): both the `desired ==
        // mtu()` and `desired == last_acted` guards short-circuit.
        let acted_again =
            reconcile_preserved_slow_path_mtu(&reinjector, 9000, &mut last_acted, |_n, _m| {
                panic!("must not reprogram when the desired MTU is unchanged");
            });
        assert!(!acted_again, "an unchanged MTU must not reconcile again");
    }

    /// #6097 fail-on-revert (item 1, SELF-HEAL): a reinjector left DEGRADED by a
    /// STARTUP `SIOCSIFMTU` failure — `mtu()` at the creation jumbo value (9000)
    /// while the live TUN is stuck at 1500 — must self-heal on the next day-2
    /// reconcile whose desired STILL equals the creation MTU. The trigger
    /// therefore has to compare `desired` against `status().live_mtu` (1500), NOT
    /// `mtu()` (9000): the old `desired == mtu()` guard would short-circuit
    /// forever and the transient startup failure would never retry via reconcile.
    /// A succeeding programmer is injected (no privileged ioctl). Reverting the
    /// trigger to `slow_path.mtu()` makes `desired == mtu()` skip and the heal
    /// assertions below go red.
    #[test]
    fn startup_degraded_tun_self_heals_on_reconcile() {
        let reinjector =
            SlowPathReinjector::new_without_worker(9000);
        // Reproduce the startup-SIOCSIFMTU-failure divergence deterministically:
        // mtu() records the creation-desired 9000, but the live TUN fell back to
        // 1500 and the path is degraded. (A real worker only reaches this via a
        // failing ioctl, which needs CAP_NET_ADMIN to provoke.)
        reinjector.force_mtu_state_for_test(9000, 1500, true);
        assert_eq!(reinjector.mtu(), 9000, "mtu() holds the creation-desired jumbo value");
        assert_eq!(
            reinjector.status().live_mtu,
            1500,
            "but the live TUN is stuck at the 1500 startup fallback"
        );

        let mut last_acted = 0i32;
        // Desired STILL equals the creation MTU (9000) — the config did not change,
        // this is a plain day-2 reconcile. The trigger must fire off live_mtu.
        let acted =
            reconcile_preserved_slow_path_mtu(&reinjector, 9000, &mut last_acted, |_n, _m| Ok(()));
        assert!(acted, "a degraded live TUN must retry the program on reconcile");
        assert_eq!(reinjector.status().live_mtu, 9000, "the live TUN heals to 9000");
        assert!(!reinjector.status().degraded, "a successful heal clears degraded");
        assert_eq!(last_acted, 9000, "the attempted value is recorded for dedup");

        // Converged: a steady-state reconcile at the same desired must NOT re-issue
        // the ioctl (now `desired == live_mtu` short-circuits).
        let again =
            reconcile_preserved_slow_path_mtu(&reinjector, 9000, &mut last_acted, |_n, _m| {
                panic!("must not reprogram once live_mtu has converged");
            });
        assert!(!again, "a converged live TUN must not reconcile again");
    }

    /// #6097 (item 1, DEDUP): with the `live_mtu` trigger a PERSISTENTLY failing
    /// program must still be deduped to ONE attempt per distinct desired value —
    /// otherwise a degraded TUN whose `live_mtu` never converges to `desired`
    /// would re-issue `SIOCSIFMTU` on every reconcile tick (an ioctl storm). The
    /// `last_acted` guard is what bounds it; this proves the dedup survives the
    /// item-1 trigger change from `mtu()` to `live_mtu`.
    #[test]
    fn persistently_degraded_tun_is_deduped_no_ioctl_storm() {
        let reinjector =
            SlowPathReinjector::new_without_worker(9000);
        reinjector.force_mtu_state_for_test(9000, 1500, true);

        let mut last_acted = 0i32;
        // First reconcile at desired 9000: the program FAILS, so live_mtu stays
        // 1500 and degraded stays set (reprogram_mtu_status keeps the live MTU on
        // failure). The attempt is recorded in last_acted.
        let acted =
            reconcile_preserved_slow_path_mtu(&reinjector, 9000, &mut last_acted, |_n, _m| {
                Err("SIOCSIFMTU: simulated persistent failure".to_string())
            });
        assert!(acted, "the first attempt at a distinct desired value runs");
        assert_eq!(
            reinjector.status().live_mtu,
            1500,
            "a failed program keeps the live MTU (never converges)"
        );
        assert!(reinjector.status().degraded, "a failed program stays degraded");
        assert_eq!(last_acted, 9000, "the attempted value is recorded");

        // Second reconcile at the SAME desired: live_mtu is still 1500 (!= 9000),
        // so ONLY the `desired == last_acted` guard prevents a re-attempt. The
        // programmer panics if invoked — proving no per-tick ioctl storm.
        let again =
            reconcile_preserved_slow_path_mtu(&reinjector, 9000, &mut last_acted, |_n, _m| {
                panic!("must not re-issue SIOCSIFMTU for an unchanged desired value");
            });
        assert!(!again, "a persistently degraded TUN is deduped by last_acted");
    }

    /// #6097 fail-on-revert (item 2, WIRING — primary deliverable): drive the
    /// ACTUAL `apply_snapshot` CALL SITE and assert it reprograms a PRESERVED
    /// reinjector on a day-2 MTU delta. `reconcile_preserved_slow_path_mtu` is
    /// unit-tested above, but reverting `apply_snapshot`'s CALL of it back to the
    /// old warn-only block turned no test red — this binds that call. A
    /// succeeding programmer is injected through the `apply_snapshot` seam so the
    /// reprogram is deterministic without a privileged `SIOCSIFMTU`. The hard
    /// gate is `mtu()`, which only `reconcile_mtu` writes (the worker never
    /// touches it) — so it goes red iff the seam call is removed/neutralized,
    /// independent of the worker thread.
    #[test]
    fn apply_snapshot_wires_day2_preserved_mtu_reconcile() {
        let mut coord = Coordinator::new();
        // Oversize name so the preserved reinjector's worker cannot program the
        // real device and race the assertions; its live_mtu stays at the 1500
        // default until reconcile moves it.
        let preserved = Arc::new(
            SlowPathReinjector::new_without_worker(1500),
        );
        assert_eq!(preserved.mtu(), 1500, "preserved reinjector starts at 1500");

        // A snapshot whose largest interface MTU is 9000 -> slow_path_mtu() == 9000.
        let snapshot = ConfigSnapshot {
            interfaces: vec![InterfaceSnapshot {
                mtu: 9000,
                ..Default::default()
            }],
            ..Default::default()
        };
        assert_eq!(
            snapshot.slow_path_mtu(),
            9000,
            "snapshot desires a 9000 slow-path MTU"
        );

        // apply_snapshot only threads these FDs through to the bring-up phase; a
        // dummy fd (-1) never names a real map and Drop's close(-1) is a harmless
        // EBADF no-op.
        let fds = ReconcileSnapshotFds {
            map_fd: OwnedFd { fd: -1 },
            heartbeat_map_fd: OwnedFd { fd: -1 },
            session_map_fd: OwnedFd { fd: -1 },
            conntrack_v4_fd: None,
            conntrack_v6_fd: None,
            dnat_table_fd: None,
            dnat_table_v6_fd: None,
            dnat_fds: DnatTableFds::default(),
            forwarding: ForwardingState::default(),
        };

        let out = apply_snapshot(
            &mut coord,
            &snapshot,
            Some(preserved.clone()),
            &[],
            true,
            fds,
            // Injected succeeding SIOCSIFMTU seam (a real ioctl is privilege-gated
            // and non-deterministic under `cargo test`).
            |_name, _mtu| Ok(()),
        );
        assert!(out.is_some(), "apply_snapshot returns the secured fds");

        let sp = coord
            .slow_path
            .as_ref()
            .expect("apply_snapshot preserved the reinjector");
        assert_eq!(
            sp.mtu(),
            9000,
            "apply_snapshot must reprogram the preserved live TUN to 9000 on the \
             MTU delta (warn-only revert leaves it at 1500)"
        );
        assert_eq!(sp.status().live_mtu, 9000, "enqueue-admission live_mtu converged");
        assert_eq!(
            coord.last_slow_path_status.live_mtu, 9000,
            "the published status snapshot reflects the reconciled MTU"
        );
        assert_eq!(
            coord.last_slow_path_mtu_reconciled, 9000,
            "the dedup field records the reconcile attempt"
        );
    }
}
