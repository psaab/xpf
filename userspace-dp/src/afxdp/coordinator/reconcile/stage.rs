//! #6244: typed reconcile progress + failure identity.
//!
//! Before this, reconcile progress, failure identity, the operator status
//! string, log lines, and control-plane errors were all coupled through a
//! single mutable free-form `Coordinator::last_reconcile_stage: String`.
//! A diagnostic string was a load-bearing transaction channel: map preflight
//! mutated it and the caller cloned it into `ReconcileError::MapSetup`, worker
//! spawn built one string and stored copies in five places, and tests parsed
//! it with `==` / `starts_with` / `contains`. #4952 existed because a
//! success-stage write once erased a failure identity.
//!
//! [`ReconcileStage`] replaces that string as the internal representation.
//! Each write site now records a TYPED value; the legacy operator string is
//! produced in exactly one place — the [`std::fmt::Display`] impl below — and
//! rendered only at the `reconcile_debug` / `debug_reconcile_stage` wire
//! boundary (`status.rs`) and inside `ReconcileError`'s `Display`. The strings
//! are preserved BYTE-FOR-BYTE so no operator tooling, JSON consumer, or wire
//! contract changes.
//!
//! Scope (per the #6244 dedup note): this types the STAGE representation — the
//! transaction channel. The underlying error payloads (`err` on
//! [`ReconcileStage::OpenMapFailed`] / [`ReconcileStage::SpawnWorkerFailed`],
//! the integrity `detail`) stay owned `String`s here; deeper typing of the
//! map-pin / setup errors is the separate #6243 / #6245 work. Failure and
//! progress are now DISTINCT variants, so an error stage can no longer be
//! silently reinterpreted as informal success text.
//!
//! Cold path only: this value is written on the reconcile / status boundary
//! and read at ~1 Hz status polls — never on the packet path. No atomics,
//! locks, callbacks, or trait objects are introduced.

use crate::afxdp::types::BindingSetupFailure;

/// The mandatory BPF map whose pin was missing at preflight. The token
/// renders into the legacy `missing_{token}_pin` string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MandatoryPin {
    Xsk,
    Heartbeat,
    Session,
}

impl MandatoryPin {
    /// The legacy stage token (`xsk` / `heartbeat` / `session`).
    fn token(self) -> &'static str {
        match self {
            MandatoryPin::Xsk => "xsk",
            MandatoryPin::Heartbeat => "heartbeat",
            MandatoryPin::Session => "session",
        }
    }
}

/// The per-attempt shortfall recorded when a spawned worker did not bind its
/// full planned queue set (or never reported readiness before the barrier
/// deadline). Owned by bring-up (`await_readiness`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WorkerBindShortfall {
    pub(crate) worker_id: u32,
    /// `Some(n)` — the worker reported binding `n` of `planned` slots (a
    /// partial/empty bind). `None` — the worker never reported before the
    /// deadline (treated as failed / timed out).
    pub(crate) bound: Option<usize>,
    pub(crate) planned: usize,
    /// #6245: the EXPLICIT per-slot binding-setup failures (slot + phase +
    /// owned error) that produced this shortfall, carried through from the
    /// worker's `WorkerStartupReport`. Empty for the timeout/no-report case
    /// (`bound: None`) — there is no reported cause to attribute — and
    /// rendered only for the `Some` (partial-bind) case by [`Display`], where
    /// an empty list surfaces as `failures=[no-explicit-failure]`.
    pub(crate) failures: Vec<BindingSetupFailure>,
}

/// Typed reconcile progress / outcome, replacing the free-form
/// `last_reconcile_stage` string. [`std::fmt::Display`] is the ONLY place the
/// string is produced. `Default` is [`ReconcileStage::Idle`], matching the
/// constructor's `"idle"` seed.
///
/// Every variant renders its byte-identical legacy operator string EXCEPT
/// `WorkerBindIncomplete`, which has been deliberately extended twice: #6245
/// appended the explicit per-slot causes, and #7497 added the NIC coordinate to
/// each cause. This sentence used to say "every variant" without the exception,
/// which #6245 had already made false. Nothing parses these strings — they are
/// operator diagnostics — so extending one is a decision about legibility, not
/// a wire change; the exception is recorded here so the next editor knows the
/// blanket claim is not the contract.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) enum ReconcileStage {
    /// Constructor seed. Renders `idle`.
    #[default]
    Idle,
    /// Recorded by an explicit stop (`Coordinator::stop` /
    /// `stop_with_event_stream`). Renders `stopped`.
    Stopped,
    /// Top of `reconcile`, before any teardown. Renders `start`.
    Start,
    /// Config-cleared / shutdown reconcile (`None` snapshot). Renders
    /// `no_snapshot`.
    NoSnapshot,
    /// A mandatory BPF map pin was absent at preflight. Renders
    /// `missing_{xsk,heartbeat,session}_pin`.
    MissingPin(MandatoryPin),
    /// A BPF map pin was present but failed to open. `map` is the map token
    /// (`xsk` / `heartbeat` / `session` / `conntrack_v4` / `conntrack_v6` /
    /// `dnat_table` / `dnat_table_v6`). Renders `open_{map}_map_failed:{err}`.
    OpenMapFailed { map: &'static str, err: String },
    /// A snapshot integrity fault surfaced by the top-of-reconcile POLICY
    /// preflight, which carries the error text. Renders
    /// `snapshot_integrity_error: {detail}`.
    SnapshotIntegrityErrorDetail(String),
    /// A snapshot integrity fault surfaced by the pre-teardown forwarding
    /// build, which records the bare descriptor. Renders
    /// `snapshot_integrity_error`.
    SnapshotIntegrityError,
    /// Worker plans built (pre-spawn). Renders
    /// `planned:workers={workers}:bindings={bindings}:live={live}`.
    Planned {
        workers: usize,
        bindings: usize,
        live: usize,
    },
    /// Preserved synced sessions replayed. Renders
    /// `replayed_synced:{count}:workers={workers}`.
    ReplayedSynced { count: usize, workers: usize },
    /// A worker thread failed to spawn (post-teardown). Renders
    /// `spawn_worker_failed:{worker_id}:{err}`.
    SpawnWorkerFailed { worker_id: u32, err: String },
    /// The XFRM-SA monitor did not complete its first full GETSA dump within
    /// the bounded dataplane-ready window; no workers may report ready.
    IpsecSaNotReady,
    /// A spawned worker bound an incomplete queue set / never reported
    /// readiness (post-teardown). Renders
    /// `worker_bind_incomplete:{id}:bound={n}:planned={p}` or
    /// `worker_bind_incomplete:{id}:timeout:planned={p}`.
    WorkerBindIncomplete(WorkerBindShortfall),
    /// Worker bring-up completed successfully. Renders
    /// `spawned:workers={handles}:identities={identities}:live={live}`.
    Spawned {
        handles: usize,
        identities: usize,
        live: usize,
    },
}

impl std::fmt::Display for ReconcileStage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReconcileStage::Idle => f.write_str("idle"),
            ReconcileStage::Stopped => f.write_str("stopped"),
            ReconcileStage::Start => f.write_str("start"),
            ReconcileStage::NoSnapshot => f.write_str("no_snapshot"),
            ReconcileStage::MissingPin(pin) => write!(f, "missing_{}_pin", pin.token()),
            ReconcileStage::OpenMapFailed { map, err } => {
                write!(f, "open_{map}_map_failed:{err}")
            }
            ReconcileStage::SnapshotIntegrityErrorDetail(detail) => {
                write!(f, "snapshot_integrity_error: {detail}")
            }
            ReconcileStage::SnapshotIntegrityError => f.write_str("snapshot_integrity_error"),
            ReconcileStage::Planned {
                workers,
                bindings,
                live,
            } => write!(f, "planned:workers={workers}:bindings={bindings}:live={live}"),
            ReconcileStage::ReplayedSynced { count, workers } => {
                write!(f, "replayed_synced:{count}:workers={workers}")
            }
            ReconcileStage::SpawnWorkerFailed { worker_id, err } => {
                write!(f, "spawn_worker_failed:{worker_id}:{err}")
            }
            ReconcileStage::IpsecSaNotReady => f.write_str("ipsec_sa_not_ready"),
            ReconcileStage::WorkerBindIncomplete(shortfall) => match shortfall.bound {
                // #6245: a partial-bind shortfall appends the EXPLICIT per-slot
                // binding-setup failures. Byte-identical to #6245's original
                // barrier string:
                // `worker_bind_incomplete:{id}:bound={n}:planned={p}:failures=[...]`.
                Some(bound) => write!(
                    f,
                    "worker_bind_incomplete:{}:bound={}:planned={}:{}",
                    shortfall.worker_id,
                    bound,
                    shortfall.planned,
                    render_binding_setup_failures(&shortfall.failures)
                ),
                // The timeout / no-report case has no reported cause to
                // attribute, so it keeps the pre-#6245 counts-only string
                // (byte-identical).
                None => write!(
                    f,
                    "worker_bind_incomplete:{}:timeout:planned={}",
                    shortfall.worker_id, shortfall.planned
                ),
            },
            ReconcileStage::Spawned {
                handles,
                identities,
                live,
            } => write!(
                f,
                "spawned:workers={handles}:identities={identities}:live={live}"
            ),
        }
    }
}

/// #6245: render a worker's EXPLICIT per-slot binding-setup failures into a
/// compact, deterministic descriptor for the fail-closed reconcile stage. The
/// failures arrive already sorted by slot (`worker_loop_setup`), so the output
/// is stable regardless of setup/channel ordering. Empty input renders
/// `failures=[no-explicit-failure]` — a shortfall with no recorded cause,
/// which should not happen once every setup leg reports through the outcome,
/// but is surfaced rather than silently dropped.
///
/// This lives here (not in bring-up) because per #6244 the legacy operator
/// string is produced in EXACTLY one place — [`ReconcileStage`]'s `Display`,
/// the sole caller.
fn render_binding_setup_failures(failures: &[BindingSetupFailure]) -> String {
    if failures.is_empty() {
        return "failures=[no-explicit-failure]".to_string();
    }
    let rendered = failures
        .iter()
        .map(|failure| {
            format!(
                "{}:slot={}:{}:q{}:{}",
                failure.phase.as_str(),
                failure.slot,
                failure.interface,
                failure.queue_id,
                failure.reason
            )
        })
        .collect::<Vec<_>>()
        .join("; ");
    format!("failures=[{rendered}]")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::afxdp::types::BindingSetupPhase;

    /// #7497: the coordinate capture copies every field from the plan's status.
    ///
    /// This is what the renderer cell below CANNOT check. That one builds a
    /// `BindingSetupFailure` directly, so it proves the string carries whatever
    /// the failure holds — not that the failure holds the right thing. Measured:
    /// replacing the interface capture with `String::new()` at the worker site
    /// passed the entire Rust suite, because no cell reaches that code without a
    /// real AF_XDP bind failure.
    ///
    /// Routing both sites through `BindingCoordinate::of` does not close that
    /// gap completely — `of(&plan.status)` at the call site is still unproven —
    /// but it moves the field-by-field copy somewhere a mutation reds, and
    /// leaves each site a single expression that cannot read the wrong field
    /// without being visibly wrong.
    #[test]
    fn binding_coordinate_copies_the_status_7497() {
        let mut status = crate::protocol::BindingStatus::default();
        status.slot = 9;
        status.interface = "ge-7-0-2".to_string();
        status.queue_id = 11;

        let coord = crate::afxdp::types::BindingCoordinate::of(&status);
        assert_eq!(coord.slot, 9, "slot not copied");
        assert_eq!(coord.interface, "ge-7-0-2", "interface not copied");
        assert_eq!(coord.queue_id, 11, "queue_id not copied");

        // ...and the failure built at that coordinate carries all three through.
        let failure = BindingSetupFailure::at(
            &coord,
            BindingSetupPhase::Private,
            "Device or resource busy".to_string(),
        );
        assert_eq!(failure.slot, 9);
        assert_eq!(failure.interface, "ge-7-0-2");
        assert_eq!(failure.queue_id, 11);
    }

    /// #7497: a fail-closed bringup refusal must name the NIC coordinate, not
    /// only the slot.
    ///
    /// Asserted as a PROPERTY rather than against a byte string. The pinned
    /// legacy-string cells above would also red if the coordinate were dropped,
    /// but they red on any format change at all, so they cannot say WHICH part
    /// of the string is load-bearing. This one can: an operator hit by a total
    /// outage has to learn which interface and which queue failed, because the
    /// slot number moves whenever any interface's queue count changes and the
    /// remedy (cap that NIC's queues, or find what else holds the socket) is
    /// per-interface.
    #[test]
    fn bind_shortfall_names_the_nic_coordinate_7497() {
        let rendered = ReconcileStage::WorkerBindIncomplete(WorkerBindShortfall {
            worker_id: 2,
            bound: Some(15),
            planned: 16,
            failures: vec![BindingSetupFailure {
                slot: 9,
                interface: "ge-7-0-2".to_string(),
                queue_id: 11,
                phase: BindingSetupPhase::Private,
                reason: "Device or resource busy".to_string(),
            }],
        })
        .to_string();

        for needle in ["ge-7-0-2", "q11", "bound=15", "planned=16", "Device or resource busy"] {
            assert!(
                rendered.contains(needle),
                "the fail-closed refusal must name {needle:?} — an operator cannot \
                 act on a slot number. Got: {rendered}"
            );
        }
    }

    /// #6245: the explicit-failure renderer is deterministic and never blank —
    /// empty input yields a "no explicit cause" marker, and populated input
    /// renders `phase:slot=<n>:<reason>` per failure joined by "; " in the
    /// caller-supplied (slot-sorted) order. Fail-on-revert: drop the phase or
    /// reason from the render and these assertions fail.
    #[test]
    fn render_binding_setup_failures_is_deterministic() {
        assert_eq!(
            render_binding_setup_failures(&[]),
            "failures=[no-explicit-failure]",
            "empty input must render an explicit no-cause marker, not a blank"
        );

        let one = [BindingSetupFailure {
            slot: 3,

            interface: "ge-0-0-1".to_string(),

            queue_id: 3,
            phase: BindingSetupPhase::Private,
            reason: "create binding umem: ENOMEM".to_string(),
        }];
        assert_eq!(
            render_binding_setup_failures(&one),
            "failures=[private:slot=3:ge-0-0-1:q3:create binding umem: ENOMEM]",
        );

        // Two failures (already slot-sorted by the producer) with distinct
        // phases render in order, joined by "; ".
        let many = [
            BindingSetupFailure {
                slot: 1,

                interface: "ge-0-0-1".to_string(),

                queue_id: 1,
                phase: BindingSetupPhase::Private,
                reason: "a".to_string(),
            },
            BindingSetupFailure {
                slot: 4,

                interface: "ge-0-0-1".to_string(),

                queue_id: 4,
                phase: BindingSetupPhase::SharedFallback,
                reason: "b".to_string(),
            },
        ];
        assert_eq!(
            render_binding_setup_failures(&many),
            "failures=[private:slot=1:ge-0-0-1:q1:a; shared-fallback:slot=4:ge-0-0-1:q4:b]",
        );
    }

    /// #6244 fail-on-revert BINDING: every typed stage must render its legacy
    /// operator string BYTE-FOR-BYTE. `reconcile_debug` / the wire
    /// `debug_reconcile_stage` and `ReconcileError::Display` are produced only
    /// through this `Display`, so any drift here is an operator/JSON contract
    /// break. Perturbing a single `write!` format string (the revert) flips
    /// the matching assertion RED.
    #[test]
    fn reconcile_stage_renders_byte_identical_legacy_strings() {
        assert_eq!(ReconcileStage::Idle.to_string(), "idle");
        assert_eq!(ReconcileStage::Stopped.to_string(), "stopped");
        assert_eq!(ReconcileStage::Start.to_string(), "start");
        assert_eq!(ReconcileStage::NoSnapshot.to_string(), "no_snapshot");
        assert_eq!(
            ReconcileStage::MissingPin(MandatoryPin::Xsk).to_string(),
            "missing_xsk_pin"
        );
        assert_eq!(
            ReconcileStage::MissingPin(MandatoryPin::Heartbeat).to_string(),
            "missing_heartbeat_pin"
        );
        assert_eq!(
            ReconcileStage::MissingPin(MandatoryPin::Session).to_string(),
            "missing_session_pin"
        );
        assert_eq!(
            ReconcileStage::OpenMapFailed {
                map: "xsk",
                err: "ENOENT".to_string(),
            }
            .to_string(),
            "open_xsk_map_failed:ENOENT"
        );
        assert_eq!(
            ReconcileStage::OpenMapFailed {
                map: "conntrack_v4",
                err: "EACCES".to_string(),
            }
            .to_string(),
            "open_conntrack_v4_map_failed:EACCES"
        );
        assert_eq!(
            ReconcileStage::SnapshotIntegrityErrorDetail(
                "UnresolvableZoneReference(ghostzone)".to_string()
            )
            .to_string(),
            "snapshot_integrity_error: UnresolvableZoneReference(ghostzone)"
        );
        assert_eq!(
            ReconcileStage::SnapshotIntegrityError.to_string(),
            "snapshot_integrity_error"
        );
        assert_eq!(
            ReconcileStage::Planned {
                workers: 2,
                bindings: 6,
                live: 6,
            }
            .to_string(),
            "planned:workers=2:bindings=6:live=6"
        );
        assert_eq!(
            ReconcileStage::ReplayedSynced {
                count: 4,
                workers: 2,
            }
            .to_string(),
            "replayed_synced:4:workers=2"
        );
        assert_eq!(
            ReconcileStage::SpawnWorkerFailed {
                worker_id: 3,
                err: "Resource temporarily unavailable (os error 11)".to_string(),
            }
            .to_string(),
            "spawn_worker_failed:3:Resource temporarily unavailable (os error 11)"
        );
        // #6245: the partial-bind (`Some`) variant APPENDS the explicit
        // per-slot binding-setup failures. This is the ONE variant whose
        // rendered string intentionally changes over the pre-#6245 legacy
        // (the counts prefix is retained; the `:failures=[...]` cause is added).
        //
        // #7497 extended it again: each cause now carries the NIC coordinate
        // (`:<interface>:q<queue>`) between the slot and the reason. A slot is a
        // position in the minted sequence with no external meaning, and since
        // per-interface queue planning the slot -> (interface, queue) mapping
        // moves whenever any interface's queue count changes — so an operator
        // reading this fail-closed refusal could not tell WHICH queue failed.
        // This is the loud blocker of #7497: the failure was always noticed,
        // but it did not say enough to act on.
        assert_eq!(
            ReconcileStage::WorkerBindIncomplete(WorkerBindShortfall {
                worker_id: 1,
                bound: Some(0),
                planned: 1,
                failures: vec![BindingSetupFailure {
                    slot: 1,

                    interface: "ge-0-0-1".to_string(),

                    queue_id: 1,
                    phase: BindingSetupPhase::Private,
                    reason: "create binding umem: ENOMEM".to_string(),
                }],
            })
            .to_string(),
            "worker_bind_incomplete:1:bound=0:planned=1:failures=[private:slot=1:ge-0-0-1:q1:create binding umem: ENOMEM]"
        );
        // A partial bind with no recorded cause still renders an explicit
        // no-cause marker (never a blank suffix).
        assert_eq!(
            ReconcileStage::WorkerBindIncomplete(WorkerBindShortfall {
                worker_id: 2,
                bound: Some(1),
                planned: 2,
                failures: Vec::new(),
            })
            .to_string(),
            "worker_bind_incomplete:2:bound=1:planned=2:failures=[no-explicit-failure]"
        );
        // The timeout / no-report (`None`) variant has no reported cause to
        // attribute and keeps the pre-#6245 counts-only string byte-identical.
        assert_eq!(
            ReconcileStage::WorkerBindIncomplete(WorkerBindShortfall {
                worker_id: 5,
                bound: None,
                planned: 3,
                failures: Vec::new(),
            })
            .to_string(),
            "worker_bind_incomplete:5:timeout:planned=3"
        );
        assert_eq!(
            ReconcileStage::Spawned {
                handles: 2,
                identities: 6,
                live: 6,
            }
            .to_string(),
            "spawned:workers=2:identities=6:live=6"
        );
    }

    /// The constructor seed and the `Default` derive must agree — the
    /// coordinator initializes the field via the enum default meaning `idle`.
    #[test]
    fn reconcile_stage_default_is_idle() {
        assert_eq!(ReconcileStage::default(), ReconcileStage::Idle);
        assert_eq!(ReconcileStage::default().to_string(), "idle");
    }
}
