//! #9506 P-MECH S9.3: owned IPsec-inner worker entry (D13) and zone gate (D14).
//!
//! This is the only Rust entry for admitted IPsec-inner datagrams. It builds
//! the owned logical frame through the shared `build_logical_ingress_packet`
//! helper (never a second synthesize/rebind/reparse path), gates attribution
//! against the immutable worker `RuntimeView`, then posts exactly one D11
//! verdict. V1 is deny-only at the final join: no q0 enqueue, no NF_ACCEPT,
//! no session install, and no NAT mutation. A frame that reaches the end of
//! the V1 deny-only slice returns `WOULD_PERMIT` as a verdict (completion
//! outcome code 10). Go suppresses only the final V1 would-permit permit join;
//! E28/byte-52 is reserved for evaluator/snapshot/worker-set unavailability.

use super::logical_ingress::{build_logical_ingress_packet, LogicalIngressParams};
use super::ipsec_inner_queue::{
    reason, IpsecInnerDescriptor, IpsecInnerSlabPool, IpsecInnerVerdict, IpsecInnerVerdictQueue,
    IPSEC_INNER_ORPHAN_PROVISIONAL_TOTAL, IPSEC_INNER_SLAB_EXHAUSTED_TOTAL,
    IPSEC_INNER_VERDICT_QUEUE_FULL_TOTAL, IPSEC_INNER_WORKER_ORPHAN_REAPED_TOTAL,
    IPSEC_INNER_WORKER_QUEUE_FULL_TOTAL, IPSEC_INNER_WORKER_RETIRED_TOTAL,
};
use super::{
    ForwardingState, IpsecTunnelRows, PMechInventory, RuntimeView, UserspaceDpMeta,
    ValidationState,
};
use std::sync::atomic::{AtomicU64, Ordering};
/// New per-protocol ECN refusal counter required by D13. The outer ESP header
/// is consumed before this hook, so the entry passes `outer_ecn=None` to the
/// shared helper; a malformed/illegal inner ECN still increments this counter.
pub(crate) static IPSEC_INNER_ECN_ILLEGAL_DROPS: AtomicU64 = AtomicU64::new(0);

// Rust-owned §4.3 counters. Names intentionally match the design/metrics
// contract (lower-case symbols are permitted here so a source-level audit can
// join each Rust counter to the exact metric name without a translation table).
#[allow(non_upper_case_globals)]
pub(crate) static zone_gate_unzoned_total: AtomicU64 = AtomicU64::new(0);
#[allow(non_upper_case_globals)]
pub(crate) static zone_gate_ambiguous_total: AtomicU64 = AtomicU64::new(0);
#[allow(non_upper_case_globals)]
pub(crate) static zone_gate_stale_total: AtomicU64 = AtomicU64::new(0);
#[allow(non_upper_case_globals)]
pub(crate) static zone_gate_no_generation_total: AtomicU64 = AtomicU64::new(0);
#[allow(non_upper_case_globals)]
pub(crate) static ipsec_inner_input_stateful_without_session_total: AtomicU64 = AtomicU64::new(0);
#[allow(non_upper_case_globals)]
pub(crate) static ipsec_inner_parse_drops_total: AtomicU64 = AtomicU64::new(0);
// #9506 counter slice: one storage cell for the IPsec-inner ECN refusal.
// The lowercase duplicate was a second, never-incremented `AtomicU64` — D13
// passes only the canonical cell to the shared helper, so reads of the old
// name observed a permanent 0 while drops accumulated invisibly in the
// canonical static.
// The alias keeps the §4.3 source-level name joinable to the metric contract
// without a translation table.
pub(crate) use IPSEC_INNER_ECN_ILLEGAL_DROPS as ipsec_inner_ecn_illegal_drops;
#[allow(non_upper_case_globals)]
pub(crate) static ipsec_inner_session_lookup_errors_total: AtomicU64 = AtomicU64::new(0);
#[allow(non_upper_case_globals)]
pub(crate) static ipsec_inner_session_lookup_recoveries_total: AtomicU64 = AtomicU64::new(0);
#[allow(non_upper_case_globals)]
pub(crate) static session_alias_ambiguous_total: AtomicU64 = AtomicU64::new(0);
#[allow(non_upper_case_globals)]
pub(crate) static ipsec_inner_alias_overflow_total: AtomicU64 = AtomicU64::new(0);
#[allow(non_upper_case_globals)]
pub(crate) static ipsec_inner_alias_replication_failures_total: AtomicU64 = AtomicU64::new(0);
#[allow(non_upper_case_globals)]
pub(crate) static ipsec_inner_session_rollback_failures_total: AtomicU64 = AtomicU64::new(0);
#[allow(non_upper_case_globals)]
pub(crate) static policy_reject_as_deny_total: AtomicU64 = AtomicU64::new(0);
#[allow(non_upper_case_globals)]
pub(crate) static tcp_rst_suppressed_total: AtomicU64 = AtomicU64::new(0);
#[allow(non_upper_case_globals)]
pub(crate) static ipsec_inner_alg_errors_total: AtomicU64 = AtomicU64::new(0);
#[allow(non_upper_case_globals)]
pub(crate) static ipsec_inner_filter_errors_total: AtomicU64 = AtomicU64::new(0);
#[allow(non_upper_case_globals)]
pub(crate) static ipsec_inner_policer_errors_total: AtomicU64 = AtomicU64::new(0);
#[allow(non_upper_case_globals)]
pub(crate) static ipsec_inner_nat_stage_errors_total: AtomicU64 = AtomicU64::new(0);
#[allow(non_upper_case_globals)]
pub(crate) static ipsec_inner_nat_rollback_failures_total: AtomicU64 = AtomicU64::new(0);
#[allow(non_upper_case_globals)]
pub(crate) static ipsec_inner_noroute_total: AtomicU64 = AtomicU64::new(0);
#[allow(non_upper_case_globals)]
pub(crate) static ipsec_inner_routed_local_total: AtomicU64 = AtomicU64::new(0);
#[allow(non_upper_case_globals)]
pub(crate) static ipsec_inner_input_routed_transit_total: AtomicU64 = AtomicU64::new(0);
#[allow(non_upper_case_globals)]
pub(crate) static ipsec_inner_input_nat_mutation_unsupported_total: AtomicU64 = AtomicU64::new(0);
#[allow(non_upper_case_globals)]
pub(crate) static ipsec_inner_syn_cookie_refusals_total: AtomicU64 = AtomicU64::new(0);
#[allow(non_upper_case_globals)]
pub(crate) static ipsec_inner_fragment_late_total: AtomicU64 = AtomicU64::new(0);
#[allow(non_upper_case_globals)]
pub(crate) static nfq_reentry_unsupported_domain_total: AtomicU64 = AtomicU64::new(0);

/// #9506 counter slice: one-call snapshot of the Rust-incremented
/// IPsec-inner counters. Definition-only §4.3 statics stay local until their
/// stage arms land; exporting permanent zero series would widen this slice
/// without adding an operator-visible signal. Go-owned counters are likewise
/// excluded.
///
/// Field names match their static names (lowercased), except the canonical
/// ECN cell whose design name intentionally has no `_total` suffix.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct IpsecInnerCounterSnapshot {
    pub zone_gate_unzoned_total: u64,
    pub zone_gate_ambiguous_total: u64,
    pub zone_gate_stale_total: u64,
    pub zone_gate_no_generation_total: u64,
    pub ipsec_inner_parse_drops_total: u64,
    pub ipsec_inner_ecn_illegal_drops: u64,
    pub ipsec_inner_worker_queue_full_total: u64,
    pub ipsec_inner_verdict_queue_full_total: u64,
    pub ipsec_inner_slab_exhausted_total: u64,
    pub ipsec_inner_worker_retired_total: u64,
    pub ipsec_inner_worker_orphan_reaped_total: u64,
    pub ipsec_inner_orphan_provisional_total: u64,
}

/// Load every counter in [`IpsecInnerCounterSnapshot`] once. `Relaxed` is
/// sufficient: these are stats-only, and no cross-counter invariant is read
/// here.
pub(crate) fn ipsec_inner_counters_snapshot() -> IpsecInnerCounterSnapshot {
    IpsecInnerCounterSnapshot {
        zone_gate_unzoned_total: zone_gate_unzoned_total.load(Ordering::Relaxed),
        zone_gate_ambiguous_total: zone_gate_ambiguous_total.load(Ordering::Relaxed),
        zone_gate_stale_total: zone_gate_stale_total.load(Ordering::Relaxed),
        zone_gate_no_generation_total: zone_gate_no_generation_total.load(Ordering::Relaxed),
        ipsec_inner_parse_drops_total: ipsec_inner_parse_drops_total.load(Ordering::Relaxed),
        ipsec_inner_ecn_illegal_drops: IPSEC_INNER_ECN_ILLEGAL_DROPS.load(Ordering::Relaxed),
        ipsec_inner_worker_queue_full_total: IPSEC_INNER_WORKER_QUEUE_FULL_TOTAL
            .load(Ordering::Relaxed),
        ipsec_inner_verdict_queue_full_total: IPSEC_INNER_VERDICT_QUEUE_FULL_TOTAL
            .load(Ordering::Relaxed),
        ipsec_inner_slab_exhausted_total: IPSEC_INNER_SLAB_EXHAUSTED_TOTAL.load(Ordering::Relaxed),
        ipsec_inner_worker_retired_total: IPSEC_INNER_WORKER_RETIRED_TOTAL.load(Ordering::Relaxed),
        ipsec_inner_worker_orphan_reaped_total: IPSEC_INNER_WORKER_ORPHAN_REAPED_TOTAL
            .load(Ordering::Relaxed),
        ipsec_inner_orphan_provisional_total: IPSEC_INNER_ORPHAN_PROVISIONAL_TOTAL
            .load(Ordering::Relaxed),
    }
}


/// Advisory/generation fields appended to each Go submit row (+70 bytes). Go
/// remains the pre-gate authority; Rust treats every value as advisory and
/// cross-checks it against the exact tunnel row and the one RuntimeView loaded
/// by the worker tick.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct IpsecInnerAdvisory {
    pub snapshot_generation: u64,
    pub config_generation: u64,
    pub fib_generation: u32,
    pub zone_id: u16,
    pub if_id: u32,
    pub pmech_inventory_generation: u64,
    pub pmech_inventory_fib_generation: u32,
    pub pmech_policy_identity: [u8; 32],
    pub expected_routing_domain: u32,
    pub expected_fib_table: u32,
}

/// Owned-frame input passed by the D11 worker. The bytes are a pool slot and
/// are borrowed for the duration of this call; D13's shared helper produces the
/// synthetic Ethernet-owned frame used by the normal stage path.
#[derive(Clone, Copy, Debug)]
pub(crate) struct IpsecInnerInput<'a> {
    pub slab_id: u32,
    pub inner_packet: &'a [u8],
    pub stn: &'a str,
    pub inner_family: u8,
    pub inner_eth_proto: u16,
    pub protocol: u8,
    pub rel_l4_offset: u16,
    pub payload_offset: u16,
    pub logical_ifindex: i32,
    pub rx_queue_index: u32,
    pub advisory: IpsecInnerAdvisory,
    /// Descriptor identity is supplied by D11; all authoritative generation
    /// values come from `RuntimeView`, never from this input.
    pub descriptor: Option<&'a IpsecInnerDescriptor>,
}

/// V1 terminal result. `WouldPermit` is deliberately distinct from `Permit`:
/// there is no permit arm on this Rust path until S9.5, but the successful
/// adjudication still returns outcome code 10 so Go can record the suppressed
/// would-permit verdict without misclassifying it as E28.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum IpsecInnerDecision {
    Deny {
        request_id: u64,
        stage: &'static str,
        reason: u8,
        policy_id: u32,
    },
    WouldPermit {
        request_id: u64,
        runtime_view_publication_generation: u64,
    },
}

impl IpsecInnerDecision {
    pub(crate) fn request_id(&self) -> u64 {
        match self {
            Self::Deny { request_id, .. } | Self::WouldPermit { request_id, .. } => *request_id,
        }
    }

    pub(crate) fn reason(&self) -> Option<u8> {
        match self {
            Self::Deny { reason, .. } => Some(*reason),
            Self::WouldPermit { .. } => None,
        }
    }

    pub(crate) fn runtime_view_publication_generation(&self) -> Option<u64> {
        match self {
            Self::WouldPermit {
                runtime_view_publication_generation,
                ..
            } => Some(*runtime_view_publication_generation),
            Self::Deny { .. } => None,
        }
    }

    pub(crate) fn is_would_permit(&self) -> bool {
        matches!(self, Self::WouldPermit { .. })
    }
}

#[inline]
fn deny(input: &IpsecInnerInput<'_>, stage: &'static str, reason_byte: u8) -> IpsecInnerDecision {
    IpsecInnerDecision::Deny {
        request_id: input
            .descriptor
            .map(|d| d.request_id)
            .unwrap_or_default(),
        stage,
        reason: reason_byte,
        // Pre-policy/D14/transport causes are unattributed by design.
        policy_id: 0,
    }
}

/// D14's exact tunnel-row + zone gate. Kept separate from the stage pipeline
/// so a policy default-permit can never make an unzoned tunnel pass. The
/// `validation` and `snapshot_generation` arguments came from the SAME
/// RuntimeView as `forwarding` and `rows`; no caller-provided live-generation
/// stamp participates in this fence.
fn d14_zone_gate(
    forwarding: &ForwardingState,
    rows: &IpsecTunnelRows,
    pmech_inventory: &PMechInventory,
    validation: ValidationState,
    snapshot_generation: u64,
    runtime_view_publication_generation: u64,
    input: &IpsecInnerInput<'_>,
) -> Result<(Vec<u8>, UserspaceDpMeta, u32), IpsecInnerDecision> {
    let advisory = input.advisory;
    if snapshot_generation == 0 || !validation.snapshot_installed {
        // D9/D16: nil/stale worker authority is E28 enforcing, not a default
        // view or a guessed generation.
        return Err(deny(input, "d14_evaluator_unavailable", reason::EVALUATOR_UNAVAILABLE));
    }
    if advisory.config_generation == 0 || advisory.fib_generation == 0 {
        zone_gate_no_generation_total.fetch_add(1, Ordering::Relaxed);
        return Err(deny(input, "d14_missing_generation", reason::MISSING_GENERATION));
    }
    if advisory.pmech_inventory_generation == 0
        || advisory.pmech_inventory_fib_generation == 0
        || runtime_view_publication_generation == 0
        || !pmech_inventory.complete()
        || !pmech_inventory.has_main_table_routes()
    {
        return Err(deny(input, "d22_inventory_unavailable", reason::EVALUATOR_UNAVAILABLE));
    }
    if advisory.snapshot_generation != snapshot_generation
        || advisory.config_generation != validation.config_generation
        || advisory.fib_generation != validation.fib_generation
        || advisory.pmech_inventory_generation != pmech_inventory.generation()
        || advisory.pmech_inventory_fib_generation != pmech_inventory.fib_generation()
        || pmech_inventory.fib_generation() != validation.fib_generation
        || !pmech_inventory.matches_policy_identity(&advisory.pmech_policy_identity)
    {
        zone_gate_stale_total.fetch_add(1, Ordering::Relaxed);
        return Err(deny(input, "d14_stale_generation", reason::STALE_GENERATION));
    }
    if advisory.expected_routing_domain != 0 || advisory.expected_fib_table != 254 {
        return Err(deny(input, "d22_route_domain_mismatch", reason::OTHER_DOMAIN));
    }
    let Some(row) = rows.exact(input.stn) else {
        zone_gate_ambiguous_total.fetch_add(1, Ordering::Relaxed);
        return Err(deny(input, "d14_unknown_or_ambiguous_stn", reason::IFID_UNDERIVABLE));
    };
    if row.logical_ifindex <= 0 || row.if_id == 0 || input.logical_ifindex != row.logical_ifindex {
        zone_gate_ambiguous_total.fetch_add(1, Ordering::Relaxed);
        return Err(deny(input, "d14_ifid_underivable", reason::IFID_UNDERIVABLE));
    }
    if advisory.if_id == 0 || advisory.if_id != row.if_id {
        zone_gate_ambiguous_total.fetch_add(1, Ordering::Relaxed);
        return Err(deny(input, "d14_ifid_advisory_mismatch", reason::ZONE_ADVISORY_MISMATCH));
    }

    // D13: the one shared logical-ingress construction path. Outer ESP is
    // already consumed at this hook, so outer_ecn is explicitly None.
    let params = LogicalIngressParams {
        inner_packet: input.inner_packet,
        inner_family: input.inner_family,
        inner_eth_proto: input.inner_eth_proto,
        protocol: input.protocol,
        rel_l4_offset: input.rel_l4_offset,
        payload_offset: input.payload_offset,
        logical_ifindex: row.logical_ifindex,
        outer_ecn: None,
        ecn_illegal_drops: &IPSEC_INNER_ECN_ILLEGAL_DROPS,
        meta_flags: IPSEC_INNER_INGRESS_FLAG,
        rx_queue_index: input.rx_queue_index,
        config_generation: advisory.config_generation,
        fib_generation: advisory.fib_generation,
    };
    let Some((owned, meta)) = build_logical_ingress_packet(forwarding, &params) else {
        ipsec_inner_parse_drops_total.fetch_add(1, Ordering::Relaxed);
        return Err(deny(input, "d13_parse_or_ecn", reason::PARSE_ECN));
    };

    // `build_logical_ingress_packet` is the source of truth for this lookup;
    // repeat no name/string resolution here. A missing map entry is zone 0 and
    // therefore an explicit E1 terminal, never policy default action.
    let ingress_zone = forwarding
        .ifindex_to_zone_id
        .get(&row.logical_ifindex)
        .copied()
        .unwrap_or(0);
    if ingress_zone != meta.ingress_zone || ingress_zone != advisory.zone_id || advisory.zone_id == 0 {
        zone_gate_ambiguous_total.fetch_add(1, Ordering::Relaxed);
        return Err(deny(input, "d14_zone_advisory_mismatch", reason::ZONE_ADVISORY_MISMATCH));
    }
    let Some(pmech_row) = pmech_inventory.exact_tunnel(input.stn, row.if_id, row.logical_ifindex) else {
        return Err(deny(input, "d22_tunnel_inventory_invalid", reason::EVALUATOR_UNAVAILABLE));
    };
    let Some(destination) =
        crate::afxdp::frame::parse_packet_destination_from_frame(&owned, meta)
    else {
        ipsec_inner_parse_drops_total.fetch_add(1, Ordering::Relaxed);
        return Err(deny(input, "d22_destination_unresolved", reason::PARSE_ECN));
    };
    if !pmech_row.allows_destination(destination) {
        return Err(deny(input, "d22_destination_outside_ingress", reason::NO_ROUTE));
    }
    let (selectors, effective_prefixes) = pmech_row.selector_projection();
    if selectors.is_empty() || effective_prefixes.is_empty() {
        return Err(deny(input, "d22_selector_inventory_invalid", reason::EVALUATOR_UNAVAILABLE));
    }
    Ok((owned, meta, row.if_id))
}
/// D13 worker entry. `view` MUST be the immutable RuntimeView already loaded
/// for this worker tick. The tunnel rows are read from that same view binding;
/// callers cannot pair a separately loaded row table with this generation.
/// The function does not load the shared ArcSwap and has a source-level canary
/// assertion (`runtime_view_publish_canary`) guarding zero additional
/// RuntimeView loads.
pub(crate) fn adjudicate_ipsec_inner(
    view: &RuntimeView,
    input: IpsecInnerInput<'_>,
) -> IpsecInnerDecision {
    // This is intentionally the sole view binding. Do not add
    // `shared_runtime.load()` here: D13 zero-new-load contract.
    let forwarding = view.forwarding().as_ref();
    let validation = view.validation();
    let rows = view.ipsec_tunnel_rows();
    let pmech_inventory = view.pmech_inventory();
    if !validation.snapshot_installed {
        return deny(&input, "d13_snapshot_unavailable", reason::EVALUATOR_UNAVAILABLE);
    }
    let snapshot_generation = view.ipsec_snapshot_generation();
    let runtime_view_publication_generation = view.runtime_view_publication_generation();
    let (_owned, _meta, _if_id) = match d14_zone_gate(
        forwarding,
        rows,
        pmech_inventory,
        validation,
        snapshot_generation,
        runtime_view_publication_generation,
        &input,
    ) {
        Ok(value) => value,
        Err(decision) => return decision,
    };

    // S9.2-S9.4/S9.6 deny-only subset: later worker stages are represented by
    // the existing poll_descriptor order, but the final permit join is OUT in
    // V1. Every would-join site carries this S9.5-removal comment: no session
    // install, flow-cache publish, NAT mutation, q0 enqueue, or NF_ACCEPT.
    // The verdict is returned as WOULD_PERMIT so Go can observe the successful
    // adjudication. It is NOT E28; Go's E28 byte-52 suppression counter is
    // reserved for evaluator/snapshot/worker-set unavailability. V1's
    // S9.5-removal comment: no session install, flow-cache publish, NAT
    // mutation, q0 enqueue, or NF_ACCEPT occurs here.
    IpsecInnerDecision::WouldPermit {
        request_id: input
            .descriptor
            .map(|d| d.request_id)
            .unwrap_or_default(),
        runtime_view_publication_generation,
    }
}

pub(crate) fn verdict_from_decision(decision: &IpsecInnerDecision) -> IpsecInnerVerdict {
    match decision {
        IpsecInnerDecision::Deny {
            request_id,
            stage,
            reason,
            policy_id,
        } => IpsecInnerVerdict::Deny {
            request_id: *request_id,
            stage,
            reason: *reason,
            policy_id: *policy_id,
        },
        IpsecInnerDecision::WouldPermit { request_id, .. } => {
            IpsecInnerVerdict::WouldPermit {
                request_id: *request_id,
            }
        }
    }
}

/// Post one D11 verdict. This is the only Rust-side output for V1; a full
/// verdict queue is an E24 uncertain terminal (never a retry or q0 fallback).
pub(crate) fn post_ipsec_inner_verdict(
    queue: &IpsecInnerVerdictQueue,
    decision: &IpsecInnerDecision,
) -> Result<(), IpsecInnerDecision> {
    queue.try_post(verdict_from_decision(decision)).map_err(|_| {
        IpsecInnerDecision::Deny {
            request_id: decision.request_id(),
            stage: "d11_verdict_queue_full",
            reason: reason::VERDICT_UNCERTAIN,
            policy_id: 0,
        }
    })
}

/// Direct helper for a descriptor already owned by a worker. It builds the
/// borrowed payload view from the pool slot then invokes D13/D14; ownership is
/// retained by the caller until the verdict ACK (`IpsecInnerSlabPool::ack_release`).
pub(crate) fn adjudicate_descriptor(
    view: &RuntimeView,
    pool: &IpsecInnerSlabPool,
    descriptor: &IpsecInnerDescriptor,
    input: IpsecInnerInput<'_>,
) -> IpsecInnerDecision {
    let Some(buffer) = pool.buffer(descriptor.slab_id) else {
        return deny(&input, "d11_slab_unavailable", reason::SLAB_EXHAUSTED);
    };
    let len = descriptor.len as usize;
    let Some(inner_packet) = buffer.get(..len) else {
        ipsec_inner_parse_drops_total.fetch_add(1, Ordering::Relaxed);
        return deny(&input, "d11_slab_length", reason::PARSE_ECN);
    };
    let input = IpsecInnerInput {
        inner_packet,
        slab_id: descriptor.slab_id,
        descriptor: Some(descriptor),
        ..input
    };
    adjudicate_ipsec_inner(view, input)
}

/// Per-protocol synthetic meta flag. It is intentionally not GRE/WG's bit.
pub(crate) const IPSEC_INNER_INGRESS_FLAG: u8 = 1 << 6;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::afxdp::types::{ForwardingState, PMechInventory, RuntimeView, ValidationState};
    use crate::afxdp::ipsec_inner_queue::reason;
    use crate::protocol::{
        IpsecMainRouteNextHopSnapshot, IpsecMainRouteSnapshot, IpsecPMechInventorySnapshot,
        IpsecPMechTunnelRowSnapshot, IpsecTrafficSelectorSnapshot,
    };
    use std::sync::Arc;

    fn test_inventory(fib_generation: u32) -> Arc<PMechInventory> {
        let snapshot = IpsecPMechInventorySnapshot {
            policy_identity: "01".repeat(32),
            generation: 77,
            fib_generation,
            complete: true,
            main_routes: vec![IpsecMainRouteSnapshot {
                table: 254,
                family: "inet".into(),
                destination: "10.0.0.0/24".into(),
                next_hops: vec![IpsecMainRouteNextHopSnapshot {
                    ifindex: 10,
                    weight: 1,
                }],
                ..Default::default()
            }],
            tunnel_rows: vec![IpsecPMechTunnelRowSnapshot {
                stn: "st0".into(),
                if_id: 1,
                logical_ifindex: 10,
                explicit_selectors: vec![IpsecTrafficSelectorSnapshot {
                    name: "selector".into(),
                    local_ts: "192.0.2.0/24".into(),
                    remote_ts: "10.0.0.0/24".into(),
                    source: "named".into(),
                }],
                effective_prefixes: vec!["10.0.0.0/24".into()],
                ingress_prefixes: vec!["10.0.0.0/24".into()],
                inventory_generation: 77,
                fib_generation,
                source_kind: "xfrmi".into(),
                selector_provenance: "named".into(),
                inventory_complete: true,
                inventory_valid: true,
                inventory_reason: String::new(),
            }],
        };
        Arc::new(PMechInventory::from_snapshot(Some(&snapshot)))
    }

    fn view_with_rows(
        config_generation: u64,
        fib_generation: u32,
        rows: IpsecTunnelRows,
        forwarding: ForwardingState,
    ) -> RuntimeView {
        RuntimeView::new_with_ipsec_authority( // runtime-view-canary: test-local
            ValidationState {
                snapshot_installed: true,
                config_generation,
                fib_generation,
            },
            Arc::new(forwarding),
            Arc::new(rows),
            config_generation,
            test_inventory(fib_generation),
            1,
        )
    }

    fn advisory(
        snapshot_generation: u64,
        config_generation: u64,
        fib_generation: u32,
        zone_id: u16,
        if_id: u32,
    ) -> IpsecInnerAdvisory {
        IpsecInnerAdvisory {
            snapshot_generation,
            config_generation,
            fib_generation,
            zone_id,
            if_id,
            pmech_inventory_generation: 77,
            pmech_inventory_fib_generation: fib_generation,
            pmech_policy_identity: [1; 32],
            expected_routing_domain: 0,
            expected_fib_table: 254,
        }
    }

    fn test_packet(destination: [u8; 4]) -> [u8; 20] {
        let mut packet = [0; 20];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&20u16.to_be_bytes());
        packet[8] = 64;
        packet[9] = 6;
        packet[12..16].copy_from_slice(&[192, 0, 2, 1]);
        packet[16..20].copy_from_slice(&destination);
        packet
    }

    fn input<'a>(bytes: &'a [u8], advisory: IpsecInnerAdvisory) -> IpsecInnerInput<'a> {
        IpsecInnerInput {
            slab_id: 0,
            inner_packet: bytes,
            stn: "st0",
            inner_family: libc::AF_INET as u8,
            inner_eth_proto: 0x0800,
            protocol: 6,
            rel_l4_offset: 20,
            payload_offset: 20,
            logical_ifindex: 10,
            rx_queue_index: 0,
            advisory,
            descriptor: None,
        }
    }

    #[test]
    fn unknown_stn_is_ifid_underivable_not_default_zone() {
        let v = view_with_rows(1, 1, IpsecTunnelRows::default(), ForwardingState::default());
        let d = adjudicate_ipsec_inner(
            &v,
            input(
                &[0x45; 20],
                advisory(1, 1, 1, 1, 1),
            ),
        );
        assert_eq!(d.reason(), Some(reason::IFID_UNDERIVABLE));
    }

    #[test]
    fn duplicate_if_id_claims_are_ambiguous_per_claimant() {
        let rows = IpsecTunnelRows::new([
            IpsecTunnelRow {
                stn: "st0".into(),
                if_id: 7,
                logical_ifindex: 10,
            },
            IpsecTunnelRow {
                stn: "st1".into(),
                if_id: 7,
                logical_ifindex: 11,
            },
            IpsecTunnelRow {
                stn: "st2".into(),
                if_id: 8,
                logical_ifindex: 12,
            },
        ]);
        assert!(rows.exact("st0").is_none());
        assert!(rows.exact("st1").is_none());
        assert_eq!(rows.exact("st2").map(|row| row.if_id), Some(8));
    }

    #[test]
    fn stale_generation_is_terminal_before_pipeline() {
        let v = view_with_rows(
            2,
            1,
            IpsecTunnelRows::new([IpsecTunnelRow {
                stn: "st0".into(),
                if_id: 1,
                logical_ifindex: 10,
            }]),
            ForwardingState::default(),
        );
        let d = adjudicate_ipsec_inner(
            &v,
            input(
                &[0x45; 20],
                advisory(1, 1, 1, 1, 1),
            ),
        );
        assert_eq!(d.reason(), Some(reason::STALE_GENERATION));
    }

    #[test]
    fn would_permit_is_a_verdict_and_never_a_rust_permit() {
        let mut forwarding = ForwardingState::default();
        forwarding.ifindex_to_zone_id.insert(10, 1);
        let rows = IpsecTunnelRows::new([IpsecTunnelRow {
            stn: "st0".into(),
            if_id: 1,
            logical_ifindex: 10,
        }]);
        let v = view_with_rows(1, 1, rows, forwarding);
        let d = adjudicate_ipsec_inner(
            &v,
            input(
                &test_packet([10, 0, 0, 1]),
                advisory(1, 1, 1, 1, 1),
            ),
        );
        assert!(d.is_would_permit());
        assert_eq!(d.reason(), None);
        assert_eq!(d.runtime_view_publication_generation(), Some(1));

        let outside = adjudicate_ipsec_inner(
            &v,
            input(
                &test_packet([203, 0, 113, 9]),
                advisory(1, 1, 1, 1, 1),
            ),
        );
        assert_eq!(outside.reason(), Some(reason::NO_ROUTE));
    }

    #[test]
    fn d14_input_logical_ifindex_mismatch_is_ifid_underivable() {
        let mut forwarding = ForwardingState::default();
        forwarding.ifindex_to_zone_id.insert(10, 1);
        let rows = IpsecTunnelRows::new([IpsecTunnelRow {
            stn: "st0".into(),
            if_id: 1,
            logical_ifindex: 10,
        }]);
        let v = view_with_rows(1, 1, rows, forwarding);
        let mut claimed = input(
            &[0x45; 20],
            advisory(1, 1, 1, 1, 1),
        );
        claimed.logical_ifindex = 11;
        assert_eq!(
            adjudicate_ipsec_inner(&v, claimed).reason(),
            Some(reason::IFID_UNDERIVABLE)
        );
    }

    #[test]
    fn d14_advisory_zone_and_ifid_mismatch_drop() {
        let mut forwarding = ForwardingState::default();
        forwarding.ifindex_to_zone_id.insert(10, 1);
        let rows = IpsecTunnelRows::new([IpsecTunnelRow {
            stn: "st0".into(),
            if_id: 7,
            logical_ifindex: 10,
        }]);
        let v = view_with_rows(1, 1, rows, forwarding);
        let mut a = advisory(1, 1, 1, 2, 7);
        assert_eq!(
            adjudicate_ipsec_inner(&v, input(&[0x45; 20], a)).reason(),
            Some(reason::ZONE_ADVISORY_MISMATCH)
        );
        a.zone_id = 1;
        a.if_id = 8;
        assert_eq!(
            adjudicate_ipsec_inner(&v, input(&[0x45; 20], a)).reason(),
            Some(reason::ZONE_ADVISORY_MISMATCH)
        );
    }
}
