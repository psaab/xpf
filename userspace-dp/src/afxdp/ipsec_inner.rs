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
    IPSEC_INNER_VERDICT_QUEUE_CONTENDED_TOTAL, IPSEC_INNER_VERDICT_QUEUE_FULL_TOTAL,
    IPSEC_INNER_WORKER_ORPHAN_REAPED_TOTAL, IPSEC_INNER_WORKER_QUEUE_FULL_TOTAL,
    IPSEC_INNER_WORKER_RETIRED_TOTAL,
};
use super::{
    ForwardingDisposition, ForwardingState, IpsecTunnelRows, PMechInventory, RouteIdentity,
    RuntimeView, UserspaceDpMeta, ValidationState,
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
#[allow(non_upper_case_globals)]
pub(crate) static ipsec_inner_permit_forward_armed_total: AtomicU64 = AtomicU64::new(0);

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
    // #15151: contention counted apart from genuine full.
    pub ipsec_inner_worker_queue_busy_total: u64,
    pub ipsec_inner_verdict_queue_full_total: u64,
    pub ipsec_inner_verdict_queue_contended_total: u64,
    pub ipsec_inner_slab_exhausted_total: u64,
    pub ipsec_inner_worker_retired_total: u64,
    pub ipsec_inner_worker_orphan_reaped_total: u64,
    pub ipsec_inner_orphan_provisional_total: u64,
    pub ipsec_inner_permit_forward_armed_total: u64,
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
        ipsec_inner_worker_queue_busy_total: IPSEC_INNER_WORKER_QUEUE_BUSY_TOTAL
            .load(Ordering::Relaxed),
        ipsec_inner_verdict_queue_full_total: IPSEC_INNER_VERDICT_QUEUE_FULL_TOTAL
            .load(Ordering::Relaxed),
        ipsec_inner_verdict_queue_contended_total: IPSEC_INNER_VERDICT_QUEUE_CONTENDED_TOTAL
            .load(Ordering::Relaxed),
        ipsec_inner_slab_exhausted_total: IPSEC_INNER_SLAB_EXHAUSTED_TOTAL.load(Ordering::Relaxed),
        ipsec_inner_worker_retired_total: IPSEC_INNER_WORKER_RETIRED_TOTAL.load(Ordering::Relaxed),
        ipsec_inner_worker_orphan_reaped_total: IPSEC_INNER_WORKER_ORPHAN_REAPED_TOTAL
            .load(Ordering::Relaxed),
        ipsec_inner_orphan_provisional_total: IPSEC_INNER_ORPHAN_PROVISIONAL_TOTAL
            .load(Ordering::Relaxed),
        ipsec_inner_permit_forward_armed_total: ipsec_inner_permit_forward_armed_total
            .load(Ordering::Relaxed),
    }
}


/// Advisory/generation fields carried in each Go submit row. They occupy 70
/// of the 79-byte `SUBMIT_PMECH_TAIL_LEN` tail; the other 9 bytes are the
/// monotonic deadline and its clock id. Go remains the pre-gate authority;
/// Rust treats every value as advisory and cross-checks it against the exact
/// tunnel row and the one RuntimeView loaded by the worker tick.
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
        connection_id: u64,
        stage: &'static str,
        reason: u8,
        policy_id: u32,
    },
    WouldPermit {
        request_id: u64,
        connection_id: u64,
        runtime_view_publication_generation: u64,
    },
}

impl IpsecInnerDecision {
    pub(crate) fn request_id(&self) -> u64 {
        match self {
            Self::Deny { request_id, .. } | Self::WouldPermit { request_id, .. } => *request_id,
        }
    }

    pub(crate) fn connection_id(&self) -> u64 {
        match self {
            Self::Deny { connection_id, .. } | Self::WouldPermit { connection_id, .. } => {
                *connection_id
            }
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
        connection_id: input
            .descriptor
            .map(|descriptor| descriptor.connection_id)
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
    // repeat no name/string resolution here. A missing map entry is zone 0,
    // which takes the explicit E1 terminal below and never reaches a policy
    // default action or the advisory comparison.
    let ingress_zone = forwarding
        .ifindex_to_zone_id
        .get(&row.logical_ifindex)
        .copied()
        .unwrap_or(0);
    if ingress_zone == 0 || meta.ingress_zone == 0 {
        zone_gate_unzoned_total.fetch_add(1, Ordering::Relaxed);
        return Err(deny(input, "d14_zone_unzoned", reason::ZONE_UNZONED));
    }
    if ingress_zone != meta.ingress_zone || ingress_zone != advisory.zone_id || advisory.zone_id == 0 {
        zone_gate_ambiguous_total.fetch_add(1, Ordering::Relaxed);
        return Err(deny(input, "d14_zone_advisory_mismatch", reason::ZONE_ADVISORY_MISMATCH));
    }
    let Some(pmech_row) = pmech_inventory.exact_tunnel(input.stn, row.if_id, row.logical_ifindex) else {
        return Err(deny(input, "d22_tunnel_inventory_invalid", reason::EVALUATOR_UNAVAILABLE));
    };
    let Some(source) = crate::afxdp::frame::parse_packet_source_from_frame(&owned, meta) else {
        ipsec_inner_parse_drops_total.fetch_add(1, Ordering::Relaxed);
        return Err(deny(input, "d21_source_unresolved", reason::PARSE_ECN));
    };
    if !pmech_row.allows_source(source) {
        return Err(deny(
            input,
            "d21_source_outside_ingress",
            reason::DOMAIN_OVERLAP,
        ));
    }
    let Some(destination) =
        crate::afxdp::frame::parse_packet_destination_from_frame(&owned, meta)
    else {
        ipsec_inner_parse_drops_total.fetch_add(1, Ordering::Relaxed);
        return Err(deny(input, "d22_destination_unresolved", reason::PARSE_ECN));
    };
    let lookup = super::forwarding::lookup_forwarding_resolution(forwarding, destination);
    let Some(actual_route) = lookup.selected_route else {
        return Err(deny(input, "d19_actual_route_missing", reason::NO_ROUTE));
    };
    if actual_route != (RouteIdentity { domain: 0, table: 254 }) {
        return Err(deny(
            input,
            "d22_route_domain_mismatch",
            reason::OTHER_DOMAIN,
        ));
    }
    if lookup.resolution.disposition != ForwardingDisposition::ForwardCandidate {
        return Err(deny(input, "d19_route_not_forwardable", reason::NO_ROUTE));
    }
    // The local selector projection is separate from the remote, route-derived
    // ingress projection checked for the decrypted packet's source above.
    // Forwarding may continue only when the destination is locally selected
    // and reachable through a non-tunnel main-table route.
    let (selectors, effective_prefixes) = pmech_row.selector_projection();
    if selectors.is_empty() || effective_prefixes.is_empty() {
        return Err(deny(input, "d22_selector_inventory_invalid", reason::EVALUATOR_UNAVAILABLE));
    }
    if !pmech_row.allows_destination(destination) {
        return Err(deny(
            input,
            "d22_destination_outside_selector",
            reason::DOMAIN_OVERLAP,
        ));
    }
    let egress_zone = forwarding.egress_zone_id(lookup.resolution.egress_ifindex);
    // AH-sighted IPv6 chains keep protocol-51 identity even though the shim
    // reports the inner TCP/UDP header. Resolve that identity before port
    // parsing or policy evaluation, matching the flowless packet path.
    let effective_protocol = crate::afxdp::frame::flowless_effective_protocol(&owned, meta);
    // Use the shared parser for declared-length-bounded TCP/UDP ports.
    // Non-first fragments contain payload, not an L4 header, at this offset.
    let ports = if !matches!(
        effective_protocol,
        crate::ip_proto::PROTO_TCP | crate::ip_proto::PROTO_UDP
    ) || crate::afxdp::frame::frame_is_non_first_fragment(&owned, meta)
    {
        None
    } else {
        crate::afxdp::frame::live_frame_ports_from_meta_bytes(&owned, meta)
    };
    let (src_port, dst_port, l4_present) = match ports {
        Some((src, dst)) => (src, dst, true),
        None => (0, 0, false),
    };
    // #14366: parse the real ICMP type/code from the same owned frame the
    // ports above were parsed from, so a type-constrained DENY term
    // (junos-icmp-ping = type 8) can match. The helper returns None for
    // non-ICMP protocols (meta.protocol on this frame is input.protocol,
    // including the native-fragment sentinel) and for truncated or
    // non-first-fragment frames, preserving fail-closed behaviour there.
    // TCP/UDP verdicts are unchanged: the argument stays None for them.
    let packet_icmp = crate::afxdp::poll_descriptor::policy_packet_icmp(&owned, meta);
    let policy = crate::policy::evaluate_policy_result_l3_aware(
        &forwarding.policy,
        ingress_zone,
        egress_zone,
        source,
        destination,
        effective_protocol,
        src_port,
        dst_port,
        packet_icmp,
        input.inner_packet.len() as u64,
        l4_present,
    );
    if !matches!(policy.action, crate::policy::PolicyAction::Permit) {
        return Err(IpsecInnerDecision::Deny {
            request_id: input.descriptor.map(|descriptor| descriptor.request_id).unwrap_or_default(),
            connection_id: input.descriptor.map(|descriptor| descriptor.connection_id).unwrap_or_default(),
            stage: "d15_zone_policy",
            reason: reason::LEGACY_POLICY_DENY,
            policy_id: policy.policy_id,
        });
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

    // S9.5 FORWARD permit join: D13/D14 above is the complete stateless
    // adjudication (zone, tunnel row, route domain, source and destination
    // containment), and the worker loop converts this WOULD_PERMIT into a
    // leased adjudicated-TUN write for SUBMIT_FLAG_FORWARD frames. Still no
    // session install, flow-cache publish, NAT mutation, screen stage, or
    // NF_ACCEPT: the permit is stateless and re-enters the kernel main table
    // (D_usp1), with the original NFQUEUE packet terminally dropped by Go to
    // avoid a duplicate. The verdict is WOULD_PERMIT either way; it is NOT
    // E28, and Go's byte-52 counter stays reserved for evaluator/snapshot/
    // worker-set unavailability.
    IpsecInnerDecision::WouldPermit {
        request_id: input
            .descriptor
            .map(|d| d.request_id)
            .unwrap_or_default(),
        connection_id: input
            .descriptor
            .map(|descriptor| descriptor.connection_id)
            .unwrap_or_default(),
        runtime_view_publication_generation,
    }
}

pub(crate) fn verdict_from_decision(decision: &IpsecInnerDecision) -> IpsecInnerVerdict {
    match decision {
        IpsecInnerDecision::Deny {
            request_id,
            connection_id,
            stage,
            reason,
            policy_id,
        } => IpsecInnerVerdict::Deny {
            request_id: *request_id,
            connection_id: *connection_id,
            stage,
            reason: *reason,
            policy_id: *policy_id,
        },
        IpsecInnerDecision::WouldPermit {
            request_id,
            connection_id,
            ..
        } => IpsecInnerVerdict::WouldPermit {
            request_id: *request_id,
            connection_id: *connection_id,
        },
    }
}

/// Post one D11 verdict. This is the only Rust-side output for V1; a
/// true-full verdict queue is an E24 uncertain terminal (never a retry or
/// q0 fallback). Contention never reaches this mapping: `post` waits on
/// the queue mutex (#15150).
pub(crate) fn post_ipsec_inner_verdict(
    queue: &IpsecInnerVerdictQueue,
    decision: &IpsecInnerDecision,
) -> Result<(), IpsecInnerDecision> {
    queue.post(verdict_from_decision(decision)).map_err(|_| {
        IpsecInnerDecision::Deny {
            request_id: decision.request_id(),
            connection_id: decision.connection_id(),
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
    use crate::afxdp::types::{
        ForwardingState, IpsecTunnelRow, LeakRuleV4, PMechInventory, RouteEntryV4, RouteIdentity,
        RuntimeView, ValidationState,
    };
    use crate::prefix::PrefixV4;
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
            main_routes: vec![
                IpsecMainRouteSnapshot {
                    domain: 0,
                    table: 254,
                    family: "inet".into(),
                    destination: "0.0.0.0/0".into(),
                    disposition: 1, // RTN_UNICAST
                    next_hops: vec![IpsecMainRouteNextHopSnapshot {
                        ifindex: 20,
                        weight: 1,
                    }],
                    ..Default::default()
                },
                IpsecMainRouteSnapshot {
                    domain: 0,
                    table: 254,
                    family: "inet".into(),
                    destination: "192.0.2.0/24".into(),
                    disposition: 1,
                    next_hops: vec![IpsecMainRouteNextHopSnapshot { ifindex: 20, weight: 1 }],
                    ..Default::default()
                },
                IpsecMainRouteSnapshot {
                    domain: 0,
                    table: 254,
                    family: "inet".into(),
                    destination: "10.0.0.0/24".into(),
                    disposition: 1, // RTN_UNICAST
                    next_hops: vec![IpsecMainRouteNextHopSnapshot {
                        ifindex: 10,
                        weight: 1,
                    }],
                    ..Default::default()
                },
            ],
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
                destination_prefixes: vec!["192.0.2.0/24".into()],
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

    fn test_forwarding_authority() -> ForwardingState {
        let mut forwarding = ForwardingState::default();
        forwarding.ifindex_to_zone_id.insert(10, 1);
        forwarding.route_table_identities.insert(
            "inet.0".into(),
            RouteIdentity {
                domain: 0,
                table: 254,
            },
        );
        forwarding.route_table_identities.insert(
            "inet6.0".into(),
            RouteIdentity {
                domain: 0,
                table: 254,
            },
        );
        forwarding.route_table_identity_map_complete = true;
        forwarding
    }

    fn test_route(prefix: &str, ifindex: i32) -> RouteEntryV4 {
        let prefix = PrefixV4::from_net(prefix.parse().expect("IPv4 route prefix"));
        let next_hop = if ifindex == 20 {
            "192.0.2.1".parse().expect("default-route next hop")
        } else {
            "10.0.0.2".parse().expect("tunnel-network next hop")
        };
        RouteEntryV4::single(
            prefix,
            ifindex,
            0,
            Some(next_hop),
            false,
            String::new(),
            0,
        )
    }

    fn test_forwarding_with_route(prefix: &str, ifindex: i32) -> ForwardingState {
        let mut forwarding = test_forwarding_authority();
        forwarding.routes_v4.insert(
            "inet.0".into(),
            vec![test_route(prefix, ifindex)],
        );
        forwarding
    }

    fn test_packet_with_source(source: [u8; 4], destination: [u8; 4]) -> [u8; 20] {
        let mut packet = [0; 20];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&20u16.to_be_bytes());
        packet[8] = 64;
        packet[9] = 6;
        packet[12..16].copy_from_slice(&source);
        packet[16..20].copy_from_slice(&destination);
        packet
    }

    fn test_forwarding_with_leaked_route() -> ForwardingState {
        let mut forwarding = test_forwarding_authority();
        forwarding.route_table_identities.insert(
            "tenant.inet.0".into(),
            RouteIdentity {
                domain: 501,
                table: 501,
            },
        );
        forwarding.route_table_identities.insert(
            "tenant.inet6.0".into(),
            RouteIdentity {
                domain: 501,
                table: 501,
            },
        );
        let prefix = PrefixV4::from_net("10.0.0.0/24".parse().expect("leak prefix"));
        forwarding.leak_rules_v4.insert(
            "inet.0".into(),
            vec![LeakRuleV4 {
                prefix,
                next_table: "tenant.inet.0".into(),
                rule_priority: 1,
                incarnation: 1,
            }],
        );
        forwarding.routes_v4.insert(
            "tenant.inet.0".into(),
            vec![test_route("10.0.0.0/24", 10)],
        );
        forwarding
    }

    fn test_packet(destination: [u8; 4]) -> [u8; 20] {
        test_packet_with_source([192, 0, 2, 1], destination)
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
        let v = view_with_rows(1, 1, IpsecTunnelRows::default(), test_forwarding_authority());
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
            test_forwarding_authority(),
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
    fn d14_source_proof_rejects_outside_source_even_with_allowed_destination_9506() {
        let forwarding = test_forwarding_with_route("10.0.0.0/24", 10);
        let rows = IpsecTunnelRows::new([IpsecTunnelRow {
            stn: "st0".into(),
            if_id: 1,
            logical_ifindex: 10,
        }]);
        let view = view_with_rows(1, 1, rows, forwarding);
        let packet = test_packet([10, 0, 0, 1]); // source 192.0.2.1 is outside ingress proof
        assert_eq!(
            adjudicate_ipsec_inner(&view, input(&packet, advisory(1, 1, 1, 1, 1))).reason(),
            Some(reason::DOMAIN_OVERLAP)
        );
    }

    #[test]
    fn d14_actual_route_miss_is_e19_9506() {
        let forwarding = test_forwarding_authority(); // no FIB route for 10.0.0.1
        let rows = IpsecTunnelRows::new([IpsecTunnelRow {
            stn: "st0".into(),
            if_id: 1,
            logical_ifindex: 10,
        }]);
        let view = view_with_rows(1, 1, rows, forwarding);
        let packet = test_packet_with_source([10, 0, 0, 1], [10, 0, 0, 1]);
        assert_eq!(
            adjudicate_ipsec_inner(&view, input(&packet, advisory(1, 1, 1, 1, 1))).reason(),
            Some(reason::NO_ROUTE)
        );
    }

    #[test]
    fn d14_actual_route_table_mismatch_is_e22_9506() {
        let forwarding = test_forwarding_with_leaked_route();
        let rows = IpsecTunnelRows::new([IpsecTunnelRow {
            stn: "st0".into(),
            if_id: 1,
            logical_ifindex: 10,
        }]);
        let view = view_with_rows(1, 1, rows, forwarding);
        let packet = test_packet_with_source([10, 0, 0, 1], [10, 0, 0, 1]);
        assert_eq!(
            adjudicate_ipsec_inner(&view, input(&packet, advisory(1, 1, 1, 1, 1))).reason(),
            Some(reason::OTHER_DOMAIN)
        );
    }

    #[test]
    fn d14_missing_neighbor_route_is_e19_style_denial_9506() {
        let forwarding = test_forwarding_with_route("10.0.0.0/24", 10);
        let rows = IpsecTunnelRows::new([IpsecTunnelRow {
            stn: "st0".into(),
            if_id: 1,
            logical_ifindex: 10,
        }]);
        let view = view_with_rows(1, 1, rows, forwarding.clone());
        let destination = "10.0.0.1".parse().expect("IPv4 destination");
        let route = crate::afxdp::forwarding::lookup_forwarding_resolution(
            &forwarding,
            destination,
        );
        assert_eq!(
            route.selected_route,
            Some(RouteIdentity {
                domain: 0,
                table: 254,
            })
        );
        assert_eq!(
            route.resolution.disposition,
            ForwardingDisposition::MissingNeighbor
        );

        let packet = test_packet_with_source([10, 0, 0, 1], [10, 0, 0, 1]);
        let decision =
            adjudicate_ipsec_inner(&view, input(&packet, advisory(1, 1, 1, 1, 1)));
        assert_eq!(decision.reason(), Some(reason::NO_ROUTE));
    }

    #[test]
    fn d14_destination_outside_selector_denies_even_with_default_route_9506() {
        // The deny-only phase let a destination outside the selector
        // projection Would-Permit when a 0/0 main-table route resolved it
        // ("source proof replaces destination prefix gate"). #9506 S9.5
        // connects the terminal to forwarding, so the explicit
        // destination-containment prerequisite now applies: a permitted
        // re-entry can never widen the reachable set beyond the tunnel's
        // selector projection.
        let mut forwarding = test_forwarding_authority();
        forwarding.routes_v4.insert(
            "inet.0".into(),
            vec![test_route("0.0.0.0/0", 20)],
        );
        let next_hop: std::net::IpAddr = "192.0.2.1".parse().expect("IPv4 next hop");
        forwarding.neighbors.insert(
            (20, next_hop),
            crate::afxdp::NeighborEntry {
                mac: [0x02, 0, 0, 0, 0, 20],
            },
        );
        let route = crate::afxdp::forwarding::lookup_forwarding_resolution(
            &forwarding,
            "203.0.113.9".parse().expect("IPv4 destination"),
        );
        assert_eq!(
            route.resolution.disposition,
            ForwardingDisposition::ForwardCandidate
        );
        let rows = IpsecTunnelRows::new([IpsecTunnelRow {
            stn: "st0".into(),
            if_id: 1,
            logical_ifindex: 10,
        }]);
        let view = view_with_rows(1, 1, rows, forwarding);
        // Source is inside the ingress proof (10.0.0.0/24); the destination
        // 203.0.113.9 is outside the selector projection.
        let packet = test_packet_with_source([10, 0, 0, 1], [203, 0, 113, 9]);
        let decision =
            adjudicate_ipsec_inner(&view, input(&packet, advisory(1, 1, 1, 1, 1)));
        assert!(!decision.is_would_permit());
        assert_eq!(decision.reason(), Some(reason::DOMAIN_OVERLAP));
        // Deny carries stage "d22_destination_outside_selector"; reason is
        // the wire-stable identity used by the event codec.
    }

    #[test]
    fn d14_destination_inside_remote_selector_but_outside_local_selector_denies_9506() {
        let mut forwarding = test_forwarding_with_route("10.0.0.0/24", 10);
        let next_hop: std::net::IpAddr = "10.0.0.2".parse().expect("IPv4 next hop");
        forwarding.neighbors.insert(
            (10, next_hop),
            crate::afxdp::NeighborEntry {
                mac: [0x02, 0, 0, 0, 0, 10],
            },
        );
        let rows = IpsecTunnelRows::new([IpsecTunnelRow {
            stn: "st0".into(),
            if_id: 1,
            logical_ifindex: 10,
        }]);
        let view = view_with_rows(1, 1, rows, forwarding);
        let packet = test_packet_with_source([10, 0, 0, 1], [10, 0, 0, 9]);
        let decision =
            adjudicate_ipsec_inner(&view, input(&packet, advisory(1, 1, 1, 1, 1)));
        assert!(!decision.is_would_permit());
        assert_eq!(decision.reason(), Some(reason::DOMAIN_OVERLAP));
    }

    #[test]
    fn would_permit_verdict_is_not_itself_a_terminal_permit() {
        let forwarding = local_lan_forwarding();
        let rows = IpsecTunnelRows::new([IpsecTunnelRow {
            stn: "st0".into(),
            if_id: 1,
            logical_ifindex: 10,
        }]);
        let v = view_with_rows(1, 1, rows, forwarding);
        let packet = test_packet_with_source([10, 0, 0, 1], [192, 0, 2, 1]);
        let d = adjudicate_ipsec_inner(&v, input(&packet, advisory(1, 1, 1, 1, 1)));
        assert!(d.is_would_permit());
        assert_eq!(d.reason(), None);
        assert_eq!(d.runtime_view_publication_generation(), Some(1));

        let outside_packet = test_packet_with_source([10, 0, 0, 1], [203, 0, 113, 9]);
        let outside = adjudicate_ipsec_inner(
            &v,
            input(&outside_packet, advisory(1, 1, 1, 1, 1)),
        );
        assert_eq!(outside.reason(), Some(reason::DOMAIN_OVERLAP));
    }

    #[test]
    fn d14_input_logical_ifindex_mismatch_is_ifid_underivable() {
        let mut forwarding = test_forwarding_authority();
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
        let mut forwarding = test_forwarding_authority();
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

    fn st0_rows() -> IpsecTunnelRows {
        IpsecTunnelRows::new([IpsecTunnelRow {
            stn: "st0".into(),
            if_id: 1,
            logical_ifindex: 10,
        }])
    }

    /// The forwarding authority behind
    /// `would_permit_is_a_verdict_and_never_a_rust_permit`: zoned st0, a
    /// main-table route to the tunnel network, and a resolved next hop.
    fn would_permit_forwarding() -> ForwardingState {
        let mut forwarding = test_forwarding_with_route("10.0.0.0/24", 10);
        let next_hop: std::net::IpAddr = "10.0.0.2".parse().expect("IPv4 next hop");
        forwarding.neighbors.insert(
            (10, next_hop),
            crate::afxdp::NeighborEntry {
                mac: [0x02, 0, 0, 0, 0, 10],
            },
        );
        forwarding
    }

    fn local_lan_forwarding() -> ForwardingState {
        let mut forwarding = test_forwarding_with_route("0.0.0.0/0", 20);
        forwarding.ifindex_to_zone_id.insert(20, 2);
        forwarding.ifindex_unambiguous_zone_id.insert(20, 2);
        forwarding.zone_id_to_name.insert(1, "vpn".into());
        forwarding.zone_id_to_name.insert(2, "lan".into());
        let next_hop: std::net::IpAddr = "192.0.2.1".parse().expect("IPv4 next hop");
        forwarding.neighbors.insert(
            (20, next_hop),
            crate::afxdp::NeighborEntry { mac: [0x02, 0, 0, 0, 0, 20] },
        );
        let mut zones: rustc_hash::FxHashMap<String, u16> = Default::default();
        zones.insert("vpn".into(), 1);
        zones.insert("lan".into(), 2);
        forwarding.policy = crate::policy::parse_policy_state("permit", &[], &zones);
        forwarding
    }

    fn view_with_inventory_fib(
        validation_fib_generation: u32,
        inventory_fib_generation: u32,
        forwarding: ForwardingState,
    ) -> RuntimeView {
        RuntimeView::new_with_ipsec_authority( // runtime-view-canary: test-local
            ValidationState {
                snapshot_installed: true,
                config_generation: 1,
                fib_generation: validation_fib_generation,
            },
            Arc::new(forwarding),
            Arc::new(st0_rows()),
            1,
            test_inventory(inventory_fib_generation),
            1,
        )
    }

    fn assert_denied(decision: IpsecInnerDecision, stage: &'static str, reason_byte: u8) {
        assert_eq!(
            decision,
            IpsecInnerDecision::Deny {
                request_id: 0,
                connection_id: 0,
                stage,
                reason: reason_byte,
                policy_id: 0,
            }
        );
    }

    /// Positive control for the cells below: the unmodified fixture reaches
    /// the deny-only V1 terminal, so each cell's denial is caused by the one
    /// field it perturbs.
    #[test]
    fn d14_fixture_reaches_would_permit_9506() {
        let view = view_with_rows(1, 1, st0_rows(), local_lan_forwarding());
        let packet = test_packet_with_source([10, 0, 0, 1], [192, 0, 2, 1]);
        let decision = adjudicate_ipsec_inner(&view, input(&packet, advisory(1, 1, 1, 1, 1)));
        assert!(decision.is_would_permit(), "{decision:?}");
    }

    #[test]
    fn h14_01_remote_to_local_lan_regression_13956() {
        let mut forwarding = local_lan_forwarding();
        let mut zones: rustc_hash::FxHashMap<String, u16> = Default::default();
        zones.insert("vpn".into(), 1);
        zones.insert("lan".into(), 2);
        forwarding.policy = crate::policy::parse_policy_state("permit", &[], &zones);
        let view = view_with_rows(1, 1, st0_rows(), forwarding);
        let packet = test_packet_with_source([10, 0, 0, 1], [192, 0, 2, 5]);
        let decision = adjudicate_ipsec_inner(&view, input(&packet, advisory(1, 1, 1, 1, 1)));
        assert!(decision.is_would_permit(), "{decision:?}");
    }

    #[test]
    fn h14_02_default_deny_policy_denies_remote_to_lan_13956() {
        let mut forwarding = local_lan_forwarding();
        let mut zones: rustc_hash::FxHashMap<String, u16> = Default::default();
        zones.insert("vpn".into(), 1);
        zones.insert("lan".into(), 2);
        forwarding.policy = crate::policy::parse_policy_state("deny", &[], &zones);
        let view = view_with_rows(1, 1, st0_rows(), forwarding);
        let packet = test_packet_with_source([10, 0, 0, 1], [192, 0, 2, 5]);
        let decision = adjudicate_ipsec_inner(&view, input(&packet, advisory(1, 1, 1, 1, 1)));
        assert_eq!(decision.reason(), Some(reason::LEGACY_POLICY_DENY), "{decision:?}");
    }
    fn port_term_policy(protocol: &str, destination_port: &str) -> crate::policy::PolicyState {
        let mut zones: rustc_hash::FxHashMap<String, u16> = Default::default();
        zones.insert("vpn".into(), 1);
        zones.insert("lan".into(), 2);
        let rule = crate::PolicyRuleSnapshot {
            name: "vpn-to-lan-port".into(),
            from_zone: "vpn".into(),
            to_zone: "lan".into(),
            source_addresses: vec!["any".into()],
            destination_addresses: vec!["any".into()],
            applications: vec!["any".into()],
            application_terms: vec![crate::PolicyApplicationSnapshot {
                name: "port-term".into(),
                protocol: protocol.into(),
                source_port: String::new(),
                destination_port: destination_port.into(),
                icmp_type: None,
                icmp_code: None,
                inactivity_timeout: None,
            }],
            action: "permit".into(),
            ..Default::default()
        };
        crate::policy::parse_policy_state("deny", &[rule], &zones)
    }
    // #14366: zone pair with a type-constrained ICMP term in one rule and an
    // unconstrained ICMP term in the other. `icmp_type: Some(8)` mirrors
    // junos-icmp-ping; `icmp_type: None` mirrors junos-icmp-all.
    fn icmp_term_policy(
        first_action: &str,
        first_icmp_type: Option<u8>,
        second_action: Option<&str>,
        second_icmp_type: Option<u8>,
        default_action: &str,
    ) -> crate::policy::PolicyState {
        let mut zones: rustc_hash::FxHashMap<String, u16> = Default::default();
        zones.insert("vpn".into(), 1);
        zones.insert("lan".into(), 2);
        let mut rules = vec![crate::PolicyRuleSnapshot {
            policy_id: 101,
            name: "vpn-to-lan-icmp-first".into(),
            from_zone: "vpn".into(),
            to_zone: "lan".into(),
            source_addresses: vec!["any".into()],
            destination_addresses: vec!["any".into()],
            applications: vec!["any".into()],
            application_terms: vec![crate::PolicyApplicationSnapshot {
                name: "icmp-term".into(),
                protocol: "icmp".into(),
                source_port: String::new(),
                destination_port: String::new(),
                icmp_type: first_icmp_type,
                icmp_code: None,
                inactivity_timeout: None,
            }],
            action: first_action.into(),
            ..Default::default()
        }];
        if let Some(action) = second_action {
            rules.push(crate::PolicyRuleSnapshot {
                policy_id: 102,
                name: "vpn-to-lan-icmp-second".into(),
                from_zone: "vpn".into(),
                to_zone: "lan".into(),
                source_addresses: vec!["any".into()],
                destination_addresses: vec!["any".into()],
                applications: vec!["any".into()],
                application_terms: vec![crate::PolicyApplicationSnapshot {
                    name: "icmp-term".into(),
                    protocol: "icmp".into(),
                    source_port: String::new(),
                    destination_port: String::new(),
                    icmp_type: second_icmp_type,
                    icmp_code: None,
                    inactivity_timeout: None,
                }],
                action: action.into(),
                ..Default::default()
            });
        }
        crate::policy::parse_policy_state(default_action, &rules, &zones)
    }

    fn v4_icmp_packet(icmp_type: u8, icmp_code: u8) -> Vec<u8> {
        let total = 28u16;
        let mut packet = vec![0u8; total as usize];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&total.to_be_bytes());
        packet[8] = 64;
        packet[9] = 1;
        packet[12..16].copy_from_slice(&[10, 0, 0, 1]);
        packet[16..20].copy_from_slice(&[192, 0, 2, 5]);
        packet[20] = icmp_type;
        packet[21] = icmp_code;
        packet
    }

    fn icmp_decision(policy: crate::policy::PolicyState, packet: &[u8]) -> IpsecInnerDecision {
        let mut forwarding = local_lan_forwarding();
        forwarding.policy = policy;
        let view = view_with_rows(1, 1, st0_rows(), forwarding);
        let mut inp = input(packet, advisory(1, 1, 1, 1, 1));
        inp.protocol = 1;
        adjudicate_ipsec_inner(&view, inp)
    }

    #[test]
    fn d14_icmp_ping_deny_above_icmp_all_permit_denies_echo_14366() {
        // deny+junos-icmp-ping (type 8, policy_id 101) above
        // permit+junos-icmp-all (policy_id 102): the type-8 frame must
        // hit the DENY at d15_zone_policy attributed to rule 101, not
        // fall through to WouldPermit or to the permit rule. Pre-fix
        // (packet_icmp=None, l4_present=false) the decision still denies
        // but only via policy.rs's #4569 fragment-association override,
        // which re-attributes to the skipped deny — the attribution and
        // the WouldPermit cells are the distinguishing signals; see the
        // docs log for the measured pre-fix shape.
        let policy = icmp_term_policy("deny", Some(8), Some("permit"), None, "deny");
        let packet = v4_icmp_packet(8, 0);
        let d = icmp_decision(policy, &packet);
        assert!(!d.is_would_permit(), "{d:?}");
        assert_eq!(d.reason(), Some(reason::LEGACY_POLICY_DENY), "{d:?}");
        match &d {
            IpsecInnerDecision::Deny { stage, policy_id, .. } => {
                assert_eq!(*stage, "d15_zone_policy", "{d:?}");
                assert_eq!(*policy_id, 101, "deny must be attributed to the ping-deny rule (101): {d:?}");
            }
            other => panic!("type-8 echo must be denied by the ping term, got {other:?}"),
        }
    }

    #[test]
    fn d14_icmp_type3_falls_through_ping_deny_to_icmp_all_permit_14366() {
        // Same pair, type 3: the ping-deny genuinely misses, the
        // permit-icmp-all applies.
        let policy = icmp_term_policy("deny", Some(8), Some("permit"), None, "deny");
        let packet = v4_icmp_packet(3, 0);
        let d = icmp_decision(policy, &packet);
        assert!(d.is_would_permit(), "{d:?}");
    }

    #[test]
    fn d14_icmp_type3_still_denies_under_permit_ping_default_deny_14366() {
        // permit+junos-icmp-ping only, default deny: passing Some((3,0))
        // must not manufacture a permit from the constrained term.
        let policy = icmp_term_policy("permit", Some(8), None, None, "deny");
        let packet = v4_icmp_packet(3, 0);
        let d = icmp_decision(policy, &packet);
        assert_eq!(d.reason(), Some(reason::LEGACY_POLICY_DENY), "{d:?}");
    }

    #[test]
    fn d14_icmp_ping_permit_type8_permits_14366() {
        // Positive control for the constrained permit term itself.
        let policy = icmp_term_policy("permit", Some(8), None, None, "deny");
        let packet = v4_icmp_packet(8, 0);
        let d = icmp_decision(policy, &packet);
        assert!(d.is_would_permit(), "{d:?}");
    }


    fn v4_l4_packet(protocol: u8, src: [u8; 4], dst: [u8; 4], src_port: u16, dst_port: u16, frag: u16) -> Vec<u8> {
        let l4_len = if protocol == 17 { 8 } else { 20 };
        let total = 20 + l4_len;
        let mut packet = vec![0u8; total];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        packet[6..8].copy_from_slice(&frag.to_be_bytes());
        packet[8] = 64;
        packet[9] = protocol;
        packet[12..16].copy_from_slice(&src);
        packet[16..20].copy_from_slice(&dst);
        packet[20..22].copy_from_slice(&src_port.to_be_bytes());
        packet[22..24].copy_from_slice(&dst_port.to_be_bytes());
        packet
    }

    fn v4_port_decision(protocol: u8, dst_port: u16, frag: u16) -> IpsecInnerDecision {
        let proto_name = if protocol == 17 { "udp" } else { "tcp" };
        let mut forwarding = local_lan_forwarding();
        forwarding.policy = port_term_policy(proto_name, "443");
        let view = view_with_rows(1, 1, st0_rows(), forwarding);
        let packet = v4_l4_packet(protocol, [10, 0, 0, 1], [192, 0, 2, 5], 40000, dst_port, frag);
        let mut inp = input(&packet, advisory(1, 1, 1, 1, 1));
        inp.protocol = protocol;
        adjudicate_ipsec_inner(&view, inp)
    }

    #[test]
    fn d14_ipv4_tcp_matching_port_permits_14090() {
        let d = v4_port_decision(6, 443, 0);
        assert!(d.is_would_permit(), "{d:?}");
    }

    #[test]
    fn d14_ipv4_tcp_nonmatching_port_denies_14090() {
        let d = v4_port_decision(6, 8443, 0);
        assert_eq!(d.reason(), Some(reason::LEGACY_POLICY_DENY), "{d:?}");
    }

    #[test]
    fn d14_ipv4_udp_matching_port_permits_14090() {
        let d = v4_port_decision(17, 443, 0);
        assert!(d.is_would_permit(), "{d:?}");
    }

    #[test]
    fn d14_ipv4_udp_nonmatching_port_denies_14090() {
        let d = v4_port_decision(17, 8443, 0);
        assert_eq!(d.reason(), Some(reason::LEGACY_POLICY_DENY), "{d:?}");
    }

    #[test]
    fn d14_ipv4_first_fragment_matching_port_permits_14090() {
        // MF set, offset 0: first fragment carries the real L4 header.
        let d = v4_port_decision(6, 443, 0x2000);
        assert!(d.is_would_permit(), "{d:?}");
    }

    #[test]
    fn d14_ipv4_nonfirst_fragment_flowless_denies_against_port_term_14090() {
        // Offset non-zero: bytes at L4 offset are payload spelling 443, must stay flowless.
        let d = v4_port_decision(6, 443, 0x0001);
        assert_eq!(d.reason(), Some(reason::LEGACY_POLICY_DENY), "{d:?}");
    }

    fn v6_view_and_packet(protocol: u8, dst_port: u16) -> (RuntimeView, Vec<u8>) {
        let proto_name = if protocol == 17 { "udp" } else { "tcp" };
        v6_view_and_packet_inner(proto_name, "443", protocol, dst_port)
    }

    fn v6_view_and_packet_with_policy(
        policy_protocol: &str,
        policy_dst_port: &str,
    ) -> (RuntimeView, Vec<u8>) {
        v6_view_and_packet_inner(policy_protocol, policy_dst_port, 6, 443)
    }

    fn v6_view_and_packet_inner(
        policy_protocol: &str,
        policy_dst_port: &str,
        protocol: u8,
        dst_port: u16,
    ) -> (RuntimeView, Vec<u8>) {
        let src: std::net::Ipv6Addr = "2001:db8:1::1".parse().expect("source");
        let dst: std::net::Ipv6Addr = "2001:db8::5".parse().expect("destination");
        let next_hop: std::net::Ipv6Addr = "2001:db8::ff".parse().expect("next hop");
        let prefixes = [
            ("::/0", 20, None),
            ("2001:db8::/64", 20, Some(next_hop)),
            ("2001:db8:1::/64", 10, Some("2001:db8:1::ff".parse().expect("tunnel hop"))),
        ];
        let routes = prefixes.iter().map(|(prefix, ifindex, hop)| {
            IpsecMainRouteSnapshot {
                domain: 0,
                table: 254,
                family: "inet6".into(),
                destination: (*prefix).into(),
                disposition: 1,
                next_hops: vec![IpsecMainRouteNextHopSnapshot { ifindex: *ifindex, weight: 1 }],
                ..Default::default()
            }
        }).collect();
        let snapshot = IpsecPMechInventorySnapshot {
            policy_identity: "01".repeat(32),
            generation: 77,
            fib_generation: 1,
            complete: true,
            main_routes: routes,
            tunnel_rows: vec![IpsecPMechTunnelRowSnapshot {
                stn: "st0".into(),
                if_id: 1,
                logical_ifindex: 10,
                explicit_selectors: vec![IpsecTrafficSelectorSnapshot {
                    name: "selector".into(),
                    local_ts: "2001:db8::/64".into(),
                    remote_ts: "2001:db8:1::/64".into(),
                    source: "named".into(),
                }],
                effective_prefixes: vec!["2001:db8:1::/64".into()],
                ingress_prefixes: vec!["2001:db8:1::/64".into()],
                destination_prefixes: vec!["2001:db8::/64".into()],
                inventory_generation: 77,
                fib_generation: 1,
                source_kind: "xfrmi".into(),
                selector_provenance: "named".into(),
                inventory_complete: true,
                inventory_valid: true,
                inventory_reason: String::new(),
            }],
        };
        let inventory = Arc::new(PMechInventory::from_snapshot(Some(&snapshot)));
        let mut forwarding = test_forwarding_authority();
        forwarding.ifindex_to_zone_id.insert(20, 2);
        forwarding.ifindex_unambiguous_zone_id.insert(20, 2);
        forwarding.zone_id_to_name.insert(1, "vpn".into());
        forwarding.zone_id_to_name.insert(2, "lan".into());
        let table = prefixes.iter().map(|(prefix, ifindex, hop)| {
            crate::afxdp::types::RouteEntryV6::single(
                crate::prefix::PrefixV6::from_net(prefix.parse().expect("route prefix")),
                *ifindex as i32,
                0,
                *hop,
                false,
                String::new(),
                0,
            )
        }).collect();
        forwarding.routes_v6.insert("inet6.0".into(), table);
        forwarding.neighbors.insert(
            (20, std::net::IpAddr::V6(next_hop)),
            crate::afxdp::NeighborEntry { mac: [2, 0, 0, 0, 0, 20] },
        );
        forwarding.policy = port_term_policy(policy_protocol, policy_dst_port);
        let view = RuntimeView::new_with_ipsec_authority(
            ValidationState { snapshot_installed: true, config_generation: 1, fib_generation: 1 },
            Arc::new(forwarding),
            Arc::new(st0_rows()),
            1,
            inventory,
            1,
        );
        let mut packet = vec![0u8; 48];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&8u16.to_be_bytes());
        packet[6] = protocol;
        packet[7] = 64;
        packet[8..24].copy_from_slice(&src.octets());
        packet[24..40].copy_from_slice(&dst.octets());
        packet[40..42].copy_from_slice(&40000u16.to_be_bytes());
        packet[42..44].copy_from_slice(&dst_port.to_be_bytes());
        (view, packet)
    }

    fn v6_ah_packet(plain: &[u8]) -> Vec<u8> {
        let mut packet = vec![0u8; 72];
        packet[..40].copy_from_slice(&plain[..40]);
        packet[4..6].copy_from_slice(&32u16.to_be_bytes());
        packet[6] = 51; // AH
        packet[40] = 6; // AH next-header: TCP
        packet[41] = 1; // 12-byte AH header
        packet[52..54].copy_from_slice(&40000u16.to_be_bytes());
        packet[54..56].copy_from_slice(&443u16.to_be_bytes());
        packet
    }

    fn v6_ah_input(packet: &[u8]) -> IpsecInnerInput<'_> {
        let mut inp = input(packet, advisory(1, 1, 1, 1, 1));
        inp.inner_family = libc::AF_INET6 as u8;
        inp.inner_eth_proto = 0x86dd;
        inp.protocol = 6; // Shim walks past AH and reports its inner TCP header.
        inp.rel_l4_offset = 52;
        inp.payload_offset = 72;
        inp
    }

    fn v6_port_decision(protocol: u8, dst_port: u16) -> IpsecInnerDecision {
        let (view, packet) = v6_view_and_packet(protocol, dst_port);
        let mut inp = input(&packet, advisory(1, 1, 1, 1, 1));
        inp.inner_family = libc::AF_INET6 as u8;
        inp.inner_eth_proto = 0x86dd;
        inp.protocol = protocol;
        inp.rel_l4_offset = 40;
        inp.payload_offset = 48;
        adjudicate_ipsec_inner(&view, inp)
    }

    #[test]
    fn d14_ipv6_tcp_matching_and_nonmatching_ports_14090() {
        for (dst_port, matches) in [(443, true), (8443, false)] {
            let d = v6_port_decision(6, dst_port);
            assert_eq!(d.is_would_permit(), matches, "{d:?}");
            assert_eq!(d.reason(), (!matches).then_some(reason::LEGACY_POLICY_DENY), "{d:?}");
        }
    }

    #[test]
    fn d14_ipv6_udp_matching_and_nonmatching_ports_14090() {
        for (dst_port, matches) in [(443, true), (8443, false)] {
            let d = v6_port_decision(17, dst_port);
            assert_eq!(d.is_would_permit(), matches, "{d:?}");
            assert_eq!(d.reason(), (!matches).then_some(reason::LEGACY_POLICY_DENY), "{d:?}");
        }
    }

    #[test]
    fn d14_ipv6_ah_sighted_tcp_443_does_not_match_tcp_term_14090() {
        let (view, plain) = v6_view_and_packet(6, 443);
        let packet = v6_ah_packet(&plain);
        let d = adjudicate_ipsec_inner(&view, v6_ah_input(&packet));
        assert_eq!(d.reason(), Some(reason::LEGACY_POLICY_DENY), "{d:?}");
    }

    #[test]
    fn d14_ipv6_ah_sighted_tcp_443_matches_only_ah_term_14217() {
        // The same AH->TCP/443 packet that denies against the TCP/443 permit
        // (cell above) is admitted only by a protocol-51 term.
        let (view, plain) = v6_view_and_packet_with_policy("ah", "");
        let packet = v6_ah_packet(&plain);
        let d = adjudicate_ipsec_inner(&view, v6_ah_input(&packet));
        assert!(d.is_would_permit(), "{d:?}");
    }

    #[test]
    fn d14_ipv6_ah_sighted_udp_443_does_not_match_udp_term_14217() {
        // UDP twin: AH next-header is UDP and the shim-stamped inner header
        // spells dst-port 443, but protocol-51 identity must not match the
        // UDP/443 permit term.
        let (view, plain) = v6_view_and_packet(17, 443);
        let mut packet = v6_ah_packet(&plain);
        packet[40] = 17; // AH next-header: UDP
        let mut inp = v6_ah_input(&packet);
        inp.protocol = 17;
        let d = adjudicate_ipsec_inner(&view, inp);
        assert_eq!(d.reason(), Some(reason::LEGACY_POLICY_DENY), "{d:?}");
    }

    #[test]
    fn h14_02_explicit_vpn_to_lan_policy_permits_remote_to_lan_13956() {
        let mut forwarding = local_lan_forwarding();
        let mut zones: rustc_hash::FxHashMap<String, u16> = Default::default();
        zones.insert("vpn".into(), 1);
        zones.insert("lan".into(), 2);
        let rule = crate::PolicyRuleSnapshot {
            name: "vpn-to-lan".into(),
            from_zone: "vpn".into(),
            to_zone: "lan".into(),
            source_addresses: vec!["any".into()],
            destination_addresses: vec!["any".into()],
            applications: vec!["any".into()],
            action: "permit".into(),
            ..Default::default()
        };
        forwarding.policy = crate::policy::parse_policy_state("deny", &[rule], &zones);
        let view = view_with_rows(1, 1, st0_rows(), forwarding);
        let packet = test_packet_with_source([10, 0, 0, 1], [192, 0, 2, 5]);
        let decision = adjudicate_ipsec_inner(&view, input(&packet, advisory(1, 1, 1, 1, 1)));
        assert!(decision.is_would_permit(), "{decision:?}");
    }

    #[test]
    fn d14_unzoned_tunnel_is_explicit_e1_terminal_9506() {
        let mut forwarding = would_permit_forwarding();
        forwarding.ifindex_to_zone_id.remove(&10);
        let view = view_with_rows(1, 1, st0_rows(), forwarding);
        let packet = test_packet_with_source([10, 0, 0, 1], [10, 0, 0, 1]);
        // Neither an unzoned advisory nor a claimed zone can carry an unzoned
        // logical interface past the explicit E1 terminal.
        for advisory_zone in [0, 1] {
            let before = zone_gate_unzoned_total.load(Ordering::Relaxed);
            assert_denied(
                adjudicate_ipsec_inner(&view, input(&packet, advisory(1, 1, 1, advisory_zone, 1))),
                "d14_zone_unzoned",
                reason::ZONE_UNZONED,
            );
            assert!(
                zone_gate_unzoned_total.load(Ordering::Relaxed) > before,
                "an unzoned denial must count zone_gate_unzoned_total"
            );
        }
    }

    #[test]
    fn d14_policy_identity_mismatch_is_stale_9506() {
        let view = view_with_rows(1, 1, st0_rows(), would_permit_forwarding());
        let packet = test_packet_with_source([10, 0, 0, 1], [10, 0, 0, 1]);
        let mut claimed = advisory(1, 1, 1, 1, 1);
        claimed.pmech_policy_identity = [2; 32];
        assert_denied(
            adjudicate_ipsec_inner(&view, input(&packet, claimed)),
            "d14_stale_generation",
            reason::STALE_GENERATION,
        );
    }

    #[test]
    fn d14_inventory_generation_advisory_mismatch_is_stale_9506() {
        let view = view_with_rows(1, 1, st0_rows(), would_permit_forwarding());
        let packet = test_packet_with_source([10, 0, 0, 1], [10, 0, 0, 1]);
        let mut claimed = advisory(1, 1, 1, 1, 1);
        claimed.pmech_inventory_generation = 78;
        assert_denied(
            adjudicate_ipsec_inner(&view, input(&packet, claimed)),
            "d14_stale_generation",
            reason::STALE_GENERATION,
        );
    }

    #[test]
    fn d14_inventory_fib_generation_advisory_mismatch_is_stale_9506() {
        let view = view_with_rows(1, 1, st0_rows(), would_permit_forwarding());
        let packet = test_packet_with_source([10, 0, 0, 1], [10, 0, 0, 1]);
        let mut claimed = advisory(1, 1, 1, 1, 1);
        claimed.pmech_inventory_fib_generation = 2;
        assert_denied(
            adjudicate_ipsec_inner(&view, input(&packet, claimed)),
            "d14_stale_generation",
            reason::STALE_GENERATION,
        );
    }

    #[test]
    fn d14_inventory_behind_validation_fib_is_stale_9506() {
        // The advisory agrees with both the inventory (FIB 1) and validation
        // (FIB 2); only the inventory-vs-validation fence can refuse it.
        let view = view_with_inventory_fib(2, 1, local_lan_forwarding());
        let packet = test_packet_with_source([10, 0, 0, 1], [192, 0, 2, 5]);
        let mut claimed = advisory(1, 1, 2, 1, 1);
        claimed.pmech_inventory_fib_generation = 1;
        assert_denied(
            adjudicate_ipsec_inner(&view, input(&packet, claimed)),
            "d14_stale_generation",
            reason::STALE_GENERATION,
        );
        let current = view_with_inventory_fib(2, 2, local_lan_forwarding());
        let mut matched = advisory(1, 1, 2, 1, 1);
        matched.pmech_inventory_fib_generation = 2;
        assert!(adjudicate_ipsec_inner(&current, input(&packet, matched)).is_would_permit());
    }
}
