//! #946 Phase 1 — per-packet pipeline stages.
//!
//! Pure code-motion extraction of seven sub-stages out of the
//! `poll_binding_process_descriptor` while-let body. No batch
//! reordering, no behavioral change. Each helper here is the
//! direct semantic equivalent of the inline block it replaces.
//!
//! Stages owned by Phase 1:
//! - stage 5: link-layer (ARP/NDP) classify  → [stage_link_layer_classify]
//! - stage 6: native GRE decap               → [stage_native_gre_decap]
//! - stage 7+8: parse flow + learn neighbor  → [stage_parse_flow_and_learn]
//! - stage 9: fabric-ingress classification  → [stage_classify_fabric_ingress]
//! - stage 10: screen / IDS slow-path        → [stage_screen_check]
//! - stage 11: IPsec passthrough             → [stage_ipsec_passthrough_check]
//!
//! Stages NOT in scope (kept inline in `poll_descriptor.rs` for
//! Phase 1; will be tackled in follow-up phases):
//! - stages 1-4: rx telemetry, parse meta, classify, slice
//! - stages 12+: flow-cache fast path, session lookup, slow-path
//!   policy/NAT/forwarding, reverse-NAT/ICMP, MissingNeighbor
//!
//! See `docs/pr/946-pipeline-phase1/plan.md` for the full plan,
//! the 9-continue table, and the hidden-invariants list.

use super::*;
use crate::screen::SynCookieAckVerdict;

/// Generic outcome for a per-packet stage. The `RecycleAndContinue`
/// arm signals that the caller should push `desc.addr` to
/// `binding.scratch.scratch_recycle` and `continue` the while-let.
/// `Continue(T)` carries the stage's output to the next stage.
pub(super) enum StageOutcome<T> {
    RecycleAndContinue,
    Continue(T),
}

/// Output of `stage_classify_fabric_ingress`. The stage *also*
/// mutates `meta.meta_flags` to set `FABRIC_INGRESS_FLAG`; this
/// struct carries the two return values the caller needs separately.
pub(super) struct FabricIngressOutcome {
    pub(super) ingress_zone_override: Option<u16>,
    pub(super) packet_fabric_ingress: bool,
}

/// Stage 5 — ARP / NDP link-layer classification.
///
/// ARP frames (Reply / Request / Other) are recycled without
/// flowing through the rest of the pipeline. ARP Reply additionally
/// learns a dynamic neighbor and adds a kernel ARP entry.
///
/// NDP NA with a Target Link-Layer Address option learns a dynamic
/// neighbor and adds a kernel neighbor entry, then falls through to
/// normal IPv6 forwarding (the NA frame itself transits the
/// firewall).
///
/// Plain non-link-layer packets fall through unchanged.
///
/// Side effects on `worker_ctx.dynamic_neighbors` (interior
/// mutability behind `Arc`) and the kernel ARP/NDP table are kept
/// inside this helper — the caller does not need visibility into
/// the learned neighbor for the same packet.
#[inline]
pub(super) fn stage_link_layer_classify(
    raw_frame: &[u8],
    meta: UserspaceDpMeta,
    worker_ctx: &WorkerContext,
) -> StageOutcome<()> {
    match parser::classify_arp(raw_frame) {
        parser::ArpClassification::Reply(arp) => {
            worker_ctx.dynamic_neighbors.insert(
                (meta.ingress_ifindex as i32, arp.sender_ip),
                NeighborEntry {
                    mac: arp.sender_mac,
                },
            );
            let neigh_ifindex = resolve_ingress_logical_ifindex(
                worker_ctx.forwarding,
                meta.ingress_ifindex as i32,
                meta.ingress_vlan_id,
            )
            .unwrap_or(meta.ingress_ifindex as i32);
            add_kernel_neighbor(neigh_ifindex, arp.sender_ip, arp.sender_mac);
            return StageOutcome::RecycleAndContinue;
        }
        parser::ArpClassification::OtherArp => {
            return StageOutcome::RecycleAndContinue;
        }
        parser::ArpClassification::NotArp => {}
    }
    if let Some(na) = parser::parse_ndp_neighbor_advert(raw_frame)
        && let Some(mac) = na.target_mac
    {
        worker_ctx.dynamic_neighbors.insert(
            (meta.ingress_ifindex as i32, na.target_ip),
            NeighborEntry { mac },
        );
        let neigh_ifindex = resolve_ingress_logical_ifindex(
            worker_ctx.forwarding,
            meta.ingress_ifindex as i32,
            meta.ingress_vlan_id,
        )
        .unwrap_or(meta.ingress_ifindex as i32);
        add_kernel_neighbor(neigh_ifindex, na.target_ip, mac);
    }
    StageOutcome::Continue(())
}

/// Stage 6 — native GRE decapsulation.
///
/// Returns the (possibly-updated) `meta` and the optional owned
/// decap frame. Caller binds the active slice locally:
///
/// ```text
/// let (meta, owned) = stage_native_gre_decap(raw_frame, meta, ...);
/// let packet_frame = owned.as_deref().unwrap_or(raw_frame);
/// ```
///
/// `owned_packet_frame: Option<Vec<u8>>` MUST be a `mut` binding at
/// the call site because the deferred stage-12+ code in
/// `poll_descriptor.rs` calls `.take()` on it (grep
/// `owned_packet_frame.take(` — the deferred flow-cache,
/// session-hit reverse-NAT, and missing-neighbor side-queue paths
/// each move the owned decap frame out before pushing the
/// resulting forward request). Symbol references rather than line
/// numbers because the line numbers drift any time a stage above
/// is touched.
///
/// The helper does NOT return the active slice — that would be a
/// self-referential return type (the slice would borrow from the
/// returned `Vec`).
#[inline]
pub(super) fn stage_native_gre_decap(
    raw_frame: &[u8],
    meta: UserspaceDpMeta,
    forwarding: &ForwardingState,
) -> (UserspaceDpMeta, Option<Vec<u8>>) {
    let native_gre_packet = try_native_gre_decap_from_frame(raw_frame, meta, forwarding);
    let new_meta = native_gre_packet
        .as_ref()
        .map(|packet| packet.meta)
        .unwrap_or(meta);
    let owned_packet_frame = native_gre_packet.map(|packet| packet.frame);
    (new_meta, owned_packet_frame)
}

/// Stage 7+8 — parse session flow and learn the source-side
/// dynamic neighbor.
///
/// `learn_from_live_frame` MUST be `owned_packet_frame.is_none()`
/// at the call site. Mirrors the GRE guard at
/// poll_descriptor.rs:113 — neighbor learning uses the un-decapped
/// raw_frame (via `area`/`desc`) so the source MAC comes from the
/// live UMEM Ethernet frame; learning from a decapped GRE inner
/// frame would record the GRE tunnel's egress MAC instead of the
/// outer host's.
///
/// Side effects: `worker_ctx.dynamic_neighbors` (interior mut),
/// `last_learned_neighbor` (caller's &mut), kernel neighbor table.
#[inline]
pub(super) fn stage_parse_flow_and_learn(
    area: &MmapArea,
    desc: XdpDesc,
    packet_frame: &[u8],
    meta: UserspaceDpMeta,
    learn_from_live_frame: bool,
    last_learned_neighbor: &mut Option<LearnedNeighborKey>,
    worker_ctx: &WorkerContext,
) -> Option<SessionFlow> {
    let flow = parse_session_flow_from_bytes(packet_frame, meta);
    if learn_from_live_frame
        && let Some(flow) = flow.as_ref()
    {
        learn_dynamic_neighbor_from_packet(
            area,
            desc,
            meta,
            flow.src_ip,
            last_learned_neighbor,
            worker_ctx.forwarding,
            worker_ctx.dynamic_neighbors,
        );
    }
    flow
}

/// Stage 9 — fabric-ingress classification.
///
/// Mutates `meta.meta_flags` to set `FABRIC_INGRESS_FLAG` when the
/// packet's ingress is a fabric overlay or carries a zone-encoded
/// fabric ingress marker. Returns the discovered zone override
/// (used by the screen stage) and the fabric flag (used by
/// downstream forwarding).
///
/// This stage MUST run before screen / IPsec / flow-cache because
/// those downstream stages read `meta.meta_flags` and the
/// `FABRIC_INGRESS_FLAG` is required to skip TTL decrement on
/// fabric-traversed packets (the sending peer already decremented
/// TTL when forwarding across the fabric link).
#[inline]
pub(super) fn stage_classify_fabric_ingress(
    packet_frame: &[u8],
    meta: &mut UserspaceDpMeta,
    worker_ctx: &WorkerContext,
) -> FabricIngressOutcome {
    let ingress_zone_override =
        parse_zone_encoded_fabric_ingress_from_frame(packet_frame, *meta, worker_ctx.forwarding);
    let packet_fabric_ingress = ingress_zone_override.is_some()
        || ingress_is_fabric_overlay(worker_ctx.forwarding, meta.ingress_ifindex as i32);
    if packet_fabric_ingress {
        meta.meta_flags |= FABRIC_INGRESS_FLAG;
    }
    FabricIngressOutcome {
        ingress_zone_override,
        packet_fabric_ingress,
    }
}

/// Stage 10 — screen / IDS slow-path check.
///
/// Only runs when screen profiles are configured (the `has_profiles`
/// gate). Resolves the ingress zone name (preferring the
/// fabric-zone override from stage 9), extracts a `ScreenPacketInfo`
/// from the packet, and runs `screen.check_packet`. On a Drop
/// verdict, bumps `counters.screen_drops` (batched, not direct
/// to `BindingLiveState` — #1187 DDoS-resilience: SYN flood is the
/// primary screen_drops trigger; unbatched atomics here would cause
/// MESI ping-pong with the coordinator's status reads under
/// volumetric attack) and returns `RecycleAndContinue`.
#[inline]
pub(super) fn stage_screen_check(
    flow: Option<&SessionFlow>,
    packet_frame: &[u8],
    meta: UserspaceDpMeta,
    ingress_zone_override: Option<u16>,
    now_secs: u64,
    screen: &mut ScreenState,
    counters: &mut BatchCounters,
    worker_ctx: &WorkerContext,
) -> StageOutcome<()> {
    if !screen.has_profiles() {
        return StageOutcome::Continue(());
    }
    let Some(flow) = flow else {
        return StageOutcome::Continue(());
    };
    let zone_id = ingress_zone_override
        .filter(|id| worker_ctx.forwarding.zone_id_to_name.contains_key(id))
        .or_else(|| {
            worker_ctx
                .forwarding
                .ifindex_to_zone_id
                .get(&(meta.ingress_ifindex as i32))
                .copied()
        });
    let Some(zone_id) = zone_id else {
        return StageOutcome::Continue(());
    };
    let Some(zone_name) = worker_ctx
        .forwarding
        .zone_id_to_name
        .get(&zone_id)
        .map(|s| s.as_str())
    else {
        return StageOutcome::Continue(());
    };
    let l3_off = if meta.ingress_vlan_id > 0 { 18 } else { 14 };
    let screen_pkt = extract_screen_info(
        packet_frame,
        meta.addr_family,
        meta.protocol,
        meta.tcp_flags,
        meta.pkt_len,
        flow.src_ip,
        flow.dst_ip,
        flow.forward_key.src_port,
        flow.forward_key.dst_port,
        l3_off,
    );
    match screen.check_packet_with_zone_id(zone_name, zone_id, &screen_pkt, now_secs) {
        ScreenVerdict::Pass => StageOutcome::Continue(()),
        ScreenVerdict::Drop(_) | ScreenVerdict::SynCookieChallenge(_) => {
            counters.touched = true;
            counters.screen_drops += 1;
            StageOutcome::RecycleAndContinue
        }
    }
}

/// SYN-cookie returning ACK validation on the session-miss path.
///
/// This runs after normal session lookup has failed, so established ACK traffic
/// keeps its normal fast/session path. A valid cookie ACK is consumed without
/// creating a session; the validated-client cache lets the client's next SYN
/// traverse the ordinary policy/NAT/session path. Invalid cookie ACKs are
/// dropped while cookie mode is active.
#[inline]
pub(super) fn stage_screen_syn_cookie_ack_on_session_miss(
    flow: Option<&SessionFlow>,
    packet_frame: &[u8],
    meta: UserspaceDpMeta,
    ingress_zone_override: Option<u16>,
    now_secs: u64,
    screen: &mut ScreenState,
    counters: &mut BatchCounters,
    worker_ctx: &WorkerContext,
) -> StageOutcome<()> {
    if !screen.has_profiles() {
        return StageOutcome::Continue(());
    }
    let Some(flow) = flow else {
        return StageOutcome::Continue(());
    };
    let zone_id = ingress_zone_override
        .filter(|id| worker_ctx.forwarding.zone_id_to_name.contains_key(id))
        .or_else(|| {
            worker_ctx
                .forwarding
                .ifindex_to_zone_id
                .get(&(meta.ingress_ifindex as i32))
                .copied()
        });
    let Some(zone_id) = zone_id else {
        return StageOutcome::Continue(());
    };
    let Some(zone_name) = worker_ctx
        .forwarding
        .zone_id_to_name
        .get(&zone_id)
        .map(|s| s.as_str())
    else {
        return StageOutcome::Continue(());
    };
    let l3_off = if meta.ingress_vlan_id > 0 { 18 } else { 14 };
    let screen_pkt = extract_screen_info(
        packet_frame,
        meta.addr_family,
        meta.protocol,
        meta.tcp_flags,
        meta.pkt_len,
        flow.src_ip,
        flow.dst_ip,
        flow.forward_key.src_port,
        flow.forward_key.dst_port,
        l3_off,
    );
    match screen.validate_syn_cookie_ack_on_session_miss(zone_name, zone_id, &screen_pkt, now_secs)
    {
        SynCookieAckVerdict::NotApplicable => StageOutcome::Continue(()),
        SynCookieAckVerdict::Validated => StageOutcome::RecycleAndContinue,
        SynCookieAckVerdict::Invalid => {
            counters.touched = true;
            counters.screen_drops += 1;
            StageOutcome::RecycleAndContinue
        }
    }
}

/// Stage 11 — IPsec passthrough.
///
/// ESP (proto 50) and IKE (UDP 500/4500) must transit the kernel
/// XFRM subsystem. On a match, this stage builds a synthetic
/// `SessionDecision` with `LocalDelivery` disposition and
/// reinjects the packet via the slow-path TUN device, then signals
/// `RecycleAndContinue` so the caller drops the UMEM frame.
///
/// Non-IPsec packets fall through unchanged.
#[inline]
pub(super) fn stage_ipsec_passthrough_check(
    flow: Option<&SessionFlow>,
    packet_frame: &[u8],
    meta: UserspaceDpMeta,
    binding_live: &BindingLiveState,
    worker_ctx: &WorkerContext,
) -> StageOutcome<()> {
    let Some(flow) = flow else {
        return StageOutcome::Continue(());
    };
    if !is_ipsec_traffic(meta.protocol, flow.forward_key.dst_port) {
        return StageOutcome::Continue(());
    }
    let ipsec_decision = SessionDecision {
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::LocalDelivery,
            local_ifindex: 0,
            egress_ifindex: 0,
            tx_ifindex: 0,
            tunnel_endpoint_id: 0,
            next_hop: None,
            neighbor_mac: None,
            src_mac: None,
            tx_vlan_id: 0,
        },
        nat: NatDecision::default(),
    };
    maybe_reinject_slow_path_from_frame(
        &worker_ctx.ident,
        binding_live,
        worker_ctx.slow_path,
        worker_ctx.local_tunnel_deliveries,
        packet_frame,
        meta,
        ipsec_decision,
        worker_ctx.recent_exceptions,
        "slow_path",
        worker_ctx.forwarding,
    );
    StageOutcome::RecycleAndContinue
}
