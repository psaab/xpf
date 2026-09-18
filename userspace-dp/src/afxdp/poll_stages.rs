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
use crate::screen::{SynCookieAckVerdict, SynCookieChallenge};

/// Generic outcome for a per-packet stage. The `RecycleAndContinue`
/// arm signals that the caller should push `desc.addr` to
/// `binding.scratch.scratch_recycle` and `continue` the while-let.
/// `Continue(T)` carries the stage's output to the next stage.
pub(super) enum StageOutcome<T> {
    RecycleAndContinue,
    Continue(T),
}

pub(super) enum ScreenCheckOutcome {
    Pass,
    SynCookieChallenge(SynCookieChallenge),
}

pub(super) enum SynCookieAckOutcome {
    Pass,
    Validated,
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
    now_ns: u64,
    neigh_limiter: &mut KernelNeighborProgramLimiter,
    worker_ctx: &WorkerContext,
) -> StageOutcome<()> {
    // #2370: learn dynamic neighbors under the LOGICAL (L3) ifindex,
    // not the physical/parent ingress ifindex. The forwarder looks up
    // dynamic neighbors keyed by the connected-route ifindex, which is
    // the logical VLAN sub-interface (see `lookup_neighbor_entry` and
    // `forwarding_build/interfaces.rs` `ConnectedRouteV4/V6 { ifindex:
    // iface.ifindex }`). For an ARP/NDP frame arriving on a VLAN
    // sub-interface, `meta.ingress_ifindex` is the parent/bind ifindex
    // and `meta.ingress_vlan_id` selects the logical interface;
    // resolving (parent, vlan) -> logical makes the insert key match the
    // lookup key, so the just-learned entry is found instead of falling
    // through to the MissingNeighbor cold path. The SAME logical ifindex
    // keys `add_kernel_neighbor` too (already correct before this fix).
    // For untagged / non-VLAN interfaces the mapping resolves
    // physical == logical, so behavior is unchanged; if no logical
    // interface matches we fall back to the physical ifindex rather than
    // dropping the learned neighbor. Two VLANs sharing a physical port
    // resolve to distinct logical ifindexes (distinct (parent, vlan)
    // keys), so a same-IP-different-subnet neighbor never collides.
    //
    // #6261: the resolve is computed ONLY inside the outlined ARP-reply /
    // NDP-NA learn-and-program handlers below, NOT at the top of the
    // stage. This stage runs per-packet for ALL ingress traffic (before
    // the flow-cache fast path), so the overwhelming majority of packets
    // (every non-ARP/non-NDP frame, including flow-cache hits) must skip
    // the FastMap lookup entirely — they pay zero resolve cost, matching
    // the pre-#2370 data path. The rare learn-and-program work now lives
    // in `#[cold] #[inline(never)]` handlers so it does not bloat the
    // inline hot stage; the ordinary (non-ARP/NDP) fast path is
    // byte-for-byte unchanged — it only classifies the EtherType and
    // probes the ARP/NDP parsers, exactly as before.
    match parser::classify_arp(raw_frame) {
        parser::ArpClassification::Reply(arp) => {
            // #6261: the accepted ARP-reply learn-and-program tail
            // (validation gates, #2370 logical-ifindex resolve,
            // change-detecting learn, #5288-limited kernel program) is
            // outlined to a #[cold] #[inline(never)] handler. ARP frames
            // never transit the firewall — recycle either way, preserving
            // the ARP-recycle semantics.
            outline_arp_reply_learn_and_program(arp, meta, now_ns, neigh_limiter, worker_ctx);
            return StageOutcome::RecycleAndContinue;
        }
        parser::ArpClassification::OtherArp => {
            return StageOutcome::RecycleAndContinue;
        }
        parser::ArpClassification::NotArp => {}
    }
    // #6261: the NDP parser probe (`parse_ndp_neighbor_advert`) and its
    // Target Link-Layer Address destructure stay inline; only the accepted
    // learn-and-program tail (unicast/own-IP gates, #2370 resolve, #4475
    // Override=0 CAS (#9893 atomic), change-detecting learn, #5288-limited
    // program) is outlined to a #[cold] #[inline(never)] handler. NDP
    // "continue" semantics are unchanged — an NA frame still transits the
    // firewall (we fall through to `Continue` below regardless of whether
    // the learn happened).
    if let Some(na) = parser::parse_ndp_neighbor_advert(raw_frame)
        && let Some(mac) = na.target_mac
    {
        outline_ndp_na_learn_and_program(na, mac, meta, now_ns, neigh_limiter, worker_ctx);
    }
    StageOutcome::Continue(())
}

/// #6261 — outlined ARP-reply learn-and-program tail of
/// [`stage_link_layer_classify`].
///
/// Split out of the inline pre-flow-cache RX stage into a `#[cold]
/// #[inline(never)]` handler so the ordinary (non-ARP/NDP) packet fast
/// path stays cache-hot: an actual ARP *reply* on the data path is rare,
/// but the inline validation / neighbor-learn / rate-limit / synchronous
/// kernel-neighbor socket work would otherwise bloat the hot stage.
///
/// Behavior is byte-for-byte identical to the pre-#6261 inline block —
/// this is a pure codegen/layout change, not a logic change:
///
/// - #2790: validate the advertised sender protocol address BEFORE
///   caching it. RFC 826 — a learnable ARP reply must name a single
///   unicast host. A reply claiming an unspecified / loopback /
///   multicast / broadcast sender IP would otherwise pollute both the
///   userspace `dynamic_neighbors` map and the kernel ARP table
///   (spoofed-reply DoS / routing disruption). Fail closed: the caller
///   recycles the ARP frame (it never transits) but this handler skips
///   learning, mirroring the #2369 fail-closed-on-malformed-ARP posture
///   and the cold neighbor warmer's unicast-only gate.
/// - #2851: anti-poisoning own-IP gate, ADDITIONAL to the #2790
///   unicast-only gate. Refuse to learn an ARP reply whose advertised
///   sender IP equals one of the router's OWN configured interface IPs.
///   A host on the local link could otherwise send an unsolicited /
///   spoofed reply claiming our own interface address and teach us
///   `(ifindex, our_ip) -> attacker_mac` in both `dynamic_neighbors` and
///   the kernel ARP table (RFC 826 — do not install a neighbor entry for
///   an address we own). This MUST run BEFORE the `insert_if_changed`
///   below so a rejected own-IP learn neither inserts nor bumps
///   `mac_change_epoch` (#3048/#3169).
/// - #2370: learn under the LOGICAL (L3) ifindex, resolving
///   `(parent, vlan) -> logical` so the insert key matches the
///   forwarder's lookup key.
/// - #3048: route the data-path learn through `insert_if_changed` so a
///   MAC change observed directly from an ARP reply advances the
///   neighbor `mac_change_epoch` and evicts stale cached dst_macs.
/// - #5288: gate the kernel-neighbor program (a raw netlink
///   socket()/sendto()/close() + Vec allocations) behind the per-worker
///   limiter. A same-key/same-MAC repeat (`!changed`) skips the netlink
///   work entirely; even a changed-flood is rate-capped, while a genuine
///   MAC change is still programmed. `#[cold]` is a layout hint, NOT a
///   rate limiter — flood bounding stays with this limiter.
///
/// The generation (`mac_change_epoch`) / limiter ordering is preserved
/// exactly: `insert_if_changed` computes `changed` first, then
/// `should_program` consults it, then `add_kernel_neighbor` runs.
#[cold]
#[inline(never)]
fn outline_arp_reply_learn_and_program(
    arp: parser::ArpReply,
    meta: UserspaceDpMeta,
    now_ns: u64,
    neigh_limiter: &mut KernelNeighborProgramLimiter,
    worker_ctx: &WorkerContext,
) {
    // #9115: the sender's HARDWARE address must be learnable too. These arms
    // gated on the IP alone, so an ARP reply carrying a multicast, broadcast or
    // all-zero sender MAC was inserted into the neighbour cache AND programmed
    // into the kernel. The sibling RX-learn arm (neighbor_dispatch.rs) has
    // always enforced this; these two never did.
    if neighbor_mac_is_learnable(arp.sender_mac)
        && neighbor_ip_is_learnable(arp.sender_ip)
        && !worker_ctx.forwarding.owns_configured_ip(arp.sender_ip)
    {
        let ifindex = resolve_ingress_logical_ifindex(
            worker_ctx.forwarding,
            meta.ingress_ifindex as i32,
            meta.ingress_vlan_id,
        )
        .unwrap_or(meta.ingress_ifindex as i32);
        let changed = worker_ctx.dynamic_neighbors.insert_if_changed(
            (ifindex, arp.sender_ip),
            NeighborEntry {
                mac: arp.sender_mac,
            },
        );
        if neigh_limiter.should_program((ifindex, arp.sender_ip), arp.sender_mac, changed, now_ns) {
            add_kernel_neighbor(ifindex, arp.sender_ip, arp.sender_mac);
        }
    }
}

/// #6261 — outlined NDP Neighbor-Advertisement learn-and-program tail of
/// [`stage_link_layer_classify`].
///
/// Split out of the inline pre-flow-cache RX stage into a `#[cold]
/// #[inline(never)]` handler for the same reason as the ARP handler
/// above. Called with the parsed `na` and its Target Link-Layer Address
/// `mac` — the caller keeps the inline `parse_ndp_neighbor_advert`
/// parser probe and the `target_mac` destructure. This handler never
/// recycles: the NA frame still transits the firewall, so the caller
/// always returns `StageOutcome::Continue(())`.
///
/// Behavior is byte-for-byte identical to the pre-#6261 inline block —
/// pure codegen/layout change:
///
/// - #2790: unicast-only gate for the NA target address — an NA
///   advertising an unspecified / loopback / multicast target IP is not
///   a learnable neighbor (RFC 4861 §7.2.4 targets are unicast). Only
///   the neighbor write is suppressed; the NA frame still transits.
/// - #2851: same anti-poisoning own-IP gate as the ARP-reply handler —
///   an NA advertising one of the router's OWN configured IPv6 addresses
///   must not be learned. Runs BEFORE `insert_if_changed` so a rejected
///   learn neither inserts nor bumps `mac_change_epoch`.
/// - #2370: learn under the LOGICAL (L3) ifindex (VLAN sub-interface).
/// - #4475 (opus-172 H-2): honor the RFC 4861 §7.2.5 Override (O) flag.
///   An NA with Override=0 MUST NOT overwrite a cached neighbor entry
///   that maps to a DIFFERENT link-layer address — the unsolicited-NA
///   next-hop hijack primitive. A legitimate host announcing a
///   link-layer-address change sets Override=1 (§7.2.6), so an Override=0
///   NA is only allowed to create a first-time entry or refresh the same
///   LLA; a live differing LLA is left untouched (this handler returns
///   without learning — the NA frame still transits). #9893: the check
///   and the write share one shard lock inside
///   `insert_ndp_na_if_override_allows` (atomic CAS), closing the
///   pre-#9893 best-effort TOCTOU where a concurrent differing-MAC insert
///   between the `get` and the `insert_if_changed` was overwritten.
/// - #3048 / #5288: same change-detecting learn and bounded kernel
///   program as the ARP handler — an NA flood for a non-owned unicast
///   target must not storm netlink on the worker.
///
/// The generation (`mac_change_epoch`) / limiter ordering is preserved
/// exactly; the Override check now happens ATOMICALLY WITH the write inside
/// the CAS (pre-#9893 it read before the write across two locks).
#[cold]
#[inline(never)]
fn outline_ndp_na_learn_and_program(
    na: parser::NdpNeighborAdvert,
    mac: [u8; 6],
    meta: UserspaceDpMeta,
    now_ns: u64,
    neigh_limiter: &mut KernelNeighborProgramLimiter,
    worker_ctx: &WorkerContext,
) {
    // #9115: the NA's target link-layer address must be learnable too — see the
    // ARP arm above and `neighbor_mac_is_learnable`.
    if neighbor_mac_is_learnable(mac)
        && neighbor_ip_is_learnable(na.target_ip)
        && !worker_ctx.forwarding.owns_configured_ip(na.target_ip)
    {
        let ifindex = resolve_ingress_logical_ifindex(
            worker_ctx.forwarding,
            meta.ingress_ifindex as i32,
            meta.ingress_vlan_id,
        )
        .unwrap_or(meta.ingress_ifindex as i32);
        // #9893: atomic Override=0 CAS — the differing-MAC check and the
        // insert share one shard lock inside the map. `None` means the
        // Override=0 gate refused a live differing LLA (return without
        // learning; the NA frame still transits). `Some(changed)` feeds the
        // #5288 limiter exactly as the old `insert_if_changed` bool did.
        let Some(changed) = worker_ctx.dynamic_neighbors.insert_ndp_na_if_override_allows(
            (ifindex, na.target_ip),
            NeighborEntry { mac },
            na.override_flag,
        ) else {
            return;
        };
        if neigh_limiter.should_program((ifindex, na.target_ip), mac, changed, now_ns) {
            add_kernel_neighbor(ifindex, na.target_ip, mac);
        }
    }
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

/// Stage 6b — WireGuard transport-data decap (#8274 step 3).
///
/// The exact shape of `stage_native_gre_decap` above, and deliberately so: the
/// consumer is the same, the substitution is the same, and a second convention
/// for "replace the outer packet with its decapsulated inner for the rest of
/// this pass" is the divergence `logical_ingress`'s module comment exists to
/// prevent.
///
/// Returns the ORIGINAL meta and `None` for every packet that is not an
/// inbound WireGuard transport-data record for a configured listener, which is
/// almost all of them; see `wg::decap::try_wg_decap_from_frame` for the gates
/// and for why a rejection here is not a drop.
///
/// The peer identity travels with the decapsulated packet rather than being
/// discarded: the control thread learns a peer's endpoint from authenticated
/// datagrams, and moving transport-data records off its socket takes its
/// dominant source of that signal away. The caller reports it back.
#[inline]
pub(super) fn stage_wg_decap(
    raw_frame: &[u8],
    meta: UserspaceDpMeta,
    forwarding: &ForwardingState,
    wg_scratch: &crate::afxdp::wg::WgWorkerScratch,
) -> (UserspaceDpMeta, Option<Vec<u8>>) {
    // Shape mirrors `stage_native_gre_decap` deliberately: meta + optional
    // owned frame, nothing else. The decapped peer's roaming endpoint is
    // reported to the engine INSIDE `try_wg_decap_from_frame` (the control
    // thread drains it on its timer pass), so handing the pubkey back up to
    // the poll loop would only create a value with no consumer — and a
    // returned-but-unused identity is how a "the caller will handle it"
    // comment outlives the caller that did.
    let decapped = crate::afxdp::wg::decap::try_wg_decap_from_frame(
        raw_frame, meta, forwarding, wg_scratch,
    );
    let new_meta = decapped.as_ref().map(|p| p.meta).unwrap_or(meta);
    let owned_packet_frame = decapped.map(|p| p.frame);
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
    // #7188: transit GRE has no 5-tuple identity, so #6837 leaves it FLOWLESS —
    // `metadata_tuple_complete` refuses protocol 47 on both arms. With
    // `gre-performance-acceleration` on, give it an identity keyed on the RFC
    // 2890 discriminator instead.
    //
    // ADDITIVE and knob-gated: with acceleration off this expression is
    // `flow` unchanged, so the path is bit-identical to today. It also leaves
    // #6837's gate untouched at its own site — the discriminator arrives from
    // the FRAME, which is the only side that can have read it, and never as a
    // metadata-side default (the shim does not parse GRE).
    let flow = match flow {
        Some(flow) => Some(flow),
        None if worker_ctx.forwarding.gre_acceleration => {
            crate::afxdp::gre_discriminator::gre_keyed_session_flow(packet_frame, meta)
        }
        None => None,
    };
    if learn_from_live_frame && let Some(flow) = flow.as_ref() {
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
    // #7699: copy a PPTP control segment out to the inbox. The test is two
    // comparisons on a tuple this stage has already parsed; everything past it
    // — locating the payload, copying it, parsing it — is either cold or off
    // this path entirely. Deliberately NOT gated on `learn_from_live_frame`:
    // that flag governs whether the FRAME is a live one to learn a neighbor
    // from, which is a different question from whether these bytes are a
    // control message, and gating on it would silently drop the association for
    // every path that passes it false.
    if let Some(flow) = flow.as_ref()
        && is_pptp_control_flow(flow)
    {
        capture_pptp_control_segment(packet_frame, flow, worker_ctx.pptp_control);
    }
    flow
}

/// Is this flow the PPTP control channel? (#7699)
///
/// EITHER direction: the reply that carries both call ids travels from the PAC
/// back to the PNS, so its SOURCE is 1723. Testing only the destination would
/// see the request — which names one side and cannot pair a call — and miss the
/// one message that can.
#[inline]
pub(in crate::afxdp) fn is_pptp_control_flow(flow: &SessionFlow) -> bool {
    flow.forward_key.protocol == crate::ip_proto::PROTO_TCP
        && (flow.forward_key.dst_port == crate::session::pptp_control::PPTP_CONTROL_PORT
            || flow.forward_key.src_port == crate::session::pptp_control::PPTP_CONTROL_PORT)
}

/// Copy a recognised control segment into the inbox. Returns whether it landed.
///
/// `#[cold]`: PPTP control traffic is a handful of small messages per call, so
/// this body has no business in the ingress loop's codegen unit — the same
/// reasoning as the source-NAT exception recorders.
///
/// **It allocates, and that is deliberate rather than overlooked.**
/// `docs/engineering-style.md` says never allocate per PACKET; this allocates
/// per CONTROL packet — a TCP flow with 1723 on one side, a handful of small
/// messages per call — into a queue capped at `PENDING_CONTROL_CAPACITY` with
/// drop-newest on full, so the total is bounded and a control-port flood cannot
/// make the data path allocate without limit. Copying rather than borrowing is
/// what lets the frame be returned to the UMEM immediately; holding a slice
/// would pin a descriptor across the drain interval.
///
/// It does NOT parse. Parsing, installing and broadcasting happen on the
/// worker's periodic drain, so nothing here waits on control-channel work and
/// the association is never needed for the segment that taught it.
#[cold]
#[inline(never)]
pub(in crate::afxdp) fn capture_pptp_control_segment(
    packet_frame: &[u8],
    flow: &SessionFlow,
    inbox: &crate::session::pptp_control::PptpControlInbox,
) -> bool {
    let Some(offset) = crate::afxdp::frame::tcp_payload_offset(packet_frame) else {
        return false;
    };
    let Some(payload) = packet_frame.get(offset..) else {
        return false;
    };
    // A pure ACK / handshake segment has no payload and cannot be a control
    // message. Buffering it would spend a capacity slot that a real message
    // then loses.
    if payload.is_empty() {
        return false;
    }
    inbox.push(crate::session::pptp_control::PendingControlSegment {
        src: flow.src_ip,
        dst: flow.dst_ip,
        src_port: flow.forward_key.src_port,
        dst_port: flow.forward_key.dst_port,
        payload: payload.to_vec(),
    })
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
///
/// #6458: the zone override is the #6458-VALIDATED stamp — a frame
/// whose zone-encoded src MAC fails the fabric-link identity (unicast
/// dst) or RG-binding check decodes to `None` here and is treated as an
/// ordinary unstamped fabric-ingress packet by every downstream consumer.
#[inline]
pub(super) fn stage_classify_fabric_ingress(
    packet_frame: &[u8],
    meta: &mut UserspaceDpMeta,
    now_secs: u64,
    worker_ctx: &WorkerContext,
) -> FabricIngressOutcome {
    let ingress_zone_override = parse_zone_encoded_fabric_ingress_from_frame(
        packet_frame,
        *meta,
        worker_ctx.forwarding,
        worker_ctx.ha_state,
        now_secs,
    );
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

/// #3902: read the real L3 source/destination addresses from the IP header
/// for the flowless screen path. A non-first IP fragment or a non-query
/// ICMP/ICMPv6 control message carries a full IP header, so its addresses are
/// present even though the packet has no transport flow. Returns
/// `(src, dst, true)` when the captured frame holds the full base header, or
/// `(unspecified, unspecified, false)` when it is too short — the caller then
/// skips the address-dependent LAND screen rather than false-dropping on
/// `unspecified == unspecified`. The IPv6 base header (and thus its addresses)
/// is already guaranteed present by `extract_screen_info`'s fail-closed
/// `l3_off + 40 <= frame.len()` gate; the IPv4 base header is a fixed 20 bytes.
fn flowless_l3_addrs(frame: &[u8], addr_family: u8, l3_off: usize) -> (IpAddr, IpAddr, bool) {
    if addr_family == libc::AF_INET6 as u8 {
        if l3_off + 40 <= frame.len()
            && let (Ok(src), Ok(dst)) = (
                <[u8; 16]>::try_from(&frame[l3_off + 8..l3_off + 24]),
                <[u8; 16]>::try_from(&frame[l3_off + 24..l3_off + 40]),
            )
        {
            return (
                IpAddr::V6(Ipv6Addr::from(src)),
                IpAddr::V6(Ipv6Addr::from(dst)),
                true,
            );
        }
        return (
            IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            false,
        );
    }
    // IPv4 (and any other family falls back to an unspecified V4 tuple, matching
    // the pre-#3902 placeholder default).
    if addr_family == libc::AF_INET as u8 && l3_off + 20 <= frame.len() {
        let src = IpAddr::V4(Ipv4Addr::new(
            frame[l3_off + 12],
            frame[l3_off + 13],
            frame[l3_off + 14],
            frame[l3_off + 15],
        ));
        let dst = IpAddr::V4(Ipv4Addr::new(
            frame[l3_off + 16],
            frame[l3_off + 17],
            frame[l3_off + 18],
            frame[l3_off + 19],
        ));
        return (src, dst, true);
    }
    (
        IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        false,
    )
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
    now_ns: u64,
    now_secs: u64,
    screen: &mut ScreenState,
    counters: &mut BatchCounters,
    worker_ctx: &WorkerContext,
) -> StageOutcome<ScreenCheckOutcome> {
    // #6860: has_screen_state, not has_profiles. The latter consults only the
    // RESOLVED profile map, so when a zone references a profile and none
    // resolves anywhere, this returned before either missing-profile WARN
    // branch could run -- the warning never fired in the one configuration it
    // exists for. A zone silently screening NOTHING is precisely what an
    // operator needs told.
    if !screen.has_screen_state() {
        return StageOutcome::Continue(ScreenCheckOutcome::Pass);
    }
    // #4155: a fabric-redirected packet (stage 9 set FABRIC_INGRESS_FLAG on
    // `meta.meta_flags`) was already rate-screened on the peer ingress node
    // before it crossed the fabric link. Skip the rate-based flood counters
    // (icmp/udp/syn-flood) on the RG owner so the same packet is not counted
    // twice against the per-zone / per-destination flood thresholds — a legit
    // high-pps synced session would otherwise false-trip a flood Drop and
    // defeat fabric cross-chassis forwarding. The stateless per-packet screens
    // still run (idempotent). See docs/fabric-cross-chassis-fwd.md.
    let skip_rate_flood = (meta.meta_flags & FABRIC_INGRESS_FLAG) != 0;
    // Zone resolution is flow-INDEPENDENT: it is keyed on the packet's
    // ingress context (logical ifindex / VLAN / fabric override), not on the
    // transport flow. Resolving it BEFORE branching on `flow` lets the
    // flowless non-first-fragment path (#3064) reach the very same zone
    // screen profile the flow path uses.
    //
    // #3022: resolve the LOGICAL ingress ifindex before the zone lookup.
    // `ifindex_to_zone_id` is keyed by the logical unit ifindex; the raw
    // physical bind ifindex either misses (no zone on the parent → screen
    // skipped entirely) or returns the parent's first-subinterface zone
    // (wrong profile), bypassing/mis-applying screen profiles on VLAN
    // subinterfaces. Non-VLAN ports resolve physical == logical.
    let logical_ifindex = resolve_ingress_logical_ifindex(
        worker_ctx.forwarding,
        meta.ingress_ifindex as i32,
        meta.ingress_vlan_id,
    )
    .unwrap_or(meta.ingress_ifindex as i32);
    let zone_id = ingress_zone_override
        .filter(|id| worker_ctx.forwarding.zone_id_to_name.contains_key(id))
        .or_else(|| {
            worker_ctx
                .forwarding
                .ifindex_to_zone_id
                .get(&logical_ifindex)
                .copied()
        });
    let Some(zone_id) = zone_id else {
        return StageOutcome::Continue(ScreenCheckOutcome::Pass);
    };
    let Some(zone_name) = worker_ctx
        .forwarding
        .zone_id_to_name
        .get(&zone_id)
        .map(|s| s.as_str())
    else {
        return StageOutcome::Continue(ScreenCheckOutcome::Pass);
    };
    // L3 starts after the 802.1Q tag whenever a tag is PRESENT, not
    // only when the VID is non-zero. 802.1p priority-tagged frames
    // carry a real tag (TPID 0x8100 + PCP bits) with VID 0, so a
    // `vlan_id > 0` test would read the IP header at offset 14 and
    // parse the tag's TPID/TCI bytes as the IPv4/IPv6 header — the
    // #2145 misclassification. `ingress_vlan_present` is the
    // tag-presence signal the shim already sets (mirrors the CoS path
    // in tx/cos_classify.rs).
    let l3_off = if meta.ingress_vlan_present != 0 {
        18
    } else {
        14
    };
    // #3064 + #3902: a non-first IP fragment (or a non-query ICMP/ICMPv6
    // control message) has no transport flow — `parse_session_flow_from_bytes`
    // returns `None` for it (#2344, so the payload is never parsed as L4
    // ports). Such a packet used to `Pass` here, which made the per-fragment
    // L3-header screens (ping-of-death, teardrop, icmp-fragment) DEAD (#3064)
    // AND — until #3902 — bypassed the SOURCE-INDEPENDENT screens (LAND,
    // ip-source-route, ICMP/UDP flood) that need no flow. The flowless branch
    // below now runs ALL of those (see the detailed #3902 note in the branch).
    // Only the genuinely FLOW/session-dependent screens (TCP-flag, SYN-flood
    // sketches, scan/sweep, SYN-cookie) stay on the flow-present path below —
    // they require a real TCP header / per-flow tuple. The #2344 flowless fast
    // path is NOT reintroduced (no L4 parse / session lookup happens here).
    let Some(flow) = flow else {
        // #3902: the flowless path (a non-first IP fragment or a non-query
        // ICMP/ICMPv6 control message) must still run the SOURCE-INDEPENDENT
        // screens — LAND anti-spoof, ip-source-route, ICMP/UDP flood — which
        // need no transport flow. Before #3902 only the three L3 fragment
        // screens ran here, so those source-independent screens were BYPASSED
        // on the flowless path (screen fail-open). LAND compares src_ip ==
        // dst_ip, so derive the REAL L3 addresses from the IP header (a
        // fragment / ICMP control message carries a full IP header) rather
        // than the pre-#3902 unspecified placeholder, which would have made
        // every flowless packet look like a LAND spoof. tcp_flags is 0
        // because a non-first fragment carries no L4 header; the fragment
        // screens never read ports, so no session lookup / L4 parse happens
        // and the #2344 flowless fast path is NOT reintroduced.
        let (screen_src, screen_dst, addrs_known) =
            flowless_l3_addrs(packet_frame, meta.addr_family, l3_off);
        let screen_pkt = match extract_screen_info(
            packet_frame,
            meta.addr_family,
            meta.protocol,
            0,
            meta.pkt_len,
            screen_src,
            screen_dst,
            0,
            0,
            l3_off,
        ) {
            Ok(pkt) => pkt,
            // FAIL-CLOSED (#2146 parity): a frame whose L3/extension-header
            // chain cannot be parsed far enough to evaluate the fragment
            // screens is dropped on the flow path, so drop it here too rather
            // than admit an unparseable fragment unscreened.
            Err(err) => {
                let reason = err.screen_reason();
                emit_screen_drop_event(
                    worker_ctx.event_stream,
                    // #5190: carry the authoritative protocol/pkt_len from
                    // `meta` and the L3 addresses already derived above, so a
                    // flowless malformed-packet drop no longer reports
                    // protocol=0 / pkt_len=0 / 0.0.0.0.
                    &screen_parse_error_info_flowless(&meta, screen_src, screen_dst),
                    meta,
                    zone_id,
                    reason,
                    event_now_ns_from_secs(now_secs),
                );
                counters.record_screen_drop(
                    reason,
                    zone_id,
                    &worker_ctx.forwarding.flood_counter_slot_map,
                );
                return StageOutcome::RecycleAndContinue;
            }
        };
        let flowless_verdict = screen.check_flowless_screens_opts(
            zone_name,
            &screen_pkt,
            addrs_known,
            now_ns,
            now_secs,
            skip_rate_flood,
        );
        return match flowless_verdict {
            ScreenVerdict::Drop(reason) => {
                // Junos `alarm-without-drop`: the check already RAN and
                // updated its counters; suppress only the packet drop and
                // raise a log-only alarm (PERMIT) carrying the tripped
                // reason, then forward.
                if screen.alarm_without_drop(zone_name) {
                    emit_screen_alarm_event(
                        worker_ctx.event_stream,
                        &screen_pkt,
                        meta,
                        zone_id,
                        reason,
                        event_now_ns_from_secs(now_secs),
                    );
                    screen.record_alarm_without_drop();
                    // #7086: the check TRIPPED; only the drop was suppressed. Tally
                    // it per zone on the ALARM triple so the surface can tell
                    // "alarming and permitting" from "nothing recorded".
                    crate::afxdp::flood_counters::record_zone_flood_alarm(
                        &worker_ctx.forwarding.flood_counter_slot_map,
                        zone_id,
                        reason,
                    );
                    StageOutcome::Continue(ScreenCheckOutcome::Pass)
                } else {
                    emit_screen_drop_event(
                        worker_ctx.event_stream,
                        &screen_pkt,
                        meta,
                        zone_id,
                        reason,
                        event_now_ns_from_secs(now_secs),
                    );
                    counters.record_screen_drop(
                        reason,
                        zone_id,
                        &worker_ctx.forwarding.flood_counter_slot_map,
                    );
                    StageOutcome::RecycleAndContinue
                }
            }
            // The flowless source-independent screens only ever return Pass
            // or Drop — they never mint a SYN-cookie challenge/bypass (those
            // are flow/TCP-only and stay on the flow-present path).
            _ => StageOutcome::Continue(ScreenCheckOutcome::Pass),
        };
    };
    let screen_pkt = match extract_screen_info(
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
    ) {
        Ok(pkt) => pkt,
        // FAIL-CLOSED (#2146): the extractor could not parse the L3
        // header far enough to evaluate the fragment/TCP screens (e.g.
        // a truncated IPv6 extension-header chain). With screen
        // profiles active on this zone, drop the unparseable frame
        // rather than admit it — a SYN-bearing frame with a truncated
        // FRAGMENT header must not bypass `syn-frag`.
        Err(err) => {
            let reason = err.screen_reason();
            let drop_info = screen_parse_error_info(&meta, flow);
            emit_screen_drop_event(
                worker_ctx.event_stream,
                &drop_info,
                meta,
                zone_id,
                reason,
                event_now_ns_from_secs(now_secs),
            );
            counters.record_screen_drop(
                reason,
                zone_id,
                &worker_ctx.forwarding.flood_counter_slot_map,
            );
            return StageOutcome::RecycleAndContinue;
        }
    };
    let verdict = screen.check_packet_with_zone_id_opts(
        zone_name,
        zone_id,
        &screen_pkt,
        now_ns,
        now_secs,
        skip_rate_flood,
    );
    // #3315: drain a pending SYN-flood alarm (alarm-threshold crossed below
    // attack-threshold). Like scan-table-pressure this is a log-only PERMIT
    // alarm — it does NOT drop and is rate-limited to ≤1/sec/zone in the screen
    // runtime — so it is emitted regardless of the verdict (the packet that
    // raised the alarm typically passes the aggregate and continues here).
    if screen.take_syn_alarm_event() {
        emit_screen_alarm_event(
            worker_ctx.event_stream,
            &screen_pkt,
            meta,
            zone_id,
            "syn-flood-alarm",
            event_now_ns_from_secs(now_secs),
        );
    }
    match verdict {
        ScreenVerdict::Pass => StageOutcome::Continue(ScreenCheckOutcome::Pass),
        ScreenVerdict::SynCookieBypass => {
            counters.touched = true;
            counters.syn_cookie_bypass += 1;
            StageOutcome::Continue(ScreenCheckOutcome::Pass)
        }
        ScreenVerdict::Drop(reason) => {
            // Junos `alarm-without-drop`: the check ran and counted; suppress
            // only the drop and raise a log-only alarm carrying the tripped
            // reason, then forward. Applies profile-wide (land, teardrop,
            // rate-based flood, session-limit, syn-cookie-unavailable, ...).
            if screen.alarm_without_drop(zone_name) {
                emit_screen_alarm_event(
                    worker_ctx.event_stream,
                    &screen_pkt,
                    meta,
                    zone_id,
                    reason,
                    event_now_ns_from_secs(now_secs),
                );
                screen.record_alarm_without_drop();
                // #7086: the check TRIPPED; only the drop was suppressed. Tally
                // it per zone on the ALARM triple so the surface can tell
                // "alarming and permitting" from "nothing recorded".
                crate::afxdp::flood_counters::record_zone_flood_alarm(
                    &worker_ctx.forwarding.flood_counter_slot_map,
                    zone_id,
                    reason,
                );
                StageOutcome::Continue(ScreenCheckOutcome::Pass)
            } else {
                emit_screen_drop_event(
                    worker_ctx.event_stream,
                    &screen_pkt,
                    meta,
                    zone_id,
                    reason,
                    event_now_ns_from_secs(now_secs),
                );
                counters.record_screen_drop(
                    reason,
                    zone_id,
                    &worker_ctx.forwarding.flood_counter_slot_map,
                );
                if reason == "syn-cookie-unavailable" {
                    counters.syn_cookie_secret_unavailable += 1;
                }
                StageOutcome::RecycleAndContinue
            }
        }
        ScreenVerdict::SynCookieChallenge(challenge) => {
            // In `alarm-without-drop` audit mode, do NOT perturb the TCP
            // handshake with a SYN-cookie challenge: log the flood as a
            // PERMIT alarm and forward the original SYN untouched.
            if screen.alarm_without_drop(zone_name) {
                emit_screen_alarm_event(
                    worker_ctx.event_stream,
                    &screen_pkt,
                    meta,
                    zone_id,
                    "syn-cookie",
                    event_now_ns_from_secs(now_secs),
                );
                screen.record_alarm_without_drop();
                // #7086: mirror the drop arm below, which passes this same
                // "syn-cookie" literal to record_screen_drop. That reason is
                // NOT one of flood_reason_index's three, so both arms
                // contribute nothing to the per-zone flood tally today. The
                // call is here anyway so the two arms cannot DRIFT: if
                // "syn-cookie" ever becomes a counted family, it starts
                // counting on the alarm arm and the drop arm together, rather
                // than re-creating #7086 for a new reason.
                crate::afxdp::flood_counters::record_zone_flood_alarm(
                    &worker_ctx.forwarding.flood_counter_slot_map,
                    zone_id,
                    "syn-cookie",
                );
                StageOutcome::Continue(ScreenCheckOutcome::Pass)
            } else {
                emit_screen_drop_event(
                    worker_ctx.event_stream,
                    &screen_pkt,
                    meta,
                    zone_id,
                    "syn-cookie",
                    event_now_ns_from_secs(now_secs),
                );
                counters.record_screen_drop(
                    "syn-cookie",
                    zone_id,
                    &worker_ctx.forwarding.flood_counter_slot_map,
                );
                counters.syn_cookie_challenges += 1;
                StageOutcome::Continue(ScreenCheckOutcome::SynCookieChallenge(challenge))
            }
        }
    }
}

/// SYN-cookie returning ACK validation on the session-miss path.
///
/// This runs after normal session lookup has failed, so established ACK traffic
/// keeps its normal fast/session path. A valid cookie ACK is consumed without
/// creating a session; the caller turns the `Validated` outcome into a bounded
/// RST reply and the validated-client cache lets the client's next SYN traverse
/// the ordinary policy/NAT/session path. Invalid cookie ACKs are dropped while
/// cookie mode is active. Poll-stage coverage intentionally pins only the
/// operational drop/bypass behavior here; the lower screen runtime owns cache
/// mechanics. `screen_tests.rs` covers bounded 4-way replacement, explicit
/// cache expiration, and current/previous secret-epoch validation.
#[inline]
pub(super) fn stage_screen_syn_cookie_ack_on_session_miss(
    flow: Option<&SessionFlow>,
    packet_frame: &[u8],
    meta: UserspaceDpMeta,
    ingress_zone_override: Option<u16>,
    now_ns: u64,
    now_secs: u64,
    screen: &mut ScreenState,
    counters: &mut BatchCounters,
    worker_ctx: &WorkerContext,
) -> StageOutcome<SynCookieAckOutcome> {
    // has_profiles is CORRECT here, unlike the #6860 change in
    // stage_screen_check above. This stage only ENFORCES -- it validates a
    // SYN-cookie ACK against a zone's resolved profile and emits no
    // missing-profile diagnostic -- so an unresolved reference gives it nothing
    // to do. Widening this gate would run the stage on every packet in a state
    // where it can only fall through, for no signal.
    if !screen.has_profiles() {
        return StageOutcome::Continue(SynCookieAckOutcome::Pass);
    }
    let Some(flow) = flow else {
        return StageOutcome::Continue(SynCookieAckOutcome::Pass);
    };
    // #3022: resolve the LOGICAL ingress ifindex first (see
    // `stage_screen_check`) so the SYN-cookie-ACK validation uses the VLAN
    // subinterface's own zone profile, not the parent's first-subinterface
    // zone. Non-VLAN ports resolve physical == logical.
    let logical_ifindex = resolve_ingress_logical_ifindex(
        worker_ctx.forwarding,
        meta.ingress_ifindex as i32,
        meta.ingress_vlan_id,
    )
    .unwrap_or(meta.ingress_ifindex as i32);
    let zone_id = ingress_zone_override
        .filter(|id| worker_ctx.forwarding.zone_id_to_name.contains_key(id))
        .or_else(|| {
            worker_ctx
                .forwarding
                .ifindex_to_zone_id
                .get(&logical_ifindex)
                .copied()
        });
    let Some(zone_id) = zone_id else {
        return StageOutcome::Continue(SynCookieAckOutcome::Pass);
    };
    let Some(zone_name) = worker_ctx
        .forwarding
        .zone_id_to_name
        .get(&zone_id)
        .map(|s| s.as_str())
    else {
        return StageOutcome::Continue(SynCookieAckOutcome::Pass);
    };
    // See `stage_screen_check`: decide L3 offset on tag PRESENCE, not
    // VID > 0, so a priority-tagged VID-0 cookie ACK is parsed at the
    // correct offset (18) instead of mis-reading the tag bytes (#2145).
    let l3_off = if meta.ingress_vlan_present != 0 {
        18
    } else {
        14
    };
    let screen_pkt = match extract_screen_info(
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
    ) {
        Ok(pkt) => pkt,
        // FAIL-CLOSED (#2146): an unparseable L3 header on the
        // SYN-cookie ACK session-miss path is dropped, never admitted.
        Err(err) => {
            let reason = err.screen_reason();
            let drop_info = screen_parse_error_info(&meta, flow);
            emit_screen_drop_event(
                worker_ctx.event_stream,
                &drop_info,
                meta,
                zone_id,
                reason,
                event_now_ns_from_secs(now_secs),
            );
            counters.record_screen_drop(
                reason,
                zone_id,
                &worker_ctx.forwarding.flood_counter_slot_map,
            );
            return StageOutcome::RecycleAndContinue;
        }
    };
    match screen.validate_syn_cookie_ack_on_session_miss(
        zone_name,
        zone_id,
        &screen_pkt,
        now_ns,
        now_secs,
    ) {
        SynCookieAckVerdict::NotApplicable => StageOutcome::Continue(SynCookieAckOutcome::Pass),
        SynCookieAckVerdict::Validated => {
            counters.touched = true;
            counters.syn_cookie_ack_valid += 1;
            StageOutcome::Continue(SynCookieAckOutcome::Validated)
        }
        SynCookieAckVerdict::Invalid => {
            emit_screen_drop_event(
                worker_ctx.event_stream,
                &screen_pkt,
                meta,
                zone_id,
                "syn-cookie",
                event_now_ns_from_secs(now_secs),
            );
            counters.record_screen_drop(
                "syn-cookie",
                zone_id,
                &worker_ctx.forwarding.flood_counter_slot_map,
            );
            counters.syn_cookie_ack_invalid += 1;
            StageOutcome::RecycleAndContinue
        }
    }
}

/// The synthetic `LocalDelivery` decision Stage 11 hands to the
/// slow-path reinjector for host-terminated IPsec passthrough
/// (ESP/AH/IKE).
///
/// `local_ifindex`/`egress_ifindex`/`tx_ifindex` are deliberately `0`
/// and MUST stay `0` (#3616). `maybe_reinject_slow_path_from_frame`
/// routes a `LocalDelivery` reinject with `local_ifindex > 0` into the
/// GRE `local_tunnel_deliveries` channel (`tx/dispatch/slow_path.rs`),
/// diverting it away from the generic kernel TUN injector. Carrying a
/// real ingress ifindex here would therefore MIS-DELIVER IPsec-to-self,
/// not enforce host-inbound — the ESP/AH passthrough short-circuits with
/// `RecycleAndContinue` before `host_inbound_admits_iface` is ever reached
/// and stays exempt from the per-zone host-inbound gate by design (see
/// `forwarding/README.md`, "Host-terminated IPsec passthrough"); IKE carries
/// its own SEPARATE in-stage admit checks (#4323 / #6471, below). Telemetry
/// carries the real ingress ifindex via `meta` on the exception record,
/// never through this routing decision.
///
/// A per-zone host-inbound gate for NEW IKE at Stage 11 landed as #4323
/// (Option B), extended by #6471 to Responder-SPI-nonzero IKE with no
/// seeded live exchange. Both run as SEPARATE admit checks BEFORE the
/// reinject, keyed on the resolved ingress zone — never by setting a real
/// `local_ifindex` here, which would divert the reinject into the GRE
/// channel.
fn ipsec_passthrough_decision() -> SessionDecision {
    SessionDecision { resolution: ForwardingResolution {
        disposition: ForwardingDisposition::LocalDelivery,
        local_ifindex: 0,
        egress_ifindex: 0,
        tx_ifindex: 0,
        tunnel_endpoint_id: 0,
        next_hop: None,
        neighbor_mac: None,
        src_mac: None,
        tx_vlan_id: 0,
    }, nat: NatDecision::default(), install_table_domain: 0, install_table_check: 0 }
}

/// #4323: the outcome of Stage 11 (IPsec passthrough) for the poll loop.
pub(super) enum IpsecPassthroughOutcome {
    /// Not IPsec (or no parsed flow) — the packet falls through Stage 11
    /// unchanged and the caller keeps processing it.
    NotClaimed,
    /// IPsec traffic reinjected toward the kernel XFRM stack — the caller
    /// recycles the UMEM frame and moves to the next descriptor.
    Passthrough,
    /// A NEW inbound IKE initiation the ingress zone's host-inbound set does
    /// NOT permit — OR (#6471) a Responder-SPI-nonzero IKE packet that matches
    /// NO seeded live exchange on such a zone — a silent drop (Junos
    /// host-inbound posture). The caller recycles the frame, accounts
    /// `host_inbound_denied_packets`, and emits the tuple-rich host-inbound
    /// deny event on `from_zone_id`.
    Denied { from_zone_id: u16 },
}

/// #4323/#6471: resolve the LOGICAL ingress ifindex + from-zone exactly as the
/// local-delivery resolver does (a VLAN sub-interface keys its own unit; a
/// fabric-ingress packet keys the override zone), then apply the per-interface
/// / per-zone host-inbound admit check for IKE. `host_inbound_admits_iface`
/// honours a per-interface override where one exists and otherwise falls back
/// to the from-zone set. Returns `Some(from_zone_id)` when IKE is NOT admitted
/// (the caller returns `Denied`), `None` when admitted.
fn ike_host_inbound_deny_zone(
    flow: &SessionFlow,
    meta: UserspaceDpMeta,
    dst_port: u16,
    ingress_zone_override: Option<u16>,
    now_secs: u64,
    worker_ctx: &WorkerContext,
) -> Option<u16> {
    let ingress_logical = crate::afxdp::forwarding::resolve_ingress_logical_ifindex(
        worker_ctx.forwarding,
        meta.ingress_ifindex as i32,
        meta.ingress_vlan_id,
    )
    .unwrap_or(meta.ingress_ifindex as i32);
    // #6458 (review fold): the V1-validated stamp drives host-inbound
    // admission only when the DESTINATION address's owner RG is
    // forwarding-active LOCALLY — the same V2 owner binding the session-miss
    // zone-pair sites apply, resolved for a host-destined packet from the
    // local address (review MEDIUM: a forged stamped NEW IKE initiation to a
    // single-primary backup's reth address was Passthrough AND seeded the
    // #6471 live-exchange table; it now degrades to the fabric zone).
    let ingress_zone_override = crate::afxdp::forwarding::gate_fabric_zone_override_on_local_owner_rg(
        worker_ctx.forwarding,
        worker_ctx.ha_state,
        now_secs,
        ingress_zone_override,
        flow.dst_ip,
    );
    let (from_zone_id, _to_zone_id) =
        crate::afxdp::forwarding::zone_pair_ids_for_flow_with_override(
            worker_ctx.forwarding,
            ingress_logical,
            ingress_zone_override,
            0,
        );
    if crate::afxdp::forwarding::host_inbound_admits_iface(
        worker_ctx.forwarding,
        ingress_logical,
        from_zone_id,
        PROTO_UDP,
        dst_port,
        matches!(flow.dst_ip, IpAddr::V6(_)),
        0,
    ) {
        None
    } else {
        Some(from_zone_id)
    }
}

/// Stage 11 — IPsec passthrough.
///
/// ESP (proto 50), AH (proto 51, IPv4) and IKE (UDP 500/4500) must
/// transit the kernel XFRM subsystem. On a match, this stage builds a
/// synthetic `SessionDecision` with `LocalDelivery` disposition
/// (`ipsec_passthrough_decision`) and reinjects the packet via the
/// slow-path TUN device, then returns `Passthrough` so the caller drops
/// the UMEM frame.
///
/// #4323 (Option B): a NEW inbound IKE initiation (an ISAKMP header with an
/// all-zero Responder SPI — see `classify_ipsec_admission`) is first gated on
/// the ingress zone's host-inbound `ike`/`ipsec` admission. A zone that omits
/// `ike` drops the unsolicited inbound IKE (`Denied`) so it never reaches the
/// local IKE daemon; a zone that lists `ike`/`ipsec` admits it. ESP/AH, the
/// IPsec data plane (ESP-in-UDP / NAT-T keepalive) stay EXEMPT (unconditional
/// passthrough) — the SA is the authorization, mirroring the kernel chain's
/// global ESP/AH accept.
///
/// #6471: a Responder-SPI-nonzero IKE packet is NOT automatically
/// "established" — the SPI bytes are attacker-controlled, so a forged
/// non-zero Responder SPI otherwise rode the #4323 `Exempt` class straight
/// to strongSwan on a zone the operator closed to IKE. Established now means
/// MATCHING the shared live-exchange table (`IkeExchangeTable`): seeded here
/// when a NEW initiation passes the host-inbound gate, and seeded in the
/// native-GRE local-origin path when the firewall initiates IKE through a
/// tunnel (its replies arrive on this stage with the Responder SPI set and
/// no inbound seed). A non-zero-Responder IKE packet that matches a seed is
/// admitted (and refreshes it); one that matches NOTHING is handed to the
/// SAME host-inbound gate a NEW initiation faces — denied on a zone that
/// omits `ike` (the forged-SPI bypass, now closed), admitted on a zone that
/// lists `ike` (config-sanctioned openness, primary-path parity: the kernel
/// chain admits NEW IKE there too). This mirrors the primary path's `ct
/// established,related accept`-first ordering, with the exchange table
/// playing the conntrack role the secondary path lacks.
///
/// This SECONDARY AF_XDP path is reached by DNAT/static-NAT-to-self IKE and by
/// native-GRE-inner local IPsec; direct IKE to a firewall interface IP / VIP is
/// still enforced on the PRIMARY path by the kernel nftables host-inbound chain
/// (`pkg/daemon/daemon_nft.go`).
///
/// #5620: the kernel-XFRM passthrough short-circuit is claimed ONLY when the
/// packet's (post-GRE-decap, on-the-wire) destination is an address the
/// firewall itself answers for (`forwarding.owns_configured_ip` — configured
/// interface IPs incl. the SNAT/WAN IP and any VIP, plus the static-NAT/DNAT
/// externals appended to `local_v*`). Stage 11 runs BEFORE NAT resolution, so
/// `flow.dst_ip` is the RAW destination; because the NAT externals are already
/// members of the local set, the raw-dst check still recognises the legitimate
/// SECONDARY-path cases — DNAT/static-NAT-to-self IKE (the external is a
/// firewall-owned address) and native-GRE-inner local IPsec (the decapped
/// inner destination is a firewall interface address). A remote / transit ESP,
/// AH or IKE destination is owned by nobody here → `NotClaimed`, so the packet
/// is NOT reinjected to the local XFRM stack and instead continues to normal
/// transit forwarding + zone-policy evaluation. Without this predicate any
/// ESP/AH/IKE packet — including one transiting to a remote host — bypassed
/// transit policy.
///
/// Non-IPsec packets fall through unchanged (`NotClaimed`).
#[inline]
pub(super) fn stage_ipsec_passthrough_check(
    flow: Option<&SessionFlow>,
    packet_frame: &[u8],
    meta: UserspaceDpMeta,
    ingress_zone_override: Option<u16>,
    binding_live: &BindingLiveState,
    worker_ctx: &WorkerContext,
    now_ns: u64,
    now_secs: u64,
) -> IpsecPassthroughOutcome {
    let Some(flow) = flow else {
        return IpsecPassthroughOutcome::NotClaimed;
    };
    let dst_port = flow.forward_key.dst_port;
    if !is_ipsec_traffic(meta.protocol, dst_port) {
        return IpsecPassthroughOutcome::NotClaimed;
    }
    // #5620: claim the kernel-XFRM passthrough short-circuit ONLY for
    // IPsec whose destination is a firewall-local address. Stage 11 runs
    // BEFORE NAT resolution (only GRE decap precedes it), so `flow.dst_ip`
    // is the RAW on-the-wire destination — but `owns_configured_ip` already
    // includes the static-NAT/DNAT externals appended to `local_v*`, so this
    // still claims DNAT/static-NAT-to-self IKE and native-GRE-inner local
    // IPsec (whose decapped inner dst is a firewall interface address). A
    // remote / transit ESP/AH/IKE destination is owned by nobody here →
    // `NotClaimed`, so the packet is NOT reinjected to the local stack and
    // instead continues to transit forwarding + zone-policy evaluation. This
    // gate runs BEFORE the #4323 host-inbound admission block, which only
    // makes sense for genuinely host-inbound (local-destined) IKE.
    //
    // Caveat: a DNAT external that maps to ANOTHER host (transit-DNAT IPsec,
    // e.g. IKE VIP -> internal gateway) is ALSO in `local_v*` (proxy-ARP/ND
    // ownership), so this raw-dst check still claims it as local passthrough
    // rather than DNAT-forwarding it onward. That exotic case is UNCHANGED by
    // #5620 — pre-#5620 Stage 11 claimed ALL IPsec, so it was already
    // reinjected locally; #5620 only fixes the transit-to-REMOTE bypass and
    // leaves the transit-DNAT-to-another-host behavior bit-identical.
    if !worker_ctx.forwarding.owns_configured_ip(flow.dst_ip) {
        return IpsecPassthroughOutcome::NotClaimed;
    }
    match crate::afxdp::forwarding::classify_ipsec_admission(
        packet_frame,
        meta.l4_offset as usize,
        meta.protocol,
        dst_port,
    ) {
        // #4323 Option B: gate a NEW inbound IKE initiation on host-inbound.
        crate::afxdp::forwarding::IpsecAdmissionClass::NewInboundIke => {
            if let Some(from_zone_id) =
                ike_host_inbound_deny_zone(flow, meta, dst_port, ingress_zone_override, now_secs, worker_ctx)
            {
                return IpsecPassthroughOutcome::Denied { from_zone_id };
            }
            // #6471: the initiation was ADMITTED — seed the exchange so its
            // established follow-ups (Responder SPI set) are recognized. A
            // DENIED initiation must never seed: a forged follow-up would
            // otherwise mint its own "established" entry and re-open the
            // bypass on a closed zone.
            if let Some(initiator_spi) = crate::afxdp::forwarding::ike_initiation_spi(
                packet_frame,
                meta.l4_offset as usize,
                dst_port,
            ) {
                worker_ctx.ike_exchanges.seed(
                    crate::afxdp::forwarding::IkeExchangeKey::new(
                        initiator_spi,
                        flow.src_ip,
                        flow.dst_ip,
                    ),
                    now_ns,
                );
            }
        }
        crate::afxdp::forwarding::IpsecAdmissionClass::Exempt => {
            // #6471: a Responder-SPI-nonzero IKE packet is "established" only
            // with a matching live-exchange seed; otherwise it faces the same
            // host-inbound gate as a NEW initiation. ESP/AH, ESP-in-UDP and
            // NAT-T keepalives (`None`) stay unconditionally exempt.
            if let Some(initiator_spi) = crate::afxdp::forwarding::established_ike_initiator_spi(
                packet_frame,
                meta.l4_offset as usize,
                dst_port,
            ) {
                let key = crate::afxdp::forwarding::IkeExchangeKey::new(
                    initiator_spi,
                    flow.src_ip,
                    flow.dst_ip,
                );
                if !worker_ctx.ike_exchanges.matches(&key, now_ns)
                    && let Some(from_zone_id) = ike_host_inbound_deny_zone(
                        flow,
                        meta,
                        dst_port,
                        ingress_zone_override,
                        now_secs,
                        worker_ctx,
                    )
                {
                    return IpsecPassthroughOutcome::Denied { from_zone_id };
                }
            }
        }
    }
    IpsecPassthroughOutcome::Passthrough
}

/// Reinject an IPsec packet only after the caller has completed every
/// fragment-overlap admission check. Keeping this side effect separate from
/// [`stage_ipsec_passthrough_check`] prevents a terminal fragment from being
/// delivered to XFRM before its late overlap reservation can reject it.
#[inline]
pub(super) fn reinject_ipsec_passthrough(
    packet_frame: &[u8],
    meta: UserspaceDpMeta,
    binding_live: &BindingLiveState,
    worker_ctx: &WorkerContext,
) -> bool {
    let ipsec_decision = ipsec_passthrough_decision();
    maybe_reinject_slow_path_from_frame(
        &worker_ctx.ident,
        binding_live,
        worker_ctx.slow_path,
        worker_ctx.local_tunnel_deliveries,
        packet_frame,
        meta,
        ipsec_decision,
        false,
        worker_ctx.recent_exceptions,
        "slow_path",
        worker_ctx.forwarding,
    )
}

#[cfg(test)]
#[path = "poll_stages_tests.rs"]
mod tests;
