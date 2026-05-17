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
/// dropped while cookie mode is active. Cache expiry, secret-epoch rotation,
/// and HA/cache-survivability semantics remain explicit #1374 follow-ups; this
/// stage only consumes already-valid cookies and installs a bounded one-shot
/// admission hint.
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_zone_ids::TEST_LAN_ZONE_ID;

    const TEST_NOW_SECS: u64 = 128;
    const TCP_FLAG_ACK: u8 = 0x10;

    fn tcp_v4_frame(
        src: Ipv4Addr,
        dst: Ipv4Addr,
        src_port: u16,
        dst_port: u16,
        flags: u8,
        seq: u32,
        ack: u32,
    ) -> Vec<u8> {
        let mut frame = Vec::new();
        write_eth_header(
            &mut frame,
            [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            [0x00, 0x25, 0x90, 0x12, 0x34, 0x56],
            0,
            0x0800,
        );
        frame.extend_from_slice(&[
            0x45, 0x00, 0x00, 0x28, 0x00, 0x01, 0x00, 0x00, 64, PROTO_TCP, 0x00, 0x00,
        ]);
        frame.extend_from_slice(&src.octets());
        frame.extend_from_slice(&dst.octets());
        let ip_csum = checksum16(&frame[14..34]);
        frame[24..26].copy_from_slice(&ip_csum.to_be_bytes());
        frame.extend_from_slice(&src_port.to_be_bytes());
        frame.extend_from_slice(&dst_port.to_be_bytes());
        frame.extend_from_slice(&seq.to_be_bytes());
        frame.extend_from_slice(&ack.to_be_bytes());
        frame.extend_from_slice(&[0x50, flags, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00]);
        recompute_l4_checksum_ipv4(&mut frame[14..], 20, PROTO_TCP, false).expect("tcp checksum");
        frame
    }

    fn tcp_v4_meta(frame: &[u8], flags: u8) -> UserspaceDpMeta {
        UserspaceDpMeta {
            magic: USERSPACE_META_MAGIC,
            version: USERSPACE_META_VERSION,
            length: std::mem::size_of::<UserspaceDpMeta>() as u16,
            ingress_ifindex: 24,
            l3_offset: 14,
            l4_offset: 34,
            payload_offset: 54,
            pkt_len: (frame.len() - 14) as u16,
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            tcp_flags: flags,
            ..UserspaceDpMeta::default()
        }
    }

    fn syn_cookie_screen() -> ScreenState {
        let mut profiles = FxHashMap::default();
        profiles.insert(
            "lan".to_string(),
            ScreenProfile {
                syn_flood_threshold: 1,
                syn_cookie: true,
                ..ScreenProfile::default()
            },
        );
        let mut screen = ScreenState::new();
        screen.update_profiles(profiles);
        screen.update_syn_cookie_master_key(Some([0x42; 16]));
        screen
    }

    #[test]
    fn session_miss_ack_stage_invokes_syn_cookie_runtime_validation() {
        let mut screen = syn_cookie_screen();
        let forwarding = build_forwarding_state(&super::super::test_fixtures::nat_snapshot());
        let ident = BindingIdentity {
            slot: 0,
            queue_id: 0,
            worker_id: 0,
            interface: Arc::<str>::from("reth1.0"),
            ifindex: 24,
        };
        let binding_lookup = WorkerBindingLookup::default();
        let ha_state = BTreeMap::new();
        let dynamic_neighbors = Arc::new(ShardedNeighborMap::default());
        let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
        let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
        let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
        let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
        let local_tunnel_deliveries = Arc::new(ArcSwap::from_pointee(BTreeMap::new()));
        let recent_exceptions = Arc::new(Mutex::new(VecDeque::new()));
        let last_resolution = Arc::new(Mutex::new(None));
        let peer_worker_commands = Vec::new();
        let dnat_fds = DnatTableFds::default();
        let rg_epochs = std::array::from_fn(|_| AtomicU32::new(0));
        let worker_ctx = WorkerContext {
            ident: &ident,
            binding_lookup: &binding_lookup,
            forwarding: &forwarding,
            ha_state: &ha_state,
            dynamic_neighbors: &dynamic_neighbors,
            shared_sessions: &shared_sessions,
            shared_nat_sessions: &shared_nat_sessions,
            shared_forward_wire_sessions: &shared_forward_wire_sessions,
            shared_owner_rg_indexes: &shared_owner_rg_indexes,
            slow_path: None,
            local_tunnel_deliveries: &local_tunnel_deliveries,
            recent_exceptions: &recent_exceptions,
            last_resolution: &last_resolution,
            peer_worker_commands: &peer_worker_commands,
            dnat_fds: &dnat_fds,
            rg_epochs: &rg_epochs,
        };

        let client = Ipv4Addr::new(192, 0, 2, 10);
        let server = Ipv4Addr::new(198, 51, 100, 20);
        let syn_frame = tcp_v4_frame(client, server, 49152, 443, TCP_FLAG_SYN, 1, 0);
        let syn_meta = tcp_v4_meta(&syn_frame, TCP_FLAG_SYN);
        let syn_flow =
            parse_session_flow_from_bytes(&syn_frame, syn_meta).expect("session flow from SYN");
        let syn_info = extract_screen_info(
            &syn_frame,
            syn_meta.addr_family,
            syn_meta.protocol,
            syn_meta.tcp_flags,
            syn_meta.pkt_len,
            syn_flow.src_ip,
            syn_flow.dst_ip,
            syn_flow.forward_key.src_port,
            syn_flow.forward_key.dst_port,
            syn_meta.l3_offset as usize,
        );

        assert_eq!(
            screen.check_packet_with_zone_id("lan", TEST_LAN_ZONE_ID, &syn_info, TEST_NOW_SECS),
            ScreenVerdict::Pass
        );
        let _challenge = match screen.check_packet_with_zone_id(
            "lan",
            TEST_LAN_ZONE_ID,
            &syn_info,
            TEST_NOW_SECS,
        ) {
            ScreenVerdict::SynCookieChallenge(challenge) => challenge,
            other => panic!("expected SYN-cookie challenge, got {other:?}"),
        };

        let invalid_ack_frame = tcp_v4_frame(
            client,
            server,
            49152,
            443,
            TCP_FLAG_ACK,
            2,
            0xdead_beef,
        );
        let invalid_ack_meta = tcp_v4_meta(&invalid_ack_frame, TCP_FLAG_ACK);
        let invalid_ack_flow =
            parse_session_flow_from_bytes(&invalid_ack_frame, invalid_ack_meta)
                .expect("session flow from invalid ACK");
        let mut invalid_counters = BatchCounters::default();

        assert!(matches!(
            stage_screen_syn_cookie_ack_on_session_miss(
                Some(&invalid_ack_flow),
                &invalid_ack_frame,
                invalid_ack_meta,
                None,
                TEST_NOW_SECS,
                &mut screen,
                &mut invalid_counters,
                &worker_ctx,
            ),
            StageOutcome::RecycleAndContinue
        ));
        assert!(
            invalid_counters.touched,
            "invalid cookie ACK must be counted as a screen drop"
        );
        assert_eq!(invalid_counters.screen_drops, 1);

        let challenge = match screen.check_packet_with_zone_id(
            "lan",
            TEST_LAN_ZONE_ID,
            &syn_info,
            TEST_NOW_SECS,
        ) {
            ScreenVerdict::SynCookieChallenge(challenge) => challenge,
            other => panic!("invalid ACK must not install SYN-cookie bypass, got {other:?}"),
        };

        let ack_frame = tcp_v4_frame(
            client,
            server,
            49152,
            443,
            TCP_FLAG_ACK,
            2,
            challenge.cookie_isn.wrapping_add(1),
        );
        let ack_meta = tcp_v4_meta(&ack_frame, TCP_FLAG_ACK);
        let ack_flow =
            parse_session_flow_from_bytes(&ack_frame, ack_meta).expect("session flow from ACK");
        let mut counters = BatchCounters::default();

        assert!(matches!(
            stage_screen_syn_cookie_ack_on_session_miss(
                Some(&ack_flow),
                &ack_frame,
                ack_meta,
                None,
                TEST_NOW_SECS,
                &mut screen,
                &mut counters,
                &worker_ctx,
            ),
            StageOutcome::RecycleAndContinue
        ));
        assert!(
            !counters.touched,
            "valid cookie ACK is consumed without counting a screen drop"
        );
        assert_eq!(counters.screen_drops, 0);

        assert_eq!(
            screen.check_packet_with_zone_id("lan", TEST_LAN_ZONE_ID, &syn_info, TEST_NOW_SECS),
            ScreenVerdict::Pass,
            "poll-stage session-miss ACK handling must invoke SYN-cookie validation"
        );
        assert!(
            matches!(
                screen.check_packet_with_zone_id("lan", TEST_LAN_ZONE_ID, &syn_info, TEST_NOW_SECS),
                ScreenVerdict::SynCookieChallenge(_)
            ),
            "validated SYN-cookie bypass must be single-use"
        );
    }
}
