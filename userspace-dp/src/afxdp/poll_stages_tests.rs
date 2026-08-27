use super::*;
use crate::event_stream::DataplaneEventRateLimitConfig;
use crate::event_stream::codec::DataplaneEventKind;
use crate::test_zone_ids::TEST_LAN_ZONE_ID;

const TEST_NOW_SECS: u64 = 128;
/// #3607: monotonic-ns companion of `TEST_NOW_SECS` for the token-bucket
/// screen paths (`stage_screen_check` / the standby-ACK stage now take a
/// `now_ns` before `now_secs`).
const TEST_NOW_NS: u64 = TEST_NOW_SECS * 1_000_000_000;
const TCP_FLAG_ACK: u8 = 0x10;

/// Test wrapper for `stage_link_layer_classify` (#5288 added a `now_ns` +
/// per-worker `KernelNeighborProgramLimiter` to its signature). These tests
/// assert on the learned userspace neighbor MAP, which `insert_if_changed`
/// updates unconditionally; the #5288 limiter only gates the (un-observable)
/// netlink `add_kernel_neighbor` syscall, so a fresh limiter per call is
/// correct here. The limiter's own repeat/flood gating is pinned directly in
/// `neighbor_program_limiter::tests`.
fn classify(
    frame: &[u8],
    meta: UserspaceDpMeta,
    ctx: &WorkerContext,
) -> StageOutcome<()> {
    let mut neigh_limiter = KernelNeighborProgramLimiter::new();
    stage_link_layer_classify(frame, meta, TEST_NOW_NS, &mut neigh_limiter, ctx)
}

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
        pkt_len: frame.len() as u16,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        tcp_flags: flags,
        ..UserspaceDpMeta::default()
    }
}

/// Build an IPv4 TCP SYN with the L2 header chosen by `vlan`:
/// `Vlan::None` → 14-byte untagged header; `Vlan::PriorityTagged`
/// → an 802.1p priority tag (TPID 0x8100, PCP 5, **VID 0**), so the
/// L3 header starts at offset 18 while `ingress_vlan_id` is 0. The
/// IPv4 header is built with `ihl` 32-bit words (5 = no options;
/// 6 = one option word carrying an LSRR source-route option, which
/// trips the `ip-source-route` screen — #2973 requires a real
/// LSRR/SSRR option, not just `ihl > 5`).
fn tcp_v4_syn_frame_with_l2(vlan: Vlan, ihl: u8) -> Vec<u8> {
    let mut frame = Vec::new();
    let dst_mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
    let src_mac = [0x00, 0x25, 0x90, 0x12, 0x34, 0x56];
    frame.extend_from_slice(&dst_mac);
    frame.extend_from_slice(&src_mac);
    if let Vlan::PriorityTagged = vlan {
        // 802.1Q TPID + TCI. TCI = PCP(3) | DEI(1) | VID(12); here
        // PCP=5, DEI=0, VID=0 — the priority-tagged-VLAN-0 shape
        // that #2145 mis-parsed.
        frame.extend_from_slice(&0x8100u16.to_be_bytes());
        frame.extend_from_slice(&(0x5u16 << 13).to_be_bytes());
    }
    frame.extend_from_slice(&0x0800u16.to_be_bytes());
    let l3 = frame.len();
    let ihl_bytes = ihl as usize * 4;
    // IPv4 header: version/IHL, then the fixed 20-byte base header,
    // then `ihl_bytes - 20` NOP option bytes.
    frame.push(0x40 | ihl);
    frame.push(0x00);
    let total_len = (ihl_bytes + 20) as u16; // IP header + 20-byte TCP
    frame.extend_from_slice(&total_len.to_be_bytes());
    frame.extend_from_slice(&[0x00, 0x01, 0x40, 0x00, 64, PROTO_TCP, 0x00, 0x00]);
    frame.extend_from_slice(&Ipv4Addr::new(192, 0, 2, 10).octets());
    frame.extend_from_slice(&Ipv4Addr::new(198, 51, 100, 20).octets());
    // IPv4 options to reach `ihl_bytes`. When options are present
    // (ihl > 5) the first option is an actual LSRR (Loose Source
    // Route, option type 131) so the `ip-source-route` screen fires.
    // #2973 made that screen require a real LSRR/SSRR option (the
    // extractor decodes the options TLVs) instead of dropping on any
    // ihl > 5, so a NOP-only options region no longer trips it. The
    // remaining bytes stay NOP (0x01); the extractor detects the
    // source-route option from the kind byte alone.
    frame.resize(l3 + ihl_bytes, 0x01);
    if ihl > 5 {
        frame[l3 + 20] = 131; // LSRR
    }
    let ip_csum = checksum16(&frame[l3..l3 + ihl_bytes]);
    frame[l3 + 10..l3 + 12].copy_from_slice(&ip_csum.to_be_bytes());
    // TCP SYN.
    let l4 = frame.len();
    frame.extend_from_slice(&49152u16.to_be_bytes());
    frame.extend_from_slice(&443u16.to_be_bytes());
    frame.extend_from_slice(&1u32.to_be_bytes()); // seq
    frame.extend_from_slice(&0u32.to_be_bytes()); // ack
    frame.extend_from_slice(&[0x50, TCP_FLAG_SYN, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00]);
    recompute_l4_checksum_ipv4(&mut frame[l3..], ihl_bytes, PROTO_TCP, false)
        .expect("tcp checksum");
    let _ = l4;
    frame
}

#[derive(Clone, Copy)]
enum Vlan {
    None,
    PriorityTagged,
}

/// Metadata mirroring the shim contract for the frame built above:
/// tagged frames carry `ingress_vlan_present = 1` with
/// `ingress_vlan_id = 0` (priority tag) and `l3_offset = 18`;
/// untagged frames carry `present = 0`, `l3_offset = 14`.
fn tcp_v4_syn_meta_with_l2(frame: &[u8], vlan: Vlan) -> UserspaceDpMeta {
    let (l3, present): (u16, u8) = match vlan {
        Vlan::None => (14, 0),
        Vlan::PriorityTagged => (18, 1),
    };
    UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        ingress_ifindex: 24,
        ingress_vlan_id: 0,
        ingress_pcp: if present != 0 { 5 } else { 0 },
        ingress_vlan_present: present,
        l3_offset: l3,
        l4_offset: l3 + 20,
        payload_offset: l3 + 40,
        pkt_len: frame.len() as u16 - l3,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        tcp_flags: TCP_FLAG_SYN,
        ..UserspaceDpMeta::default()
    }
}

/// #5806: a ScreenState carrying ONLY an unresolved profile reference — the
/// tolerant-load shape where the `security screen` definitions are gone
/// entirely but a zone still names one. No resolved profile exists, so
/// `has_profiles()` is false.
fn missing_only_screen() -> ScreenState {
    let mut screen = ScreenState::new();
    let mut missing = FxHashMap::default();
    missing.insert("lan".to_string(), "ghost".to_string());
    screen.update_missing_profiles(missing);
    screen
}

/// #5806: an unresolved reference for `lan` ALONGSIDE a resolved profile for a
/// different zone, so `has_profiles()` is true and the screen stage actually
/// runs for the `lan` packet.
fn missing_plus_resolved_screen() -> ScreenState {
    let mut profiles = FxHashMap::default();
    profiles.insert(
        "other".to_string(),
        ScreenProfile {
            source_route: true,
            ..ScreenProfile::default()
        },
    );
    let mut screen = ScreenState::new();
    screen.update_profiles(profiles);
    let mut missing = FxHashMap::default();
    missing.insert("lan".to_string(), "ghost".to_string());
    screen.update_missing_profiles(missing);
    screen
}

/// Screen state with only the IP source-route check armed. The
/// check fires on an actual LSRR/SSRR option decoded from the IPv4
/// options region (post-#2973) read from the frame at the computed
/// L3 offset, so the verdict is a direct probe of whether the screen
/// stage parsed the IP header at the right offset.
fn source_route_screen() -> ScreenState {
    let mut profiles = FxHashMap::default();
    profiles.insert(
        "lan".to_string(),
        ScreenProfile {
            source_route: true,
            ..ScreenProfile::default()
        },
    );
    let mut screen = ScreenState::new();
    screen.update_profiles(profiles);
    screen
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
    let mirror_targets = MirrorTargetMap::default();
    let ha_state = BTreeMap::new();
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::default());
    let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
    let ike_exchanges = Arc::new(crate::afxdp::forwarding::IkeExchangeTable::new());
    let local_tunnel_deliveries = Arc::new(ArcSwap::from_pointee(BTreeMap::new()));
    let recent_exceptions = Arc::new(Mutex::new(ExceptionEventRing::new()));
    let last_resolution = Arc::new(Mutex::new(None));
    let peer_worker_commands = Vec::new();
    let dnat_fds = DnatTableFds::default();
    let rg_epochs = std::array::from_fn(|_| AtomicU32::new(0));
    let (event_handle, event_rx) = crate::event_stream::test_worker_handle(
        8,
        DataplaneEventRateLimitConfig {
            events_per_second: 0,
            burst: 0,
        },
    );
    let worker_ctx = WorkerContext {
        ident: &ident,
        binding_lookup: &binding_lookup,
        mirror_targets: &mirror_targets,
        forwarding: &forwarding,
        ha_state: &ha_state,
        dynamic_neighbors: &dynamic_neighbors,
        neighbor_resolver: None,
        shared_sessions: &shared_sessions,
        shared_nat_sessions: &shared_nat_sessions,
        shared_forward_wire_sessions: &shared_forward_wire_sessions,
        shared_owner_rg_indexes: &shared_owner_rg_indexes,
        ike_exchanges: &ike_exchanges,
        slow_path: None,
        event_stream: Some(&event_handle),
        local_tunnel_deliveries: &local_tunnel_deliveries,
        recent_exceptions: &recent_exceptions,
        last_resolution: &last_resolution,
        peer_worker_commands: &peer_worker_commands,
        dnat_fds: &dnat_fds,
        rg_epochs: &rg_epochs,
        cold_path_sample_mask: 0xff,
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
    )
    .expect("valid SYN frame parses");

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

    let invalid_ack_frame =
        tcp_v4_frame(client, server, 49152, 443, TCP_FLAG_ACK, 2, 0xdead_beef);
    let invalid_ack_meta = tcp_v4_meta(&invalid_ack_frame, TCP_FLAG_ACK);
    let invalid_ack_flow = parse_session_flow_from_bytes(&invalid_ack_frame, invalid_ack_meta)
        .expect("session flow from invalid ACK");
    let mut invalid_counters = BatchCounters::default();

    assert!(matches!(
        stage_screen_syn_cookie_ack_on_session_miss(
            Some(&invalid_ack_flow),
            &invalid_ack_frame,
            invalid_ack_meta,
            None,
            TEST_NOW_NS,
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
    assert_eq!(invalid_counters.syn_cookie_ack_invalid, 1);
    let screen_event = event_rx
        .try_recv()
        .expect("screen-drop event")
        .decode_dataplane_event()
        .expect("screen-drop payload");
    assert_eq!(screen_event.kind, DataplaneEventKind::ScreenDrop);
    assert_eq!(screen_event.ingress_zone_id, TEST_LAN_ZONE_ID);
    assert_eq!(screen_event.ingress_ifindex, 24);
    assert_eq!(screen_event.screen_id, 1 << 14);
    assert_eq!(event_handle.dataplane_event_stats().screen_drop.sent, 1);

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
            TEST_NOW_NS,
            TEST_NOW_SECS,
            &mut screen,
            &mut counters,
            &worker_ctx,
        ),
        StageOutcome::Continue(SynCookieAckOutcome::Validated)
    ));
    assert!(
        counters.touched,
        "valid cookie ACK must be counted without counting a screen drop"
    );
    assert_eq!(counters.screen_drops, 0);
    assert_eq!(counters.syn_cookie_ack_valid, 1);
    assert!(
        event_rx.try_recv().is_err(),
        "valid cookie ACK must not emit a screen-drop event"
    );

    assert_eq!(
        screen.check_packet_with_zone_id("lan", TEST_LAN_ZONE_ID, &syn_info, TEST_NOW_SECS),
        ScreenVerdict::SynCookieBypass,
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

// #5806 (binds the "policy evaluation is unaffected" claim, and records a second
// finding). The Go-side status text and metric HELP assert that when a zone's
// screen profile reference does not resolve, "no screen checks are applied to
// this zone; policy evaluation is unaffected". Go cannot demonstrate that — the
// decision lives here — so it is bound at the stage where it is decidable.
//
// What "policy evaluation is unaffected" MEANS at this seam: the stage must
// return `StageOutcome::Continue(ScreenCheckOutcome::Pass)` — the EXACT variant,
// not merely `Continue(_)`. `Continue` alone is too weak: its sibling payload
// `ScreenCheckOutcome::SynCookieChallenge` also continues, but the caller then
// answers the packet with a challenge instead of carrying it on to policy, so
// `Continue(_)` would accept an outcome that does NOT satisfy the claim.
// `RecycleAndContinue` is the drop outcome.
//
// The second subtest records a REAL GAP found while binding this, filed as
// #6860. It is NOT a property of this change: `stage_screen_check`
// short-circuits on `!screen.has_profiles()` (poll_stages.rs), and
// `has_profiles()` is `!self.zones.is_empty()` — the RESOLVED map only. So when
// the `security screen` stanza is absent ENTIRELY, which is exactly the
// tolerant-load shape that strands a reference, the stage returns before
// `maybe_warn_missing_profile` can run and THE RATE-LIMITED RUNTIME WARN
// specifically cannot fire. Stated precisely: other reporting still exists
// (tolerant-load configuration warnings, daemon logging), so this is NOT "no
// diagnostic anywhere" — it is that the runtime dataplane WARN #5806 relies on
// is unreachable in that configuration.
//
// Asserting `warns == 0` alone would bind NOTHING: zero is also the failure
// default if the missing-profile threading were deleted outright or
// `update_missing_profiles` were a no-op. The subtest therefore ARMS the gate
// afterwards on the SAME state — adding a resolved profile for an unrelated
// zone, leaving the `lan` reference untouched — and requires the warn to
// appear. That pair distinguishes "the gate suppresses a working mechanism"
// from "there is no mechanism".
//
// #6860 has since been FIXED, and the second subtest is inverted rather than
// deleted: the gate now asks has_screen_state() (something to enforce OR
// something to report) instead of has_profiles() (something to enforce). The
// recorded gap became the assertion that it is closed, plus a negative control
// that an EMPTY state still short-circuits -- without which widening the gate to
// an unconditional true would satisfy everything else here.
//
// RED on revert: make the missing-profile None branch drop instead of pass and
// the first subtest fails; revert the gate to has_profiles() and the #6860
// subtest fails; widen has_screen_state() to always-true and the negative
// control fails.
#[test]
fn unresolved_screen_profile_zone_continues_to_policy_5806() {
    let forwarding = build_forwarding_state(&super::super::test_fixtures::nat_snapshot());
    let ident = BindingIdentity {
        slot: 0,
        queue_id: 0,
        worker_id: 0,
        interface: Arc::<str>::from("reth1.0"),
        ifindex: 24,
    };
    let binding_lookup = WorkerBindingLookup::default();
    let mirror_targets = MirrorTargetMap::default();
    let ha_state = BTreeMap::new();
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::default());
    let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
    let ike_exchanges = Arc::new(crate::afxdp::forwarding::IkeExchangeTable::new());
    let local_tunnel_deliveries = Arc::new(ArcSwap::from_pointee(BTreeMap::new()));
    let recent_exceptions = Arc::new(Mutex::new(ExceptionEventRing::new()));
    let last_resolution = Arc::new(Mutex::new(None));
    let peer_worker_commands = Vec::new();
    let dnat_fds = DnatTableFds::default();
    let rg_epochs = std::array::from_fn(|_| AtomicU32::new(0));
    let (event_handle, _event_rx) = crate::event_stream::test_worker_handle(
        8,
        DataplaneEventRateLimitConfig {
            events_per_second: 0,
            burst: 0,
        },
    );
    let worker_ctx = WorkerContext {
        ident: &ident,
        binding_lookup: &binding_lookup,
        forwarding: &forwarding,
        mirror_targets: &mirror_targets,
        ha_state: &ha_state,
        dynamic_neighbors: &dynamic_neighbors,
        shared_sessions: &shared_sessions,
        shared_nat_sessions: &shared_nat_sessions,
        shared_forward_wire_sessions: &shared_forward_wire_sessions,
        shared_owner_rg_indexes: &shared_owner_rg_indexes,
        ike_exchanges: &ike_exchanges,
        local_tunnel_deliveries: &local_tunnel_deliveries,
        neighbor_resolver: None,
        slow_path: None,
        event_stream: Some(&event_handle),
        recent_exceptions: &recent_exceptions,
        last_resolution: &last_resolution,
        peer_worker_commands: &peer_worker_commands,
        dnat_fds: &dnat_fds,
        rg_epochs: &rg_epochs,
        cold_path_sample_mask: 0xff,
    };

    let run = |screen: &mut ScreenState| -> (bool, u64) {
        let frame = tcp_v4_syn_frame_with_l2(Vlan::None, 5);
        let meta = tcp_v4_syn_meta_with_l2(&frame, Vlan::None);
        let flow = parse_session_flow_from_bytes(&frame, meta).expect("session flow from SYN");
        let mut counters = BatchCounters::default();
        let outcome = stage_screen_check(
            Some(&flow),
            &frame,
            meta,
            None,
            TEST_NOW_NS,
            TEST_NOW_SECS,
            screen,
            &mut counters,
            &worker_ctx,
        );
        (
            matches!(outcome, StageOutcome::Continue(ScreenCheckOutcome::Pass)),
            screen.missing_profile_warn_count(),
        )
    };

    // A zone whose profile reference does not resolve, with the screen stage
    // actually running: the packet CONTINUES. It is not dropped and the
    // descriptor is not consumed, so the poll loop goes on to evaluate zone
    // policy — which is precisely what the operator-facing wording claims.
    let mut screen = missing_plus_resolved_screen();
    let (continued, warns) = run(&mut screen);
    assert!(
        continued,
        "#5806: an unresolved screen-profile zone must CONTINUE through the screen          stage (no drop, descriptor not consumed) so policy evaluation still runs"
    );
    assert_eq!(
        warns, 1,
        "the runtime WARN must fire when the stage actually runs for the zone"
    );

    // #6860, FIXED. This subtest recorded the gap and is now inverted.
    //
    // With NO resolved profile anywhere -- the exact tolerant-load shape that
    // strands a reference -- has_profiles() is still false, and that is
    // correct: it answers "is there anything to ENFORCE?". The stage gate no
    // longer asks it. It asks has_screen_state(), which is true when there is
    // something to enforce OR something to REPORT, so the rate-limited runtime
    // WARN now fires in the one configuration it was written for.
    let mut only_missing = missing_only_screen();
    assert!(
        !only_missing.has_profiles(),
        "has_profiles() counts RESOLVED profiles only — an unresolved reference \
         alone must not claim there is something to enforce"
    );
    assert!(
        only_missing.has_screen_state(),
        "#6860: an unresolved reference IS screen state — there is something to \
         report, which is what the stage gate must now ask about"
    );
    let (continued, warns) = run(&mut only_missing);
    assert!(
        continued,
        "the unresolved-reference path must still continue to policy: #6860 makes \
         the stage RUN, and running it must not start dropping packets a zone \
         with no enforceable profile should carry"
    );
    assert_eq!(
        warns, 1,
        "#6860: with every screen definition absent, the runtime WARN must fire. \
         A zone the operator believes is screened and which screens NOTHING is \
         exactly the state this warning exists for, and it is reachable only \
         through the tolerant paths — strict commit rejects a dangling reference"
    );

    // The gate is the DIFFERENCE, not the mechanism. Arming has_profiles() on
    // the SAME state -- adding a resolved profile for an UNRELATED zone, `lan`
    // untouched -- must still warn exactly once. Before #6860 this pair
    // distinguished "the gate suppresses a working mechanism" from "there is no
    // mechanism"; it now guards the other direction, that widening the gate did
    // not double-count.
    let mut armed = FxHashMap::default();
    armed.insert(
        "other".to_string(),
        ScreenProfile {
            source_route: true,
            ..ScreenProfile::default()
        },
    );
    only_missing.update_profiles(armed);
    assert!(
        only_missing.has_profiles(),
        "adding a resolved profile must arm has_profiles()"
    );
    let (_, warns_armed) = run(&mut only_missing);
    assert_eq!(
        warns_armed, 1,
        "the SAME unresolved `lan` reference must warn exactly once with the \
         resolved profile present too — one warn per packet, not one per gate"
    );

    // NEGATIVE CONTROL for the widened gate. An EMPTY state -- nothing resolved,
    // nothing missing -- must still short-circuit. Without this, widening the
    // gate to `true` unconditionally would satisfy every assertion above while
    // running the screen stage for every packet on a box with no screen
    // configuration at all.
    let mut empty = ScreenState::new();
    assert!(
        !empty.has_screen_state(),
        "#6860: an empty screen state must NOT arm the stage — the widened gate \
         must still be false when there is nothing to enforce and nothing to report"
    );
    let (continued_empty, warns_empty) = run(&mut empty);
    assert!(continued_empty, "an empty screen state must continue to policy");
    assert_eq!(
        warns_empty, 0,
        "an empty screen state has no unresolved reference, so there is nothing \
         to warn about"
    );
}

/// #2145 regression: a priority-tagged VLAN-0 SYN
/// (`ingress_vlan_present = 1`, `ingress_vlan_id = 0`) must have its
/// IP header parsed at offset 18 by the screen + SYN-cookie stages,
/// not at the untagged offset 14. The screen carries an IPv4 header
/// with IHL = 6 holding an LSRR source-route option, so the
/// `ip-source-route` check fires *iff* the stage reads the IP header
/// (and decodes the option) from the real header at offset 18.
/// Pre-fix (`ingress_vlan_id > 0`) the stage used offset 14, read the
/// 802.1Q TPID byte (0x81) as the IP header → `ip_ihl = 1`,
/// source-route did NOT fire, and the SYN passed. An untagged
/// control frame (with the same IHL-6 header at offset 14) keeps
/// dropping, proving the assertion is not tautological.
///
/// KEEP THIS DOC ADJACENT TO ITS `fn`. #6839 round 2: the #5806 test was
/// inserted between this block and this declaration. Plain `//` comments are
/// whitespace to the parser, so the `///` block kept attaching to whatever item
/// came next — it documented `unresolved_screen_profile_zone_continues_to_policy_5806`
/// as the #2145 VLAN-0 regression and left this test undocumented. The same
/// class was already caught and fixed once in this file during the previous
/// round; it recurs because inserting above a declaration is the natural place
/// to add code and nothing in the build can see the transfer.
#[test]
fn priority_tagged_vlan0_screen_stage_parses_l3_at_offset_18() {
    let forwarding = build_forwarding_state(&super::super::test_fixtures::nat_snapshot());
    let ident = BindingIdentity {
        slot: 0,
        queue_id: 0,
        worker_id: 0,
        interface: Arc::<str>::from("reth1.0"),
        ifindex: 24,
    };
    let binding_lookup = WorkerBindingLookup::default();
    let mirror_targets = MirrorTargetMap::default();
    let ha_state = BTreeMap::new();
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::default());
    let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
    let ike_exchanges = Arc::new(crate::afxdp::forwarding::IkeExchangeTable::new());
    let local_tunnel_deliveries = Arc::new(ArcSwap::from_pointee(BTreeMap::new()));
    let recent_exceptions = Arc::new(Mutex::new(ExceptionEventRing::new()));
    let last_resolution = Arc::new(Mutex::new(None));
    let peer_worker_commands = Vec::new();
    let dnat_fds = DnatTableFds::default();
    let rg_epochs = std::array::from_fn(|_| AtomicU32::new(0));
    let (event_handle, _event_rx) = crate::event_stream::test_worker_handle(
        8,
        DataplaneEventRateLimitConfig {
            events_per_second: 0,
            burst: 0,
        },
    );
    let worker_ctx = WorkerContext {
        ident: &ident,
        binding_lookup: &binding_lookup,
        mirror_targets: &mirror_targets,
        forwarding: &forwarding,
        ha_state: &ha_state,
        dynamic_neighbors: &dynamic_neighbors,
        neighbor_resolver: None,
        shared_sessions: &shared_sessions,
        shared_nat_sessions: &shared_nat_sessions,
        shared_forward_wire_sessions: &shared_forward_wire_sessions,
        shared_owner_rg_indexes: &shared_owner_rg_indexes,
        ike_exchanges: &ike_exchanges,
        slow_path: None,
        event_stream: Some(&event_handle),
        local_tunnel_deliveries: &local_tunnel_deliveries,
        recent_exceptions: &recent_exceptions,
        last_resolution: &last_resolution,
        peer_worker_commands: &peer_worker_commands,
        dnat_fds: &dnat_fds,
        rg_epochs: &rg_epochs,
        cold_path_sample_mask: 0xff,
    };

    // Run one SYN through stage_screen_check and return the verdict
    // (true = dropped) plus the screen_drops delta.
    let run_screen = |vlan: Vlan| -> bool {
        let mut screen = source_route_screen();
        let frame = tcp_v4_syn_frame_with_l2(vlan, 6);
        let meta = tcp_v4_syn_meta_with_l2(&frame, vlan);
        let flow =
            parse_session_flow_from_bytes(&frame, meta).expect("session flow from tagged SYN");
        let mut counters = BatchCounters::default();
        let outcome = stage_screen_check(
            Some(&flow),
            &frame,
            meta,
            None,
            TEST_NOW_NS,
            TEST_NOW_SECS,
            &mut screen,
            &mut counters,
            &worker_ctx,
        );
        matches!(outcome, StageOutcome::RecycleAndContinue)
    };

    // Priority-tagged VID-0 frame: real IP header (IHL 6) sits at
    // offset 18. Post-fix the stage reads it and source-route fires.
    assert!(
        run_screen(Vlan::PriorityTagged),
        "priority-tagged VLAN-0 SYN with IHL=6 must be parsed at \
         offset 18 and dropped by ip-source-route (#2145)"
    );
    // Untagged control: same IHL-6 header at offset 14, still dropped.
    assert!(
        run_screen(Vlan::None),
        "untagged SYN with IHL=6 must still be parsed at offset 14 \
         and dropped by ip-source-route"
    );

    // The same offset bug lives in the SYN-cookie ACK stage. The
    // returning cookie ACK's TCP acknowledgement number is read
    // from the frame at l3_off + ihl*4 + 8; if l3_off is wrong, the
    // cookie ack is read from the wrong bytes and validation fails.
    // Drive a real challenge/validate cycle with priority-tagged
    // VID-0 frames (IHL 5, so the TCP ack sits at offset 18+20+8 =
    // 46). Post-fix the stage reads the correct cookie+1 and
    // returns Validated; pre-fix it read offset 14, parsed garbage,
    // and returned Invalid → RecycleAndContinue.
    let mut cookie_screen = syn_cookie_screen();
    let syn_frame = tcp_v4_syn_frame_with_l2(Vlan::PriorityTagged, 5);
    let syn_meta = tcp_v4_syn_meta_with_l2(&syn_frame, Vlan::PriorityTagged);
    let syn_flow = parse_session_flow_from_bytes(&syn_frame, syn_meta)
        .expect("session flow from tagged SYN");
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
    )
    .expect("valid SYN frame parses");
    // First SYN passes; second crosses the flood threshold and
    // mints the cookie challenge (mirrors the SYN-cookie test).
    assert_eq!(
        cookie_screen.check_packet_with_zone_id(
            "lan",
            TEST_LAN_ZONE_ID,
            &syn_info,
            TEST_NOW_SECS
        ),
        ScreenVerdict::Pass
    );
    let challenge = match cookie_screen.check_packet_with_zone_id(
        "lan",
        TEST_LAN_ZONE_ID,
        &syn_info,
        TEST_NOW_SECS,
    ) {
        ScreenVerdict::SynCookieChallenge(challenge) => challenge,
        other => panic!("expected SYN-cookie challenge, got {other:?}"),
    };

    // Returning ACK: priority-tagged VID-0, ack = cookie + 1, with
    // the TCP ack field written at the correct offset-18 layout.
    let ack_frame = {
        let mut f = tcp_v4_syn_frame_with_l2(Vlan::PriorityTagged, 5);
        // l3=18, ihl=20 → TCP at 38, flags byte at 38+13=51, ack
        // field at 38+8=46.
        f[51] = TCP_FLAG_ACK;
        f[46..50].copy_from_slice(&challenge.cookie_isn.wrapping_add(1).to_be_bytes());
        recompute_l4_checksum_ipv4(&mut f[18..], 20, PROTO_TCP, false).expect("tcp checksum");
        f
    };
    let ack_meta = tcp_v4_syn_meta_with_l2(&ack_frame, Vlan::PriorityTagged);
    // The shim contract reports the real protocol/flags; flip the
    // meta's TCP flag to ACK so the stage routes this as a returning
    // ACK (the meta tcp_flags field is set by the parser, not read
    // from the frame's l3 offset).
    let ack_meta = UserspaceDpMeta {
        tcp_flags: TCP_FLAG_ACK,
        ..ack_meta
    };
    let ack_flow = parse_session_flow_from_bytes(&ack_frame, ack_meta)
        .expect("session flow from tagged ACK");
    let mut counters = BatchCounters::default();
    assert!(
        matches!(
            stage_screen_syn_cookie_ack_on_session_miss(
                Some(&ack_flow),
                &ack_frame,
                ack_meta,
                None,
                TEST_NOW_NS,
                TEST_NOW_SECS,
                &mut cookie_screen,
                &mut counters,
                &worker_ctx,
            ),
            StageOutcome::Continue(SynCookieAckOutcome::Validated)
        ),
        "priority-tagged VLAN-0 cookie ACK must be parsed at offset \
         18 by the SYN-cookie stage so its TCP ack matches cookie+1 \
         (#2145); pre-fix it read offset 14 and rejected the cookie"
    );
    assert_eq!(
        counters.syn_cookie_ack_valid, 1,
        "the tagged cookie ACK must validate exactly once"
    );
}

// ===================================================================
// #2370 — learned dynamic neighbors must be keyed by the LOGICAL
// (L3 / VLAN sub-interface) ifindex the forwarder looks them up by,
// not the physical/parent ingress ifindex they arrived on.
// ===================================================================

/// Build a `WorkerContext` over the supplied forwarding state and a
/// fresh empty dynamic-neighbor map, returning the map so the test
/// can assert the key the stage inserted under.
///
/// The boxed values are intentionally `Box::leak`'d to obtain the
/// `&'static` borrows the `WorkerContext<'a>` shape requires, instead
/// of threading a dozen owned locals through every call site. The
/// leak is NOT one-shot: a single test binary runs many tests in one
/// process, so each `neighbor_learn_ctx` call adds a small, bounded
/// allocation that persists for the test-binary lifetime. This is
/// test-only and the per-call footprint is tiny (a handful of empty
/// maps + the context struct), so the accumulation is harmless.
fn neighbor_learn_ctx(
    forwarding: &'static ForwardingState,
) -> (&'static WorkerContext<'static>, Arc<ShardedNeighborMap>) {
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::default());
    let ident = Box::leak(Box::new(BindingIdentity {
        slot: 0,
        queue_id: 0,
        worker_id: 0,
        interface: Arc::<str>::from("ge-0-0-0"),
        ifindex: 11,
    }));
    let binding_lookup = Box::leak(Box::new(WorkerBindingLookup::default()));
    let mirror_targets = Box::leak(Box::new(MirrorTargetMap::default()));
    let ha_state = Box::leak(Box::new(BTreeMap::new()));
    let dynamic_neighbors_ref =
        Box::leak(Box::new(dynamic_neighbors.clone())) as &'static Arc<_>;
    let shared_sessions = Box::leak(Box::new(Arc::new(Mutex::new(FastMap::default()))));
    let shared_nat_sessions = Box::leak(Box::new(Arc::new(Mutex::new(FastMap::default()))));
    let shared_forward_wire_sessions =
        Box::leak(Box::new(Arc::new(Mutex::new(FastMap::default()))));
    let shared_owner_rg_indexes = Box::leak(Box::new(SharedSessionOwnerRgIndexes::default()));
    let ike_exchanges = Box::leak(Box::new(Arc::new(
        crate::afxdp::forwarding::IkeExchangeTable::new(),
    )));
    let local_tunnel_deliveries =
        Box::leak(Box::new(Arc::new(ArcSwap::from_pointee(BTreeMap::new()))));
    let recent_exceptions = Box::leak(Box::new(Arc::new(Mutex::new(ExceptionEventRing::new()))));
    let last_resolution = Box::leak(Box::new(Arc::new(Mutex::new(None))));
    let peer_worker_commands = Box::leak(Box::new(Vec::new()));
    let dnat_fds = Box::leak(Box::new(DnatTableFds::default()));
    let rg_epochs = Box::leak(Box::new(std::array::from_fn(|_| AtomicU32::new(0))));
    let ctx = Box::leak(Box::new(WorkerContext {
        ident,
        binding_lookup,
        mirror_targets,
        forwarding,
        ha_state,
        dynamic_neighbors: dynamic_neighbors_ref,
        neighbor_resolver: None,
        shared_sessions,
        shared_nat_sessions,
        shared_forward_wire_sessions,
        shared_owner_rg_indexes,
        ike_exchanges,
        slow_path: None,
        event_stream: None,
        local_tunnel_deliveries,
        recent_exceptions,
        last_resolution,
        peer_worker_commands,
        dnat_fds,
        rg_epochs,
        cold_path_sample_mask: 0xff,
    }));
    (ctx, dynamic_neighbors)
}

/// ARP reply frame (untagged) with a configurable sender IP. The
/// stage classifies it as `Reply` and learns `(learn_ifindex,
/// sender_ip) -> sender_mac`.
fn arp_reply_frame(sender_ip: Ipv4Addr, sender_mac: [u8; 6]) -> Vec<u8> {
    let mut f = Vec::new();
    f.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]); // dst
    f.extend_from_slice(&sender_mac); // src
    f.extend_from_slice(&[0x08, 0x06]); // ethertype ARP
    // htype=1, ptype=0x0800, hlen=6, plen=4, op=2 (reply)
    f.extend_from_slice(&[0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x02]);
    f.extend_from_slice(&sender_mac); // sender mac
    f.extend_from_slice(&sender_ip.octets()); // sender ip
    f.extend_from_slice(&[0x00; 6]); // target mac
    f.extend_from_slice(&[10, 0, 0, 1]); // target ip
    f
}

/// Meta for a frame arriving on physical ifindex `parent` with the
/// given `vlan` (0 = untagged). Only the fields the link-layer stage
/// reads (`ingress_ifindex`, `ingress_vlan_id`) matter here.
fn link_layer_meta(parent: u32, vlan: u16) -> UserspaceDpMeta {
    UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        ingress_ifindex: parent,
        ingress_vlan_id: vlan,
        ingress_vlan_present: (vlan != 0) as u8,
        l3_offset: 14,
        ..UserspaceDpMeta::default()
    }
}

/// #2370 fail-on-revert (ARP, VLAN sub-interface). The `nat_snapshot`
/// fixture defines `reth0.80` as logical ifindex 12 on parent
/// ifindex 11 / VLAN 80. An ARP reply arriving on (parent=11,
/// vlan=80) MUST be learned under the LOGICAL ifindex 12 — the key
/// the forwarder's connected-route lookup uses — NOT the physical
/// ifindex 11. If the insert reverts to `meta.ingress_ifindex` the
/// entry lands under (11, ip), `lookup_neighbor_entry` (which probes
/// the logical ifindex 12) misses, and these asserts fail.
#[test]
fn arp_learns_vlan_neighbor_under_logical_ifindex_2370() {
    let forwarding: &'static ForwardingState = Box::leak(Box::new(build_forwarding_state(
        &super::super::test_fixtures::nat_snapshot(),
    )));
    let (ctx, neighbors) = neighbor_learn_ctx(forwarding);

    let sender_ip = Ipv4Addr::new(172, 16, 80, 9);
    let sender_mac = [0xde, 0xad, 0xbe, 0xef, 0x00, 0x09];
    let frame = arp_reply_frame(sender_ip, sender_mac);
    let meta = link_layer_meta(11, 80);

    // Sanity: the fixture really maps (parent=11, vlan=80) -> 12.
    assert_eq!(
        resolve_ingress_logical_ifindex(forwarding, 11, 80),
        Some(12),
        "fixture must map parent ifindex 11 / VLAN 80 to logical 12"
    );

    let outcome = classify(&frame, meta, ctx);
    assert!(matches!(outcome, StageOutcome::RecycleAndContinue));

    // The forwarder looks up by the logical (route egress) ifindex.
    let found = lookup_neighbor_entry(
        forwarding,
        Some(&neighbors),
        12, // logical ifindex (reth0.80)
        IpAddr::V4(sender_ip),
    );
    assert_eq!(
        found.map(|e| e.mac),
        Some(sender_mac),
        "ARP learned on a VLAN sub-interface must be found by the \
         forwarder's LOGICAL-ifindex (12) lookup (#2370); a physical \
         ifindex (11) key would miss here"
    );
    // And it must NOT have landed under the physical/parent ifindex.
    assert!(
        neighbors.get(&(11, IpAddr::V4(sender_ip))).is_none(),
        "the learned entry must not be keyed by the physical/parent \
         ifindex 11 (the bug); only the logical ifindex 12"
    );
}

/// #2370 — a non-VLAN (physical == logical) ARP neighbor still
/// learns under the interface ifindex unchanged. `reth1.0` in the
/// fixture has ifindex 24 and no parent (untagged), so
/// `resolve_ingress_logical_ifindex(24, 0)` resolves to 24 and the
/// learn key equals the lookup key.
#[test]
fn arp_learns_untagged_neighbor_under_same_ifindex_2370() {
    let forwarding: &'static ForwardingState = Box::leak(Box::new(build_forwarding_state(
        &super::super::test_fixtures::nat_snapshot(),
    )));
    let (ctx, neighbors) = neighbor_learn_ctx(forwarding);

    let sender_ip = Ipv4Addr::new(10, 0, 61, 50);
    let sender_mac = [0xde, 0xad, 0xbe, 0xef, 0x00, 0x18];
    let frame = arp_reply_frame(sender_ip, sender_mac);
    let meta = link_layer_meta(24, 0);

    let outcome = classify(&frame, meta, ctx);
    assert!(matches!(outcome, StageOutcome::RecycleAndContinue));

    let found = lookup_neighbor_entry(forwarding, Some(&neighbors), 24, IpAddr::V4(sender_ip));
    assert_eq!(
        found.map(|e| e.mac),
        Some(sender_mac),
        "untagged ARP must learn under the (logical==physical) ifindex 24"
    );
}

/// #2370 multi-VLAN no-collision. Two VLAN sub-interfaces (VID 80 and
/// VID 50) share ONE physical parent (ifindex 11) but own distinct
/// logical ifindexes (12 and 13) in different subnets. The SAME
/// neighbor IP learned on each VLAN must land under DISTINCT keys
/// (12, ip) and (13, ip) — proving the logical-ifindex key keeps
/// them apart. Keying by the shared physical ifindex would collapse
/// both into (11, ip) and the second learn would overwrite the
/// first, corrupting one VLAN's neighbor entry.
#[test]
fn arp_two_vlans_same_ip_distinct_logical_keys_2370() {
    let forwarding: &'static ForwardingState =
        Box::leak(Box::new(build_forwarding_state(&two_vlan_snapshot())));
    let (ctx, neighbors) = neighbor_learn_ctx(forwarding);

    assert_eq!(
        resolve_ingress_logical_ifindex(forwarding, 11, 80),
        Some(12),
        "parent 11 / VLAN 80 -> logical 12"
    );
    assert_eq!(
        resolve_ingress_logical_ifindex(forwarding, 11, 50),
        Some(13),
        "parent 11 / VLAN 50 -> logical 13"
    );

    let ip = Ipv4Addr::new(172, 16, 0, 99);
    let mac_v80 = [0x02, 0x00, 0x00, 0x00, 0x00, 0x80];
    let mac_v50 = [0x02, 0x00, 0x00, 0x00, 0x00, 0x50];

    // Same physical port (11), same neighbor IP, different VLANs.
    let _ =
        classify(&arp_reply_frame(ip, mac_v80), link_layer_meta(11, 80), ctx);
    let _ =
        classify(&arp_reply_frame(ip, mac_v50), link_layer_meta(11, 50), ctx);

    assert_eq!(
        neighbors.get(&(12, IpAddr::V4(ip))).map(|e| e.mac),
        Some(mac_v80),
        "VLAN-80 neighbor must be keyed by logical ifindex 12"
    );
    assert_eq!(
        neighbors.get(&(13, IpAddr::V4(ip))).map(|e| e.mac),
        Some(mac_v50),
        "VLAN-50 neighbor must be keyed by logical ifindex 13 — a \
         physical-ifindex key would collide both into (11, ip)"
    );
    assert!(
        neighbors.get(&(11, IpAddr::V4(ip))).is_none(),
        "neither learn may land under the shared physical ifindex 11"
    );
}

/// #2370 NDP variant. A valid Neighbor Advertisement (hop-limit 255,
/// code 0, valid ICMPv6 checksum, TLLA option) arriving on a VLAN
/// sub-interface must learn its target under the LOGICAL ifindex too.
/// Shares the exact `learn_ifindex` computation with the ARP path.
#[test]
fn ndp_learns_vlan_neighbor_under_logical_ifindex_2370() {
    let forwarding: &'static ForwardingState = Box::leak(Box::new(build_forwarding_state(
        &super::super::test_fixtures::nat_snapshot(),
    )));
    let (ctx, neighbors) = neighbor_learn_ctx(forwarding);

    let (frame, target_ip, target_mac) = ndp_na_frame();
    // Frame is built untagged; the meta declares VLAN 80 on parent
    // 11 (the shim conveys the VLAN out-of-band in meta, not in the
    // already-stripped L2 header for the learn-key decision).
    let meta = link_layer_meta(11, 80);

    let outcome = classify(&frame, meta, ctx);
    assert!(matches!(outcome, StageOutcome::Continue(())));

    let found = lookup_neighbor_entry(forwarding, Some(&neighbors), 12, target_ip);
    assert_eq!(
        found.map(|e| e.mac),
        Some(target_mac),
        "NDP NA learned on a VLAN sub-interface must be found by the \
         forwarder's LOGICAL-ifindex (12) lookup (#2370)"
    );
    assert!(
        neighbors.get(&(11, target_ip)).is_none(),
        "the NDP entry must not be keyed by the physical ifindex 11"
    );
}

/// #6261 outline regression. The ARP-reply and NDP-NA learn-and-program
/// tails were moved out of the inline `stage_link_layer_classify` into
/// dedicated `#[cold] #[inline(never)]` handlers
/// (`outline_arp_reply_learn_and_program` /
/// `outline_ndp_na_learn_and_program`). That is a pure codegen/layout
/// change and MUST remain behavior-preserving: driving a valid ARP reply
/// and a valid NDP NA through the stage must still learn the neighbor
/// under the LOGICAL ifindex AND preserve the ARP-recycle vs NDP-continue
/// dispositions. If the extraction ever drops the learn, mis-passes an
/// argument, or flips a disposition, these asserts fail.
#[test]
fn outlined_arp_ndp_handlers_still_learn_and_program_6261() {
    let forwarding: &'static ForwardingState = Box::leak(Box::new(build_forwarding_state(
        &super::super::test_fixtures::nat_snapshot(),
    )));
    let (ctx, neighbors) = neighbor_learn_ctx(forwarding);

    // ARP reply on VLAN 80 (parent 11 -> logical 12): the outlined ARP
    // handler must learn AND the stage must still recycle the ARP frame.
    let arp_ip = Ipv4Addr::new(172, 16, 80, 61);
    let arp_mac = [0x02, 0x00, 0x00, 0x00, 0x62, 0x61];
    let arp_outcome = classify(&arp_reply_frame(arp_ip, arp_mac), link_layer_meta(11, 80), ctx);
    assert!(
        matches!(arp_outcome, StageOutcome::RecycleAndContinue),
        "ARP frames must still recycle after outlining (#6261)"
    );
    assert_eq!(
        neighbors.get(&(12, IpAddr::V4(arp_ip))).map(|e| e.mac),
        Some(arp_mac),
        "outlined ARP handler must still learn under logical ifindex 12 (#6261)"
    );

    // NDP NA on VLAN 80: the outlined NDP handler must learn AND the
    // stage must still Continue (the NA frame transits).
    let (na_frame, na_ip, na_mac) = ndp_na_frame();
    let na_outcome = classify(&na_frame, link_layer_meta(11, 80), ctx);
    assert!(
        matches!(na_outcome, StageOutcome::Continue(())),
        "NDP NA must still Continue (transit) after outlining (#6261)"
    );
    assert_eq!(
        neighbors.get(&(12, na_ip)).map(|e| e.mac),
        Some(na_mac),
        "outlined NDP handler must still learn under logical ifindex 12 (#6261)"
    );
}

/// A `nat_snapshot`-shaped config with TWO VLAN sub-interfaces on the
/// same physical parent (ifindex 11): `reth0.80` (logical 12, VID 80)
/// and `reth0.50` (logical 13, VID 50), in different subnets.
fn two_vlan_snapshot() -> crate::ConfigSnapshot {
    let mut snap = super::super::test_fixtures::nat_snapshot();
    // Existing reth0.80 already has ifindex 12, parent 11, VID 80.
    snap.interfaces.push(crate::InterfaceSnapshot {
        name: "reth0.50".to_string(),
        zone: "wan".to_string(),
        linux_name: "ge-0-0-0.50".to_string(),
        ifindex: 13,
        parent_ifindex: 11,
        redundancy_group: 1,
        vlan_id: 50,
        hardware_addr: "02:bf:72:00:50:08".to_string(),
        addresses: vec![crate::InterfaceAddressSnapshot {
            family: "inet".to_string(),
            address: "172.16.50.8/24".to_string(),
            scope: 0,
        }],
        ..Default::default()
    });
    snap
}

/// Build a minimal but VALID untagged IPv6 Neighbor Advertisement
/// (hop-limit 255, code 0, TLLA option, correct ICMPv6 checksum) and
/// return `(frame, target_ip, target_mac)`. Mirrors the parser-test
/// builder; the checksum is stamped so the strict #2368 NA parser
/// accepts it.
fn ndp_na_frame() -> (Vec<u8>, IpAddr, [u8; 6]) {
    // Default advertised target: fe80::abcd:ef01:0:42 (a legitimate,
    // non-own unicast neighbor). #2851 tests pass an own-IP target.
    ndp_na_frame_with_target([
        0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0xab, 0xcd, 0xef, 0x01, 0x00, 0x00, 0x00, 0x42,
    ])
}

/// Same builder, but with a caller-supplied advertised target address.
/// Used by the #2851 own-IP anti-poisoning tests to advertise one of
/// the router's OWN configured IPv6 addresses.
fn ndp_na_frame_with_target(target_bytes: [u8; 16]) -> (Vec<u8>, IpAddr, [u8; 6]) {
    const NEXT_HEADER_ICMPV6: u8 = 58;
    const ICMPV6_TYPE_NA: u8 = 136;
    const NDP_OPT_TARGET_LL: u8 = 2;
    let target_mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
    let mut f = Vec::new();
    f.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]); // dst
    f.extend_from_slice(&target_mac); // src
    f.extend_from_slice(&[0x86, 0xdd]); // ethertype IPv6
    let l3_start = 14usize;
    let payload_len = 32u16; // NA(24) + TLLA(8)
    f.extend_from_slice(&[0x60, 0x00, 0x00, 0x00]);
    f.extend_from_slice(&payload_len.to_be_bytes());
    f.push(NEXT_HEADER_ICMPV6);
    f.push(255); // hop limit (required)
    // src ip fe80::abcd:ef01:0:1
    f.extend_from_slice(&[
        0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0xab, 0xcd, 0xef, 0x01, 0x00, 0x00, 0x00, 0x01,
    ]);
    // dst ip (all-ff placeholder; not validated for unicast target)
    f.extend_from_slice(&[0xff; 16]);
    let l4_start = l3_start + 40;
    f.push(ICMPV6_TYPE_NA);
    f.push(0); // code
    f.extend_from_slice(&[0x00, 0x00]); // checksum placeholder
    f.extend_from_slice(&[0; 4]); // flags
    // target (caller-supplied)
    f.extend_from_slice(&target_bytes);
    // TLLA option
    f.push(NDP_OPT_TARGET_LL);
    f.push(1);
    f.extend_from_slice(&target_mac);
    let packet_end = l3_start + 40 + payload_len as usize;
    // Shared stamper (single source of truth, also used by the #2368
    // parser tests) — the strict NA parser requires a valid checksum.
    super::super::test_fixtures::stamp_icmpv6_checksum(
        &mut f, l3_start, l4_start, packet_end,
    );
    (f, IpAddr::V6(Ipv6Addr::from(target_bytes)), target_mac)
}

/// #2790 fail-on-revert (ARP). A valid unicast on-subnet sender IS
/// learned; an ARP reply whose sender protocol address is unspecified
/// (`0.0.0.0`), the limited broadcast (`255.255.255.255`), or
/// multicast (`224.0.0.1`) is NOT learned — the frame is still
/// recycled (ARP never transits) but no neighbor write occurs.
///
/// Reverting the `neighbor_ip_is_learnable(arp.sender_ip)` gate in
/// `stage_link_layer_classify` caches the bad sender IPs, so the
/// "must NOT be present" asserts fail RED. The valid-unicast assert
/// keeps the gate from over-rejecting a legitimate neighbor.
#[test]
fn arp_invalid_sender_ip_not_learned_2790() {
    let forwarding: &'static ForwardingState = Box::leak(Box::new(build_forwarding_state(
        &super::super::test_fixtures::nat_snapshot(),
    )));
    let (ctx, neighbors) = neighbor_learn_ctx(forwarding);

    // reth1.0 is logical==physical ifindex 24 (untagged) in 10.0.61.0/24.
    let meta = link_layer_meta(24, 0);

    // 1) Valid unicast on-subnet sender — MUST be learned.
    let good_ip = Ipv4Addr::new(10, 0, 61, 50);
    let good_mac = [0xde, 0xad, 0xbe, 0xef, 0x00, 0x18];
    let outcome =
        classify(&arp_reply_frame(good_ip, good_mac), meta, ctx);
    assert!(matches!(outcome, StageOutcome::RecycleAndContinue));
    assert_eq!(
        neighbors.get(&(24, IpAddr::V4(good_ip))).map(|e| e.mac),
        Some(good_mac),
        "a valid unicast on-subnet ARP sender must be learned (#2790 \
         gate must not over-reject)"
    );

    // 2) Illegitimate senders — each recycled but NEVER cached.
    for bad_ip in [
        Ipv4Addr::new(0, 0, 0, 0),             // unspecified
        Ipv4Addr::new(255, 255, 255, 255),     // limited broadcast
        Ipv4Addr::new(224, 0, 0, 1),           // multicast
        Ipv4Addr::new(127, 0, 0, 1),           // loopback
    ] {
        let bad_mac = [0x02, 0x00, 0x00, 0x00, 0xba, 0xad];
        let outcome =
            classify(&arp_reply_frame(bad_ip, bad_mac), meta, ctx);
        // ARP is always recycled (it never transits the firewall).
        assert!(
            matches!(outcome, StageOutcome::RecycleAndContinue),
            "ARP reply with sender {bad_ip} must still be recycled"
        );
        assert!(
            neighbors.get(&(24, IpAddr::V4(bad_ip))).is_none(),
            "ARP reply claiming illegitimate sender {bad_ip} must NOT be \
             cached (#2790 cache-pollution gate)"
        );
    }
}

/// #2790 direct predicate coverage — `neighbor_ip_is_learnable`
/// accepts only legitimate unicast addresses (the contract the ARP /
/// NDP learn sites rely on).
#[test]
fn neighbor_ip_is_learnable_rejects_non_unicast_2790() {
    // Learnable unicast.
    assert!(neighbor_ip_is_learnable(IpAddr::V4(Ipv4Addr::new(10, 0, 61, 50))));
    assert!(neighbor_ip_is_learnable(IpAddr::V6(Ipv6Addr::from([
        0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0xab, 0xcd, 0xef, 0x01, 0x00, 0x00, 0x00, 0x42,
    ]))));
    // Rejected IPv4 classes.
    assert!(!neighbor_ip_is_learnable(IpAddr::V4(Ipv4Addr::UNSPECIFIED)));
    assert!(!neighbor_ip_is_learnable(IpAddr::V4(Ipv4Addr::BROADCAST)));
    assert!(!neighbor_ip_is_learnable(IpAddr::V4(Ipv4Addr::new(224, 0, 0, 1))));
    assert!(!neighbor_ip_is_learnable(IpAddr::V4(Ipv4Addr::LOCALHOST)));
    // Rejected IPv6 classes (no broadcast in v6).
    assert!(!neighbor_ip_is_learnable(IpAddr::V6(Ipv6Addr::UNSPECIFIED)));
    assert!(!neighbor_ip_is_learnable(IpAddr::V6(Ipv6Addr::LOCALHOST)));
    assert!(!neighbor_ip_is_learnable(IpAddr::V6(Ipv6Addr::new(
        0xff02, 0, 0, 0, 0, 0, 0, 1
    ))));
}

/// #2851 fail-on-revert (ARP own-IP anti-poisoning). An ARP reply
/// claiming one of the router's OWN configured interface IPs
/// (`reth1.0` = 10.0.61.1 in the `nat_snapshot` fixture) must NOT be
/// learned — neither into `dynamic_neighbors` nor (by extension) the
/// kernel ARP table. A legitimate NON-own neighbor on the same
/// interface must still learn unchanged (the own-IP gate must not
/// over-reject). The frame is still recycled (ARP never transits).
///
/// Reverting the `!worker_ctx.forwarding.owns_configured_ip(...)`
/// guard in `stage_link_layer_classify` caches `(24, 10.0.61.1) ->
/// attacker_mac`, so the "must NOT be present" assert fails RED; the
/// non-own learn assert keeps the gate honest.
#[test]
fn arp_own_ip_reply_not_learned_2851() {
    let forwarding: &'static ForwardingState = Box::leak(Box::new(build_forwarding_state(
        &super::super::test_fixtures::nat_snapshot(),
    )));
    // The router's own reth1.0 (lan zone, ifindex 24) IPv4 must be in
    // the local-delivery set — the authoritative own-IP set this gate
    // reuses. (The wan reth0.80 IP is excluded as an interface-mode
    // SNAT translated address, which is why we assert on the lan IP.)
    let own_ip = Ipv4Addr::new(10, 0, 61, 1);
    assert!(
        forwarding.owns_configured_ip(IpAddr::V4(own_ip)),
        "test precondition: reth1.0 10.0.61.1 must be a configured \
         own IP in local_v4"
    );
    let (ctx, neighbors) = neighbor_learn_ctx(forwarding);
    let meta = link_layer_meta(24, 0);

    // 1) Spoofed reply claiming the router's OWN IP — must NOT learn.
    let attacker_mac = [0x02, 0x00, 0x00, 0x00, 0xba, 0xad];
    let outcome =
        classify(&arp_reply_frame(own_ip, attacker_mac), meta, ctx);
    assert!(
        matches!(outcome, StageOutcome::RecycleAndContinue),
        "an ARP reply (even an own-IP one) is still recycled"
    );
    assert!(
        neighbors.get(&(24, IpAddr::V4(own_ip))).is_none(),
        "an ARP reply claiming the router's OWN configured IP must NOT \
         be learned (#2851 anti-poisoning gate)"
    );

    // 2) A legitimate NON-own neighbor on the same interface still
    //    learns — the own-IP gate must not over-reject.
    let good_ip = Ipv4Addr::new(10, 0, 61, 50);
    let good_mac = [0xde, 0xad, 0xbe, 0xef, 0x00, 0x18];
    let _ = classify(&arp_reply_frame(good_ip, good_mac), meta, ctx);
    assert_eq!(
        neighbors.get(&(24, IpAddr::V4(good_ip))).map(|e| e.mac),
        Some(good_mac),
        "a legitimate non-own ARP neighbor must still be learned"
    );
}

/// #2851 fail-on-revert (NDP NA own-IP anti-poisoning). A Neighbor
/// Advertisement advertising one of the router's OWN configured IPv6
/// addresses (`reth1.0` = 2001:559:8585:ef00::1) must NOT be learned.
/// A legitimate non-own NA still learns. Mirrors the ARP test above.
#[test]
fn ndp_own_ip_advert_not_learned_2851() {
    let forwarding: &'static ForwardingState = Box::leak(Box::new(build_forwarding_state(
        &super::super::test_fixtures::nat_snapshot(),
    )));
    let own_v6_bytes = [
        0x20, 0x01, 0x05, 0x59, 0x85, 0x85, 0xef, 0x00, 0, 0, 0, 0, 0, 0, 0, 0x01,
    ];
    let own_v6 = IpAddr::V6(Ipv6Addr::from(own_v6_bytes));
    assert!(
        forwarding.owns_configured_ip(own_v6),
        "test precondition: reth1.0 2001:559:8585:ef00::1 must be a \
         configured own IP in local_v6"
    );
    let (ctx, neighbors) = neighbor_learn_ctx(forwarding);
    // reth1.0 is untagged logical==physical ifindex 24; the NA learn
    // resolves to ifindex 24 too. (The own-IP gate is global, so the
    // exact learn ifindex is immaterial to the rejection.)
    let meta = link_layer_meta(24, 0);

    // 1) NA advertising the router's OWN IPv6 — must NOT learn.
    let (frame, target_ip, _mac) = ndp_na_frame_with_target(own_v6_bytes);
    assert_eq!(target_ip, own_v6, "frame target must be the own IPv6");
    let outcome = classify(&frame, meta, ctx);
    assert!(matches!(outcome, StageOutcome::Continue(())));
    assert!(
        neighbors.get(&(24, own_v6)).is_none(),
        "an NDP NA advertising the router's OWN configured IPv6 must \
         NOT be learned (#2851 anti-poisoning gate)"
    );

    // 2) A legitimate non-own NA still learns (own-IP gate must not
    //    over-reject). The default `ndp_na_frame()` advertises
    //    fe80::abcd:ef01:0:42 (non-own).
    let (good_frame, good_target, good_mac) = ndp_na_frame();
    assert!(
        !forwarding.owns_configured_ip(good_target),
        "the default NA target must be a non-own neighbor"
    );
    let _ = classify(&good_frame, meta, ctx);
    assert_eq!(
        neighbors.get(&(24, good_target)).map(|e| e.mac),
        Some(good_mac),
        "a legitimate non-own NDP NA neighbor must still be learned"
    );
}

/// Flip the RFC 4861 §4.4 Override (O) bit ON in an already-built NA
/// frame and re-stamp its ICMPv6 checksum (the strict parser rejects a
/// bad checksum). The flags byte sits at `l4_start + 4` = 58 for the
/// untagged `ndp_na_frame_with_target` layout (l3=14, l4=54).
fn set_na_override(frame: &mut [u8]) {
    frame[58] |= 0x20;
    super::super::test_fixtures::stamp_icmpv6_checksum(frame, 14, 54, 86);
}

/// #4475 fail-on-revert (NDP NA Override honoring). An NA with
/// Override=0 MUST NOT overwrite a cached neighbor entry that maps to a
/// DIFFERENT link-layer address — the unsolicited-NA next-hop hijack
/// primitive. An NA with Override=1 (a legitimate link-layer-address
/// change announcement per §7.2.6) still updates it. Reverting the
/// `!na.override_flag && existing-differing` skip in
/// `stage_link_layer_classify` lets the Override=0 NA overwrite the
/// live entry, failing the "unchanged" assert RED.
#[test]
fn ndp_na_override0_does_not_overwrite_live_differing_lla_4475() {
    let forwarding: &'static ForwardingState = Box::leak(Box::new(build_forwarding_state(
        &super::super::test_fixtures::nat_snapshot(),
    )));
    let (ctx, neighbors) = neighbor_learn_ctx(forwarding);
    let meta = link_layer_meta(24, 0);

    // Default NA target fe80::abcd:ef01:0:42 (non-own, learnable),
    // advertised LLA aa:bb:cc:dd:ee:ff.
    let (frame_ov0, target, na_mac) = ndp_na_frame();
    assert!(!forwarding.owns_configured_ip(target));

    // Pre-seed a LIVE entry with a DIFFERENT MAC (a legitimately
    // resolved gateway) — the entry a poison would try to hijack.
    let live_mac = [0x02, 0x00, 0x00, 0x00, 0x0a, 0x0a];
    assert_ne!(live_mac, na_mac);
    neighbors.insert((24, target), NeighborEntry { mac: live_mac });

    // 1) Override=0 (default) NA advertising a DIFFERENT MAC — must be
    //    refused; the live entry is left untouched. The NA frame still
    //    transits (Continue).
    let outcome = classify(&frame_ov0, meta, ctx);
    assert!(matches!(outcome, StageOutcome::Continue(())));
    assert_eq!(
        neighbors.get(&(24, target)).map(|e| e.mac),
        Some(live_mac),
        "an Override=0 NA must NOT overwrite a live entry with a \
         different LLA (#4475 next-hop hijack gate)"
    );

    // 2) Override=1 NA (legitimate §7.2.6 LLA-change announcement) —
    //    must update the binding.
    let mut frame_ov1 = frame_ov0.clone();
    set_na_override(&mut frame_ov1);
    assert!(
        parser::parse_ndp_neighbor_advert(&frame_ov1)
            .expect("override NA parses")
            .override_flag,
        "test frame must carry Override=1"
    );
    let outcome = classify(&frame_ov1, meta, ctx);
    assert!(matches!(outcome, StageOutcome::Continue(())));
    assert_eq!(
        neighbors.get(&(24, target)).map(|e| e.mac),
        Some(na_mac),
        "an Override=1 NA must update the binding (legit LLA change)"
    );
}

/// #4475 companion: the Override honor must NOT break legitimate
/// resolution. An Override=0 NA for an ABSENT neighbor (no cached
/// entry) still creates it — the anti-hijack skip only fires when a
/// live entry with a DIFFERENT LLA already exists.
#[test]
fn ndp_na_override0_first_time_learn_still_creates_4475() {
    let forwarding: &'static ForwardingState = Box::leak(Box::new(build_forwarding_state(
        &super::super::test_fixtures::nat_snapshot(),
    )));
    let (ctx, neighbors) = neighbor_learn_ctx(forwarding);
    let meta = link_layer_meta(24, 0);

    // A different non-own learnable target with no pre-seeded entry.
    let target_bytes = [
        0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0xab, 0xcd, 0xef, 0x01, 0x00, 0x00, 0x00, 0x43,
    ];
    let (frame, target, na_mac) = ndp_na_frame_with_target(target_bytes);
    assert!(!forwarding.owns_configured_ip(target));
    assert!(neighbors.get(&(24, target)).is_none());
    assert!(
        !parser::parse_ndp_neighbor_advert(&frame)
            .expect("NA parses")
            .override_flag,
        "the base frame is Override=0"
    );

    let outcome = classify(&frame, meta, ctx);
    assert!(matches!(outcome, StageOutcome::Continue(())));
    assert_eq!(
        neighbors.get(&(24, target)).map(|e| e.mac),
        Some(na_mac),
        "a first-time Override=0 NA learn must still create the entry \
         (#4475 gate must not over-reject legit resolution)"
    );
}

/// #3182 fail-on-revert (ARP own-IP anti-poison, NAT-EXCLUDED interface
/// IP). The `nat_snapshot` fixture has `reth0.80` (wan zone, logical
/// ifindex 12) with IP `172.16.80.8`. The wan zone is an interface-mode
/// SNAT `to_zone`, so `nat_translated_local_exclusions` strips
/// `172.16.80.8` from `local_v4` (it lands in `interface_nat_v4`). Under
/// #2851 the anti-poison gate read `local_v4`, so an ARP reply claiming
/// the router's OWN WAN IP was NOT rejected — it was learned + written to
/// the kernel ARP table. The #3182 gate is driven from the NAT-decoupled
/// `configured_iface_v4` set, so it is now REJECTED.
///
/// Reverting `owns_configured_ip` to the NAT-excluded `local_v4` set
/// (`self.local_v4.contains(&v4)`) makes the "must NOT be present" assert
/// fail RED (172.16.80.8 is not in `local_v4`); the non-own learn assert
/// keeps the gate honest.
#[test]
fn arp_nat_excluded_wan_ip_not_learned_3182() {
    let forwarding: &'static ForwardingState = Box::leak(Box::new(build_forwarding_state(
        &super::super::test_fixtures::nat_snapshot(),
    )));
    let wan_ip = Ipv4Addr::new(172, 16, 80, 8);
    // Precondition that distinguishes #3182 from #2851: the WAN/SNAT IP
    // is NAT-excluded from local_v4 yet IS an owned interface IP via the
    // decoupled set. (If this IP were in local_v4 the test would not
    // prove the decoupling.)
    assert!(
        !forwarding.local_v4.contains(&wan_ip),
        "test precondition: the interface-mode-SNAT WAN IP must be \
         NAT-excluded from local_v4"
    );
    assert!(
        forwarding.owns_configured_ip(IpAddr::V4(wan_ip)),
        "the WAN IP must be owned via the decoupled configured_iface_v4 set"
    );
    let (ctx, neighbors) = neighbor_learn_ctx(forwarding);
    // Arrive on (parent=11, vlan=80) → logical reth0.80 (ifindex 12).
    let meta = link_layer_meta(11, 80);

    // 1) Spoofed reply claiming the router's OWN WAN IP — must NOT learn.
    let attacker_mac = [0x02, 0x00, 0x00, 0x00, 0xba, 0xad];
    let outcome =
        classify(&arp_reply_frame(wan_ip, attacker_mac), meta, ctx);
    assert!(matches!(outcome, StageOutcome::RecycleAndContinue));
    assert!(
        neighbors.get(&(12, IpAddr::V4(wan_ip))).is_none(),
        "an ARP reply claiming the router's OWN NAT-excluded WAN IP must \
         NOT be learned (#3182)"
    );
    assert!(
        neighbors.get(&(11, IpAddr::V4(wan_ip))).is_none(),
        "and not under the physical/parent ifindex either"
    );

    // 2) A legitimate NON-own neighbor on the same VLAN still learns.
    let good_ip = Ipv4Addr::new(172, 16, 80, 9);
    let good_mac = [0xde, 0xad, 0xbe, 0xef, 0x00, 0x09];
    let _ = classify(&arp_reply_frame(good_ip, good_mac), meta, ctx);
    assert_eq!(
        neighbors.get(&(12, IpAddr::V4(good_ip))).map(|e| e.mac),
        Some(good_mac),
        "a legitimate non-own ARP neighbor on the WAN VLAN must still learn"
    );
}

/// #3182 — same NAT-excluded own-IP anti-poison, NDP NA / IPv6 side.
/// `reth0.80`'s IPv6 `2001:559:8585:80::8` is NAT-excluded from
/// `local_v6` (interface-mode SNAT to_zone), so the #2851 gate did not
/// reject an NA advertising it. The #3182 decoupled set does.
#[test]
fn ndp_nat_excluded_wan_ip_not_learned_3182() {
    let forwarding: &'static ForwardingState = Box::leak(Box::new(build_forwarding_state(
        &super::super::test_fixtures::nat_snapshot(),
    )));
    let wan_v6_bytes = [
        0x20, 0x01, 0x05, 0x59, 0x85, 0x85, 0x00, 0x80, 0, 0, 0, 0, 0, 0, 0, 0x08,
    ];
    let wan_v6 = IpAddr::V6(Ipv6Addr::from(wan_v6_bytes));
    assert!(
        !forwarding.local_v6.contains(&Ipv6Addr::from(wan_v6_bytes)),
        "test precondition: the SNAT WAN IPv6 must be NAT-excluded from \
         local_v6"
    );
    assert!(
        forwarding.owns_configured_ip(wan_v6),
        "the WAN IPv6 must be owned via the decoupled configured_iface_v6 set"
    );
    let (ctx, neighbors) = neighbor_learn_ctx(forwarding);
    let meta = link_layer_meta(11, 80);

    let (frame, target_ip, _mac) = ndp_na_frame_with_target(wan_v6_bytes);
    assert_eq!(target_ip, wan_v6, "frame target must be the own WAN IPv6");
    let outcome = classify(&frame, meta, ctx);
    assert!(matches!(outcome, StageOutcome::Continue(())));
    assert!(
        neighbors.get(&(12, wan_v6)).is_none() && neighbors.get(&(11, wan_v6)).is_none(),
        "an NDP NA advertising the router's OWN NAT-excluded WAN IPv6 must \
         NOT be learned (#3182)"
    );
}

/// #3182 fail-on-revert (RX source-MAC learn path own-IP anti-poison).
/// `learn_dynamic_neighbor` (the #1787 RX learn, reached via
/// `stage_parse_flow_and_learn`) caches `(ingress_ifindex, flow.src_ip)
/// -> src_mac` from every transit packet's source. An attacker can spoof
/// a packet whose SOURCE is one of the router's own interface IPs. The
/// #3182 guard rejects such a learn before the `learn_pair_if_changed`
/// insert; a non-own source still caches.
///
/// Removing the `if forwarding.owns_configured_ip(src_ip) { return; }`
/// guard at the top of `learn_dynamic_neighbor` makes the "own-IP must
/// NOT be present" asserts fail RED; the non-own assert keeps it honest.
#[test]
fn rx_learn_own_wan_ip_rejected_3182() {
    let forwarding = build_forwarding_state(&super::super::test_fixtures::nat_snapshot());
    let neighbors = Arc::new(ShardedNeighborMap::default());

    let wan_ip = Ipv4Addr::new(172, 16, 80, 8);
    let own_wan = IpAddr::V4(wan_ip);
    assert!(
        !forwarding.local_v4.contains(&wan_ip),
        "test precondition: the WAN IP is NAT-excluded from local_v4"
    );
    assert!(
        forwarding.owns_configured_ip(own_wan),
        "the WAN IP is owned via the decoupled set"
    );

    // 1) Spoofed transit packet sourced FROM the router's own WAN IP —
    //    must NOT be cached under either the physical (11) or logical
    //    (12) ifindex.
    let attacker_mac = [0x02, 0x00, 0x00, 0x00, 0xba, 0xad];
    crate::afxdp::neighbor_dispatch::learn_dynamic_neighbor(
        &forwarding,
        &neighbors,
        11,
        80,
        own_wan,
        attacker_mac,
    );
    assert!(
        neighbors.get(&(12, own_wan)).is_none() && neighbors.get(&(11, own_wan)).is_none(),
        "the RX learn path must reject an own-IP source (#3182)"
    );

    // 2) A non-own transit source still caches (under the logical
    //    ifindex 12, the route-egress key).
    let good = IpAddr::V4(Ipv4Addr::new(172, 16, 80, 9));
    let good_mac = [0xde, 0xad, 0xbe, 0xef, 0x00, 0x09];
    crate::afxdp::neighbor_dispatch::learn_dynamic_neighbor(
        &forwarding,
        &neighbors,
        11,
        80,
        good,
        good_mac,
    );
    assert_eq!(
        neighbors.get(&(12, good)).map(|e| e.mac),
        Some(good_mac),
        "a non-own RX-learned source must still cache (#3182 guard must \
         not over-reject)"
    );
}

/// #4889 fail-on-revert (RX source-MAC learn path illegitimate source-IP
/// CLASS anti-poison). The #1787 RX learn path (`learn_dynamic_neighbor`,
/// reached via `stage_parse_flow_and_learn`) derives the neighbor identity
/// from a LIVE transit frame's L3 source. Before #4889 it validated only
/// the Ethernet source-MAC class and the own-IP overlap (#3182) — NOT the
/// source-IP class. A packet with a unicast source MAC but a spoofed source
/// IP whose class can never name a real next-hop (loopback / multicast /
/// limited-broadcast / unspecified, v4 and v6) therefore seeded an
/// impossible `(ingress_ifindex, spoofed_ip) -> src_mac` entry into the
/// userspace `dynamic_neighbors` cache — the same poisoning the ARP-reply
/// and NDP-NA learn arms already reject via `neighbor_ip_is_learnable`
/// (#2790).
///
/// This drives each spoofed class (both address families) with a valid
/// unicast source MAC and asserts NO entry is cached under either the
/// physical (11) or resolved logical (12) ifindex, plus a legitimate
/// unicast source that IS still learned (no over-rejection regression).
///
/// Removing the `if !neighbor_ip_is_learnable(src_ip) { return; }` guard at
/// the top of `learn_dynamic_neighbor` makes every spoofed-class assert
/// fail RED (the illegitimate entry would be inserted); the legitimate-learn
/// assert keeps the guard honest against over-rejection.
#[test]
fn rx_learn_non_unicast_src_ip_rejected_4889() {
    let forwarding = build_forwarding_state(&super::super::test_fixtures::nat_snapshot());
    let neighbors = Arc::new(ShardedNeighborMap::default());

    // A syntactically valid, locally-administered UNICAST source MAC —
    // the source-MAC class gate (frame[6] & 1 == 0) accepts it, so only
    // the source-IP class gate can stop the spoofed learn.
    let unicast_mac = [0x02, 0x00, 0x00, 0x00, 0xba, 0xad];

    // Every illegitimate source-IP class the ARP/NDP paths reject, v4 + v6:
    //   loopback (127/8, ::1), multicast (224/4, ff00::/8),
    //   limited broadcast (255.255.255.255), unspecified (0.0.0.0, ::).
    let spoofed: [IpAddr; 6] = [
        IpAddr::V4(Ipv4Addr::LOCALHOST),          // 127.0.0.1
        IpAddr::V4(Ipv4Addr::new(224, 0, 0, 1)),  // multicast
        IpAddr::V4(Ipv4Addr::BROADCAST),          // 255.255.255.255
        IpAddr::V4(Ipv4Addr::UNSPECIFIED),        // 0.0.0.0
        IpAddr::V6(Ipv6Addr::LOCALHOST),          // ::1
        IpAddr::V6(Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1)), // ff02::1
    ];

    for src in spoofed {
        // Physical ingress 11 + VLAN 80 resolves the logical (route-egress)
        // ifindex 12 in this fixture — the #3182 test exercises the same
        // key pair. A rejected learn must touch NEITHER key.
        crate::afxdp::neighbor_dispatch::learn_dynamic_neighbor(
            &forwarding,
            &neighbors,
            11,
            80,
            src,
            unicast_mac,
        );
        assert!(
            neighbors.get(&(11, src)).is_none() && neighbors.get(&(12, src)).is_none(),
            "the RX learn path must reject an illegitimate source-IP class \
             ({src}) even with a unicast source MAC (#4889)"
        );
    }

    // A legitimate unicast source is still learned (caches under the
    // resolved logical ifindex 12), proving the class gate does not
    // over-reject.
    let good = IpAddr::V4(Ipv4Addr::new(172, 16, 80, 42));
    let good_mac = [0xde, 0xad, 0xbe, 0xef, 0x00, 0x2a];
    crate::afxdp::neighbor_dispatch::learn_dynamic_neighbor(
        &forwarding,
        &neighbors,
        11,
        80,
        good,
        good_mac,
    );
    assert_eq!(
        neighbors.get(&(12, good)).map(|e| e.mac),
        Some(good_mac),
        "a legitimate unicast RX-learned source must still cache (#4889 \
         guard must not over-reject)"
    );
}

// ===================================================================
// #3021 / #3022 — the ingress ZONE lookup (zone-pair policy for
// forwarding, and screen/SYN-cookie zone resolution) must key on the
// LOGICAL (VLAN sub-interface) ifindex resolved through
// `resolve_ingress_logical_ifindex`, NOT the raw physical
// `meta.ingress_ifindex`. `ifindex_to_zone_id` is keyed by the logical
// unit ifindex; the parent physical ifindex only ever maps to its
// FIRST sub-interface's zone (forwarding_build/interfaces.rs:77), so a
// parent carrying two VLAN units in DISTINCT zones would evaluate the
// wrong zone — wrong policy (#3021) and the wrong/absent screen
// profile (#3022) — for every unit but the first.
// ===================================================================

/// A snapshot with TWO VLAN sub-interfaces on the same physical parent
/// (ifindex 11) in DISTINCT zones: `reth0.80` (logical 12, VID 80,
/// zone `wan`, the parent's first sub-interface) and `reth0.50`
/// (logical 13, VID 50, zone `lan`). The parent ifindex 11 inherits
/// only the first sub-interface's zone (`wan`), so a physical-keyed
/// lookup for the VID-50 unit returns `wan` instead of its own `lan`.
fn two_vlan_distinct_zone_snapshot() -> crate::ConfigSnapshot {
    let mut snap = super::super::test_fixtures::nat_snapshot();
    // reth0.80 (logical 12, parent 11, VID 80) is already zone "wan".
    snap.interfaces.push(crate::InterfaceSnapshot {
        name: "reth0.50".to_string(),
        zone: "lan".to_string(),
        linux_name: "ge-0-0-0.50".to_string(),
        ifindex: 13,
        parent_ifindex: 11,
        redundancy_group: 1,
        vlan_id: 50,
        hardware_addr: "02:bf:72:00:50:08".to_string(),
        addresses: vec![crate::InterfaceAddressSnapshot {
            family: "inet".to_string(),
            address: "172.16.50.8/24".to_string(),
            scope: 0,
        }],
        ..Default::default()
    });
    snap
}

/// #3021 fail-on-revert. `zone_pair_ids_for_flow_with_override` derives
/// the FROM-zone from the ingress ifindex it is handed. The forwarder
/// (poll_descriptor/mod.rs) now resolves the logical ifindex first; this
/// test proves the VID-50 unit's `from_zone` is its OWN `lan`, and that
/// the pre-fix physical-keyed call would return the parent's `wan`. If
/// the fix reverts to `meta.ingress_ifindex as i32`, the "correct"
/// branch below collapses onto the "pre-fix" value and the distinct-zone
/// assert fails RED.
#[test]
fn forwarding_zone_pair_uses_logical_ingress_ifindex_3021() {
    use crate::test_zone_ids::{TEST_LAN_ZONE_ID, TEST_WAN_ZONE_ID};
    let forwarding = build_forwarding_state(&two_vlan_distinct_zone_snapshot());

    // Fixture sanity: parent 11 / VID 50 -> logical 13 (zone lan);
    // parent 11 / VID 80 -> logical 12 (zone wan).
    assert_eq!(
        resolve_ingress_logical_ifindex(&forwarding, 11, 50),
        Some(13),
        "parent 11 / VLAN 50 must resolve to logical ifindex 13"
    );
    assert_eq!(
        forwarding.ifindex_to_zone_id.get(&13).copied(),
        Some(TEST_LAN_ZONE_ID),
        "logical ifindex 13 (reth0.50) is zone lan"
    );

    // egress is the WAN unit (logical 12) — to_zone is irrelevant here;
    // we only assert the from_zone (ingress) resolution.
    let egress_ifindex = 12;

    // Correct (#3021): classify the VID-50 ingress on the LOGICAL
    // ifindex 13 -> from_zone == lan.
    let logical = resolve_ingress_logical_ifindex(&forwarding, 11, 50).unwrap();
    let (from_correct, _) =
        zone_pair_ids_for_flow_with_override(&forwarding, logical, None, egress_ifindex);
    assert_eq!(
        from_correct, TEST_LAN_ZONE_ID,
        "the VID-50 unit must evaluate its OWN ingress zone (lan)"
    );

    // Pre-fix: classify on the raw PHYSICAL parent ifindex 11 ->
    // from_zone == wan (the parent's first-sub-interface zone). This is
    // the #3021 bug: the VID-50 unit would be policed under wan's
    // zone-pair, not lan's.
    let (from_physical, _) =
        zone_pair_ids_for_flow_with_override(&forwarding, 11, None, egress_ifindex);
    assert_eq!(
        from_physical, TEST_WAN_ZONE_ID,
        "the raw physical parent ifindex 11 wrongly resolves to wan \
         (the #3021 bug the logical-ifindex resolution fixes)"
    );
    assert_ne!(
        from_correct, from_physical,
        "logical-keyed (lan) and physical-keyed (wan) FROM-zones must \
         diverge, proving the fix changes the evaluated zone-pair"
    );
}

/// #3022 fail-on-revert (literal — drives `stage_screen_check`).
/// `source_route_screen()` arms the `ip-source-route` profile ONLY on
/// the `lan` zone. A SYN arriving on the VID-50 unit (logical 13, zone
/// `lan`, parent physical 11) with an IHL-6 IP header must be DROPPED:
/// the stage resolves the logical ifindex 13 -> zone lan -> the armed
/// profile fires. If #3022 reverts to `meta.ingress_ifindex` (physical
/// 11), the lookup returns the parent's first-sub-interface zone `wan`,
/// which has NO profile, the stage returns `Pass`, and the drop assert
/// fails RED. The untagged control (logical == physical) still drops,
/// keeping the assertion non-tautological / preserving non-VLAN behavior.
#[test]
fn screen_zone_lookup_uses_logical_ingress_ifindex_3022() {
    let forwarding = build_forwarding_state(&two_vlan_distinct_zone_snapshot());
    let ident = BindingIdentity {
        slot: 0,
        queue_id: 0,
        worker_id: 0,
        interface: Arc::<str>::from("ge-0-0-0"),
        ifindex: 11,
    };
    let binding_lookup = WorkerBindingLookup::default();
    let mirror_targets = MirrorTargetMap::default();
    let ha_state = BTreeMap::new();
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::default());
    let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
    let ike_exchanges = Arc::new(crate::afxdp::forwarding::IkeExchangeTable::new());
    let local_tunnel_deliveries = Arc::new(ArcSwap::from_pointee(BTreeMap::new()));
    let recent_exceptions = Arc::new(Mutex::new(ExceptionEventRing::new()));
    let last_resolution = Arc::new(Mutex::new(None));
    let peer_worker_commands = Vec::new();
    let dnat_fds = DnatTableFds::default();
    let rg_epochs = std::array::from_fn(|_| AtomicU32::new(0));
    let (event_handle, _event_rx) = crate::event_stream::test_worker_handle(
        8,
        DataplaneEventRateLimitConfig {
            events_per_second: 0,
            burst: 0,
        },
    );
    let worker_ctx = WorkerContext {
        ident: &ident,
        binding_lookup: &binding_lookup,
        mirror_targets: &mirror_targets,
        forwarding: &forwarding,
        ha_state: &ha_state,
        dynamic_neighbors: &dynamic_neighbors,
        neighbor_resolver: None,
        shared_sessions: &shared_sessions,
        shared_nat_sessions: &shared_nat_sessions,
        shared_forward_wire_sessions: &shared_forward_wire_sessions,
        shared_owner_rg_indexes: &shared_owner_rg_indexes,
        ike_exchanges: &ike_exchanges,
        slow_path: None,
        event_stream: Some(&event_handle),
        local_tunnel_deliveries: &local_tunnel_deliveries,
        recent_exceptions: &recent_exceptions,
        last_resolution: &last_resolution,
        peer_worker_commands: &peer_worker_commands,
        dnat_fds: &dnat_fds,
        rg_epochs: &rg_epochs,
        cold_path_sample_mask: 0xff,
    };

    // Source-route SYN arriving on the VID-50 unit. The shim strips the
    // VLAN tag and conveys the VID out of band in meta (present=0, l3 at
    // 14), exactly as the ARP/NDP learn tests model it.
    let frame = tcp_v4_syn_frame_with_l2(Vlan::None, 6);
    let mut meta = tcp_v4_syn_meta_with_l2(&frame, Vlan::None);
    meta.ingress_ifindex = 11; // physical parent
    meta.ingress_vlan_id = 50; // -> logical 13 (zone lan)
    let flow = parse_session_flow_from_bytes(&frame, meta)
        .expect("session flow from source-route SYN");

    let mut screen = source_route_screen();
    let mut counters = BatchCounters::default();
    let outcome = stage_screen_check(
        Some(&flow),
        &frame,
        meta,
        None,
        TEST_NOW_NS,
        TEST_NOW_SECS,
        &mut screen,
        &mut counters,
        &worker_ctx,
    );
    assert!(
        matches!(outcome, StageOutcome::RecycleAndContinue),
        "the VID-50 unit (logical 13, zone lan) must resolve its OWN \
         lan screen profile and DROP the source-route SYN (#3022); a \
         physical-keyed lookup resolves zone wan (no profile) and would \
         wrongly Pass"
    );
    assert_eq!(
        counters.screen_drops, 1,
        "exactly one screen drop must be recorded for the VID-50 unit"
    );

    // Counterfactual / non-VLAN preservation: the SAME source-route SYN
    // on the UNTAGGED reth1.0 (logical == physical == 24, zone lan) is
    // also dropped — the resolution is identity there, so the fix does
    // not change non-VLAN behavior, and the drop above is not a fluke of
    // a globally-armed profile.
    let mut frame_untagged = tcp_v4_syn_frame_with_l2(Vlan::None, 6);
    let _ = &mut frame_untagged;
    let mut meta_untagged = tcp_v4_syn_meta_with_l2(&frame_untagged, Vlan::None);
    meta_untagged.ingress_ifindex = 24;
    meta_untagged.ingress_vlan_id = 0;
    let flow_untagged = parse_session_flow_from_bytes(&frame_untagged, meta_untagged)
        .expect("session flow from untagged source-route SYN");
    let mut screen2 = source_route_screen();
    let mut counters2 = BatchCounters::default();
    let outcome_untagged = stage_screen_check(
        Some(&flow_untagged),
        &frame_untagged,
        meta_untagged,
        None,
        TEST_NOW_NS,
        TEST_NOW_SECS,
        &mut screen2,
        &mut counters2,
        &worker_ctx,
    );
    assert!(
        matches!(outcome_untagged, StageOutcome::RecycleAndContinue),
        "the untagged reth1.0 unit (logical == physical 24, zone lan) \
         still drops the source-route SYN — non-VLAN behavior unchanged"
    );
}

/// Build an untagged IPv4 fragment frame (#3064 tests). `frag_off` is
/// the raw 16-bit fragment-offset field (top 3 bits flags: 0x2000=MF;
/// low 13 bits = offset in 8-byte units). `payload_len` bytes of zeroed
/// L4/data follow the fixed 20-byte IPv4 header. IHL is 5 (no options).
fn ipv4_fragment_frame(frag_off: u16, protocol: u8, payload_len: usize) -> Vec<u8> {
    let mut frame = Vec::new();
    write_eth_header(
        &mut frame,
        [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
        [0x00, 0x25, 0x90, 0x12, 0x34, 0x56],
        0,
        0x0800,
    );
    let l3 = frame.len();
    frame.push(0x45); // IPv4, IHL 5
    frame.push(0x00); // DSCP/ECN
    let total_len = (20 + payload_len) as u16;
    frame.extend_from_slice(&total_len.to_be_bytes());
    frame.extend_from_slice(&[0x00, 0x01]); // identification
    frame.extend_from_slice(&frag_off.to_be_bytes()); // flags + frag offset
    frame.push(64); // TTL
    frame.push(protocol);
    frame.extend_from_slice(&[0x00, 0x00]); // header checksum placeholder
    frame.extend_from_slice(&Ipv4Addr::new(192, 0, 2, 10).octets());
    frame.extend_from_slice(&Ipv4Addr::new(198, 51, 100, 20).octets());
    let ip_csum = checksum16(&frame[l3..l3 + 20]);
    frame[l3 + 10..l3 + 12].copy_from_slice(&ip_csum.to_be_bytes());
    frame.resize(frame.len() + payload_len, 0x00);
    frame
}

/// Metadata for the untagged IPv4 fragment frame above: L3 at offset 14,
/// ingress on ifindex 24 (zone `lan` in `nat_snapshot`). `tcp_flags` is
/// 0 — a non-first fragment carries no L4 header.
fn ipv4_fragment_meta(frame: &[u8], protocol: u8) -> UserspaceDpMeta {
    UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        ingress_ifindex: 24,
        ingress_vlan_id: 0,
        ingress_vlan_present: 0,
        l3_offset: 14,
        l4_offset: 34,
        payload_offset: 34,
        pkt_len: frame.len() as u16,
        addr_family: libc::AF_INET as u8,
        protocol,
        tcp_flags: 0,
        ..UserspaceDpMeta::default()
    }
}

/// Screen profile (zone `lan`) arming the L3 fragment screens
/// (ping-of-death, teardrop, icmp-fragment) PLUS three flow/L4-only
/// screens (land, syn-fin, no-flag). The flow-only screens are armed
/// deliberately: on the flowless non-first-fragment path they MUST NOT
/// run. In particular `land` would drop the placeholder unspecified
/// (src == dst) tuple if the flowless path wrongly invoked the full
/// `check_packet_with_zone_id`, so a PASS on a benign fragment proves
/// the #2344 flowless fast path is preserved (no transport
/// classification, no land/flag screens).
fn fragment_screen() -> ScreenState {
    let mut profiles = FxHashMap::default();
    profiles.insert(
        "lan".to_string(),
        ScreenProfile {
            ping_death: true,
            teardrop: true,
            icmp_fragment: true,
            land: true,
            syn_fin: true,
            no_flag: true,
            ..ScreenProfile::default()
        },
    );
    let mut screen = ScreenState::new();
    screen.update_profiles(profiles);
    screen
}

/// Drive ONE packet through the live `stage_screen_check` against a
/// `nat_snapshot` forwarding state (ifindex 24 -> zone `lan`). Returns
/// `(dropped, screen_drops)`. The whole worker context is built and torn
/// down inside this helper so the #3064 cases below can be independent
/// `#[test]` functions (each observable under fail-on-revert).
fn run_stage_screen(
    screen: &mut ScreenState,
    frame: &[u8],
    meta: UserspaceDpMeta,
    flow: Option<&SessionFlow>,
) -> (bool, u64) {
    let (dropped, drops, _events) = run_stage_screen_capture(screen, frame, meta, flow);
    (dropped, drops)
}

/// #5190: same live drive as `run_stage_screen`, but also DRAINS the
/// worker event stream so a test can assert on the emitted screen-drop
/// event frame (not just the counter). Needed to bind the
/// `screen_parse_error_info_flowless` call site inside the real
/// `stage_screen_check`, not just the constructor in isolation.
fn run_stage_screen_capture(
    screen: &mut ScreenState,
    frame: &[u8],
    meta: UserspaceDpMeta,
    flow: Option<&SessionFlow>,
) -> (bool, u64, Vec<crate::event_stream::codec::DataplaneEventPayload>) {
    let forwarding = build_forwarding_state(&super::super::test_fixtures::nat_snapshot());
    let ident = BindingIdentity {
        slot: 0,
        queue_id: 0,
        worker_id: 0,
        interface: Arc::<str>::from("reth1.0"),
        ifindex: 24,
    };
    let binding_lookup = WorkerBindingLookup::default();
    let mirror_targets = MirrorTargetMap::default();
    let ha_state = BTreeMap::new();
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::default());
    let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
    let ike_exchanges = Arc::new(crate::afxdp::forwarding::IkeExchangeTable::new());
    let local_tunnel_deliveries = Arc::new(ArcSwap::from_pointee(BTreeMap::new()));
    let recent_exceptions = Arc::new(Mutex::new(ExceptionEventRing::new()));
    let last_resolution = Arc::new(Mutex::new(None));
    let peer_worker_commands = Vec::new();
    let dnat_fds = DnatTableFds::default();
    let rg_epochs = std::array::from_fn(|_| AtomicU32::new(0));
    let (event_handle, event_rx) = crate::event_stream::test_worker_handle(
        8,
        DataplaneEventRateLimitConfig {
            events_per_second: 0,
            burst: 0,
        },
    );
    let worker_ctx = WorkerContext {
        ident: &ident,
        binding_lookup: &binding_lookup,
        mirror_targets: &mirror_targets,
        forwarding: &forwarding,
        ha_state: &ha_state,
        dynamic_neighbors: &dynamic_neighbors,
        neighbor_resolver: None,
        shared_sessions: &shared_sessions,
        shared_nat_sessions: &shared_nat_sessions,
        shared_forward_wire_sessions: &shared_forward_wire_sessions,
        shared_owner_rg_indexes: &shared_owner_rg_indexes,
        ike_exchanges: &ike_exchanges,
        slow_path: None,
        event_stream: Some(&event_handle),
        local_tunnel_deliveries: &local_tunnel_deliveries,
        recent_exceptions: &recent_exceptions,
        last_resolution: &last_resolution,
        peer_worker_commands: &peer_worker_commands,
        dnat_fds: &dnat_fds,
        rg_epochs: &rg_epochs,
        cold_path_sample_mask: 0xff,
    };
    let mut counters = BatchCounters::default();
    let outcome = stage_screen_check(
        flow,
        frame,
        meta,
        None,
        TEST_NOW_NS,
        TEST_NOW_SECS,
        screen,
        &mut counters,
        &worker_ctx,
    );
    let events: Vec<crate::event_stream::codec::DataplaneEventPayload> = std::iter::from_fn(|| {
        event_rx
            .try_recv()
            .ok()
            .map(|frame| frame.decode_dataplane_event())
    })
    .flatten()
    .collect();
    (
        matches!(outcome, StageOutcome::RecycleAndContinue),
        counters.screen_drops,
        events,
    )
}

const FRAG_PROTO_UDP: u8 = 17;

/// #3064 fail-on-revert (1/4): a Teardrop non-first fragment (offset 1
/// unit = 8 bytes, MF=0, payload 4 < 8) is DROPPED by the LIVE
/// `stage_screen_check` even though it is flowless (#2344). Restoring the
/// early `Continue(Pass)` on `flow == None` turns this RED.
#[test]
fn flowless_teardrop_fragment_dropped_3064() {
    let frame = ipv4_fragment_frame(0x0001, FRAG_PROTO_UDP, 4);
    let meta = ipv4_fragment_meta(&frame, FRAG_PROTO_UDP);
    assert!(
        parse_session_flow_from_bytes(&frame, meta).is_none(),
        "a non-first fragment must be flowless (#2344) so the live \
         screen stage sees flow == None"
    );
    let mut screen = fragment_screen();
    let (dropped, drops) = run_stage_screen(&mut screen, &frame, meta, None);
    assert!(
        dropped && drops == 1,
        "teardrop non-first fragment (payload < 8) must be DROPPED by \
         the flowless screen path (#3064)"
    );
}

/// #3064 fail-on-revert (2/4): a Ping-of-Death non-first fragment whose
/// offset*8 + total length overflows the 65535 reassembly ceiling is
/// DROPPED. frag_off 0x1FFE -> offset 8190 units -> 65520 bytes;
/// total_len = 20 + 64 = 84 -> 65604 > 65535. Restoring the early
/// `Continue(Pass)` on `flow == None` turns this RED.
#[test]
fn flowless_ping_of_death_fragment_dropped_3064() {
    let frame = ipv4_fragment_frame(0x1FFE, FRAG_PROTO_UDP, 64);
    let meta = ipv4_fragment_meta(&frame, FRAG_PROTO_UDP);
    assert!(parse_session_flow_from_bytes(&frame, meta).is_none());
    let mut screen = fragment_screen();
    let (dropped, drops) = run_stage_screen(&mut screen, &frame, meta, None);
    assert!(
        dropped && drops == 1,
        "ping-of-death non-first fragment (offset*8 + total > 65535) \
         must be DROPPED by the flowless screen path (#3064)"
    );
}

/// #5190 (A1-b1-F5) fail-on-revert: the fail-closed screen drop emitted
/// from the FLOWLESS branch of the live `stage_screen_check` must carry
/// the authoritative `meta.protocol` and the real L3 addresses, not the
/// hard-coded `protocol: 0` + UNSPECIFIED placeholder that
/// `screen_parse_error_info_flowless` used to mint from `addr_family`
/// alone.
///
/// Fixture: a NON-FIRST IPv4 fragment (offset 10 units -> flowless per
/// #2344) whose IHL claims a 60-byte header while only the fixed 20
/// bytes plus 4 payload bytes were captured. `extract_screen_info`
/// therefore fails CLOSED (`TruncatedIpv4Header` -> reason
/// `ip-malformed`, #4167), while the 20 fixed bytes ARE present so
/// `flowless_l3_addrs` reads the REAL source/destination — which is
/// exactly what makes the pre-#5190 placeholder observable.
///
/// Reverting the constructor to `protocol: 0` / the UNSPECIFIED
/// addresses, or reverting the call site to stop threading `meta` and
/// the derived addresses, turns the protocol and address assertions RED.
#[test]
fn flowless_parse_error_drop_event_carries_meta_protocol_and_addrs_5190() {
    let mut frame = ipv4_fragment_frame(0x000A, FRAG_PROTO_UDP, 4);
    // IHL = 15 (60-byte header) but only 24 bytes captured past l3 ->
    // l3_offset + ihl*4 > frame.len() -> #4167 fail-closed parse error.
    frame[14] = 0x4F;
    let meta = ipv4_fragment_meta(&frame, FRAG_PROTO_UDP);
    assert!(
        parse_session_flow_from_bytes(&frame, meta).is_none(),
        "a non-first fragment must be flowless (#2344) so the live screen \
         stage takes the #3064 flowless branch"
    );
    let mut screen = fragment_screen();
    let (dropped, drops, events) = run_stage_screen_capture(&mut screen, &frame, meta, None);
    assert!(
        dropped && drops == 1,
        "an IPv4 header whose IHL runs past the captured frame must be \
         DROPPED fail-closed (#4167) on the flowless path"
    );
    let event = events
        .iter()
        .find(|e| e.kind == DataplaneEventKind::ScreenDrop)
        .expect("fail-closed flowless screen drop must emit a ScreenDrop event");
    assert_eq!(
        event.protocol, FRAG_PROTO_UDP,
        "#5190: the flowless malformed-packet screen drop must report the \
         authoritative meta.protocol, not the hard-coded 0"
    );
    assert_eq!(
        event.addr_family,
        libc::AF_INET as u8,
        "#5190: address family must survive to the event"
    );
    assert_eq!(
        event.src_ip,
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
        "#5190: the flowless screen drop must report the REAL source read \
         from the IP header, not the UNSPECIFIED placeholder"
    );
    assert_eq!(
        event.dst_ip,
        IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20)),
        "#5190: the flowless screen drop must report the REAL destination"
    );
}

/// #3064 fail-on-revert (3/4): a benign non-first fragment (offset 10
/// units = 80 bytes, 100-byte payload, UDP) PASSES — no L3 fragment
/// screen fires AND no flow/port classification happens. The flow-only
/// `land`/`syn-fin`/`no-flag` screens are armed but MUST NOT run on the
/// flowless path (if the full `check_packet` ran, `land` would drop the
/// placeholder src == dst tuple). This proves the #2344 flowless fast
/// path is preserved, and it STAYS GREEN under the early-return revert.
#[test]
fn flowless_benign_fragment_passes_and_skips_classification_3064() {
    let frame = ipv4_fragment_frame(0x000A, FRAG_PROTO_UDP, 100);
    let meta = ipv4_fragment_meta(&frame, FRAG_PROTO_UDP);
    assert!(
        parse_session_flow_from_bytes(&frame, meta).is_none(),
        "benign non-first fragment is flowless — proves the #2344 fast \
         path is intact (no port classification)"
    );
    let mut screen = fragment_screen();
    let (dropped, drops) = run_stage_screen(&mut screen, &frame, meta, None);
    assert!(
        !dropped && drops == 0,
        "benign non-first fragment must PASS — no false positive and no \
         flow/port classification (land/syn-fin/no-flag must not fire)"
    );
}

/// #3064 fail-on-revert (4/4) — regression: a non-fragmented packet
/// still takes the FLOW path and is screened by the full `check_packet`.
/// `land` (a flow-only screen) fires on src == dst; a benign packet
/// passes. This proves the flow-present path behaves exactly as before
/// the #3064 change, and it STAYS GREEN under the early-return revert.
#[test]
fn flow_path_nonfragment_still_screens_3064() {
    let land_frame = tcp_v4_frame(
        Ipv4Addr::new(203, 0, 113, 7),
        Ipv4Addr::new(203, 0, 113, 7),
        40000,
        443,
        TCP_FLAG_SYN,
        1,
        0,
    );
    let land_meta = tcp_v4_meta(&land_frame, TCP_FLAG_SYN);
    let land_flow = parse_session_flow_from_bytes(&land_frame, land_meta)
        .expect("non-fragmented TCP yields a session flow (flow path)");
    let mut screen = fragment_screen();
    let (dropped, drops) = run_stage_screen(&mut screen, &land_frame, land_meta, Some(&land_flow));
    assert!(
        dropped && drops == 1,
        "regression: a non-fragmented packet still flows through the \
         flow path and the full check_packet runs land (src == dst)"
    );

    let benign_frame = tcp_v4_frame(
        Ipv4Addr::new(203, 0, 113, 7),
        Ipv4Addr::new(203, 0, 113, 9),
        40000,
        443,
        TCP_FLAG_ACK,
        1,
        1,
    );
    let benign_meta = tcp_v4_meta(&benign_frame, TCP_FLAG_ACK);
    let benign_flow = parse_session_flow_from_bytes(&benign_frame, benign_meta)
        .expect("non-fragmented TCP yields a session flow (flow path)");
    let mut screen = fragment_screen();
    let (dropped, drops) =
        run_stage_screen(&mut screen, &benign_frame, benign_meta, Some(&benign_flow));
    assert!(
        !dropped && drops == 0,
        "regression: a benign non-fragmented packet still passes the \
         flow path with no false positive"
    );
}

/// A `fragment_screen()` profile plus the Junos profile-wide
/// `alarm-without-drop` audit modifier.
fn fragment_screen_alarm_without_drop() -> ScreenState {
    let mut profiles = FxHashMap::default();
    profiles.insert(
        "lan".to_string(),
        ScreenProfile {
            ping_death: true,
            teardrop: true,
            icmp_fragment: true,
            land: true,
            syn_fin: true,
            no_flag: true,
            alarm_without_drop: true,
            ..ScreenProfile::default()
        },
    );
    let mut screen = ScreenState::new();
    screen.update_profiles(profiles);
    screen
}

/// fable-review-164 L-10 fail-on-revert: Junos `alarm-without-drop` audit
/// mode FORWARDS a packet that would otherwise trip a screen — exercising
/// BOTH verdict consumers (the flowless L3 teardrop path AND the flow-path
/// land screen) — while still raising a log-only alarm and counting it.
/// Without the modifier the identical packets DROP (the baseline arms
/// prove the drop is real). Reverting either consumer's alarm branch turns
/// the `!dropped`/`drops == 0`/`alarm_without_drop_events == 1` asserts RED.
#[test]
fn alarm_without_drop_forwards_but_alarms_l10() {
    // (1) Flowless teardrop fragment (offset 1 unit, payload 4 < 8).
    let frag = ipv4_fragment_frame(0x0001, FRAG_PROTO_UDP, 4);
    let frag_meta = ipv4_fragment_meta(&frag, FRAG_PROTO_UDP);
    assert!(
        parse_session_flow_from_bytes(&frag, frag_meta).is_none(),
        "teardrop non-first fragment is flowless"
    );
    let mut base = fragment_screen();
    let (d0, n0) = run_stage_screen(&mut base, &frag, frag_meta, None);
    assert!(d0 && n0 == 1, "baseline: teardrop fragment must DROP");

    let mut alarm = fragment_screen_alarm_without_drop();
    let (d1, n1) = run_stage_screen(&mut alarm, &frag, frag_meta, None);
    assert!(
        !d1 && n1 == 0,
        "alarm-without-drop must FORWARD the teardrop fragment on the \
         flowless path (no drop, no screen_drop counter)"
    );
    assert_eq!(
        alarm.alarm_without_drop_events(),
        1,
        "alarm-without-drop raises exactly one log-only alarm (flowless)"
    );

    // (2) Flow-path land screen (src == dst) on a non-fragmented SYN.
    let land = tcp_v4_frame(
        Ipv4Addr::new(203, 0, 113, 7),
        Ipv4Addr::new(203, 0, 113, 7),
        40000,
        443,
        TCP_FLAG_SYN,
        1,
        0,
    );
    let land_meta = tcp_v4_meta(&land, TCP_FLAG_SYN);
    let land_flow = parse_session_flow_from_bytes(&land, land_meta)
        .expect("non-fragmented TCP yields a session flow (flow path)");
    let mut base2 = fragment_screen();
    let (d2, n2) = run_stage_screen(&mut base2, &land, land_meta, Some(&land_flow));
    assert!(d2 && n2 == 1, "baseline: land (src == dst) must DROP");

    let mut alarm2 = fragment_screen_alarm_without_drop();
    let (d3, n3) = run_stage_screen(&mut alarm2, &land, land_meta, Some(&land_flow));
    assert!(
        !d3 && n3 == 0,
        "alarm-without-drop must FORWARD the land packet on the flow path"
    );
    assert_eq!(
        alarm2.alarm_without_drop_events(),
        1,
        "alarm-without-drop raises exactly one log-only alarm (flow path)"
    );
}

/// Zone `lan` screen arming ONLY the UDP flood counter (per-zone /
/// per-destination), threshold `n`. Used to prove the #4155 fabric skip:
/// a fabric-redirected packet must NOT tick this counter on the owner.
fn udp_flood_screen(n: u32) -> ScreenState {
    let mut profiles = FxHashMap::default();
    profiles.insert(
        "lan".to_string(),
        ScreenProfile {
            udp_flood_threshold: n,
            ..ScreenProfile::default()
        },
    );
    let mut screen = ScreenState::new();
    screen.update_profiles(profiles);
    screen
}

/// #4155 fail-on-revert (integration, flood double-count): drive the LIVE
/// `stage_screen_check` with a benign flowless non-first UDP fragment on
/// zone `lan` well past a UDP flood threshold of 2, once with a
/// FABRIC-INGRESS meta (`meta_flags = FABRIC_INGRESS_FLAG`, as stage 9
/// sets for a fabric-redirected packet) and once with a DIRECT-ingress
/// meta. The fabric packet must NEVER drop (the ingress node already
/// counted it; the owner must not re-count), while the direct packet
/// crosses the threshold and drops. Reverting the
/// `skip_rate_flood`/`FABRIC_INGRESS_FLAG` gate re-counts the fabric
/// packet and turns the fabric-Pass assertion RED.
#[test]
fn fabric_ingress_skips_rate_flood_direct_still_counts_4155() {
    // frag_off field 185 (offset 1480 bytes, MF=0) → benign non-first
    // tail fragment: flowless (#2344) and trips no L3 fragment screen
    // (payload 100 ≥ 8; 1480 + 120 < 65535). Only the source-independent
    // UDP flood counter can act on it.
    const FRAG_PROTO_UDP: u8 = 17;
    let frame = ipv4_fragment_frame(0x00B9, FRAG_PROTO_UDP, 100);
    let direct_meta = ipv4_fragment_meta(&frame, FRAG_PROTO_UDP);
    assert!(
        parse_session_flow_from_bytes(&frame, direct_meta).is_none(),
        "benign non-first fragment must be flowless so the flowless \
         screen path (with the rate flood counter) runs"
    );
    let mut fabric_meta = direct_meta;
    fabric_meta.meta_flags |= FABRIC_INGRESS_FLAG;

    // Fabric-redirected: the owner must NOT tick the UDP flood counter,
    // so the packet passes on every iteration regardless of rate.
    let mut fab_screen = udp_flood_screen(2);
    for i in 0..8 {
        let (dropped, drops) = run_stage_screen(&mut fab_screen, &frame, fabric_meta, None);
        assert!(
            !dropped && drops == 0,
            "iteration {i}: a FABRIC-redirected packet was already \
             flood-screened on the ingress node; the owner must not \
             re-count it (double-count would false-trip udp-flood)"
        );
    }

    // Direct ingress on the SAME zone: the counter runs and the third
    // packet (threshold 2) drops — proving the skip is scoped to fabric
    // traffic and the flood screen still protects direct ingress at the
    // CORRECT count (not halved by a phantom fabric double-count).
    let mut direct_screen = udp_flood_screen(2);
    let (d1, c1) = run_stage_screen(&mut direct_screen, &frame, direct_meta, None);
    let (d2, c2) = run_stage_screen(&mut direct_screen, &frame, direct_meta, None);
    let (d3, c3) = run_stage_screen(&mut direct_screen, &frame, direct_meta, None);
    assert!(!d1 && c1 == 0, "1st direct packet under threshold passes");
    assert!(!d2 && c2 == 0, "2nd direct packet at threshold passes");
    assert!(
        d3 && c3 == 1,
        "3rd direct packet crosses udp-flood threshold 2 and DROPS"
    );
}

// --- #3616: Stage 11 IPsec passthrough ratified host-inbound exemption ---
//
// Stage 11 recognizes host-terminated IPsec (ESP/AH/IKE) and reinjects it
// toward the kernel XFRM stack BEFORE the per-zone host-inbound admission
// gate, so the passthrough is EXEMPT from that gate — the ratified
// userspace-dataplane semantic (#3616 Option A). The genuine parity gate
// for NEW inbound IKE lives on the PRIMARY kernel nftables path
// (`pkg/daemon/daemon_nft.go`): it gates NEW IKE on `system-services
// ike`/`ipsec`, accepts raw ESP/AH globally, and rides established/return
// IKE on `ct established,related accept`. Gating NEW IKE / inner-ESP at
// Stage 11 (this SECONDARY AF_XDP path) is deferred hardening (Option B).
//
// These pins fail-on-revert on BOTH halves of the ratified decision:
//   1. the synthetic reinject decision keeps `local_ifindex` (and the other
//      routing ifindexes) at 0 — a non-zero value diverts the reinject into
//      the GRE `local_tunnel_deliveries` channel and mis-delivers
//      IPsec-to-self (it does NOT enforce host-inbound); and
//   2. the stage intercepts every IPsec class with `RecycleAndContinue`
//      and leaves non-IPsec traffic untouched (`Continue`).
// If Option B is ever implemented these tests must be updated deliberately.

/// A firewall-LOCAL-destined IPsec flow. Since #5620, Stage 11 claims the
/// kernel-XFRM passthrough short-circuit ONLY when `flow.dst_ip` is an address
/// the firewall owns, so the exemption / host-inbound-gate assertions below —
/// which are all about LOCAL-destined IPsec — must use a firewall-local
/// destination. `10.0.61.1` / `2001:559:8585:ef00::1` is the lan interface IP
/// in both the `nat_snapshot` and `ike_gate_snapshot` fixtures (it lives in
/// `local_v*` AND `configured_iface_v*`). Remote/transit-destination cases use
/// [`ipsec_flow_to`] with a non-firewall address.
fn ipsec_flow(family: i32, protocol: u8, dst_port: u16) -> SessionFlow {
    let dst_ip = if family == libc::AF_INET6 {
        IpAddr::V6(Ipv6Addr::new(0x2001, 0x559, 0x8585, 0xef00, 0, 0, 0, 0x1))
    } else {
        IpAddr::V4(Ipv4Addr::new(10, 0, 61, 1))
    };
    ipsec_flow_to(family, protocol, dst_port, dst_ip)
}

/// As [`ipsec_flow`] but with an explicit destination — used by the #5620
/// remote/transit-destination tests (a non-firewall dst that `owns_configured_ip`
/// rejects) and the DNAT-to-self preservation test (a NAT external in `local_v*`).
fn ipsec_flow_to(family: i32, protocol: u8, dst_port: u16, dst_ip: IpAddr) -> SessionFlow {
    let src_ip = if family == libc::AF_INET6 {
        IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x10))
    } else {
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))
    };
    SessionFlow {
        src_ip,
        dst_ip,
        forward_key: SessionKey {
            addr_family: family as u8,
            protocol,
            src_ip,
            dst_ip,
            src_port: 40000,
            dst_port,
        },
    }
}

#[test]
fn ipsec_passthrough_decision_keeps_local_ifindex_zero_3616() {
    let decision = ipsec_passthrough_decision();
    assert_eq!(
        decision.resolution.disposition,
        ForwardingDisposition::LocalDelivery
    );
    // #3616: these MUST stay 0. A non-zero `local_ifindex` makes
    // `maybe_reinject_slow_path_from_frame` route the reinject through the
    // GRE `local_tunnel_deliveries` channel instead of the generic kernel
    // TUN injector (`tx/dispatch/slow_path.rs`), mis-delivering
    // IPsec-to-self. Carrying a real ingress ifindex here does NOT enforce
    // host-inbound — Stage 11 short-circuits before the gate.
    assert_eq!(decision.resolution.local_ifindex, 0);
    assert_eq!(decision.resolution.egress_ifindex, 0);
    assert_eq!(decision.resolution.tx_ifindex, 0);
    assert_eq!(decision.resolution.tunnel_endpoint_id, 0);
}

#[test]
fn stage_ipsec_passthrough_exempts_all_classes_3616() {
    // Full worker-context harness (slow_path: None — the reinject records a
    // slow-path exception, but the stage's return value is what we pin).
    let forwarding = build_forwarding_state(&super::super::test_fixtures::nat_snapshot());
    let ident = BindingIdentity {
        slot: 0,
        queue_id: 0,
        worker_id: 0,
        interface: Arc::<str>::from("reth1.0"),
        ifindex: 24,
    };
    let live = BindingLiveState::new();
    let binding_lookup = WorkerBindingLookup::default();
    let mirror_targets = MirrorTargetMap::default();
    let ha_state = BTreeMap::new();
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::default());
    let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
    let ike_exchanges = Arc::new(crate::afxdp::forwarding::IkeExchangeTable::new());
    let local_tunnel_deliveries = Arc::new(ArcSwap::from_pointee(BTreeMap::new()));
    let recent_exceptions = Arc::new(Mutex::new(ExceptionEventRing::new()));
    let last_resolution = Arc::new(Mutex::new(None));
    let peer_worker_commands = Vec::new();
    let dnat_fds = DnatTableFds::default();
    let rg_epochs = std::array::from_fn(|_| AtomicU32::new(0));
    let (event_handle, _event_rx) = crate::event_stream::test_worker_handle(
        8,
        DataplaneEventRateLimitConfig {
            events_per_second: 0,
            burst: 0,
        },
    );
    let worker_ctx = WorkerContext {
        ident: &ident,
        binding_lookup: &binding_lookup,
        mirror_targets: &mirror_targets,
        forwarding: &forwarding,
        ha_state: &ha_state,
        dynamic_neighbors: &dynamic_neighbors,
        neighbor_resolver: None,
        shared_sessions: &shared_sessions,
        shared_nat_sessions: &shared_nat_sessions,
        shared_forward_wire_sessions: &shared_forward_wire_sessions,
        shared_owner_rg_indexes: &shared_owner_rg_indexes,
        ike_exchanges: &ike_exchanges,
        slow_path: None,
        event_stream: Some(&event_handle),
        local_tunnel_deliveries: &local_tunnel_deliveries,
        recent_exceptions: &recent_exceptions,
        last_resolution: &last_resolution,
        peer_worker_commands: &peer_worker_commands,
        dnat_fds: &dnat_fds,
        rg_epochs: &rg_epochs,
        cold_path_sample_mask: 0xff,
    };

    // A benign IPv4 frame; classification keys on `meta.protocol` +
    // `flow.forward_key.dst_port`, not on the frame bytes, and the stage
    // returns `RecycleAndContinue` regardless of whether the reinject
    // succeeds — so the exact frame is immaterial to the pin.
    let frame = tcp_v4_frame(
        Ipv4Addr::new(192, 0, 2, 10),
        Ipv4Addr::new(198, 51, 100, 1),
        40000,
        500,
        TCP_FLAG_ACK,
        1,
        1,
    );

    // UNCONDITIONALLY-EXEMPT classes: raw ESP/AH are passed through
    // (reinjected) regardless of the zone host-inbound config — the
    // negotiated SA is the authorization, mirroring the kernel chain's global
    // `meta l4proto { 50, 51 } accept`. The `nat_snapshot` fixture zones
    // carry `system-services all`, but the ESP/AH exemption holds identically
    // on a zone that OMITS ike/ipsec (Stage 11 never consults the
    // host-inbound set for these classes). AH is v4-only (the shim walks the
    // IPv6 NEXTHDR_AUTH header, see README). IKE (UDP 500/4500) admission is
    // now GATED on host-inbound (#4323) and is covered separately by
    // `stage_ipsec_passthrough_gates_new_ike_4323`. (family, proto, dst).
    let exempt = [
        (libc::AF_INET, PROTO_ESP, 0u16),  // IPv4 ESP
        (libc::AF_INET, PROTO_AH, 0u16),   // IPv4 AH (v4-only)
        (libc::AF_INET6, PROTO_ESP, 0u16), // IPv6 ESP
    ];
    for (family, protocol, dst_port) in exempt {
        let flow = ipsec_flow(family, protocol, dst_port);
        let mut meta = tcp_v4_meta(&frame, TCP_FLAG_ACK);
        meta.addr_family = family as u8;
        meta.protocol = protocol;
        let outcome =
            stage_ipsec_passthrough_check(Some(&flow), &frame, meta, None, &live, &worker_ctx, TEST_NOW_NS, TEST_NOW_SECS);
        assert!(
            matches!(outcome, IpsecPassthroughOutcome::Passthrough),
            "Stage 11 must exempt raw IPsec (family {family}, proto {protocol}, \
             dst_port {dst_port}) from host-inbound and reinject it \
             (Passthrough) — ratified #3616 Option A / #4323 ESP-AH exemption"
        );
    }

    // Non-IPsec traffic is NOT intercepted — it falls through Stage 11
    // unchanged (`NotClaimed`).
    let non_ipsec = ipsec_flow(libc::AF_INET, PROTO_UDP, 443);
    let mut meta = tcp_v4_meta(&frame, TCP_FLAG_ACK);
    meta.protocol = PROTO_UDP;
    assert!(
        matches!(
            stage_ipsec_passthrough_check(
                Some(&non_ipsec),
                &frame,
                meta,
                None,
                &live,
                &worker_ctx,
                TEST_NOW_NS, TEST_NOW_SECS,
            ),
            IpsecPassthroughOutcome::NotClaimed
        ),
        "non-IPsec UDP (dst_port 443) must fall through Stage 11 unchanged"
    );

    // A flowless packet (no SessionFlow) is never claimed by Stage 11.
    let meta = tcp_v4_meta(&frame, TCP_FLAG_ACK);
    assert!(
        matches!(
            stage_ipsec_passthrough_check(None, &frame, meta, None, &live, &worker_ctx, TEST_NOW_NS, TEST_NOW_SECS),
            IpsecPassthroughOutcome::NotClaimed
        ),
        "a flowless packet is not claimed by Stage 11"
    );
}

/// #4323: build a minimal IPv4/UDP frame whose UDP payload (offset 42, after
/// a 14-byte Ethernet + 20-byte IPv4 + 8-byte UDP header) carries an ISAKMP
/// header. `natt_marker` prepends the RFC 3948 4-byte non-ESP marker (as on
/// NAT-T UDP 4500); `responder_spi_zero` controls the Responder SPI — zero
/// marks the FIRST packet of a new exchange (a NEW inbound IKE), non-zero an
/// established/reply packet. Only the byte layout at/after `l4_offset` matters
/// to `classify_ipsec_admission`; the L2/L3/UDP header bytes are filler (the
/// stage reads `meta.protocol`, not the IP header, and does not verify
/// checksums).
fn ike_v4_frame(natt_marker: bool, responder_spi_zero: bool) -> Vec<u8> {
    ike_v4_frame_spis(
        natt_marker,
        0x1122_3344_5566_7788,
        if responder_spi_zero {
            0
        } else {
            0xdead_beef_cafe_0001
        },
    )
}

/// #6471: as [`ike_v4_frame`] but with explicit Initiator/Responder SPIs — a
/// FORGED "established" packet picks arbitrary non-zero Responder bytes with
/// an Initiator SPI that matches no seeded exchange.
fn ike_v4_frame_spis(natt_marker: bool, initiator_spi: u64, responder_spi: u64) -> Vec<u8> {
    let mut frame = vec![0u8; 42];
    frame[12] = 0x08; // IPv4 ethertype (readability only)
    frame[13] = 0x00;
    frame[14] = 0x45; // IPv4 version/IHL
    frame[23] = PROTO_UDP; // IP protocol (readability only)
    if natt_marker {
        frame.extend_from_slice(&[0, 0, 0, 0]); // NAT-T non-ESP marker
    }
    // ISAKMP: Initiator SPI, Responder SPI.
    frame.extend_from_slice(&initiator_spi.to_be_bytes());
    frame.extend_from_slice(&responder_spi.to_be_bytes());
    // next-payload / version (2.0) / exchange (34 = IKE_SA_INIT) / flags.
    frame.extend_from_slice(&[0x00, 0x20, 0x22, 0x08]);
    frame.extend_from_slice(&0u32.to_be_bytes()); // message id
    frame.extend_from_slice(&0u32.to_be_bytes()); // length (filler)
    frame
}

/// #4323: an ESP-in-UDP frame on UDP 4500 — the first payload word is a
/// NON-zero ESP SPI (NOT the all-zero non-ESP marker), so it is the IPsec
/// data plane and must stay EXEMPT, never gated as IKE.
fn esp_in_udp_v4_frame() -> Vec<u8> {
    let mut frame = vec![0u8; 42];
    frame[12] = 0x08;
    frame[13] = 0x00;
    frame[14] = 0x45;
    frame[23] = PROTO_UDP;
    frame.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd]); // ESP SPI (non-zero)
    frame.extend_from_slice(&[0u8; 16]); // ESP seq + start of payload
    frame
}

fn ike_v4_meta(frame: &[u8], ingress_ifindex: u32) -> UserspaceDpMeta {
    UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        ingress_ifindex,
        l3_offset: 14,
        l4_offset: 34,
        payload_offset: 42,
        pkt_len: frame.len() as u16,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_UDP,
        ..UserspaceDpMeta::default()
    }
}

/// #4323: a snapshot with a DENY zone (`deny-zone`, ifindex 24, host-inbound
/// omits `ike`) and a PERMIT zone (`permit-zone`, ifindex 25, host-inbound
/// lists `ike`), so the Stage-11 IKE gate can be exercised on both.
fn ike_gate_snapshot() -> crate::ConfigSnapshot {
    use crate::test_zone_ids::{TEST_LAN_ZONE_ID, TEST_WAN_ZONE_ID};
    crate::ConfigSnapshot {
        zones: vec![
            crate::ZoneSnapshot {
                name: "deny-zone".to_string(),
                id: TEST_LAN_ZONE_ID,
                host_inbound_configured: true,
                // ping only — NO ike/ipsec, so a NEW inbound IKE is denied.
                host_inbound_system_services: vec!["ping".to_string()],
                ..Default::default()
            },
            crate::ZoneSnapshot {
                name: "permit-zone".to_string(),
                id: TEST_WAN_ZONE_ID,
                host_inbound_configured: true,
                host_inbound_system_services: vec!["ike".to_string()],
                ..Default::default()
            },
        ],
        interfaces: vec![
            crate::InterfaceSnapshot {
                name: "ge-0-0-1".to_string(),
                zone: "deny-zone".to_string(),
                linux_name: "ge-0-0-1".to_string(),
                ifindex: 24,
                hardware_addr: "02:bf:72:01:00:01".to_string(),
                addresses: vec![crate::InterfaceAddressSnapshot {
                    family: "inet".to_string(),
                    address: "10.0.61.1/24".to_string(),
                    scope: 0,
                }],
                ..Default::default()
            },
            crate::InterfaceSnapshot {
                name: "ge-0-0-2".to_string(),
                zone: "permit-zone".to_string(),
                linux_name: "ge-0-0-2".to_string(),
                ifindex: 25,
                hardware_addr: "02:bf:72:02:00:01".to_string(),
                addresses: vec![crate::InterfaceAddressSnapshot {
                    family: "inet".to_string(),
                    address: "172.16.80.8/24".to_string(),
                    scope: 0,
                }],
                ..Default::default()
            },
        ],
        default_policy: "deny".to_string(),
        ..Default::default()
    }
}

/// #4323 RED-on-revert: Stage 11 gates a NEW inbound IKE initiation on the
/// ingress zone's host-inbound `ike`/`ipsec` admission, while ESP/AH and the
/// IPsec data plane (ESP-in-UDP) stay exempt (unconditional passthrough).
/// #6471: an "established" (Responder-SPI-set) IKE packet is exempt ONLY with
/// a matching live-exchange seed; an unseeded one faces the same gate.
///
/// - NEW IKE (Responder SPI == 0) from a zone OMITTING ike  → `Denied`.
/// - NEW IKE from a zone LISTING ike                        → `Passthrough` + seeds.
/// - NEW NAT-T IKE (4500 + non-ESP marker) from deny zone   → `Denied`.
/// - established IKE matching the seeded exchange, deny zone → `Passthrough`.
/// - FORGED established IKE (Responder SPI set, no seed) on deny zone → `Denied`.
/// - ESP-in-UDP (4500, non-marker) from deny zone           → `Passthrough`.
/// - raw ESP from deny zone                                  → `Passthrough`.
///
/// Fail-on-revert: drop the `NewInboundIke` gate (always reinject) and the
/// `Denied` assertions flip — a NEW inbound IKE from an unpermitted source
/// would reach the local IKE daemon unfiltered.
#[test]
fn stage_ipsec_passthrough_gates_new_ike_4323() {
    const DENY_IF: u32 = 24;
    const PERMIT_IF: u32 = 25;

    let forwarding = build_forwarding_state(&ike_gate_snapshot());
    let ident = BindingIdentity {
        slot: 0,
        queue_id: 0,
        worker_id: 0,
        interface: Arc::<str>::from("ge-0-0-1"),
        ifindex: DENY_IF as i32,
    };
    let live = BindingLiveState::new();
    let binding_lookup = WorkerBindingLookup::default();
    let mirror_targets = MirrorTargetMap::default();
    let ha_state = BTreeMap::new();
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::default());
    let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
    let ike_exchanges = Arc::new(crate::afxdp::forwarding::IkeExchangeTable::new());
    let local_tunnel_deliveries = Arc::new(ArcSwap::from_pointee(BTreeMap::new()));
    let recent_exceptions = Arc::new(Mutex::new(ExceptionEventRing::new()));
    let last_resolution = Arc::new(Mutex::new(None));
    let peer_worker_commands = Vec::new();
    let dnat_fds = DnatTableFds::default();
    let rg_epochs = std::array::from_fn(|_| AtomicU32::new(0));
    let (event_handle, _event_rx) = crate::event_stream::test_worker_handle(
        8,
        DataplaneEventRateLimitConfig {
            events_per_second: 0,
            burst: 0,
        },
    );
    let worker_ctx = WorkerContext {
        ident: &ident,
        binding_lookup: &binding_lookup,
        mirror_targets: &mirror_targets,
        forwarding: &forwarding,
        ha_state: &ha_state,
        dynamic_neighbors: &dynamic_neighbors,
        neighbor_resolver: None,
        shared_sessions: &shared_sessions,
        shared_nat_sessions: &shared_nat_sessions,
        shared_forward_wire_sessions: &shared_forward_wire_sessions,
        shared_owner_rg_indexes: &shared_owner_rg_indexes,
        ike_exchanges: &ike_exchanges,
        slow_path: None,
        event_stream: Some(&event_handle),
        local_tunnel_deliveries: &local_tunnel_deliveries,
        recent_exceptions: &recent_exceptions,
        last_resolution: &last_resolution,
        peer_worker_commands: &peer_worker_commands,
        dnat_fds: &dnat_fds,
        rg_epochs: &rg_epochs,
        cold_path_sample_mask: 0xff,
    };

    // NEW inbound IKE (Responder SPI == 0) on the DENY zone → dropped.
    let new_ike = ike_v4_frame(false, true);
    let flow = ipsec_flow(libc::AF_INET, PROTO_UDP, 500);
    let outcome = stage_ipsec_passthrough_check(
        Some(&flow),
        &new_ike,
        ike_v4_meta(&new_ike, DENY_IF),
        None,
        &live,
        &worker_ctx,
        TEST_NOW_NS, TEST_NOW_SECS,
    );
    assert!(
        matches!(
            outcome,
            IpsecPassthroughOutcome::Denied {
                from_zone_id
            } if from_zone_id == TEST_LAN_ZONE_ID
        ),
        "NEW inbound IKE from a zone omitting `ike` must be Denied (silent \
         drop), not reach the IKE daemon (#4323)",
    );

    // NEW inbound IKE on the PERMIT zone → admitted (passthrough) AND the
    // exchange is SEEDED (#6471), so its established follow-ups are
    // recognized below. The `ike_v4_frame` initiator SPI is
    // 0x1122334455667788; the flow is 192.0.2.10 -> 10.0.61.1.
    let permit_flow = ipsec_flow(libc::AF_INET, PROTO_UDP, 500);
    assert!(
        matches!(
            stage_ipsec_passthrough_check(
                Some(&permit_flow),
                &new_ike,
                ike_v4_meta(&new_ike, PERMIT_IF),
                None,
                &live,
                &worker_ctx,
                TEST_NOW_NS, TEST_NOW_SECS,
            ),
            IpsecPassthroughOutcome::Passthrough
        ),
        "NEW inbound IKE from a zone listing `ike` must be admitted (Passthrough)",
    );
    assert!(
        ike_exchanges.matches(
            &crate::afxdp::forwarding::IkeExchangeKey::new(
                0x1122_3344_5566_7788,
                IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
                IpAddr::V4(Ipv4Addr::new(10, 0, 61, 1)),
            ),
            TEST_NOW_NS,
        ),
        "#6471: an ADMITTED NEW inbound IKE must seed the live-exchange table          (a denied initiation must NOT seed — asserted by the forged-SPI deny          cases in `stage_ipsec_passthrough_gates_forged_responder_spi_6471`)",
    );

    // NEW NAT-T IKE (UDP 4500 + non-ESP marker, Responder SPI == 0) on the
    // DENY zone → dropped.
    let new_natt = ike_v4_frame(true, true);
    let natt_flow = ipsec_flow(libc::AF_INET, PROTO_UDP, 4500);
    assert!(
        matches!(
            stage_ipsec_passthrough_check(
                Some(&natt_flow),
                &new_natt,
                ike_v4_meta(&new_natt, DENY_IF),
                None,
                &live,
                &worker_ctx,
                TEST_NOW_NS, TEST_NOW_SECS,
            ),
            IpsecPassthroughOutcome::Denied { .. }
        ),
        "NEW inbound NAT-T IKE (4500) from a zone omitting `ike` must be Denied",
    );

    // ESTABLISHED IKE (Responder SPI set) matching the seeded exchange on the
    // DENY zone → passthrough (#6471: the live-exchange seed is the
    // established discriminator, mirroring `ct established,related accept`;
    // return/reply IKE of a REAL exchange never drops).
    let est_ike = ike_v4_frame(false, false);
    assert!(
        matches!(
            stage_ipsec_passthrough_check(
                Some(&flow),
                &est_ike,
                ike_v4_meta(&est_ike, DENY_IF),
                None,
                &live,
                &worker_ctx,
                TEST_NOW_NS, TEST_NOW_SECS,
            ),
            IpsecPassthroughOutcome::Passthrough
        ),
        "established/reply IKE matching a seeded exchange must stay admitted \
         even on a zone omitting `ike` — established-first ordering (#6471)",
    );

    // ESP-in-UDP (UDP 4500, first word a non-zero ESP SPI, NOT a marker) on
    // the DENY zone → passthrough (IPsec data plane, exempt like raw ESP).
    let esp_udp = esp_in_udp_v4_frame();
    assert!(
        matches!(
            stage_ipsec_passthrough_check(
                Some(&natt_flow),
                &esp_udp,
                ike_v4_meta(&esp_udp, DENY_IF),
                None,
                &live,
                &worker_ctx,
                TEST_NOW_NS, TEST_NOW_SECS,
            ),
            IpsecPassthroughOutcome::Passthrough
        ),
        "ESP-in-UDP on 4500 must stay exempt (data plane), never gated as IKE",
    );

    // Raw ESP (proto 50) on the DENY zone → passthrough (SA authorizes).
    let esp_flow = ipsec_flow(libc::AF_INET, PROTO_ESP, 0);
    let mut esp_meta = ike_v4_meta(&new_ike, DENY_IF);
    esp_meta.protocol = PROTO_ESP;
    assert!(
        matches!(
            stage_ipsec_passthrough_check(
                Some(&esp_flow),
                &new_ike,
                esp_meta,
                None,
                &live,
                &worker_ctx,
                TEST_NOW_NS, TEST_NOW_SECS,
            ),
            IpsecPassthroughOutcome::Passthrough
        ),
        "raw ESP must stay unconditionally exempt on any zone (#4323)",
    );
}

/// #6471 RED-on-revert: a FORGED Responder-SPI-nonzero IKE packet to a
/// firewall-local address on the secondary path must NOT ride the
/// established exemption — without a matching live-exchange seed it faces the
/// same host-inbound `ike` gate a NEW initiation faces (denied on a zone
/// that omits `ike`), while the legitimate follow-up of a seeded exchange is
/// admitted.
///
/// - forged Responder-SPI IKE (500) on DENY zone, no seed        → `Denied`.
/// - forged NAT-T Responder-SPI IKE (4500) on DENY zone, no seed → `Denied`.
/// - forged Responder-SPI IKE on PERMIT zone, no seed            → `Passthrough`
///   (the zone admits IKE by configuration — primary-path parity: the kernel
///   chain also admits NEW IKE there).
/// - seeded exchange follow-up (matching Initiator SPI + addrs) on DENY zone
///   → `Passthrough`.
/// - seeded exchange, WRONG Initiator SPI / WRONG peer address   → `Denied`.
/// - ESP-in-UDP (non-marker 4500) on DENY zone                   → `Passthrough`
///   (data plane untouched by the discriminator).
///
/// Fail-on-revert: restore the unconditional `Exempt` for Responder-SPI-set
/// IKE and every `Denied` assertion below flips to `Passthrough` — the
/// forged packet would reach strongSwan on a zone the operator closed to IKE.
#[test]
fn stage_ipsec_passthrough_gates_forged_responder_spi_6471() {
    const DENY_IF: u32 = 24;
    const PERMIT_IF: u32 = 25;

    let forwarding = build_forwarding_state(&ike_gate_snapshot());
    let ident = BindingIdentity {
        slot: 0,
        queue_id: 0,
        worker_id: 0,
        interface: Arc::<str>::from("ge-0-0-1"),
        ifindex: DENY_IF as i32,
    };
    let live = BindingLiveState::new();
    let binding_lookup = WorkerBindingLookup::default();
    let mirror_targets = MirrorTargetMap::default();
    let ha_state = BTreeMap::new();
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::default());
    let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
    let ike_exchanges = Arc::new(crate::afxdp::forwarding::IkeExchangeTable::new());
    let local_tunnel_deliveries = Arc::new(ArcSwap::from_pointee(BTreeMap::new()));
    let recent_exceptions = Arc::new(Mutex::new(ExceptionEventRing::new()));
    let last_resolution = Arc::new(Mutex::new(None));
    let peer_worker_commands = Vec::new();
    let dnat_fds = DnatTableFds::default();
    let rg_epochs = std::array::from_fn(|_| AtomicU32::new(0));
    let (event_handle, _event_rx) = crate::event_stream::test_worker_handle(
        8,
        DataplaneEventRateLimitConfig {
            events_per_second: 0,
            burst: 0,
        },
    );
    let worker_ctx = WorkerContext {
        ident: &ident,
        binding_lookup: &binding_lookup,
        mirror_targets: &mirror_targets,
        forwarding: &forwarding,
        ha_state: &ha_state,
        dynamic_neighbors: &dynamic_neighbors,
        neighbor_resolver: None,
        shared_sessions: &shared_sessions,
        shared_nat_sessions: &shared_nat_sessions,
        shared_forward_wire_sessions: &shared_forward_wire_sessions,
        shared_owner_rg_indexes: &shared_owner_rg_indexes,
        ike_exchanges: &ike_exchanges,
        slow_path: None,
        event_stream: Some(&event_handle),
        local_tunnel_deliveries: &local_tunnel_deliveries,
        recent_exceptions: &recent_exceptions,
        last_resolution: &last_resolution,
        peer_worker_commands: &peer_worker_commands,
        dnat_fds: &dnat_fds,
        rg_epochs: &rg_epochs,
        cold_path_sample_mask: 0xff,
    };

    let flow = ipsec_flow(libc::AF_INET, PROTO_UDP, 500);
    let natt_flow = ipsec_flow(libc::AF_INET, PROTO_UDP, 4500);

    // FORGED "established" IKE (Responder SPI set, Initiator SPI matching NO
    // seed) on the DENY zone → Denied. On the pre-#6471 code this was
    // unconditionally Exempt → the fail-on-revert core.
    let forged = ike_v4_frame_spis(false, 0x0102_0304_0506_0708, 0xaabb_ccdd_eeff_0011);
    assert!(
        matches!(
            stage_ipsec_passthrough_check(
                Some(&flow),
                &forged,
                ike_v4_meta(&forged, DENY_IF),
                None,
                &live,
                &worker_ctx,
                TEST_NOW_NS, TEST_NOW_SECS,
            ),
            IpsecPassthroughOutcome::Denied { .. }
        ),
        "forged Responder-SPI IKE with no live-exchange seed must be Denied \
         on a zone omitting `ike` (#6471)",
    );

    // Same forgery over NAT-T (4500 + non-ESP marker) → Denied.
    let forged_natt = ike_v4_frame_spis(true, 0x0102_0304_0506_0708, 0xaabb_ccdd_eeff_0011);
    assert!(
        matches!(
            stage_ipsec_passthrough_check(
                Some(&natt_flow),
                &forged_natt,
                ike_v4_meta(&forged_natt, DENY_IF),
                None,
                &live,
                &worker_ctx,
                TEST_NOW_NS, TEST_NOW_SECS,
            ),
            IpsecPassthroughOutcome::Denied { .. }
        ),
        "forged NAT-T Responder-SPI IKE with no live-exchange seed must be \
         Denied on a zone omitting `ike` (#6471)",
    );

    // The same forged packet on the PERMIT zone → admitted: the zone lists
    // `ike`, so IKE to it is config-sanctioned (primary-path parity — the
    // kernel chain admits NEW IKE there too).
    assert!(
        matches!(
            stage_ipsec_passthrough_check(
                Some(&flow),
                &forged,
                ike_v4_meta(&forged, PERMIT_IF),
                None,
                &live,
                &worker_ctx,
                TEST_NOW_NS, TEST_NOW_SECS,
            ),
            IpsecPassthroughOutcome::Passthrough
        ),
        "a zone listing `ike` admits IKE regardless of the exchange seed \
         (config-sanctioned openness)",
    );

    // SEED a live exchange exactly as the firewall-initiated outbound path
    // does (`maybe_seed_local_origin_ike` in the GRE local-origin thread):
    // the peer 192.0.2.10, the firewall-local address 10.0.61.1, Initiator
    // SPI 0x5152....
    let seeded_key = crate::afxdp::forwarding::IkeExchangeKey::new(
        0x5152_5354_5556_5758,
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 61, 1)),
    );
    ike_exchanges.seed(seeded_key, TEST_NOW_NS);

    // The legitimate Responder packet of that established exchange on the
    // DENY zone → admitted (the seed — not the SPI bytes alone — vouches).
    let legit = ike_v4_frame_spis(false, 0x5152_5354_5556_5758, 0xdead_beef_cafe_0001);
    assert!(
        matches!(
            stage_ipsec_passthrough_check(
                Some(&flow),
                &legit,
                ike_v4_meta(&legit, DENY_IF),
                None,
                &live,
                &worker_ctx,
                TEST_NOW_NS, TEST_NOW_SECS,
            ),
            IpsecPassthroughOutcome::Passthrough
        ),
        "the Responder packet of a seeded live exchange must be admitted even \
         on a zone omitting `ike` (#6471 established-first parity)",
    );

    // Same packet shape but a WRONG Initiator SPI (no matching seed) → Denied.
    let wrong_spi = ike_v4_frame_spis(false, 0x6152_5354_5556_5758, 0xdead_beef_cafe_0001);
    assert!(
        matches!(
            stage_ipsec_passthrough_check(
                Some(&flow),
                &wrong_spi,
                ike_v4_meta(&wrong_spi, DENY_IF),
                None,
                &live,
                &worker_ctx,
                TEST_NOW_NS, TEST_NOW_SECS,
            ),
            IpsecPassthroughOutcome::Denied { .. }
        ),
        "a Responder-SPI packet whose Initiator SPI matches no seed must be \
         Denied on a zone omitting `ike` (#6471)",
    );

    // Same SPIs but from a DIFFERENT peer address (no matching seed) → Denied.
    let mut wrong_peer_flow = ipsec_flow(libc::AF_INET, PROTO_UDP, 500);
    wrong_peer_flow.src_ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 11));
    wrong_peer_flow.forward_key.src_ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 11));
    assert!(
        matches!(
            stage_ipsec_passthrough_check(
                Some(&wrong_peer_flow),
                &legit,
                ike_v4_meta(&legit, DENY_IF),
                None,
                &live,
                &worker_ctx,
                TEST_NOW_NS, TEST_NOW_SECS,
            ),
            IpsecPassthroughOutcome::Denied { .. }
        ),
        "a packet matching the seed's SPIs but not its address pair must be \
         Denied on a zone omitting `ike` (#6471)",
    );

    // ESP-in-UDP on 4500 (non-zero ESP SPI, no marker) → data plane, still
    // unconditionally exempt.
    let esp_udp = esp_in_udp_v4_frame();
    assert!(
        matches!(
            stage_ipsec_passthrough_check(
                Some(&natt_flow),
                &esp_udp,
                ike_v4_meta(&esp_udp, DENY_IF),
                None,
                &live,
                &worker_ctx,
                TEST_NOW_NS, TEST_NOW_SECS,
            ),
            IpsecPassthroughOutcome::Passthrough
        ),
        "ESP-in-UDP must stay exempt — the #6471 discriminator touches IKE \
         only, never the IPsec data plane",
    );
}

/// #5620 test harness: run Stage 11 against `forwarding` with a full but inert
/// (`slow_path: None`) WorkerContext and return the stage outcome. The frame /
/// meta are supplied by the caller; the ingress ifindex (24) matches the lan
/// interface in `nat_snapshot`, so the #4323 host-inbound resolve keys the lan
/// zone (which carries `system-services all`).
fn run_stage11(
    forwarding: &ForwardingState,
    flow: &SessionFlow,
    frame: &[u8],
    meta: UserspaceDpMeta,
) -> IpsecPassthroughOutcome {
    let ident = BindingIdentity {
        slot: 0,
        queue_id: 0,
        worker_id: 0,
        interface: Arc::<str>::from("reth1.0"),
        ifindex: 24,
    };
    let live = BindingLiveState::new();
    let binding_lookup = WorkerBindingLookup::default();
    let mirror_targets = MirrorTargetMap::default();
    let ha_state = BTreeMap::new();
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::default());
    let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
    let ike_exchanges = Arc::new(crate::afxdp::forwarding::IkeExchangeTable::new());
    let local_tunnel_deliveries = Arc::new(ArcSwap::from_pointee(BTreeMap::new()));
    let recent_exceptions = Arc::new(Mutex::new(ExceptionEventRing::new()));
    let last_resolution = Arc::new(Mutex::new(None));
    let peer_worker_commands = Vec::new();
    let dnat_fds = DnatTableFds::default();
    let rg_epochs = std::array::from_fn(|_| AtomicU32::new(0));
    let (event_handle, _event_rx) = crate::event_stream::test_worker_handle(
        8,
        DataplaneEventRateLimitConfig {
            events_per_second: 0,
            burst: 0,
        },
    );
    let worker_ctx = WorkerContext {
        ident: &ident,
        binding_lookup: &binding_lookup,
        mirror_targets: &mirror_targets,
        forwarding,
        ha_state: &ha_state,
        dynamic_neighbors: &dynamic_neighbors,
        neighbor_resolver: None,
        shared_sessions: &shared_sessions,
        shared_nat_sessions: &shared_nat_sessions,
        shared_forward_wire_sessions: &shared_forward_wire_sessions,
        shared_owner_rg_indexes: &shared_owner_rg_indexes,
        ike_exchanges: &ike_exchanges,
        slow_path: None,
        event_stream: Some(&event_handle),
        local_tunnel_deliveries: &local_tunnel_deliveries,
        recent_exceptions: &recent_exceptions,
        last_resolution: &last_resolution,
        peer_worker_commands: &peer_worker_commands,
        dnat_fds: &dnat_fds,
        rg_epochs: &rg_epochs,
        cold_path_sample_mask: 0xff,
    };
    stage_ipsec_passthrough_check(Some(flow), frame, meta, None, &live, &worker_ctx, TEST_NOW_NS, TEST_NOW_SECS)
}

/// #5620 RED-on-revert: Stage 11 must NOT claim the kernel-XFRM passthrough
/// short-circuit for IPsec whose destination is REMOTE (not a firewall-local
/// address). Before the fix, `is_ipsec_traffic` claimed ANY ESP/AH/IKE packet
/// regardless of destination, so a TRANSIT ESP/AH/IKE packet was reinjected to
/// the local XFRM stack and skipped transit zone-policy enforcement.
///
/// A remote-destination UDP/500, UDP/4500, IPv4 AH (proto 51), IPv4 ESP
/// (proto 50) and IPv6 ESP packet must each return `NotClaimed` so it falls
/// through to normal transit forwarding + policy.
///
/// Fail-on-revert: drop the `owns_configured_ip(flow.dst_ip)` predicate in
/// `stage_ipsec_passthrough_check` and every assertion below flips to
/// `Passthrough` — the transit-policy bypass returns.
#[test]
fn stage_ipsec_passthrough_rejects_remote_transit_dst_5620() {
    let forwarding = build_forwarding_state(&super::super::test_fixtures::nat_snapshot());

    // Frame bytes are immaterial: the #5620 predicate returns `NotClaimed`
    // before `classify_ipsec_admission` ever parses the frame. Classification
    // keys on `meta.protocol` + `flow.forward_key.dst_port` + `flow.dst_ip`.
    let frame = tcp_v4_frame(
        Ipv4Addr::new(192, 0, 2, 10),
        Ipv4Addr::new(198, 51, 100, 1),
        40000,
        500,
        TCP_FLAG_ACK,
        1,
        1,
    );
    let remote_v4 = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1));
    let remote_v6 = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x1));

    // (family, proto, dst_port, remote_dst, label)
    let cases: [(i32, u8, u16, IpAddr, &str); 5] = [
        (libc::AF_INET, PROTO_UDP, 500, remote_v4, "IKE UDP/500 v4"),
        (libc::AF_INET, PROTO_UDP, 4500, remote_v4, "NAT-T UDP/4500 v4"),
        (libc::AF_INET, PROTO_AH, 0, remote_v4, "AH proto 51 v4"),
        (libc::AF_INET, PROTO_ESP, 0, remote_v4, "ESP proto 50 v4"),
        (libc::AF_INET6, PROTO_ESP, 0, remote_v6, "ESP proto 50 v6"),
    ];
    for (family, protocol, dst_port, dst_ip, label) in cases {
        let flow = ipsec_flow_to(family, protocol, dst_port, dst_ip);
        let mut meta = tcp_v4_meta(&frame, TCP_FLAG_ACK);
        meta.addr_family = family as u8;
        meta.protocol = protocol;
        assert!(
            matches!(
                run_stage11(&forwarding, &flow, &frame, meta),
                IpsecPassthroughOutcome::NotClaimed
            ),
            "#5620: remote-destination {label} must NOT be claimed by Stage 11 \
             (NotClaimed) — it must fall through to transit zone policy, not be \
             reinjected to the local XFRM stack",
        );
    }
}

/// #5620 over-reject guard + DNAT-to-self preservation: Stage 11 MUST still
/// claim legitimate LOCAL-destined IPsec after the local-destination predicate
/// is added. This pins the CRITICAL preservation cases the fix must not break
/// (breaking VPN termination is worse than the transit bypass):
///
///   - ESP to the lan interface IP (`10.0.61.1`, in `local_v*`)          → Passthrough
///   - ESP to the WAN/SNAT interface IP (`172.16.80.8`) — EXCLUDED from
///     `local_v*` by the interface-mode-SNAT `nat_translated_local_exclusions`
///     but present in `configured_iface_v*`, so `owns_configured_ip` still
///     recognises it (the most common VPN termination address)             → Passthrough
///   - ESP to a DNAT-to-self external (`203.0.113.9`, appended to `local_v*`
///     by the DNAT rule's destination address) — proves the RAW pre-NAT dst
///     check does NOT wrongly reject NAT-to-self                            → Passthrough
///
/// A never-configured remote address (`203.0.113.200`) is the control: it is
/// in neither set → `NotClaimed`, proving the DNAT append (not a blanket
/// accept) is what claims `203.0.113.9`.
///
/// Fail-on-revert: this test guards AGAINST over-reject; it stays GREEN with
/// the fix and would break if the predicate rejected a firewall-owned dst.
#[test]
fn stage_ipsec_passthrough_claims_local_and_nat_to_self_dst_5620() {
    let mut snap = super::super::test_fixtures::nat_snapshot();
    // DNAT a public external (UDP/500 IKE) to the firewall itself — NAT-to-self.
    // The rule's `destination_address` is appended to `local_v4`, so the raw
    // pre-NAT dst check in Stage 11 recognises it as firewall-local.
    snap.destination_nat_rules = vec![crate::DestinationNATRuleSnapshot {
        name: "ike-dnat-to-self".to_string(),
        from_zone: "wan".to_string(),
        destination_address: "203.0.113.9".to_string(),
        destination_port: 500,
        protocol: "udp".to_string(),
        pool_address: "10.0.61.1".to_string(),
        pool_port: 500,
        ..Default::default()
    }];
    let forwarding = build_forwarding_state(&snap);
    // Precondition: the DNAT external is a firewall-local address; the control
    // remote address is not.
    assert!(
        forwarding
            .owns_configured_ip(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)))
    );
    assert!(
        !forwarding
            .owns_configured_ip(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 200)))
    );

    let frame = tcp_v4_frame(
        Ipv4Addr::new(192, 0, 2, 10),
        Ipv4Addr::new(203, 0, 113, 9),
        40000,
        500,
        TCP_FLAG_ACK,
        1,
        1,
    );

    // (dst, expect_passthrough, label)
    let cases: [(IpAddr, bool, &str); 4] = [
        (
            IpAddr::V4(Ipv4Addr::new(10, 0, 61, 1)),
            true,
            "lan interface IP (local_v4)",
        ),
        (
            IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8)),
            true,
            "WAN/SNAT interface IP (configured_iface_v4 only)",
        ),
        (
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)),
            true,
            "DNAT-to-self external (local_v4 via DNAT append)",
        ),
        (
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 200)),
            false,
            "never-configured remote (control)",
        ),
    ];
    for (dst, expect_passthrough, label) in cases {
        // Raw ESP: unconditionally exempt from the #4323 host-inbound gate, so
        // this isolates the #5620 local-destination predicate.
        let flow = ipsec_flow_to(libc::AF_INET, PROTO_ESP, 0, dst);
        let mut meta = tcp_v4_meta(&frame, TCP_FLAG_ACK);
        meta.protocol = PROTO_ESP;
        let outcome = run_stage11(&forwarding, &flow, &frame, meta);
        if expect_passthrough {
            assert!(
                matches!(outcome, IpsecPassthroughOutcome::Passthrough),
                "#5620: LOCAL-destined ESP to {label} must stay claimed \
                 (Passthrough) — over-rejecting it would break VPN termination",
            );
        } else {
            assert!(
                matches!(outcome, IpsecPassthroughOutcome::NotClaimed),
                "#5620: ESP to {label} must be NotClaimed (proves the claim is \
                 scoped to firewall-owned addresses, not a blanket accept)",
            );
        }
    }
}
