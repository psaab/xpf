//! #13081 structural regression for the per-batch PMech replay stage.

#[test]
fn pmech_replay_drain_is_a_sibling_stage_13081() {
    let source = include_str!("mod.rs");
    assert!(
        source.contains("pmech_replay::drain_pending_pmech_replays(")
            && source.contains("&mut binding.pending_pmech_reverse")
            && source.contains("&mut binding.pending_pmech_replay"),
        "the poll loop delegates pending PMech reverse replay to its sibling stage"
    );
    assert!(
        !source.contains("match pmech_directory.probe_token(held.token)")
            && !source.contains("for _ in 0..pmech_scan_len"),
        "the large poll function must not inline PMech replay-stage control flow"
    );
}

#[test]
fn syn_cookie_admission_uses_effective_tuple_and_finalized_zone_pair_17920() {
    let cookie = include_str!("cookie_reply.rs");
    let admission = include_str!("session_admission.rs");
    let poll = include_str!("mod.rs");
    let prescreen = cookie
        .split("pub(super) fn syn_cookie_challenge_is_session_miss(")
        .nth(1)
        .expect("challenge session-miss guard exists")
        .split("pub(super) fn syn_cookie_final_admission(")
        .next()
        .expect("challenge guard ends before final admission");
    assert!(
        prescreen.contains("has_session_hit_at")
            && !prescreen.contains("transit_admission_verdict("),
        "the early challenge gate must not judge an incomplete raw tuple"
    );
    let final_admission = cookie
        .split("pub(super) fn syn_cookie_final_admission_with_fence(")
        .nth(1)
        .expect("final admission helper exists")
        .split("/// Host-bound counterpart")
        .next()
        .expect("final helper ends before host helper");
    let final_wrapper = cookie
        .split("pub(super) fn syn_cookie_final_admission(")
        .nth(1)
        .expect("final admission wrapper exists")
        .split("pub(super) fn syn_cookie_final_admission_with_fence(")
        .next()
        .expect("final wrapper ends before fenced final");
    const REENCODED: [&str; 6] = [
        "evaluate_policy_result_without_counting_at(",
        "evaluate_policy_result_with_icmp_at(",
        "evaluate_policy_query",
        "transit_destination_class_drop(",
        "transit_source_class_drop(",
        "transit_dst_is_martian",
    ];
    assert!(final_admission.contains("cookie_reply_admission_verdict("));
    for banned in REENCODED {
        assert!(
            !final_admission.contains(banned),
            "final admission must not re-encode policy or martian admission ({banned})"
        );
        assert!(
            !final_wrapper.contains(banned),
            "final wrapper must not re-encode policy or martian admission ({banned})"
        );
    }
    assert!(
        final_admission.contains("class_dst: flow.dst_ip")
            && final_admission.contains("translated_dst,")
            && final_admission.contains("policy_dst: effective_dst"),
        "final admission keeps raw/class and translated policy tuples distinct"
    );
    assert!(
        final_admission.contains(
            "packet_fabric_ingress,\n        fabric_link_ingress,\n        meta.ingress_ifindex as i32,\n        from_zone_id,\n        ha_startup_grace_until_secs,"
        ),
        "cookie HA finalization receives the packet's fabric and startup-grace context"
    );
    assert!(
        final_admission.contains("session_miss_zone_pair_ids("),
        "cookie admission uses the same finalized zone-pair helper as session misses"
    );
    for field in [
        "class_dst",
        "translated_dst",
        "policy_dst",
        "from_zone_id",
        "to_zone_id",
    ] {
        assert!(
            admission.contains(&format!("pub(super) {field}:")),
            "the shared chain must carry {field} explicitly"
        );
    }
    assert!(admission.contains("pub(super) fn transit_admission_verdict("));
    assert!(admission.contains("pub(super) fn cookie_reply_admission_verdict("));
    assert!(
        admission.contains("let local_policy_disposition = matches!(")
            && admission.contains(
                "ForwardingDisposition::ForwardCandidate | ForwardingDisposition::MissingNeighbor"
            )
            && admission.contains(
                "authorize_fabric_redirect\n        && input.resolution.disposition == ForwardingDisposition::FabricRedirect"
            ),
        "ordinary punts delegate policy while locally consumed cookie replies evaluate finalized redirects"
    );
    assert!(
        poll.contains("let route_from_zone_id = from_zone_id;")
            && poll.contains("let route_to_zone_id = to_zone_id;")
            && poll.contains("route_from_zone_id,\n                                    seed_to_zone_id,")
            && poll.contains("route_from_zone_id,\n                                route_to_zone_id,"),
        "punt-seed authorization retains the real pre-redirect route zone pair"
    );
    let miss_class = poll
        .split("// #11413/#10689: share the pure destination/source")
        .nth(1)
        .expect("session-miss class gate exists")
        .split("// #10597 G5: apply the local-only fence")
        .next()
        .expect("session-miss class gate ends before the local-only fence");
    assert!(
        miss_class.contains("transit_class_verdict(")
            && miss_class.contains("record_martian_drop()")
            && miss_class.contains("record_transit_source_martian_drop()"),
        "the session-miss effects preserve both class-drop counters"
    );
    let finalized_zone_pair = poll
        .split("let final_resolution = finalize_new_flow_ha_resolution(")
        .nth(1)
        .expect("session-miss HA finalization exists")
        .split("if miss_input_policer_gate_covers(final_resolution.disposition)")
        .next()
        .expect("finalized zone pair is selected before downstream admission");
    assert!(
        finalized_zone_pair.contains("decision.resolution = final_resolution")
            && finalized_zone_pair.contains("session_miss_zone_pair_ids("),
        "the miss path recomputes its policy zone pair after HA finalization"
    );
    assert!(
        finalized_zone_pair
            .contains("admission_to_zone = if final_resolution.disposition")
            && finalized_zone_pair.contains("route_to_zone_id"),
        "FabricRedirect accounting retains the routed admission zone"
    );
    let cookie_challenge_call = poll
        .split("syn_cookie_final_admission_with_fence(")
        .nth(1)
        .expect("cookie challenge admission call exists")
        .split(");")
        .next()
        .expect("cookie challenge admission call is terminated");
    let cookie_ack_call = poll
        .split("syn_cookie_final_admission(")
        .nth(1)
        .expect("cookie ACK admission call exists")
        .split(");")
        .next()
        .expect("cookie ACK admission call is terminated");
    for call in [cookie_challenge_call, cookie_ack_call] {
        assert!(
            call.contains("packet_fabric_ingress")
                && call.contains("fabric_link_ingress")
                && call.contains("ha_startup_grace_until_secs"),
            "each production cookie finalizer receives the miss-path HA context"
        );
    }
    let miss_policy = poll
        .split("let admission_verdict = transit_admission_verdict(")
        .nth(1)
        .expect("session-miss shared policy site exists")
        .split("// #1620: cold-path latency histogram post-eval record")
        .next()
        .expect("session-miss policy verdict precedes histogram accounting");
    assert!(
        miss_policy.contains("policy_icmp: policy_packet_icmp(packet_frame, meta)"),
        "session-miss passes the packet ICMP tuple into the shared verdict"
    );
    assert!(
        miss_policy.contains("count_policy_evaluation_result("),
        "session-miss applies the effect to the shared pure policy verdict"
    );
    for banned in REENCODED {
        assert!(
            !miss_policy.contains(banned),
            "session-miss must not re-encode policy beside the shared verdict ({banned})"
        );
    }
}

// #13766: behavioral drain coverage for the #13636 TX-pool return.
//
// Drive the real `drain_pending_pmech_replays` with fresh directories (never
// `PMechSessionDirectory::global()`) and assert the actual destination deques.
// Test both terminal reasons: an expired token becomes Absent, and a held
// packet's owner generation can mismatch a newer token owner generation. Each
// reason is exercised for both injected TX-pool frames and native RX frames.
// Reverting, swapping, or removing the `is_injected` branch must fail these
// assertions even though no source-string check is involved.
mod pmech_drain_13766 {
    use super::super::pmech_replay::drain_pending_pmech_replays;
    use crate::afxdp::types::{PendingPMechReversePacket, UserspaceDpMeta};
    use crate::session::{
        PMechClaimKind, PMechClaimSpec, PMechDirection, PMechSessionDirectory, PMechWaiterRef,
        SessionKey, TunnelDiscriminator,
    };
    use crate::xsk_ffi::xdp::XdpDesc;
    use std::collections::VecDeque;
    use std::net::{IpAddr, Ipv4Addr};

    const GEN: u64 = 7;

    fn test_key() -> SessionKey {
        SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: crate::ip_proto::PROTO_UDP,
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 137, 66, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 137)),
            src_port: 13_766,
            dst_port: 443,
            discriminator: TunnelDiscriminator::Ipsec(137_066),
            routing_domain: 7,
        }
    }

    fn reserve_pending(directory: &PMechSessionDirectory, owner_generation: u64) -> u64 {
        directory
            .reserve_claims(
                owner_generation,
                u64::MAX,
                &[PMechClaimSpec::new(
                    test_key(),
                    PMechClaimKind::Pending,
                    PMechDirection::Reverse,
                )],
            )
            .expect("reserve test pmech claim")
    }

    fn held(
        is_injected: bool,
        token: u64,
        owner_generation: u64,
        addr: u64,
    ) -> PendingPMechReversePacket {
        PendingPMechReversePacket {
            desc: XdpDesc {
                addr,
                len: 64,
                options: 0,
            },
            meta: UserspaceDpMeta::default(),
            waiter: PMechWaiterRef {
                arrival_worker_id: 137,
                defer_id: addr,
            },
            token,
            owner_generation,
            is_injected,
            owned_frame: None,
        }
    }

    fn run_drain(
        directory: &PMechSessionDirectory,
        pending_reverse: &mut VecDeque<PendingPMechReversePacket>,
    ) -> (Vec<u64>, Vec<u64>) {
        let mut pending_replay = VecDeque::new();
        let mut scratch_recycle = Vec::new();
        let mut tx_recycle = VecDeque::new();
        drain_pending_pmech_replays(
            directory,
            pending_reverse,
            &mut pending_replay,
            &mut scratch_recycle,
            &mut tx_recycle,
        );
        assert!(
            pending_replay.is_empty(),
            "terminal probes must not enqueue packets for replay"
        );
        assert!(
            pending_reverse.is_empty(),
            "terminal probes must drain every held packet"
        );
        (scratch_recycle, tx_recycle.into_iter().collect())
    }

    fn assert_routing(is_injected: bool, addr: u64, scratch: &[u64], tx: &[u64]) {
        if is_injected {
            assert_eq!(
                tx,
                &[addr],
                "injected (WireGuard plaintext) frame descriptor addr {addr} came from the TX pool and MUST return to tx_recycle"
            );
            assert!(
                scratch.is_empty(),
                "injected frame addr {addr} must never land in scratch_recycle (RX fill ring): got {scratch:?}"
            );
        } else {
            assert_eq!(
                scratch,
                &[addr],
                "native RX frame descriptor addr {addr} MUST return to scratch_recycle"
            );
            assert!(
                tx.is_empty(),
                "native RX addr {addr} must never land in tx_recycle (TX pool): got {tx:?}"
            );
        }
    }

    #[test]
    fn expired_token_recycles_injected_to_tx_and_native_to_scratch_13766() {
        for is_injected in [true, false] {
            let directory = PMechSessionDirectory::new();
            let token = reserve_pending(&directory, GEN);
            assert!(
                directory.mark_uncertain(token, GEN, 100),
                "fixture: reserved token must become uncertain-denied"
            );
            assert_eq!(directory.expire_uncertain(100), 1);
            let addr = if is_injected { 0xA001 } else { 0xA002 };
            let mut pending: VecDeque<_> = [held(is_injected, token, GEN, addr)].into();
            let (scratch, tx) = run_drain(&directory, &mut pending);
            assert_routing(is_injected, addr, &scratch, &tx);
        }
    }

    #[test]
    fn changed_generation_recycles_injected_to_tx_and_native_to_scratch_13766() {
        // A Live token belonging to a newer owner generation is not replayable
        // by a packet held under the old generation, and must be recycled.
        for is_injected in [true, false] {
            let directory = PMechSessionDirectory::new();
            let live_gen = GEN + 1;
            let token = reserve_pending(&directory, live_gen);
            assert!(
                directory.mark_live(token, live_gen, 1, 2),
                "fixture: reserved token must become live"
            );
            let addr = if is_injected { 0xB001 } else { 0xB002 };
            let mut pending: VecDeque<_> = [held(is_injected, token, GEN, addr)].into();
            let (scratch, tx) = run_drain(&directory, &mut pending);
            assert_routing(is_injected, addr, &scratch, &tx);
        }
    }

    #[test]
    fn mixed_batch_routes_each_frame_to_its_own_pool_13766() {
        let directory = PMechSessionDirectory::new();
        let mut pending: VecDeque<_> = [
            held(true, 0xDEAD, GEN, 0xC001),
            held(false, 0xDEAD, GEN, 0xC002),
        ]
        .into();
        let (scratch, tx) = run_drain(&directory, &mut pending);
        assert_eq!(
            tx,
            vec![0xC001],
            "the single injected frame returns to tx_recycle exactly once"
        );
        assert_eq!(
            scratch,
            vec![0xC002],
            "the single native RX frame returns to scratch_recycle exactly once"
        );
    }
}

// #15243 (A60-01): hold-admission and replay-fidelity coverage.
//
// A native GRE/WG-decapsulated reverse packet carries the INNER packet's
// meta while its descriptor still references the OUTER UMEM frame. Holding
// it (as the pre-fix code did) strands it: replay slices the outer frame
// at inner offsets and re-runs decap against inner bytes, which returns
// NotGre/NotWg, so the packet is never delivered. The fix refuses such
// holds (`pmech_hold_admissible`), and replay sources `raw_frame` from a
// held packet's owned frame when one is present.
//
// These cells drive the real helpers: reverting the admissibility gate to
// `true`, or making the replay path ignore the owned frame, turns them
// RED (see the structural pin below for the replay half).
mod pmech_hold_15243 {
    use super::super::pmech_replay::pmech_hold_admissible;
    use crate::afxdp::poll_stages::{GreDecapStage, stage_native_gre_decap};
    use crate::afxdp::types::UserspaceDpMeta;

    #[test]
    fn native_decapped_reverse_packet_is_refused_at_hold_15243() {
        assert!(
            !pmech_hold_admissible(false, true),
            "native decapped (owned_frame.is_some()) reverse packet MUST be refused at hold: \
             its desc references the outer UMEM frame while meta describes the inner packet"
        );
    }

    #[test]
    fn native_plain_and_injected_packets_stay_admissible_15243() {
        assert!(
            pmech_hold_admissible(false, false),
            "control: a native non-decapped reverse packet (meta describes its desc frame) stays holdable"
        );
        assert!(
            pmech_hold_admissible(true, true),
            "control: an injected packet's desc already holds its owned frame bytes (TX-pool frame), so it stays holdable"
        );
        assert!(
            pmech_hold_admissible(true, false),
            "control: an injected packet without an owned frame stays holdable"
        );
    }

    // The second half of the mechanism: WHY a refused hold matters. The
    // inner bytes a decapsulated packet carries are not a GRE frame, so
    // feeding them back through the native GRE decap stage (what the
    // pre-fix replay did, by slicing the outer frame at inner offsets and
    // re-entering stage 6 with the inner meta) yields NotGre — the packet
    // falls through as an ordinary non-GRE packet described by the inner
    // meta, i.e. it is never delivered as the tunnel inner packet it is.
    #[test]
    fn inner_frame_fed_back_through_gre_decap_is_not_gre_15243() {
        // A minimal inner IPv4/UDP packet (the shape a decapsulated GRE
        // inner frame takes after `build_logical_ingress_ethernet_packet`:
        // Ethernet header + inner IP). Its IP protocol is UDP, not GRE.
        let mut inner = vec![0u8; 14 + 20 + 8];
        inner[12] = 0x08;
        inner[13] = 0x00;
        inner[14] = 0x45; // IPv4, IHL 5
        inner[14 + 9] = crate::ip_proto::PROTO_UDP;
        let inner_meta = UserspaceDpMeta {
            addr_family: libc::AF_INET as u8,
            protocol: crate::ip_proto::PROTO_UDP,
            l3_offset: 14,
            l4_offset: 14 + 20,
            ..UserspaceDpMeta::default()
        };
        let forwarding = crate::afxdp::forwarding_build::build_forwarding_state(
            &crate::afxdp::test_fixtures::native_gre_snapshot(false),
        );
        let mut reassembler = crate::afxdp::gre_reassembly::GreReassembler::default();
        let mut allows = |_: &[u8], _: UserspaceDpMeta| true;
        let stage = stage_native_gre_decap(
            &inner,
            inner_meta,
            &forwarding,
            &mut reassembler,
            0,
            &mut allows,
        );
        assert!(
            matches!(stage, GreDecapStage::NotGre(_)),
            "inner (decapsulated) bytes re-entered into GRE decap MUST come back NotGre — \
             this is the drop the refused hold avoids"
        );
    }
}

// #15243 (A60-01): the replay half of the mechanism. The poll loop must
// source `raw_frame` for a replayed held packet from its owned frame when
// one is present — otherwise the fix's refused holds would be the only
// thing standing between a decapsulated packet and a mis-parsed replay,
// and any future admissible owned-frame hold would silently regress.
// This is a structural pin (like the 13081 sibling-stage pin above)
// because the full poll loop needs a UMEM area; the behavioral half is
// `pmech_hold_15243` above. Removing either the `replay_owned_frame`
// threading or the owned-frame slice turns this RED.
#[test]
fn pmech_replay_sources_owned_frame_for_held_packets_15243() {
    let source = include_str!("mod.rs");
    assert!(
        source.contains("replay_owned_frame = held.owned_frame"),
        "the replay pop must move the held packet's owned frame out for this pass"
    );
    assert!(
        source.contains("replay_scratch_frame.as_slice()"),
        "the replay pass must parse the owned frame bytes as raw_frame"
    );
    assert!(
        source.contains("pmech_hold_admissible("),
        "the hold site must consult the A60-01 admissibility gate"
    );
    assert!(
        source.contains("pmech_decap_hold_refused"),
        "a refused decapsulated hold must be counted"
    );
}
