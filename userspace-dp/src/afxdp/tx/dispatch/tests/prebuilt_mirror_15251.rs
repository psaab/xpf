// #15251 (A75-04) + #16603: Prebuilt transit frames (embedded-ICMP NAT
// reversal, including the NAT64 cross-family variant) are forwarded as
// already-translated wire frames, but the port-mirror clone must carry
// the RECEIVED frame (plan-1376: "full original Ethernet frame"), not
// the translated egress frame. These cells drive the real dispatcher
// with a PrebuiltTransit request whose ingress bytes differ from the
// wire bytes and assert the analyzer clone equals the ingress bytes
// (ingress L2/VLAN/family/TTL), while the primary forward still carries
// the rewritten wire frame. Sampling and the no-mirror allocation gate
// are pinned by the 15947/16603 cells below.

use super::*;
use crate::afxdp::tx::test_support::{build_ipv4_test_packet, build_ipv6_test_packet};

/// Drive one PrebuiltTransit dispatch. `wire_frame` is the translated
/// egress frame that must be forwarded; `ingress_frame` is the received
/// frame that must be mirrored. Returns the bindings so callers can read
/// both the forward queue (binding 1) and the analyzer queue (binding 2).
fn run_prebuilt_dispatch(
    wire_frame: Vec<u8>,
    ingress_frame: Vec<u8>,
    is_v6_wire: bool,
    reject_output: bool,
) -> (Vec<BindingWorker>, DebugPollCounters) {
    let mut bindings = vec![
        BindingWorker::new_for_mirror_test(0, 0, 11, 0),
        BindingWorker::new_for_mirror_test(1, 0, 22, 0),
        BindingWorker::new_for_mirror_test(2, 0, 33, 0),
    ];
    // This fixture carries ingress bytes in the request's Owned source;
    // dispatch does not read mirror bytes from the UMEM descriptor.
    let mut forwarding = test_forwarding_with_egress_mtu(1500);
    forwarding.mirror_configs.insert(
        11,
        MirrorRuntimeConfig {
            output_ifindex: 33,
            rate: 0,
        },
    );
    if reject_output {
        forwarding.filter_state = crate::filter::parse_filter_state(
            &[crate::FirewallFilterSnapshot {
                name: "analyzer-discard".into(),
                family: "inet".into(),
                terms: vec![crate::FirewallTermSnapshot {
                    name: "discard-all".into(),
                    action: "discard".into(),
                    ..Default::default()
                }],
            }],
            &[],
            &[crate::InterfaceSnapshot {
                name: "analyzer".into(),
                ifindex: 33,
                filter_output_v4: "analyzer-discard".into(),
                ..Default::default()
            }],
            "",
            "",
        )
        .expect("filter state compiles");
        forwarding.tx_selection_enabled_v4 = true;
    }
    let lookup = WorkerBindingLookup::from_bindings(&bindings);
    let mirror_targets = MirrorTargetMap::default();
    let mut request = test_live_forward_request_for_frame(
        wire_frame.len(),
        test_forwarding_decision_to_bound_ifindex(22),
    );
    let mut wire_frame = wire_frame;
    wire_frame[0..6].copy_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
    wire_frame[6..12].copy_from_slice(&[0x02, 0xbf, 0x72, 0x16, 0x00, 0x01]);
    // Ingress meta describes the RECEIVED packet (pre-reversal).
    let mut ingress_meta = request.meta;
    if is_v6_wire {
        // NAT64: wire is v6, ingress was v4.
        ingress_meta.addr_family = libc::AF_INET as u8;
        ingress_meta.protocol = PROTO_ICMP;
        ingress_meta.flow_src_addr = [0u8; 16];
        ingress_meta.flow_dst_addr = [0u8; 16];
        ingress_meta.flow_src_addr[..4].copy_from_slice(&ingress_frame[26..30]);
        ingress_meta.flow_dst_addr[..4].copy_from_slice(&ingress_frame[30..34]);
        request.meta.addr_family = libc::AF_INET6 as u8;
        request.meta.protocol = PROTO_TCP;
        request.meta.flow_src_addr = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        request.meta.flow_dst_addr = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
    } else {
        ingress_meta.flow_src_addr[..4].copy_from_slice(&ingress_frame[26..30]);
        ingress_meta.flow_dst_addr[..4].copy_from_slice(&ingress_frame[30..34]);
        request.meta.flow_src_addr[..4].copy_from_slice(&wire_frame[26..30]);
        request.meta.flow_dst_addr[..4].copy_from_slice(&wire_frame[30..34]);
    }
    request.frame = PendingForwardFrame::PrebuiltTransit {
        frame: wire_frame.clone().into(),
        ingress_source: PrebuiltTransitIngress::Owned(ingress_frame.clone()),
        ingress_meta,
    };
    request.desc.len = ingress_frame.len() as u32;
    request.flow_key = None;
    let mut pending = vec![request];
    let mut post_recycles = Vec::new();
    let ingress_ident = bindings[0].identity();
    let ingress_live = &*bindings[0].live as *const BindingLiveState;
    let local_tunnel_deliveries: Arc<ArcSwap<BTreeMap<i32, LocalTunnelDelivery>>> =
        Arc::new(ArcSwap::from_pointee(BTreeMap::new()));
    let recent_exceptions = Arc::new(Mutex::new(ExceptionEventRing::new()));
    let worker_commands_by_id: BTreeMap<u32, Arc<Mutex<VecDeque<WorkerCommand>>>> = BTreeMap::new();
    let mut dbg = DebugPollCounters::default();
    let (left, rest) = bindings.split_at_mut(0);
    let (ingress, right) = rest.split_first_mut().expect("ingress binding");
    enqueue_pending_forwards(
        left,
        0,
        ingress,
        right,
        &lookup,
        &mirror_targets,
        &mut pending,
        &mut post_recycles,
        1,
        &forwarding,
        None,
        &ingress_ident,
        unsafe { &*ingress_live },
        None,
        &local_tunnel_deliveries,
        &recent_exceptions,
        &mut dbg,
        &mut BatchCounters::default(),
        0,
        &worker_commands_by_id,
    );
    (bindings, dbg)
}

fn mirrored_bytes(bindings: &[BindingWorker]) -> Vec<u8> {
    let mirror_req = bindings[2]
        .tx_pipeline
        .pending_tx_prepared
        .front()
        .expect("mirror clone must be queued on the analyzer binding");
    assert!(mirror_req.mirror_clone);
    assert_eq!(mirror_req.egress_ifindex, 33);
    bindings[2]
        .umem
        .area()
        .slice(mirror_req.offset as usize, mirror_req.len as usize)
        .expect("mirrored frame")
        .to_vec()
}

#[test]
fn prebuilt_transit_frame_is_mirrored_15251() {
    // #16603: the wire frame is the post-reversal frame (egress MACs,
    // internal addresses); the ingress frame is what crossed the outside
    // wire. They deliberately differ in L2 and L3 so a mirror of the
    // wrong one cannot pass.
    let mut ingress_frame = build_ipv4_test_packet(0);
    ingress_frame[0..6].copy_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    ingress_frame[6..12].copy_from_slice(&[0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb]);
    // Ingress L3: 198.51.100.1 -> 192.0.2.1 (pre-reversal, TTL 57).
    ingress_frame[26..30].copy_from_slice(&[198, 51, 100, 1]);
    ingress_frame[30..34].copy_from_slice(&[192, 0, 2, 1]);
    ingress_frame[22] = 57;
    let mut wire_frame = build_ipv4_test_packet(0);
    wire_frame[26..30].copy_from_slice(&[10, 0, 0, 1]);
    wire_frame[30..34].copy_from_slice(&[10, 0, 0, 2]);
    wire_frame[22] = 56;
    let (bindings, dbg) = run_prebuilt_dispatch(wire_frame, ingress_frame.clone(), false, false);
    assert_eq!(dbg.enqueue_ok, 1, "the prebuilt frame itself must forward");
    assert_eq!(
        bindings[0].live.mirrored_packets.load(Ordering::Relaxed),
        1,
        "#15251: a forwarded Prebuilt transit frame must be port-mirrored"
    );
    assert_eq!(
        bindings[0].live.mirrored_bytes.load(Ordering::Relaxed),
        ingress_frame.len() as u64,
        "#16603: mirrored_bytes must count the ingress frame, not the wire frame"
    );
    assert_eq!(
        mirrored_bytes(&bindings),
        ingress_frame.as_slice(),
        "#16603: the mirror clone must carry the received ingress frame, \
         not the translated egress frame"
    );
}

#[test]
fn prebuilt_nat64_frame_is_mirrored_15251() {
    // #16603 NAT64: the wire frame is cross-family v6 (translated
    // egress); the received frame is v4. The mirror clone must carry
    // the v4 ingress bytes, in the original family.
    let mut ingress_frame = build_ipv4_test_packet(0);
    ingress_frame[0..6].copy_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    ingress_frame[6..12].copy_from_slice(&[0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb]);
    ingress_frame[26..30].copy_from_slice(&[198, 51, 100, 9]);
    ingress_frame[30..34].copy_from_slice(&[192, 0, 2, 9]);
    let wire_frame = build_ipv6_test_packet(0);
    let (bindings, dbg) = run_prebuilt_dispatch(wire_frame, ingress_frame.clone(), true, false);
    assert_eq!(
        dbg.enqueue_ok, 1,
        "the NAT64 prebuilt frame itself must forward"
    );
    assert_eq!(
        bindings[0].live.mirrored_packets.load(Ordering::Relaxed),
        1,
        "#15251: a forwarded NAT64 Prebuilt frame must be port-mirrored"
    );
    assert_eq!(
        bindings[0].live.mirrored_bytes.load(Ordering::Relaxed),
        ingress_frame.len() as u64
    );
    assert_eq!(
        mirrored_bytes(&bindings),
        ingress_frame.as_slice(),
        "#16603: the NAT64 mirror clone must carry the received v4 ingress \
         frame, not the translated v6 wire frame"
    );
}

#[test]
fn prebuilt_nat64_v6_ingress_frame_is_mirrored_16603() {
    // Reverse NAT64 direction: v6 ingress, v4 wire. The helper's
    // `is_v6_wire` flag keys on the wire, so drive it inline here.
    // Reuse the v4-wire path by swapping roles: ingress v6 bytes are
    // carried verbatim regardless of family; assert clone == ingress.
    let mut ingress_frame = build_ipv6_test_packet(0);
    ingress_frame[0..6].copy_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    ingress_frame[6..12].copy_from_slice(&[0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb]);
    let wire_frame = build_ipv4_test_packet(0);
    // is_v6_wire=false makes ingress_meta v4; override by using the
    // generic helper with wire=v4 would stamp v4 ingress meta. The
    // mirror filter tuple is not under test here (no output filter is
    // configured), so only bytes/counts are asserted.
    let (bindings, dbg) = run_prebuilt_dispatch(wire_frame, ingress_frame.clone(), false, false);
    assert_eq!(dbg.enqueue_ok, 1);
    assert_eq!(
        mirrored_bytes(&bindings),
        ingress_frame.as_slice(),
        "#16603: v6-ingress NAT64 mirror must carry the received frame"
    );
}

#[test]
fn prebuilt_sampled_out_frame_forwards_without_mirror_15947() {
    // #15947 (H26-02 arm 4): with a mirror configured but the sample
    // rate declining this packet, the Prebuilt frame must still
    // forward and no mirror clone may be queued. (The pre-fix code
    // cloned the Vec before learning the sample outcome; the copy
    // itself is not observable here — what this pins is that the
    // deferred-copy restructure keeps the forward + no-mirror
    // behaviour intact on the sampled-out branch.)
    let mut bindings = vec![
        BindingWorker::new_for_mirror_test(0, 0, 11, 0),
        BindingWorker::new_for_mirror_test(1, 0, 22, 0),
        BindingWorker::new_for_mirror_test(2, 0, 33, 0),
    ];
    let mut forwarding = test_forwarding_with_egress_mtu(1500);
    // Rate 3: mirror_sample_allows selects only counters divisible
    // by the rate. The ingress sample counter is driven to 1 before
    // dispatch below, so this packet is sampled out.
    forwarding.mirror_configs.insert(
        11,
        MirrorRuntimeConfig {
            output_ifindex: 33,
            rate: 3,
        },
    );
    bindings[0].mirror_sample_counter = 1;
    let lookup = WorkerBindingLookup::from_bindings(&bindings);
    let mirror_targets = MirrorTargetMap::default();
    let mut frame = build_ipv4_test_packet(0);
    frame[0..6].copy_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
    frame[6..12].copy_from_slice(&[0x02, 0xbf, 0x72, 0x16, 0x00, 0x01]);
    let mut request = test_live_forward_request_for_frame(
        frame.len(),
        test_forwarding_decision_to_bound_ifindex(22),
    );
    let mut ingress_frame = build_ipv4_test_packet(0);
    ingress_frame[26..30].copy_from_slice(&[198, 51, 100, 3]);
    ingress_frame[30..34].copy_from_slice(&[192, 0, 2, 3]);
    let mut ingress_meta = request.meta;
    ingress_meta.flow_src_addr[..4].copy_from_slice(&ingress_frame[26..30]);
    ingress_meta.flow_dst_addr[..4].copy_from_slice(&ingress_frame[30..34]);
    request.frame = PendingForwardFrame::PrebuiltTransit {
        frame: frame.clone().into(),
        ingress_source: PrebuiltTransitIngress::Owned(ingress_frame),
        ingress_meta,
    };
    request.desc.len = frame.len() as u32;
    request.meta.flow_src_addr[..4].copy_from_slice(&frame[26..30]);
    request.meta.flow_dst_addr[..4].copy_from_slice(&frame[30..34]);
    request.flow_key = None;
    let mut pending = vec![request];
    let mut post_recycles = Vec::new();
    let ingress_ident = bindings[0].identity();
    let ingress_live = &*bindings[0].live as *const BindingLiveState;
    let local_tunnel_deliveries: Arc<ArcSwap<BTreeMap<i32, LocalTunnelDelivery>>> =
        Arc::new(ArcSwap::from_pointee(BTreeMap::new()));
    let recent_exceptions = Arc::new(Mutex::new(ExceptionEventRing::new()));
    let worker_commands_by_id: BTreeMap<u32, Arc<Mutex<VecDeque<WorkerCommand>>>> = BTreeMap::new();
    let mut dbg = DebugPollCounters::default();
    let (left, rest) = bindings.split_at_mut(0);
    let (ingress, right) = rest.split_first_mut().expect("ingress binding");
    enqueue_pending_forwards(
        left,
        0,
        ingress,
        right,
        &lookup,
        &mirror_targets,
        &mut pending,
        &mut post_recycles,
        1,
        &forwarding,
        None,
        &ingress_ident,
        unsafe { &*ingress_live },
        None,
        &local_tunnel_deliveries,
        &recent_exceptions,
        &mut dbg,
        &mut BatchCounters::default(),
        0,
        &worker_commands_by_id,
    );
    assert_eq!(dbg.enqueue_ok, 1, "sampled-out prebuilt must still forward");
    assert_eq!(
        bindings[0].live.mirrored_packets.load(Ordering::Relaxed),
        0,
        "sampled-out prebuilt must not be mirrored"
    );
    assert!(
        bindings[2].tx_pipeline.pending_tx_prepared.is_empty(),
        "sampled-out prebuilt must not queue a mirror clone"
    );
}

#[test]
fn prebuilt_transit_no_mirror_no_extra_alloc_16603() {
    // #17718: count the full dispatch mirror shape against the unchanged
    // plain-Prebuilt path. Ingress bytes are seeded in UMEM and the wire
    // fixture is built before the measured window; this exercises the
    // production descriptor source rather than a test-only owned clone.
    fn dispatch(
        transit: bool,
        mirror: Option<MirrorRuntimeConfig>,
        sample_counter: u64,
    ) -> (u64, DebugPollCounters, Option<bool>) {
        let mut bindings = vec![
            BindingWorker::new_for_mirror_test(0, 0, 11, 0),
            BindingWorker::new_for_mirror_test(1, 0, 22, 0),
            BindingWorker::new_for_mirror_test(2, 0, 33, 0),
        ];
        let mut forwarding = test_forwarding_with_egress_mtu(1500);
        if let Some(cfg) = mirror {
            forwarding.mirror_configs.insert(11, cfg);
        }
        bindings[0].mirror_sample_counter = sample_counter;
        // The mirror target's queue growth is unrelated to the ingress copy;
        // reserve outside the measured window so the selected delta is the
        // single staged frame snapshot.
        bindings[2].tx_pipeline.pending_tx_prepared.reserve(1);
        let mut wire_frame = build_ipv4_test_packet(0);
        wire_frame[0..6].copy_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        wire_frame[6..12].copy_from_slice(&[0x02, 0xbf, 0x72, 0x16, 0x00, 0x01]);
        let mut ingress_frame = build_ipv4_test_packet(0);
        ingress_frame[26..30].copy_from_slice(&[198, 51, 100, 4]);
        ingress_frame[30..34].copy_from_slice(&[192, 0, 2, 4]);
        unsafe {
            bindings[0]
                .umem
                .area()
                .slice_mut_unchecked(0, ingress_frame.len())
        }
        .expect("ingress frame")
        .copy_from_slice(&ingress_frame);
        let lookup = WorkerBindingLookup::from_bindings(&bindings);
        let mirror_targets = MirrorTargetMap::default();
        let mut request = test_live_forward_request_for_frame(
            wire_frame.len(),
            test_forwarding_decision_to_bound_ifindex(22),
        );
        request.meta.flow_src_addr[..4].copy_from_slice(&wire_frame[26..30]);
        request.meta.flow_dst_addr[..4].copy_from_slice(&wire_frame[30..34]);
        request.frame = if transit {
            let mut ingress_meta = request.meta;
            ingress_meta.flow_src_addr[..4].copy_from_slice(&ingress_frame[26..30]);
            ingress_meta.flow_dst_addr[..4].copy_from_slice(&ingress_frame[30..34]);
            PendingForwardFrame::PrebuiltTransit {
                frame: wire_frame.into(),
                ingress_source: PrebuiltTransitIngress::Descriptor,
                ingress_meta,
            }
        } else {
            PendingForwardFrame::Prebuilt(wire_frame.into())
        };
        request.desc.len = 34;
        request.flow_key = None;
        let mut pending = vec![request];
        let mut post_recycles = Vec::new();
        let ingress_ident = bindings[0].identity();
        let ingress_live = &*bindings[0].live as *const BindingLiveState;
        let local_tunnel_deliveries: Arc<ArcSwap<BTreeMap<i32, LocalTunnelDelivery>>> =
            Arc::new(ArcSwap::from_pointee(BTreeMap::new()));
        let recent_exceptions = Arc::new(Mutex::new(ExceptionEventRing::new()));
        let worker_commands_by_id: BTreeMap<u32, Arc<Mutex<VecDeque<WorkerCommand>>>> =
            BTreeMap::new();
        let mut dbg = DebugPollCounters::default();
        let mut counters = BatchCounters::default();
        let (left, rest) = bindings.split_at_mut(0);
        let (ingress, right) = rest.split_first_mut().expect("ingress binding");
        let (_, allocs) = crate::test_alloc::count_allocs(|| {
            enqueue_pending_forwards(
                left,
                0,
                ingress,
                right,
                &lookup,
                &mirror_targets,
                &mut pending,
                &mut post_recycles,
                1,
                &forwarding,
                None,
                &ingress_ident,
                unsafe { &*ingress_live },
                None,
                &local_tunnel_deliveries,
                &recent_exceptions,
                &mut dbg,
                &mut counters,
                0,
                &worker_commands_by_id,
            );
        });
        let mirrored_matches_ingress = bindings[2]
            .tx_pipeline
            .pending_tx_prepared
            .front()
            .map(|mirror_req| {
                assert!(mirror_req.mirror_clone);
                bindings[2]
                    .umem
                    .area()
                    .slice(mirror_req.offset as usize, mirror_req.len as usize)
                    .is_some_and(|frame| frame == ingress_frame.as_slice())
            });
        (allocs, dbg, mirrored_matches_ingress)
    }

    let (plain_prebuilt_allocs, plain_dbg, plain_mirrored) = dispatch(false, None, 0);
    let (no_mirror_allocs, no_mirror_dbg, no_mirror) = dispatch(true, None, 0);
    let (sampled_out_allocs, sampled_out_dbg, sampled_out) = dispatch(
        true,
        Some(MirrorRuntimeConfig {
            output_ifindex: 33,
            rate: 3,
        }),
        1,
    );
    let (selected_allocs, selected_dbg, selected) = dispatch(
        true,
        Some(MirrorRuntimeConfig {
            output_ifindex: 33,
            rate: 3,
        }),
        0,
    );

    assert_eq!(plain_dbg.enqueue_ok, 1);
    assert_eq!(no_mirror_dbg.enqueue_ok, 1);
    assert_eq!(sampled_out_dbg.enqueue_ok, 1);
    assert_eq!(selected_dbg.enqueue_ok, 1);
    assert_eq!(plain_mirrored, None);
    assert_eq!(no_mirror, None);
    assert_eq!(sampled_out, None);
    assert_eq!(selected, Some(true));
    assert_eq!(
        no_mirror_allocs, plain_prebuilt_allocs,
        "#17718: a no-mirror PrebuiltTransit must not allocate/copy ingress \
         bytes versus the plain Prebuilt control arm"
    );
    assert_eq!(
        sampled_out_allocs, plain_prebuilt_allocs,
        "#17718: a sampled-out PrebuiltTransit must not allocate/copy ingress \
         bytes versus the plain Prebuilt control arm"
    );
    assert_eq!(
        selected_allocs,
        plain_prebuilt_allocs + 1,
        "#17718: a selected PrebuiltTransit must allocate exactly one staged \
         ingress copy, not copy once in the producer and again in dispatch"
    );
}

#[test]
fn prebuilt_transit_oversize_owned_mirror_is_no_frame_17718() {
    let ingress_frame = vec![0; crate::afxdp::tx_frame_capacity() + 1];
    let (bindings, dbg) = run_prebuilt_dispatch(
        build_ipv4_test_packet(0),
        ingress_frame,
        false,
        true,
    );

    assert_eq!(dbg.enqueue_ok, 1, "oversize mirror must not block forwarding");
    assert!(
        bindings[2].tx_pipeline.pending_tx_prepared.is_empty(),
        "oversize ingress must not enqueue an empty analyzer frame"
    );
    assert_eq!(
        bindings[0]
            .live
            .mirror_drops_no_frame
            .load(Ordering::Relaxed),
        1,
        "oversize ingress must retain the NoFrame mirror outcome"
    );
}
