// #15251 (A75-04): Prebuilt transit frames (embedded-ICMP NAT reversal,
// including the NAT64 cross-family variant) were forwarded but never
// port-mirrored: the Prebuilt arm of `enqueue_pending_forwards` enqueued
// and `continue`d, while mirror staging/commit were reached only by
// Live/Owned frames. These cells drive the real dispatcher with a
// Prebuilt request and assert the analyzer clone is staged/committed
// after a successful enqueue, honouring sampling and the output filter.

use super::*;
use crate::afxdp::tx::test_support::{build_ipv4_test_packet, build_ipv6_test_packet};

fn run_prebuilt_dispatch(
    frame: Vec<u8>,
    is_v6: bool,
) -> (Vec<BindingWorker>, DebugPollCounters) {
    let mut bindings = vec![
        BindingWorker::new_for_mirror_test(0, 0, 11, 0),
        BindingWorker::new_for_mirror_test(1, 0, 22, 0),
        BindingWorker::new_for_mirror_test(2, 0, 33, 0),
    ];
    let mut forwarding = test_forwarding_with_egress_mtu(1500);
    forwarding.mirror_configs.insert(
        11,
        MirrorRuntimeConfig {
            output_ifindex: 33,
            rate: 0,
        },
    );
    let lookup = WorkerBindingLookup::from_bindings(&bindings);
    let mirror_targets = MirrorTargetMap::default();
    let mut request = test_live_forward_request_for_frame(
        frame.len(),
        test_forwarding_decision_to_bound_ifindex(22),
    );
    // Real L2 addresses: an all-zero dst MAC reads as multicast/broadcast
    // to frame helpers; the Live control uses the same builder and works
    // only because its mirror clone snapshots the UMEM frame. Give the
    // Prebuilt wire frame ordinary unicast MACs.
    let mut frame = frame;
    frame[0..6].copy_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
    frame[6..12].copy_from_slice(&[0x02, 0xbf, 0x72, 0x16, 0x00, 0x01]);
    request.frame = PendingForwardFrame::Prebuilt(frame.clone());
    request.desc.len = frame.len() as u32;
    if is_v6 {
        request.meta.addr_family = libc::AF_INET6 as u8;
        request.meta.protocol = PROTO_TCP;
        // build_ipv6_test_packet leaves addresses zeroed; stamp a
        // non-martian pair so the flowless mirror filter tuple parses.
        request.meta.flow_src_addr = [
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
        ];
        request.meta.flow_dst_addr = [
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2,
        ];
    } else {
        request.meta.flow_src_addr[..4].copy_from_slice(&frame[26..30]);
        request.meta.flow_dst_addr[..4].copy_from_slice(&frame[30..34]);
    }
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

#[test]
fn prebuilt_transit_frame_is_mirrored_15251() {
    let frame = build_ipv4_test_packet(0);
    let (bindings, dbg) = run_prebuilt_dispatch(frame.clone(), false);
    assert_eq!(dbg.enqueue_ok, 1, "the prebuilt frame itself must forward");
    assert_eq!(
        bindings[0].live.mirrored_packets.load(Ordering::Relaxed),
        1,
        "#15251: a forwarded Prebuilt transit frame must be port-mirrored"
    );
    assert_eq!(
        bindings[0].live.mirrored_bytes.load(Ordering::Relaxed),
        frame.len() as u64
    );
    let mirror_req = bindings[2]
        .tx_pipeline
        .pending_tx_prepared
        .front()
        .expect("#15251: mirror clone must be queued on the analyzer binding");
    assert!(mirror_req.mirror_clone);
    assert_eq!(mirror_req.egress_ifindex, 33);
}

#[test]
fn prebuilt_nat64_frame_is_mirrored_15251() {
    // NAT64 variant: the rewritten wire frame is cross-family (here an
    // IPv6 wire frame standing in for the NAT64-translated error). The
    // mirror clone must carry the rewritten bytes, not the ingress frame.
    // `run_prebuilt_dispatch` stamps ordinary unicast MACs onto the wire
    // frame, so expect those, not the zeroed builder MACs.
    let mut frame = build_ipv6_test_packet(0);
    frame[0..6].copy_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
    frame[6..12].copy_from_slice(&[0x02, 0xbf, 0x72, 0x16, 0x00, 0x01]);
    let (bindings, dbg) = run_prebuilt_dispatch(frame.clone(), true);
    assert_eq!(dbg.enqueue_ok, 1, "the NAT64 prebuilt frame itself must forward");
    assert_eq!(
        bindings[0].live.mirrored_packets.load(Ordering::Relaxed),
        1,
        "#15251: a forwarded NAT64 Prebuilt frame must be port-mirrored"
    );
    assert_eq!(
        bindings[0].live.mirrored_bytes.load(Ordering::Relaxed),
        frame.len() as u64
    );
    let mirror_req = bindings[2]
        .tx_pipeline
        .pending_tx_prepared
        .front()
        .expect("#15251: NAT64 mirror clone must be queued on the analyzer binding");
    assert!(mirror_req.mirror_clone);
    assert_eq!(
        bindings[2]
            .umem
            .area()
            .slice(mirror_req.offset as usize, mirror_req.len as usize)
            .expect("mirrored NAT64 frame"),
        frame.as_slice(),
        "#15251: the mirror clone must carry the rewritten (NAT64) wire frame"
    );
}
