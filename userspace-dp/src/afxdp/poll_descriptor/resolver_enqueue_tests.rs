use super::*;

#[cfg(test)]
mod try_enqueue_resolver_tests {
    use super::*;
    use crate::afxdp::neighbor_resolver::{NeighborResolver, ResolveItem, ResolverCounters};
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;
    use std::sync::atomic::AtomicU64;
    use std::sync::mpsc;

    fn make_resolver() -> (NeighborResolver, mpsc::Receiver<ResolveItem>) {
        let (tx, rx) = mpsc::sync_channel::<ResolveItem>(8);
        let resolver = NeighborResolver::new(
            tx,
            Arc::new(ResolverCounters::default()),
            Arc::new(AtomicU64::new(0)),
            Arc::new(crate::afxdp::neighbor_latency::NeighborLatencyHist::default()),
            Arc::new(AtomicU64::new(0)),
            Arc::new(AtomicU64::new(0)),
        );
        (resolver, rx)
    }

    #[test]
    fn try_enqueue_resolver_throttles_within_window_and_bounds_map() {
        let (resolver, rx) = make_resolver();
        let mut throttle: FastMap<(i32, IpAddr), u64> = FastMap::default();
        let mut names: FastMap<i32, String> = FastMap::default();
        names.insert(12, "ge-0-0-2.80".to_string());
        let key = (12, IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)));

        // First call enqueues and records the throttle entry.
        assert!(try_enqueue_resolver(
            &resolver,
            &mut throttle,
            &names,
            key,
            1_000
        ));
        assert_eq!(rx.try_recv().expect("first enqueue").ifindex, 12);
        assert!(throttle.contains_key(&key));

        // Second call within RESOLVER_ENQUEUE_THROTTLE_NS is throttled: no
        // enqueue (storm bound — at most one per key per window).
        assert!(!try_enqueue_resolver(
            &resolver,
            &mut throttle,
            &names,
            key,
            1_000 + RESOLVER_ENQUEUE_THROTTLE_NS - 1
        ));
        assert!(rx.try_recv().is_err(), "throttled call must not enqueue");

        // After the window elapses, it enqueues again.
        assert!(try_enqueue_resolver(
            &resolver,
            &mut throttle,
            &names,
            key,
            1_000 + RESOLVER_ENQUEUE_THROTTLE_NS
        ));
        assert_eq!(rx.try_recv().expect("post-window enqueue").ifindex, 12);
    }

    #[test]
    fn try_enqueue_resolver_skips_when_iface_has_no_name() {
        let (resolver, rx) = make_resolver();
        let mut throttle: FastMap<(i32, IpAddr), u64> = FastMap::default();
        let names: FastMap<i32, String> = FastMap::default(); // empty
        let key = (362, IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)));
        // No name for the ifindex ⇒ no enqueue, no throttle entry.
        assert!(!try_enqueue_resolver(
            &resolver,
            &mut throttle,
            &names,
            key,
            1_000
        ));
        assert!(rx.try_recv().is_err());

        assert!(throttle.is_empty());
    }

    #[test]
    fn throttle_reclaim_preserves_live_rate_limits() {
        let mut throttle: FastMap<(i32, IpAddr), u64> = FastMap::default();
        let mut names: FastMap<i32, String> = FastMap::default();
        names.insert(12, "ge-0-0-2.80".to_string());
        for i in 0..(MAX_NEG_NEIGH_CACHE - 1) {
            throttle.insert(
                (
                    12,
                    IpAddr::V4(Ipv4Addr::new(10, 0, (i / 255) as u8, (i % 255) as u8)),
                ),
                1_000,
            );
        }
        let protected = (12, IpAddr::V4(Ipv4Addr::new(10, 1, 0, 1)));
        throttle.insert(protected, 1_001);
        assert_eq!(throttle.len(), MAX_NEG_NEIGH_CACHE);
        let new_key = (12, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)));
        assert!(note_kernel_probe(&mut throttle, &names, new_key, 1_002));
        assert!(throttle.len() <= MAX_NEG_NEIGH_CACHE);
        assert!(
            throttle.contains_key(&protected),
            "an overflow must not wipe unrelated active throttle windows"
        );
        assert!(
            probe_throttled(&throttle, &protected, 1_002),
            "the protected key remains rate-limited"
        );
        assert!(probe_throttled(&throttle, &new_key, 1_002));
    }

    // #13762: behavioral poll-loop coverage for the capacity/NAT64
    // MissingNeighbor probe bound. Two identical permitted NAT64 packets
    // whose extracted-IPv4 next-hop (172.16.80.1 on ifindex 12) is
    // unresolved are driven through the real descriptor path within one
    // frozen 100ms window. The NAT64 fail-closed arm records the probe
    // attempt via note_kernel_probe instead of buffering the frame, so
    // the first packet must consume exactly one throttle window and the
    // second must observe that same window without adding another entry.
    // #14661: a discarded NAT64 packet emits NO wire probe at all (the
    // probe is deferred to committed seeds only); the throttle-record
    // assertions below still fail if capacity/NAT64 stops recording.
    #[test]
    fn nat64_missing_neighbor_poll_path_consumes_one_throttle_window() {
        use crate::afxdp::tests_support::{
            build_txn_tcp_syn_frame_v6, lan_to_wan_permit, nat64_snapshot, txn_ha_state,
            txn_run_descriptor_checked,
        };
        use crate::afxdp::build_forwarding_state;
        use crate::afxdp::{
            kernel_arp_probe_test_capture_count, start_kernel_arp_probe_test_capture,
            stop_kernel_arp_probe_test_capture, TCP_FLAG_SYN, USERSPACE_META_MAGIC,
            USERSPACE_META_VERSION,
        };
        use crate::ip_proto::PROTO_TCP;
        use crate::session::SessionTable;
        use std::net::Ipv6Addr;

        let mut snapshot = nat64_snapshot(lan_to_wan_permit("8.8.8.8/32", "permit-nat64-v4-13762"));
        snapshot.neighbors.clear();
        let forwarding = build_forwarding_state(&snapshot);
        let ha_state = txn_ha_state();
        let mut binding = crate::afxdp::worker::BindingWorker::new_for_mirror_test(0, 0, 24, 0);
        binding.interface = std::sync::Arc::<str>::from("reth1.0");
        let mut sessions = SessionTable::new();

        let src: Ipv6Addr = "2001:559:8585:ef00::102".parse().expect("src v6");
        let dst: Ipv6Addr = "64:ff9b::808:808".parse().expect("nat64 dst");
        let frame = build_txn_tcp_syn_frame_v6(
            src,
            dst,
            12345,
            443,
            crate::afxdp::tests_support::TEST_LAN_MAC,
        );
        let meta = crate::afxdp::types::UserspaceDpMeta {
            flow_src_addr: src.octets(),
            flow_dst_addr: dst.octets(),
            magic: USERSPACE_META_MAGIC,
            version: USERSPACE_META_VERSION,
            length: std::mem::size_of::<crate::afxdp::types::UserspaceDpMeta>() as u16,
            ingress_ifindex: 24,
            l3_offset: 14,
            l4_offset: 54,
            payload_offset: 74,
            pkt_len: (frame.len() - 14) as u16,
            addr_family: libc::AF_INET6 as u8,
            protocol: PROTO_TCP,
            tcp_flags: TCP_FLAG_SYN,
            config_generation: 7,
            fib_generation: 9,
            ..crate::afxdp::types::UserspaceDpMeta::default()
        };
        let throttle_key = (12, IpAddr::V4(Ipv4Addr::new(172, 16, 80, 1)));

        start_kernel_arp_probe_test_capture();
        let (_batch1, dbg1) = txn_run_descriptor_checked(
            &mut binding,
            &mut sessions,
            &forwarding,
            &ha_state,
            &frame,
            meta,
            true,
        );
        assert_eq!(dbg1.nat64_missing_neigh_drop, 1);
        assert_eq!(
            kernel_arp_probe_test_capture_count(),
            0,
            "#14661: a discarded NAT64 miss must not invoke a kernel probe"
        );
        let first_probe_at = *binding
            .resolver_enqueue_throttle
            .get(&throttle_key)
            .expect("first NAT64 miss must consume the kernel-probe throttle window");
        assert_eq!(binding.resolver_enqueue_throttle.len(), 1);

        let (_batch2, dbg2) = txn_run_descriptor_checked(
            &mut binding,
            &mut sessions,
            &forwarding,
            &ha_state,
            &frame,
            crate::afxdp::types::UserspaceDpMeta { ..meta },
            true,
        );
        assert_eq!(dbg2.nat64_missing_neigh_drop, 1);
        assert_eq!(
            kernel_arp_probe_test_capture_count(),
            0,
            "#14661: discarded NAT64 misses never invoke a kernel probe"
        );
        stop_kernel_arp_probe_test_capture();
        assert_eq!(
            binding.resolver_enqueue_throttle.len(),
            1,
            "second same-key NAT64 miss within the window must not consume another probe window"
        );
        assert_eq!(
            binding.resolver_enqueue_throttle.get(&throttle_key),
            Some(&first_probe_at),
            "second same-key NAT64 miss must preserve the first probe timestamp"
        );
        assert!(probe_throttled(
            &binding.resolver_enqueue_throttle,
            &throttle_key,
            first_probe_at,
        ));
    }
}
