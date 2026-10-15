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

    #[test]
    fn missing_neighbor_probe_path_is_globally_throttled_and_borrows_name() {
        let poll = include_str!("mod.rs");
        let start = poll
            .find("let throttle_key = (neigh_if, next_hop);")
            .expect("MissingNeighbor probe key");
        let end = poll[start..]
            .find("// #5174: NAT64 MissingNeighbor fail-closed.")
            .map(|offset| start + offset)
            .expect("end of probe block");
        let probe = &poll[start..end];
        assert!(
            probe.contains("let is_probe_throttled = probe_throttled("),
            "native, NAT64, capacity-drop, and tunnel probes share the per-key window"
        );
        assert!(
            probe.contains(".map(String::as_str)"),
            "poll-loop probe borrows interface name rather than allocating a String"
        );
        assert!(
            !probe.contains(".cloned()"),
            "poll-loop probe must not clone the interface name"
        );
        assert!(
            !probe.contains("throttle.clear()"),
            "probe overflow must preserve other keys' rate-limit windows"
        );
    }
}
