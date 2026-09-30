//! #6710 negative-cache / lladdr-less-egress cell, split out of
//! `neighbor_dispatch.rs`'s `mirror_tests` so that file stays under the
//! 1500 LOC [WATCH] modularity floor. It is a CHILD of `mirror_tests`, so the
//! private fixtures there (`push_pending`, `resolved_neighbor_decision`,
//! `pending_neighbor_meta`, `build_ipv4_test_packet`, ...) are in scope via
//! `use super::*` with no visibility changes.

use super::*;
/// #6710 — THE FIX, at the only site in this chain a test can execute.
///
/// The dead-host negative cache (#1651 B3) is armed by a pending_neigh
/// TIMEOUT, and its escape hatch is resolved-neighbor-wins: the entry is
/// evicted the moment the host answers. An IPsec xfrmi has no link-layer
/// address, so it has nothing to answer with — the escape can never fire
/// and the arm/expire cycle repeats for as long as the tunnel carries
/// traffic. Every armed window recycles the frame at the top of the
/// MissingNeighbor arm (`break 'missing_neighbor RecycleAndContinue`),
/// which skips the fall-through to the slow-path reinject, and that
/// reinject is the ONLY way a LAN→tunnel packet reaches the kernel XFRM
/// stack at all, since an xfrmi gets no AF_XDP binding.
///
/// So the cache is not paying for a dead host here; it is dropping
/// permitted, policy-evaluated traffic on a healthy tunnel. This asserts
/// the timeout no longer arms it for such an egress.
///
/// The NEGATIVE CONTROL is the load-bearing half. Without it this cell
/// would pass equally well against a change that disabled #1651 outright,
/// which would reopen the multi-hop-scan exhaustion the cache exists for.
#[test]
fn lan_to_xfrmi_timeout_does_not_arm_the_dead_host_cache_6710() {
    // egress_ifindex 80 is what resolved_neighbor_decision resolves to.
    const XFRMI_EGRESS: i32 = 80;

    fn timed_out_arms_cache(lladdrless: bool) -> bool {
        let mut bindings = vec![
            BindingWorker::new_for_mirror_test(0, 0, 11, 0),
            BindingWorker::new_for_mirror_test(1, 0, 22, 0),
        ];
        let original_frame = build_ipv4_test_packet(0);
        // SAFETY: single-threaded test over a UMEM created just above; no
        // other borrow into [0, len) exists and the mutable slice is
        // consumed by the immediate copy_from_slice.
        unsafe {
            bindings[0]
                .umem
                .area()
                .slice_mut_unchecked(0, original_frame.len())
        }
        .expect("ingress frame")
        .copy_from_slice(&original_frame);

        let next_hop = IpAddr::V4(Ipv4Addr::new(10, 5, 5, 2));
        let meta = pending_neighbor_meta(original_frame.len());
        push_pending(
            &mut bindings[0],
            PendingNeighPacket {
                addr: 0,
                desc: XdpDesc {
                    addr: 0,
                    len: original_frame.len() as u32,
                    options: 0,
                },
                meta,
                fabric_ingress_zone: None,
                decision: resolved_neighbor_decision(next_hop),
                flow_key: Some(test_session_key(12345, 443)),
                queued_ns: 0,
                // Every probe already fired; an xfrmi never resolves.
                probe_attempts: PROBE_SCHEDULE_NS.len() as u8,
            },
        );

        let mut forwarding = ForwardingState::default();
        if lladdrless {
            forwarding.lladdrless_egress.insert(XFRMI_EGRESS);
        }
        let lookup = WorkerBindingLookup::from_bindings(&bindings);
        let mirror_targets = MirrorTargetMap::default();
        let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
        let mut shared_recycles = Vec::new();
        let area = bindings[0].umem.area() as *const MmapArea;
        let (left, rest) = bindings.split_at_mut(0);
        let (binding, right) = rest.split_first_mut().expect("ingress binding");

        let now_ns = PENDING_NEIGH_TIMEOUT_NS + 1;
        let recent_exceptions = std::sync::Arc::new(std::sync::Mutex::new(
            crate::afxdp::ExceptionEventRing::new(),
        ));
        let mut debug_counters = crate::afxdp::DebugPollCounters::default();
        retry_pending_neigh(
            binding,
            left,
            0,
            right,
            &lookup,
            &mirror_targets,
            &forwarding,
            &dynamic_neighbors,
            None,
            now_ns,
            // SAFETY: as in the sibling timeout test — `area` was cast
            // from a `&MmapArea` borrowed out of bindings[0].umem above,
            // the Rc-backed allocation outlives this call, the split
            // borrows cover disjoint binding state, and the test is
            // single-threaded.
            unsafe { &*area },
            &mut shared_recycles,
            None,
            &mut BatchCounters::default(),
            &recent_exceptions,
            &mut debug_counters,
        );

        assert!(
            bindings[0].pending_neigh.is_empty(),
            "premise: the timeout must still DROP the packet and drain the \
             queue in both configurations — this change is about the cache, \
             not about holding the frame longer",
        );
        let key = (XFRMI_EGRESS, next_hop);
        crate::afxdp::neg_neigh::neg_neigh_active(
            &mut bindings[0].neg_neigh_cache,
            &key,
            now_ns,
        )
    }

    assert!(
        !timed_out_arms_cache(true),
        "a timeout on an lladdr-less egress ARMED the dead-host cache. The \
         next 3s of permitted LAN→tunnel packets then fast-fail and are \
         recycled BEFORE the slow-path reinject, which is the only path to \
         the kernel XFRM stack — and because an xfrmi can never resolve a \
         neighbor, resolved-neighbor-wins never evicts it, so the cycle \
         repeats indefinitely on a healthy tunnel (#6710)",
    );
    assert!(
        timed_out_arms_cache(false),
        "a timeout on an ORDINARY egress no longer arms the dead-host cache. \
         The #1651 B3 protection must keep working everywhere else — without \
         it a multi-hop scan re-buffers every window and exhausts the \
         distinct-hop cap. The fix must be keyed on the egress, not a \
         blanket disable",
    );
}


