//! #7156: the `retry_pending_neigh` dispatch/mirror test suite, extracted from
//! `neighbor_dispatch.rs`.
//!
//! Moved rather than grown in place: that file sat at 1493 LOC, seven lines
//! under the 1500 [WATCH] modularity floor, so the #7156 sweep tests could not
//! be added to it without crossing. Extracting the tests leaves the production
//! sweep at ~1100 LOC with room to be read.
//!
//! Included with `#[path]` from its parent, so `super::` still resolves to
//! `neighbor_dispatch` and every existing import is unchanged by the move.
    use super::*;
    use crate::afxdp::tx::test_support::{build_ipv4_test_packet, test_session_key};
    use std::sync::atomic::Ordering;

    /// #1771 §2.2: `pending_neigh` is keyed by `(egress_ifindex, next_hop)`.
    /// Test helper that buffers one packet under its derived key, preserving
    /// the old `push_back`-one-packet ergonomics for the retry-sweep tests.
    ///
    /// NOTE: this is single-entry seeding — it `insert`s (last-write-wins),
    /// NOT the production admission keep-oldest+recycle-duplicate semantics
    /// (poll_descriptor). Every test here seeds one packet per distinct key,
    /// so the distinction never bites; do not reuse this to model duplicate
    /// admission.
    fn push_pending(b: &mut BindingWorker, pkt: PendingNeighPacket) {
        let key = (
            pkt.decision.resolution.egress_ifindex,
            pkt.decision
                .resolution
                .next_hop
                .expect("test pending pkt has a next_hop"),
        );
        let due = next_due_for_pending(pkt.queued_ns, pkt.queued_ns, pkt.probe_attempts,
            PENDING_NEIGH_TIMEOUT_NS, PROBE_SCHEDULE_NS);
        b.pending_neigh.insert(key, pkt);
        b.pending_neigh_schedule.arm(key, due);
    }

    fn resolved_neighbor_decision(next_hop: IpAddr) -> SessionDecision {
        SessionDecision { resolution: ForwardingResolution {
            disposition: ForwardingDisposition::MissingNeighbor,
            local_ifindex: 0,
            egress_ifindex: 80,
            tx_ifindex: 22,
            tunnel_endpoint_id: 0,
            next_hop: Some(next_hop),
            neighbor_mac: None,
            src_mac: Some([0x02, 0xbf, 0x72, 0x16, 0x00, 0x01]),
            tx_vlan_id: 0,
        }, nat: NatDecision::default(), install_table_domain: 0, install_table_check: 0 }
    }

    fn pending_neighbor_meta(frame_len: usize) -> UserspaceDpMeta {
        UserspaceDpMeta {
            ingress_ifindex: 11,
            l3_offset: 14,
            l4_offset: 34,
            pkt_len: frame_len as u16,
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            ..UserspaceDpMeta::default()
        }
    }

    /// #7156 fixture: `n` distinct unresolved next-hops on one binding, all
    /// queued at `queued_ns`. Returns the bindings so the caller drives the
    /// sweep against them.
    ///
    /// Uses the map's own length as the visit counter: every key here is past
    /// its timeout when swept at a late `now_ns`, so a visited key is REMOVED.
    /// That counts visits through production-visible state rather than a
    /// test-only counter wired into the sweep.
    fn pending_neigh_fixture_7156(n: usize, queued_ns: u64) -> Vec<BindingWorker> {
        let mut bindings = vec![BindingWorker::new_for_mirror_test(0, 0, 11, 0)];
        let frame = build_ipv4_test_packet(0);
        let meta = pending_neighbor_meta(frame.len());
        for i in 0..n {
            let nh = IpAddr::V4(Ipv4Addr::new(
                10,
                ((i >> 16) & 0xff) as u8,
                ((i >> 8) & 0xff) as u8,
                (i & 0xff) as u8,
            ));
            push_pending(
                &mut bindings[0],
                PendingNeighPacket {
                    addr: 0,
                    desc: XdpDesc { addr: 0, len: frame.len() as u32, options: 0 },
                    meta,
                    decision: resolved_neighbor_decision(nh),
                    flow_key: None,
                    queued_ns,
                    probe_attempts: 0,
                },
            );
        }
        assert_eq!(bindings[0].pending_neigh.len(), n, "fixture must hold n keys");
        bindings
    }

    /// Drive one sweep against `bindings[0]` at `now_ns`, with an optional
    /// pre-populated dynamic neighbor map.
    fn sweep_7156(
        bindings: &mut [BindingWorker],
        dynamic_neighbors: &Arc<ShardedNeighborMap>,
        now_ns: u64,
    ) {
        let forwarding = ForwardingState::default();
        let lookup = WorkerBindingLookup::from_bindings(bindings);
        let mirror_targets = MirrorTargetMap::default();
        let mut shared_recycles = Vec::new();
        let area = bindings[0].umem.area() as *const MmapArea;
        let (left, rest) = bindings.split_at_mut(0);
        let (binding, right) = rest.split_first_mut().expect("binding");
        retry_pending_neigh(
            binding, left, 0, right, &lookup, &mirror_targets, &forwarding,
            dynamic_neighbors, None, now_ns,
            // SAFETY: `area` was cast from the &MmapArea borrowed out of
            // bindings[0].umem above; the allocation outlives this call, the
            // split borrows cover disjoint binding state, and this is
            // single-threaded.
            unsafe { &*area },
            &mut shared_recycles,
            None,
            &mut BatchCounters::default(),
        );
    }

    /// #7156 acceptance 1: with a full pending map and NOTHING due, a sweep must
    /// do no per-key work.
    ///
    /// This is the regime the issue is about — an idle binding holding stale
    /// next-hops — and the one the old sweep paid ~182 us for, twice per poll,
    /// walking all 4096 keys and allocating ~98 KiB. Asserted through state
    /// rather than timing: no key may be touched, so nothing is removed and
    /// nothing is recycled.
    ///
    /// FAIL-ON-REVERT: restore the `binding.pending_neigh.keys().collect()` walk
    /// and every key is visited; with `now_ns` before any timeout they survive,
    /// but the probe-attempt and recycle assertions below still bind the visit.
    #[test]
    fn a_sweep_with_nothing_due_touches_no_pending_key_7156() {
        const N: usize = 4096;
        const QUEUED: u64 = 1_000_000_000;
        let mut bindings = pending_neigh_fixture_7156(N, QUEUED);
        let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
        // 100 ns after queueing: first probe slot (10 ms), the 50 ms recheck and
        // the 2 s timeout are all in the future, so no key is due.
        sweep_7156(&mut bindings, &dynamic_neighbors, QUEUED + 100);

        // THE assertion. The removal/recycle checks below cannot see this
        // defect: with nothing due, walking all 4096 keys finds nothing to do
        // and leaves exactly the same state as walking none. Only the visit
        // counter distinguishes "did no work" from "did 4096 lookups, each
        // taking a neighbor shard mutex, and found nothing".
        assert_eq!(
            bindings[0]
                .live
                .pending_neigh_visits
                .load(Ordering::Relaxed),
            0,
            "a sweep with nothing due must touch NO pending key. {N} visits \
             here is the pre-#7156 full-map walk: ~182 us and ~98 KiB per \
             sweep, twice per poll, on a binding that has nothing to do"
        );
        assert_eq!(
            bindings[0].pending_neigh.len(),
            N,
            "no key is due, so none may be removed"
        );
        assert!(
            bindings[0].tx_pipeline.pending_fill_frames.is_empty(),
            "no key is due, so no frame may be recycled"
        );
        assert!(
            bindings[0].pending_neigh.values().all(|p| p.probe_attempts == 0),
            "no key is due, so no probe may have been attempted"
        );
    }

    /// #7156 acceptance 2: when MORE keys are due than the budget allows, a
    /// sweep makes bounded progress, and successive sweeps drain the backlog
    /// without starving anyone.
    ///
    /// Exactly `PENDING_NEIGH_SWEEP_BUDGET` keys are serviced per sweep — the
    /// bound — and the count keeps falling by that step until the map empties,
    /// which is the no-starvation half: a key deferred by the budget is not
    /// deferred for ever, and no key is serviced twice while another waits (the
    /// step would be short if it were).
    #[test]
    fn due_keys_beyond_the_budget_drain_without_starvation_7156() {
        const N: usize = 4096;
        const QUEUED: u64 = 1_000_000_000;
        let mut bindings = pending_neigh_fixture_7156(N, QUEUED);
        let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
        // Well past the 2 s timeout: every key is due, and a visited key is
        // removed, so the map length counts exactly the keys not yet serviced.
        let now = QUEUED + PENDING_NEIGH_TIMEOUT_NS + 1_000_000_000;

        sweep_7156(&mut bindings, &dynamic_neighbors, now);
        assert_eq!(
            bindings[0].pending_neigh.len(),
            N - PENDING_NEIGH_SWEEP_BUDGET,
            "one sweep must service exactly the budget, not all {N} due keys — \
             an unbounded sweep empties the map here"
        );
        assert_eq!(
            bindings[0]
                .live
                .pending_neigh_visits
                .load(Ordering::Relaxed),
            PENDING_NEIGH_SWEEP_BUDGET as u64,
            "the budget must bound VISITS, not just removals — a sweep that \
             looked at every key and only acted on the budget would leave the \
             per-key cost exactly where #7156 found it"
        );

        let mut sweeps = 1;
        while !bindings[0].pending_neigh.is_empty() {
            let before = bindings[0].pending_neigh.len();
            sweep_7156(&mut bindings, &dynamic_neighbors, now);
            let after = bindings[0].pending_neigh.len();
            assert_eq!(
                before - after,
                PENDING_NEIGH_SWEEP_BUDGET.min(before),
                "sweep {sweeps}: each sweep must service a full budget of DUE \
                 keys. A short step means budget was spent re-visiting a key \
                 already serviced while others still waited"
            );
            sweeps += 1;
            assert!(sweeps <= N / PENDING_NEIGH_SWEEP_BUDGET + 2, "must terminate");
        }
        assert_eq!(
            sweeps,
            N / PENDING_NEIGH_SWEEP_BUDGET,
            "the backlog must drain in exactly ceil(N/budget) sweeps"
        );
    }

    /// #7156: a key may be visited at most ONCE per sweep, so the budget bounds
    /// distinct keys and not merely iterations.
    ///
    /// The path that makes this non-trivial is the iface-name miss: `probe_due`
    /// is true but `forwarding.ifindex_to_name` has no entry, so no probe fires
    /// and `probe_attempts` is deliberately NOT advanced — the existing contract
    /// is that the key retries this slot next sweep. Its next deadline is
    /// therefore its probe slot, which is already in the PAST, so without the
    /// clamp in `next_due_for_pending` it re-arms as due, returns to the head of
    /// the heap, and is popped again inside the same sweep. One key would then
    /// consume the whole budget while 4095 others waited — the starvation the
    /// budget is supposed to prevent, reintroduced by the fix.
    ///
    /// Asserted as drainage at a FIXED `now`: if each sweep takes `budget`
    /// distinct keys, ceil(N/budget) sweeps exhaust everything due and one more
    /// does nothing. If keys re-arm into the past, sweeps never stop finding
    /// work at that same instant.
    ///
    /// This is the cell the starvation test above CANNOT provide: there every
    /// key is past its timeout and is removed on its visit, so nothing re-arms
    /// and the clamp is never reached. Deleting the clamp leaves that test green.
    #[test]
    fn a_key_is_visited_at_most_once_per_sweep_7156() {
        const N: usize = 256;
        const QUEUED: u64 = 1_000_000_000;
        let mut bindings = pending_neigh_fixture_7156(N, QUEUED);
        let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
        // Past the first probe slot, far short of the timeout. The fixture's
        // ForwardingState::default() has an empty ifindex_to_name, so this is
        // exactly the probe-due / name-miss state.
        let now = QUEUED + PROBE_SCHEDULE_NS[0] + 1;

        let sweeps = N / PENDING_NEIGH_SWEEP_BUDGET;
        for _ in 0..sweeps {
            sweep_7156(&mut bindings, &dynamic_neighbors, now);
        }
        assert_eq!(
            bindings[0].live.pending_neigh_visits.load(Ordering::Relaxed),
            N as u64,
            "after ceil(N/budget) sweeps every key must have been visited \
             exactly once. More than {N} means a key was re-visited while \
             another still waited"
        );
        assert_eq!(
            bindings[0].pending_neigh.len(),
            N,
            "none of these keys is resolved or timed out, so all must survive"
        );

        // The discriminator: everything due has now been serviced, so a further
        // sweep at the SAME instant must find nothing.
        let before = bindings[0].live.pending_neigh_visits.load(Ordering::Relaxed);
        sweep_7156(&mut bindings, &dynamic_neighbors, now);
        assert_eq!(
            bindings[0].live.pending_neigh_visits.load(Ordering::Relaxed),
            before,
            "a sweep after the backlog is drained must do NOTHING at the same \
             instant. Work here means keys re-armed into the past and are being \
             serviced repeatedly within one instant, starving the rest"
        );
    }

    /// #7156: the deadline queue must hold at most ONE entry per live pending
    /// key, across any number of resolution passes.
    ///
    /// This is the issue's "must not admit attacker-driven unbounded tombstones"
    /// requirement, arriving by the other door — duplicates rather than
    /// tombstones. A resolution pass reaches keys by walking the MAP without
    /// popping them, so their heap entry is still live; re-arming there adds a
    /// second entry for the same key. Every subsequent pass adds another, so the
    /// heap grows by the pending population per pass and never shrinks, and each
    /// duplicate is a wasted budget slot at some future sweep.
    ///
    /// Driven with a neighbour that resolves NOTHING pending, so the pass
    /// happens and every key survives it — the shape that duplicates. A pass
    /// that dispatched its keys would hide the defect by removing them.
    #[test]
    fn resolution_passes_do_not_duplicate_schedule_entries_7156() {
        const N: usize = 64;
        const QUEUED: u64 = 1_000_000_000;
        let mut bindings = pending_neigh_fixture_7156(N, QUEUED);
        let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
        assert_eq!(
            bindings[0].pending_neigh_schedule.len(),
            N,
            "precondition: one armed entry per key at insert"
        );

        for pass in 1..=3u16 {
            // A neighbour on an ifindex nothing is waiting on: it bumps the
            // insert generation, so the sweep takes the resolution path, but
            // resolves no pending key, so all N survive the walk.
            dynamic_neighbors.insert(
                (9_000 + pass as i32, IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1))),
                NeighborEntry { mac: [2, 2, 2, 2, 2, pass as u8] },
            );
            sweep_7156(&mut bindings, &dynamic_neighbors, QUEUED + 100);

            assert_eq!(
                bindings[0].pending_neigh.len(),
                N,
                "pass {pass}: nothing resolvable and nothing due, so every key \
                 must survive — otherwise this fixture is not exercising the \
                 duplicating shape"
            );
            assert_eq!(
                bindings[0].pending_neigh_schedule.len(),
                N,
                "pass {pass}: the schedule must still hold exactly one entry \
                 per live key. {} entries for {N} keys means each resolution \
                 pass re-armed keys it never popped, so the queue grows by the \
                 pending population every time a neighbour appears and never \
                 shrinks (#7156)",
                bindings[0].pending_neigh_schedule.len()
            );
        }
    }

    /// #7156 acceptance 3: a neighbour that resolves is dispatched on the NEXT
    /// sweep, not when the key's own deadline happens to come round.
    ///
    /// This is the property deadline ordering alone destroys, and the reason the
    /// generation gate exists. A key has nothing scheduled between its last
    /// probe (queued + 260 ms) and its timeout (2 s here), so a neighbour that
    /// appears at 300 ms would go unseen until the key TIMED OUT and its packet
    /// was dropped — a correctness regression, not a latency one.
    ///
    /// The resolved key is deliberately the LAST one inserted, so it sits behind
    /// 4095 others: "promptly, not queued behind thousands of future deadlines".
    ///
    /// FAIL-ON-REVERT: delete the `resolution_pass` gate (leave only the
    /// deadline path) and the key is still pending after the sweep.
    #[test]
    fn a_neighbour_that_resolves_is_dispatched_on_the_next_sweep_7156() {
        const N: usize = 4096;
        const QUEUED: u64 = 1_000_000_000;
        let mut bindings = pending_neigh_fixture_7156(N, QUEUED);
        let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());

        // The tail key, and the egress its decision resolved to.
        let tail = IpAddr::V4(Ipv4Addr::new(10, 0, 15, 255));
        let key = (
            resolved_neighbor_decision(tail).resolution.egress_ifindex,
            tail,
        );
        assert!(
            bindings[0].pending_neigh.contains_key(&key),
            "precondition: the tail key must be pending"
        );

        // Control: with nothing resolved, a sweep at this time leaves it alone —
        // so the dispatch below is the resolution being noticed, not the key
        // simply being due.
        sweep_7156(&mut bindings, &dynamic_neighbors, QUEUED + 100);
        assert_eq!(
            bindings[0].pending_neigh.len(),
            N,
            "control: nothing resolved and nothing due, so nothing moves"
        );

        // The neighbour appears, mid-schedule: past every probe slot, far short
        // of the timeout — precisely the window with no deadline of its own.
        dynamic_neighbors.insert(key, NeighborEntry { mac: [1, 2, 3, 4, 5, 6] });
        sweep_7156(&mut bindings, &dynamic_neighbors, QUEUED + 300_000_000);

        assert!(
            !bindings[0].pending_neigh.contains_key(&key),
            "a resolved next-hop must leave pending_neigh on the very next \
             sweep. Still pending here means the packet waits for its timeout \
             and is then DROPPED as never-resolved (#7156)"
        );
        assert_eq!(
            bindings[0].pending_neigh.len(),
            N - 1,
            "only the resolved key may be consumed; the rest are neither \
             resolved nor timed out"
        );
    }

    /// #7156 MEASUREMENT (not a fix): what does the O(all-keys) sweep
    /// actually cost at a realistic and at a worst-case pending population?
    ///
    /// Steady state per key on the "still unresolved" path is: one
    /// `pending_neigh` hash lookup, a timeout compare, one `forwarding.neighbors`
    /// hash lookup, one `dynamic_neighbors` lookup which takes a SHARD MUTEX,
    /// and a `probe_due` evaluation. Plus one fresh `Vec<(i32, IpAddr)>` of the
    /// whole key set per sweep, and the sweep runs TWICE per poll iteration.
    #[test]
    #[ignore = "MEASUREMENT: not an assertion; run with --ignored --nocapture"]
    fn measure_pending_neigh_sweep_cost_7156() {
        use std::time::Instant;
        let key_bytes = std::mem::size_of::<(i32, IpAddr)>();
        println!("\nsize_of::<(i32, IpAddr)>() = {key_bytes} bytes");
        // Read the columns knowing what each is: "nothing-due" is a warm
        // steady-state average over many reps and is the regime an idle worker
        // holding a backlog actually pays, twice per poll. "all-due" is ONE
        // COLD sweep, so it carries first-touch misses over the whole map and is
        // noisy and pessimistic; it rises with n despite `visited` being capped
        // because a larger map gives worse locality per random-key lookup, not
        // because the sweep does more work. The load-bearing column is
        // `visited`: it is the budget, flat at 64, where the pre-fix sweep
        // visited every one of n.
        println!(" N     nothing-due    all-due  visited   pre-fix Vec/sweep");
        for n in [0usize, 1, 64, 1024, 4096] {
            let mut bindings = vec![BindingWorker::new_for_mirror_test(0, 0, 11, 0)];
            let frame = build_ipv4_test_packet(0);
            let meta = pending_neighbor_meta(frame.len());
            for i in 0..n {
                // Distinct next-hops => distinct keys, so the map really holds n.
                let nh = IpAddr::V4(Ipv4Addr::new(
                    10,
                    ((i >> 16) & 0xff) as u8,
                    ((i >> 8) & 0xff) as u8,
                    (i & 0xff) as u8,
                ));
                push_pending(
                    &mut bindings[0],
                    PendingNeighPacket {
                        addr: 0,
                        desc: XdpDesc { addr: 0, len: frame.len() as u32, options: 0 },
                        meta,
                        decision: resolved_neighbor_decision(nh),
                        flow_key: None,
                        // queued "now" so nothing times out during the run.
                        queued_ns: 1_000_000_000,
                        probe_attempts: 0,
                    },
                );
            }
            assert_eq!(bindings[0].pending_neigh.len(), n, "fixture must hold n keys");
            // Empty forwarding: every key misses both neighbor maps, which is
            // the UNRESOLVED steady state the issue is about. ifindex_to_name is
            // empty too, so no probe ever fires and the loop body is the pure
            // per-key scheduler cost.
            let forwarding = ForwardingState::default();
            let lookup = WorkerBindingLookup::from_bindings(&bindings);
            let mirror_targets = MirrorTargetMap::default();
            let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
            let mut shared_recycles = Vec::new();
            let area = bindings[0].umem.area() as *const MmapArea;

            let reps = if n > 512 { 200 } else { 5_000 };
            let (left, rest) = bindings.split_at_mut(0);
            let (binding, right) = rest.split_first_mut().expect("binding");
            // Warm.
            for _ in 0..(reps / 10).max(1) {
                retry_pending_neigh(
                    binding, left, 0, right, &lookup, &mirror_targets, &forwarding,
                    &dynamic_neighbors, None, 1_000_000_100, unsafe { &*area },
                    &mut shared_recycles,
                    None,
                    &mut BatchCounters::default(),
                );
            }
            let t0 = Instant::now();
            for _ in 0..reps {
                retry_pending_neigh(
                    binding, left, 0, right, &lookup, &mirror_targets, &forwarding,
                    &dynamic_neighbors, None, 1_000_000_100, unsafe { &*area },
                    &mut shared_recycles,
                    None,
                    &mut BatchCounters::default(),
                );
            }
            let per = t0.elapsed().as_nanos() as f64 / reps as f64;
            assert_eq!(
                binding.pending_neigh.len(), n,
                "the sweep must not have drained the fixture (would void the timing)"
            );
            // ALL-DUE: advance past the first probe slot so every key is due.
            // This is the worst case the BUDGET has to bound; reporting only the
            // nothing-due column would be a flattering measurement.
            //
            // Timed as a SINGLE sweep on a fresh backlog, deliberately. Looping
            // it measures the wrong thing: the first sweep drains `budget` keys
            // and re-arms them past `now_ns`, so after ceil(n/budget) sweeps at
            // one fixed `now_ns` the queue is drained and every later rep
            // measures the nothing-due path again. The average over a loop is
            // then a blend of the two regimes that belongs to neither, and it
            // gets cheaper as n grows, which is exactly backwards.
            let due_now = 1_000_000_000 + PROBE_SCHEDULE_NS[0] + 5_000_000;
            let t1 = Instant::now();
            retry_pending_neigh(
                binding, left, 0, right, &lookup, &mirror_targets, &forwarding,
                &dynamic_neighbors, None, due_now, unsafe { &*area },
                &mut shared_recycles,
                None,
                &mut BatchCounters::default(),
            );
            let per_due = t1.elapsed().as_nanos() as f64;
            let visited = n.min(PENDING_NEIGH_SWEEP_BUDGET);
            println!(
                "{n:5}  {per:11.0}  {per_due:11.0}  {visited:7}   {:>12}",
                n * key_bytes
            );
        }
    }

    #[test]
    fn retry_pending_neighbor_mirrors_original_frame_before_rewrite() {
        let mut bindings = vec![
            BindingWorker::new_for_mirror_test(0, 0, 11, 0),
            BindingWorker::new_for_mirror_test(1, 0, 22, 0),
            BindingWorker::new_for_mirror_test(2, 0, 33, 0),
        ];
        // §8916 made this fixture's UMEM assumption LOAD-BEARING, so it is now
        // stated instead of inherited.
        //
        // `new_for_mirror_test` gives each binding its own allocation. §8916
        // made a cross-binding forward to a target that does NOT share the
        // ingress UMEM fall back to a copy, because a `PreparedTxRequest`
        // carries an offset into the ingress UMEM and that offset is
        // meaningless in a different one. This cell is about MIRROR IDENTITY
        // -- that the primary forward does not inherit `mirror_clone` -- and
        // it reads that off the prepared queue, so it needs the shared-UMEM
        // case to have a prepared request to read at all.
        //
        // Sharing the allocation keeps the cell measuring what it was written
        // to measure. The cross-UMEM behaviour it no longer exercises is
        // covered directly by
        // `neighbor_retry_foreign_umem_falls_back_to_a_copy_8916` and its
        // shared-UMEM control.
        // ONLY the forward target (index 1) shares. The MIRROR target (index
        // 2) must keep its own allocation: this cell reads the mirrored frame
        // back out of `bindings[2].umem` and asserts it holds PRE-rewrite L2
        // bytes. Sharing that one too makes the mirror read the same memory
        // the in-place rewrite just mutated, and the pre-rewrite assertion
        // fails against post-rewrite bytes -- measured, not reasoned: sharing
        // all three reds this cell with the rewritten MACs in `left`.
        bindings[1].umem = bindings[0].umem.clone();
        let original_frame = build_ipv4_test_packet(0);
        // SAFETY: single-threaded test over a UMEM created just above; no
        // other borrow into [0, len) exists and the mutable slice is
        // consumed by the immediate copy_from_slice before anything else
        // touches the area.
        unsafe {
            bindings[0]
                .umem
                .area()
                .slice_mut_unchecked(0, original_frame.len())
        }
        .expect("ingress frame")
        .copy_from_slice(&original_frame);

        let next_hop = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
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
                decision: resolved_neighbor_decision(next_hop),
                flow_key: Some(test_session_key(12345, 443)),
                queued_ns: 0,
                probe_attempts: 0,
            },
        );

        let mut forwarding = ForwardingState::default();
        forwarding.neighbors.insert(
            (80, next_hop),
            NeighborEntry {
                mac: [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            },
        );
        forwarding.mirror_configs.insert(
            11,
            MirrorRuntimeConfig {
                output_ifindex: 33,
                rate: 0,
            },
        );

        let lookup = WorkerBindingLookup::from_bindings(&bindings);
        let mirror_targets = MirrorTargetMap::default();
        let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
        let mut shared_recycles = Vec::new();
        let area = bindings[0].umem.area() as *const MmapArea;
        let (left, rest) = bindings.split_at_mut(0);
        let (binding, right) = rest.split_first_mut().expect("ingress binding");

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
            1,
            // SAFETY: `area` was cast from `&MmapArea` borrowed out of
            // bindings[0].umem just above; the Rc-backed allocation lives
            // past this call, the split_at_mut borrows cover disjoint
            // binding state (not the umem area), and the test is
            // single-threaded.
            unsafe { &*area },
            &mut shared_recycles,
            None,
            &mut BatchCounters::default(),
        );

        assert!(bindings[0].pending_neigh.is_empty());
        assert_eq!(bindings[0].live.mirrored_packets.load(Ordering::Relaxed), 1);
        assert_eq!(
            bindings[0].live.mirrored_bytes.load(Ordering::Relaxed),
            original_frame.len() as u64
        );

        let mirror_req = bindings[2]
            .tx_pipeline
            .pending_tx_prepared
            .front()
            .expect("mirror prepared request");
        assert!(mirror_req.mirror_clone);
        assert_eq!(mirror_req.egress_ifindex, 33);
        assert_eq!(mirror_req.len, original_frame.len() as u32);
        assert_eq!(
            bindings[2]
                .umem
                .area()
                .slice(mirror_req.offset as usize, mirror_req.len as usize)
                .expect("mirrored frame"),
            original_frame.as_slice(),
            "deferred neighbor path must mirror pre-rewrite L2 bytes",
        );

        let forwarded_req = bindings[1]
            .tx_pipeline
            .pending_tx_prepared
            .front()
            .expect("forwarded prepared request");
        assert!(
            !forwarded_req.mirror_clone,
            "primary forwarding request must not inherit mirror identity",
        );
    }

    /// #1651 B3: a never-resolving pending packet that crosses the timeout
    /// must (a) be dropped (recycled, removed from the queue) and (b) record
    /// its (egress_ifindex, next_hop) in the binding's negative cache so
    /// subsequent cold packets to the same dead host fast-fail.
    #[test]
    fn timed_out_pending_neighbor_records_negative_cache() {
        let mut bindings = vec![
            BindingWorker::new_for_mirror_test(0, 0, 11, 0),
            BindingWorker::new_for_mirror_test(1, 0, 22, 0),
        ];
        let original_frame = build_ipv4_test_packet(0);
        // SAFETY: single-threaded test over a UMEM created just above; no
        // other borrow into [0, len) exists and the mutable slice is
        // consumed by the immediate copy_from_slice before anything else
        // touches the area.
        unsafe {
            bindings[0]
                .umem
                .area()
                .slice_mut_unchecked(0, original_frame.len())
        }
        .expect("ingress frame")
        .copy_from_slice(&original_frame);

        let next_hop = IpAddr::V4(Ipv4Addr::new(172, 16, 80, 137));
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
                decision: resolved_neighbor_decision(next_hop),
                flow_key: Some(test_session_key(12345, 443)),
                queued_ns: 0,
                // All probes already fired; the dst never resolved.
                probe_attempts: PROBE_SCHEDULE_NS.len() as u8,
            },
        );

        // No neighbor for `next_hop` anywhere → unresolved. Use the
        // compile-time fallback timeout (default ForwardingState leaves
        // pending_neigh_timeout_ns == 0).
        let forwarding = ForwardingState::default();
        let lookup = WorkerBindingLookup::from_bindings(&bindings);
        let mirror_targets = MirrorTargetMap::default();
        let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
        let mut shared_recycles = Vec::new();
        let area = bindings[0].umem.area() as *const MmapArea;
        let (left, rest) = bindings.split_at_mut(0);
        let (binding, right) = rest.split_first_mut().expect("ingress binding");

        // now_ns just past the 2s fallback timeout.
        let now_ns = PENDING_NEIGH_TIMEOUT_NS + 1;
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
            // SAFETY: `area` was cast from `&MmapArea` borrowed out of
            // bindings[0].umem just above; the Rc-backed allocation lives
            // past this call, the split_at_mut borrows cover disjoint
            // binding state (not the umem area), and the test is
            // single-threaded.
            unsafe { &*area },
            &mut shared_recycles,
            None,
            &mut BatchCounters::default(),
        );

        // The packet was dropped (recycled to fill ring, queue drained).
        assert!(
            bindings[0].pending_neigh.is_empty(),
            "timed-out pending packet must be dropped",
        );
        // The dead-host key was recorded and is active.
        let key = (80i32, next_hop); // egress_ifindex 80 per resolved_neighbor_decision
        assert!(
            crate::afxdp::neg_neigh::neg_neigh_active(
                &mut bindings[0].neg_neigh_cache,
                &key,
                now_ns,
            ),
            "timed-out dst must be negatively cached",
        );
    }

    // #6710 lives in its own file (neighbor_dispatch/mirror_tests/) so
    // appending it does not push this one past the 1500 LOC [WATCH] modularity
    // floor (pkg/refactoraudit). A child module can see this module's private
    // helpers, so `push_pending`, `resolved_neighbor_decision` and friends are
    // reachable unchanged via `use super::*`.
    // #7156: explicit path — this module's parent moved out of
    // `neighbor_dispatch.rs` into a `#[path]`-loaded sibling file, so the
    // implicit `neighbor_dispatch/mirror_tests/` directory lookup no longer
    // applies. The child file itself is unmoved.
    #[path = "neighbor_dispatch/mirror_tests/xfrmi_6710_tests.rs"]
    mod xfrmi_6710_tests;

    /// #1772: build a worker-facing `NeighborResolver` handle wired to a
    /// fresh latency-telemetry set, so a test can pass it into
    /// `retry_pending_neigh` and read back the recorded dwell / drop /
    /// depth. The channel `rx` is returned so the producer end is not
    /// dropped (which would mark every enqueue Disconnected).
    fn resolver_with_latency() -> (
        Arc<NeighborResolver>,
        std::sync::mpsc::Receiver<crate::afxdp::neighbor_resolver::ResolveItem>,
        Arc<crate::afxdp::neighbor_latency::NeighborLatencyHist>,
        Arc<AtomicU64>,
        Arc<AtomicU64>,
    ) {
        let (tx, rx) = std::sync::mpsc::sync_channel::<crate::afxdp::neighbor_resolver::ResolveItem>(
            crate::afxdp::neighbor_resolver::RESOLVER_QUEUE_DEPTH,
        );
        let dwell = Arc::new(crate::afxdp::neighbor_latency::NeighborLatencyHist::default());
        let drops = Arc::new(AtomicU64::new(0));
        let depth = Arc::new(AtomicU64::new(0));
        let resolver = Arc::new(NeighborResolver::new(
            tx,
            Arc::new(crate::afxdp::neighbor_resolver::ResolverCounters::default()),
            Arc::new(AtomicU64::new(0)),
            dwell.clone(),
            drops.clone(),
            depth.clone(),
        ));
        (resolver, rx, dwell, drops, depth)
    }

    /// #1772 acceptance: a buffered packet with a known `queued_ns` that
    /// resolves at a later `now_ns` records its dwell into the histogram
    /// (correct bucket + count) AND the max-depth high-water gauge is set.
    #[test]
    fn resolved_pending_neighbor_records_dwell_and_depth() {
        let mut bindings = vec![
            BindingWorker::new_for_mirror_test(0, 0, 11, 0),
            BindingWorker::new_for_mirror_test(1, 0, 22, 0),
        ];
        let original_frame = build_ipv4_test_packet(0);
        // SAFETY: single-threaded test over a UMEM created just above; no
        // other borrow into [0, len) exists and the mutable slice is
        // consumed by the immediate copy_from_slice before anything else
        // touches the area.
        unsafe {
            bindings[0]
                .umem
                .area()
                .slice_mut_unchecked(0, original_frame.len())
        }
        .expect("ingress frame")
        .copy_from_slice(&original_frame);

        let next_hop = IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200));
        let meta = pending_neighbor_meta(original_frame.len());
        // Buffered at queued_ns = 1_000_000 ns; resolves at a now_ns that
        // gives a 500 ms dwell — well under the 2 s PENDING_NEIGH_TIMEOUT
        // so the packet DISPATCHES (and records its dwell) rather than
        // timing out. The 3 s → tail-bucket mapping is covered by the
        // neighbor_latency unit tests; here we verify the record fires on
        // the real dispatch path with the correct sum + bucket.
        let queued_ns = 1_000_000u64;
        let dwell_ns = 500_000_000u64; // 500 ms
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
                decision: resolved_neighbor_decision(next_hop),
                flow_key: Some(test_session_key(12345, 443)),
                queued_ns,
                probe_attempts: 0,
            },
        );

        let mut forwarding = ForwardingState::default();
        // Neighbor IS resolved now → the retry sweep dispatches it and
        // records the dwell.
        forwarding.neighbors.insert(
            (80, next_hop),
            NeighborEntry {
                mac: [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            },
        );

        let lookup = WorkerBindingLookup::from_bindings(&bindings);
        let mirror_targets = MirrorTargetMap::default();
        let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
        let mut shared_recycles = Vec::new();
        let (resolver, _rx, dwell, _drops, depth) = resolver_with_latency();
        let area = bindings[0].umem.area() as *const MmapArea;
        let (left, rest) = bindings.split_at_mut(0);
        let (binding, right) = rest.split_first_mut().expect("ingress binding");

        let now_ns = queued_ns + dwell_ns;
        retry_pending_neigh(
            binding,
            left,
            0,
            right,
            &lookup,
            &mirror_targets,
            &forwarding,
            &dynamic_neighbors,
            Some(&resolver),
            now_ns,
            // SAFETY: `area` was cast from `&MmapArea` borrowed out of
            // bindings[0].umem just above; the Rc-backed allocation lives
            // past this call, the split_at_mut borrows cover disjoint
            // binding state (not the umem area), and the test is
            // single-threaded.
            unsafe { &*area },
            &mut shared_recycles,
            None,
            &mut BatchCounters::default(),
        );

        assert!(bindings[0].pending_neigh.is_empty(), "packet must dispatch");
        let snap = dwell.snapshot();
        assert_eq!(snap.count, 1, "exactly one dwell sample recorded");
        assert_eq!(snap.sum_ns, dwell_ns, "sum is the recorded dwell");
        let expect_bucket = crate::afxdp::neighbor_latency::neigh_latency_bucket_index(dwell_ns);
        assert_eq!(
            snap.buckets[expect_bucket], 1,
            "500 ms dwell recorded into its pow2-ns bucket",
        );
        assert_eq!(
            depth.load(Ordering::Relaxed),
            1,
            "max-depth high-water must reflect the 1 queued packet",
        );
    }

    /// #1772: a never-resolving packet that crosses the timeout records a
    /// timeout-drop and records NO dwell sample.
    #[test]
    fn timed_out_pending_neighbor_records_timeout_drop_not_dwell() {
        let mut bindings = vec![
            BindingWorker::new_for_mirror_test(0, 0, 11, 0),
            BindingWorker::new_for_mirror_test(1, 0, 22, 0),
        ];
        let original_frame = build_ipv4_test_packet(0);
        // SAFETY: single-threaded test over a UMEM created just above; no
        // other borrow into [0, len) exists and the mutable slice is
        // consumed by the immediate copy_from_slice before anything else
        // touches the area.
        unsafe {
            bindings[0]
                .umem
                .area()
                .slice_mut_unchecked(0, original_frame.len())
        }
        .expect("ingress frame")
        .copy_from_slice(&original_frame);

        let next_hop = IpAddr::V4(Ipv4Addr::new(172, 16, 80, 138));
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
                decision: resolved_neighbor_decision(next_hop),
                flow_key: Some(test_session_key(12345, 443)),
                queued_ns: 0,
                probe_attempts: PROBE_SCHEDULE_NS.len() as u8,
            },
        );

        // No neighbor anywhere → never resolves → timeout drop.
        let forwarding = ForwardingState::default();
        let lookup = WorkerBindingLookup::from_bindings(&bindings);
        let mirror_targets = MirrorTargetMap::default();
        let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
        let mut shared_recycles = Vec::new();
        let (resolver, _rx, dwell, drops, _depth) = resolver_with_latency();
        let area = bindings[0].umem.area() as *const MmapArea;
        let (left, rest) = bindings.split_at_mut(0);
        let (binding, right) = rest.split_first_mut().expect("ingress binding");

        let now_ns = PENDING_NEIGH_TIMEOUT_NS + 1;
        retry_pending_neigh(
            binding,
            left,
            0,
            right,
            &lookup,
            &mirror_targets,
            &forwarding,
            &dynamic_neighbors,
            Some(&resolver),
            now_ns,
            // SAFETY: `area` was cast from `&MmapArea` borrowed out of
            // bindings[0].umem just above; the Rc-backed allocation lives
            // past this call, the split_at_mut borrows cover disjoint
            // binding state (not the umem area), and the test is
            // single-threaded.
            unsafe { &*area },
            &mut shared_recycles,
            None,
            &mut BatchCounters::default(),
        );

        assert!(
            bindings[0].pending_neigh.is_empty(),
            "timed-out pkt dropped"
        );
        assert_eq!(
            drops.load(Ordering::Relaxed),
            1,
            "one timeout-drop must be counted",
        );
        assert_eq!(
            dwell.snapshot().count,
            0,
            "a timed-out (never-resolved) packet must NOT record a dwell sample",
        );
    }

    // =======================================================================
    // #8916: the deferred retry must not push an INGRESS-UMEM offset onto a
    // binding that does not share that UMEM.
    // =======================================================================

    /// Two bindings: [0] is the ingress (ifindex 11), [1] is the cross-binding
    /// egress target the decision's `tx_ifindex: 22` resolves to.
    ///
    /// `share_umem` decides whether [1] holds a CLONE of [0]'s `WorkerUmem`
    /// (same `Rc`, so `shares_allocation_with` is true) or its own allocation.
    /// That single variable is the whole subject of these cells, so nothing
    /// else differs between the two arms.
    fn cross_binding_fixture_8916(share_umem: bool) -> Vec<BindingWorker> {
        let mut bindings = vec![
            BindingWorker::new_for_mirror_test(0, 0, 11, 0),
            BindingWorker::new_for_mirror_test(1, 0, 22, 0),
        ];
        if share_umem {
            bindings[1].umem = bindings[0].umem.clone();
        }
        let frame = build_ipv4_test_packet(0);
        let meta = pending_neighbor_meta(frame.len());
        // The retry rewrites the frame IN PLACE, so the bytes have to actually
        // be in the ingress UMEM -- `pending_neigh_fixture_7156` never needed
        // this because its tests bail before the rewrite. Without it
        // `rewrite_forwarded_frame_in_place` returns None and the packet is
        // recycled to fill, which reads exactly like "the guard dropped it".
        {
            // SAFETY: `slice_mut_unchecked` takes `&self` by design -- it is the
            // same seam the production sweep writes through, which also holds
            // only a shared `&MmapArea`. Single-threaded test, no other borrow
            // of this extent is live, and the length is bounds-checked inside.
            let area = bindings[0].umem.area();
            unsafe { area.slice_mut_unchecked(0, frame.len()) }
                .expect("umem slice for the test frame")
                .copy_from_slice(&frame);
        }
        let nh = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 7));
        push_pending(
            &mut bindings[0],
            PendingNeighPacket {
                addr: 0,
                desc: XdpDesc {
                    addr: 0,
                    len: frame.len() as u32,
                    options: 0,
                },
                meta,
                decision: resolved_neighbor_decision(nh),
                flow_key: None,
                queued_ns: 1_000_000_000,
                probe_attempts: 0,
            },
        );
        bindings
    }

    fn sweep_two_8916(bindings: &mut [BindingWorker], now_ns: u64) {
        let forwarding = ForwardingState::default();
        let lookup = WorkerBindingLookup::from_bindings(bindings);
        let mirror_targets = MirrorTargetMap::default();
        let mut shared_recycles = Vec::new();
        let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
        // The pending-neigh key is (egress_ifindex, next_hop) -- 80, not the
        // tx_ifindex 22 the BINDING lookup uses. Getting this wrong leaves the
        // packet pending and the sweep dispatches nothing, which is how the
        // first version of these cells failed BOTH arms including the control.
        dynamic_neighbors.insert(
            (
                resolved_neighbor_decision(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 7)))
                    .resolution
                    .egress_ifindex,
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 7)),
            ),
            NeighborEntry {
                mac: [0x02, 0, 0, 0, 0, 0x22],
            },
        );
        let area = bindings[0].umem.area() as *const MmapArea;
        let (left, rest) = bindings.split_at_mut(0);
        let (binding, right) = rest.split_first_mut().expect("binding");
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
            // SAFETY: same contract as sweep_7156 above.
            unsafe { &*area },
            &mut shared_recycles,
            None,
            &mut BatchCounters::default(),
        );
    }

    /// The CONTROL. When the two bindings DO share a UMEM, the prepared
    /// (zero-copy) path is still taken — the fix must not degrade the case it
    /// is not about.
    ///
    /// Without this, "the guard fires" is satisfied by a guard that always
    /// fires, which would turn every cross-binding retry into a copy and
    /// silently cost the zero-copy path it exists to protect.
    #[test]
    fn neighbor_retry_shared_umem_still_uses_the_prepared_path_8916() {
        let mut bindings = cross_binding_fixture_8916(true);
        sweep_two_8916(&mut bindings, 1_300_000_000);

        assert_eq!(
            bindings[1].tx_pipeline.pending_tx_prepared.len(),
            1,
            "CONTROL FAILED: with a SHARED UMEM the cross-binding retry must still \
                 submit a prepared offset. If this is 0 the #8916 guard is rejecting \
                 the case it was never about, and the copy assertion in the sibling \
                 cell proves nothing about UMEM ownership"
        );
        assert_eq!(
            bindings[1].tx_pipeline.pending_tx_local.len(),
            0,
            "CONTROL: a shared-UMEM target must not take the copy fallback"
        );
        assert_eq!(
            bindings[1].tx_counters.neighbor_retry_cross_umem_copies, 0,
            "CONTROL: no cross-UMEM copy should be counted when the UMEM is shared"
        );
    }

    /// The fix. With SEPARATE UMEMs — `shared_umem` mode `off`, a supported
    /// configuration — the prepared offset must NOT be submitted.
    #[test]
    fn neighbor_retry_foreign_umem_falls_back_to_a_copy_8916() {
        let mut bindings = cross_binding_fixture_8916(false);
        assert!(
            !bindings[1].umem.shares_allocation_with(&bindings[0].umem),
            "NON-VACUITY: the two fixture bindings must NOT share a UMEM, or this \
                 cell is measuring the shared case under a different name"
        );

        sweep_two_8916(&mut bindings, 1_300_000_000);

        assert_eq!(
            bindings[1].tx_pipeline.pending_tx_prepared.len(),
            0,
            "#8916: a PreparedTxRequest carrying an offset into binding 0's UMEM was \
                 pushed onto binding 1, which does not share that allocation. \
                 `WorkerBindingLookup::target_index` resolves purely by (egress_ifindex, \
                 ingress_queue_id) with a first_by_if fallback — no UMEM or ownership \
                 term — so a target on a different NIC is an ordinary result. Under \
                 `shared_umem` mode `off` that offset does not address the same frame in \
                 the target's UMEM, or any valid frame. The normal dispatcher guards \
                 exactly this and falls back to the single-copy path; this deferred \
                 retry path was the one exit that did not."
        );
        assert_eq!(
            bindings[1].tx_pipeline.pending_tx_local.len(),
            1,
            "#8916: the frame must fall back to a COPY on the target rather than be \
                 dropped. Its neighbor has just resolved and the frame is already \
                 rewritten, so recycling it to fill would discard a deliverable packet \
                 on a path that is already off the fast path"
        );
        assert_eq!(
            bindings[1].tx_counters.neighbor_retry_cross_umem_copies, 1,
            "#8916: the cross-UMEM copy must be counted. Without it, a deployment \
                 crossing a UMEM boundary on every retry looks identical to one that \
                 never does, and the fallback cannot be distinguished from dead code"
        );
    }
