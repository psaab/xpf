// Neighbor-dispatch helpers extracted from afxdp.rs (Issue 67.2).
//
// `retry_pending_neigh` is the post-poll loop that walks the
// per-binding pending-neighbor queue, re-issues bpf_fib_lookup +
// neighbor lookups, and resumes any flow whose neighbor has now
// resolved (or drops it if the cap is exceeded).
//
// `learn_dynamic_neighbor*` are called from the RX descriptor
// path when an inbound ARP/NDP advert resolves a previously
// missing neighbor — they upsert into the dynamic neighbor map.
// #1787: the upsert is cheap-first — 1-2 single-shard reads elide
// the write entirely when every key already maps to src_mac, so
// the 64-shard bulk lock is only taken for genuine changes.
//
// `build_missing_neighbor_session_metadata` constructs the
// SessionMetadata stub used while the neighbor is unresolved
// so subsequent retries have the full forward context.
//
// Pure relocation. `use super::*;` brings every type, helper,
// and sibling-submodule item from afxdp.rs into scope.

use crate::afxdp::neigh_schedule::{
    next_due_for_pending, PENDING_NEIGH_SWEEP_BUDGET,
};
use super::*;

/// GEMINI-NEXT.md Section 3 cold-start: re-fire ARP/NDP solicitation
/// at exponential intervals after the initial probe in
/// `poll_descriptor.rs`. Each entry is the cumulative ns delay from
/// `PendingNeighPacket::queued_ns` at which to issue the next
/// `trigger_kernel_arp_probe()`. After all entries elapse, no further
/// probes — the packet just waits for kernel resolution or the
/// PENDING_NEIGH_TIMEOUT.
///
/// 10/60/260 ms covers a 4-probe schedule (initial + 3 retries) over
/// 260 ms total. The deltas (10, 50, 200 ms) match the cold-start
/// exponential design in GEMINI-NEXT.md and give the kernel three
/// retransmits if the first solicitation is dropped.
pub(super) const PROBE_SCHEDULE_NS: &[u64] = &[
    10_000_000,  // first retry at queued + 10 ms
    60_000_000,  // second retry at queued + 60 ms (delta 50 ms)
    260_000_000, // third retry at queued + 260 ms (delta 200 ms)
];

/// #1636 option D: the drop timeout comes per snapshot from the kernel
/// retrans_time_ms sysctls (800 ms when fast-retrans is confirmed, else
/// 2000 ms). `0` means a snapshot predating the field (e.g. a test-built
/// `ForwardingState::default()`) — fall back to the compile-time constant.
///
/// #7156: extracted because the deadline-queue ARM site (`poll_descriptor`'s
/// MissingNeighbor arm) and this sweep must compute the same timeout. If the
/// arm used a longer one the key would be visited only after it had already
/// timed out; if shorter, it would be popped, found not-yet-timed-out, and
/// re-armed — burning budget for nothing.
#[inline]
pub(super) fn effective_pending_neigh_timeout_ns(forwarding: &ForwardingState) -> u64 {
    if forwarding.pending_neigh_timeout_ns != 0 {
        forwarding.pending_neigh_timeout_ns
    } else {
        PENDING_NEIGH_TIMEOUT_NS
    }
}

/// Returns true when the next scheduled probe is due. Pure function —
/// no side effects, easy to unit-test the schedule edges.
fn probe_due(elapsed_ns: u64, attempts: u8) -> bool {
    PROBE_SCHEDULE_NS
        .get(attempts as usize)
        .is_some_and(|&target| elapsed_ns >= target)
}

/// #1771 §2.2/§2.4: the pure `pending_neigh` buffer-admission decision
/// used at the `MissingNeighbor` handler in `poll_descriptor`. Extracted
/// (behavior-identical) so invariant N1's second half — "`pending_neigh`
/// admits at most ONE packet per `(egress_ifindex, next_hop)`" — is a
/// tested decision rather than an inline branch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum PendingNeighAdmission {
    /// Key absent and below cap → buffer this packet (it becomes the
    /// per-key representative driving the probe/dwell clock).
    Buffer,
    /// Key already pending → duplicate sibling: drop + recycle now
    /// (keep-OLDEST; the buffered representative is never replaced, so
    /// each unresolved hop pins at most one UMEM frame).
    DuplicateDrop,
    /// New key but the map is at `MAX_PENDING_NEIGH` distinct hops →
    /// capacity drop (counted SEPARATELY in `pending_neigh_capacity_drops`
    /// per the #2375 split; the duplicate counter must not conflate this
    /// case).
    CapacityDrop,
}

/// Pure admission decision over the two map facts the caller reads
/// (`contains_key`, `len`). `#[inline]` — compiles to the identical
/// branch pair the inline code had.
#[inline]
pub(super) fn pending_neigh_admission(already_pending: bool, len: usize) -> PendingNeighAdmission {
    if already_pending {
        PendingNeighAdmission::DuplicateDrop
    } else if len < MAX_PENDING_NEIGH {
        PendingNeighAdmission::Buffer
    } else {
        PendingNeighAdmission::CapacityDrop
    }
}

/// #2375: record the per-binding drop counter for a non-buffered
/// `pending_neigh` admission decision. Extracted (behavior-identical to
/// the inline `fetch_add`s) so the two drop counters are a tested
/// side-effect rather than an inline branch — a unit test FAILS if
/// either increment is removed. `Buffer` is not a drop, so it is a
/// no-op here (the caller does the insert). The two drop cases are kept
/// SEPARATE per the #1782/#2375 split:
///   - `DuplicateDrop` (`pending_neigh_duplicate_drops`) — the key was
///     already pending: normal cold-start sibling coalescing.
///   - `CapacityDrop` (`pending_neigh_capacity_drops`) — a NEW distinct
///     hop refused because the map is at `MAX_PENDING_NEIGH`:
///     distinct-hop neighbor exhaustion (the scan/upstream-outage
///     failure mode).
#[inline]
pub(super) fn record_pending_neigh_admission_drop(
    live: &BindingLiveState,
    admission: PendingNeighAdmission,
) {
    match admission {
        PendingNeighAdmission::DuplicateDrop => {
            live.pending_neigh_duplicate_drops
                .fetch_add(1, Ordering::Relaxed);
        }
        PendingNeighAdmission::CapacityDrop => {
            live.pending_neigh_capacity_drops
                .fetch_add(1, Ordering::Relaxed);
        }
        PendingNeighAdmission::Buffer => {}
    }
}

/// The flow key stored on a buffered `PendingNeighPacket` (next-hop
/// unresolved). `retry_pending_neigh` later feeds this key into CoS / TX
/// output-filter classification (`resolve_cos_tx_selection_at`) and the
/// prepared TX request, so a fabricated tuple here misclassifies the flushed
/// packet exactly like the immediate forward path would.
///
/// Precedence (highest first), behavior-identical to the inline closure it
/// replaces:
///   1. a real conntrack/frame-derived `flow` → its `forward_key`;
///   2. otherwise, the metadata fallback — but gated:
///      - a non-first IP fragment (#2344/#2357) → `None` (no L4 header);
///      - a non-identifier-bearing ICMP/ICMPv6 packet (#3290 — error /
///        control / ND/MLD / truncated query) → `None`. The XDP shim stamps
///        `meta.flow_src_port` from bytes [l4+4..l4+6] for EVERY ICMP type
///        with no query-type gate, so trusting it here would buffer a fake
///        pseudo-port. This is the SAME gate the conntrack-side
///        `parse_session_flow_from_bytes` and the immediate
///        `build_live_forward_request_from_frame` meta-fallback apply, keeping
///        all three pending/immediate/conntrack paths consistent;
///      - a TCP/UDP packet whose stamped ports lie outside the IP-declared
///        datagram (#9894 — short total_len/payload_len + slack) → `None`.
///        The shim reads L4 against the frame end including slack, so the
///        tuple is phantom and the primary `flow` is already `None` for it
///        (conntrack-side fast-path gate). Same gate as the immediate path;
///      - otherwise the metadata tuple (legitimate flowless TCP/UDP or an
///        identifier-bearing ICMP query) → its `forward_key`.
pub(super) fn pending_neigh_flow_key(
    flow: Option<&SessionFlow>,
    raw_frame: &[u8],
    meta: UserspaceDpMeta,
) -> Option<SessionKey> {
    flow.map(|flow| flow.forward_key.clone()).or_else(|| {
        if frame_is_non_first_fragment(raw_frame, meta) {
            None
        } else if matches!(meta.protocol, PROTO_ICMP | PROTO_ICMPV6)
            && !meta_icmp_identifier_bearing(raw_frame, meta)
        {
            None
        } else if matches!(meta.protocol, PROTO_TCP | PROTO_UDP)
            && !meta_l4_ports_in_declared_end(raw_frame, meta)
        {
            None
        } else {
            parse_session_flow_from_meta(meta).map(|flow| flow.forward_key)
        }
    })
}

#[allow(clippy::too_many_arguments)]
pub(super) fn retry_pending_neigh(
    binding: &mut BindingWorker,
    left: &mut [BindingWorker],
    binding_index: usize,
    right: &mut [BindingWorker],
    binding_lookup: &WorkerBindingLookup,
    mirror_targets: &MirrorTargetMap,
    forwarding: &ForwardingState,
    dynamic_neighbors: &Arc<ShardedNeighborMap>,
    // #1772: optional latency-telemetry handle. `None` when the resolver
    // thread failed to spawn (telemetry simply not recorded; no
    // forwarding-behavior change). Recording fires only on the rare
    // retry-sweep events (timeout drop, successful resolve dispatch), all
    // off the per-packet forwarded fast path.
    neighbor_resolver: Option<&Arc<NeighborResolver>>,
    now_ns: u64,
    area: &MmapArea,
    shared_recycles: &mut Vec<(u32, u64)>,
    // #7176 (C179-001): a buffered packet's output filter is evaluated HERE and
    // nowhere else, so this path owes the same `then reject` reply and `then
    // log` event the immediate forward path emits. Both need context the flush
    // did not previously carry: the event stream to publish the filter-log
    // event on, and the batch counters `enqueue_filter_reject_reply` meters the
    // synthesized reply against.
    event_stream: Option<&crate::event_stream::EventStreamWorkerHandle>,
    counters: &mut BatchCounters,
) {
    if binding.pending_neigh.is_empty() {
        return;
    }
    // #1772: observe the pending-neigh queue depth at sweep entry for the
    // high-water gauge (after the empty-queue early-out so an idle binding
    // never touches the atomic).
    if let Some(resolver) = neighbor_resolver {
        resolver.observe_pending_depth(binding.pending_neigh.len() as u64);
    }
    let ingress_slot = binding.slot;
    let ingress_ifindex = binding.ifindex;
    // §8916: cloned (an Rc bump) so the cross-binding push below can ask
    // whether the target shares this binding's UMEM while `binding` is
    // mutably borrowed inside the loop.
    //
    // `shares_allocation_with` rather than comparing `allocation_ptr()`: the
    // codebase already expresses this question, and re-deriving it here would
    // be a second implementation of the same predicate that can drift from the
    // first.
    let ingress_umem = binding.umem.clone();
    let ingress_queue = binding.queue_id;
    // #1636 option D: the drop timeout is computed per snapshot from the
    // kernel retrans_time_ms sysctls (800ms when fast-retrans is
    // confirmed, else 2000ms). `0` means a snapshot that predates the
    // field (e.g. a test-built ForwardingState::default()) — fall back
    // to the compile-time PENDING_NEIGH_TIMEOUT_NS.
    let pending_neigh_timeout_ns = effective_pending_neigh_timeout_ns(forwarding);
    // #1771 §2.2: pending_neigh is keyed by (egress_ifindex, next_hop) with
    // ONE representative packet per hop, so the per-sweep probe-dedup
    // BTreeSet is gone (each hop fires at most one probe naturally).
    //
    // #7156: and the key sweep that replaced the old O(n²) rotation is itself
    // now deadline-driven and budgeted. It used to collect EVERY unresolved key
    // into a fresh Vec and walk all of them on every sweep, twice per poll —
    // measured at ~182 us and ~98 KiB per sweep at the MAX_PENDING_NEIGH cap,
    // against 8 ns for the empty-map early-out above. See `neigh_schedule` for
    // the table and for why the heap needs no tombstone handling.
    //
    // Nothing due costs one heap peek. The budget bounds the worst case, and
    // because the heap is deadline-ordered a truncated sweep leaves the
    // LATEST-deadline keys unvisited: timeouts and due probes always win.
    // #7156: has any neighbour been INSERTED since this worker last swept?
    //
    // This is the whole point. The old sweep's cost was a resolution check per
    // pending key — a `forwarding.neighbors` hash lookup plus a
    // `dynamic_neighbors` lookup that takes a shard MUTEX — and it ran whether
    // or not anything had resolved. One relaxed-Acquire load answers "could any
    // buffered next-hop have become resolvable?", and when the answer is no the
    // sweep only services deadline-due keys: timeouts and probes.
    //
    // That is exactly the attacker's case. Filling MAX_PENDING_NEIGH with
    // distinct unresolvable hops produces NO neighbour inserts, so it now buys
    // no walks at all — where before it bought a full 4096-key walk twice per
    // poll, ~182 us each.
    //
    // And when a neighbour DOES appear, the walk is the old one: every pending
    // key is re-checked on that very sweep, so a resolved packet is dispatched
    // with the same latency as before. Deadline order alone could not do that —
    // a key has nothing scheduled between its last probe (queued + 260 ms) and
    // its timeout, so a neighbour resolving at 300 ms would go unnoticed until
    // the key timed out and its packet was DROPPED.
    //
    // Known residual, not closed here: an on-link attacker who can force real
    // neighbour churn (answering ARP/NDP for many addresses) can drive walks.
    // That is a strictly harder position than the one this issue describes — it
    // requires answering probes rather than merely being unreachable — and it
    // is separately bounded by MAX_DYNAMIC_NEIGHBORS_PER_SHARD and the #5673
    // learn cap.
    // Two signals, because there are two neighbour maps and the sweep consults
    // both in `lookup_neighbor_entry` order. `dynamic_neighbors` is the runtime
    // learn/resolve path and carries a true insert counter. `forwarding.neighbors`
    // is the STATIC/permanent config-derived map, rebuilt wholesale on commit and
    // reaching the worker as a fresh snapshot, so it has no counter to bump — its
    // length stands in, which is exact for the add and remove that a config change
    // actually performs. A same-size REPLACEMENT is the one static edit this misses,
    // and RESOLUTION_RECHECK_INTERVAL_NS is the backstop for it: 50 ms, against a
    // pending timeout of 800 ms-2 s, so such a packet still dispatches rather than
    // being dropped. Stated rather than papered over — the dynamic path, which is
    // the one on the packet-latency critical path, is exact.
    let neigh_generation = (
        dynamic_neighbors.insert_generation(),
        forwarding.neighbors.len(),
    );
    let resolution_pass = neigh_generation != binding.last_neigh_generation;
    binding.last_neigh_generation = neigh_generation;
    if resolution_pass {
        // Reuse the scratch so the walk allocates nothing steady-state. The old
        // sweep built a fresh Vec of every key on EVERY sweep (~98 KiB at the
        // cap, ~196 KiB per poll); this one reuses its capacity and only runs
        // when a neighbour actually appeared. `mem::take` because the fill
        // borrows `pending_neigh` while writing `pending_neigh_scan`.
        let mut scan = std::mem::take(&mut binding.pending_neigh_scan);
        scan.clear();
        scan.extend(binding.pending_neigh.keys().copied());
        binding.pending_neigh_scan = scan;
    }
    let mut scan_idx = 0usize;
    let mut budget = PENDING_NEIGH_SWEEP_BUDGET;
    loop {
        let key = if resolution_pass {
            // A resolution pass covers every key: it is the path that must not
            // miss a newly-resolvable hop, and it is rare by construction.
            let next = binding.pending_neigh_scan.get(scan_idx).copied();
            scan_idx += 1;
            match next {
                Some(k) => k,
                None => break,
            }
        } else {
            if budget == 0 {
                break;
            }
            budget -= 1;
            match binding.pending_neigh_schedule.pop_due(now_ns) {
                Some(k) => k,
                None => break,
            }
        };
        // #7156: count the visit before any early-out, so this measures work
        // ATTEMPTED per sweep rather than work that happened to find something.
        binding
            .live
            .pending_neigh_visits
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        // Peek queued_ns / probe_attempts without holding a borrow across
        // the dispatch tail.
        let (queued_ns, probe_attempts) = match binding.pending_neigh.get(&key) {
            Some(p) => (p.queued_ns, p.probe_attempts),
            // A removal during a RESOLUTION PASS leaves its heap entry behind,
            // since that path does not pop. This is where such an entry is
            // discarded. Self-limiting rather than an unbounded tombstone leak:
            // at most one entry per removal, and each is reclaimed the first
            // time its own deadline comes up, which is bounded by the key's
            // timeout.
            None => continue,
        };
        // Timeout: recycle frame and drop.
        if now_ns.saturating_sub(queued_ns) > pending_neigh_timeout_ns {
            // #1651 B3: this dst timed out after best-effort ARP/NDP probes
            // and never resolved — negatively cache (egress_ifindex,
            // next_hop) so subsequent cold packets fast-fail at the
            // MissingNeighbor buffer site instead of re-buffering for
            // another full PENDING_NEIGH_TIMEOUT. The timeout (not the probe
            // count) is the signal: the dst never landed in the neighbor
            // maps within the window. The map key IS (egress_ifindex,
            // next_hop) — the same lookup key the fast-fail gate uses.
            let pkt = binding
                .pending_neigh
                .remove(&key)
                .expect("key from this map");
            // #6710: do NOT arm the dead-host cache against an egress that has
            // no link-layer address by construction (an IPsec xfrmi).
            //
            // The cache exists to stop packets to a host that is NOT ANSWERING
            // from re-buffering every window, and its escape hatch is
            // resolved-neighbor-wins: the entry is evicted the moment the host
            // answers. An xfrmi has nothing to answer with, so that escape can
            // never fire and the arm/expire cycle repeats for as long as the
            // tunnel carries traffic.
            //
            // That is not a 3 s penalty, it is a permanent one, because the
            // fast-fail recycles the frame at the top of the MissingNeighbor
            // arm and so skips the fall-through to the slow-path reinject —
            // and the reinject is the ONLY way a LAN→tunnel packet reaches the
            // kernel XFRM stack, since an xfrmi gets no AF_XDP binding
            // (`userspace_unbindable_netdev`). Every armed window drops
            // permitted, policy-evaluated traffic on a healthy tunnel.
            //
            // Skipping the arming costs nothing the cache was buying. Its
            // stated purpose is protecting the BOUNDED pending_neigh map from
            // a multi-hop scan, and post-#1771 §2.2 that map holds ONE
            // representative packet per (egress_ifindex, next_hop) — so an
            // xfrmi hop pins exactly one entry whether or not it is cached.
            // The probe and resolver enqueue are separately rate-limited.
            if !forwarding.lladdrless_egress.contains(&key.0) {
                neg_neigh_record(&mut binding.neg_neigh_cache, key, now_ns);
            }
            // #1772: count the never-resolved timeout drop.
            if let Some(resolver) = neighbor_resolver {
                resolver.record_pending_timeout_drop();
            }
            binding.tx_pipeline.pending_fill_frames.push_back(pkt.addr);
            continue;
        }
        // Check if neighbor MAC is now available, mirroring the lookup
        // order from lookup_neighbor_entry(): static/permanent neighbors
        // first, then dynamic_neighbors. The map key IS the neighbor key.
        let mac = forwarding
            .neighbors
            .get(&key)
            .map(|e| e.mac)
            .or_else(|| dynamic_neighbors.get(&key).map(|e| e.mac));
        let Some(neighbor_mac) = mac else {
            // Still pending — re-fire the ARP/NDP probe if the next slot in
            // the exponential schedule is due (GEMINI-NEXT.md Section 3
            // cold-start). One entry per (egress_ifindex, next_hop) means at
            // most one probe per hop per sweep with no extra dedup. Advance
            // probe_attempts in place so each schedule slot fires once.
            if probe_due(now_ns.saturating_sub(queued_ns), probe_attempts) {
                if let Some(name) = forwarding.ifindex_to_name.get(&key.0) {
                    trigger_kernel_arp_probe(name, key.0, key.1);
                    if let Some(p) = binding.pending_neigh.get_mut(&key) {
                        p.probe_attempts = p.probe_attempts.saturating_add(1);
                    }
                }
                // else: iface lookup miss → no probe fires, probe_attempts
                // NOT advanced; the key retries this slot next sweep.
            }
            // #7156: this is the ONLY path on which the key stays in the map,
            // so it is the only re-arm. Both removals below drop the key, and
            // no path in the dispatch tail re-inserts it (every failure there
            // recycles the frame), so re-arming anywhere else would create the
            // stale entry this design otherwise cannot produce.
            //
            // Re-read probe_attempts rather than reusing the value peeked
            // above: a probe may have just advanced it, and arming against the
            // stale count would re-arm on the slot that has already fired.
            let attempts_now = binding
                .pending_neigh
                .get(&key)
                .map_or(probe_attempts, |p| p.probe_attempts);
            // Only the deadline path re-arms. A resolution pass reaches keys by
            // walking the map WITHOUT popping them, so their heap entry is still
            // live; arming again there would put a second entry on one key and
            // manufacture exactly the duplicate this design otherwise cannot
            // produce.
            if !resolution_pass {
                let due = next_due_for_pending(
                    now_ns,
                    queued_ns,
                    attempts_now,
                    pending_neigh_timeout_ns,
                    PROBE_SCHEDULE_NS,
                );
                binding.pending_neigh_schedule.arm(key, due);
            }
            continue;
        };
        // #1772: the neighbor is now usable — record the pending-neigh
        // dwell (`now_ns - queued_ns`). This is THE key metric: how long
        // the buffered packet waited for its neighbor to resolve. Both
        // timestamps come from the same CLOCK_MONOTONIC source so the
        // saturating_sub cannot underflow. Recorded at the resolved point
        // (not after the subsequent rare cos/slice/target early-outs) so
        // it measures resolution latency rather than dispatch success.
        if let Some(resolver) = neighbor_resolver {
            resolver.record_pending_dwell(now_ns.saturating_sub(queued_ns));
        }
        // Own the packet (removes it from the map) so the dispatch tail can
        // borrow `&mut binding` freely.
        let pkt = binding
            .pending_neigh
            .remove(&key)
            .expect("key from this map");
        let mut decision = pkt.decision;
        // #1873 R-E defense-in-depth: tunnel-marked entries are excluded
        // at admission (poll_descriptor), so this should be unreachable —
        // but an in-place rewrite of a tunnel inner packet transmits it
        // PLAINTEXT (rewrite_forwarded_frame_in_place does MAC/VLAN/NAT
        // only, no encapsulation), so a stray entry is dropped + counted,
        // never TXed.
        if decision.resolution.tunnel_endpoint_id != 0 {
            binding
                .live
                .tunnel_encap_unresolved_drops
                .fetch_add(1, Ordering::Relaxed);
            binding.tx_pipeline.pending_fill_frames.push_back(pkt.addr);
            continue;
        }
        // #9752 round 5 item 3: revalidate the installing table on retry.
        // The buffered decision was stamped when the packet was buffered;
        // the table may have been removed/re-homed since, and serving the
        // buffered egress unchecked forwards stale (the types/mod.rs
        // contract says a retried packet re-resolves in its installing
        // table). Unresolvable → drop + count + arm the purge (D8); the
        // frame is recycled like every other retry failure. Keyless
        // (flowless) packets keep legacy behavior — only keyed flows can
        // carry a stamp to revalidate.
        if let Some(flow_key) = pkt.flow_key.as_ref() {
            let target = decision.nat.rewrite_dst.unwrap_or(flow_key.dst_ip);
            if matches!(
                super::session_glue::resolve_install_table_for_session(forwarding, decision, target),
                super::session_glue::InstallTable::Unresolvable
            ) {
                binding.live.table_unavailable_packets.fetch_add(1, Ordering::Relaxed);
                super::session_glue::flag_install_table_purge(binding.worker_id);
                binding.tx_pipeline.pending_fill_frames.push_back(pkt.addr);
                continue;
            }
        }
        decision.resolution.neighbor_mac = Some(neighbor_mac);
        decision.resolution.disposition = ForwardingDisposition::ForwardCandidate;
        let expected_ports = None;
        let Some(source_frame) = area.slice(pkt.desc.addr as usize, pkt.desc.len as usize) else {
            binding.tx_pipeline.pending_fill_frames.push_back(pkt.addr);
            continue;
        };
        // #2362 fold B: this is the ARP/NDP-resolved retransmit of a real
        // buffered transit frame — build the fragment-safe per-packet match
        // inputs from that frame so an output filter's tcp-flags / is-fragment /
        // icmp-type term matches the same packet it would on the immediate path.
        let cos_extra = crate::afxdp::frame::term_match_extra_from_frame(source_frame, pkt.meta);
        // #3642: this is the ARP/NDP-resolved retransmit of a buffered transit
        // frame — the egress output filter must match the POST-NAT on-wire tuple.
        // Derive the egress wire key from the pre-NAT buffered key + this frame's
        // NAT decision (apply-to-this-packet form, correct for both directions).
        // #5158: pass the POST-NAT wire key for the egress output filter but the
        // pre-NAT buffered `flow_key` as the ingress re-walk key — the ingress
        // INPUT filter matched this packet on its pre-NAT tuple.
        let tx_selection_wire_key = pkt
            .flow_key
            .as_ref()
            .map(|key| crate::session::forward_wire_key(key, decision.nat));
        // #7656: the buffered frame can also be FLOWLESS (a non-first fragment
        // whose association carried no key). It has the same defect as the
        // immediate path — every downstream read falls back to the ingress meta,
        // which under NAT64 is the pre-translation family/addresses/protocol —
        // and `decision.nat` is available here just as it is there, so it gets
        // the same synthesized post-NAT tuple rather than a `None` that would
        // leave this path quietly wrong.
        let flowless_wire_flow = if pkt.flow_key.is_none() {
            crate::afxdp::forward_request::l3_wire_session_flow_from_meta(pkt.meta, decision.nat)
        } else {
            None
        };
        let cos = resolve_cos_tx_selection_at_prenat(
            forwarding,
            decision.resolution.egress_ifindex,
            pkt.meta,
            tx_selection_wire_key.as_ref(),
            pkt.flow_key.as_ref(),
            cos_extra,
            now_ns,
            flowless_wire_flow.as_ref().map(|f| &f.forward_key),
        );
        if cos.drop {
            // #7176 (C179-001): apply the SAME reject-reply / filter-log side
            // effects the immediate forward path applies. Before this, a
            // dropping verdict here recycled the frame silently, so an output
            // filter `then reject` degraded to `then discard` and a `then log`
            // term emitted nothing — for every packet unlucky enough to arrive
            // before its neighbor resolved. `cos` is resolved from the same
            // `resolve_cos_tx_selection_at_prenat` the immediate path uses, so
            // the verdict is identical; only the handling of it diverged.
            //
            // The flow is rebuilt from the buffered pre-NAT session key, which
            // is the deferred equivalent of the immediate path's
            // `tx_selection_flow`. A packet buffered without a key (a non-first
            // fragment, #2357) yields `None` and keeps the silent drop, which
            // matches the immediate path's flowless behaviour (#3615 -- no L4
            // header to synthesize a reply from).
            let deferred_flow = pkt.flow_key.as_ref().map(|key| SessionFlow {
                src_ip: key.src_ip,
                dst_ip: key.dst_ip,
                forward_key: key.clone(),
            });
            crate::afxdp::forward_request::apply_cos_drop_side_effects(
                &cos,
                crate::afxdp::forward_request::CoSDropSideEffects {
                    forwarding,
                    meta: pkt.meta,
                    ingress_ifindex: pkt.meta.ingress_ifindex as i32,
                    egress_ifindex: decision.resolution.egress_ifindex,
                    // A deferred packet is never a fabric ingress: the fabric
                    // redirect path forwards immediately and never buffers.
                    fabric_ingress_zone: None,
                    now_ns,
                    flowless_wire_flow,
                },
                source_frame,
                deferred_flow.as_ref(),
                Some(crate::afxdp::forward_request::ForwardRejectReply {
                    tx_pipeline: &mut binding.tx_pipeline,
                    counters,
                }),
                event_stream,
            );
            binding.tx_pipeline.pending_fill_frames.push_back(pkt.addr);
            continue;
        }
        if let Some(result) = enqueue_sampled_mirror_clone(
            left,
            binding_index,
            binding,
            right,
            binding_lookup,
            mirror_targets,
            forwarding,
            pkt.meta.ingress_ifindex as i32,
            pkt.meta.ingress_vlan_id,
            ingress_queue,
            source_frame,
            pkt.meta.into(),
            pkt.flow_key.as_ref(),
        ) {
            record_mirror_clone_result(&binding.live, result, source_frame.len());
        }
        let selected_tcp_mss = select_tcp_mss(forwarding, &decision, &pkt.meta.into());
        let Some(rewrite_result) = rewrite_forwarded_frame_in_place(
            &*area,
            pkt.desc,
            pkt.meta,
            &decision,
            false,
            expected_ports,
            selected_tcp_mss,
        ) else {
            binding.tx_pipeline.pending_fill_frames.push_back(pkt.addr);
            continue;
        };
        let target_ifindex = if decision.resolution.tx_ifindex > 0 {
            decision.resolution.tx_ifindex
        } else {
            resolve_tx_binding_ifindex(forwarding, decision.resolution.egress_ifindex)
        };
        let Some(target_idx) = binding_lookup.target_index(
            binding_index,
            ingress_ifindex,
            ingress_queue,
            target_ifindex,
        ) else {
            binding.tx_pipeline.pending_fill_frames.push_back(pkt.addr);
            continue;
        };
        let req = PreparedTxRequest {
            offset: rewrite_result.offset,
            len: rewrite_result.len,
            recycle: PreparedTxRecycle::fill_on_slot(
                ingress_slot,
                rewrite_result.offset,
                pkt.desc.addr,
            ),
            expected_ports: None,
            expected_addr_family: pkt.meta.addr_family,
            expected_protocol: pkt.meta.protocol,
            flow_key: pkt.flow_key.clone(),
            egress_ifindex: decision.resolution.egress_ifindex,
            cos_queue_id: cos.queue_id,
            dscp_rewrite: cos.dscp_rewrite,
            mirror_clone: false,
            overlap_admissions: None,
            enqueue_ns: 0,
        };
        if target_idx == binding_index {
            binding.tx_pipeline.pending_tx_prepared.push_back(req);
            binding.tx_counters.pending_in_place_tx_packets += 1;
            binding
                .tx_counters
                .record_in_place_l2_rewrite(rewrite_result.l2_rewrite);
        } else if let Some(target) =
            binding_by_index_mut(left, binding_index, binding, right, target_idx)
        {
            // §8916: A PREPARED REQUEST CARRIES AN OFFSET INTO THE *INGRESS*
            // UMEM. Pushing it onto another binding's queue is only meaningful
            // when the two bindings share that UMEM.
            //
            // `WorkerBindingLookup::target_index` resolves purely by
            // `(egress_ifindex, ingress_queue_id)` with a `first_by_if`
            // fallback -- no UMEM, sharing-group or ownership term -- so a
            // target on a DIFFERENT NIC with its own UMEM is an ordinary
            // result. With `shared_umem` mode `off` (a supported
            // configuration) the bindings do not share an allocation, and
            // `rewrite_result.offset` does not address the same frame in the
            // target's UMEM, or any valid frame.
            //
            // The normal dispatcher already refuses this: it gates the
            // prepared/zero-copy path on the target sharing the ingress
            // allocation and falls back to the single-copy local path
            // otherwise. That guard appears three times in
            // `tx/dispatch/mod.rs` and zero times here -- this deferred
            // neighbor-retry path was the one exit that did not have it.
            //
            // FALL BACK TO A COPY RATHER THAN DROPPING. The frame has already
            // been rewritten in place and its neighbor has just resolved, so
            // the packet is deliverable; copying it into the target's local
            // queue delivers it at the cost of one memcpy on a deferred path
            // that is already off the fast path. Recycling it to fill instead
            // would drop a packet the dataplane went to some trouble to hold.
            if target.umem.shares_allocation_with(&ingress_umem) {
                target.tx_pipeline.pending_tx_prepared.push_back(req);
                bound_pending_tx_prepared(target, Some(shared_recycles));
                target.tx_counters.pending_in_place_tx_packets += 1;
                target
                    .tx_counters
                    .record_in_place_l2_rewrite(rewrite_result.l2_rewrite);
            } else if let Some(bytes) =
                area.slice(rewrite_result.offset as usize, rewrite_result.len as usize)
            {
                target.tx_pipeline.pending_tx_local.push_back(TxRequest {
                    bytes: bytes.to_vec(),
                    expected_ports: req.expected_ports,
                    expected_addr_family: req.expected_addr_family,
                    expected_protocol: req.expected_protocol,
                    flow_key: req.flow_key,
                    egress_ifindex: req.egress_ifindex,
                    cos_queue_id: req.cos_queue_id,
                    dscp_rewrite: req.dscp_rewrite,
                    mirror_clone: req.mirror_clone,
                    overlap_admissions: None,
                    enqueue_ns: req.enqueue_ns,
                });
                target.tx_counters.neighbor_retry_cross_umem_copies += 1;
                // The ingress descriptor is ours to recycle: the copy owns the
                // bytes now, so the frame goes back to this binding's fill
                // ring rather than riding a foreign recycle.
                binding.tx_pipeline.pending_fill_frames.push_back(pkt.addr);
            } else {
                // The rewritten extent is not addressable in our own area --
                // recycle rather than submit anything.
                binding.tx_pipeline.pending_fill_frames.push_back(pkt.addr);
            }
        } else {
            binding.tx_pipeline.pending_fill_frames.push_back(pkt.addr);
        }
    }
    apply_shared_recycles(
        left,
        binding_index,
        binding,
        right,
        binding_lookup,
        shared_recycles,
    );
}

pub(super) fn learn_dynamic_neighbor_from_packet(
    area: &MmapArea,
    desc: XdpDesc,
    meta: UserspaceDpMeta,
    src_ip: IpAddr,
    last_learned_neighbor: &mut Option<LearnedNeighborKey>,
    forwarding: &ForwardingState,
    dynamic_neighbors: &Arc<ShardedNeighborMap>,
) {
    let Some(frame) = area.slice(desc.addr as usize, desc.len as usize) else {
        return;
    };
    if frame.len() < 12 {
        return;
    }
    // #3075: skip learning xpf's own synthetic fabric-zone-encoded src MAC
    // (02:bf:72:fe:HI:LO, where HI:LO is the big-endian u16 zone id). The
    // discriminator is the 02:bf:72 OUI + the FABRIC_ZONE_MAC_MAGIC byte; the
    // former frame[10]==0x00 guard is dropped because the zone-id high byte may
    // now be nonzero (ids > 255).
    if frame[6] == 0x02
        && frame[7] == 0xbf
        && frame[8] == 0x72
        && frame[9] == FABRIC_ZONE_MAC_MAGIC
    {
        return;
    }
    let mut src_mac = [0u8; 6];
    src_mac.copy_from_slice(&frame[6..12]);
    // #9115: routed through the shared predicate rather than spelled inline.
    // This test existed HERE and nowhere else, while the ARP-reply and NDP-NA
    // learn arms in poll_stages.rs had none — a shared name is what keeps the
    // three from drifting again.
    if !crate::afxdp::frame::neighbor_mac_is_learnable(src_mac) {
        return;
    }
    let learned = LearnedNeighborKey {
        ingress_ifindex: meta.ingress_ifindex as i32,
        ingress_vlan_id: meta.ingress_vlan_id,
        src_ip,
        src_mac,
    };
    if last_learned_neighbor.as_ref() == Some(&learned) {
        return;
    }
    learn_dynamic_neighbor(
        forwarding,
        dynamic_neighbors,
        meta.ingress_ifindex as i32,
        meta.ingress_vlan_id,
        src_ip,
        src_mac,
    );
    *last_learned_neighbor = Some(learned);
}

/// #1787: pure decision helper for the cheap-first RX learn pre-check.
/// `current` holds the pre-read MAC (or `None` on miss) for each
/// candidate key; a bulk write is needed iff ANY entry is missing or
/// differs from `src_mac`. Factored out so the elision decision is
/// unit-testable directly — an elided write and an idempotent
/// overwrite leave identical map contents (RX learn bumps no
/// generation), so map-state comparison alone cannot prove elision.
pub(super) fn pair_write_needed(current: &[Option<[u8; 6]>], src_mac: [u8; 6]) -> bool {
    current.iter().any(|mac| *mac != Some(src_mac))
}

pub(super) fn learn_dynamic_neighbor(
    forwarding: &ForwardingState,
    dynamic_neighbors: &Arc<ShardedNeighborMap>,
    ingress_ifindex: i32,
    ingress_vlan_id: u16,
    src_ip: IpAddr,
    src_mac: [u8; 6],
) {
    // #4889: illegitimate source-IP CLASS gate on the #1787 RX source-MAC
    // learn path, mirroring the #2790 unicast-only gate the ARP-reply and
    // NDP-NA learn arms already apply in poll_stages.rs. Unlike those L2
    // advert paths, this 5th learn path derives the neighbor identity from
    // a LIVE transit frame's L3 source (`flow.src_ip`) — an attacker can
    // therefore send a normal TCP/UDP packet with a unicast source MAC but
    // a spoofed source IP whose CLASS can never name a real next-hop host
    // (unspecified `0.0.0.0`/`::`, loopback `127/8`/`::1`, multicast
    // `224/4`/`ff00::/8`, or the IPv4 limited broadcast
    // `255.255.255.255`). Caching such a `(ingress_ifindex, spoofed_ip) ->
    // src_mac` entry poisons the userspace `dynamic_neighbors` map (and,
    // via `add_kernel_neighbor` on the ARP/NDP siblings, could feed the
    // kernel table) with an impossible next-hop identity. Reuse the single
    // source of truth `neighbor_ip_is_learnable` (handles v4+v6) rather
    // than re-deriving the class checks. Runs BEFORE the own-IP gate and
    // the `learn_pair_if_changed` insert so a rejected learn neither caches
    // nor bumps `mac_change_epoch` (#3048/#3169). Rejection means
    // do-not-learn only — the packet still forwards; this is a learn-path
    // guard, not a packet filter.
    if !neighbor_ip_is_learnable(src_ip) {
        return;
    }
    // #3182: anti-poisoning own-IP gate on the #1787 RX source-MAC learn
    // path, mirroring the #2851 ARP/NDP gate in poll_stages.rs. An attacker
    // can spoof a transit packet whose SOURCE IP is one of the router's own
    // configured interface IPs; never cache `(ingress_ifindex, our_own_ip)
    // -> attacker_mac`. Driven from the NAT-decoupled
    // `configured_iface_v*` set (via `owns_configured_ip`) so the
    // NAT-excluded WAN/SNAT interface IP — the only forwarding-relevant
    // own-IP overlap on this path — is rejected too. Runs BEFORE the
    // dedup pre-check / `learn_pair_if_changed` insert so a rejected own-IP
    // neither caches nor bumps `mac_change_epoch` (#3048/#3169). Genuine
    // non-own neighbors are unaffected.
    if forwarding.owns_configured_ip(src_ip) {
        return;
    }
    // #1787: stack array, no per-packet heap alloc. At most 2 keys:
    // the physical ingress ifindex plus the resolved logical (VLAN
    // sub-) ifindex when it differs. keys[1] stays an unused
    // placeholder when n == 1.
    let mut keys: [(i32, IpAddr); 2] = [(ingress_ifindex, src_ip), (0, src_ip)];
    let mut n = 1usize;
    if let Some(logical_ifindex) =
        resolve_ingress_logical_ifindex(forwarding, ingress_ifindex, ingress_vlan_id)
    {
        if logical_ifindex > 0 && logical_ifindex != ingress_ifindex {
            keys[1] = (logical_ifindex, src_ip);
            n = 2;
        }
    }
    // #1787 cheap-first pre-check: 1-2 single-shard reads replace the
    // unconditional 64-shard bulk acquisition in the steady state
    // (every key already maps to src_mac → return with no write, no
    // bulk lock, no alloc).
    //
    // Linearization semantics: a no-op learn linearizes at this
    // pre-check read. A concurrent remove (netlink FAILED/delete,
    // resolver authoritative-FAILED revoke, manager replace/bulk
    // remove) that lands AFTER the read wins — the elided write does
    // not re-create the entry — and the next packet from this source
    // that REACHES this function pre-check-misses and re-learns via
    // the bulk path below.
    //
    // Dedup window: the caller sets the per-binding
    // last_learned_neighbor dedup after this returns (including after
    // an elided no-op), so identical follow-up packets may not reach
    // this function until the dedup key changes. That dedup-delayed
    // re-learn is PRE-EXISTING behavior — a write also set the dedup,
    // so a remove landing after the write was equally suppressed.
    // Recovery comes from the same paths as before: a second source
    // key evicting the 1-entry dedup, the ARP/NDP learn stage
    // (poll_stages.rs), and the #1769 resolver probe on forwarding
    // miss.
    let mut current: [Option<[u8; 6]>; 2] = [None, None];
    // #5673: track whether EVERY candidate key is a NEW learn whose shard is
    // already at the per-shard cap. `get_with_capacity` reads the MAC and the
    // shard fullness under ONE shard lock (same cost as the former `get`), so
    // the pre-check pays no extra lock. Starts true and is cleared the moment
    // any key is already present (an update, not growth) OR any key's shard
    // still has room (a learnable new key).
    let mut all_new_at_cap = n > 0;
    for (slot, key) in current.iter_mut().zip(keys[..n].iter()) {
        let (entry, shard_full) = dynamic_neighbors.get_with_capacity(key);
        *slot = entry.map(|e| e.mac);
        if entry.is_some() || !shard_full {
            all_new_at_cap = false;
        }
    }
    if !pair_write_needed(&current[..n], src_mac) {
        return;
    }
    // #5673: pure spoofed-source flood — every candidate key is a NEW learn
    // whose shard is at the per-shard cap, so `learn_pair_if_changed` would
    // refuse the pair wholesale. Skip the 64-shard `with_all_shards`
    // acquisition entirely: taking that bulk lock on every flood packet is
    // the all-shard serialization the M02/#5673 DoS relied on. Account the
    // refusal so it is observable, exactly like the authoritative refusal in
    // `learn_pair_if_changed` (which still covers the mixed-key and TOCTOU
    // cases where a shard fills between this pre-check and the bulk lock).
    if all_new_at_cap {
        dynamic_neighbors.note_learn_cap_drop();
        return;
    }
    // #949: multi-ifindex insert atomically vs readers — both
    // ingress_ifindex and the resolved logical (VLAN sub-) ifindex
    // get the same MAC under one bulk acquisition so a reader sees
    // either both or neither, never a stale half. Genuine changes
    // (first sighting, MAC flip, removed key) keep this exact path.
    //
    // #3169: route through the bump-aware bulk insert so a MAC CHANGE on
    // an existing dynamic neighbor advances `mac_change_epoch` — without
    // it a flow-cache `RewriteDescriptor.dst_mac` resolved from this map
    // (lookup_neighbor_entry's dynamic_neighbors fallback) stays stale
    // until session expiry, the #3048 blackhole class. The bump fires
    // only on an actual MAC change; a first sighting or same-MAC re-learn
    // adds a single Relaxed read per key and no bump.
    dynamic_neighbors.learn_pair_if_changed(&keys[..n], NeighborEntry { mac: src_mac });
}

pub(super) fn build_missing_neighbor_session_metadata(
    forwarding: &ForwardingState,
    ingress_zone: u16,
    egress_zone: u16,
    // #4983: the ingress binding of the frame that created this seed
    // (`meta.ingress_ifindex` / `meta.ingress_vlan_id`). A missing-neighbor
    // seed is a FORWARD session that survives for the life of the flow — the
    // pending-neighbor retry sweep replays the buffered frame but never
    // re-installs the session, so whatever is stamped here is the identity
    // the session carries until it expires. Leaving it 0 (as before) meant
    // every flow whose first packet raced an unresolved ARP/NDP kept the zone
    // approximation forever — a routine cold-start case on a busy LAN.
    ingress_ifindex: u32,
    ingress_vlan_id: u16,
    fabric_ingress: bool,
    decision: SessionDecision,
    // #10267: the policy result is already available on the flow-backed
    // MissingNeighbor path. Preserve its matched application timeout on the
    // seed; the retry sweep never reinstalls this entry, so dropping the value
    // here silently falls back to the global per-protocol timeout for the
    // flow's entire lifetime. `None`/0 keeps the global-timeout sentinel for
    // default-timeout and flowless paths.
    inactivity_timeout: Option<u32>,
) -> SessionMetadata {
    SessionMetadata {
        ingress_ifindex,
        ingress_vlan_id,
        ingress_zone,
        egress_zone,
        ingress_zone_check: crate::session::zone_vintage_check_for_id(
            &forwarding.zone_id_to_name,
            ingress_zone,
        ),
        egress_zone_check: crate::session::zone_vintage_check_for_id(
            &forwarding.zone_id_to_name,
            egress_zone,
        ),
        owner_rg_id: owner_rg_for_resolution(forwarding, decision.resolution),
        fabric_ingress,
        is_reverse: false,
        nat64_reverse: None,
        // #2508: neighbor-seed sessions carry no per-policy `then log`.
        log_session_init: false,
        log_session_close: false,
        // #3056: a neighbor-seed session is a transient pre-resolution stub,
        // not a policy-admitted flow, so it carries no admitting policy ID.
        policy_id: 0,
        // #10267: a permitted flow-backed seed may be admitted by an
        // application with its own idle window. Convert through the shared
        // authority so zero stays the use-global sentinel and corrupt wire
        // values remain bounded by the commit-time maximum.
        inactivity_timeout_ns: crate::session::app_inactivity_timeout_ns(inactivity_timeout),
        // #3073: a neighbor-seed stub is not policy-admitted; no hit counter.
        policy_counter_idx: 0,
        policy_counter: None,
    }
}

#[cfg(test)]
#[path = "neighbor_dispatch_mirror_tests.rs"]
mod mirror_tests;

#[cfg(test)]
#[path = "neighbor_dispatch_deferred_verdict_tests.rs"]
mod deferred_verdict_tests;
#[cfg(test)]
#[path = "neighbor_dispatch_seed_timeout_10267_tests.rs"]
mod seed_timeout_10267_tests;

#[cfg(test)]
mod cold_start_probe_schedule_tests {
    use super::{PROBE_SCHEDULE_NS, probe_due};

    #[test]
    fn schedule_values_match_design() {
        // Pin the exact schedule so accidental edits fail the build
        // rather than silently regressing the cold-start design from
        // GEMINI-NEXT.md Section 3.
        assert_eq!(
            PROBE_SCHEDULE_NS,
            &[10_000_000u64, 60_000_000u64, 260_000_000u64],
        );
    }

    #[test]
    fn schedule_is_strictly_monotonic() {
        for window in PROBE_SCHEDULE_NS.windows(2) {
            assert!(
                window[0] < window[1],
                "PROBE_SCHEDULE_NS must be strictly increasing: {:?}",
                PROBE_SCHEDULE_NS
            );
        }
    }

    #[test]
    fn probe_due_fires_only_at_or_after_schedule_boundary() {
        let first = PROBE_SCHEDULE_NS[0];
        assert!(!probe_due(first - 1, 0));
        assert!(probe_due(first, 0));
        assert!(probe_due(first + 1, 0));
    }

    #[test]
    fn probe_due_walks_each_schedule_slot() {
        // After attempts=0 fires, probe_due(elapsed, 1) must wait until
        // PROBE_SCHEDULE_NS[1]; same for each subsequent slot.
        for (idx, &target) in PROBE_SCHEDULE_NS.iter().enumerate() {
            let attempts = idx as u8;
            assert!(
                !probe_due(target.saturating_sub(1), attempts),
                "slot {idx} should not fire one ns before target",
            );
            assert!(
                probe_due(target, attempts),
                "slot {idx} should fire at target",
            );
        }
    }

    #[test]
    fn probe_due_returns_false_after_schedule_exhausted() {
        let exhausted = PROBE_SCHEDULE_NS.len() as u8;
        // Even with elapsed_ns = u64::MAX, no further probes once
        // every slot has fired.
        assert!(!probe_due(u64::MAX, exhausted));
        assert!(!probe_due(u64::MAX, exhausted.saturating_add(1)));
    }

    #[test]
    fn schedule_total_window_under_pending_neigh_timeout() {
        // The schedule must finish before the SMALLEST possible
        // PENDING_NEIGH_TIMEOUT so all 3 retries fire while the packet
        // is still queued, regardless of whether option D's fast 800ms
        // timeout (kernel retrans confirmed <=250ms) or the 2000ms
        // fallback is active (#1636). We gate on the 800ms fast value
        // minus a 100ms margin so the assertion holds under both paths.
        let last = *PROBE_SCHEDULE_NS.last().expect("schedule non-empty");
        let min_timeout = super::super::forwarding_build::PENDING_NEIGH_TIMEOUT_FAST_NS;
        assert!(
            min_timeout < super::PENDING_NEIGH_TIMEOUT_NS,
            "fast timeout must be below the 2s fallback",
        );
        assert!(
            last < min_timeout.saturating_sub(100_000_000),
            "last probe slot {last}ns must be < min PENDING_NEIGH_TIMEOUT ({min_timeout}ns) - 100ms",
        );
    }

    // #1771 §2.2: the former `simulate_sweep_for_neighbor` helper and its
    // `dedup_emits_one_probe_*` / `iface_miss_*` tests modeled the OLD
    // per-sweep BTreeSet probe-dedup over many packets sharing one
    // `(egress_ifindex, next_hop)`. That dedup no longer exists: the keyed
    // `pending_neigh` map holds exactly ONE entry per hop, so "one probe per
    // neighbor per slot" is now a structural invariant rather than a
    // runtime-deduped property. The probe schedule itself stays covered by
    // the `PROBE_SCHEDULE_NS` / `probe_due` bound tests above, and the live
    // sweep (incl. the iface-miss no-advance branch) by the
    // `retry_pending_*` dispatch tests in `mirror_tests`. Removed rather than
    // left asserting impossible multi-packet-same-key state (Codex r2).
}

#[cfg(test)]
mod learn_precheck_tests {
    use super::pair_write_needed;

    const MAC: [u8; 6] = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
    const OTHER: [u8; 6] = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];

    #[test]
    fn single_key_current_needs_no_write() {
        assert!(!pair_write_needed(&[Some(MAC)], MAC));
    }

    #[test]
    fn single_key_miss_needs_write() {
        assert!(pair_write_needed(&[None], MAC));
    }

    #[test]
    fn single_key_stale_needs_write() {
        assert!(pair_write_needed(&[Some(OTHER)], MAC));
    }

    #[test]
    fn pair_matrix_any_miss_or_stale_needs_write() {
        // Full 3x3 matrix over {current, stale, miss} per slot: a
        // write is needed unless BOTH slots already carry src_mac.
        let states: [Option<[u8; 6]>; 3] = [Some(MAC), Some(OTHER), None];
        for a in states {
            for b in states {
                let expected = !(a == Some(MAC) && b == Some(MAC));
                assert_eq!(
                    pair_write_needed(&[a, b], MAC),
                    expected,
                    "slots {a:?}/{b:?}",
                );
            }
        }
    }

    #[test]
    fn empty_slice_needs_no_write() {
        // Degenerate: learn_dynamic_neighbor always passes n >= 1.
        // Pinned so the `any`-over-slice semantics stay explicit.
        assert!(!pair_write_needed(&[], MAC));
    }
}

#[cfg(test)]
mod pending_admission_tests {
    use super::{PendingNeighAdmission, pending_neigh_admission};
    use crate::afxdp::MAX_PENDING_NEIGH;

    /// Invariant N1's buffering half (#1771 §2.4): exactly one buffered
    /// packet per `(egress_ifindex, next_hop)` — the first packet
    /// buffers, every same-key sibling is a DuplicateDrop regardless of
    /// how much room remains.
    #[test]
    fn first_packet_buffers_siblings_duplicate_drop() {
        assert_eq!(
            pending_neigh_admission(false, 0),
            PendingNeighAdmission::Buffer
        );
        assert_eq!(
            pending_neigh_admission(true, 1),
            PendingNeighAdmission::DuplicateDrop
        );
        // Duplicate wins even with plenty of room…
        assert_eq!(
            pending_neigh_admission(true, 10),
            PendingNeighAdmission::DuplicateDrop
        );
        // …and even at the cap (the duplicate counter must not be
        // conflated with the capacity case — #1782 split).
        assert_eq!(
            pending_neigh_admission(true, MAX_PENDING_NEIGH),
            PendingNeighAdmission::DuplicateDrop
        );
    }

    /// The cap applies only to NEW keys: the last slot below the cap
    /// buffers, at the cap a new key is a CapacityDrop.
    #[test]
    fn new_key_capacity_boundary() {
        assert_eq!(
            pending_neigh_admission(false, MAX_PENDING_NEIGH - 1),
            PendingNeighAdmission::Buffer
        );
        assert_eq!(
            pending_neigh_admission(false, MAX_PENDING_NEIGH),
            PendingNeighAdmission::CapacityDrop
        );
    }

    /// #2375 fail-on-revert: the capacity-drop branch increments
    /// `pending_neigh_capacity_drops` and ONLY that counter, kept
    /// distinct from `pending_neigh_duplicate_drops`. This test drives
    /// the same `record_pending_neigh_admission_drop` helper the poll
    /// loop calls, so deleting the capacity increment (the original
    /// silent `CapacityDrop => {}` bug) fails here. Buffer is a no-op.
    #[test]
    fn record_drop_counts_capacity_separately() {
        use super::record_pending_neigh_admission_drop;
        use crate::afxdp::binding_state::BindingLiveState;
        use std::sync::atomic::Ordering;

        let live = BindingLiveState::new();
        assert_eq!(live.pending_neigh_capacity_drops.load(Ordering::Relaxed), 0);
        assert_eq!(
            live.pending_neigh_duplicate_drops.load(Ordering::Relaxed),
            0
        );

        // Buffer is not a drop — neither counter moves.
        record_pending_neigh_admission_drop(&live, PendingNeighAdmission::Buffer);
        assert_eq!(live.pending_neigh_capacity_drops.load(Ordering::Relaxed), 0);
        assert_eq!(
            live.pending_neigh_duplicate_drops.load(Ordering::Relaxed),
            0
        );

        // A capacity drop bumps ONLY the capacity counter.
        record_pending_neigh_admission_drop(&live, PendingNeighAdmission::CapacityDrop);
        assert_eq!(live.pending_neigh_capacity_drops.load(Ordering::Relaxed), 1);
        assert_eq!(
            live.pending_neigh_duplicate_drops.load(Ordering::Relaxed),
            0,
            "capacity drop must not be conflated with the duplicate counter"
        );

        // Three more distinct-hop capacity drops → exactly 4 total
        // (mirrors the issue's MAX_PENDING_NEIGH-then-one-more scenario
        // repeated; the increment is per refused new key).
        for _ in 0..3 {
            record_pending_neigh_admission_drop(&live, PendingNeighAdmission::CapacityDrop);
        }
        assert_eq!(live.pending_neigh_capacity_drops.load(Ordering::Relaxed), 4);

        // A duplicate drop bumps ONLY the duplicate counter, leaving the
        // capacity counter narrow.
        record_pending_neigh_admission_drop(&live, PendingNeighAdmission::DuplicateDrop);
        assert_eq!(
            live.pending_neigh_duplicate_drops.load(Ordering::Relaxed),
            1
        );
        assert_eq!(live.pending_neigh_capacity_drops.load(Ordering::Relaxed), 4);
    }
}

#[cfg(test)]
mod pending_neigh_flow_key_tests {
    use super::*;

    /// Full (non-fragment) IPv4 ICMP frame: eth(14) + IPv4(20, proto=ICMP) +
    /// 8-byte ICMP header of the given type. `total_len` covers the ICMP
    /// header so the type byte and the [l4+4..l4+6] word both lie inside the
    /// declared datagram. Bytes [l4+4..l4+6] are 0xBEEF — the ungated
    /// pseudo source port the shim stamps for every ICMP type.
    fn eth_ipv4_icmp_frame(icmp_type: u8) -> Vec<u8> {
        let mut f = vec![
            0x02, 0xbf, 0x72, 0x00, 0x80, 0x08, 0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5, 0x08, 0x00,
        ];
        let icmp = [icmp_type, 0x00, 0x00, 0x00, 0xbe, 0xef, 0x00, 0x01];
        let mut ip = vec![0u8; 20];
        ip[0] = 0x45;
        let total = (20 + icmp.len()) as u16;
        ip[2..4].copy_from_slice(&total.to_be_bytes());
        ip[8] = 64; // ttl
        ip[9] = PROTO_ICMP;
        ip[12..16].copy_from_slice(&[10, 0, 61, 100]); // src
        ip[16..20].copy_from_slice(&[172, 16, 80, 200]); // dst
        f.extend_from_slice(&ip);
        f.extend_from_slice(&icmp);
        f
    }

    fn hostile_meta(protocol: u8) -> UserspaceDpMeta {
        UserspaceDpMeta {
            addr_family: libc::AF_INET as u8,
            protocol,
            l3_offset: 14,
            l4_offset: 34,
            flow_src_port: 0xBEEF,
            flow_dst_port: 0,
            flow_src_addr: [10, 0, 61, 100, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            flow_dst_addr: [172, 16, 80, 200, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            ..UserspaceDpMeta::default()
        }
    }

    #[test]
    fn control_icmp_buffers_no_synthesized_flow_key() {
        // #3290 (pending-neigh path): a non-query ICMPv4 control packet
        // (Time-Exceeded) whose next-hop is UNRESOLVED must NOT buffer the
        // shim's fake pseudo-port as PendingNeighPacket.flow_key. The primary
        // flow is None for these packets (conntrack-side #3290 gate); the
        // metadata fallback must therefore also yield None so retry_pending_neigh
        // feeds None into CoS/TX. Reverting the ICMP gate makes the fallback
        // synthesize Some(src_port=0xBEEF) -> RED.
        let frame = eth_ipv4_icmp_frame(11);
        assert_eq!(
            pending_neigh_flow_key(None, &frame, hostile_meta(PROTO_ICMP)),
            None,
            "control ICMP must buffer no metadata-derived pending flow key"
        );
    }

    #[test]
    fn echo_icmp_keeps_identifier_pending_flow_key() {
        // Identifier-bearing query (Echo Request) keeps its meta tuple — the
        // gate must not over-suppress legitimate query flows.
        let frame = eth_ipv4_icmp_frame(8);
        let key = pending_neigh_flow_key(None, &frame, hostile_meta(PROTO_ICMP))
            .expect("ICMP echo keeps its identifier pending flow key");
        assert_eq!(key.src_port, 0xBEEF);
        assert_eq!(key.dst_port, 0);
    }

    #[test]
    fn flowless_tcp_keeps_meta_pending_flow_key() {
        // The ICMP gate is protocol-scoped: a flowless TCP packet with
        // in-declared ports still buffers its real meta-derived ports. (#9894
        // reads the frame for the declared-end check now, but this fixture's
        // [l4,l4+4) lies inside its total_len=28, so the fallback is kept.)
        let frame = eth_ipv4_icmp_frame(8);
        let key = pending_neigh_flow_key(None, &frame, hostile_meta(PROTO_TCP))
            .expect("flowless TCP keeps its meta pending flow key");
        assert_eq!(key.src_port, 0xBEEF);
    }

    /// Short-total_len TCP frame: total_len=20 (no declared L4) with 4
    /// trailing slack bytes spelling (1111, 443) — what the shim copies
    /// into metadata from beyond the declared datagram.
    fn eth_ipv4_slack_tcp_frame() -> Vec<u8> {
        let mut f = vec![
            0x02, 0xbf, 0x72, 0x00, 0x80, 0x08, 0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5, 0x08, 0x00,
        ];
        let mut ip = vec![0u8; 20];
        ip[0] = 0x45;
        ip[2..4].copy_from_slice(&20u16.to_be_bytes());
        ip[8] = 64; // ttl
        ip[9] = PROTO_TCP;
        ip[12..16].copy_from_slice(&[10, 0, 61, 100]); // src
        ip[16..20].copy_from_slice(&[172, 16, 80, 200]); // dst
        f.extend_from_slice(&ip);
        f.extend_from_slice(&[0x04, 0x57, 0x01, 0xbb]); // slack (1111, 443)
        f
    }

    #[test]
    fn slack_tcp_buffers_no_synthesized_flow_key_9894() {
        // #9894 (GPT-3, deferred path): a short-total_len TCP packet whose
        // next-hop is UNRESOLVED must NOT buffer the shim's slack-spelled
        // tuple as PendingNeighPacket.flow_key. The primary flow is None
        // for it (conntrack-side fast-path gate); the metadata fallback
        // must therefore also yield None so retry_pending_neigh feeds None
        // into CoS/TX — the same gate the immediate path applies. Reverting
        // it buffers Some((1111, 443)) -> RED.
        let frame = eth_ipv4_slack_tcp_frame();
        let meta = UserspaceDpMeta {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            l3_offset: 14,
            l4_offset: 34,
            flow_src_port: 1111,
            flow_dst_port: 443,
            flow_src_addr: [10, 0, 61, 100, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            flow_dst_addr: [172, 16, 80, 200, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            ..UserspaceDpMeta::default()
        };
        assert_eq!(
            pending_neigh_flow_key(None, &frame, meta),
            None,
            "slack TCP must buffer no metadata-derived pending flow key"
        );
    }
}
