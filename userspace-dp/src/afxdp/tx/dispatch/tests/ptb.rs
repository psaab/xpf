// #2301 / #2328 egress-MTU Packet-Too-Big (PTB) end-to-end tests through
// `enqueue_pending_forwards`: ICMP Frag-Needed generation + oversized-original
// drop, the in-MTU counter-factual, and generated-reply classification by the
// PTB's own egress tuple (output-filter discard / DSCP rewrite / fail-closed
// parse error). Local harness helpers `large_udp_v4_df_frame`,
// `forwarding_for_ptb[_with_output_term]`, `run_ptb_dispatch[_with_forwarding]`.

use super::*;

// #2301: end-to-end egress-MTU PTB through `enqueue_pending_forwards`.
//
// Build a large UDP IPv4 (DF) frame in the ingress UMEM, point the forward
// at egress ifindex 80 with a SMALL MTU, and add an egress entry for the
// INGRESS interface (ifindex 11) so the reflected reply can be sourced.
// The dispatcher must:
//   - enqueue an ICMP Frag-Needed (type 3 code 4, next-hop MTU) back out
//     the ingress binding,
//   - NOT forward the oversized original to the egress binding,
//   - recycle the ingress descriptor exactly once,
//   - record the `egress_mtu_exceeded` exception.
// The counter-factual (large MTU) proves the gate fires only on a real MTU
// violation: the frame forwards normally and no PTB lands on the ingress.

/// Build a large IPv4 UDP frame (Ethernet + IP + UDP + payload) with the
/// DF bit set. `l3_payload` is the total L3 length excluding the 14-byte
/// Ethernet header.
fn large_udp_v4_df_frame(l3_payload: usize) -> Vec<u8> {
    assert!(l3_payload >= 28, "need room for IP+UDP headers");
    let mut frame = Vec::with_capacity(14 + l3_payload);
    // L2: dst = firewall NIC, src = sender. EtherType IPv4.
    frame.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
    frame.extend_from_slice(&[0x00, 0x25, 0x90, 0x12, 0x34, 0x56]);
    frame.extend_from_slice(&0x0800u16.to_be_bytes());
    let l3 = frame.len();
    frame.push(0x45);
    frame.push(0x00);
    frame.extend_from_slice(&(l3_payload as u16).to_be_bytes());
    frame.extend_from_slice(&[0x00, 0x01]); // ID
    frame.extend_from_slice(&0x4000u16.to_be_bytes()); // DF=1
    frame.extend_from_slice(&[64, 17, 0x00, 0x00]); // TTL, proto UDP, csum
    frame.extend_from_slice(&[198, 51, 100, 20]); // src
    frame.extend_from_slice(&[203, 0, 113, 9]); // dst
    let csum = crate::afxdp::tx::test_support::compute_ipv4_header_checksum(&frame[l3..l3 + 20]);
    frame[l3 + 10..l3 + 12].copy_from_slice(&csum.to_be_bytes());
    // UDP header + payload to fill out to l3_payload.
    frame.extend_from_slice(&49152u16.to_be_bytes());
    frame.extend_from_slice(&5201u16.to_be_bytes());
    frame.extend_from_slice(&((l3_payload - 20) as u16).to_be_bytes());
    frame.extend_from_slice(&0u16.to_be_bytes());
    frame.resize(14 + l3_payload, 0xAB);
    frame
}

/// Forwarding state for the PTB e2e test: egress 80 with `mtu`, plus an
/// egress entry for the ingress interface (ifindex 11) carrying a primary
/// v4 so the reflected error can be built.
fn forwarding_for_ptb(mtu: usize) -> ForwardingState {
    let mut forwarding = test_forwarding_with_egress_mtu(mtu);
    forwarding.egress.insert(
        11,
        EgressInterface {
            bind_ifindex: 11,
            vlan_id: 0,
            mtu: 1500,
            src_mac: [0x02, 0xbf, 0x72, 0x16, 0x00, 0x01],
            zone_id: TEST_TRUST_ZONE_ID,
            redundancy_group: 0,
            primary_v4: Some(std::net::Ipv4Addr::new(10, 0, 1, 1)),
            primary_v6: None,
        },
    );
    forwarding
}

fn run_ptb_dispatch(egress_mtu: usize) -> (Vec<BindingWorker>, DebugPollCounters, Vec<String>) {
    let (bindings, dbg, _counters, reasons) =
        run_ptb_dispatch_with_forwarding(forwarding_for_ptb(egress_mtu));
    (bindings, dbg, reasons)
}

/// #2328: PTB e2e harness parameterized on the full `ForwardingState` so a
/// test can install an output firewall filter / CoS classifier on the egress
/// (ingress-reflected) interface (ifindex 11) and observe the generated PTB
/// being classified by its OWN egress tuple. Returns the `BatchCounters` so
/// the fail-on-revert tests can assert the generated-reply drop counters.
fn run_ptb_dispatch_with_forwarding(
    forwarding: ForwardingState,
) -> (
    Vec<BindingWorker>,
    DebugPollCounters,
    BatchCounters,
    Vec<String>,
) {
    run_ptb_dispatch_with_forwarding_and_vlan(forwarding, 0)
}

/// #6102: PTB e2e harness variant that stamps the ingress frame's meta with a
/// VLAN id, so a test can drive a tagged sub-interface through the physical
/// bind port (ifindex 11) and exercise `resolve_ingress_logical_ifindex` in
/// both the PTB build and classify sites.
fn run_ptb_dispatch_with_forwarding_and_vlan(
    forwarding: ForwardingState,
    ingress_vlan_id: u16,
) -> (
    Vec<BindingWorker>,
    DebugPollCounters,
    BatchCounters,
    Vec<String>,
) {
    let mut bindings = vec![
        BindingWorker::new_for_mirror_test(0, 0, 11, 0),
        BindingWorker::new_for_mirror_test(1, 0, 22, 0),
    ];
    // 1600-byte L3 payload -> 1614-byte frame. Fits a 4096 UMEM frame but
    // exceeds a 1400 egress MTU.
    let frame = large_udp_v4_df_frame(1600);
    unsafe { bindings[0].umem.area().slice_mut_unchecked(0, frame.len()) }
        .expect("ingress frame")
        .copy_from_slice(&frame);

    let lookup = WorkerBindingLookup::from_bindings(&bindings);
    let mirror_targets = MirrorTargetMap::default();
    // UDP (not TCP) so the TCP-segmentation path is skipped and the
    // egress-MTU decision is the only oversized handler.
    let mut req = test_live_forward_request_for_frame(
        frame.len(),
        test_forwarding_decision_to_bound_ifindex(22),
    );
    req.meta.protocol = PROTO_UDP;
    req.meta.l3_offset = 14;
    req.meta.l4_offset = 34;
    req.meta.pkt_len = frame.len() as u16;
    req.meta.ingress_vlan_id = ingress_vlan_id;
    let mut pending = vec![req];
    let mut post_recycles = Vec::new();
    let ingress_ident = bindings[0].identity();
    let ingress_live = &*bindings[0].live as *const BindingLiveState;
    let local_tunnel_deliveries: Arc<ArcSwap<BTreeMap<i32, LocalTunnelDelivery>>> =
        Arc::new(ArcSwap::from_pointee(BTreeMap::new()));
    let recent_exceptions = Arc::new(Mutex::new(ExceptionEventRing::new()));
    let worker_commands_by_id: BTreeMap<u32, Arc<Mutex<VecDeque<WorkerCommand>>>> = BTreeMap::new();
    let mut dbg = DebugPollCounters::default();
    let mut counters = BatchCounters::default();

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
        &mut counters,
        0,
        &worker_commands_by_id,
    );
    let reasons: Vec<String> = recent_exceptions
        .lock()
        .expect("exceptions")
        .iter()
        .map(|e| e.reason().to_string())
        .collect();
    (bindings, dbg, counters, reasons)
}

#[test]
fn oversized_forward_emits_ptb_and_drops_original() {
    // #5567: emits a PTB — serialise over the shared PacketTooBig bucket so a
    // concurrent drainer test cannot empty it mid-assertion.
    let _g = crate::afxdp::icmp_ratelimit::global_bucket_test_lock();
    let (bindings, _dbg, reasons) = run_ptb_dispatch(1400);

    // PTB enqueued back out the INGRESS binding (slot 0).
    let ingress_tx = &bindings[0].tx_pipeline.pending_tx_local;
    assert_eq!(
        ingress_tx.len(),
        1,
        "exactly one ICMP Frag-Needed must be enqueued on the ingress binding"
    );
    let reply = &ingress_tx[0];
    assert_eq!(
        reply.egress_ifindex, 11,
        "PTB leaves via the ingress interface"
    );
    let b = &reply.bytes;
    assert_eq!(
        &b[0..6],
        &[0x00, 0x25, 0x90, 0x12, 0x34, 0x56],
        "reflected to the sender"
    );
    assert_eq!(&b[12..14], &[0x08, 0x00], "IPv4 reply");
    assert_eq!(b[14], 0x45);
    assert_eq!(b[23], PROTO_ICMP, "outer ICMP");
    let icmp = 14 + 20;
    assert_eq!(b[icmp], 3, "ICMP type 3");
    assert_eq!(b[icmp + 1], 4, "code 4 (Frag Needed)");
    assert_eq!(
        u16::from_be_bytes([b[icmp + 6], b[icmp + 7]]),
        1400,
        "advertised next-hop MTU"
    );

    // The oversized original was NOT forwarded to the egress binding.
    assert_eq!(
        bindings[1].tx_pipeline.pending_tx_local.len(),
        0,
        "oversized original must not be forwarded"
    );
    assert_eq!(
        bindings[1].tx_pipeline.pending_tx_prepared.len(),
        0,
        "oversized original must not be prepared for the egress TX ring"
    );
    // Ingress descriptor recycled exactly once (no leak, no double).
    assert_eq!(ingress_recycled_count(&bindings[0]), 1);
    assert!(
        reasons.iter().any(|r| r == "egress_mtu_exceeded"),
        "egress-MTU exception recorded: {reasons:?}"
    );
    // The original was NOT silently dropped without a signal: no
    // oversized_forward_frame / slow-path drop was recorded.
    assert!(
        !reasons.iter().any(|r| r == "oversized_forward_frame"),
        "MTU drop must not be miscounted as a descriptor-capacity overflow: {reasons:?}"
    );
}

#[test]
fn in_mtu_forward_emits_no_ptb_counterfactual() {
    // Same 1614-byte frame, but a 9000 (jumbo) egress MTU. The frame now
    // fits, so it forwards normally and NO PTB lands on the ingress. This
    // is the fail-on-revert pin: if the decision wrongly fired on an
    // in-MTU frame, the ingress would carry a spurious ICMP error.
    let (bindings, _dbg, reasons) = run_ptb_dispatch(9000);
    assert_eq!(
        bindings[0].tx_pipeline.pending_tx_local.len(),
        0,
        "no PTB may be generated for an in-MTU frame"
    );
    assert!(
        !reasons.iter().any(|r| r == "egress_mtu_exceeded"),
        "no egress-MTU exception for an in-MTU frame: {reasons:?}"
    );
    // The frame was actually forwarded to the egress binding (slot 1),
    // proving the in-MTU fast path is untouched.
    let egress_tx = bindings[1].tx_pipeline.pending_tx_local.len()
        + bindings[1].tx_pipeline.pending_tx_prepared.len();
    assert_eq!(
        egress_tx, 1,
        "in-MTU frame must forward to the egress binding"
    );
}

/// #2328: build a v4 output firewall filter on the PTB egress interface
/// (ifindex 11 — the ingress interface the PTB is reflected back out of)
/// carrying a single term, and splice it onto `forwarding_for_ptb`. The
/// trigger frame is UDP, so a term keyed on `protocol icmp` fires ONLY for
/// the GENERATED ICMP Frag-Needed reply — proving classify-by-the-PTB's-own
/// egress tuple, not the UDP trigger tuple.
fn forwarding_for_ptb_with_output_term(
    mtu: usize,
    term: crate::FirewallTermSnapshot,
) -> ForwardingState {
    let mut forwarding = forwarding_for_ptb(mtu);
    forwarding.filter_state = crate::filter::parse_filter_state(
        &[crate::FirewallFilterSnapshot {
            name: "ptb-out".into(),
            family: "inet".into(),
            terms: vec![term],
        }],
        &[],
        &[crate::InterfaceSnapshot {
            name: "ge-0/0/0.0".into(),
            ifindex: 11,
            filter_output_v4: "ptb-out".into(),
            ..Default::default()
        }],
        "",
        "",
    ).expect("filter state compiles");
    forwarding.tx_selection_enabled_v4 = true;
    forwarding
}

/// #2328: an OUTPUT firewall filter `then discard` matching `protocol icmp`
/// on the PTB egress interface drops the GENERATED Frag-Needed reply — the
/// PTB is now classified by its own egress tuple (#2238 contract parity with
/// Time Exceeded / policy-reject / SYN-cookie). The drop lands on the
/// dedicated `ptb_output_filter_drops` counter. Fail-on-revert: if the PTB
/// enqueue reverts to the pre-#2328 unclassified `cos_queue_id: None,
/// dscp_rewrite: None` (no `classify_generated_reply` call), the PTB would be
/// enqueued and this assertion fails.
#[test]
fn ptb_dropped_by_egress_output_filter_discard() {
    // #5567: the PTB must be built + pass the token before the output-filter
    // classify runs, so this drop-attribution test needs a non-empty bucket.
    let _g = crate::afxdp::icmp_ratelimit::global_bucket_test_lock();
    let (bindings, _dbg, counters, reasons) =
        run_ptb_dispatch_with_forwarding(forwarding_for_ptb_with_output_term(
            1400,
            crate::FirewallTermSnapshot {
                name: "drop-icmp".into(),
                action: "discard".into(),
                protocols: vec!["icmp".into()],
                ..Default::default()
            },
        ));
    // The generated PTB was DROPPED (not enqueued) by the output `discard`.
    assert_eq!(
        bindings[0].tx_pipeline.pending_tx_local.len(),
        0,
        "an output `then discard` (protocol icmp) on the egress interface must drop the generated PTB"
    );
    // Drop attributed to the dedicated PTB counter, not the parse-error one.
    assert!(
        counters.ptb_output_filter_drops >= 1,
        "output-filter drop of the PTB must land on ptb_output_filter_drops"
    );
    assert_eq!(counters.generated_reply_classify_parse_errors, 0);
    // The oversized original is still dropped (PMTUD), and the descriptor is
    // recycled exactly once — no leak past the fail-closed drop.
    assert_eq!(bindings[1].tx_pipeline.pending_tx_local.len(), 0);
    assert_eq!(bindings[1].tx_pipeline.pending_tx_prepared.len(), 0);
    assert_eq!(ingress_recycled_count(&bindings[0]), 1);
    assert!(reasons.iter().any(|r| r == "egress_mtu_exceeded"));
}

/// #6102 forwarding state: a tagged VLAN sub-interface. The ingress AF_XDP
/// binding is the PHYSICAL parent (ifindex 11); the reflected-reply egress and
/// its output filter live on the LOGICAL unit (ifindex 12, reth0.80). There is
/// NO egress entry for the physical parent 11 — so a physical-keyed build (a
/// reverted #6102 fix) misses and the PTB is silently build-dropped. The
/// daemon's `ingress_logical_ifindex` map resolves `(11, 80) -> 12`.
fn forwarding_for_ptb_vlan_subif_6102(mtu: usize) -> ForwardingState {
    // Base carries the FORWARD egress (ifindex 80, small MTU) that triggers the
    // PTB; it does NOT add an egress for the physical ingress parent 11.
    let mut forwarding = test_forwarding_with_egress_mtu(mtu);
    // The reflected reply's egress, keyed by the LOGICAL unit 12 ONLY.
    forwarding.egress.insert(
        12,
        EgressInterface {
            bind_ifindex: 11,
            vlan_id: 80,
            mtu: 1500,
            src_mac: [0x02, 0xbf, 0x72, 0x00, 0x80, 0x08],
            zone_id: TEST_WAN_ZONE_ID,
            redundancy_group: 0,
            primary_v4: Some(std::net::Ipv4Addr::new(172, 16, 80, 8)),
            primary_v6: None,
        },
    );
    // Daemon-built `(physical bind, vlan) -> logical unit` map (the SSOT the fix
    // resolves through, interfaces.rs:291-301).
    forwarding.ingress_logical_ifindex.insert((11, 80), 12);
    // OUTPUT `then discard protocol icmp` on the LOGICAL unit 12 ONLY; the
    // physical parent 11 carries no filter and no egress.
    forwarding.filter_state = crate::filter::parse_filter_state(
        &[crate::FirewallFilterSnapshot {
            name: "ptb-out".into(),
            family: "inet".into(),
            terms: vec![crate::FirewallTermSnapshot {
                name: "drop-icmp".into(),
                action: "discard".into(),
                protocols: vec!["icmp".into()],
                ..Default::default()
            }],
        }],
        &[],
        &[crate::InterfaceSnapshot {
            name: "reth0.80".into(),
            ifindex: 12,
            parent_ifindex: 11,
            vlan_id: 80,
            filter_output_v4: "ptb-out".into(),
            ..Default::default()
        }],
        "",
        "",
    )
    .expect("filter state compiles");
    forwarding.tx_selection_enabled_v4 = true;
    forwarding
}

/// #6102 fail-on-revert (PTB analogue of the Time Exceeded test): the generated
/// egress-MTU PTB on a tagged VLAN sub-interface must be BUILT from and
/// CLASSIFIED on the LOGICAL unit (ifindex 12), resolved from the physical bind
/// port (ifindex 11) + `ingress_vlan_id` 80 — not the physical
/// `ingress_ident.ifindex`. The unit's OWN output `then discard protocol icmp`
/// filter drops the PTB. The double assertion (`len == 0` AND
/// `ptb_output_filter_drops == 1`) fails RED on every revert to the physical
/// index:
///   - revert the BUILD to physical 11 -> `egress.get(11)` = None -> PTB never
///     built -> nothing enqueued but `ptb_output_filter_drops == 0` FAILS RED
///     (this is the primary silent-drop bug the fix closes).
///   - revert the CLASSIFY to physical 11 -> PTB built on 12 but classified on
///     11 (no filter) -> PTB ENQUEUED -> `len == 0` FAILS RED.
#[test]
fn ptb_resolves_logical_ingress_for_build_and_classify_6102() {
    // #5567: the PTB must be built + pass the token before the output-filter
    // classify runs, so this drop-attribution test needs a non-empty bucket.
    let _g = crate::afxdp::icmp_ratelimit::global_bucket_test_lock();
    let (bindings, _dbg, counters, reasons) =
        run_ptb_dispatch_with_forwarding_and_vlan(forwarding_for_ptb_vlan_subif_6102(1400), 80);
    // Built on logical unit 12 (egress miss on physical 11 would have dropped
    // it) and dropped by unit 12's OWN output `discard` (a physical-keyed
    // classify on parent 11 would have wrongly admitted it).
    assert_eq!(
        bindings[0].tx_pipeline.pending_tx_local.len(),
        0,
        "the VLAN unit's output `then discard protocol icmp` (logical ifindex 12) \
         must drop the generated PTB (#6102); classifying on the physical parent \
         11 (no filter) would wrongly enqueue it"
    );
    assert_eq!(
        counters.ptb_output_filter_drops, 1,
        "the logical-egress output-filter drop must land on ptb_output_filter_drops \
         — a value of 0 means the PTB build was keyed on the physical parent 11 \
         (no egress entry) and was BUILD-dropped, not filter-dropped (a reverted \
         #6102 fix)"
    );
    assert_eq!(counters.generated_reply_classify_parse_errors, 0);
    // The oversized original is still dropped (PMTUD) and recycled once.
    assert_eq!(bindings[1].tx_pipeline.pending_tx_local.len(), 0);
    assert_eq!(ingress_recycled_count(&bindings[0]), 1);
    assert!(reasons.iter().any(|r| r == "egress_mtu_exceeded"));
}

/// #2328: an output filter matching the UDP TRIGGER tuple does NOT drop the
/// generated ICMP PTB — discriminating proof the PTB is classified by its
/// OWN (ICMP) egress tuple, not the trigger's (UDP). Sibling of the Time
/// Exceeded `ignores_trigger_matching_output_filter` test.
#[test]
fn ptb_ignores_trigger_matching_output_filter() {
    // #5567: emits a PTB (Some) — needs a non-empty bucket.
    let _g = crate::afxdp::icmp_ratelimit::global_bucket_test_lock();
    let (bindings, _dbg, counters, _reasons) =
        run_ptb_dispatch_with_forwarding(forwarding_for_ptb_with_output_term(
            1400,
            crate::FirewallTermSnapshot {
                name: "drop-udp".into(),
                action: "discard".into(),
                protocols: vec!["udp".into()],
                ..Default::default()
            },
        ));
    assert_eq!(
        bindings[0].tx_pipeline.pending_tx_local.len(),
        1,
        "an output filter matching the UDP trigger must NOT drop the generated ICMP PTB"
    );
    assert_eq!(counters.ptb_output_filter_drops, 0);
    assert_eq!(counters.generated_reply_classify_parse_errors, 0);
}

/// #2328: a forwarding-class / DSCP-rewrite output filter matching the
/// generated PTB's ICMP tuple sets the enqueued PTB TxRequest's
/// `dscp_rewrite` from the classifier verdict — NOT the pre-#2328
/// hard-coded `None`. Fail-on-revert: reverting the PTB enqueue to
/// `dscp_rewrite: None` makes the asserted rewrite disappear.
#[test]
fn ptb_dscp_rewrite_comes_from_classifier_not_none() {
    // #5567: emits a PTB (Some) — needs a non-empty bucket.
    let _g = crate::afxdp::icmp_ratelimit::global_bucket_test_lock();
    let (bindings, _dbg, counters, _reasons) =
        run_ptb_dispatch_with_forwarding(forwarding_for_ptb_with_output_term(
            1400,
            crate::FirewallTermSnapshot {
                name: "mark-icmp".into(),
                action: "accept".into(),
                protocols: vec!["icmp".into()],
                dscp_rewrite: Some(46),
                ..Default::default()
            },
        ));
    let ptb = &bindings[0].tx_pipeline.pending_tx_local;
    assert_eq!(ptb.len(), 1, "PTB accepted (then accept) and enqueued");
    assert_eq!(
        ptb[0].dscp_rewrite,
        Some(46),
        "the PTB TxRequest dscp_rewrite must come from classify_generated_reply, not None"
    );
    assert_eq!(counters.ptb_output_filter_drops, 0);
    assert_eq!(counters.generated_reply_classify_parse_errors, 0);
}

/// #2328 §6.2 fail-CLOSED canary: the PTB path routes a generated-reply parse
/// failure through `classify_generated_reply`, which returns
/// `drop: true, parse_error: true` for bytes it cannot re-parse. The
/// dispatch wiring maps that verdict onto
/// `generated_reply_classify_parse_errors` and drops the PTB (never leaking
/// it past an output `discard`). This pins the shared mechanism the PTB
/// enqueue depends on: truncated/malformed reply bytes fail closed.
#[test]
fn ptb_parse_failure_fails_closed_with_parse_error_verdict() {
    let forwarding = forwarding_for_ptb(1400);
    // Bytes too short for an L3 header — frame_l3_offset / the v4 parser
    // reject them, exactly the canary a malformed PTB builder would hit.
    let malformed: Vec<u8> = vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
    let verdict = classify_generated_reply(&forwarding, 11, &malformed, 1);
    assert!(
        verdict.drop,
        "unparseable generated bytes must fail CLOSED (drop)"
    );
    assert!(
        verdict.parse_error,
        "the drop must be attributed as a parse error so the PTB path bumps generated_reply_classify_parse_errors"
    );
    assert_eq!(verdict.cos_queue_id, None);
    assert_eq!(verdict.dscp_rewrite, None);
}

/// #5567 HEADLINE fail-on-revert (PTB sibling of the TE test): a flood of
/// reply-ELIGIBLE-but-UNBUILDABLE Packet-Too-Big triggers — an oversized-DF
/// frame whose ingress interface has NO egress object, so `build_frag_needed_v4`
/// returns None — must NOT consume a PacketTooBig token. Pre-#5567 the token
/// was spent before the build, so such a flood drained the shared per-reason
/// bucket and starved buildable PMTUD on another interface (cross-interface
/// false-deny DoS).
///
/// Proof (mirrors the reject path's #3656 H11): pin the PacketTooBig bucket
/// EMPTY at a far-future epoch (zero refill at the call site's real clock),
/// then drive the dispatch with a forwarding that FIRES the egress-MTU
/// decision (egress 80, small MTU) but has NO egress entry for the ingress
/// interface (ifindex 11), so the PTB is unbuildable. On the fixed code the
/// build returns None and short-circuits BEFORE `allow_generated_error`, so
/// the empty bucket is untouched. On a revert the empty-bucket deny bumps the
/// rate-limited counter → RED. The oversized original is still dropped
/// (`egress_mtu_exceeded`) — the trigger disposition is unchanged.
#[test]
fn ptb_unbuildable_missing_egress_does_not_drain_token_5567() {
    use crate::afxdp::icmp_ratelimit::{
        GeneratedErrorReason, allow_generated_error_at, global_bucket_test_lock,
        rate_limited_count, reset_bucket_for_test,
    };
    let _g = global_bucket_test_lock();
    let far_future = u64::MAX / 2;
    reset_bucket_for_test(GeneratedErrorReason::PacketTooBig, far_future);
    while allow_generated_error_at(GeneratedErrorReason::PacketTooBig, far_future, 1000, 1000) {}
    let before = rate_limited_count(GeneratedErrorReason::PacketTooBig);

    // `test_forwarding_with_egress_mtu` inserts egress ONLY for the forward
    // target (ifindex 80); there is NO egress for the ingress interface
    // (ifindex 11), so `build_frag_needed_v4` returns None: reply-eligible
    // (the decision fires EmitPacketTooBig) but UNBUILDABLE.
    let (bindings, _dbg, _counters, reasons) =
        run_ptb_dispatch_with_forwarding(test_forwarding_with_egress_mtu(1400));

    assert_eq!(
        bindings[0].tx_pipeline.pending_tx_local.len(),
        0,
        "an unbuildable PTB (no egress for the ingress ifindex) enqueues nothing"
    );
    // Trigger disposition unchanged: the oversized original is still dropped.
    assert!(
        reasons.iter().any(|r| r == "egress_mtu_exceeded"),
        "the oversized original must still be dropped: {reasons:?}"
    );
    assert_eq!(bindings[1].tx_pipeline.pending_tx_local.len(), 0);
    assert_eq!(bindings[1].tx_pipeline.pending_tx_prepared.len(), 0);
    assert_eq!(ingress_recycled_count(&bindings[0]), 1);
    assert_eq!(
        rate_limited_count(GeneratedErrorReason::PacketTooBig),
        before,
        "unbuildable PTB attempts must NOT touch the shared PacketTooBig token \
         bucket (pre-#5567 they drained it and starved buildable replies)"
    );
    // Restore a full bucket so sibling emission tests are unaffected.
    reset_bucket_for_test(GeneratedErrorReason::PacketTooBig, 0);
}

/// #5567 PTB sibling: a BUILDABLE Packet-Too-Big is still rate-limited when the
/// token is exhausted (rate-limiting preserved), and a buildable PTB under a
/// full bucket is emitted while consuming a token (the rate-limited counter
/// does not move on success). The oversized original is dropped in every case.
#[test]
fn ptb_buildable_respects_and_consumes_token_5567() {
    use crate::afxdp::icmp_ratelimit::{
        GeneratedErrorReason, allow_generated_error_at, global_bucket_test_lock,
        rate_limited_count, reset_bucket_for_test,
    };
    let _g = global_bucket_test_lock();

    // (1) Exhausted bucket: a BUILDABLE PTB is suppressed and the counter bumps.
    let far_future = u64::MAX / 2;
    reset_bucket_for_test(GeneratedErrorReason::PacketTooBig, far_future);
    while allow_generated_error_at(GeneratedErrorReason::PacketTooBig, far_future, 1000, 1000) {}
    let before_rl = rate_limited_count(GeneratedErrorReason::PacketTooBig);
    let (bindings, _dbg, _counters, reasons) =
        run_ptb_dispatch_with_forwarding(forwarding_for_ptb(1400));
    assert_eq!(
        bindings[0].tx_pipeline.pending_tx_local.len(),
        0,
        "a buildable PTB must still be suppressed when the token is exhausted"
    );
    assert!(
        rate_limited_count(GeneratedErrorReason::PacketTooBig) > before_rl,
        "a rate-limited (buildable) PTB must bump the observable PacketTooBig counter"
    );
    assert!(reasons.iter().any(|r| r == "egress_mtu_exceeded"));
    assert_eq!(ingress_recycled_count(&bindings[0]), 1);

    // (2) Full bucket: the buildable PTB is emitted; the counter does not move.
    reset_bucket_for_test(GeneratedErrorReason::PacketTooBig, 0);
    let before_rl = rate_limited_count(GeneratedErrorReason::PacketTooBig);
    let (bindings, _dbg, _counters, reasons) =
        run_ptb_dispatch_with_forwarding(forwarding_for_ptb(1400));
    assert_eq!(
        bindings[0].tx_pipeline.pending_tx_local.len(),
        1,
        "a buildable PTB under a full bucket must be emitted"
    );
    assert_eq!(
        rate_limited_count(GeneratedErrorReason::PacketTooBig),
        before_rl,
        "a successful PTB consumes a token but must not bump the rate-limited counter"
    );
    assert!(reasons.iter().any(|r| r == "egress_mtu_exceeded"));
    reset_bucket_for_test(GeneratedErrorReason::PacketTooBig, 0);
}
