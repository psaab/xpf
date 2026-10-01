// #6922 — the NAT64 build-`None` drop attribution at the TX copy-fallback site.
//
// WHY THIS FILE EXISTS AT ALL. The issue's release condition asked for the
// cp1/cp2 and NAT64-attribution cells to be DEMONSTRATED to bind before the
// de-duplication is dispatched. Demonstrated at master, three of the four
// escape: swapping the two NAT64 guards' order in EITHER copy left the whole
// suite green (4816 passed, 0 failed, same collection as the control), and so
// did inverting the cp1 oversized guard. Only the cp2 oversized/enqueue
// behaviour binds, through `enqueue_failure.rs`.
//
// So the attribution — the thing the duplication is actually about — had no
// test at either copy. `nat64_tests.rs` binds the two PREDICATES standalone;
// nothing bound WHICH predicate the dispatcher consults first or WHICH counter
// it records. Collapsing two copies of code nothing checks would have produced
// one copy nothing checks.
//
// WHAT IS ASSERTED. The order is the whole rationale: `write_v6_to_v4_into`
// applies the #5625 ext-header eligibility gate BEFORE the #2562 fragment
// guards, so an AH / active-Routing / Mobility / HIP / Shim6 packet must be
// attributed to `nat64_exthdr_ineligible`, and only a genuine non-ext-header
// fragment drop may fall through to `nat64_frag_dropped`. A dispatcher that
// tested the fragment predicate first would attribute an AH packet to the wrong
// counter, and an operator reading the drop reason would chase a fragmentation
// problem that does not exist.

use super::*;
use std::sync::atomic::Ordering;

/// The DISCRIMINATING frame: IPv6 → Fragment header (non-first) → AH → TCP.
///
/// Both SSOT predicates answer TRUE for it — it is a non-first fragment AND it
/// carries an Authentication Header — and that is the entire point. The guard
/// ORDER is only observable on a frame both predicates match; on a frame only
/// one matches, `if A {a} else if B {b}` and `if B {b} else if A {a}` produce
/// the identical counter, so an order swap is a no-op and the cell measures
/// nothing.
///
/// This was learned the hard way: the first version of this file used a plain
/// AH frame (not a fragment), and swapping the dispatcher's guard order left
/// the full suite green at 4818 passed / 0 failed. The precondition test below
/// is what makes that impossible to ship unnoticed.
fn ah_fragment_v6_frame_6922() -> Vec<u8> {
    let src = std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
    let dst = std::net::Ipv6Addr::new(0x64, 0xff9b, 0, 0, 0, 0, 0xc000, 0x0201);
    // AH block: next-header TCP, length, then the SPI/sequence words.
    let ah: [u8; 12] = [PROTO_TCP, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0];
    let payload = b"hi";
    let tcp_len = 20 + payload.len();
    // Fragment header: next-header AH(51), reserved, offset<<3 (offset units
    // 1 = a NON-first fragment, which is a fragment drop for ANY protocol),
    // then the identification word.
    let frag: [u8; 8] = [51, 0, 0x00, 0x08, 0, 0, 0, 1];

    let mut l3 = vec![0u8; 40 + frag.len() + ah.len() + tcp_len];
    l3[0] = 0x60;
    l3[4..6].copy_from_slice(&((frag.len() + ah.len() + tcp_len) as u16).to_be_bytes());
    l3[6] = 44; // next header = Fragment
    l3[7] = 64; // hop limit
    l3[8..24].copy_from_slice(&src.octets());
    l3[24..40].copy_from_slice(&dst.octets());
    l3[40..40 + frag.len()].copy_from_slice(&frag);
    let a = 40 + frag.len();
    l3[a..a + ah.len()].copy_from_slice(&ah);
    let t = a + ah.len();
    l3[t..t + 2].copy_from_slice(&12345u16.to_be_bytes());
    l3[t + 2..t + 4].copy_from_slice(&80u16.to_be_bytes());
    l3[t + 12] = 0x50;
    l3[t + 13] = 0x02;
    l3[t + 14..t + 16].copy_from_slice(&1024u16.to_be_bytes());
    l3[t + 20..t + 20 + payload.len()].copy_from_slice(payload);

    let mut frame = vec![0u8; 14];
    frame[12..14].copy_from_slice(&0x86DDu16.to_be_bytes());
    frame.extend_from_slice(&l3);
    frame
}

/// PRECONDITION, and it is the assertion that makes the ordering cell mean
/// anything: BOTH predicates must answer true for this frame.
///
/// If only one matched, the two guard orders would record the same counter and
/// the cell below would pass against a dispatcher with the order reversed —
/// measured, not hypothesised. If neither matched, both counters would stay at
/// zero and the cell would assert an attribution the frame cannot produce.
#[test]
fn discriminating_frame_matches_both_nat64_predicates_6922() {
    let frame = ah_fragment_v6_frame_6922();
    assert!(
        crate::nat64::frame_is_nat64_exthdr_ineligible(&frame, libc::AF_INET6),
        "fixture must carry an ext-header the translator refuses (#5625)"
    );
    assert!(
        crate::nat64::frame_is_nat64_fragment_drop(&frame, libc::AF_INET6),
        "fixture must ALSO be a fragment drop (#2562) — the guard ORDER is only \
         observable when both predicates match. With only one matching, \
         `if A else if B` and `if B else if A` record the same counter and an \
         order swap escapes"
    );
}

#[test]
fn nat64_build_none_attributes_exthdr_before_fragment_6922() {
    let mut bindings = vec![
        BindingWorker::new_for_mirror_test(0, 0, 11, 0),
        BindingWorker::new_for_mirror_test(1, 0, 22, 0),
    ];
    let frame = ah_fragment_v6_frame_6922();
    unsafe { bindings[0].umem.area().slice_mut_unchecked(0, frame.len()) }
        .expect("ingress frame")
        .copy_from_slice(&frame);
    // Drain the egress free-TX pool so direct TX is unavailable and dispatch
    // takes the Vec-copy fallback, where the attribution lives.
    bindings[1].tx_pipeline.free_tx_frames.clear();

    let forwarding = test_forwarding_with_egress_mtu(1500);
    let lookup = WorkerBindingLookup::from_bindings(&bindings);
    let mirror_targets = MirrorTargetMap::default();

    let mut decision = test_forwarding_decision_to_bound_ifindex(22);
    decision.nat.nat64 = true;
    let mut request = test_live_forward_request_for_frame(frame.len(), decision);
    request.meta.addr_family = libc::AF_INET6 as u8;
    let mut pending = vec![request];

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

    // NON-VACUITY. If the build had SUCCEEDED there would be no drop to
    // attribute, and "exthdr == 1, frag == 0" would be a claim about a branch
    // that never ran.
    assert_eq!(
        dbg.build_fail, 1,
        "the NAT64 build must have returned None for an AH-bearing frame — with a \
         successful build there is no drop to attribute and the counters below \
         measure nothing"
    );
    assert_eq!(
        dbg.enqueue_ok, 0,
        "no TX enqueue may have succeeded for a frame the translator refused"
    );

    assert_eq!(
        counters.nat64_exthdr_ineligible, 1,
        "an AH-bearing frame whose NAT64 build returned None must be attributed to \
         nat64_exthdr_ineligible (#5625). The dispatcher's guard order mirrors the \
         translator's: write_v6_to_v4_into applies the ext-header eligibility gate \
         BEFORE the #2562 fragment guards"
    );
    assert_eq!(
        counters.nat64_frag_dropped, 0,
        "an ext-header-ineligible frame must NOT be attributed to nat64_frag_dropped. \
         Testing the fragment predicate first sends an operator chasing a \
         fragmentation problem that does not exist"
    );

    // The ingress descriptor still has to come back exactly once — the #2208
    // property, restated here so a change to the attribution cannot quietly
    // reintroduce the leak on the NAT64 branch specifically.
    assert_eq!(
        ingress_recycled_count(&bindings[0]),
        1,
        "ingress descriptor must be recycled exactly once on a NAT64 build failure"
    );
    assert_eq!(
        bindings[0].live.slow_path_drops.load(Ordering::Relaxed),
        1,
        "a NAT64 build failure must still reach the slow-path reinject"
    );
}

/// The OTHER copy's NAT64 attribution is DEAD CODE, and this pins the invariant
/// that makes it dead.
///
/// `tx/dispatch/mod.rs` carries the copy fallback twice — 102 lines agreeing on
/// 100 (#6922). The first copy sits inside `if can_rewrite_in_place { ... }`,
/// and `can_rewrite_in_place` requires `!is_nat64`. `is_nat64` is bound once and
/// never reassigned, so inside that copy it is provably FALSE: its
/// `if is_nat64 { ... }` attribution block, and the `build_nat64_forwarded_frame`
/// call it guards, can never run.
///
/// That is worse than plain duplication, because the AUTHORITATIVE rationale for
/// the guard order lives in the dead copy and the LIVE copy carries a comment
/// pointing at it ("same SSOT predicates + translator-order rationale as the
/// direct/in-place copy path above"). A reader auditing the attribution finds a
/// cross-reference to a comment attached to unreachable code.
///
/// It also explains the escape measured at master: swapping the guard order in
/// the first copy left the whole suite green because nothing reaches it.
///
/// If someone drops `!is_nat64` from `can_rewrite_in_place`, NAT64 frames would
/// start taking the in-place path — a far larger change than a refactor — and
/// this test makes that deliberate rather than incidental.
#[test]
fn nat64_never_reaches_the_in_place_rewrite_path_6922() {
    let src = include_str!("../mod.rs");

    // Strip comments first: the paragraphs above and in mod.rs discuss
    // `!is_nat64` at length, and a scan that a doc comment can satisfy is not
    // a scan of the code.
    let mut code = String::with_capacity(src.len());
    let mut in_block = false;
    for line in src.lines() {
        let mut l = line;
        if in_block {
            match l.find("*/") {
                Some(i) => {
                    in_block = false;
                    l = &l[i + 2..];
                }
                None => continue,
            }
        }
        if let Some(i) = l.find("/*") {
            in_block = true;
            l = &l[..i];
        }
        if let Some(i) = l.find("//") {
            l = &l[..i];
        }
        code.push_str(l);
        code.push('\n');
    }

    // NON-VACUITY: the stripper must not have eaten the code.
    let gate = code
        .find("let can_rewrite_in_place")
        .expect("can_rewrite_in_place binding not found in the stripped source — the \
                 comment stripper or the dispatcher changed shape, so this guard is \
                 not reading what it claims to read");
    let tail = &code[gate..];
    let end = tail
        .find(';')
        .expect("can_rewrite_in_place binding has no terminator");
    let expr = &tail[..end];

    assert!(
        expr.contains("!is_nat64"),
        "`can_rewrite_in_place` no longer excludes NAT64. The first copy of the TX \
         copy fallback is only dead code for NAT64 BECAUSE of that term; without it, \
         NAT64 frames take the in-place rewrite path and its long-unreachable \
         attribution block becomes live. Expression was:\n{expr}"
    );
}

/// #8890 — a tunnel-marked NAT64 build-`None` is attributed to
/// `nat64_tunnel_encap_unsupported`, AHEAD of both #6922 reasons.
///
/// **This cell exists because the builder-level cell cannot answer the
/// reachability question.** `nat64_8890_tunnel_marked_decision_is_not_emitted_plaintext`
/// calls `build_nat64_forwarded_frame` directly and proves it fails closed.
/// It says nothing about whether a tunnel-marked NAT64 request actually
/// *reaches* that builder through the dispatcher — `enqueue_pending_forwards`
/// refuses direct TX when `is_nat64 || uses_native_tunnel`, and that `||` is
/// the whole routing argument of #8890. A gate on an unreachable path is inert,
/// and inert is indistinguishable from working by inspection. This drives the
/// real dispatcher.
///
/// It reuses `ah_fragment_v6_frame_6922` deliberately: that frame matches BOTH
/// #6922 predicates, so all three attribution reasons are live at once and the
/// guard order is observable. On a frame only the tunnel reason matched, any
/// ordering would record the same counter and this cell would measure nothing —
/// the lesson the top of this file records about its own first version.
///
/// **SCOPE, corrected after a hostile review: this cell binds the attribution
/// ORDER and NOTHING ELSE.** Its fixture is independently untranslatable, so
/// every "the frame did not go out" assertion in it is true whatever the #8890
/// gate does — measured, by deleting the production gate, at which point this
/// cell stayed GREEN. The paragraph above about reachability was written of a
/// cell that could not establish it. The gate itself is bound by
/// `nat64_otherwise_forwardable_packet_is_not_enqueued_when_tunnelled_8890`,
/// which uses a frame that WOULD reach the wire.
#[test]
fn nat64_tunnel_marked_build_none_attributes_tunnel_first_8890() {
    let mut bindings = vec![
        BindingWorker::new_for_mirror_test(0, 0, 11, 0),
        BindingWorker::new_for_mirror_test(1, 0, 22, 0),
    ];
    let frame = ah_fragment_v6_frame_6922();
    unsafe { bindings[0].umem.area().slice_mut_unchecked(0, frame.len()) }
        .expect("ingress frame")
        .copy_from_slice(&frame);
    bindings[1].tx_pipeline.free_tx_frames.clear();

    let forwarding = test_forwarding_with_egress_mtu(1500);
    let lookup = WorkerBindingLookup::from_bindings(&bindings);
    let mirror_targets = MirrorTargetMap::default();

    let mut decision = test_forwarding_decision_to_bound_ifindex(22);
    decision.nat.nat64 = true;
    // The ONLY difference from the #6922 cell above.
    decision.resolution.tunnel_endpoint_id = 7;

    let mut request = test_live_forward_request_for_frame(frame.len(), decision);
    request.meta.addr_family = libc::AF_INET6 as u8;
    let mut pending = vec![request];

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

    // REACHABILITY + NON-VACUITY. Both must hold before any counter below
    // means anything: the request has to have reached the NAT64 builder AND
    // the builder has to have refused it.
    assert_eq!(
        dbg.build_fail, 1,
        "a tunnel-marked NAT64 request must reach the copy-fallback builder and \
         fail there. If this is 0 the request never got to the #8890 gate — a \
         gate on an unreachable path is inert, and every counter assertion below \
         would be describing a branch that did not run"
    );

    // NOT the security property, and the correction matters. This fixture is
    // ext-header-ineligible and a fragment, so the translator refuses it
    // ANYWAY: `enqueue_ok == 0` holds here whatever the #8890 gate does —
    // measured, by deleting the production gate and watching this whole cell
    // stay green. Kept as a consistency check only.
    //
    // `nat64_otherwise_forwardable_packet_is_not_enqueued_when_tunnelled_8890`
    // is where the no-plaintext property is actually bound, with a control
    // proving the same packet otherwise reaches TX.
    assert_eq!(
        dbg.enqueue_ok, 0,
        "a refused NAT64 frame must not be enqueued (consistency only — this \
         fixture is independently untranslatable, so this cannot distinguish the \
         #8890 gate from the #5625/#2562 refusals)"
    );

    assert_eq!(
        counters.nat64_tunnel_encap_unsupported, 1,
        "#8890: the drop must be attributed to nat64_tunnel_encap_unsupported"
    );
    assert_eq!(
        counters.nat64_exthdr_ineligible, 0,
        "#8890 orders BEFORE #5625. This frame is also ext-header-ineligible, so \
         an attribution chain that tested exthdr first would record that instead \
         — and an operator would chase an AH/translation problem when the real \
         signal is that a NAT64 + tunnel route is not forwarded at all"
    );
    assert_eq!(
        counters.nat64_frag_dropped, 0,
        "#8890 orders BEFORE #2562 as well — this frame is also a non-first \
         fragment"
    );

    // The #2208 property, restated here for the new branch: a new early return
    // in the attribution chain must not skip the recycle or the reinject.
    assert_eq!(
        ingress_recycled_count(&bindings[0]),
        1,
        "ingress descriptor must be recycled exactly once on the #8890 drop"
    );
    // This AH/non-first-fragment fixture also makes NAT64 slow-path packet
    // preparation fail, before the independent #1873 reinject tunnel gate.
    // The otherwise-forwardable #8890 sibling pins the TX gate; the dedicated
    // tunnel tests pin #1873, so this cell stays focused on attribution order.
}

/// A PLAIN IPv6 TCP frame the NAT64 translator will happily translate.
///
/// Deliberately NOT `ah_fragment_v6_frame_6922`: no extension headers and no
/// fragment header, so neither #5625 nor #2562 refuses it and the ONLY reason
/// the build can fail is the #8890 gate.
fn plain_v6_tcp_frame_8890() -> Vec<u8> {
    let src = std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
    let dst = std::net::Ipv6Addr::new(0x64, 0xff9b, 0, 0, 0, 0, 0x0808, 0x0808);
    let payload = b"hi";
    let tcp_len = 20 + payload.len();
    let mut l3 = vec![0u8; 40 + tcp_len];
    l3[0] = 0x60;
    l3[4..6].copy_from_slice(&(tcp_len as u16).to_be_bytes());
    l3[6] = PROTO_TCP;
    l3[7] = 64;
    l3[8..24].copy_from_slice(&src.octets());
    l3[24..40].copy_from_slice(&dst.octets());
    l3[40..42].copy_from_slice(&5000u16.to_be_bytes());
    l3[42..44].copy_from_slice(&443u16.to_be_bytes());
    l3[52] = 0x50;
    l3[53] = 0x02;
    l3[54..56].copy_from_slice(&1024u16.to_be_bytes());
    l3[60..60 + payload.len()].copy_from_slice(payload);
    let mut frame = vec![0u8; 14];
    frame[12..14].copy_from_slice(&0x86DDu16.to_be_bytes());
    frame.extend_from_slice(&l3);
    frame
}

/// Drive the dispatcher for one NAT64 request, returning what it did.
fn run_nat64_dispatch_8890(frame: &[u8], tunnel_endpoint_id: u16) -> (DebugPollCounters, BatchCounters) {
    let mut bindings = vec![
        BindingWorker::new_for_mirror_test(0, 0, 11, 0),
        BindingWorker::new_for_mirror_test(1, 0, 22, 0),
    ];
    unsafe { bindings[0].umem.area().slice_mut_unchecked(0, frame.len()) }
        .expect("ingress frame")
        .copy_from_slice(frame);
    bindings[1].tx_pipeline.free_tx_frames.clear();

    let forwarding = test_forwarding_with_egress_mtu(1500);
    let lookup = WorkerBindingLookup::from_bindings(&bindings);
    let mirror_targets = MirrorTargetMap::default();

    let mut decision = test_forwarding_decision_to_bound_ifindex(22);
    // A REAL NAT64 forward translation, not just the flag: without the rewrite
    // addresses the builder returns None at `rewrite_src` and the frame would
    // fail for a reason that has nothing to do with #8890.
    decision.nat = crate::nat64::Nat64State::forward_decision(
        std::net::Ipv4Addr::new(203, 0, 113, 1),
        std::net::Ipv4Addr::new(8, 8, 8, 8),
        40001,
    );
    decision.resolution.tunnel_endpoint_id = tunnel_endpoint_id;

    let mut request = test_live_forward_request_for_frame(frame.len(), decision);
    request.meta.addr_family = libc::AF_INET6 as u8;
    let mut pending = vec![request];

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
        left, 0, ingress, right, &lookup, &mirror_targets, &mut pending,
        &mut post_recycles, 1, &forwarding, &ingress_ident,
        unsafe { &*ingress_live }, None, &local_tunnel_deliveries,
        &recent_exceptions, &mut dbg, &mut counters, 0, &worker_commands_by_id,
    );
    (dbg, counters)
}

/// #8890 — THE GATE, not the attribution: an otherwise-forwardable NAT64 packet
/// is NOT enqueued for TX when its route resolves through a tunnel.
///
/// **This cell exists because the sibling cell above could not establish it,
/// and a hostile review caught that.** That cell uses the #6922 AH-fragment
/// fixture, which the translator refuses ANYWAY for #5625/#2562 reasons. So its
/// `enqueue_ok == 0` was true no matter what the #8890 gate did — measured:
/// deleting the production gate entirely left that cell GREEN. It binds the
/// attribution ORDER, which is what it was reused for, and it binds nothing
/// about the gate.
///
/// The fix is the same one the builder cell already used: an arm that WOULD
/// SUCCEED. `plain_v6_tcp_frame_8890` carries no extension header and no
/// fragment, and the decision carries a real forward translation, so the only
/// thing standing between this packet and the wire is the tunnel field.
#[test]
fn nat64_otherwise_forwardable_packet_is_not_enqueued_when_tunnelled_8890() {
    // CONTROL: identical in every respect except the tunnel endpoint.
    let (ctl_dbg, ctl_counters) = run_nat64_dispatch_8890(&plain_v6_tcp_frame_8890(), 0);
    assert_eq!(
        ctl_dbg.enqueue_ok, 1,
        "NON-VACUITY: the untunnelled control MUST reach TX. If this frame does \
         not enqueue, then `enqueue_ok == 0` in the subject below is satisfied by \
         the packet being unforwardable for some unrelated reason — which is \
         exactly the defect this cell was written to correct in its sibling"
    );
    assert_eq!(
        ctl_dbg.build_fail, 0,
        "the control must BUILD; a control that fails to build proves nothing"
    );
    assert_eq!(
        ctl_counters.nat64_tunnel_encap_unsupported, 0,
        "the untunnelled control must not be attributed to the #8890 counter"
    );

    // SUBJECT: the same packet, routed through a tunnel endpoint.
    let (dbg, counters) = run_nat64_dispatch_8890(&plain_v6_tcp_frame_8890(), 7);
    assert_eq!(
        dbg.enqueue_ok, 0,
        "#8890: a NAT64 packet whose route resolves through a tunnel endpoint must \
         NOT be enqueued for TX. The control above proves this same packet \
         otherwise reaches the wire, so an enqueue here is the inner packet going \
         onto the underlay unencapsulated — measured, before the gate, as a frame \
         byte-identical to the untunnelled output"
    );
    assert_eq!(
        dbg.build_fail, 1,
        "#8890: the build must FAIL for the tunnelled packet"
    );
    assert_eq!(
        counters.nat64_tunnel_encap_unsupported, 1,
        "#8890: and the drop must be attributed to nat64_tunnel_encap_unsupported"
    );
}
