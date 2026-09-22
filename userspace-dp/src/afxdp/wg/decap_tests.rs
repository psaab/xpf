//! #8274 step 3: the worker-side WireGuard decap stage, driven end to end on a
//! REAL authenticated record.
//!
//! The defect these cells exist for is not subtle and not narrow: an
//! authenticated peer's inner plaintext was written straight to the `wgN` TUN
//! for the kernel to route, with no zone lookup, no session, no policy and no
//! counter between `try_decap` and the write. A peer's `allowed-ips` is a
//! cryptographic check on the inner SOURCE address — no destination, no zone
//! pair, no application, no direction — so it is not a security policy and it
//! was the only thing in the path.
//!
//! WHAT THE LOAD-BEARING ASSERTION IS, and why it is the zone rather than the
//! absence of a TUN write. A cell asserting "the plaintext no longer reaches
//! the TUN" would pass for a stage that dropped the packet on the floor, and it
//! would pass for one that adjudicated the inner packet under the UNDERLAY's
//! zone — which is the #7167 invariant-2 failure and would silently give inner
//! traffic the WAN's policy. So the assertion is that the decapsulated meta
//! carries the TUNNEL's logical ifindex and the zone that ifindex maps to.

use super::super::test_fixtures::wg_outer_mtu_snapshot;
use crate::test_zone_ids::TEST_SFMIX_ZONE_ID;
use super::super::tests_support::{
    txn_ha_state, txn_run_descriptor, txn_run_descriptor_checked, txn_run_descriptor_inner,
};
use super::super::*;
use super::tests::established_pair;
use super::{WgEngine, WgWorkerScratch};
use crate::afxdp::coordinator::{
    build_wg_tun_origin_entries, parse_wg_tun_origin_flow, publish_wg_tun_origin_entries,
    sweep_wg_tun_origin_idle, wg_tun_origin_packet_initiates,
};

const TUNNEL_LOGICAL_IFINDEX: i32 = 400;
const WG_PORT: u16 = 51820;
/// The fixture's tunnel source — the outer DESTINATION of an inbound record.
const XPF_OUTER: [u8; 4] = [172, 16, 80, 8];
/// The fixture's configured peer endpoint — the outer SOURCE.
const PEER_OUTER: [u8; 4] = [203, 0, 113, 7];
const PEER_SPORT: u16 = 51820;

/// An inner IPv4 packet (UDP) from `src` to `dst`, the plaintext the peer sends.
fn inner_v4(src: [u8; 4], dst: [u8; 4]) -> Vec<u8> {
    let mut p = vec![0u8; 20 + 8];
    p[0] = 0x45;
    let total = p.len() as u16;
    p[2..4].copy_from_slice(&total.to_be_bytes());
    p[8] = 64;
    p[9] = PROTO_UDP;
    p[12..16].copy_from_slice(&src);
    p[16..20].copy_from_slice(&dst);
    p[20..22].copy_from_slice(&1111u16.to_be_bytes());
    p[22..24].copy_from_slice(&2222u16.to_be_bytes());
    p[24..26].copy_from_slice(&8u16.to_be_bytes());
    p
}

/// Wrap `record` in Ethernet + IPv4 + UDP, as it arrives on the underlay.
fn outer_frame(record: &[u8], dst_port: u16) -> Vec<u8> {
    let mut f = vec![0u8; 14 + 20 + 8 + record.len()];
    // #10314: the poll-loop path validates the Ethernet destination against
    // the underlay's configured MAC before it reaches tunnel decap. Keep this
    // hermetic frame shaped like a real frame; an all-zero unicast destination
    // is PACKET_OTHERHOST and would be recycled before #8274 runs.
    f[..6].copy_from_slice(&[0x02, 0xbf, 0x72, 0x00, 0x50, 0x08]);
    f[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
    f[14] = 0x45;
    let ip_total = (20 + 8 + record.len()) as u16;
    f[16..18].copy_from_slice(&ip_total.to_be_bytes());
    f[22] = 64;
    f[23] = PROTO_UDP;
    f[26..30].copy_from_slice(&PEER_OUTER);
    f[30..34].copy_from_slice(&XPF_OUTER);
    f[34..36].copy_from_slice(&PEER_SPORT.to_be_bytes());
    f[36..38].copy_from_slice(&dst_port.to_be_bytes());
    let udp_len = (8 + record.len()) as u16;
    f[38..40].copy_from_slice(&udp_len.to_be_bytes());
    f[42..].copy_from_slice(record);
    f
}

fn outer_meta(frame_len: usize) -> UserspaceDpMeta {
    UserspaceDpMeta {
        l3_offset: 14,
        l4_offset: 34,
        payload_offset: 42,
        pkt_len: frame_len as u16,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_UDP,
        // #7167 invariant 5: the stage MUST inherit these from the RX meta.
        // Distinctive values so a cell can prove they were carried rather than
        // defaulted.
        config_generation: 0x5150_4646,
        fib_generation: 0x0BAD_F00D,
        rx_queue_index: 3,
        ..UserspaceDpMeta::default()
    }
}

/// Build the fixture forwarding state with `resp` installed as the live engine
/// for the WireGuard tunnel endpoint, and return it with that endpoint's id.
fn forwarding_with_engine(resp: WgEngine) -> (ForwardingState, u16) {
    let mut forwarding = build_forwarding_state(&wg_outer_mtu_snapshot());
    let id = *forwarding
        .wg_engines
        .keys()
        .next()
        .expect("the fixture configures a WireGuard tunnel");
    // Replace the fixture's engine (whose keys nothing holds) with one that has
    // a live session, so the decap below is a REAL AEAD open and not a stub.
    forwarding.wg_engines.insert(id, std::sync::Arc::new(resp));
    (forwarding, id)
}

/// Sum of every decap outcome counter the engine keeps. A record the stage
/// declines on its OWN gate must leave all of them untouched; a record it
/// hands to `try_decap` moves exactly one, whichever way `try_decap` rules.
/// That difference is the only observable distinction between "the worker
/// refused to claim this" and "the worker claimed it and the crypto said no",
/// and without it a cell asserting only `is_none()` stays green when the
/// stage's type gate is deleted (the mutation that escaped on first run).
fn decap_outcomes_observed(engine: &WgEngine) -> u64 {
    let c = engine.counters();
    [
        &c.decap_keepalives,
        &c.decap_drops_malformed_header,
        &c.decap_drops_unknown_session,
        &c.decap_drops_counter_ceiling,
        &c.decap_drops_crypto,
        &c.decap_drops_replay,
        &c.decap_drops_allowed_ips,
        &c.decap_drops_malformed_inner,
        &c.decap_drops_buffer,
        &c.decap_drops_expired,
    ]
    .iter()
    .map(|a| a.load(std::sync::atomic::Ordering::Relaxed))
    .sum()
}

/// The whole point of #8274: an authenticated transport-data record is
/// decapsulated in the WORKER and its inner packet is presented for
/// adjudication under the TUNNEL's zone.
#[test]
fn worker_decap_presents_inner_under_the_tunnel_zone_8274() {
    let inner_src = [10, 123, 0, 5];
    let allowed: Vec<ipnet::IpNet> = vec!["10.123.0.0/24".parse().unwrap()];
    let (init, resp, init_pub, resp_pub) = established_pair(allowed.clone(), allowed);
    let (forwarding, id) = forwarding_with_engine(resp);

    let inner = inner_v4(inner_src, [10, 0, 61, 102]);
    let mut wire = vec![0u8; 2048];
    let enc = init
        .try_encap(&resp_pub, &inner, &mut wire)
        .expect("initiator encap");
    let frame = outer_frame(&wire[..enc.len], WG_PORT);
    let meta = outer_meta(frame.len());

    let scratch = WgWorkerScratch::new(4096);
    let decapped = super::decap::try_wg_decap_from_frame(&frame, meta, &forwarding, &scratch)
        .expect("an authenticated transport-data record must be decapsulated by the worker");

    // THE assertion. Adjudicating the inner packet under the UNDERLAY's zone
    // would be the #7167 invariant-2 failure: inner traffic would get the WAN's
    // policy, which is a different and equally wrong answer from the old
    // no-policy-at-all behaviour.
    assert_eq!(
        decapped.meta.ingress_ifindex as i32, TUNNEL_LOGICAL_IFINDEX,
        "the decapsulated inner packet must present the TUNNEL's logical \
         ifindex, not the underlay's — the ingress zone is derived from it, so \
         a physical ifindex here adjudicates inner traffic under the WAN's zone \
         (#7167 invariant 2 / #8274)"
    );
    assert_eq!(
        decapped.meta.ingress_zone, TEST_SFMIX_ZONE_ID,
        "the inner packet must be adjudicated under the tunnel interface's own \
         zone. This is what the old path never did at all: it wrote the \
         plaintext to the wgN TUN and let the kernel forward it with no zone \
         policy (#8274)"
    );
    // #7167 invariant 5: fabricating these would compile, adjudicate, and look
    // current. They must be the RX meta's.
    assert_eq!(
        decapped.meta.config_generation, 0x5150_4646,
        "the inner meta must INHERIT config_generation from the triggering RX \
         meta — a fabricated generation always looks current and silently \
         defeats attachment fencing (#7167 invariant 5)"
    );
    assert_eq!(decapped.meta.fib_generation, 0x0BAD_F00D, "fib_generation");
    // The plaintext survived intact behind the synthesized Ethernet header.
    assert_eq!(
        &decapped.frame[14..],
        &inner[..],
        "the decapsulated inner packet must be the plaintext the peer sent"
    );
    assert_eq!(
        decapped.peer_pubkey, init_pub,
        "the record must be attributed to the peer whose keys opened it"
    );

    // The roam report: the endpoint the worker observed is queued for the
    // control thread, which no longer sees these records on its socket.
    let engine = forwarding.wg_engines.get(&id).unwrap();
    assert_eq!(
        engine.take_worker_observed_endpoint(&init_pub),
        Some(std::net::SocketAddr::from((PEER_OUTER, PEER_SPORT))),
        "the worker must report the endpoint it observed on an authenticated \
         record — moving type-4 decap off the control thread's socket takes its \
         dominant endpoint-learning signal away (#8274)"
    );
    // Drained, not merely readable: a second take must be empty, or the control
    // thread would re-adopt the same roam on every pass.
    assert_eq!(engine.take_worker_observed_endpoint(&init_pub), None);
}

/// A HANDSHAKE record on the same 5-tuple is not the worker's.
///
/// The control thread owns the handshake state machine and the #1865
/// unknown-type accounting. This is the direction that would break the tunnel
/// if it were wrong, and it varies ONLY the first payload byte — a fixture that
/// varied the 5-tuple would pass on the port match and prove nothing.
#[test]
fn worker_decap_declines_a_handshake_record_8274() {
    let allowed: Vec<ipnet::IpNet> = vec!["10.123.0.0/24".parse().unwrap()];
    let (init, resp, _init_pub, resp_pub) = established_pair(allowed.clone(), allowed);
    let (forwarding, id) = forwarding_with_engine(resp);
    let engine = std::sync::Arc::clone(&forwarding.wg_engines[&id]);

    let inner = inner_v4([10, 123, 0, 5], [10, 0, 61, 102]);
    let mut wire = vec![0u8; 2048];
    let enc = init.try_encap(&resp_pub, &inner, &mut wire).unwrap();
    let mut record = wire[..enc.len].to_vec();
    // The ONLY difference from the admitted case above.
    record[0] = super::WG_TYPE_INITIATION;

    let frame = outer_frame(&record, WG_PORT);
    let scratch = WgWorkerScratch::new(4096);
    let before = decap_outcomes_observed(&engine);
    assert!(
        super::decap::try_wg_decap_from_frame(
            &frame,
            outer_meta(frame.len()),
            &forwarding,
            &scratch
        )
        .is_none(),
        "a handshake record must be left for the control thread; claiming it \
         here hands the handshake state machine to a stage that does not \
         implement it (#8274)"
    );
    assert_eq!(
        decap_outcomes_observed(&engine),
        before,
        "the stage must decline a non-type-4 record on its OWN gate, without \
         calling try_decap. try_decap also refuses this record (its header \
         parse fails), so `is_none()` alone stays true with the gate deleted — \
         only counter-freedom distinguishes declining from claiming-and-failing. \
         A stage that forwards handshakes into try_decap turns every peer's \
         handshake into a spurious decap drop and races the control thread for \
         the session map (#8274)"
    );
}

/// A datagram on a port no WireGuard tunnel listens on is not the worker's,
/// however well-formed the payload looks.
#[test]
fn worker_decap_declines_a_foreign_port_8274() {
    let allowed: Vec<ipnet::IpNet> = vec!["10.123.0.0/24".parse().unwrap()];
    let (init, resp, _init_pub, resp_pub) = established_pair(allowed.clone(), allowed);
    let (forwarding, _id) = forwarding_with_engine(resp);

    let inner = inner_v4([10, 123, 0, 5], [10, 0, 61, 102]);
    let mut wire = vec![0u8; 2048];
    let enc = init.try_encap(&resp_pub, &inner, &mut wire).unwrap();
    let frame = outer_frame(&wire[..enc.len], WG_PORT + 1);
    let scratch = WgWorkerScratch::new(4096);
    assert!(
        super::decap::try_wg_decap_from_frame(
            &frame,
            outer_meta(frame.len()),
            &forwarding,
            &scratch
        )
        .is_none(),
        "a datagram on a port no tunnel listens on must take the ordinary \
         policy path, not a decap stage (#8274)"
    );
}

/// An `allowed-ips` mismatch is refused by the ENGINE, before any of this
/// stage's output exists — so no inner packet is presented for adjudication and
/// nothing counts as if it had reached the policy evaluator.
#[test]
fn worker_decap_refuses_an_allowed_ips_mismatch_8274() {
    // The responder permits 10.123.0.0/24; the initiator sends from outside it.
    let permitted: Vec<ipnet::IpNet> = vec!["10.123.0.0/24".parse().unwrap()];
    let (init, resp, _init_pub, resp_pub) =
        established_pair(permitted.clone(), permitted.clone());
    let (forwarding, _id) = forwarding_with_engine(resp);

    let inner = inner_v4([192, 0, 2, 77], [10, 0, 61, 102]);
    let mut wire = vec![0u8; 2048];
    let enc = init.try_encap(&resp_pub, &inner, &mut wire).unwrap();
    let frame = outer_frame(&wire[..enc.len], WG_PORT);
    let scratch = WgWorkerScratch::new(4096);
    assert!(
        super::decap::try_wg_decap_from_frame(
            &frame,
            outer_meta(frame.len()),
            &forwarding,
            &scratch
        )
        .is_none(),
        "a record whose inner source is outside the peer's allowed-ips must be \
         refused before it becomes a packet — `allowed-ips` is the ONE check \
         the old path did have, and this stage must not lose it (#8274)"
    );
}

// ---------------------------------------------------------------------------
// #8274 WIRING binding.
//
// The four cells above call `try_wg_decap_from_frame` directly. Every one of
// them stays GREEN when the stage is deleted from the poll loop — verified by
// mutation: replacing the `if wg_frame.is_some()` adoption in
// `poll_descriptor/mod.rs` with `if false` reds nothing above. That is the
// exact failure this board has paid for twice (a packet-path change that is
// never called, every cell green, the box unchanged), so the wiring gets its
// own cells, driven through the REAL `poll_binding_process_descriptor` body.
//
// The pair below is one packet and one difference. Same authenticated record,
// same fixture, same underlay ingress; the ONLY thing that changes is whether
// a policy permits the INNER flow. Permit installs a session stamped with the
// TUNNEL's ingress identity; deny installs nothing. Before #8274 neither
// outcome was reachable, because the inner plaintext never met a policy at
// all — it went to the `wgN` TUN and the kernel routed it. That the two
// outcomes now DIFFER on the policy is the whole security-posture change, and
// it is stated in the direction the change actually runs: traffic that flows
// today can start being DENIED.

/// Build the WG fixture with an optional `sfmix -> wan` permit for the inner
/// flow, and an engine holding a live session.
fn wiring_fixture(permit_inner: bool) -> (ForwardingState, WgEngine, [u8; 32]) {
    let allowed: Vec<ipnet::IpNet> = vec!["10.123.0.0/24".parse().unwrap()];
    let (init, resp, _ipub, rpub) = established_pair(allowed.clone(), allowed);
    let mut snap = wg_outer_mtu_snapshot();
    if permit_inner {
        snap.policies = vec![crate::PolicyRuleSnapshot {
            name: "permit-inner".to_string(),
            from_zone: "sfmix".to_string(),
            to_zone: "wan".to_string(),
            source_addresses: vec!["any".to_string()],
            destination_addresses: vec!["any".to_string()],
            applications: vec!["any".to_string()],
            application_terms: Vec::new(),
            action: "permit".to_string(),
            ..Default::default()
        }];
    } else {
        snap.policies = Vec::new();
    }
    let mut forwarding = build_forwarding_state(&snap);
    let id = *forwarding.wg_engines.keys().next().expect("wg tunnel");
    forwarding.wg_engines.insert(id, std::sync::Arc::new(resp));
    (forwarding, init, rpub)
}

/// One authenticated type-4 record on the wire, as it arrives on the underlay.
fn wiring_record(init: &WgEngine, rpub: &[u8; 32]) -> Vec<u8> {
    let inner = inner_v4([10, 123, 0, 5], [203, 0, 113, 50]);
    let mut wire = vec![0u8; 2048];
    let enc = init.try_encap(rpub, &inner, &mut wire).unwrap();
    outer_frame(&wire[..enc.len], WG_PORT)
}

fn wiring_meta(frame_len: usize) -> UserspaceDpMeta {
    let mut m = outer_meta(frame_len);
    // The record arrives on the WAN unit reth0.80 (ifindex 12) — the UNDERLAY.
    m.ingress_ifindex = 12;
    // The direct-call cells above use DISTINCTIVE generations to prove the
    // stage inherits rather than fabricates them. Here the packet must clear
    // `classify_metadata`'s generation fence to reach the stage at all, so it
    // carries the harness's validated pair (`txn_meta_v4`: 7 / 9). Leaving the
    // distinctive values here drops the frame as STALE before any stage runs —
    // which presents as "the stage never fired", i.e. exactly the failure this
    // cell is built to detect, from an unrelated cause.
    m.config_generation = 7;
    m.fib_generation = 9;
    // `try_parse_metadata` reads the descriptor's meta out of the UMEM and
    // refuses it on magic/version — a default-constructed meta parses as
    // NOTHING and the descriptor is dropped before any stage. The direct-call
    // cells never go through that reader, which is why they do not need these.
    m.magic = USERSPACE_META_MAGIC;
    m.version = USERSPACE_META_VERSION;
    m.length = std::mem::size_of::<UserspaceDpMeta>() as u16;
    m
}

/// WIRING, permit arm. The poll loop must actually CALL the decap stage, and
/// the session it installs must carry the TUNNEL's ingress identity.
///
/// A session keyed on the inner flow and stamped `ingress_ifindex 400` cannot
/// exist unless the stage ran inside `poll_binding_process_descriptor`: nothing
/// else in the loop can turn an outer UDP datagram addressed to the firewall
/// into an inner-flow session on a tunnel ifindex.
#[test]
fn poll_loop_adjudicates_wg_inner_plaintext_under_the_tunnel_zone_8274() {
    let (forwarding, init, rpub) = wiring_fixture(true);
    let frame = wiring_record(&init, &rpub);
    let meta = wiring_meta(frame.len());

    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 12, 0);
    binding.interface = std::sync::Arc::<str>::from("ge-0-0-2.80");
    let ha_state = txn_ha_state();
    let mut sessions = SessionTable::new();
    let (_b, _dbg) = txn_run_descriptor_checked(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame,
        meta,
        true,
    );

    let mut tunnel_zones: Vec<u16> = Vec::new();
    let mut total = 0usize;
    sessions.iter_with_origin(|_k, _d, m, _o| {
        total += 1;
        if m.ingress_ifindex == TUNNEL_LOGICAL_IFINDEX as u32 {
            tunnel_zones.push(m.ingress_zone);
        }
    });
    assert!(
        !tunnel_zones.is_empty(),
        "the poll loop must call the WireGuard decap stage: no session carries \
         the tunnel's ingress ifindex {TUNNEL_LOGICAL_IFINDEX}, so the inner \
         plaintext never reached policy. This is the assertion that dies when \
         the stage is built but not WIRED — every direct-call cell in this file \
         stays green in that state. Installed sessions: {total}"
    );
    for z in &tunnel_zones {
        assert_eq!(
            *z, TEST_SFMIX_ZONE_ID,
            "the inner flow must be adjudicated in the TUNNEL's zone; the \
             underlay's zone here would give inner traffic the WAN's policy \
             (#7167 invariant 2)"
        );
    }
}

/// WIRING, deny arm — and the security DIRECTION of #8274 stated as a test.
///
/// The same record, the same fixture, the policy removed. Before this change
/// the inner packet was written to the `wgN` TUN and the kernel forwarded it
/// with no policy consulted, so this packet was DELIVERED. After it, the flow
/// has no permitting policy and installs nothing. An operator upgrading into
/// this sees exactly that on the first packet: WireGuard inner traffic that
/// flowed yesterday is denied until a policy admits it.
#[test]
fn poll_loop_denies_wg_inner_plaintext_with_no_permitting_policy_8274() {
    let (forwarding, init, rpub) = wiring_fixture(false);
    let frame = wiring_record(&init, &rpub);
    let meta = wiring_meta(frame.len());

    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 12, 0);
    binding.interface = std::sync::Arc::<str>::from("ge-0-0-2.80");
    let ha_state = txn_ha_state();
    let mut sessions = SessionTable::new();
    let (_batch, dbg) = txn_run_descriptor_checked(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame,
        meta,
        true,
    );

    // NON-VACUITY CONTROL. "No tunnel session" is also what a packet that never
    // reached the stage produces, and this cell was observed GREEN in exactly
    // that state while its permit sibling was red — the descriptor was being
    // dropped on the metadata magic before any stage ran. So the cell asserts
    // the packet got FAR ENOUGH to be denied: the deny must come from policy,
    // not from the frame never arriving.
    assert!(
        dbg.policy_deny >= 1,
        "the inner flow must reach POLICY and be denied there. Zero policy \
         denies means the packet never got that far, and the \
         no-tunnel-session assertion below would hold for free"
    );

    let mut tunnel_sessions = 0usize;
    sessions.iter_with_origin(|_k, _d, m, _o| {
        if m.ingress_ifindex == TUNNEL_LOGICAL_IFINDEX as u32 {
            tunnel_sessions += 1;
        }
    });
    assert_eq!(
        tunnel_sessions, 0,
        "with no policy admitting sfmix -> wan the inner flow must install NO \
         session. A session here means the decap stage is presenting plaintext \
         that policy never adjudicated — the pre-#8274 posture wearing the new \
         code path's shape"
    );
}

// ---------------------------------------------------------------------------
// #9251: an UNZONED WireGuard tunnel on the dataplane path is DENIED.
// ---------------------------------------------------------------------------

/// The `wiring_fixture` record path under a posture in which ONLY the #6682
/// unzoned-ingress guard can refuse the inner flow: `default-policy permit` and
/// a both-any permit rule. `zoned` keeps the tunnel in `sfmix`; otherwise the
/// tunnel's interface row and endpoint carry no zone.
fn unzoned_wiring_fixture_9251(zoned: bool) -> (ForwardingState, WgEngine, [u8; 32]) {
    let allowed: Vec<ipnet::IpNet> = vec!["10.123.0.0/24".parse().unwrap()];
    let (init, resp, _ipub, rpub) = established_pair(allowed.clone(), allowed);
    let mut snap = wg_outer_mtu_snapshot();
    if !zoned {
        for iface in snap
            .interfaces
            .iter_mut()
            .filter(|i| i.ifindex == TUNNEL_LOGICAL_IFINDEX)
        {
            iface.zone = String::new();
        }
        for ep in snap.tunnel_endpoints.iter_mut() {
            ep.zone = String::new();
        }
    }
    snap.default_policy = "permit".to_string();
    snap.policies = vec![crate::PolicyRuleSnapshot {
        name: "both-any-permit".to_string(),
        from_zone: "any".to_string(),
        to_zone: "any".to_string(),
        source_addresses: vec!["any".to_string()],
        destination_addresses: vec!["any".to_string()],
        applications: vec!["any".to_string()],
        application_terms: Vec::new(),
        action: "permit".to_string(),
        ..Default::default()
    }];
    let mut forwarding = build_forwarding_state(&snap);
    let id = *forwarding.wg_engines.keys().next().expect("wg tunnel");
    forwarding.wg_engines.insert(id, std::sync::Arc::new(resp));
    (forwarding, init, rpub)
}

/// Run one authenticated record through the poll loop; return the debug
/// counters, the tunnel-ingress session count and the #6682 counter delta.
fn run_unzoned_wiring_9251(forwarding: &ForwardingState, init: &WgEngine, rpub: &[u8; 32]) -> (DebugPollCounters, usize, u64) {
    let frame = wiring_record(init, rpub);
    let meta = wiring_meta(frame.len());
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 12, 0);
    binding.interface = std::sync::Arc::<str>::from("ge-0-0-2.80");
    let ha_state = txn_ha_state();
    let mut sessions = SessionTable::new();
    let before = crate::policy::UNZONED_INGRESS_DENIED.load(Ordering::Relaxed);
    let (_batch, dbg) = txn_run_descriptor_checked(
        &mut binding,
        &mut sessions,
        forwarding,
        &ha_state,
        &frame,
        meta,
        true,
    );
    let after = crate::policy::UNZONED_INGRESS_DENIED.load(Ordering::Relaxed);
    let mut tunnel_sessions = 0usize;
    sessions.iter_with_origin(|_k, _d, m, _o| {
        if m.ingress_ifindex == TUNNEL_LOGICAL_IFINDEX as u32 {
            tunnel_sessions += 1;
        }
    });
    (dbg, tunnel_sessions, after.saturating_sub(before))
}

/// #9251: the #5618 commit advisory now tells an operator that an UNZONED
/// WireGuard tunnel's decapsulated transit is "DENIED on the dataplane path
/// (#6682)". This cell is that sentence's proof, through the poll loop.
///
/// It composes facts no single cell pinned together. The decap call site puts
/// the TUNNEL's logical ifindex on the inner meta's `ingress_ifindex`
/// (`build_logical_ingress_packet`). The policy stage resolves the from-zone
/// from that ifindex — `zone_pair_ids_for_flow_with_override`: the fabric
/// override, else `ifindex_to_zone_id[ingress_ifindex]`, else 0 — so a tunnel in
/// no zone is zone 0. And `policy.rs` refuses transit from ingress zone 0 before
/// the implicit default (#6682). A call site that passed the UNDERLAY's ifindex
/// would adjudicate the inner flow under the WAN's zone, and a fallback that
/// yielded any real zone instead of 0 would let the both-any permit forward it.
///
/// What this cell does NOT bind: the `ingress_zone` value
/// `build_logical_ingress_packet` STAMPS on the meta. The policy stage does not
/// read it for this packet — a mutant that made only the stamp fall back to a
/// configured zone survived this cell (#9251), and this paragraph used to name
/// the stamp as the mechanism.
///
/// The posture is chosen so that ONLY the #6682 guard can refuse, and the
/// POSITIVE CONTROL proves it: the same record, the same posture, the tunnel
/// zoned, installs a tunnel session. Without that arm, "no session" would also
/// be what a rule that matches nothing on this path produces.
#[test]
fn poll_loop_denies_unzoned_wg_tunnel_transit_under_permit_all_9251() {
    let (forwarding, init, rpub) = unzoned_wiring_fixture_9251(true);
    assert!(
        forwarding
            .ifindex_to_zone_id
            .get(&TUNNEL_LOGICAL_IFINDEX)
            .is_some(),
        "setup: the zoned arm's tunnel must resolve to a zone"
    );
    let (_dbg, zoned_sessions, _) = run_unzoned_wiring_9251(&forwarding, &init, &rpub);
    assert!(
        zoned_sessions >= 1,
        "positive control: with the tunnel ZONED, default-policy permit plus a \
         both-any permit must admit the inner flow and install a tunnel session. \
         If it does not, the unzoned deny below is not evidence of anything"
    );

    let (forwarding, init, rpub) = unzoned_wiring_fixture_9251(false);
    assert_eq!(
        forwarding.ifindex_to_zone_id.get(&TUNNEL_LOGICAL_IFINDEX),
        None,
        "setup: the unzoned arm's tunnel must really be in no zone"
    );
    let (dbg, unzoned_sessions, unzoned_denies) = run_unzoned_wiring_9251(&forwarding, &init, &rpub);
    // ORDER MATTERS. The security assertion comes first so a mutant that lets the
    // flow through is reported as what it is. With the non-vacuity check first,
    // a PERMITTED flow (zero policy denies) would be reported as "never reached
    // policy" — the wrong cause, in the direction that sends a reader looking at
    // the fixture instead of the zone.
    assert_eq!(
        unzoned_sessions, 0,
        "an UNZONED WireGuard tunnel's inner transit installed a session under a \
         permit-all posture: the decap stage adjudicated it in some zone other than \
         zone 0, and the #5618 advisory's 'DENIED on the dataplane path' is false"
    );
    assert!(
        dbg.policy_deny >= 1,
        "no session, but zero policy denies either: the record never reached \
         policy, so the no-session assertion above held for free"
    );
    assert!(
        unzoned_denies >= 1,
        "the deny must be the #6682 unzoned-ingress guard. Anything else refusing \
         here contradicts the posture (permit default, both-any permit), and the \
         advisory's sentence names #6682"
    );
}

// ---------------------------------------------------------------------------
// #9018: the worker's declined-but-AUTHENTICATED arms must still roam the peer.
// ---------------------------------------------------------------------------

/// A NAT-rebound / roaming peer's new outer endpoint. Deliberately a different
/// address AND a different source port from `PEER_OUTER`/`PEER_SPORT`: a NAT
/// rebind usually moves the port, and a fixture that changed only the address
/// would stay green against a fix that ignored the port.
const ROAMED_OUTER: [u8; 4] = [198, 51, 100, 22];
const ROAMED_SPORT: u16 = 41001;

/// `outer_frame` with a caller-chosen source endpoint, so a cell can present
/// the SAME authenticated record arriving from somewhere new.
fn outer_frame_from(record: &[u8], dst_port: u16, src_ip: [u8; 4], src_port: u16) -> Vec<u8> {
    let mut f = outer_frame(record, dst_port);
    f[26..30].copy_from_slice(&src_ip);
    f[34..36].copy_from_slice(&src_port.to_be_bytes());
    f
}

/// A KEEPALIVE from a changed endpoint must roam the peer.
///
/// This is the NAT-traversal case WireGuard keepalives exist for, and before
/// #9018 it moved nothing. `try_decap` returns `Err(DecapError::Keepalive(pk))`
/// carrying the proven peer — added by #7230 for exactly this — and the worker
/// collapsed it with `.ok()?`. The socket path in wg_control/dispatch.rs does
/// map that arm to `Authenticated(pk)`, but it never sees these records: a
/// keepalive is a type-4 transport record, so `wg_worker_claims_record` claims
/// it for the worker and the shim declines `cpumap_or_pass`.
#[test]
fn worker_decap_roams_endpoint_on_keepalive_9018() {
    let allowed: Vec<ipnet::IpNet> = vec!["10.123.0.0/24".parse().unwrap()];
    let (init, resp, init_pub, resp_pub) = established_pair(allowed.clone(), allowed);
    let (forwarding, id) = forwarding_with_engine(resp);
    let engine = std::sync::Arc::clone(&forwarding.wg_engines[&id]);

    let mut wire = vec![0u8; 2048];
    let enc = init
        .create_keepalive(&resp_pub, &mut wire)
        .expect("initiator keepalive");
    let frame = outer_frame_from(&wire[..enc.len], WG_PORT, ROAMED_OUTER, ROAMED_SPORT);
    let meta = outer_meta(frame.len());

    let scratch = WgWorkerScratch::new(4096);
    let decapped = super::decap::try_wg_decap_from_frame(&frame, meta, &forwarding, &scratch);
    assert!(
        decapped.is_none(),
        "a keepalive carries no inner packet, so the stage must still decline \
         the frame — #9018 adds endpoint learning, it does not make a keepalive \
         deliverable"
    );

    assert_eq!(
        engine.take_worker_observed_endpoint(&init_pub),
        Some(std::net::SocketAddr::from((ROAMED_OUTER, ROAMED_SPORT))),
        "an AUTHENTICATED keepalive from a new endpoint must roam the peer. \
         Before #9018 `.ok()?` discarded DecapError::Keepalive(pk) and the \
         endpoint stayed stale until the peer's next handshake — which is the \
         only reason the tunnel recovered at all"
    );
    // Drained, not merely readable: a second take must be empty, or the control
    // thread re-adopts the same roam on every pass.
    assert_eq!(engine.take_worker_observed_endpoint(&init_pub), None);
    // It is still counted as a keepalive, not as a drop.
    assert_eq!(
        engine.counters().decap_keepalives.load(Ordering::Relaxed),
        1,
        "the keepalive counter is unchanged by #9018"
    );
}

/// The same for MALFORMED INNER: authenticated, undeliverable, still roams.
///
/// #7686 gave this arm the peer identity for the same reason #7230 gave it to
/// keepalives, and the worker discarded both with the one `.ok()?`.
#[test]
fn worker_decap_roams_endpoint_on_malformed_inner_9018() {
    let allowed: Vec<ipnet::IpNet> = vec!["10.123.0.0/24".parse().unwrap()];
    let (init, resp, init_pub, resp_pub) = established_pair(allowed.clone(), allowed);
    let (forwarding, id) = forwarding_with_engine(resp);
    let engine = std::sync::Arc::clone(&forwarding.wg_engines[&id]);

    // A non-empty plaintext whose first nibble is neither 4 nor 6 does not
    // parse as an inner packet, so try_decap returns MalformedInner(pk).
    let junk = [0xffu8; 32];
    let mut wire = vec![0u8; 2048];
    let enc = init
        .try_encap(&resp_pub, &junk, &mut wire)
        .expect("initiator encap");
    let frame = outer_frame_from(&wire[..enc.len], WG_PORT, ROAMED_OUTER, ROAMED_SPORT);
    let meta = outer_meta(frame.len());

    let scratch = WgWorkerScratch::new(4096);
    assert!(
        super::decap::try_wg_decap_from_frame(&frame, meta, &forwarding, &scratch).is_none(),
        "a malformed inner is not deliverable"
    );
    assert_eq!(
        engine.take_worker_observed_endpoint(&init_pub),
        Some(std::net::SocketAddr::from((ROAMED_OUTER, ROAMED_SPORT))),
        "an authenticated record with an unparseable inner still proves the \
         peer is at this endpoint (#7686 + #9018)"
    );
}

/// CONTROL: an UNAUTHENTICATED datagram must never move an endpoint.
///
/// This is the arm that makes the two cells above safe rather than merely
/// convenient. If the roam report were hoisted above the crypto — or the
/// catch-all `Err(_)` arm were widened — anyone who can reach the listen port
/// could redirect a tunnel's egress. Every cell above would still pass.
#[test]
fn worker_decap_does_not_roam_on_unauthenticated_record_9018() {
    let allowed: Vec<ipnet::IpNet> = vec!["10.123.0.0/24".parse().unwrap()];
    let (init, resp, init_pub, resp_pub) = established_pair(allowed.clone(), allowed);
    let (forwarding, id) = forwarding_with_engine(resp);
    let engine = std::sync::Arc::clone(&forwarding.wg_engines[&id]);

    let inner = inner_v4([10, 123, 0, 5], [10, 0, 61, 102]);
    let mut wire = vec![0u8; 2048];
    let enc = init
        .try_encap(&resp_pub, &inner, &mut wire)
        .expect("initiator encap");
    // Corrupt the ciphertext so the AEAD tag check fails: same session, same
    // receiver_index, so it is demuxed to a peer and then REJECTED.
    let mut record = wire[..enc.len].to_vec();
    let last = record.len() - 1;
    record[last] ^= 0xff;
    let frame = outer_frame_from(&record, WG_PORT, ROAMED_OUTER, ROAMED_SPORT);
    let meta = outer_meta(frame.len());

    let scratch = WgWorkerScratch::new(4096);
    assert!(
        super::decap::try_wg_decap_from_frame(&frame, meta, &forwarding, &scratch).is_none(),
        "a record that fails AEAD is not deliverable"
    );
    assert_eq!(
        engine.take_worker_observed_endpoint(&init_pub),
        None,
        "an UNAUTHENTICATED datagram must never move a peer's endpoint — \
         otherwise anyone who can send to the listen port redirects the \
         tunnel's egress. Only post-AEAD arms may roam"
    );
    assert!(
        engine.counters().decap_drops_crypto.load(Ordering::Relaxed) >= 1,
        "the corrupted record must be counted as a crypto failure, or this \
         cell is asserting about a record that never reached try_decap"
    );
}

/// #9018: the T7 no-reply arm and the endpoint update now move TOGETHER.
///
/// `note_authenticated_recv` clears `t7_armed_send_ns` from a received
/// keepalive, and it runs INSIDE `try_decap` — before the caller can do
/// anything with the error. Before this change the worker then discarded the
/// identity, so the session was refreshed as alive while its endpoint stayed
/// stale, and the reinit arm that would have forced an earlier re-handshake was
/// disarmed by the very packet that should have roamed the peer.
///
/// The report suggests not clearing T7 when the endpoint could not be applied.
/// That is deliberately NOT done: with the endpoint applied, "the peer is
/// alive" is now accurate, and the no-reply reinit arm is the wrong mechanism
/// to compensate for a stale endpoint — changing it is a protocol-timing change
/// with a far wider blast radius. This cell PINS the pairing instead, so a
/// future change to either half is deliberate rather than incidental.
#[test]
fn worker_decap_keepalive_clears_t7_and_roams_together_9018() {
    let allowed: Vec<ipnet::IpNet> = vec!["10.123.0.0/24".parse().unwrap()];
    let (init, resp, init_pub, resp_pub) = established_pair(allowed.clone(), allowed);
    let (forwarding, id) = forwarding_with_engine(resp);
    let engine = std::sync::Arc::clone(&forwarding.wg_engines[&id]);

    // ARM T7 first, or the assertion below is vacuous: an unarmed peer reads
    // 0 whether or not the keepalive cleared anything.
    let peer = engine.peer_arc(&init_pub).expect("responder knows the peer");
    peer.note_data_send(1_000);
    assert_ne!(
        peer.t7_armed_send_ns.load(std::sync::atomic::Ordering::Relaxed),
        0,
        "fixture precondition: T7 must be armed before the keepalive arrives, \
         or this cell cannot observe it being cleared"
    );

    let mut wire = vec![0u8; 2048];
    let enc = init
        .create_keepalive(&resp_pub, &mut wire)
        .expect("initiator keepalive");
    let frame = outer_frame_from(&wire[..enc.len], WG_PORT, ROAMED_OUTER, ROAMED_SPORT);
    let meta = outer_meta(frame.len());
    let scratch = WgWorkerScratch::new(4096);
    assert!(super::decap::try_wg_decap_from_frame(&frame, meta, &forwarding, &scratch).is_none());

    assert_eq!(
        peer.t7_armed_send_ns.load(std::sync::atomic::Ordering::Relaxed),
        0,
        "a received keepalive still clears the T7 no-reply arm (unchanged by \
         #9018 — see this cell's doc comment for why that is deliberate)"
    );
    assert_eq!(
        engine.take_worker_observed_endpoint(&init_pub),
        Some(std::net::SocketAddr::from((ROAMED_OUTER, ROAMED_SPORT))),
        "...and the endpoint moves in the SAME pass. That pairing is the whole \
         justification for leaving T7 alone: before #9018 the session was \
         marked alive while its endpoint stayed stale"
    );
}

/// #9587 closes the CONTROL THREAD's kernel-path delivery for unsteered ports
/// and must not reach this stage. The worker matches every configured listen
/// port (`wg_endpoint_for_listen_port`), and which records reach it is decided
/// by the shim, not by the steered set alone: a listener on an
/// interface-mode source-NAT address is not `is_local_destination`, so its
/// records are redirected to the worker whatever their port. Gating this stage
/// on the steered set would black-hole those tunnels and close nothing, so a
/// snapshot that steers some OTHER port must leave worker decap untouched.
#[test]
fn worker_decap_is_not_gated_by_the_steered_port_9521() {
    let allowed: Vec<ipnet::IpNet> = vec!["10.123.0.0/24".parse().unwrap()];
    let (init, resp, _init_pub, resp_pub) = established_pair(allowed.clone(), allowed);
    let (mut forwarding, _id) = forwarding_with_engine(resp);
    let mut other = [0u16; crate::afxdp::types::WG_STEERED_PORT_SET_MAX];
    other[0] = WG_PORT.wrapping_add(1);
    forwarding.wg_steered_listen_ports = other;
    forwarding.wg_steered_listen_port_count = 1;

    let inner = inner_v4([10, 123, 0, 5], [10, 0, 61, 102]);
    let mut wire = vec![0u8; 2048];
    let enc = init.try_encap(&resp_pub, &inner, &mut wire).expect("initiator encap");
    let frame = outer_frame(&wire[..enc.len], WG_PORT);
    let meta = outer_meta(frame.len());
    let scratch = WgWorkerScratch::new(4096);
    let decapped = super::decap::try_wg_decap_from_frame(&frame, meta, &forwarding, &scratch)
        .expect("worker decap must not depend on which port the shim's scalar steers");
    assert_eq!(decapped.meta.ingress_zone, TEST_SFMIX_ZONE_ID);
    assert_eq!(&decapped.frame[14..], &inner[..]);
}

/// An inner IPv4 ICMP echo packet (request type 8 / reply type 0), bare IP.
/// Checksums computed (not zero) so no screen can refuse it for that reason.
fn icmp_echo_inner_v4(icmp_type: u8, src: [u8; 4], dst: [u8; 4], ident: u16, seq: u16) -> Vec<u8> {
    let mut p = vec![0u8; 20 + 8];
    p[0] = 0x45;
    p[2..4].copy_from_slice(&28u16.to_be_bytes());
    p[8] = 64;
    p[9] = PROTO_ICMP;
    p[12..16].copy_from_slice(&src);
    p[16..20].copy_from_slice(&dst);
    let ip_sum = crate::afxdp::frame::checksum::checksum16(&p[..20]);
    p[10..12].copy_from_slice(&ip_sum.to_be_bytes());
    p[20] = icmp_type;
    p[21] = 0;
    p[24..26].copy_from_slice(&ident.to_be_bytes());
    p[26..28].copy_from_slice(&seq.to_be_bytes());
    let icmp_sum = crate::afxdp::frame::checksum::checksum16(&p[20..28]);
    p[22..24].copy_from_slice(&icmp_sum.to_be_bytes());
    p
}

/// Parse a bare inner IP packet's session flow (eth-wrap + frame parse).
fn inner_flow_key(packet: &[u8], protocol: u8) -> SessionFlow {
    let mut frame = vec![0u8; 14 + packet.len()];
    frame[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
    frame[14..].copy_from_slice(packet);
    let meta = UserspaceDpMeta {
        l3_offset: 14,
        l4_offset: 34,
        payload_offset: 34,
        pkt_len: frame.len() as u16,
        addr_family: libc::AF_INET as u8,
        protocol,
        ..UserspaceDpMeta::default()
    };
    crate::afxdp::frame::parse_session_flow_from_bytes(&frame, meta)
        .expect("inner echo must parse to a session flow")
}

/// Forwarding with a live engine, optionally permitting the TUN-origin
/// forward pair (sfmix→sfmix) so #9604 lets the HIT through to host-inbound.
fn tun_origin_forwarding(resp: WgEngine, permit_forward: bool) -> (ForwardingState, u16) {
    tun_origin_forwarding_opts(resp, permit_forward, false, false)
}

/// `tun_origin_forwarding` with the B8 posture pins: a `sfmix -> junos-host`
/// deny (the junos-host-skip pin) and an lo0 filter discarding ICMP (the
/// lo0-still-filters pin). V1/V2 delegate with both off — behavior unchanged.
fn tun_origin_forwarding_opts(
    resp: WgEngine,
    permit_forward: bool,
    junos_host_deny: bool,
    lo0_discard_icmp: bool,
) -> (ForwardingState, u16) {
    let mut snap = wg_outer_mtu_snapshot();
    if permit_forward {
        snap.policies = vec![crate::PolicyRuleSnapshot {
            name: "permit-tun-origin-forward".to_string(),
            from_zone: "sfmix".to_string(),
            to_zone: "sfmix".to_string(),
            source_addresses: vec!["any".to_string()],
            destination_addresses: vec!["any".to_string()],
            applications: vec!["any".to_string()],
            application_terms: Vec::new(),
            action: "permit".to_string(),
            ..Default::default()
        }];
    }
    if junos_host_deny {
        snap.policies.push(crate::PolicyRuleSnapshot {
            name: "sfmix-no-host".to_string(),
            from_zone: "sfmix".to_string(),
            to_zone: "junos-host".to_string(),
            source_addresses: vec!["any".to_string()],
            destination_addresses: vec!["any".to_string()],
            applications: vec!["any".to_string()],
            application_terms: Vec::new(),
            action: "deny".to_string(),
            ..Default::default()
        });
    }
    if lo0_discard_icmp {
        snap.filters.push(crate::FirewallFilterSnapshot {
            name: "protect-re".to_string(),
            family: "inet".to_string(),
            terms: vec![crate::FirewallTermSnapshot {
                name: "no-icmp".to_string(),
                protocols: vec!["icmp".to_string()],
                action: "discard".to_string(),
                ..Default::default()
            }],
        });
        snap.flow.lo0_filter_input_v4 = "protect-re".to_string();
    }
    let mut forwarding = build_forwarding_state(&snap);
    let id = *forwarding.wg_engines.keys().next().expect("wg tunnel");
    forwarding.wg_engines.insert(id, std::sync::Arc::new(resp));
    (forwarding, id)
}

/// Shared body for the V1/V2 #10038 cells: fw (10.123.0.1, wg0.0) pings peer
/// (10.123.0.5); the request leaves via the wgN TUN (control thread, no
/// worker session — the install half of #10038). The peer's echo-reply
/// arrives as type-4, is decapped in the worker, and — with the forward +
/// reverse the TUN path SHOULD have published pre-installed here — must be
/// admitted as a solicited reply.
fn run_tun_origin_case_10038(permit_forward: bool) {
    const FW: [u8; 4] = [10, 123, 0, 1];
    const PEER: [u8; 4] = [10, 123, 0, 5];
    const IDENT: u16 = 0x3857;
    let allowed: Vec<ipnet::IpNet> = vec!["10.123.0.0/24".parse().unwrap()];
    let (init, resp, _init_pub, rpub) = established_pair(allowed.clone(), allowed);
    let (forwarding, tun_id) = tun_origin_forwarding(resp, permit_forward);
    // The two halves of the TUN-originated flow, keyed by parsing (robust to
    // the ICMP ident pseudo-port convention — no hand-built SessionKey).
    let request = icmp_echo_inner_v4(8, FW, PEER, IDENT, 1);
    let reply = icmp_echo_inner_v4(0, PEER, FW, IDENT, 1);
    let fwd_key = inner_flow_key(&request, PROTO_ICMP).forward_key;
    let rev_key = inner_flow_key(&reply, PROTO_ICMP).forward_key;
    assert_ne!(fwd_key, rev_key, "request and reply must key differently");

    // The pair the TUN path SHOULD publish (forward: TUN-origin-shaped;
    // reverse: host-bound solicited). Metadata mirrors
    // build_local_origin_tunnel_tx_request (zero policy: self-originated).
    let fwd_decision = SessionDecision {
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::ForwardCandidate,
            local_ifindex: 0,
            egress_ifindex: TUNNEL_LOGICAL_IFINDEX,
            tx_ifindex: 12,
            tunnel_endpoint_id: tun_id,
            next_hop: None,
            neighbor_mac: None,
            src_mac: None,
            tx_vlan_id: 0,
        },
        nat: NatDecision::default(),
        install_table_domain: 0,
        install_table_check: 0,
    };
    let rev_decision = SessionDecision {
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::LocalDelivery,
            local_ifindex: TUNNEL_LOGICAL_IFINDEX,
            egress_ifindex: TUNNEL_LOGICAL_IFINDEX,
            tx_ifindex: TUNNEL_LOGICAL_IFINDEX,
            tunnel_endpoint_id: 0,
            next_hop: None,
            neighbor_mac: None,
            src_mac: None,
            tx_vlan_id: 0,
        },
        nat: NatDecision::default(),
        install_table_domain: 0,
        install_table_check: 0,
    };
    let mk_meta = |is_reverse: bool| SessionMetadata {
        ingress_zone: TEST_SFMIX_ZONE_ID,
        egress_zone: TEST_SFMIX_ZONE_ID,
        ingress_ifindex: 0,
        ingress_vlan_id: 0,
        owner_rg_id: 1,
        fabric_ingress: false,
        is_reverse,
        nat64_reverse: None,
        log_session_init: false,
        log_session_close: false,
        policy_id: 0,
        inactivity_timeout_ns: None,
        policy_counter_idx: 0,
        policy_counter: None,
    };
    let install_pair = |sessions: &mut SessionTable| {
        assert!(
            sessions.install_with_protocol_with_origin(
                fwd_key.clone(),
                fwd_decision,
                mk_meta(false),
                SessionOrigin::TunOrigin,
                122_000_000_000,
                PROTO_ICMP,
                0,
            ),
            "forward must install"
        );
        assert!(
            sessions.install_with_protocol_with_origin(
                rev_key.clone(),
                rev_decision,
                mk_meta(true),
                SessionOrigin::TunOrigin,
                122_000_000_000,
                PROTO_ICMP,
                0,
            ),
            "reverse must install"
        );
    };

    // Fresh outer record PER RUN: each try_decap consumes its nonce in the
    // responder's replay window, so reusing one record across runs would make
    // every run after the first fail decap as replay (observed while writing
    // this cell: a shared record reds on MISS, not on the HIT arm).
    let ha_state = txn_ha_state();
    let run = |sessions: &mut SessionTable| {
        let mut wire = vec![0u8; 2048];
        let enc = init
            .try_encap(&rpub, &reply, &mut wire)
            .expect("encap reply");
        let frame = outer_frame(&wire[..enc.len], WG_PORT);
        let meta = wiring_meta(frame.len());
        let mut binding = BindingWorker::new_for_mirror_test(0, 0, 12, 0);
        binding.interface = std::sync::Arc::<str>::from("ge-0-0-2.80");
        txn_run_descriptor_checked(&mut binding, sessions, &forwarding, &ha_state, &frame, meta, true)
    };

    // CONTROL (passes on base AND after fix): no session → MISS → the
    // ping-less sfmix zone denies at host-inbound. Proves the packet reaches
    // the gate, so the subject's RED is the HIT arm denying, not a fixture
    // that never arrives.
    {
        let mut sessions = SessionTable::new();
        let (batch, dbg) = run(&mut sessions);
        assert_eq!(dbg.session_hit, 0, "control must MISS (no session)");
        assert_eq!(
            batch.host_inbound_denied_packets, 1,
            "control: an unsolicited echo-reply on a ping-less zone must die \
             at host-inbound (fail-closed; this arm is unchanged by #10038)"
        );
    }

    // SUBJECT (RED on base, green after fix): WITH the TUN-origin pair
    // installed, the solicited reply HITS and must be admitted.
    {
        let mut sessions = SessionTable::new();
        install_pair(&mut sessions);
        let (batch, dbg) = run(&mut sessions);
        assert!(
            dbg.session_hit >= 1,
            "the reply must HIT the pre-installed reverse (no HIT = the keys \
             diverge and this cell is vacuous)"
        );
        // C5: pin the post-fix steady state precisely — no revocation, no
        // host-inbound deny, both rows survive, reply delivered. Each assert
        // reds on base (V1 via #9604 revoke, V2 via HIT-deny teardown).
        assert_eq!(
            dbg.policy_revoked_sessions, 0,
            "#10038: the solicited HIT must not revoke the TUN-origin pair"
        );
        assert_eq!(
            batch.host_inbound_denied_packets, 0,
            "#10038: a solicited reply HIT must bypass host-inbound admission \
             (it is admitted by its TUN-origin session, not by the zone's \
             service set)"
        );
        let mut rows = 0usize;
        sessions.iter_with_origin(|_, _, _, _| rows += 1);
        assert_eq!(rows, 2, "#10038: forward + reverse must both survive");
        assert!(
            dbg.local >= 1 || batch.local_delivery_packets >= 1,
            "#10038: the solicited reply must be delivered host-bound"
        );
    }
}

/// #10038 V1 (RED on base via #9604 revocation; pins Part C): no forward-pair
/// permit, so on base the reverse HIT is judged by its forward companion's
/// transit pair (sfmix→sfmix), the default DENY revokes the pair, and the
/// reply dies before host-inbound. After the fix #9604 declines TUN-origin
/// forwards (self-originated runs no policy) and the reply is delivered.
#[test]
fn wg_solicited_reply_revoked_without_tun_origin_gates_10038() {
    run_tun_origin_case_10038(false);
}

/// #10038 V2 (RED on base via host-inbound HIT deny; pins Part B): the
/// forward pair permits, so on base the HIT reaches the LocalDelivery
/// host-inbound re-check, which denies type 0 on the ping-less sfmix zone
/// and tears the session down. After the fix the solicited HIT bypasses
/// admission (forward-companion TUN-origin proof) and is delivered.
#[test]
fn wg_solicited_reply_dies_at_host_inbound_10038() {
    run_tun_origin_case_10038(true);
}

/// #10038 E2E (pins Part A + the production shared-only shape): the forward +
/// reverse come from the PRODUCTION builder (not hand-built) and live ONLY in
/// the shared maps — never installed locally, because forward packets bypass
/// the worker and the forward never materializes. The reply HITS shared, the
/// materialized reverse is exempted via its shared forward companion, and the
/// reply is delivered — with NO tunnel permit (the shared-only path never
/// reaches #9604's companion arm: the lone reverse declines by the
/// pre-existing arm, so this cell is C-insensitive by design).
#[test]
fn wg_tun_origin_builder_to_shared_to_delivery_10038() {
    const FW: [u8; 4] = [10, 123, 0, 1];
    const PEER: [u8; 4] = [10, 123, 0, 5];
    const IDENT: u16 = 0x3857;
    let allowed: Vec<ipnet::IpNet> = vec!["10.123.0.0/24".parse().unwrap()];
    let (init, resp, _init_pub, rpub) = established_pair(allowed.clone(), allowed);
    let (forwarding, tun_id) = tun_origin_forwarding(resp, false);
    let request = icmp_echo_inner_v4(8, FW, PEER, IDENT, 1);
    let reply = icmp_echo_inner_v4(0, PEER, FW, IDENT, 1);
    let fwd_key = inner_flow_key(&request, PROTO_ICMP).forward_key;
    let rev_key = inner_flow_key(&reply, PROTO_ICMP).forward_key;

    // The loop's publish path, minus the loop: production parse + build +
    // shared publish.
    let neighbors = Arc::new(ShardedNeighborMap::new());
    let ha = txn_ha_state();
    let parsed =
        parse_wg_tun_origin_flow(&request, &forwarding, tun_id).expect("request must parse");
    assert_eq!(
        parsed.flow.forward_key, fwd_key,
        "the builder must key what the worker will HIT, or this E2E is vacuous"
    );
    let peer_ep: std::net::SocketAddr = "203.0.113.7:51820".parse().unwrap();
    let entries =
        build_wg_tun_origin_entries(&parsed, peer_ep, tun_id, &forwarding, &ha, &neighbors, 123)
            .expect("build must succeed");
    assert_eq!(entries.forward.origin, SessionOrigin::TunOrigin);
    assert_eq!(entries.forward.metadata.ingress_ifindex, 0);
    assert_eq!(
        entries.forward.decision.resolution.tunnel_endpoint_id,
        tun_id
    );
    let reverse = entries.reverse.as_ref().expect("reverse must synthesize");
    assert_eq!(
        reverse.decision.resolution.disposition,
        ForwardingDisposition::LocalDelivery
    );
    let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
    // Production publish (not raw shared inserts): the request initiates,
    // so the item-4 gate allows and the pair lands exactly as the burst
    // would publish it.
    assert!(wg_tun_origin_packet_initiates(&parsed));
    let mut dedup_ns = FastMap::<SessionKey, u64>::default();
    let mut tombstones = FastMap::<SessionKey, u64>::default();
    publish_wg_tun_origin_entries(
        &shared_sessions,
        &shared_nat_sessions,
        &shared_forward_wire_sessions,
        &shared_owner_rg_indexes,
        &mut dedup_ns,
        &mut tombstones,
        &entries,
        true,
        122_000_000_000,
    );

    // The reply through the worker with an EMPTY local table.
    let mut wire = vec![0u8; 2048];
    let enc = init
        .try_encap(&rpub, &reply, &mut wire)
        .expect("encap reply");
    let frame = outer_frame(&wire[..enc.len], WG_PORT);
    let meta = wiring_meta(frame.len());
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 12, 0);
    binding.interface = std::sync::Arc::<str>::from("ge-0-0-2.80");
    let mut sessions = SessionTable::new();
    let local_tunnel_deliveries = Arc::new(ArcSwap::from_pointee(BTreeMap::new()));
    let (batch, dbg) = txn_run_descriptor_inner(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha,
        &frame,
        meta,
        &local_tunnel_deliveries,
        &shared_sessions,
    );
    assert!(
        dbg.session_hit >= 1,
        "the reply must HIT the shared reverse (no HIT = the builder keyed \
         something the worker cannot find and this cell is vacuous)"
    );
    assert_eq!(dbg.policy_revoked_sessions, 0, "no revocation on the HIT");
    assert_eq!(
        batch.host_inbound_denied_packets, 0,
        "the solicited HIT must bypass host-inbound admission"
    );
    assert!(
        dbg.local >= 1 || batch.local_delivery_packets >= 1,
        "the solicited reply must be delivered host-bound"
    );
    // Shared-only pin: the reverse materialized locally, the forward never
    // did (forward packets bypass the worker in production).
    let mut local_keys = Vec::new();
    sessions.iter_with_origin(|key, _, _, _| local_keys.push(key.clone()));
    assert!(
        local_keys.contains(&rev_key),
        "reverse must materialize locally"
    );
    assert!(
        !local_keys.contains(&fwd_key),
        "forward must stay shared-only"
    );
    assert!(
        shared_sessions
            .lock()
            .expect("shared map")
            .contains_key(&fwd_key),
        "the forward must still be in the shared map"
    );
}

// =======================================================================
// #10038 B8 suite: the HIT-exemption boundary pins. V2 (permit, marker pair,
// delivered) is the shared positive control every cell below is shaped
// against — each cell varies ONE dimension (posture, forward shape, or
// arrival) and asserts the resulting verdict.
// =======================================================================

/// Install a solicited-pair shape: the forward half exactly as described
/// (origin/ingress/policy-counter are the discriminator inputs under test),
/// the reverse always the host-bound solicited shape. `install_forward=false`
/// installs the lone reverse (fail-closed pin).
#[allow(clippy::too_many_arguments)]
fn install_solicited_pair_10038(
    sessions: &mut SessionTable,
    fwd_key: &SessionKey,
    rev_key: &SessionKey,
    tun_id: u16,
    fwd_origin: SessionOrigin,
    fwd_ingress_ifindex: u32,
    fwd_policy_counter_idx: u32,
    rev_origin: SessionOrigin,
    install_forward: bool,
) {
    let fwd_decision = SessionDecision {
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::ForwardCandidate,
            local_ifindex: 0,
            egress_ifindex: TUNNEL_LOGICAL_IFINDEX,
            tx_ifindex: 12,
            tunnel_endpoint_id: tun_id,
            next_hop: None,
            neighbor_mac: None,
            src_mac: None,
            tx_vlan_id: 0,
        },
        nat: NatDecision::default(),
        install_table_domain: 0,
        install_table_check: 0,
    };
    let rev_decision = SessionDecision {
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::LocalDelivery,
            local_ifindex: TUNNEL_LOGICAL_IFINDEX,
            egress_ifindex: TUNNEL_LOGICAL_IFINDEX,
            tx_ifindex: TUNNEL_LOGICAL_IFINDEX,
            tunnel_endpoint_id: 0,
            next_hop: None,
            neighbor_mac: None,
            src_mac: None,
            tx_vlan_id: 0,
        },
        nat: NatDecision::default(),
        install_table_domain: 0,
        install_table_check: 0,
    };
    let mk_meta = |is_reverse: bool, ingress: u32, policy_idx: u32| SessionMetadata {
        ingress_zone: TEST_SFMIX_ZONE_ID,
        egress_zone: TEST_SFMIX_ZONE_ID,
        ingress_ifindex: ingress,
        ingress_vlan_id: 0,
        owner_rg_id: 1,
        fabric_ingress: false,
        is_reverse,
        nat64_reverse: None,
        log_session_init: false,
        log_session_close: false,
        policy_id: 0,
        inactivity_timeout_ns: None,
        policy_counter_idx: policy_idx,
        policy_counter: None,
    };
    if install_forward {
        assert!(
            sessions.install_with_protocol_with_origin(
                fwd_key.clone(),
                fwd_decision,
                mk_meta(false, fwd_ingress_ifindex, fwd_policy_counter_idx),
                fwd_origin,
                122_000_000_000,
                PROTO_ICMP,
                0,
            ),
            "forward must install"
        );
    }
    assert!(
        sessions.install_with_protocol_with_origin(
            rev_key.clone(),
            rev_decision,
            mk_meta(true, 0, 0),
            rev_origin,
            122_000_000_000,
            PROTO_ICMP,
            0,
        ),
        "reverse must install"
    );
}

/// Encap `inner` (an echo reply — or request — the peer sends) and drive it
/// through the worker once. Fresh outer record per call (see V1/V2).
fn drive_solicited_inner_10038(
    forwarding: &ForwardingState,
    sessions: &mut SessionTable,
    init: &WgEngine,
    rpub: &[u8; 32],
    inner: &[u8],
) -> (BatchCounters, DebugPollCounters) {
    let ha_state = txn_ha_state();
    let mut wire = vec![0u8; 2048];
    let enc = init.try_encap(rpub, inner, &mut wire).expect("encap inner");
    let frame = outer_frame(&wire[..enc.len], WG_PORT);
    let meta = wiring_meta(frame.len());
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 12, 0);
    binding.interface = std::sync::Arc::<str>::from("ge-0-0-2.80");
    txn_run_descriptor_checked(&mut binding, sessions, forwarding, &ha_state, &frame, meta, true)
}

/// Drive `inner` (an echo reply 5-tuple) as a PLAIN frame arriving on the
/// underlay (reth0.80/wan, ifindex 12) — no WG encap, no decap, so the meta
/// keeps the arrival interface and the packet is FOREIGN to the sfmix
/// TUN-origin pair it HITS by 5-tuple. Fresh binding per call (no flow-cache
/// carryover — the #9519 discipline).
fn drive_spoofed_plain_10038(
    forwarding: &ForwardingState,
    sessions: &mut SessionTable,
    inner: &[u8],
) -> (BatchCounters, DebugPollCounters) {
    let ha_state = txn_ha_state();
    // Exact-size wrap (byte-identical to `inner_flow_key`): the frame parser
    // validates against the IP-declared length, so padding breaks the parse.
    let mut frame = vec![0u8; 14 + inner.len()];
    // #10314: same MAC-guard repair as `outer_frame` — an all-zero unicast
    // destination is PACKET_OTHERHOST and would be recycled pre-L3.
    frame[..6].copy_from_slice(&[0x02, 0xbf, 0x72, 0x00, 0x50, 0x08]);
    frame[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
    frame[14..].copy_from_slice(inner);
    // From `wiring_meta` (same fence/generation/rx fields as every working
    // drive), re-pointed at the plain inner: same arrival interface, ICMP.
    let mut meta = wiring_meta(frame.len());
    meta.l4_offset = 34;
    meta.payload_offset = 34;
    meta.protocol = PROTO_ICMP;
    meta.tcp_flags = 0;
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 12, 0);
    binding.interface = std::sync::Arc::<str>::from("ge-0-0-2.80");
    txn_run_descriptor_checked(&mut binding, sessions, forwarding, &ha_state, &frame, meta, true)
}

fn session_row_count_10038(sessions: &SessionTable) -> usize {
    let mut rows = 0usize;
    sessions.iter_with_origin(|_, _, _, _| rows += 1);
    rows
}

/// #10038 B8 (lo0-preserved): the exemption skips host-inbound admission, NOT
/// the lo0 packet filter. Same V2 shape + an lo0 filter discarding ICMP: the
/// reply HITS, is denied by the filter (`policy_deny`, not
/// `host_inbound_denied`), and the owner session tears down. RED on base (the
/// HIT dies at host-inbound there, so `policy_deny` stays 0).
#[test]
fn wg_solicited_reply_lo0_still_filters_10038() {
    const FW: [u8; 4] = [10, 123, 0, 1];
    const PEER: [u8; 4] = [10, 123, 0, 5];
    const IDENT: u16 = 0x3857;
    let allowed: Vec<ipnet::IpNet> = vec!["10.123.0.0/24".parse().unwrap()];
    let (init, resp, _init_pub, rpub) = established_pair(allowed.clone(), allowed);
    let (forwarding, tun_id) = tun_origin_forwarding_opts(resp, true, false, true);
    let request = icmp_echo_inner_v4(8, FW, PEER, IDENT, 1);
    let reply = icmp_echo_inner_v4(0, PEER, FW, IDENT, 1);
    let fwd_key = inner_flow_key(&request, PROTO_ICMP).forward_key;
    let rev_key = inner_flow_key(&reply, PROTO_ICMP).forward_key;
    let mut sessions = SessionTable::new();
    install_solicited_pair_10038(
        &mut sessions,
        &fwd_key,
        &rev_key,
        tun_id,
        SessionOrigin::TunOrigin,
        0,
        0,
        SessionOrigin::TunOrigin,
        true,
    );
    let (batch, dbg) =
        drive_solicited_inner_10038(&forwarding, &mut sessions, &init, &rpub, &reply);
    assert!(dbg.session_hit >= 1, "the reply must HIT the reverse");
    assert_eq!(
        dbg.policy_deny, 1,
        "lo0 discards ICMP: the solicited reply must die by the packet filter"
    );
    assert_eq!(
        batch.host_inbound_denied_packets, 0,
        "host-inbound admission must be bypassed (it is what is exempted)"
    );
    assert_eq!(
        batch.local_delivery_packets, 0,
        "the reply must not deliver"
    );
    assert_eq!(
        session_row_count_10038(&sessions),
        0,
        "a terminal filter verdict on owner traffic tears the pair down"
    );
}

/// #10038 B8 (spoof-plant negative): a MISS-installed forward
/// (`ForwardFlow`, arrival ingress, admitting policy counter) proves nothing
/// about TUN origin, so the exemption must NOT fire. The forward permit is
/// set, so #9604 passes and the reply reaches host-inbound — which denies it
/// on the ping-less zone. Guard cell: green on base AND after the fix (it
/// reds only if the exemption over-fires — see the predicate-weakening
/// mutation in docs/log/10038.md).
#[test]
fn wg_spoof_plant_forward_does_not_exempt_10038() {
    const FW: [u8; 4] = [10, 123, 0, 1];
    const PEER: [u8; 4] = [10, 123, 0, 5];
    const IDENT: u16 = 0x3857;
    let allowed: Vec<ipnet::IpNet> = vec!["10.123.0.0/24".parse().unwrap()];
    let (init, resp, _init_pub, rpub) = established_pair(allowed.clone(), allowed);
    let (forwarding, tun_id) = tun_origin_forwarding_opts(resp, true, false, false);
    let request = icmp_echo_inner_v4(8, FW, PEER, IDENT, 1);
    let reply = icmp_echo_inner_v4(0, PEER, FW, IDENT, 1);
    let fwd_key = inner_flow_key(&request, PROTO_ICMP).forward_key;
    let rev_key = inner_flow_key(&reply, PROTO_ICMP).forward_key;
    let mut sessions = SessionTable::new();
    // The plant shape: a forward-tuple packet that arrived tunnel-side and
    // MISS-installed (arrival = tunnel logical 400, admitting policy 1).
    install_solicited_pair_10038(
        &mut sessions,
        &fwd_key,
        &rev_key,
        tun_id,
        SessionOrigin::ForwardFlow,
        400,
        1,
        SessionOrigin::ReverseFlow,
        true,
    );
    let (batch, dbg) =
        drive_solicited_inner_10038(&forwarding, &mut sessions, &init, &rpub, &reply);
    assert!(dbg.session_hit >= 1, "the reply must HIT the reverse");
    assert_eq!(
        batch.host_inbound_denied_packets, 1,
        "a plant forward proves no TUN origin: the reply must die at host-inbound"
    );
    assert_eq!(
        batch.local_delivery_packets, 0,
        "the reply must not deliver"
    );
}

/// #10038 B8 (junos-host pin): the exemption skips the junos-host re-check
/// too (self-originated runs no junos-host policy either). Same V2 shape +
/// a `sfmix -> junos-host` deny: the reply is STILL delivered, with no
/// policy deny. RED on base (dies at host-inbound); the targeted mutation
/// (restore the junos gate only) reds via `policy_deny`, proving the deny
/// rule matches and this cell is non-vacuous.
#[test]
fn wg_solicited_reply_skips_junos_host_10038() {
    const FW: [u8; 4] = [10, 123, 0, 1];
    const PEER: [u8; 4] = [10, 123, 0, 5];
    const IDENT: u16 = 0x3857;
    let allowed: Vec<ipnet::IpNet> = vec!["10.123.0.0/24".parse().unwrap()];
    let (init, resp, _init_pub, rpub) = established_pair(allowed.clone(), allowed);
    let (forwarding, tun_id) = tun_origin_forwarding_opts(resp, true, true, false);
    let request = icmp_echo_inner_v4(8, FW, PEER, IDENT, 1);
    let reply = icmp_echo_inner_v4(0, PEER, FW, IDENT, 1);
    let fwd_key = inner_flow_key(&request, PROTO_ICMP).forward_key;
    let rev_key = inner_flow_key(&reply, PROTO_ICMP).forward_key;
    let mut sessions = SessionTable::new();
    install_solicited_pair_10038(
        &mut sessions,
        &fwd_key,
        &rev_key,
        tun_id,
        SessionOrigin::TunOrigin,
        0,
        0,
        SessionOrigin::TunOrigin,
        true,
    );
    let (batch, dbg) =
        drive_solicited_inner_10038(&forwarding, &mut sessions, &init, &rpub, &reply);
    assert!(dbg.session_hit >= 1, "the reply must HIT the reverse");
    assert_eq!(
        batch.host_inbound_denied_packets, 0,
        "host-inbound admission must be bypassed"
    );
    assert_eq!(dbg.policy_deny, 0, "the junos-host deny must be skipped");
    assert_eq!(dbg.policy_revoked_sessions, 0, "no revocation on the HIT");
    assert_eq!(
        session_row_count_10038(&sessions),
        2,
        "both rows must survive"
    );
    assert!(
        dbg.local >= 1 || batch.local_delivery_packets >= 1,
        "the solicited reply must be delivered despite the junos-host deny"
    );
}

/// #10038 B8 (tightening pin — forward-dies): a FORWARD host-bound HIT still
/// faces the every-hit host-inbound re-check (tightening voids nothing for
/// forwards). An echo request to the firewall HITS its hand-installed forward
/// LocalDelivery entry and dies at host-inbound on the ping-less zone.
/// Green on base AND after (control half of the tightening pair).
#[test]
fn wg_host_bound_forward_still_faces_host_inbound_10038() {
    const FW: [u8; 4] = [10, 123, 0, 1];
    const PEER: [u8; 4] = [10, 123, 0, 5];
    const IDENT: u16 = 0x3857;
    let allowed: Vec<ipnet::IpNet> = vec!["10.123.0.0/24".parse().unwrap()];
    let (init, resp, _init_pub, rpub) = established_pair(allowed.clone(), allowed);
    let (forwarding, _tun_id) = tun_origin_forwarding_opts(resp, true, false, false);
    // An echo REQUEST to the firewall's own WG address.
    let request = icmp_echo_inner_v4(8, PEER, FW, IDENT, 1);
    let req_key = inner_flow_key(&request, PROTO_ICMP).forward_key;
    let mut sessions = SessionTable::new();
    // Its MISS-installed forward shape: host-bound, non-reverse, arrival =
    // tunnel logical, admitted by policy 1.
    assert!(
        sessions.install_with_protocol_with_origin(
            req_key,
            SessionDecision {
                resolution: ForwardingResolution {
                    disposition: ForwardingDisposition::LocalDelivery,
                    local_ifindex: TUNNEL_LOGICAL_IFINDEX,
                    egress_ifindex: TUNNEL_LOGICAL_IFINDEX,
                    tx_ifindex: TUNNEL_LOGICAL_IFINDEX,
                    tunnel_endpoint_id: 0,
                    next_hop: None,
                    neighbor_mac: None,
                    src_mac: None,
                    tx_vlan_id: 0,
                },
                nat: NatDecision::default(),
                install_table_domain: 0,
                install_table_check: 0,
            },
            SessionMetadata {
                ingress_zone: TEST_SFMIX_ZONE_ID,
                egress_zone: TEST_SFMIX_ZONE_ID,
                ingress_ifindex: 400,
                ingress_vlan_id: 0,
                owner_rg_id: 1,
                fabric_ingress: false,
                is_reverse: false,
                nat64_reverse: None,
                log_session_init: false,
                log_session_close: false,
                policy_id: 0,
                inactivity_timeout_ns: None,
                policy_counter_idx: 1,
                policy_counter: None,
            },
            SessionOrigin::ForwardFlow,
            122_000_000_000,
            PROTO_ICMP,
            0,
        ),
        "forward must install"
    );
    let (batch, dbg) =
        drive_solicited_inner_10038(&forwarding, &mut sessions, &init, &rpub, &request);
    assert!(dbg.session_hit >= 1, "the request must HIT the forward");
    assert_eq!(
        batch.host_inbound_denied_packets, 1,
        "a forward host-bound HIT must still face host-inbound (tightening intact)"
    );
    assert_eq!(
        batch.local_delivery_packets, 0,
        "the request must not deliver"
    );
    assert_eq!(
        session_row_count_10038(&sessions),
        0,
        "owner teardown on the denied HIT"
    );
    // Reverse-survives half: the V2 shape delivers (full asserts inside).
    run_tun_origin_case_10038(true);
}

/// #10038 B8 (lone-reverse pin): a reverse with NO forward anywhere fails
/// closed — the exemption needs forward-companion TUN-origin proof. Guard
/// cell: green on base AND after (reds only if lone reverses are exempted).
#[test]
fn wg_lone_reverse_without_forward_denies_10038() {
    const FW: [u8; 4] = [10, 123, 0, 1];
    const PEER: [u8; 4] = [10, 123, 0, 5];
    const IDENT: u16 = 0x3857;
    let allowed: Vec<ipnet::IpNet> = vec!["10.123.0.0/24".parse().unwrap()];
    let (init, resp, _init_pub, rpub) = established_pair(allowed.clone(), allowed);
    let (forwarding, tun_id) = tun_origin_forwarding_opts(resp, true, false, false);
    let request = icmp_echo_inner_v4(8, FW, PEER, IDENT, 1);
    let reply = icmp_echo_inner_v4(0, PEER, FW, IDENT, 1);
    let fwd_key = inner_flow_key(&request, PROTO_ICMP).forward_key;
    let rev_key = inner_flow_key(&reply, PROTO_ICMP).forward_key;
    let mut sessions = SessionTable::new();
    install_solicited_pair_10038(
        &mut sessions,
        &fwd_key,
        &rev_key,
        tun_id,
        SessionOrigin::TunOrigin,
        0,
        0,
        SessionOrigin::TunOrigin,
        false,
    );
    let (batch, dbg) =
        drive_solicited_inner_10038(&forwarding, &mut sessions, &init, &rpub, &reply);
    assert!(dbg.session_hit >= 1, "the reply must HIT the reverse");
    assert_eq!(
        batch.host_inbound_denied_packets, 1,
        "with no forward companion the exemption must not fire"
    );
    assert_eq!(
        batch.local_delivery_packets, 0,
        "the reply must not deliver"
    );
}

/// #10038 B8 (fragments residual): a non-first fragment of the solicited
/// reply carries no session key (flowless arm), so the exemption — which is
/// keyed on the reverse HIT — cannot apply. Explicit residual: fragmented
/// solicited replies stay denied, and the pair is untouched (no key, no
/// teardown). Guard cell: green on base AND after.
#[test]
fn wg_fragmented_solicited_reply_stays_denied_10038() {
    const FW: [u8; 4] = [10, 123, 0, 1];
    const PEER: [u8; 4] = [10, 123, 0, 5];
    const IDENT: u16 = 0x3857;
    let allowed: Vec<ipnet::IpNet> = vec!["10.123.0.0/24".parse().unwrap()];
    let (init, resp, _init_pub, rpub) = established_pair(allowed.clone(), allowed);
    let (forwarding, tun_id) = tun_origin_forwarding_opts(resp, true, false, false);
    let request = icmp_echo_inner_v4(8, FW, PEER, IDENT, 1);
    let reply = icmp_echo_inner_v4(0, PEER, FW, IDENT, 1);
    let fwd_key = inner_flow_key(&request, PROTO_ICMP).forward_key;
    let rev_key = inner_flow_key(&reply, PROTO_ICMP).forward_key;
    let mut sessions = SessionTable::new();
    install_solicited_pair_10038(
        &mut sessions,
        &fwd_key,
        &rev_key,
        tun_id,
        SessionOrigin::TunOrigin,
        0,
        0,
        SessionOrigin::TunOrigin,
        true,
    );
    // The reply with a non-zero fragment offset (bytes 6..8 of the inner IP
    // header) + a recomputed header checksum — flowless by construction.
    let mut frag = reply.clone();
    frag[7] = 0x01;
    frag[10..12].copy_from_slice(&[0, 0]);
    let ip_sum = crate::afxdp::frame::checksum::checksum16(&frag[..20]);
    frag[10..12].copy_from_slice(&ip_sum.to_be_bytes());
    let (batch, dbg) = drive_solicited_inner_10038(&forwarding, &mut sessions, &init, &rpub, &frag);
    assert_eq!(
        dbg.session_hit, 0,
        "a non-first fragment is flowless: no HIT"
    );
    assert_eq!(
        batch.local_delivery_packets, 0,
        "the fragment must not deliver"
    );
    assert_eq!(
        session_row_count_10038(&sessions),
        2,
        "the flowless deny must not tear down the pair it cannot key"
    );
}

/// #10038 B8 (GRE-shaped, no permit — pins Part C on production GRE): GRE
/// local-origin publishes shared AND UpsertLocals the pair to every worker,
/// so a GRE TUN-origin forward is LOCALLY present — and #9604 would judge it
/// by its transit pair and revoke on a default-deny box. This cell builds
/// the pair with the REAL GRE builder, installs it through the UpsertLocal
/// path, and delivers the reply with NO tunnel permit. RED on base (revoke).
#[test]
fn gre_tun_origin_pair_needs_no_permit_10038() {
    const FW: [u8; 4] = [10, 123, 0, 1];
    const PEER: [u8; 4] = [10, 123, 0, 5];
    const IDENT: u16 = 0x3857;
    const GRE_TUN_ID: u16 = 2;
    let allowed: Vec<ipnet::IpNet> = vec!["10.123.0.0/24".parse().unwrap()];
    let (init, resp, _init_pub, rpub) = established_pair(allowed.clone(), allowed);
    // One forwarding for both halves: the WG row (reply decap vehicle) plus
    // a GRE-mode clone (the builder's tunnel row) and the outer next-hop
    // neighbor the GRE builder needs for a ForwardCandidate outer.
    let mut snap = wg_outer_mtu_snapshot();
    snap.neighbors.push(crate::NeighborSnapshot {
        interface: "reth0.80".to_string(),
        ifindex: 12,
        family: "inet".to_string(),
        ip: "172.16.80.1".to_string(),
        mac: "00:11:22:33:44:55".to_string(),
        state: "reachable".to_string(),
        router: true,
        ..Default::default()
    });
    let mut forwarding = build_forwarding_state(&snap);
    let wg_id = *forwarding.wg_engines.keys().next().expect("wg tunnel");
    forwarding
        .wg_engines
        .insert(wg_id, std::sync::Arc::new(resp));
    let mut gre_row = forwarding
        .tunnel_endpoints
        .get(&wg_id)
        .expect("wg row")
        .clone();
    gre_row.id = GRE_TUN_ID;
    gre_row.mode = "gre".to_string();
    // A WG row hydrates with an UNSPECIFIED outer pair (multi-peer: no single
    // destination — `forwarding_build/tunnels.rs`); a genuine GRE row carries
    // concrete outers, so stamp them (this is also why the WG builder resolves
    // per selected peer endpoint instead of reading the row).
    gre_row.source = "172.16.80.8".parse().unwrap();
    gre_row.destination = "203.0.113.7".parse().unwrap();
    forwarding.tunnel_endpoints.insert(GRE_TUN_ID, gre_row);
    // The pair from the REAL GRE builder (not hand-built).
    let request = icmp_echo_inner_v4(8, FW, PEER, IDENT, 1);
    let reply = icmp_echo_inner_v4(0, PEER, FW, IDENT, 1);
    let neighbors = Arc::new(ShardedNeighborMap::new());
    // Real-time-active HA: the GRE builder stamps against the live clock
    // (`monotonic_nanos`), so the t=123 fixture lease (`txn_ha_state`) reads
    // expired and the build enforces HAInactive. Same shape as the GRE
    // builder cells (`active_ha_runtime`), inlined (that helper lives in
    // `frame::tests_support`, outside this module's reach).
    let now_secs = monotonic_nanos() / 1_000_000_000;
    let ha = BTreeMap::from([(
        1,
        HAGroupRuntime {
            active: true,
            watchdog_timestamp: now_secs,
            lease: HAGroupRuntime::active_lease_until(now_secs, now_secs),
        },
    )]);
    let ike = crate::afxdp::forwarding::IkeExchangeTable::new();
    let plan = crate::afxdp::tunnel::build_local_origin_tunnel_tx_request(
        &request,
        GRE_TUN_ID,
        &forwarding,
        &ha,
        &neighbors,
        &ike,
    )
    .expect("GRE builder must succeed");
    assert_eq!(
        plan.session_entry.key,
        inner_flow_key(&request, PROTO_ICMP).forward_key,
        "the GRE builder must key what the worker will HIT"
    );
    // The UpsertLocal install path (what the GRE loop enqueues per worker).
    let mut sessions = SessionTable::new();
    let now_ns = 122_000_000_000u64;
    assert!(
        sessions.upsert_synced_with_origin(
            plan.session_entry.clone().into_session_install(now_ns),
            true,
        ),
        "GRE forward must install via the UpsertLocal path"
    );
    let gre_reverse = plan.reverse_session_entry.clone().expect("GRE reverse");
    assert!(
        sessions.upsert_synced_with_origin(gre_reverse.into_session_install(now_ns), true),
        "GRE reverse must install via the UpsertLocal path"
    );
    // The reply arrives (WG decap vehicle — session keys are tunnel-agnostic)
    // with NO tunnel permit anywhere in the forwarding.
    let (batch, dbg) =
        drive_solicited_inner_10038(&forwarding, &mut sessions, &init, &rpub, &reply);
    assert!(dbg.session_hit >= 1, "the reply must HIT the reverse");
    assert_eq!(
        dbg.policy_revoked_sessions, 0,
        "the locally-present GRE TUN-origin forward must be declined, not revoked"
    );
    assert_eq!(
        batch.host_inbound_denied_packets, 0,
        "the solicited HIT must bypass host-inbound admission"
    );
    assert_eq!(
        session_row_count_10038(&sessions),
        2,
        "both rows must survive"
    );
    assert!(
        dbg.local >= 1 || batch.local_delivery_packets >= 1,
        "the GRE solicited reply must be delivered"
    );
}

/// Parent-review item 6 (GRE twin): the REAL GRE builder on a VRF stamps
/// domain 7 AND synthesizes a LocalDelivery reverse against the tunnel's
/// instance table (not NoRoute against inet.0); the pair installs via
/// UpsertLocal and the reply delivers with no tunnel permit. RED without
/// the table-scoped synthesis (NoRoute reverse → no LocalDelivery HIT).
#[test]
fn gre_tun_origin_vrf_reverse_resolves_local_10038() {
    const FW: [u8; 4] = [10, 123, 0, 1];
    const PEER: [u8; 4] = [10, 123, 0, 5];
    const IDENT: u16 = 0x3857;
    const GRE_TUN_ID: u16 = 2;
    let allowed: Vec<ipnet::IpNet> = vec!["10.123.0.0/24".parse().unwrap()];
    let (init, resp, _init_pub, rpub) = established_pair(allowed.clone(), allowed);
    let mut snap = wg_outer_mtu_snapshot();
    snap.interfaces
        .iter_mut()
        .find(|i| i.ifindex == TUNNEL_LOGICAL_IFINDEX)
        .expect("wg0.0 row")
        .routing_instance = "cust".to_string();
    snap.interfaces
        .iter_mut()
        .find(|i| i.ifindex == TUNNEL_LOGICAL_IFINDEX)
        .expect("wg0.0 row")
        .routing_domain = 7;
    snap.neighbors.push(crate::NeighborSnapshot {
        interface: "reth0.80".to_string(),
        ifindex: 12,
        family: "inet".to_string(),
        ip: "172.16.80.1".to_string(),
        mac: "00:11:22:33:44:55".to_string(),
        state: "reachable".to_string(),
        router: true,
        ..Default::default()
    });
    let mut forwarding = build_forwarding_state(&snap);
    let wg_id = *forwarding.wg_engines.keys().next().expect("wg tunnel");
    forwarding
        .wg_engines
        .insert(wg_id, std::sync::Arc::new(resp));
    let mut gre_row = forwarding
        .tunnel_endpoints
        .get(&wg_id)
        .expect("wg row")
        .clone();
    gre_row.id = GRE_TUN_ID;
    gre_row.mode = "gre".to_string();
    gre_row.source = "172.16.80.8".parse().unwrap();
    gre_row.destination = "203.0.113.7".parse().unwrap();
    forwarding.tunnel_endpoints.insert(GRE_TUN_ID, gre_row);
    let request = icmp_echo_inner_v4(8, FW, PEER, IDENT, 1);
    let reply = icmp_echo_inner_v4(0, PEER, FW, IDENT, 1);
    let neighbors = Arc::new(ShardedNeighborMap::new());
    let now_secs = monotonic_nanos() / 1_000_000_000;
    let ha = BTreeMap::from([(
        1,
        HAGroupRuntime {
            active: true,
            watchdog_timestamp: now_secs,
            lease: HAGroupRuntime::active_lease_until(now_secs, now_secs),
        },
    )]);
    let ike = crate::afxdp::forwarding::IkeExchangeTable::new();
    let plan = crate::afxdp::tunnel::build_local_origin_tunnel_tx_request(
        &request,
        GRE_TUN_ID,
        &forwarding,
        &ha,
        &neighbors,
        &ike,
    )
    .expect("GRE builder must succeed");
    assert_eq!(
        plan.session_entry.key.routing_domain, 7,
        "the GRE builder must stamp the VRF domain"
    );
    let gre_reverse = plan.reverse_session_entry.clone().expect("GRE reverse");
    assert_eq!(
        gre_reverse.decision.resolution.disposition,
        ForwardingDisposition::LocalDelivery,
        "the VRF reverse must resolve LocalDelivery against the instance table"
    );
    let mut sessions = SessionTable::new();
    let now_ns = 122_000_000_000u64;
    assert!(
        sessions.upsert_synced_with_origin(
            plan.session_entry.clone().into_session_install(now_ns),
            true,
        ),
        "GRE forward must install via the UpsertLocal path"
    );
    assert!(
        sessions.upsert_synced_with_origin(gre_reverse.into_session_install(now_ns), true),
        "GRE reverse must install via the UpsertLocal path"
    );
    let (batch, dbg) =
        drive_solicited_inner_10038(&forwarding, &mut sessions, &init, &rpub, &reply);
    assert!(dbg.session_hit >= 1, "the reply must HIT the reverse");
    assert_eq!(
        dbg.policy_revoked_sessions, 0,
        "the VRF GRE TUN-origin forward must be declined, not revoked"
    );
    assert_eq!(
        batch.host_inbound_denied_packets, 0,
        "the VRF solicited HIT must bypass host-inbound admission"
    );
    assert!(
        dbg.local >= 1 || batch.local_delivery_packets >= 1,
        "the VRF GRE solicited reply must be delivered"
    );
}

/// #10038 parent-review (GPT-1 + SPARK-B1): the exemption is Owner-only. A
/// foreign arrival spoofing a live TUN-origin reply 5-tuple HITS the reverse
/// (the session lookup is zoneless) but must NOT bypass host-inbound — no WG
/// decap ever authenticated it. Control leg (owner, via decap) delivers;
/// subject leg (same 5-tuple, plain, wan arrival) dies at host-inbound with
/// the pair intact. RED without the `foreign_arrival_zone.is_none()` conjunct
/// (the spoof delivers).
#[test]
fn wg_foreign_spoof_reply_gets_no_exemption_10038() {
    const FW: [u8; 4] = [10, 123, 0, 1];
    const PEER: [u8; 4] = [10, 123, 0, 5];
    const IDENT: u16 = 0x3857;
    let allowed: Vec<ipnet::IpNet> = vec!["10.123.0.0/24".parse().unwrap()];
    let (init, resp, _init_pub, rpub) = established_pair(allowed.clone(), allowed);
    let (forwarding, tun_id) = tun_origin_forwarding_opts(resp, true, false, false);
    let request = icmp_echo_inner_v4(8, FW, PEER, IDENT, 1);
    let reply = icmp_echo_inner_v4(0, PEER, FW, IDENT, 1);
    let fwd_key = inner_flow_key(&request, PROTO_ICMP).forward_key;
    let rev_key = inner_flow_key(&reply, PROTO_ICMP).forward_key;
    let mut sessions = SessionTable::new();
    install_solicited_pair_10038(
        &mut sessions,
        &fwd_key,
        &rev_key,
        tun_id,
        SessionOrigin::TunOrigin,
        0,
        0,
        SessionOrigin::TunOrigin,
        true,
    );
    // Control: the decapped (owner) reply is exempt and delivered.
    let (batch_o, dbg_o) =
        drive_solicited_inner_10038(&forwarding, &mut sessions, &init, &rpub, &reply);
    assert!(dbg_o.session_hit >= 1, "control must HIT the reverse");
    assert_eq!(
        batch_o.host_inbound_denied_packets, 0,
        "control: the owner reply must bypass host-inbound admission"
    );
    assert!(
        dbg_o.local >= 1 || batch_o.local_delivery_packets >= 1,
        "control: the owner reply must be delivered"
    );
    // Subject: the same 5-tuple, plain, arriving foreign (wan).
    let (batch_f, dbg_f) = drive_spoofed_plain_10038(&forwarding, &mut sessions, &reply);
    assert!(
        dbg_f.session_hit >= 1,
        "the spoof must HIT the reverse (zoneless lookup) — no HIT means this cell is vacuous"
    );
    assert_eq!(
        batch_f.host_inbound_denied_packets, 1,
        "a foreign arrival must face host-inbound admission, never the exemption"
    );
    assert_eq!(
        batch_f.local_delivery_packets, 0,
        "the unauthenticated spoof must not deliver"
    );
    assert_eq!(
        session_row_count_10038(&sessions),
        2,
        "the refusal drops the packet, not the session"
    );
}

/// Parent-review item 4 (through-Part-A tightening): a kernel echo RESPONSE
/// (firewall→peer type 0) run through the PRODUCTION parse+build+publish
/// must create NO exempting state — and a subsequent peer echo REQUEST on a
/// stateless worker (empty local table, production shared maps wired) must
/// MISS and face host-inbound admission, never ride a solicited exemption.
/// RED without the create gate (the response publishes a TUN-origin pair
/// whose reverse admits the request).
#[test]
fn wg_tun_origin_response_creates_no_exempting_state_10038() {
    const FW: [u8; 4] = [10, 123, 0, 1];
    const PEER: [u8; 4] = [10, 123, 0, 5];
    const IDENT: u16 = 0x3857;
    let allowed: Vec<ipnet::IpNet> = vec!["10.123.0.0/24".parse().unwrap()];
    let (init, resp, _init_pub, rpub) = established_pair(allowed.clone(), allowed);
    let (forwarding, tun_id) = tun_origin_forwarding(resp, true);
    // The kernel's answer to an admitted inbound request, read from the TUN.
    let response = icmp_echo_inner_v4(0, FW, PEER, IDENT, 1);
    let neighbors = Arc::new(ShardedNeighborMap::new());
    let ha = txn_ha_state();
    let parsed =
        parse_wg_tun_origin_flow(&response, &forwarding, tun_id).expect("response must parse");
    assert!(
        !wg_tun_origin_packet_initiates(&parsed),
        "an echo reply is response-shaped"
    );
    let peer_ep: std::net::SocketAddr = "203.0.113.7:51820".parse().unwrap();
    let entries =
        build_wg_tun_origin_entries(&parsed, peer_ep, tun_id, &forwarding, &ha, &neighbors, 123)
            .expect("build must succeed");
    let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
    let mut dedup = FastMap::<SessionKey, u64>::default();
    let mut tombstones = FastMap::<SessionKey, u64>::default();
    publish_wg_tun_origin_entries(
        &shared_sessions,
        &shared_nat_sessions,
        &shared_forward_wire_sessions,
        &shared_owner_rg_indexes,
        &mut dedup,
        &mut tombstones,
        &entries,
        false,
        122_000_000_000,
    );
    assert!(
        shared_sessions.lock().expect("shared map").is_empty(),
        "a response must not create shared TUN-origin state"
    );
    // The peer's next echo REQUEST on a stateless worker: MISS + deny.
    let request = icmp_echo_inner_v4(8, PEER, FW, IDENT, 1);
    let mut wire = vec![0u8; 2048];
    let enc = init
        .try_encap(&rpub, &request, &mut wire)
        .expect("encap request");
    let frame = outer_frame(&wire[..enc.len], WG_PORT);
    let meta = wiring_meta(frame.len());
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 12, 0);
    binding.interface = std::sync::Arc::<str>::from("ge-0-0-2.80");
    let mut sessions = SessionTable::new();
    let local_tunnel_deliveries = Arc::new(ArcSwap::from_pointee(BTreeMap::new()));
    let (batch, dbg) = txn_run_descriptor_inner(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha,
        &frame,
        meta,
        &local_tunnel_deliveries,
        &shared_sessions,
    );
    assert_eq!(
        batch.host_inbound_denied_packets, 1,
        "with no TUN-origin state, the inbound request must face host-inbound admission"
    );
    assert_eq!(
        batch.local_delivery_packets, 0,
        "the inbound request must not deliver as a solicited reply"
    );
    assert_eq!(
        dbg.session_hit, 0,
        "nothing to HIT — the response created nothing"
    );
}

/// Parent-review item 2 (post-idle lifecycle): a TUN-origin pair published
/// through production publish delivers its reply; after the publisher-owned
/// idle sweep (21s, fake clock) the pair is gone and a late reply on a
/// stateless worker MISSES and faces host-inbound admission. RED without
/// the sweep's delete (the late reply still HITS shared and delivers).
#[test]
fn wg_tun_origin_swept_pair_faces_gates_10038() {
    const FW: [u8; 4] = [10, 123, 0, 1];
    const PEER: [u8; 4] = [10, 123, 0, 5];
    const IDENT: u16 = 0x3857;
    const T0: u64 = 100_000_000_000;
    let allowed: Vec<ipnet::IpNet> = vec!["10.123.0.0/24".parse().unwrap()];
    let (init, resp, _init_pub, rpub) = established_pair(allowed.clone(), allowed);
    let (forwarding, tun_id) = tun_origin_forwarding(resp, true);
    let request = icmp_echo_inner_v4(8, FW, PEER, IDENT, 1);
    let reply = icmp_echo_inner_v4(0, PEER, FW, IDENT, 1);
    let neighbors = Arc::new(ShardedNeighborMap::new());
    let ha = txn_ha_state();
    let parsed =
        parse_wg_tun_origin_flow(&request, &forwarding, tun_id).expect("request must parse");
    let peer_ep: std::net::SocketAddr = "203.0.113.7:51820".parse().unwrap();
    let entries =
        build_wg_tun_origin_entries(&parsed, peer_ep, tun_id, &forwarding, &ha, &neighbors, 123)
            .expect("build must succeed");
    let fwd_key = entries.forward.key.clone();
    let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
    let mut dedup = FastMap::<SessionKey, u64>::default();
    let mut tombstones = FastMap::<SessionKey, u64>::default();
    let mut last_sweep = 0u64;
    publish_wg_tun_origin_entries(
        &shared_sessions,
        &shared_nat_sessions,
        &shared_forward_wire_sessions,
        &shared_owner_rg_indexes,
        &mut dedup,
        &mut tombstones,
        &entries,
        true,
        T0,
    );
    assert!(
        shared_sessions
            .lock()
            .expect("shared map")
            .contains_key(&fwd_key)
    );
    // Pre-sweep control: the reply HITS shared and delivers.
    let drive_reply = |sessions: &mut SessionTable| {
        let mut wire = vec![0u8; 2048];
        let enc = init
            .try_encap(&rpub, &reply, &mut wire)
            .expect("encap reply");
        let frame = outer_frame(&wire[..enc.len], WG_PORT);
        let meta = wiring_meta(frame.len());
        let mut binding = BindingWorker::new_for_mirror_test(0, 0, 12, 0);
        binding.interface = std::sync::Arc::<str>::from("ge-0-0-2.80");
        let local_tunnel_deliveries = Arc::new(ArcSwap::from_pointee(BTreeMap::new()));
        txn_run_descriptor_inner(
            &mut binding,
            sessions,
            &forwarding,
            &ha,
            &frame,
            meta,
            &local_tunnel_deliveries,
            &shared_sessions,
        )
    };
    let mut sessions = SessionTable::new();
    let (batch_pre, dbg_pre) = drive_reply(&mut sessions);
    assert!(dbg_pre.session_hit >= 1, "control must HIT the shared pair");
    assert!(
        dbg_pre.local >= 1 || batch_pre.local_delivery_packets >= 1,
        "control: the reply must deliver before the sweep"
    );
    // Idle 21s: the sweep deletes the pair (tombstone kept for resume).
    sweep_wg_tun_origin_idle(
        &shared_sessions,
        &shared_nat_sessions,
        &shared_forward_wire_sessions,
        &shared_owner_rg_indexes,
        &mut tombstones,
        &mut last_sweep,
        T0 + 21_000_000_000,
    );
    assert!(shared_sessions.lock().expect("shared map").is_empty());
    // Late reply on a stateless worker (fresh table — never materialized):
    // MISS + host-inbound deny, never a solicited delivery.
    let mut cold_sessions = SessionTable::new();
    let (batch_post, dbg_post) = drive_reply(&mut cold_sessions);
    assert_eq!(dbg_post.session_hit, 0, "the swept pair must not HIT");
    assert_eq!(
        batch_post.host_inbound_denied_packets, 1,
        "the late reply must face host-inbound admission"
    );
    assert_eq!(
        batch_post.local_delivery_packets, 0,
        "the late reply must not deliver"
    );
}

/// #10038 Part C forward arm: a tunnel-side forward-tuple packet
/// (peer-spoofed or reflected — same 5-tuple as the TUN-origin forward)
/// HITS the forward entry and must be DECLINED, not judged-and-revoked:
/// self-originated runs no zone policy, so there is no admitting pair to
/// re-derive. No-permit box (the V1 posture); the pair must survive
/// intact. RED with only the forward arm reverted (revoke + teardown).
#[test]
fn wg_tun_origin_forward_tuple_hit_declines_10038() {
    const FW: [u8; 4] = [10, 123, 0, 1];
    const PEER: [u8; 4] = [10, 123, 0, 5];
    const IDENT: u16 = 0x3857;
    let allowed: Vec<ipnet::IpNet> = vec!["10.123.0.0/24".parse().unwrap()];
    let (init, resp, _init_pub, rpub) = established_pair(allowed.clone(), allowed);
    let (forwarding, tun_id) = tun_origin_forwarding(resp, false);
    let request = icmp_echo_inner_v4(8, FW, PEER, IDENT, 1);
    let reply = icmp_echo_inner_v4(0, PEER, FW, IDENT, 1);
    let fwd_key = inner_flow_key(&request, PROTO_ICMP).forward_key;
    let rev_key = inner_flow_key(&reply, PROTO_ICMP).forward_key;
    let mut sessions = SessionTable::new();
    install_solicited_pair_10038(
        &mut sessions,
        &fwd_key,
        &rev_key,
        tun_id,
        SessionOrigin::TunOrigin,
        0,
        0,
        SessionOrigin::TunOrigin,
        true,
    );
    // The forward tuple itself, arriving tunnel-side (decap): HITS forward.
    let (batch, dbg) =
        drive_solicited_inner_10038(&forwarding, &mut sessions, &init, &rpub, &request);
    assert!(
        dbg.session_hit >= 1,
        "the forward tuple must HIT the forward entry"
    );
    assert_eq!(
        dbg.policy_revoked_sessions, 0,
        "a TUN-origin forward HIT must decline revalidation, not revoke"
    );
    assert_eq!(
        session_row_count_10038(&sessions),
        2,
        "the decline must leave the pair intact (no teardown, no poison)"
    );
    let _ = batch;
}

/// Parent-review item 5 (preservation): the shared-only twin of the
/// forward-arm cell. The pair comes from the PRODUCTION build+publish;
/// the tunnel-side forward tuple HITS shared, materializes locally, and
/// the materialized forward must KEEP `TunOrigin` (else the decline
/// below stops matching and the HIT revokes). Pins
/// `materialized_shared_hit_origin` preservation behaviorally.
#[test]
fn wg_tun_origin_shared_forward_hit_keeps_provenance_10038() {
    const FW: [u8; 4] = [10, 123, 0, 1];
    const PEER: [u8; 4] = [10, 123, 0, 5];
    const IDENT: u16 = 0x3857;
    let allowed: Vec<ipnet::IpNet> = vec!["10.123.0.0/24".parse().unwrap()];
    let (init, resp, _init_pub, rpub) = established_pair(allowed.clone(), allowed);
    let (forwarding, tun_id) = tun_origin_forwarding(resp, false);
    let request = icmp_echo_inner_v4(8, FW, PEER, IDENT, 1);
    let fwd_key = inner_flow_key(&request, PROTO_ICMP).forward_key;
    let neighbors = Arc::new(ShardedNeighborMap::new());
    let ha = txn_ha_state();
    let parsed =
        parse_wg_tun_origin_flow(&request, &forwarding, tun_id).expect("request must parse");
    let peer_ep: std::net::SocketAddr = "203.0.113.7:51820".parse().unwrap();
    let entries =
        build_wg_tun_origin_entries(&parsed, peer_ep, tun_id, &forwarding, &ha, &neighbors, 123)
            .expect("build must succeed");
    let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
    let mut dedup = FastMap::<SessionKey, u64>::default();
    let mut tombstones = FastMap::<SessionKey, u64>::default();
    publish_wg_tun_origin_entries(
        &shared_sessions,
        &shared_nat_sessions,
        &shared_forward_wire_sessions,
        &shared_owner_rg_indexes,
        &mut dedup,
        &mut tombstones,
        &entries,
        true,
        122_000_000_000,
    );
    // The forward tuple through the worker with an EMPTY local table.
    let mut wire = vec![0u8; 2048];
    let enc = init
        .try_encap(&rpub, &request, &mut wire)
        .expect("encap forward tuple");
    let frame = outer_frame(&wire[..enc.len], WG_PORT);
    let meta = wiring_meta(frame.len());
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 12, 0);
    binding.interface = std::sync::Arc::<str>::from("ge-0-0-2.80");
    let mut sessions = SessionTable::new();
    let local_tunnel_deliveries = Arc::new(ArcSwap::from_pointee(BTreeMap::new()));
    let (batch, dbg) = txn_run_descriptor_inner(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha,
        &frame,
        meta,
        &local_tunnel_deliveries,
        &shared_sessions,
    );
    assert!(dbg.session_hit >= 1, "the forward tuple must HIT shared");
    assert_eq!(
        dbg.policy_revoked_sessions, 0,
        "the materialized forward HIT must decline, not revoke"
    );
    let (_, _, fwd_origin) = sessions
        .entry_with_origin(&fwd_key)
        .expect("the forward must materialize locally");
    assert_eq!(
        fwd_origin,
        SessionOrigin::TunOrigin,
        "materialization must preserve TUN provenance"
    );
    let _ = batch;
}

/// Parent-review item 6 (SPARK-A2): the fix works end-to-end on a VRF, not
/// just domain 0. The tunnel egress interface sits in routing domain 7;
/// the builder stamps 7 (unit-pinned), the worker stamps 7 at stage 9b,
/// and the reply HITS the shared domain-7 pair and delivers. Any stamp
/// divergence (either side 0) key-mismatches into a MISS and reds — the
/// domain asserts below are what make that non-vacuous. (Mismatch
/// fails closed by key construction; this cell pins the positive path.)
#[test]
fn wg_tun_origin_domain_vrf_hit_delivers_10038() {
    const FW: [u8; 4] = [10, 123, 0, 1];
    const PEER: [u8; 4] = [10, 123, 0, 5];
    const IDENT: u16 = 0x3857;
    let allowed: Vec<ipnet::IpNet> = vec!["10.123.0.0/24".parse().unwrap()];
    let (init, resp, _init_pub, rpub) = established_pair(allowed.clone(), allowed);
    // Domain-bearing forwarding: wg0.0 in routing instance cust/domain 7.
    let mut snap = wg_outer_mtu_snapshot();
    snap.interfaces
        .iter_mut()
        .find(|i| i.ifindex == TUNNEL_LOGICAL_IFINDEX)
        .expect("wg0.0 row")
        .routing_instance = "cust".to_string();
    snap.interfaces
        .iter_mut()
        .find(|i| i.ifindex == TUNNEL_LOGICAL_IFINDEX)
        .expect("wg0.0 row")
        .routing_domain = 7;
    let mut forwarding = build_forwarding_state(&snap);
    let tun_id = *forwarding.wg_engines.keys().next().expect("wg tunnel");
    forwarding
        .wg_engines
        .insert(tun_id, std::sync::Arc::new(resp));
    let request = icmp_echo_inner_v4(8, FW, PEER, IDENT, 1);
    let reply = icmp_echo_inner_v4(0, PEER, FW, IDENT, 1);
    // Production parse + build + publish (the loop's path, minus the loop).
    let neighbors = Arc::new(ShardedNeighborMap::new());
    let ha = txn_ha_state();
    let parsed =
        parse_wg_tun_origin_flow(&request, &forwarding, tun_id).expect("request must parse");
    assert_eq!(
        parsed.flow.forward_key.routing_domain, 7,
        "the builder must stamp the tunnel egress interface's domain"
    );
    let peer_ep: std::net::SocketAddr = "203.0.113.7:51820".parse().unwrap();
    let entries =
        build_wg_tun_origin_entries(&parsed, peer_ep, tun_id, &forwarding, &ha, &neighbors, 123)
            .expect("build must succeed");
    let fwd_key = entries.forward.key.clone();
    let rev_key = crate::session::reverse_session_key(&fwd_key, entries.forward.decision.nat);
    assert_eq!(rev_key.routing_domain, 7, "the pair must live in domain 7");
    let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
    let mut dedup = FastMap::<SessionKey, u64>::default();
    let mut tombstones = FastMap::<SessionKey, u64>::default();
    publish_wg_tun_origin_entries(
        &shared_sessions,
        &shared_nat_sessions,
        &shared_forward_wire_sessions,
        &shared_owner_rg_indexes,
        &mut dedup,
        &mut tombstones,
        &entries,
        true,
        122_000_000_000,
    );
    // The reply through the worker with an EMPTY local table.
    let mut wire = vec![0u8; 2048];
    let enc = init
        .try_encap(&rpub, &reply, &mut wire)
        .expect("encap reply");
    let frame = outer_frame(&wire[..enc.len], WG_PORT);
    let meta = wiring_meta(frame.len());
    assert!(
        crate::afxdp::forwarding::ingress_destination_mac_accepted(
            &forwarding,
            meta.ingress_ifindex as i32,
            meta.ingress_vlan_id,
            &frame,
        ),
        "fixture MAC must match the WAN underlay before VRF WG decap"
    );
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 12, 0);
    binding.interface = std::sync::Arc::<str>::from("ge-0-0-2.80");
    let mut sessions = SessionTable::new();
    let local_tunnel_deliveries = Arc::new(ArcSwap::from_pointee(BTreeMap::new()));
    let (batch, dbg) = txn_run_descriptor_inner(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha,
        &frame,
        meta,
        &local_tunnel_deliveries,
        &shared_sessions,
    );
    assert!(
        dbg.session_hit >= 1,
        "the reply must HIT the shared domain-7 reverse (a stamp divergence MISSes here)"
    );
    assert_eq!(
        batch.host_inbound_denied_packets, 0,
        "the VRF solicited HIT must bypass host-inbound admission"
    );
    assert!(
        dbg.local >= 1 || batch.local_delivery_packets >= 1,
        "the VRF solicited reply must be delivered host-bound"
    );
    let mut local_keys = Vec::new();
    sessions.iter_with_origin(|key, _, _, _| local_keys.push(key.clone()));
    assert!(
        local_keys.contains(&rev_key),
        "the domain-7 reverse must materialize locally"
    );
}
