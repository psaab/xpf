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
use super::super::*;
use super::super::tests_support::{txn_ha_state, txn_run_descriptor};
use super::tests::established_pair;
use super::{WgEngine, WgWorkerScratch};

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
    let (_b, _dbg) = txn_run_descriptor(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame,
        meta,
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
    let (_batch, dbg) = txn_run_descriptor(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame,
        meta,
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
    let (_batch, dbg) = txn_run_descriptor(
        &mut binding,
        &mut sessions,
        forwarding,
        &ha_state,
        &frame,
        meta,
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

/// #9521 closes the CONTROL THREAD's kernel-path delivery for unsteered ports
/// and must not reach this stage. The worker matches every configured listen
/// port (`wg_endpoint_for_listen_port`), and which records reach it is decided
/// by the shim, not by the steered scalar alone: a listener on an
/// interface-mode source-NAT address is not `is_local_destination`, so its
/// records are redirected to the worker whatever their port. Gating this stage
/// on the steered port would black-hole those tunnels and close nothing, so a
/// snapshot that steers some OTHER port must leave worker decap untouched.
#[test]
fn worker_decap_is_not_gated_by_the_steered_port_9521() {
    let allowed: Vec<ipnet::IpNet> = vec!["10.123.0.0/24".parse().unwrap()];
    let (init, resp, _init_pub, resp_pub) = established_pair(allowed.clone(), allowed);
    let (mut forwarding, _id) = forwarding_with_engine(resp);
    forwarding.wg_steered_listen_port = WG_PORT.wrapping_add(1);

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
