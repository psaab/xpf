//! #7160 (#2387) — the routing-domain stamp, exercised on the REAL poll path.
//!
//! Everything else about the routing domain is bound at a layer below this:
//! `forwarding::ingress_routing_domain` resolves it, the key transforms carry
//! or drop it, `find_forward_nat_match` prefers on it. None of that reaches the
//! WIRING — the one assignment in `poll_binding_process_descriptor` that puts
//! the resolved domain onto the flow. That assignment is the whole populate
//! step, and a mutation that neutralises it (`= 0 * ingress_routing_domain(..)`)
//! left every other cell in this change GREEN, including the doc guard, whose
//! textual assertions the mutation satisfied verbatim.
//!
//! So these drive a frame through `poll_binding_process_descriptor` with two
//! sessions installed that differ ONLY in `routing_domain`, and assert which
//! one the packet was adjudicated against. That is #7160's defect stated as a
//! packet: with the stamp working, tenant B's flow finds tenant B's session;
//! without it, tenant B's flow inherits tenant A's cached egress, NAT and
//! policy decision.

use super::test_fixtures::*;
use super::tests_support::*;
use super::*;
use crate::session::{SessionKey, SessionMetadata, SessionTable};
use crate::test_zone_ids::*;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

/// The LAN interface (`reth1.0`, ifindex 24) is a member of a routing
/// instance; the domain is whatever Go computed for that instance's name.
const TENANT_DOMAIN: u32 = 100_001;

const CLIENT: Ipv4Addr = Ipv4Addr::new(10, 0, 61, 102);
const SERVER: Ipv4Addr = Ipv4Addr::new(1, 1, 1, 1);
const CLIENT_PORT: u16 = 12345;
const SERVER_PORT: u16 = 80;
/// The SNAT source each session translates to. Different per session, so the
/// answer to "which session adjudicated this packet" is readable off the
/// session's own decision rather than inferred.
const TENANT_SNAT: Ipv4Addr = Ipv4Addr::new(172, 16, 80, 41);
const DEFAULT_SNAT: Ipv4Addr = Ipv4Addr::new(172, 16, 80, 42);

fn session_key(routing_domain: u32) -> SessionKey {
    SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        src_ip: IpAddr::V4(CLIENT),
        dst_ip: IpAddr::V4(SERVER),
        src_port: CLIENT_PORT,
        dst_port: SERVER_PORT,
        discriminator: Default::default(),
        routing_domain,
    }
}

fn decision_snatting_to(snat: Ipv4Addr, install_table_domain: u32) -> SessionDecision {
    let install_table_check = if install_table_domain == 0 { 0 } else { 1 };
    SessionDecision { resolution: ForwardingResolution {
        disposition: ForwardingDisposition::ForwardCandidate,
        local_ifindex: 0,
        egress_ifindex: 12,
        tx_ifindex: 12,
        tunnel_endpoint_id: 0,
        next_hop: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 1))),
        neighbor_mac: Some([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
        src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x80, 0x08]),
        tx_vlan_id: 80,
    }, nat: NatDecision {
        rewrite_src: Some(IpAddr::V4(snat)),
        rewrite_dst: None,
        rewrite_src_port: Some(40000),
        rewrite_dst_port: None,
        nat64: false,
        nptv6: false,
    }, install_table_domain, install_table_check }
}

fn forward_metadata() -> SessionMetadata {
    SessionMetadata {
        ingress_zone: TEST_LAN_ZONE_ID,
        egress_zone: TEST_WAN_ZONE_ID,
        ingress_ifindex: 24,
        ingress_vlan_id: 0,
        owner_rg_id: 0,
        fabric_ingress: false,
        is_reverse: false,
        nat64_reverse: None,
        log_session_init: false,
        log_session_close: false,
        policy_id: 0,
        inactivity_timeout_ns: None,
        policy_counter_idx: 0,
        policy_counter: None,
    }
}

/// Drive ONE established-flow TCP segment in on the LAN unit and return the
/// forward the poll path queued for it, if any.
///
/// `install` seeds the session table before the packet is processed, so the
/// packet takes the established-session fast path — the arm #7160 is about,
/// and the arm that short-circuits before `ingress_route_table_override`.
fn drive_lan_segment(
    lan_routing_domain: u32,
    install: impl FnOnce(&mut SessionTable),
) -> Option<(Option<SessionKey>, SessionDecision)> {
    let mut snapshot = nat_snapshot();
    // reth1.0 (the LAN unit, ifindex 24) is a routing-instance member. Go ships
    // the number; the Rust side only folds it into the key.
    for iface in snapshot.interfaces.iter_mut() {
        if iface.ifindex == 24 {
            iface.routing_domain = lan_routing_domain;
        }
    }
    let mut forwarding = build_forwarding_state(&snapshot);
    // The hand-built session below carries an explicit native-RI install
    // identity. Seed the corresponding registry row so route-hit
    // revalidation can distinguish this fixture's table from MAIN.
    forwarding.install_tables.insert(
        TENANT_DOMAIN,
        crate::afxdp::types::InstallTables {
            v4: Some("tenant.inet.0".to_string()),
            v6: None,
            h2: 1,
        },
    );
    let ha_state = txn_ha_state();

    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
    binding.interface = Arc::<str>::from("reth1.0");

    let mut sessions = SessionTable::new();
    install(&mut sessions);

    // An established segment (ACK, no SYN): on a session MISS the #4400/#4539
    // guard declines to seed a session for a non-SYN first packet, so "which
    // session was found" is the only thing that can produce a forward here.
    let frame = build_txn_tcp_syn_frame_v4(CLIENT, SERVER, CLIENT_PORT, SERVER_PORT, 0x10, crate::afxdp::tests_support::TEST_LAN_MAC);
    let meta = txn_meta_v4(24, 0x10, frame.len() as u16);
    let _ = txn_run_descriptor_checked(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame,
        meta,
        true,
    );

    binding
        .scratch
        .scratch_forwards
        .first()
        .map(|fwd| (fwd.flow_key.clone(), fwd.decision))
}

/// #7160's defect, as a packet on the real poll path.
///
/// Two sessions with the SAME 5-tuple, differing only in `routing_domain` —
/// one in the tenant's routing instance, one in the default instance. The
/// segment arrives on an interface that is a MEMBER of the tenant's instance,
/// so it must be adjudicated against the tenant's session and translate to the
/// tenant's SNAT address.
///
/// FAIL-ON-REVERT: neutralise the stage-9b stamp in
/// `poll_binding_process_descriptor` (delete it, or make it resolve 0) and this
/// packet matches the DEFAULT-instance session instead — the cross-tenant
/// policy/NAT/egress inheritance #7160 exists to close.
#[test]
fn a_segment_on_a_routing_instance_member_matches_that_instances_session_7160() {
    let out = drive_lan_segment(TENANT_DOMAIN, |sessions| {
        // Install the DEFAULT-instance session FIRST so bucket / table order
        // cannot be what makes the right answer come out.
        assert!(sessions.install_with_protocol(
            session_key(0),
            decision_snatting_to(DEFAULT_SNAT, 0),
            forward_metadata(),
            100_000_000_000,
            PROTO_TCP,
            0x18,
        ));
        assert!(sessions.install_with_protocol(
            session_key(TENANT_DOMAIN),
            decision_snatting_to(TENANT_SNAT, TENANT_DOMAIN),
            forward_metadata(),
            100_000_000_000,
            PROTO_TCP,
            0x18,
        ));
    })
    .expect("the segment must be forwarded — it matched an established session");

    let (flow_key, decision) = out;
    let nat = decision.nat;
    let key = flow_key.expect("a session-backed forward must carry its flow key");
    assert_eq!(
        key.routing_domain, TENANT_DOMAIN,
        "the poll path adjudicated this segment in routing domain {:#x}, but it \
         arrived on an interface that is a member of routing domain {:#x}. The \
         stage-9b stamp is not reaching the key, so the established-session \
         fast path is free to hand this tenant another tenant's session.",
        key.routing_domain, TENANT_DOMAIN
    );
    assert_eq!(
        nat.rewrite_src,
        Some(IpAddr::V4(TENANT_SNAT)),
        "the segment was translated with the DEFAULT instance's NAT decision. \
         This is #7160 verbatim: a flow inheriting a colliding flow's cached \
         NAT (and, in production, its egress and policy verdict) because the \
         conntrack identity could not tell the two routing instances apart"
    );
}

/// The other half of the same fixture: a deployment with NO routing-instance
/// interface membership must be bit-identical to pre-#7160. The domain-0
/// session is the only one installed and the segment matches it, with the
/// domain never leaving 0 anywhere on the path.
#[test]
fn a_segment_with_no_routing_instance_membership_is_unchanged_7160() {
    let out = drive_lan_segment(0, |sessions| {
        assert!(sessions.install_with_protocol(
            session_key(0),
            decision_snatting_to(DEFAULT_SNAT, 0),
            forward_metadata(),
            100_000_000_000,
            PROTO_TCP,
            0x18,
        ));
    })
    .expect("the segment must be forwarded on the default-instance path");

    let (flow_key, decision) = out;
    let nat = decision.nat;
    let key = flow_key.expect("a session-backed forward must carry its flow key");
    assert_eq!(
        key.routing_domain, 0,
        "an interface in no routing instance stamped a non-zero domain; every \
         pre-#7160 deployment must keep byte-identical session identity"
    );
    assert_eq!(nat.rewrite_src, Some(IpAddr::V4(DEFAULT_SNAT)));
}
