//! #9517: bind the WIRING of the routing-domain demotion, not only the
//! predicate it calls.
//!
//! `uses_kernel_local_session_map_entry` is pinned by
//! `routing_domains_demote_kernel_local_to_redirect_9517` in `bpf_map_tests.rs`.
//! That cell cannot see a caller that hands the predicate the wrong flag: the
//! first mutation run severed `forwarding.has_routing_domains` at the worker
//! publish site and every test still passed, because the only effect is a BPF
//! map write and an unprivileged `cargo test` cannot create a map.
//!
//! These cells drive the REAL worker publish path against a map fd that is
//! valid-looking but never a map, and read what it ATTEMPTED to write through
//! the `SESSION_MAP_WRITES` seam in `bpf_map`. The syscalls fail, which is the
//! point: the recorder sees the write before the kernel refuses it.
//!
//! Scope: `publish_worker_session_map_entry` is the ONLY live consumer of the
//! flag. Every other threaded site reaches `publish_session_map_entry_for_session`,
//! which hardcodes `SessionOrigin::ForwardFlow`, so the peer-synced clause of the
//! predicate is false there and the flag cannot change what they publish today.

use super::*;
use crate::afxdp::bpf_map::{SessionMapWriteRecord, clear_session_map_writes, session_map_writes};
use crate::test_zone_ids::*;
use std::net::Ipv4Addr;

/// Not negative, so `publish_worker_session_map_entry` does not take its
/// `session_map_fd < 0` early return; never an open BPF map, so every syscall
/// fails harmlessly after the recorder has seen it.
const NOT_A_MAP_FD: c_int = i32::MAX;

fn host_bound_key() -> SessionKey {
    SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 1)),
        src_port: 40000,
        dst_port: 22,
        discriminator: Default::default(),
        routing_domain: 0,
    }
}

fn local_delivery() -> SessionDecision {
    SessionDecision {
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::LocalDelivery,
            local_ifindex: 0,
            egress_ifindex: 0,
            tx_ifindex: 0,
            tunnel_endpoint_id: 0,
            next_hop: None,
            neighbor_mac: None,
            src_mac: None,
            tx_vlan_id: 0,
        },
        nat: NatDecision::default(),
    }
}

fn synced_forward_metadata() -> SessionMetadata {
    SessionMetadata {
        ingress_zone: TEST_TRUST_ZONE_ID,
        egress_zone: TEST_TRUST_ZONE_ID,
        ingress_ifindex: 0,
        ingress_vlan_id: 0,
        owner_rg_id: 1,
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

/// What the worker publish path attempts for one peer-synced, host-bound,
/// non-tunnel forward session — the exact shape the kernel-local predicate
/// selects — on a node whose forwarding state says `has_routing_domains`.
fn worker_publish_writes(has_routing_domains: bool, allow_replace_local: bool) -> Vec<SessionMapWriteRecord> {
    worker_publish_writes_for(host_bound_key(), has_routing_domains, allow_replace_local)
}

fn worker_publish_writes_for(
    key: SessionKey,
    has_routing_domains: bool,
    allow_replace_local: bool,
) -> Vec<SessionMapWriteRecord> {
    let forwarding = ForwardingState {
        has_routing_domains,
        ..ForwardingState::default()
    };
    clear_session_map_writes();
    publish_worker_session_map_entry(
        NOT_A_MAP_FD,
        &forwarding,
        &key,
        local_delivery(),
        &synced_forward_metadata(),
        SessionOrigin::SyncImport,
        allow_replace_local,
    );
    session_map_writes()
}

fn pass_to_kernel_writes(writes: &[SessionMapWriteRecord]) -> usize {
    writes
        .iter()
        .filter(|w| w.value == Some(USERSPACE_SESSION_ACTION_PASS_TO_KERNEL))
        .count()
}

fn deletes(writes: &[SessionMapWriteRecord]) -> usize {
    writes.iter().filter(|w| w.value.is_none()).count()
}

#[test]
fn the_worker_publish_reads_this_nodes_routing_domain_flag_9517() {
    let single_instance = worker_publish_writes(false, false);
    assert_eq!(
        pass_to_kernel_writes(&single_instance),
        1,
        "control: on a node WITHOUT routing domains this session must be \
         published PASS_TO_KERNEL, or the fixture never reaches the kernel-local \
         branch and every assertion below is vacuous. Writes: {single_instance:?}"
    );

    let multi_instance = worker_publish_writes(true, false);
    assert_eq!(
        pass_to_kernel_writes(&multi_instance),
        0,
        "with routing domains the 40-byte steering key cannot tell two domains \
         apart, so a PASS_TO_KERNEL row here would overwrite another domain's \
         REDIRECT row and hand its packets to the kernel past zone policy. The \
         worker publish must read THIS node's `has_routing_domains` and demote \
         to REDIRECT (#9517). Writes: {multi_instance:?}"
    );
    assert!(
        multi_instance.iter().any(|w| w.key == host_bound_key()
            && w.value == Some(USERSPACE_SESSION_ACTION_REDIRECT)),
        "the demoted session must still be PUBLISHED, as REDIRECT — demotion \
         routes it through the helper, it must not drop the steering row. \
         Writes: {multi_instance:?}"
    );
    assert_eq!(
        deletes(&multi_instance),
        0,
        "the kernel-local verdict also decides whether a stale live row is \
         DELETED before the publish. A demoted session has no kernel-local row \
         to replace, so a delete here means that verdict was computed without \
         the routing-domain flag — a window with NO steering row for the tuple \
         on every republish (#9517). Writes: {multi_instance:?}"
    );
}

/// The forced-live-redirect branch (`allow_replace_local`) must reach the same
/// answer. With routing domains both branches publish REDIRECT, so this cell
/// pins the OUTCOME, not which branch produced it.
#[test]
fn a_replace_local_publish_is_demoted_the_same_way_9517() {
    let multi_instance = worker_publish_writes(true, true);
    assert_eq!(
        pass_to_kernel_writes(&multi_instance),
        0,
        "a replace-local publish on a routing-domain node must not write \
         PASS_TO_KERNEL either (#9517). Writes: {multi_instance:?}"
    );
    assert_eq!(
        deletes(&multi_instance),
        0,
        "and must not delete the live row first (#9517). Writes: {multi_instance:?}"
    );
}

/// The GRE arm needs no routing domains: on a SINGLE-instance node the worker
/// publish must still demote a session whose key carries a tunnel discriminator,
/// because the steering row it would write is shared with every other tunnel
/// between the same endpoints. Driven through the real publish path so the KEY
/// the path hands the predicate is bound, not only the predicate.
#[test]
fn a_keyed_gre_session_is_demoted_on_a_single_instance_node_9517() {
    let plain = worker_publish_writes_for(host_bound_key(), false, false);
    assert_eq!(
        pass_to_kernel_writes(&plain),
        1,
        "control: the same session with no discriminator is published PASS_TO_KERNEL \
         on a single-instance node, or the demotion below is vacuous. Writes: {plain:?}"
    );
    let keyed = SessionKey {
        protocol: 47,
        src_port: 0,
        dst_port: 0,
        discriminator: crate::session::TunnelDiscriminator::Keyed(7),
        ..host_bound_key()
    };
    let writes = worker_publish_writes_for(keyed.clone(), false, false);
    assert_eq!(
        pass_to_kernel_writes(&writes),
        0,
        "two keyed GRE tunnels between one endpoint pair share one 40-byte steering \
         row on ANY node, so this session must be published REDIRECT (#9517). \
         Writes: {writes:?}"
    );
    assert!(
        writes.iter().any(|w| w.key == keyed && w.value == Some(USERSPACE_SESSION_ACTION_REDIRECT)),
        "and still PUBLISHED, as REDIRECT. Writes: {writes:?}"
    );
    assert_eq!(deletes(&writes), 0, "with no stale kernel-local row deleted first. Writes: {writes:?}");
}
