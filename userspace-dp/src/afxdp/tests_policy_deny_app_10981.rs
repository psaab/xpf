//! #10981: secondary policy-deny emitters must identify the application from
//! the service port the gate evaluated, while retaining the packet's wire tuple.

use super::test_fixtures::{nat_snapshot, policy_deny_snapshot};
use super::tests_support::*;
use super::*;
use crate::tcp_flags::TCP_SYN as TCP_FLAG_SYN;
use crate::{
    AppCatalogEntry, DestinationNATRuleSnapshot, PolicyApplicationSnapshot, PolicyRuleSnapshot,
};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::mpsc::Receiver;

const WAN_IFINDEX: i32 = 12;
const LAN_IFINDEX: i32 = 24;
const CLIENT: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 10);
const VIP: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 9);
const CLIENT_PORT: u16 = 54321;

fn catalog_entry(app_id: u16, port: u16) -> AppCatalogEntry {
    AppCatalogEntry {
        app_id,
        protocol: crate::ip_proto::PROTO_TCP,
        dst_port_low: port,
        dst_port_high: port,
        ..Default::default()
    }
}

fn dnat_to_self_snapshot() -> crate::ConfigSnapshot {
    let mut snapshot = nat_snapshot();
    snapshot.destination_nat_rules = vec![DestinationNATRuleSnapshot {
        name: "vip-to-self".to_string(),
        from_zone: "wan".to_string(),
        destination_address: VIP.to_string(),
        destination_port: 2222,
        protocol: "tcp".to_string(),
        pool_address: "10.0.61.1".to_string(),
        pool_port: 22,
        ..Default::default()
    }];
    // Deliberately distinguish the public wire port from the evaluated
    // post-DNAT service so resolving from the wrong tuple is observable.
    snapshot.app_catalog = vec![catalog_entry(17, 22), catalog_entry(18, 2222)];
    snapshot
}

fn junos_host_ssh_deny() -> PolicyRuleSnapshot {
    PolicyRuleSnapshot {
        name: "deny-ssh-to-host".to_string(),
        from_zone: "wan".to_string(),
        to_zone: "junos-host".to_string(),
        source_addresses: vec!["any".to_string()],
        destination_addresses: vec!["any".to_string()],
        applications: vec!["junos-ssh".to_string()],
        application_terms: vec![PolicyApplicationSnapshot {
            name: "junos-ssh".to_string(),
            protocol: "tcp".to_string(),
            source_port: String::new(),
            destination_port: "22".to_string(),
            icmp_type: None,
            icmp_code: None,
            inactivity_timeout: None,
        }],
        action: "deny".to_string(),
        ..Default::default()
    }
}

fn tcp_syn(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    dst_port: u16,
    ingress_ifindex: u32,
    dst_mac: [u8; 6],
) -> (Vec<u8>, UserspaceDpMeta) {
    let frame = build_txn_tcp_syn_frame_v4(src, dst, CLIENT_PORT, dst_port, TCP_FLAG_SYN, dst_mac);
    let meta = txn_meta_v4(ingress_ifindex, TCP_FLAG_SYN, frame.len() as u16);
    (frame, meta)
}

fn drive_capturing_events(
    forwarding: &ForwardingState,
    sessions: &mut SessionTable,
    frame: &[u8],
    meta: UserspaceDpMeta,
    ingress_ifindex: i32,
    interface: &'static str,
) -> (
    DebugPollCounters,
    crate::event_stream::EventStreamWorkerHandle,
    Receiver<crate::event_stream::codec::EventFrame>,
) {
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, ingress_ifindex, 0);
    binding.interface = Arc::<str>::from(interface);
    let (_batch, dbg, event_handle, event_rx) = txn_run_descriptor_capturing_events(
        &mut binding,
        sessions,
        forwarding,
        &txn_ha_state(),
        frame,
        meta,
    );
    (dbg, event_handle, event_rx)
}

fn next_deny_event(
    rx: &Receiver<crate::event_stream::codec::EventFrame>,
) -> crate::event_stream::codec::DataplaneEventPayload {
    rx.try_recv()
        .expect("deny path emits a dataplane event")
        .decode_dataplane_event()
        .expect("deny event payload")
}

#[test]
fn dnat_junos_host_deny_logs_the_evaluated_ssh_service_10981() {
    let mut snapshot = dnat_to_self_snapshot();
    snapshot.policies.push(junos_host_ssh_deny());
    let forwarding = build_forwarding_state(&snapshot);
    let mut sessions = SessionTable::new();
    let (frame, meta) = tcp_syn(CLIENT, VIP, 2222, WAN_IFINDEX as u32, TEST_WAN_MAC);
    let (dbg, _event_handle, event_rx) = drive_capturing_events(
        &forwarding,
        &mut sessions,
        &frame,
        meta,
        WAN_IFINDEX,
        "reth0.80",
    );

    assert_eq!(
        dbg.policy_deny, 1,
        "the post-DNAT junos-host ssh deny must match"
    );
    assert_eq!(
        dbg.session_create, 0,
        "a denied host-bound SYN installs no session"
    );
    let event = next_deny_event(&event_rx);
    assert_eq!(
        event.kind,
        crate::event_stream::codec::DataplaneEventKind::PolicyDeny
    );
    assert_eq!(event.reason, 5);
    assert_eq!(
        event.application_id, 17,
        "resolve junos-ssh from the evaluated tcp/22 service, not wire tcp/2222"
    );
    assert_eq!(event.src_ip, IpAddr::V4(CLIENT));
    assert_eq!(event.dst_ip, IpAddr::V4(VIP));
    assert_eq!(event.src_port, CLIENT_PORT);
    assert_eq!(
        event.dst_port, 2222,
        "RT_FLOW keeps the original wire tuple"
    );
    assert_eq!(
        event.nat_dst_ip, None,
        "junos-host deny retains its existing no-NAT event shape"
    );
    assert_eq!(event.nat_dst_port, 0);
}

#[test]
fn dnat_host_inbound_deny_logs_the_evaluated_service_10981() {
    let mut snapshot = dnat_to_self_snapshot();
    snapshot
        .zones
        .iter_mut()
        .find(|zone| zone.name == "wan")
        .expect("fixture has wan zone")
        .host_inbound_system_services
        .clear();
    let forwarding = build_forwarding_state(&snapshot);
    let mut sessions = SessionTable::new();
    let (frame, meta) = tcp_syn(CLIENT, VIP, 2222, WAN_IFINDEX as u32, TEST_WAN_MAC);
    let (dbg, _event_handle, event_rx) = drive_capturing_events(
        &forwarding,
        &mut sessions,
        &frame,
        meta,
        WAN_IFINDEX,
        "reth0.80",
    );

    assert_eq!(
        dbg.host_inbound_deny, 1,
        "the host-inbound gate must deny tcp/22"
    );
    let event = next_deny_event(&event_rx);
    assert_eq!(
        event.kind,
        crate::event_stream::codec::DataplaneEventKind::PolicyDeny
    );
    assert_eq!(event.reason, 6);
    assert_eq!(event.application_id, 17, "resolve the service after DNAT");
    assert_eq!(event.dst_ip, IpAddr::V4(VIP));
    assert_eq!(
        event.dst_port, 2222,
        "RT_FLOW keeps the original wire tuple"
    );
}

#[test]
fn flow_backed_noroute_deny_logs_its_evaluated_application_10981() {
    let mut snapshot = policy_deny_snapshot();
    snapshot.app_catalog = vec![catalog_entry(7, 443), catalog_entry(8, 80)];
    let forwarding = build_forwarding_state(&snapshot);
    let mut sessions = SessionTable::new();
    let dst = Ipv4Addr::new(198, 51, 100, 40);
    let (frame, meta) = tcp_syn(
        Ipv4Addr::new(10, 0, 61, 100),
        dst,
        443,
        LAN_IFINDEX as u32,
        TEST_LAN_MAC,
    );
    let (dbg, _event_handle, event_rx) = drive_capturing_events(
        &forwarding,
        &mut sessions,
        &frame,
        meta,
        LAN_IFINDEX,
        "reth1.0",
    );

    assert_eq!(dbg.no_route, 1, "the fixture must exercise the NoRoute arm");
    assert_eq!(dbg.policy_deny, 1, "default-deny NoRoute traffic is denied");
    let event = next_deny_event(&event_rx);
    assert_eq!(
        event.kind,
        crate::event_stream::codec::DataplaneEventKind::PolicyDeny
    );
    assert_eq!(event.reason, 5);
    assert_eq!(
        event.application_id, 7,
        "flow-backed NoRoute resolves tcp/443 as junos-https"
    );
    assert_eq!(event.dst_ip, IpAddr::V4(dst));
    assert_eq!(event.dst_port, 443);
}
