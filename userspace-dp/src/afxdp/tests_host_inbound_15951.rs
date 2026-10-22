//! #15951: host-inbound defects — trusted fallthrough on install failure and
//! uncredited `junos-host` policy denies.
//!
//! H41-01: a cacheable LocalDelivery session-miss whose session cannot be
//! installed (capacity refused, or the install helper fails) must be dropped,
//! not delivered through the Trusted slow-path outlet without a session.
//! H41-02: every `to-zone junos-host` deny must credit the global
//! `policy_denied_packets` counter (`xpf_policy_denies_total`), and a
//! DNAT-to-local deny record must carry the translated tuple it was judged on.
//!
//! Instruments are the poll's own counters plus the session table. The batch
//! counters returned by the txn driver carry `policy_denied_packets` /
//! `host_inbound_denied_packets`; delivery on the miss path is read as
//! `local == 1` and installation as `session_create == 1`. Every counter used
//! exists without the fix, so each cell reds at base on its primary assertion
//! rather than failing to compile.

#![allow(unused_imports)]

use super::test_fixtures::*;
use super::tests_support::*;
use super::*;
use crate::tcp_flags::TCP_ACK;
use crate::{DestinationNATRuleSnapshot, PolicyRuleSnapshot};
use std::net::Ipv4Addr;

const WAN_IFINDEX: i32 = 12;
const CLIENT: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 10);
const VIP: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 9);
/// `reth1.0`'s own address in `nat_snapshot`.
const LOCAL: Ipv4Addr = Ipv4Addr::new(10, 0, 61, 1);
const CLIENT_PORT: u16 = 54321;

struct Fixture {
    dnat: Option<(u16, u16)>,
    junos_host: Vec<PolicyRuleSnapshot>,
}

const PLAIN: Fixture = Fixture {
    dnat: Some((443, 8080)),
    junos_host: Vec::new(),
};

fn forwarding(f: Fixture) -> ForwardingState {
    let mut s = nat_snapshot();
    if let Some((vip_port, local_port)) = f.dnat {
        s.destination_nat_rules = vec![DestinationNATRuleSnapshot {
            name: "vip-to-self".to_string(),
            from_zone: "wan".to_string(),
            destination_address: "203.0.113.9".to_string(),
            destination_port: vip_port,
            protocol: "tcp".to_string(),
            pool_address: "10.0.61.1".to_string(),
            pool_port: local_port,
            ..Default::default()
        }];
    }
    s.policies.extend(f.junos_host);
    build_forwarding_state(&s)
}

fn junos_host_rule(name: &str, action: &str) -> PolicyRuleSnapshot {
    PolicyRuleSnapshot {
        name: name.to_string(),
        from_zone: "wan".to_string(),
        to_zone: "junos-host".to_string(),
        source_addresses: vec!["any".to_string()],
        destination_addresses: vec!["any".to_string()],
        applications: vec!["any".to_string()],
        application_terms: Vec::new(),
        action: action.to_string(),
        ..Default::default()
    }
}

fn from_wan(
    fw: &ForwardingState,
    sessions: &mut SessionTable,
    dst: Ipv4Addr,
    dport: u16,
    flags: u8,
) -> (BatchCounters, DebugPollCounters) {
    let frame = build_txn_tcp_syn_frame_v4(
        CLIENT,
        dst,
        CLIENT_PORT,
        dport,
        flags,
        crate::afxdp::tests_support::TEST_WAN_MAC,
    );
    let mut meta = txn_meta_v4(WAN_IFINDEX as u32, flags, frame.len() as u16);
    meta.ingress_vlan_id = 80;
    let mut b = BindingWorker::new_for_mirror_test(0, 0, WAN_IFINDEX, 0);
    b.interface = Arc::<str>::from("reth0.80");
    let ha_state = txn_ha_state();
    txn_run_descriptor_checked(&mut b, sessions, fw, &ha_state, &frame, meta, true)
}

fn session_count(sessions: &SessionTable) -> usize {
    let mut n = 0;
    sessions.iter_with_origin(|_k, _d, _m, _o| n += 1);
    n
}

/// H41-01 control: with capacity available the same DNAT-to-local SYN is
/// delivered and installed, so the refusal cell below cannot pass vacuously.
#[test]
fn dnat_to_self_delivers_and_installs_with_capacity_15951() {
    let fw = forwarding(PLAIN);
    let mut sessions = SessionTable::new();
    sessions.set_max_sessions_for_test(16);
    let (_batch, d) = from_wan(&fw, &mut sessions, VIP, 443, TCP_FLAG_SYN);
    assert_eq!(d.local, 1, "control: delivered (local={})", d.local);
    assert_eq!(d.session_create, 1, "control: installed");
    assert_eq!(session_count(&sessions), 1);
    assert_eq!(sessions.admission_refused(), 0);
}

/// H41-01: at capacity, a cacheable DNAT-to-local SYN that passes host-inbound
/// and `junos-host` must be recycled/dropped — no Trusted delivery, no session.
#[test]
fn capacity_refused_local_delivery_is_dropped_not_trusted_15951() {
    let fw = forwarding(PLAIN);
    let mut sessions = SessionTable::new();
    sessions.set_max_sessions_for_test(0);
    let (_batch, d) = from_wan(&fw, &mut sessions, VIP, 443, TCP_FLAG_SYN);
    assert_eq!(
        d.local, 0,
        "capacity-refused host-bound packet must not be delivered via Trusted \
         (local={} means it fell through to the slow-path reinject)",
        d.local
    );
    assert_eq!(d.session_create, 0, "no session may be installed at cap 0");
    assert_eq!(session_count(&sessions), 0);
    assert_eq!(
        sessions.admission_refused(),
        1,
        "the refusal must be counted exactly once"
    );
}

/// H41-02 (session-miss): a `junos-host` deny credits `policy_denied_packets`.
#[test]
fn junos_host_deny_on_miss_credits_policy_denied_15951() {
    let fw = forwarding(Fixture {
        junos_host: vec![junos_host_rule("no-host", "deny")],
        ..PLAIN
    });
    let mut sessions = SessionTable::new();
    sessions.set_max_sessions_for_test(16);
    let (batch, d) = from_wan(&fw, &mut sessions, VIP, 443, TCP_FLAG_SYN);
    assert_eq!(d.policy_deny, 1, "control: the deny arm ran");
    assert_eq!(d.session_create, 0, "a denied SYN installs nothing");
    assert_eq!(
        batch.policy_denied_packets, 1,
        "junos-host deny must credit xpf_policy_denies_total"
    );
}

/// H41-02 (session-hit): an established DNAT-to-self session meeting a new
/// `junos-host` deny on its next packet credits the counter exactly once.
#[test]
fn junos_host_deny_on_hit_credits_policy_denied_15951() {
    let fw = forwarding(PLAIN);
    let mut sessions = SessionTable::new();
    sessions.set_max_sessions_for_test(16);
    let (_b, syn) = from_wan(&fw, &mut sessions, VIP, 443, TCP_FLAG_SYN);
    assert_eq!(syn.session_create, 1, "control: installed");

    let closed = forwarding(Fixture {
        junos_host: vec![junos_host_rule("no-host", "deny")],
        ..PLAIN
    });
    let (batch, ack) = from_wan(&closed, &mut sessions, VIP, 443, TCP_ACK);
    assert_eq!(ack.session_hit, 1, "the ACK must HIT the installed session");
    assert_eq!(ack.policy_deny, 1, "control: the hit deny arm ran");
    assert_eq!(
        batch.policy_denied_packets, 1,
        "session-hit junos-host deny must credit the global counter once"
    );
}

/// H41-02 (reject arm): `then reject` is also a policy deny for the counter.
#[test]
fn junos_host_reject_on_miss_credits_policy_denied_15951() {
    let fw = forwarding(Fixture {
        junos_host: vec![junos_host_rule("no-host", "reject")],
        ..PLAIN
    });
    let mut sessions = SessionTable::new();
    sessions.set_max_sessions_for_test(16);
    let (batch, d) = from_wan(&fw, &mut sessions, VIP, 443, TCP_FLAG_SYN);
    assert_eq!(d.policy_deny, 1, "control: the reject arm ran");
    assert_eq!(batch.policy_denied_packets, 1);
}
/// H41-02 (event): a DNAT-to-local deny record carries the translated tuple
/// the policy was judged on, not `None`/`0`. The wire tuple stays original.
#[test]
fn dnat_junos_host_deny_event_carries_translated_tuple_15951() {
    let fw = forwarding(Fixture {
        junos_host: vec![junos_host_rule("no-host", "deny")],
        ..PLAIN
    });
    let mut sessions = SessionTable::new();
    sessions.set_max_sessions_for_test(16);
    let frame = build_txn_tcp_syn_frame_v4(
        CLIENT,
        VIP,
        CLIENT_PORT,
        443,
        TCP_FLAG_SYN,
        crate::afxdp::tests_support::TEST_WAN_MAC,
    );
    let mut meta = txn_meta_v4(WAN_IFINDEX as u32, TCP_FLAG_SYN, frame.len() as u16);
    meta.ingress_vlan_id = 80;
    let mut b = BindingWorker::new_for_mirror_test(0, 0, WAN_IFINDEX, 0);
    b.interface = Arc::<str>::from("reth0.80");
    let (_batch, d, _handle, rx) = txn_run_descriptor_capturing_events(
        &mut b,
        &mut sessions,
        &fw,
        &txn_ha_state(),
        &frame,
        meta,
    );
    assert_eq!(d.policy_deny, 1, "control: the deny arm ran");
    let event = rx
        .try_recv()
        .expect("junos-host deny emits a dataplane event")
        .decode_dataplane_event()
        .expect("deny event payload");
    assert_eq!(
        event.dst_ip,
        std::net::IpAddr::V4(VIP),
        "wire tuple retained"
    );
    assert_eq!(event.dst_port, 443, "wire port retained");
    assert_eq!(
        event.nat_dst_ip,
        Some(std::net::IpAddr::V4(LOCAL)),
        "deny record must carry the translated destination it was judged on"
    );
    assert_eq!(event.nat_dst_port, 8080);
}
