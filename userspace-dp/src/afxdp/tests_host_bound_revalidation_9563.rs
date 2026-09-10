//! #9563: the #8356 zone-policy re-derivation must not judge a HOST-BOUND session.
//!
//! A lan host opens SSH to the firewall's own lan address (`reth1.0`, 10.0.61.1)
//! through the real poll path (`txn_run_descriptor`). The session installs as
//! `LocalDelivery`, and every local-delivery resolution sets `egress_ifindex` to the
//! local interface. A zone-pair re-derivation therefore asks `lan -> lan`, a pair that
//! host-inbound admission never consulted. Before #9563 the owner's own first ACK
//! revoked the session.
//!
//! Host-bound authority is the host-inbound gate plus `to-zone junos-host` policy, and
//! the established-hit path re-evaluates both on every packet. The last cell pins that
//! a junos-host deny still drops the established hit once the re-derivation declines.

use super::test_fixtures::*;
use super::tests_support::*;
use super::*;
use crate::protocol::PolicyApplicationSnapshot;
use crate::tcp_flags::{TCP_ACK, TCP_SYN};
use crate::PolicyRuleSnapshot;
use std::net::Ipv4Addr;

/// `reth1.0` in `nat_snapshot`, zone `lan`.
const LAN_IFINDEX: i32 = 24;
const LAN_HOST: Ipv4Addr = Ipv4Addr::new(10, 0, 61, 102);
/// `reth1.0`'s own address in `nat_snapshot`.
const LOCAL: Ipv4Addr = Ipv4Addr::new(10, 0, 61, 1);
const HOST_PORT: u16 = 40000;

fn forwarding(junos_host: Vec<PolicyRuleSnapshot>) -> ForwardingState {
    let mut s = nat_snapshot();
    s.policies.extend(junos_host);
    build_forwarding_state(&s)
}

/// A `to-zone junos-host` deny from lan for tcp/22 to the firewall's lan address.
fn lan_ssh_junos_host_deny() -> PolicyRuleSnapshot {
    PolicyRuleSnapshot {
        name: "deny-lan-ssh-to-self".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "junos-host".to_string(),
        source_addresses: vec!["any".to_string()],
        destination_addresses: vec!["10.0.61.1/32".to_string()],
        applications: vec!["ssh-9563".to_string()],
        application_terms: vec![PolicyApplicationSnapshot {
            name: "ssh-9563".to_string(),
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

fn from_lan(fw: &ForwardingState, sessions: &mut SessionTable, flags: u8) -> DebugPollCounters {
    let frame = build_txn_tcp_syn_frame_v4(LAN_HOST, LOCAL, HOST_PORT, 22, flags);
    let meta = txn_meta_v4(LAN_IFINDEX as u32, flags, frame.len() as u16);
    let mut b = BindingWorker::new_for_mirror_test(0, 0, LAN_IFINDEX, 0);
    b.interface = Arc::<str>::from("reth1.0");
    let ha_state = txn_ha_state();
    let (_batch, dbg) = txn_run_descriptor(&mut b, sessions, fw, &ha_state, &frame, meta);
    dbg
}

fn delivered(d: &DebugPollCounters) -> bool {
    d.local == 1 && d.policy_deny == 0 && d.host_inbound_deny == 0
}

fn session_count(sessions: &SessionTable) -> usize {
    let mut n = 0;
    sessions.iter_with_origin(|_k, _d, _m, _o| n += 1);
    n
}

#[test]
fn the_lan_ssh_to_self_fixture_delivers_and_installs_9563() {
    let fw = forwarding(Vec::new());
    let mut sessions = SessionTable::new();
    let syn = from_lan(&fw, &mut sessions, TCP_SYN);
    assert!(
        delivered(&syn),
        "control: lan's host-inbound services admit SSH to 10.0.61.1, so the SYN must be \
         delivered (local={} policy_deny={} host_inbound_deny={})",
        syn.local, syn.policy_deny, syn.host_inbound_deny
    );
    assert!(session_count(&sessions) > 0, "control: the SYN must install the host-bound session");
}

#[test]
fn a_host_bound_session_survives_its_own_first_ack_9563() {
    let fw = forwarding(Vec::new());
    let mut sessions = SessionTable::new();
    let syn = from_lan(&fw, &mut sessions, TCP_SYN);
    assert!(delivered(&syn) && session_count(&sessions) > 0, "control: the SYN installs the session");
    let installed = session_count(&sessions);

    let ack = from_lan(&fw, &mut sessions, TCP_ACK);
    assert_eq!(
        ack.policy_revoked_sessions, 0,
        "the owner's own first ACK revoked the host-bound session: the #8356 re-derivation \
         judged it by the transit pair lan -> lan, which host-inbound admission never consulted"
    );
    assert_eq!(session_count(&sessions), installed, "the host-bound session must still be installed");
    assert!(delivered(&ack), "the established ACK must still be delivered");
}

#[test]
fn a_junos_host_deny_still_drops_the_established_host_bound_hit_9563() {
    let plain = forwarding(Vec::new());
    let denying = forwarding(vec![lan_ssh_junos_host_deny()]);
    let mut sessions = SessionTable::new();
    let syn = from_lan(&plain, &mut sessions, TCP_SYN);
    assert!(delivered(&syn) && session_count(&sessions) > 0, "control: the SYN installs the session");

    let ack = from_lan(&denying, &mut sessions, TCP_ACK);
    assert_eq!(
        ack.policy_deny, 1,
        "a `to-zone junos-host` deny for tcp/22 must still drop the established host-bound hit"
    );
    assert!(!delivered(&ack), "the denied ACK must not be delivered");
    assert_eq!(
        ack.policy_revoked_sessions, 0,
        "the drop must come from the host-bound gate on the hit, not from a zone-pair revocation"
    );
}
