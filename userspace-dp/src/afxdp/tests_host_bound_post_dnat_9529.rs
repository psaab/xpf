//! #9529: the host-bound gates judge the POST-destination-translation tuple.
//!
//! A packet that is host-bound only BY VIRTUE of a destination translation —
//! `203.0.113.9:443` DNATed to the firewall's own `10.0.61.1:8080` — used to be
//! judged by the host-inbound service gate and `to-zone junos-host` policy on
//! the WIRE tuple, so a fine deny written on the firewall address or the
//! translated port matched nothing. Transit already judges post-translation
//! (#2345); these cells hold the host-bound path to the same doctrine.
//!
//! Instruments are the poll's own counters. On the host-bound paths a
//! `junos-host` deny counts `policy_deny`, a service-gate deny counts
//! `host_inbound_deny`, and BOTH drop arms also count `local`, so delivery is
//! read as `local == 1` with no deny and a `session_create` on the miss path.
//! Every counter used exists without the fix, so each cell reds at base on its
//! primary assertion rather than failing to compile.

#![allow(unused_imports)]

use super::test_fixtures::*;
use super::tests_support::*;
use super::*;
use crate::protocol::PolicyApplicationSnapshot;
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
    /// `(vip_port, local_port)` for a DNAT `203.0.113.9:vip_port -> 10.0.61.1:local_port`.
    dnat: Option<(u16, u16)>,
    /// Replace wan's host-inbound system-services (default: any-service).
    wan_services: Option<&'static [&'static str]>,
    junos_host: Vec<PolicyRuleSnapshot>,
    /// A wan -> lan permit naming the local address. The #8356 re-derivation
    /// judges a host-bound session by that transit pair and would otherwise
    /// revoke it on its first ACK (#9563); the hit-path cells need the ACK to
    /// reach the host-bound gates.
    permit_wan_to_local: bool,
}

const PLAIN: Fixture = Fixture {
    dnat: Some((443, 8080)),
    wan_services: None,
    junos_host: Vec::new(),
    permit_wan_to_local: false,
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
    if let Some(services) = f.wan_services {
        for zone in s.zones.iter_mut() {
            if zone.name == "wan" {
                zone.host_inbound_system_services = services.iter().map(|x| x.to_string()).collect();
            }
        }
    }
    s.policies.extend(f.junos_host);
    if f.permit_wan_to_local {
        s.policies.push(PolicyRuleSnapshot {
            name: "wan-to-self".to_string(),
            from_zone: "wan".to_string(),
            to_zone: "lan".to_string(),
            source_addresses: vec!["any".to_string()],
            destination_addresses: vec!["10.0.61.1/32".to_string()],
            applications: vec!["any".to_string()],
            application_terms: Vec::new(),
            action: "permit".to_string(),
            ..Default::default()
        });
    }
    build_forwarding_state(&s)
}

/// A `to-zone junos-host` deny from wan. `app` is `(name, tcp destination port)`.
fn junos_host_deny(name: &str, source: &str, destination: &str, app: Option<(&str, &str)>) -> PolicyRuleSnapshot {
    let (applications, application_terms) = match app {
        None => (vec!["any".to_string()], Vec::new()),
        Some((app_name, dport)) => (
            vec![app_name.to_string()],
            vec![PolicyApplicationSnapshot {
                name: app_name.to_string(),
                protocol: "tcp".to_string(),
                source_port: String::new(),
                destination_port: dport.to_string(),
                icmp_type: None,
                icmp_code: None,
                inactivity_timeout: None,
            }],
        ),
    };
    PolicyRuleSnapshot {
        name: name.to_string(),
        from_zone: "wan".to_string(),
        to_zone: "junos-host".to_string(),
        source_addresses: vec![source.to_string()],
        destination_addresses: vec![destination.to_string()],
        applications,
        application_terms,
        action: "deny".to_string(),
        ..Default::default()
    }
}

fn from_wan(
    fw: &ForwardingState,
    sessions: &mut SessionTable,
    dst: Ipv4Addr,
    dport: u16,
    flags: u8,
) -> DebugPollCounters {
    let frame = build_txn_tcp_syn_frame_v4(CLIENT, dst, CLIENT_PORT, dport, flags);
    let meta = txn_meta_v4(WAN_IFINDEX as u32, flags, frame.len() as u16);
    let mut b = BindingWorker::new_for_mirror_test(0, 0, WAN_IFINDEX, 0);
    b.interface = Arc::<str>::from("reth0.80");
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
fn the_dnat_to_self_fixture_delivers_and_installs_9529() {
    let fw = forwarding(PLAIN);
    let mut sessions = SessionTable::new();
    let d = from_wan(&fw, &mut sessions, VIP, 443, TCP_FLAG_SYN);
    assert!(
        delivered(&d) && d.session_create == 1,
        "control: with no junos-host rule the client's SYN to VIP:443 is translated to \
         the firewall's own 10.0.61.1:8080, delivered and installed. If not, no deny below \
         can be read (local={} policy_deny={} host_inbound_deny={} create={})",
        d.local, d.policy_deny, d.host_inbound_deny, d.session_create
    );
}

#[test]
fn a_destination_scoped_junos_host_deny_matches_the_translated_address_9529() {
    let fw = forwarding(Fixture {
        junos_host: vec![junos_host_deny("no-self", "any", "10.0.61.1/32", None)],
        ..PLAIN
    });
    let mut sessions = SessionTable::new();
    let d = from_wan(&fw, &mut sessions, VIP, 443, TCP_FLAG_SYN);
    assert_eq!(
        d.policy_deny, 1,
        "the packet is host-bound only because it was translated to 10.0.61.1, and a \
         junos-host deny naming 10.0.61.1 must match it. 0 means the gate judged the WIRE \
         destination 203.0.113.9 and let the translation carry the packet past the rule (#9529)"
    );
    assert_eq!(d.session_create, 0, "a denied host-bound SYN installs nothing");
}

#[test]
fn an_application_scoped_junos_host_deny_matches_the_translated_port_9529() {
    let fw = forwarding(Fixture {
        junos_host: vec![junos_host_deny("no-alt-web", "any", "any", Some(("alt-web", "8080")))],
        ..PLAIN
    });
    let mut sessions = SessionTable::new();
    let d = from_wan(&fw, &mut sessions, VIP, 443, TCP_FLAG_SYN);
    assert_eq!(
        d.policy_deny, 1,
        "the listener is reached on 8080, so a junos-host deny on tcp/8080 must match. 0 \
         means the gate read the WIRE port 443 (#9529)"
    );
}

/// The other half of judging post-translation: a rule that names ONLY the wire
/// port no longer governs, exactly as it would not on the transit path (#2345).
#[test]
fn a_junos_host_deny_naming_only_the_wire_port_no_longer_matches_9529() {
    let fw = forwarding(Fixture {
        junos_host: vec![junos_host_deny("no-https", "any", "any", Some(("https-only", "443")))],
        ..PLAIN
    });
    let mut sessions = SessionTable::new();
    let d = from_wan(&fw, &mut sessions, VIP, 443, TCP_FLAG_SYN);
    assert!(
        delivered(&d),
        "after translation the packet is tcp/8080; a deny naming only tcp/443 describes \
         the pre-translation tuple, which the host-bound gates no longer judge (#9529). \
         local={} policy_deny={}",
        d.local, d.policy_deny
    );
}

/// Byte-identical for traffic that needs no translation: the same rule set, the
/// same verdicts, whether or not a DNAT rule exists elsewhere.
#[test]
fn direct_to_local_traffic_is_judged_exactly_as_before_9529() {
    let open = forwarding(PLAIN);
    let mut sessions = SessionTable::new();
    let d = from_wan(&open, &mut sessions, LOCAL, 8080, TCP_FLAG_SYN);
    assert!(
        delivered(&d),
        "direct-to-local with no rule is delivered (local={} policy_deny={})",
        d.local, d.policy_deny
    );
    let closed = forwarding(Fixture {
        junos_host: vec![junos_host_deny("no-self", "any", "10.0.61.1/32", None)],
        ..PLAIN
    });
    let mut sessions = SessionTable::new();
    let d = from_wan(&closed, &mut sessions, LOCAL, 8080, TCP_FLAG_SYN);
    assert_eq!(
        d.policy_deny, 1,
        "and a destination-scoped deny on the local address drops it, as it always did"
    );
}

#[test]
fn a_source_scoped_junos_host_deny_still_matches_9529() {
    let fw = forwarding(Fixture {
        junos_host: vec![junos_host_deny("no-client", "198.51.100.10/32", "any", None)],
        ..PLAIN
    });
    let mut sessions = SessionTable::new();
    let d = from_wan(&fw, &mut sessions, VIP, 443, TCP_FLAG_SYN);
    assert_eq!(
        d.policy_deny, 1,
        "destination translation does not touch the source, so a source-scoped deny \
         matches before and after this change (#9529)"
    );
}

/// The coarse service gate reads the translated service port too. wan admits
/// only SSH; `VIP:2222 -> 10.0.61.1:22` reaches sshd, `VIP:2223 -> :8080` does not.
#[test]
fn the_host_inbound_service_gate_reads_the_translated_port_9529() {
    let ssh = forwarding(Fixture {
        dnat: Some((2222, 22)),
        wan_services: Some(&["ssh"]),
        ..PLAIN
    });
    let mut sessions = SessionTable::new();
    let d = from_wan(&ssh, &mut sessions, VIP, 2222, TCP_FLAG_SYN);
    assert!(
        delivered(&d),
        "the packet reaches the local stack on tcp/22, which wan's `ssh` service admits. A \
         host-inbound deny here means the gate judged the WIRE port 2222 (#9529). \
         local={} host_inbound_deny={}",
        d.local, d.host_inbound_deny
    );
    let other = forwarding(Fixture {
        dnat: Some((2223, 8080)),
        wan_services: Some(&["ssh"]),
        ..PLAIN
    });
    let mut sessions = SessionTable::new();
    let d = from_wan(&other, &mut sessions, VIP, 2223, TCP_FLAG_SYN);
    assert_eq!(
        d.host_inbound_deny, 1,
        "control: translated to tcp/8080, which `ssh` does not admit, the same gate denies"
    );
}

/// The session-HIT path judges the same way. Installed with no junos-host rule;
/// the operator then adds a deny naming the local address, and the established
/// flow's next packet must meet it.
#[test]
fn an_established_dnat_to_self_session_meets_a_junos_host_deny_on_the_translated_address_9529() {
    let install = forwarding(Fixture {
        permit_wan_to_local: true,
        ..PLAIN
    });
    let mut sessions = SessionTable::new();
    let syn = from_wan(&install, &mut sessions, VIP, 443, TCP_FLAG_SYN);
    assert!(delivered(&syn) && syn.session_create == 1, "control: installed");
    let closed = forwarding(Fixture {
        junos_host: vec![junos_host_deny("no-self", "any", "10.0.61.1/32", None)],
        permit_wan_to_local: true,
        ..PLAIN
    });
    let ack = from_wan(&closed, &mut sessions, VIP, 443, TCP_ACK);
    assert_eq!(ack.session_hit, 1, "the ACK must HIT the installed session");
    assert_eq!(ack.policy_revoked_sessions, 0, "and survive the #8356 re-derivation (see `permit_wan_to_local`)");
    assert_eq!(
        ack.policy_deny, 1,
        "the established flow's packets reach 10.0.61.1 too, so the new junos-host deny \
         must drop them. 0 means the session-hit gate judged the wire destination (#9529)"
    );
}

#[test]
fn an_established_dnat_to_self_session_meets_the_service_gate_on_the_translated_port_9529() {
    let fw = forwarding(Fixture {
        dnat: Some((2222, 22)),
        wan_services: Some(&["ssh"]),
        permit_wan_to_local: true,
        ..PLAIN
    });
    let mut sessions = SessionTable::new();
    let syn = from_wan(&fw, &mut sessions, VIP, 2222, TCP_FLAG_SYN);
    assert!(delivered(&syn) && syn.session_create == 1, "control: installed");
    let ack = from_wan(&fw, &mut sessions, VIP, 2222, TCP_ACK);
    assert_eq!(ack.session_hit, 1, "the ACK must HIT the installed session");
    assert_eq!(ack.policy_revoked_sessions, 0, "and survive the #8356 re-derivation");
    assert_eq!(
        ack.host_inbound_deny, 0,
        "the established flow reaches sshd on tcp/22, which wan admits. A deny here means the \
         session-hit gate judged the WIRE port 2222 and tore down a flow its own SYN was \
         admitted for (#9529)"
    );
}
