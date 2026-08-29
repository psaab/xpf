// Tests for the filter module (#1049). Originally inline in filter.rs,
// relocated as filter_tests.rs in P1 (PR #1052), then renamed to
// filter/tests.rs alongside the structural split into compiler/engine/policer.
// Loaded as a sibling submodule via `#[path = "tests.rs"]` from filter/mod.rs.

use super::*;
// #3077: the flexible-match-range wire struct lives in protocol::security; it is
// only referenced by the flex tests below, so import it here rather than in the
// non-test filter module (which would warn unused in release builds).
use crate::FlexMatchSnapshot;

fn make_filter_state(
    filters: &[FirewallFilterSnapshot],
    policers: &[PolicerSnapshot],
) -> FilterState {
    parse_filter_state(filters, policers, &[], "", "").expect("filter state compiles")
}

fn make_filter_state_with_three_color(
    filters: &[FirewallFilterSnapshot],
    three_color_policers: &[ThreeColorPolicerSnapshot],
) -> FilterState {
    parse_filter_state_with_three_color(filters, &[], three_color_policers, &[], "", "")
        .expect("filter state compiles")
}

fn make_filter_state_with_interfaces(
    filters: &[FirewallFilterSnapshot],
    interfaces: &[crate::InterfaceSnapshot],
) -> FilterState {
    parse_filter_state(filters, &[], interfaces, "", "").expect("filter state compiles")
}

#[test]
fn basic_accept_discard() {
    let state = make_filter_state(
        &[FirewallFilterSnapshot {
            name: "test-filter".into(),
            family: "inet".into(),
            terms: vec![
                FirewallTermSnapshot {
                    name: "deny-ssh".into(),
                    source_except: false,
                    destination_except: false,
                    source_constrained: false,
                    destination_constrained: false,
                    destination_addresses: vec![],
                    source_addresses: vec![],
                    protocols: vec!["tcp".into()],
                    source_ports: vec![],
                    destination_ports: vec!["22".into()],
                    dscp_values: vec![],
                    action: "discard".into(),
                    next_term: false,
                    count: String::new(),
                    log: false,
                    syslog: false,
                    reject_message_type: String::new(),
                    policer: String::new(),
                    routing_instance: String::new(),
                    forwarding_class: String::new(),
                    dscp_rewrite: None,
                    tcp_flags: None,
                    tcp_flags_forbidden: None,
                    tcp_flags_unparseable: false,
                icmp_type_unrepresentable: false,
                icmp_code_unrepresentable: false,
                dscp_match_unrepresentable: false,
                ports_unrepresentable: false,
                address_unrepresentable: false,
                    is_fragment: false,
                    icmp_types: vec![],
                    icmp_codes: vec![],
                    flex_match: None,
                    source_ports_except: vec![],
                    destination_ports_except: vec![],
                },
                FirewallTermSnapshot {
                    name: "allow-all".into(),
                    source_except: false,
                    destination_except: false,
                    source_constrained: false,
                    destination_constrained: false,
                    destination_addresses: vec![],
                    source_addresses: vec![],
                    protocols: vec![],
                    source_ports: vec![],
                    destination_ports: vec![],
                    dscp_values: vec![],
                    action: "accept".into(),
                    next_term: false,
                    count: String::new(),
                    log: false,
                    syslog: false,
                    reject_message_type: String::new(),
                    policer: String::new(),
                    routing_instance: String::new(),
                    forwarding_class: String::new(),
                    dscp_rewrite: None,
                    tcp_flags: None,
                    tcp_flags_forbidden: None,
                    tcp_flags_unparseable: false,
                icmp_type_unrepresentable: false,
                icmp_code_unrepresentable: false,
                dscp_match_unrepresentable: false,
                ports_unrepresentable: false,
                address_unrepresentable: false,
                    is_fragment: false,
                    icmp_types: vec![],
                    icmp_codes: vec![],
                    flex_match: None,
                    source_ports_except: vec![],
                    destination_ports_except: vec![],
                },
            ],
        }],
        &[],
    );
    // SSH traffic should be discarded
    let result = evaluate_filter(
        &state,
        "inet:test-filter",
        IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 1, 2)),
        PROTO_TCP,
        12345,
        22,
        0,
        TermMatchExtra::default(),
    );
    assert_eq!(result.action, FilterAction::Discard);

    // HTTP traffic should be accepted
    let result = evaluate_filter(
        &state,
        "inet:test-filter",
        IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 1, 2)),
        PROTO_TCP,
        12345,
        80,
        0,
        TermMatchExtra::default(),
    );
    assert_eq!(result.action, FilterAction::Accept);
}

/// #2521: `then reject` compiles to `FilterAction::Reject(RejectMessage::ADMIN_PROHIBITED)` and stays DISTINCT
/// from `then discard` (`FilterAction::Discard`). The dataplane uses this
/// distinction to synthesize an active reply for reject while keeping discard a
/// silent drop. Fail-on-revert: if the compiler collapses `reject` to
/// `Discard` (the historical silent-drop behavior), this asserts fail.
#[test]
fn reject_action_compiles_distinct_from_discard() {
    let state = make_filter_state(
        &[FirewallFilterSnapshot {
            name: "reject-filter".into(),
            family: "inet".into(),
            terms: vec![
                FirewallTermSnapshot {
                    name: "reject-ssh".into(),
                    protocols: vec!["tcp".into()],
                    destination_ports: vec!["22".into()],
                    action: "reject".into(),
                    ..Default::default()
                },
                FirewallTermSnapshot {
                    name: "discard-telnet".into(),
                    protocols: vec!["tcp".into()],
                    destination_ports: vec!["23".into()],
                    action: "discard".into(),
                    ..Default::default()
                },
            ],
        }],
        &[],
    );
    let reject = evaluate_filter(
        &state,
        "inet:reject-filter",
        IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 1, 2)),
        PROTO_TCP,
        12345,
        22,
        0,
        TermMatchExtra::default(),
    );
    assert_eq!(
        reject.action,
        FilterAction::Reject(RejectMessage::ADMIN_PROHIBITED),
        "`then reject` must compile to FilterAction::Reject(RejectMessage::ADMIN_PROHIBITED), not collapse to Discard"
    );
    let discard = evaluate_filter(
        &state,
        "inet:reject-filter",
        IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 1, 2)),
        PROTO_TCP,
        12345,
        23,
        0,
        TermMatchExtra::default(),
    );
    assert_eq!(discard.action, FilterAction::Discard);
}

#[test]
fn interface_filter_log_match_returns_filter_and_term_identity() {
    let state = make_filter_state_with_interfaces(
        &[FirewallFilterSnapshot {
            name: "edge-in".into(),
            family: "inet".into(),
            terms: vec![FirewallTermSnapshot {
                name: "log-web".into(),
                protocols: vec!["tcp".into()],
                destination_ports: vec!["443".into()],
                action: "accept".into(),
                log: true,
                syslog: false,
                reject_message_type: String::new(),
                ..Default::default()
            }],
        }],
        &[crate::InterfaceSnapshot {
            ifindex: 7,
            filter_input_v4: "edge-in".into(),
            ..Default::default()
        }],
    );

    let log_match = evaluate_interface_filter_log_match(
        &state,
        7,
        false,
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 10)),
        IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20)),
        PROTO_TCP,
        49152,
        443,
        0,
        TermMatchExtra::default(),
        true,
    )
    .expect("logged input filter hit");

    assert_eq!(log_match.filter_id, 0);
    assert_eq!(log_match.term_id, 0);
    assert_eq!(log_match.action, FilterAction::Accept);
}

#[test]
fn interface_filter_log_match_skips_pbr_terms_without_double_emit() {
    let state = make_filter_state_with_interfaces(
        &[FirewallFilterSnapshot {
            name: "pbr-in".into(),
            family: "inet".into(),
            terms: vec![FirewallTermSnapshot {
                name: "route-and-log".into(),
                protocols: vec!["tcp".into()],
                destination_ports: vec!["443".into()],
                action: "accept".into(),
                log: true,
                syslog: false,
                reject_message_type: String::new(),
                routing_instance: "blue".into(),
                ..Default::default()
            }],
        }],
        &[crate::InterfaceSnapshot {
            ifindex: 7,
            filter_input_v4: "pbr-in".into(),
            ..Default::default()
        }],
    );

    let log_match = evaluate_interface_filter_log_match(
        &state,
        7,
        false,
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 10)),
        IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20)),
        PROTO_TCP,
        49152,
        443,
        0,
        TermMatchExtra::default(),
        true,
    );

    assert_eq!(log_match, None);
}

#[test]
fn port_range_matching() {
    let state = make_filter_state(
        &[FirewallFilterSnapshot {
            name: "port-range".into(),
            family: "inet".into(),
            terms: vec![FirewallTermSnapshot {
                name: "high-ports".into(),
                source_except: false,
                destination_except: false,
                source_constrained: false,
                destination_constrained: false,
                destination_addresses: vec![],
                source_addresses: vec![],
                protocols: vec!["tcp".into()],
                source_ports: vec![],
                destination_ports: vec!["1024-65535".into()],
                dscp_values: vec![],
                action: "discard".into(),
                next_term: false,
                count: String::new(),
                log: false,
                syslog: false,
                reject_message_type: String::new(),
                policer: String::new(),
                routing_instance: String::new(),
                forwarding_class: String::new(),
                dscp_rewrite: None,
                tcp_flags: None,
                tcp_flags_forbidden: None,
                tcp_flags_unparseable: false,
                icmp_type_unrepresentable: false,
                icmp_code_unrepresentable: false,
                dscp_match_unrepresentable: false,
                ports_unrepresentable: false,
                address_unrepresentable: false,
                is_fragment: false,
                icmp_types: vec![],
                icmp_codes: vec![],
                flex_match: None,
                source_ports_except: vec![],
                destination_ports_except: vec![],
            }],
        }],
        &[],
    );
    // Port 2000 is in range
    let result = evaluate_filter(
        &state,
        "inet:port-range",
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        PROTO_TCP,
        54321,
        2000,
        0,
        TermMatchExtra::default(),
    );
    assert_eq!(result.action, FilterAction::Discard);

    // Port 80 is not in range — no match, implicit accept
    let result = evaluate_filter(
        &state,
        "inet:port-range",
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        PROTO_TCP,
        54321,
        80,
        0,
        TermMatchExtra::default(),
    );
    assert_eq!(result.action, FilterAction::Accept);
}

// #2622: negated port match (Junos `destination-port-except` /
// `source-port-except`). A `destination-port-except [ 22 80 ]` term must
// DISCARD every TCP packet whose destination port is NOT 22 and NOT 80, and
// must NOT match (implicit accept) a packet whose dst port IS 22 or 80.
//
// FAIL-ON-REVERT: if the `except` inversion in port_match is reverted to plain
// membership, the two assertions swap — port 80 would discard and port 12345
// would accept — and both asserts below go RED.
#[test]
fn destination_port_except_negation() {
    let state = make_filter_state(
        &[FirewallFilterSnapshot {
            name: "dport-except".into(),
            family: "inet".into(),
            terms: vec![FirewallTermSnapshot {
                name: "deny-except-web".into(),
                source_except: false,
                destination_except: false,
                source_constrained: false,
                destination_constrained: false,
                destination_addresses: vec![],
                source_addresses: vec![],
                protocols: vec!["tcp".into()],
                source_ports: vec![],
                destination_ports: vec![],
                dscp_values: vec![],
                action: "discard".into(),
                next_term: false,
                count: String::new(),
                log: false,
                syslog: false,
                reject_message_type: String::new(),
                policer: String::new(),
                routing_instance: String::new(),
                forwarding_class: String::new(),
                dscp_rewrite: None,
                tcp_flags: None,
                tcp_flags_forbidden: None,
                tcp_flags_unparseable: false,
                icmp_type_unrepresentable: false,
                icmp_code_unrepresentable: false,
                dscp_match_unrepresentable: false,
                ports_unrepresentable: false,
                address_unrepresentable: false,
                is_fragment: false,
                icmp_types: vec![],
                icmp_codes: vec![],
                flex_match: None,
                source_ports_except: vec![],
                destination_ports_except: vec!["22".into(), "80".into()],
            }],
        }],
        &[],
    );
    // Port 80 IS in the except list -> term does NOT match -> implicit accept.
    let result = evaluate_filter(
        &state,
        "inet:dport-except",
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        PROTO_TCP,
        54321,
        80,
        0,
        TermMatchExtra::default(),
    );
    assert_eq!(
        result.action,
        FilterAction::Accept,
        "port 80 is in the except list, must NOT match the discard term"
    );
    // Port 22 IS in the except list -> implicit accept.
    let result = evaluate_filter(
        &state,
        "inet:dport-except",
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        PROTO_TCP,
        54321,
        22,
        0,
        TermMatchExtra::default(),
    );
    assert_eq!(result.action, FilterAction::Accept, "port 22 is excepted");
    // Port 12345 is NOT in the except list -> term matches -> discard.
    let result = evaluate_filter(
        &state,
        "inet:dport-except",
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        PROTO_TCP,
        54321,
        12345,
        0,
        TermMatchExtra::default(),
    );
    assert_eq!(
        result.action,
        FilterAction::Discard,
        "port 12345 is NOT excepted, must match the discard term"
    );
}

// #2622: source-port-except sibling of the test above, confirming the
// inversion is wired on the SOURCE direction too. FAIL-ON-REVERT: drop the
// source_port_except plumbing in compiler.rs and the second assert goes RED.
#[test]
fn source_port_except_negation() {
    let state = make_filter_state(
        &[FirewallFilterSnapshot {
            name: "sport-except".into(),
            family: "inet".into(),
            terms: vec![FirewallTermSnapshot {
                name: "deny-except-ephemeral".into(),
                source_except: false,
                destination_except: false,
                source_constrained: false,
                destination_constrained: false,
                destination_addresses: vec![],
                source_addresses: vec![],
                protocols: vec!["udp".into()],
                source_ports: vec![],
                destination_ports: vec![],
                dscp_values: vec![],
                action: "discard".into(),
                next_term: false,
                count: String::new(),
                log: false,
                syslog: false,
                reject_message_type: String::new(),
                policer: String::new(),
                routing_instance: String::new(),
                forwarding_class: String::new(),
                dscp_rewrite: None,
                tcp_flags: None,
                tcp_flags_forbidden: None,
                tcp_flags_unparseable: false,
                icmp_type_unrepresentable: false,
                icmp_code_unrepresentable: false,
                dscp_match_unrepresentable: false,
                ports_unrepresentable: false,
                address_unrepresentable: false,
                is_fragment: false,
                icmp_types: vec![],
                icmp_codes: vec![],
                flex_match: None,
                source_ports_except: vec!["53".into()],
                destination_ports_except: vec![],
            }],
        }],
        &[],
    );
    // Source port 53 IS excepted -> no match -> accept.
    let result = evaluate_filter(
        &state,
        "inet:sport-except",
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        crate::ip_proto::PROTO_UDP,
        53,
        4000,
        0,
        TermMatchExtra::default(),
    );
    assert_eq!(
        result.action,
        FilterAction::Accept,
        "src port 53 is excepted"
    );
    // Source port 9999 is NOT excepted -> match -> discard.
    let result = evaluate_filter(
        &state,
        "inet:sport-except",
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        crate::ip_proto::PROTO_UDP,
        9999,
        4000,
        0,
        TermMatchExtra::default(),
    );
    assert_eq!(
        result.action,
        FilterAction::Discard,
        "src port 9999 is NOT excepted, must match the discard term"
    );
}

#[test]
fn protocol_matching() {
    let state = make_filter_state(
        &[FirewallFilterSnapshot {
            name: "proto-filter".into(),
            family: "inet".into(),
            terms: vec![FirewallTermSnapshot {
                name: "deny-icmp".into(),
                source_except: false,
                destination_except: false,
                source_constrained: false,
                destination_constrained: false,
                destination_addresses: vec![],
                source_addresses: vec![],
                protocols: vec!["icmp".into()],
                source_ports: vec![],
                destination_ports: vec![],
                dscp_values: vec![],
                action: "discard".into(),
                next_term: false,
                count: String::new(),
                log: false,
                syslog: false,
                reject_message_type: String::new(),
                policer: String::new(),
                routing_instance: String::new(),
                forwarding_class: String::new(),
                dscp_rewrite: None,
                tcp_flags: None,
                tcp_flags_forbidden: None,
                tcp_flags_unparseable: false,
                icmp_type_unrepresentable: false,
                icmp_code_unrepresentable: false,
                dscp_match_unrepresentable: false,
                ports_unrepresentable: false,
                address_unrepresentable: false,
                is_fragment: false,
                icmp_types: vec![],
                icmp_codes: vec![],
                flex_match: None,
                source_ports_except: vec![],
                destination_ports_except: vec![],
            }],
        }],
        &[],
    );
    // ICMP should be discarded
    let result = evaluate_filter(
        &state,
        "inet:proto-filter",
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        PROTO_ICMP,
        0,
        0,
        0,
        TermMatchExtra::default(),
    );
    assert_eq!(result.action, FilterAction::Discard);

    // TCP should pass (no match)
    let result = evaluate_filter(
        &state,
        "inet:proto-filter",
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        PROTO_TCP,
        1234,
        80,
        0,
        TermMatchExtra::default(),
    );
    assert_eq!(result.action, FilterAction::Accept);
}

#[test]
fn dscp_rewrite_action() {
    let state = make_filter_state(
        &[FirewallFilterSnapshot {
            name: "dscp-rewrite".into(),
            family: "inet".into(),
            terms: vec![FirewallTermSnapshot {
                name: "mark-ef".into(),
                source_except: false,
                destination_except: false,
                source_constrained: false,
                destination_constrained: false,
                destination_addresses: vec![],
                source_addresses: vec![],
                protocols: vec!["udp".into()],
                source_ports: vec![],
                destination_ports: vec!["5060".into()],
                dscp_values: vec![],
                action: "accept".into(),
                next_term: false,
                count: String::new(),
                log: false,
                syslog: false,
                reject_message_type: String::new(),
                policer: String::new(),
                routing_instance: String::new(),
                forwarding_class: String::new(),
                dscp_rewrite: Some(46), // EF
                tcp_flags: None,
                tcp_flags_forbidden: None,
                tcp_flags_unparseable: false,
                icmp_type_unrepresentable: false,
                icmp_code_unrepresentable: false,
                dscp_match_unrepresentable: false,
                ports_unrepresentable: false,
                address_unrepresentable: false,
                is_fragment: false,
                icmp_types: vec![],
                icmp_codes: vec![],
                flex_match: None,
                source_ports_except: vec![],
                destination_ports_except: vec![],
            }],
        }],
        &[],
    );
    let result = evaluate_filter(
        &state,
        "inet:dscp-rewrite",
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        PROTO_UDP,
        54321,
        5060,
        0,
        TermMatchExtra::default(),
    );
    assert_eq!(result.action, FilterAction::Accept);
    assert_eq!(result.dscp_rewrite, Some(46));
}

#[test]
fn dscp_rewrite_action_allows_default_zero() {
    let state = make_filter_state(
        &[FirewallFilterSnapshot {
            name: "dscp-default".into(),
            family: "inet".into(),
            terms: vec![FirewallTermSnapshot {
                name: "mark-default".into(),
                source_except: false,
                destination_except: false,
                source_constrained: false,
                destination_constrained: false,
                destination_addresses: vec![],
                source_addresses: vec![],
                protocols: vec!["udp".into()],
                source_ports: vec![],
                destination_ports: vec!["5060".into()],
                dscp_values: vec![],
                action: "accept".into(),
                next_term: false,
                count: String::new(),
                log: false,
                syslog: false,
                reject_message_type: String::new(),
                policer: String::new(),
                routing_instance: String::new(),
                forwarding_class: String::new(),
                dscp_rewrite: Some(0),
                tcp_flags: None,
                tcp_flags_forbidden: None,
                tcp_flags_unparseable: false,
                icmp_type_unrepresentable: false,
                icmp_code_unrepresentable: false,
                dscp_match_unrepresentable: false,
                ports_unrepresentable: false,
                address_unrepresentable: false,
                is_fragment: false,
                icmp_types: vec![],
                icmp_codes: vec![],
                flex_match: None,
                source_ports_except: vec![],
                destination_ports_except: vec![],
            }],
        }],
        &[],
    );
    let result = evaluate_filter(
        &state,
        "inet:dscp-default",
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        PROTO_UDP,
        54321,
        5060,
        0,
        TermMatchExtra::default(),
    );
    assert_eq!(result.action, FilterAction::Accept);
    assert_eq!(result.dscp_rewrite, Some(0));
}

// #4514: a legacy single-rate `firewall policer` with `then discard` must be
// ENFORCED on the dataplane — traffic above the committed token bucket is
// dropped, in-rate traffic passes, and the metered term is flow-cache-safe (the
// runtime handle is cached and re-metered, never frozen as a static verdict).
// Before #4514 the term's policer was parsed into a `state.policers` map that
// nothing consumed, so the rate-limit was silently unenforced (fail-open). This
// test drops with the compiler lowering removed (RED on revert).
#[test]
fn single_rate_policer_discard_is_enforced() {
    let state = make_filter_state(
        &[FirewallFilterSnapshot {
            name: "rl".into(),
            family: "inet".into(),
            terms: vec![
                FirewallTermSnapshot {
                    name: "meter".into(),
                    // Fall-through modifier-only term (`then policer P`): the
                    // policer meters every matched (UDP) packet.
                    protocols: vec!["udp".into()],
                    policer: "rl-1kbps".into(),
                    ..Default::default()
                },
                FirewallTermSnapshot {
                    name: "unpoliced".into(),
                    protocols: vec!["tcp".into()],
                    action: "accept".into(),
                    ..Default::default()
                },
            ],
        }],
        &[PolicerSnapshot {
            name: "rl-1kbps".into(),
            bandwidth_bps: 8_000, // 1000 bytes/sec committed rate
            burst_bytes: 1_000,   // 1000-byte bucket
            discard_excess: true,
        }],
    );

    let filter = state.filters.get("inet:rl").expect("compiled filter");
    // The single-rate policer is lowered into the metered three-color runtime.
    assert!(
        filter.has_three_color_policer_terms,
        "single-rate policer must link a metered runtime"
    );

    let meter = |bytes: u64| {
        evaluate_filter_ref_tx_selection_runtime_counted(
            filter,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            PROTO_UDP,
            12345,
            5000,
            0,
            TermMatchExtra::default(),
            bytes,
            0, // now_ns fixed so no refill between packets
        )
    };

    // First packet drains most of the 1000-byte bucket — conforming (passes).
    let first = meter(900);
    assert!(!first.policer_drop, "in-rate packet must pass");
    // Next packet exceeds the remaining ~100 tokens — non-conforming (dropped).
    let second = meter(900);
    assert!(
        second.policer_drop,
        "traffic above the committed rate must be discarded"
    );

    // A non-policed term is unaffected: TCP matches the second term (no policer)
    // and is accepted without a policer drop.
    let unpoliced = evaluate_filter_ref_tx_selection_runtime_counted(
        filter,
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        PROTO_TCP,
        12345,
        5000,
        0,
        TermMatchExtra::default(),
        9_000,
        0,
    );
    assert!(
        !unpoliced.policer_drop,
        "a non-policed term must not be policed"
    );
    assert_eq!(unpoliced.action, FilterAction::Accept);

    // The metered term is NOT flow-cached as a static verdict: the cached
    // TX-selection descriptor carries the policer runtime handle so it re-meters
    // on every hit (mirrors three-color cache treatment).
    let cached = evaluate_filter_ref_tx_selection_cached(
        filter,
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        PROTO_UDP,
        12345,
        5000,
        0,
    );
    assert_eq!(
        cached.three_color_policers.len(),
        1,
        "policed term must cache the runtime handle for per-hit re-metering"
    );

    // Status exposes the lowered runtime as a single-rate policer.
    let status = state.three_color_policer_statuses();
    assert_eq!(status.len(), 1);
    assert_eq!(status[0].mode, "single-rate");
    assert!(status[0].drop_packets >= 1, "a drop must be counted");
}

#[test]
fn three_color_runtime_ids_and_miss_path_counters_are_stable() {
    let state = make_filter_state_with_three_color(
        &[FirewallFilterSnapshot {
            name: "policed".into(),
            family: "inet".into(),
            terms: vec![FirewallTermSnapshot {
                name: "meter".into(),
                action: "accept".into(),
                policer: "alpha".into(),
                ..Default::default()
            }],
        }],
        &[
            ThreeColorPolicerSnapshot {
                name: "zeta".into(),
                mode: "single-rate".into(),
                color_blind: true,
                committed_rate_bytes_per_sec: 1,
                committed_burst_bytes: 100,
                peak_or_excess_burst_bytes: 50,
                then_action: "discard".into(),
                ..Default::default()
            },
            ThreeColorPolicerSnapshot {
                name: "alpha".into(),
                mode: "single-rate".into(),
                color_blind: true,
                committed_rate_bytes_per_sec: 1,
                committed_burst_bytes: 100,
                peak_or_excess_burst_bytes: 50,
                then_action: "discard".into(),
                ..Default::default()
            },
        ],
    );

    let ids = state
        .three_color_policers
        .iter()
        .map(|runtime| (runtime.id, runtime.name.as_ref().to_string()))
        .collect::<Vec<_>>();
    assert_eq!(
        ids,
        vec![
            (three_color_policer_runtime_id("alpha"), "alpha".into()),
            (three_color_policer_runtime_id("zeta"), "zeta".into()),
        ]
    );

    let filter = state.filters.get("inet:policed").unwrap();
    assert!(filter.has_three_color_policer_terms);
    let first = evaluate_filter_ref_tx_selection_runtime_counted(
        filter,
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        PROTO_UDP,
        12345,
        5000,
        0,
        TermMatchExtra::default(),
        100,
        0,
    );
    assert!(!first.policer_drop);

    let second = evaluate_filter_ref_tx_selection_runtime_counted(
        filter,
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        PROTO_UDP,
        12345,
        5000,
        0,
        TermMatchExtra::default(),
        51,
        0,
    );
    assert!(second.policer_drop);

    let status = state.three_color_policer_statuses();
    let alpha = status.iter().find(|item| item.name == "alpha").unwrap();
    assert_eq!(alpha.mode, "single-rate");
    assert!(alpha.color_blind);
    assert_eq!(alpha.green_packets, 1);
    assert_eq!(alpha.green_bytes, 100);
    assert_eq!(alpha.red_packets, 1);
    assert_eq!(alpha.red_bytes, 51);
    assert_eq!(alpha.drop_packets, 1);
    assert_eq!(alpha.drop_bytes, 51);
}

#[test]
fn flow_cache_hits_run_three_color_policer() {
    let state = make_filter_state_with_three_color(
        &[FirewallFilterSnapshot {
            name: "policed".into(),
            family: "inet".into(),
            terms: vec![FirewallTermSnapshot {
                name: "meter".into(),
                action: "accept".into(),
                policer: "cache-pol".into(),
                ..Default::default()
            }],
        }],
        &[ThreeColorPolicerSnapshot {
            name: "cache-pol".into(),
            mode: "single-rate".into(),
            color_blind: true,
            committed_rate_bytes_per_sec: 1,
            committed_burst_bytes: 100,
            peak_or_excess_burst_bytes: 50,
            then_action: "discard".into(),
            ..Default::default()
        }],
    );

    let filter = state.filters.get("inet:policed").unwrap();
    let cached = evaluate_filter_ref_tx_selection_cached(
        filter,
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        PROTO_UDP,
        12345,
        5000,
        0,
    );
    assert_eq!(cached.three_color_policers.len(), 1);

    let first = apply_cached_three_color_policers(&cached.three_color_policers, 0, 100);
    assert!(!first.drop);
    let second = apply_cached_three_color_policers(&cached.three_color_policers, 0, 51);
    assert!(second.drop);

    let status = state.three_color_policer_statuses();
    assert_eq!(status[0].green_packets, 1);
    assert_eq!(status[0].red_packets, 1);
    assert_eq!(status[0].drop_packets, 1);
}

// #4566: three fall-through three-color policer terms on ONE flow. The cached
// TX-selection replay MUST carry all three policers — the previous two-`Option`
// layout silently dropped the 3rd, so its rate limit was never enforced on the
// cached path. RED on revert: `len()` is 2 and `gamma` never meters.
#[test]
fn flow_cache_hit_runs_all_three_fall_through_policers() {
    fn policer(name: &str) -> ThreeColorPolicerSnapshot {
        ThreeColorPolicerSnapshot {
            name: name.into(),
            mode: "single-rate".into(),
            color_blind: true,
            // Generous committed burst so a single 100-byte packet is GREEN on
            // every policer — the assertion checks each one metered, not that it
            // dropped.
            committed_rate_bytes_per_sec: 1,
            committed_burst_bytes: 10_000,
            peak_or_excess_burst_bytes: 5_000,
            then_action: "discard".into(),
            ..Default::default()
        }
    }
    fn fall_through_term(name: &str, policer: &str, terminating: bool) -> FirewallTermSnapshot {
        FirewallTermSnapshot {
            name: name.into(),
            // Empty action => fall-through (continue_term); a terminating
            // "accept" stops the walk but still merges its own policer first.
            action: if terminating { "accept".into() } else { String::new() },
            policer: policer.into(),
            ..Default::default()
        }
    }

    let state = make_filter_state_with_three_color(
        &[FirewallFilterSnapshot {
            name: "policed".into(),
            family: "inet".into(),
            terms: vec![
                fall_through_term("t-alpha", "alpha", false),
                fall_through_term("t-beta", "beta", false),
                fall_through_term("t-gamma", "gamma", true),
            ],
        }],
        &[policer("alpha"), policer("beta"), policer("gamma")],
    );

    let filter = state.filters.get("inet:policed").unwrap();
    let cached = evaluate_filter_ref_tx_selection_cached(
        filter,
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        PROTO_UDP,
        12345,
        5000,
        0,
    );
    // The 3rd policer must NOT be truncated out of the cached set (RED: 2).
    assert_eq!(
        cached.three_color_policers.len(),
        3,
        "cached path must carry all three fall-through policers"
    );

    // One cached-path packet must meter ALL THREE policers. On revert `gamma` is
    // dropped from the cached set and never records a green packet.
    let action = apply_cached_three_color_policers(&cached.three_color_policers, 0, 100);
    assert!(!action.drop);

    let status = state.three_color_policer_statuses();
    for name in ["alpha", "beta", "gamma"] {
        let item = status
            .iter()
            .find(|item| item.name == name)
            .unwrap_or_else(|| panic!("policer {name} missing from status"));
        assert_eq!(
            item.green_packets, 1,
            "policer {name} must meter the cached-path packet"
        );
    }
}

// #4566 unchanged-behavior guard: a flow with exactly TWO fall-through policer
// terms still caches both and meters both — identical to pre-fix behavior for
// the common case (the fix only affects the 3rd+ policer).
#[test]
fn flow_cache_hit_runs_both_fall_through_policers() {
    fn policer(name: &str) -> ThreeColorPolicerSnapshot {
        ThreeColorPolicerSnapshot {
            name: name.into(),
            mode: "single-rate".into(),
            color_blind: true,
            committed_rate_bytes_per_sec: 1,
            committed_burst_bytes: 10_000,
            peak_or_excess_burst_bytes: 5_000,
            then_action: "discard".into(),
            ..Default::default()
        }
    }

    let state = make_filter_state_with_three_color(
        &[FirewallFilterSnapshot {
            name: "policed".into(),
            family: "inet".into(),
            terms: vec![
                FirewallTermSnapshot {
                    name: "t-alpha".into(),
                    action: String::new(),
                    policer: "alpha".into(),
                    ..Default::default()
                },
                FirewallTermSnapshot {
                    name: "t-beta".into(),
                    action: "accept".into(),
                    policer: "beta".into(),
                    ..Default::default()
                },
            ],
        }],
        &[policer("alpha"), policer("beta")],
    );

    let filter = state.filters.get("inet:policed").unwrap();
    let cached = evaluate_filter_ref_tx_selection_cached(
        filter,
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        PROTO_UDP,
        12345,
        5000,
        0,
    );
    assert_eq!(cached.three_color_policers.len(), 2);

    let action = apply_cached_three_color_policers(&cached.three_color_policers, 0, 100);
    assert!(!action.drop);
    let status = state.three_color_policer_statuses();
    for name in ["alpha", "beta"] {
        let item = status.iter().find(|item| item.name == name).unwrap();
        assert_eq!(item.green_packets, 1);
    }
}

#[test]
fn equivalent_snapshot_refresh_preserves_three_color_state_and_counters() {
    let filters = [FirewallFilterSnapshot {
        name: "policed".into(),
        family: "inet".into(),
        terms: vec![FirewallTermSnapshot {
            name: "meter".into(),
            action: "accept".into(),
            policer: "stable-pol".into(),
            ..Default::default()
        }],
    }];
    let policers = [ThreeColorPolicerSnapshot {
        name: "stable-pol".into(),
        mode: "single-rate".into(),
        color_blind: true,
        committed_rate_bytes_per_sec: 1,
        committed_burst_bytes: 100,
        peak_or_excess_burst_bytes: 50,
        then_action: "discard".into(),
        ..Default::default()
    }];

    let state = make_filter_state_with_three_color(&filters, &policers);
    let filter = state.filters.get("inet:policed").unwrap();
    let green = evaluate_filter_ref_tx_selection_runtime_counted(
        filter,
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        PROTO_UDP,
        12345,
        5000,
        0,
        TermMatchExtra::default(),
        100,
        0,
    );
    assert!(!green.policer_drop);

    let refreshed = parse_filter_state_with_three_color_preserving(
        &filters,
        &[],
        &policers,
        &[],
        "",
        "",
        Some(&state),
    )
    .expect("filter state compiles");
    assert!(
        std::sync::Arc::ptr_eq(
            &state.three_color_policers[0],
            &refreshed.three_color_policers[0]
        ),
        "compatible refresh must reuse the live runtime, not clone state"
    );
    let refreshed_filter = refreshed.filters.get("inet:policed").unwrap();
    let red = evaluate_filter_ref_tx_selection_runtime_counted(
        refreshed_filter,
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        PROTO_UDP,
        12345,
        5000,
        0,
        TermMatchExtra::default(),
        51,
        0,
    );

    assert!(
        red.policer_drop,
        "equivalent snapshot refresh must preserve consumed token state"
    );
    let status = refreshed.three_color_policer_statuses();
    assert_eq!(status[0].green_packets, 1);
    assert_eq!(status[0].green_bytes, 100);
    assert_eq!(status[0].red_packets, 1);
    assert_eq!(status[0].red_bytes, 51);
    assert_eq!(status[0].drop_packets, 1);
    assert_eq!(status[0].drop_bytes, 51);
}

#[test]
fn three_color_adding_lower_sorted_policer_does_not_reset_existing_runtime() {
    let filters = [FirewallFilterSnapshot {
        name: "policed".into(),
        family: "inet".into(),
        terms: vec![FirewallTermSnapshot {
            name: "meter".into(),
            action: "accept".into(),
            policer: "stable-pol".into(),
            ..Default::default()
        }],
    }];
    let stable = ThreeColorPolicerSnapshot {
        name: "stable-pol".into(),
        mode: "single-rate".into(),
        color_blind: true,
        committed_rate_bytes_per_sec: 1,
        committed_burst_bytes: 100,
        peak_or_excess_burst_bytes: 50,
        then_action: "discard".into(),
        ..Default::default()
    };
    let inserted = ThreeColorPolicerSnapshot {
        name: "aaa-new-pol".into(),
        ..stable.clone()
    };

    let state = make_filter_state_with_three_color(&filters, &[stable.clone()]);
    let filter = state.filters.get("inet:policed").unwrap();
    let first = evaluate_filter_ref_tx_selection_runtime_counted(
        filter,
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        PROTO_UDP,
        12345,
        5000,
        0,
        TermMatchExtra::default(),
        100,
        0,
    );
    assert!(!first.policer_drop);

    let refreshed = parse_filter_state_with_three_color_preserving(
        &filters,
        &[],
        &[inserted, stable],
        &[],
        "",
        "",
        Some(&state),
    )
    .expect("filter state compiles");
    let previous_runtime = state
        .three_color_policer_by_name
        .get("stable-pol")
        .expect("previous runtime");
    let refreshed_runtime = refreshed
        .three_color_policer_by_name
        .get("stable-pol")
        .expect("refreshed runtime");
    assert!(
        std::sync::Arc::ptr_eq(previous_runtime, refreshed_runtime),
        "adding an alphabetically earlier policer must not reset stable-pol"
    );
    assert_eq!(
        refreshed_runtime.id,
        three_color_policer_runtime_id("stable-pol")
    );

    let refreshed_filter = refreshed.filters.get("inet:policed").unwrap();
    let second = evaluate_filter_ref_tx_selection_runtime_counted(
        refreshed_filter,
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        PROTO_UDP,
        12345,
        5000,
        0,
        TermMatchExtra::default(),
        51,
        0,
    );
    assert!(
        second.policer_drop,
        "refreshed stable-pol must retain tokens consumed before insertion"
    );
}

#[test]
fn three_color_compatible_refresh_observes_old_runtime_mutations_after_rebuild() {
    let filters = [FirewallFilterSnapshot {
        name: "policed".into(),
        family: "inet".into(),
        terms: vec![FirewallTermSnapshot {
            name: "meter".into(),
            action: "accept".into(),
            policer: "stable-pol".into(),
            ..Default::default()
        }],
    }];
    let policers = [ThreeColorPolicerSnapshot {
        name: "stable-pol".into(),
        mode: "single-rate".into(),
        color_blind: true,
        committed_rate_bytes_per_sec: 1,
        committed_burst_bytes: 100,
        peak_or_excess_burst_bytes: 50,
        then_action: "discard".into(),
        ..Default::default()
    }];

    let state = make_filter_state_with_three_color(&filters, &policers);
    let refreshed = parse_filter_state_with_three_color_preserving(
        &filters,
        &[],
        &policers,
        &[],
        "",
        "",
        Some(&state),
    )
    .expect("filter state compiles");
    assert!(std::sync::Arc::ptr_eq(
        &state.three_color_policers[0],
        &refreshed.three_color_policers[0]
    ));

    let old_filter = state.filters.get("inet:policed").unwrap();
    let old_green = evaluate_filter_ref_tx_selection_runtime_counted(
        old_filter,
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        PROTO_UDP,
        12345,
        5000,
        0,
        TermMatchExtra::default(),
        100,
        0,
    );
    assert!(!old_green.policer_drop);

    let refreshed_filter = refreshed.filters.get("inet:policed").unwrap();
    let refreshed_red = evaluate_filter_ref_tx_selection_runtime_counted(
        refreshed_filter,
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        PROTO_UDP,
        12345,
        5000,
        0,
        TermMatchExtra::default(),
        51,
        0,
    );

    assert!(
        refreshed_red.policer_drop,
        "post-rebuild mutations through the old handle must be visible"
    );
    let status = refreshed.three_color_policer_statuses();
    assert_eq!(status[0].green_packets, 1);
    assert_eq!(status[0].red_packets, 1);
    assert_eq!(status[0].drop_packets, 1);
}

#[test]
fn changed_snapshot_shape_resets_three_color_runtime_state() {
    let filters = [FirewallFilterSnapshot {
        name: "policed".into(),
        family: "inet".into(),
        terms: vec![FirewallTermSnapshot {
            name: "meter".into(),
            action: "accept".into(),
            policer: "stable-pol".into(),
            ..Default::default()
        }],
    }];
    let original = [ThreeColorPolicerSnapshot {
        name: "stable-pol".into(),
        mode: "single-rate".into(),
        color_blind: true,
        committed_rate_bytes_per_sec: 1,
        committed_burst_bytes: 100,
        peak_or_excess_burst_bytes: 50,
        then_action: "discard".into(),
        ..Default::default()
    }];
    let changed = [ThreeColorPolicerSnapshot {
        committed_burst_bytes: 200,
        ..original[0].clone()
    }];

    let state = make_filter_state_with_three_color(&filters, &original);
    let filter = state.filters.get("inet:policed").unwrap();
    let first = evaluate_filter_ref_tx_selection_runtime_counted(
        filter,
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        PROTO_UDP,
        12345,
        5000,
        0,
        TermMatchExtra::default(),
        100,
        0,
    );
    assert!(!first.policer_drop);

    let refreshed = parse_filter_state_with_three_color_preserving(
        &filters,
        &[],
        &changed,
        &[],
        "",
        "",
        Some(&state),
    )
    .expect("filter state compiles");
    let refreshed_filter = refreshed.filters.get("inet:policed").unwrap();
    let second = evaluate_filter_ref_tx_selection_runtime_counted(
        refreshed_filter,
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        PROTO_UDP,
        12345,
        5000,
        0,
        TermMatchExtra::default(),
        200,
        0,
    );

    assert!(
        !second.policer_drop,
        "changed token shape should create a fresh runtime with new burst"
    );
    let status = refreshed.three_color_policer_statuses();
    assert_eq!(status[0].green_packets, 1);
    assert_eq!(status[0].green_bytes, 200);
}

#[test]
fn unsupported_three_color_snapshots_fail_closed_in_rust_compiler() {
    let cases = vec![
        (
            "color-aware",
            ThreeColorPolicerSnapshot {
                name: "bad-pol".into(),
                mode: "single-rate".into(),
                color_blind: false,
                committed_rate_bytes_per_sec: 1_000,
                committed_burst_bytes: 100,
                peak_or_excess_burst_bytes: 50,
                then_action: "discard".into(),
                ..Default::default()
            },
        ),
        (
            "non-discard-action",
            ThreeColorPolicerSnapshot {
                name: "bad-pol".into(),
                mode: "single-rate".into(),
                color_blind: true,
                committed_rate_bytes_per_sec: 1_000,
                committed_burst_bytes: 100,
                peak_or_excess_burst_bytes: 50,
                then_action: "loss-priority high".into(),
                ..Default::default()
            },
        ),
        (
            "invalid-token-shape",
            ThreeColorPolicerSnapshot {
                name: "bad-pol".into(),
                mode: "single-rate".into(),
                color_blind: true,
                committed_rate_bytes_per_sec: 0,
                committed_burst_bytes: 100,
                peak_or_excess_burst_bytes: 50,
                then_action: "discard".into(),
                ..Default::default()
            },
        ),
        (
            "mode-drift",
            ThreeColorPolicerSnapshot {
                name: "bad-pol".into(),
                mode: "single_rate".into(),
                color_blind: true,
                committed_rate_bytes_per_sec: 1_000,
                committed_burst_bytes: 100,
                peak_or_excess_burst_bytes: 50,
                then_action: "discard".into(),
                ..Default::default()
            },
        ),
        (
            "pir-below-cir",
            ThreeColorPolicerSnapshot {
                name: "bad-pol".into(),
                mode: "two-rate".into(),
                color_blind: true,
                committed_rate_bytes_per_sec: 1_000,
                committed_burst_bytes: 100,
                peak_or_excess_rate_bytes_per_sec: 999,
                peak_or_excess_burst_bytes: 100,
                then_action: "discard".into(),
                ..Default::default()
            },
        ),
        (
            "zero-pir-two-rate",
            ThreeColorPolicerSnapshot {
                name: "bad-pol".into(),
                mode: "two-rate".into(),
                color_blind: true,
                committed_rate_bytes_per_sec: 1_000,
                committed_burst_bytes: 100,
                peak_or_excess_rate_bytes_per_sec: 0,
                peak_or_excess_burst_bytes: 100,
                then_action: "discard".into(),
                ..Default::default()
            },
        ),
        (
            "zero-committed-burst-two-rate",
            ThreeColorPolicerSnapshot {
                name: "bad-pol".into(),
                mode: "two-rate".into(),
                color_blind: true,
                committed_rate_bytes_per_sec: 1_000,
                committed_burst_bytes: 0,
                peak_or_excess_rate_bytes_per_sec: 2_000,
                peak_or_excess_burst_bytes: 100,
                then_action: "discard".into(),
                ..Default::default()
            },
        ),
        (
            "peak-burst-below-committed-burst",
            ThreeColorPolicerSnapshot {
                name: "bad-pol".into(),
                mode: "two-rate".into(),
                color_blind: true,
                committed_rate_bytes_per_sec: 1_000,
                committed_burst_bytes: 100,
                peak_or_excess_rate_bytes_per_sec: 2_000,
                peak_or_excess_burst_bytes: 99,
                then_action: "discard".into(),
                ..Default::default()
            },
        ),
        (
            "zero-peak-burst-two-rate",
            ThreeColorPolicerSnapshot {
                name: "bad-pol".into(),
                mode: "two-rate".into(),
                color_blind: true,
                committed_rate_bytes_per_sec: 1_000,
                committed_burst_bytes: 100,
                peak_or_excess_rate_bytes_per_sec: 2_000,
                peak_or_excess_burst_bytes: 0,
                then_action: "discard".into(),
                ..Default::default()
            },
        ),
        (
            "zero-excess-burst",
            ThreeColorPolicerSnapshot {
                name: "bad-pol".into(),
                mode: "single-rate".into(),
                color_blind: true,
                committed_rate_bytes_per_sec: 1_000,
                committed_burst_bytes: 100,
                peak_or_excess_burst_bytes: 0,
                then_action: "discard".into(),
                ..Default::default()
            },
        ),
        (
            "serde-defaulted-malformed",
            serde_json::from_value(serde_json::json!({
                "name": "bad-pol",
                "color_blind": true,
                "then_action": "discard"
            }))
            .expect("defaulted malformed snapshot decodes"),
        ),
    ];

    for (name, snapshot) in cases {
        let state = make_filter_state_with_three_color(
            &[FirewallFilterSnapshot {
                name: format!("policed-{name}"),
                family: "inet".into(),
                terms: vec![FirewallTermSnapshot {
                    name: "meter".into(),
                    action: "accept".into(),
                    policer: "bad-pol".into(),
                    ..Default::default()
                }],
            }],
            &[snapshot],
        );

        let filter = state
            .filters
            .get(&format!("inet:policed-{name}"))
            .expect("compiled filter");
        assert!(
            filter.has_three_color_policer_terms,
            "{name}: unsupported snapshot must still link a fail-closed runtime"
        );

        let result = evaluate_filter_ref_tx_selection_runtime_counted(
            filter,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            PROTO_UDP,
            12345,
            5000,
            0,
            TermMatchExtra::default(),
            1,
            0,
        );

        assert!(
            result.policer_drop,
            "{name}: unsupported snapshot must drop matching traffic"
        );
        let status = state.three_color_policer_statuses();
        assert_eq!(status.len(), 1, "{name}: status should expose runtime");
        assert_eq!(status[0].mode, "unsupported", "{name}: mode");
        assert_eq!(status[0].red_packets, 1, "{name}: red packets");
        assert_eq!(status[0].drop_packets, 1, "{name}: drop packets");
    }
}

#[test]
fn three_color_empty_then_action_uses_default_discard() {
    let state = make_filter_state_with_three_color(
        &[FirewallFilterSnapshot {
            name: "policed".into(),
            family: "inet".into(),
            terms: vec![FirewallTermSnapshot {
                name: "meter".into(),
                action: "accept".into(),
                policer: "default-action-pol".into(),
                ..Default::default()
            }],
        }],
        &[ThreeColorPolicerSnapshot {
            name: "default-action-pol".into(),
            mode: "single-rate".into(),
            color_blind: true,
            committed_rate_bytes_per_sec: 1,
            committed_burst_bytes: 100,
            peak_or_excess_burst_bytes: 50,
            then_action: String::new(),
            ..Default::default()
        }],
    );

    let filter = state.filters.get("inet:policed").unwrap();
    let green = evaluate_filter_ref_tx_selection_runtime_counted(
        filter,
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        PROTO_UDP,
        12345,
        5000,
        0,
        TermMatchExtra::default(),
        100,
        0,
    );
    let red = evaluate_filter_ref_tx_selection_runtime_counted(
        filter,
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        PROTO_UDP,
        12345,
        5000,
        0,
        TermMatchExtra::default(),
        51,
        0,
    );

    assert!(!green.policer_drop);
    assert!(red.policer_drop);
    let status = state.three_color_policer_statuses();
    assert_eq!(status[0].mode, "single-rate");
    assert_eq!(status[0].green_packets, 1);
    assert_eq!(status[0].red_packets, 1);
    assert_eq!(status[0].drop_packets, 1);
}

#[test]
fn cached_three_color_descriptor_dedupes_without_vec_allocation() {
    let state = make_filter_state_with_three_color(
        &[
            FirewallFilterSnapshot {
                name: "in".into(),
                family: "inet".into(),
                terms: vec![FirewallTermSnapshot {
                    name: "meter-in".into(),
                    action: "accept".into(),
                    policer: "same-pol".into(),
                    ..Default::default()
                }],
            },
            FirewallFilterSnapshot {
                name: "out".into(),
                family: "inet".into(),
                terms: vec![FirewallTermSnapshot {
                    name: "meter-out".into(),
                    action: "accept".into(),
                    policer: "same-pol".into(),
                    ..Default::default()
                }],
            },
        ],
        &[ThreeColorPolicerSnapshot {
            name: "same-pol".into(),
            mode: "single-rate".into(),
            color_blind: true,
            committed_rate_bytes_per_sec: 1,
            committed_burst_bytes: 100,
            peak_or_excess_burst_bytes: 50,
            then_action: "discard".into(),
            ..Default::default()
        }],
    );

    let mut combined = evaluate_filter_ref_tx_selection_cached(
        state.filters.get("inet:out").unwrap(),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        PROTO_UDP,
        12345,
        5000,
        0,
    )
    .three_color_policers;
    combined.extend(
        evaluate_filter_ref_tx_selection_cached(
            state.filters.get("inet:in").unwrap(),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            PROTO_UDP,
            12345,
            5000,
            0,
        )
        .three_color_policers,
    );

    assert_eq!(combined.len(), 1);
    assert!(!apply_cached_three_color_policers(&combined, 0, 100).drop);
    assert!(apply_cached_three_color_policers(&combined, 0, 51).drop);
}

#[test]
fn multiple_terms_first_match_wins() {
    let state = make_filter_state(
        &[FirewallFilterSnapshot {
            name: "multi".into(),
            family: "inet".into(),
            terms: vec![
                FirewallTermSnapshot {
                    name: "allow-dns".into(),
                    source_except: false,
                    destination_except: false,
                    source_constrained: false,
                    destination_constrained: false,
                    destination_addresses: vec![],
                    source_addresses: vec![],
                    protocols: vec!["udp".into()],
                    source_ports: vec![],
                    destination_ports: vec!["53".into()],
                    dscp_values: vec![],
                    action: "accept".into(),
                    next_term: false,
                    count: String::new(),
                    log: false,
                    syslog: false,
                    reject_message_type: String::new(),
                    policer: String::new(),
                    routing_instance: String::new(),
                    forwarding_class: String::new(),
                    dscp_rewrite: None,
                    tcp_flags: None,
                    tcp_flags_forbidden: None,
                    tcp_flags_unparseable: false,
                icmp_type_unrepresentable: false,
                icmp_code_unrepresentable: false,
                dscp_match_unrepresentable: false,
                ports_unrepresentable: false,
                address_unrepresentable: false,
                    is_fragment: false,
                    icmp_types: vec![],
                    icmp_codes: vec![],
                    flex_match: None,
                    source_ports_except: vec![],
                    destination_ports_except: vec![],
                },
                FirewallTermSnapshot {
                    name: "deny-all-udp".into(),
                    source_except: false,
                    destination_except: false,
                    source_constrained: false,
                    destination_constrained: false,
                    destination_addresses: vec![],
                    source_addresses: vec![],
                    protocols: vec!["udp".into()],
                    source_ports: vec![],
                    destination_ports: vec![],
                    dscp_values: vec![],
                    action: "discard".into(),
                    next_term: false,
                    count: String::new(),
                    log: false,
                    syslog: false,
                    reject_message_type: String::new(),
                    policer: String::new(),
                    routing_instance: String::new(),
                    forwarding_class: String::new(),
                    dscp_rewrite: None,
                    tcp_flags: None,
                    tcp_flags_forbidden: None,
                    tcp_flags_unparseable: false,
                icmp_type_unrepresentable: false,
                icmp_code_unrepresentable: false,
                dscp_match_unrepresentable: false,
                ports_unrepresentable: false,
                address_unrepresentable: false,
                    is_fragment: false,
                    icmp_types: vec![],
                    icmp_codes: vec![],
                    flex_match: None,
                    source_ports_except: vec![],
                    destination_ports_except: vec![],
                },
            ],
        }],
        &[],
    );
    // DNS should be accepted (first term wins)
    let result = evaluate_filter(
        &state,
        "inet:multi",
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        PROTO_UDP,
        12345,
        53,
        0,
        TermMatchExtra::default(),
    );
    assert_eq!(result.action, FilterAction::Accept);

    // Other UDP should be discarded (second term)
    let result = evaluate_filter(
        &state,
        "inet:multi",
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        PROTO_UDP,
        12345,
        1234,
        0,
        TermMatchExtra::default(),
    );
    assert_eq!(result.action, FilterAction::Discard);
}

#[test]
fn source_dest_address_matching() {
    let state = make_filter_state(
        &[FirewallFilterSnapshot {
            name: "addr-filter".into(),
            family: "inet".into(),
            terms: vec![FirewallTermSnapshot {
                name: "deny-from-subnet".into(),
                source_except: false,
                destination_except: false,
                source_constrained: false,
                destination_constrained: false,
                source_addresses: vec!["192.168.1.0/24".into()],
                destination_addresses: vec!["10.0.0.0/8".into()],
                protocols: vec![],
                source_ports: vec![],
                destination_ports: vec![],
                dscp_values: vec![],
                action: "discard".into(),
                next_term: false,
                count: String::new(),
                log: false,
                syslog: false,
                reject_message_type: String::new(),
                policer: String::new(),
                routing_instance: String::new(),
                forwarding_class: String::new(),
                dscp_rewrite: None,
                tcp_flags: None,
                tcp_flags_forbidden: None,
                tcp_flags_unparseable: false,
                icmp_type_unrepresentable: false,
                icmp_code_unrepresentable: false,
                dscp_match_unrepresentable: false,
                ports_unrepresentable: false,
                address_unrepresentable: false,
                is_fragment: false,
                icmp_types: vec![],
                icmp_codes: vec![],
                flex_match: None,
                source_ports_except: vec![],
                destination_ports_except: vec![],
            }],
        }],
        &[],
    );
    // Matching src+dst
    let result = evaluate_filter(
        &state,
        "inet:addr-filter",
        IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        PROTO_TCP,
        1234,
        80,
        0,
        TermMatchExtra::default(),
    );
    assert_eq!(result.action, FilterAction::Discard);

    // Non-matching source
    let result = evaluate_filter(
        &state,
        "inet:addr-filter",
        IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        PROTO_TCP,
        1234,
        80,
        0,
        TermMatchExtra::default(),
    );
    assert_eq!(result.action, FilterAction::Accept);
}

#[test]
fn interface_filter_assignment() {
    let ifaces = vec![crate::InterfaceSnapshot {
        name: "ge-0/0/0.0".into(),
        ifindex: 5,
        filter_input_v4: "protect-RE".into(),
        filter_input_v6: "protect-RE-v6".into(),
        filter_output_v4: "egress-v4".into(),
        filter_output_v6: "egress-v6".into(),
        ..Default::default()
    }];
    let state = parse_filter_state(
        &[
            FirewallFilterSnapshot {
                name: "protect-RE".into(),
                family: "inet".into(),
                terms: vec![FirewallTermSnapshot {
                    name: "deny-all".into(),
                    action: "discard".into(),
                    ..Default::default()
                }],
            },
            FirewallFilterSnapshot {
                name: "protect-RE-v6".into(),
                family: "inet6".into(),
                terms: vec![FirewallTermSnapshot {
                    name: "deny-all".into(),
                    action: "discard".into(),
                    ..Default::default()
                }],
            },
            FirewallFilterSnapshot {
                name: "egress-v4".into(),
                family: "inet".into(),
                terms: vec![FirewallTermSnapshot {
                    name: "classify".into(),
                    action: "accept".into(),
                    forwarding_class: "bandwidth-10mb".into(),
                    protocols: vec!["tcp".into()],
                    destination_ports: vec!["5201".into()],
                    ..Default::default()
                }],
            },
            FirewallFilterSnapshot {
                name: "egress-v6".into(),
                family: "inet6".into(),
                terms: vec![FirewallTermSnapshot {
                    name: "classify".into(),
                    action: "accept".into(),
                    forwarding_class: "bandwidth-10mb".into(),
                    protocols: vec!["tcp".into()],
                    destination_ports: vec!["5201".into()],
                    ..Default::default()
                }],
            },
        ],
        &[],
        &ifaces,
        "",
        "",
    )
    .expect("filter state compiles");
    // v4 filter on ifindex 5
    let result = evaluate_interface_filter(
        &state,
        5,
        false,
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        PROTO_TCP,
        1234,
        80,
        0,
        TermMatchExtra::default(),
    );
    assert_eq!(result.action, FilterAction::Discard);

    // No filter on ifindex 6
    let result = evaluate_interface_filter(
        &state,
        6,
        false,
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        PROTO_TCP,
        1234,
        80,
        0,
        TermMatchExtra::default(),
    );
    assert_eq!(result.action, FilterAction::Accept);

    let result = evaluate_interface_output_filter(
        &state,
        5,
        false,
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        PROTO_TCP,
        1234,
        5201,
        0,
        TermMatchExtra::default(),
    );
    assert_eq!(result.forwarding_class.as_deref(), Some("bandwidth-10mb"));
}

/// #5151: FilterResult's forwarding-class accumulator is zero-allocation on the
/// warmed packet path. The default (accumulator init for every full v4/v6/lo0
/// eval) must be `None` — NOT an allocated empty `Arc::<str>::from("")`. A
/// filter eval that matches NO `then forwarding-class` term must yield `None`
/// (zero-alloc, semantically identical to the historical empty `""`), and a
/// term that DOES set a forwarding-class must yield `Some("class")`.
///
/// Fail-on-revert: reverting the default to `Arc::<str>::from("")` makes the
/// `None` assertions RED (the default becomes `Some("")`), and reverting the
/// `merge_matched_modifiers` write to a bare `Arc` clone fails to compile.
#[test]
fn filter_result_forwarding_class_defaults_none_zero_alloc() {
    // The accumulator init is `None` — no empty Arc header/data block allocated.
    assert_eq!(FilterResult::default().forwarding_class, None);

    let ifaces = vec![crate::InterfaceSnapshot {
        name: "ge-0/0/0.0".into(),
        ifindex: 5,
        filter_output_v4: "fc-egress".into(),
        filter_output_v6: "plain-egress".into(),
        ..Default::default()
    }];
    let state = parse_filter_state(
        &[
            // Output filter WITH a `then forwarding-class` term.
            FirewallFilterSnapshot {
                name: "fc-egress".into(),
                family: "inet".into(),
                terms: vec![FirewallTermSnapshot {
                    name: "classify".into(),
                    action: "accept".into(),
                    forwarding_class: "iperf-a".into(),
                    protocols: vec!["tcp".into()],
                    destination_ports: vec!["5201".into()],
                    ..Default::default()
                }],
            },
            // Output filter with NO forwarding-class term at all.
            FirewallFilterSnapshot {
                name: "plain-egress".into(),
                family: "inet6".into(),
                terms: vec![FirewallTermSnapshot {
                    name: "accept-all".into(),
                    action: "accept".into(),
                    ..Default::default()
                }],
            },
        ],
        &[],
        &ifaces,
        "",
        "",
    )
    .expect("filter state compiles");

    // A matching `then forwarding-class` term → Some("iperf-a").
    let matched = evaluate_interface_output_filter(
        &state,
        5,
        false,
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        PROTO_TCP,
        1234,
        5201,
        0,
        TermMatchExtra::default(),
    );
    assert_eq!(matched.forwarding_class.as_deref(), Some("iperf-a"));

    // No forwarding-class term matched → None (zero-alloc, == old empty "").
    let no_fc = evaluate_interface_output_filter(
        &state,
        5,
        true,
        IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
        IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2)),
        PROTO_TCP,
        1234,
        5201,
        0,
        TermMatchExtra::default(),
    );
    assert_eq!(no_fc.forwarding_class, None);
}

/// #5444: a matched term's `policer`, `routing-instance`, and
/// `forwarding-class` modifiers round-trip into the FilterResult accumulator.
///
/// This is a PERF change with a CORRECTNESS guard — NOT a RED-on-revert. The
/// fix converts the two owned `String` modifier slots
/// (`FilterTerm`/`FilterResult` `policer_name` and `routing_instance`) to
/// reference-counted `Arc<str>` so `merge_matched_modifiers` propagates them
/// with a refcount bump instead of a per-packet String heap allocation+copy on
/// the filter fast path. The VALUES carried are byte-identical either way, so a
/// revert to `String` would still pass this test. It exists so a future
/// refactor of the modifier merge cannot silently drop or mis-propagate a
/// modifier, and to pin the zero-alloc `None` default on the no-match path.
#[test]
fn filter_result_modifiers_roundtrip_5444() {
    let ifaces = vec![crate::InterfaceSnapshot {
        name: "ge-0/0/0.0".into(),
        ifindex: 9,
        filter_input_v4: "steer".into(),
        ..Default::default()
    }];
    let state = parse_filter_state(
        &[FirewallFilterSnapshot {
            name: "steer".into(),
            family: "inet".into(),
            terms: vec![FirewallTermSnapshot {
                name: "mark".into(),
                action: "accept".into(),
                protocols: vec!["tcp".into()],
                destination_ports: vec!["5201".into()],
                policer: "p-lo".into(),
                routing_instance: "blue".into(),
                forwarding_class: "assured".into(),
                ..Default::default()
            }],
        }],
        // #6540: `p-lo` must be DEFINED. Before #6540 this fixture named a
        // policer that existed nowhere, the compiler resolved it to `None`,
        // and the meter silently no-opped — so this test asserted the policer
        // NAME propagates into the accumulator while the rate limit it names
        // was not being enforced at all. It was an unwitting demonstration of
        // the bug. Meter-only (`discard_excess: false`) so the policer cannot
        // drop the probe packet and change the assertions below; this fixture
        // is about modifier propagation, not about metering.
        &[PolicerSnapshot {
            name: "p-lo".into(),
            bandwidth_bps: 1_000_000,
            burst_bytes: 125_000,
            discard_excess: false,
        }],
        &ifaces,
        "",
        "",
    )
    .expect("filter state compiles");

    // A matching flow carries all three modifiers into the FilterResult.
    let matched = evaluate_interface_filter(
        &state,
        9,
        false,
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        PROTO_TCP,
        40000,
        5201,
        0,
        TermMatchExtra::default(),
    );
    assert_eq!(matched.action, FilterAction::Accept);
    assert_eq!(matched.policer_name.as_deref(), Some("p-lo"));
    assert_eq!(matched.routing_instance.as_deref(), Some("blue"));
    assert_eq!(matched.forwarding_class.as_deref(), Some("assured"));

    // A non-matching flow leaves every modifier at the zero-alloc default None.
    let unmatched = evaluate_interface_filter(
        &state,
        9,
        false,
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        PROTO_TCP,
        40000,
        22,
        0,
        TermMatchExtra::default(),
    );
    assert_eq!(unmatched.policer_name, None);
    assert_eq!(unmatched.routing_instance, None);
    assert_eq!(unmatched.forwarding_class, None);
}

#[test]
fn filter_state_struct_size_is_reported() {
    // #6236 PR-1 evidence + #6350 revert guard: print the compiled size of
    // FilterState so the dead-field deletion (31 -> 23 fields) is measurable
    // rather than back-solved. Run with `-- --nocapture` to see the value.
    // The exact byte count is toolchain-dependent (hashbrown inline size,
    // niche packing), so the ceiling is `<=` the measured post-deletion size
    // rather than an exact `==` — a benign alignment shift will not false-RED,
    // but re-adding ANY deleted field (each was >= 24 bytes: HashSet<u32> is
    // 48, Option<u8> plus padding is 24, so the struct jumps to >= 520) breaks
    // the ceiling. The old `<= 736` ceiling was the PRE-deletion footprint and
    // passed even after a full revert; this tightens it to guard the deletion.
    let bytes = std::mem::size_of::<FilterState>();
    println!("FilterState size_of = {bytes} bytes");
    assert!(
        bytes <= 496,
        "FilterState grew past the post-#6236 footprint ({bytes} bytes) — a \
         deleted dead field was likely re-added"
    );
}

#[test]
fn parse_filter_state_prequalifies_interface_and_lo0_filter_keys() {
    let ifaces = vec![crate::InterfaceSnapshot {
        name: "reth0.80".into(),
        ifindex: 7,
        filter_input_v4: "ingress-v4".into(),
        filter_output_v6: "egress-v6".into(),
        ..Default::default()
    }];
    let state = parse_filter_state(
        &[
            FirewallFilterSnapshot {
                name: "ingress-v4".into(),
                family: "inet".into(),
                terms: vec![FirewallTermSnapshot {
                    name: "tx-select".into(),
                    forwarding_class: "best-effort".into(),
                    routing_instance: "sfmix".into(),
                    ..Default::default()
                }],
            },
            FirewallFilterSnapshot {
                name: "egress-v6".into(),
                family: "inet6".into(),
                terms: vec![],
            },
            FirewallFilterSnapshot {
                name: "protect-re".into(),
                family: "inet".into(),
                terms: vec![],
            },
            FirewallFilterSnapshot {
                name: "protect-re-v6".into(),
                family: "inet6".into(),
                terms: vec![],
            },
        ],
        &[],
        &ifaces,
        "protect-re",
        "protect-re-v6",
    )
    .expect("filter state compiles");
    // #6236 PR-1: the dead per-interface/lo0 name maps and the dead input
    // `iface_filter_v4_affects_tx_selection` set are removed. The retained fast
    // maps carry the resolved `Arc<Filter>` (name is the unqualified filter
    // name), and the aggregate boolean carries the family-wide tx-selection
    // fact. #6236 PR-2B: the route-lookup and output needs_tx_eval property sets
    // are deleted — the capability facts are now read through the migrated
    // accessors (which read the flag off the fast map) and the retained
    // `has_output_needs_tx_eval_*` aggregate.
    assert_eq!(
        state.iface_filter_v4_fast.get(&7).map(|f| f.name.as_str()),
        Some("ingress-v4")
    );
    assert!(state.has_input_tx_selection_v4);
    assert!(interface_filter_affects_route_lookup(&state, 7, false));
    assert!(!interface_output_filter_needs_tx_eval(&state, 7, false));
    assert!(!interface_output_filter_needs_tx_eval(&state, 7, true));
    assert!(!state.has_output_needs_tx_eval_v4);
    assert!(!state.has_output_needs_tx_eval_v6);
    assert_eq!(
        state
            .iface_filter_out_v6_fast
            .get(&7)
            .map(|f| f.name.as_str()),
        Some("egress-v6")
    );
    assert_eq!(
        state.lo0_filter_v4_fast.as_ref().map(|f| f.name.as_str()),
        Some("protect-re")
    );
    assert_eq!(
        state.lo0_filter_v6_fast.as_ref().map(|f| f.name.as_str()),
        Some("protect-re-v6")
    );
}

#[test]
fn accept_only_output_filter_does_not_need_tx_eval() {
    let ifaces = vec![crate::InterfaceSnapshot {
        name: "reth0.80".into(),
        ifindex: 7,
        filter_output_v4: "wan-allow".into(),
        ..Default::default()
    }];
    let state = parse_filter_state(
        &[FirewallFilterSnapshot {
            name: "wan-allow".into(),
            family: "inet".into(),
            terms: vec![FirewallTermSnapshot {
                name: "allow".into(),
                action: "accept".into(),
                protocols: vec!["tcp".into()],
                destination_ports: vec!["5201".into()],
                ..Default::default()
            }],
        }],
        &[],
        &ifaces,
        "",
        "",
    )
    .expect("filter state compiles");

    assert!(!interface_output_filter_needs_tx_eval(&state, 7, false));
    // #6236 PR-2B: `filter_state_has_output_tx_selection` is deleted; an
    // accept-only output filter leaves the retained needs-tx-eval aggregate false.
    assert!(!state.has_output_needs_tx_eval_v4);
}

/// #6236 PR-2A parent-RED anchor: a `then count`-only OUTPUT filter (no
/// forwarding-class / dscp-rewrite, no terminal action, no log, no policer)
/// still needs a TX-path walk. This binds `Filter::needs_tx_eval()` — the SOLE
/// five-flag predicate — to (a) the compiler set-insert (via the
/// `interface_output_filter_needs_tx_eval` accessor), and (b) the
/// `has_output_needs_tx_eval_v4` aggregate recomputed from the final fast map.
/// Dropping `has_counter_terms` from `Filter::needs_tx_eval()` fails all of them
/// RED. It also pins `needs_tx_eval ⊋ affects_tx_selection` (the old
/// `has_output_tx_selection` clause stays false).
#[test]
fn counter_only_output_filter_needs_tx_eval_and_sets_aggregate() {
    let ifaces = vec![crate::InterfaceSnapshot {
        name: "reth0.80".into(),
        ifindex: 7,
        filter_output_v4: "wan-count".into(),
        ..Default::default()
    }];
    let state = parse_filter_state(
        &[FirewallFilterSnapshot {
            name: "wan-count".into(),
            family: "inet".into(),
            terms: vec![FirewallTermSnapshot {
                name: "tally".into(),
                action: "accept".into(),
                count: "wan-bytes".into(),
                ..Default::default()
            }],
        }],
        &[],
        &ifaces,
        "",
        "",
    )
    .expect("filter state compiles");

    let filter = state
        .iface_filter_out_v4_fast
        .get(&7)
        .expect("output filter present in fast map");
    assert!(filter.needs_tx_eval(), "counter-only filter needs a TX walk");
    assert!(
        !filter.affects_tx_selection,
        "counter is not a tx-selection action"
    );
    // #6236 PR-2B: the accessor now reads `Filter::needs_tx_eval()` off the
    // output fast-map entry (the set is deleted).
    assert!(interface_output_filter_needs_tx_eval(&state, 7, false));
    // Aggregate recomputed from the FINAL output fast map.
    assert!(state.has_output_needs_tx_eval_v4);
    // needs_tx_eval strictly supersets affects_tx_selection — read the flag off
    // the fast-map filter now that `has_output_tx_selection_v4` is deleted.
    assert!(!filter.affects_tx_selection);
}

/// #6236 PR-2A blocker-#1 pin (updated for PR-2B): a duplicate ifindex where a
/// needs-tx-eval output filter is followed by a plain-accept one at the SAME
/// ifindex+family+direction. The fast map overwrites last-wins (holds the
/// SECOND, plain filter); the `has_output_needs_tx_eval_v4` aggregate —
/// recomputed from the FINAL map, NOT accumulated in-loop — therefore reads
/// FALSE, agreeing with the filter the hot path actually evaluates. PR-2B
/// deleted the monotonic `iface_filter_out_v4_needs_tx_eval` set, so the
/// migrated `interface_output_filter_needs_tx_eval` accessor now also reads the
/// last-wins fast-map filter → FALSE (part c), closing the §5.1 divergence at
/// the per-interface level too. The snapshot still compiles Ok (last-wins
/// canonical, NOT reject-fail-closed).
#[test]
fn duplicate_ifindex_output_filter_aggregate_is_last_wins() {
    let ifaces = vec![
        crate::InterfaceSnapshot {
            name: "reth0.80".into(),
            ifindex: 7,
            filter_output_v4: "wan-count".into(),
            ..Default::default()
        },
        crate::InterfaceSnapshot {
            name: "reth0.80-dup".into(),
            ifindex: 7,
            filter_output_v4: "plain".into(),
            ..Default::default()
        },
    ];
    let state = parse_filter_state(
        &[
            FirewallFilterSnapshot {
                name: "wan-count".into(),
                family: "inet".into(),
                terms: vec![FirewallTermSnapshot {
                    name: "tally".into(),
                    action: "accept".into(),
                    count: "wan-bytes".into(),
                    ..Default::default()
                }],
            },
            FirewallFilterSnapshot {
                name: "plain".into(),
                family: "inet".into(),
                terms: vec![FirewallTermSnapshot {
                    name: "ok".into(),
                    action: "accept".into(),
                    ..Default::default()
                }],
            },
        ],
        &[],
        &ifaces,
        "",
        "",
    )
    .expect("duplicate ifindex is accepted (last-wins canonical, not rejected)");

    // (a) last-wins: the fast map holds the SECOND (plain) filter.
    assert_eq!(
        state.iface_filter_out_v4_fast.get(&7).map(|f| f.name.as_str()),
        Some("plain")
    );
    // (b) the recomputed aggregate follows the final map (plain → false), NOT the
    // stale union.
    assert!(
        !state.has_output_needs_tx_eval_v4,
        "aggregate must derive from the final last-wins filter"
    );
    // (c) #6236 PR-2B: the monotonic set is deleted and the accessor now reads
    // `Filter::needs_tx_eval()` off the last-wins fast-map entry — so it returns
    // FALSE, agreeing with the (plain) filter the TX path actually evaluates.
    // This is exactly the divergence the fold closes: before PR-2B the set
    // `.contains(&7)` was stale-true while the fast map held the plain filter.
    assert!(!interface_output_filter_needs_tx_eval(&state, 7, false));
}

/// #6236 PR-2B equivalence gate. During development this assertion was written
/// and confirmed green in the pre-deletion form
/// (`set.contains(&if) == fast.get(&if).is_some_and(flag)`) to PROVE the
/// accessor body-swap is behavior-preserving before the eight property sets
/// were removed; that pre-deletion form is not a separate commit in this
/// squashed PR. Post-deletion it survives as an
/// accessor-semantics regression pin: for a normally compiled `FilterState`
/// (unique ifindices) each migrated capability accessor returns exactly the
/// mirrored `Filter` flag off the per-interface fast map, across both families
/// and both directions. If any accessor drifts to the wrong flag/map this fails.
#[test]
fn capability_accessors_equal_fast_map_flags_for_unique_ifindices() {
    let ifaces = vec![
        // input v4 / v6 route-lookup (routing-instance term)
        crate::InterfaceSnapshot {
            name: "a".into(),
            ifindex: 10,
            filter_input_v4: "pbr4".into(),
            ..Default::default()
        },
        crate::InterfaceSnapshot {
            name: "b".into(),
            ifindex: 11,
            filter_input_v6: "pbr6".into(),
            ..Default::default()
        },
        // input v4 / v6 DSCP match
        crate::InterfaceSnapshot {
            name: "c".into(),
            ifindex: 20,
            filter_input_v4: "dscp4".into(),
            ..Default::default()
        },
        crate::InterfaceSnapshot {
            name: "d".into(),
            ifindex: 21,
            filter_input_v6: "dscp6".into(),
            ..Default::default()
        },
        // input v4 / v6 per-packet L4 match (tcp-flags)
        crate::InterfaceSnapshot {
            name: "e".into(),
            ifindex: 30,
            filter_input_v4: "ppl4".into(),
            ..Default::default()
        },
        crate::InterfaceSnapshot {
            name: "f".into(),
            ifindex: 31,
            filter_input_v6: "ppl6".into(),
            ..Default::default()
        },
        // output v4 (counter) / v6 (log) → needs_tx_eval
        crate::InterfaceSnapshot {
            name: "g".into(),
            ifindex: 40,
            filter_output_v4: "count4".into(),
            ..Default::default()
        },
        crate::InterfaceSnapshot {
            name: "h".into(),
            ifindex: 41,
            filter_output_v6: "log6".into(),
            ..Default::default()
        },
        // plain-accept input+output (no capability flag) — negative side
        crate::InterfaceSnapshot {
            name: "i".into(),
            ifindex: 50,
            filter_input_v4: "plain4".into(),
            filter_input_v6: "plain6".into(),
            filter_output_v4: "plain4".into(),
            filter_output_v6: "plain6".into(),
            ..Default::default()
        },
    ];
    let state = parse_filter_state(
        &[
            FirewallFilterSnapshot {
                name: "pbr4".into(),
                family: "inet".into(),
                terms: vec![FirewallTermSnapshot {
                    name: "t".into(),
                    action: "accept".into(),
                    routing_instance: "ri".into(),
                    ..Default::default()
                }],
            },
            FirewallFilterSnapshot {
                name: "pbr6".into(),
                family: "inet6".into(),
                terms: vec![FirewallTermSnapshot {
                    name: "t".into(),
                    action: "accept".into(),
                    routing_instance: "ri".into(),
                    ..Default::default()
                }],
            },
            FirewallFilterSnapshot {
                name: "dscp4".into(),
                family: "inet".into(),
                terms: vec![FirewallTermSnapshot {
                    name: "t".into(),
                    action: "accept".into(),
                    dscp_values: vec![46],
                    ..Default::default()
                }],
            },
            FirewallFilterSnapshot {
                name: "dscp6".into(),
                family: "inet6".into(),
                terms: vec![FirewallTermSnapshot {
                    name: "t".into(),
                    action: "accept".into(),
                    dscp_values: vec![46],
                    ..Default::default()
                }],
            },
            FirewallFilterSnapshot {
                name: "ppl4".into(),
                family: "inet".into(),
                terms: vec![FirewallTermSnapshot {
                    name: "t".into(),
                    action: "accept".into(),
                    protocols: vec!["tcp".into()],
                    tcp_flags: Some(0x02),
                    ..Default::default()
                }],
            },
            FirewallFilterSnapshot {
                name: "ppl6".into(),
                family: "inet6".into(),
                terms: vec![FirewallTermSnapshot {
                    name: "t".into(),
                    action: "accept".into(),
                    protocols: vec!["tcp".into()],
                    tcp_flags: Some(0x02),
                    ..Default::default()
                }],
            },
            FirewallFilterSnapshot {
                name: "count4".into(),
                family: "inet".into(),
                terms: vec![FirewallTermSnapshot {
                    name: "t".into(),
                    action: "accept".into(),
                    count: "c4".into(),
                    ..Default::default()
                }],
            },
            FirewallFilterSnapshot {
                name: "log6".into(),
                family: "inet6".into(),
                terms: vec![FirewallTermSnapshot {
                    name: "t".into(),
                    action: "accept".into(),
                    log: true,
                    syslog: false,
                    reject_message_type: String::new(),
                    ..Default::default()
                }],
            },
            FirewallFilterSnapshot {
                name: "plain4".into(),
                family: "inet".into(),
                terms: vec![FirewallTermSnapshot {
                    name: "t".into(),
                    action: "accept".into(),
                    ..Default::default()
                }],
            },
            FirewallFilterSnapshot {
                name: "plain6".into(),
                family: "inet6".into(),
                terms: vec![FirewallTermSnapshot {
                    name: "t".into(),
                    action: "accept".into(),
                    ..Default::default()
                }],
            },
        ],
        &[],
        &ifaces,
        "",
        "",
    )
    .expect("filter state compiles");

    // Probe every used ifindex plus absent ones (0, 1, 99) so both the positive
    // and negative sides of the equivalence are exercised.
    let probe: [i32; 12] = [10, 11, 20, 21, 30, 31, 40, 41, 50, 99, 0, 1];
    for &ifx in &probe {
        assert_eq!(
            interface_filter_affects_route_lookup(&state, ifx, false),
            state
                .iface_filter_v4_fast
                .get(&ifx)
                .is_some_and(|f| f.affects_route_lookup),
            "v4 affects_route_lookup accessor != fast-map flag at {ifx}"
        );
        assert_eq!(
            interface_filter_affects_route_lookup(&state, ifx, true),
            state
                .iface_filter_v6_fast
                .get(&ifx)
                .is_some_and(|f| f.affects_route_lookup),
            "v6 affects_route_lookup accessor != fast-map flag at {ifx}"
        );
        assert_eq!(
            interface_input_filter_has_dscp_match(&state, ifx, false),
            state
                .iface_filter_v4_fast
                .get(&ifx)
                .is_some_and(|f| f.has_dscp_match_terms),
            "v4 has_dscp_match accessor != fast-map flag at {ifx}"
        );
        assert_eq!(
            interface_input_filter_has_dscp_match(&state, ifx, true),
            state
                .iface_filter_v6_fast
                .get(&ifx)
                .is_some_and(|f| f.has_dscp_match_terms),
            "v6 has_dscp_match accessor != fast-map flag at {ifx}"
        );
        assert_eq!(
            interface_input_filter_has_per_packet_l4_match(&state, ifx, false),
            state
                .iface_filter_v4_fast
                .get(&ifx)
                .is_some_and(|f| f.has_per_packet_l4_match_terms),
            "v4 has_per_packet_l4_match accessor != fast-map flag at {ifx}"
        );
        assert_eq!(
            interface_input_filter_has_per_packet_l4_match(&state, ifx, true),
            state
                .iface_filter_v6_fast
                .get(&ifx)
                .is_some_and(|f| f.has_per_packet_l4_match_terms),
            "v6 has_per_packet_l4_match accessor != fast-map flag at {ifx}"
        );
        assert_eq!(
            interface_output_filter_needs_tx_eval(&state, ifx, false),
            state
                .iface_filter_out_v4_fast
                .get(&ifx)
                .is_some_and(|f| f.needs_tx_eval()),
            "v4 out needs_tx_eval accessor != fast-map flag at {ifx}"
        );
        assert_eq!(
            interface_output_filter_needs_tx_eval(&state, ifx, true),
            state
                .iface_filter_out_v6_fast
                .get(&ifx)
                .is_some_and(|f| f.needs_tx_eval()),
            "v6 out needs_tx_eval accessor != fast-map flag at {ifx}"
        );
    }

    // Sanity: the fixture actually drives a positive result on every
    // accessor/flag pair (otherwise the equivalence above is vacuously true).
    assert!(interface_filter_affects_route_lookup(&state, 10, false));
    assert!(interface_filter_affects_route_lookup(&state, 11, true));
    assert!(interface_input_filter_has_dscp_match(&state, 20, false));
    assert!(interface_input_filter_has_dscp_match(&state, 21, true));
    assert!(interface_input_filter_has_per_packet_l4_match(&state, 30, false));
    assert!(interface_input_filter_has_per_packet_l4_match(&state, 31, true));
    assert!(interface_output_filter_needs_tx_eval(&state, 40, false));
    assert!(interface_output_filter_needs_tx_eval(&state, 41, true));
}

/// #6236 PR-2C fail-on-revert equivalence gate. PR-2C folds the co-located
/// multi-flag hot-path checks into ONE `.get()` per call site via shared pure
/// `&Filter` evaluator cores. This test proves each folded single-lookup path
/// returns EXACTLY the value the pre-fold two-lookup path returned, for
/// representative filters (DSCP-only, L4-only, both, needs-tx-eval, none) across
/// both families and both directions.
///
/// The three cores under test:
///   1. route-lookup: `interface_filter_route_lookup_affecting(..).is_some()`
///      == the bool precheck, AND the borrow feeds the routing-instance
///      evaluator core so `evaluate_filter_ref_routing_instance_event_counted`
///      (one lookup) == `evaluate_interface_filter_routing_instance_event_counted`
///      (its own lookup).
///   2. DSCP/L4: `interface_input_filter_varies_per_packet` (the folded session-
///      hit re-eval gate) == `has_dscp_match(..) || has_per_packet_l4_match(..)`.
///   3. needs-tx-eval: `interface_output_filter_needing_tx_eval(..).is_some()`
///      == the bool accessor `interface_output_filter_needs_tx_eval`.
///
/// Reverts that make a core read the wrong flag, or drop one of the two OR'd
/// flags (`Filter::varies_per_packet_within_flow`), fail this test at a
/// representative ifindex.
#[test]
fn pr2c_folded_single_lookup_equals_two_lookup_path() {
    let ifaces = vec![
        // input v4/v6 DSCP-only
        crate::InterfaceSnapshot {
            name: "dscp-a".into(),
            ifindex: 100,
            filter_input_v4: "dscp4".into(),
            ..Default::default()
        },
        crate::InterfaceSnapshot {
            name: "dscp-b".into(),
            ifindex: 101,
            filter_input_v6: "dscp6".into(),
            ..Default::default()
        },
        // input v4/v6 per-packet-L4-only (tcp-flags)
        crate::InterfaceSnapshot {
            name: "l4-a".into(),
            ifindex: 110,
            filter_input_v4: "ppl4".into(),
            ..Default::default()
        },
        crate::InterfaceSnapshot {
            name: "l4-b".into(),
            ifindex: 111,
            filter_input_v6: "ppl6".into(),
            ..Default::default()
        },
        // input v4/v6 BOTH DSCP and per-packet-L4 on one term
        crate::InterfaceSnapshot {
            name: "both-a".into(),
            ifindex: 120,
            filter_input_v4: "both4".into(),
            ..Default::default()
        },
        crate::InterfaceSnapshot {
            name: "both-b".into(),
            ifindex: 121,
            filter_input_v6: "both6".into(),
            ..Default::default()
        },
        // input v4/v6 route-lookup-affecting (routing-instance PBR term)
        crate::InterfaceSnapshot {
            name: "pbr-a".into(),
            ifindex: 130,
            filter_input_v4: "pbr4".into(),
            ..Default::default()
        },
        crate::InterfaceSnapshot {
            name: "pbr-b".into(),
            ifindex: 131,
            filter_input_v6: "pbr6".into(),
            ..Default::default()
        },
        // output v4 (counter) / v6 (log) → needs_tx_eval
        crate::InterfaceSnapshot {
            name: "out-a".into(),
            ifindex: 140,
            filter_output_v4: "count4".into(),
            ..Default::default()
        },
        crate::InterfaceSnapshot {
            name: "out-b".into(),
            ifindex: 141,
            filter_output_v6: "log6".into(),
            ..Default::default()
        },
        // plain input+output both families (no capability flag) — negative side
        crate::InterfaceSnapshot {
            name: "plain".into(),
            ifindex: 150,
            filter_input_v4: "plain4".into(),
            filter_input_v6: "plain6".into(),
            filter_output_v4: "plain4".into(),
            filter_output_v6: "plain6".into(),
            ..Default::default()
        },
    ];
    let dscp_term = |dscp: bool, l4: bool| FirewallTermSnapshot {
        name: "t".into(),
        action: "accept".into(),
        dscp_values: if dscp { vec![46] } else { vec![] },
        protocols: if l4 { vec!["tcp".into()] } else { vec![] },
        tcp_flags: if l4 { Some(0x02) } else { None },
        ..Default::default()
    };
    let state = parse_filter_state(
        &[
            FirewallFilterSnapshot {
                name: "dscp4".into(),
                family: "inet".into(),
                terms: vec![dscp_term(true, false)],
            },
            FirewallFilterSnapshot {
                name: "dscp6".into(),
                family: "inet6".into(),
                terms: vec![dscp_term(true, false)],
            },
            FirewallFilterSnapshot {
                name: "ppl4".into(),
                family: "inet".into(),
                terms: vec![dscp_term(false, true)],
            },
            FirewallFilterSnapshot {
                name: "ppl6".into(),
                family: "inet6".into(),
                terms: vec![dscp_term(false, true)],
            },
            FirewallFilterSnapshot {
                name: "both4".into(),
                family: "inet".into(),
                terms: vec![dscp_term(true, true)],
            },
            FirewallFilterSnapshot {
                name: "both6".into(),
                family: "inet6".into(),
                terms: vec![dscp_term(true, true)],
            },
            FirewallFilterSnapshot {
                name: "pbr4".into(),
                family: "inet".into(),
                terms: vec![FirewallTermSnapshot {
                    name: "t".into(),
                    action: "accept".into(),
                    routing_instance: "ri".into(),
                    ..Default::default()
                }],
            },
            FirewallFilterSnapshot {
                name: "pbr6".into(),
                family: "inet6".into(),
                terms: vec![FirewallTermSnapshot {
                    name: "t".into(),
                    action: "accept".into(),
                    routing_instance: "ri".into(),
                    ..Default::default()
                }],
            },
            FirewallFilterSnapshot {
                name: "count4".into(),
                family: "inet".into(),
                terms: vec![FirewallTermSnapshot {
                    name: "t".into(),
                    action: "accept".into(),
                    count: "c4".into(),
                    ..Default::default()
                }],
            },
            FirewallFilterSnapshot {
                name: "log6".into(),
                family: "inet6".into(),
                terms: vec![FirewallTermSnapshot {
                    name: "t".into(),
                    action: "accept".into(),
                    log: true,
                    syslog: false,
                    reject_message_type: String::new(),
                    ..Default::default()
                }],
            },
            FirewallFilterSnapshot {
                name: "plain4".into(),
                family: "inet".into(),
                terms: vec![FirewallTermSnapshot {
                    name: "t".into(),
                    action: "accept".into(),
                    ..Default::default()
                }],
            },
            FirewallFilterSnapshot {
                name: "plain6".into(),
                family: "inet6".into(),
                terms: vec![FirewallTermSnapshot {
                    name: "t".into(),
                    action: "accept".into(),
                    ..Default::default()
                }],
            },
        ],
        &[],
        &ifaces,
        "",
        "",
    )
    .expect("filter state compiles");

    // Probe every used ifindex plus absent ones so both sides of each
    // equivalence are exercised.
    let probe: [i32; 15] = [
        100, 101, 110, 111, 120, 121, 130, 131, 140, 141, 150, 0, 1, 999, 42,
    ];
    for &ifx in &probe {
        for is_v6 in [false, true] {
            // Core 1a: route-lookup borrow `.is_some()` == the bool precheck.
            let borrow = interface_filter_route_lookup_affecting(&state, ifx, is_v6);
            assert_eq!(
                borrow.is_some(),
                interface_filter_affects_route_lookup(&state, ifx, is_v6),
                "route-lookup borrow.is_some() != bool precheck at {ifx} v6={is_v6}"
            );
            // The borrow, when present, is a route-lookup-affecting filter.
            if let Some(filter) = borrow {
                assert!(
                    filter.affects_route_lookup,
                    "route-lookup borrow returned a non-affecting filter at {ifx} v6={is_v6}"
                );
            }

            // Core 2: the folded DSCP||L4 gate == OR of the two per-flag
            // accessors the flow-cache decline gate still uses individually.
            assert_eq!(
                interface_input_filter_varies_per_packet(&state, ifx, is_v6),
                interface_input_filter_has_dscp_match(&state, ifx, is_v6)
                    || interface_input_filter_has_per_packet_l4_match(&state, ifx, is_v6),
                "varies_per_packet != (has_dscp || has_l4) at {ifx} v6={is_v6}"
            );

            // Core 3: needs-tx-eval borrow `.is_some()` == the bool accessor,
            // and the borrow, when present, actually needs a TX walk.
            let out_borrow = interface_output_filter_needing_tx_eval(&state, ifx, is_v6);
            assert_eq!(
                out_borrow.is_some(),
                interface_output_filter_needs_tx_eval(&state, ifx, is_v6),
                "needs-tx-eval borrow.is_some() != bool accessor at {ifx} v6={is_v6}"
            );
            if let Some(filter) = out_borrow {
                assert!(
                    filter.needs_tx_eval(),
                    "needs-tx-eval borrow returned a filter that does not need eval at {ifx} v6={is_v6}"
                );
            }
        }
    }

    // Core 1b: the routing-instance evaluator core off the shared borrow returns
    // the same override the two-lookup entry point returns, for the v4 and v6
    // route-lookup-affecting interfaces. A `routing-instance ri; accept` term
    // with no `from` match steers every packet.
    for &(ifx, is_v6, src, dst) in &[
        (
            130i32,
            false,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        ),
        (
            131i32,
            true,
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2)),
        ),
    ] {
        let two_lookup = evaluate_interface_filter_routing_instance_event_counted(
            &state,
            ifx,
            is_v6,
            src,
            dst,
            PROTO_TCP,
            40000,
            5201,
            0,
            TermMatchExtra::default(),
            1400,
        );
        let borrow = interface_filter_route_lookup_affecting(&state, ifx, is_v6)
            .expect("route-lookup-affecting filter present");
        let single_lookup = evaluate_filter_ref_routing_instance_event_counted(
            borrow,
            src,
            dst,
            PROTO_TCP,
            40000,
            5201,
            0,
            TermMatchExtra::default(),
            1400,
        );
        assert_eq!(
            two_lookup.map(|r| r.routing_instance),
            single_lookup.map(|r| r.routing_instance),
            "routing-instance override diverged between one- and two-lookup paths at {ifx} v6={is_v6}"
        );
        assert_eq!(
            single_lookup.map(|r| r.routing_instance),
            Some("ri"),
            "expected the fixture PBR term to steer to `ri` at {ifx} v6={is_v6}"
        );
    }

    // Sanity: the fixture drives a positive result on each folded core so the
    // equivalences above are not vacuously true.
    assert!(interface_filter_route_lookup_affecting(&state, 130, false).is_some());
    assert!(interface_filter_route_lookup_affecting(&state, 131, true).is_some());
    assert!(interface_input_filter_varies_per_packet(&state, 100, false)); // dscp-only
    assert!(interface_input_filter_varies_per_packet(&state, 110, false)); // l4-only
    assert!(interface_input_filter_varies_per_packet(&state, 120, false)); // both
    assert!(interface_input_filter_varies_per_packet(&state, 121, true)); // both v6
    assert!(!interface_input_filter_varies_per_packet(&state, 150, false)); // plain
    assert!(interface_output_filter_needing_tx_eval(&state, 140, false).is_some());
    assert!(interface_output_filter_needing_tx_eval(&state, 141, true).is_some());
    assert!(interface_output_filter_needing_tx_eval(&state, 150, false).is_none());
}

#[test]
fn interface_filter_routing_instance_counted_returns_matching_override() {
    let ifaces = vec![crate::InterfaceSnapshot {
        name: "reth1.0".into(),
        ifindex: 11,
        filter_input_v6: "sfmix-pbr".into(),
        ..Default::default()
    }];
    let state = parse_filter_state(
        &[FirewallFilterSnapshot {
            name: "sfmix-pbr".into(),
            family: "inet6".into(),
            terms: vec![
                FirewallTermSnapshot {
                    name: "match-iperf".into(),
                    action: "accept".into(),
                    count: "iperf-v6".into(),
                    protocols: vec!["tcp".into()],
                    destination_ports: vec!["5201".into()],
                    routing_instance: "sfmix".into(),
                    ..Default::default()
                },
                FirewallTermSnapshot {
                    name: "default".into(),
                    action: "accept".into(),
                    ..Default::default()
                },
            ],
        }],
        &[],
        &ifaces,
        "",
        "",
    )
    .expect("filter state compiles");

    assert!(interface_filter_affects_route_lookup(&state, 11, true));
    let routing_instance = evaluate_interface_filter_routing_instance_counted(
        &state,
        11,
        true,
        IpAddr::V6("2001:db8::10".parse().unwrap()),
        IpAddr::V6("2001:db8::200".parse().unwrap()),
        PROTO_TCP,
        12345,
        5201,
        0,
        TermMatchExtra::default(),
        1500,
    );
    assert_eq!(routing_instance, Some("sfmix"));
    let filter = state.iface_filter_v6_fast.get(&11).expect("input filter");
    assert_eq!(filter.terms[0].counter.packets.load(Ordering::Relaxed), 1);
    assert_eq!(filter.terms[0].counter.bytes.load(Ordering::Relaxed), 1500);
}

/// #4499 H6: an IPv6 PBR term `from destination-port 80 then routing-instance
/// vrf1` steers a tcp/80 packet into vrf1, and a packet on ANY OTHER port does
/// NOT match the term — it falls through to the default (routing-instance-less)
/// term, so the evaluator returns None (no override) and the flow uses BASE
/// routing. This is the fail-CLOSED behavior: the dest-port constraint is
/// honored, so a PBR dest-port term can never be bypassed into matching every
/// port (which would silently steer/leak unrelated flows). The L4-offset walk
/// PAST IPv6 extension headers (so port 80 is extractable behind a Hop-by-Hop /
/// Dest-Opts / Mobility header) is separately pinned by #4517's
/// `inspect_walkers_traverse_exotic_length_prefixed_ext_headers`; this pins the
/// PBR dest-port MATCH + fail-closed decision at the filter engine.
#[test]
fn pbr_destination_port_term_matches_and_fails_closed_no_bypass() {
    let ifaces = vec![crate::InterfaceSnapshot {
        name: "reth1.0".into(),
        ifindex: 11,
        filter_input_v6: "pbr6".into(),
        ..Default::default()
    }];
    let state = parse_filter_state(
        &[FirewallFilterSnapshot {
            name: "pbr6".into(),
            family: "inet6".into(),
            terms: vec![
                FirewallTermSnapshot {
                    name: "steer-http".into(),
                    action: "accept".into(),
                    protocols: vec!["tcp".into()],
                    destination_ports: vec!["80".into()],
                    routing_instance: "vrf1".into(),
                    ..Default::default()
                },
                FirewallTermSnapshot {
                    name: "default".into(),
                    action: "accept".into(),
                    ..Default::default()
                },
            ],
        }],
        &[],
        &ifaces,
        "",
        "",
    )
    .expect("filter state compiles");
    assert!(interface_filter_affects_route_lookup(&state, 11, true));

    let src = IpAddr::V6("2001:db8::10".parse().unwrap());
    let dst = IpAddr::V6("2001:db8::200".parse().unwrap());

    // tcp/80 matches the PBR dest-port term -> steered into vrf1.
    let matched = evaluate_interface_filter_routing_instance_counted(
        &state,
        11,
        true,
        src,
        dst,
        PROTO_TCP,
        40000,
        80,
        0,
        TermMatchExtra::default(),
        1500,
    );
    assert_eq!(
        matched,
        Some("vrf1"),
        "a tcp/80 packet must be PBR-steered into vrf1"
    );

    // tcp/8080 does NOT match the dest-port term -> the default (no-RI) term
    // matches -> no routing-instance override -> None -> base routing. Fail
    // CLOSED: the dest-port constraint is enforced, so there is no bypass.
    let miss = evaluate_interface_filter_routing_instance_counted(
        &state,
        11,
        true,
        src,
        dst,
        PROTO_TCP,
        40000,
        8080,
        0,
        TermMatchExtra::default(),
        1500,
    );
    assert_eq!(
        miss, None,
        "a non-80 packet must NOT match the PBR dest-port term (fail-closed to base routing, no bypass)"
    );
}

/// #4499 H4 (Rust kernel): the per-interface OUTPUT filter is a pure function of
/// the EGRESS interface config + packet tuple. `evaluate_interface_output_filter`
/// takes NO session argument and reads only `state` (egress config) + the tuple,
/// so it is NOT part of synced session state and is RE-EVALUATED per egress
/// packet. Therefore, on a NEW PRIMARY after an HA failover, the SAME egress
/// config yields the SAME verdict — a session synced from the old primary carries
/// no output-filter decision and cannot suppress the new primary's egress filter.
///
/// This pins that kernel by building the FilterState TWICE from the SAME egress
/// config (two independent instances standing in for the pre- and post-failover
/// nodes) and asserting BOTH deny tcp/80 on the egress ifindex — with no session
/// / NatDecision involved. The full cross-chassis failover-under-traffic
/// assertion is the cluster integration test the issue calls out (out of scope
/// for a Rust-only, test-only PR).
#[test]
fn output_filter_reevaluated_from_egress_config_not_session_state() {
    let ifaces = vec![crate::InterfaceSnapshot {
        name: "reth0.80".into(),
        ifindex: 7,
        filter_output_v4: "deny-80".into(),
        ..Default::default()
    }];
    let filters = [FirewallFilterSnapshot {
        name: "deny-80".into(),
        family: "inet".into(),
        terms: vec![
            FirewallTermSnapshot {
                name: "block-http".into(),
                protocols: vec!["tcp".into()],
                destination_ports: vec!["80".into()],
                action: "discard".into(),
                ..Default::default()
            },
            FirewallTermSnapshot {
                name: "default".into(),
                action: "accept".into(),
                ..Default::default()
            },
        ],
    }];
    let build =
        || parse_filter_state(&filters, &[], &ifaces, "", "").expect("filter state compiles");
    // Two independent nodes with identical egress config: the original primary
    // and the new primary after failover.
    let node_a = build();
    let new_primary = build();

    let src = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5));
    let dst = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9));
    for (label, state) in [("original-primary", &node_a), ("new-primary", &new_primary)] {
        let verdict = evaluate_interface_output_filter_counted(
            state,
            7,
            false,
            src,
            dst,
            PROTO_TCP,
            40000,
            80,
            0,
            TermMatchExtra::default(),
            1500,
        );
        assert_eq!(
            verdict.action,
            FilterAction::Discard,
            "{label}: the egress output filter must deny tcp/80 (re-evaluated from egress config, never synced session state)"
        );
    }

    // The new primary forwards a non-80 port identically — the verdict is a
    // function of the tuple + egress config, not carried session state.
    let allowed = evaluate_interface_output_filter_counted(
        &new_primary,
        7,
        false,
        src,
        dst,
        PROTO_TCP,
        40000,
        443,
        0,
        TermMatchExtra::default(),
        1500,
    );
    assert_eq!(allowed.action, FilterAction::Accept);
}

#[test]
fn interface_output_filter_counted_records_term_hits() {
    let ifaces = vec![crate::InterfaceSnapshot {
        name: "reth0.80".into(),
        ifindex: 7,
        filter_output_v6: "bandwidth-output".into(),
        ..Default::default()
    }];
    let state = parse_filter_state(
        &[FirewallFilterSnapshot {
            name: "bandwidth-output".into(),
            family: "inet6".into(),
            terms: vec![FirewallTermSnapshot {
                name: "iperf-a".into(),
                action: "accept".into(),
                forwarding_class: "iperf-a".into(),
                count: "iperf-a-v6".into(),
                protocols: vec!["tcp".into()],
                destination_ports: vec!["5201".into()],
                ..Default::default()
            }],
        }],
        &[],
        &ifaces,
        "",
        "",
    )
    .expect("filter state compiles");
    let result = evaluate_interface_output_filter_counted(
        &state,
        7,
        true,
        IpAddr::V6("2001:db8::10".parse().unwrap()),
        IpAddr::V6("2001:db8::200".parse().unwrap()),
        PROTO_TCP,
        40000,
        5201,
        0,
        TermMatchExtra::default(),
        1514,
    );
    assert_eq!(result.forwarding_class.as_deref(), Some("iperf-a"));
    let filter = state
        .filters
        .get("inet6:bandwidth-output")
        .expect("inet6 output filter");
    let term = filter.terms.first().expect("first term");
    assert_eq!(term.counter.packets.load(Ordering::Relaxed), 1);
    assert_eq!(term.counter.bytes.load(Ordering::Relaxed), 1514);
}

#[test]
fn interface_output_filter_without_count_does_not_record_term_hits() {
    let ifaces = vec![crate::InterfaceSnapshot {
        name: "reth0.80".into(),
        ifindex: 7,
        filter_output_v6: "bandwidth-output".into(),
        ..Default::default()
    }];
    let state = parse_filter_state(
        &[FirewallFilterSnapshot {
            name: "bandwidth-output".into(),
            family: "inet6".into(),
            terms: vec![FirewallTermSnapshot {
                name: "iperf-a".into(),
                action: "accept".into(),
                forwarding_class: "iperf-a".into(),
                protocols: vec!["tcp".into()],
                destination_ports: vec!["5201".into()],
                ..Default::default()
            }],
        }],
        &[],
        &ifaces,
        "",
        "",
    )
    .expect("filter state compiles");
    let result = evaluate_interface_output_filter_counted(
        &state,
        7,
        true,
        IpAddr::V6("2001:db8::10".parse().unwrap()),
        IpAddr::V6("2001:db8::200".parse().unwrap()),
        PROTO_TCP,
        40000,
        5201,
        0,
        TermMatchExtra::default(),
        1514,
    );
    assert_eq!(result.forwarding_class.as_deref(), Some("iperf-a"));
    let filter = state
        .filters
        .get("inet6:bandwidth-output")
        .expect("inet6 output filter");
    let term = filter.terms.first().expect("first term");
    assert_eq!(term.counter.packets.load(Ordering::Relaxed), 0);
    assert_eq!(term.counter.bytes.load(Ordering::Relaxed), 0);
}

#[test]
fn lo0_filter_evaluation() {
    let state = parse_filter_state(
        &[FirewallFilterSnapshot {
            name: "protect-RE".into(),
            family: "inet".into(),
            terms: vec![
                FirewallTermSnapshot {
                    name: "allow-ssh".into(),
                    protocols: vec!["tcp".into()],
                    destination_ports: vec!["22".into()],
                    action: "accept".into(),
                    ..Default::default()
                },
                FirewallTermSnapshot {
                    name: "deny-rest".into(),
                    action: "discard".into(),
                    ..Default::default()
                },
            ],
        }],
        &[],
        &[],
        "protect-RE",
        "",
    )
    .expect("filter state compiles");
    // SSH should pass lo0 filter
    let result = evaluate_lo0_filter(
        &state,
        false,
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        PROTO_TCP,
        12345,
        22,
        0,
        TermMatchExtra::default(),
    );
    assert_eq!(result.action, FilterAction::Accept);

    // HTTP should be denied by lo0 filter
    let result = evaluate_lo0_filter(
        &state,
        false,
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        PROTO_TCP,
        12345,
        80,
        0,
        TermMatchExtra::default(),
    );
    assert_eq!(result.action, FilterAction::Discard);
}

#[test]
fn dscp_match_in_term() {
    let state = make_filter_state(
        &[FirewallFilterSnapshot {
            name: "dscp-filter".into(),
            family: "inet".into(),
            terms: vec![
                FirewallTermSnapshot {
                    name: "match-ef".into(),
                    dscp_values: vec![46],
                    action: "accept".into(),
                    dscp_rewrite: None,
                    ..Default::default()
                },
                FirewallTermSnapshot {
                    name: "deny-rest".into(),
                    action: "discard".into(),
                    ..Default::default()
                },
            ],
        }],
        &[],
    );
    // DSCP 46 (EF) matches
    let result = evaluate_filter(
        &state,
        "inet:dscp-filter",
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        PROTO_UDP,
        1234,
        5060,
        46,
        TermMatchExtra::default(),
    );
    assert_eq!(result.action, FilterAction::Accept);

    // DSCP 0 doesn't match first term, falls through to deny
    let result = evaluate_filter(
        &state,
        "inet:dscp-filter",
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        PROTO_UDP,
        1234,
        5060,
        0,
        TermMatchExtra::default(),
    );
    assert_eq!(result.action, FilterAction::Discard);
}

#[test]
fn input_dscp_filter_families_changed_detects_same_ifindex_content_change() {
    let iface = crate::InterfaceSnapshot {
        name: "reth1.0".into(),
        ifindex: 10,
        filter_input_v4: "dscp-filter".into(),
        ..Default::default()
    };
    let old = make_filter_state_with_interfaces(
        &[FirewallFilterSnapshot {
            name: "dscp-filter".into(),
            family: "inet".into(),
            terms: vec![FirewallTermSnapshot {
                name: "dscp-term".into(),
                dscp_values: vec![0],
                action: "accept".into(),
                ..Default::default()
            }],
        }],
        std::slice::from_ref(&iface),
    );
    let new = make_filter_state_with_interfaces(
        &[FirewallFilterSnapshot {
            name: "dscp-filter".into(),
            family: "inet".into(),
            terms: vec![FirewallTermSnapshot {
                name: "dscp-term".into(),
                dscp_values: vec![46],
                action: "discard".into(),
                log: true,
                syslog: false,
                reject_message_type: String::new(),
                ..Default::default()
            }],
        }],
        &[iface],
    );

    assert_eq!(
        input_dscp_filter_families_changed(&old, &new),
        (true, false)
    );
}

#[test]
fn input_dscp_filter_families_changed_ignores_unchanged_filter() {
    let iface = crate::InterfaceSnapshot {
        name: "reth1.0".into(),
        ifindex: 10,
        filter_input_v4: "dscp-filter".into(),
        ..Default::default()
    };
    let filter = FirewallFilterSnapshot {
        name: "dscp-filter".into(),
        family: "inet".into(),
        terms: vec![FirewallTermSnapshot {
            name: "dscp-term".into(),
            dscp_values: vec![46],
            action: "discard".into(),
            log: true,
            syslog: false,
            reject_message_type: String::new(),
            ..Default::default()
        }],
    };
    let old = make_filter_state_with_interfaces(
        std::slice::from_ref(&filter),
        std::slice::from_ref(&iface),
    );
    let new = make_filter_state_with_interfaces(&[filter], &[iface]);

    assert_eq!(
        input_dscp_filter_families_changed(&old, &new),
        (false, false)
    );
}

#[test]
fn input_dscp_filter_families_changed_ignores_positional_filter_id_change() {
    let iface = crate::InterfaceSnapshot {
        name: "reth1.0".into(),
        ifindex: 10,
        filter_input_v4: "dscp-filter".into(),
        ..Default::default()
    };
    let unrelated = FirewallFilterSnapshot {
        name: "unrelated".into(),
        family: "inet".into(),
        terms: vec![FirewallTermSnapshot {
            name: "accept".into(),
            action: "accept".into(),
            ..Default::default()
        }],
    };
    let dscp_filter = FirewallFilterSnapshot {
        name: "dscp-filter".into(),
        family: "inet".into(),
        terms: vec![FirewallTermSnapshot {
            name: "dscp-term".into(),
            dscp_values: vec![46],
            action: "discard".into(),
            log: true,
            syslog: false,
            reject_message_type: String::new(),
            ..Default::default()
        }],
    };
    let old = make_filter_state_with_interfaces(
        &[unrelated.clone(), dscp_filter.clone()],
        std::slice::from_ref(&iface),
    );
    let new = make_filter_state_with_interfaces(&[dscp_filter, unrelated], &[iface]);

    assert_ne!(
        old.iface_filter_v4_fast.get(&10).unwrap().id,
        new.iface_filter_v4_fast.get(&10).unwrap().id,
        "test setup must shift the compiler-positional filter id"
    );
    assert_eq!(
        input_dscp_filter_families_changed(&old, &new),
        (false, false)
    );
}

#[test]
fn input_dscp_filter_families_changed_detects_three_color_shape_change() {
    let iface = crate::InterfaceSnapshot {
        name: "reth1.0".into(),
        ifindex: 10,
        filter_input_v4: "dscp-filter".into(),
        ..Default::default()
    };
    let filters = [FirewallFilterSnapshot {
        name: "dscp-filter".into(),
        family: "inet".into(),
        terms: vec![FirewallTermSnapshot {
            name: "dscp-term".into(),
            dscp_values: vec![46],
            action: "accept".into(),
            policer: "stable-pol".into(),
            ..Default::default()
        }],
    }];
    let original = [ThreeColorPolicerSnapshot {
        name: "stable-pol".into(),
        mode: "single-rate".into(),
        color_blind: true,
        committed_rate_bytes_per_sec: 1,
        committed_burst_bytes: 100,
        peak_or_excess_burst_bytes: 50,
        then_action: "discard".into(),
        ..Default::default()
    }];
    let changed = [ThreeColorPolicerSnapshot {
        committed_burst_bytes: 200,
        ..original[0].clone()
    }];

    let old = parse_filter_state_with_three_color(
        &filters,
        &[],
        &original,
        std::slice::from_ref(&iface),
        "",
        "",
    )
    .expect("filter state compiles");
    let new = parse_filter_state_with_three_color_preserving(
        &filters,
        &[],
        &changed,
        &[iface],
        "",
        "",
        Some(&old),
    )
    .expect("filter state compiles");

    assert!(
        !std::sync::Arc::ptr_eq(
            old.iface_filter_v4_fast.get(&10).unwrap().terms[0]
                .three_color_policer
                .as_ref()
                .unwrap(),
            new.iface_filter_v4_fast.get(&10).unwrap().terms[0]
                .three_color_policer
                .as_ref()
                .unwrap(),
        ),
        "test setup must create a new runtime for the changed policer shape"
    );
    assert_eq!(
        input_dscp_filter_families_changed(&old, &new),
        (true, false)
    );
}

// AC2 coverage for #1546: add/remove of a DSCP-sensitive interface filter
// must invalidate the affected family. The same_ifindex/positional/three-color
// tests above cover the other three AC2 scenarios; these two close the gap.

#[test]
fn input_dscp_filter_families_changed_detects_filter_added_to_interface() {
    let iface = crate::InterfaceSnapshot {
        name: "reth1.0".into(),
        ifindex: 10,
        filter_input_v4: "dscp-filter".into(),
        ..Default::default()
    };
    let filter = FirewallFilterSnapshot {
        name: "dscp-filter".into(),
        family: "inet".into(),
        terms: vec![FirewallTermSnapshot {
            name: "dscp-term".into(),
            dscp_values: vec![46],
            action: "discard".into(),
            log: true,
            syslog: false,
            reject_message_type: String::new(),
            ..Default::default()
        }],
    };

    // `old` has no DSCP-sensitive filter bound to ifindex 10.
    let bare_iface = crate::InterfaceSnapshot {
        name: "reth1.0".into(),
        ifindex: 10,
        ..Default::default()
    };
    let old = make_filter_state_with_interfaces(&[], std::slice::from_ref(&bare_iface));
    // `new` adds the DSCP-sensitive filter on the same interface — must trigger v4 family change.
    let new = make_filter_state_with_interfaces(&[filter], &[iface]);

    assert_eq!(
        input_dscp_filter_families_changed(&old, &new),
        (true, false)
    );
}

#[test]
fn input_dscp_filter_families_changed_detects_filter_removed_from_interface() {
    let iface = crate::InterfaceSnapshot {
        name: "reth1.0".into(),
        ifindex: 10,
        filter_input_v4: "dscp-filter".into(),
        ..Default::default()
    };
    let filter = FirewallFilterSnapshot {
        name: "dscp-filter".into(),
        family: "inet".into(),
        terms: vec![FirewallTermSnapshot {
            name: "dscp-term".into(),
            dscp_values: vec![46],
            action: "discard".into(),
            log: true,
            syslog: false,
            reject_message_type: String::new(),
            ..Default::default()
        }],
    };

    // `old` has the DSCP-sensitive filter bound to ifindex 10.
    let old = make_filter_state_with_interfaces(
        std::slice::from_ref(&filter),
        std::slice::from_ref(&iface),
    );
    // `new` removes the filter binding — must trigger v4 family change.
    let bare_iface = crate::InterfaceSnapshot {
        name: "reth1.0".into(),
        ifindex: 10,
        ..Default::default()
    };
    let new = make_filter_state_with_interfaces(&[], &[bare_iface]);

    assert_eq!(
        input_dscp_filter_families_changed(&old, &new),
        (true, false)
    );
}

// ============================================================
// #1725 — engine evaluation coverage gaps
//
// filter/tests.rs already covers most of eval.rs / tx_selection.rs /
// cache_sensitive.rs. The tests below fill the nine genuinely-uncovered
// behaviors identified in docs/pr/1725-filter-engine-tests/plan.md:
// Reject via the plain evaluate_filter path; missing-filter / empty-filter
// default; address-family mismatch default; IPv6 baseline evaluate / lo0 /
// interface-input paths; baseline counter increment; the non-routing
// (PBR-reject) variant; the FilterState-keyed tx_selection wrappers; the
// thin accessor predicates; and cached-vs-runtime baseline parity.
// ============================================================

// --- Gap 1: FilterAction::Reject(RejectMessage::ADMIN_PROHIBITED) through the plain evaluate_filter path ---
#[test]
fn evaluate_filter_returns_reject_action() {
    let state = make_filter_state(
        &[FirewallFilterSnapshot {
            name: "reject-filter".into(),
            family: "inet".into(),
            terms: vec![FirewallTermSnapshot {
                name: "reject-telnet".into(),
                protocols: vec!["tcp".into()],
                destination_ports: vec!["23".into()],
                action: "reject".into(),
                ..Default::default()
            }],
        }],
        &[],
    );
    let result = evaluate_filter(
        &state,
        "inet:reject-filter",
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        PROTO_TCP,
        40000,
        23,
        0,
        TermMatchExtra::default(),
    );
    assert_eq!(result.action, FilterAction::Reject(RejectMessage::ADMIN_PROHIBITED));
}

// --- Gap 2: missing filter key + empty filter both fall through to Accept ---
#[test]
fn evaluate_filter_missing_key_returns_default_accept() {
    let state = make_filter_state(
        &[FirewallFilterSnapshot {
            name: "present".into(),
            family: "inet".into(),
            terms: vec![FirewallTermSnapshot {
                name: "deny-all".into(),
                action: "discard".into(),
                ..Default::default()
            }],
        }],
        &[],
    );
    // A key that was never compiled must return the implicit Accept default,
    // never panic and never reach into an unrelated filter.
    let result = evaluate_filter(
        &state,
        "inet:does-not-exist",
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        PROTO_TCP,
        1234,
        80,
        0,
        TermMatchExtra::default(),
    );
    assert_eq!(result.action, FilterAction::Accept);
    assert_eq!(result, FilterResult::default());
}

#[test]
fn evaluate_filter_empty_filter_returns_default_accept() {
    let state = make_filter_state(
        &[FirewallFilterSnapshot {
            name: "empty".into(),
            family: "inet".into(),
            terms: vec![],
        }],
        &[],
    );
    let result = evaluate_filter(
        &state,
        "inet:empty",
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        PROTO_TCP,
        1234,
        80,
        0,
        TermMatchExtra::default(),
    );
    // A compiled-but-empty filter must fall through to the full default,
    // distinguishable from the missing-key path: the filter exists with zero
    // terms, so a compiler bug that dropped empty filters would also surface
    // here.
    assert_eq!(result, FilterResult::default());
    let filter = state
        .filters
        .get("inet:empty")
        .expect("empty filter compiled");
    assert!(filter.terms.is_empty());
}

// --- Gap 3: address-family mismatch (V4 src + V6 dst) takes the default arm ---
#[test]
fn evaluate_filter_mixed_address_family_returns_default_accept() {
    let state = make_filter_state(
        &[FirewallFilterSnapshot {
            name: "deny-all".into(),
            family: "inet".into(),
            terms: vec![FirewallTermSnapshot {
                name: "deny".into(),
                action: "discard".into(),
                ..Default::default()
            }],
        }],
        &[],
    );
    // A V4 source with a V6 destination hits the `_ => default` arm in
    // evaluate_filter_ref_counted rather than matching the discard term.
    let result = evaluate_filter(
        &state,
        "inet:deny-all",
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V6("2001:db8::2".parse().unwrap()),
        PROTO_TCP,
        1234,
        80,
        0,
        TermMatchExtra::default(),
    );
    // The default arm must produce the full default result, not just an Accept
    // action with leftover rewrite/routing/forwarding-class fields.
    assert_eq!(result, FilterResult::default());
}

// --- Gap 4: IPv6 baseline evaluate_filter / lo0 / interface-input paths ---
#[test]
fn evaluate_filter_ipv6_matches_term() {
    let state = make_filter_state(
        &[FirewallFilterSnapshot {
            name: "v6-filter".into(),
            family: "inet6".into(),
            terms: vec![
                FirewallTermSnapshot {
                    name: "deny-from-doc".into(),
                    source_addresses: vec!["2001:db8::/32".into()],
                    action: "discard".into(),
                    ..Default::default()
                },
                FirewallTermSnapshot {
                    name: "allow-rest".into(),
                    action: "accept".into(),
                    ..Default::default()
                },
            ],
        }],
        &[],
    );
    // In-prefix source matches the discard term.
    let denied = evaluate_filter(
        &state,
        "inet6:v6-filter",
        IpAddr::V6("2001:db8::100".parse().unwrap()),
        IpAddr::V6("2001:db8::200".parse().unwrap()),
        PROTO_TCP,
        40000,
        443,
        0,
        TermMatchExtra::default(),
    );
    assert_eq!(denied.action, FilterAction::Discard);
    // Out-of-prefix source falls through to the accept term.
    let allowed = evaluate_filter(
        &state,
        "inet6:v6-filter",
        IpAddr::V6("2001:db9::1".parse().unwrap()),
        IpAddr::V6("2001:db8::200".parse().unwrap()),
        PROTO_TCP,
        40000,
        443,
        0,
        TermMatchExtra::default(),
    );
    assert_eq!(allowed.action, FilterAction::Accept);
}

#[test]
fn evaluate_lo0_filter_ipv6_path() {
    let state = parse_filter_state(
        &[FirewallFilterSnapshot {
            name: "protect-RE-v6".into(),
            family: "inet6".into(),
            terms: vec![
                FirewallTermSnapshot {
                    name: "allow-ssh".into(),
                    protocols: vec!["tcp".into()],
                    destination_ports: vec!["22".into()],
                    action: "accept".into(),
                    ..Default::default()
                },
                FirewallTermSnapshot {
                    name: "deny-rest".into(),
                    action: "discard".into(),
                    ..Default::default()
                },
            ],
        }],
        &[],
        &[],
        "",
        "protect-RE-v6",
    )
    .expect("filter state compiles");
    let accepted = evaluate_lo0_filter(
        &state,
        true,
        IpAddr::V6("2001:db8::1".parse().unwrap()),
        IpAddr::V6("2001:db8::2".parse().unwrap()),
        PROTO_TCP,
        40000,
        22,
        0,
        TermMatchExtra::default(),
    );
    assert_eq!(accepted.action, FilterAction::Accept);
    let discarded = evaluate_lo0_filter(
        &state,
        true,
        IpAddr::V6("2001:db8::1".parse().unwrap()),
        IpAddr::V6("2001:db8::2".parse().unwrap()),
        PROTO_TCP,
        40000,
        80,
        0,
        TermMatchExtra::default(),
    );
    assert_eq!(discarded.action, FilterAction::Discard);
}

#[test]
fn evaluate_interface_filter_ipv6_input_path() {
    let ifaces = vec![crate::InterfaceSnapshot {
        name: "reth0.80".into(),
        ifindex: 9,
        filter_input_v6: "edge-in-v6".into(),
        ..Default::default()
    }];
    let state = parse_filter_state(
        &[FirewallFilterSnapshot {
            name: "edge-in-v6".into(),
            family: "inet6".into(),
            terms: vec![FirewallTermSnapshot {
                name: "deny-web".into(),
                protocols: vec!["tcp".into()],
                destination_ports: vec!["443".into()],
                action: "discard".into(),
                ..Default::default()
            }],
        }],
        &[],
        &ifaces,
        "",
        "",
    )
    .expect("filter state compiles");
    let result = evaluate_interface_filter(
        &state,
        9,
        true,
        IpAddr::V6("2001:db8::10".parse().unwrap()),
        IpAddr::V6("2001:db8::200".parse().unwrap()),
        PROTO_TCP,
        49152,
        443,
        0,
        TermMatchExtra::default(),
    );
    assert_eq!(result.action, FilterAction::Discard);
}

// --- Gap 5: baseline evaluate_filter_counted hit-counter increment (v4 + v6) ---
#[test]
fn evaluate_filter_counted_increments_term_counter() {
    let state = make_filter_state(
        &[FirewallFilterSnapshot {
            name: "counted".into(),
            family: "inet".into(),
            terms: vec![FirewallTermSnapshot {
                name: "count-web".into(),
                protocols: vec!["tcp".into()],
                destination_ports: vec!["80".into()],
                action: "accept".into(),
                count: "web-hits".into(),
                ..Default::default()
            }],
        }],
        &[],
    );
    let result = evaluate_filter_counted(
        &state,
        "inet:counted",
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        PROTO_TCP,
        40000,
        80,
        0,
        TermMatchExtra::default(),
        1400,
    );
    assert_eq!(result.action, FilterAction::Accept);
    let filter = state.filters.get("inet:counted").expect("counted filter");
    let term = filter.terms.first().expect("first term");
    assert_eq!(term.counter.packets.load(Ordering::Relaxed), 1);
    assert_eq!(term.counter.bytes.load(Ordering::Relaxed), 1400);

    // A non-matching packet (wrong port) must not bump the counter.
    let miss = evaluate_filter_counted(
        &state,
        "inet:counted",
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        PROTO_TCP,
        40000,
        443,
        0,
        TermMatchExtra::default(),
        1400,
    );
    assert_eq!(miss.action, FilterAction::Accept);
    assert_eq!(term.counter.packets.load(Ordering::Relaxed), 1);
    assert_eq!(term.counter.bytes.load(Ordering::Relaxed), 1400);
}

#[test]
fn evaluate_filter_counted_increments_term_counter_ipv6() {
    let state = make_filter_state(
        &[FirewallFilterSnapshot {
            name: "counted6".into(),
            family: "inet6".into(),
            terms: vec![FirewallTermSnapshot {
                name: "count-web".into(),
                protocols: vec!["tcp".into()],
                destination_ports: vec!["80".into()],
                action: "accept".into(),
                count: "web-hits-v6".into(),
                ..Default::default()
            }],
        }],
        &[],
    );
    let result = evaluate_filter_counted(
        &state,
        "inet6:counted6",
        IpAddr::V6("2001:db8::1".parse().unwrap()),
        IpAddr::V6("2001:db8::2".parse().unwrap()),
        PROTO_TCP,
        40000,
        80,
        0,
        TermMatchExtra::default(),
        1500,
    );
    assert_eq!(result.action, FilterAction::Accept);
    let filter = state.filters.get("inet6:counted6").expect("counted filter");
    let term = filter.terms.first().expect("first term");
    assert_eq!(term.counter.packets.load(Ordering::Relaxed), 1);
    assert_eq!(term.counter.bytes.load(Ordering::Relaxed), 1500);
}

// --- Gap 6: evaluate_interface_filter_non_routing_counted PBR-reject behavior ---
#[test]
fn interface_filter_non_routing_counted_defers_pbr_term() {
    let ifaces = vec![crate::InterfaceSnapshot {
        name: "reth1.0".into(),
        ifindex: 12,
        filter_input_v4: "mixed-pbr".into(),
        ..Default::default()
    }];
    let state = parse_filter_state(
        &[FirewallFilterSnapshot {
            name: "mixed-pbr".into(),
            family: "inet".into(),
            terms: vec![
                FirewallTermSnapshot {
                    name: "route-to-blue".into(),
                    protocols: vec!["tcp".into()],
                    destination_ports: vec!["5201".into()],
                    action: "accept".into(),
                    count: "pbr-hits".into(),
                    routing_instance: "blue".into(),
                    ..Default::default()
                },
                FirewallTermSnapshot {
                    name: "plain-deny".into(),
                    protocols: vec!["udp".into()],
                    destination_ports: vec!["53".into()],
                    action: "discard".into(),
                    count: "dns-hits".into(),
                    ..Default::default()
                },
            ],
        }],
        &[],
        &ifaces,
        "",
        "",
    )
    .expect("filter state compiles");

    // A packet that matches the routing-instance term must short-circuit to
    // the default (route-lookup wins) and must NOT increment that term's
    // counter — the non-routing evaluator returns before recording.
    let pbr = evaluate_interface_filter_non_routing_counted(
        &state,
        12,
        false,
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        PROTO_TCP,
        40000,
        5201,
        0,
        TermMatchExtra::default(),
        1400,
        NonRoutingCountPolicy::Always,
    );
    assert_eq!(pbr.action, FilterAction::Accept);
    // #5444: FilterResult.routing_instance is Option<Arc<str>>; the non-routing
    // evaluator resets it to None (it defers PBR to the routing-instance eval).
    assert!(pbr.routing_instance.is_none());
    let filter = state.iface_filter_v4_fast.get(&12).expect("input filter");
    assert_eq!(filter.terms[0].counter.packets.load(Ordering::Relaxed), 0);

    // A packet matching the plain (non-routing) term gets its action and a
    // counter bump as normal.
    let plain = evaluate_interface_filter_non_routing_counted(
        &state,
        12,
        false,
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        PROTO_UDP,
        40000,
        53,
        0,
        TermMatchExtra::default(),
        500,
        NonRoutingCountPolicy::Always,
    );
    assert_eq!(plain.action, FilterAction::Discard);
    assert_eq!(filter.terms[1].counter.packets.load(Ordering::Relaxed), 1);
    assert_eq!(filter.terms[1].counter.bytes.load(Ordering::Relaxed), 500);
}

// --- Gap 7: FilterState-keyed tx_selection dispatch wrappers ---
#[test]
fn interface_filter_tx_selection_wrappers_dispatch_and_default() {
    let ifaces = vec![crate::InterfaceSnapshot {
        name: "reth0.80".into(),
        ifindex: 7,
        filter_input_v4: "tx-in".into(),
        filter_output_v4: "tx-out".into(),
        ..Default::default()
    }];
    let state = parse_filter_state(
        &[
            FirewallFilterSnapshot {
                name: "tx-in".into(),
                family: "inet".into(),
                terms: vec![FirewallTermSnapshot {
                    name: "classify-in".into(),
                    protocols: vec!["tcp".into()],
                    destination_ports: vec!["5201".into()],
                    action: "accept".into(),
                    forwarding_class: "iperf-a".into(),
                    ..Default::default()
                }],
            },
            FirewallFilterSnapshot {
                name: "tx-out".into(),
                family: "inet".into(),
                terms: vec![FirewallTermSnapshot {
                    name: "classify-out".into(),
                    protocols: vec!["tcp".into()],
                    destination_ports: vec!["5202".into()],
                    action: "accept".into(),
                    forwarding_class: "iperf-b".into(),
                    ..Default::default()
                }],
            },
        ],
        &[],
        &ifaces,
        "",
        "",
    )
    .expect("filter state compiles");

    let input = evaluate_interface_filter_tx_selection_counted(
        &state,
        7,
        false,
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        PROTO_TCP,
        40000,
        5201,
        0,
        TermMatchExtra::default(),
        1400,
    );
    assert_eq!(input.action, FilterAction::Accept);
    assert_eq!(input.forwarding_class, Some("iperf-a"));

    let output = evaluate_interface_output_filter_tx_selection_counted(
        &state,
        7,
        false,
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        PROTO_TCP,
        40000,
        5202,
        0,
        TermMatchExtra::default(),
        1400,
    );
    assert_eq!(output.action, FilterAction::Accept);
    assert_eq!(output.forwarding_class, Some("iperf-b"));

    // No filter bound to an unrelated ifindex returns the default.
    let none_in = evaluate_interface_filter_tx_selection_counted(
        &state,
        99,
        false,
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        PROTO_TCP,
        40000,
        5201,
        0,
        TermMatchExtra::default(),
        1400,
    );
    assert_eq!(none_in.action, FilterAction::Accept);
    assert_eq!(none_in.forwarding_class, None);
}

// --- Gap 8: thin accessor predicates (grouped, table-driven) ---
#[test]
fn thin_accessor_predicates() {
    // Two separate input ifindices so the TX-selection and DSCP-match
    // accessors are cross-checked: ifindex 21 is TX-selection-only (a
    // forwarding-class term, no DSCP match), ifindex 22 is DSCP-only (a DSCP
    // match, no forwarding class). An accessor that consulted the wrong set
    // (aliasing bug) would flip on one of the cross-negative assertions
    // below. ifindex 23 carries a DSCP-match output filter.
    let ifaces = vec![
        crate::InterfaceSnapshot {
            name: "reth1.0".into(),
            ifindex: 21,
            filter_input_v4: "tx-only-in".into(),
            ..Default::default()
        },
        crate::InterfaceSnapshot {
            name: "reth1.1".into(),
            ifindex: 22,
            filter_input_v4: "dscp-only-in".into(),
            ..Default::default()
        },
        crate::InterfaceSnapshot {
            name: "reth1.2".into(),
            ifindex: 23,
            filter_output_v4: "dscp-out".into(),
            ..Default::default()
        },
    ];
    let state = parse_filter_state(
        &[
            FirewallFilterSnapshot {
                name: "tx-only-in".into(),
                family: "inet".into(),
                terms: vec![FirewallTermSnapshot {
                    name: "classify".into(),
                    protocols: vec!["tcp".into()],
                    action: "accept".into(),
                    forwarding_class: "iperf-a".into(),
                    ..Default::default()
                }],
            },
            FirewallFilterSnapshot {
                name: "dscp-only-in".into(),
                family: "inet".into(),
                terms: vec![FirewallTermSnapshot {
                    name: "match-ef".into(),
                    dscp_values: vec![46],
                    action: "accept".into(),
                    ..Default::default()
                }],
            },
            FirewallFilterSnapshot {
                name: "dscp-out".into(),
                family: "inet".into(),
                terms: vec![FirewallTermSnapshot {
                    name: "match-ef".into(),
                    dscp_values: vec![46],
                    action: "accept".into(),
                    ..Default::default()
                }],
            },
        ],
        &[],
        &ifaces,
        "",
        "",
    )
    .expect("filter state compiles");

    // #6236 PR-1: the per-ifindex `interface_filter_affects_tx_selection`
    // helper and its dead `iface_filter_v*_affects_tx_selection` sets are
    // removed. The retained family-wide aggregate carries the same fact: an
    // inet input filter affects TX selection (v4), none does for inet6.
    assert!(filter_state_has_input_tx_selection(&state, false));
    assert!(!filter_state_has_input_tx_selection(&state, true));

    // DSCP-match accessor reads the DSCP set, NOT the TX-selection set:
    // true on the DSCP-only ifindex, false on the TX-only ifindex.
    assert!(interface_input_filter_has_dscp_match(&state, 22, false));
    assert!(!interface_input_filter_has_dscp_match(&state, 21, false));
    assert!(!interface_input_filter_has_dscp_match(&state, 22, true));
    assert!(interface_output_filter_has_dscp_match(&state, 23, false));
    assert!(!interface_output_filter_has_dscp_match(&state, 23, true));
    // No filter bound to an unrelated ifindex.
    assert!(!interface_input_filter_has_dscp_match(&state, 99, false));
    assert!(!state.iface_filter_v4_fast.contains_key(&99));
}

// --- Gap 8b: a DSCP-match-only filter does not imply TX selection ---
#[test]
fn dscp_only_filter_does_not_imply_tx_selection() {
    // #6350 (#6236 PR-1 follow-up): the `thin_accessor_predicates` rewrite
    // deleted the per-ifindex `!interface_filter_affects_tx_selection(&state,
    // 22, false)` negative when the dead helper was removed. Restore that
    // guarantee at the retained family-wide accessor: a filter whose ONLY
    // modifier is a DSCP *match* (`from dscp`) — NO forwarding-class
    // classification, NO `then dscp` rewrite, NO counter / log /
    // three-color-policer / terminal action — must NOT flip the input
    // tx-selection aggregate. `affects_tx_selection` keys strictly on
    // forwarding-class or dscp_rewrite (compiler.rs), so a from-dscp match
    // sets `has_dscp_match_terms` but leaves tx-selection untouched. Make it
    // the ONLY input filter so the family-wide aggregate reflects it alone.
    let ifaces = vec![crate::InterfaceSnapshot {
        name: "reth1.0".into(),
        ifindex: 41,
        filter_input_v4: "dscp-only-in".into(),
        ..Default::default()
    }];
    let state = parse_filter_state(
        &[FirewallFilterSnapshot {
            name: "dscp-only-in".into(),
            family: "inet".into(),
            terms: vec![FirewallTermSnapshot {
                name: "match-ef".into(),
                dscp_values: vec![46],
                action: "accept".into(),
                ..Default::default()
            }],
        }],
        &[],
        &ifaces,
        "",
        "",
    )
    .expect("filter state compiles");

    // The DSCP-only input filter must NOT imply tx-selection for either
    // family. If the compiler ever mis-classified a DSCP-bearing filter as
    // tx-selecting (e.g. keying `affects_tx_selection` on dscp_match_enabled),
    // the v4 assertion goes RED.
    assert!(
        !filter_state_has_input_tx_selection(&state, false),
        "a DSCP-match-only input filter must not imply v4 tx-selection"
    );
    assert!(
        !filter_state_has_input_tx_selection(&state, true),
        "no inet6 input filter is present"
    );
    // Sanity: the filter IS bound and IS a DSCP-match filter, proving the
    // negatives above are about tx-selection classification, not a missing
    // filter bind that would trivially make every accessor false.
    assert!(interface_input_filter_has_dscp_match(&state, 41, false));
    assert_eq!(
        state.iface_filter_v4_fast.get(&41).map(|f| f.name.as_str()),
        Some("dscp-only-in")
    );
}

// --- Gap 9: cached-vs-runtime baseline parity for a plain (no-policer) term ---
#[test]
fn cached_and_runtime_tx_selection_agree_on_plain_term() {
    let ifaces = vec![crate::InterfaceSnapshot {
        name: "reth0.80".into(),
        ifindex: 30,
        filter_input_v4: "parity".into(),
        ..Default::default()
    }];
    let state = parse_filter_state(
        &[FirewallFilterSnapshot {
            name: "parity".into(),
            family: "inet".into(),
            terms: vec![FirewallTermSnapshot {
                name: "classify".into(),
                protocols: vec!["tcp".into()],
                destination_ports: vec!["5201".into()],
                action: "accept".into(),
                forwarding_class: "iperf-a".into(),
                dscp_rewrite: Some(46),
                log: true,
                syslog: false,
                reject_message_type: String::new(),
                ..Default::default()
            }],
        }],
        &[],
        &ifaces,
        "",
        "",
    )
    .expect("filter state compiles");
    let filter = state.iface_filter_v4_fast.get(&30).expect("input filter");
    let src = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let dst = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

    let runtime = evaluate_filter_ref_tx_selection_runtime_counted(
        filter,
        src,
        dst,
        PROTO_TCP,
        40000,
        5201,
        0,
        TermMatchExtra::default(),
        0,
        1,
    );
    let cached =
        evaluate_filter_ref_tx_selection_cached(filter, src, dst, PROTO_TCP, 40000, 5201, 0);

    // A term with no three-color policer must yield identical action,
    // forwarding-class, DSCP rewrite, and log-match identity on both paths.
    assert_eq!(runtime.action, cached.action);
    assert_eq!(runtime.action, FilterAction::Accept);
    assert_eq!(runtime.forwarding_class, cached.forwarding_class.as_deref());
    assert_eq!(runtime.forwarding_class, Some("iperf-a"));
    assert_eq!(runtime.dscp_rewrite, cached.dscp_rewrite);
    assert_eq!(runtime.dscp_rewrite, Some(46));
    assert_eq!(runtime.log_match, cached.log_match);
    assert!(runtime.log_match.is_some());
    assert!(!runtime.policer_drop);
}

// ===========================================================================
// #2362 per-packet L4 match conditions (tcp-flags / is-fragment / icmp-type /
// icmp-code). These were parsed by the Go compiler but dropped on the wire and
// absent from the Rust matcher, so a term matched broader than authored. The
// tests below exercise the runtime match predicate directly: a packet matching
// the condition triggers the term action; one that does not (wrong flags / not
// a fragment / wrong icmp-type / wrong protocol) falls through to the default.
// ===========================================================================

// Build a one-term filter carrying explicit per-packet conditions, then a
// trailing accept-all term so a non-match is observably Accept.
fn per_packet_filter(
    family: &str,
    proto: &str,
    tcp_flags: Option<u8>,
    is_fragment: bool,
    icmp_type: Option<u8>,
    icmp_code: Option<u8>,
) -> Vec<FirewallFilterSnapshot> {
    vec![FirewallFilterSnapshot {
        name: "pp".into(),
        family: family.into(),
        terms: vec![
            FirewallTermSnapshot {
                name: "match".into(),
                protocols: if proto.is_empty() {
                    vec![]
                } else {
                    vec![proto.into()]
                },
                action: "discard".into(),
                tcp_flags,
                is_fragment,
                // #2545: icmp-type / icmp-code are multi-value on the wire. The
                // helper still takes an Option for call-site brevity; map
                // Some(v) -> single-element set, None -> empty (no constraint).
                icmp_types: icmp_type.into_iter().collect(),
                icmp_codes: icmp_code.into_iter().collect(),
                ..Default::default()
            },
            FirewallTermSnapshot {
                name: "rest".into(),
                action: "accept".into(),
                ..Default::default()
            },
        ],
    }]
}

fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(a, b, c, d))
}

fn extra_tcp(flags: u8) -> TermMatchExtra<'static> {
    TermMatchExtra {
        tcp_flags: flags,
        // A real (first/atomic) TCP segment has an L4 header — the matcher
        // gates tcp-flags on l4_present (#2362 fold A).
        l4_present: true,
        flex_l3: None,
        ..Default::default()
    }
}

#[test]
fn tcp_flags_term_matches_syn_only() {
    // tcp-flags syn then discard: SYN(0x02) is dropped, a pure ACK forwards.
    let state = make_filter_state(
        &per_packet_filter("inet", "tcp", Some(0x02), false, None, None),
        &[],
    );
    let syn = evaluate_filter(
        &state,
        "inet:pp",
        v4(10, 0, 0, 1),
        v4(10, 0, 0, 2),
        PROTO_TCP,
        1000,
        22,
        0,
        extra_tcp(0x02),
    );
    assert_eq!(
        syn.action,
        FilterAction::Discard,
        "SYN must match tcp-flags syn"
    );
    let ack = evaluate_filter(
        &state,
        "inet:pp",
        v4(10, 0, 0, 1),
        v4(10, 0, 0, 2),
        PROTO_TCP,
        1000,
        22,
        0,
        extra_tcp(0x10),
    );
    assert_eq!(
        ack.action,
        FilterAction::Accept,
        "pure ACK must NOT match tcp-flags syn"
    );
    // SYN+ACK has SYN set -> still matches (Junos `tcp-flags syn` semantics).
    let synack = evaluate_filter(
        &state,
        "inet:pp",
        v4(10, 0, 0, 1),
        v4(10, 0, 0, 2),
        PROTO_TCP,
        1000,
        22,
        0,
        extra_tcp(0x12),
    );
    assert_eq!(
        synack.action,
        FilterAction::Discard,
        "SYN+ACK has SYN set -> matches"
    );
}

#[test]
fn tcp_flags_term_requires_all_listed_flags() {
    // tcp-flags (syn & ack) folded to mask 0x12: only a segment with BOTH set matches.
    let state = make_filter_state(
        &per_packet_filter("inet", "tcp", Some(0x12), false, None, None),
        &[],
    );
    let synack = evaluate_filter(
        &state,
        "inet:pp",
        v4(10, 0, 0, 1),
        v4(10, 0, 0, 2),
        PROTO_TCP,
        1000,
        80,
        0,
        extra_tcp(0x12),
    );
    assert_eq!(synack.action, FilterAction::Discard);
    let syn = evaluate_filter(
        &state,
        "inet:pp",
        v4(10, 0, 0, 1),
        v4(10, 0, 0, 2),
        PROTO_TCP,
        1000,
        80,
        0,
        extra_tcp(0x02),
    );
    assert_eq!(
        syn.action,
        FilterAction::Accept,
        "SYN alone lacks ACK -> no match"
    );
}

#[test]
fn tcp_flags_term_forbidden_mask_excludes_negated_flag() {
    // #3076: `tcp-flags "syn & !ack"` -> required SYN(0x02), forbidden ACK(0x10).
    // A bare SYN matches; a SYN+ACK does NOT (ACK is forbidden); a pure ACK does
    // NOT (SYN missing). Before #3076 the `!ack` half was dropped on the wire, so
    // a SYN+ACK wrongly matched (the term fired regardless of the ACK bit).
    let filter = vec![FirewallFilterSnapshot {
        name: "pp".into(),
        family: "inet".into(),
        terms: vec![
            FirewallTermSnapshot {
                name: "match".into(),
                protocols: vec!["tcp".into()],
                action: "discard".into(),
                tcp_flags: Some(0x02),
                tcp_flags_forbidden: Some(0x10),
                tcp_flags_unparseable: false,
                icmp_type_unrepresentable: false,
                icmp_code_unrepresentable: false,
                dscp_match_unrepresentable: false,
                ports_unrepresentable: false,
                address_unrepresentable: false,
                ..Default::default()
            },
            FirewallTermSnapshot {
                name: "rest".into(),
                action: "accept".into(),
                ..Default::default()
            },
        ],
    }];
    let state = make_filter_state(&filter, &[]);
    let eval = |flags: u8| {
        evaluate_filter(
            &state,
            "inet:pp",
            v4(10, 0, 0, 1),
            v4(10, 0, 0, 2),
            PROTO_TCP,
            1000,
            22,
            0,
            extra_tcp(flags),
        )
        .action
    };
    assert_eq!(
        eval(0x02),
        FilterAction::Discard,
        "bare SYN must match syn & !ack"
    );
    assert_eq!(
        eval(0x12),
        FilterAction::Accept,
        "SYN+ACK must NOT match syn & !ack (ACK forbidden) — pre-#3076 fail-open"
    );
    assert_eq!(
        eval(0x10),
        FilterAction::Accept,
        "pure ACK must NOT match syn & !ack (SYN required)"
    );
}

#[test]
fn tcp_flags_term_forbidden_only_mask() {
    // #3076: a pure-negation `!rst` -> required None, forbidden RST(0x04). Any TCP
    // segment without RST matches; one with RST does not.
    let filter = vec![FirewallFilterSnapshot {
        name: "pp".into(),
        family: "inet".into(),
        terms: vec![
            FirewallTermSnapshot {
                name: "match".into(),
                protocols: vec!["tcp".into()],
                action: "discard".into(),
                tcp_flags: None,
                tcp_flags_forbidden: Some(0x04),
                tcp_flags_unparseable: false,
                icmp_type_unrepresentable: false,
                icmp_code_unrepresentable: false,
                dscp_match_unrepresentable: false,
                ports_unrepresentable: false,
                address_unrepresentable: false,
                ..Default::default()
            },
            FirewallTermSnapshot {
                name: "rest".into(),
                action: "accept".into(),
                ..Default::default()
            },
        ],
    }];
    let state = make_filter_state(&filter, &[]);
    let eval = |flags: u8| {
        evaluate_filter(
            &state,
            "inet:pp",
            v4(10, 0, 0, 1),
            v4(10, 0, 0, 2),
            PROTO_TCP,
            1000,
            22,
            0,
            extra_tcp(flags),
        )
        .action
    };
    assert_eq!(
        eval(0x02),
        FilterAction::Discard,
        "SYN (no RST) matches !rst"
    );
    assert_eq!(
        eval(0x04),
        FilterAction::Accept,
        "RST set must NOT match !rst"
    );
}

#[test]
fn tcp_flags_term_does_not_match_non_tcp() {
    // A tcp-flags term must never match a UDP packet even if the (meaningless)
    // tcp_flags byte happens to carry the bits.
    let state = make_filter_state(
        &per_packet_filter("inet", "", Some(0x02), false, None, None),
        &[],
    );
    let udp = evaluate_filter(
        &state,
        "inet:pp",
        v4(10, 0, 0, 1),
        v4(10, 0, 0, 2),
        PROTO_UDP,
        1000,
        53,
        0,
        extra_tcp(0x02),
    );
    assert_eq!(
        udp.action,
        FilterAction::Accept,
        "UDP must not match a tcp-flags term"
    );
}

#[test]
fn is_fragment_term_spares_non_fragments() {
    let state = make_filter_state(&per_packet_filter("inet", "", None, true, None, None), &[]);
    let frag = TermMatchExtra {
        is_fragment: true,
        ..Default::default()
    };
    let dropped = evaluate_filter(
        &state,
        "inet:pp",
        v4(10, 0, 0, 1),
        v4(10, 0, 0, 2),
        PROTO_UDP,
        1000,
        53,
        0,
        frag,
    );
    assert_eq!(
        dropped.action,
        FilterAction::Discard,
        "a fragment must match is-fragment"
    );
    let whole = evaluate_filter(
        &state,
        "inet:pp",
        v4(10, 0, 0, 1),
        v4(10, 0, 0, 2),
        PROTO_UDP,
        1000,
        53,
        0,
        TermMatchExtra::default(),
    );
    assert_eq!(
        whole.action,
        FilterAction::Accept,
        "a non-fragment must NOT match is-fragment"
    );
}

#[test]
fn icmp_type_term_matches_only_that_type_v4() {
    // icmp-type 8 (echo-request) then discard must NOT collapse to drop-all-ICMP.
    let state = make_filter_state(
        &per_packet_filter("inet", "icmp", None, false, Some(8), None),
        &[],
    );
    let echo = TermMatchExtra {
        icmp_type: 8,
        l4_present: true,
        flex_l3: None,
        ..Default::default()
    };
    let drop = evaluate_filter(
        &state,
        "inet:pp",
        v4(10, 0, 0, 1),
        v4(10, 0, 0, 2),
        PROTO_ICMP,
        0,
        0,
        0,
        echo,
    );
    assert_eq!(
        drop.action,
        FilterAction::Discard,
        "echo-request must match icmp-type 8"
    );
    let reply = TermMatchExtra {
        icmp_type: 0,
        l4_present: true,
        flex_l3: None,
        ..Default::default()
    };
    let pass = evaluate_filter(
        &state,
        "inet:pp",
        v4(10, 0, 0, 1),
        v4(10, 0, 0, 2),
        PROTO_ICMP,
        0,
        0,
        0,
        reply,
    );
    assert_eq!(
        pass.action,
        FilterAction::Accept,
        "echo-reply (type 0) must NOT match icmp-type 8"
    );
}

#[test]
fn icmp_type_term_matches_icmpv6() {
    // icmp-type 128 (ICMPv6 echo-request) on an inet6 filter.
    let state = make_filter_state(
        &per_packet_filter("inet6", "icmpv6", None, false, Some(128), None),
        &[],
    );
    let v6 = |s: &str| IpAddr::V6(s.parse::<Ipv6Addr>().unwrap());
    let echo = TermMatchExtra {
        icmp_type: 128,
        l4_present: true,
        flex_l3: None,
        ..Default::default()
    };
    let drop = evaluate_filter(
        &state,
        "inet6:pp",
        v6("2001:db8::1"),
        v6("2001:db8::2"),
        PROTO_ICMPV6,
        0,
        0,
        0,
        echo,
    );
    assert_eq!(drop.action, FilterAction::Discard);
    let na = TermMatchExtra {
        icmp_type: 136,
        l4_present: true,
        flex_l3: None,
        ..Default::default()
    };
    let pass = evaluate_filter(
        &state,
        "inet6:pp",
        v6("2001:db8::1"),
        v6("2001:db8::2"),
        PROTO_ICMPV6,
        0,
        0,
        0,
        na,
    );
    assert_eq!(
        pass.action,
        FilterAction::Accept,
        "neighbor-advert (136) must NOT match icmp-type 128"
    );
}

#[test]
fn icmp_code_term_narrows_within_type() {
    // icmp-type 3 code 4 (frag-needed) — code 0 must not match.
    let state = make_filter_state(
        &per_packet_filter("inet", "icmp", None, false, Some(3), Some(4)),
        &[],
    );
    let frag_needed = TermMatchExtra {
        icmp_type: 3,
        icmp_code: 4,
        l4_present: true,
        flex_l3: None,
        ..Default::default()
    };
    let drop = evaluate_filter(
        &state,
        "inet:pp",
        v4(10, 0, 0, 1),
        v4(10, 0, 0, 2),
        PROTO_ICMP,
        0,
        0,
        0,
        frag_needed,
    );
    assert_eq!(drop.action, FilterAction::Discard);
    let net_unreach = TermMatchExtra {
        icmp_type: 3,
        icmp_code: 0,
        l4_present: true,
        flex_l3: None,
        ..Default::default()
    };
    let pass = evaluate_filter(
        &state,
        "inet:pp",
        v4(10, 0, 0, 1),
        v4(10, 0, 0, 2),
        PROTO_ICMP,
        0,
        0,
        0,
        net_unreach,
    );
    assert_eq!(
        pass.action,
        FilterAction::Accept,
        "code 0 must NOT match icmp-code 4"
    );
}

#[test]
fn icmp_term_does_not_match_non_icmp() {
    let state = make_filter_state(
        &per_packet_filter("inet", "", None, false, Some(8), None),
        &[],
    );
    // A TCP packet whose byte happens to equal 8 must not match an icmp-type term.
    // l4_present: true so this proves the PROTOCOL gate, not the l4-absence gate.
    let tcp = TermMatchExtra {
        tcp_flags: 0x02,
        icmp_type: 8,
        l4_present: true,
        flex_l3: None,
        ..Default::default()
    };
    let pass = evaluate_filter(
        &state,
        "inet:pp",
        v4(10, 0, 0, 1),
        v4(10, 0, 0, 2),
        PROTO_TCP,
        1000,
        80,
        0,
        tcp,
    );
    assert_eq!(
        pass.action,
        FilterAction::Accept,
        "TCP must not match an icmp-type term"
    );
}

#[test]
fn per_packet_match_action_applies_with_count() {
    // The term action AND its count side-effect apply on a per-packet match.
    let filters = vec![FirewallFilterSnapshot {
        name: "c".into(),
        family: "inet".into(),
        terms: vec![FirewallTermSnapshot {
            name: "syn".into(),
            protocols: vec!["tcp".into()],
            action: "discard".into(),
            count: "syns".into(),
            tcp_flags: Some(0x02),
            ..Default::default()
        }],
    }];
    let state = make_filter_state(&filters, &[]);
    let r = evaluate_filter_counted(
        &state,
        "inet:c",
        v4(10, 0, 0, 1),
        v4(10, 0, 0, 2),
        PROTO_TCP,
        1000,
        22,
        0,
        extra_tcp(0x02),
        1500,
    );
    assert_eq!(r.action, FilterAction::Discard);
    let filter = state.filters.get("inet:c").expect("filter");
    assert_eq!(filter.terms[0].counter.packets.load(Ordering::Relaxed), 1);
    assert_eq!(filter.terms[0].counter.bytes.load(Ordering::Relaxed), 1500);
    // A non-matching ACK must NOT bump the counter.
    let _ = evaluate_filter_counted(
        &state,
        "inet:c",
        v4(10, 0, 0, 1),
        v4(10, 0, 0, 2),
        PROTO_TCP,
        1000,
        22,
        0,
        extra_tcp(0x10),
        1500,
    );
    assert_eq!(filter.terms[0].counter.packets.load(Ordering::Relaxed), 1);
}

#[test]
fn per_packet_match_marks_filter_cache_sensitive() {
    // A filter carrying any per-packet L4 match term must be flagged so the
    // flow-cache declines (path (b), #1431/#2362) and the on-session re-eval
    // gate fires.
    let filters = per_packet_filter("inet", "tcp", Some(0x02), false, None, None);
    let interfaces = [crate::InterfaceSnapshot {
        ifindex: 7,
        filter_input_v4: "pp".into(),
        ..Default::default()
    }];
    let state =
        parse_filter_state(&filters, &[], &interfaces, "", "").expect("filter state compiles");
    // #6236 PR-2B: read the `has_per_packet_l4_match_terms` flag off the fast
    // map (the `iface_filter_v4_has_per_packet_l4_match` set is deleted).
    assert!(
        state
            .iface_filter_v4_fast
            .get(&7)
            .is_some_and(|f| f.has_per_packet_l4_match_terms),
        "interface input filter with a tcp-flags term must be marked per-packet-L4 cache-sensitive"
    );
    assert!(interface_input_filter_has_per_packet_l4_match(
        &state, 7, false
    ));
    let filter = state.iface_filter_v4_fast.get(&7).expect("filter");
    assert!(filter.has_per_packet_l4_match_terms);
}

// #2362 / #1961-class wire round-trip: a Go-encoded FirewallTermSnapshot with
// the new fields must decode into the Rust DTO with the same values. Guards the
// one-sided-field decode-failure (whole-snapshot abort -> no transit) class.
#[test]
fn firewall_term_snapshot_per_packet_fields_round_trip() {
    let json = r#"{
        "name": "syn-only",
        "protocols": ["tcp"],
        "action": "discard",
        "tcp_flags": 2,
        "is_fragment": true,
        "icmp_types": [8, 13],
        "icmp_codes": [0]
    }"#;
    let term: FirewallTermSnapshot = serde_json::from_str(json).expect("decode");
    assert_eq!(term.tcp_flags, Some(2));
    assert!(term.is_fragment);
    // #2545: icmp-type / icmp-code are multi-value sets on the wire.
    assert_eq!(term.icmp_types, vec![8, 13]);
    assert_eq!(term.icmp_codes, vec![0]);
    // Absent fields default to empty/None/false (forward/backward compat).
    let minimal: FirewallTermSnapshot =
        serde_json::from_str(r#"{"name":"x","action":"accept"}"#).expect("decode minimal");
    assert_eq!(minimal.tcp_flags, None);
    assert!(!minimal.is_fragment);
    assert!(minimal.icmp_types.is_empty());
    assert!(minimal.icmp_codes.is_empty());
}

// #2362 fold A (Copilot): the L4-present gate. Forcing the icmp byte to 0 for a
// non-first fragment is NOT sufficient, because 0 is a valid icmp-type
// (echo-reply) and a valid icmp-code — a value-only check would still match
// `from { icmp-type 0 }` / `from { icmp-code 0 }`. The matcher MUST key off
// extra.l4_present (false for a non-first fragment) so those terms fail closed,
// while is-fragment (L3-derived) STILL matches. These fail if the gate reverts
// to the value-0 sentinel.
#[test]
fn non_first_fragment_does_not_match_icmp_type_zero() {
    let state = make_filter_state(
        &per_packet_filter("inet", "icmp", None, false, Some(0), None),
        &[],
    );
    // What term_match_extra_from_frame produces for a non-first ICMP fragment:
    // l4_present false, icmp bytes forced 0, is_fragment true.
    let frag = TermMatchExtra {
        l4_present: false,
        flex_l3: None,
        icmp_type: 0,
        is_fragment: true,
        ..Default::default()
    };
    let r = evaluate_filter(
        &state,
        "inet:pp",
        v4(10, 0, 0, 1),
        v4(10, 0, 0, 2),
        PROTO_ICMP,
        0,
        0,
        0,
        frag,
    );
    assert_eq!(
        r.action,
        FilterAction::Accept,
        "a non-first fragment (no L4 header) must NOT match `icmp-type 0` (#2362 fold A)"
    );
    // Anti-over-gate: a real echo-reply (type 0, l4_present) DOES match.
    let echo_reply = TermMatchExtra {
        l4_present: true,
        flex_l3: None,
        icmp_type: 0,
        ..Default::default()
    };
    let r2 = evaluate_filter(
        &state,
        "inet:pp",
        v4(10, 0, 0, 1),
        v4(10, 0, 0, 2),
        PROTO_ICMP,
        0,
        0,
        0,
        echo_reply,
    );
    assert_eq!(
        r2.action,
        FilterAction::Discard,
        "a real echo-reply (icmp-type 0, L4 present) MUST match `icmp-type 0`"
    );
}

#[test]
fn non_first_fragment_does_not_match_icmp_code_zero() {
    let state = make_filter_state(
        &per_packet_filter("inet", "icmp", None, false, None, Some(0)),
        &[],
    );
    let frag = TermMatchExtra {
        l4_present: false,
        flex_l3: None,
        icmp_code: 0,
        is_fragment: true,
        ..Default::default()
    };
    let r = evaluate_filter(
        &state,
        "inet:pp",
        v4(10, 0, 0, 1),
        v4(10, 0, 0, 2),
        PROTO_ICMP,
        0,
        0,
        0,
        frag,
    );
    assert_eq!(
        r.action,
        FilterAction::Accept,
        "a non-first fragment must NOT match `icmp-code 0` (#2362 fold A)"
    );
    let real = TermMatchExtra {
        l4_present: true,
        flex_l3: None,
        icmp_code: 0,
        ..Default::default()
    };
    let r2 = evaluate_filter(
        &state,
        "inet:pp",
        v4(10, 0, 0, 1),
        v4(10, 0, 0, 2),
        PROTO_ICMP,
        0,
        0,
        0,
        real,
    );
    assert_eq!(
        r2.action,
        FilterAction::Discard,
        "a real ICMP packet with code 0 (L4 present) MUST match `icmp-code 0`"
    );
}

// #3008 (meta sibling of #2449): end-to-end matcher proof for the meta-only
// TX-selection path. `term_match_extra_from_meta` cannot read the ICMP type/code
// (no frame), so for an ICMP-family packet it emits `l4_present: false` with
// `icmp_type/icmp_code = 0`. The matcher MUST treat that exactly like a non-first
// fragment: the `icmp-type 0` / `icmp-code 0` terms fail closed. A genuinely-
// known type/code 0 (l4_present true, e.g. the frame path on a full echo-reply)
// MUST still match. Pre-fix the meta helper stamped l4_present=true, so these
// terms false-matched every meta-only ICMP packet.
#[test]
fn meta_only_icmp_does_not_match_icmp_type_zero_but_known_type_does() {
    let state = make_filter_state(
        &per_packet_filter("inet", "icmp", None, false, Some(0), None),
        &[],
    );
    // What the fixed `term_match_extra_from_meta` produces for a meta-only ICMP
    // packet: l4_present FALSE (type/code unknown), icmp bytes 0, not a fragment.
    let meta_icmp = TermMatchExtra {
        l4_present: false,
        flex_l3: None,
        icmp_type: 0,
        is_fragment: false,
        ..Default::default()
    };
    let r = evaluate_filter(
        &state,
        "inet:pp",
        v4(10, 0, 0, 1),
        v4(10, 0, 0, 2),
        PROTO_ICMP,
        0,
        0,
        0,
        meta_icmp,
    );
    assert_eq!(
        r.action,
        FilterAction::Accept,
        "a meta-only ICMP packet (real type unknown) must NOT match `icmp-type 0` (#3008)"
    );
    // A genuinely-known echo-reply (type 0, L4 parsed) DOES match.
    let known = TermMatchExtra {
        l4_present: true,
        flex_l3: None,
        icmp_type: 0,
        ..Default::default()
    };
    let r2 = evaluate_filter(
        &state,
        "inet:pp",
        v4(10, 0, 0, 1),
        v4(10, 0, 0, 2),
        PROTO_ICMP,
        0,
        0,
        0,
        known,
    );
    assert_eq!(
        r2.action,
        FilterAction::Discard,
        "a packet with a genuinely-known icmp-type 0 (L4 present) MUST still match (#3008)"
    );
}

#[test]
fn non_first_fragment_still_matches_is_fragment() {
    // The is-fragment term is L3-derived and NOT gated by l4_present.
    let state = make_filter_state(&per_packet_filter("inet", "", None, true, None, None), &[]);
    let frag = TermMatchExtra {
        l4_present: false,
        flex_l3: None,
        is_fragment: true,
        ..Default::default()
    };
    let r = evaluate_filter(
        &state,
        "inet:pp",
        v4(10, 0, 0, 1),
        v4(10, 0, 0, 2),
        PROTO_ICMP,
        0,
        0,
        0,
        frag,
    );
    assert_eq!(
        r.action,
        FilterAction::Discard,
        "a non-first fragment IS a fragment — is-fragment must still match (#2362 fold A)"
    );
}

// #2545: icmp-type / icmp-code are multi-value SET membership (match-ANY). A
// term `from { icmp-type 8; icmp-type 13; } then discard` must drop a packet of
// EITHER type, leave a third type untouched, and an empty set must match any.
// Build a filter with a multi-element icmp-type set directly on the snapshot.
fn icmp_type_set_filter(types: Vec<u8>) -> Vec<FirewallFilterSnapshot> {
    vec![FirewallFilterSnapshot {
        name: "pp".into(),
        family: "inet".into(),
        terms: vec![
            FirewallTermSnapshot {
                name: "match".into(),
                protocols: vec!["icmp".into()],
                action: "discard".into(),
                icmp_types: types,
                ..Default::default()
            },
            FirewallTermSnapshot {
                name: "rest".into(),
                action: "accept".into(),
                ..Default::default()
            },
        ],
    }]
}

#[test]
fn icmp_type_multi_value_matches_any_in_set_2545() {
    let state = make_filter_state(&icmp_type_set_filter(vec![8, 13]), &[]);
    let eval = |t: u8| {
        evaluate_filter(
            &state,
            "inet:pp",
            v4(10, 0, 0, 1),
            v4(10, 0, 0, 2),
            PROTO_ICMP,
            0,
            0,
            0,
            TermMatchExtra {
                icmp_type: t,
                l4_present: true,
                flex_l3: None,
                ..Default::default()
            },
        )
        .action
    };
    // Either configured type matches (match-ANY).
    assert_eq!(eval(8), FilterAction::Discard, "type 8 in set must drop");
    assert_eq!(eval(13), FilterAction::Discard, "type 13 in set must drop");
    // A third type does NOT match — the earlier value was NOT dropped by the
    // last-write-wins scalar bug.
    assert_eq!(
        eval(0),
        FilterAction::Accept,
        "type 0 (not in {{8,13}}) must NOT match"
    );
}

#[test]
fn icmp_type_empty_set_matches_any_2545() {
    // An EMPTY icmp-type set means the criterion is unconstrained: the term
    // (protocol icmp, discard) matches any ICMP type.
    let state = make_filter_state(&icmp_type_set_filter(vec![]), &[]);
    let r = evaluate_filter(
        &state,
        "inet:pp",
        v4(10, 0, 0, 1),
        v4(10, 0, 0, 2),
        PROTO_ICMP,
        0,
        0,
        0,
        TermMatchExtra {
            icmp_type: 42,
            l4_present: true,
            flex_l3: None,
            ..Default::default()
        },
    );
    assert_eq!(
        r.action,
        FilterAction::Discard,
        "empty icmp-type set must leave the type unconstrained (match any)"
    );
}

// #2399 (032-16): a snapshot/version-drift term carrying a NON-EMPTY but
// unrecognized action string must fail CLOSED (discard), never silently permit.
// The Go commit gate (validateFilterActionsStrict) rejects an unknown `then`
// token before it can be persisted, so a non-empty unknown action can only
// reach the dataplane via a mixed-version snapshot — and for a firewall filter
// that must deny, not accept. MUST FAIL if parse_term's non-empty arm reverts
// to FilterAction::Accept.
#[test]
fn unknown_nonempty_action_fails_closed_discard() {
    let state = make_filter_state(
        &[FirewallFilterSnapshot {
            name: "drift".into(),
            family: "inet".into(),
            terms: vec![FirewallTermSnapshot {
                name: "future-action".into(),
                protocols: vec!["tcp".into()],
                // An action a future/peer version understands but this one does
                // not. Today's code silently treated this as Accept.
                action: "future-permit".into(),
                ..Default::default()
            }],
        }],
        &[],
    );
    let r = evaluate_filter(
        &state,
        "inet:drift",
        v4(10, 0, 0, 1),
        v4(10, 0, 0, 2),
        PROTO_TCP,
        12345,
        80,
        0,
        TermMatchExtra::default(),
    );
    assert_eq!(
        r.action,
        FilterAction::Discard,
        "an unknown non-empty filter action must fail closed (discard), not accept"
    );
}

// An EMPTY action is the legitimate "no terminating action" case: the term
// carries only modifiers and falls through to the next term. It must remain
// Accept (today's fall-through semantics) so a valid `then count`-only term is
// not turned into a deny. MUST FAIL if the empty-string arm is folded into the
// fail-closed default.
#[test]
fn empty_action_falls_through_to_accept() {
    let state = make_filter_state(
        &[FirewallFilterSnapshot {
            name: "fallthrough".into(),
            family: "inet".into(),
            terms: vec![FirewallTermSnapshot {
                name: "count-only".into(),
                protocols: vec!["tcp".into()],
                count: "c1".into(),
                // No terminating action — empty string.
                action: String::new(),
                ..Default::default()
            }],
        }],
        &[],
    );
    let r = evaluate_filter(
        &state,
        "inet:fallthrough",
        v4(10, 0, 0, 1),
        v4(10, 0, 0, 2),
        PROTO_TCP,
        12345,
        80,
        0,
        TermMatchExtra::default(),
    );
    assert_eq!(
        r.action,
        FilterAction::Accept,
        "an empty (no terminating) action must keep fall-through accept semantics"
    );
}

// ============================================================
// #2400 (codex 032-18 / 032-19): all-malformed firewall-filter
// addresses/ports must FAIL CLOSED (match nothing), never degrade to
// match-any (fail-open filter broadening). A `discard` term scoped to
// an all-malformed address/port set must NOT become discard-all.
//
// The fail-on-revert pivot: the filter's implicit (no-term-match) action
// is Accept (see evaluate_filter docstring). So a single `discard` term
// scoped to bad addresses/ports yields Accept when the term correctly
// matches NOTHING, and Discard if it wrongly broadens to match-any.
// ============================================================

/// One `discard` term scoped to an all-malformed source-address list. The fix
/// makes the term match nothing -> the packet falls through to implicit Accept.
/// REVERT (empty parsed list -> match-any) makes the term match every packet ->
/// Discard, failing this assert.
#[test]
fn term_2400_all_malformed_source_address_fails_closed_v4() {
    let state = make_filter_state(
        &[FirewallFilterSnapshot {
            name: "scoped-discard".into(),
            family: "inet".into(),
            terms: vec![FirewallTermSnapshot {
                name: "drop-bad-src".into(),
                // Every entry is unparseable as an IP/CIDR.
                source_addresses: vec!["not-an-ip".into(), "10.0.0.0/99".into()],
                action: "discard".into(),
                ..Default::default()
            }],
        }],
        &[],
    );
    let result = evaluate_filter(
        &state,
        "inet:scoped-discard",
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)),
        IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9)),
        PROTO_TCP,
        12345,
        443,
        0,
        TermMatchExtra::default(),
    );
    assert_eq!(
        result.action,
        FilterAction::Accept,
        "all-malformed source-address must fail CLOSED (term matches nothing -> \
         implicit accept); a match-any regression would Discard"
    );
}

/// Same for destination-address.
#[test]
fn term_2400_all_malformed_destination_address_fails_closed_v4() {
    let state = make_filter_state(
        &[FirewallFilterSnapshot {
            name: "scoped-discard".into(),
            family: "inet".into(),
            terms: vec![FirewallTermSnapshot {
                name: "drop-bad-dst".into(),
                destination_addresses: vec!["garbage".into(), "999.1.2.3".into()],
                action: "discard".into(),
                ..Default::default()
            }],
        }],
        &[],
    );
    let result = evaluate_filter(
        &state,
        "inet:scoped-discard",
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)),
        IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9)),
        PROTO_TCP,
        12345,
        443,
        0,
        TermMatchExtra::default(),
    );
    assert_eq!(
        result.action,
        FilterAction::Accept,
        "all-malformed destination-address must fail CLOSED"
    );
}

/// v6 sibling: all-malformed source-address in an inet6 filter.
#[test]
fn term_2400_all_malformed_source_address_fails_closed_v6() {
    let state = make_filter_state(
        &[FirewallFilterSnapshot {
            name: "scoped-discard6".into(),
            family: "inet6".into(),
            terms: vec![FirewallTermSnapshot {
                name: "drop-bad-src6".into(),
                source_addresses: vec!["xyzzy".into(), "2001:db8::/200".into()],
                action: "discard".into(),
                ..Default::default()
            }],
        }],
        &[],
    );
    let result = evaluate_filter(
        &state,
        "inet6:scoped-discard6",
        IpAddr::V6("2001:db8::10".parse().unwrap()),
        IpAddr::V6("2001:db8::200".parse().unwrap()),
        PROTO_TCP,
        12345,
        443,
        0,
        TermMatchExtra::default(),
    );
    assert_eq!(
        result.action,
        FilterAction::Accept,
        "all-malformed inet6 source-address must fail CLOSED"
    );
}

/// v6 sibling of the destination-address fail-closed test: all-malformed
/// destination-address in an inet6 filter must match nothing (fail closed).
/// REVERT of the v6 dest fail-closed path makes the term broaden to match-any
/// -> Discard, failing this assert.
#[test]
fn term_2400_all_malformed_destination_address_fails_closed_v6() {
    let state = make_filter_state(
        &[FirewallFilterSnapshot {
            name: "scoped-discard6".into(),
            family: "inet6".into(),
            terms: vec![FirewallTermSnapshot {
                name: "drop-bad-dst6".into(),
                destination_addresses: vec!["plugh".into(), "fe80::/200".into()],
                action: "discard".into(),
                ..Default::default()
            }],
        }],
        &[],
    );
    let result = evaluate_filter(
        &state,
        "inet6:scoped-discard6",
        IpAddr::V6("2001:db8::10".parse().unwrap()),
        IpAddr::V6("2001:db8::200".parse().unwrap()),
        PROTO_TCP,
        12345,
        443,
        0,
        TermMatchExtra::default(),
    );
    assert_eq!(
        result.action,
        FilterAction::Accept,
        "all-malformed inet6 destination-address must fail CLOSED"
    );
}

/// All-malformed source-port set -> fail closed.
#[test]
fn term_2400_all_malformed_source_port_fails_closed() {
    let state = make_filter_state(
        &[FirewallFilterSnapshot {
            name: "scoped-discard".into(),
            family: "inet".into(),
            terms: vec![FirewallTermSnapshot {
                name: "drop-bad-sport".into(),
                // Unparseable port specs: a name not in the table, an out-of-range
                // number, and an inverted range.
                source_ports: vec!["nonsense".into(), "70000".into(), "100-50".into()],
                action: "discard".into(),
                ..Default::default()
            }],
        }],
        &[],
    );
    let result = evaluate_filter(
        &state,
        "inet:scoped-discard",
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)),
        IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9)),
        PROTO_TCP,
        40000,
        443,
        0,
        TermMatchExtra::default(),
    );
    assert_eq!(
        result.action,
        FilterAction::Accept,
        "all-malformed source-port must fail CLOSED (term matches nothing); a \
         PortMatcher::Any regression would Discard"
    );
}

/// All-malformed destination-port set -> fail closed.
#[test]
fn term_2400_all_malformed_destination_port_fails_closed() {
    let state = make_filter_state(
        &[FirewallFilterSnapshot {
            name: "scoped-discard".into(),
            family: "inet".into(),
            terms: vec![FirewallTermSnapshot {
                name: "drop-bad-dport".into(),
                destination_ports: vec!["bogus".into(), "0".into()],
                action: "discard".into(),
                ..Default::default()
            }],
        }],
        &[],
    );
    let result = evaluate_filter(
        &state,
        "inet:scoped-discard",
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)),
        IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9)),
        PROTO_TCP,
        40000,
        443,
        0,
        TermMatchExtra::default(),
    );
    assert_eq!(
        result.action,
        FilterAction::Accept,
        "all-malformed destination-port must fail CLOSED"
    );
}

/// A bare-host match address (no /prefix) scopes correctly: the matching host
/// hits the term, a different host does not (anti-over-restrict + anti-fail-open
/// at once). IpNet::parse rejects a bare IP, so this exercises the bare-IP
/// fallback to /32.
#[test]
fn term_2400_bare_host_source_address_scopes_correctly() {
    let state = make_filter_state(
        &[FirewallFilterSnapshot {
            name: "scoped-discard".into(),
            family: "inet".into(),
            terms: vec![FirewallTermSnapshot {
                name: "drop-one-host".into(),
                source_addresses: vec!["203.0.113.7".into()], // bare host, no /32
                action: "discard".into(),
                ..Default::default()
            }],
        }],
        &[],
    );
    // The configured host is dropped.
    let hit = evaluate_filter(
        &state,
        "inet:scoped-discard",
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)),
        IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9)),
        PROTO_TCP,
        12345,
        443,
        0,
        TermMatchExtra::default(),
    );
    assert_eq!(
        hit.action,
        FilterAction::Discard,
        "bare-host source-address must match the configured host (bare-IP /32 fallback)"
    );
    // A different host is NOT dropped (falls through to implicit accept).
    let miss = evaluate_filter(
        &state,
        "inet:scoped-discard",
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, 8)),
        IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9)),
        PROTO_TCP,
        12345,
        443,
        0,
        TermMatchExtra::default(),
    );
    assert_eq!(
        miss.action,
        FilterAction::Accept,
        "a non-configured host must NOT match the bare-host-scoped term"
    );
}

/// Anti-over-restrict: a VALID UNSCOPED discard term (no address/port) still
/// matches everything. The constrained flags must not narrow a genuinely
/// unscoped term.
#[test]
fn term_2400_valid_unscoped_term_still_matches_all() {
    let state = make_filter_state(
        &[FirewallFilterSnapshot {
            name: "unscoped".into(),
            family: "inet".into(),
            terms: vec![FirewallTermSnapshot {
                name: "drop-all".into(),
                // no source/destination addresses, no ports.
                action: "discard".into(),
                ..Default::default()
            }],
        }],
        &[],
    );
    let result = evaluate_filter(
        &state,
        "inet:unscoped",
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)),
        IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9)),
        PROTO_TCP,
        12345,
        443,
        0,
        TermMatchExtra::default(),
    );
    assert_eq!(
        result.action,
        FilterAction::Discard,
        "a valid unscoped term must still match all traffic (no over-restriction)"
    );
}

/// Anti-over-restrict: a VALID SCOPED term matches only its address and port,
/// and falls through (accept) for everything else.
#[test]
fn term_2400_valid_scoped_term_matches_only_its_scope() {
    let state = make_filter_state(
        &[FirewallFilterSnapshot {
            name: "scoped".into(),
            family: "inet".into(),
            terms: vec![FirewallTermSnapshot {
                name: "drop-net-port".into(),
                source_addresses: vec!["203.0.113.0/24".into()],
                protocols: vec!["tcp".into()],
                destination_ports: vec!["443".into()],
                action: "discard".into(),
                ..Default::default()
            }],
        }],
        &[],
    );
    // In-scope: matches -> discard.
    let in_scope = evaluate_filter(
        &state,
        "inet:scoped",
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, 50)),
        IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9)),
        PROTO_TCP,
        12345,
        443,
        0,
        TermMatchExtra::default(),
    );
    assert_eq!(
        in_scope.action,
        FilterAction::Discard,
        "in-scope must match"
    );
    // Wrong port: out of scope -> accept.
    let wrong_port = evaluate_filter(
        &state,
        "inet:scoped",
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, 50)),
        IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9)),
        PROTO_TCP,
        12345,
        80,
        0,
        TermMatchExtra::default(),
    );
    assert_eq!(
        wrong_port.action,
        FilterAction::Accept,
        "a valid scoped term must NOT match a packet outside its port scope"
    );
    // Wrong source: out of scope -> accept.
    let wrong_src = evaluate_filter(
        &state,
        "inet:scoped",
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9)),
        PROTO_TCP,
        12345,
        443,
        0,
        TermMatchExtra::default(),
    );
    assert_eq!(
        wrong_src.action,
        FilterAction::Accept,
        "a valid scoped term must NOT match a packet outside its address scope"
    );
}

/// Composition with #2362 (tcp-flags) and #2399 (action) intact: a term that
/// mixes a VALID scope with a tcp-flags constraint matches only the in-scope
/// SYN packet, and an all-malformed address with the same tcp-flags still fails
/// closed (does not broaden to match-any-SYN).
#[test]
fn term_2400_composes_with_2362_tcp_flags() {
    // Valid scope + tcp-flags syn -> matches the in-scope SYN.
    let state = make_filter_state(
        &[FirewallFilterSnapshot {
            name: "syn-scoped".into(),
            family: "inet".into(),
            terms: vec![FirewallTermSnapshot {
                name: "drop-syn-from-net".into(),
                source_addresses: vec!["203.0.113.0/24".into()],
                tcp_flags: Some(0x02), // SYN
                action: "discard".into(),
                ..Default::default()
            }],
        }],
        &[],
    );
    let syn_extra = TermMatchExtra {
        tcp_flags: 0x02,
        l4_present: true,
        flex_l3: None,
        ..Default::default()
    };
    let in_scope_syn = evaluate_filter(
        &state,
        "inet:syn-scoped",
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, 50)),
        IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9)),
        PROTO_TCP,
        12345,
        443,
        0,
        syn_extra,
    );
    assert_eq!(
        in_scope_syn.action,
        FilterAction::Discard,
        "valid scope + tcp-flags must still match the in-scope SYN (#2362 intact)"
    );

    // All-malformed address + the same tcp-flags -> fail closed even for a SYN.
    let bad_state = make_filter_state(
        &[FirewallFilterSnapshot {
            name: "syn-bad".into(),
            family: "inet".into(),
            terms: vec![FirewallTermSnapshot {
                name: "drop-syn-bad-src".into(),
                source_addresses: vec!["not-an-ip".into()],
                tcp_flags: Some(0x02),
                action: "discard".into(),
                ..Default::default()
            }],
        }],
        &[],
    );
    let bad_syn = evaluate_filter(
        &bad_state,
        "inet:syn-bad",
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, 50)),
        IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9)),
        PROTO_TCP,
        12345,
        443,
        0,
        syn_extra,
    );
    assert_eq!(
        bad_syn.action,
        FilterAction::Accept,
        "all-malformed address + tcp-flags must fail CLOSED, not broaden to match-any-SYN"
    );
}

/// A term mixing one VALID and one malformed address keeps the valid scope
/// (the malformed entry is dropped, the term stays constrained and matches the
/// valid prefix only). This guards against an over-correction that would fail
/// the whole term closed when ANY entry is bad.
#[test]
fn term_2400_partial_malformed_address_keeps_valid_scope() {
    let state = make_filter_state(
        &[FirewallFilterSnapshot {
            name: "partial".into(),
            family: "inet".into(),
            terms: vec![FirewallTermSnapshot {
                name: "drop-mixed".into(),
                source_addresses: vec!["203.0.113.0/24".into(), "garbage".into()],
                action: "discard".into(),
                ..Default::default()
            }],
        }],
        &[],
    );
    let in_valid = evaluate_filter(
        &state,
        "inet:partial",
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, 50)),
        IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9)),
        PROTO_TCP,
        12345,
        443,
        0,
        TermMatchExtra::default(),
    );
    assert_eq!(
        in_valid.action,
        FilterAction::Discard,
        "the surviving valid prefix must still match (partial-malformed != all-malformed)"
    );
}

// =====================================================================
// #2505: firewall-filter protocol resolution uses the SHARED, normalizing
// resolver (ip_proto::proto_number) and fails CLOSED on an unresolvable
// token in a non-empty list. The pre-fix local parse_protocol recognized
// only tcp/udp/icmp/icmpv6/gre/ospf/ipip + bare numeric and silently
// dropped everything else; an all-dropped list disabled the protocol match
// so a `from protocol esp; then discard` term matched EVERY protocol
// (fail-WIDE).
// =====================================================================

// Build a single-term `discard` filter scoped to one `from protocol` token,
// returning the compiled FilterState result (Ok or the integrity Err).
fn filter_for_protocol(token: &str) -> Result<FilterState, SnapshotIntegrityError> {
    parse_filter_state(
        &[FirewallFilterSnapshot {
            name: "f".into(),
            family: "inet".into(),
            terms: vec![FirewallTermSnapshot {
                name: "scoped".into(),
                protocols: vec![token.into()],
                action: "discard".into(),
                ..Default::default()
            }],
        }],
        &[],
        &[],
        "",
        "",
    )
}

// Assert a token resolves to a protocol-SCOPED term: the term discards ITS
// protocol and ACCEPTS (no match) a different one — proving the protocol
// match is enabled and not a fail-wide match-all.
fn assert_scoped_to(token: &str, want_proto: u8) {
    let state = filter_for_protocol(token)
        .unwrap_or_else(|e| panic!("token {token:?} should resolve, got {e}"));
    let term = state
        .filters
        .get("inet:f")
        .expect("filter compiled")
        .terms
        .first()
        .expect("one term");
    assert!(
        term.protocol_match_enabled,
        "token {token:?} must enable the protocol match (else the term is fail-wide match-all)"
    );

    // The scoped protocol is discarded.
    let hit = evaluate_filter(
        &state,
        "inet:f",
        v4(10, 0, 0, 1),
        v4(10, 0, 0, 2),
        want_proto,
        0,
        0,
        0,
        TermMatchExtra::default(),
    );
    assert_eq!(
        hit.action,
        FilterAction::Discard,
        "token {token:?} (proto {want_proto}) must be discarded by its own term"
    );

    // A DIFFERENT protocol must NOT match (proves it is not match-all).
    let other = if want_proto == PROTO_TCP {
        PROTO_UDP
    } else {
        PROTO_TCP
    };
    let miss = evaluate_filter(
        &state,
        "inet:f",
        v4(10, 0, 0, 1),
        v4(10, 0, 0, 2),
        other,
        0,
        0,
        0,
        TermMatchExtra::default(),
    );
    assert_eq!(
        miss.action,
        FilterAction::Accept,
        "token {token:?} term must NOT match a different protocol ({other}) — that would be fail-wide"
    );
}

#[test]
fn protocol_2505_named_protocols_resolve_scoped() {
    // The protocols the Go commit gate accepts but the stale local parser
    // dropped. Each must resolve to its IANA number AND produce a scoped term.
    assert_scoped_to("esp", 50);
    assert_scoped_to("ah", 51);
    assert_scoped_to("sctp", 132);
    assert_scoped_to("vrrp", 112);
    assert_scoped_to("igmp", 2);
    assert_scoped_to("pim", 103);
    assert_scoped_to("egp", 8);
}

#[test]
fn protocol_3393_ipv6_resolves_scoped() {
    // #3393 RED-on-revert guard: `from protocol ipv6` reaches the snapshot
    // VERBATIM as the name "ipv6" (filters.go emits term.Protocols unresolved,
    // unlike the application/NAT paths that pre-canonicalize to a number). The
    // Go filter commit gate (filterProtocolResolvable) accepts "ipv6" since
    // appid.ProtocolNumber("ipv6")==41 was closed, so proto_number — the Rust
    // mirror — must resolve it to 41 too. Without the "ipv6" arm this errors
    // with UnrepresentableFilterProtocol (commit/apply drift). Reverting the
    // ip_proto.rs arm makes this fail.
    assert_scoped_to("ipv6", 41);
    assert_scoped_to("IPv6", 41);
    assert_scoped_to(" ipv6 ", 41);
}

#[test]
fn protocol_2505_normalization_uppercase_and_whitespace() {
    // The stale local parser did not trim/lowercase. The shared resolver does,
    // matching the Go gate's strings.TrimSpace + ToLower.
    assert_scoped_to("GRE", 47);
    assert_scoped_to(" icmp ", PROTO_ICMP);
    assert_scoped_to("Esp", 50);
}

#[test]
fn protocol_2505_junos_aliases_resolve() {
    // Gate<->dataplane parity: filterProtocolResolvable accepts these junos-*
    // aliases and they reach the snapshot VERBATIM (compileFilterFrom does no
    // alias resolution), so proto_number must resolve them too.
    assert_scoped_to("junos-tcp-any", PROTO_TCP);
    assert_scoped_to("junos-udp-any", PROTO_UDP);
    assert_scoped_to("junos-ping", PROTO_ICMP);
    assert_scoped_to("junos-gre", 47);
    assert_scoped_to("junos-ospf", 89);
    assert_scoped_to("junos-ip-in-ip", 4);
}

#[test]
fn filter_protocol_accept_set_subset_of_resolver() {
    // Contract guard (#3393): EVERY named token the Go firewall-filter commit
    // gate (config.filterProtocolResolvable, pkg/config/
    // compiler_validate_strict.go) accepts MUST resolve through proto_number,
    // because a filter's `from protocol <token>` reaches this snapshot path
    // VERBATIM (filters.go emits term.Protocols with no name->number
    // canonicalization). A token the gate accepts but proto_number cannot
    // resolve commits in Go yet fails snapshot compilation here with
    // UnrepresentableFilterProtocol — commit/apply drift (the #1961 / #3393
    // class). The numeric-token arm (0..=255) is covered separately.
    //
    // CAVEAT: this list is a HARDCODED mirror of the filterProtocolResolvable
    // named set — it is NOT a mechanical cross-language enumeration. The loop
    // only exercises the tokens written below, so it CANNOT notice a protocol
    // newly ADDED to that Go gate; this array MUST be updated in lockstep with
    // filterProtocolResolvable (and with proto_number above). The lockstep is
    // enforced on the Go side by pkg/config TestFilterProtocolNamedSetMatchesRustMirror,
    // which parses the named set out of BOTH this array and the Go gate source
    // and fails if they diverge — keep that pin green when editing either list.
    for token in [
        "tcp",
        "junos-tcp-any",
        "udp",
        "junos-udp-any",
        "icmp",
        "junos-icmp-all",
        "junos-ping",
        "icmpv6",
        "icmp6",
        "junos-icmp6-all",
        "junos-pingv6",
        "gre",
        "junos-gre",
        "ospf",
        "junos-ospf",
        "junos-ip-in-ip",
        "junos-ipip",
        "ipip",
        "ipv6",
        "egp",
        "igmp",
        "pim",
        "ah",
        "esp",
        "sctp",
        "vrrp",
    ] {
        assert!(
            proto_number(token).is_some(),
            "filterProtocolResolvable accepts {token:?} but proto_number does not \
             resolve it — Go commit-accept vs Rust-apply drift (#3393)"
        );
    }
}

// Build a single-term `discard` filter carrying the #3367
// `tcp_flags_unparseable` wire marker, returning the compiled FilterState
// result (Ok or the integrity Err).
fn filter_with_tcp_flags_unparseable(
    family: &str,
    unparseable: bool,
) -> Result<FilterState, SnapshotIntegrityError> {
    parse_filter_state(
        &[FirewallFilterSnapshot {
            name: "f".into(),
            family: family.into(),
            terms: vec![FirewallTermSnapshot {
                name: "flagged".into(),
                protocols: vec!["tcp".into()],
                tcp_flags_unparseable: unparseable,
                action: "discard".into(),
                ..Default::default()
            }],
        }],
        &[],
        &[],
        "",
        "",
    )
}

#[test]
fn tcp_flags_unparseable_marker_fails_closed_not_match_all() {
    // #3367 RED-on-revert: a filter term carrying the `tcp_flags_unparseable`
    // wire marker (the Go control plane could not parse the tcp-flags
    // expression) must reject the WHOLE snapshot — NOT compile into a term with
    // no tcp-flags constraint. Pre-fix the Go builder logged + left both masks
    // nil, and this compiler ignored the marker, so the term matched EVERY TCP
    // segment (a `then discard` term that should drop only a specific flag combo
    // would discard ALL TCP — fail-WIDE). Reverting the parse_term guard returns
    // Ok here, so this is non-tautological.
    let err = filter_with_tcp_flags_unparseable("inet", true)
        .expect_err("an unparseable tcp-flags marker must fail the build closed");
    match err {
        SnapshotIntegrityError::UnrepresentableFilterTCPFlags {
            family,
            filter,
            term,
        } => {
            assert_eq!(family, "inet");
            assert_eq!(filter, "f");
            assert_eq!(term, "flagged");
        }
        other => panic!("expected UnrepresentableFilterTCPFlags, got {other:?}"),
    }

    // A term WITHOUT the marker compiles fine (proves the guard is keyed on the
    // marker, not on every TCP-scoped term).
    filter_with_tcp_flags_unparseable("inet", false)
        .expect("a term without the unparseable marker must compile");
}

#[test]
fn tcp_flags_unparseable_error_names_the_family_for_reused_filter_names() {
    // Filter names can be reused across families; the diagnostic must name the
    // family carrying the unparseable marker.
    let err = filter_with_tcp_flags_unparseable("inet6", true)
        .expect_err("an unparseable tcp-flags marker must fail the build closed");
    match err {
        SnapshotIntegrityError::UnrepresentableFilterTCPFlags { family, .. } => {
            assert_eq!(family, "inet6");
        }
        other => panic!("expected UnrepresentableFilterTCPFlags, got {other:?}"),
    }
}

// =====================================================================
// #3723: firewall-filter CROSS-FIELD satisfiability backstop. A term whose
// resolved protocol constraint is PRESENT but incompatible with a
// co-configured L4 predicate (a port on a non-port-bearing protocol,
// tcp-flags on a non-TCP protocol, or icmp-type/code on a non-ICMP protocol)
// is a NEVER-MATCH. Because a filter falls through to the implicit ACCEPT on
// no-match, a `then discard`/`reject` term over such a pair silently fails
// OPEN. The Go commit gate (validateFilterCrossFieldStrict) is the primary
// defense; parse_filter_state is the helper-boundary backstop that rejects the
// whole snapshot (fail closed) for a leniently-loaded / drifted snapshot.
// =====================================================================

// Build a single-term `discard` filter with an arbitrary cross-field shape.
fn crossfield_filter(
    family: &str,
    protocols: Vec<String>,
    dst_ports: Vec<String>,
    tcp_flags: Option<u8>,
    icmp_types: Vec<u8>,
) -> Result<FilterState, SnapshotIntegrityError> {
    parse_filter_state(
        &[FirewallFilterSnapshot {
            name: "f".into(),
            family: family.into(),
            terms: vec![FirewallTermSnapshot {
                name: "x".into(),
                protocols,
                destination_ports: dst_ports,
                tcp_flags,
                icmp_types,
                action: "discard".into(),
                ..Default::default()
            }],
        }],
        &[],
        &[],
        "",
        "",
    )
}

#[test]
fn filter_crossfield_3723_port_on_nonport_protocol_rejected() {
    // H01: a destination-port on a non-port-bearing protocol (gre) is a
    // never-match. The backstop rejects the whole snapshot rather than compile a
    // silently-inert discard. Reverting the parse_term guard returns Ok here, so
    // this is non-tautological.
    let err = crossfield_filter("inet", vec!["gre".into()], vec!["80".into()], None, vec![])
        .expect_err("a port on gre must fail the build closed");
    match err {
        SnapshotIntegrityError::UnsatisfiableFilterCrossField {
            family,
            filter,
            term,
            predicate,
            protocol,
        } => {
            assert_eq!(family, "inet");
            assert_eq!(filter, "f");
            assert_eq!(term, "x");
            assert_eq!(predicate, "port");
            assert_eq!(protocol, crate::ip_proto::PROTO_GRE);
        }
        other => panic!("expected UnsatisfiableFilterCrossField, got {other:?}"),
    }
}

#[test]
fn filter_crossfield_3723_tcpflags_on_nontcp_rejected() {
    // H02: tcp-flags on a non-TCP protocol (udp — port-bearing but NOT TCP) is a
    // never-match.
    let err = crossfield_filter("inet", vec!["udp".into()], vec![], Some(0x02), vec![])
        .expect_err("tcp-flags on udp must fail the build closed");
    match err {
        SnapshotIntegrityError::UnsatisfiableFilterCrossField {
            predicate, protocol, ..
        } => {
            assert_eq!(predicate, "tcp-flags");
            assert_eq!(protocol, PROTO_UDP);
        }
        other => panic!("expected UnsatisfiableFilterCrossField, got {other:?}"),
    }
}

#[test]
fn filter_crossfield_3723_icmp_on_nonicmp_rejected() {
    // H03: an icmp-type on a non-ICMP protocol (tcp) is a never-match.
    let err = crossfield_filter("inet", vec!["tcp".into()], vec![], None, vec![8])
        .expect_err("icmp-type on tcp must fail the build closed");
    match err {
        SnapshotIntegrityError::UnsatisfiableFilterCrossField {
            predicate, protocol, ..
        } => {
            assert_eq!(predicate, "icmp-type/code");
            assert_eq!(protocol, PROTO_TCP);
        }
        other => panic!("expected UnsatisfiableFilterCrossField, got {other:?}"),
    }
}

#[test]
fn filter_crossfield_3723_mixed_list_rejected() {
    // M01: a mixed protocol list [tcp gre] with a port only enforces on tcp and
    // silently never-matches gre. The backstop rejects on the incompatible gre.
    let err = crossfield_filter(
        "inet",
        vec!["tcp".into(), "gre".into()],
        vec!["80".into()],
        None,
        vec![],
    )
    .expect_err("a mixed port-bearing/non-port list with a port must fail closed");
    match err {
        SnapshotIntegrityError::UnsatisfiableFilterCrossField {
            predicate, protocol, ..
        } => {
            assert_eq!(predicate, "port");
            assert_eq!(protocol, crate::ip_proto::PROTO_GRE);
        }
        other => panic!("expected UnsatisfiableFilterCrossField, got {other:?}"),
    }
}

#[test]
fn filter_crossfield_3723_family_named_for_reused_names() {
    // Filter names can be reused across families; the diagnostic must name the
    // family carrying the never-match term (M02: next-header lowers into
    // protocols, so an inet6 esp+port term hits the same backstop).
    let err = crossfield_filter("inet6", vec!["esp".into()], vec!["80".into()], None, vec![])
        .expect_err("an inet6 port-on-esp term must fail closed");
    match err {
        SnapshotIntegrityError::UnsatisfiableFilterCrossField { family, .. } => {
            assert_eq!(family, "inet6");
        }
        other => panic!("expected UnsatisfiableFilterCrossField, got {other:?}"),
    }
}

#[test]
fn filter_crossfield_3723_satisfiable_compiles() {
    // Positive controls — a satisfiable same-protocol term must still compile.
    crossfield_filter("inet", vec!["tcp".into()], vec!["22".into()], None, vec![])
        .expect("tcp + port compiles");
    crossfield_filter("inet", vec!["udp".into()], vec!["53".into()], None, vec![])
        .expect("udp + port compiles");
    crossfield_filter("inet", vec!["tcp".into()], vec![], Some(0x02), vec![])
        .expect("tcp + tcp-flags compiles");
    crossfield_filter("inet", vec!["icmp".into()], vec![], None, vec![8])
        .expect("icmp + icmp-type compiles");
    crossfield_filter(
        "inet",
        vec!["tcp".into(), "udp".into()],
        vec!["80".into()],
        None,
        vec![],
    )
    .expect("a fully port-bearing mixed list compiles");
}

#[test]
fn filter_crossfield_3723_no_protocol_is_enforceable() {
    // A port / tcp-flags / icmp predicate with NO protocol is legitimate and
    // enforceable for a FILTER (the matcher matches the port on whatever
    // port-bearing packet arrives, and the tcp-flags/icmp arms self-gate on the
    // packet protocol). The backstop must NOT reject these.
    crossfield_filter("inet", vec![], vec!["80".into()], None, vec![])
        .expect("port with no protocol is enforceable");
    crossfield_filter("inet", vec![], vec![], Some(0x02), vec![])
        .expect("tcp-flags with no protocol is enforceable");
    crossfield_filter("inet", vec![], vec![], None, vec![8])
        .expect("icmp-type with no protocol is enforceable");
}

#[test]
fn filter_crossfield_3723_never_match_fails_open_at_runtime() {
    // L06 runtime guard: FABRICATE the never-match term the backstop normally
    // prevents (protocol gre + destination-port 80) and prove it matches NOTHING,
    // documenting the fail-OPEN #3723 closes — the operator's `then discard` is
    // dead and the traffic is admitted by the implicit accept. Built by cloning a
    // valid gre discard term (compiled without a port) and overriding the port
    // fields, so it exercises the REAL matcher (engine/matching.rs) end to end.
    let state = filter_for_protocol("gre").expect("gre discard term compiles");
    let base = state
        .filters
        .get("inet:f")
        .expect("filter compiled")
        .terms
        .first()
        .expect("one term")
        .clone();
    let never = FilterTerm {
        dest_ports: PortMatcher::Single(80),
        dest_port_constrained: true,
        counter: Arc::new(FilterTermCounter::default()),
        ..base
    };
    let mut filter: Filter = (**state.filters.get("inet:f").unwrap()).clone();
    filter.terms = vec![never];
    let mut st = FilterState::default();
    st.filters.insert("inet:f".into(), Arc::new(filter));

    // A GRE packet carries no L4 ports (dst_port 0): protocol matches gre, but
    // port 0 != 80 -> no match -> Accept (the discard never fires).
    let gre = evaluate_filter(
        &st,
        "inet:f",
        v4(10, 0, 0, 1),
        v4(10, 0, 0, 2),
        crate::ip_proto::PROTO_GRE,
        0,
        0,
        0,
        TermMatchExtra::default(),
    );
    assert_eq!(
        gre.action,
        FilterAction::Accept,
        "gre+port term never matches a gre packet (port 0) — the discard fails OPEN"
    );

    // A TCP:80 packet: protocol gre != tcp -> no match -> Accept.
    let tcp = evaluate_filter(
        &st,
        "inet:f",
        v4(10, 0, 0, 1),
        v4(10, 0, 0, 2),
        PROTO_TCP,
        1000,
        80,
        0,
        TermMatchExtra::default(),
    );
    assert_eq!(
        tcp.action,
        FilterAction::Accept,
        "gre+port term never matches a tcp:80 packet (protocol mismatch) — the discard fails OPEN"
    );
}

#[test]
fn protocol_2505_unresolvable_fails_closed_not_match_all() {
    // A non-empty list with an unresolvable token must reject the whole
    // snapshot (fail closed), NOT silently drop it into an empty match-all
    // term.
    let err = filter_for_protocol("bogusproto")
        .expect_err("an unresolvable protocol token must fail the build closed");
    match err {
        SnapshotIntegrityError::UnrepresentableFilterProtocol {
            family,
            filter,
            term,
            token,
        } => {
            assert_eq!(family, "inet");
            assert_eq!(filter, "f");
            assert_eq!(term, "scoped");
            assert_eq!(token, "bogusproto");
        }
        other => panic!("expected UnrepresentableFilterProtocol, got {other:?}"),
    }
}

#[test]
fn protocol_2505_error_names_the_family_for_reused_filter_names() {
    // Filter names can be reused across families. When the inet6 copy carries
    // the unresolvable token, the diagnostic must name family inet6 (not just
    // the ambiguous filter name) so the operator can find the offending filter.
    let bad_term = || FirewallTermSnapshot {
        name: "scoped".into(),
        protocols: vec!["bogusproto".into()],
        action: "discard".into(),
        ..Default::default()
    };
    let good_term = || FirewallTermSnapshot {
        name: "ok".into(),
        protocols: vec!["tcp".into()],
        action: "discard".into(),
        ..Default::default()
    };
    let err = parse_filter_state(
        &[
            FirewallFilterSnapshot {
                name: "dup".into(),
                family: "inet".into(),
                terms: vec![good_term()],
            },
            FirewallFilterSnapshot {
                name: "dup".into(),
                family: "inet6".into(),
                terms: vec![bad_term()],
            },
        ],
        &[],
        &[],
        "",
        "",
    )
    .expect_err("the inet6 filter's unresolvable token must fail the build closed");
    match err {
        SnapshotIntegrityError::UnrepresentableFilterProtocol {
            family,
            filter,
            term,
            token,
        } => {
            assert_eq!(family, "inet6", "the error must name the inet6 family");
            assert_eq!(filter, "dup");
            assert_eq!(term, "scoped");
            assert_eq!(token, "bogusproto");
        }
        other => panic!("expected UnrepresentableFilterProtocol, got {other:?}"),
    }
}

#[test]
fn protocol_2505_empty_list_is_unconstrained() {
    // An EMPTY input protocol list legitimately means "no protocol
    // constraint" — protocol_match_enabled=false, NOT an error.
    let state = parse_filter_state(
        &[FirewallFilterSnapshot {
            name: "f".into(),
            family: "inet".into(),
            terms: vec![FirewallTermSnapshot {
                name: "any-proto".into(),
                protocols: vec![],
                action: "discard".into(),
                ..Default::default()
            }],
        }],
        &[],
        &[],
        "",
        "",
    )
    .expect("empty protocol list is not an error");
    let term = state
        .filters
        .get("inet:f")
        .expect("filter compiled")
        .terms
        .first()
        .expect("one term");
    assert!(
        !term.protocol_match_enabled,
        "an empty protocol list must leave the protocol match disabled (match-any constraint)"
    );
}

// Build a single-term `discard` filter carrying one of the #3406 unrepresentable
// wire markers, returning the compiled FilterState result (Ok or the integrity
// Err). The closure mutates a default term so each test sets exactly one marker.
fn filter_with_marked_term(
    family: &str,
    mark: impl FnOnce(&mut FirewallTermSnapshot),
) -> Result<FilterState, SnapshotIntegrityError> {
    let mut term = FirewallTermSnapshot {
        name: "marked".into(),
        action: "discard".into(),
        ..Default::default()
    };
    mark(&mut term);
    parse_filter_state(
        &[FirewallFilterSnapshot {
            name: "f".into(),
            family: family.into(),
            terms: vec![term],
        }],
        &[],
        &[],
        "",
        "",
    )
}

#[test]
fn icmp_type_unrepresentable_marker_fails_closed_not_match_all() {
    // #3406 RED-on-revert: a term carrying the `icmp_type_unrepresentable` wire
    // marker (the Go control plane could not resolve a `from icmp-type` token to a
    // byte in 0..255) must reject the WHOLE snapshot — NOT compile into a term with
    // no ICMP constraint. Pre-#3406 the Go builder dropped the unresolved token; an
    // all-unresolvable list emitted an empty `icmp_types` vec, which this matcher
    // reads as "no constraint" → the term matched EVERY ICMP packet (a `then
    // discard` term that should drop only one type would discard ALL ICMP —
    // fail-WIDE). Reverting the parse_term guard returns Ok here.
    let err = filter_with_marked_term("inet", |t| t.icmp_type_unrepresentable = true)
        .expect_err("an unrepresentable icmp-type marker must fail the build closed");
    match err {
        SnapshotIntegrityError::UnrepresentableFilterICMP {
            family,
            filter,
            term,
            dimension,
        } => {
            assert_eq!(family, "inet");
            assert_eq!(filter, "f");
            assert_eq!(term, "marked");
            assert_eq!(dimension, "icmp-type");
        }
        other => panic!("expected UnrepresentableFilterICMP, got {other:?}"),
    }
    // A term WITHOUT the marker compiles fine (the guard is keyed on the marker).
    filter_with_marked_term("inet", |_| {})
        .expect("a term without the marker must compile");
}

#[test]
fn icmp_code_unrepresentable_marker_fails_closed() {
    // Sibling of the icmp-type guard for the code dimension; names inet6 to prove
    // the family is carried (filter names can be reused across families).
    let err = filter_with_marked_term("inet6", |t| t.icmp_code_unrepresentable = true)
        .expect_err("an unrepresentable icmp-code marker must fail the build closed");
    match err {
        SnapshotIntegrityError::UnrepresentableFilterICMP {
            family, dimension, ..
        } => {
            assert_eq!(family, "inet6");
            assert_eq!(dimension, "icmp-code");
        }
        other => panic!("expected UnrepresentableFilterICMP, got {other:?}"),
    }
}

#[test]
fn dscp_match_unrepresentable_marker_fails_closed_not_match_all() {
    // #3406 RED-on-revert: the `dscp_match_unrepresentable` marker (an unresolvable
    // `from dscp` MATCH token) must reject the whole snapshot. Pre-#3406 the Go
    // builder dropped the bad token; an all-unresolvable list left `dscp_values`
    // empty, which this matcher reads as "no DSCP constraint" → match all DSCPs
    // (fail-WIDE).
    let err = filter_with_marked_term("inet", |t| t.dscp_match_unrepresentable = true)
        .expect_err("an unrepresentable from-dscp match marker must fail the build closed");
    match err {
        SnapshotIntegrityError::UnrepresentableFilterDSCP {
            family,
            filter,
            term,
        } => {
            assert_eq!(family, "inet");
            assert_eq!(filter, "f");
            assert_eq!(term, "marked");
        }
        other => panic!("expected UnrepresentableFilterDSCP, got {other:?}"),
    }
}

#[test]
fn ports_unrepresentable_marker_fails_closed_not_narrowed() {
    // #6459 RED-on-revert: a term carrying the `ports_unrepresentable` wire
    // marker (the Go control plane could not resolve one of the term's
    // `{source,destination}-port[-except]` tokens, e.g. `[ ssh bogussvc ]`)
    // must reject the WHOLE snapshot — NOT compile a matcher over only the
    // surviving subset. Pre-fix the compiler dropped the unresolvable token
    // PER-TOKEN (`filter_map(parse_port_spec)`), so a partially-unresolvable
    // list on a `then discard`/`reject` term silently enforced a NARROWER port
    // set than the operator wrote: traffic to the dropped ports fell through
    // to the implicit accept (fail-OPEN). The term below carries a SURVIVING
    // port ("22") alongside the marker, so reverting the parse_term guard
    // returns Ok here (non-tautological).
    let err = filter_with_marked_term("inet", |t| {
        t.destination_ports = vec!["22".into(), "bogussvc".into()];
        t.ports_unrepresentable = true;
    })
    .expect_err("an unrepresentable ports marker must fail the build closed");
    match err {
        SnapshotIntegrityError::UnrepresentableFilterPorts {
            family,
            filter,
            term,
        } => {
            assert_eq!(family, "inet");
            assert_eq!(filter, "f");
            assert_eq!(term, "marked");
        }
        other => panic!("expected UnrepresentableFilterPorts, got {other:?}"),
    }
    // A term WITHOUT the marker compiles fine (the guard is keyed on the
    // marker, not on every port-scoped term).
    filter_with_marked_term("inet", |t| {
        t.destination_ports = vec!["22".into()];
    })
    .expect("a term without the marker must compile");
}

#[test]
fn ports_unrepresentable_error_names_the_family_for_reused_filter_names() {
    // Filter names can be reused across families; the diagnostic must name the
    // family carrying the marker.
    let err = filter_with_marked_term("inet6", |t| t.ports_unrepresentable = true)
        .expect_err("an unrepresentable ports marker must fail the build closed");
    match err {
        SnapshotIntegrityError::UnrepresentableFilterPorts { family, .. } => {
            assert_eq!(family, "inet6");
        }
        other => panic!("expected UnrepresentableFilterPorts, got {other:?}"),
    }
}

#[test]
fn address_unrepresentable_marker_fails_closed_not_narrowed() {
    // #6463 RED-on-revert: a term carrying the `address_unrepresentable` wire
    // marker (the Go control plane classified one of the term's literal
    // `from source-address` / `destination-address` tokens as not a parseable
    // IP/CIDR, e.g. `[ 10.0.0.0/8 garbage.example ]`) must reject the WHOLE
    // snapshot — NOT compile a matcher over only the surviving prefixes.
    // Pre-fix `parse_address` dropped the malformed token PER-TOKEN (its
    // `Err(_)` arm pushed nothing), so a partially-malformed list on a `then
    // discard`/`reject` term silently enforced a NARROWER address set than the
    // operator wrote: a host in the dropped range fell through to the implicit
    // accept (fail-OPEN). The term below carries a SURVIVING prefix alongside
    // the marker, so reverting the parse_term guard returns Ok here
    // (non-tautological).
    let err = filter_with_marked_term("inet", |t| {
        t.source_addresses = vec!["10.0.0.0/8".into(), "garbage.example".into()];
        t.address_unrepresentable = true;
    })
    .expect_err("an unrepresentable address marker must fail the build closed");
    match err {
        SnapshotIntegrityError::UnrepresentableFilterAddress {
            family,
            filter,
            term,
        } => {
            assert_eq!(family, "inet");
            assert_eq!(filter, "f");
            assert_eq!(term, "marked");
        }
        other => panic!("expected UnrepresentableFilterAddress, got {other:?}"),
    }
    // A term WITHOUT the marker compiles fine (the guard is keyed on the
    // marker, not on every address-scoped term).
    filter_with_marked_term("inet", |t| {
        t.source_addresses = vec!["10.0.0.0/8".into()];
    })
    .expect("a term without the marker must compile");
}

#[test]
fn filter_parse_port_spec_rejects_signed_6477() {
    // #6477 RED-on-revert: the filter-side port parser must reject a
    // non-canonical SIGNED token. Rust's u16 FromStr accepts a leading '+'
    // ("+80" -> Ok(80)), so the pre-fix `.parse::<u16>()` built Single(80) and
    // enforced it — while the Go commit gate, the Go capability gate, and the
    // policy-side Rust parser (parse_port_u16, #3606) all reject the token.
    // One of four port parsers being more lenient violates the #3606 agreement
    // invariant. A rejected token yields ZERO ranges: the direction stays
    // constrained (port_is_real) with PortMatcher::Any, so the matcher fails
    // the term closed (matches nothing) rather than enforcing 80. Reverting
    // the shared-helper routing restores Single(80) here — RED.
    let state = make_filter_state(
        &[FirewallFilterSnapshot {
            name: "f".into(),
            family: "inet".into(),
            terms: vec![FirewallTermSnapshot {
                name: "signed".into(),
                protocols: vec!["tcp".into()],
                destination_ports: vec!["+80".into()],
                action: "discard".into(),
                ..Default::default()
            }],
        }],
        &[],
    );
    let term = state
        .filters
        .get("inet:f")
        .expect("filter compiled")
        .terms
        .first()
        .expect("one term");
    assert!(
        term.dest_port_constrained,
        "a non-empty port token keeps the direction constrained"
    );
    assert!(
        matches!(term.dest_ports, PortMatcher::Any),
        "'+80' must be rejected (zero ranges -> PortMatcher::Any, fail closed); \
         a Single(80) here means the signed token was enforced (#6477)"
    );
    // Range endpoints are signed-checked too (mirrors the #3606 policy-side
    // pins): a signed low or high must reject the whole spec.
    for spec in ["+80-90", "80-+90"] {
        let state = make_filter_state(
            &[FirewallFilterSnapshot {
                name: "f".into(),
                family: "inet".into(),
                terms: vec![FirewallTermSnapshot {
                    name: "signed-range".into(),
                    protocols: vec!["tcp".into()],
                    destination_ports: vec![spec.into()],
                    action: "discard".into(),
                    ..Default::default()
                }],
            }],
            &[],
        );
        let term = state
            .filters
            .get("inet:f")
            .expect("filter compiled")
            .terms
            .first()
            .expect("one term");
        assert!(
            matches!(term.dest_ports, PortMatcher::Any),
            "{spec:?} must be rejected (signed endpoint); a range here means a \
             signed endpoint was enforced (#6477)"
        );
    }
}

#[test]
fn dscp_rewrite_out_of_range_fails_closed_not_masked() {
    // #3715 RED-on-revert (Bug A): a `then dscp` REWRITE wire value outside the
    // 0..=63 6-bit range must reject the whole snapshot — NOT be masked into a
    // different valid code point. Pre-fix `parse_term` computed
    // `snap.dscp_rewrite.map(|v| v & 0x3f)`, so 110 & 0x3f == 46 (EF): a corrupt
    // byte actively marked traffic with a code point the operator never authored.
    // Reverting the preflight range check (and restoring the mask) makes this
    // compile Ok with dscp_rewrite == Some(46).
    let err = filter_with_marked_term("inet", |t| t.dscp_rewrite = Some(110))
        .expect_err("an out-of-range dscp rewrite must fail the build closed");
    match err {
        SnapshotIntegrityError::FilterDSCPOutOfRange {
            family,
            filter,
            term,
            dimension,
            value,
        } => {
            assert_eq!(family, "inet");
            assert_eq!(filter, "f");
            assert_eq!(term, "marked");
            assert_eq!(dimension, "rewrite");
            assert_eq!(value, 110, "the error must carry the raw offending byte, not 110 & 0x3f");
        }
        other => panic!("expected FilterDSCPOutOfRange, got {other:?}"),
    }
    // A rewrite at the top of the valid range (63) still compiles verbatim.
    let ok = filter_with_marked_term("inet", |t| t.dscp_rewrite = Some(63))
        .expect("a valid 0..=63 dscp rewrite must compile");
    assert_eq!(
        ok.filters
            .get("inet:f")
            .expect("filter compiled")
            .terms
            .first()
            .expect("one term")
            .dscp_rewrite,
        Some(63),
        "a valid rewrite must be carried verbatim (no masking)"
    );
}

#[test]
fn dscp_match_out_of_range_fails_closed_not_dropped() {
    // #3715 RED-on-revert (Bug B): a `from dscp` MATCH wire value >= 64 must reject
    // the whole snapshot. Pre-fix `build_u6_match_bitmap` silently SKIPPED any value
    // >= 64 (its `value < 64` guard) while `dscp_match_enabled` stayed true — a term
    // carrying [46, 64] appeared to match two selectors but silently matched only EF
    // (fail-WIDE / silently-wrong). Reverting the preflight range check makes this
    // compile Ok with the 64 dropped from the bitmap. inet6 names the family to
    // prove it is carried (filter names can be reused across families).
    let err = filter_with_marked_term("inet6", |t| t.dscp_values = vec![46, 64])
        .expect_err("an out-of-range dscp match value must fail the build closed");
    match err {
        SnapshotIntegrityError::FilterDSCPOutOfRange {
            family,
            dimension,
            value,
            ..
        } => {
            assert_eq!(family, "inet6");
            assert_eq!(dimension, "match");
            assert_eq!(value, 64, "the error must carry the first out-of-range value");
        }
        other => panic!("expected FilterDSCPOutOfRange, got {other:?}"),
    }
    // The boundary value 63 is in range; a fully in-range match set compiles and
    // keeps the DSCP match enabled.
    let ok = filter_with_marked_term("inet", |t| t.dscp_values = vec![0, 46, 63])
        .expect("a fully in-range dscp match set must compile");
    let term = ok
        .filters
        .get("inet:f")
        .expect("filter compiled")
        .terms
        .first()
        .expect("one term");
    assert!(
        term.dscp_match_enabled,
        "an in-range dscp match set must keep the DSCP match enabled"
    );
}

#[test]
fn flex_match_oversized_width_fails_closed_not_truncated() {
    // #3406 RED-on-revert: a present flex_match whose byte `length` is outside
    // 1..=4 (the value/mask wire fields are u32) must reject the whole snapshot.
    // Pre-#3406 the Go builder capped an oversized width to 4 and still emitted the
    // term, so only the truncated 4-byte window was compared and the match
    // BROADENED (fail-open); the matcher's `flex_enabled` derivation would also
    // silently disable an out-of-range flex (no constraint = match-any). Reverting
    // the parse_term guard returns Ok with the flex silently disabled.
    let err = filter_with_marked_term("inet", |t| {
        t.flex_match = Some(FlexMatchSnapshot {
            offset: 0,
            length: 5, // 5 bytes — exceeds the u32 wire value
            value: 0x1,
            mask: 0xFFFF_FFFF,
            match_start: String::new(),
        });
    })
    .expect_err("an oversized flex-match width must fail the build closed");
    match err {
        SnapshotIntegrityError::UnrepresentableFilterFlexMatch {
            family,
            filter,
            term,
            length,
        } => {
            assert_eq!(family, "inet");
            assert_eq!(filter, "f");
            assert_eq!(term, "marked");
            assert_eq!(length, 5);
        }
        other => panic!("expected UnrepresentableFilterFlexMatch, got {other:?}"),
    }

    // A representable 1..=4-byte flex compiles fine (the guard is keyed on the
    // out-of-range length, not on every flex term).
    filter_with_marked_term("inet", |t| {
        t.flex_match = Some(FlexMatchSnapshot {
            offset: 0,
            length: 4,
            value: 0x1,
            mask: 0xFFFF_FFFF,
            match_start: String::new(),
        });
    })
    .expect("a representable 4-byte flex must compile");
}

// #3296: an interface hook naming a filter NOT present in the compiled table
// must reject the whole snapshot (fail closed / preflight preserves prior
// good state), NOT leave the per-interface fast-path empty and fall through to
// the default Accept. This is the fail-on-revert canary: deleting the `else`
// arm in compiler.rs that raises MissingFilterRef turns the missing reference
// back into a silent Accept and flips these asserts.
#[test]
fn missing_filter_ref_3296_input_v4_rejects_not_accepts() {
    let ifaces = vec![crate::InterfaceSnapshot {
        name: "ge-0/0/0.0".into(),
        ifindex: 5,
        // typo: the defined filter is WAN_BLOCK; the hook names WAN-BLOCK
        filter_input_v4: "WAN-BLOCK".into(),
        ..Default::default()
    }];
    let err = parse_filter_state(
        &[FirewallFilterSnapshot {
            name: "WAN_BLOCK".into(),
            family: "inet".into(),
            terms: vec![FirewallTermSnapshot {
                name: "deny-all".into(),
                action: "discard".into(),
                ..Default::default()
            }],
        }],
        &[],
        &ifaces,
        "",
        "",
    )
    .expect_err("a missing input filter reference must fail the build closed");
    match err {
        SnapshotIntegrityError::MissingFilterRef {
            interface,
            family,
            direction,
            filter,
        } => {
            assert_eq!(interface, "ge-0/0/0.0");
            assert_eq!(family, "inet");
            assert_eq!(direction, "input");
            assert_eq!(filter, "WAN-BLOCK");
        }
        other => panic!("expected MissingFilterRef, got {other:?}"),
    }
}

#[test]
fn missing_filter_ref_3296_output_v6_rejects_not_accepts() {
    // The output path is independently fail-open (no needs_tx_eval flag set
    // for a missing ref), so it must be covered too.
    let ifaces = vec![crate::InterfaceSnapshot {
        name: "ge-0/0/0.0".into(),
        ifindex: 5,
        filter_output_v6: "egress6-ghost".into(),
        ..Default::default()
    }];
    let err = parse_filter_state(&[], &[], &ifaces, "", "")
        .expect_err("a missing output v6 filter reference must fail the build closed");
    assert!(
        matches!(
            err,
            SnapshotIntegrityError::MissingFilterRef { ref direction, ref family, .. }
                if direction == "output" && family == "inet6"
        ),
        "expected MissingFilterRef output/inet6, got {err:?}"
    );
}

#[test]
fn missing_filter_ref_3296_lo0_input_rejects_not_accepts() {
    // lo0 host-bound filter (the protect-RE lockout hook) names a filter not
    // in the table → must reject, not silently leave lo0_filter_v4_fast None
    // (which falls through to Accept).
    let err = parse_filter_state(&[], &[], &[], "protect-re-typo", "")
        .expect_err("a missing lo0 input filter reference must fail the build closed");
    assert!(
        matches!(
            err,
            SnapshotIntegrityError::MissingFilterRef { ref interface, ref filter, .. }
                if interface == "lo0" && filter == "protect-re-typo"
        ),
        "expected MissingFilterRef lo0/protect-re-typo, got {err:?}"
    );
}

#[test]
fn defined_filter_ref_3296_compiles_cleanly() {
    // The positive control: a hook whose referenced filter IS defined must
    // compile (the gate only rejects DANGLING references).
    let ifaces = vec![crate::InterfaceSnapshot {
        name: "ge-0/0/0.0".into(),
        ifindex: 5,
        filter_input_v4: "WAN_BLOCK".into(),
        ..Default::default()
    }];
    let state = parse_filter_state(
        &[FirewallFilterSnapshot {
            name: "WAN_BLOCK".into(),
            family: "inet".into(),
            terms: vec![FirewallTermSnapshot {
                name: "deny-all".into(),
                action: "discard".into(),
                ..Default::default()
            }],
        }],
        &[],
        &ifaces,
        "",
        "",
    )
    .expect("a defined filter reference must compile cleanly");
    assert!(
        state.iface_filter_v4_fast.contains_key(&5),
        "the resolved filter must be installed on the interface fast path"
    );
}

// Go->Rust fixture: the exact #2505 reproduction — `from protocol esp; then
// discard` must discard ONLY ESP, not all protocols. This is the fail-on-
// revert canary: restoring the stale local parse_protocol (which drops esp)
// turns the term into a match-all and BOTH of these asserts flip.
#[test]
fn protocol_2505_esp_discard_fixture_scopes_only_esp() {
    let state = filter_for_protocol("esp").expect("esp resolves");
    // ESP (proto 50) is discarded.
    let esp = evaluate_filter(
        &state,
        "inet:f",
        v4(10, 0, 0, 1),
        v4(10, 0, 0, 2),
        50,
        0,
        0,
        0,
        TermMatchExtra::default(),
    );
    assert_eq!(esp.action, FilterAction::Discard, "ESP must be discarded");
    // TCP is NOT discarded — the bug made this Discard (match-all).
    let tcp = evaluate_filter(
        &state,
        "inet:f",
        v4(10, 0, 0, 1),
        v4(10, 0, 0, 2),
        PROTO_TCP,
        12345,
        443,
        0,
        TermMatchExtra::default(),
    );
    assert_eq!(
        tcp.action,
        FilterAction::Accept,
        "TCP must NOT be discarded by a `from protocol esp` term — fail-wide regression (#2505)"
    );
}

// === #2506: source/destination-prefix-list expansion + `except` inversion ===
//
// The Go control plane resolves a `from source-prefix-list NAME [except]`
// reference to explicit CIDRs and sets the per-direction `source_except` /
// `destination_except` flag. These tests pin the Rust matcher half: a positive
// prefix set scopes the term to those prefixes; an `except` set inverts the
// membership so the term matches every address NOT in the set. They fail on a
// matcher that ignores the except flag (the inverted term would match the
// listed prefixes instead of excluding them — exactly the dropped-scope bug).

#[test]
fn prefix_list_positive_scopes_term_to_listed_addrs() {
    let state = make_filter_state(
        &[FirewallFilterSnapshot {
            name: "f".into(),
            family: "inet".into(),
            terms: vec![
                FirewallTermSnapshot {
                    name: "scoped-discard".into(),
                    source_addresses: vec!["10.0.0.0/24".into()],
                    action: "discard".into(),
                    ..Default::default()
                },
                FirewallTermSnapshot {
                    name: "default-accept".into(),
                    action: "accept".into(),
                    ..Default::default()
                },
            ],
        }],
        &[],
    );
    // A source IN the prefix is discarded.
    let r = evaluate_filter(
        &state,
        "inet:f",
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)),
        IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1)),
        PROTO_TCP,
        1000,
        80,
        0,
        TermMatchExtra::default(),
    );
    assert_eq!(
        r.action,
        FilterAction::Discard,
        "in-prefix source must hit the scoped discard"
    );
    // A source OUT of the prefix falls through to accept.
    let r = evaluate_filter(
        &state,
        "inet:f",
        IpAddr::V4(Ipv4Addr::new(172, 16, 0, 5)),
        IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1)),
        PROTO_TCP,
        1000,
        80,
        0,
        TermMatchExtra::default(),
    );
    assert_eq!(
        r.action,
        FilterAction::Accept,
        "out-of-prefix source must NOT hit the scoped discard"
    );
}

#[test]
fn prefix_list_except_inverts_membership() {
    // `from destination-prefix-list internal except; then discard` — discard
    // everything EXCEPT destinations in 10.0.0.0/8.
    let state = make_filter_state(
        &[FirewallFilterSnapshot {
            name: "f".into(),
            family: "inet".into(),
            terms: vec![
                FirewallTermSnapshot {
                    name: "except-discard".into(),
                    destination_addresses: vec!["10.0.0.0/8".into()],
                    destination_except: true,
                    action: "discard".into(),
                    ..Default::default()
                },
                FirewallTermSnapshot {
                    name: "default-accept".into(),
                    action: "accept".into(),
                    ..Default::default()
                },
            ],
        }],
        &[],
    );
    // A dest IN the except list is NOT discarded (falls through to accept).
    let r = evaluate_filter(
        &state,
        "inet:f",
        IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3)),
        PROTO_TCP,
        1000,
        80,
        0,
        TermMatchExtra::default(),
    );
    assert_eq!(
        r.action,
        FilterAction::Accept,
        "a dest INSIDE the except list must be EXCLUDED from the discard (#2506) — \
         a matcher ignoring `except` would wrongly discard it"
    );
    // A dest OUTSIDE the except list IS discarded.
    let r = evaluate_filter(
        &state,
        "inet:f",
        IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
        PROTO_TCP,
        1000,
        80,
        0,
        TermMatchExtra::default(),
    );
    assert_eq!(
        r.action,
        FilterAction::Discard,
        "a dest OUTSIDE the except list must be discarded (match-all-except)"
    );
}

#[test]
fn prefix_list_except_inverts_membership_v6() {
    let state = make_filter_state(
        &[FirewallFilterSnapshot {
            name: "f6".into(),
            family: "inet6".into(),
            terms: vec![
                FirewallTermSnapshot {
                    name: "except-discard".into(),
                    source_addresses: vec!["2001:db8::/32".into()],
                    source_except: true,
                    action: "discard".into(),
                    ..Default::default()
                },
                FirewallTermSnapshot {
                    name: "default-accept".into(),
                    action: "accept".into(),
                    ..Default::default()
                },
            ],
        }],
        &[],
    );
    // Source inside the except set -> accepted (excluded from discard).
    let r = evaluate_filter(
        &state,
        "inet6:f6",
        "2001:db8::1".parse().unwrap(),
        "2001:db8::2".parse().unwrap(),
        PROTO_TCP,
        1000,
        80,
        0,
        TermMatchExtra::default(),
    );
    assert_eq!(r.action, FilterAction::Accept);
    // Source outside the except set -> discarded.
    let r = evaluate_filter(
        &state,
        "inet6:f6",
        "2001:dead::1".parse().unwrap(),
        "2001:db8::2".parse().unwrap(),
        PROTO_TCP,
        1000,
        80,
        0,
        TermMatchExtra::default(),
    );
    assert_eq!(r.action, FilterAction::Discard);
}

// === #2506 (Copilot): empty-resolution prefix-list scope must NOT fail open ===
//
// A `from source-prefix-list X` whose X is defined-but-empty (passes the strict
// gate) OR unresolved on the lenient/peer-sync path resolves to ZERO prefixes.
// The Go control plane still sets source_constrained=true (the operator wrote a
// scope), so the matcher must NOT collapse to match-any:
//   - positive (no except), empty -> match NOTHING (fail-closed).
//   - except, empty -> match ALL (Junos "not in {}").
// These fail on a matcher that derives `constrained` from the resolved list
// length, or whose empty guard returns a hardcoded false.

#[test]
fn empty_positive_prefix_list_scope_matches_nothing() {
    // `from source-prefix-list X; then discard` with X empty: constrained but
    // zero prefixes, no except -> the discard term must match NO source, so a
    // packet falls through to the default accept (it is NOT discarded).
    let state = make_filter_state(
        &[FirewallFilterSnapshot {
            name: "f".into(),
            family: "inet".into(),
            terms: vec![
                FirewallTermSnapshot {
                    name: "empty-scope-discard".into(),
                    source_addresses: vec![], // X resolved empty
                    source_constrained: true, // but a scope WAS specified
                    action: "discard".into(),
                    ..Default::default()
                },
                FirewallTermSnapshot {
                    name: "default-accept".into(),
                    action: "accept".into(),
                    ..Default::default()
                },
            ],
        }],
        &[],
    );
    let r = evaluate_filter(
        &state,
        "inet:f",
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)),
        IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1)),
        PROTO_TCP,
        1000,
        80,
        0,
        TermMatchExtra::default(),
    );
    assert_eq!(
        r.action,
        FilterAction::Accept,
        "an empty positive prefix-list scope must match NOTHING (fail-closed) — \
         a matcher that collapses empty-constrained to match-any would DISCARD \
         this packet (#2506 Copilot)"
    );
}

#[test]
fn empty_positive_prefix_list_scope_accept_does_not_match_all() {
    // The fail-OPEN sibling: `from source-prefix-list X; then accept` with X
    // empty must NOT accept everything. A packet must NOT be accepted by this
    // term (it falls through to the terminal discard).
    let state = make_filter_state(
        &[FirewallFilterSnapshot {
            name: "f".into(),
            family: "inet".into(),
            terms: vec![
                FirewallTermSnapshot {
                    name: "empty-scope-accept".into(),
                    source_addresses: vec![],
                    source_constrained: true,
                    action: "accept".into(),
                    ..Default::default()
                },
                FirewallTermSnapshot {
                    name: "default-discard".into(),
                    action: "discard".into(),
                    ..Default::default()
                },
            ],
        }],
        &[],
    );
    let r = evaluate_filter(
        &state,
        "inet:f",
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)),
        IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1)),
        PROTO_TCP,
        1000,
        80,
        0,
        TermMatchExtra::default(),
    );
    assert_eq!(
        r.action,
        FilterAction::Discard,
        "an empty positive prefix-list scope must NOT accept all traffic \
         (fail-open) — the packet must fall through to the terminal discard (#2506)"
    );
}

#[test]
fn empty_except_prefix_list_scope_matches_all() {
    // `from source-prefix-list X except; then discard` with X empty: "discard
    // sources NOT in {}" = discard ALL. A packet must be discarded.
    let state = make_filter_state(
        &[FirewallFilterSnapshot {
            name: "f".into(),
            family: "inet".into(),
            terms: vec![
                FirewallTermSnapshot {
                    name: "empty-except-discard".into(),
                    source_addresses: vec![], // X resolved empty
                    source_except: true,
                    source_constrained: true,
                    action: "discard".into(),
                    ..Default::default()
                },
                FirewallTermSnapshot {
                    name: "default-accept".into(),
                    action: "accept".into(),
                    ..Default::default()
                },
            ],
        }],
        &[],
    );
    let r = evaluate_filter(
        &state,
        "inet:f",
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)),
        IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1)),
        PROTO_TCP,
        1000,
        80,
        0,
        TermMatchExtra::default(),
    );
    assert_eq!(
        r.action,
        FilterAction::Discard,
        "an empty `except` prefix-list scope must match ALL (sources not in {{}} = \
         all) — the matcher's empty guard must return `except` (#2506)"
    );
}

// #5097: the source_except POLARITY the Go control plane lowers for an
// UNRESOLVED sole `except` prefix-list is load-bearing at the matcher. This
// pairs the two snapshots to prove it:
//   - FIXED lowering (source_except=true, empty, constrained) -> the matcher's
//     empty-except guard returns `except` = match ALL, so a discard term drops
//     the packet (fail CLOSED).
//   - BUGGY lowering (source_except=false, empty, constrained) -> the empty
//     positive guard returns false = match NOTHING, so the discard term matches
//     no packet and traffic falls through to the terminal accept (fail OPEN).
// The Go fix flips the emitted flag from the second shape to the first; this
// test locks the matcher contract the fix depends on.
//
// FAIL-ON-REVERT: revert the `nets_match_v4`/`nets_match_v6` empty guard from
// `return except` to a hardcoded `return false` (the pre-#2506 collapse) and the
// FIXED-lowering assertion below flips Discard -> Accept and goes RED.
#[test]
fn unresolved_sole_except_polarity_is_load_bearing_5097() {
    let src = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7));
    let dst = IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1));

    // FIXED (#5097) lowering: unresolved sole except -> except=true, empty,
    // constrained. Discard term must match ALL -> packet discarded (fail closed).
    let fixed = make_filter_state(
        &[FirewallFilterSnapshot {
            name: "f".into(),
            family: "inet".into(),
            terms: vec![
                FirewallTermSnapshot {
                    name: "unresolved-except-discard".into(),
                    source_addresses: vec![], // unresolved -> no prefixes
                    source_except: true,      // ...but polarity preserved
                    source_constrained: true,
                    action: "discard".into(),
                    ..Default::default()
                },
                FirewallTermSnapshot {
                    name: "default-accept".into(),
                    action: "accept".into(),
                    ..Default::default()
                },
            ],
        }],
        &[],
    );
    let r = evaluate_filter(
        &fixed, "inet:f", src, dst, PROTO_TCP, 1000, 80, 0, TermMatchExtra::default(),
    );
    assert_eq!(
        r.action,
        FilterAction::Discard,
        "the FIXED #5097 lowering (unresolved sole except -> except=true) must \
         match ALL and DISCARD (fail closed); a matcher whose empty-except guard \
         returns match-none reintroduces the fail-OPEN"
    );

    // BUGGY (pre-#5097) lowering: the `continue` dropped the polarity, emitting
    // except=false. Empty positive scope matches NOTHING, so the discard term
    // never fires and the packet falls through to the terminal accept (fail
    // OPEN). This asserts the flag — not the empty list — decides the outcome.
    let buggy = make_filter_state(
        &[FirewallFilterSnapshot {
            name: "f".into(),
            family: "inet".into(),
            terms: vec![
                FirewallTermSnapshot {
                    name: "lost-polarity-discard".into(),
                    source_addresses: vec![],
                    source_except: false, // #5097 bug: polarity lost
                    source_constrained: true,
                    action: "discard".into(),
                    ..Default::default()
                },
                FirewallTermSnapshot {
                    name: "default-accept".into(),
                    action: "accept".into(),
                    ..Default::default()
                },
            ],
        }],
        &[],
    );
    let r = evaluate_filter(
        &buggy, "inet:f", src, dst, PROTO_TCP, 1000, 80, 0, TermMatchExtra::default(),
    );
    assert_eq!(
        r.action,
        FilterAction::Accept,
        "the BUGGY pre-#5097 lowering (except=false) matches NOTHING -> the \
         discard never fires -> fail OPEN. Proves source_except is load-bearing."
    );
}

#[test]
fn except_v4_list_does_not_constrain_v6_packet() {
    // Cross-family: `from source-prefix-list X except` where X is v4-only. For a
    // v6 packet, the v6 vec is empty but the direction is constrained + except,
    // so the empty guard returns `except` = true: a v6 source is trivially "not
    // in" a v4 list -> the except term matches it. A v4 source inside X does NOT
    // match (it IS in the except set); a v4 source outside X matches.
    let state = make_filter_state(
        &[FirewallFilterSnapshot {
            name: "f".into(),
            family: "inet".into(), // family label is the filter's; terms carry both
            terms: vec![
                FirewallTermSnapshot {
                    name: "v4-except-discard".into(),
                    source_addresses: vec!["10.0.0.0/8".into()],
                    source_except: true,
                    source_constrained: true,
                    action: "discard".into(),
                    ..Default::default()
                },
                FirewallTermSnapshot {
                    name: "default-accept".into(),
                    action: "accept".into(),
                    ..Default::default()
                },
            ],
        }],
        &[],
    );
    // v6 packet: matches the except term (not in the v4 list) -> discarded.
    let r = evaluate_filter(
        &state,
        "inet:f",
        "2001:db8::1".parse().unwrap(),
        "2001:db8::2".parse().unwrap(),
        PROTO_TCP,
        1000,
        80,
        0,
        TermMatchExtra::default(),
    );
    assert_eq!(
        r.action,
        FilterAction::Discard,
        "a v6 source is 'not in' a v4-only except list -> the except term must \
         match it (the v4 list does not constrain v6) (#2506)"
    );
    // v4 source INSIDE the except list -> NOT discarded (it IS in the set).
    let r = evaluate_filter(
        &state,
        "inet:f",
        IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3)),
        IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1)),
        PROTO_TCP,
        1000,
        80,
        0,
        TermMatchExtra::default(),
    );
    assert_eq!(r.action, FilterAction::Accept);
    // v4 source OUTSIDE the except list -> discarded.
    let r = evaluate_filter(
        &state,
        "inet:f",
        IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
        IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1)),
        PROTO_TCP,
        1000,
        80,
        0,
        TermMatchExtra::default(),
    );
    assert_eq!(r.action, FilterAction::Discard);
}

// ---------------------------------------------------------------------------
// #2544: firewall-filter fall-through. A term whose `then` carries NO
// terminating action — either an explicit `then next term` (Action == "",
// next_term == true) OR a modifier-only term (only count/log/forwarding-class/
// policer/dscp) — must APPLY its modifiers and FALL THROUGH to the next term
// (Junos), instead of terminating as Accept and short-circuiting the loop.
//
// Pre-fix (master): the empty action compiled to FilterAction::Accept and the
// evaluator returned on the first match, so a packet matching a fall-through
// term was ACCEPTED at that term and a later `discard` term was never reached.
// These tests FAIL on master (assert Discard, master returns Accept) and pass
// with continue_term wired through.
// ---------------------------------------------------------------------------

#[test]
fn fallthrough_explicit_next_term_reaches_later_discard() {
    let state = make_filter_state(
        &[FirewallFilterSnapshot {
            name: "ft".into(),
            family: "inet".into(),
            terms: vec![
                // term1: matches the test 5-tuple, `then next term` (no
                // terminating action) -> must fall through.
                FirewallTermSnapshot {
                    name: "count-then-next".into(),
                    protocols: vec!["tcp".into()],
                    destination_ports: vec!["80".into()],
                    action: String::new(),
                    next_term: true,
                    count: "ft-hits".into(),
                    ..Default::default()
                },
                // term2: same match, discards.
                FirewallTermSnapshot {
                    name: "drop-web".into(),
                    protocols: vec!["tcp".into()],
                    destination_ports: vec!["80".into()],
                    action: "discard".into(),
                    ..Default::default()
                },
            ],
        }],
        &[],
    );
    let r = evaluate_filter_counted(
        &state,
        "inet:ft",
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        PROTO_TCP,
        40000,
        80,
        0,
        TermMatchExtra::default(),
        1400,
    );
    // Fell through term1 (Accept on master) and was discarded by term2.
    assert_eq!(r.action, FilterAction::Discard);
    // Modifier (count) on the fall-through term still applied.
    let filter = state.filters.get("inet:ft").expect("filter");
    assert_eq!(filter.terms[0].counter.packets.load(Ordering::Relaxed), 1);
    assert_eq!(filter.terms[0].counter.bytes.load(Ordering::Relaxed), 1400);
}

#[test]
fn fallthrough_modifier_only_term_reaches_later_discard() {
    // A modifier-only term: empty action, NO explicit next_term flag set on the
    // snapshot. The compiler still treats an empty terminating action as
    // fall-through (continue_term true), matching Junos implicit fall-through.
    let state = make_filter_state(
        &[FirewallFilterSnapshot {
            name: "mo".into(),
            family: "inet".into(),
            terms: vec![
                FirewallTermSnapshot {
                    name: "count-only".into(),
                    protocols: vec!["tcp".into()],
                    destination_ports: vec!["80".into()],
                    action: String::new(),
                    next_term: false, // modifier-only, no explicit `next term`
                    count: "mo-hits".into(),
                    ..Default::default()
                },
                FirewallTermSnapshot {
                    name: "drop-web".into(),
                    protocols: vec!["tcp".into()],
                    destination_ports: vec!["80".into()],
                    action: "discard".into(),
                    ..Default::default()
                },
            ],
        }],
        &[],
    );
    // Confirm the compiler marked term0 as fall-through.
    let filter = state.filters.get("inet:mo").expect("filter");
    assert!(
        filter.terms[0].continue_term,
        "modifier-only term must compile to a fall-through term"
    );
    let r = evaluate_filter_counted(
        &state,
        "inet:mo",
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        PROTO_TCP,
        40000,
        80,
        0,
        TermMatchExtra::default(),
        1400,
    );
    assert_eq!(r.action, FilterAction::Discard);
    assert_eq!(filter.terms[0].counter.packets.load(Ordering::Relaxed), 1);
}

#[test]
fn fallthrough_terminal_term_still_returns_immediately() {
    // A terminating term (accept) must NOT over-continue: a matching accept term
    // returns Accept even though a later discard term also matches.
    let state = make_filter_state(
        &[FirewallFilterSnapshot {
            name: "term".into(),
            family: "inet".into(),
            terms: vec![
                FirewallTermSnapshot {
                    name: "accept-web".into(),
                    protocols: vec!["tcp".into()],
                    destination_ports: vec!["80".into()],
                    action: "accept".into(),
                    ..Default::default()
                },
                FirewallTermSnapshot {
                    name: "drop-web".into(),
                    protocols: vec!["tcp".into()],
                    destination_ports: vec!["80".into()],
                    action: "discard".into(),
                    ..Default::default()
                },
            ],
        }],
        &[],
    );
    let r = evaluate_filter(
        &state,
        "inet:term",
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        PROTO_TCP,
        40000,
        80,
        0,
        TermMatchExtra::default(),
    );
    assert_eq!(r.action, FilterAction::Accept);
}

#[test]
fn fallthrough_no_later_match_uses_default_accept_with_modifiers() {
    // term1 matches and falls through (count); term2 does NOT match. With no
    // terminating term reached, the implicit default Accept applies, but the
    // fall-through modifier (count) still fired.
    let state = make_filter_state(
        &[FirewallFilterSnapshot {
            name: "ftd".into(),
            family: "inet".into(),
            terms: vec![
                FirewallTermSnapshot {
                    name: "count-next".into(),
                    protocols: vec!["tcp".into()],
                    destination_ports: vec!["80".into()],
                    action: String::new(),
                    next_term: true,
                    count: "ftd-hits".into(),
                    ..Default::default()
                },
                FirewallTermSnapshot {
                    name: "drop-telnet".into(),
                    protocols: vec!["tcp".into()],
                    destination_ports: vec!["23".into()],
                    action: "discard".into(),
                    ..Default::default()
                },
            ],
        }],
        &[],
    );
    let r = evaluate_filter_counted(
        &state,
        "inet:ftd",
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        PROTO_TCP,
        40000,
        80,
        0,
        TermMatchExtra::default(),
        1400,
    );
    assert_eq!(r.action, FilterAction::Accept);
    let filter = state.filters.get("inet:ftd").expect("filter");
    assert_eq!(filter.terms[0].counter.packets.load(Ordering::Relaxed), 1);
}

#[test]
fn fallthrough_tx_selection_applies_forwarding_class_then_discards() {
    // TX-selection path: a fall-through term sets a forwarding-class and falls
    // through; a later term discards. The forwarding-class modifier is applied
    // (accumulated) AND the terminal discard is honored.
    let ifaces = vec![crate::InterfaceSnapshot {
        name: "reth0.80".into(),
        ifindex: 7,
        filter_output_v4: "tx-ft".into(),
        ..Default::default()
    }];
    let state = parse_filter_state(
        &[FirewallFilterSnapshot {
            name: "tx-ft".into(),
            family: "inet".into(),
            terms: vec![
                FirewallTermSnapshot {
                    name: "fc-next".into(),
                    protocols: vec!["tcp".into()],
                    destination_ports: vec!["80".into()],
                    action: String::new(),
                    next_term: true,
                    forwarding_class: "expedited".into(),
                    count: "tx-ft-hits".into(),
                    ..Default::default()
                },
                FirewallTermSnapshot {
                    name: "drop-web".into(),
                    protocols: vec!["tcp".into()],
                    destination_ports: vec!["80".into()],
                    action: "discard".into(),
                    ..Default::default()
                },
            ],
        }],
        &[],
        &ifaces,
        "",
        "",
    )
    .expect("filter state compiles");
    let result = evaluate_interface_output_filter_tx_selection_counted(
        &state,
        7,
        false,
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        PROTO_TCP,
        40000,
        80,
        0,
        TermMatchExtra::default(),
        1514,
    );
    assert_eq!(result.action, FilterAction::Discard);
    assert_eq!(result.forwarding_class, Some("expedited"));
    let filter = state.filters.get("inet:tx-ft").expect("filter");
    assert_eq!(filter.terms[0].counter.packets.load(Ordering::Relaxed), 1);
}

// ---------------------------------------------------------------------------
// #5142 (security, filter fail-open): a term carrying a REAL terminating action
// (discard/reject/accept) AND next_term=true is a contradiction. The runtime
// must FAIL CLOSED — the terminating deny MUST apply, the fall-through bit must
// NEVER suppress it (vSRX filter semantics). The Go commit gate rejects the
// contradiction, but the tolerant peer-sync path could still deliver such a
// snapshot, so the compiler treats a nonempty action as terminating regardless
// of next_term (continue_term := action.is_empty() && routing_instance.empty).
//
// FAIL-ON-REVERT: restore `continue_term: (snap.next_term ||
// snap.action.is_empty()) && snap.routing_instance.is_empty()` and the
// discard/reject asserts below go RED — the term falls through and the implicit
// default Accept survives (fail-OPEN).
// ---------------------------------------------------------------------------

#[test]
fn terminal_discard_with_next_term_still_discards_5142() {
    // A single term: `then discard` AND next_term=true (the #5142 contradiction
    // a mixed-version peer could deliver). The deny MUST apply — the fall-through
    // bit must not suppress it. There is no later term, so a fall-through would
    // return the implicit default Accept (the fail-OPEN bug).
    let state = make_filter_state(
        &[FirewallFilterSnapshot {
            name: "deny".into(),
            family: "inet".into(),
            terms: vec![FirewallTermSnapshot {
                name: "drop-web".into(),
                protocols: vec!["tcp".into()],
                destination_ports: vec!["80".into()],
                action: "discard".into(),
                next_term: true, // contradiction: terminal + fall-through
                ..Default::default()
            }],
        }],
        &[],
    );
    // The compiler must NOT mark a term with a real terminal action as a
    // fall-through, even though next_term is set.
    let filter = state.filters.get("inet:deny").expect("filter");
    assert!(
        !filter.terms[0].continue_term,
        "a term with a terminal action must terminate, not fall through (#5142)"
    );
    let r = evaluate_filter(
        &state,
        "inet:deny",
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        PROTO_TCP,
        40000,
        80,
        0,
        TermMatchExtra::default(),
    );
    assert_eq!(
        r.action,
        FilterAction::Discard,
        "discard+next_term must apply the deny, not fall through to implicit Accept (#5142)"
    );
}

#[test]
fn terminal_reject_with_next_term_still_rejects_5142() {
    let state = make_filter_state(
        &[FirewallFilterSnapshot {
            name: "deny".into(),
            family: "inet".into(),
            terms: vec![FirewallTermSnapshot {
                name: "reject-web".into(),
                protocols: vec!["tcp".into()],
                destination_ports: vec!["80".into()],
                action: "reject".into(),
                next_term: true,
                ..Default::default()
            }],
        }],
        &[],
    );
    let r = evaluate_filter(
        &state,
        "inet:deny",
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        PROTO_TCP,
        40000,
        80,
        0,
        TermMatchExtra::default(),
    );
    assert_eq!(
        r.action,
        FilterAction::Reject(RejectMessage::ADMIN_PROHIBITED),
        "reject+next_term must apply the deny, not fall through (#5142)"
    );
}

#[test]
fn terminal_discard_with_next_term_beats_later_accept_5142() {
    // A discard+next_term term ahead of an `accept` term for the same 5-tuple:
    // the fail-OPEN bug would fall through term0 and ACCEPT at term1. Fail-closed
    // the discard terminates at term0.
    let state = make_filter_state(
        &[FirewallFilterSnapshot {
            name: "order".into(),
            family: "inet".into(),
            terms: vec![
                FirewallTermSnapshot {
                    name: "drop-web".into(),
                    protocols: vec!["tcp".into()],
                    destination_ports: vec!["80".into()],
                    action: "discard".into(),
                    next_term: true,
                    ..Default::default()
                },
                FirewallTermSnapshot {
                    name: "accept-all".into(),
                    protocols: vec!["tcp".into()],
                    action: "accept".into(),
                    ..Default::default()
                },
            ],
        }],
        &[],
    );
    let r = evaluate_filter(
        &state,
        "inet:order",
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        PROTO_TCP,
        40000,
        80,
        0,
        TermMatchExtra::default(),
    );
    assert_eq!(r.action, FilterAction::Discard);
}

#[test]
fn modifier_only_next_term_still_falls_through_5142() {
    // The valid #2544/#3427 case must be UNCHANGED by the #5142 fix: a
    // modifier-only term (empty action) with next_term=true falls through and a
    // later discard term applies.
    let state = make_filter_state(
        &[FirewallFilterSnapshot {
            name: "mo".into(),
            family: "inet".into(),
            terms: vec![
                FirewallTermSnapshot {
                    name: "count-next".into(),
                    protocols: vec!["tcp".into()],
                    destination_ports: vec!["80".into()],
                    action: String::new(), // modifier-only — no terminal
                    next_term: true,
                    count: "mo-hits".into(),
                    ..Default::default()
                },
                FirewallTermSnapshot {
                    name: "drop-web".into(),
                    protocols: vec!["tcp".into()],
                    destination_ports: vec!["80".into()],
                    action: "discard".into(),
                    ..Default::default()
                },
            ],
        }],
        &[],
    );
    let filter = state.filters.get("inet:mo").expect("filter");
    assert!(
        filter.terms[0].continue_term,
        "modifier-only next-term term must still fall through (#2544/#3427)"
    );
    let r = evaluate_filter(
        &state,
        "inet:mo",
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        PROTO_TCP,
        40000,
        80,
        0,
        TermMatchExtra::default(),
    );
    assert_eq!(
        r.action,
        FilterAction::Discard,
        "modifier-only next-term must fall through to the later discard"
    );
}

// ---------------------------------------------------------------------------
// #2573: the cached TX-selection path must record EVERY matched `then count`
// term, not just the last. With #2544 fall-through a single packet can match
// two count terms on the same flow-cache key; the old single-Arc slot kept only
// the last, so the earlier fall-through count term was silently under-counted on
// the cached replay path (the uncached full-eval path counted both).
//
// FAIL-ON-REVERT: reverting `merge_matched_cached_modifiers` to
// `acc.counter = Some(term.counter.clone())` (last-only) makes the cached result
// carry one counter and replay increments only the terminal term — the
// `terms[0].counter` assert below then fails RED.
// ---------------------------------------------------------------------------

#[test]
fn cached_tx_selection_records_all_fallthrough_count_terms() {
    // Two fall-through `then count` terms both match the same 5-tuple, followed
    // by a terminating accept. The output filter is the TX-selection filter.
    let ifaces = vec![crate::InterfaceSnapshot {
        name: "reth0.80".into(),
        ifindex: 9,
        filter_output_v4: "multi-count".into(),
        ..Default::default()
    }];
    let state = parse_filter_state(
        &[FirewallFilterSnapshot {
            name: "multi-count".into(),
            family: "inet".into(),
            terms: vec![
                FirewallTermSnapshot {
                    name: "count-a".into(),
                    protocols: vec!["tcp".into()],
                    destination_ports: vec!["80".into()],
                    action: String::new(),
                    next_term: true,
                    count: "count-a-hits".into(),
                    ..Default::default()
                },
                FirewallTermSnapshot {
                    name: "count-b".into(),
                    protocols: vec!["tcp".into()],
                    destination_ports: vec!["80".into()],
                    action: String::new(),
                    next_term: true,
                    count: "count-b-hits".into(),
                    ..Default::default()
                },
                FirewallTermSnapshot {
                    name: "accept-rest".into(),
                    protocols: vec!["tcp".into()],
                    destination_ports: vec!["80".into()],
                    action: "accept".into(),
                    ..Default::default()
                },
            ],
        }],
        &[],
        &ifaces,
        "",
        "",
    )
    .expect("filter state compiles");

    let filter = state
        .iface_filter_out_v4_fast
        .get(&9)
        .expect("output filter present");
    // The compiler must mark the first two terms as fall-through count terms.
    assert!(filter.terms[0].continue_term && filter.terms[0].has_count);
    assert!(filter.terms[1].continue_term && filter.terms[1].has_count);

    let src = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let dst = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let cached = evaluate_filter_ref_tx_selection_cached(filter, src, dst, PROTO_TCP, 40000, 80, 0);

    // The cached descriptor must carry BOTH matched count terms (deduped to 2).
    assert_eq!(
        cached.counters.len(),
        2,
        "cached TX-selection must record every matched `then count` term, not just the last"
    );
    assert_eq!(cached.action, FilterAction::Accept);

    // Replay exactly as the flow-cache hit path does: record each cached counter.
    cached.counters.for_each(|counter| {
        crate::filter::record_filter_counter(counter, 1500);
    });
    crate::filter::flush_recorded_filter_counters();

    // BOTH fall-through count terms must have incremented on the cached replay.
    // Revert to last-only and terms[0] stays 0 -> this assert fails RED.
    assert_eq!(
        filter.terms[0].counter.packets.load(Ordering::Relaxed),
        1,
        "first fall-through count term must increment on the cached path"
    );
    assert_eq!(filter.terms[0].counter.bytes.load(Ordering::Relaxed), 1500);
    assert_eq!(
        filter.terms[1].counter.packets.load(Ordering::Relaxed),
        1,
        "second fall-through count term must increment on the cached path"
    );
    assert_eq!(filter.terms[1].counter.bytes.load(Ordering::Relaxed), 1500);
}

// ---------------------------------------------------------------------------
// #2616: a fall-through `then { log; next term; }` term followed by a terminal
// discard/reject must report the FINAL verdict (deny) in its RT_FLOW log action,
// not the Accept placeholder the fall-through term carries. Pre-fix the
// log_match action was term.action (Accept) — the event lied "permit" while the
// packet was denied. These FAIL on master (assert Discard/Reject, master
// returns Accept on log_match.action) and pass with normalize_log_match_action.
// ---------------------------------------------------------------------------

#[test]
fn fallthrough_log_action_follows_terminal_discard() {
    let state = make_filter_state(
        &[FirewallFilterSnapshot {
            name: "lt".into(),
            family: "inet".into(),
            terms: vec![
                FirewallTermSnapshot {
                    name: "log-first".into(),
                    protocols: vec!["tcp".into()],
                    destination_ports: vec!["443".into()],
                    action: String::new(),
                    next_term: true,
                    log: true,
                    syslog: false,
                    reject_message_type: String::new(),
                    ..Default::default()
                },
                FirewallTermSnapshot {
                    name: "deny-web".into(),
                    protocols: vec!["tcp".into()],
                    destination_ports: vec!["443".into()],
                    action: "discard".into(),
                    ..Default::default()
                },
            ],
        }],
        &[],
    );
    let r = evaluate_filter(
        &state,
        "inet:lt",
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        PROTO_TCP,
        40000,
        443,
        0,
        TermMatchExtra::default(),
    );
    assert_eq!(r.action, FilterAction::Discard);
    let lm = r
        .log_match
        .expect("fall-through log term must emit a log_match");
    // Identity is the fall-through logging term (term 0), but the action must be
    // the terminal verdict, NOT the Accept placeholder.
    assert_eq!(lm.term_id, 0);
    assert_eq!(
        lm.action,
        FilterAction::Discard,
        "RT_FLOW log action must follow the terminal verdict (#2616)"
    );
}

#[test]
fn fallthrough_log_action_follows_terminal_reject() {
    let state = make_filter_state(
        &[FirewallFilterSnapshot {
            name: "lr".into(),
            family: "inet6".into(),
            terms: vec![
                FirewallTermSnapshot {
                    name: "log-first".into(),
                    protocols: vec!["tcp".into()],
                    destination_ports: vec!["443".into()],
                    action: String::new(),
                    next_term: true,
                    log: true,
                    syslog: false,
                    reject_message_type: String::new(),
                    ..Default::default()
                },
                FirewallTermSnapshot {
                    name: "reject-web".into(),
                    protocols: vec!["tcp".into()],
                    destination_ports: vec!["443".into()],
                    action: "reject".into(),
                    ..Default::default()
                },
            ],
        }],
        &[],
    );
    let r = evaluate_filter(
        &state,
        "inet6:lr",
        IpAddr::V6("2001:db8::1".parse().unwrap()),
        IpAddr::V6("2001:db8::2".parse().unwrap()),
        PROTO_TCP,
        40000,
        443,
        0,
        TermMatchExtra::default(),
    );
    assert_eq!(r.action, FilterAction::Reject(RejectMessage::ADMIN_PROHIBITED));
    let lm = r
        .log_match
        .expect("fall-through log term must emit a log_match");
    assert_eq!(
        lm.action,
        FilterAction::Reject(RejectMessage::ADMIN_PROHIBITED),
        "RT_FLOW log action must follow the terminal reject (#2616)"
    );
}

#[test]
fn fallthrough_log_action_terminating_log_term_unchanged() {
    // Regression guard: a terminating logging term still reports its OWN action
    // (here Accept) — normalization is a no-op because term.action == acc.action.
    let state = make_filter_state(
        &[FirewallFilterSnapshot {
            name: "la".into(),
            family: "inet".into(),
            terms: vec![FirewallTermSnapshot {
                name: "log-accept".into(),
                protocols: vec!["tcp".into()],
                destination_ports: vec!["443".into()],
                action: "accept".into(),
                log: true,
                syslog: false,
                reject_message_type: String::new(),
                ..Default::default()
            }],
        }],
        &[],
    );
    let r = evaluate_filter(
        &state,
        "inet:la",
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        PROTO_TCP,
        40000,
        443,
        0,
        TermMatchExtra::default(),
    );
    assert_eq!(r.action, FilterAction::Accept);
    assert_eq!(r.log_match.expect("log_match").action, FilterAction::Accept);
}

// ---------------------------------------------------------------------------
// #2618: the log-only helper (evaluate_interface_filter_log_match) must share
// the full evaluator's latest-matched-logging-term semantics. With two matched
// `then { log; next term; }` terms, both the full evaluator and the log-only
// helper must point at the SECOND term, and (with a terminal discard) both must
// report the terminal action. Pre-fix the log-only helper returned the FIRST
// term and the placeholder Accept.
// ---------------------------------------------------------------------------

#[test]
fn log_only_helper_matches_full_evaluator_latest_term_and_action() {
    let state = make_filter_state_with_interfaces(
        &[FirewallFilterSnapshot {
            name: "two-log".into(),
            family: "inet".into(),
            terms: vec![
                FirewallTermSnapshot {
                    name: "log-a".into(),
                    protocols: vec!["tcp".into()],
                    destination_ports: vec!["443".into()],
                    action: String::new(),
                    next_term: true,
                    log: true,
                    syslog: false,
                    reject_message_type: String::new(),
                    ..Default::default()
                },
                FirewallTermSnapshot {
                    name: "log-b".into(),
                    protocols: vec!["tcp".into()],
                    destination_ports: vec!["443".into()],
                    action: String::new(),
                    next_term: true,
                    log: true,
                    syslog: false,
                    reject_message_type: String::new(),
                    ..Default::default()
                },
                FirewallTermSnapshot {
                    name: "deny-web".into(),
                    protocols: vec!["tcp".into()],
                    destination_ports: vec!["443".into()],
                    action: "discard".into(),
                    ..Default::default()
                },
            ],
        }],
        &[crate::InterfaceSnapshot {
            ifindex: 7,
            filter_input_v4: "two-log".into(),
            ..Default::default()
        }],
    );
    let src = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 10));
    let dst = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20));

    let full = evaluate_interface_filter_counted(
        &state,
        7,
        false,
        src,
        dst,
        PROTO_TCP,
        49152,
        443,
        0,
        TermMatchExtra::default(),
        0,
    );
    let full_lm = full.log_match.expect("full evaluator log_match");

    let log_only = evaluate_interface_filter_log_match(
        &state,
        7,
        false,
        src,
        dst,
        PROTO_TCP,
        49152,
        443,
        0,
        TermMatchExtra::default(),
        true,
    )
    .expect("log-only helper log_match");

    // Latest-matched: term 1 (log-b), not the first matched logging term.
    assert_eq!(full_lm.term_id, 1);
    assert_eq!(log_only.term_id, full_lm.term_id);
    assert_eq!(log_only.filter_id, full_lm.filter_id);
    // Both report the terminal verdict (discard), not the placeholder Accept.
    assert_eq!(full.action, FilterAction::Discard);
    assert_eq!(full_lm.action, FilterAction::Discard);
    assert_eq!(log_only.action, FilterAction::Discard);
}

// ---------------------------------------------------------------------------
// #2619: the PBR (routing-instance) evaluator must preserve a fall-through
// `then { log; next term; }` term's log metadata seen BEFORE the
// routing-instance term. Pre-fix FilterRoutingInstanceResult carried only the
// routing-instance term's log; the earlier fall-through log was dropped.
// The accumulated log_match.action is normalized to the routing-instance term's
// own action (the verdict the packet receives on the PBR path, #2616).
// ---------------------------------------------------------------------------

#[test]
fn pbr_evaluator_preserves_fallthrough_log_before_routing_instance() {
    let state = make_filter_state_with_interfaces(
        &[FirewallFilterSnapshot {
            name: "pbr-log".into(),
            family: "inet".into(),
            terms: vec![
                FirewallTermSnapshot {
                    name: "audit-pbr".into(),
                    protocols: vec!["tcp".into()],
                    destination_ports: vec!["5201".into()],
                    action: String::new(),
                    next_term: true,
                    log: true,
                    syslog: false,
                    reject_message_type: String::new(),
                    ..Default::default()
                },
                FirewallTermSnapshot {
                    name: "steer-blue".into(),
                    protocols: vec!["tcp".into()],
                    destination_ports: vec!["5201".into()],
                    action: "accept".into(),
                    routing_instance: "blue".into(),
                    ..Default::default()
                },
            ],
        }],
        &[crate::InterfaceSnapshot {
            ifindex: 12,
            filter_input_v4: "pbr-log".into(),
            ..Default::default()
        }],
    );
    let result = evaluate_interface_filter_routing_instance_event_counted(
        &state,
        12,
        false,
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        PROTO_TCP,
        40000,
        5201,
        0,
        TermMatchExtra::default(),
        1400,
    )
    .expect("routing-instance override");
    assert_eq!(result.routing_instance, "blue");
    let lm = result
        .log_match
        .expect("fall-through log before routing-instance must be preserved (#2619)");
    // Identity is the fall-through audit term (term 0).
    assert_eq!(lm.term_id, 0);
    // Action follows the routing-instance term's verdict (Accept here).
    assert_eq!(lm.action, FilterAction::Accept);
}

#[test]
fn pbr_evaluator_log_on_routing_instance_term_itself() {
    // The routing-instance term carries `then log` directly (no fall-through
    // term ahead). log_match must point at it (latest matched wins).
    let state = make_filter_state_with_interfaces(
        &[FirewallFilterSnapshot {
            name: "pbr-self-log".into(),
            family: "inet".into(),
            terms: vec![FirewallTermSnapshot {
                name: "steer-and-log".into(),
                protocols: vec!["tcp".into()],
                destination_ports: vec!["5201".into()],
                action: "accept".into(),
                log: true,
                syslog: false,
                reject_message_type: String::new(),
                routing_instance: "green".into(),
                ..Default::default()
            }],
        }],
        &[crate::InterfaceSnapshot {
            ifindex: 13,
            filter_input_v4: "pbr-self-log".into(),
            ..Default::default()
        }],
    );
    let result = evaluate_interface_filter_routing_instance_event_counted(
        &state,
        13,
        false,
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        PROTO_TCP,
        40000,
        5201,
        0,
        TermMatchExtra::default(),
        1400,
    )
    .expect("routing-instance override");
    assert_eq!(result.routing_instance, "green");
    let lm = result.log_match.expect("routing-instance term log");
    assert_eq!(lm.term_id, 0);
    assert_eq!(lm.action, FilterAction::Accept);
}

// ---------------------------------------------------------------------------
// #2620: counting on the PBR session-miss path must be EXACTLY ONCE per matched
// `then count` term, on every exit. The miss path runs TWO evaluators over the
// same interface filter — the non-routing precheck
// (`evaluate_interface_filter_non_routing_counted`) for the verdict, then, ONLY
// when the precheck returns Accept, the routing-instance evaluator
// (`evaluate_interface_filter_routing_instance_event_counted`, via
// `ingress_route_table_override`). On a non-Accept verdict the poll path
// `continue`s and the routing evaluator never runs.
//
// The precheck's counter ownership is selected by `NonRoutingCountPolicy`, which
// `evaluate_non_pbr_input_filter` derives as
// `OnlyTerminalNonAccept` when (routing_eval_follows && affects_route_lookup)
// else `Always`. The helper below mirrors that derivation so the tests exercise
// the SAME discriminator the dataplane uses.
//
// Cases covered:
//   1. Accept + routing-instance term  → counted once (routing eval).
//   2. terminal discard BEFORE the routing-instance term → counted once
//      (precheck; the routing eval never runs — finding 1 regression guard).
//   3. plain non-PBR filter            → counted once (precheck, Always).
//   4. session-HIT DSCP/L4 + PBR-affecting → counted once per packet (Always),
//      the routing evaluator is never invoked on that path (finding 3).
// ---------------------------------------------------------------------------

/// Mirror of `evaluate_non_pbr_input_filter`'s #2620 policy derivation so the
/// tests pick the precheck count policy from the same discriminator as the
/// dataplane.
fn miss_path_count_policy(
    state: &FilterState,
    ifindex: i32,
    is_v6: bool,
    routing_eval_follows: bool,
) -> NonRoutingCountPolicy {
    if routing_eval_follows && interface_filter_affects_route_lookup(state, ifindex, is_v6) {
        NonRoutingCountPolicy::OnlyTerminalNonAccept
    } else {
        NonRoutingCountPolicy::Always
    }
}

#[test]
fn pbr_miss_path_counts_fallthrough_term_exactly_once() {
    let state = make_filter_state_with_interfaces(
        &[FirewallFilterSnapshot {
            name: "pbr-count".into(),
            family: "inet".into(),
            terms: vec![
                FirewallTermSnapshot {
                    name: "count-before-pbr".into(),
                    protocols: vec!["tcp".into()],
                    destination_ports: vec!["5201".into()],
                    action: String::new(),
                    next_term: true,
                    count: "pre-pbr".into(),
                    ..Default::default()
                },
                FirewallTermSnapshot {
                    name: "steer-blue".into(),
                    protocols: vec!["tcp".into()],
                    destination_ports: vec!["5201".into()],
                    action: "accept".into(),
                    routing_instance: "blue".into(),
                    ..Default::default()
                },
            ],
        }],
        &[crate::InterfaceSnapshot {
            ifindex: 14,
            filter_input_v4: "pbr-count".into(),
            ..Default::default()
        }],
    );

    let src = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let dst = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

    // Miss path, Accept verdict → routing evaluator follows. Policy resolves to
    // OnlyTerminalNonAccept: the precheck must NOT count on the Accept exit.
    let policy = miss_path_count_policy(&state, 14, false, true);
    assert_eq!(policy, NonRoutingCountPolicy::OnlyTerminalNonAccept);

    // Step 1 — non-routing precheck (verdict). The fall-through term matches but
    // the routing-instance term defers → default Accept; nothing counted here.
    let precheck = evaluate_interface_filter_non_routing_counted(
        &state,
        14,
        false,
        src,
        dst,
        PROTO_TCP,
        40000,
        5201,
        0,
        TermMatchExtra::default(),
        1400,
        policy,
    );
    assert_eq!(precheck.action, FilterAction::Accept);
    // #5444: FilterResult.routing_instance is Option<Arc<str>>; None on the
    // non-routing precheck (the PBR override rides FilterRoutingInstanceResult).
    assert!(precheck.routing_instance.is_none());

    // Step 2 — routing-instance evaluator (route override). It owns the count.
    let routing = evaluate_interface_filter_routing_instance_event_counted(
        &state,
        14,
        false,
        src,
        dst,
        PROTO_TCP,
        40000,
        5201,
        0,
        TermMatchExtra::default(),
        1400,
    )
    .expect("routing-instance override");
    assert_eq!(routing.routing_instance, "blue");

    // Counted EXACTLY ONCE (the routing evaluator), not twice. Pre-#2620 (the
    // precheck also counts) this reads 2.
    let filter = state.iface_filter_v4_fast.get(&14).expect("input filter");
    assert_eq!(
        filter.terms[0].counter.packets.load(Ordering::Relaxed),
        1,
        "pre-PBR fall-through count must increment exactly once on the Accept miss path (#2620)"
    );
    assert_eq!(
        filter.terms[0].counter.bytes.load(Ordering::Relaxed),
        1400,
        "byte counter must reflect a single packet"
    );
}

// #2620 finding 1: a terminal `discard`/`reject` term BEFORE the
// routing-instance term ends evaluation at the precheck; the poll path
// `continue`s and the routing evaluator NEVER runs. The earlier fall-through
// `then count` term must be counted by the precheck (exactly once), not dropped
// to zero. The coarse boolean gate (precheck count=false whenever the filter has
// any routing-instance term) under-counted this exit. Counter-factual guard: a
// gate that suppresses the count on this exit reads 0.
#[test]
fn pbr_miss_path_terminal_discard_before_routing_instance_counts_once() {
    let state = make_filter_state_with_interfaces(
        &[FirewallFilterSnapshot {
            name: "pbr-discard".into(),
            family: "inet".into(),
            terms: vec![
                FirewallTermSnapshot {
                    name: "count-then-fall".into(),
                    // dport 5201 — matches the test packet; falls through.
                    protocols: vec!["tcp".into()],
                    destination_ports: vec!["5201".into()],
                    action: String::new(),
                    next_term: true,
                    count: "pre-discard".into(),
                    ..Default::default()
                },
                FirewallTermSnapshot {
                    // Terminal discard that matches the SAME packet, BEFORE the
                    // routing-instance term below.
                    name: "deny".into(),
                    protocols: vec!["tcp".into()],
                    destination_ports: vec!["5201".into()],
                    action: "discard".into(),
                    ..Default::default()
                },
                FirewallTermSnapshot {
                    // Routing-instance term — makes the filter route-lookup-
                    // affecting, but this packet never reaches it.
                    name: "steer-blue".into(),
                    protocols: vec!["udp".into()],
                    destination_ports: vec!["53".into()],
                    action: "accept".into(),
                    routing_instance: "blue".into(),
                    ..Default::default()
                },
            ],
        }],
        &[crate::InterfaceSnapshot {
            ifindex: 15,
            filter_input_v4: "pbr-discard".into(),
            ..Default::default()
        }],
    );

    let src = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let dst = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

    // The filter IS route-lookup-affecting, and the miss path's routing eval
    // would follow on an Accept — so the precheck uses OnlyTerminalNonAccept.
    let policy = miss_path_count_policy(&state, 15, false, true);
    assert_eq!(policy, NonRoutingCountPolicy::OnlyTerminalNonAccept);

    let precheck = evaluate_interface_filter_non_routing_counted(
        &state,
        15,
        false,
        src,
        dst,
        PROTO_TCP,
        40000,
        5201,
        0,
        TermMatchExtra::default(),
        1400,
        policy,
    );
    // Terminal discard → non-Accept verdict. The poll path `continue`s here;
    // ingress_route_table_override is NEVER called for this packet.
    assert_eq!(precheck.action, FilterAction::Discard);

    let filter = state.iface_filter_v4_fast.get(&15).expect("input filter");
    assert_eq!(
        filter.terms[0].counter.packets.load(Ordering::Relaxed),
        1,
        "pre-discard fall-through count must increment once on the terminal-discard exit (#2620 finding 1)"
    );
    assert_eq!(
        filter.terms[0].counter.bytes.load(Ordering::Relaxed),
        1400,
        "byte counter must reflect a single packet"
    );
}

// #2620: a plain non-PBR filter (no routing-instance term anywhere) — the
// routing evaluator returns early at the affects_route_lookup guard and counts
// nothing, so the precheck is the SOLE counter and the policy resolves to
// Always. A matched fall-through `then count` term is counted once.
#[test]
fn non_pbr_miss_path_counts_fallthrough_term_once() {
    let state = make_filter_state_with_interfaces(
        &[FirewallFilterSnapshot {
            name: "plain".into(),
            family: "inet".into(),
            terms: vec![
                FirewallTermSnapshot {
                    name: "count-then-fall".into(),
                    protocols: vec!["tcp".into()],
                    destination_ports: vec!["5201".into()],
                    action: String::new(),
                    next_term: true,
                    count: "hits".into(),
                    ..Default::default()
                },
                FirewallTermSnapshot {
                    name: "accept".into(),
                    protocols: vec!["tcp".into()],
                    destination_ports: vec!["5201".into()],
                    action: "accept".into(),
                    ..Default::default()
                },
            ],
        }],
        &[crate::InterfaceSnapshot {
            ifindex: 16,
            filter_input_v4: "plain".into(),
            ..Default::default()
        }],
    );

    let src = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let dst = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

    // No routing-instance term → not route-lookup-affecting → Always.
    assert!(!interface_filter_affects_route_lookup(&state, 16, false));
    let policy = miss_path_count_policy(&state, 16, false, true);
    assert_eq!(policy, NonRoutingCountPolicy::Always);

    let precheck = evaluate_interface_filter_non_routing_counted(
        &state,
        16,
        false,
        src,
        dst,
        PROTO_TCP,
        40000,
        5201,
        0,
        TermMatchExtra::default(),
        1400,
        policy,
    );
    assert_eq!(precheck.action, FilterAction::Accept);

    let filter = state.iface_filter_v4_fast.get(&16).expect("input filter");
    assert_eq!(
        filter.terms[0].counter.packets.load(Ordering::Relaxed),
        1,
        "plain non-PBR fall-through count must increment once (precheck Always, #2620)"
    );
}

// #2620 finding 3: on the session-HIT DSCP/L4 re-eval path the routing
// evaluator is NEVER invoked (routing_eval_follows == false), so the precheck is
// the SOLE counter even when the filter is route-lookup-affecting. The policy
// resolves to Always so a matched fall-through `then count` term still counts
// per packet (pre-#2620 behavior), not zero.
#[test]
fn pbr_session_hit_path_counts_fallthrough_term_per_packet() {
    let state = make_filter_state_with_interfaces(
        &[FirewallFilterSnapshot {
            name: "pbr-hit".into(),
            family: "inet".into(),
            terms: vec![
                FirewallTermSnapshot {
                    name: "count-then-fall".into(),
                    protocols: vec!["tcp".into()],
                    destination_ports: vec!["5201".into()],
                    action: String::new(),
                    next_term: true,
                    count: "hit-count".into(),
                    ..Default::default()
                },
                FirewallTermSnapshot {
                    name: "steer-blue".into(),
                    protocols: vec!["tcp".into()],
                    destination_ports: vec!["5201".into()],
                    action: "accept".into(),
                    routing_instance: "blue".into(),
                    ..Default::default()
                },
            ],
        }],
        &[crate::InterfaceSnapshot {
            ifindex: 17,
            filter_input_v4: "pbr-hit".into(),
            ..Default::default()
        }],
    );

    let src = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let dst = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

    // Route-lookup-affecting, BUT the session-hit path does not run the routing
    // evaluator → routing_eval_follows = false → Always (sole counter).
    assert!(interface_filter_affects_route_lookup(&state, 17, false));
    let policy = miss_path_count_policy(&state, 17, false, false);
    assert_eq!(policy, NonRoutingCountPolicy::Always);

    // Two session-hit packets → two counts (per-packet, pre-#2620 behavior). A
    // gate that suppresses the hit-path count for a PBR-affecting filter reads 0.
    for _ in 0..2 {
        let eval = evaluate_interface_filter_non_routing_counted(
            &state,
            17,
            false,
            src,
            dst,
            PROTO_TCP,
            40000,
            5201,
            0,
            TermMatchExtra::default(),
            1400,
            policy,
        );
        assert_eq!(eval.action, FilterAction::Accept);
    }

    let filter = state.iface_filter_v4_fast.get(&17).expect("input filter");
    assert_eq!(
        filter.terms[0].counter.packets.load(Ordering::Relaxed),
        2,
        "session-hit re-eval counts the fall-through term per packet (#2620 finding 3)"
    );
}

// ===================================================================
// #3077 flexible-match-range byte-offset match
// ===================================================================

// Build a one-term filter carrying a flexible-match-range constraint, then a
// trailing accept-all term so a non-match is observably Accept.
fn flex_filter(family: &str, proto: &str, flex: FlexMatchSnapshot) -> Vec<FirewallFilterSnapshot> {
    vec![FirewallFilterSnapshot {
        name: "fx".into(),
        family: family.into(),
        terms: vec![
            FirewallTermSnapshot {
                name: "match".into(),
                protocols: if proto.is_empty() {
                    vec![]
                } else {
                    vec![proto.into()]
                },
                action: "discard".into(),
                flex_match: Some(flex),
                ..Default::default()
            },
            FirewallTermSnapshot {
                name: "rest".into(),
                action: "accept".into(),
                ..Default::default()
            },
        ],
    }]
}

// TermMatchExtra carrying an L3-header slice for the flex byte-offset read.
fn extra_flex(l3: &[u8]) -> TermMatchExtra<'_> {
    TermMatchExtra {
        l4_present: true,
        flex_l3: Some(l3),
        ..Default::default()
    }
}

#[test]
fn flex_match_matches_when_masked_bytes_equal_value() {
    // Match 2 bytes at L3 offset 0 (the IPv4 version/IHL + DSCP bytes), mask
    // 0xFFFF, expect 0x4500 (IPv4, IHL 5, DSCP 0). A packet whose first two L3
    // bytes are 0x45,0x00 matches and is discarded.
    let state = make_filter_state(
        &flex_filter(
            "inet",
            "tcp",
            FlexMatchSnapshot {
                offset: 0,
                length: 2,
                value: 0x4500,
                mask: 0xFFFF,
                match_start: String::new(),
            },
        ),
        &[],
    );
    let l3 = [0x45u8, 0x00, 0x00, 0x28, 0xde, 0xad];
    let hit = evaluate_filter(
        &state,
        "inet:fx",
        v4(10, 0, 0, 1),
        v4(10, 0, 0, 2),
        PROTO_TCP,
        1000,
        80,
        0,
        extra_flex(&l3),
    );
    assert_eq!(
        hit.action,
        FilterAction::Discard,
        "L3 bytes 0x4500 at offset 0 must match flex value 0x4500"
    );
}

#[test]
fn flex_match_does_not_match_when_bytes_differ() {
    // Same term, but the packet's first two L3 bytes are 0x46,0x00 — the masked
    // value 0x4600 != 0x4500, so the discard term must NOT match (the trailing
    // accept term wins). This is the #3077 fail-OPEN regression guard: before
    // the wire fix the flex constraint was dropped and EVERY packet matched the
    // discard term (matched too broadly).
    let state = make_filter_state(
        &flex_filter(
            "inet",
            "tcp",
            FlexMatchSnapshot {
                offset: 0,
                length: 2,
                value: 0x4500,
                mask: 0xFFFF,
                match_start: String::new(),
            },
        ),
        &[],
    );
    let l3 = [0x46u8, 0x00, 0x00, 0x28, 0xde, 0xad];
    let miss = evaluate_filter(
        &state,
        "inet:fx",
        v4(10, 0, 0, 1),
        v4(10, 0, 0, 2),
        PROTO_TCP,
        1000,
        80,
        0,
        extra_flex(&l3),
    );
    assert_eq!(
        miss.action,
        FilterAction::Accept,
        "L3 bytes 0x4600 must NOT match flex value 0x4500 (fail-open guard)"
    );
}

#[test]
fn flex_match_non_byte_aligned_12bit_field() {
    // #3203: a 12-bit field lowers (Go control plane) to length=2 (ceil(12/8))
    // and the default mask 0x0FFF (low 12 bits). The matcher reads 2 bytes
    // big-endian, ANDs the mask, and compares. A packet whose 12-bit field
    // equals 0x0ABC must match regardless of the upper 4 bits; one whose field
    // differs must NOT. Before #3203 the Go side truncated length to 1 byte (so
    // this read only the high byte) AND defaulted the mask to 0xFFFFFFFF (which
    // a 2-byte read could never satisfy) — both made a 12-bit match impossible
    // (silent fail-closed). These lowered values are what the Go compiler now
    // emits; this test confirms they select the intended field.
    let state = make_filter_state(
        &flex_filter(
            "inet",
            "tcp",
            FlexMatchSnapshot {
                offset: 0,
                length: 2,
                value: 0x0ABC,
                mask: 0x0FFF,
                match_start: String::new(),
            },
        ),
        &[],
    );
    // High nibble 0x1 is outside the 12-bit mask: 0x1ABC & 0x0FFF == 0x0ABC.
    let l3_hit = [0x1Au8, 0xBC, 0x00, 0x00];
    let hit = evaluate_filter(
        &state,
        "inet:fx",
        v4(10, 0, 0, 1),
        v4(10, 0, 0, 2),
        PROTO_TCP,
        1000,
        80,
        0,
        extra_flex(&l3_hit),
    );
    assert_eq!(
        hit.action,
        FilterAction::Discard,
        "12-bit field 0x0ABC (bytes 0x1A,0xBC masked 0x0FFF) must match"
    );
    // Field 0x0ABD != 0x0ABC -> the discard term must NOT match.
    let l3_miss = [0x1Au8, 0xBD, 0x00, 0x00];
    let miss = evaluate_filter(
        &state,
        "inet:fx",
        v4(10, 0, 0, 1),
        v4(10, 0, 0, 2),
        PROTO_TCP,
        1000,
        80,
        0,
        extra_flex(&l3_miss),
    );
    assert_eq!(
        miss.action,
        FilterAction::Accept,
        "12-bit field 0x0ABD must NOT match flex value 0x0ABC"
    );
}

#[test]
fn flex_match_respects_mask() {
    // Mask 0x00FF over 2 bytes at offset 2: only the low byte matters. Value
    // 0x0028 matches any packet whose 4th L3 byte is 0x28 regardless of byte 3.
    let state = make_filter_state(
        &flex_filter(
            "inet",
            "",
            FlexMatchSnapshot {
                offset: 2,
                length: 2,
                value: 0x0028,
                mask: 0x00FF,
                match_start: String::new(),
            },
        ),
        &[],
    );
    let l3 = [0x45u8, 0x00, 0xff, 0x28];
    let hit = evaluate_filter(
        &state,
        "inet:fx",
        v4(10, 0, 0, 1),
        v4(10, 0, 0, 2),
        PROTO_TCP,
        1000,
        80,
        0,
        extra_flex(&l3),
    );
    assert_eq!(
        hit.action,
        FilterAction::Discard,
        "masked low byte 0x28 must match value 0x0028 with mask 0x00FF"
    );
    let l3_miss = [0x45u8, 0x00, 0xff, 0x29];
    let miss = evaluate_filter(
        &state,
        "inet:fx",
        v4(10, 0, 0, 1),
        v4(10, 0, 0, 2),
        PROTO_TCP,
        1000,
        80,
        0,
        extra_flex(&l3_miss),
    );
    assert_eq!(
        miss.action,
        FilterAction::Accept,
        "low byte 0x29 must not match"
    );
}

#[test]
fn flex_match_fails_closed_on_short_packet() {
    // The window (offset 4, length 4 -> bytes [4,8)) lies beyond a 6-byte L3
    // slice. The flex condition must be FALSE (term does not match) and must NOT
    // panic / read out of bounds. Fail-closed: the accept term wins.
    let state = make_filter_state(
        &flex_filter(
            "inet",
            "tcp",
            FlexMatchSnapshot {
                offset: 4,
                length: 4,
                value: 0,
                mask: 0,
                match_start: String::new(),
            },
        ),
        &[],
    );
    let l3 = [0x45u8, 0x00, 0x00, 0x28, 0xde, 0xad]; // only 6 bytes
    let res = evaluate_filter(
        &state,
        "inet:fx",
        v4(10, 0, 0, 1),
        v4(10, 0, 0, 2),
        PROTO_TCP,
        1000,
        80,
        0,
        extra_flex(&l3),
    );
    assert_eq!(
        res.action,
        FilterAction::Accept,
        "a packet too short for the flex window must fail closed (no match, no panic)"
    );
}

#[test]
fn flex_match_fails_closed_without_l3_slice() {
    // No L3 bytes available on this path (flex_l3 == None) — the flex term must
    // fail closed rather than silently passing (the pre-#3077 fail-open).
    let state = make_filter_state(
        &flex_filter(
            "inet",
            "tcp",
            FlexMatchSnapshot {
                offset: 0,
                length: 2,
                value: 0x4500,
                mask: 0xFFFF,
                match_start: String::new(),
            },
        ),
        &[],
    );
    let res = evaluate_filter(
        &state,
        "inet:fx",
        v4(10, 0, 0, 1),
        v4(10, 0, 0, 2),
        PROTO_TCP,
        1000,
        80,
        0,
        TermMatchExtra {
            l4_present: true,
            flex_l3: None,
            ..Default::default()
        },
    );
    assert_eq!(
        res.action,
        FilterAction::Accept,
        "no L3 slice => flex term fails closed (no match)"
    );
}

#[test]
fn term_without_flex_is_unaffected() {
    // A term carrying NO flex constraint behaves exactly as before: it matches
    // on its other criteria regardless of flex_l3. Here a protocol-only discard
    // term matches a TCP packet even though flex_l3 is None.
    let mut filters = flex_filter(
        "inet",
        "tcp",
        FlexMatchSnapshot {
            offset: 0,
            length: 2,
            value: 0x4500,
            mask: 0xFFFF,
            match_start: String::new(),
        },
    );
    // Strip the flex constraint from the discard term.
    filters[0].terms[0].flex_match = None;
    let state = make_filter_state(&filters, &[]);
    let res = evaluate_filter(
        &state,
        "inet:fx",
        v4(10, 0, 0, 1),
        v4(10, 0, 0, 2),
        PROTO_TCP,
        1000,
        80,
        0,
        TermMatchExtra {
            l4_present: true,
            flex_l3: None,
            ..Default::default()
        },
    );
    assert_eq!(
        res.action,
        FilterAction::Discard,
        "a term without flex-match matches on its other criteria, unaffected by flex_l3"
    );
}

#[test]
fn flex_match_marks_filter_cache_sensitive() {
    // A flex-constrained term reads raw packet bytes (not the 5-tuple), so the
    // filter MUST be flagged cache-sensitive so the flow-cache declines it
    // (#1431 / #3077). Mirrors the tcp-flags / icmp per-packet behavior.
    let state = make_filter_state(
        &flex_filter(
            "inet",
            "tcp",
            FlexMatchSnapshot {
                offset: 0,
                length: 2,
                value: 0x4500,
                mask: 0xFFFF,
                match_start: String::new(),
            },
        ),
        &[],
    );
    let filter = state.filters.get("inet:fx").expect("filter present");
    assert!(
        filter.has_per_packet_l4_match_terms,
        "a flex-match term must mark the filter cache-sensitive"
    );
}

// === #3232: flexible-match-range match-start layer-4 ===
//
// A `match-start layer-4` flex term must read its byte window relative to the
// L4/transport header (TermMatchExtra::flex_l4), NOT the L3 header. Before #3232
// the wire builder + Rust matcher ignored match-start and always read from the
// L3 base, so a layer-4 config silently matched the wrong bytes.

// TermMatchExtra carrying BOTH an L3 slice and a distinct L4 slice, so a test
// can prove the matcher reads from the correct base.
fn extra_flex_l3_l4<'a>(l3: &'a [u8], l4: &'a [u8]) -> TermMatchExtra<'a> {
    TermMatchExtra {
        l4_present: true,
        flex_l3: Some(l3),
        flex_l4: Some(l4),
        ..Default::default()
    }
}

#[test]
fn flex_match_layer4_matches_at_l4_offset() {
    // offset 0, length 2, value 0xABCD over the L4 header. The L3 bytes at the
    // same offset are 0x4500 (a real IPv4 version/IHL+DSCP), DIFFERENT from the
    // L4 bytes 0xABCD — so a match proves the read came from the L4 base.
    //
    // FAIL-ON-REVERT: make `flex_matches` ignore `flex_match_start` and always
    // read `flex_l3` (the pre-#3232 behavior); the L3 bytes 0x4500 != 0xABCD, so
    // the discard term no longer matches and the action flips to Accept -> RED.
    let state = make_filter_state(
        &flex_filter(
            "inet",
            "tcp",
            FlexMatchSnapshot {
                offset: 0,
                length: 2,
                value: 0xABCD,
                mask: 0xFFFF,
                match_start: "layer-4".into(),
            },
        ),
        &[],
    );
    let l3 = [0x45u8, 0x00, 0x00, 0x28, 0xde, 0xad];
    let l4 = [0xABu8, 0xCD, 0x00, 0x50]; // e.g. src port 0xABCD
    let hit = evaluate_filter(
        &state,
        "inet:fx",
        v4(10, 0, 0, 1),
        v4(10, 0, 0, 2),
        PROTO_TCP,
        1000,
        80,
        0,
        extra_flex_l3_l4(&l3, &l4),
    );
    assert_eq!(
        hit.action,
        FilterAction::Discard,
        "match-start layer-4 must read the L4 bytes 0xABCD, not the L3 bytes 0x4500"
    );
}

#[test]
fn flex_match_layer3_default_still_reads_l3_when_l4_differs() {
    // The layer-3 control for the test above: same packet, but match-start
    // layer-3 (default). The matcher must read the L3 bytes 0x4500 and IGNORE
    // the L4 bytes 0xABCD. Proves layer-3 is byte-identical to pre-#3232.
    let state = make_filter_state(
        &flex_filter(
            "inet",
            "tcp",
            FlexMatchSnapshot {
                offset: 0,
                length: 2,
                value: 0x4500,
                mask: 0xFFFF,
                match_start: String::new(), // layer-3 default
            },
        ),
        &[],
    );
    let l3 = [0x45u8, 0x00, 0x00, 0x28, 0xde, 0xad];
    let l4 = [0xABu8, 0xCD, 0x00, 0x50];
    let hit = evaluate_filter(
        &state,
        "inet:fx",
        v4(10, 0, 0, 1),
        v4(10, 0, 0, 2),
        PROTO_TCP,
        1000,
        80,
        0,
        extra_flex_l3_l4(&l3, &l4),
    );
    assert_eq!(
        hit.action,
        FilterAction::Discard,
        "match-start layer-3 (default) must read the L3 bytes 0x4500"
    );
}

#[test]
fn flex_match_layer4_fails_closed_without_l4_slice() {
    // match-start layer-4 but flex_l4 == None (a non-first fragment, or the
    // meta-only / deferred path). The term must FAIL CLOSED (no match) rather
    // than fall back to the L3 base. The L3 slice is present and would match if
    // the matcher wrongly read it.
    let state = make_filter_state(
        &flex_filter(
            "inet",
            "tcp",
            FlexMatchSnapshot {
                offset: 0,
                length: 2,
                value: 0x4500, // would match the L3 bytes if read from L3
                mask: 0xFFFF,
                match_start: "layer-4".into(),
            },
        ),
        &[],
    );
    let l3 = [0x45u8, 0x00, 0x00, 0x28, 0xde, 0xad];
    let res = evaluate_filter(
        &state,
        "inet:fx",
        v4(10, 0, 0, 1),
        v4(10, 0, 0, 2),
        PROTO_TCP,
        1000,
        80,
        0,
        TermMatchExtra {
            l4_present: true,
            flex_l3: Some(&l3),
            flex_l4: None,
            ..Default::default()
        },
    );
    assert_eq!(
        res.action,
        FilterAction::Accept,
        "match-start layer-4 with no L4 slice must fail closed, not read the L3 base"
    );
}

#[test]
fn flex_match_unsupported_start_fails_closed() {
    // Defense-in-depth for the tolerant peer-sync path: a match-start the Go
    // commit gate rejects (e.g. "payload") could still arrive on the wire. It
    // lowers to FlexMatchStart::Unsupported and must FAIL CLOSED — never be
    // silently evaluated at the L3 base (the #3232 bug). The L3/L4 bytes both
    // match the value, so only the Unsupported gate can produce a non-match.
    let state = make_filter_state(
        &flex_filter(
            "inet",
            "tcp",
            FlexMatchSnapshot {
                offset: 0,
                length: 2,
                value: 0x4500,
                mask: 0xFFFF,
                match_start: "payload".into(),
            },
        ),
        &[],
    );
    let l3 = [0x45u8, 0x00, 0x00, 0x28, 0xde, 0xad];
    let l4 = [0x45u8, 0x00, 0x00, 0x50];
    let res = evaluate_filter(
        &state,
        "inet:fx",
        v4(10, 0, 0, 1),
        v4(10, 0, 0, 2),
        PROTO_TCP,
        1000,
        80,
        0,
        extra_flex_l3_l4(&l3, &l4),
    );
    assert_eq!(
        res.action,
        FilterAction::Accept,
        "an unsupported match-start must fail closed, not evaluate at the L3 base"
    );
}

// === #3205 (agy-070 #08): port-except must FAIL CLOSED on an unresolved port ===
//
// A `destination-port-except <name>` whose name the dataplane cannot parse to a
// port range (e.g. an unresolved symbolic name that slipped past the Go commit
// gate on a tolerant load) leaves the port set constrained-but-empty
// (PortMatcher::Any). The except path must NOT invert that empty set into
// "match ALL ports" — that was the fail-OPEN hole where an `accept` term
// accepted every port, including the one it was meant to exclude.
//
// FAIL-ON-REVERT: restore `port_match`'s `return except` (the constrained+Any
// branch returning match-all for except) and the assertion below flips to
// Accept -> RED.
#[test]
fn destination_port_except_unresolved_fails_closed_3205() {
    let state = make_filter_state(
        &[FirewallFilterSnapshot {
            name: "f".into(),
            family: "inet".into(),
            terms: vec![
                FirewallTermSnapshot {
                    name: "accept-except-unresolved".into(),
                    protocols: vec!["tcp".into()],
                    // Unparseable token: non-empty (so the direction is
                    // constrained) but yields ZERO ranges -> PortMatcher::Any.
                    destination_ports_except: vec!["notaport".into()],
                    action: "accept".into(),
                    ..Default::default()
                },
                FirewallTermSnapshot {
                    name: "default-discard".into(),
                    action: "discard".into(),
                    ..Default::default()
                },
            ],
        }],
        &[],
    );
    // A packet on ANY port must NOT be accepted by the broken except term; it
    // must fall through to the terminal discard (fail closed).
    let r = evaluate_filter(
        &state,
        "inet:f",
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        PROTO_TCP,
        54321,
        12345,
        0,
        TermMatchExtra::default(),
    );
    assert_eq!(
        r.action,
        FilterAction::Discard,
        "an unresolved port-except (constrained + zero ranges) must NOT invert \
         to match-ALL — the accept term must match NOTHING and the packet must \
         fall through to the terminal discard (#3205 fail-open)"
    );
}

// === #3205: a RESOLVED named port-except still matches correctly ===
//
// The fail-closed change must not regress the normal path: a port-except whose
// name the dataplane DOES resolve (ssh -> 22) must except exactly that port and
// match every other port.
#[test]
fn destination_port_except_resolved_name_matches_3205() {
    let state = make_filter_state(
        &[FirewallFilterSnapshot {
            name: "f".into(),
            family: "inet".into(),
            terms: vec![FirewallTermSnapshot {
                name: "discard-except-ssh".into(),
                protocols: vec!["tcp".into()],
                destination_ports_except: vec!["ssh".into()], // resolves to 22
                action: "discard".into(),
                ..Default::default()
            }],
        }],
        &[],
    );
    // Port 22 IS excepted -> term does NOT match -> implicit accept.
    let r = evaluate_filter(
        &state,
        "inet:f",
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        PROTO_TCP,
        54321,
        22,
        0,
        TermMatchExtra::default(),
    );
    assert_eq!(
        r.action,
        FilterAction::Accept,
        "port 22 (ssh) is in the resolved except list, must NOT match the discard term"
    );
    // Port 9999 is NOT excepted -> term matches -> discard.
    let r = evaluate_filter(
        &state,
        "inet:f",
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        PROTO_TCP,
        54321,
        9999,
        0,
        TermMatchExtra::default(),
    );
    assert_eq!(
        r.action,
        FilterAction::Discard,
        "port 9999 is NOT excepted, must match the discard term"
    );
}

// === #3716: a snapshot carrying BOTH a positive and an except port list for
// one direction resolves POSITIVE-WINS at the Rust boundary ===
//
// The Go commit gate `validateFilterPortExceptStrict` (#3297) rejects a term
// that sets both `destination-port` and `destination-port-except`, so a
// committed config never reaches the dataplane in this shape. A hand-built /
// version-drifted / leniently-loaded snapshot still can, and the compiler
// (filter/compiler.rs) resolves it deterministically as POSITIVE-WINS: the
// positive list builds the matcher and the except list is IGNORED (the except
// inversion flag stays false). That is a deliberate NARROWING — the term
// matches only the positive ports, strictly tighter than the operator-authored
// except would have been — never a widening, so it is fail-safe at the Rust
// boundary even without a SnapshotIntegrityError.
//
// FAIL-ON-REVERT: change the compiler's selection to except-wins (make the
// except list win, or set the except flag, when both are present) and the
// port-9999 assertion below flips from Accept to Discard -> RED.
#[test]
fn port_both_positive_and_except_positive_wins_3716() {
    let state = make_filter_state(
        &[FirewallFilterSnapshot {
            name: "f".into(),
            family: "inet".into(),
            terms: vec![FirewallTermSnapshot {
                name: "discard-both".into(),
                protocols: vec!["tcp".into()],
                // Both lists on the same direction (Junos-invalid; the #3297 Go
                // gate rejects it, so only a drifted snapshot lands here).
                // Positive wins: matcher = {22}, the except list is IGNORED.
                destination_ports: vec!["22".into()],
                destination_ports_except: vec!["443".into()],
                action: "discard".into(),
                ..Default::default()
            }],
        }],
        &[],
    );
    // Port 22 IS in the positive set -> the term matches -> discard.
    let r = evaluate_filter(
        &state,
        "inet:f",
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        PROTO_TCP,
        54321,
        22,
        0,
        TermMatchExtra::default(),
    );
    assert_eq!(
        r.action,
        FilterAction::Discard,
        "positive-wins: port 22 is in the positive set, must match the discard term"
    );
    // Port 9999 is NOT in the positive set {22} -> no match -> implicit accept.
    // Under except-wins (match every port != 443) this would DISCARD -> RED.
    let r = evaluate_filter(
        &state,
        "inet:f",
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        PROTO_TCP,
        54321,
        9999,
        0,
        TermMatchExtra::default(),
    );
    assert_eq!(
        r.action,
        FilterAction::Accept,
        "positive-wins: port 9999 is NOT in the positive set {{22}} and the except \
         list is IGNORED, so the term does NOT match — a revert to except-wins \
         (match every port except 443) would DISCARD this (#3716)"
    );
    // The (ignored) except entry 443 is also not in the positive set {22}, so it
    // too falls through to implicit accept — confirming the except list is dropped.
    let r = evaluate_filter(
        &state,
        "inet:f",
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        PROTO_TCP,
        54321,
        443,
        0,
        TermMatchExtra::default(),
    );
    assert_eq!(
        r.action,
        FilterAction::Accept,
        "positive-wins: the except entry 443 is IGNORED; 443 is not in the positive \
         set {{22}} so the term does not match"
    );
}

// ---------------------------------------------------------------------------
// #6540: `then policer <name>` resolving to nothing must fail the snapshot
// closed, not forward unpoliced.
//
// Policer was the odd one out of three sibling reference mechanisms: filters
// raise MissingFilterRef, screen reports ScreenMissingProfileRef, and the
// policer reference had NO backstop at all — `three_color_policers.get(...)`
// yielded None and `apply_term_three_color_policer` no-opped the meter, with no
// Err, no warning and no counter.
//
// Reachability: the Go STRICT commit gate (#2217 Finding A) rejects a dangling
// policer reference, so these snapshots arrive only over the LENIENT path —
// Store.Load at boot or Store.SyncApply on HA peer-sync
// (opts.lenientFirewallRefs, #1960 no-brick), where that gate is downgraded to
// a warning. That is exactly the route these cells drive: a snapshot handed
// straight to the compiler without a strict commit in front of it.
// ---------------------------------------------------------------------------

/// Build a one-term filter whose `then policer` names `policer_name`, bound to
/// an interface input hook so the term actually compiles.
fn policer_ref_fixture_6540(policer_name: &str) -> (Vec<FirewallFilterSnapshot>, Vec<crate::InterfaceSnapshot>) {
    (
        vec![FirewallFilterSnapshot {
            name: "rl".into(),
            family: "inet".into(),
            terms: vec![FirewallTermSnapshot {
                name: "limit".into(),
                action: "accept".into(),
                policer: policer_name.into(),
                ..Default::default()
            }],
        }],
        vec![crate::InterfaceSnapshot {
            name: "ge-0/0/0.0".into(),
            ifindex: 11,
            filter_input_v4: "rl".into(),
            ..Default::default()
        }],
    )
}

/// RED-on-revert: delete `preflight_term_policer_ref` from `parse_term` and an
/// undefined policer reference compiles cleanly again, leaving the rate limit
/// unenforced. Asserts WHICH error fired and every field, so a different
/// fail-closed guard tripping for an unrelated reason cannot pass this cell.
#[test]
fn missing_policer_ref_6540_rejects_rather_than_forwarding_unpoliced() {
    let (filters, ifaces) = policer_ref_fixture_6540("no-such-policer");
    let err = parse_filter_state(&filters, &[], &ifaces, "", "")
        .expect_err("an undefined `then policer` reference must fail the snapshot closed");
    match err {
        SnapshotIntegrityError::MissingPolicerRef {
            family,
            filter,
            term,
            policer,
        } => {
            assert_eq!(family, "inet");
            assert_eq!(filter, "rl");
            assert_eq!(term, "limit");
            assert_eq!(policer, "no-such-policer");
        }
        other => panic!("expected MissingPolicerRef, got {other:?}"),
    }
}

/// Positive control: a reference satisfied by `firewall policer` compiles.
#[test]
fn defined_single_rate_policer_ref_6540_compiles() {
    let (filters, ifaces) = policer_ref_fixture_6540("rl-1m");
    let state = parse_filter_state(
        &filters,
        &[PolicerSnapshot {
            name: "rl-1m".into(),
            bandwidth_bps: 1_000_000,
            burst_bytes: 125_000,
            discard_excess: true,
        }],
        &ifaces,
        "",
        "",
    )
    .expect("a defined single-rate policer reference must compile");
    assert!(
        state.three_color_policer_by_name.contains_key("rl-1m"),
        "the #4514 lowering must place a healthy single-rate policer in the runtime map"
    );
}

/// Positive control: a reference satisfied by `firewall three-color-policer`
/// compiles. The two stanzas are distinct config, and the preflight must accept
/// a name defined in EITHER — reading only one collection would reject half of
/// all valid configs.
#[test]
fn defined_three_color_policer_ref_6540_compiles() {
    let (filters, ifaces) = policer_ref_fixture_6540("tcp-3c");
    parse_filter_state_with_three_color(
        &filters,
        &[],
        &[ThreeColorPolicerSnapshot {
            name: "tcp-3c".into(),
            committed_rate_bytes_per_sec: 125_000,
            committed_burst_bytes: 12_500,
            peak_or_excess_rate_bytes_per_sec: 250_000,
            peak_or_excess_burst_bytes: 25_000,
            ..Default::default()
        }],
        &ifaces,
        "",
        "",
    )
    .expect("a defined three-color policer reference must compile");
}

/// The cell that distinguishes this fix from the naive one.
///
/// #6540 as filed prescribes rejecting when the term's policer is absent from
/// the compiled `three_color_policer_by_name` map. That predicate is WRONG:
/// `lower_single_rate_policer_runtimes` (#4514) deliberately SKIPS a degenerate
/// zero-rate METER-ONLY policer, on the stated grounds that it has no action to
/// enforce. Such a policer IS defined and boots fine today, so keying the
/// rejection on the map would refuse a working config — a brick, not a fix.
///
/// This asserts both halves of that distinction: the policer is genuinely
/// ABSENT from the runtime map, AND the snapshot still compiles. Re-key the
/// preflight to the map and this cell reds.
#[test]
fn degenerate_meter_only_policer_ref_6540_is_defined_and_must_not_be_rejected() {
    let (filters, ifaces) = policer_ref_fixture_6540("meter-only");
    let state = parse_filter_state(
        &filters,
        &[PolicerSnapshot {
            name: "meter-only".into(),
            bandwidth_bps: 0,
            burst_bytes: 0,
            discard_excess: false,
        }],
        &ifaces,
        "",
        "",
    )
    .expect(
        "a DEFINED but degenerate meter-only policer must not be rejected — \
         #4514 skips it on purpose and this config boots today",
    );
    assert!(
        !state.three_color_policer_by_name.contains_key("meter-only"),
        "fixture no longer exercises the map/definedness distinction: #4514 is \
         expected to SKIP this policer, so it must be absent from the runtime \
         map. If it is present, this cell has gone vacuous and no longer \
         guards against re-keying the preflight to the map."
    );
}

/// An EMPTY `then policer` is the legitimate "unpoliced" case, not a dangling
/// reference. A preflight that rejected the empty string would fail every term
/// in every filter that does not police.
#[test]
fn empty_policer_ref_6540_is_unpoliced_not_an_error() {
    let (filters, ifaces) = policer_ref_fixture_6540("");
    parse_filter_state(&filters, &[], &ifaces, "", "")
        .expect("a term with no policer must compile — empty means unpoliced");
}

/// #6854: the full `then reject <message-type>` mapping, one row per token the
/// Go compiler accepts.
///
/// This table IS the reviewable artifact of #6854, so it is spelled out in full
/// rather than derived — a test that recomputed the mapping from the same match
/// arms would agree with any mistake in them. Every one of the fifteen tokens in
/// `rejectMessageTypes` (pkg/config/compiler_firewall.go) appears exactly once.
///
/// The v4 column is RFC 792 Destination Unreachable and maps exactly. The v6
/// column is RFC 4443, which is NOT a relabelling of RFC 792: only four rows
/// have an honest counterpart, and the rest deliberately keep code 1
/// (administratively prohibited) rather than an invented code. Keeping 1 is not
/// a placeholder — it is precisely what the dataplane sent for every reject
/// before this change, so an operator who configures a v4-only message-type
/// sees unchanged v6 behaviour instead of a guess.
#[test]
fn reject_message_type_maps_every_accepted_token_6854() {
    // (token, v4 code, v6 code)
    let table: [(&str, u8, u8); 15] = [
        // Honest v6 counterparts.
        ("network-unreachable", 0, 0), // RFC 4443 code 0, no route to destination
        ("host-unreachable", 1, 3),    // RFC 4443 code 3, address unreachable
        ("port-unreachable", 3, 4),    // RFC 4443 code 4, port unreachable
        // Prohibitions: RFC 4443 code 1 is the honest counterpart for all three.
        ("administratively-prohibited", 13, 1),
        ("network-prohibited", 9, 1),
        ("host-prohibited", 10, 1),
        // IPv4-only machinery with no ICMPv6 equivalent — v6 stays at 1.
        ("protocol-unreachable", 2, 1),
        ("source-route-failed", 5, 1),
        ("source-host-isolated", 8, 1),
        ("bad-network-tos", 11, 1),
        ("bad-host-tos", 12, 1),
        ("precedence-violation", 14, 1),
        ("precedence-cutoff", 15, 1),
        // Not an ICMP message at all. `tcp-reset` changes behaviour only on the
        // TCP path, where a RST is sent and no ICMP reply is built, so it
        // carries the default here.
        ("tcp-reset", 13, 1),
        // No message-type configured.
        ("", 13, 1),
    ];

    for (token, want_v4, want_v6) in table {
        let got = super::resolve_reject_message(token);
        assert_eq!(
            (got.v4_code, got.v6_code),
            (want_v4, want_v6),
            "#6854: `then reject {token}` must resolve to ICMPv4 code {want_v4} / ICMPv6 code \
             {want_v6}"
        );
    }

    // Anti-vacuity: the table must not have collapsed to a single value. If a
    // future edit made every token resolve to the default, every row above
    // would still pass for the ten rows whose expectation IS the default.
    let distinct_v4: std::collections::BTreeSet<u8> = table
        .iter()
        .map(|(t, _, _)| super::resolve_reject_message(t).v4_code)
        .collect();
    assert!(
        distinct_v4.len() >= 13,
        "#6854: the v4 mapping collapsed to {} distinct codes; the table is not discriminating",
        distinct_v4.len()
    );

    // An unrecognized token degrades to the default rather than failing the
    // snapshot. Deliberate, and different from an unknown filter ACTION: the
    // action decides whether a packet is forwarded, this decides only which
    // code an already-decided reject carries.
    let unknown = super::resolve_reject_message("not-a-junos-message-type");
    assert_eq!(
        (unknown.v4_code, unknown.v6_code),
        (13, 1),
        "#6854: an unrecognized token must degrade to administratively-prohibited"
    );
}

/// #6854 WIRING: the snapshot's `reject_message_type` must actually reach
/// `FilterAction::Reject`.
///
/// This cell exists because the mutation matrix caught its absence. With the
/// resolver correct and the ICMP builder correct, replacing
/// `resolve_term_action`'s lookup with a hardcoded default left the ENTIRE
/// suite green: the resolver had a test, the builder had a test, and the hop
/// between them had none. A feature can be complete at both ends and connected
/// by nothing.
#[test]
fn reject_message_type_reaches_the_filter_action_6854() {
    use crate::protocol::FirewallTermSnapshot;

    let typed = FirewallTermSnapshot {
        name: "t".to_string(),
        action: "reject".to_string(),
        reject_message_type: "host-unreachable".to_string(),
        ..Default::default()
    };
    match super::compiler::resolve_term_action_for_test(&typed) {
        super::FilterAction::Reject(msg) => assert_eq!(
            (msg.v4_code, msg.v6_code),
            (1, 3),
            "#6854: the term's message-type did not reach FilterAction::Reject — the \
             resolver and the ICMP builder are both correct and nothing connects them"
        ),
        other => panic!("expected Reject, got {other:?}"),
    }

    // A term with no message-type must still resolve to the pre-#6854 codes,
    // so this change is invisible to a config that does not use the feature.
    let plain = FirewallTermSnapshot {
        name: "t".to_string(),
        action: "reject".to_string(),
        ..Default::default()
    };
    match super::compiler::resolve_term_action_for_test(&plain) {
        super::FilterAction::Reject(msg) => assert_eq!(
            (msg.v4_code, msg.v6_code),
            (13, 1),
            "#6854: a bare `then reject` must keep administratively-prohibited"
        ),
        other => panic!("expected Reject, got {other:?}"),
    }
}

// #7053: the routing-instance pairing named in comments must be the one
// production runs.
//
// This class of rot is not hypothetical here — it is what happened. `eval.rs`
// named `evaluate_interface_filter_routing_instance_event_counted` as the
// production pairing; the symbol is `#[cfg(test)]`. PR #6835 then EDITED that
// sentence ("the only external call site" -> "each of its external call sites")
// without noticing, turning one wrong reference into three. A comment cannot
// fail, so nothing caught either revision.
//
// The guard is structural because the property is: "no production file calls
// this symbol". Comments and string bodies are blanked first, so the corrected
// comments — which QUOTE the wrong symbol in order to name it — cannot satisfy
// or trip the scan.

/// Production `.rs` sources under `userspace-dp/src`, comments and strings
/// blanked. Test files are excluded by the same predicate the #6929 sweep uses.
fn production_sources_7053() -> Vec<(String, String)> {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    crate::afxdp::worker_queue::tests::afxdp_rs_files(&root, &mut files);
    let mut out = Vec::new();
    for path in files {
        let rel = path
            .strip_prefix(&root)
            .expect("under src")
            .to_string_lossy()
            .replace('\\', "/");
        if crate::afxdp::worker_queue::tests::is_fixture(&rel) {
            continue;
        }
        let src = std::fs::read_to_string(&path).expect("read source");
        out.push((
            rel,
            crate::afxdp::worker_queue::tests::blank_comments_and_strings(&src),
        ));
    }
    out
}

#[test]
fn no_production_caller_of_the_test_only_routing_instance_wrapper_7053() {
    const TEST_ONLY: &str = "evaluate_interface_filter_routing_instance_event_counted(";
    const PRODUCTION: &str = "evaluate_filter_ref_routing_instance_event_counted(";

    let sources = production_sources_7053();
    assert!(
        sources.len() >= 100,
        "only {} production sources were scanned; the walk or the fixture filter \
         is broken and every absence below is vacuous",
        sources.len()
    );

    // The test-only wrapper may appear ONLY in filter/engine/eval.rs, which
    // defines it and holds the `#[cfg(test)]` wrapper that calls it. Anywhere
    // else is a production caller of a symbol that is not in the shipped binary.
    let mut callers: Vec<&str> = sources
        .iter()
        .filter(|(rel, cleaned)| rel != "filter/engine/eval.rs" && cleaned.contains(TEST_ONLY))
        .map(|(rel, _)| rel.as_str())
        .collect();
    callers.sort_unstable();
    assert!(
        callers.is_empty(),
        "production file(s) {callers:?} name \
         `evaluate_interface_filter_routing_instance_event_counted`, which is \
         `#[cfg(test)]`. Production pairs with the `&Filter` core \
         `evaluate_filter_ref_routing_instance_event_counted`, reached through \
         `ingress_route_table_override` (afxdp/forwarding/pbr.rs) (#7053)"
    );

    // POSITIVE CONTROL. Without it the assertion above passes if the scan reads
    // nothing, if the needle stops matching, or if the production symbol is
    // renamed and the whole pairing disappears.
    let prod_callers: Vec<&str> = sources
        .iter()
        .filter(|(rel, cleaned)| rel != "filter/engine/eval.rs" && cleaned.contains(PRODUCTION))
        .map(|(rel, _)| rel.as_str())
        .collect();
    assert!(
        prod_callers.contains(&"afxdp/forwarding/pbr.rs"),
        "the PRODUCTION routing-instance evaluator is not called from \
         afxdp/forwarding/pbr.rs (found in {prod_callers:?}). Either the pairing \
         moved — in which case the eval.rs comments naming pbr.rs are now wrong \
         again — or this scan is matching nothing (#7053)"
    );

    // And the definition really is test-only, which is the premise the whole
    // guard rests on.
    let eval = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/filter/engine/eval.rs"),
    )
    .expect("read eval.rs");
    let def = eval
        .find("pub(crate) fn evaluate_interface_filter_routing_instance_event_counted")
        .expect("the wrapper definition must exist");
    assert!(
        eval[..def].trim_end().ends_with("#[cfg(test)]"),
        "`evaluate_interface_filter_routing_instance_event_counted` is no longer \
         `#[cfg(test)]`. If it became production, the eval.rs comments corrected \
         by #7053 need revisiting — they say it is not on a production path"
    );
}
