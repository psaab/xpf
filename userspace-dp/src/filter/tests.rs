// Tests for the filter module (#1049). Originally inline in filter.rs,
// relocated as filter_tests.rs in P1 (PR #1052), then renamed to
// filter/tests.rs alongside the structural split into compiler/engine/policer.
// Loaded as a sibling submodule via `#[path = "tests.rs"]` from filter/mod.rs.

use super::*;

fn make_filter_state(
    filters: &[FirewallFilterSnapshot],
    policers: &[PolicerSnapshot],
) -> FilterState {
    parse_filter_state(filters, policers, &[], "", "")
}

fn make_filter_state_with_three_color(
    filters: &[FirewallFilterSnapshot],
    three_color_policers: &[ThreeColorPolicerSnapshot],
) -> FilterState {
    parse_filter_state_with_three_color(filters, &[], three_color_policers, &[], "", "")
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
                    destination_addresses: vec![],
                    source_addresses: vec![],
                    protocols: vec!["tcp".into()],
                    source_ports: vec![],
                    destination_ports: vec!["22".into()],
                    dscp_values: vec![],
                    action: "discard".into(),
                    count: String::new(),
                    log: false,
                    policer: String::new(),
                    routing_instance: String::new(),
                    forwarding_class: String::new(),
                    dscp_rewrite: None,
                },
                FirewallTermSnapshot {
                    name: "allow-all".into(),
                    destination_addresses: vec![],
                    source_addresses: vec![],
                    protocols: vec![],
                    source_ports: vec![],
                    destination_ports: vec![],
                    dscp_values: vec![],
                    action: "accept".into(),
                    count: String::new(),
                    log: false,
                    policer: String::new(),
                    routing_instance: String::new(),
                    forwarding_class: String::new(),
                    dscp_rewrite: None,
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
    );
    assert_eq!(result.action, FilterAction::Accept);
}

#[test]
fn port_range_matching() {
    let state = make_filter_state(
        &[FirewallFilterSnapshot {
            name: "port-range".into(),
            family: "inet".into(),
            terms: vec![FirewallTermSnapshot {
                name: "high-ports".into(),
                destination_addresses: vec![],
                source_addresses: vec![],
                protocols: vec!["tcp".into()],
                source_ports: vec![],
                destination_ports: vec!["1024-65535".into()],
                dscp_values: vec![],
                action: "discard".into(),
                count: String::new(),
                log: false,
                policer: String::new(),
                routing_instance: String::new(),
                forwarding_class: String::new(),
                dscp_rewrite: None,
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
    );
    assert_eq!(result.action, FilterAction::Accept);
}

#[test]
fn protocol_matching() {
    let state = make_filter_state(
        &[FirewallFilterSnapshot {
            name: "proto-filter".into(),
            family: "inet".into(),
            terms: vec![FirewallTermSnapshot {
                name: "deny-icmp".into(),
                destination_addresses: vec![],
                source_addresses: vec![],
                protocols: vec!["icmp".into()],
                source_ports: vec![],
                destination_ports: vec![],
                dscp_values: vec![],
                action: "discard".into(),
                count: String::new(),
                log: false,
                policer: String::new(),
                routing_instance: String::new(),
                forwarding_class: String::new(),
                dscp_rewrite: None,
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
                destination_addresses: vec![],
                source_addresses: vec![],
                protocols: vec!["udp".into()],
                source_ports: vec![],
                destination_ports: vec!["5060".into()],
                dscp_values: vec![],
                action: "accept".into(),
                count: String::new(),
                log: false,
                policer: String::new(),
                routing_instance: String::new(),
                forwarding_class: String::new(),
                dscp_rewrite: Some(46), // EF
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
                destination_addresses: vec![],
                source_addresses: vec![],
                protocols: vec!["udp".into()],
                source_ports: vec![],
                destination_ports: vec!["5060".into()],
                dscp_values: vec![],
                action: "accept".into(),
                count: String::new(),
                log: false,
                policer: String::new(),
                routing_instance: String::new(),
                forwarding_class: String::new(),
                dscp_rewrite: Some(0),
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
    );
    assert_eq!(result.action, FilterAction::Accept);
    assert_eq!(result.dscp_rewrite, Some(0));
}

#[test]
fn token_bucket_policer() {
    let mut policer = PolicerState::new(
        "1mbps".into(),
        1_000_000, // 1 Mbps = 125,000 bytes/sec
        125_000,   // burst = 125KB
        true,
    );

    // First packet at t=0 — should be within burst
    let conforming = policer.consume(0, 1000);
    assert!(conforming, "first packet within burst should conform");

    // Consume most of the burst
    let conforming = policer.consume(0, 120_000);
    assert!(conforming, "second packet within burst should conform");

    // This should exceed burst (only ~4000 tokens left)
    let conforming = policer.consume(0, 10_000);
    assert!(
        !conforming,
        "packet exceeding burst should be non-conforming"
    );

    // After 1 second, tokens should have refilled
    let conforming = policer.consume(1_000_000_000, 1000);
    assert!(conforming, "packet after refill should conform");
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
    assert_eq!(ids, vec![(1, "alpha".into()), (2, "zeta".into())]);

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
                    destination_addresses: vec![],
                    source_addresses: vec![],
                    protocols: vec!["udp".into()],
                    source_ports: vec![],
                    destination_ports: vec!["53".into()],
                    dscp_values: vec![],
                    action: "accept".into(),
                    count: String::new(),
                    log: false,
                    policer: String::new(),
                    routing_instance: String::new(),
                    forwarding_class: String::new(),
                    dscp_rewrite: None,
                },
                FirewallTermSnapshot {
                    name: "deny-all-udp".into(),
                    destination_addresses: vec![],
                    source_addresses: vec![],
                    protocols: vec!["udp".into()],
                    source_ports: vec![],
                    destination_ports: vec![],
                    dscp_values: vec![],
                    action: "discard".into(),
                    count: String::new(),
                    log: false,
                    policer: String::new(),
                    routing_instance: String::new(),
                    forwarding_class: String::new(),
                    dscp_rewrite: None,
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
                source_addresses: vec!["192.168.1.0/24".into()],
                destination_addresses: vec!["10.0.0.0/8".into()],
                protocols: vec![],
                source_ports: vec![],
                destination_ports: vec![],
                dscp_values: vec![],
                action: "discard".into(),
                count: String::new(),
                log: false,
                policer: String::new(),
                routing_instance: String::new(),
                forwarding_class: String::new(),
                dscp_rewrite: None,
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
    );
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
    );
    assert_eq!(result.forwarding_class.as_ref(), "bandwidth-10mb");
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
    );
    assert_eq!(
        state.iface_filter_v4.get(&7).map(String::as_str),
        Some("inet:ingress-v4")
    );
    assert!(state.iface_filter_v4_affects_tx_selection.contains(&7));
    assert!(state.has_input_tx_selection_v4);
    assert!(state.iface_filter_v4_affects_route_lookup.contains(&7));
    assert!(!state.iface_filter_out_v4_needs_tx_eval.contains(&7));
    assert!(!state.iface_filter_out_v6_needs_tx_eval.contains(&7));
    assert!(!state.has_output_tx_selection_v4);
    assert!(!state.has_output_tx_selection_v6);
    assert_eq!(
        state.iface_filter_out_v6.get(&7).map(String::as_str),
        Some("inet6:egress-v6")
    );
    assert_eq!(state.lo0_filter_v4, "inet:protect-re");
    assert_eq!(state.lo0_filter_v6, "inet6:protect-re-v6");
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
    );

    assert!(!interface_output_filter_needs_tx_eval(&state, 7, false));
    assert!(!filter_state_has_output_tx_selection(&state, false));
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
    );

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
        1500,
    );
    assert_eq!(routing_instance, Some("sfmix"));
    let filter = state.iface_filter_v6_fast.get(&11).expect("input filter");
    assert_eq!(filter.terms[0].counter.packets.load(Ordering::Relaxed), 1);
    assert_eq!(filter.terms[0].counter.bytes.load(Ordering::Relaxed), 1500);
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
    );
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
        1514,
    );
    assert_eq!(result.forwarding_class.as_ref(), "iperf-a");
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
    );
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
        1514,
    );
    assert_eq!(result.forwarding_class.as_ref(), "iperf-a");
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
    );
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
    );
    assert_eq!(result.action, FilterAction::Discard);
}
