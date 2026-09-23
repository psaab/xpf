//! Bounded generated-input strategies for policy agreement properties.

use super::oracle::{EMITTER_SEED, GeneratedQuery, GeneratedSnapshot, seed_rows};
use super::*;
use proptest::prelude::*;
use proptest::strategy::ValueTree;
const IPV4: &[&str] = &[
    "10.0.1.5",
    "10.0.1.100",
    "10.0.1.101",
    "10.0.2.5",
    "192.168.9.9",
];
const IPV6: &[&str] = &["2001:db8::5", "2001:db8::100", "::ffff:10.0.1.5"];
const PROTOCOLS: &[&str] = &["tcp", "udp", "icmp", "icmpv6", "89", "gre"];

pub(crate) fn seed_row_strategy() -> impl Strategy<Value = GeneratedRow> {
    prop::sample::select(seed_rows())
}

pub(crate) fn concrete_ip_strategy() -> impl Strategy<Value = String> {
    prop_oneof![
        prop::sample::select(IPV4.iter().map(|s| (*s).to_string()).collect::<Vec<_>>()),
        prop::sample::select(IPV6.iter().map(|s| (*s).to_string()).collect::<Vec<_>>()),
    ]
}

pub(crate) fn port_strategy() -> impl Strategy<Value = u16> {
    prop_oneof![
        Just(0u16),
        Just(1u16),
        Just(1023u16),
        Just(1024u16),
        Just(65535u16),
        2u16..=65534u16,
    ]
}

pub(crate) fn protocol_strategy() -> impl Strategy<Value = String> {
    prop::sample::select(
        PROTOCOLS
            .iter()
            .map(|s| (*s).to_string())
            .collect::<Vec<_>>(),
    )
}

/// Bounded packet tuples. The config is selected from the committed seed
/// corpus, so every differential row remains strictly compilable while this
/// strategy explores the packet dimensions that are easy to miss.
pub(crate) fn query_strategy() -> impl Strategy<Value = GeneratedQuery> {
    (
        prop::sample::select(vec![
            "trust".to_string(),
            "untrust".to_string(),
            "dmz".to_string(),
        ]),
        prop::sample::select(vec![
            "trust".to_string(),
            "untrust".to_string(),
            "dmz".to_string(),
            JUNOS_HOST_ZONE_NAME.to_string(),
        ]),
        concrete_ip_strategy(),
        concrete_ip_strategy(),
        protocol_strategy(),
        port_strategy(),
        port_strategy(),
        any::<bool>(),
        any::<bool>(),
        prop::option::of(0u8..=255u8),
        prop::option::of(0u8..=255u8),
    )
        .prop_map(
            |(
                from_zone,
                to_zone,
                src_ip,
                dst_ip,
                protocol,
                src_port,
                dst_port,
                frag,
                l4_present,
                icmp_type,
                icmp_code,
            )| GeneratedQuery {
                from_zone,
                to_zone,
                src_ip,
                dst_ip,
                protocol,
                src_port,
                dst_port,
                frag,
                l4_present: l4_present && !frag,
                icmp_type,
                icmp_code,
            },
        )
}

#[derive(Clone, Debug)]
pub(crate) struct GeneratedConfig {
    pub(crate) set_lines: Vec<String>,
    pub(crate) snapshot: GeneratedSnapshot,
    pub(crate) query: GeneratedQuery,
}

#[derive(Clone, Copy, Debug)]
struct RuleSpec {
    tier: u8,
    action_permit: bool,
    term: u8,
    excluded: bool,
}

/// Generate 1–3 zones and 0–6 rules across exact, wildcard, both-any, and
/// scoped-global tiers. The snapshot is assembled from the same wire structs
/// consumed by `parse_policy_state_with_counters`; `set_lines` is the
/// corresponding operator grammar used when a row is emitted to Go.
pub(crate) fn generated_config_strategy() -> impl Strategy<Value = GeneratedConfig> {
    (
        (
            1usize..=3usize,
            prop::collection::vec(
                (0u8..=4u8, any::<bool>(), 0u8..=4u8, any::<bool>())
                    .prop_map(|(tier, action_permit, term, excluded)| RuleSpec {
                        tier,
                        action_permit,
                        term,
                        excluded,
                    }),
                0..=6,
            ),
            any::<bool>(),
            0usize..=2usize,
            0usize..=2usize,
            concrete_ip_strategy(),
            concrete_ip_strategy(),
            protocol_strategy(),
            port_strategy(),
            port_strategy(),
        ),
        (
            any::<bool>(),
            prop::option::of(0u8..=255u8),
            prop::option::of(0u8..=255u8),
        ),
    )
        .prop_map(
            |(
                (
                    zone_count,
                    specs,
                    permit_default,
                    from_index,
                    to_index,
                    src_ip,
                    dst_ip,
                    protocol,
                    src_port,
                    dst_port,
                ),
                (frag, icmp_type, icmp_code),
            )| {
                let zones: Vec<String> = (0..zone_count).map(|i| format!("z{i}")).collect();
                let dst_ip = if src_ip.contains(':') == dst_ip.contains(':') {
                    dst_ip
                } else if src_ip.contains(':') {
                    IPV6[0].to_string()
                } else {
                    IPV4[0].to_string()
                };
                let from_zone = zones[from_index.min(zone_count - 1)].clone();
                let to_zone = zones[to_index.min(zone_count - 1)].clone();
                let mut set_lines = Vec::new();
                let mut zone_snapshots = Vec::new();
                for (i, zone) in zones.iter().enumerate() {
                    set_lines.push(format!(
                        "set interfaces ge-0/0/{i} unit 0 family inet address 10.0.{i}.1/24"
                    ));
                    set_lines.push(format!(
                        "set security zones security-zone {zone} interfaces ge-0/0/{i}.0"
                    ));
                    zone_snapshots.push(ZoneSnapshot {
                        name: zone.clone(),
                        id: (i as u16) + 1,
                        host_inbound_configured: true,
                        ..ZoneSnapshot::default()
                    });
                }

                let default_policy = if permit_default {
                    "permit".to_string()
                } else {
                    "deny".to_string()
                };
                set_lines.push(format!(
                    "set security policies default-policy {}-all",
                    if permit_default { "permit" } else { "deny" }
                ));

                let mut rules = Vec::new();
                for (idx, spec) in specs.iter().enumerate() {
                    let name = format!("gen-p{idx}");
                    let (rule_from, rule_to, match_from, match_to) = match spec.tier {
                        0 => (from_zone.clone(), to_zone.clone(), Vec::new(), Vec::new()),
                        1 => ("any".to_string(), to_zone.clone(), Vec::new(), Vec::new()),
                        2 => (from_zone.clone(), "any".to_string(), Vec::new(), Vec::new()),
                        3 => ("any".to_string(), "any".to_string(), Vec::new(), Vec::new()),
                        _ => (
                            "junos-global".to_string(),
                            "junos-global".to_string(),
                            vec![from_zone.clone()],
                            vec![to_zone.clone()],
                        ),
                    };
                    let (source_literals, destination_literals) = if spec.term == 3 {
                        (vec!["10.0.0.0/8".to_string()], vec!["any".to_string()])
                    } else if spec.term == 4 && spec.excluded {
                        (vec!["10.0.1.0/24".to_string()], vec!["any".to_string()])
                    } else {
                        (vec!["any".to_string()], vec!["any".to_string()])
                    };
                    let (applications, application_terms) = match spec.term {
                        1 => (
                            vec!["gen-tcp".to_string()],
                            vec![PolicyApplicationSnapshot {
                                name: "gen-tcp".to_string(),
                                protocol: "tcp".to_string(),
                                destination_port: "22".to_string(),
                                ..PolicyApplicationSnapshot::default()
                            }],
                        ),
                        2 => (
                            vec!["gen-icmp".to_string()],
                            vec![PolicyApplicationSnapshot {
                                name: "gen-icmp".to_string(),
                                protocol: "icmp".to_string(),
                                icmp_type: Some(8),
                                ..PolicyApplicationSnapshot::default()
                            }],
                        ),
                        _ => (vec!["any".to_string()], Vec::new()),
                    };
                    let action = if spec.action_permit { "permit" } else { "deny" };
                    let prefix = if spec.tier == 4 {
                        format!("set security policies global policy {name}")
                    } else {
                        format!(
                            "set security policies from-zone {rule_from} to-zone {rule_to} policy {name}"
                        )
                    };
                    if spec.tier == 4 {
                        set_lines.push(format!("{prefix} match from-zone {from_zone}"));
                        set_lines.push(format!("{prefix} match to-zone {to_zone}"));
                    }
                    let source_token = if spec.term == 3 {
                        "10.0.0.0/8"
                    } else if spec.term == 4 && spec.excluded {
                        "10.0.1.0/24"
                    } else {
                        "any"
                    };
                    set_lines.push(format!("{prefix} match source-address {source_token}"));
                    if spec.term == 4 && spec.excluded {
                        set_lines.push(format!("{prefix} match source-address-excluded"));
                    }
                    set_lines.push(format!("{prefix} match destination-address any"));
                    set_lines.push(format!("{prefix} match application {}", applications[0]));
                    set_lines.push(format!("{prefix} then {action}"));
                    if spec.term == 1 {
                        set_lines.push(
                            "set applications application gen-tcp protocol tcp".to_string(),
                        );
                        set_lines.push(
                            "set applications application gen-tcp destination-port 22"
                                .to_string(),
                        );
                    } else if spec.term == 2 {
                        set_lines.push(
                            "set applications application gen-icmp protocol icmp icmp-type 8"
                                .to_string(),
                        );
                    }
                    rules.push(PolicyRuleSnapshot {
                        rule_id: format!("{}->{}/{}", rule_from, rule_to, name),
                        name: name.clone(),
                        policy_id: idx as u32,
                        from_zone: rule_from,
                        to_zone: rule_to,
                        source_literals,
                        destination_literals,
                        source_address_excluded: spec.term == 4 && spec.excluded,
                        applications,
                        application_terms,
                        action: action.to_string(),
                        match_from_zones: match_from,
                        match_to_zones: match_to,
                        ..PolicyRuleSnapshot::default()
                    });
                }

                GeneratedConfig {
                    set_lines,
                    snapshot: GeneratedSnapshot {
                        default_policy,
                        rules,
                        zones: zone_snapshots,
                        address_books: Vec::new(),
                    },
                    query: GeneratedQuery {
                        from_zone,
                        to_zone,
                        src_ip,
                        dst_ip,
                        protocol,
                        src_port,
                        dst_port,
                        frag,
                        l4_present: !frag,
                        icmp_type,
                        icmp_code,
                    },
                }
            },
        )
}

/// Draw a bounded, reproducible batch for the opt-in cross-language emitter.
/// Every generated row records `oracle::EMITTER_SEED` so an evidence directory
/// can be regenerated byte-identically.
pub(crate) fn emitted_configs(cases: u32) -> Vec<GeneratedConfig> {
    let mut runner = proptest::test_runner::TestRunner::new(proptest::test_runner::Config {
        cases,
        failure_persistence: None,
        rng_seed: proptest::test_runner::RngSeed::Fixed(EMITTER_SEED),
        ..proptest::test_runner::Config::default()
    });
    (0..cases)
        .map(|_| {
            generated_config_strategy()
                .new_tree(&mut runner)
                .expect("generated policy strategy must produce a value")
                .current()
        })
        .collect()
}

pub(crate) fn case_rows(case: &str) -> Vec<GeneratedRow> {
    seed_rows()
        .into_iter()
        .filter(|row| row.source_case == case)
        .collect()
}

pub(crate) fn row_named(id: &str) -> GeneratedRow {
    seed_rows()
        .into_iter()
        .find(|row| row.id == id)
        .unwrap_or_else(|| panic!("generated seed row {id:?} is missing"))
}
