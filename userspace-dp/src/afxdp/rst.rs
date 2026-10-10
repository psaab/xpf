use super::*;

/// RST suppression is now managed by the Go daemon via netlink (pkg/nftables).
/// This function is a no-op retained to avoid breaking the call site.
pub(super) fn install_kernel_rst_suppression(_state: &ForwardingState) {
    // No-op: the Go daemon installs nftables rules via the netlink API
    // (github.com/google/nftables). See pkg/nftables/rst_suppress.go.
}

/// Removal is also handled by the Go daemon.
pub(crate) fn remove_kernel_rst_suppression() {
    // No-op: the Go daemon manages the nftables table lifecycle.
}

pub(super) fn nat_translated_local_exclusions(
    snapshot: &ConfigSnapshot,
) -> (FastSet<Ipv4Addr>, FastSet<Ipv6Addr>) {
    let mut excluded_v4 = FastSet::default();
    let mut excluded_v6 = FastSet::default();
    if snapshot.source_nat_rules.is_empty() || snapshot.interfaces.is_empty() {
        return (excluded_v4, excluded_v6);
    }

    struct Candidate {
        v4: Option<Ipv4Addr>,
        v6: Option<Ipv6Addr>,
    }

    let mut candidates = Vec::with_capacity(snapshot.interfaces.len());
    let mut by_scope: std::collections::HashMap<(&str, &str, &str), Vec<usize>> =
        std::collections::HashMap::with_capacity(snapshot.interfaces.len());
    for iface in &snapshot.interfaces {
        if !interface_can_be_snat_egress(iface) {
            continue;
        }
        let item = Candidate {
            v4: pick_interface_v4(iface),
            v6: pick_interface_v6(iface),
        };
        if item.v4.is_none() && item.v6.is_none() {
            continue;
        }
        let index = candidates.len();
        candidates.push(item);
        for mask in 0..8 {
            if (mask & 1 != 0 && iface.name.is_empty())
                || (mask & 2 != 0 && iface.routing_instance.is_empty())
                || (mask & 4 != 0 && iface.egress_zone.is_empty())
            {
                continue;
            }
            let to_interface = if mask & 1 != 0 { iface.name.as_str() } else { "" };
            let to_routing_instance = if mask & 2 != 0 {
                iface.routing_instance.as_str()
            } else {
                ""
            };
            let to_zone = if mask & 4 != 0 {
                iface.egress_zone.as_str()
            } else {
                ""
            };
            by_scope
                .entry((to_interface, to_routing_instance, to_zone))
                .or_default()
                .push(index);
        }
    }

    let mut seen_scopes: FastSet<(&str, &str, &str)> = FastSet::default();
    for rule in &snapshot.source_nat_rules {
        if !rule.interface_mode || rule.off {
            continue;
        }
        let scope = (
            rule.to_interface.as_str(),
            rule.to_routing_instance.as_str(),
            rule.to_zone.as_str(),
        );
        if !seen_scopes.insert(scope) {
            continue;
        }
        if let Some(indices) = by_scope.get(&scope) {
            for &index in indices {
                let item = &candidates[index];
                if let Some(v4) = item.v4 {
                    excluded_v4.insert(v4);
                }
                if let Some(v6) = item.v6 {
                    excluded_v6.insert(v6);
                }
            }
        }
    }
    (excluded_v4, excluded_v6)
}

/// Whether a row can be a runtime SNAT egress and may register its address.
/// Empty-zone addresses stay local so the #5659 sentinel remains armed.
fn interface_can_be_snat_egress(iface: &InterfaceSnapshot) -> bool {
    if iface.ifindex <= 0 || iface.admin_disabled || iface.zone.is_empty() {
        return false;
    }
    let base = iface
        .name
        .split_once('.')
        .map_or(iface.name.as_str(), |(base, _)| base);
    !base.starts_with("fxp")
        && !base.starts_with("em")
        && !base.starts_with("fab")
        && base != "lo0"
}

#[cfg(test)]
mod nat_iface_scope_12085_tests {
    use super::*;
    use crate::protocol::{ConfigSnapshot, InterfaceSnapshot, SourceNATRuleSnapshot, ZoneSnapshot};
    use serde::Deserialize;

    #[derive(Deserialize)]
    struct MatrixFixture {
        interfaces: Vec<InterfaceSnapshot>,
        zones: Vec<ZoneSnapshot>,
        cases: Vec<MatrixCase>,
    }

    #[derive(Deserialize)]
    struct MatrixCase {
        name: String,
        rule: SourceNATRuleSnapshot,
        want: Vec<String>,
    }

    fn fixture() -> MatrixFixture {
        serde_json::from_str(include_str!(
            "../../tests/fixtures/nat_iface_scope_12085.json"
        ))
        .expect("shared Go/Rust matrix fixture must decode")
    }

    fn snapshot(fixture: &MatrixFixture, rule: &SourceNATRuleSnapshot) -> ConfigSnapshot {
        ConfigSnapshot {
            interfaces: fixture.interfaces.clone(),
            zones: fixture.zones.clone(),
            source_nat_rules: vec![rule.clone()],
            ..Default::default()
        }
    }

    fn addresses(v4: &FastSet<Ipv4Addr>, v6: &FastSet<Ipv6Addr>) -> Vec<String> {
        let mut out: Vec<String> = v4
            .iter()
            .map(ToString::to_string)
            .chain(v6.iter().map(ToString::to_string))
            .collect();
        out.sort();
        out
    }

    #[test]
    fn interface_nat_exclusions_match_shared_go_matrix_12085() {
        let fixture = fixture();
        for case in &fixture.cases {
            let snapshot = snapshot(&fixture, &case.rule);
            let (v4, v6) = nat_translated_local_exclusions(&snapshot);
            let mut want = case.want.clone();
            want.sort();
            assert_eq!(
                addresses(&v4, &v6),
                want,
                "Rust interface-NAT exclusion set differs from shared Go/Rust vector {}",
                case.name
            );
        }
    }

    #[test]
    fn forwarding_interface_nat_map_matches_shared_go_matrix_12085() {
        let fixture = fixture();
        for case in &fixture.cases {
            let state = crate::afxdp::forwarding_build::build_forwarding_state(
                &snapshot(&fixture, &case.rule),
            );
            let mut got: Vec<String> = state
                .interface_nat_v4
                .keys()
                .map(ToString::to_string)
                .chain(state.interface_nat_v6.keys().map(ToString::to_string))
                .collect();
            let mut want = case.want.clone();
            got.sort();
            want.sort();
            assert_eq!(
                got, want,
                "Rust forwarding interface-NAT map differs from shared Go/Rust vector {}",
                case.name
            );
        }
    }

    #[test]
    fn to_interface_only_rule_registers_egress_address_12085() {
        let fixture = fixture();
        let case = fixture
            .cases
            .iter()
            .find(|case| case.name == "to-interface")
            .expect("shared fixture has to-interface row");
        let snapshot = snapshot(&fixture, &case.rule);
        let state = crate::afxdp::forwarding_build::build_forwarding_state(&snapshot);
        let egress: Ipv4Addr = "192.0.2.2".parse().expect("IPv4 fixture address");
        assert_eq!(
            state.interface_nat_v4.get(&egress),
            Some(&11),
            "to-interface-only rule must route the egress address through interface_nat_v4"
        );
        assert!(
            !state.local_v4.contains(&egress),
            "to-interface egress address must not remain local"
        );
    }

    #[test]
    fn off_rule_does_not_register_interface_nat_addresses_12085() {
        let fixture = fixture();
        let case = fixture
            .cases
            .iter()
            .find(|case| case.name == "off-rule")
            .expect("shared fixture has off-rule row");
        let (v4, v6) = nat_translated_local_exclusions(&snapshot(&fixture, &case.rule));
        assert!(v4.is_empty() && v6.is_empty(), "off rule registered addresses");
    }

    #[test]
    fn to_interface_requires_the_runtime_logical_name_12085() {
        let fixture = fixture();
        let mut rule = SourceNATRuleSnapshot {
            interface_mode: true,
            to_interface: "ge-0/0/1".into(),
            ..Default::default()
        };
        let bare = snapshot(&fixture, &rule);
        let (v4, v6) = nat_translated_local_exclusions(&bare);
        assert!(v4.is_empty() && v6.is_empty(), "bare base name matched a unit");

        rule.to_interface = "ge-0/0/1.0".into();
        let exact = snapshot(&fixture, &rule);
        let (v4, v6) = nat_translated_local_exclusions(&exact);
        assert_eq!(
            addresses(&v4, &v6),
            vec!["192.0.2.2".to_string(), "2001:db8:1::2".to_string()],
            "exact runtime logical name must still match"
        );
    }

    #[test]
    fn unzoned_interface_keeps_local_delivery_and_5659_sentinel_armed_12085() {
        let fixture = fixture();
        let case = fixture
            .cases
            .iter()
            .find(|case| case.name == "unscoped")
            .expect("shared fixture has unscoped row");
        let snapshot = snapshot(&fixture, &case.rule);
        let addr: Ipv4Addr = "203.0.113.2".parse().expect("unzoned fixture address");
        let (v4, _) = nat_translated_local_exclusions(&snapshot);
        assert!(!v4.contains(&addr), "unzoned address entered interface-NAT exclusions");

        let state = crate::afxdp::forwarding_build::build_forwarding_state(&snapshot);
        assert!(state.local_v4.contains(&addr), "unzoned address must remain local");
        assert!(
            !state.interface_nat_v4.contains_key(&addr),
            "unzoned address must not enter interface_nat_v4"
        );
        assert!(
            state.ifindex_host_inbound.contains_key(&12),
            "#5659 sentinel must stay armed for the unzoned addressed interface"
        );
        assert!(
            !crate::afxdp::forwarding::host_inbound_admits_iface(
                &state,
                12,
                0,
                crate::ip_proto::PROTO_TCP,
                22,
                false,
                0,
            ),
            "the armed #5659 sentinel must deny host-bound SSH"
        );
    }
}
