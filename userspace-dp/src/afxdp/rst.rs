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
    for rule in &snapshot.source_nat_rules {
        if !rule.interface_mode || rule.off {
            continue;
        }
        for iface in &snapshot.interfaces {
            if !interface_matches_nat_to_scope(rule, iface) {
                continue;
            }
            if let Some(v4) = pick_interface_v4(iface) {
                excluded_v4.insert(v4);
            }
            if let Some(v6) = pick_interface_v6(iface) {
                excluded_v6.insert(v6);
            }
        }
    }
    (excluded_v4, excluded_v6)
}

/// Applies the runtime NAT rule-set's non-empty-AND, empty-wildcard to-side
/// matching to one candidate interface address row.
fn interface_matches_nat_to_scope(
    rule: &crate::protocol::SourceNATRuleSnapshot,
    iface: &InterfaceSnapshot,
) -> bool {
    if !rule.to_interface.is_empty()
        && rule.to_interface != iface.name
        && iface
            .name
            .split_once('.')
            .map_or(true, |(base, _)| rule.to_interface != base)
    {
        return false;
    }
    if !rule.to_routing_instance.is_empty() && rule.to_routing_instance != iface.routing_instance {
        return false;
    }
    if !rule.to_zone.is_empty() && rule.to_zone != iface.zone {
        return false;
    }
    true
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
}
