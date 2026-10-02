use super::*;
use crate::protocol::{FibNextHopWire, FibRouteWire};

impl super::Coordinator {
    /// Return one coherent helper-side FIB snapshot and its generation.
    ///
    /// This runs only on an operator control request, never on a packet path.
    /// Entries from separate route maps are flattened and sorted so repeated
    /// dumps are useful for comparison even though the runtime maps are hash
    /// maps. ECMP leg order is retained because it is meaningful to the
    /// dataplane's weighted selector.
    pub(crate) fn dump_fib(&self) -> (u32, Vec<FibRouteWire>) {
        let forwarding = &self.forwarding;
        let mut routes = Vec::new();

        for (table, entries) in &forwarding.routes_v4 {
            for entry in entries {
                routes.push(FibRouteWire {
                    table: table.clone(),
                    family: "inet".to_string(),
                    destination: format!("{}/{}", entry.prefix.addr(), entry.prefix.prefix_len()),
                    kind: "route".to_string(),
                    next_hops: entry
                        .next_hops
                        .iter()
                        .map(|hop| FibNextHopWire {
                            next_hop: hop.next_hop.map(|ip| ip.to_string()).unwrap_or_default(),
                            ifindex: hop.ifindex,
                            interface: forwarding
                                .ifindex_to_name
                                .get(&hop.ifindex)
                                .cloned()
                                .unwrap_or_default(),
                            tunnel_endpoint_id: hop.tunnel_endpoint_id,
                            weight: hop.weight,
                        })
                        .collect(),
                    discard: entry.discard,
                    next_table: entry.next_table.clone(),
                    rule_priority: entry.rule_priority,
                    preference: entry.preference,
                    mtu: entry.mtu,
                });
            }
        }
        for (table, entries) in &forwarding.routes_v6 {
            for entry in entries {
                routes.push(FibRouteWire {
                    table: table.clone(),
                    family: "inet6".to_string(),
                    destination: format!("{}/{}", entry.prefix.addr(), entry.prefix.prefix_len()),
                    kind: "route".to_string(),
                    next_hops: entry
                        .next_hops
                        .iter()
                        .map(|hop| FibNextHopWire {
                            next_hop: hop.next_hop.map(|ip| ip.to_string()).unwrap_or_default(),
                            ifindex: hop.ifindex,
                            interface: forwarding
                                .ifindex_to_name
                                .get(&hop.ifindex)
                                .cloned()
                                .unwrap_or_default(),
                            tunnel_endpoint_id: hop.tunnel_endpoint_id,
                            weight: hop.weight,
                        })
                        .collect(),
                    discard: entry.discard,
                    next_table: entry.next_table.clone(),
                    rule_priority: entry.rule_priority,
                    preference: entry.preference,
                    mtu: entry.mtu,
                });
            }
        }

        for connected in &forwarding.connected_v4 {
            routes.push(FibRouteWire {
                table: connected.table.clone(),
                family: "inet".to_string(),
                destination: format!(
                    "{}/{}",
                    connected.prefix.addr(),
                    connected.prefix.prefix_len()
                ),
                kind: "connected".to_string(),
                next_hops: vec![FibNextHopWire {
                    ifindex: connected.ifindex,
                    interface: forwarding
                        .ifindex_to_name
                        .get(&connected.ifindex)
                        .cloned()
                        .unwrap_or_default(),
                    tunnel_endpoint_id: connected.tunnel_endpoint_id,
                    weight: 1,
                    ..Default::default()
                }],
                ..Default::default()
            });
        }
        for connected in &forwarding.connected_v6 {
            routes.push(FibRouteWire {
                table: connected.table.clone(),
                family: "inet6".to_string(),
                destination: format!(
                    "{}/{}",
                    connected.prefix.addr(),
                    connected.prefix.prefix_len()
                ),
                kind: "connected".to_string(),
                next_hops: vec![FibNextHopWire {
                    ifindex: connected.ifindex,
                    interface: forwarding
                        .ifindex_to_name
                        .get(&connected.ifindex)
                        .cloned()
                        .unwrap_or_default(),
                    tunnel_endpoint_id: connected.tunnel_endpoint_id,
                    weight: 1,
                    ..Default::default()
                }],
                ..Default::default()
            });
        }

        for (table, entries) in &forwarding.leak_rules_v4 {
            for entry in entries {
                routes.push(FibRouteWire {
                    table: table.clone(),
                    family: "inet".to_string(),
                    destination: format!("{}/{}", entry.prefix.addr(), entry.prefix.prefix_len()),
                    kind: "next-table".to_string(),
                    next_table: entry.next_table.clone(),
                    rule_priority: entry.rule_priority,
                    ..Default::default()
                });
            }
        }
        for (table, entries) in &forwarding.leak_rules_v6 {
            for entry in entries {
                routes.push(FibRouteWire {
                    table: table.clone(),
                    family: "inet6".to_string(),
                    destination: format!("{}/{}", entry.prefix.addr(), entry.prefix.prefix_len()),
                    kind: "next-table".to_string(),
                    next_table: entry.next_table.clone(),
                    rule_priority: entry.rule_priority,
                    ..Default::default()
                });
            }
        }

        routes.sort_by(|a, b| {
            a.table
                .cmp(&b.table)
                .then_with(|| a.family.cmp(&b.family))
                .then_with(|| a.destination.cmp(&b.destination))
                .then_with(|| a.kind.cmp(&b.kind))
                .then_with(|| a.rule_priority.cmp(&b.rule_priority))
                .then_with(|| a.preference.cmp(&b.preference))
                .then_with(|| a.next_table.cmp(&b.next_table))
        });
        (self.validation.fib_generation, routes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fib_dump_returns_installed_route_and_generation_11370() {
        let snapshot = crate::ConfigSnapshot {
            routes: vec![crate::RouteSnapshot {
                table: "inet.0".to_string(),
                family: "inet".to_string(),
                destination: "203.0.113.0/24".to_string(),
                discard: true,
                preference: 17,
                mtu: 1400,
                ..Default::default()
            }],
            ..Default::default()
        };
        let mut coordinator = super::super::Coordinator::new();
        coordinator.forwarding = crate::afxdp::forwarding_build::build_forwarding_state(&snapshot);
        coordinator.validation.fib_generation = 9;

        let (generation, rows) = coordinator.dump_fib();
        assert_eq!(generation, 9);
        let route = rows
            .iter()
            .find(|row| row.table == "inet.0" && row.destination == "203.0.113.0/24")
            .expect("the installed helper route must be dumped");
        assert_eq!(route.family, "inet");
        assert_eq!(route.kind, "route");
        assert!(route.discard);
        assert_eq!(route.preference, 17);
        assert_eq!(route.mtu, 1400);
    }
}
