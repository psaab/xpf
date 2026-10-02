use super::*;
use crate::protocol::{FibNextHopWire, FibRouteWire};

const FIB_DUMP_RESPONSE_RESERVE_BYTES: usize = 1024 * 1024;

impl super::Coordinator {
    /// Return one coherent helper-side FIB snapshot and its generation.
    ///
    /// This runs only on an operator control request, never on a packet path.
    /// Entries from separate route maps are flattened and sorted so repeated
    /// dumps are useful for comparison even though the runtime maps are hash
    /// maps. ECMP leg order is retained because it is meaningful to the
    /// dataplane's weighted selector.
    pub(crate) fn dump_fib(&self) -> Result<(u32, Vec<FibRouteWire>), String> {
        self.dump_fib_with_budget(
            crate::protocol::MAX_CONTROL_RESPONSE_BYTES - FIB_DUMP_RESPONSE_RESERVE_BYTES,
        )
    }

    fn dump_fib_with_budget(
        &self,
        route_byte_limit: usize,
    ) -> Result<(u32, Vec<FibRouteWire>), String> {
        // Keep the route tables and generation tied to the exact RuntimeView
        // published to packet workers. Retained coordinator fields are
        // candidates for the next publish and may already have moved on.
        let view = self.ha.runtime.load();
        let forwarding = view.forwarding();
        let generation = view.validation().fib_generation;
        let mut routes = Vec::new();
        let mut route_bytes = 0usize;

        macro_rules! push_route {
            ($route:expr) => {{
                let route = $route;
                let row_bytes = serde_json::to_vec(&route)
                    .map_err(|error| format!("serialize FIB route: {error}"))?
                    .len();
                let next_bytes =
                    route_bytes.saturating_add(row_bytes + usize::from(!routes.is_empty()));
                if next_bytes > route_byte_limit {
                    return Err(format!(
                        "fib_dump route rows exceed the {}-byte control response budget \
                         ({}-byte framing/status reserve)",
                        route_byte_limit, FIB_DUMP_RESPONSE_RESERVE_BYTES
                    ));
                }
                route_bytes = next_bytes;
                routes.push(route);
            }};
        }

        for (table, entries) in &forwarding.routes_v4 {
            for entry in entries {
                push_route!(FibRouteWire {
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
                push_route!(FibRouteWire {
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
            push_route!(FibRouteWire {
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
            push_route!(FibRouteWire {
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
                push_route!(FibRouteWire {
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
                push_route!(FibRouteWire {
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
        Ok((generation, routes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fib_dump_returns_installed_route_and_generation_11370() {
        let snapshot = crate::ConfigSnapshot {
            fib_generation: 9,
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
        coordinator
            .refresh_runtime_snapshot_disarmed(&snapshot)
            .expect("publish the test snapshot");

        let (generation, rows) = coordinator.dump_fib().expect("dump fits");
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
    #[test]
    fn fib_dump_reads_published_view_not_retained_fields_11767() {
        let snapshot = crate::ConfigSnapshot {
            fib_generation: 9,
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
        coordinator
            .refresh_runtime_snapshot_disarmed(&snapshot)
            .expect("publish the test snapshot");
        // Diverge the retained candidate halves AFTER the publish: the dump
        // must keep reading the published RuntimeView, not these fields.
        coordinator.forwarding.routes_v4.clear();
        coordinator.forwarding.routes_v6.clear();
        coordinator.forwarding.connected_v4.clear();
        coordinator.forwarding.connected_v6.clear();
        coordinator.forwarding.leak_rules_v4.clear();
        coordinator.forwarding.leak_rules_v6.clear();
        coordinator.validation.fib_generation = 10;

        let (generation, rows) = coordinator.dump_fib().expect("dump fits");
        assert_eq!(
            generation, 9,
            "the dump must carry the published generation, not the retained one"
        );
        assert!(
            rows.iter()
                .any(|row| row.table == "inet.0" && row.destination == "203.0.113.0/24"),
            "the dump must carry the published route, not the emptied retained tables"
        );
    }

    #[test]
    fn fib_dump_refuses_over_budget_without_returning_partial_rows_11767() {
        let snapshot = crate::ConfigSnapshot {
            routes: vec![
                crate::RouteSnapshot {
                    table: "inet.0".to_string(),
                    family: "inet".to_string(),
                    destination: "203.0.113.0/24".to_string(),
                    ..Default::default()
                },
                crate::RouteSnapshot {
                    table: "inet.0".to_string(),
                    family: "inet".to_string(),
                    destination: "198.51.100.0/24".to_string(),
                    ..Default::default()
                },
            ],
            ..Default::default()
        };
        let mut coordinator = super::super::Coordinator::new();
        coordinator
            .refresh_runtime_snapshot_disarmed(&snapshot)
            .expect("publish the test snapshot");

        let (_, rows) = coordinator.dump_fib().expect("fixture dump fits");
        assert!(rows.len() >= 2, "fixture must contain both route rows");
        let total_route_bytes = rows
            .iter()
            .map(|row| serde_json::to_vec(row).expect("serialize row").len())
            .sum::<usize>()
            + rows.len()
            - 1;
        let error = coordinator
            .dump_fib_with_budget(total_route_bytes - 1)
            .expect_err("an over-budget FIB must be refused");
        assert!(
            error.contains("fib_dump route rows exceed"),
            "the refusal must identify the FIB response budget: {error}"
        );
    }
}
