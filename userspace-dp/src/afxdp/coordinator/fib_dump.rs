use super::*;
use crate::protocol::{FibNextHopWire, FibRouteWire, MAX_CONTROL_RESPONSE_BYTES};
use std::io::{self, Write};

const FIB_DUMP_RESPONSE_RESERVE_BYTES: usize = 1024 * 1024;
const MAX_FIB_DUMP_ROUTE_BYTES: usize =
    MAX_CONTROL_RESPONSE_BYTES - FIB_DUMP_RESPONSE_RESERVE_BYTES;

#[derive(Default)]
struct SerializedByteCounter(usize);

impl Write for SerializedByteCounter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0 = self.0.saturating_add(bytes.len());
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn push_fib_route(
    routes: &mut Vec<FibRouteWire>,
    encoded_route_bytes: &mut usize,
    route: FibRouteWire,
    max_encoded_bytes: usize,
) -> Result<(), String> {
    let mut counter = SerializedByteCounter::default();
    serde_json::to_writer(&mut counter, &route)
        .map_err(|err| format!("encode helper FIB route size: {err}"))?;
    let separator_bytes = usize::from(!routes.is_empty());
    let next_size = encoded_route_bytes
        .checked_add(counter.0)
        .and_then(|size| size.checked_add(separator_bytes))
        .ok_or_else(|| "helper FIB response size overflow".to_string())?;
    if next_size > max_encoded_bytes {
        return Err(format!(
            "helper FIB dump exceeds its bounded response budget for the {}-byte control-response cap; no partial FIB was returned",
            MAX_CONTROL_RESPONSE_BYTES
        ));
    }
    *encoded_route_bytes = next_size;
    routes.push(route);
    Ok(())
}

impl super::Coordinator {
    /// Return one coherent helper-side FIB snapshot and its generation.
    ///
    /// This runs only on an operator control request, never on a packet path.
    /// Entries from separate route maps are flattened and sorted so repeated
    /// dumps are useful for comparison even though the runtime maps are hash
    /// maps. ECMP leg order is retained because it is meaningful to the
    /// dataplane's weighted selector.
    pub(crate) fn dump_fib(&self) -> Result<(u32, Vec<FibRouteWire>), String> {
        self.dump_fib_with_budget(MAX_FIB_DUMP_ROUTE_BYTES)
    }

    fn dump_fib_with_budget(
        &self,
        max_encoded_bytes: usize,
    ) -> Result<(u32, Vec<FibRouteWire>), String> {
        let view = self.ha.runtime.load();
        let forwarding = view.forwarding();
        let mut routes = Vec::new();
        let mut encoded_route_bytes = 2; // JSON array brackets.

        for (table, entries) in &forwarding.routes_v4 {
            for entry in entries {
                push_fib_route(
                    &mut routes,
                    &mut encoded_route_bytes,
                    FibRouteWire {
                        table: table.clone(),
                        family: "inet".to_string(),
                        destination: format!(
                            "{}/{}",
                            entry.prefix.addr(),
                            entry.prefix.prefix_len()
                        ),
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
                    },
                    max_encoded_bytes,
                )?;
            }
        }
        for (table, entries) in &forwarding.routes_v6 {
            for entry in entries {
                push_fib_route(
                    &mut routes,
                    &mut encoded_route_bytes,
                    FibRouteWire {
                        table: table.clone(),
                        family: "inet6".to_string(),
                        destination: format!(
                            "{}/{}",
                            entry.prefix.addr(),
                            entry.prefix.prefix_len()
                        ),
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
                    },
                    max_encoded_bytes,
                )?;
            }
        }

        for connected in &forwarding.connected_v4 {
            push_fib_route(
                &mut routes,
                &mut encoded_route_bytes,
                FibRouteWire {
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
                },
                max_encoded_bytes,
            )?;
        }
        for connected in &forwarding.connected_v6 {
            push_fib_route(
                &mut routes,
                &mut encoded_route_bytes,
                FibRouteWire {
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
                },
                max_encoded_bytes,
            )?;
        }

        for (table, entries) in &forwarding.leak_rules_v4 {
            for entry in entries {
                push_fib_route(
                    &mut routes,
                    &mut encoded_route_bytes,
                    FibRouteWire {
                        table: table.clone(),
                        family: "inet".to_string(),
                        destination: format!(
                            "{}/{}",
                            entry.prefix.addr(),
                            entry.prefix.prefix_len()
                        ),
                        kind: "next-table".to_string(),
                        next_table: entry.next_table.clone(),
                        rule_priority: entry.rule_priority,
                        ..Default::default()
                    },
                    max_encoded_bytes,
                )?;
            }
        }
        for (table, entries) in &forwarding.leak_rules_v6 {
            for entry in entries {
                push_fib_route(
                    &mut routes,
                    &mut encoded_route_bytes,
                    FibRouteWire {
                        table: table.clone(),
                        family: "inet6".to_string(),
                        destination: format!(
                            "{}/{}",
                            entry.prefix.addr(),
                            entry.prefix.prefix_len()
                        ),
                        kind: "next-table".to_string(),
                        next_table: entry.next_table.clone(),
                        rule_priority: entry.rule_priority,
                        ..Default::default()
                    },
                    max_encoded_bytes,
                )?;
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
        Ok((view.validation().fib_generation, routes))
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
        coordinator.publish_runtime_view();

        // Retained coordinator state may move ahead while workers still hold
        // the last published pair. Dump the route and generation workers read.
        coordinator.forwarding =
            crate::afxdp::forwarding_build::build_forwarding_state(&Default::default());
        coordinator.validation.fib_generation = 10;

        let (generation, rows) = coordinator.dump_fib().expect("bounded FIB snapshot");
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
        let err = coordinator
            .dump_fib_with_budget(2)
            .expect_err("an oversized snapshot must not return partial routes");
        assert!(err.contains("no partial FIB was returned"), "{err}");
    }
}
