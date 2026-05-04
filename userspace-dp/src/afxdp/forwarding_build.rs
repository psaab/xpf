use super::*;
use crate::RouteSnapshot;

pub(super) fn build_screen_profiles(snapshot: &ConfigSnapshot) -> FxHashMap<String, ScreenProfile> {
    let mut profiles = FxHashMap::default();
    for sp in &snapshot.screens {
        if sp.zone.is_empty() {
            continue;
        }
        profiles.insert(
            sp.zone.clone(),
            ScreenProfile {
                land: sp.land,
                syn_fin: sp.syn_fin,
                no_flag: sp.tcp_no_flag,
                fin_no_ack: sp.fin_no_ack,
                winnuke: sp.winnuke,
                ping_death: sp.ping_death,
                teardrop: sp.teardrop,
                icmp_fragment: sp.icmp_fragment,
                syn_frag: sp.syn_frag,
                source_route: sp.source_route,
                icmp_flood_threshold: sp.icmp_flood_threshold,
                udp_flood_threshold: sp.udp_flood_threshold,
                syn_flood_threshold: sp.syn_flood_threshold,
                session_limit_src: sp.session_limit_src,
                session_limit_dst: sp.session_limit_dst,
                port_scan_threshold: sp.port_scan_threshold,
                ip_sweep_threshold: sp.ip_sweep_threshold,
            },
        );
    }
    profiles
}

fn build_cos_dscp_queue_table(
    classifier_name: &str,
    classifiers: &FastMap<String, CoSDSCPClassifierConfig>,
) -> [u8; 64] {
    let mut table = [u8::MAX; 64];
    if classifier_name.is_empty() {
        return table;
    }
    if let Some(classifier) = classifiers.get(classifier_name) {
        for (&dscp, &queue_id) in &classifier.queue_by_dscp {
            let idx = usize::from(dscp & 0x3f);
            table[idx] = queue_id;
        }
    }
    table
}

fn build_cos_ieee8021_queue_table(
    classifier_name: &str,
    classifiers: &FastMap<String, CoSIEEE8021ClassifierConfig>,
) -> [u8; 8] {
    let mut table = [u8::MAX; 8];
    if classifier_name.is_empty() {
        return table;
    }
    if let Some(classifier) = classifiers.get(classifier_name) {
        for (&pcp, &queue_id) in &classifier.queue_by_pcp {
            let idx = usize::from(pcp.min(7));
            table[idx] = queue_id;
        }
    }
    table
}

pub(super) fn build_forwarding_state(snapshot: &ConfigSnapshot) -> ForwardingState {
    let mut state = ForwardingState::default();
    let mut name_to_ifindex = BTreeMap::new();
    let mut linux_to_ifindex = BTreeMap::new();
    let mut mac_by_ifindex = BTreeMap::new();
    let (excluded_local_v4, excluded_local_v6) = nat_translated_local_exclusions(snapshot);

    for zone in &snapshot.zones {
        if zone.id == 0 || zone.name.is_empty() {
            continue;
        }
        // #919/#922: reserve the top of the u16 space for the
        // `JUNOS_GLOBAL_ZONE_ID` sentinel. Reject any snapshot that
        // would collide.
        if zone.id >= crate::policy::ZONE_ID_RESERVED_MIN {
            eprintln!(
                "xpf-userspace-dp: zone {:?} has reserved id {}; skipping (max usable id is {})",
                zone.name,
                zone.id,
                crate::policy::ZONE_ID_RESERVED_MIN - 1
            );
            continue;
        }
        // #919/#922: defense-in-depth. The event-stream codec writes
        // zone IDs as u8 (release builds elide the debug_assert). A
        // hostile or future malformed snapshot with id > 255 would
        // silently corrupt wire-level zone IDs without this gate.
        if zone.id > u8::MAX as u16 {
            eprintln!(
                "xpf-userspace-dp: zone {:?} has id {} > wire u8 max {}; skipping",
                zone.name,
                zone.id,
                u8::MAX
            );
            continue;
        }
        state.zone_name_to_id.insert(zone.name.clone(), zone.id);
        state.zone_id_to_name.insert(zone.id, zone.name.clone());
    }

    for endpoint in &snapshot.tunnel_endpoints {
        if endpoint.id == 0 || endpoint.ifindex <= 0 {
            continue;
        }
        let Ok(source) = endpoint.source.parse::<IpAddr>() else {
            continue;
        };
        let Ok(destination) = endpoint.destination.parse::<IpAddr>() else {
            continue;
        };
        let outer_family = match (endpoint.outer_family.as_str(), destination) {
            ("inet6", _) => libc::AF_INET6,
            ("inet", _) => libc::AF_INET,
            (_, IpAddr::V6(_)) => libc::AF_INET6,
            _ => libc::AF_INET,
        };
        let transport_table =
            canonical_route_table(&endpoint.transport_table, outer_family == libc::AF_INET6);
        state.tunnel_endpoints.insert(
            endpoint.id,
            TunnelEndpoint {
                id: endpoint.id,
                logical_ifindex: endpoint.ifindex,
                redundancy_group: endpoint.redundancy_group,
                mode: endpoint.mode.clone(),
                outer_family,
                source,
                destination,
                key: endpoint.key,
                ttl: endpoint.ttl.max(0) as u8,
                transport_table,
            },
        );
        state
            .tunnel_endpoint_by_ifindex
            .insert(endpoint.ifindex, endpoint.id);
    }

    for iface in &snapshot.interfaces {
        if iface.ifindex <= 0 {
            continue;
        }
        let label = if iface.linux_name.is_empty() {
            iface.name.clone()
        } else {
            iface.linux_name.clone()
        };
        state.ifindex_to_name.insert(iface.ifindex, label);
        state
            .ifindex_to_config_name
            .insert(iface.ifindex, iface.name.clone());
        name_to_ifindex.insert(iface.name.clone(), iface.ifindex);
        if !iface.linux_name.is_empty() {
            linux_to_ifindex.insert(iface.linux_name.clone(), iface.ifindex);
        }
        if !iface.zone.is_empty() {
            // #921: resolve zone NAME → u16 once at config build, so
            // every read on the hot path is one HashMap lookup
            // (ifindex → u16). Unknown / dropped zones map to 0 (the
            // canonical "unknown" sentinel).
            let zone_id = state
                .zone_name_to_id
                .get(&iface.zone)
                .copied()
                .unwrap_or(0);
            state.ifindex_to_zone_id.insert(iface.ifindex, zone_id);
            if iface.parent_ifindex > 0 {
                match state.ifindex_to_zone_id.get(&iface.parent_ifindex) {
                    Some(existing) if *existing != zone_id => {}
                    _ => {
                        state.ifindex_to_zone_id.insert(iface.parent_ifindex, zone_id);
                    }
                }
            }
        }
        if iface.tunnel {
            state.tunnel_interfaces.insert(iface.ifindex);
        }
        if let Some(mac) = parse_mac(&iface.hardware_addr) {
            mac_by_ifindex.insert(iface.ifindex, mac);
        }
        let tunnel_endpoint_id = state
            .tunnel_endpoint_by_ifindex
            .get(&iface.ifindex)
            .copied()
            .unwrap_or(0);
        for addr in &iface.addresses {
            let Ok(net) = addr.address.parse::<IpNet>() else {
                continue;
            };
            match net {
                IpNet::V4(v4) => {
                    if excluded_local_v4.contains(&v4.addr()) {
                        state.interface_nat_v4.insert(v4.addr(), iface.ifindex);
                    } else {
                        state.local_v4.insert(v4.addr());
                    }
                    state.connected_v4.push(ConnectedRouteV4 {
                        prefix: PrefixV4::from_net(v4),
                        ifindex: iface.ifindex,
                        tunnel_endpoint_id,
                    });
                }
                IpNet::V6(v6) => {
                    if excluded_local_v6.contains(&v6.addr()) {
                        state.interface_nat_v6.insert(v6.addr(), iface.ifindex);
                    } else {
                        state.local_v6.insert(v6.addr());
                    }
                    state.connected_v6.push(ConnectedRouteV6 {
                        prefix: PrefixV6::from_net(v6),
                        ifindex: iface.ifindex,
                        tunnel_endpoint_id,
                    });
                }
            }
        }
    }

    for iface in &snapshot.interfaces {
        if iface.ifindex <= 0 {
            continue;
        }
        let bind_ifindex = if iface.parent_ifindex > 0 {
            iface.parent_ifindex
        } else {
            iface.ifindex
        };
        let ingress_key = (bind_ifindex, iface.vlan_id.max(0) as u16);
        if iface.parent_ifindex > 0 {
            state
                .ingress_logical_ifindex
                .insert(ingress_key, iface.ifindex);
        } else {
            state
                .ingress_logical_ifindex
                .entry(ingress_key)
                .or_insert(iface.ifindex);
        }
        let src_mac = match parse_mac(&iface.hardware_addr)
            .or_else(|| mac_by_ifindex.get(&bind_ifindex).copied())
            .or_else(|| iface.tunnel.then_some([0; 6]))
        {
            Some(mac) => mac,
            None => continue,
        };
        // #921: resolve zone name → u16 at build time. 0 for
        // unknown / dropped zones (consistent with ifindex_to_zone_id).
        let zone_id = state.zone_name_to_id.get(&iface.zone).copied().unwrap_or(0);
        state.egress.insert(
            iface.ifindex,
            EgressInterface {
                bind_ifindex,
                vlan_id: iface.vlan_id.max(0) as u16,
                mtu: iface.mtu.max(0) as usize,
                src_mac,
                zone_id,
                redundancy_group: iface.redundancy_group,
                primary_v4: pick_interface_v4(iface),
                primary_v6: pick_interface_v6(iface),
            },
        );
    }

    state
        .connected_v4
        .sort_by(|a, b| b.prefix.prefix_len().cmp(&a.prefix.prefix_len()));
    state
        .connected_v6
        .sort_by(|a, b| b.prefix.prefix_len().cmp(&a.prefix.prefix_len()));

    for route in &snapshot.routes {
        if let Ok(prefix) = route.destination.parse::<Ipv4Net>() {
            let (next_hop, ifindex, tunnel_endpoint_id) =
                resolve_route_target_v4(route, &name_to_ifindex, &linux_to_ifindex, &state);
            let table = canonical_route_table(&route.table, false);
            state
                .routes_v4
                .entry(table)
                .or_default()
                .push(RouteEntryV4 {
                    prefix: PrefixV4::from_net(prefix),
                    ifindex,
                    tunnel_endpoint_id,
                    next_hop,
                    discard: route.discard,
                    next_table: route.next_table.clone(),
                });
            continue;
        }
        if let Ok(prefix) = route.destination.parse::<Ipv6Net>() {
            let (next_hop, ifindex, tunnel_endpoint_id) =
                resolve_route_target_v6(route, &name_to_ifindex, &linux_to_ifindex, &state);
            let table = canonical_route_table(&route.table, true);
            state
                .routes_v6
                .entry(table)
                .or_default()
                .push(RouteEntryV6 {
                    prefix: PrefixV6::from_net(prefix),
                    ifindex,
                    tunnel_endpoint_id,
                    next_hop,
                    discard: route.discard,
                    next_table: route.next_table.clone(),
                });
        }
    }
    for routes in state.routes_v4.values_mut() {
        routes.sort_by(|a, b| b.prefix.prefix_len().cmp(&a.prefix.prefix_len()));
    }
    for routes in state.routes_v6.values_mut() {
        routes.sort_by(|a, b| b.prefix.prefix_len().cmp(&a.prefix.prefix_len()));
    }

    for neigh in &snapshot.neighbors {
        if neigh.ifindex <= 0 || !neighbor_state_usable(&neigh.state) {
            continue;
        }
        let Ok(ip) = neigh.ip.parse::<IpAddr>() else {
            continue;
        };
        let Some(mac) = parse_mac(&neigh.mac) else {
            continue;
        };
        state
            .neighbors
            .insert((neigh.ifindex, ip), NeighborEntry { mac });
    }
    for fabric in &snapshot.fabrics {
        if fabric.parent_ifindex <= 0 {
            continue;
        }
        let Ok(peer_addr) = fabric.peer_address.parse::<IpAddr>() else {
            continue;
        };
        let local_mac = parse_mac(&fabric.local_mac)
            .or_else(|| mac_by_ifindex.get(&fabric.parent_ifindex).copied());
        let Some(local_mac) = local_mac else {
            continue;
        };
        let peer_mac = parse_mac(&fabric.peer_mac).or_else(|| {
            state
                .neighbors
                .get(&(fabric.overlay_ifindex, peer_addr))
                .or_else(|| state.neighbors.get(&(fabric.parent_ifindex, peer_addr)))
                .map(|entry| entry.mac)
        });
        let Some(peer_mac) = peer_mac else {
            continue;
        };
        state.fabrics.push(FabricLink {
            parent_ifindex: fabric.parent_ifindex,
            overlay_ifindex: fabric.overlay_ifindex,
            peer_addr,
            peer_mac,
            local_mac,
        });
    }
    state.policy = parse_policy_state(
        &snapshot.default_policy,
        &snapshot.policies,
        &state.zone_name_to_id,
    );
    state.allow_dns_reply = snapshot.flow.allow_dns_reply;
    state.allow_embedded_icmp = snapshot.flow.allow_embedded_icmp;
    state.session_timeouts = crate::session::SessionTimeouts::from_seconds(
        snapshot.flow.tcp_session_timeout,
        snapshot.flow.udp_session_timeout,
        snapshot.flow.icmp_session_timeout,
    );
    state.source_nat_rules = parse_source_nat_rules(&snapshot.source_nat_rules);
    state.static_nat = StaticNatTable::from_snapshots(&snapshot.static_nat_rules);
    state.dnat_table = DnatTable::from_snapshots(&snapshot.destination_nat_rules);
    state.nat64 = Nat64State::from_snapshots(&snapshot.nat64_rules);
    state.nptv6 = Nptv6State::from_snapshots(&snapshot.nptv6_rules);
    state.screen_profiles = build_screen_profiles(snapshot);
    state.tcp_mss_all_tcp = snapshot.flow.tcp_mss_all_tcp;
    state.tcp_mss_ipsec_vpn = snapshot.flow.tcp_mss_ipsec_vpn;
    state.tcp_mss_gre_in = snapshot.flow.tcp_mss_gre_in;
    state.tcp_mss_gre_out = snapshot.flow.tcp_mss_gre_out;
    // Build filter state from snapshot
    state.filter_state = crate::filter::parse_filter_state(
        &snapshot.filters,
        &snapshot.policers,
        &snapshot.interfaces,
        &snapshot.flow.lo0_filter_input_v4,
        &snapshot.flow.lo0_filter_input_v6,
    );
    state.cos = build_cos_state(snapshot);
    let has_cos_interfaces = !state.cos.interfaces.is_empty();
    state.tx_selection_enabled_v4 = has_cos_interfaces
        || state.filter_state.has_input_tx_selection_v4
        || state.filter_state.has_output_tx_selection_v4;
    state.tx_selection_enabled_v6 = has_cos_interfaces
        || state.filter_state.has_input_tx_selection_v6
        || state.filter_state.has_output_tx_selection_v6;
    // Build flow export config from snapshot
    state.flow_export_config = snapshot.flow_export.as_ref().and_then(|fe| {
        let addr = format!("{}:{}", fe.collector_address, fe.collector_port);
        addr.parse::<std::net::SocketAddr>().ok().map(|collector| {
            crate::flowexport::FlowExportConfig {
                collector,
                sampling_rate: fe.sampling_rate,
                active_timeout_secs: fe.active_timeout as u64,
                inactive_timeout_secs: fe.inactive_timeout as u64,
            }
        })
    });

    // Add static NAT external IPs as local delivery targets so inbound
    // traffic destined to external IPs is recognized by the firewall.
    for ext_ip in state.static_nat.external_ips() {
        match ext_ip {
            IpAddr::V4(v4) => {
                state.local_v4.insert(*v4);
            }
            IpAddr::V6(v6) => {
                state.local_v6.insert(*v6);
            }
        }
    }

    // Add DNAT destination IPs as local delivery targets so traffic
    // to those IPs is recognized as locally-destined and processed.
    for dst_ip in state.dnat_table.destination_ips() {
        match dst_ip {
            IpAddr::V4(v4) => {
                state.local_v4.insert(v4);
            }
            IpAddr::V6(v6) => {
                state.local_v6.insert(v6);
            }
        }
    }

    // Debug: dump zone mappings and policy rules
    #[cfg(feature = "debug-log")]
    {
        // #921: ifindex_to_zone_id is u16 — render with names via
        // zone_id_to_name for log readability.
        let ifindex_to_zone_named: Vec<(i32, &str)> = state
            .ifindex_to_zone_id
            .iter()
            .map(|(&ifidx, id)| {
                let name = state
                    .zone_id_to_name
                    .get(id)
                    .map(|s| s.as_str())
                    .unwrap_or("");
                (ifidx, name)
            })
            .collect();
        debug_log!("FWD_STATE: ifindex_to_zone={:?}", ifindex_to_zone_named);
        debug_log!(
            "FWD_STATE: egress keys={:?}",
            state.egress.keys().collect::<Vec<_>>()
        );
        for (ifidx, eg) in &state.egress {
            // #921: render eg.zone_id back to name for debug.
            let zone_name = state
                .zone_id_to_name
                .get(&eg.zone_id)
                .map(|s| s.as_str())
                .unwrap_or("");
            debug_log!(
                "FWD_STATE: egress[{}] bind={} zone={} vlan={} mtu={}",
                ifidx,
                eg.bind_ifindex,
                zone_name,
                eg.vlan_id,
                eg.mtu,
            );
        }
        debug_log!(
            "FWD_STATE: policy default={:?} rules={}",
            state.policy.default_action,
            state.policy.rules.len(),
        );
        for (i, rule) in state.policy.rules.iter().enumerate() {
            debug_log!(
                "FWD_STATE: policy[{}] {}->{}  action={:?} src_v4={} dst_v4={} apps={}",
                i,
                rule.from_zone,
                rule.to_zone,
                rule.action,
                rule.source_v4.prefix_count(),
                rule.destination_v4.prefix_count(),
                rule.applications.len(),
            );
        }
        debug_log!(
            "FWD_STATE: local_v4={:?} interface_nat_v4={:?}",
            state.local_v4,
            state.interface_nat_v4,
        );
        debug_log!(
            "FWD_STATE: snat_rules={} static_nat={} dnat_table={} nptv6={} connected_v4={} routes_v4={}",
            state.source_nat_rules.len(),
            if state.static_nat.is_empty() {
                0
            } else {
                state.static_nat.external_ips().count()
            },
            if state.dnat_table.is_empty() {
                0
            } else {
                state.dnat_table.destination_ips().count()
            },
            if state.nptv6.is_empty() {
                0
            } else {
                state.nptv6.external_prefixes().len()
            },
            state.connected_v4.len(),
            state.routes_v4.values().map(|v| v.len()).sum::<usize>(),
        );
    }

    // Install nftables rules to suppress kernel TCP RSTs from SNAT IPs.
    //
    // When the AF_XDP fill ring momentarily runs dry under high load,
    // the mlx5 driver falls back to the regular RX path. Those leaked
    // packets reach the kernel TCP stack which — having no matching
    // socket — sends RSTs to the server, killing the connection.
    // Blocking outgoing RSTs for SNAT-managed IPs is a targeted fix:
    // the DP handles all TCP state for those addresses.
    install_kernel_rst_suppression(&state);

    state
}

fn build_cos_state(snapshot: &ConfigSnapshot) -> CoSState {
    let Some(cos) = snapshot.class_of_service.as_ref() else {
        return CoSState::default();
    };

    let class_to_queue = cos
        .forwarding_classes
        .iter()
        .filter_map(|class| {
            if class.name.is_empty() || !(0..=u8::MAX as i32).contains(&class.queue) {
                return None;
            }
            Some((class.name.clone(), class.queue as u8))
        })
        .collect::<FastMap<_, _>>();
    let dscp_classifiers = cos
        .dscp_classifiers
        .iter()
        .filter(|classifier| !classifier.name.is_empty())
        .map(|classifier| {
            let mut queue_by_dscp = FastMap::default();
            for entry in &classifier.entries {
                if entry.forwarding_class.is_empty() {
                    continue;
                }
                let Some(queue_id) = class_to_queue.get(&entry.forwarding_class).copied() else {
                    continue;
                };
                for dscp in &entry.dscp_values {
                    queue_by_dscp.insert(*dscp, queue_id);
                }
            }
            (
                classifier.name.clone(),
                CoSDSCPClassifierConfig { queue_by_dscp },
            )
        })
        .collect::<FastMap<_, _>>();
    let ieee8021_classifiers = cos
        .ieee8021_classifiers
        .iter()
        .filter(|classifier| !classifier.name.is_empty())
        .map(|classifier| {
            let mut queue_by_pcp = FastMap::default();
            for entry in &classifier.entries {
                if entry.forwarding_class.is_empty() {
                    continue;
                }
                let Some(queue_id) = class_to_queue.get(&entry.forwarding_class).copied() else {
                    continue;
                };
                for pcp in &entry.code_points {
                    queue_by_pcp.insert(*pcp, queue_id);
                }
            }
            (
                classifier.name.clone(),
                CoSIEEE8021ClassifierConfig { queue_by_pcp },
            )
        })
        .collect::<FastMap<_, _>>();
    let dscp_rewrite_rules = cos
        .dscp_rewrite_rules
        .iter()
        .filter(|rewrite_rule| !rewrite_rule.name.is_empty())
        .map(|rewrite_rule| {
            let mut dscp_by_forwarding_class = FastMap::default();
            for entry in &rewrite_rule.entries {
                if entry.forwarding_class.is_empty() {
                    continue;
                }
                dscp_by_forwarding_class
                    .entry(entry.forwarding_class.clone())
                    .or_insert(entry.dscp_value);
            }
            (
                rewrite_rule.name.clone(),
                CoSDSCPRewriteRuleConfig {
                    dscp_by_forwarding_class,
                },
            )
        })
        .collect::<FastMap<_, _>>();

    let schedulers = cos
        .schedulers
        .iter()
        .filter(|sched| !sched.name.is_empty())
        .map(|sched| (sched.name.clone(), sched))
        .collect::<FastMap<_, _>>();
    let scheduler_maps = cos
        .scheduler_maps
        .iter()
        .filter(|sched_map| !sched_map.name.is_empty())
        .map(|sched_map| (sched_map.name.clone(), sched_map))
        .collect::<FastMap<_, _>>();

    let mut state = CoSState::default();
    for iface in &snapshot.interfaces {
        // Skip interfaces that do not contribute any usable CoS state.
        //
        // f0e364d7 (#916) removed the prior `shaping_rate == 0` skip so
        // that zero-shaping-rate-with-classes interfaces would get a
        // transparent-root CoS runtime instead of being silently dropped.
        // That side-effect added every interface that produced no usable
        // CoS state to `CoSState` too — and any `CoSState` entry triggers
        // the cross-binding redirect that funnels every TX through the
        // per-interface owner worker, collapsing 6-worker parallelism
        // to one CPU and capping reverse throughput at ~2 Gbps instead
        // of ~22 Gbps on the loss userspace cluster.
        //
        // The fix is to gate on whether the interface PRODUCES anything
        // useful — not on whether knob *names* are populated. We resolve
        // the scheduler-map, DSCP classifier, 802.1p classifier, and
        // DSCP rewrite-rule first, then only insert a `CoSState` entry
        // when at least one of these is true:
        //   - `cos_shaping_rate_bytes_per_sec > 0` (interface shaping cap)
        //   - the scheduler-map resolved to ≥ 1 queue
        //   - the DSCP classifier targets ≥ 1 queue_id this interface
        //     will materialize (real scheduler-map queues, or the
        //     synthetic default best-effort queue 0)
        //   - the 802.1p classifier targets ≥ 1 materialized queue_id
        //     (same materialization rule)
        //   - the DSCP rewrite-rule targets ≥ 1 materialized
        //     forwarding-class (real scheduler-map class, or synthetic
        //     "best-effort" if the rule has a "best-effort" entry)
        //
        // This cleanly handles every config shape that downstream falls
        // back to a synthetic default best-effort queue with no
        // classification/rewrite/rate cap — including:
        //   - forwarding-only (no CoS knobs at all)
        //   - burst-only without rate
        //     (`pkg/config/compiler_class_of_service.go:285-312` allows
        //     a committed snapshot of this shape; pre-f0e364d7 also
        //     skipped it via the rate-zero skip, so admitting it would
        //     be the divergence)
        //   - typo'd named references (e.g. `wan-mapp` vs `wan-map`)
        //     where the named entity does not exist
        //   - empty named entities (e.g. a scheduler-map declared with
        //     no entries — `compileClassOfService` keeps these)
        //   - scheduler-maps / classifiers whose entries all reference
        //     undefined forwarding-classes (warning-only configs that
        //     survive validation)
        //
        // f0e364d7's transparent-root runtime fast paths still apply
        // whenever at least one resolution produces real CoS state.
        if iface.ifindex <= 0 {
            continue;
        }
        let burst_bytes = if iface.cos_shaping_burst_bytes > 0 {
            iface.cos_shaping_burst_bytes
        } else {
            default_cos_burst_bytes(iface.cos_shaping_rate_bytes_per_sec)
        };
        let mut queues = Vec::new();
        let dscp_rewrite_rule = dscp_rewrite_rules.get(&iface.cos_dscp_rewrite_rule);
        if let Some(sched_map) = scheduler_maps.get(&iface.cos_scheduler_map) {
            for entry in &sched_map.entries {
                let Some(queue_id) = class_to_queue.get(&entry.forwarding_class).copied() else {
                    continue;
                };
                let scheduler = schedulers.get(&entry.scheduler).copied();
                let transmit_rate_bytes = scheduler
                    .map(|sched| sched.transmit_rate_bytes)
                    .filter(|rate| *rate > 0)
                    .unwrap_or(iface.cos_shaping_rate_bytes_per_sec);
                queues.push(CoSQueueConfig {
                    queue_id,
                    forwarding_class: entry.forwarding_class.clone(),
                    priority: cos_priority_rank(
                        scheduler
                            .map(|sched| sched.priority.as_str())
                            .unwrap_or("low"),
                    ),
                    transmit_rate_bytes,
                    exact: scheduler
                        .map(|sched| sched.transmit_rate_exact)
                        .unwrap_or(false),
                    surplus_weight: cos_surplus_weight(
                        transmit_rate_bytes.max(1),
                        iface.cos_shaping_rate_bytes_per_sec,
                    ),
                    buffer_bytes: scheduler
                        .map(|sched| sched.buffer_size_bytes)
                        .filter(|size| *size > 0)
                        .unwrap_or_else(|| default_cos_burst_bytes(transmit_rate_bytes)),
                    dscp_rewrite: dscp_rewrite_rule.and_then(|rewrite_rule| {
                        rewrite_rule
                            .dscp_by_forwarding_class
                            .get(&entry.forwarding_class)
                            .copied()
                    }),
                });
            }
        }
        let scheduler_map_resolved_to_queues = !queues.is_empty();

        // Determine the set of (queue_id, forwarding_class) pairs that this
        // interface will actually materialize at runtime. If the
        // scheduler-map resolved, those are the configured queues. If not,
        // the synthetic default best-effort queue (queue_id=0,
        // class="best-effort") is added later — but ONLY if we admit the
        // interface, so we model it here for the gate's purposes.
        let (iface_queue_ids, iface_classes): (Vec<u8>, Vec<&str>) =
            if scheduler_map_resolved_to_queues {
                (
                    queues.iter().map(|q| q.queue_id).collect(),
                    queues.iter().map(|q| q.forwarding_class.as_str()).collect(),
                )
            } else {
                (vec![0], vec!["best-effort"])
            };

        // A classifier arm contributes only if it maps at least one
        // DSCP/802.1p code-point to a queue_id the interface actually
        // materializes. A classifier mapping to queue 5 on an interface
        // that only has queue 0 admits the interface for nothing —
        // packets land in `resolve_cos_queue_idx` and get dropped, the
        // owner-worker redirect engages, and no observable classification
        // happens. Same logic for the rewrite-rule: it contributes only
        // if it has an entry for a forwarding-class the interface
        // materializes.
        let dscp_classifier_targets_iface_queue = dscp_classifiers
            .get(&iface.cos_dscp_classifier)
            .map(|c| {
                c.queue_by_dscp
                    .values()
                    .any(|q| iface_queue_ids.contains(q))
            })
            .unwrap_or(false);
        let ieee8021_classifier_targets_iface_queue = ieee8021_classifiers
            .get(&iface.cos_ieee8021_classifier)
            .map(|c| {
                c.queue_by_pcp
                    .values()
                    .any(|q| iface_queue_ids.contains(q))
            })
            .unwrap_or(false);
        let dscp_rewrite_targets_iface_class = dscp_rewrite_rule
            .map(|r| {
                r.dscp_by_forwarding_class
                    .keys()
                    .any(|fc| iface_classes.contains(&fc.as_str()))
            })
            .unwrap_or(false);

        // Post-build gate. See comment above for rationale.
        let contributes_usable_cos_state = iface.cos_shaping_rate_bytes_per_sec > 0
            || scheduler_map_resolved_to_queues
            || dscp_classifier_targets_iface_queue
            || ieee8021_classifier_targets_iface_queue
            || dscp_rewrite_targets_iface_class;
        if !contributes_usable_cos_state {
            continue;
        }
        let dscp_queue_by_dscp =
            build_cos_dscp_queue_table(&iface.cos_dscp_classifier, &dscp_classifiers);
        let ieee8021_queue_by_pcp =
            build_cos_ieee8021_queue_table(&iface.cos_ieee8021_classifier, &ieee8021_classifiers);

        if queues.is_empty() {
            queues.push(CoSQueueConfig {
                queue_id: 0,
                forwarding_class: "best-effort".to_string(),
                priority: cos_priority_rank("low"),
                transmit_rate_bytes: iface.cos_shaping_rate_bytes_per_sec,
                exact: false,
                surplus_weight: 1,
                buffer_bytes: burst_bytes,
                dscp_rewrite: dscp_rewrite_rule
                    .and_then(|rewrite_rule| {
                        rewrite_rule.dscp_by_forwarding_class.get("best-effort")
                    })
                    .copied(),
            });
        }
        queues.sort_by(|a, b| a.queue_id.cmp(&b.queue_id));
        let queue_by_forwarding_class = queues
            .iter()
            .map(|queue| (queue.forwarding_class.clone(), queue.queue_id))
            .collect::<FastMap<_, _>>();
        let default_queue = queues
            .iter()
            .find(|queue| queue.forwarding_class == "best-effort")
            .map(|queue| queue.queue_id)
            .unwrap_or_else(|| queues[0].queue_id);
        state.interfaces.insert(
            iface.ifindex,
            CoSInterfaceConfig {
                shaping_rate_bytes: iface.cos_shaping_rate_bytes_per_sec,
                burst_bytes,
                default_queue,
                dscp_classifier: iface.cos_dscp_classifier.clone(),
                ieee8021_classifier: iface.cos_ieee8021_classifier.clone(),
                dscp_queue_by_dscp,
                ieee8021_queue_by_pcp,
                queue_by_forwarding_class,
                queues,
            },
        );
    }

    state.dscp_classifiers = dscp_classifiers;
    state.ieee8021_classifiers = ieee8021_classifiers;
    state.dscp_rewrite_rules = dscp_rewrite_rules;

    state
}

fn default_cos_burst_bytes(rate_bytes: u64) -> u64 {
    rate_bytes
        .checked_div(100)
        .unwrap_or_default()
        .max(64 * 1500)
}

fn cos_surplus_weight(rate_bytes: u64, root_rate_bytes: u64) -> u32 {
    if rate_bytes == 0 || root_rate_bytes == 0 {
        return 1;
    }
    ((rate_bytes as u128) * 16)
        .div_ceil(root_rate_bytes as u128)
        .clamp(1, 16) as u32
}

fn cos_priority_rank(priority: &str) -> u8 {
    match priority {
        "strict-high" => 0,
        "high" => 1,
        "medium-high" => 2,
        "medium" => 3,
        "medium-low" => 4,
        _ => 5,
    }
}

pub(super) fn pick_interface_v4(iface: &InterfaceSnapshot) -> Option<Ipv4Addr> {
    let mut fallback = None;
    for addr in &iface.addresses {
        if addr.family != "inet" {
            continue;
        }
        let Ok(net) = addr.address.parse::<Ipv4Net>() else {
            continue;
        };
        let ip = net.addr();
        if fallback.is_none() {
            fallback = Some(ip);
        }
        if !ip.is_link_local() {
            return Some(ip);
        }
    }
    fallback
}

pub(super) fn pick_interface_v6(iface: &InterfaceSnapshot) -> Option<Ipv6Addr> {
    let mut fallback = None;
    for addr in &iface.addresses {
        if addr.family != "inet6" {
            continue;
        }
        let Ok(net) = addr.address.parse::<Ipv6Net>() else {
            continue;
        };
        let ip = net.addr();
        if fallback.is_none() {
            fallback = Some(ip);
        }
        if !ip.is_unicast_link_local() {
            return Some(ip);
        }
    }
    fallback
}

pub(super) fn resolve_route_target_v4(
    route: &RouteSnapshot,
    names: &BTreeMap<String, i32>,
    linux_names: &BTreeMap<String, i32>,
    state: &ForwardingState,
) -> (Option<Ipv4Addr>, i32, u16) {
    if route.discard || !route.next_table.is_empty() {
        return (None, 0, 0);
    }
    let Some((next_hop, interface)) = route
        .next_hops
        .first()
        .map(|nh| parse_route_next_hop(nh.as_str()))
    else {
        return (None, 0, 0);
    };
    let target = interface
        .as_deref()
        .and_then(|name| resolve_ifindex(name, names, linux_names))
        .map(|ifindex| {
            (
                ifindex,
                state
                    .tunnel_endpoint_by_ifindex
                    .get(&ifindex)
                    .copied()
                    .unwrap_or(0),
            )
        })
        .or_else(|| next_hop.and_then(|ip| infer_connected_route_target_v4(state, ip)));
    let (ifindex, tunnel_endpoint_id) = target.unwrap_or((0, 0));
    (next_hop, ifindex, tunnel_endpoint_id)
}

pub(super) fn resolve_route_target_v6(
    route: &RouteSnapshot,
    names: &BTreeMap<String, i32>,
    linux_names: &BTreeMap<String, i32>,
    state: &ForwardingState,
) -> (Option<Ipv6Addr>, i32, u16) {
    if route.discard || !route.next_table.is_empty() {
        return (None, 0, 0);
    }
    let Some((next_hop, interface)) = route
        .next_hops
        .first()
        .map(|nh| parse_route_next_hop_v6(nh.as_str()))
    else {
        return (None, 0, 0);
    };
    let target = interface
        .as_deref()
        .and_then(|name| resolve_ifindex(name, names, linux_names))
        .map(|ifindex| {
            (
                ifindex,
                state
                    .tunnel_endpoint_by_ifindex
                    .get(&ifindex)
                    .copied()
                    .unwrap_or(0),
            )
        })
        .or_else(|| next_hop.and_then(|ip| infer_connected_route_target_v6(state, ip)));
    let (ifindex, tunnel_endpoint_id) = target.unwrap_or((0, 0));
    (next_hop, ifindex, tunnel_endpoint_id)
}

pub(super) fn parse_route_next_hop(spec: &str) -> (Option<Ipv4Addr>, Option<String>) {
    let (ip_part, if_part) = if let Some((lhs, rhs)) = spec.split_once('@') {
        (lhs, rhs)
    } else {
        (spec, "")
    };
    let ip = if ip_part.is_empty() {
        None
    } else {
        ip_part.parse::<Ipv4Addr>().ok()
    };
    let iface = if if_part.is_empty() {
        None
    } else {
        Some(if_part.to_string())
    };
    (ip, iface)
}

pub(super) fn parse_route_next_hop_v6(spec: &str) -> (Option<Ipv6Addr>, Option<String>) {
    let (ip_part, if_part) = if let Some((lhs, rhs)) = spec.split_once('@') {
        (lhs, rhs)
    } else {
        (spec, "")
    };
    let ip = if ip_part.is_empty() {
        None
    } else {
        ip_part.parse::<Ipv6Addr>().ok()
    };
    let iface = if if_part.is_empty() {
        None
    } else {
        Some(if_part.to_string())
    };
    (ip, iface)
}

pub(super) fn resolve_ifindex(
    name: &str,
    names: &BTreeMap<String, i32>,
    linux_names: &BTreeMap<String, i32>,
) -> Option<i32> {
    names
        .get(name)
        .copied()
        .or_else(|| linux_names.get(name).copied())
}

pub(super) fn infer_connected_route_target_v4(
    state: &ForwardingState,
    ip: Ipv4Addr,
) -> Option<(i32, u16)> {
    state
        .connected_v4
        .iter()
        .find(|entry| entry.prefix.contains(ip))
        .map(|entry| (entry.ifindex, entry.tunnel_endpoint_id))
}

pub(super) fn infer_connected_route_target_v6(
    state: &ForwardingState,
    ip: Ipv6Addr,
) -> Option<(i32, u16)> {
    state
        .connected_v6
        .iter()
        .find(|entry| entry.prefix.contains(ip))
        .map(|entry| (entry.ifindex, entry.tunnel_endpoint_id))
}

#[cfg(test)]
#[path = "forwarding_build_tests.rs"]
mod tests;
