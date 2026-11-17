//! #19171 cost benches, master vs the connected-owner derivation. Ignored; run
//! in release:
//! `cargo test --release --bins connected_owner_cost_bench -- --ignored --nocapture`.
//! They use only APIs present on master, so the same file measures both trees.
//! - **refresh-scan** (r24 P3-4): `handle_refresh_owner_rgs` over a realistic
//!   table (N LAN-client reverse rows and N routed rows), with the FIB honest and
//!   on the split node.
//! - **takeover-burst** (r24 addendum): per-call `reresolve_stored_session` for
//!   a stale forward hit to a peer-owned LAN server on the split node (the
//!   contradicted path), and for the same hit with the FIB honest.

use super::*;
use crate::afxdp::forwarding_build::build_forwarding_state;
use crate::afxdp::test_fixtures::nat_snapshot_with_fabric;

const NOW_SECS: u64 = 1_000;
const NOW_NS: u64 = NOW_SECS * 1_000_000_000;

fn rg(active: bool) -> HAGroupRuntime {
    if active {
        HAGroupRuntime {
            active: true,
            watchdog_timestamp: NOW_SECS,
            lease: HAGroupRuntime::active_lease_until(NOW_SECS, NOW_SECS),
        }
    } else {
        HAGroupRuntime {
            active: false,
            watchdog_timestamp: NOW_SECS,
            lease: HAForwardingLease::Inactive,
        }
    }
}

fn forwarding(withheld: bool) -> ForwardingState {
    let mut snapshot = nat_snapshot_with_fabric();
    if withheld {
        for iface in &mut snapshot.interfaces {
            if iface.name == "reth1.0" {
                iface.connected_rg_peer_owned = true;
            }
        }
    }
    build_forwarding_state(&snapshot)
}

fn metadata(state: &ForwardingState, is_reverse: bool, owner_rg_id: i32) -> SessionMetadata {
    SessionMetadata {
        forward_wire_alias_origin: false,
        ingress_zone: state.egress_zone_id(12),
        egress_zone: state.egress_zone_id(24),
        ingress_zone_check: 0,
        egress_zone_check: 0,
        ingress_ifindex: 12,
        ingress_vlan_id: 0,
        forward_ingress_vlan_id: None,
        owner_rg_id,
        fabric_ingress: false,
        is_reverse,
        nat64_reverse: None,
        log_session_init: false,
        log_session_close: false,
        policy_id: 0,
        inactivity_timeout_ns: None,
        policy_counter_idx: 0,
        policy_counter: None,
        nat_scope_ifindex: None,
    }
}

fn key(dst: Ipv4Addr, sport: u16, dport: u16) -> SessionKey {
    SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        src_ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9)),
        dst_ip: IpAddr::V4(dst),
        src_port: sport,
        dst_port: dport,
        discriminator: Default::default(),
        routing_domain: 0,
    }
}

fn pct(sorted: &[u64], p: f64) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    sorted[((sorted.len() as f64 - 1.0) * p).round() as usize]
}

#[test]
#[ignore = "#19171 cost bench: cargo test --release --bins connected_owner_cost_bench -- --ignored --nocapture"]
fn connected_owner_cost_bench_19171() {
    const ROWS: u16 = 10_000;
    let honest = forwarding(false);
    let neighbors = Arc::new(ShardedNeighborMap::new());
    for host in 2..=250u8 {
        neighbors.insert(
            (24, IpAddr::V4(Ipv4Addr::new(10, 0, 61, host))),
            crate::afxdp::types::NeighborEntry {
                mac: [0x02, 0, 0, 0, 0x61, host],
            },
        );
    }
    let split_ha = BTreeMap::from([(1, rg(true)), (2, rg(false))]);
    // refresh-scan
    for round in 0..3 {
        for (label, withheld) in [("honest", false), ("split", true)] {
            let state = forwarding(withheld);
            let mut sessions = SessionTable::new();
            for i in 0..ROWS {
                let lan = Ipv4Addr::new(10, 0, 61, (2 + (i % 249)) as u8);
                let lan_key = key(lan, 443, 10_000 + i);
                let lan_res = lookup_forwarding_resolution_with_dynamic_for_flow(
                    &honest,
                    &neighbors,
                    IpAddr::V4(lan),
                    &lan_key,
                )
                .resolution;
                let _ = sessions.install_with_protocol_with_origin(
                    lan_key,
                    SessionDecision {
                        resolution: lan_res,
                        nat: NatDecision::default(),
                        install_table_domain: 0,
                        install_table_check: 0,
                    },
                    metadata(&honest, true, 2),
                    SessionOrigin::ReverseFlow,
                    NOW_NS,
                    PROTO_TCP,
                    0x10,
                );
                let net = Ipv4Addr::new(203, 0, 113, (1 + (i % 250)) as u8);
                let net_key = key(net, 20_000 + i, 443);
                let net_res = lookup_forwarding_resolution_with_dynamic_for_flow(
                    &honest,
                    &neighbors,
                    IpAddr::V4(net),
                    &net_key,
                )
                .resolution;
                let _ = sessions.install_with_protocol_with_origin(
                    net_key,
                    SessionDecision {
                        resolution: net_res,
                        nat: NatDecision::default(),
                        install_table_domain: 0,
                        install_table_check: 0,
                    },
                    metadata(&honest, false, 1),
                    SessionOrigin::ForwardFlow,
                    NOW_NS,
                    PROTO_TCP,
                    0x10,
                );
            }
            let started = std::time::Instant::now();
            let _ = super::commands::handle_refresh_owner_rgs(
                &mut sessions,
                SteeringMap::unshared_for_test(-1),
                &state,
                &split_ha,
                &neighbors,
                vec![1],
                NOW_NS,
                NOW_SECS,
            );
            let us = started.elapsed().as_micros();
            eprintln!(
                "COST19171 bench=refresh-scan round={round} fib={label} rows={} total_us={us} ns_per_row={:.0}",
                u32::from(ROWS) * 2,
                us as f64 * 1000.0 / f64::from(u32::from(ROWS) * 2)
            );
        }
    }
    // takeover-burst
    const N: u32 = 200_000;
    let server = Ipv4Addr::new(10, 0, 61, 50);
    let fwd_key = key(server, 50_000, 443);
    let stored = SessionDecision {
        resolution: lookup_forwarding_resolution_with_dynamic_for_flow(
            &honest,
            &neighbors,
            IpAddr::V4(server),
            &fwd_key,
        )
        .resolution,
        nat: NatDecision::default(),
        install_table_domain: 0,
        install_table_check: 0,
    };
    let flow = SessionFlow {
        src_ip: fwd_key.src_ip,
        dst_ip: fwd_key.dst_ip,
        forward_key: fwd_key.clone(),
    };
    let target = resolution_target_for_session(&flow, stored);
    let arrival = FabricArrival::Packet {
        fabric_ingress: false,
        fabric_link_ingress: false,
        ingress_ifindex: 12,
        ha_startup_grace_until_secs: 0,
        fabric_adopted: false,
        adopted_recovery: None,
    };
    for round in 0..3 {
        for (label, withheld) in [("honest", false), ("split", true)] {
            let state = forwarding(withheld);
            let looked_up = lookup_forwarding_resolution_for_session_without_cache(
                &state, &neighbors, &flow, stored,
            )
            .resolution;
            let meta = metadata(&state, false, 2);
            let mut per = Vec::with_capacity(64);
            for _ in 0..64 {
                let started = std::time::Instant::now();
                for _ in 0..(N / 64) {
                    std::hint::black_box(reresolve_stored_session(
                        &state, &split_ha, &neighbors, NOW_SECS, &stored, &meta, &fwd_key, target,
                        looked_up, arrival,
                    ));
                }
                per.push(started.elapsed().as_nanos() as u64 / u64::from(N / 64));
            }
            per.sort_unstable();
            eprintln!(
                "COST19171 bench=takeover-burst round={round} fib={label} ns_per_call p50={} p90={} max={}",
                pct(&per, 0.5),
                pct(&per, 0.9),
                per.last().copied().unwrap_or(0)
            );
        }
    }
}
