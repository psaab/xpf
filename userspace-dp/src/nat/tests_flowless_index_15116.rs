// #15116 (A77-01): flowless NAT possibility probes must not linearly scan
// the whole static/DNAT tables per packet. RED/GREEN ratio + correctness.
#![allow(unused_imports)]

use super::destination::DnatTable;
use super::static_nat::StaticNatTable;
use super::*;
use crate::NatPortRangeWire;
use crate::{DestinationNATRuleSnapshot, StaticNATRuleSnapshot};
use std::net::IpAddr;
use std::time::Instant;

fn dst(i: u32) -> IpAddr {
    IpAddr::V4(std::net::Ipv4Addr::from(0xCB00_7100u32 + i)) // 203.0.113.x-ish base + i (wraps octets naturally)
}

fn pool(i: u32) -> String {
    format!("192.168.{}.{}", (i >> 8) & 0xff, i & 0xff)
}

fn dnat_table_n(n: u32) -> DnatTable {
    let snaps: Vec<DestinationNATRuleSnapshot> = (0..n)
        .map(|i| DestinationNATRuleSnapshot {
            name: format!("r{i}"),
            destination_address: dst(i).to_string(),
            destination_port: 443,
            protocol: "tcp".to_string(),
            pool_address: pool(i),
            pool_port: 8443,
            match_source_ports: vec![NatPortRangeWire { low: 1024, high: 65535 }],
            ..DestinationNATRuleSnapshot::default()
        })
        .collect();
    DnatTable::from_snapshots(&snaps, &NatCounterStore::default())
}

fn static_table_n(n: u32) -> StaticNatTable {
    let snaps: Vec<StaticNATRuleSnapshot> = (0..n)
        .map(|i| StaticNATRuleSnapshot {
            name: format!("s{i}"),
            external_ip: dst(i).to_string(),
            internal_ip: pool(i),
            match_destination_port: 443,
            mapped_port: 8443,
            ..StaticNATRuleSnapshot::default()
        })
        .collect();
    StaticNatTable::from_snapshots(&snaps, &NatCounterStore::default())
}

fn time_n<F: FnMut()>(mut f: F, iters: usize) -> std::time::Duration {
    // warmup
    for _ in 0..200 { f(); }
    let t = Instant::now();
    for _ in 0..iters { f(); }
    t.elapsed()
}

#[test]
fn flowless_probes_do_not_scale_with_table_size_15116() {
    let src: IpAddr = "198.51.100.1".parse().unwrap();
    let miss: IpAddr = "198.51.100.99".parse().unwrap(); // not any rule dst
    let small_d = dnat_table_n(10);
    let large_d = dnat_table_n(10_000);
    let small_s = static_table_n(10);
    let large_s = static_table_n(10_000);

    // Correctness controls: hit on last rule, miss elsewhere (both tables).
    assert!(large_d.flowless_l4_translation_possible(crate::ip_proto::PROTO_TCP, src, dst(9999), "", "", "", None),
        "DNAT L4 rule on last of 10k must be possible");
    assert!(!large_d.flowless_l4_translation_possible(crate::ip_proto::PROTO_TCP, src, miss, "", "", "", None));
    assert!(large_s.flowless_l4_dnat_translation_possible(crate::ip_proto::PROTO_TCP, src, dst(9999), "", "", ""));
    assert!(large_s.flowless_non_tcp_udp_port_map_possible(Some(253), src, dst(9999), "", "", ""));
    assert!(large_d.flowless_non_tcp_udp_port_map_possible(None, src, dst(9999), "", "", ""), "unknown wire protocol keeps every DNAT tier possible");
    assert!(!large_s.flowless_l4_dnat_translation_possible(crate::ip_proto::PROTO_TCP, src, miss, "", "", ""));

    let iters = 2_000usize;
    // Best-of-3 to damp noise; compare per-call.
    let mut best = |small: &dyn Fn() -> bool, large: &dyn Fn() -> bool| -> (f64, f64) {
        let mut bs = f64::MAX; let mut bl = f64::MAX;
        for _ in 0..3 {
            let s = time_n(|| { std::hint::black_box(small()); }, iters).as_nanos() as f64 / iters as f64;
            let l = time_n(|| { std::hint::black_box(large()); }, iters).as_nanos() as f64 / iters as f64;
            bs = bs.min(s); bl = bl.min(l);
        }
        (bs, bl)
    };
    let (s1, l1) = best(&|| small_d.flowless_l4_translation_possible(crate::ip_proto::PROTO_TCP, src, miss, "", "", "", None),
                        &|| large_d.flowless_l4_translation_possible(crate::ip_proto::PROTO_TCP, src, miss, "", "", "", None));
    let (s2, l2) = best(&|| small_s.flowless_l4_dnat_translation_possible(crate::ip_proto::PROTO_TCP, src, miss, "", "", ""),
                        &|| large_s.flowless_l4_dnat_translation_possible(crate::ip_proto::PROTO_TCP, src, miss, "", "", ""));
    let (s3, l3) = best(&|| small_d.flowless_non_tcp_udp_port_map_possible(Some(253), src, miss, "", "", ""),
                        &|| large_d.flowless_non_tcp_udp_port_map_possible(Some(253), src, miss, "", "", ""));
    let (s4, l4) = best(&|| small_s.flowless_non_tcp_udp_port_map_possible(Some(253), src, miss, "", "", ""),
                        &|| large_s.flowless_non_tcp_udp_port_map_possible(Some(253), src, miss, "", "", ""));
    eprintln!("15116 ratios: dnat_l4 {l1:.0}/{s1:.0}={:.2} static_l4 {l2:.0}/{s2:.0}={:.2} dnat_portmap {l3:.0}/{s3:.0}={:.2} static_portmap {l4:.0}/{s4:.0}={:.2}", l1/s1.max(1.0), l2/s2.max(1.0), l3/s3.max(1.0), l4/s4.max(1.0));
    for (name, s, l) in [("dnat_l4", s1, l1), ("static_l4", s2, l2), ("dnat_portmap", s3, l3), ("static_portmap", s4, l4)] {
        assert!(l < 2.0 * s.max(20.0) + 100.0, "{name}: 10k/10 ratio must be <2x (small {s:.0}ns large {l:.0}ns ratio {:.2})", l / s.max(1.0));
    }
}
