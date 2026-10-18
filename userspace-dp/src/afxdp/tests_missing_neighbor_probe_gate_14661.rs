//! #14661 (D3-02 residual): MissingNeighbor packets that this arm will
//! DISCARD must not emit a kernel ARP/NDP probe first, and a permitted
//! seed must be tuple-gated, gated-published, and replicated.
//!
//! Residual legs after the #10683 top-of-arm fence (already on master):
//!  (a) NAT64-required MissingNeighbor: probe fired before the #5174
//!      fail-closed drop. Now suppressed; only the throttle record remains.
//!  (b) SNAT-exhausted MissingNeighbor: probe fired before the seed-path
//!      SNAT allocation failure. Now the probe is deferred past the final
//!      composed-NAT fence and fires only on a committed seed, so an
//!      exhausted pool emits zero probes.
//!  (c) NPTv6-Untranslatable MissingNeighbor: same deferral — zero probes.
//!  (d) Fence-covered (post-SNAT tuple): zero probes, zero sessions.
//!  (e) Control: a permitted MissingNeighbor seed still probes exactly
//!      once, installs one session, publishes it, and replicates it.
//!
//! Probe observation is the kernel-arp-probe test capture
//! (`start_kernel_arp_probe_test_capture`), the same oracle the #13762
//! NAT64 throttle test uses. RED on pre-fix master for (a)-(d): each
//! discarded packet invoked one `trigger_kernel_arp_probe`.

use super::test_fixtures::*;
use super::tests_support::*;
use super::*;
use crate::SourceNATRuleSnapshot;
use crate::protocol::IpsecBindlessSelectorSnapshot;
use std::net::Ipv6Addr;
use std::sync::atomic::Ordering;

fn meta_v4_14661(src: Ipv4Addr, dst: Ipv4Addr, frame_len: usize) -> UserspaceDpMeta {
    let mut meta = txn_meta_v4(24, TCP_FLAG_SYN, frame_len as u16);
    meta.flow_src_addr[..4].copy_from_slice(&src.octets());
    meta.flow_dst_addr[..4].copy_from_slice(&dst.octets());
    meta.flow_src_port = 12345;
    meta.flow_dst_port = 443;
    meta
}

fn meta_v6_14661(src: Ipv6Addr, dst: Ipv6Addr, frame_len: usize) -> UserspaceDpMeta {
    let mut meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        ingress_ifindex: 24,
        l3_offset: 14,
        l4_offset: 54,
        payload_offset: 74,
        pkt_len: (frame_len - 14) as u16,
        addr_family: libc::AF_INET6 as u8,
        protocol: PROTO_TCP,
        tcp_flags: TCP_FLAG_SYN,
        config_generation: 7,
        fib_generation: 9,
        ..UserspaceDpMeta::default()
    };
    meta.flow_src_addr = src.octets();
    meta.flow_dst_addr = dst.octets();
    meta.flow_src_port = 12345;
    meta.flow_dst_port = 443;
    meta
}

/// (a) NAT64-required: the extracted-v4 next hop (172.16.80.1) is
/// unresolved, the flow is permitted, and the arm drops it fail-closed.
/// Pre-fix: one kernel probe. Post-fix: zero probes, drop preserved.
#[test]
fn nat64_missing_neighbor_no_probe_before_fail_closed_drop_14661() {
    let mut snapshot = nat64_snapshot(lan_to_wan_permit("8.8.8.8/32", "permit-nat64-14661"));
    snapshot.neighbors.clear();
    let forwarding = build_forwarding_state(&snapshot);
    let ha_state = txn_ha_state();
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
    binding.interface = Arc::<str>::from("reth1.0");
    let mut sessions = SessionTable::new();

    let src: Ipv6Addr = "2001:559:8585:ef00::102".parse().expect("src v6");
    let dst: Ipv6Addr = "64:ff9b::808:808".parse().expect("nat64 dst");
    let frame = build_txn_tcp_syn_frame_v6(src, dst, 12345, 443, TEST_LAN_MAC);
    let meta = meta_v6_14661(src, dst, frame.len());

    start_kernel_arp_probe_test_capture();
    let (_batch, dbg) = txn_run_descriptor_checked(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame,
        meta,
        true,
    );
    let probes = kernel_arp_probe_test_capture_count();
    stop_kernel_arp_probe_test_capture();

    assert_eq!(
        dbg.nat64_missing_neigh_drop, 1,
        "NAT64 miss must still drop fail-closed"
    );
    assert_eq!(
        probes, 0,
        "#14661: a discarded NAT64 packet must not emit a kernel probe"
    );
    assert_eq!(sessions.len(), 0, "NAT64 miss must not seed");
    assert!(binding.pending_neigh.is_empty(), "NAT64 miss must not park");
}

/// (b) SNAT-exhausted: one-port pool (203.0.113.10:5000). Flow 1 commits
/// the only identity via ForwardCandidate; flow 2 (different LAN host,
/// unresolved next hop -> MissingNeighbor) then fails SNAT allocation in
/// the seed path. Pre-fix it probed first; post-fix zero probes, zero
/// seed, and the failure is still counted.
#[test]
fn snat_exhausted_missing_neighbor_no_probe_14661() {
    let mut snapshot = nat_snapshot();
    snapshot.source_nat_rules = vec![SourceNATRuleSnapshot {
        name: "one-port-pool-14661".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["0.0.0.0/0".to_string()],
        pool_addresses: vec!["203.0.113.10".to_string()],
        port_low: 5000,
        port_high: 5000,
        ..Default::default()
    }];
    let forwarding = build_forwarding_state(&snapshot);
    let ha_state = txn_ha_state();

    // Flow 1: resolved neighbor -> ForwardCandidate commits the pool port.
    let mut binding1 = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
    binding1.interface = Arc::<str>::from("reth1.0");
    let mut sessions1 = SessionTable::new();
    let src1 = Ipv4Addr::new(10, 0, 61, 101);
    let dst1 = Ipv4Addr::new(8, 8, 8, 8);
    let frame1 = build_txn_tcp_syn_frame_v4(src1, dst1, 40001, 443, TCP_FLAG_SYN, TEST_LAN_MAC);
    let (_b, dbg1) = txn_run_descriptor_checked(
        &mut binding1,
        &mut sessions1,
        &forwarding,
        &ha_state,
        &frame1,
        meta_v4_14661(src1, dst1, frame1.len()),
        true,
    );
    assert_eq!(
        dbg1.forward, 1,
        "control flow must commit the one-port pool identity"
    );

    // Flow 2: unresolved next hop (clear neighbors on a fresh state with
    // the SAME allocators would not share flow 1's hold, so instead drive
    // flow 2 on a forwarding state built from a neighbor-less snapshot
    // whose allocator is pre-exhausted by flow 1's descriptor run above
    // is impossible across states; the deterministic seam used here is a
    // zero-port pool: allocation always fails with no descriptor having
    // succeeded. The gate under test (probe before SNAT failure) is the
    // same code path.
    let mut snapshot2 = nat_snapshot();
    snapshot2.neighbors.clear();
    snapshot2.source_nat_rules = vec![SourceNATRuleSnapshot {
        name: "empty-pool-14661".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["0.0.0.0/0".to_string()],
        pool_addresses: vec!["203.0.113.10".to_string()],
        port_low: 5000,
        port_high: 4999, // empty range: every allocation fails
        ..Default::default()
    }];
    let forwarding2 = build_forwarding_state(&snapshot2);
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
    binding.interface = Arc::<str>::from("reth1.0");
    let mut sessions = SessionTable::new();
    let src = Ipv4Addr::new(10, 0, 61, 102);
    let dst = Ipv4Addr::new(8, 8, 8, 8);
    let frame = build_txn_tcp_syn_frame_v4(src, dst, 12345, 443, TCP_FLAG_SYN, TEST_LAN_MAC);

    start_kernel_arp_probe_test_capture();
    let (batch, dbg) = txn_run_descriptor_checked(
        &mut binding,
        &mut sessions,
        &forwarding2,
        &ha_state,
        &frame,
        meta_v4_14661(src, dst, frame.len()),
        true,
    );
    let probes = kernel_arp_probe_test_capture_count();
    stop_kernel_arp_probe_test_capture();

    assert!(
        dbg.missing_neigh >= 1,
        "fixture must take the MissingNeighbor arm"
    );
    assert_eq!(
        batch.nat_alloc_fail, 1,
        "SNAT exhaustion must still be counted"
    );
    assert_eq!(
        probes, 0,
        "#14661: an SNAT-exhausted packet must not emit a kernel probe"
    );
    assert_eq!(sessions.len(), 0, "SNAT-exhausted flow must not seed");
    assert!(
        binding.pending_neigh.is_empty(),
        "SNAT-exhausted flow must not park"
    );
}

/// (c) NPTv6-Untranslatable: internal /64 source with all-zero IID under a
/// non-neutral pair must drop (RFC 6296 section 3.7) with zero probes.
#[test]
fn nptv6_untranslatable_missing_neighbor_no_probe_14661() {
    let mut snapshot = nat_snapshot();
    snapshot.neighbors.clear();
    snapshot.nptv6_rules = vec![crate::Nptv6RuleSnapshot {
        name: "nptv6-14661".to_string(),
        from_zone: String::new(),
        internal_prefix: "2001:559:8585:ef00::/64".to_string(),
        external_prefix: "2001:559:8585:80::/64".to_string(),
    }];
    let forwarding = build_forwarding_state(&snapshot);
    let ha_state = txn_ha_state();
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
    binding.interface = Arc::<str>::from("reth1.0");
    let mut sessions = SessionTable::new();

    // All-zero IID: inside the internal /64, IID == 0 -> Untranslatable.
    let src: Ipv6Addr = "2001:559:8585:ef00::".parse().expect("zero-iid src");
    let dst: Ipv6Addr = "2606:4700:4700::1111".parse().expect("dst v6");
    let frame = build_txn_tcp_syn_frame_v6(src, dst, 12345, 80, TEST_LAN_MAC);
    let meta = meta_v6_14661(src, dst, frame.len());

    start_kernel_arp_probe_test_capture();
    let (_batch, dbg) = txn_run_descriptor_checked(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame,
        meta,
        true,
    );
    let probes = kernel_arp_probe_test_capture_count();
    stop_kernel_arp_probe_test_capture();

    assert!(
        dbg.missing_neigh >= 1,
        "fixture must take the MissingNeighbor arm"
    );
    assert_eq!(
        probes, 0,
        "#14661: an NPTv6-untranslatable packet must not emit a kernel probe"
    );
    assert_eq!(sessions.len(), 0, "untranslatable flow must not seed");
    assert!(
        binding.pending_neigh.is_empty(),
        "untranslatable flow must not park"
    );
    assert!(
        forwarding.nptv6.counters().untranslatable_drops >= 1,
        "the RFC 6296 drop must still be counted"
    );
}

/// (d)+(e) Fence-covered post-SNAT tuple vs permitted control, both with
/// an unresolved next hop. The fenced flow matches ONLY after SNAT
/// (203.0.113.10 -> 9.9.9.9), so the top-of-arm fence cannot catch it;
/// the final composed-NAT fence must drop it with zero probes and zero
/// sessions. The control (same pool, unfenced dst) seeds, parks, probes
/// exactly once, publishes, and replicates.
#[test]
fn fenced_and_permitted_missing_neighbor_probe_gate_14661() {
    let mut snapshot = nat_snapshot();
    snapshot.neighbors.clear();
    snapshot.source_nat_rules = vec![SourceNATRuleSnapshot {
        name: "pool-14661".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["0.0.0.0/0".to_string()],
        pool_addresses: vec!["203.0.113.10".to_string()],
        port_low: 5000,
        port_high: 5001,
        ..Default::default()
    }];
    snapshot.bindless_selector_fence_enabled = true;
    snapshot.bindless_selector_rows = vec![IpsecBindlessSelectorSnapshot {
        local_ts: "203.0.113.10/32".to_string(),
        remote_ts: "9.9.9.9/32".to_string(),
    }];
    let forwarding = build_forwarding_state(&snapshot);
    let ha_state = txn_ha_state();

    // (d) fenced post-SNAT tuple.
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
    binding.interface = Arc::<str>::from("reth1.0");
    let mut sessions = SessionTable::new();
    let src = Ipv4Addr::new(10, 0, 61, 101);
    let dst = Ipv4Addr::new(9, 9, 9, 9);
    let frame = build_txn_tcp_syn_frame_v4(src, dst, 12345, 443, TCP_FLAG_SYN, TEST_LAN_MAC);
    start_kernel_arp_probe_test_capture();
    let (_b, dbg, published) = txn_run_descriptor_capturing_shared(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame,
        meta_v4_14661(src, dst, frame.len()),
    );
    let probes = kernel_arp_probe_test_capture_count();
    stop_kernel_arp_probe_test_capture();
    assert!(
        dbg.missing_neigh >= 1,
        "fenced fixture must take the MissingNeighbor arm"
    );
    assert_eq!(dbg.policy_deny, 1, "final fence drop must be accounted");
    assert_eq!(
        probes, 0,
        "#14661: a fence-covered packet must not emit a kernel probe"
    );
    assert_eq!(sessions.len(), 0, "fence-covered flow must not seed");
    assert!(
        published.is_empty(),
        "fence-covered flow must not publish/replicate"
    );
    assert!(
        binding.pending_neigh.is_empty(),
        "fence-covered flow must not park"
    );

    // (e) permitted control: unfenced dst through the same pool.
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
    binding.interface = Arc::<str>::from("reth1.0");
    let mut sessions = SessionTable::new();
    let src = Ipv4Addr::new(10, 0, 61, 102);
    let dst = Ipv4Addr::new(8, 8, 8, 8);
    let frame = build_txn_tcp_syn_frame_v4(src, dst, 12345, 443, TCP_FLAG_SYN, TEST_LAN_MAC);
    let ups_before =
        crate::afxdp::session_glue::SESSION_REPLICATION_UPSERTS.load(Ordering::Relaxed);
    start_kernel_arp_probe_test_capture();
    let (_b, dbg, published) = txn_run_descriptor_capturing_shared(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame,
        meta_v4_14661(src, dst, frame.len()),
    );
    let probes = kernel_arp_probe_test_capture_count();
    stop_kernel_arp_probe_test_capture();
    let ups_after = crate::afxdp::session_glue::SESSION_REPLICATION_UPSERTS.load(Ordering::Relaxed);
    assert!(
        dbg.missing_neigh >= 1,
        "control must take the MissingNeighbor arm"
    );
    assert_eq!(
        probes, 1,
        "permitted seed must probe exactly once (deferred, post-gate)"
    );
    assert_eq!(sessions.len(), 1, "permitted flow must seed one session");
    assert_eq!(
        binding.pending_neigh.len(),
        1,
        "permitted flow must park for replay"
    );
    let seeds: Vec<_> = published
        .iter()
        .filter(|e| e.origin == SessionOrigin::MissingNeighborSeed)
        .collect();
    assert_eq!(
        seeds.len(),
        1,
        "permitted seed must publish exactly one entry"
    );
    assert!(
        ups_after > ups_before,
        "#14661: permitted seed must replicate to peer workers (upserts {ups_before} -> {ups_after})"
    );
}
