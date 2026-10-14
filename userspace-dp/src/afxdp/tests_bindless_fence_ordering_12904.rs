// #12904: the bind-less IPsec selector fence (#10683) must drop matching
// transit BEFORE any state is published or any pool resource is consumed,
// and must also refuse the NoRoute kernel slow-path delegation. On master
// the fence runs only at the poll tail — after the forward/reverse session
// install, BPF/shared publication and peer replication — and the NoRoute arm
// reinjects fenced frames to the kernel FIB outright.

use super::test_fixtures::*;
use super::tests_support::*;
use super::*;
use crate::SourceNATRuleSnapshot;
use crate::protocol::IpsecBindlessSelectorSnapshot;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::sync::atomic::Ordering;

/// #12904 publication fixture: lan (reth1.0/ifindex 24) → wan
/// (reth0.80/ifindex 12, default route over a reachable neighbor),
/// permit-all policy, and a ONE-PORT pool-mode SNAT rule
/// (203.0.113.10:5000-5000) so any committed forward flow consumes the only
/// translated identity the pool owns. Selector rows:
/// - row 1 (10.0.61.0/24 ↔ 8.8.8.0/24) covers the ORIGINAL tuple of flow A
///   (10.0.61.101 → 8.8.8.8): the fence must fire BEFORE allocation.
/// - row 2 (9.9.9.0/24 ↔ 203.0.113.0/24) covers ONLY the post-SNAT tuple of
///   flow C (10.0.61.103 → 9.9.9.9 leaves as 203.0.113.10 → 9.9.9.9): the
///   fence must fire AFTER allocation, with the just-reserved pool identity
///   rolled back.
fn fenced_publication_snapshot_12904() -> ConfigSnapshot {
    let mut snapshot = nat_snapshot();
    snapshot.source_nat_rules = vec![SourceNATRuleSnapshot {
        name: "one-port-pool".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["0.0.0.0/0".to_string()],
        pool_addresses: vec!["203.0.113.10".to_string()],
        port_low: 5000,
        port_high: 5000,
        ..Default::default()
    }];
    snapshot.bindless_selector_fence_enabled = true;
    snapshot.bindless_selector_rows = vec![
        IpsecBindlessSelectorSnapshot {
            local_ts: "10.0.61.0/24".to_string(),
            remote_ts: "8.8.8.0/24".to_string(),
        },
        IpsecBindlessSelectorSnapshot {
            local_ts: "9.9.9.0/24".to_string(),
            remote_ts: "203.0.113.0/24".to_string(),
        },
    ];
    snapshot
}

/// #12904 NoRoute fixture: same lan/wan topology but NO inet route, so the
/// selector-covered destination resolves NoRoute. Default-permit with no
/// policies keeps #7480 from refusing the frame for an unrelated reason, and
/// no SNAT rules exist so the #10679 untranslated-NAT reinject suppression
/// cannot mask the delegation either: the ONLY thing that may stop this
/// frame from reaching the kernel slow path is the selector fence.
fn fenced_noroute_snapshot_12904() -> ConfigSnapshot {
    let mut snapshot = nat_snapshot();
    snapshot.routes.retain(|route| route.family != "inet");
    snapshot.default_policy = "permit".to_string();
    snapshot.policies.clear();
    snapshot.source_nat_rules.clear();
    snapshot.bindless_selector_fence_enabled = true;
    snapshot.bindless_selector_rows = vec![IpsecBindlessSelectorSnapshot {
        local_ts: "10.0.61.0/24".to_string(),
        remote_ts: "192.0.2.0/24".to_string(),
    }];
    snapshot
}

fn selector_meta_12904(src: Ipv4Addr, dst: Ipv4Addr, frame_len: usize) -> UserspaceDpMeta {
    let mut meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        ingress_ifindex: 24,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        pkt_len: frame_len as u16,
        l3_offset: 14,
        l4_offset: 34,
        flow_src_port: 40000,
        flow_dst_port: 443,
        tcp_flags: TCP_FLAG_SYN,
        config_generation: 7,
        fib_generation: 9,
        ..UserspaceDpMeta::default()
    };
    meta.flow_src_addr[..4].copy_from_slice(&src.octets());
    meta.flow_dst_addr[..4].copy_from_slice(&dst.octets());
    meta
}

/// #12904 main regression: a fenced session MISS must not install a session,
/// publish one into the shared (replicated) session map, or leave a pool
/// identity held. On master the fence sits at the poll tail, so both flows
/// first run the full install/publication/replication pipeline and the
/// one-port pool stays consumed by the ghost.
#[test]
fn fenced_miss_publishes_no_session_and_holds_no_pool_identity_12904() {
    let forwarding = build_forwarding_state(&fenced_publication_snapshot_12904());
    let ha_state = txn_ha_state();

    struct Case {
        label: &'static str,
        src: Ipv4Addr,
        dst: Ipv4Addr,
        src_port: u16,
    }
    let cases = [
        // (A) original-tuple match: fence must fire BEFORE allocation.
        Case {
            label: "original-tuple-match",
            src: Ipv4Addr::new(10, 0, 61, 101),
            dst: Ipv4Addr::new(8, 8, 8, 8),
            src_port: 40001,
        },
        // (C) post-SNAT-only match: fence must fire AFTER allocation and
        // roll the just-reserved translation back.
        Case {
            label: "post-snat-tuple-match",
            src: Ipv4Addr::new(10, 0, 61, 103),
            dst: Ipv4Addr::new(9, 9, 9, 9),
            src_port: 40003,
        },
    ];
    for case in cases {
        let mut binding = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
        binding.interface = Arc::<str>::from("reth1.0");
        let mut sessions = SessionTable::new();
        let frame = build_txn_tcp_syn_frame_v4(
            case.src,
            case.dst,
            case.src_port,
            443,
            TCP_FLAG_SYN,
            TEST_LAN_MAC,
        );
        let meta = selector_meta_12904(case.src, case.dst, frame.len());
        let (batch, dbg, published) = txn_run_descriptor_capturing_shared(
            &mut binding,
            &mut sessions,
            &forwarding,
            &ha_state,
            &frame,
            meta,
        );
        assert_eq!(
            batch.validated_packets, 1,
            "{}: packet must reach validation",
            case.label,
        );
        assert_eq!(dbg.rx, 1, "{}: descriptor must reach poll", case.label);
        assert_eq!(
            dbg.forward, 0,
            "{}: fenced transit must never forward",
            case.label,
        );
        assert_eq!(
            dbg.policy_deny, 1,
            "{}: the selector-fence drop must be accounted",
            case.label,
        );
        assert_eq!(
            sessions.len(),
            0,
            "{}: a fenced miss must not install the forward/reverse session pair \
             (ghost session left behind by the tail-only fence)",
            case.label,
        );
        assert!(
            published.is_empty(),
            "{}: a fenced miss must not publish/replicate any session entry, got {:?}",
            case.label,
            published,
        );
    }

    // NAT-pool accounting unchanged: after both fenced flows, the pool's
    // single translated identity must still be free for an UNFENCED flow.
    // On master the two ghosts hold the only pool port, so this control flow
    // dies in SNAT exhaustion instead of forwarding.
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
    binding.interface = Arc::<str>::from("reth1.0");
    let mut sessions = SessionTable::new();
    let control_src = Ipv4Addr::new(10, 0, 61, 102);
    let control_dst = Ipv4Addr::new(1, 1, 1, 1);
    let frame = build_txn_tcp_syn_frame_v4(
        control_src,
        control_dst,
        40002,
        443,
        TCP_FLAG_SYN,
        TEST_LAN_MAC,
    );
    let meta = selector_meta_12904(control_src, control_dst, frame.len());
    let (_batch, dbg) = txn_run_descriptor_checked(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame,
        meta,
        true,
    );
    assert_eq!(
        dbg.forward, 1,
        "the one-port pool identity must still be committable by an unfenced flow \
         (fenced flows leaked a hold)",
    );
}

/// #12904 NoRoute regression: a selector-fenced frame that misses the FIB
/// must never be delegated to the kernel slow path. On master the NoRoute arm
/// reinjects the permitted frame (the driver has no reinjector, so the
/// attempt is visible as a slow-path drop + exception), and there is no
/// selector fence anywhere on that path.
#[test]
fn fenced_noroute_frame_is_never_delegated_to_kernel_slow_path_12904() {
    let forwarding = build_forwarding_state(&fenced_noroute_snapshot_12904());
    let ha_state = txn_ha_state();
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
    binding.interface = Arc::<str>::from("reth1.0");
    let mut sessions = SessionTable::new();
    let src = Ipv4Addr::new(10, 0, 61, 101);
    let dst = Ipv4Addr::new(192, 0, 2, 1);
    let frame = build_txn_tcp_syn_frame_v4(src, dst, 40000, 443, TCP_FLAG_SYN, TEST_LAN_MAC);
    let meta = selector_meta_12904(src, dst, frame.len());
    let (batch, dbg) = txn_run_descriptor_checked(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame,
        meta,
        true,
    );
    assert_eq!(batch.validated_packets, 1, "packet must reach validation");
    assert_eq!(dbg.rx, 1, "descriptor must reach poll");
    assert_eq!(dbg.forward, 0, "a fenced NoRoute frame must never forward");
    assert_eq!(
        dbg.policy_deny, 1,
        "the selector-fence refusal of the NoRoute delegation must be accounted",
    );
    assert_eq!(
        binding.live.slow_path_drops.load(Ordering::Relaxed),
        0,
        "a selector-fenced NoRoute frame must never be handed to the kernel \
         slow path (master reinjects it: the steerable cleartext bypass)",
    );
    assert_eq!(
        sessions.len(),
        0,
        "a fenced NoRoute miss must not install sessions",
    );
}
