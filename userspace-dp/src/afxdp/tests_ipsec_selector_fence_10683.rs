use super::test_fixtures::*;
use super::tests_support::*;
use super::*;
use crate::protocol::IpsecBindlessSelectorSnapshot;
use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use std::sync::Arc;

fn bindless_selector_forwarding_10683() -> ForwardingState {
    let mut snapshot = policy_deny_snapshot();
    snapshot.default_policy = "permit".to_string();
    snapshot.policies.clear();
    snapshot.neighbors = vec![frag_transit_wan_neighbor()];
    snapshot.bindless_selector_fence_enabled = true;
    snapshot.bindless_selector_rows = vec![IpsecBindlessSelectorSnapshot {
        local_ts: "10.0.61.0/24".to_string(),
        remote_ts: "172.16.80.0/24".to_string(),
    }];
    build_forwarding_state(&snapshot)
}

fn selector_meta_10683(src: Ipv4Addr, dst: Ipv4Addr, frame_len: usize) -> UserspaceDpMeta {
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
        flow_src_port: 33333,
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

#[test]
fn poll_drops_bindless_selector_with_no_sa_and_preserves_precision_10683() {
    let dst = Ipv4Addr::new(172, 16, 80, 200);
    for (label, src, want_forward, want_deny) in [
        (
            "matching-selector-no-sa",
            Ipv4Addr::new(10, 0, 61, 101),
            0,
            1,
        ),
        (
            "outside-local-selector",
            Ipv4Addr::new(10, 0, 62, 101),
            1,
            0,
        ),
    ] {
        let forwarding = bindless_selector_forwarding_10683();
        let mut binding = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
        binding.interface = Arc::<str>::from("reth1.0");
        let frame = build_txn_tcp_syn_frame_v4(src, dst, 33333, 443, TCP_FLAG_SYN, TEST_LAN_MAC);
        let meta = selector_meta_10683(src, dst, frame.len());
        let mut sessions = SessionTable::new();
        let ha_state = BTreeMap::new();

        let (batch, dbg) = txn_run_descriptor_checked(
            &mut binding,
            &mut sessions,
            &forwarding,
            &ha_state,
            &frame,
            meta,
            true,
        );
        assert_eq!(dbg.rx, 1, "{label}: descriptor must reach poll");
        assert_eq!(batch.validated_packets, 1, "{label}: packet must validate");
        assert_eq!(dbg.forward, want_forward, "{label}: forward count");
        assert_eq!(
            dbg.policy_deny, want_deny,
            "{label}: selector-fence drop count"
        );
        assert_eq!(
            batch.transit_ipsec_fence_drops, want_deny as u64,
            "{label}: #15941 fence counter must track the drop"
        );
    }
}

/// #15954 site 6 (common-tail selector fence): a flowless non-first
/// fragment has no session flow, so it never passes the install-time
/// fence gates (pre-NAT, post-NAT, NoRoute, MissingNeighbor seed); the
/// ONLY fence that can refuse it is the common tail at
/// poll_descriptor/mod.rs (`bindless_selector_match`). A permitted
/// flowless fragment whose tuple matches the bindless selector must be
/// dropped there with `transit_ipsec_fence_drops == 1` and no session.
/// Removing the tail increment turns this RED (counter stays 0 while
/// the drop still happens via `dbg.policy_deny`).
#[test]
fn poll_tail_selector_fence_counts_flowless_fragment_15954() {
    let mut snapshot = policy_deny_snapshot();
    snapshot.default_policy = "permit".to_string();
    snapshot.policies = vec![crate::PolicyRuleSnapshot {
        name: "permit-lan-wan".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["any".to_string()],
        destination_addresses: vec!["any".to_string()],
        applications: vec!["any".to_string()],
        action: "permit".to_string(),
        ..Default::default()
    }];
    snapshot.neighbors = vec![frag_transit_wan_neighbor()];
    snapshot.bindless_selector_fence_enabled = true;
    // frag_v4_transit_frame: src 10.0.61.100 -> dst 172.16.80.200.
    snapshot.bindless_selector_rows = vec![IpsecBindlessSelectorSnapshot {
        local_ts: "10.0.61.0/24".to_string(),
        remote_ts: "172.16.80.0/24".to_string(),
    }];
    let forwarding = build_forwarding_state(&snapshot);
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
    binding.interface = Arc::<str>::from("reth1.0");
    let mut sessions = SessionTable::new();
    let ha_state = BTreeMap::new();
    let frame = frag_v4_transit_frame(TEST_LAN_MAC);
    let (batch, dbg, reasons) = txn_run_descriptor_capturing_exceptions(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame,
        frag_v4_transit_meta(),
    );
    assert_eq!(batch.validated_packets, 1, "fragment must reach validation");
    assert_eq!(dbg.rx, 1, "descriptor must reach poll");
    assert_eq!(dbg.forward, 0, "tail-fenced fragment must not forward");
    assert_eq!(
        batch.transit_ipsec_fence_drops, 1,
        "#15954 common-tail fence site must increment transit_ipsec_fence_drops"
    );
    assert_eq!(
        sessions.len(),
        0,
        "tail-fenced fragment must install no session"
    );
    let _ = reasons;
}
