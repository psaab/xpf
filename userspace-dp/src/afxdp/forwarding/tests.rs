use super::super::forwarding_build::*;
use super::super::test_fixtures::*;
use super::*;
use crate::event_stream::DataplaneEventRateLimitConfig;
use crate::event_stream::codec::DataplaneEventKind;
use crate::nat::SourceNatFailureReason;
use crate::test_zone_ids::*;
use crate::{
    FabricSnapshot, InterfaceAddressSnapshot, NeighborSnapshot, PolicyRuleSnapshot, RouteSnapshot,
    SourceNATRuleSnapshot, ZoneSnapshot,
};

fn active_ha_runtime(now_secs: u64) -> HAGroupRuntime {
    HAGroupRuntime {
        active: true,
        watchdog_timestamp: now_secs,
        lease: HAGroupRuntime::active_lease_until(now_secs, now_secs),
    }
}

fn inactive_ha_runtime(watchdog_timestamp: u64) -> HAGroupRuntime {
    HAGroupRuntime {
        active: false,
        watchdog_timestamp,
        lease: HAForwardingLease::Inactive,
    }
}

#[test]
fn metadata_classification_accepts_matching_generations() {
    let validation = ValidationState {
        snapshot_installed: true,
        config_generation: 11,
        fib_generation: 7,
    };
    assert_eq!(
        classify_metadata(valid_meta(), validation),
        PacketDisposition::Valid
    );
}

#[test]
fn metadata_classification_rejects_generation_mismatch() {
    let validation = ValidationState {
        snapshot_installed: true,
        config_generation: 22,
        fib_generation: 9,
    };
    assert_eq!(
        classify_metadata(valid_meta(), validation),
        PacketDisposition::ConfigGenerationMismatch
    );
    let validation = ValidationState {
        snapshot_installed: true,
        config_generation: 11,
        fib_generation: 9,
    };
    assert_eq!(
        classify_metadata(valid_meta(), validation),
        PacketDisposition::FibGenerationMismatch
    );
}

#[test]
fn metadata_classification_rejects_unknown_address_family() {
    let validation = ValidationState {
        snapshot_installed: true,
        config_generation: 11,
        fib_generation: 7,
    };
    let mut meta = valid_meta();
    meta.addr_family = 0;
    assert_eq!(
        classify_metadata(meta, validation),
        PacketDisposition::UnsupportedPacket
    );
}
#[test]
fn ha_resolution_blocks_inactive_owner_rg() {
    let state = build_forwarding_state(&nat_snapshot());
    let ha_state = Arc::new(ArcSwap::from_pointee(BTreeMap::from([(
        1,
        inactive_ha_runtime(monotonic_nanos() / 1_000_000_000),
    )])));
    let resolved = enforce_ha_resolution(
        &state,
        &ha_state,
        lookup_forwarding_resolution(&state, IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
    );
    assert_eq!(resolved.disposition, ForwardingDisposition::HAInactive);
}

#[test]
fn ha_resolution_allows_fresh_active_owner_rg() {
    let state = build_forwarding_state(&nat_snapshot());
    let ha_state = Arc::new(ArcSwap::from_pointee(BTreeMap::from([(
        1,
        active_ha_runtime(monotonic_nanos() / 1_000_000_000),
    )])));
    let resolved = enforce_ha_resolution(
        &state,
        &ha_state,
        lookup_forwarding_resolution(&state, IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
    );
    assert_eq!(
        resolved.disposition,
        ForwardingDisposition::ForwardCandidate
    );
}

#[test]
fn cached_flow_decision_invalidates_when_owner_rg_is_demoted() {
    let state = build_forwarding_state(&nat_snapshot());
    let active = BTreeMap::from([(1, active_ha_runtime(monotonic_nanos() / 1_000_000_000))]);
    let demoted = BTreeMap::from([(1, inactive_ha_runtime(monotonic_nanos() / 1_000_000_000))]);
    let resolution = lookup_forwarding_resolution(&state, IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
    let now_secs = monotonic_nanos() / 1_000_000_000;
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());

    assert!(cached_flow_decision_valid(
        &state,
        &active,
        &dynamic_neighbors,
        now_secs,
        1,
        false,
        IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
        resolution
    ));
    assert!(!cached_flow_decision_valid(
        &state,
        &demoted,
        &dynamic_neighbors,
        now_secs,
        1,
        false,
        IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
        resolution
    ));
}

#[test]
fn cached_flow_decision_invalidates_fabric_redirect_on_fabric_ingress_when_local_owner_active() {
    let state = build_forwarding_state(&nat_snapshot_with_fabric());
    let now_secs = monotonic_nanos() / 1_000_000_000;
    let ha_state = BTreeMap::from([(1, active_ha_runtime(now_secs))]);
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
    let resolution = resolve_fabric_redirect(&state).expect("fabric redirect");

    assert!(!cached_flow_decision_valid(
        &state,
        &ha_state,
        &dynamic_neighbors,
        now_secs,
        1,
        true,
        IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
        resolution
    ));
}

#[test]
fn cached_flow_decision_invalidates_fabric_redirect_on_non_fabric_ingress_when_local_owner_active()
{
    let state = build_forwarding_state(&nat_snapshot_with_fabric());
    let now_secs = monotonic_nanos() / 1_000_000_000;
    let ha_state = BTreeMap::from([(1, active_ha_runtime(now_secs))]);
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
    let resolution = resolve_fabric_redirect(&state).expect("fabric redirect");

    assert!(!cached_flow_decision_valid(
        &state,
        &ha_state,
        &dynamic_neighbors,
        now_secs,
        1,
        false,
        IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
        resolution
    ));
}

#[test]
fn cached_flow_decision_keeps_fabric_redirect_on_fabric_ingress_when_local_owner_inactive() {
    let state = build_forwarding_state(&nat_snapshot_with_fabric());
    let now_secs = monotonic_nanos() / 1_000_000_000;
    let ha_state = BTreeMap::from([(1, inactive_ha_runtime(now_secs))]);
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
    let resolution = resolve_fabric_redirect(&state).expect("fabric redirect");

    assert!(cached_flow_decision_valid(
        &state,
        &ha_state,
        &dynamic_neighbors,
        now_secs,
        1,
        true,
        IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
        resolution
    ));
}

#[test]
fn cached_flow_decision_keeps_fabric_redirect_on_non_fabric_ingress_when_local_owner_inactive() {
    let state = build_forwarding_state(&nat_snapshot_with_fabric());
    let now_secs = monotonic_nanos() / 1_000_000_000;
    let ha_state = BTreeMap::from([(1, inactive_ha_runtime(now_secs))]);
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
    let resolution = resolve_fabric_redirect(&state).expect("fabric redirect");

    assert!(cached_flow_decision_valid(
        &state,
        &ha_state,
        &dynamic_neighbors,
        now_secs,
        1,
        false,
        IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
        resolution
    ));
}

#[test]
fn cached_local_delivery_decision_invalidates_when_owner_rg_is_demoted() {
    let state = build_forwarding_state(&nat_snapshot());
    let active = BTreeMap::from([(1, active_ha_runtime(monotonic_nanos() / 1_000_000_000))]);
    let demoted = BTreeMap::from([(1, inactive_ha_runtime(monotonic_nanos() / 1_000_000_000))]);
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
    let resolution = interface_nat_local_resolution(&state, "172.16.80.8".parse().expect("v4"))
        .expect("interface nat local delivery");
    let now_secs = monotonic_nanos() / 1_000_000_000;

    assert!(cached_flow_decision_valid(
        &state,
        &active,
        &dynamic_neighbors,
        now_secs,
        1,
        false,
        IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8)),
        resolution
    ));
    assert!(!cached_flow_decision_valid(
        &state,
        &demoted,
        &dynamic_neighbors,
        now_secs,
        1,
        false,
        IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8)),
        resolution
    ));
}

#[test]
fn inactive_owner_rg_redirects_established_session_to_fabric() {
    let state = build_forwarding_state(&nat_snapshot_with_fabric());
    let ha_state = Arc::new(ArcSwap::from_pointee(BTreeMap::from([(
        1,
        inactive_ha_runtime(monotonic_nanos() / 1_000_000_000),
    )])));
    let blocked = enforce_ha_resolution(
        &state,
        &ha_state,
        lookup_forwarding_resolution(&state, IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
    );
    assert_eq!(blocked.disposition, ForwardingDisposition::HAInactive);
    let redirected = redirect_via_fabric_if_needed(&state, blocked, 24);
    assert_eq!(
        redirected.disposition,
        ForwardingDisposition::FabricRedirect
    );
    assert_eq!(redirected.egress_ifindex, 21);
    assert_eq!(redirected.tx_ifindex, 21);
    assert_eq!(
        redirected.next_hop,
        Some(IpAddr::V4(Ipv4Addr::new(10, 99, 13, 2)))
    );
    assert_eq!(
        redirected.neighbor_mac,
        Some([0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee])
    );
    assert_eq!(
        redirected.src_mac,
        Some([0x02, 0xbf, 0x72, 0xff, 0x00, 0x01])
    );
}

#[test]
fn inactive_owner_missing_neighbor_redirects_to_fabric() {
    let mut snapshot = nat_snapshot_with_fabric();
    snapshot
        .neighbors
        .retain(|neighbor| neighbor.ip != "172.16.80.1");
    let state = build_forwarding_state(&snapshot);
    let ha_state = Arc::new(ArcSwap::from_pointee(BTreeMap::from([(
        1,
        inactive_ha_runtime(monotonic_nanos() / 1_000_000_000),
    )])));
    let blocked = enforce_ha_resolution(
        &state,
        &ha_state,
        lookup_forwarding_resolution(&state, IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
    );
    assert_eq!(blocked.disposition, ForwardingDisposition::HAInactive);
    let redirected = redirect_via_fabric_if_needed(&state, blocked, 24);
    assert_eq!(
        redirected.disposition,
        ForwardingDisposition::FabricRedirect
    );
    assert_eq!(redirected.egress_ifindex, 21);
    assert_eq!(redirected.tx_ifindex, 21);
    assert_eq!(
        redirected.next_hop,
        Some(IpAddr::V4(Ipv4Addr::new(10, 99, 13, 2)))
    );
}

#[test]
fn fabric_ingress_prefers_local_active_owner_resolution_over_fabric_redirect() {
    let state = build_forwarding_state(&nat_snapshot_with_fabric());
    let now_secs = monotonic_nanos() / 1_000_000_000;
    let ha_state = BTreeMap::from([(1, active_ha_runtime(now_secs))]);
    let redirected = resolve_fabric_redirect(&state).expect("fabric redirect");
    let preferred = prefer_local_forward_candidate_for_fabric_ingress(
        &state,
        &ha_state,
        &Default::default(),
        now_secs,
        true,
        IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
        redirected,
    );
    assert_eq!(
        preferred.disposition,
        ForwardingDisposition::ForwardCandidate
    );
    assert_eq!(preferred.egress_ifindex, 12);
    assert_eq!(owner_rg_for_resolution(&state, preferred), 1);
}

#[test]
fn build_forwarding_state_uses_fabric_snapshot_macs_without_parent_interface() {
    let mut snapshot = nat_snapshot();
    snapshot.fabrics = vec![FabricSnapshot {
        parent_unbindable: false,
        name: "fab0".to_string(),
        parent_interface: "ge-0/0/0".to_string(),
        parent_linux_name: "ge-0-0-0".to_string(),
        parent_ifindex: 21,
        overlay_linux_name: "fab0".to_string(),
        overlay_ifindex: 101,
        rx_queues: 2,
        peer_address: "10.99.13.2".to_string(),
        local_mac: "02:bf:72:ff:00:01".to_string(),
        peer_mac: "00:aa:bb:cc:dd:ee".to_string(),
        up: true,
    }];
    let state = build_forwarding_state(&snapshot);
    let redirect = resolve_fabric_redirect(&state).expect("fabric redirect");
    assert_eq!(redirect.egress_ifindex, 21);
    assert_eq!(redirect.tx_ifindex, 21);
    assert_eq!(
        redirect.neighbor_mac,
        Some([0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee])
    );
    assert_eq!(redirect.src_mac, Some([0x02, 0xbf, 0x72, 0xff, 0x00, 0x01]));
}

#[test]
fn zone_encoded_fabric_redirect_preserves_ingress_zone() {
    let state = build_forwarding_state(&nat_snapshot_with_fabric());
    let redirected =
        resolve_zone_encoded_fabric_redirect_by_id(&state, TEST_LAN_ZONE_ID)
        .expect("zone-encoded redirect");
    assert_eq!(
        redirected.disposition,
        ForwardingDisposition::FabricRedirect
    );
    assert_eq!(redirected.egress_ifindex, 21);
    assert_eq!(redirected.tx_ifindex, 21);
    assert_eq!(
        redirected.src_mac,
        Some([0x02, 0xbf, 0x72, FABRIC_ZONE_MAC_MAGIC, 0x00, 0x01])
    );
}

// #3075 fail-on-revert: the synthetic fabric zone-encoded src MAC must carry a
// stable name-hash zone id > 255 across BOTH trailing MAC bytes (big-endian).
// The old u8 scheme hardcoded MAC[4]=0x00 and rejected ids > 255 (returning
// None / dropping the redirect), so the common-case hashed id failed fabric
// cross-chassis forwarding. Reverting either the encode (forwarding/mod.rs) or
// the decode (frame/inspect.rs) makes this RED.
#[test]
fn zone_encoded_fabric_redirect_round_trips_zone_id_above_255() {
    let mut state = build_forwarding_state(&nat_snapshot_with_fabric());
    let zone_id: u16 = 300; // 0x012c — above the old u8 cap
    state.zone_id_to_name.insert(zone_id, "highzone".into());
    // #6458: a configured high-id zone is RG-bound (a reth member), so the
    // stamp validation finds it in `zone_to_rgs`.
    state.zone_to_rgs.insert(zone_id, vec![2]);

    // Encode: the src MAC carries 300 as 02:bf:72:fe:01:2c.
    let redirected = resolve_zone_encoded_fabric_redirect_by_id(&state, zone_id)
        .expect("fabric redirect must resolve for a zone id > 255");
    assert_eq!(
        redirected.src_mac,
        Some([0x02, 0xbf, 0x72, FABRIC_ZONE_MAC_MAGIC, 0x01, 0x2c])
    );

    // Decode: the same MAC parses back to 300. #6458: the frame must be
    // unicast to the fabric link's local MAC and the claimed zone's RG (2)
    // must not be forwarding-active locally — an empty ha_state satisfies
    // both here.
    let mut frame = vec![0u8; 64];
    frame[0..6].copy_from_slice(&[0x02, 0xbf, 0x72, 0xff, 0x00, 0x01]);
    frame[6..12].copy_from_slice(&[0x02, 0xbf, 0x72, FABRIC_ZONE_MAC_MAGIC, 0x01, 0x2c]);
    let mut area = MmapArea::new(4096).expect("mmap");
    area.slice_mut(0, frame.len())
        .expect("slice")
        .copy_from_slice(&frame);
    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        ingress_ifindex: 21,
        ..UserspaceDpMeta::default()
    };
    assert_eq!(
        parse_zone_encoded_fabric_ingress(
            &area,
            XdpDesc {
                addr: 0,
                len: frame.len() as u32,
                options: 0,
            },
            meta,
            &state,
            &BTreeMap::new(),
            0,
        ),
        Some(zone_id)
    );
}

#[test]
fn parse_zone_encoded_fabric_ingress_uses_zone_override() {
    let state = build_forwarding_state(&nat_snapshot_with_fabric());
    let mut frame = vec![0u8; 64];
    // #6458: the legitimate stamp is unicast to the fabric link's local MAC
    // (02:bf:72:ff:00:01 on ifindex 21 in this fixture).
    frame[0..6].copy_from_slice(&[0x02, 0xbf, 0x72, 0xff, 0x00, 0x01]);
    frame[6..12].copy_from_slice(&[0x02, 0xbf, 0x72, FABRIC_ZONE_MAC_MAGIC, 0x00, 0x01]);
    let mut area = MmapArea::new(4096).expect("mmap");
    area.slice_mut(0, frame.len())
        .expect("slice")
        .copy_from_slice(&frame);
    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        ingress_ifindex: 21,
        ..UserspaceDpMeta::default()
    };
    assert_eq!(
        parse_zone_encoded_fabric_ingress(
            &area,
            XdpDesc {
                addr: 0,
                len: frame.len() as u32,
                options: 0,
            },
            meta,
            &state,
            // The lan zone's RG (2) is NOT forwarding-active locally (empty
            // ha_state) — the split-RG shape the stamp exists for.
            &BTreeMap::new(),
            0,
        ),
        Some(TEST_LAN_ZONE_ID)
    );
}

// #6458 fail-on-revert: a zone-encoded stamp addressed to something OTHER
// than the fabric link's own local MAC is not a peer redirect — the
// legitimate sender always unicasts to `FabricLink.local_mac`. Before the
// fix the decode ignored the destination MAC entirely and returned
// `Some(zone)` for this frame (magic + zone-exists only).
#[test]
fn zone_encoded_fabric_stamp_rejected_on_non_unicast_dst_6458() {
    let state = build_forwarding_state(&nat_snapshot_with_fabric());
    let mut frame = vec![0u8; 64];
    // dst = all-zero (a spray / off-target frame), NOT 02:bf:72:ff:00:01.
    frame[6..12].copy_from_slice(&[0x02, 0xbf, 0x72, FABRIC_ZONE_MAC_MAGIC, 0x00, 0x01]);
    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        ingress_ifindex: 21,
        ..UserspaceDpMeta::default()
    };
    assert_eq!(
        parse_zone_encoded_fabric_ingress_from_frame(frame.as_slice(), meta, &state, &BTreeMap::new(), 0),
        None,
        "stamp with a non-fabric destination MAC must be ignored"
    );
}

// #6458 fail-on-revert: the claimed zone's RG is forwarding-active LOCALLY
// — on this node `lan` (RG 2) traffic ingresses directly, so the peer has
// no business stamping it. This is the single-primary-node case that
// rejects EVERY stamp on the RG owner. Before the fix the decode returned
// `Some(lan)` and the attacker picked the ingress zone.
#[test]
fn zone_encoded_fabric_stamp_rejected_when_claimed_zone_rg_local_6458() {
    let state = build_forwarding_state(&nat_snapshot_with_fabric());
    let now_secs = monotonic_nanos() / 1_000_000_000;
    let ha_state = BTreeMap::from([(2, active_ha_runtime(now_secs))]);
    let mut frame = vec![0u8; 64];
    frame[0..6].copy_from_slice(&[0x02, 0xbf, 0x72, 0xff, 0x00, 0x01]);
    frame[6..12].copy_from_slice(&[0x02, 0xbf, 0x72, FABRIC_ZONE_MAC_MAGIC, 0x00, 0x01]);
    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        ingress_ifindex: 21,
        ..UserspaceDpMeta::default()
    };
    assert_eq!(
        parse_zone_encoded_fabric_ingress_from_frame(frame.as_slice(), meta, &state, &ha_state, now_secs),
        None,
        "stamp claiming a locally-primary zone must be ignored"
    );
}

// #6458 fail-on-revert: a zone with NO RG-bound member interfaces
// (mgmt/fxp0, control/em0+fab, or an empty zone) can never be legitimately
// stamped — node-specific traffic is never punted across the fabric. This
// kills the host-inbound variant's `mgmt` claim. Before the fix any
// configured zone name hashed to an accepted id.
#[test]
fn zone_encoded_fabric_stamp_rejected_for_zone_without_rg_members_6458() {
    let mut state = build_forwarding_state(&nat_snapshot_with_fabric());
    let mgmt_id: u16 = 9;
    state.zone_id_to_name.insert(mgmt_id, "mgmt".into());
    // No zone_to_rgs entry: mgmt has no RG-bound members.
    let mut frame = vec![0u8; 64];
    frame[0..6].copy_from_slice(&[0x02, 0xbf, 0x72, 0xff, 0x00, 0x01]);
    frame[6..12].copy_from_slice(&[0x02, 0xbf, 0x72, FABRIC_ZONE_MAC_MAGIC, 0x00, 0x09]);
    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        ingress_ifindex: 21,
        ..UserspaceDpMeta::default()
    };
    assert_eq!(
        parse_zone_encoded_fabric_ingress_from_frame(frame.as_slice(), meta, &state, &BTreeMap::new(), 0),
        None,
        "stamp claiming a zone with no RG-bound members must be ignored"
    );
}

// #6458 preservation pin: the legitimate split-RG shape — claimed zone
// `lan` (RG 2) is NOT forwarding-active locally while a DIFFERENT RG (1)
// is — plus the unicast fabric dst MAC — keeps the override working.
#[test]
fn zone_encoded_fabric_stamp_honored_for_remote_rg_zone_6458() {
    let state = build_forwarding_state(&nat_snapshot_with_fabric());
    let now_secs = monotonic_nanos() / 1_000_000_000;
    let ha_state = BTreeMap::from([(1, active_ha_runtime(now_secs))]);
    let mut frame = vec![0u8; 64];
    frame[0..6].copy_from_slice(&[0x02, 0xbf, 0x72, 0xff, 0x00, 0x01]);
    frame[6..12].copy_from_slice(&[0x02, 0xbf, 0x72, FABRIC_ZONE_MAC_MAGIC, 0x00, 0x01]);
    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        ingress_ifindex: 21,
        ..UserspaceDpMeta::default()
    };
    assert_eq!(
        parse_zone_encoded_fabric_ingress_from_frame(frame.as_slice(), meta, &state, &ha_state, now_secs),
        Some(TEST_LAN_ZONE_ID),
        "legitimate split-RG stamp must keep working"
    );
}

// #6458 (review fold) preservation pin — the multi-RG-zone refinement. A
// zone spanning TWO redundancy groups (reth1.0→RG2 + reth2.0→RG1, both
// `lan`) on a split-RG node: one bound RG locally active, one peer-active.
// V1b must ACCEPT the legitimate punt stamp (the NONE-active form
// over-rejected this shape and default-denied active/active new flows).
// The kill is preserved only when EVERY bound RG is locally active (the
// single-primary posture for a multi-RG zone).
#[test]
fn zone_encoded_fabric_stamp_honored_for_multi_rg_zone_split_6458() {
    let mut state = build_forwarding_state(&nat_snapshot_with_fabric());
    let now_secs = monotonic_nanos() / 1_000_000_000;
    // lan spans RG 1 and RG 2 in this fixture mutation.
    state.zone_to_rgs.insert(TEST_LAN_ZONE_ID, vec![1, 2]);
    let mut frame = vec![0u8; 64];
    frame[0..6].copy_from_slice(&[0x02, 0xbf, 0x72, 0xff, 0x00, 0x01]);
    frame[6..12].copy_from_slice(&[0x02, 0xbf, 0x72, FABRIC_ZONE_MAC_MAGIC, 0x00, 0x01]);
    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        ingress_ifindex: 21,
        ..UserspaceDpMeta::default()
    };
    // Split node: RG 1 locally active, RG 2 peer-active → accept (the
    // peer owns part of the zone and legitimately punts its flows).
    let split = BTreeMap::from([
        (1, active_ha_runtime(now_secs)),
        (2, inactive_ha_runtime(now_secs)),
    ]);
    assert_eq!(
        parse_zone_encoded_fabric_ingress_from_frame(frame.as_slice(), meta, &state, &split, now_secs),
        Some(TEST_LAN_ZONE_ID),
        "multi-RG zone with a peer-active RG must keep the legitimate stamp"
    );
    // Every bound RG locally active → reject (the kill shape).
    let all_local = BTreeMap::from([
        (1, active_ha_runtime(now_secs)),
        (2, active_ha_runtime(now_secs)),
    ]);
    assert_eq!(
        parse_zone_encoded_fabric_ingress_from_frame(frame.as_slice(), meta, &state, &all_local, now_secs),
        None,
        "multi-RG zone with every RG locally active must still reject the stamp"
    );
}

// #6458 fail-on-revert (V2 owner binding): a validated stamp drives
// NEW-flow zone-pair policy only when the resolution's owner RG is
// forwarding-active locally. The egress in this fixture is reth0.80
// (ifindex 12, RG 1). Before the fix there was no gate — the override
// passed straight through.
#[test]
fn gate_fabric_zone_override_on_owner_rg_6458() {
    let state = build_forwarding_state(&nat_snapshot_with_fabric());
    let now_secs = monotonic_nanos() / 1_000_000_000;
    let resolution = ForwardingResolution {
        disposition: ForwardingDisposition::ForwardCandidate,
        local_ifindex: 0,
        egress_ifindex: 12,
        tx_ifindex: 12,
        tunnel_endpoint_id: 0,
        next_hop: None,
        neighbor_mac: None,
        src_mac: None,
        tx_vlan_id: 0,
    };
    // Owner RG (1) locally active -> honored (legitimate punt).
    let active = BTreeMap::from([(1, active_ha_runtime(now_secs))]);
    assert_eq!(
        gate_fabric_zone_override_on_owner_rg(
            &state,
            &active,
            now_secs,
            Some(TEST_LAN_ZONE_ID),
            resolution,
        ),
        Some(TEST_LAN_ZONE_ID)
    );
    // Owner RG present but NOT forwarding-active -> stripped (backup node).
    let inactive = BTreeMap::from([(1, inactive_ha_runtime(now_secs))]);
    assert_eq!(
        gate_fabric_zone_override_on_owner_rg(
            &state,
            &inactive,
            now_secs,
            Some(TEST_LAN_ZONE_ID),
            resolution,
        ),
        None
    );
    // Owner RG absent from ha_state (startup window / not local) -> stripped.
    assert_eq!(
        gate_fabric_zone_override_on_owner_rg(
            &state,
            &BTreeMap::new(),
            now_secs,
            Some(TEST_LAN_ZONE_ID),
            resolution,
        ),
        None
    );
    // No stamp -> None in, None out.
    assert_eq!(
        gate_fabric_zone_override_on_owner_rg(&state, &active, now_secs, None, resolution),
        None
    );
}

// #6458 (review fold) fail-on-revert: the HOST-DESTINED (Stage-11 IKE)
// variant of the V2 owner binding. A stamped zone drives host-inbound
// admission for a local address only when THAT address's owner RG is
// forwarding-active locally — on a single-primary backup a forged stamp to
// the backup's reth address (172.16.80.8 on reth0.80, RG 1 in this fixture)
// is stripped, so the forged NEW IKE initiation degrades to the fabric
// zone (default-deny) instead of seeding the #6471 live-exchange table.
#[test]
fn gate_fabric_zone_override_on_local_owner_rg_6458() {
    let state = build_forwarding_state(&nat_snapshot_with_fabric());
    let now_secs = monotonic_nanos() / 1_000_000_000;
    let reth_addr = IpAddr::V4(std::net::Ipv4Addr::new(172, 16, 80, 8));
    // The fixture maps the local address to its interface's RG.
    let owner = owner_rg_for_local_address(&state, reth_addr);
    assert_eq!(owner, 1, "reth0.80's primary address must resolve to RG 1");
    // Owner RG (1) locally active -> honored (legitimate punt of a
    // host-inbound flow we own).
    let active = BTreeMap::from([(1, active_ha_runtime(now_secs))]);
    assert_eq!(
        gate_fabric_zone_override_on_local_owner_rg(
            &state,
            &active,
            now_secs,
            Some(TEST_LAN_ZONE_ID),
            reth_addr,
        ),
        Some(TEST_LAN_ZONE_ID)
    );
    // Owner RG NOT forwarding-active (single-primary backup) -> stripped:
    // the forged stamped IKE initiation falls to the fabric zone.
    let inactive = BTreeMap::from([(1, inactive_ha_runtime(now_secs))]);
    assert_eq!(
        gate_fabric_zone_override_on_local_owner_rg(
            &state,
            &inactive,
            now_secs,
            Some(TEST_LAN_ZONE_ID),
            reth_addr,
        ),
        None
    );
    // A destination with no RG-bound owning interface (owner 0 — e.g. the
    // fabric peer address or an lo0 address) -> stripped, never trusted.
    let no_rg_dst = IpAddr::V4(std::net::Ipv4Addr::new(10, 99, 13, 1));
    assert_eq!(owner_rg_for_local_address(&state, no_rg_dst), 0);
    assert_eq!(
        gate_fabric_zone_override_on_local_owner_rg(
            &state,
            &active,
            now_secs,
            Some(TEST_LAN_ZONE_ID),
            no_rg_dst,
        ),
        None
    );
    // No stamp -> None in, None out.
    assert_eq!(
        gate_fabric_zone_override_on_local_owner_rg(&state, &active, now_secs, None, reth_addr),
        None
    );
}

// #6458: the zone -> RG-bound-member map drives the RG-binding check. The
// fixture's lan (reth1.0, RG 2) and wan (reth0.80, RG 1) zones map to
// their single RGs; the fabric parent (ge-0/0/0, RG 0, unzoned here)
// contributes nothing.
#[test]
fn zone_to_rgs_built_from_member_redundancy_groups_6458() {
    let state = build_forwarding_state(&nat_snapshot_with_fabric());
    assert_eq!(state.zone_to_rgs.get(&TEST_LAN_ZONE_ID), Some(&vec![2]));
    assert_eq!(state.zone_to_rgs.get(&TEST_WAN_ZONE_ID), Some(&vec![1]));
    assert!(
        state.zone_to_rgs.len() == 2,
        "only RG-bound zones are mapped: {:?}",
        state.zone_to_rgs
    );
}

#[test]
fn zone_encoded_fabric_ingress_skips_dynamic_neighbor_learning() {
    let state = build_forwarding_state(&nat_snapshot_with_fabric());
    let mut frame = vec![0u8; 64];
    frame[6..12].copy_from_slice(&[0x02, 0xbf, 0x72, FABRIC_ZONE_MAC_MAGIC, 0x00, 0x01]);
    let mut area = MmapArea::new(4096).expect("mmap");
    area.slice_mut(0, frame.len())
        .expect("slice")
        .copy_from_slice(&frame);
    let neighbors = Arc::new(ShardedNeighborMap::new());
    let mut last_learned = None;
    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        ingress_ifindex: 21,
        ..UserspaceDpMeta::default()
    };
    learn_dynamic_neighbor_from_packet(
        &area,
        XdpDesc {
            addr: 0,
            len: frame.len() as u32,
            options: 0,
        },
        meta,
        IpAddr::V4(Ipv4Addr::new(10, 0, 61, 100)),
        &mut last_learned,
        &state,
        &neighbors,
    );
    assert!(neighbors.is_empty());
}

#[test]
fn manager_neighbor_replace_preserves_packet_learned_entries() {
    let mut coordinator = Coordinator::new();
    coordinator.dynamic_neighbors_ref().insert(
        (
            5,
            IpAddr::V6(Ipv6Addr::new(
                0x2001, 0x559, 0x8585, 0xef00, 0x1266, 0x6aff, 0xfe0b, 0xd017,
            )),
        ),
        NeighborEntry {
            mac: [0x10, 0x66, 0x6a, 0x0b, 0xd0, 0x17],
        },
    );

    coordinator.apply_manager_neighbors(
        true,
        0,
        &[(
            13,
            IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
            NeighborEntry {
                mac: [0x56, 0x4a, 0xe8, 0x1e, 0xa8, 0x32],
            },
        )],
    );

    let neighbors = coordinator.dynamic_neighbors_ref();
    assert_eq!(neighbors.len(), 2);
    assert!(neighbors.contains_key(&(
        5,
        IpAddr::V6(Ipv6Addr::new(
            0x2001, 0x559, 0x8585, 0xef00, 0x1266, 0x6aff, 0xfe0b, 0xd017,
        ))
    )));
    assert!(neighbors.contains_key(&(13, IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)))));
}

#[test]
fn manager_neighbor_replace_overrides_snapshot_neighbor_entry() {
    let mut coordinator = Coordinator::new();
    let target = IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200));
    coordinator
        .refresh_runtime_snapshot(&ConfigSnapshot {
            neighbors: vec![NeighborSnapshot {
                ifindex: 13,
                family: "inet".to_string(),
                ip: target.to_string(),
                mac: "00:11:22:33:44:55".to_string(),
                state: "reachable".to_string(),
                ..Default::default()
            }],
            ..Default::default()
        })
        .expect("refresh_runtime_snapshot must succeed");

    let before = lookup_neighbor_entry(
        &coordinator.forwarding,
        Some(coordinator.dynamic_neighbors_ref()),
        13,
        target,
    )
    .expect("snapshot neighbor");
    assert_eq!(before.mac, [0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);

    coordinator.apply_manager_neighbors(
        true,
        0,
        &[(
            13,
            target,
            NeighborEntry {
                mac: [0x56, 0x4a, 0xe8, 0x1e, 0xa8, 0x32],
            },
        )],
    );

    let after = lookup_neighbor_entry(
        &coordinator.forwarding,
        Some(coordinator.dynamic_neighbors_ref()),
        13,
        target,
    )
    .expect("updated manager neighbor");
    assert_eq!(after.mac, [0x56, 0x4a, 0xe8, 0x1e, 0xa8, 0x32]);
}

#[test]
fn manager_neighbor_replace_removes_snapshot_seeded_neighbor_entry() {
    let mut coordinator = Coordinator::new();
    let target = IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200));
    coordinator
        .refresh_runtime_snapshot(&ConfigSnapshot {
            neighbors: vec![NeighborSnapshot {
                ifindex: 13,
                family: "inet".to_string(),
                ip: target.to_string(),
                mac: "00:11:22:33:44:55".to_string(),
                state: "reachable".to_string(),
                ..Default::default()
            }],
            ..Default::default()
        })
        .expect("refresh_runtime_snapshot must succeed");

    coordinator.apply_manager_neighbors(true, 0, &[]);

    assert!(
        lookup_neighbor_entry(
            &coordinator.forwarding,
            Some(coordinator.dynamic_neighbors_ref()),
            13,
            target,
        )
        .is_none()
    );
}

#[test]
fn refresh_runtime_snapshot_clears_old_manager_neighbor_cache_entries() {
    let mut coordinator = Coordinator::new();
    let target = IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200));
    coordinator.apply_manager_neighbors(
        true,
        0,
        &[(
            13,
            target,
            NeighborEntry {
                mac: [0x56, 0x4a, 0xe8, 0x1e, 0xa8, 0x32],
            },
        )],
    );
    assert!(
        coordinator
            .dynamic_neighbors_ref()
            .contains_key(&(13, target))
    );

    coordinator.refresh_runtime_snapshot(&ConfigSnapshot::default()).expect("refresh_runtime_snapshot must succeed");

    assert!(
        !coordinator
            .dynamic_neighbors_ref()
            .contains_key(&(13, target))
    );
    assert!(
        lookup_neighbor_entry(
            &coordinator.forwarding,
            Some(coordinator.dynamic_neighbors_ref()),
            13,
            target,
        )
        .is_none()
    );
}

// #6034 fail-on-revert guard: the replace-generation fence must REJECT a stale
// or reordered authoritative replace (generation <= last applied) without
// clobbering the newer table, ACCEPT a strictly higher generation, and expose
// the applied generation for the manager ACK. Reverting the fence in
// apply_manager_neighbors lets the stale replace overwrite the table and fails
// the "must not clobber" assertions.
#[test]
fn manager_neighbor_replace_generation_fences_stale_and_reordered() {
    let mut coordinator = Coordinator::new();
    let target = IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200));
    let mac_a = NeighborEntry {
        mac: [0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa],
    };
    let mac_b = NeighborEntry {
        mac: [0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb],
    };

    let lookup_mac = |coordinator: &Coordinator| {
        lookup_neighbor_entry(
            &coordinator.forwarding,
            Some(coordinator.dynamic_neighbors_ref()),
            13,
            target,
        )
        .expect("manager neighbor entry present")
        .mac
    };

    // Generation 5 applies and advances the ACK.
    assert!(coordinator.apply_manager_neighbors(true, 5, &[(13, target, mac_a)]));
    assert_eq!(coordinator.last_applied_manager_neighbor_generation(), 5);
    assert_eq!(lookup_mac(&coordinator), mac_a.mac);

    // A reordered / stale replace at generation 4 is REJECTED; table unchanged.
    assert!(!coordinator.apply_manager_neighbors(true, 4, &[(13, target, mac_b)]));
    assert_eq!(coordinator.last_applied_manager_neighbor_generation(), 5);
    assert_eq!(
        lookup_mac(&coordinator),
        mac_a.mac,
        "a stale replace must not clobber the newer table"
    );

    // A duplicate at the SAME generation 5 is also rejected (fence is `<=`).
    assert!(!coordinator.apply_manager_neighbors(true, 5, &[(13, target, mac_b)]));
    assert_eq!(lookup_mac(&coordinator), mac_a.mac);

    // A strictly higher generation 6 applies and advances the ACK.
    assert!(coordinator.apply_manager_neighbors(true, 6, &[(13, target, mac_b)]));
    assert_eq!(coordinator.last_applied_manager_neighbor_generation(), 6);
    assert_eq!(lookup_mac(&coordinator), mac_b.mac);
}

// #6034: a generation-0 (unversioned / pre-#6034) push bypasses the fence and
// is always applied, and it does NOT disturb the applied-generation ACK — so a
// mixed-version older manager keeps working unchanged.
#[test]
fn manager_neighbor_unversioned_generation_bypasses_fence() {
    let mut coordinator = Coordinator::new();
    let target = IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200));
    let mac_a = NeighborEntry {
        mac: [0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa],
    };
    let mac_b = NeighborEntry {
        mac: [0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb],
    };
    let lookup_mac = |coordinator: &Coordinator| {
        lookup_neighbor_entry(
            &coordinator.forwarding,
            Some(coordinator.dynamic_neighbors_ref()),
            13,
            target,
        )
        .expect("manager neighbor entry present")
        .mac
    };

    assert!(coordinator.apply_manager_neighbors(true, 9, &[(13, target, mac_a)]));
    assert_eq!(coordinator.last_applied_manager_neighbor_generation(), 9);

    // Unversioned push (generation 0) applies regardless and leaves the fence.
    assert!(coordinator.apply_manager_neighbors(true, 0, &[(13, target, mac_b)]));
    assert_eq!(
        coordinator.last_applied_manager_neighbor_generation(),
        9,
        "an unversioned push must not advance the applied-generation ACK"
    );
    assert_eq!(lookup_mac(&coordinator), mac_b.mac);
}

#[test]
fn new_flow_to_inactive_owner_rg_uses_zone_encoded_fabric_redirect() {
    let state = build_forwarding_state(&nat_snapshot_with_fabric());
    let now_secs = monotonic_nanos() / 1_000_000_000;
    let ha_state = BTreeMap::from([(1, inactive_ha_runtime(now_secs))]);
    let routed = lookup_forwarding_resolution(&state, IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
    let (from_zone, _) = zone_pair_for_flow(&state, 24, routed.egress_ifindex);
    let redirected = finalize_new_flow_ha_resolution(
        &state,
        &ha_state,
        now_secs,
        routed,
        false,
        24,
        state.zone_name_to_id.get(&from_zone).copied().unwrap_or(0),
        0,
    );
    assert_eq!(
        redirected.disposition,
        ForwardingDisposition::FabricRedirect
    );
    assert_eq!(
        redirected.src_mac,
        Some([0x02, 0xbf, 0x72, FABRIC_ZONE_MAC_MAGIC, 0x00, 0x01])
    );
}

#[test]
fn new_flow_from_fabric_keeps_forward_candidate_when_owner_rg_inactive() {
    let state = build_forwarding_state(&nat_snapshot_with_fabric());
    let now_secs = monotonic_nanos() / 1_000_000_000;
    let ha_state = BTreeMap::from([(1, inactive_ha_runtime(now_secs))]);
    let routed = lookup_forwarding_resolution(&state, IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
    let resolved =
        finalize_new_flow_ha_resolution(&state, &ha_state, now_secs, routed, true, 21, 1, 0);
    assert_eq!(
        resolved.disposition,
        ForwardingDisposition::ForwardCandidate
    );
    assert_eq!(resolved.egress_ifindex, routed.egress_ifindex);
}

#[test]
fn fabric_originated_reverse_session_prefers_local_client_delivery_when_rg_active() {
    let state = build_forwarding_state(&nat_snapshot_with_fabric());
    let ha_state = BTreeMap::from([(2, active_ha_runtime(monotonic_nanos() / 1_000_000_000))]);
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
    dynamic_neighbors.insert(
        (24, IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102))),
        NeighborEntry {
            mac: [0xde, 0xad, 0xbe, 0xef, 0x00, 0x01],
        },
    );

    let resolved = reverse_resolution_for_session(
        &state,
        &ha_state,
        &dynamic_neighbors,
        IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)),
        1,
        true,
        monotonic_nanos() / 1_000_000_000,
        false,
    );

    assert_eq!(
        resolved.disposition,
        ForwardingDisposition::ForwardCandidate
    );
    assert_eq!(resolved.egress_ifindex, 24);
    assert_eq!(resolved.tx_ifindex, 24);
}

#[test]
fn fabric_originated_reverse_session_uses_zone_encoded_fabric_redirect_when_client_rg_inactive() {
    let state = build_forwarding_state(&nat_snapshot_with_fabric());
    let ha_state = BTreeMap::from([(2, inactive_ha_runtime(monotonic_nanos() / 1_000_000_000))]);
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());

    let resolved = reverse_resolution_for_session(
        &state,
        &ha_state,
        &dynamic_neighbors,
        IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)),
        1,
        true,
        monotonic_nanos() / 1_000_000_000,
        false,
    );

    assert_eq!(resolved.disposition, ForwardingDisposition::FabricRedirect);
    assert_eq!(resolved.egress_ifindex, 21);
    assert_eq!(resolved.tx_ifindex, 21);
    assert_eq!(
        resolved.src_mac,
        Some([0x02, 0xbf, 0x72, FABRIC_ZONE_MAC_MAGIC, 0x00, 0x01])
    );
}


// #4082: the cross-chassis fabric redirect must prefer a fabric whose local
// parent carrier is UP so a dual-fabric cluster fails over to the secondary
// when the primary parent goes down. RED-on-revert: reverting the selection to
// the pre-#4082 pin-to-first-resolvable makes the fab0-DOWN case pick fab0 and
// blackhole.
#[test]
fn fabric_redirect_prefers_up_fabric_4082() {
    let fab0 = FabricLink {
        parent_ifindex: 21,
        overlay_ifindex: 101,
        peer_addr: IpAddr::V4(Ipv4Addr::new(10, 99, 13, 2)),
        peer_mac: [0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee],
        local_mac: [0x02, 0xbf, 0x72, 0xff, 0x00, 0x01],
        up: true,
    };
    let fab1 = FabricLink {
        parent_ifindex: 22,
        overlay_ifindex: 102,
        peer_addr: IpAddr::V4(Ipv4Addr::new(10, 99, 14, 2)),
        peer_mac: [0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xef],
        local_mac: [0x02, 0xbf, 0x72, 0xff, 0x00, 0x02],
        up: true,
    };

    // fab0 DOWN, fab1 UP → select fab1. This is the failover the fix delivers;
    // reverting to the pin-to-first-resolvable selects fab0 (ifindex 21) here
    // and the redirect blackholes.
    let mut d0 = fab0;
    d0.up = false;
    let r = resolve_fabric_redirect_from_list(&[d0, fab1]).expect("redirect");
    assert_eq!(
        r.egress_ifindex, 22,
        "down primary must fail the redirect over to fab1"
    );
    assert_eq!(r.tx_ifindex, 22);
    assert_eq!(r.next_hop, Some(fab1.peer_addr));

    // Both UP → select fab0 (first in the stable Go-sorted order). No behavior
    // change for the common single- or dual-fabric-both-up case.
    let r = resolve_fabric_redirect_from_list(&[fab0, fab1]).expect("redirect");
    assert_eq!(
        r.egress_ifindex, 21,
        "both up selects the primary fab0 (unchanged from pre-#4082)"
    );

    // Both DOWN → fail-open to the first resolvable fabric (fab0). A blackhole
    // is no worse than a drop, and this preserves the pre-#4082 behavior for a
    // genuine all-fabrics-down state.
    let mut a = fab0;
    let mut b = fab1;
    a.up = false;
    b.up = false;
    let r = resolve_fabric_redirect_from_list(&[a, b]).expect("redirect");
    assert_eq!(
        r.egress_ifindex, 21,
        "all fabrics down falls open to the first resolvable fabric"
    );

    // Reversed order with fab1 the only up link still selects fab1 regardless of
    // position — selection is by up-state, not slot.
    let mut d1 = fab1;
    d1.up = false;
    let r = resolve_fabric_redirect_from_list(&[d1, fab0]).expect("redirect");
    assert_eq!(
        r.egress_ifindex, 21,
        "the up fabric is selected irrespective of list position"
    );
}

// #4082: a snapshot from a STALE daemon that omits the `up` wire field must
// deserialize to up=true (fail-open back-compat), while an explicit `up:false`
// is honored.
#[test]
fn fabric_snapshot_up_serde_default_true_4082() {
    let absent: FabricSnapshot =
        serde_json::from_str(r#"{"name":"fab0","parent_ifindex":21}"#).expect("parse absent up");
    assert!(
        absent.up,
        "an absent `up` field defaults to true (stale-daemon fail-open)"
    );

    let down: FabricSnapshot =
        serde_json::from_str(r#"{"name":"fab0","parent_ifindex":21,"up":false}"#)
            .expect("parse up=false");
    assert!(!down.up, "an explicit up=false is honored");

    let up: FabricSnapshot =
        serde_json::from_str(r#"{"name":"fab0","parent_ifindex":21,"up":true}"#)
            .expect("parse up=true");
    assert!(up.up, "an explicit up=true is honored");
}

#[test]
fn missing_neighbor_session_metadata_preserves_fabric_ingress() {
    let mut state = build_forwarding_state(&native_gre_pbr_snapshot(false));
    state.fabrics.push(FabricLink {
        parent_ifindex: 4,
        overlay_ifindex: 104,
        peer_addr: IpAddr::V4(Ipv4Addr::new(10, 99, 13, 2)),
        peer_mac: [0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee],
        local_mac: [0x02, 0xbf, 0x72, 0xff, 0x00, 0x01],
        up: true,
    });
    let decision = SessionDecision {
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::MissingNeighbor,
            local_ifindex: 0,
            egress_ifindex: 13,
            tx_ifindex: 13,
            tunnel_endpoint_id: 0,
            next_hop: Some(IpAddr::V6(Ipv6Addr::new(
                0x2001, 0x559, 0x8585, 0x50, 0, 0, 0, 0x1,
            ))),
            neighbor_mac: None,
            src_mac: None,
            tx_vlan_id: 0,
        },
        nat: NatDecision::default(),
    };

    let metadata = build_missing_neighbor_session_metadata(
        &state,
        TEST_LAN_ZONE_ID,
        TEST_WAN_ZONE_ID,
        11,
        50,
        true,
        decision,
    );

    assert_eq!(metadata.ingress_zone, 1);
    assert_eq!(metadata.egress_zone, 2);
    assert!(metadata.fabric_ingress);
    assert!(!metadata.is_reverse);
    // #4983: the seed carries the frame's ingress binding through, not 0.
    assert_eq!(metadata.ingress_ifindex, 11);
    assert_eq!(metadata.ingress_vlan_id, 50);
}

#[test]
fn reverse_session_prefers_interface_snat_ipv4_local_delivery() {
    let state = build_forwarding_state(&nat_snapshot());
    let ha_state = BTreeMap::new();
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());

    let resolved = reverse_resolution_for_session(
        &state,
        &ha_state,
        &dynamic_neighbors,
        IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8)),
        2,
        false,
        monotonic_nanos() / 1_000_000_000,
        false,
    );

    assert_eq!(resolved.disposition, ForwardingDisposition::LocalDelivery);
    assert_eq!(resolved.local_ifindex, 12);
    assert_eq!(resolved.egress_ifindex, 12);
    assert_eq!(resolved.tx_ifindex, 12);
}

#[test]
fn reverse_session_blocks_inactive_interface_snat_ipv4_local_delivery() {
    let state = build_forwarding_state(&nat_snapshot());
    let ha_state = BTreeMap::from([(1, inactive_ha_runtime(monotonic_nanos() / 1_000_000_000))]);
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());

    let resolved = reverse_resolution_for_session(
        &state,
        &ha_state,
        &dynamic_neighbors,
        IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8)),
        2,
        false,
        monotonic_nanos() / 1_000_000_000,
        false,
    );

    assert_eq!(resolved.disposition, ForwardingDisposition::HAInactive);
    assert_eq!(resolved.local_ifindex, 12);
    assert_eq!(resolved.egress_ifindex, 12);
}

#[test]
fn reverse_session_prefers_interface_snat_ipv6_local_delivery() {
    let state = build_forwarding_state(&nat_snapshot());
    let ha_state = BTreeMap::new();
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());

    let resolved = reverse_resolution_for_session(
        &state,
        &ha_state,
        &dynamic_neighbors,
        "2001:559:8585:80::8".parse().expect("dst"),
        2,
        false,
        monotonic_nanos() / 1_000_000_000,
        false,
    );

    assert_eq!(resolved.disposition, ForwardingDisposition::LocalDelivery);
    assert_eq!(resolved.local_ifindex, 12);
    assert_eq!(resolved.egress_ifindex, 12);
    assert_eq!(resolved.tx_ifindex, 12);
}

#[test]
fn session_hit_keeps_interface_snat_ipv4_local_delivery() {
    let state = build_forwarding_state(&nat_snapshot());
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
    let flow = SessionFlow {
        src_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8)),
        forward_key: SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8)),
            src_port: 5201,
            dst_port: 43600,
                    discriminator: Default::default(),
                    routing_domain: 0,
        },
    };
    let decision = SessionDecision {
        resolution: interface_nat_local_resolution(&state, flow.dst_ip)
            .expect("interface nat local delivery"),
        nat: NatDecision::default(),
    };

    let resolved =
        lookup_forwarding_resolution_for_session(&state, &dynamic_neighbors, &flow, decision);

    assert_eq!(resolved.disposition, ForwardingDisposition::LocalDelivery);
    assert_eq!(resolved.local_ifindex, 12);
}

#[test]
fn inactive_interface_snat_session_hit_redirects_to_fabric() {
    let state = build_forwarding_state(&nat_snapshot_with_fabric());
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
    let ha_state = Arc::new(ArcSwap::from_pointee(BTreeMap::from([(
        1,
        inactive_ha_runtime(monotonic_nanos() / 1_000_000_000),
    )])));
    let flow = SessionFlow {
        src_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8)),
        forward_key: SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8)),
            src_port: 5201,
            dst_port: 43600,
                    discriminator: Default::default(),
                    routing_domain: 0,
        },
    };
    let decision = SessionDecision {
        resolution: interface_nat_local_resolution(&state, flow.dst_ip)
            .expect("interface nat local delivery"),
        nat: NatDecision::default(),
    };

    let looked_up =
        lookup_forwarding_resolution_for_session(&state, &dynamic_neighbors, &flow, decision);
    let blocked = enforce_ha_resolution(&state, &ha_state, looked_up);
    let redirected = redirect_via_fabric_if_needed(&state, blocked, 12);

    assert_eq!(
        redirected.disposition,
        ForwardingDisposition::FabricRedirect
    );
    assert_eq!(redirected.egress_ifindex, 21);
    assert_eq!(redirected.tx_ifindex, 21);
}

#[test]
fn session_hit_keeps_interface_snat_ipv6_local_delivery() {
    let state = build_forwarding_state(&nat_snapshot());
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
    let flow = SessionFlow {
        src_ip: "2001:559:8585:80::200".parse().expect("src"),
        dst_ip: "2001:559:8585:80::8".parse().expect("dst"),
        forward_key: SessionKey {
            addr_family: libc::AF_INET6 as u8,
            protocol: PROTO_TCP,
            src_ip: "2001:559:8585:80::200".parse().expect("src"),
            dst_ip: "2001:559:8585:80::8".parse().expect("dst"),
            src_port: 5201,
            dst_port: 43600,
                    discriminator: Default::default(),
                    routing_domain: 0,
        },
    };
    let decision = SessionDecision {
        resolution: interface_nat_local_resolution(&state, flow.dst_ip)
            .expect("interface nat local delivery"),
        nat: NatDecision::default(),
    };

    let resolved =
        lookup_forwarding_resolution_for_session(&state, &dynamic_neighbors, &flow, decision);

    assert_eq!(resolved.disposition, ForwardingDisposition::LocalDelivery);
    assert_eq!(resolved.local_ifindex, 12);
}

#[test]
fn embedded_icmp_to_inactive_owner_rg_uses_zone_encoded_fabric_redirect() {
    let state = build_forwarding_state(&nat_snapshot_with_fabric());
    let ha_state = BTreeMap::from([(2, inactive_ha_runtime(monotonic_nanos() / 1_000_000_000))]);
    let icmp_match = EmbeddedIcmpMatch {
        nat: NatDecision {
            rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
            ..NatDecision::default()
        },
        original_src: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)),
        original_src_port: 33434,
        original_dst: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)),
        original_dst_port: 33434,
        embedded_proto: PROTO_UDP,
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::ForwardCandidate,
            local_ifindex: 0,
            egress_ifindex: 24,
            tx_ifindex: 24,
            tunnel_endpoint_id: 0,
            next_hop: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102))),
            neighbor_mac: Some([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
            src_mac: Some([0x02, 0xbf, 0x72, 0x01, 0x00, 0x01]),
            tx_vlan_id: 0,
        },
        metadata: SessionMetadata {
            ingress_zone: TEST_WAN_ZONE_ID,
            egress_zone: TEST_LAN_ZONE_ID,
            ingress_ifindex: 0,
            ingress_vlan_id: 0,
            owner_rg_id: 2,
            fabric_ingress: false,
            is_reverse: false,
            nat64_reverse: None,
            log_session_init: false,
            log_session_close: false,
            policy_id: 0,
            inactivity_timeout_ns: None,
            policy_counter_idx: 0,
            policy_counter: None,
        },
        outbound_snat: false,
    };

    let resolved = finalize_embedded_icmp_resolution(
        &state,
        &ha_state,
        monotonic_nanos() / 1_000_000_000,
        12,
        &icmp_match,
    );
    assert_eq!(resolved.disposition, ForwardingDisposition::FabricRedirect);
    assert_eq!(resolved.egress_ifindex, 21);
    assert_eq!(resolved.tx_ifindex, 21);
    assert_eq!(
        resolved.src_mac,
        Some([0x02, 0xbf, 0x72, FABRIC_ZONE_MAC_MAGIC, 0x00, 0x02])
    );
}

#[test]
fn embedded_icmp_no_route_uses_zone_encoded_fabric_redirect() {
    let state = build_forwarding_state(&nat_snapshot_with_fabric());
    let ha_state = BTreeMap::new();
    let icmp_match = EmbeddedIcmpMatch {
        nat: NatDecision {
            rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
            ..NatDecision::default()
        },
        original_src: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)),
        original_src_port: 33434,
        original_dst: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)),
        original_dst_port: 33434,
        embedded_proto: PROTO_UDP,
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::NoRoute,
            local_ifindex: 0,
            egress_ifindex: 0,
            tx_ifindex: 0,
            tunnel_endpoint_id: 0,
            next_hop: None,
            neighbor_mac: None,
            src_mac: None,
            tx_vlan_id: 0,
        },
        metadata: SessionMetadata {
            ingress_zone: TEST_WAN_ZONE_ID,
            egress_zone: TEST_LAN_ZONE_ID,
            ingress_ifindex: 0,
            ingress_vlan_id: 0,
            owner_rg_id: 2,
            fabric_ingress: false,
            is_reverse: false,
            nat64_reverse: None,
            log_session_init: false,
            log_session_close: false,
            policy_id: 0,
            inactivity_timeout_ns: None,
            policy_counter_idx: 0,
            policy_counter: None,
        },
        outbound_snat: false,
    };

    let resolved = finalize_embedded_icmp_resolution(
        &state,
        &ha_state,
        monotonic_nanos() / 1_000_000_000,
        12,
        &icmp_match,
    );
    assert_eq!(resolved.disposition, ForwardingDisposition::FabricRedirect);
    assert_eq!(resolved.egress_ifindex, 21);
    assert_eq!(resolved.tx_ifindex, 21);
    assert_eq!(
        resolved.src_mac,
        Some([0x02, 0xbf, 0x72, FABRIC_ZONE_MAC_MAGIC, 0x00, 0x02])
    );
}

#[test]
fn embedded_icmp_discard_route_uses_zone_encoded_fabric_redirect() {
    let state = build_forwarding_state(&nat_snapshot_with_fabric());
    let ha_state = BTreeMap::new();
    let icmp_match = EmbeddedIcmpMatch {
        nat: NatDecision {
            rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
            ..NatDecision::default()
        },
        original_src: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)),
        original_src_port: 33434,
        original_dst: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)),
        original_dst_port: 33434,
        embedded_proto: PROTO_UDP,
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::DiscardRoute,
            local_ifindex: 0,
            egress_ifindex: 24,
            tx_ifindex: 24,
            tunnel_endpoint_id: 0,
            next_hop: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102))),
            neighbor_mac: None,
            src_mac: None,
            tx_vlan_id: 0,
        },
        metadata: SessionMetadata {
            ingress_zone: TEST_WAN_ZONE_ID,
            egress_zone: TEST_LAN_ZONE_ID,
            ingress_ifindex: 0,
            ingress_vlan_id: 0,
            owner_rg_id: 2,
            fabric_ingress: false,
            is_reverse: false,
            nat64_reverse: None,
            log_session_init: false,
            log_session_close: false,
            policy_id: 0,
            inactivity_timeout_ns: None,
            policy_counter_idx: 0,
            policy_counter: None,
        },
        outbound_snat: false,
    };

    let resolved = finalize_embedded_icmp_resolution(
        &state,
        &ha_state,
        monotonic_nanos() / 1_000_000_000,
        12,
        &icmp_match,
    );
    assert_eq!(resolved.disposition, ForwardingDisposition::FabricRedirect);
    assert_eq!(resolved.egress_ifindex, 21);
    assert_eq!(resolved.tx_ifindex, 21);
}

#[test]
fn embedded_icmp_from_fabric_does_not_redirect_back_to_fabric() {
    let state = build_forwarding_state(&nat_snapshot_with_fabric());
    let ha_state = BTreeMap::from([(2, inactive_ha_runtime(monotonic_nanos() / 1_000_000_000))]);
    let icmp_match = EmbeddedIcmpMatch {
        nat: NatDecision {
            rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
            ..NatDecision::default()
        },
        original_src: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)),
        original_src_port: 33434,
        original_dst: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)),
        original_dst_port: 33434,
        embedded_proto: PROTO_UDP,
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::ForwardCandidate,
            local_ifindex: 0,
            egress_ifindex: 24,
            tx_ifindex: 24,
            tunnel_endpoint_id: 0,
            next_hop: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102))),
            neighbor_mac: Some([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
            src_mac: Some([0x02, 0xbf, 0x72, 0x01, 0x00, 0x01]),
            tx_vlan_id: 0,
        },
        metadata: SessionMetadata {
            ingress_zone: TEST_WAN_ZONE_ID,
            egress_zone: TEST_LAN_ZONE_ID,
            ingress_ifindex: 0,
            ingress_vlan_id: 0,
            owner_rg_id: 2,
            fabric_ingress: false,
            is_reverse: false,
            nat64_reverse: None,
            log_session_init: false,
            log_session_close: false,
            policy_id: 0,
            inactivity_timeout_ns: None,
            policy_counter_idx: 0,
            policy_counter: None,
        },
        outbound_snat: false,
    };

    let resolved = finalize_embedded_icmp_resolution(
        &state,
        &ha_state,
        monotonic_nanos() / 1_000_000_000,
        21,
        &icmp_match,
    );
    assert_eq!(resolved.disposition, ForwardingDisposition::HAInactive);
}

#[test]
fn fabric_ingress_does_not_redirect_back_to_fabric() {
    let state = build_forwarding_state(&nat_snapshot_with_fabric());
    let blocked = ForwardingResolution {
        disposition: ForwardingDisposition::HAInactive,
        local_ifindex: 0,
        egress_ifindex: 12,
        tx_ifindex: 12,
        tunnel_endpoint_id: 0,
        next_hop: Some(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
        neighbor_mac: Some([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
        src_mac: None,
        tx_vlan_id: 80,
    };
    assert_eq!(
        redirect_via_fabric_if_needed(&state, blocked, 21).disposition,
        ForwardingDisposition::HAInactive
    );
}

#[test]
fn source_nat_selection_uses_interface_addresses() {
    let state = build_forwarding_state(&nat_snapshot());
    let flow = SessionFlow {
        src_ip: "10.0.61.102".parse().expect("src"),
        dst_ip: "172.16.80.200".parse().expect("dst"),
        forward_key: SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            src_ip: "10.0.61.102".parse().expect("src"),
            dst_ip: "172.16.80.200".parse().expect("dst"),
            src_port: 12345,
            dst_port: 5201,
                    discriminator: Default::default(),
                    routing_domain: 0,
        },
    };
    let (from_zone, to_zone) = zone_pair_for_flow(&state, 24, 12);
    assert_eq!(
        match_source_nat_for_flow(&state, 24, &from_zone, &to_zone, 12, &flow),
        Some(NatDecision {
            rewrite_src: Some("172.16.80.8".parse().expect("snat")),
            rewrite_dst: None,
            ..NatDecision::default()
        })
    );
}

#[test]
fn source_nat_selection_uses_interface_addresses_v6() {
    let state = build_forwarding_state(&nat_snapshot());
    let flow = SessionFlow {
        src_ip: "2001:559:8585:ef00::100".parse().expect("src"),
        dst_ip: "2001:559:8585:80::200".parse().expect("dst"),
        forward_key: SessionKey {
            addr_family: libc::AF_INET6 as u8,
            protocol: PROTO_TCP,
            src_ip: "2001:559:8585:ef00::100".parse().expect("src"),
            dst_ip: "2001:559:8585:80::200".parse().expect("dst"),
            src_port: 12345,
            dst_port: 5201,
                    discriminator: Default::default(),
                    routing_domain: 0,
        },
    };
    let (from_zone, to_zone) = zone_pair_for_flow(&state, 24, 12);
    assert_eq!(
        match_source_nat_for_flow(&state, 24, &from_zone, &to_zone, 12, &flow),
        Some(NatDecision {
            rewrite_src: Some("2001:559:8585:80::8".parse().expect("snat")),
            rewrite_dst: None,
            ..NatDecision::default()
        })
    );
}

#[test]
fn source_nat_pool_unavailable_reports_rule_and_pool_identity() {
    let mut snapshot = nat_snapshot();
    snapshot.source_nat_rules = vec![SourceNATRuleSnapshot {
        name: "wrong-family".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["0.0.0.0/0".to_string()],
        pool_name: "v6-only".to_string(),
        pool_addresses: vec!["2001:db8::10".to_string()],
        port_low: 10_000,
        port_high: 10_010,
        ..Default::default()
    }];
    let state = build_forwarding_state(&snapshot);
    let flow = SessionFlow {
        src_ip: "10.0.61.102".parse().expect("src"),
        dst_ip: "172.16.80.200".parse().expect("dst"),
        forward_key: SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            src_ip: "10.0.61.102".parse().expect("src"),
            dst_ip: "172.16.80.200".parse().expect("dst"),
            src_port: 12345,
            dst_port: 5201,
                    discriminator: Default::default(),
                    routing_domain: 0,
        },
    };
    let (from_zone, to_zone) = zone_pair_for_flow(&state, 24, 12);

    assert_eq!(
        match_source_nat_for_flow_result(&state, 24, &from_zone, &to_zone, 12, &flow),
        SourceNatLookup::Unavailable(SourceNatFailure {
            rule_name: "wrong-family".to_string(),
            pool_name: "v6-only".to_string(),
            reason: SourceNatFailureReason::WrongAddressFamily,
        })
    );
}

#[test]
fn source_nat_allocator_exhausted_reports_rule_and_pool_identity() {
    let mut snapshot = nat_snapshot();
    snapshot.source_nat_rules = vec![SourceNATRuleSnapshot {
        name: "exhausted".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["0.0.0.0/0".to_string()],
        pool_name: "tiny-pool".to_string(),
        pool_unusable: true,
        pool_unusable_reason: "allocator_exhausted".to_string(),
        ..Default::default()
    }];
    let state = build_forwarding_state(&snapshot);
    let flow = SessionFlow {
        src_ip: "10.0.61.102".parse().expect("src"),
        dst_ip: "172.16.80.200".parse().expect("dst"),
        forward_key: SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            src_ip: "10.0.61.102".parse().expect("src"),
            dst_ip: "172.16.80.200".parse().expect("dst"),
            src_port: 12345,
            dst_port: 5201,
                    discriminator: Default::default(),
                    routing_domain: 0,
        },
    };
    let (from_zone, to_zone) = zone_pair_for_flow(&state, 24, 12);

    assert_eq!(
        match_source_nat_for_flow_result(&state, 24, &from_zone, &to_zone, 12, &flow),
        SourceNatLookup::Unavailable(SourceNatFailure {
            rule_name: "exhausted".to_string(),
            pool_name: "tiny-pool".to_string(),
            reason: SourceNatFailureReason::AllocatorExhausted,
        })
    );
}

#[test]
fn interface_snat_addresses_are_not_treated_as_local_delivery() {
    let state = build_forwarding_state(&nat_snapshot());
    let resolved_v4 = lookup_forwarding_resolution(&state, "172.16.80.8".parse().expect("v4"));
    assert_ne!(
        resolved_v4.disposition,
        ForwardingDisposition::LocalDelivery
    );
    let resolved_v6 =
        lookup_forwarding_resolution(&state, "2001:559:8585:80::8".parse().expect("v6"));
    assert_ne!(
        resolved_v6.disposition,
        ForwardingDisposition::LocalDelivery
    );
}

#[test]
fn interface_snat_addresses_are_local_delivered_on_session_miss() {
    let state = build_forwarding_state(&nat_snapshot());
    let resolved_v4 = interface_nat_local_resolution(&state, "172.16.80.8".parse().expect("v4"))
        .expect("v4 nat local delivery");
    assert_eq!(
        resolved_v4.disposition,
        ForwardingDisposition::LocalDelivery
    );
    assert_eq!(resolved_v4.local_ifindex, 12);

    let resolved_v6 =
        interface_nat_local_resolution(&state, "2001:559:8585:80::8".parse().expect("v6"))
            .expect("v6 nat local delivery");
    assert_eq!(
        resolved_v6.disposition,
        ForwardingDisposition::LocalDelivery
    );
    assert_eq!(resolved_v6.local_ifindex, 12);
}

#[test]
fn icmp_session_miss_resolution_prefers_frame_destination_for_interface_nat_local_delivery() {
    let state = build_forwarding_state(&nat_snapshot());
    let frame = vlan_icmp_reply_frame();
    let mut area = MmapArea::new(4096).expect("mmap");
    area.slice_mut(0, frame.len())
        .expect("slice")
        .copy_from_slice(&frame);
    let mut meta = valid_meta();
    meta.l3_offset = 18;
    meta.l4_offset = 38;
    meta.flow_src_addr[..4].copy_from_slice(&[172, 16, 80, 201]);
    // Deliberately poison the metadata tuple to model a stamped-dst mismatch.
    meta.flow_dst_addr[..4].copy_from_slice(&[10, 0, 61, 1]);

    let flow = parse_session_flow(
        &area,
        XdpDesc {
            addr: 0,
            len: frame.len() as u32,
            options: 0,
        },
        meta,
    )
    .expect("flow");
    assert_eq!(flow.dst_ip, IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8)));

    let resolution_target = parse_packet_destination(
        &area,
        XdpDesc {
            addr: 0,
            len: frame.len() as u32,
            options: 0,
        },
        meta,
    )
    .expect("frame destination");
    assert_eq!(resolution_target, IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8)));

    let resolved =
        interface_nat_local_resolution_on_session_miss(&state, resolution_target, PROTO_ICMP)
            .expect("nat local delivery");
    assert_eq!(resolved.disposition, ForwardingDisposition::LocalDelivery);
    assert_eq!(resolved.local_ifindex, 12);
}

#[test]
fn tcp_session_miss_local_delivers_interface_nat_address() {
    let state = build_forwarding_state(&nat_snapshot());
    let resolved_v4 = interface_nat_local_resolution_on_session_miss(
        &state,
        "172.16.80.8".parse().expect("v4"),
        PROTO_TCP,
    )
    .expect("tcp v4 nat local delivery");
    assert_eq!(
        resolved_v4.disposition,
        ForwardingDisposition::LocalDelivery
    );
    assert_eq!(resolved_v4.local_ifindex, 12);

    let resolved_v6 = interface_nat_local_resolution_on_session_miss(
        &state,
        "2001:559:8585:80::8".parse().expect("v6"),
        PROTO_UDP,
    )
    .expect("udp v6 nat local delivery");
    assert_eq!(
        resolved_v6.disposition,
        ForwardingDisposition::LocalDelivery
    );
    assert_eq!(resolved_v6.local_ifindex, 12);
}

#[test]
fn tcp_ack_session_miss_does_not_cache_interface_nat_local_delivery() {
    let state = build_forwarding_state(&nat_snapshot());
    let resolution = interface_nat_local_resolution_on_session_miss(
        &state,
        "172.16.80.8".parse().expect("v4"),
        PROTO_TCP,
    )
    .expect("tcp nat local delivery");
    assert!(!should_cache_local_delivery_session_on_miss(
        &state,
        "172.16.80.8".parse().expect("v4"),
        resolution,
        PROTO_TCP,
        0x10,
    ));
}

#[test]
fn tcp_syn_session_miss_still_caches_interface_nat_local_delivery() {
    let state = build_forwarding_state(&nat_snapshot());
    let resolution = interface_nat_local_resolution_on_session_miss(
        &state,
        "172.16.80.8".parse().expect("v4"),
        PROTO_TCP,
    )
    .expect("tcp nat local delivery");
    assert!(should_cache_local_delivery_session_on_miss(
        &state,
        "172.16.80.8".parse().expect("v4"),
        resolution,
        PROTO_TCP,
        0x02,
    ));
}

/// #4487 (residual of P6 / #4400): a bare TCP RST / FIN on the LocalDelivery
/// session-MISS path must NOT seed a firewall-local session (host-IP
/// session-table DoS + policy-evaluation skip). The #2151 ACK-only gate caught
/// FIN|ACK / RST|ACK but missed the bare RST (0x04) and bare FIN (0x01) with no
/// ACK bit — the exact residual. RED on revert: without the `is_closing &&
/// !has_syn` guard the bare-RST / bare-FIN asserts flip to `true` (a closing
/// session is cached). The packet itself is still DELIVERED to the host (the
/// LocalDelivery disposition reinjects it) — this gate only declines to CACHE,
/// so a peer RST tearing down a firewall-originated flow still reaches the
/// local stack (the #4400 LocalDelivery drop-exemption).
#[test]
fn bare_rst_fin_session_miss_does_not_cache_local_delivery() {
    let state = build_forwarding_state(&nat_snapshot());
    let target = "172.16.80.8";
    // Model both LocalDelivery resolvers the poll loop feeds this gate:
    // interface-NAT-local and ingress-interface-local. Both must decline to
    // cache a bare teardown segment.
    let resolvers: [ForwardingResolution; 2] = [
        interface_nat_local_resolution_on_session_miss(
            &state,
            target.parse().expect("v4"),
            PROTO_TCP,
        )
        .expect("tcp nat local delivery"),
        ingress_interface_local_resolution_on_session_miss(
            &state,
            11,
            80,
            target.parse().expect("v4"),
            PROTO_TCP,
        )
        .expect("tcp ingress local delivery"),
    ];
    for resolution in resolvers {
        // Bare RST (0x04) and bare FIN (0x01) — no ACK, no SYN: the #4487
        // residual the #2151 ACK-only gate let through. RED on revert.
        assert!(
            !should_cache_local_delivery_session_on_miss(
                &state,
                target.parse().expect("v4"),
                resolution,
                PROTO_TCP,
                0x04,
            ),
            "bare RST must not seed a host-local session"
        );
        assert!(
            !should_cache_local_delivery_session_on_miss(
                &state,
                target.parse().expect("v4"),
                resolution,
                PROTO_TCP,
                0x01,
            ),
            "bare FIN must not seed a host-local session"
        );
        // FIN|ACK (0x11) and RST|ACK (0x14) — already declined by the #2151
        // ACK gate; the #4487 predicate keeps them declined (consistency).
        assert!(!should_cache_local_delivery_session_on_miss(
            &state,
            target.parse().expect("v4"),
            resolution,
            PROTO_TCP,
            0x11,
        ));
        assert!(!should_cache_local_delivery_session_on_miss(
            &state,
            target.parse().expect("v4"),
            resolution,
            PROTO_TCP,
            0x14,
        ));
        // PRESERVED: a bare SYN (0x02) to a firewall host service still seeds
        // the session — a legitimate inbound connection open is unaffected.
        assert!(
            should_cache_local_delivery_session_on_miss(
                &state,
                target.parse().expect("v4"),
                resolution,
                PROTO_TCP,
                0x02,
            ),
            "a SYN to a host service must still create a session"
        );
        // PRESERVED: a SYN|ACK (0x12) — a firewall-originated flow's inbound
        // handshake response — still seeds the host-local session.
        assert!(should_cache_local_delivery_session_on_miss(
            &state,
            target.parse().expect("v4"),
            resolution,
            PROTO_TCP,
            0x12,
        ));
    }
    // A non-LocalDelivery disposition never caches here regardless of flags —
    // the guard is scoped to host-inbound, and an ESTABLISHED-session packet is
    // a session HIT that never consults this MISS-only gate in the first place.
    let mut transit = interface_nat_local_resolution_on_session_miss(
        &state,
        target.parse().expect("v4"),
        PROTO_TCP,
    )
    .expect("tcp nat local delivery");
    transit.disposition = ForwardingDisposition::ForwardCandidate;
    assert!(!should_cache_local_delivery_session_on_miss(
        &state,
        target.parse().expect("v4"),
        transit,
        PROTO_TCP,
        0x02,
    ));
}

/// #4539 (gate-consistency hardening; subsumes #2151 + #4487): the
/// LocalDelivery session-MISS cache gate must seed a host-local TCP session
/// ONLY off the handshake. A `has_syn` positive predicate now replaces the two
/// prior narrow decline-gates, closing the residual where a NON-handshake,
/// non-ACK, non-closing first packet — pure PSH (0x08), a null segment (0x00),
/// pure URG (0x20), an ECE-only (0x40) or CWR-only (0x80) segment — fell
/// through to the default `true` and seeded a 300s host-local session. RED on
/// revert: with the old two-gate form these anomalous first packets assert
/// `true` (cached). The fix is TCP-only: non-TCP (UDP/ICMP) LocalDelivery still
/// caches unconditionally.
#[test]
fn non_handshake_tcp_session_miss_does_not_cache_local_delivery() {
    let state = build_forwarding_state(&nat_snapshot());
    let target = "172.16.80.8";
    let resolvers: [ForwardingResolution; 2] = [
        interface_nat_local_resolution_on_session_miss(
            &state,
            target.parse().expect("v4"),
            PROTO_TCP,
        )
        .expect("tcp nat local delivery"),
        ingress_interface_local_resolution_on_session_miss(
            &state,
            11,
            80,
            target.parse().expect("v4"),
            PROTO_TCP,
        )
        .expect("tcp ingress local delivery"),
    ];
    for resolution in resolvers {
        // The #4539 residual: non-handshake anomalous / crafted first packets
        // that are neither ACK-set (#2151) nor closing (#4487). Each must now
        // be DECLINED. RED on revert (old default-`true` cached them).
        for (flags, label) in [
            (0x08u8, "pure PSH"),
            (0x00u8, "null segment"),
            (0x20u8, "pure URG"),
            (0x40u8, "ECE-only"),
            (0x80u8, "CWR-only"),
            (0x28u8, "PSH|URG"),
        ] {
            assert!(
                !should_cache_local_delivery_session_on_miss(
                    &state,
                    target.parse().expect("v4"),
                    resolution,
                    PROTO_TCP,
                    flags,
                ),
                "non-handshake first packet ({label}, 0x{flags:02x}) must not seed a host-local session"
            );
        }
        // PRESERVED: SYN (0x02), SYN|ACK (0x12), and a data-carrying SYN|PSH
        // (0x0a) still cache — a legitimate handshake open is unaffected.
        for (flags, label) in [(0x02u8, "SYN"), (0x12u8, "SYN|ACK"), (0x0au8, "SYN|PSH")] {
            assert!(
                should_cache_local_delivery_session_on_miss(
                    &state,
                    target.parse().expect("v4"),
                    resolution,
                    PROTO_TCP,
                    flags,
                ),
                "a handshake first packet ({label}, 0x{flags:02x}) must still seed a session"
            );
        }
        // SUBSUMED: the #2151 bare-ACK and #4487 bare-RST/FIN declines still
        // decline under the single has_syn gate.
        for (flags, label) in [
            (0x10u8, "#2151 bare ACK"),
            (0x04u8, "#4487 bare RST"),
            (0x01u8, "#4487 bare FIN"),
        ] {
            assert!(
                !should_cache_local_delivery_session_on_miss(
                    &state,
                    target.parse().expect("v4"),
                    resolution,
                    PROTO_TCP,
                    flags,
                ),
                "{label} (0x{flags:02x}) must remain declined"
            );
        }
        // PRESERVED (fix is TCP-only): a non-TCP (UDP, ICMP) LocalDelivery
        // first packet still caches unconditionally — the tcp_flags byte is
        // meaningless for these protocols and must not gate them, even for a
        // flag pattern that would be declined as TCP (0x00 null / 0x08 PSH).
        for proto in [PROTO_UDP, PROTO_ICMP] {
            for flags in [0x00u8, 0x08u8, 0x10u8] {
                assert!(
                    should_cache_local_delivery_session_on_miss(
                        &state,
                        target.parse().expect("v4"),
                        resolution,
                        proto,
                        flags,
                    ),
                    "non-TCP proto {proto} LocalDelivery must cache regardless of the tcp_flags byte (0x{flags:02x})"
                );
            }
        }
    }
}

#[test]
fn tunnel_session_miss_blocks_interface_nat_local_delivery() {
    let mut snapshot = native_gre_snapshot(true);
    snapshot.source_nat_rules = vec![SourceNATRuleSnapshot {
        name: "lan-to-sfmix".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "sfmix".to_string(),
        source_addresses: vec!["0.0.0.0/0".to_string()],
        interface_mode: true,
        ..Default::default()
    }];
    let state = build_forwarding_state(&snapshot);
    let tunnel_snat_ip = "10.255.192.42".parse().expect("tunnel snat");
    assert!(should_block_tunnel_interface_nat_session_miss(
        &state,
        tunnel_snat_ip,
        PROTO_TCP,
    ));
    assert!(should_block_tunnel_interface_nat_session_miss(
        &state,
        tunnel_snat_ip,
        PROTO_UDP,
    ));
    assert!(should_block_tunnel_interface_nat_session_miss(
        &state,
        tunnel_snat_ip,
        PROTO_ICMP,
    ));
}

#[test]
fn ingress_interface_local_resolution_matches_vlan_local_address() {
    let state = build_forwarding_state(&nat_snapshot());
    let resolved =
        ingress_interface_local_resolution(&state, 11, 80, "172.16.80.8".parse().expect("dst"))
            .expect("ingress local delivery");
    assert_eq!(resolved.disposition, ForwardingDisposition::LocalDelivery);
    assert_eq!(resolved.local_ifindex, 12);
}

#[test]
fn tcp_session_miss_local_delivers_ingress_vlan_address() {
    let state = build_forwarding_state(&nat_snapshot());
    let resolved_v4 = ingress_interface_local_resolution_on_session_miss(
        &state,
        11,
        80,
        "172.16.80.8".parse().expect("dst"),
        PROTO_TCP,
    )
    .expect("tcp ingress local delivery");
    assert_eq!(
        resolved_v4.disposition,
        ForwardingDisposition::LocalDelivery
    );
    assert_eq!(resolved_v4.local_ifindex, 12);

    let resolved_v6 = ingress_interface_local_resolution_on_session_miss(
        &state,
        11,
        80,
        "2001:559:8585:80::8".parse().expect("dst"),
        PROTO_UDP,
    )
    .expect("udp ingress local delivery");
    assert_eq!(
        resolved_v6.disposition,
        ForwardingDisposition::LocalDelivery
    );
    assert_eq!(resolved_v6.local_ifindex, 12);
}

#[test]
fn tcp_ack_session_miss_does_not_cache_ingress_local_delivery() {
    let state = build_forwarding_state(&nat_snapshot());
    let resolution = ingress_interface_local_resolution_on_session_miss(
        &state,
        11,
        80,
        "172.16.80.8".parse().expect("dst"),
        PROTO_TCP,
    )
    .expect("tcp ingress local delivery");
    assert!(!should_cache_local_delivery_session_on_miss(
        &state,
        "172.16.80.8".parse().expect("dst"),
        resolution,
        PROTO_TCP,
        0x10,
    ));
}

#[test]
fn tcp_syn_session_miss_still_caches_ingress_local_delivery() {
    let state = build_forwarding_state(&nat_snapshot());
    let resolution = ingress_interface_local_resolution_on_session_miss(
        &state,
        11,
        80,
        "172.16.80.8".parse().expect("dst"),
        PROTO_TCP,
    )
    .expect("tcp ingress local delivery");
    assert!(should_cache_local_delivery_session_on_miss(
        &state,
        "172.16.80.8".parse().expect("dst"),
        resolution,
        PROTO_TCP,
        0x02,
    ));
}

#[test]
fn helper_local_session_on_miss_stays_out_of_shared_alias_maps() {
    let mut sessions = SessionTable::new();
    let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
    let state = build_forwarding_state(&nat_snapshot());
    let key = SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        src_ip: "172.16.80.8".parse().expect("src"),
        dst_ip: "172.16.80.200".parse().expect("dst"),
        src_port: 40278,
        dst_port: 5201,
            discriminator: Default::default(),
            routing_domain: 0,
    };
    let decision = SessionDecision {
        resolution: ingress_interface_local_resolution_on_session_miss(
            &state, 11, 80, key.src_ip, PROTO_TCP,
        )
        .expect("tcp ingress local delivery"),
        nat: NatDecision::default(),
    };
    let metadata = SessionMetadata {
        ingress_zone: TEST_LAN_ZONE_ID,
        egress_zone: TEST_WAN_ZONE_ID,
        ingress_ifindex: 0,
        ingress_vlan_id: 0,
        owner_rg_id: 0,
        fabric_ingress: false,
        is_reverse: false,
        nat64_reverse: None,
        log_session_init: false,
        log_session_close: false,
        policy_id: 0,
        inactivity_timeout_ns: None,
        policy_counter_idx: 0,
        policy_counter: None,
    };

    assert!(install_helper_local_session_on_miss(
        &mut sessions,
        -1,
        &shared_sessions,
        &shared_nat_sessions,
        &shared_forward_wire_sessions,
        &shared_owner_rg_indexes,
        &key,
        decision,
        metadata,
        SessionOrigin::LocalMiss,
        1_000_000,
        PROTO_TCP,
        0x10,
        false,
    ));
    assert!(sessions.lookup(&key, 1_000_000, 0x10).is_some());
    assert!(
        shared_sessions
            .lock()
            .expect("shared lock")
            .get(&key)
            .is_none()
    );
    assert!(shared_nat_sessions.lock().expect("nat lock").is_empty());
    assert!(
        shared_forward_wire_sessions
            .lock()
            .expect("forward wire lock")
            .is_empty()
    );
}

#[test]
fn helper_local_session_on_miss_clears_stale_shared_aliases() {
    let mut sessions = SessionTable::new();
    let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
    let state = build_forwarding_state(&nat_snapshot());
    let key = SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        src_ip: "172.16.80.8".parse().expect("src"),
        dst_ip: "172.16.80.200".parse().expect("dst"),
        src_port: 40278,
        dst_port: 5201,
            discriminator: Default::default(),
            routing_domain: 0,
    };
    let decision = SessionDecision {
        resolution: ingress_interface_local_resolution_on_session_miss(
            &state, 11, 80, key.src_ip, PROTO_TCP,
        )
        .expect("tcp ingress local delivery"),
        nat: NatDecision::default(),
    };
    let metadata = SessionMetadata {
        ingress_zone: TEST_LAN_ZONE_ID,
        egress_zone: TEST_WAN_ZONE_ID,
        ingress_ifindex: 0,
        ingress_vlan_id: 0,
        owner_rg_id: 0,
        fabric_ingress: false,
        is_reverse: false,
        nat64_reverse: None,
        log_session_init: false,
        log_session_close: false,
        policy_id: 0,
        inactivity_timeout_ns: None,
        policy_counter_idx: 0,
        policy_counter: None,
    };
    let entry = SyncedSessionEntry {
        key: key.clone(),
        decision,
        metadata: metadata.clone(),
        origin: SessionOrigin::SyncImport,
        protocol: PROTO_TCP,
        tcp_flags: 0x10,
        // #2170 test fixture: no peer install generation.
        generation: 0,
        session_id: 0,
    };

    // Install with SyncImport origin so take_synced_local recognizes
    // this as a peer-synced session.
    assert!(sessions.install_with_protocol_with_origin(
        key.clone(),
        decision,
        metadata,
        SessionOrigin::SyncImport,
        1_000_000,
        PROTO_TCP,
        0x10,
    ));
    publish_shared_session(
        &shared_sessions,
        &shared_nat_sessions,
        &shared_forward_wire_sessions,
        &shared_owner_rg_indexes,
        &entry,
    );

    assert!(install_helper_local_session_on_miss(
        &mut sessions,
        -1,
        &shared_sessions,
        &shared_nat_sessions,
        &shared_forward_wire_sessions,
        &shared_owner_rg_indexes,
        &key,
        decision,
        entry.metadata.clone(),
        SessionOrigin::LocalMiss,
        2_000_000,
        PROTO_TCP,
        0x10,
        false,
    ));
    assert!(
        shared_sessions
            .lock()
            .expect("shared lock")
            .get(&key)
            .is_none()
    );
    assert!(shared_nat_sessions.lock().expect("nat lock").is_empty());
    assert!(
        shared_forward_wire_sessions
            .lock()
            .expect("forward wire lock")
            .is_empty()
    );
}

#[test]
fn unsolicited_dns_reply_respects_flow_knob() {
    let mut state = build_forwarding_state(&nat_snapshot());
    let flow = SessionFlow {
        src_ip: "172.16.80.53".parse().expect("src"),
        dst_ip: "10.0.61.102".parse().expect("dst"),
        forward_key: SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_UDP,
            src_ip: "172.16.80.53".parse().expect("src"),
            dst_ip: "10.0.61.102".parse().expect("dst"),
            src_port: 53,
            dst_port: 5353,
                    discriminator: Default::default(),
                    routing_domain: 0,
        },
    };
    state.allow_dns_reply = true;
    assert!(allow_unsolicited_dns_reply(&state, &flow));
    state.allow_dns_reply = false;
    assert!(!allow_unsolicited_dns_reply(&state, &flow));
}

#[test]
fn policy_selection_permits_matching_zone_pair() {
    let state = build_forwarding_state(&nat_snapshot());
    let flow = SessionFlow {
        src_ip: "10.0.61.102".parse().expect("src"),
        dst_ip: "172.16.80.200".parse().expect("dst"),
        forward_key: SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            src_ip: "10.0.61.102".parse().expect("src"),
            dst_ip: "172.16.80.200".parse().expect("dst"),
            src_port: 12345,
            dst_port: 5201,
                    discriminator: Default::default(),
                    routing_domain: 0,
        },
    };
    let (from_id, to_id) = zone_pair_ids_for_flow(&state, 24, 12);
    assert_eq!(
        evaluate_policy(
            &state.policy,
            from_id,
            to_id,
            flow.src_ip,
            flow.dst_ip,
            flow.forward_key.protocol,
            flow.forward_key.src_port,
            flow.forward_key.dst_port,
        ),
        PolicyAction::Permit
    );
}

#[test]
fn policy_selection_denies_on_default_policy() {
    let state = build_forwarding_state(&policy_deny_snapshot());
    let flow = SessionFlow {
        src_ip: "10.0.61.102".parse().expect("src"),
        dst_ip: "172.16.80.200".parse().expect("dst"),
        forward_key: SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            src_ip: "10.0.61.102".parse().expect("src"),
            dst_ip: "172.16.80.200".parse().expect("dst"),
            src_port: 12345,
            dst_port: 5201,
                    discriminator: Default::default(),
                    routing_domain: 0,
        },
    };
    let (from_id, to_id) = zone_pair_ids_for_flow(&state, 24, 12);
    assert_eq!(
        evaluate_policy(
            &state.policy,
            from_id,
            to_id,
            flow.src_ip,
            flow.dst_ip,
            flow.forward_key.protocol,
            flow.forward_key.src_port,
            flow.forward_key.dst_port,
        ),
        PolicyAction::Deny
    );
}

#[test]
fn policy_selection_deny_emits_rt_flow_event() {
    let mut snapshot = policy_deny_snapshot();
    snapshot.zones = vec![
        ZoneSnapshot {
            name: "lan".to_string(),
            id: TEST_LAN_ZONE_ID,
            ..Default::default()
        },
        ZoneSnapshot {
            name: "wan".to_string(),
            id: TEST_WAN_ZONE_ID,
            ..Default::default()
        },
        ZoneSnapshot {
            name: "dmz".to_string(),
            id: TEST_DMZ_ZONE_ID,
            ..Default::default()
        },
    ];
    let state = build_forwarding_state(&snapshot);
    let flow = SessionFlow {
        src_ip: "10.0.61.102".parse().expect("src"),
        dst_ip: "172.16.80.200".parse().expect("dst"),
        forward_key: SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            src_ip: "10.0.61.102".parse().expect("src"),
            dst_ip: "172.16.80.200".parse().expect("dst"),
            src_port: 12345,
            dst_port: 5201,
                    discriminator: Default::default(),
                    routing_domain: 0,
        },
    };
    let (from_id, to_id) = zone_pair_ids_for_flow(&state, 24, 12);
    let action = evaluate_policy(
        &state.policy,
        from_id,
        to_id,
        flow.src_ip,
        flow.dst_ip,
        flow.forward_key.protocol,
        flow.forward_key.src_port,
        flow.forward_key.dst_port,
    );
    assert_eq!(action, PolicyAction::Deny);

    let (event_handle, event_rx) = crate::event_stream::test_worker_handle(
        8,
        DataplaneEventRateLimitConfig {
            events_per_second: 0,
            burst: 0,
        },
    );
    let meta = UserspaceDpMeta {
        ingress_ifindex: 24,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        pkt_len: 60,
        ..Default::default()
    };

    super::super::emit_policy_deny_event(
        Some(&event_handle),
        &flow,
        &crate::nat::NatDecision::default(),
        meta,
        from_id,
        to_id,
        1,
        42,
        action,
        0,
        // #3615: action is Deny (asserted above), so reject_reply_enqueued is
        // ignored — pass false.
        false,
        123,
    );

    let event = event_rx
        .try_recv()
        .expect("policy-deny event")
        .decode_dataplane_event()
        .expect("policy-deny payload");
    assert_eq!(event.kind, DataplaneEventKind::PolicyDeny);
    assert_eq!(event.action, 0);
    assert_eq!(event.reason, 5);
    assert_eq!(event.ingress_zone_id, TEST_LAN_ZONE_ID);
    assert_eq!(event.egress_zone_id, TEST_WAN_ZONE_ID);
    assert_eq!(event.ingress_ifindex, 24);
    assert_eq!(event.policy_id, 42);
    assert_eq!(event.rule_id, 42);
    assert_eq!(event.src_port, 12345);
    assert_eq!(event.dst_port, 5201);
    assert_eq!(event_handle.dataplane_event_stats().policy_deny.sent, 1);
}

#[test]
fn forwarding_resolution_reports_egress_and_neighbor() {
    let state = build_forwarding_state(&forwarding_snapshot(true));
    let resolved = lookup_forwarding_resolution(&state, IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
    assert_eq!(
        resolved.disposition,
        ForwardingDisposition::ForwardCandidate
    );
    assert_eq!(resolved.egress_ifindex, 12);
    assert_eq!(
        resolved.next_hop,
        Some(IpAddr::V4(Ipv4Addr::new(172, 16, 50, 1)))
    );
    assert_eq!(
        resolved.neighbor_mac,
        Some([0x00, 0x11, 0x22, 0x33, 0x44, 0x55])
    );
}

#[test]
fn forwarding_resolution_supports_next_table_recursion() {
    let state = build_forwarding_state(&forwarding_snapshot_with_next_table(true));
    let resolved = lookup_forwarding_resolution(&state, IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
    assert_eq!(
        resolved.disposition,
        ForwardingDisposition::ForwardCandidate
    );
    assert_eq!(resolved.egress_ifindex, 12);
    assert_eq!(
        resolved.next_hop,
        Some(IpAddr::V4(Ipv4Addr::new(172, 16, 50, 1)))
    );

    let resolved_v6 = lookup_forwarding_resolution(
        &state,
        IpAddr::V6("2606:4700:4700::1111".parse().expect("ipv6")),
    );
    assert_eq!(
        resolved_v6.disposition,
        ForwardingDisposition::ForwardCandidate
    );
    assert_eq!(resolved_v6.egress_ifindex, 12);
    assert_eq!(
        resolved_v6.next_hop,
        Some(IpAddr::V6("2001:559:8585:50::1".parse().expect("v6 nh")))
    );
}

#[test]
fn forwarding_state_normalizes_ipv6_routes_emitted_in_inet_table() {
    let mut snapshot = forwarding_snapshot(true);
    // Override ONLY the table name (inet.0) for a v6-destination route to
    // exercise `canonical_route_table` (inet.0 -> inet6.0 when the destination
    // parses as v6). #3771 (M4): the `family` must stay consistent with the
    // destination ("inet6") — a family="inet" here now fails the snapshot
    // CLOSED (RouteFamilyMismatch) rather than being silently ignored, so the
    // fixture keeps its correct v6 family.
    snapshot.routes[1].table = "inet.0".to_string();
    let state = build_forwarding_state(&snapshot);
    let resolved = lookup_forwarding_resolution(
        &state,
        IpAddr::V6("2606:4700:4700::1111".parse().expect("ipv6")),
    );
    assert_eq!(
        resolved.disposition,
        ForwardingDisposition::ForwardCandidate
    );
    assert_eq!(resolved.egress_ifindex, 12);
    assert_eq!(
        resolved.next_hop,
        Some(IpAddr::V6("2001:559:8585:50::1".parse().expect("v6 nh")))
    );
}

#[test]
fn canonical_route_table_borrows_default_and_owns_vrf() {
    // #4674: the default-table remaps must borrow the 'static
    // DEFAULT_V4_TABLE/DEFAULT_V6_TABLE constants so the per-new-flow FIB
    // resolution path allocates nothing; only the rare per-VRF suffix rewrite
    // or a non-canonical passthrough owns a heap String. RED-on-revert: the
    // pre-#4674 `String` return type cannot match the `Cow::Borrowed` /
    // `Cow::Owned` patterns, so this test fails to compile against the
    // reverted signature.
    use crate::afxdp::forwarding::fib::{DEFAULT_V4_TABLE, DEFAULT_V6_TABLE};
    use std::borrow::Cow;

    // v4 -> v6 default remap: borrowed (zero alloc), equals inet6.0.
    let v6_default = canonical_route_table("inet.0", true);
    assert!(matches!(v6_default, Cow::Borrowed(_)));
    assert_eq!(v6_default, "inet6.0");

    // v6 -> v4 default remap: borrowed (zero alloc), equals inet.0.
    let v4_default = canonical_route_table("inet6.0", false);
    assert!(matches!(v4_default, Cow::Borrowed(_)));
    assert_eq!(v4_default, "inet.0");

    // Per-VRF suffix rewrite: owned (rare path), correct family rewrite.
    let vrf_v6 = canonical_route_table("myvrf.inet.0", true);
    assert!(matches!(vrf_v6, Cow::Owned(_)));
    assert_eq!(vrf_v6, "myvrf.inet6.0");

    let vrf_v4 = canonical_route_table("myvrf.inet6.0", false);
    assert!(matches!(vrf_v4, Cow::Owned(_)));
    assert_eq!(vrf_v4, "myvrf.inet.0");

    // Non-canonical passthrough: BORROWED since #7204 (A1-b7-F5), unchanged.
    //
    // This assertion used to require `Cow::Owned`, pinning the copy rather than
    // the behaviour: the function returned its own argument and allocated only
    // to satisfy a `'static` return type. That is the allocation A1-b7-F5 is
    // about, and it was on the common same-family path, so the assertion has
    // been flipped rather than deleted — the VALUE assertion below is what this
    // case was really guarding and it is unchanged.
    let passthrough = canonical_route_table("custom.table", true);
    assert!(
        matches!(passthrough, Cow::Borrowed(_)),
        "a name with nothing to rewrite must be borrowed, not copied (#7204)"
    );
    assert_eq!(passthrough, "custom.table");
}

#[test]
fn dynamic_neighbor_cache_enables_forward_candidate() {
    let state = build_forwarding_state(&forwarding_snapshot(false));
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
    dynamic_neighbors.insert(
        (12, IpAddr::V4(Ipv4Addr::new(172, 16, 50, 1))),
        NeighborEntry {
            mac: [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
        },
    );
    let resolved = lookup_forwarding_resolution_with_dynamic(
        &state,
        &dynamic_neighbors,
        IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
    );
    assert_eq!(
        resolved.disposition,
        ForwardingDisposition::ForwardCandidate
    );
    assert_eq!(
        resolved.neighbor_mac,
        Some([0x00, 0x11, 0x22, 0x33, 0x44, 0x55])
    );
}

#[test]
fn parse_neighbor_entries_accepts_stale_ipv4_and_ipv6_rows() {
    let parsed = parse_neighbor_entries(
        "172.16.80.200 lladdr ba:86:e9:f6:4b:d5 STALE\n2001:559:8585:80::200 lladdr ba:86:e9:f6:4b:d5 STALE\n",
    );
    assert_eq!(parsed.len(), 2);
    assert_eq!(parsed[0].0, IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)));
    assert_eq!(
        parsed[1].0,
        IpAddr::V6("2001:559:8585:80::200".parse().expect("ipv6"))
    );
    assert_eq!(parsed[0].1.mac, [0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5]);
    assert_eq!(parsed[1].1.mac, [0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5]);
}

/// #3771 (M12): neighbor-state classification is an ALLOWLIST, not the pre-fix
/// denylist. A recognized usable state installs; failed/incomplete are known-
/// unusable; an empty / `none` / future / corrupt token is UNKNOWN (skipped +
/// counted). Fail-on-revert: the denylist
/// (`!(contains("failed") || contains("incomplete"))`) classifies `none` /
/// `bogus` as usable, flipping the `Unknown` assertions and
/// `!neighbor_state_usable("none")` red.
#[test]
fn classify_neighbor_state_is_an_allowlist() {
    for s in [
        "reachable",
        "stale",
        "delay",
        "probe",
        "permanent",
        "noarp",
        "REACHABLE",
        "Stale",
    ] {
        assert_eq!(
            classify_neighbor_state(s),
            NeighborStateClass::Usable,
            "{s} must be usable"
        );
        assert!(neighbor_state_usable(s), "{s} must be usable");
    }
    for s in ["failed", "incomplete", "FAILED", "reachable|failed"] {
        assert_eq!(
            classify_neighbor_state(s),
            NeighborStateClass::KnownUnusable,
            "{s} must be known-unusable"
        );
        assert!(!neighbor_state_usable(s), "{s} must not be usable");
    }
    for s in ["", "none", "bogus", "future-state", "stale|bogus"] {
        assert_eq!(
            classify_neighbor_state(s),
            NeighborStateClass::Unknown,
            "{s} must be unknown"
        );
        assert!(!neighbor_state_usable(s), "{s} must not be usable");
    }
}

#[test]
fn learned_ingress_neighbor_enables_reverse_lan_resolution() {
    let state = build_forwarding_state(&nat_snapshot());
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
    learn_dynamic_neighbor(
        &state,
        &dynamic_neighbors,
        24,
        0,
        IpAddr::V4(Ipv4Addr::new(10, 0, 61, 100)),
        [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
    );
    let resolved = lookup_forwarding_resolution_with_dynamic(
        &state,
        &dynamic_neighbors,
        IpAddr::V4(Ipv4Addr::new(10, 0, 61, 100)),
    );
    assert_eq!(
        resolved.disposition,
        ForwardingDisposition::ForwardCandidate
    );
    assert_eq!(resolved.egress_ifindex, 24);
    assert_eq!(
        resolved.neighbor_mac,
        Some([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])
    );
}

#[test]
fn learned_vlan_ingress_neighbor_maps_to_logical_ifindex() {
    let state = build_forwarding_state(&nat_snapshot());
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
    learn_dynamic_neighbor(
        &state,
        &dynamic_neighbors,
        11,
        80,
        IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
        [0xde, 0xad, 0xbe, 0xef, 0x00, 0x01],
    );
    let resolved = lookup_forwarding_resolution_with_dynamic(
        &state,
        &dynamic_neighbors,
        IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
    );
    assert_eq!(
        resolved.disposition,
        ForwardingDisposition::ForwardCandidate
    );
    assert_eq!(resolved.egress_ifindex, 12);
    assert_eq!(
        resolved.neighbor_mac,
        Some([0xde, 0xad, 0xbe, 0xef, 0x00, 0x01])
    );
}

// #1787: end-state assertions for the cheap-first learn rework. The
// elision decision itself is covered by the pure-helper matrix in
// neighbor_dispatch::learn_precheck_tests (map contents cannot
// distinguish an elided write from an idempotent overwrite).

const LEARN_MAC_A: [u8; 6] = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
const LEARN_MAC_B: [u8; 6] = [0x66, 0x55, 0x44, 0x33, 0x22, 0x11];

#[test]
fn learn_dynamic_neighbor_first_learn_inserts_single_key_without_vlan() {
    let state = build_forwarding_state(&nat_snapshot());
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
    let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 61, 100));
    // reth1.0 has no parent: (24, 0) resolves to logical 24 ==
    // ingress, so exactly one key is written.
    learn_dynamic_neighbor(&state, &dynamic_neighbors, 24, 0, ip, LEARN_MAC_A);
    assert_eq!(
        dynamic_neighbors.get(&(24, ip)).map(|e| e.mac),
        Some(LEARN_MAC_A)
    );
    // The unused stack-array placeholder key (0, ip) must never leak
    // into the map.
    assert!(dynamic_neighbors.get(&(0, ip)).is_none());
    assert_eq!(dynamic_neighbors.len(), 1);
}

#[test]
fn learn_dynamic_neighbor_vlan_first_learn_inserts_both_keys() {
    let state = build_forwarding_state(&nat_snapshot());
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
    let ip = IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200));
    // (11, vlan 80) resolves to logical sub-interface 12: the #949
    // pair — physical 11 AND logical 12 — is written together.
    learn_dynamic_neighbor(&state, &dynamic_neighbors, 11, 80, ip, LEARN_MAC_A);
    assert_eq!(
        dynamic_neighbors.get(&(11, ip)).map(|e| e.mac),
        Some(LEARN_MAC_A)
    );
    assert_eq!(
        dynamic_neighbors.get(&(12, ip)).map(|e| e.mac),
        Some(LEARN_MAC_A)
    );
    assert_eq!(dynamic_neighbors.len(), 2);
}

#[test]
fn learn_dynamic_neighbor_same_mac_relearn_is_noop_precheck() {
    let state = build_forwarding_state(&nat_snapshot());
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
    let ip = IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200));
    learn_dynamic_neighbor(&state, &dynamic_neighbors, 11, 80, ip, LEARN_MAC_A);
    // After the first learn, the pre-check decision for the same MAC
    // must be "no write needed" — this is the steady-state elision.
    let current = [
        dynamic_neighbors.get(&(11, ip)).map(|e| e.mac),
        dynamic_neighbors.get(&(12, ip)).map(|e| e.mac),
    ];
    assert!(!pair_write_needed(&current, LEARN_MAC_A));
    // A second identical learn leaves contents unchanged.
    learn_dynamic_neighbor(&state, &dynamic_neighbors, 11, 80, ip, LEARN_MAC_A);
    assert_eq!(
        dynamic_neighbors.get(&(11, ip)).map(|e| e.mac),
        Some(LEARN_MAC_A)
    );
    assert_eq!(
        dynamic_neighbors.get(&(12, ip)).map(|e| e.mac),
        Some(LEARN_MAC_A)
    );
    assert_eq!(dynamic_neighbors.len(), 2);
}

#[test]
fn learn_dynamic_neighbor_mac_flip_updates_both_keys() {
    let state = build_forwarding_state(&nat_snapshot());
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
    let ip = IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200));
    learn_dynamic_neighbor(&state, &dynamic_neighbors, 11, 80, ip, LEARN_MAC_A);
    learn_dynamic_neighbor(&state, &dynamic_neighbors, 11, 80, ip, LEARN_MAC_B);
    assert_eq!(
        dynamic_neighbors.get(&(11, ip)).map(|e| e.mac),
        Some(LEARN_MAC_B)
    );
    assert_eq!(
        dynamic_neighbors.get(&(12, ip)).map(|e| e.mac),
        Some(LEARN_MAC_B)
    );
    assert_eq!(dynamic_neighbors.len(), 2);
}

#[test]
fn learn_dynamic_neighbor_relearns_removed_key() {
    let state = build_forwarding_state(&nat_snapshot());
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
    let ip = IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200));
    learn_dynamic_neighbor(&state, &dynamic_neighbors, 11, 80, ip, LEARN_MAC_A);
    // A remove (netlink delete / resolver revoke / manager replace)
    // takes one half of the pair out. The next learn that reaches
    // this function pre-check-misses and restores BOTH keys via the
    // bulk path.
    dynamic_neighbors.remove(&(12, ip));
    assert!(dynamic_neighbors.get(&(12, ip)).is_none());
    learn_dynamic_neighbor(&state, &dynamic_neighbors, 11, 80, ip, LEARN_MAC_A);
    assert_eq!(
        dynamic_neighbors.get(&(11, ip)).map(|e| e.mac),
        Some(LEARN_MAC_A)
    );
    assert_eq!(
        dynamic_neighbors.get(&(12, ip)).map(|e| e.mac),
        Some(LEARN_MAC_A)
    );
}

#[test]
fn forwarding_resolution_rejects_next_table_loop() {
    let state = build_forwarding_state(&forwarding_snapshot_with_next_table_loop());
    let resolved = lookup_forwarding_resolution(&state, IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
    assert_eq!(
        resolved.disposition,
        ForwardingDisposition::NextTableUnsupported
    );
}

// #3768 (M5): the v6 next-table recursion must canonicalize the next-table
// name for the v6 family before looking it up. Here the v6 leak route
// carries its next-table in the WRONG v4 form ("blue.inet.0") — exactly
// what the pre-#3768-H6 Go emitter produced. routes_v6 is keyed as
// "blue.inet6.0", so without canonicalization the recursion into
// "blue.inet.0" misses -> NoRoute -> the leaked IPv6 route blackholes. With
// the M5 fix the recursion rewrites "blue.inet.0" -> "blue.inet6.0" and the
// lookup hits the VRF v6 table. On revert of M5 this asserts RED (NoRoute
// instead of ForwardCandidate).
#[test]
fn forwarding_v6_next_table_canonicalizes_inet_form_on_recursion() {
    let mut snapshot = forwarding_snapshot_with_next_table(true);
    // routes[2] is the v6 leak: inet6.0 -> next_table blue.inet6.0. Rewrite
    // it to the v4-form name a pre-H6 snapshot would carry.
    assert_eq!(snapshot.routes[2].table, "inet6.0");
    assert_eq!(snapshot.routes[2].next_table, "blue.inet6.0");
    snapshot.routes[2].next_table = "blue.inet.0".to_string();

    let state = build_forwarding_state(&snapshot);
    let resolved = lookup_forwarding_resolution(
        &state,
        IpAddr::V6("2606:4700:4700::1111".parse().expect("ipv6")),
    );
    assert_eq!(
        resolved.disposition,
        ForwardingDisposition::ForwardCandidate,
        "v6 next-table in .inet.0 form must canonicalize to the v6 VRF table"
    );
    assert_eq!(resolved.egress_ifindex, 12);
    assert_eq!(
        resolved.next_hop,
        Some(IpAddr::V6("2001:559:8585:50::1".parse().expect("v6 nh")))
    );
}

// #3768 (M6): an A->B->A cross-table next-table cycle is rejected as
// NextTableUnsupported via the per-resolution visited-table set. The
// pre-fix guard only caught a direct self-loop (next == current table), so
// a two-table cycle recursed until MAX_NEXT_TABLE_DEPTH. This asserts the
// terminal disposition and that resolution terminates (no hang / panic);
// the visited set makes it terminate at the first revisit rather than
// burning the full depth budget.
#[test]
fn forwarding_resolution_rejects_cross_table_next_table_cycle() {
    let snapshot = ConfigSnapshot {
        routes: vec![
            crate::RouteSnapshot {
                table: "inet.0".to_string(),
                family: "inet".to_string(),
                destination: "0.0.0.0/0".to_string(),
                next_hops: vec![],
                discard: false,
                next_table: "red.inet.0".to_string(),
                preference: 0,
            },
            crate::RouteSnapshot {
                table: "red.inet.0".to_string(),
                family: "inet".to_string(),
                destination: "0.0.0.0/0".to_string(),
                next_hops: vec![],
                discard: false,
                next_table: "inet.0".to_string(),
                preference: 0,
            },
        ],
        ..Default::default()
    };
    let state = build_forwarding_state(&snapshot);
    let resolved = lookup_forwarding_resolution(&state, IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
    assert_eq!(
        resolved.disposition,
        ForwardingDisposition::NextTableUnsupported
    );
}

#[test]
fn tx_binding_resolution_prefers_bind_ifindex_for_vlan_units() {
    let state = build_forwarding_state(&nat_snapshot());
    assert_eq!(resolve_tx_binding_ifindex(&state, 12), 11);
}

#[test]
fn tx_binding_resolution_uses_fabric_parent_ifindex() {
    let state = build_forwarding_state(&nat_snapshot_with_fabric());
    assert_eq!(resolve_tx_binding_ifindex(&state, 21), 21);
}

// === #1912: cold ENCAP outer next-hop neighbor keying ===

#[test]
fn outer_neighbor_ifindex_non_tunnel_returns_egress_ifindex() {
    // For a non-tunnel resolution the helper must be byte-identical to
    // egress_ifindex (the off-tunnel path is unchanged).
    let state = build_forwarding_state(&nat_snapshot());
    let resolution = lookup_forwarding_resolution_v4(
        &state,
        None,
        Ipv4Addr::new(172, 16, 80, 200),
        "inet.0",
        0,
        true,
        None,
    );
    assert_eq!(resolution.tunnel_endpoint_id, 0);
    assert_eq!(
        outer_neighbor_ifindex(&state, None, &resolution),
        resolution.egress_ifindex
    );
}

#[test]
fn resolve_tunnel_outer_returns_outer_l3_egress() {
    // The factored SSOT returns the OUTER transport resolution whose
    // egress_ifindex is the outer L3 egress (reth0.80, ifindex 12 — a VLAN
    // subif), NOT the tunnel logical ifindex (gr-0-0-0, 362).
    let state = build_forwarding_state(&native_gre_snapshot(true));
    let outer = resolve_tunnel_outer(&state, None, 1, 0).expect("outer resolves");
    assert_eq!(outer.egress_ifindex, 12);
    // VLAN outer transport: tx_ifindex is the PARENT (bind_ifindex 6), so
    // the neighbor key (the subif) differs from tx_ifindex — keying by
    // tx_ifindex would be wrong.
    assert_eq!(outer.tx_ifindex, 6);
}

#[test]
fn outer_neighbor_ifindex_tunnel_returns_outer_vlan_subif_not_logical_or_parent() {
    // A tunnel-marked resolution carries egress_ifindex = tunnel logical
    // (362) but next_hop = outer hop. The helper must return the outer L3
    // egress (12, the VLAN subif), not the tunnel logical (362) and not the
    // VLAN parent / tx_ifindex (6).
    let state = build_forwarding_state(&native_gre_snapshot(false));
    let resolution = resolve_tunnel_forwarding_resolution(&state, None, 1, 0);
    assert_ne!(resolution.tunnel_endpoint_id, 0);
    assert_eq!(resolution.egress_ifindex, 362);
    assert_eq!(resolution.disposition, ForwardingDisposition::MissingNeighbor);
    let neigh_if = outer_neighbor_ifindex(&state, None, &resolution);
    assert_eq!(neigh_if, 12, "outer L3 subif, not tunnel logical");
    assert_ne!(neigh_if, resolution.egress_ifindex, "not the tunnel logical");
    assert_ne!(neigh_if, resolution.tx_ifindex, "not the VLAN parent");
}

#[test]
fn outer_neighbor_ifindex_missing_endpoint_falls_back_to_egress_ifindex() {
    // The `> 0` fallback: a tunnel-marked resolution whose endpoint id is
    // unknown to live state must fall back to egress_ifindex rather than
    // probe ifindex 0.
    let state = build_forwarding_state(&native_gre_snapshot(true));
    let mut resolution = no_route_resolution(None);
    resolution.tunnel_endpoint_id = 9999; // not present in state
    resolution.egress_ifindex = 777;
    assert_eq!(outer_neighbor_ifindex(&state, None, &resolution), 777);
}

// --- is_ipsec_traffic recognition (#2385) ---------------------------------
//
// Host-terminated IPsec must be steered to the kernel XFRM slow path. The
// recognition predicate must cover ESP (proto 50), AH (proto 51), and IKE /
// NAT-T (UDP 500/4500). AH (#2385) is the regression guard: it was omitted,
// so AH-protected SAs fell through to ordinary transit forwarding and were
// dropped. The dst_port argument is ignored for the protocol-number arms, so
// these cases hold for both IPv4 and IPv6 (the protocol number is the only
// input, taken from meta.protocol regardless of L3 family).

#[test]
fn is_ipsec_traffic_recognizes_ah_proto_51() {
    // FAIL-ON-REVERT: AH (proto 51) must be recognized as IPsec passthrough,
    // exactly like ESP. If PROTO_AH is removed from is_ipsec_traffic this
    // assertion fails. AH carries no transport port, so dst_port is
    // irrelevant — assert across a representative spread of ports.
    assert_eq!(PROTO_AH, 51, "AH protocol number");
    for port in [0u16, 80, 443, 500, 4500, 65535] {
        assert!(
            is_ipsec_traffic(PROTO_AH, port),
            "AH (proto 51) must be IPsec-passthrough regardless of port \
             (port={port})"
        );
    }
}

#[test]
fn is_ipsec_traffic_recognizes_esp_and_ike() {
    // No-regression: ESP (proto 50) and IKE/NAT-T (UDP 500/4500) must still
    // be recognized.
    assert_eq!(PROTO_ESP, 50, "ESP protocol number");
    for port in [0u16, 443, 500, 4500, 65535] {
        assert!(
            is_ipsec_traffic(PROTO_ESP, port),
            "ESP (proto 50) must be IPsec-passthrough regardless of port \
             (port={port})"
        );
    }
    assert!(
        is_ipsec_traffic(PROTO_UDP, 500),
        "IKE on UDP/500 must be IPsec-passthrough"
    );
    assert!(
        is_ipsec_traffic(PROTO_UDP, 4500),
        "NAT-T on UDP/4500 must be IPsec-passthrough"
    );
}

#[test]
fn is_ipsec_traffic_rejects_non_ipsec() {
    // No over-match: ordinary transit protocols must NOT be classified as
    // IPsec passthrough.
    assert!(
        !is_ipsec_traffic(PROTO_TCP, 443),
        "TCP/443 is not IPsec passthrough"
    );
    assert!(
        !is_ipsec_traffic(PROTO_UDP, 53),
        "UDP/53 (DNS) is not IPsec passthrough"
    );
    assert!(
        !is_ipsec_traffic(PROTO_UDP, 4499),
        "UDP near-miss port is not IPsec passthrough"
    );
    // GRE (proto 47) sits between UDP(17) and ESP(50)/AH(51) — guard the
    // protocol boundary so the predicate does not widen to a range check.
    assert!(
        !is_ipsec_traffic(PROTO_GRE, 0),
        "GRE (proto 47) is not IPsec passthrough"
    );
}

// ---------------------------------------------------------------------------
// #2388 / #2389 / #2390 — Rust FIB route-snapshot correctness regressions.
// Each test FAILS if the corresponding fix is reverted.
// ---------------------------------------------------------------------------

/// #2388: connected routes must be table-scoped. Two routing-instances own
/// the SAME connected prefix (10.0.0.0/24) on different interfaces. A
/// lookup in tenant-b's table must resolve to tenant-b's interface, never
/// leak to tenant-a's connected route. Revert (drop the `entry.table ==
/// table` filter in the connected scan) → the global scan returns
/// tenant-a's interface (pushed first) → egress mismatch → RED.
#[test]
fn connected_routes_are_table_scoped_no_cross_vrf_leak() {
    let snapshot = crate::ConfigSnapshot {
        zones: vec![
            crate::ZoneSnapshot {
                name: "za".to_string(),
                id: TEST_TRUST_ZONE_ID,
                ..Default::default()
            },
            crate::ZoneSnapshot {
                name: "zb".to_string(),
                id: TEST_UNTRUST_ZONE_ID,
                ..Default::default()
            },
        ],
        interfaces: vec![
            crate::InterfaceSnapshot {
                name: "ge-0/0/1.80".to_string(),
                zone: "za".to_string(),
                routing_instance: "tenant-a".to_string(),
                linux_name: "ge-0-0-1.80".to_string(),
                ifindex: 101,
                hardware_addr: "02:00:00:00:00:a1".to_string(),
                addresses: vec![crate::InterfaceAddressSnapshot {
                    family: "inet".to_string(),
                    address: "10.0.0.1/24".to_string(),
                    scope: 0,
                }],
                ..Default::default()
            },
            crate::InterfaceSnapshot {
                name: "ge-0/0/1.90".to_string(),
                zone: "zb".to_string(),
                routing_instance: "tenant-b".to_string(),
                linux_name: "ge-0-0-1.90".to_string(),
                ifindex: 202,
                hardware_addr: "02:00:00:00:00:b2".to_string(),
                addresses: vec![crate::InterfaceAddressSnapshot {
                    family: "inet".to_string(),
                    address: "10.0.0.1/24".to_string(),
                    scope: 0,
                }],
                ..Default::default()
            },
        ],
        ..Default::default()
    };
    let state = build_forwarding_state(&snapshot);

    // A lookup directed into tenant-b's table for a host in the overlapping
    // prefix must egress tenant-b's interface (202), never tenant-a's (101).
    let resolved = lookup_forwarding_resolution_v4(
        &state,
        None,
        Ipv4Addr::new(10, 0, 0, 42),
        "tenant-b.inet.0",
        0,
        true,
        None,
    );
    assert_eq!(
        resolved.egress_ifindex, 202,
        "tenant-b lookup must resolve tenant-b's connected interface, not tenant-a's (cross-VRF leak)",
    );

    // And the mirror: tenant-a's table resolves tenant-a's interface.
    let resolved_a = lookup_forwarding_resolution_v4(
        &state,
        None,
        Ipv4Addr::new(10, 0, 0, 42),
        "tenant-a.inet.0",
        0,
        true,
        None,
    );
    assert_eq!(resolved_a.egress_ifindex, 101);
}

/// #3151: local-delivery (to-self) resolution must be table-scoped, mirroring
/// the #2388 route-path fix. Two routing-instances own the SAME local address
/// (10.0.0.1) on different interfaces. A to-self packet resolved in tenant-b's
/// table must attribute local/egress/tx ifindex to tenant-b's interface (202),
/// never leak to tenant-a's (101, pushed first). Revert (drop the
/// `entry.table == table` filter in the local-delivery connected scan) → the
/// global scan returns tenant-a's interface → wrong VRF/zone/RG attribution →
/// RED.
#[test]
fn local_delivery_is_table_scoped_no_cross_vrf_leak() {
    let snapshot = crate::ConfigSnapshot {
        zones: vec![
            crate::ZoneSnapshot {
                name: "za".to_string(),
                id: TEST_TRUST_ZONE_ID,
                tcp_rst: false,
                ..Default::default()
            },
            crate::ZoneSnapshot {
                name: "zb".to_string(),
                id: TEST_UNTRUST_ZONE_ID,
                tcp_rst: false,
                ..Default::default()
            },
        ],
        interfaces: vec![
            crate::InterfaceSnapshot {
                name: "ge-0/0/1.80".to_string(),
                zone: "za".to_string(),
                routing_instance: "tenant-a".to_string(),
                linux_name: "ge-0-0-1.80".to_string(),
                ifindex: 101,
                hardware_addr: "02:00:00:00:00:a1".to_string(),
                addresses: vec![crate::InterfaceAddressSnapshot {
                    family: "inet".to_string(),
                    address: "10.0.0.1/32".to_string(),
                    scope: 0,
                }],
                ..Default::default()
            },
            crate::InterfaceSnapshot {
                name: "ge-0/0/1.90".to_string(),
                zone: "zb".to_string(),
                routing_instance: "tenant-b".to_string(),
                linux_name: "ge-0-0-1.90".to_string(),
                ifindex: 202,
                hardware_addr: "02:00:00:00:00:b2".to_string(),
                addresses: vec![crate::InterfaceAddressSnapshot {
                    family: "inet".to_string(),
                    address: "10.0.0.1/32".to_string(),
                    scope: 0,
                }],
                ..Default::default()
            },
        ],
        ..Default::default()
    };
    let state = build_forwarding_state(&snapshot);
    let neighbors = Arc::new(ShardedNeighborMap::new());

    // The destination is one of our own local addresses (to-self): it is in
    // both VRFs' connected lists. Resolved in tenant-b's table → tenant-b's
    // interface (202).
    let resolved_b = lookup_forwarding_resolution_in_table_with_dynamic(
        &state,
        &neighbors,
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        Some("tenant-b.inet.0"),
    );
    assert_eq!(
        resolved_b.disposition,
        ForwardingDisposition::LocalDelivery,
        "to-self traffic must be local-delivery",
    );
    assert_eq!(
        resolved_b.local_ifindex, 202,
        "tenant-b to-self must attribute tenant-b's interface, not tenant-a's (cross-VRF leak)",
    );
    assert_eq!(resolved_b.egress_ifindex, 202);

    // Mirror: tenant-a's table resolves tenant-a's interface (101).
    let resolved_a = lookup_forwarding_resolution_in_table_with_dynamic(
        &state,
        &neighbors,
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        Some("tenant-a.inet.0"),
    );
    assert_eq!(resolved_a.local_ifindex, 101);
}

/// #3151 (v6): identical table-scoped local-delivery guarantee for the IPv6
/// branch (connected_v6). Revert the `entry.table == table` filter → tenant-a
/// leak → RED.
#[test]
fn local_delivery_v6_is_table_scoped_no_cross_vrf_leak() {
    let snapshot = crate::ConfigSnapshot {
        zones: vec![
            crate::ZoneSnapshot {
                name: "za".to_string(),
                id: TEST_TRUST_ZONE_ID,
                tcp_rst: false,
                ..Default::default()
            },
            crate::ZoneSnapshot {
                name: "zb".to_string(),
                id: TEST_UNTRUST_ZONE_ID,
                tcp_rst: false,
                ..Default::default()
            },
        ],
        interfaces: vec![
            crate::InterfaceSnapshot {
                name: "ge-0/0/1.80".to_string(),
                zone: "za".to_string(),
                routing_instance: "tenant-a".to_string(),
                linux_name: "ge-0-0-1.80".to_string(),
                ifindex: 301,
                hardware_addr: "02:00:00:00:00:a1".to_string(),
                addresses: vec![crate::InterfaceAddressSnapshot {
                    family: "inet6".to_string(),
                    address: "2001:db8::1/128".to_string(),
                    scope: 0,
                }],
                ..Default::default()
            },
            crate::InterfaceSnapshot {
                name: "ge-0/0/1.90".to_string(),
                zone: "zb".to_string(),
                routing_instance: "tenant-b".to_string(),
                linux_name: "ge-0-0-1.90".to_string(),
                ifindex: 402,
                hardware_addr: "02:00:00:00:00:b2".to_string(),
                addresses: vec![crate::InterfaceAddressSnapshot {
                    family: "inet6".to_string(),
                    address: "2001:db8::1/128".to_string(),
                    scope: 0,
                }],
                ..Default::default()
            },
        ],
        ..Default::default()
    };
    let state = build_forwarding_state(&snapshot);
    let neighbors = Arc::new(ShardedNeighborMap::new());

    let resolved_b = lookup_forwarding_resolution_in_table_with_dynamic(
        &state,
        &neighbors,
        IpAddr::V6("2001:db8::1".parse().unwrap()),
        Some("tenant-b.inet6.0"),
    );
    assert_eq!(
        resolved_b.disposition,
        ForwardingDisposition::LocalDelivery,
    );
    assert_eq!(
        resolved_b.local_ifindex, 402,
        "tenant-b to-self (v6) must attribute tenant-b's interface, not tenant-a's",
    );

    let resolved_a = lookup_forwarding_resolution_in_table_with_dynamic(
        &state,
        &neighbors,
        IpAddr::V6("2001:db8::1".parse().unwrap()),
        Some("tenant-a.inet6.0"),
    );
    assert_eq!(resolved_a.local_ifindex, 301);
}

/// #3769: the local-delivery DECISION (not merely the ifindex ATTRIBUTION
/// #3151) must be table-scoped for a static-NAT external IP, which has NO
/// connected route so its owning routing-instance was previously lost. The
/// external IP is inserted into the GLOBAL `local_v4` set; before #3769 a
/// packet resolved in a DIFFERENT VRF hit the global membership and
/// short-circuited to LocalDelivery (ifindex 0), bypassing that VRF's FIB +
/// zone/policy + HA-RG owner check. After #3769 only the owning VRF delivers
/// locally. Revert (remove the `local_tables_v4` table gate on the
/// membership shortcut) → tenant-a resolves LocalDelivery → RED.
#[test]
fn static_nat_local_delivery_is_table_scoped_no_cross_vrf_leak() {
    let snapshot = crate::ConfigSnapshot {
        static_nat_rules: vec![crate::StaticNATRuleSnapshot {
            name: "web".to_string(),
            from_routing_instance: "tenant-b".to_string(),
            external_ip: "203.0.113.10".to_string(),
            internal_ip: "192.168.1.10".to_string(),
            ..Default::default()
        }],
        ..Default::default()
    };
    let state = build_forwarding_state(&snapshot);
    let neighbors = Arc::new(ShardedNeighborMap::new());
    let ext = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10));

    // The external IP is a member of the GLOBAL local set (precondition —
    // otherwise the shortcut is never reached and the test proves nothing).
    assert!(
        state.local_v4.contains(&Ipv4Addr::new(203, 0, 113, 10)),
        "static-NAT external IP must be a global local-delivery member",
    );

    // Owning VRF (tenant-b): the NAT subsystem owns the external IP →
    // LocalDelivery, ifindex 0 (no interface owns a NAT external IP; #3769 L5
    // gates this ifindex-0 delivery on table ownership).
    let owner = lookup_forwarding_resolution_in_table_with_dynamic(
        &state,
        &neighbors,
        ext,
        Some("tenant-b.inet.0"),
    );
    assert_eq!(
        owner.disposition,
        ForwardingDisposition::LocalDelivery,
        "NAT external IP must local-deliver in its OWN routing-instance",
    );
    assert_eq!(
        owner.local_ifindex, 0,
        "a NAT-only external IP has no interface → ifindex 0 (gated, counted)",
    );

    // Cross-VRF (tenant-a): NOT owned here → must NOT leak to LocalDelivery;
    // it follows the tenant-a FIB (no route → NoRoute).
    let cross = lookup_forwarding_resolution_in_table_with_dynamic(
        &state,
        &neighbors,
        ext,
        Some("tenant-a.inet.0"),
    );
    assert_ne!(
        cross.disposition,
        ForwardingDisposition::LocalDelivery,
        "a VRF-A packet to a NAT address owned only in VRF-B must NOT \
         short-circuit to LocalDelivery (#3769 cross-VRF leak)",
    );
    assert_eq!(
        cross.disposition,
        ForwardingDisposition::NoRoute,
        "tenant-a has no route for the tenant-b NAT external IP",
    );

    // Default table (None → inet.0): also not the owner → no leak.
    let dflt =
        lookup_forwarding_resolution_in_table_with_dynamic(&state, &neighbors, ext, None);
    assert_ne!(
        dflt.disposition,
        ForwardingDisposition::LocalDelivery,
        "default-table packet to a tenant-b NAT external IP must not leak",
    );
}

/// #3769 (DNAT): identical table-scoped local-delivery guarantee for a DNAT
/// destination IP owned by a rule in tenant-b. Revert the table gate →
/// tenant-a leaks to LocalDelivery → RED.
#[test]
fn dnat_local_delivery_is_table_scoped_no_cross_vrf_leak() {
    let snapshot = crate::ConfigSnapshot {
        destination_nat_rules: vec![crate::DestinationNATRuleSnapshot {
            name: "web-dnat".to_string(),
            from_routing_instance: "tenant-b".to_string(),
            destination_address: "198.51.100.20".to_string(),
            destination_port: 443,
            protocol: "tcp".to_string(),
            pool_address: "10.0.61.102".to_string(),
            pool_port: 8443,
            ..Default::default()
        }],
        ..Default::default()
    };
    let state = build_forwarding_state(&snapshot);
    let neighbors = Arc::new(ShardedNeighborMap::new());
    let dst = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20));

    let owner = lookup_forwarding_resolution_in_table_with_dynamic(
        &state,
        &neighbors,
        dst,
        Some("tenant-b.inet.0"),
    );
    assert_eq!(
        owner.disposition,
        ForwardingDisposition::LocalDelivery,
        "DNAT destination IP must local-deliver in its owning VRF",
    );

    let cross = lookup_forwarding_resolution_in_table_with_dynamic(
        &state,
        &neighbors,
        dst,
        Some("tenant-a.inet.0"),
    );
    assert_eq!(
        cross.disposition,
        ForwardingDisposition::NoRoute,
        "cross-VRF packet to a DNAT destination owned in tenant-b must \
         follow the tenant-a FIB, not LocalDelivery (#3769)",
    );
}

/// #3769 (v6): a static-NAT external IPv6 owned in tenant-b must not
/// local-deliver a tenant-a packet. Revert the `local_tables_v6` gate → RED.
#[test]
fn nat_local_delivery_v6_is_table_scoped_no_cross_vrf_leak() {
    let snapshot = crate::ConfigSnapshot {
        static_nat_rules: vec![crate::StaticNATRuleSnapshot {
            name: "web6".to_string(),
            from_routing_instance: "tenant-b".to_string(),
            external_ip: "2001:db8:ff::10".to_string(),
            internal_ip: "2001:db8:1::10".to_string(),
            ..Default::default()
        }],
        ..Default::default()
    };
    let state = build_forwarding_state(&snapshot);
    let neighbors = Arc::new(ShardedNeighborMap::new());
    let ext: IpAddr = "2001:db8:ff::10".parse().unwrap();

    let owner = lookup_forwarding_resolution_in_table_with_dynamic(
        &state,
        &neighbors,
        ext,
        Some("tenant-b.inet6.0"),
    );
    assert_eq!(owner.disposition, ForwardingDisposition::LocalDelivery);
    assert_eq!(owner.local_ifindex, 0);

    let cross = lookup_forwarding_resolution_in_table_with_dynamic(
        &state,
        &neighbors,
        ext,
        Some("tenant-a.inet6.0"),
    );
    assert_ne!(
        cross.disposition,
        ForwardingDisposition::LocalDelivery,
        "v6 NAT external IP owned in tenant-b must not local-deliver a \
         tenant-a packet (#3769)",
    );
}

/// #3769: default routing-instance (from-routing-instance "") behaviour is
/// unchanged — a default-VRF NAT external IP still LocalDelivers in inet.0 —
/// and the ifindex-0 diagnostic counter advances for the NAT-only delivery.
#[test]
fn nat_local_delivery_default_vrf_unchanged_and_counts_ifindex0() {
    let snapshot = crate::ConfigSnapshot {
        static_nat_rules: vec![crate::StaticNATRuleSnapshot {
            name: "web-default".to_string(),
            from_routing_instance: String::new(), // default instance
            external_ip: "203.0.113.50".to_string(),
            internal_ip: "192.168.1.50".to_string(),
            ..Default::default()
        }],
        ..Default::default()
    };
    let state = build_forwarding_state(&snapshot);
    let neighbors = Arc::new(ShardedNeighborMap::new());
    let ext = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 50));

    let before = LOCAL_DELIVERY_IFINDEX0.load(std::sync::atomic::Ordering::Relaxed);
    // Default table via explicit inet.0 and via None both deliver locally.
    for table in [Some("inet.0"), None] {
        let r = lookup_forwarding_resolution_in_table_with_dynamic(
            &state, &neighbors, ext, table,
        );
        assert_eq!(
            r.disposition,
            ForwardingDisposition::LocalDelivery,
            "default-VRF NAT external IP must local-deliver in the default table",
        );
        assert_eq!(r.local_ifindex, 0, "NAT-only external IP → ifindex 0");
    }
    let after = LOCAL_DELIVERY_IFINDEX0.load(std::sync::atomic::Ordering::Relaxed);
    assert!(
        after >= before + 2,
        "ifindex-0 LocalDelivery counter must advance for NAT-only delivery \
         (before={before}, after={after})",
    );
}

/// #3769: the table-scoped DECISION also fixes the interface-address residual
/// #3151 left — an interface IP owned in ONLY ONE routing-instance must not
/// LocalDeliver a packet resolved in a DIFFERENT instance (the #3151 test used
/// the SAME IP in BOTH VRFs; here it exists in tenant-b only). Before #3769 the
/// global `local_v4` membership short-circuited the tenant-a packet to
/// LocalDelivery with ifindex 0; after #3769 it falls through to the tenant-a
/// FIB. Revert the decision gate → tenant-a LocalDelivery → RED.
#[test]
fn interface_local_delivery_single_vrf_no_cross_vrf_leak() {
    let snapshot = crate::ConfigSnapshot {
        zones: vec![crate::ZoneSnapshot {
            name: "zb".to_string(),
            id: TEST_UNTRUST_ZONE_ID,
            tcp_rst: false,
            ..Default::default()
        }],
        interfaces: vec![crate::InterfaceSnapshot {
            name: "ge-0/0/1.90".to_string(),
            zone: "zb".to_string(),
            routing_instance: "tenant-b".to_string(),
            linux_name: "ge-0-0-1.90".to_string(),
            ifindex: 202,
            hardware_addr: "02:00:00:00:00:b2".to_string(),
            addresses: vec![crate::InterfaceAddressSnapshot {
                family: "inet".to_string(),
                address: "10.0.0.1/32".to_string(),
                scope: 0,
            }],
            ..Default::default()
        }],
        ..Default::default()
    };
    let state = build_forwarding_state(&snapshot);
    let neighbors = Arc::new(ShardedNeighborMap::new());
    let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

    // Owning VRF (tenant-b): interface owns it → LocalDelivery with the real
    // ifindex (unchanged #3151 attribution).
    let owner = lookup_forwarding_resolution_in_table_with_dynamic(
        &state,
        &neighbors,
        ip,
        Some("tenant-b.inet.0"),
    );
    assert_eq!(owner.disposition, ForwardingDisposition::LocalDelivery);
    assert_eq!(owner.local_ifindex, 202);

    // Cross-VRF (tenant-a): the interface IP is not owned here → no leak.
    let cross = lookup_forwarding_resolution_in_table_with_dynamic(
        &state,
        &neighbors,
        ip,
        Some("tenant-a.inet.0"),
    );
    assert_ne!(
        cross.disposition,
        ForwardingDisposition::LocalDelivery,
        "an interface IP owned only in tenant-b must not local-deliver a \
         tenant-a packet (#3769 generalizes #3151)",
    );
}

/// #3769 (review MINOR): an UNSCOPED NAT/DNAT rule (`from routing-instance`
/// empty — the common `from zone` / `from interface` inbound-DNAT case) is a
/// WILDCARD that `scope_ok` matches against ANY ingress routing-instance.
/// Attributing its external IP to `inet.0` only would over-isolate it when the
/// ingress zone lives in a non-default VRF. The external IP must resolve as
/// locally-owned in a NAMED VRF too (via `local_nat_any_table_v*`), NOT fall
/// through to NoRoute. Revert (route the empty scope through
/// `connected_route_tables("")` → inet.0 only) → this goes NoRoute in
/// tenant-a → RED. The named-VRF isolation tests above must still hold.
#[test]
fn unscoped_nat_local_delivery_is_wildcard_across_vrfs() {
    let snapshot = crate::ConfigSnapshot {
        static_nat_rules: vec![crate::StaticNATRuleSnapshot {
            name: "web-unscoped".to_string(),
            from_zone: "untrust".to_string(), // zone-scoped → RI left empty
            from_routing_instance: String::new(),
            external_ip: "203.0.113.77".to_string(),
            internal_ip: "192.168.1.77".to_string(),
            ..Default::default()
        }],
        destination_nat_rules: vec![crate::DestinationNATRuleSnapshot {
            name: "dnat-unscoped".to_string(),
            from_zone: "untrust".to_string(),
            from_routing_instance: String::new(),
            destination_address: "198.51.100.88".to_string(),
            destination_port: 443,
            protocol: "tcp".to_string(),
            pool_address: "10.0.61.88".to_string(),
            pool_port: 8443,
            ..Default::default()
        }],
        ..Default::default()
    };
    let state = build_forwarding_state(&snapshot);
    let neighbors = Arc::new(ShardedNeighborMap::new());
    let ext = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 77));
    let dnat = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 88));

    // Unscoped externals must local-deliver in EVERY table: the default table
    // AND a named non-default VRF (mirrors `scope_ok`'s wildcard).
    for table in [None, Some("inet.0"), Some("tenant-a.inet.0")] {
        let r = lookup_forwarding_resolution_in_table_with_dynamic(
            &state, &neighbors, ext, table,
        );
        assert_eq!(
            r.disposition,
            ForwardingDisposition::LocalDelivery,
            "unscoped static-NAT external must local-deliver in table {table:?} \
             (wildcard), not fall through to NoRoute (#3769 review MINOR)",
        );
        let d = lookup_forwarding_resolution_in_table_with_dynamic(
            &state, &neighbors, dnat, table,
        );
        assert_eq!(
            d.disposition,
            ForwardingDisposition::LocalDelivery,
            "unscoped DNAT destination must local-deliver in table {table:?} (wildcard)",
        );
    }
}

/// #2389: a static route with two next-hops must retain BOTH in the FIB
/// (equal-cost), and a dead first next-hop must fall back to a live
/// alternate. Revert the build to `next_hops.first()` → only one candidate
/// retained → len 1 → RED; revert the selection → a dead NH[0] blackholes.
#[test]
fn ecmp_static_route_retains_all_next_hops_and_skips_dead() {
    let snapshot = crate::ConfigSnapshot {
        zones: vec![crate::ZoneSnapshot {
            name: "wan".to_string(),
            id: TEST_WAN_ZONE_ID,
            ..Default::default()
        }],
        interfaces: vec![
            crate::InterfaceSnapshot {
                name: "ge-0/0/1".to_string(),
                zone: "wan".to_string(),
                linux_name: "ge-0-0-1".to_string(),
                ifindex: 11,
                hardware_addr: "02:00:00:00:00:11".to_string(),
                addresses: vec![crate::InterfaceAddressSnapshot {
                    family: "inet".to_string(),
                    address: "192.0.2.1/24".to_string(),
                    scope: 0,
                }],
                ..Default::default()
            },
            crate::InterfaceSnapshot {
                name: "ge-0/0/2".to_string(),
                zone: "wan".to_string(),
                linux_name: "ge-0-0-2".to_string(),
                ifindex: 22,
                hardware_addr: "02:00:00:00:00:22".to_string(),
                addresses: vec![crate::InterfaceAddressSnapshot {
                    family: "inet".to_string(),
                    address: "192.0.3.1/24".to_string(),
                    scope: 0,
                }],
                ..Default::default()
            },
        ],
        routes: vec![crate::RouteSnapshot {
            table: "inet.0".to_string(),
            family: "inet".to_string(),
            destination: "203.0.113.0/24".to_string(),
            // Two equal-cost next-hops, each via a distinct interface.
            next_hops: vec![
                "192.0.2.2@ge-0/0/1".to_string(),
                "192.0.3.2@ge-0/0/2".to_string(),
            ],
            discard: false,
            next_table: String::new(),
            preference: 5,
        }],
        // Only the SECOND next-hop's neighbor is resolved; the first is dead.
        neighbors: vec![crate::NeighborSnapshot {
            interface: "ge-0-0-2".to_string(),
            ifindex: 22,
            family: "inet".to_string(),
            ip: "192.0.3.2".to_string(),
            mac: "00:11:22:33:44:66".to_string(),
            state: "reachable".to_string(),
            router: true,
            link_local: false,
        }],
        ..Default::default()
    };
    let state = build_forwarding_state(&snapshot);

    // Build retains BOTH next-hops (not just the first).
    let route = &state.routes_v4.get("inet.0").expect("table")[0];
    assert_eq!(
        route.next_hops.len(),
        2,
        "ECMP route must retain all next-hops, not collapse to the first",
    );

    // Selection skips the dead first next-hop and forwards via the live
    // second (egress ge-0/0/2 = ifindex 22), producing a ForwardCandidate
    // rather than a MissingNeighbor blackhole on NH[0].
    let resolved = lookup_forwarding_resolution_v4(
        &state,
        None,
        Ipv4Addr::new(203, 0, 113, 5),
        "inet.0",
        0,
        true,
        None,
    );
    assert_eq!(
        resolved.disposition,
        ForwardingDisposition::ForwardCandidate,
        "live alternate next-hop must forward despite a dead first next-hop",
    );
    assert_eq!(
        resolved.egress_ifindex, 22,
        "must egress the live next-hop's interface",
    );
}

/// #5161: a MIXED ECMP group of a GATEWAY member (explicit next-hop, already
/// resolved) plus an INTERFACE-ONLY member (`next_hop == None`, a "via <if>"
/// candidate whose neighbor is the PER-FLOW destination) must select BOTH
/// members — ECMP width 2, not collapsed to width-1.
///
/// The interface-only member's neighbor is the destination itself, which the
/// coordinator warmer cannot pre-resolve (it is a whole prefix, unknown at
/// route-sweep time). The pre-#5161 `is_live` closure gated EVERY direct
/// member on `neighbor-resolved-on-that-ifindex`, evaluating the target as the
/// destination for an interface-only member. With the gateway member already
/// resolved the live set was non-empty, so the unresolved interface-only
/// member was permanently excluded → every flow pinned to the gateway member
/// → ECMP starved to width-1.
///
/// The fix marks an up interface-only member LIVE (`ifindex > 0`) so it joins
/// the live set; the MissingNeighbor cold path then resolves the destination
/// lazily per flow (mirroring the single-member interface-only path). Here the
/// gateway member (192.0.2.2 via ge-0/0/1, ifindex 11) is resolved and the
/// interface-only member (via ge-0/0/2, ifindex 22) has NO destination
/// neighbor. Sweeping distinct per-flow hashes must reach BOTH egress
/// interfaces, and the interface-only member must forward as MissingNeighbor.
///
/// FAIL-ON-REVERT: revert the `if nh.next_hop.is_none() { return nh.ifindex >
/// 0 }` branch in the v4 selection closure and the interface-only member is
/// dead again; with the gateway member live, selection collapses to ifindex 11
/// only, so `egress_seen` never contains 22 (width 1) and the disposition
/// probe stays None → both interface-only assertions go RED.
#[test]
fn ecmp_interface_only_member_is_live_alongside_gateway() {
    let snapshot = crate::ConfigSnapshot {
        zones: vec![crate::ZoneSnapshot {
            name: "wan".to_string(),
            id: TEST_WAN_ZONE_ID,
            ..Default::default()
        }],
        interfaces: vec![
            crate::InterfaceSnapshot {
                name: "ge-0/0/1".to_string(),
                zone: "wan".to_string(),
                linux_name: "ge-0-0-1".to_string(),
                ifindex: 11,
                hardware_addr: "02:00:00:00:00:11".to_string(),
                addresses: vec![crate::InterfaceAddressSnapshot {
                    family: "inet".to_string(),
                    address: "192.0.2.1/24".to_string(),
                    scope: 0,
                }],
                ..Default::default()
            },
            crate::InterfaceSnapshot {
                name: "ge-0/0/2".to_string(),
                zone: "wan".to_string(),
                linux_name: "ge-0-0-2".to_string(),
                ifindex: 22,
                hardware_addr: "02:00:00:00:00:22".to_string(),
                addresses: vec![crate::InterfaceAddressSnapshot {
                    family: "inet".to_string(),
                    address: "192.0.3.1/24".to_string(),
                    scope: 0,
                }],
                ..Default::default()
            },
        ],
        routes: vec![crate::RouteSnapshot {
            table: "inet.0".to_string(),
            family: "inet".to_string(),
            destination: "203.0.113.0/24".to_string(),
            // Member 0: explicit gateway via ge-0/0/1. Member 1: INTERFACE-ONLY
            // (empty IP part before '@') via ge-0/0/2 — `next_hop == None`.
            next_hops: vec![
                "192.0.2.2@ge-0/0/1".to_string(),
                "@ge-0/0/2".to_string(),
            ],
            discard: false,
            next_table: String::new(),
            preference: 5,
        }],
        // ONLY the gateway member's neighbor is resolved. The interface-only
        // member's neighbor (the per-flow destination) is deliberately absent —
        // it can only resolve lazily once the member is actually selected.
        neighbors: vec![crate::NeighborSnapshot {
            interface: "ge-0-0-1".to_string(),
            ifindex: 11,
            family: "inet".to_string(),
            ip: "192.0.2.2".to_string(),
            mac: "00:11:22:33:44:55".to_string(),
            state: "reachable".to_string(),
            router: true,
            link_local: false,
        }],
        ..Default::default()
    };
    let state = build_forwarding_state(&snapshot);

    // Sanity: the FIB built member 1 as a genuine interface-only candidate
    // (`next_hop == None`, ifindex 22). Guards against a future next-hop
    // string-format change silently turning this into a gateway member (which
    // would make the test pass trivially).
    let route = &state.routes_v4.get("inet.0").expect("table")[0];
    assert_eq!(route.next_hops.len(), 2, "ECMP route must retain both members");
    assert!(
        route.next_hops[1].next_hop.is_none() && route.next_hops[1].ifindex == 22,
        "member 1 must be an interface-only candidate (next_hop==None, ifindex 22)",
    );

    // Sweep distinct per-flow hashes and collect the set of selected egress
    // interfaces plus the interface-only member's disposition.
    let mut egress_seen: std::collections::BTreeSet<i32> = std::collections::BTreeSet::new();
    let mut interface_only_disposition: Option<ForwardingDisposition> = None;
    for h in 0u64..64 {
        let r = lookup_forwarding_resolution_v4(
            &state,
            None,
            Ipv4Addr::new(203, 0, 113, 5),
            "inet.0",
            0,
            true,
            Some(h),
        );
        egress_seen.insert(r.egress_ifindex);
        if r.egress_ifindex == 22 {
            interface_only_disposition = Some(r.disposition);
        }
    }

    assert!(
        egress_seen.contains(&11),
        "gateway member (ifindex 11) must remain selectable",
    );
    assert!(
        egress_seen.contains(&22),
        "#5161: interface-only member (ifindex 22, next_hop==None) must join the \
         live ECMP set — not starve to width-1 behind the resolved gateway member",
    );
    assert_eq!(
        egress_seen.len(),
        2,
        "ECMP must spread across BOTH members (width 2), not collapse to width-1",
    );
    assert_eq!(
        interface_only_disposition,
        Some(ForwardingDisposition::MissingNeighbor),
        "interface-only member forwards via the MissingNeighbor cold path so its \
         destination resolves lazily per flow",
    );
}

/// #2923: a MIXED direct+tunnel ECMP group must select BOTH paths. The
/// pre-fix liveness closure gated EVERY candidate on `ifindex > 0 &&
/// neighbor-resolved-on-that-ifindex`. A tunnel next-hop is the logical
/// tunnel ifindex with no neighbor for the inner destination, so it always
/// failed that gate. With a live DIRECT member also present, `live > 0`
/// restricted selection to the direct member and the tunnel path was
/// starved — every flow pinned to the direct hop, the tunnel endpoint never
/// selected even though its underlay was fully up.
///
/// The fix makes liveness type-aware: a tunnel candidate is live when its
/// endpoint resolves a usable underlay (`resolve_tunnel_outer`). This test
/// builds a direct hop (egress ifindex 11) plus a GRE tunnel hop (endpoint
/// id 1, logical ifindex 362, IPv6 outer that resolves via reth0.80 with a
/// live neighbor) on ONE inet.0 ECMP prefix, and asserts that sweeping the
/// per-flow hash selects BOTH the direct egress (11) and the tunnel egress
/// (362, carrying tunnel_endpoint_id 1).
///
/// FAIL-ON-REVERT: revert the tunnel-liveness branch in the v4 selection
/// closure and the tunnel candidate is marked dead again; with the direct
/// member live, selection collapses to ifindex 11 only and the tunnel egress
/// assertion goes RED (tunnel starved).
#[test]
fn ecmp_mixed_direct_and_tunnel_selects_both_paths() {
    // Base GRE fixture: tunnel endpoint id 1 on gr-0/0/0.0 (logical ifindex
    // 362), IPv6 outer destination resolving via reth0.80 (ifindex 12) with
    // a live outer neighbor (include_neighbor = true).
    let mut snapshot = native_gre_snapshot(true);
    // Add a DIRECT next-hop interface in a routable zone with a live neighbor.
    snapshot.interfaces.push(crate::InterfaceSnapshot {
        name: "ge-0/0/1".to_string(),
        zone: "wan".to_string(),
        linux_name: "ge-0-0-1".to_string(),
        ifindex: 11,
        hardware_addr: "02:00:00:00:00:11".to_string(),
        addresses: vec![crate::InterfaceAddressSnapshot {
            family: "inet".to_string(),
            address: "192.0.2.1/24".to_string(),
            scope: 0,
        }],
        ..Default::default()
    });
    snapshot.neighbors.push(crate::NeighborSnapshot {
        interface: "ge-0-0-1".to_string(),
        ifindex: 11,
        family: "inet".to_string(),
        ip: "192.0.2.2".to_string(),
        mac: "00:11:22:33:44:77".to_string(),
        state: "reachable".to_string(),
        router: true,
        link_local: false,
    });
    // One inet.0 ECMP prefix with a mixed direct + tunnel next-hop set.
    snapshot.routes.push(crate::RouteSnapshot {
        table: "inet.0".to_string(),
        family: "inet".to_string(),
        destination: "203.0.113.0/24".to_string(),
        next_hops: vec![
            "192.0.2.2@ge-0/0/1".to_string(), // direct
            "@gr-0/0/0.0".to_string(),        // tunnel (endpoint id 1)
        ],
        discard: false,
        next_table: String::new(),
        preference: 5,
    });
    let state = build_forwarding_state(&snapshot);

    // The FIB retains BOTH next-hops, and exactly one carries a tunnel id.
    let route = &state.routes_v4.get("inet.0").expect("table")[0];
    assert_eq!(route.next_hops.len(), 2, "ECMP route must retain both hops");
    assert!(
        route.next_hops.iter().any(|nh| nh.tunnel_endpoint_id == 1),
        "the tunnel next-hop must carry tunnel_endpoint_id 1",
    );
    assert!(
        route.next_hops.iter().any(|nh| nh.tunnel_endpoint_id == 0),
        "the direct next-hop must carry no tunnel id",
    );

    // Sweep the per-flow hash; both the direct egress (11) and the tunnel
    // egress (logical ifindex 362) must be selected. Pre-fix, the tunnel
    // candidate is dead and selection collapses to 11 only.
    let mut egresses = std::collections::BTreeSet::new();
    let mut saw_tunnel_id = false;
    for h in 0u64..64 {
        let resolved = lookup_forwarding_resolution_v4(
            &state,
            None,
            Ipv4Addr::new(203, 0, 113, 5),
            "inet.0",
            0,
            true,
            Some(h),
        );
        assert_eq!(
            resolved.disposition,
            ForwardingDisposition::ForwardCandidate,
            "both the direct and tunnel members must forward (live)",
        );
        egresses.insert(resolved.egress_ifindex);
        if resolved.tunnel_endpoint_id == 1 {
            saw_tunnel_id = true;
            assert_eq!(
                resolved.egress_ifindex, 362,
                "a tunnel selection must egress the logical tunnel ifindex",
            );
        }
    }
    assert!(
        egresses.contains(&11),
        "the direct ECMP member (ifindex 11) must be selected",
    );
    assert!(
        egresses.contains(&362),
        "the tunnel ECMP member (logical ifindex 362) must be selected \
         — RED pre-fix: the direct-neighbor gate starves the tunnel path",
    );
    assert!(
        saw_tunnel_id,
        "a tunnel selection must carry tunnel_endpoint_id 1",
    );
}

/// #2923 (review finding #1): a tunnel candidate whose OUTER underlay route is
/// WITHDRAWN must be DEAD, not live. `resolve_tunnel_outer` still returns
/// `Some(NoRoute)` for an endpoint with no usable underlay route (it only
/// returns `None` for unknown-endpoint / local-delivery / recursion), so a
/// bare `.is_some()` liveness test would mark the dead tunnel live and ~half
/// the flows in a mixed group would hash to it and DROP (NoRoute) despite a
/// fully live direct member. The fix gates tunnel liveness on a FORWARDABLE
/// disposition (ForwardCandidate | MissingNeighbor).
///
/// FAIL-ON-REVERT: revert `tunnel_next_hop_live` to bare `.is_some()` and the
/// NoRoute tunnel is selected for ~half the hashes → a NoRoute disposition
/// appears and the "all flows forward via the live direct hop" assertion goes
/// RED (partial blackhole).
#[test]
fn ecmp_mixed_with_noroute_underlay_tunnel_uses_only_live_direct_hop() {
    // Same base as the mixed test, but the GRE tunnel's OUTER route
    // (2602:ffd3:0:2::/64 in inet6.0) is WITHDRAWN — its underlay is down, so
    // the outer resolves to NoRoute and the tunnel must be DEAD.
    let mut snapshot = native_gre_snapshot(true);
    snapshot
        .routes
        .retain(|r| r.destination != "2602:ffd3:0:2::/64");
    snapshot.interfaces.push(crate::InterfaceSnapshot {
        name: "ge-0/0/1".to_string(),
        zone: "wan".to_string(),
        linux_name: "ge-0-0-1".to_string(),
        ifindex: 11,
        hardware_addr: "02:00:00:00:00:11".to_string(),
        addresses: vec![crate::InterfaceAddressSnapshot {
            family: "inet".to_string(),
            address: "192.0.2.1/24".to_string(),
            scope: 0,
        }],
        ..Default::default()
    });
    snapshot.neighbors.push(crate::NeighborSnapshot {
        interface: "ge-0-0-1".to_string(),
        ifindex: 11,
        family: "inet".to_string(),
        ip: "192.0.2.2".to_string(),
        mac: "00:11:22:33:44:77".to_string(),
        state: "reachable".to_string(),
        router: true,
        link_local: false,
    });
    snapshot.routes.push(crate::RouteSnapshot {
        table: "inet.0".to_string(),
        family: "inet".to_string(),
        destination: "203.0.113.0/24".to_string(),
        next_hops: vec![
            "192.0.2.2@ge-0/0/1".to_string(), // direct, live
            "@gr-0/0/0.0".to_string(),        // tunnel, underlay WITHDRAWN
        ],
        discard: false,
        next_table: String::new(),
        preference: 5,
    });
    let state = build_forwarding_state(&snapshot);

    // Sweep the per-flow hash: EVERY flow must forward via the live direct hop
    // (ifindex 11). The dead tunnel must never be selected — no NoRoute, no
    // tunnel egress (362).
    let mut egresses = std::collections::BTreeSet::new();
    for h in 0u64..64 {
        let resolved = lookup_forwarding_resolution_v4(
            &state,
            None,
            Ipv4Addr::new(203, 0, 113, 5),
            "inet.0",
            0,
            true,
            Some(h),
        );
        assert_eq!(
            resolved.disposition,
            ForwardingDisposition::ForwardCandidate,
            "no flow may blackhole (NoRoute) on the dead tunnel — every flow \
             must forward via the live direct hop",
        );
        assert_eq!(
            resolved.tunnel_endpoint_id, 0,
            "the dead (NoRoute-underlay) tunnel must never be selected",
        );
        egresses.insert(resolved.egress_ifindex);
    }
    assert_eq!(
        egresses,
        std::collections::BTreeSet::from([11]),
        "every flow must forward via the live direct hop (ifindex 11) — a \
         NoRoute-underlay tunnel must NOT be selected (RED if liveness stays \
         bare .is_some(): the dead tunnel is picked for ~half the hashes)",
    );
}

/// #2923 (review finding #2): the v6 selection path must apply the same
/// type-aware tunnel liveness. Mirrors `ecmp_mixed_direct_and_tunnel_*` but
/// drives `lookup_forwarding_resolution_v6` with an INNER v6 prefix whose ECMP
/// set mixes a direct v6 hop (ifindex 11) and the GRE tunnel hop (endpoint 1,
/// logical ifindex 362, IPv6 outer resolving via reth0.80).
///
/// FAIL-ON-REVERT: revert the v6 tunnel-liveness branch and the tunnel
/// candidate is dead again; with the direct v6 member live, selection
/// collapses to ifindex 11 only and the tunnel-egress assertion goes RED.
#[test]
fn ecmp_mixed_direct_and_tunnel_selects_both_paths_v6() {
    let mut snapshot = native_gre_snapshot(true);
    // Direct v6 next-hop interface in a routable zone with a live v6 neighbor.
    snapshot.interfaces.push(crate::InterfaceSnapshot {
        name: "ge-0/0/1".to_string(),
        zone: "wan".to_string(),
        linux_name: "ge-0-0-1".to_string(),
        ifindex: 11,
        hardware_addr: "02:00:00:00:00:11".to_string(),
        addresses: vec![crate::InterfaceAddressSnapshot {
            family: "inet6".to_string(),
            address: "2001:db8:ec::1/64".to_string(),
            scope: 0,
        }],
        ..Default::default()
    });
    snapshot.neighbors.push(crate::NeighborSnapshot {
        interface: "ge-0-0-1".to_string(),
        ifindex: 11,
        family: "inet6".to_string(),
        ip: "2001:db8:ec::2".to_string(),
        mac: "00:11:22:33:44:88".to_string(),
        state: "reachable".to_string(),
        router: true,
        link_local: false,
    });
    // One inet6.0 INNER ECMP prefix mixing a direct v6 hop + the tunnel hop.
    // (Disjoint from the GRE outer prefix 2602:ffd3:0:2::/64.)
    snapshot.routes.push(crate::RouteSnapshot {
        table: "inet6.0".to_string(),
        family: "inet6".to_string(),
        destination: "2001:db8:dead::/48".to_string(),
        next_hops: vec![
            "2001:db8:ec::2@ge-0/0/1".to_string(), // direct
            "@gr-0/0/0.0".to_string(),             // tunnel (endpoint id 1)
        ],
        discard: false,
        next_table: String::new(),
        preference: 5,
    });
    let state = build_forwarding_state(&snapshot);

    // The inet6.0 table also holds the GRE outer prefix; find OUR mixed prefix.
    let dead_net: Ipv6Addr = "2001:db8:dead::".parse().unwrap();
    let route = state
        .routes_v6
        .get("inet6.0")
        .expect("table")
        .iter()
        .find(|r| r.prefix.contains(dead_net))
        .expect("mixed inet6.0 ECMP route present");
    assert_eq!(route.next_hops.len(), 2, "ECMP route must retain both hops");
    assert!(
        route.next_hops.iter().any(|nh| nh.tunnel_endpoint_id == 1),
        "the tunnel next-hop must carry tunnel_endpoint_id 1",
    );

    let mut egresses = std::collections::BTreeSet::new();
    let mut saw_tunnel_id = false;
    for h in 0u64..64 {
        let resolved = lookup_forwarding_resolution_v6(
            &state,
            None,
            "2001:db8:dead::5".parse::<Ipv6Addr>().unwrap(),
            "inet6.0",
            0,
            true,
            Some(h),
        );
        assert_eq!(
            resolved.disposition,
            ForwardingDisposition::ForwardCandidate,
            "both the direct and tunnel v6 members must forward (live)",
        );
        egresses.insert(resolved.egress_ifindex);
        if resolved.tunnel_endpoint_id == 1 {
            saw_tunnel_id = true;
            assert_eq!(
                resolved.egress_ifindex, 362,
                "a v6 tunnel selection must egress the logical tunnel ifindex",
            );
        }
    }
    assert!(
        egresses.contains(&11),
        "the direct v6 ECMP member (ifindex 11) must be selected",
    );
    assert!(
        egresses.contains(&362),
        "the v6 tunnel ECMP member (logical ifindex 362) must be selected \
         — RED if the v6 tunnel-liveness branch is reverted",
    );
    assert!(
        saw_tunnel_id,
        "a v6 tunnel selection must carry tunnel_endpoint_id 1",
    );
}

/// #2734: ECMP must spread by the per-FLOW 5-tuple, not per-destination.
///
/// Two equal-cost next-hops to the same prefix, BOTH neighbors live.
/// Distinct flows to the SAME destination IP must spread across both
/// members (per-flow), while every probe of ONE flow pins to a single
/// member (flow consistency — no intra-flow reordering). The
/// per-destination fallback (`None`) collapses every flow onto ONE member
/// — that is the pre-#2734 behavior and the fail-on-revert guard: if the
/// production path is reverted to per-dst selection, the spread assertion
/// goes RED.
#[test]
fn ecmp_static_route_spreads_per_flow_not_per_destination() {
    let snapshot = crate::ConfigSnapshot {
        zones: vec![crate::ZoneSnapshot {
            name: "wan".to_string(),
            id: TEST_WAN_ZONE_ID,
            ..Default::default()
        }],
        interfaces: vec![
            crate::InterfaceSnapshot {
                name: "ge-0/0/1".to_string(),
                zone: "wan".to_string(),
                linux_name: "ge-0-0-1".to_string(),
                ifindex: 11,
                hardware_addr: "02:00:00:00:00:11".to_string(),
                addresses: vec![crate::InterfaceAddressSnapshot {
                    family: "inet".to_string(),
                    address: "192.0.2.1/24".to_string(),
                    scope: 0,
                }],
                ..Default::default()
            },
            crate::InterfaceSnapshot {
                name: "ge-0/0/2".to_string(),
                zone: "wan".to_string(),
                linux_name: "ge-0-0-2".to_string(),
                ifindex: 22,
                hardware_addr: "02:00:00:00:00:22".to_string(),
                addresses: vec![crate::InterfaceAddressSnapshot {
                    family: "inet".to_string(),
                    address: "192.0.3.1/24".to_string(),
                    scope: 0,
                }],
                ..Default::default()
            },
        ],
        routes: vec![crate::RouteSnapshot {
            table: "inet.0".to_string(),
            family: "inet".to_string(),
            destination: "203.0.113.0/24".to_string(),
            next_hops: vec![
                "192.0.2.2@ge-0/0/1".to_string(),
                "192.0.3.2@ge-0/0/2".to_string(),
            ],
            discard: false,
            next_table: String::new(),
            preference: 5,
        }],
        // BOTH next-hop neighbors are resolved/live, so the live pool is
        // the full set of equal-cost members.
        neighbors: vec![
            crate::NeighborSnapshot {
                interface: "ge-0-0-1".to_string(),
                ifindex: 11,
                family: "inet".to_string(),
                ip: "192.0.2.2".to_string(),
                mac: "00:11:22:33:44:55".to_string(),
                state: "reachable".to_string(),
                router: true,
                link_local: false,
            },
            crate::NeighborSnapshot {
                interface: "ge-0-0-2".to_string(),
                ifindex: 22,
                family: "inet".to_string(),
                ip: "192.0.3.2".to_string(),
                mac: "00:11:22:33:44:66".to_string(),
                state: "reachable".to_string(),
                router: true,
                link_local: false,
            },
        ],
        ..Default::default()
    };
    let state = build_forwarding_state(&snapshot);
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());

    let dst = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5));
    let make_flow = |src_port: u16| SessionFlow {
        src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 7)),
        dst_ip: dst,
        forward_key: crate::session::SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 7)),
            dst_ip: dst,
            src_port,
            dst_port: 443,
                    discriminator: Default::default(),
                    routing_domain: 0,
        },
    };
    // A non-LocalDelivery, non-tunnel, non-cacheable decision resolution so
    // the production session path RE-RESOLVES via the flow hash (rather than
    // returning a cached ForwardCandidate). This exercises the real wiring
    // (`lookup_forwarding_resolution_for_session`), not just the helper.
    let resolve_for_flow = |flow: &SessionFlow| {
        let decision = SessionDecision {
            resolution: no_route_resolution(None),
            nat: NatDecision::default(),
        };
        lookup_forwarding_resolution_for_session(&state, &dynamic_neighbors, flow, decision)
    };

    // (a) Per-FLOW spread: distinct 5-tuples (varying source port) to the
    // SAME destination must hit BOTH equal-cost members through the real
    // session resolution path.
    let mut egresses = std::collections::BTreeSet::new();
    for src_port in 1024u16..1124 {
        let resolved = resolve_for_flow(&make_flow(src_port));
        assert_eq!(
            resolved.disposition,
            ForwardingDisposition::ForwardCandidate,
            "every live flow must forward",
        );
        egresses.insert(resolved.egress_ifindex);
    }
    assert_eq!(
        egresses,
        std::collections::BTreeSet::from([11, 22]),
        "distinct flows to one dst must spread across BOTH ECMP members \
         (per-flow), not pin to one — RED if reverted to per-destination",
    );

    // (b) Flow consistency: repeated probes of ONE flow pin to ONE member.
    let one_flow = make_flow(1042);
    let pinned = resolve_for_flow(&one_flow).egress_ifindex;
    for _ in 0..50 {
        let again = resolve_for_flow(&one_flow).egress_ifindex;
        assert_eq!(
            again, pinned,
            "a single flow's packets must pin to one member (no reorder)",
        );
    }

    // (c) Fail-on-revert: the per-DESTINATION path (None flow hash, the
    // pre-#2734 behavior) collapses EVERY flow onto a SINGLE member —
    // exactly the spread the per-flow path fixes.
    let mut dst_egresses = std::collections::BTreeSet::new();
    for src_port in 1024u16..1124 {
        // The 5-tuple differs, but the per-dst path ignores it.
        let _ = src_port;
        let resolved = lookup_forwarding_resolution_v4(
            &state,
            Some(&dynamic_neighbors),
            Ipv4Addr::new(203, 0, 113, 5),
            "inet.0",
            0,
            true,
            None,
        );
        dst_egresses.insert(resolved.egress_ifindex);
    }
    assert_eq!(
        dst_egresses.len(),
        1,
        "per-destination ECMP must collapse all flows to one member \
         (the bug #2734 fixes)",
    );
}

/// #2734: the seeded per-flow ECMP hash is deterministic within a boot
/// (flow consistency) and spreads distinct 5-tuples across the index
/// space. Pin the seed so the assertions are stable across the parallel
/// runner; production folds in the per-boot process seed.
#[test]
fn ecmp_flow_hash_is_stable_and_spreads() {
    let key_a = crate::session::SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 7)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5)),
        src_port: 1024,
        dst_port: 443,
            discriminator: Default::default(),
            routing_domain: 0,
    };
    let mut key_b = key_a.clone();
    key_b.src_port = 1025;

    let seed = 0x1234_5678_9abc_def0u64;
    // Intra-seed stability: same key, same hash (a flow never splits).
    assert_eq!(
        ecmp_hash_flow_seeded(seed, &key_a),
        ecmp_hash_flow_seeded(seed, &key_a),
    );
    // Distinct 5-tuples map to distinct hashes under one seed (spread).
    assert_ne!(
        ecmp_hash_flow_seeded(seed, &key_a),
        ecmp_hash_flow_seeded(seed, &key_b),
    );
    // Cross-seed reshuffle: a different per-boot seed remaps the flow.
    assert_ne!(
        ecmp_hash_flow_seeded(seed, &key_a),
        ecmp_hash_flow_seeded(seed ^ 0xffff_ffff_ffff_ffff, &key_a),
    );
}

/// #2390: two same-prefix static routes with different preference must
/// select the lower-preference one regardless of insertion order. The
/// worse route is inserted FIRST. Revert (sort by prefix length only) →
/// insertion order wins → the worse next-hop is selected → RED.
#[test]
fn same_prefix_routes_tie_break_by_preference_not_insertion_order() {
    let snapshot = crate::ConfigSnapshot {
        zones: vec![crate::ZoneSnapshot {
            name: "wan".to_string(),
            id: TEST_WAN_ZONE_ID,
            ..Default::default()
        }],
        interfaces: vec![
            crate::InterfaceSnapshot {
                name: "ge-0/0/1".to_string(),
                zone: "wan".to_string(),
                linux_name: "ge-0-0-1".to_string(),
                ifindex: 11,
                hardware_addr: "02:00:00:00:00:11".to_string(),
                addresses: vec![crate::InterfaceAddressSnapshot {
                    family: "inet".to_string(),
                    address: "192.0.2.1/24".to_string(),
                    scope: 0,
                }],
                ..Default::default()
            },
            crate::InterfaceSnapshot {
                name: "ge-0/0/2".to_string(),
                zone: "wan".to_string(),
                linux_name: "ge-0-0-2".to_string(),
                ifindex: 22,
                hardware_addr: "02:00:00:00:00:22".to_string(),
                addresses: vec![crate::InterfaceAddressSnapshot {
                    family: "inet".to_string(),
                    address: "192.0.3.1/24".to_string(),
                    scope: 0,
                }],
                ..Default::default()
            },
        ],
        routes: vec![
            // WORSE route first (higher preference = less preferred).
            crate::RouteSnapshot {
                table: "inet.0".to_string(),
                family: "inet".to_string(),
                destination: "203.0.113.0/24".to_string(),
                next_hops: vec!["192.0.2.2@ge-0/0/1".to_string()],
                discard: false,
                next_table: String::new(),
                preference: 50,
            },
            // BETTER route second (lower preference).
            crate::RouteSnapshot {
                table: "inet.0".to_string(),
                family: "inet".to_string(),
                destination: "203.0.113.0/24".to_string(),
                next_hops: vec!["192.0.3.2@ge-0/0/2".to_string()],
                discard: false,
                next_table: String::new(),
                preference: 5,
            },
        ],
        neighbors: vec![
            crate::NeighborSnapshot {
                interface: "ge-0-0-1".to_string(),
                ifindex: 11,
                family: "inet".to_string(),
                ip: "192.0.2.2".to_string(),
                mac: "00:11:22:33:44:55".to_string(),
                state: "reachable".to_string(),
                router: true,
                link_local: false,
            },
            crate::NeighborSnapshot {
                interface: "ge-0-0-2".to_string(),
                ifindex: 22,
                family: "inet".to_string(),
                ip: "192.0.3.2".to_string(),
                mac: "00:11:22:33:44:66".to_string(),
                state: "reachable".to_string(),
                router: true,
                link_local: false,
            },
        ],
        ..Default::default()
    };
    let state = build_forwarding_state(&snapshot);

    let resolved = lookup_forwarding_resolution_v4(
        &state,
        None,
        Ipv4Addr::new(203, 0, 113, 5),
        "inet.0",
        0,
        true,
        None,
    );
    assert_eq!(
        resolved.disposition,
        ForwardingDisposition::ForwardCandidate
    );
    assert_eq!(
        resolved.egress_ifindex, 22,
        "lower-preference route (pref 5, ge-0/0/2) must win over the higher-preference route (pref 50, ge-0/0/1) inserted first",
    );
}

/// #2922: `select_route_next_hop` must evaluate the (impure) liveness
/// predicate exactly ONCE per candidate — not twice (count + nth).
///
/// FAIL-ON-REVERT: the pre-#2922 two-pass form called `is_live` for the
/// `count()` pass AND again for the `nth()` pass — `2 * candidates.len()`
/// calls. This test pins the call count to exactly `candidates.len()`, so
/// reverting to the double-eval form makes the assertion RED.
#[test]
fn select_route_next_hop_evaluates_liveness_once_per_candidate() {
    use std::cell::Cell;
    let candidates = [10u32, 20, 30, 40];
    let calls = Cell::new(0usize);
    let selected = select_route_next_hop(&candidates, 1, |_c| {
        calls.set(calls.get() + 1);
        true // all live
    });
    assert_eq!(
        calls.get(),
        candidates.len(),
        "liveness predicate must be evaluated exactly once per candidate (single snapshot); \
         the reverted double-eval form calls it 2x",
    );
    // Selection still works over the live set: ip_hash 1 % 4 live = index 1.
    assert_eq!(selected, Some(&20));
}

/// #2922: a candidate that flips from live→dead between the count pass and
/// the selection pass must not cause a wrong/dead pick (or a spurious
/// no-route). With a single snapshot this is structurally impossible.
///
/// FAIL-ON-REVERT: the closure here returns `true` on the FIRST observation
/// of a given candidate and `false` on every later observation — modeling a
/// neighbor the monitor thread removes between passes. Under the old
/// two-pass form the `count()` pass saw all 4 live (`live == 4`,
/// `pool_len == 4`, `pick == 4 % 4 == 0`), then the `nth(0)` pass re-ran the
/// closure and EVERY candidate now reported dead → the filtered iterator was
/// empty → `nth(0)` returned `None` → spurious no-route despite live members
/// at count time. The single-pass form snapshots liveness once, so the pick
/// resolves to a real, live candidate.
#[test]
fn select_route_next_hop_consistent_under_liveness_flip_between_passes() {
    use std::cell::RefCell;
    use std::collections::HashSet;
    let candidates = [10u32, 20, 30, 40];
    // Each candidate is "live" only the first time it is observed; any
    // subsequent observation (a second pass) reports it dead.
    let seen: RefCell<HashSet<u32>> = RefCell::new(HashSet::new());
    let selected = select_route_next_hop(&candidates, 0, |c| {
        let mut s = seen.borrow_mut();
        s.insert(*c) // true on first insert, false if already present
    });
    assert!(
        selected.is_some(),
        "single liveness snapshot must not yield a spurious no-route when \
         live candidates existed at evaluation time (the reverted double-eval \
         form returns None here)",
    );
    let pick = selected.unwrap();
    assert!(
        candidates.contains(pick),
        "selected next-hop must be a real candidate from the snapshot",
    );
}

// ---------------------------------------------------------------------------
// #3773 (M13): fabric-link skip classification. Before #3773 populate_fabrics
// dropped a fabric link with a malformed peer/local MAC or peer address on a
// bare `continue` — no counter, log, or status — so an HA cross-chassis fabric
// link that silently failed to install (and therefore silently did not
// forward) was invisible to the operator. These tests assert the deterministic
// per-build `fabric_skips` record (race-free) plus the cumulative diagnostic
// atomic (`> before`, safe for a monotonic counter under parallel tests).
// fail-on-revert: reinstating the bare `continue` leaves `fabric_skips` empty
// and bumps no counter → RED.
// ---------------------------------------------------------------------------

fn fabric_snapshot_template() -> FabricSnapshot {
    FabricSnapshot {
        parent_unbindable: false,
        name: "fab0".into(),
        parent_interface: "ge-0/0/0".into(),
        parent_linux_name: "ge-0-0-0".into(),
        parent_ifindex: 21,
        overlay_linux_name: "fab0".into(),
        overlay_ifindex: 101,
        rx_queues: 2,
        peer_address: "10.99.13.2".into(),
        local_mac: "02:bf:72:ff:00:01".into(),
        peer_mac: "00:aa:bb:cc:dd:ee".into(),
        up: true,
    }
}

#[test]
fn fabric_link_well_formed_installs_with_no_skip() {
    let mut snapshot = nat_snapshot();
    snapshot.fabrics = vec![fabric_snapshot_template()];
    let state = build_forwarding_state(&snapshot);
    assert_eq!(state.fabrics.len(), 1, "a well-formed fabric must install");
    assert!(
        state.fabric_skips.is_empty(),
        "a well-formed fabric must not be recorded as skipped: {:?}",
        state.fabric_skips
    );
}

#[test]
fn fabric_link_malformed_peer_mac_is_skipped_and_counted() {
    let before = crate::afxdp::forwarding::FABRIC_LINK_SKIPPED_MALFORMED
        .load(std::sync::atomic::Ordering::Relaxed);
    let mut snapshot = nat_snapshot();
    let mut fab = fabric_snapshot_template();
    fab.peer_mac = "not-a-mac".into(); // NON-EMPTY but unparseable
    snapshot.fabrics = vec![fab];
    let state = build_forwarding_state(&snapshot);
    assert!(
        state.fabrics.is_empty(),
        "a fabric with a malformed peer MAC must not install"
    );
    assert_eq!(state.fabric_skips.len(), 1, "the skip must be recorded");
    assert_eq!(state.fabric_skips[0].name, "fab0");
    assert_eq!(
        state.fabric_skips[0].reason,
        FabricSkipReason::MalformedPeerMac
    );
    assert!(state.fabric_skips[0].reason.is_malformed());
    let after = crate::afxdp::forwarding::FABRIC_LINK_SKIPPED_MALFORMED
        .load(std::sync::atomic::Ordering::Relaxed);
    assert!(
        after > before,
        "a malformed fabric must bump FABRIC_LINK_SKIPPED_MALFORMED"
    );
}

#[test]
fn fabric_link_invalid_parent_ifindex_is_skipped_malformed() {
    let mut snapshot = nat_snapshot();
    let mut fab = fabric_snapshot_template();
    fab.parent_ifindex = 0; // unusable parent netdev index
    snapshot.fabrics = vec![fab];
    let state = build_forwarding_state(&snapshot);
    assert!(state.fabrics.is_empty());
    assert_eq!(state.fabric_skips.len(), 1);
    assert_eq!(
        state.fabric_skips[0].reason,
        FabricSkipReason::InvalidParentIfindex
    );
    assert!(state.fabric_skips[0].reason.is_malformed());
}

#[test]
fn fabric_link_unparseable_peer_address_is_skipped_malformed() {
    let mut snapshot = nat_snapshot();
    let mut fab = fabric_snapshot_template();
    fab.peer_address = "not-an-ip".into();
    snapshot.fabrics = vec![fab];
    let state = build_forwarding_state(&snapshot);
    assert!(state.fabrics.is_empty());
    assert_eq!(state.fabric_skips.len(), 1);
    assert_eq!(
        state.fabric_skips[0].reason,
        FabricSkipReason::UnparseablePeerAddress
    );
}

#[test]
fn fabric_link_empty_peer_mac_is_skipped_as_unresolved_peer() {
    let before = crate::afxdp::forwarding::FABRIC_LINK_UNRESOLVED_PEER
        .load(std::sync::atomic::Ordering::Relaxed);
    let mut snapshot = nat_snapshot();
    let mut fab = fabric_snapshot_template();
    // EMPTY peer MAC + a peer address with no matching neighbor entry: the
    // expected late-resolution transient (awaiting ARP/NDP), classified
    // UNRESOLVED rather than malformed.
    fab.peer_mac = String::new();
    snapshot.fabrics = vec![fab];
    let state = build_forwarding_state(&snapshot);
    assert!(state.fabrics.is_empty());
    assert_eq!(state.fabric_skips.len(), 1);
    assert_eq!(
        state.fabric_skips[0].reason,
        FabricSkipReason::UnresolvedPeerMac
    );
    assert!(
        !state.fabric_skips[0].reason.is_malformed(),
        "an empty (unresolved) peer MAC is a distinct non-malformed state"
    );
    let after = crate::afxdp::forwarding::FABRIC_LINK_UNRESOLVED_PEER
        .load(std::sync::atomic::Ordering::Relaxed);
    assert!(
        after > before,
        "an unresolved fabric peer must bump FABRIC_LINK_UNRESOLVED_PEER"
    );
}

// ===================== #6713: MAC-less egress zone resolution =====================
//
// An IPsec secure tunnel (xfrmi) is `ARPHRD_NONE`: it has no link-layer
// address, so `populate_egress`'s `src_mac` gate skips it and the interface
// gets NO `state.egress` row. All three of that gate's MAC sources fail for it
// unconditionally: `hardware_addr` is empty (netlink reports `hw_len=0`),
// `mac_by_ifindex[bind_ifindex]` is absent (the parent is itself a MAC-less
// xfrmi), and `iface.tunnel` is false (that flag means a Junos
// `tunnel {source destination}` stanza, which `st0` does not have).
//
// The to-zone of a forwarding decision used to be read from `state.egress`
// alone, so a correctly-zoned tunnel adjudicated as zone id 0 — the reserved
// "unknown" sentinel that `evaluate_policy_result_l3_aware` refuses to match
// ANY exact, wildcard or `junos-global` rule against. Every LAN->tunnel packet
// therefore fell to the default policy no matter what the operator permitted.

/// The zone id the #6713 fixture gives the tunnel's `vpn` zone. Reuses an
/// existing test-only constant; only distinctness from the LAN zone matters.
const TEST_VPN_ZONE_ID_6713: u16 = TEST_DMZ_ZONE_ID;

const TUNNEL_IFINDEX_6713: i32 = 42;
const LAN_IFINDEX_6713: i32 = 24;
/// The MAC-ful ifindex a zoned trunk (`ge-0/0/9`) SHARES with its declared but
/// deliberately unzoned unit 0 — `snapshotLinuxName` collapses a non-VLAN unit
/// 0 onto the base netdev, so one ifindex carries two snapshot rows and
/// `populate_egress` (last-write-wins) leaves the unit-0 row's `zone_id == 0`
/// on it while `ifindex_to_zone_id` carries the trunk's zone. The scoping
/// guard.
const TRUNK_UNIT0_IFINDEX_6713: i32 = 90;

/// Policy shape for the #6713 fixture.
#[derive(Clone, Copy, PartialEq, Eq)]
enum TunnelPolicy6713 {
    /// `from-zone lan to-zone vpn ... then permit` -- what an operator writes
    /// for a route-based VPN.
    PermitLanToVpn,
    /// A permit that exists but is scoped to a DIFFERENT zone pair. The tunnel
    /// must NOT inherit it; the default-DENY policy must still deny.
    PermitOtherPairOnly,
    /// `from-zone lan to-zone vpn ... then deny` -- the operator's OWN deny,
    /// which must be the attributed verdict rather than the implicit default.
    DenyLanToVpn,
}

fn secure_tunnel_snapshot_6713(policy: TunnelPolicy6713) -> ConfigSnapshot {
    crate::afxdp::test_fixtures::v5(ConfigSnapshot {
        zones: vec![
            ZoneSnapshot {
                name: "lan".to_string(),
                id: TEST_LAN_ZONE_ID,
                host_inbound_configured: true,
                host_inbound_system_services: vec!["any-service".to_string()],
                ..Default::default()
            },
            ZoneSnapshot {
                name: "vpn".to_string(),
                id: TEST_VPN_ZONE_ID_6713,
                host_inbound_configured: true,
                host_inbound_system_services: vec!["any-service".to_string()],
                ..Default::default()
            },
        ],
        interfaces: vec![
            InterfaceSnapshot {
                name: "reth1.0".to_string(),
                zone: "lan".to_string(),
                linux_name: "ge-0-0-1".to_string(),
                ifindex: LAN_IFINDEX_6713,
                mtu: 1500,
                hardware_addr: "02:bf:72:01:00:01".to_string(),
                addresses: vec![InterfaceAddressSnapshot {
                    family: "inet".to_string(),
                    address: "10.0.61.1/24".to_string(),
                    scope: 0,
                }],
                ..Default::default()
            },
            // The secure tunnel, base + unit 0. Both share the xfrmi's single
            // netdev/ifindex, both carry the `vpn` zone, and NEITHER has a
            // hardware address -- the deployed shape of a route-based VPN.
            InterfaceSnapshot {
                name: "st0".to_string(),
                zone: "vpn".to_string(),
                linux_name: "st0".to_string(),
                ifindex: TUNNEL_IFINDEX_6713,
                mtu: 1400,
                unit_count: 1,
                addresses: vec![InterfaceAddressSnapshot {
                    family: "inet".to_string(),
                    address: "10.5.5.1/30".to_string(),
                    scope: 0,
                }],
                ..Default::default()
            },
            InterfaceSnapshot {
                name: "st0.0".to_string(),
                zone: "vpn".to_string(),
                linux_name: "st0".to_string(),
                parent_linux_name: "st0".to_string(),
                ifindex: TUNNEL_IFINDEX_6713,
                parent_ifindex: TUNNEL_IFINDEX_6713,
                mtu: 1400,
                addresses: vec![InterfaceAddressSnapshot {
                    family: "inet".to_string(),
                    address: "10.5.5.1/30".to_string(),
                    scope: 0,
                }],
                ..Default::default()
            },
            // Scoping control, in the shape the GO BUILDER ACTUALLY EMITS
            // (#6722 r3 — measured with `buildInterfaceZoneMap` +
            // `buildInterfaceSnapshots`, see
            // `pkg/dataplane/userspace/zone_propagation_6722_test.go`):
            //
            //   set interfaces ge-0/0/9 unit 0 family inet filter input guard
            //   set interfaces ge-0/0/9 unit 100 vlan-id 100 family inet address ...
            //   set security zones security-zone lan interfaces ge-0/0/9.100
            //
            // The BASE row arrives carrying `lan` — a unit-suffixed zone
            // reference writes `out[base]` in Go — and unit 0 collapses onto
            // the base netdev, so rows 1 and 2 share ifindex 90 and both are
            // MAC-ful. `populate_egress` is last-write-wins, so the UNZONED
            // unit-0 row wins and `egress[90].zone_id == 0` while
            // `ifindex_to_zone_id[90] == lan`. That divergence is what makes
            // `egress_zone_id`'s `Some(0)` short-circuit load-bearing.
            InterfaceSnapshot {
                name: "ge-0/0/9".to_string(),
                zone: "lan".to_string(),
                linux_name: "ge-0-0-9".to_string(),
                ifindex: TRUNK_UNIT0_IFINDEX_6713,
                mtu: 1500,
                unit_count: 2,
                hardware_addr: "02:bf:72:09:00:00".to_string(),
                ..Default::default()
            },
            InterfaceSnapshot {
                name: "ge-0/0/9.0".to_string(),
                linux_name: "ge-0-0-9".to_string(),
                parent_linux_name: "ge-0-0-9".to_string(),
                ifindex: TRUNK_UNIT0_IFINDEX_6713,
                parent_ifindex: TRUNK_UNIT0_IFINDEX_6713,
                mtu: 1500,
                hardware_addr: "02:bf:72:09:00:00".to_string(),
                ..Default::default()
            },
            InterfaceSnapshot {
                name: "ge-0/0/9.100".to_string(),
                zone: "lan".to_string(),
                linux_name: "ge-0-0-9.100".to_string(),
                parent_linux_name: "ge-0-0-9".to_string(),
                ifindex: 91,
                parent_ifindex: TRUNK_UNIT0_IFINDEX_6713,
                vlan_id: 100,
                mtu: 1500,
                hardware_addr: "02:bf:72:09:00:00".to_string(),
                ..Default::default()
            },
        ],
        routes: vec![RouteSnapshot {
            table: "inet.0".to_string(),
            family: "inet".to_string(),
            destination: "192.168.99.0/24".to_string(),
            next_hops: vec!["10.5.5.2".to_string()],
            discard: false,
            next_table: String::new(),
            preference: 5,
        }],
        default_policy: "deny".to_string(),
        policies: vec![match policy {
            TunnelPolicy6713::PermitLanToVpn => PolicyRuleSnapshot {
                name: "lan-to-vpn".to_string(),
                from_zone: "lan".to_string(),
                to_zone: "vpn".to_string(),
                source_addresses: vec!["any".to_string()],
                destination_addresses: vec!["any".to_string()],
                applications: vec!["any".to_string()],
                application_terms: Vec::new(),
                action: "permit".to_string(),
                ..Default::default()
            },
            // Scoped to (vpn, lan) -- the RETURN pair, not the transit pair
            // under test. A fix that widened the tunnel's zone into "matches
            // anything" would pick this up.
            TunnelPolicy6713::PermitOtherPairOnly => PolicyRuleSnapshot {
                name: "vpn-to-lan".to_string(),
                from_zone: "vpn".to_string(),
                to_zone: "lan".to_string(),
                source_addresses: vec!["any".to_string()],
                destination_addresses: vec!["any".to_string()],
                applications: vec!["any".to_string()],
                application_terms: Vec::new(),
                action: "permit".to_string(),
                ..Default::default()
            },
            TunnelPolicy6713::DenyLanToVpn => PolicyRuleSnapshot {
                name: "lan-to-vpn-deny".to_string(),
                from_zone: "lan".to_string(),
                to_zone: "vpn".to_string(),
                source_addresses: vec!["any".to_string()],
                destination_addresses: vec!["any".to_string()],
                applications: vec!["any".to_string()],
                application_terms: Vec::new(),
                action: "deny".to_string(),
                ..Default::default()
            },
        }],
        ..Default::default()
    })
}

/// Asserts the fixture still reproduces the #6713 shape: the tunnel is zoned,
/// has NO `egress` row, and the real FIB hands its ifindex to the policy site.
/// Without this the zone-pair assertions could pass vacuously.
fn assert_secure_tunnel_preconditions_6713(state: &ForwardingState) -> ForwardingResolution {
    assert!(
        !state.egress.contains_key(&TUNNEL_IFINDEX_6713),
        "precondition: the MAC-less tunnel must have NO state.egress row -- that hole is what \
         #6713 is about. If populate_egress now admits MAC-less interfaces, this test no longer \
         exercises the defect and must be re-pointed."
    );
    assert_eq!(
        state
            .ifindex_to_zone_id
            .get(&TUNNEL_IFINDEX_6713)
            .copied()
            .unwrap_or(0),
        TEST_VPN_ZONE_ID_6713,
        "precondition: the tunnel IS correctly zoned in the authoritative map"
    );
    let resolution = lookup_forwarding_resolution_v4(
        state,
        None,
        "192.168.99.7".parse().expect("dst"),
        "inet.0",
        0,
        true,
        None,
    );
    assert_eq!(
        resolution.egress_ifindex, TUNNEL_IFINDEX_6713,
        "precondition: the real FIB must hand the tunnel ifindex to the policy site \
         (disposition {:?})",
        resolution.disposition
    );
    resolution
}

/// #6713 core, fail-on-revert. A LAN -> secure-tunnel packet must be
/// adjudicated against `(lan, vpn)` and PERMITTED by the operator's explicit
/// `from-zone lan to-zone vpn permit` under a default-DENY policy.
///
/// Revert `ForwardingState::egress_zone_id`'s `ifindex_to_zone_id` fallback and
/// the to-zone collapses to 0, no rule can match, and the action becomes the
/// default Deny -- this test goes RED on both the zone-pair and the action.
#[test]
fn secure_tunnel_to_zone_reaches_policy_6713() {
    let state = build_forwarding_state(&secure_tunnel_snapshot_6713(
        TunnelPolicy6713::PermitLanToVpn,
    ));
    let resolution = assert_secure_tunnel_preconditions_6713(&state);

    let (from_id, to_id) =
        zone_pair_ids_for_flow(&state, LAN_IFINDEX_6713, resolution.egress_ifindex);
    assert_eq!(from_id, TEST_LAN_ZONE_ID, "from-zone");
    assert_eq!(
        to_id, TEST_VPN_ZONE_ID_6713,
        "to-zone must be the tunnel's configured zone, not the 0 'unknown' sentinel"
    );

    let result = crate::policy::evaluate_policy_result_with_icmp(
        &state.policy,
        from_id,
        to_id,
        "10.0.61.102".parse().expect("src"),
        "192.168.99.7".parse().expect("dst"),
        PROTO_TCP,
        40000,
        443,
        None,
        64,
    );
    assert_eq!(
        result.action,
        PolicyAction::Permit,
        "the operator's explicit from-zone lan to-zone vpn permit must match"
    );
    assert_ne!(
        result.policy_id,
        crate::policy::DEFAULT_POLICY_SENTINEL_ID,
        "the verdict must come from the operator's rule, not the implicit default policy"
    );

    // The String twin used by test-only callers must agree with the production
    // u16 resolver -- it reads the same egress-zone helper.
    let (from_zone, to_zone) =
        zone_pair_for_flow(&state, LAN_IFINDEX_6713, resolution.egress_ifindex);
    assert_eq!(from_zone, "lan");
    assert_eq!(to_zone, "vpn");
}

/// #6713 fail-CLOSED direction. The fix must not turn "policy cannot see the
/// tunnel" into "the tunnel is permitted". With the SAME topology and NO
/// matching permit, a LAN -> tunnel packet is still DENIED, and the denial is
/// now attributed to the implicit default policy for the REAL zone pair
/// `(lan, vpn)` rather than to the unknown-zone accident.
#[test]
fn secure_tunnel_without_permit_still_denies_6713() {
    let state = build_forwarding_state(&secure_tunnel_snapshot_6713(
        TunnelPolicy6713::PermitOtherPairOnly,
    ));
    let resolution = assert_secure_tunnel_preconditions_6713(&state);

    let (from_id, to_id) =
        zone_pair_ids_for_flow(&state, LAN_IFINDEX_6713, resolution.egress_ifindex);
    assert_eq!(
        to_id, TEST_VPN_ZONE_ID_6713,
        "the deny must be a REAL adjudication of (lan, vpn), not a zone-0 fallthrough"
    );

    let result = crate::policy::evaluate_policy_result_with_icmp(
        &state.policy,
        from_id,
        to_id,
        "10.0.61.102".parse().expect("src"),
        "192.168.99.7".parse().expect("dst"),
        PROTO_TCP,
        40000,
        443,
        None,
        64,
    );
    assert_eq!(
        result.action,
        PolicyAction::Deny,
        "the only permit in the config is scoped to (vpn, lan); the tunnel must NOT \
         inherit it and the default-DENY policy must still deny"
    );
    assert_eq!(
        result.policy_id,
        crate::policy::DEFAULT_POLICY_SENTINEL_ID,
        "attributed to the implicit default policy"
    );
}

/// #6713, the other half of "the fix does not fail open": the operator's OWN
/// `from-zone lan to-zone vpn ... then deny` must be the ATTRIBUTED verdict.
/// Before the fix the packet was also denied -- but by the implicit default
/// policy, because the to-zone was 0 and the operator's rule was never
/// consulted. Same drop, different (and truthful) attribution: this is what
/// makes `show security policies` and the RT_FLOW deny event point at the rule
/// that actually decided.
///
/// Revert the `egress_zone_id` fallback and the policy id becomes the default
/// sentinel -- RED.
#[test]
fn secure_tunnel_operator_deny_is_attributed_to_its_rule_6713() {
    let state =
        build_forwarding_state(&secure_tunnel_snapshot_6713(TunnelPolicy6713::DenyLanToVpn));
    let resolution = assert_secure_tunnel_preconditions_6713(&state);

    let (from_id, to_id) =
        zone_pair_ids_for_flow(&state, LAN_IFINDEX_6713, resolution.egress_ifindex);
    assert_eq!(to_id, TEST_VPN_ZONE_ID_6713);

    let result = crate::policy::evaluate_policy_result_with_icmp(
        &state.policy,
        from_id,
        to_id,
        "10.0.61.102".parse().expect("src"),
        "192.168.99.7".parse().expect("dst"),
        PROTO_TCP,
        40000,
        443,
        None,
        64,
    );
    assert_eq!(result.action, PolicyAction::Deny);
    assert_ne!(
        result.policy_id,
        crate::policy::DEFAULT_POLICY_SENTINEL_ID,
        "the operator's explicit deny must be the attributed verdict, not the implicit default"
    );
}

/// #6713 scoping guard, RE-AIMED in #6722 round 10 at what it can still
/// distinguish.
///
/// WHAT IT USED TO CLAIM, and why that claim is dead. Through round 9 this
/// bound `egress_zone_id`'s `Some(0)` short-circuit: the resolver read
/// `state.egress` first, and a row carrying `zone_id == 0` had to stay 0 rather
/// than fall through. That claim went VACUOUS at ad4f0c113, when
/// `populate_egress` began sourcing `EgressInterface::zone_id` from the same
/// ledger the fallback read — both arms then returned the same number for every
/// state, and the mutation the doc named (filter zero before `or_else`) still
/// returned 0. Round 10 collapsed the resolver to a single map read, so the
/// short-circuit does not exist to bind.
///
/// WHAT IT BINDS NOW, measured rather than asserted. The one remaining choice is
/// WHICH MAP the egress half reads, and that is observable only in a state where
/// the two maps DISAGREE. Point the resolver at `ifindex_to_zone_id` and this
/// test reds with `left: 7  right: 0`.
///
/// RETARGETED IN #7509 — the fixture moved, the subject did not. Through #8407
/// the diverging state was a zoned trunk with a declared-but-unzoned unit 0:
/// `ifindex_to_zone_id[90]` carried the trunk's `lan` while the ledger had no
/// entry. #7509 made INGRESS refuse that inheritance too, so both maps now
/// answer 0 there and the cell could no longer tell "the egress half read the
/// right map" from "nothing is zoned" — a green for the wrong reason.
///
/// The state that still diverges is two INTERFACES on one recycled ifindex that
/// AGREE on a zone (`reused_ifindex_agreeing_zones_snapshot_7509`). Ingress
/// admits `vpnb` because every row names it; egress refuses because
/// `egressIdentitiesCohere` sees two independent claimants on one device and
/// agreement between two unrelated claimants is not authorisation. Every other
/// #6722 shape now answers the same on both halves, which is the #6727 symmetry
/// arriving — this is the residue.
///
/// Kept rather than deleted for that reason, and re-documented rather than
/// left under its old claim: a test whose doc names a mechanism the code no
/// longer has reads as coverage it is not providing.
#[test]
fn unzoned_interface_with_egress_row_stays_zone_zero_6713() {
    let state = build_forwarding_state(&reused_ifindex_agreeing_zones_snapshot_7509());

    assert_eq!(
        state
            .ifindex_to_zone_id
            .get(&SHARED_TUNNEL_IFINDEX_6722)
            .copied()
            .unwrap_or(0),
        TEST_SIBLING_VPN_ZONE_ID_6722,
        "precondition: INGRESS resolves `vpnb` for the recycled ifindex -- without \
         that divergence this test cannot detect an over-firing fallback, because \
         a resolver reading either map would answer 0"
    );

    let (_, to_id) =
        zone_pair_ids_for_flow(&state, LAN_IFINDEX_6722, SHARED_TUNNEL_IFINDEX_6722);
    assert_eq!(
        to_id, 0,
        "the egress half must read `ifindex_unambiguous_zone_id`, NOT \
         `ifindex_to_zone_id`. The latter is the INGRESS attribution map, and it \
         carries `vpnb` for this ifindex because both interfaces' rows happen to \
         name it -- while the device itself was authorised into that zone by \
         neither claimant alone. Reading it here hands a device a zone on the \
         strength of a coincidence, which is the fail-OPEN direction"
    );
}

// ---------------------------------------------------------------------------
// #6722: what a MAC-less unit that SHARES an ifindex with another unit
// resolves to on the EGRESS half.
//
// Several logical units collapse onto one netdev, so an ifindex is not a unit
// identity. `snapshotLinuxName` maps a non-VLAN unit 0 back onto its base, and
// `ifindex_to_zone_id` — the from-zone source — records the LAST zoned row on
// that ifindex plus the child->parent propagation. Reading it for the to-zone
// hands an interface a zone it was never configured with, and a nonzero
// to-zone is what makes an operator permit MATCH. Three producible shapes do
// exactly that; all three are built below from `build_forwarding_state` and
// adjudicated through the real FIB and the real policy evaluator.
//
// The gate is `ifindex_unambiguous_zone_id`: an ifindex resolves a to-zone only
// when EVERY snapshot row on it named the same nonzero zone. Disagreement
// resolves the 0 sentinel — the pre-#6713 answer — and the default policy
// decides. #6713 itself is untouched, because in every #6713 shape the rows on
// the tunnel's ifindex agree.
//
// This deliberately makes the two DIRECTIONS disagree for an ambiguous ifindex.
// Round 3 asserted directional coherence as the property that made the wide
// answer defensible; it is not defensible, because the wide answer is a permit
// the operator did not write. The justification is DIRECTIONAL, not a claim
// that the ingress surface is unreachable: in the quarantine shape every row is
// unzoned so the ifindex is not an AF_XDP bind target at all
// (`interfaces.go`, `if iface.Zone == "" { continue }`), but in the sibling and
// divergent shapes the BASE row is zoned and ingress really does answer `vpnb`
// there. Ingress answering wide is pre-existing (#921/#3618) and untouched
// here; egress answering wide would be a NEW fail-open on the exact interface
// class #6713 routed through the fallback.
// ---------------------------------------------------------------------------

/// Resolve `dst` through the real FIB and assert it egresses `expect_ifindex`,
/// then adjudicate LAN -> that ifindex through the real policy evaluator.
fn adjudicate_lan_transit_6722(
    state: &ForwardingState,
    dst: &str,
    expect_ifindex: i32,
) -> (u16, crate::policy::PolicyEvaluationResult) {
    let resolution = lookup_forwarding_resolution_v4(
        state,
        None,
        dst.parse().expect("dst"),
        "inet.0",
        0,
        true,
        None,
    );
    assert_eq!(
        resolution.egress_ifindex, expect_ifindex,
        "precondition: the real FIB must hand {dst} to ifindex {expect_ifindex} \
         (disposition {:?})",
        resolution.disposition
    );
    let (from_id, to_id) =
        zone_pair_ids_for_flow(state, LAN_IFINDEX_6722, resolution.egress_ifindex);
    assert_eq!(from_id, TEST_LAN_ZONE_ID, "from-zone");
    let result = crate::policy::evaluate_policy_result_with_icmp(
        &state.policy,
        from_id,
        to_id,
        "10.0.61.102".parse().expect("src"),
        dst.parse().expect("dst"),
        PROTO_TCP,
        40000,
        443,
        None,
        64,
    );
    (to_id, result)
}

/// Assert the shared preconditions that make a #6722 case interesting at all:
/// the ifindex has NO `egress` row (so the #6713 fallback is the only resolver
/// in play), and BOTH halves now resolve no zone for it.
///
/// #7509 removed the parameter this used to take. Through #8407 it said "what
/// should INGRESS say for this cell's class", with 0 for a zoned-vs-zoned
/// contest and the sibling's zone for a zoned-vs-UNZONED one — ingress still
/// inherited there, on the ground that separating a sibling unit that must not
/// inherit from a trunk parent that legitimately does needed provenance that was
/// "not on the wire". It is on the wire: the base row's UNIT SIBLINGS on the
/// same ifindex carry it, because `InterfaceZoneMap` fans a BARE reference DOWN
/// onto every unit and a unit-suffixed one only UP. Every shape in this family
/// now answers 0 on both halves, so a per-caller expectation would be a
/// parameter with one value at every call site.
///
/// The non-vacuity protection that used to ride on that parameter ("to-zone 0
/// must not be indistinguishable from an empty state") lives in the control
/// below, and is stronger: an UNCONTESTED sibling ifindex in the SAME state must
/// still be zoned, so a build that lost zoning entirely reds here instead of
/// passing everywhere.
fn assert_ambiguous_ifindex_preconditions_6722(state: &ForwardingState, ifindex: i32) {
    assert!(
        !state.egress.contains_key(&ifindex),
        "precondition: ifindex {ifindex} must have NO egress row -- without that \
         the #6713 fallback never fires and nothing here is exercised"
    );
    assert_eq!(
        state
            .ifindex_to_zone_id
            .get(&ifindex)
            .copied()
            .unwrap_or(0),
        0,
        "ifindex {ifindex} is shared by rows that do not agree about its zone, so \
         INGRESS must refuse to attribute a zone to it too (#7509) -- not only \
         egress"
    );
    assert_ne!(
        state
            .ifindex_to_zone_id
            .get(&LAN_IFINDEX_6722)
            .copied()
            .unwrap_or(0),
        0,
        "control: the UNCONTESTED lan ifindex must still carry its own zone, or \
         the assertion above passes on a state with no zones at all and the cell \
         cannot tell 'contested is refused' from 'nothing is zoned'"
    );
    assert!(
        !state.ifindex_unambiguous_zone_id.contains_key(&ifindex),
        "ifindex {ifindex} is shared by rows that disagree about its zone, so it \
         must not appear in the unambiguous map at all"
    );
}

/// #6722 MAJOR, the fail-OPEN direction. `st0.0` is in NO security zone; its
/// zoned sibling `st0.1` shares the base ifindex through the Go builder's
/// `out[base]` write. Transit routed out unit 0 must NOT be adjudicated under
/// the sibling's zone — that applies an operator permit written for a
/// DIFFERENT interface, forwarding out an IPsec SA the operator never
/// authorised for this traffic.
///
/// #7509 note: the INGRESS half of this same shape is now bound by
/// `shared_ifindex_ingress_and_egress_both_refuse_a_siblings_zone_7509` below.
/// Until then this cell's precondition recorded ingress answering `vpnb` for
/// ifindex 42 — i.e. it pinned the open half of the asymmetry as a fact about
/// the state rather than as a defect.
#[test]
fn unzoned_macless_unit_does_not_inherit_a_zoned_siblings_zone_6722() {
    let state = build_forwarding_state(&sibling_tunnel_units_snapshot_6722());
    assert_ambiguous_ifindex_preconditions_6722(&state, SHARED_TUNNEL_IFINDEX_6722);

    let (to_id, result) =
        adjudicate_lan_transit_6722(&state, "192.168.99.7", SHARED_TUNNEL_IFINDEX_6722);

    assert_eq!(
        to_id, 0,
        "an interface the operator left in NO zone must not adjudicate under a \
         sibling unit's zone; the ambiguous ifindex resolves the 0 sentinel"
    );
    assert_ne!(
        to_id, TEST_SIBLING_VPN_ZONE_ID_6722,
        "specifically NOT `vpnb` -- naming the wrong value the fail-open would \
         produce, so this cannot pass by resolving some other nonzero zone"
    );
    assert_eq!(
        result.action,
        PolicyAction::Deny,
        "with no to-zone, no rule matches and the deny-all default decides"
    );
    assert_eq!(
        result.policy_id,
        crate::policy::DEFAULT_POLICY_SENTINEL_ID,
        "the verdict must come from the DEFAULT policy, not from the sibling's \
         `from-zone lan to-zone vpnb permit`"
    );

    // The String twin used by test-only callers reads the same helper.
    let (from_zone, to_zone) =
        zone_pair_for_flow(&state, LAN_IFINDEX_6722, SHARED_TUNNEL_IFINDEX_6722);
    assert_eq!(from_zone, "lan");
    assert_eq!(
        to_zone, "",
        "the String twin must report no to-zone, not `vpnb`"
    );
}

/// #7509 ACCEPTANCE: the executable statement of the PAIR for the reported
/// shared-ifindex shape — both directions, through the real
/// `build_forwarding_state`, on the row shapes
/// `pkg/dataplane/userspace/zone_propagation_6722_test.go` case A measures the
/// Go builder emitting for exactly this config.
///
/// The reported config: `st0.1` in `vpnb`, `st0.0` deliberately in NO zone,
/// both resolving to base ifindex 42 (`snapshotLinuxName` collapses a non-VLAN
/// unit 0 onto its base netdev). Before this change the two halves disagreed:
///
/// | direction | resolved | mechanism |
/// |---|---|---|
/// | ingress | `vpnb` | `ifindex_to_zone_id` — the base row's INHERITED zone |
/// | egress  | `0`    | `ifindex_unambiguous_zone_id` — the #6722 gate |
///
/// A packet arriving on ifindex 42 is a packet on `st0.0`. Attributing it to
/// `vpnb` adjudicates it under the policy set the operator wrote for the tunnel
/// unit that terminates an authorised SA — a policy BYPASS, and the exact
/// asymmetry #6727 warned would be worse than leaving the whole thing alone.
///
/// WHY THE PERMIT IS IN THE FIXTURE. Without a `from-zone vpnb` rule, "ingress
/// says vpnb" and "ingress says nothing" produce the same verdict under
/// `deny-all`, and the cell would be a map reading rather than a statement about
/// traffic. `sibling_tunnel_units_reverse_policy_snapshot_7509` adds
/// `from-zone vpnb to-zone lan permit`, so the defect PERMITS and the fix DENIES.
#[test]
fn shared_ifindex_ingress_and_egress_both_refuse_a_siblings_zone_7509() {
    let state = build_forwarding_state(&sibling_tunnel_units_reverse_policy_snapshot_7509());

    // Precondition: the ifindex really is shared, and the zoned sibling really
    // is on its own. Without this the cell could pass on a state where `st0.0`
    // simply does not exist.
    assert_eq!(
        state
            .ifindex_to_config_name
            .get(&ZONED_TUNNEL_IFINDEX_6722)
            .map(String::as_str),
        Some("st0.1"),
        "precondition: the zoned sibling is on its OWN ifindex 43"
    );

    // ---- the PAIR, both halves, for the shared ifindex ----
    let (from_id, _) = zone_pair_ids_for_flow(&state, SHARED_TUNNEL_IFINDEX_6722, LAN_IFINDEX_6722);
    assert_eq!(
        from_id, 0,
        "INGRESS: a packet arriving on ifindex 42 is a packet on `st0.0`, which the \
         operator left in no zone. It must not be attributed to `st0.1`'s zone"
    );
    assert_ne!(
        from_id, TEST_SIBLING_VPN_ZONE_ID_6722,
        "specifically NOT `vpnb` -- naming the wrong value the bypass produces, so \
         this cannot pass by resolving some other nonzero zone"
    );
    let (_, to_id) = zone_pair_ids_for_flow(&state, LAN_IFINDEX_6722, SHARED_TUNNEL_IFINDEX_6722);
    assert_eq!(
        to_id, 0,
        "EGRESS: unchanged by #7509 -- the #6722 gate already refused. Asserted \
         here so the PAIR is stated in one place rather than inferred from two \
         cells that could drift apart"
    );

    // ---- the HARM, adjudicated through the real policy evaluator ----
    let denied = crate::policy::evaluate_policy_result_with_icmp(
        &state.policy,
        from_id,
        TEST_LAN_ZONE_ID,
        "10.5.5.2".parse().expect("src"),
        "10.0.61.102".parse().expect("dst"),
        PROTO_TCP,
        40000,
        443,
        None,
        64,
    );
    assert_eq!(
        denied.action,
        PolicyAction::Deny,
        "traffic in from the unzoned unit must not reach `from-zone vpnb to-zone \
         lan permit` -- that rule was written for the tunnel unit the operator \
         DID zone"
    );
    assert_eq!(
        denied.policy_id,
        crate::policy::DEFAULT_POLICY_SENTINEL_ID,
        "and the verdict must come from the DEFAULT policy, not from an operator \
         rule that happened to deny"
    );

    // ---- POSITIVE CONTROL on the accept side ----
    // A gate that refused every ingress attribution would satisfy every
    // assertion above. The zoned sibling on ifindex 43 must still resolve its
    // own zone and still MATCH the operator's permit.
    let (sibling_from, _) =
        zone_pair_ids_for_flow(&state, ZONED_TUNNEL_IFINDEX_6722, LAN_IFINDEX_6722);
    assert_eq!(
        sibling_from, TEST_SIBLING_VPN_ZONE_ID_6722,
        "control: `st0.1` owns ifindex 43 outright and must still be `vpnb`"
    );
    let permitted = crate::policy::evaluate_policy_result_with_icmp(
        &state.policy,
        sibling_from,
        TEST_LAN_ZONE_ID,
        "10.6.6.2".parse().expect("src"),
        "10.0.61.102".parse().expect("dst"),
        PROTO_TCP,
        40000,
        443,
        None,
        64,
    );
    assert_eq!(
        permitted.action,
        PolicyAction::Permit,
        "control: the operator's `vpnb -> lan` permit must still match for the \
         unit that IS in `vpnb`"
    );
    assert_ne!(
        permitted.policy_id,
        crate::policy::DEFAULT_POLICY_SENTINEL_ID,
        "control: and it must be the RULE that permitted, not a permissive default"
    );
}

/// #7509 SCOPE CONTROL, the direction the fix must NOT reach: a trunk parent
/// whose units all have netdevs of their own still inherits (#921/#3618).
///
/// The refusal is scoped to a parent ifindex that carries a LOGICAL UNIT ROW of
/// its own. That is the discriminator #6727 and #8407 both recorded as "not on
/// the wire": a base row whose zone was AUTHORED by a bare
/// `security-zone <z> interfaces <ifc>` reference has unit rows carrying that
/// same zone, because `InterfaceZoneMap` fans a bare reference DOWN onto every
/// unit; a base row whose zone was INHERITED from a unit-suffixed reference has
/// unit siblings that do not. Provenance is not on the ROW — it is in the
/// AGREEMENT between the row and its unit siblings on the same ifindex.
///
/// Here `st0` carries no unit row at all on ifindex 42 (unit 0 is absent from
/// the config), so `st0.1`'s child->parent propagation is the only claim on it
/// and nothing contradicts it. This is the case the propagation exists to serve,
/// and widening the refusal to "a zoned row plus an unzoned row is a contest"
/// would have broken it.
#[test]
fn a_parent_with_no_unit_row_still_inherits_its_childs_zone_7509() {
    let mut snapshot = sibling_tunnel_units_snapshot_6722();
    // Drop `st0.0` — the operator never configured unit 0 — and leave the base
    // row and the zoned `st0.1` exactly as the builder emits them.
    snapshot.interfaces.retain(|iface| iface.name != "st0.0");
    assert!(
        snapshot.interfaces.iter().any(|i| i.name == "st0")
            && snapshot.interfaces.iter().any(|i| i.name == "st0.1"),
        "precondition: the base row and the zoned unit must both survive the retain"
    );
    let state = build_forwarding_state(&snapshot);

    assert_eq!(
        state
            .ifindex_to_zone_id
            .get(&SHARED_TUNNEL_IFINDEX_6722)
            .copied()
            .unwrap_or(0),
        TEST_SIBLING_VPN_ZONE_ID_6722,
        "a parent ifindex with NO unit row of its own must keep inheriting \
         (#921/#3618) -- #7509 refuses only where a unit row on the SAME ifindex \
         contradicts the inheritance"
    );
}

/// #7509 SCOPE CONTROL, the other side: a BARE base-interface zone reference
/// still zones the shared ifindex.
///
/// `security-zone vpnb interfaces st0` fans DOWN onto every configured unit, so
/// `st0.0`'s row carries `vpnb` too and agrees with the base. Over-tightening
/// into "a base row and a unit row on one ifindex means no zone" would deny an
/// ordinary single-unit tunnel — the #6713 deployment itself.
#[test]
fn a_bare_base_zone_reference_still_zones_the_shared_ifindex_7509() {
    let state = build_forwarding_state(&unanimous_shared_ifindex_tunnel_snapshot_6722());
    assert_eq!(
        state
            .ifindex_to_zone_id
            .get(&SHARED_TUNNEL_IFINDEX_6722)
            .copied()
            .unwrap_or(0),
        TEST_SIBLING_VPN_ZONE_ID_6722,
        "the unit row AGREES with the base row, so nothing is refused"
    );
    let (to_id, result) =
        adjudicate_lan_transit_6722(&state, "192.168.99.7", SHARED_TUNNEL_IFINDEX_6722);
    assert_eq!(to_id, TEST_SIBLING_VPN_ZONE_ID_6722);
    assert_eq!(result.action, PolicyAction::Permit);
    assert_ne!(
        result.policy_id,
        crate::policy::DEFAULT_POLICY_SENTINEL_ID,
        "and the operator's rule is what permitted it"
    );
}

/// #6722, the alphabetical-accident shape. Two units in DIFFERENT zones on one
/// `st0`: `buildInterfaceZoneMap`'s `out[base]` write is FIRST-write-wins over
/// SORTED zone names, so the base row carries `vpnb` only because "vpnb" sorts
/// before "vpnc". Unit 0, in neither zone, shares that ifindex. Adjudicating it
/// under `vpnb` would make the applied policy a function of zone NAMING.
#[test]
fn divergently_zoned_sibling_units_do_not_pick_a_zone_6722() {
    let state = build_forwarding_state(&divergent_zone_sibling_units_snapshot_6722());
    assert_ambiguous_ifindex_preconditions_6722(&state, SHARED_TUNNEL_IFINDEX_6722);

    let (to_id, result) =
        adjudicate_lan_transit_6722(&state, "192.168.99.7", SHARED_TUNNEL_IFINDEX_6722);

    assert_eq!(
        to_id, 0,
        "an ifindex two differently-zoned units share names no single zone"
    );
    assert_ne!(to_id, TEST_SIBLING_VPN_ZONE_ID_6722, "not `vpnb`");
    assert_ne!(to_id, TEST_OTHER_VPN_ZONE_ID_6722, "and not `vpnc` either");
    assert_eq!(result.action, PolicyAction::Deny);
    assert_eq!(
        result.policy_id,
        crate::policy::DEFAULT_POLICY_SENTINEL_ID,
        "neither `lan->vpnb` nor `lan->vpnc` may match"
    );

    // The sibling that DOES own its ifindex is unaffected: unit 1 is on its own
    // netdev, unambiguously `vpnb`, and still reaches the policy plane.
    let (unit1_to_id, unit1_result) =
        adjudicate_lan_transit_6722(&state, "192.168.98.7", ZONED_TUNNEL_IFINDEX_6722);
    assert_eq!(unit1_to_id, TEST_SIBLING_VPN_ZONE_ID_6722);
    assert_eq!(unit1_result.action, PolicyAction::Permit);
    assert_ne!(
        unit1_result.policy_id,
        crate::policy::DEFAULT_POLICY_SENTINEL_ID,
        "the gate must be scoped to the AMBIGUOUS ifindex -- an unambiguous \
         sibling on the same base must keep resolving its own zone"
    );
}

/// #6722, the StableZoneID-QUARANTINE shape, and the counterexample to round
/// 3's claim that `populate_interfaces`' child->parent propagation is
/// unreachable for a Go-produced snapshot.
///
/// `quarantineCollidingZones` blanks `Zone` on every row bound to a colliding
/// zone AFTER `buildInterfaceSnapshots` ran, expressly so those interfaces fail
/// CLOSED ("An unzoned interface matches no zone policy -> default-deny",
/// `pkg/dataplane/userspace/zones_quarantine.go`). When the quarantined zone is
/// the one that won `out["st0"]`, the base and unit 0 arrive UNZONED beside a
/// surviving zoned `st0.1` — and the Rust propagation then writes the
/// survivor's zone onto the base ifindex. Reading that for the to-zone would
/// hand the quarantine's deliberate deny back a permit.
#[test]
fn quarantine_unzoned_base_does_not_inherit_the_surviving_childs_zone_6722() {
    let state = build_forwarding_state(&quarantined_base_tunnel_snapshot_6722());

    // The propagation is REACHABLE: no row on ifindex 42 carries a zone, yet
    // `ifindex_to_zone_id` has one, and it can only have come from `st0.1`.
    assert_ambiguous_ifindex_preconditions_6722(&state, SHARED_TUNNEL_IFINDEX_6722);

    let (to_id, result) =
        adjudicate_lan_transit_6722(&state, "192.168.99.7", SHARED_TUNNEL_IFINDEX_6722);

    assert_eq!(
        to_id, 0,
        "a zone the quarantine deliberately stripped must not come back through \
         the child->parent propagation"
    );
    assert_ne!(to_id, TEST_SIBLING_VPN_ZONE_ID_6722, "not `vpnb`");
    assert_eq!(result.action, PolicyAction::Deny);
    assert_eq!(
        result.policy_id,
        crate::policy::DEFAULT_POLICY_SENTINEL_ID,
        "the quarantine's fail-closed intent must survive to the policy verdict"
    );
}

/// #6722, a RECYCLED ifindex. Two unrelated interfaces in different zones
/// landing on one ifindex — no parent/child relationship, so nothing even
/// suggests which zone is "the" zone. Must resolve 0.
#[test]
fn reused_ifindex_across_two_zoned_interfaces_resolves_no_zone_6722() {
    let state = build_forwarding_state(&reused_ifindex_snapshot_6722());
    assert!(
        !state.egress.contains_key(&SHARED_TUNNEL_IFINDEX_6722),
        "precondition: both rows are MAC-less, so there is no egress row"
    );
    // #7509 RETARGET. This pinned the ARBITRARY PICK as a precondition -- two
    // zoned interfaces reusing one ifindex, `ifindex_to_zone_id` keeping
    // whichever row was walked last -- to assert the pick did not reach the
    // to-zone. Ingress no longer picks, so the precondition inverts: both halves
    // now refuse, which is the #6727 symmetry.
    //
    // The control keeps it from going vacuous: with the pick gone, "ingress is
    // 0" is satisfied by a state with no zones at all.
    assert_eq!(
        state
            .ifindex_to_zone_id
            .get(&SHARED_TUNNEL_IFINDEX_6722)
            .copied()
            .unwrap_or(0),
        0,
        "two zoned interfaces reusing one ifindex must leave it UNZONED on the \
         ingress side too -- the arbitrary last-row-wins pick is gone (#7509)"
    );
    assert_ne!(
        state
            .ifindex_to_zone_id
            .get(&LAN_IFINDEX_6722)
            .copied()
            .unwrap_or(0),
        0,
        "control: an UNCONTESTED ifindex in the same state must still be zoned, \
         or the assertion above passes on a state with no zones at all"
    );
    assert_eq!(
        zone_pair_ids_for_flow(&state, LAN_IFINDEX_6722, SHARED_TUNNEL_IFINDEX_6722).1,
        0,
        "a recycled ifindex claimed by two differently-zoned interfaces names no \
         zone"
    );
}

// ---------------------------------------------------------------------------
// #6722 B1: the OTHER arm of `egress_zone_id`.
//
// Everything above reaches the fallback, because a MAC-less xfrmi gets no
// `state.egress` row. But `egress_zone_id` consults `state.egress` FIRST, and
// `populate_egress` writes that map last-write-wins per ifindex. An
// interface-level WireGuard tunnel puts several differently-zoned units on ONE
// ifindex and DOES give them egress rows, so the last row's zone was returned
// without the agreement ledger ever being read — the #6722 fail-open, intact,
// underneath a green ambiguity suite.
//
// The fix makes `populate_egress` take the egress row's `zone_id` FROM the
// ledger rather than from the row's own zone, so both arms of the resolver
// derive from one source and cannot disagree.
// ---------------------------------------------------------------------------

/// Assert the preconditions that make an interface-level tunnel case
/// interesting: the ifindex HAS an egress row (so the fallback is NOT what is
/// under test), and the ledger holds it ambiguous.
fn assert_egress_row_ambiguous_preconditions_6722(state: &ForwardingState, ifindex: i32) {
    assert!(
        state.egress.contains_key(&ifindex),
        "precondition: ifindex {ifindex} must HAVE an egress row -- that is the \
         arm this test exists for; without it this is just another fallback test"
    );
    assert!(
        !state.ifindex_unambiguous_zone_id.contains_key(&ifindex),
        "precondition: the ledger must hold ifindex {ifindex} ambiguous, or there \
         is no disagreement for the egress row to override"
    );
}

/// #6722 B1, the fail-open through `state.egress`. `wg0.0` is in NO security
/// zone; its zoned sibling `wg0.1` shares the ifindex because an
/// interface-level tunnel's units share the base device. `populate_egress` is
/// last-write-wins, so the sibling's zone landed in `egress[42].zone_id` and
/// was returned before the ledger was ever consulted.
#[test]
fn unzoned_iface_tunnel_unit_does_not_inherit_a_siblings_zone_via_egress_row_6722() {
    let state = build_forwarding_state(&wg_iface_tunnel_unzoned_unit_snapshot_6722());
    assert_egress_row_ambiguous_preconditions_6722(&state, SHARED_TUNNEL_IFINDEX_6722);

    // The specific value the fail-open produced, named so this cannot pass by
    // resolving some other zone.
    assert_eq!(
        state
            .egress
            .get(&SHARED_TUNNEL_IFINDEX_6722)
            .map(|i| i.zone_id)
            .unwrap_or(0),
        0,
        "the egress row of an AMBIGUOUS ifindex must carry the 0 sentinel, not \
         whichever row `populate_egress` happened to write last"
    );

    let (to_id, result) =
        adjudicate_lan_transit_6722(&state, "192.168.99.7", SHARED_TUNNEL_IFINDEX_6722);

    assert_eq!(
        to_id, 0,
        "transit out an interface the operator left in NO zone must not be \
         adjudicated under a sibling unit's zone"
    );
    assert_ne!(to_id, TEST_SIBLING_VPN_ZONE_ID_6722, "specifically NOT `vpnb`");
    assert_eq!(result.action, PolicyAction::Deny);
    assert_eq!(
        result.policy_id,
        crate::policy::DEFAULT_POLICY_SENTINEL_ID,
        "the verdict must come from the DEFAULT policy, not the sibling's permit"
    );
}

/// #6722 B1, zero sentinel FIRST with egress rows. Two unzoned rows then a
/// zoned one: `populate_egress`'s last write is the zone, so relying on
/// emission order to land 0 -- which is what the pre-#6722 code did -- fails
/// exactly here.
#[test]
fn iface_tunnel_egress_row_is_not_upgraded_by_a_later_zoned_unit_6722() {
    let state = build_forwarding_state(&wg_iface_tunnel_sentinel_first_snapshot_6722());
    assert_egress_row_ambiguous_preconditions_6722(&state, SHARED_TUNNEL_IFINDEX_6722);

    let (to_id, result) =
        adjudicate_lan_transit_6722(&state, "192.168.99.7", SHARED_TUNNEL_IFINDEX_6722);

    assert_eq!(
        to_id, 0,
        "a zoned row emitted LAST must not decide the zone of an ifindex whose \
         other rows name none"
    );
    assert_eq!(result.action, PolicyAction::Deny);
    assert_eq!(result.policy_id, crate::policy::DEFAULT_POLICY_SENTINEL_ID);
}

/// #6722 B1 SCOPE control, and the case the gate must NOT over-tighten:
/// `set security zones security-zone vpnb interfaces wg0` fans out to every
/// unit, so all three rows on the ifindex agree. An ordinary WireGuard
/// deployment must keep resolving its zone and matching the operator's permit.
#[test]
fn unanimous_iface_tunnel_units_still_reach_policy_6722() {
    let state = build_forwarding_state(&wg_iface_tunnel_unanimous_snapshot_6722());

    assert!(
        state.egress.contains_key(&SHARED_TUNNEL_IFINDEX_6722),
        "precondition: an interface-level tunnel HAS an egress row"
    );
    assert_eq!(
        state
            .ifindex_unambiguous_zone_id
            .get(&SHARED_TUNNEL_IFINDEX_6722)
            .copied()
            .unwrap_or(0),
        TEST_SIBLING_VPN_ZONE_ID_6722,
        "three rows that AGREE keep the ifindex in the unambiguous map"
    );
    assert_eq!(
        state
            .egress
            .get(&SHARED_TUNNEL_IFINDEX_6722)
            .map(|i| i.zone_id)
            .unwrap_or(0),
        TEST_SIBLING_VPN_ZONE_ID_6722,
        "and the egress row must still carry that zone -- deriving it from the \
         ledger must not blank an unambiguous interface"
    );

    let (to_id, result) =
        adjudicate_lan_transit_6722(&state, "192.168.99.7", SHARED_TUNNEL_IFINDEX_6722);

    assert_eq!(to_id, TEST_SIBLING_VPN_ZONE_ID_6722);
    assert_eq!(
        result.action,
        PolicyAction::Permit,
        "an ordinary WireGuard deployment must keep forwarding"
    );
    assert_ne!(
        result.policy_id,
        crate::policy::DEFAULT_POLICY_SENTINEL_ID,
        "the operator's rule must be the one that matched"
    );
}

/// #6713 at a SHARED ifindex, and the guard that keeps the #6722 gate from
/// being a blanket "shared ifindex means no zone". `set security zones
/// security-zone vpnb interfaces st0` fans out to every unit, so the `st0` base
/// and `st0.0` rows BOTH carry `vpnb` on one ifindex. They agree, so the
/// ifindex names exactly one zone and the fallback must resolve it — this is
/// #6713's own deployed shape and it must still be permitted.
#[test]
fn unanimously_zoned_shared_ifindex_still_reaches_policy_6713() {
    let state = build_forwarding_state(&unanimous_shared_ifindex_tunnel_snapshot_6722());

    assert!(
        !state.egress.contains_key(&SHARED_TUNNEL_IFINDEX_6722),
        "precondition: MAC-less, so NO egress row -- the fallback is the only \
         thing that can resolve this zone"
    );
    assert_eq!(
        state
            .ifindex_unambiguous_zone_id
            .get(&SHARED_TUNNEL_IFINDEX_6722)
            .copied()
            .unwrap_or(0),
        TEST_SIBLING_VPN_ZONE_ID_6722,
        "two rows on one ifindex that AGREE keep it in the unambiguous map"
    );

    let (to_id, result) =
        adjudicate_lan_transit_6722(&state, "192.168.99.7", SHARED_TUNNEL_IFINDEX_6722);

    assert_eq!(
        to_id, TEST_SIBLING_VPN_ZONE_ID_6722,
        "the tunnel's configured zone must reach the policy plane"
    );
    assert_eq!(
        result.action,
        PolicyAction::Permit,
        "the operator's from-zone lan to-zone vpnb permit must match"
    );
    assert_ne!(
        result.policy_id,
        crate::policy::DEFAULT_POLICY_SENTINEL_ID,
        "the verdict must come from the operator's rule, not the default policy"
    );
}

/// #6713 in the per-UNIT spelling. Real Junos zones the UNIT
/// (`set security zones security-zone vpnb interfaces st0.1`), and `st0.1` has
/// its OWN netdev/ifindex — one row, so unambiguous by construction. It is
/// MAC-less, so the #6713 fallback is the only thing that can resolve it, and
/// it must reach the policy plane and be permitted even though a SIBLING on the
/// same base is ambiguous.
#[test]
fn zoned_macless_unit_still_reaches_policy_6713() {
    let state = build_forwarding_state(&sibling_tunnel_units_snapshot_6722());

    assert!(
        !state.egress.contains_key(&ZONED_TUNNEL_IFINDEX_6722),
        "precondition: the zoned unit is MAC-less too, so it also has NO egress row \
         -- the fallback is the only thing that can resolve its zone"
    );

    let (to_id, result) =
        adjudicate_lan_transit_6722(&state, "192.168.98.7", ZONED_TUNNEL_IFINDEX_6722);

    assert_eq!(
        to_id, TEST_SIBLING_VPN_ZONE_ID_6722,
        "the tunnel unit's OWN configured zone must reach the policy plane"
    );
    assert_eq!(
        result.action,
        PolicyAction::Permit,
        "the operator's from-zone lan to-zone vpnb permit must match"
    );
    assert_ne!(
        result.policy_id,
        crate::policy::DEFAULT_POLICY_SENTINEL_ID,
        "the verdict must come from the operator's rule, not the default policy"
    );

    // The String twin used by test-only callers reads the same helper.
    let (from_zone, to_zone) =
        zone_pair_for_flow(&state, LAN_IFINDEX_6722, ZONED_TUNNEL_IFINDEX_6722);
    assert_eq!(from_zone, "lan");
    assert_eq!(to_zone, "vpnb");
}

// ---------------------------------------------------------------------------
// #6722 B2: the BONDLESS-RETH shape. See
// `reth_member_unzoned_row_snapshot_6722` for why a RETH member's unzoned row
// is NOT an operator statement and must cast no zone vote.
// ---------------------------------------------------------------------------

/// Resolve `dst` through the real FIB, assert it egresses `expect_ifindex`,
/// then adjudicate WAN -> that ifindex through the real policy evaluator. The
/// mirror of `adjudicate_lan_transit_6722` with the LAN as the TO-zone, which
/// is the half #6722 B1 rewrote.
fn adjudicate_wan_to_lan_transit_6722(
    state: &ForwardingState,
    dst: &str,
    expect_ifindex: i32,
) -> (u16, u16, crate::policy::PolicyEvaluationResult) {
    let resolution = lookup_forwarding_resolution_v4(
        state,
        None,
        dst.parse().expect("dst"),
        "inet.0",
        0,
        true,
        None,
    );
    assert_eq!(
        resolution.egress_ifindex, expect_ifindex,
        "precondition: the real FIB must hand {dst} to ifindex {expect_ifindex} \
         (disposition {:?})",
        resolution.disposition
    );
    let (from_id, to_id) =
        zone_pair_ids_for_flow(state, WAN_IFINDEX_6722, resolution.egress_ifindex);
    let result = crate::policy::evaluate_policy_result_with_icmp(
        &state.policy,
        from_id,
        to_id,
        "203.0.113.7".parse().expect("src"),
        dst.parse().expect("dst"),
        PROTO_TCP,
        40000,
        443,
        None,
        64,
    );
    (from_id, to_id, result)
}

/// #6722 B2 BLOCKER, the fail-CLOSED direction that #6722 B1 introduced.
///
/// `ResolveReth` collapses `reth1` and `reth1.0` onto their physical member's
/// netdev, so the deliberately-unzoned `ge-0/0/1` row and the two `lan` RETH
/// rows all land on ifindex 24. Sourcing the egress row's zone from the
/// agreement ledger then reads `None` and adjudicates to-zone 0, and
/// `evaluate_policy_result_l3_aware` refuses to match ANY rule -- exact,
/// wildcard or `junos-global` -- when either zone id is 0. Under
/// `default-policy deny-all` every WAN->LAN, sfmix->LAN and tunnel->LAN
/// transit flow on a bondless-RETH cluster blackholes. LAN->WAN survives,
/// because its egress ifindex has a single row, which is why an iperf3 smoke
/// in the usual direction comes back green.
///
/// This is not a hypothetical config: `docs/ha-cluster-userspace.conf` is what
/// `test/incus/loss-userspace-cluster.env` points every HA smoke test at, and
/// the full `buildSnapshot` measures `ifindex 24: [ge-0/0/1="" reth1="lan"
/// reth1.0="lan"]` on it.
#[test]
fn unzoned_reth_member_row_does_not_strip_the_reths_egress_zone_6722() {
    let state = build_forwarding_state(&reth_member_unzoned_row_snapshot_6722());

    // Preconditions. The bondless-RETH netdev is MAC-ful, so this is the
    // `state.egress` arm rather than the #6713 fallback.
    assert!(
        state.egress.contains_key(&LAN_IFINDEX_6722),
        "precondition: the bondless-RETH member netdev is MAC-ful, so it HAS an \
         egress row -- this is the `state.egress` arm"
    );
    // The asymmetry is the tell: only the EGRESS half regresses.
    assert_eq!(
        state
            .ifindex_to_zone_id
            .get(&LAN_IFINDEX_6722)
            .copied()
            .unwrap_or(0),
        TEST_LAN_ZONE_ID,
        "precondition: the INGRESS half is unaffected -- `ifindex_to_zone_id` \
         still carries `lan`, so a packet ARRIVING on the LAN is attributed \
         correctly and only the to-zone is in question"
    );

    let (from_id, to_id, result) =
        adjudicate_wan_to_lan_transit_6722(&state, "10.0.61.102", LAN_IFINDEX_6722);

    assert_eq!(from_id, TEST_WAN_ZONE_ID, "from-zone");
    assert_eq!(
        to_id, TEST_LAN_ZONE_ID,
        "a RETH and its physical member are ONE kernel netdev -- nothing can \
         egress ge-0/0/1 that is not reth1.0 traffic -- so the member's unzoned \
         row must not make the RETH's own zone ambiguous"
    );
    assert_eq!(
        result.action,
        PolicyAction::Permit,
        "the operator's `from-zone wan to-zone lan permit` must match; a \
         to-zone of 0 matches no rule at all and default-policy deny-all \
         blackholes every WAN->LAN transit flow on the reference HA cluster"
    );
    assert_ne!(
        result.policy_id,
        crate::policy::DEFAULT_POLICY_SENTINEL_ID,
        "the verdict must come from the operator's rule, not the default policy"
    );
}

/// #6722 B2 OVER-REACH CONTROL 1, and the reason the exemption is scoped to an
/// UNZONED member row.
///
/// `set security zones security-zone wan interfaces ge-0/0/1` on the MEMBER,
/// against `lan` on the RETH, is a genuine operator statement about a genuine
/// conflict rather than an artefact of one netdev described three times. It
/// must keep failing CLOSED. Exempting every member row regardless of its own
/// zone would silently discard the operator's word.
///
/// Kept in its own `#[test]` body so it cannot be skipped by an earlier
/// assertion in the binder above.
#[test]
fn explicitly_zoned_reth_member_still_makes_the_ifindex_ambiguous_6722() {
    let state = build_forwarding_state(&reth_member_explicitly_zoned_snapshot_6722());

    assert!(
        !state
            .ifindex_unambiguous_zone_id
            .contains_key(&LAN_IFINDEX_6722),
        "a member row carrying its OWN zone is a real operator statement, so \
         the ifindex must stay ambiguous"
    );
    assert_eq!(
        state.egress_zone_id(LAN_IFINDEX_6722),
        0,
        "and the egress half must refuse to guess -- fail CLOSED"
    );

    let (_, to_id, result) =
        adjudicate_wan_to_lan_transit_6722(&state, "10.0.61.102", LAN_IFINDEX_6722);
    assert_eq!(to_id, 0, "to-zone must be the 0 sentinel");
    assert_eq!(
        result.action,
        PolicyAction::Deny,
        "default-policy deny-all decides an ambiguous egress"
    );
}

/// #6722 B2 OVER-REACH CONTROL 2: the RETH exemption must NOT leak to genuine
/// logical units.
///
/// `wg0` / `wg0.0` (unzoned) / `wg0.1` (`vpnb`) is the interface-level
/// WireGuard shape from #6722 B1. Those ARE three distinct logical units that
/// Junos zones individually -- `wg0.0`'s "no zone" is a real operator
/// statement -- so the ifindex must stay ambiguous and the egress half must
/// still resolve the 0 sentinel. If this goes green the original #6722
/// fail-open is reopened, which is worse than the bug B2 fixes.
///
/// Its own `#[test]` body, for the same reason as control 1.
#[test]
fn reth_exemption_does_not_leak_to_iface_tunnel_units_6722() {
    let state = build_forwarding_state(&wg_iface_tunnel_unzoned_unit_snapshot_6722());

    assert!(
        !state
            .ifindex_unambiguous_zone_id
            .contains_key(&SHARED_TUNNEL_IFINDEX_6722),
        "wg0.0 is a genuine unzoned logical unit, NOT a redundant description \
         of another row's netdev -- the ifindex must stay ambiguous"
    );
    assert_eq!(
        state.egress_zone_id(SHARED_TUNNEL_IFINDEX_6722),
        0,
        "the egress half must still refuse to hand wg0.0 its sibling's zone"
    );

    let (to_id, result) =
        adjudicate_lan_transit_6722(&state, "192.168.99.7", SHARED_TUNNEL_IFINDEX_6722);
    assert_eq!(to_id, 0, "to-zone must be the 0 sentinel");
    assert_ne!(
        to_id, TEST_SIBLING_VPN_ZONE_ID_6722,
        "specifically NOT `vpnb` -- that is the #6722 fail-open"
    );
    assert_eq!(result.action, PolicyAction::Deny);
}

// ---------------------------------------------------------------------------
// #6722 round 10: the helper CORROBORATES the Go builder's egress-zone answer,
// it does not adjudicate one.
//
// `stampEgressZones` (pkg/dataplane/userspace/interfaces.go) decides which zone
// an ifindex egresses into and stamps it on every row; `populate_interfaces`
// reads it. The four cells below drive the four states that decision can arrive
// in, by varying ONLY `egress_zone` on the reference bondless-RETH fixture —
// whose rows are `[ge-0/0/1="" reth1="lan" reth1.0="lan"]` on one ifindex, the
// shape the HA cluster actually produces.
//
// The comment this block replaced described "the four tests below" binding a
// three-conjunct projection gate. Those tests did not exist — the block was a
// trailing comment with nothing after it — and the gate it described is gone.
// ---------------------------------------------------------------------------

/// The reference LAN fixture with every row's `egress_zone` replaced. Row zones
/// are left alone, so `carried` on that ifindex is `{"", "lan"}`.
fn reth_snapshot_with_claim_6722(claim: &str) -> crate::protocol::ConfigSnapshot {
    let mut snapshot = reth_member_unzoned_row_snapshot_6722();
    for iface in &mut snapshot.interfaces {
        if iface.ifindex == LAN_IFINDEX_6722 {
            iface.egress_zone = claim.to_string();
        }
    }
    snapshot
}

/// A DECIDED-empty claim overrides UNANIMOUS row agreement and fails closed.
///
/// This is the cell that makes the Go decision load-bearing rather than
/// decorative, and the fixture has to be the unanimous one to bind it. EVERY
/// row on this ifindex names `lan` — so any rule that resolved from the rows,
/// including the compatibility arm, would answer `lan` — while the builder
/// stamps "".
///
/// That combination is producible, not contrived: a reth member that the
/// operator zoned into the SAME zone as its reth and that also carries its own
/// addressed unit. `buildInterfaceZoneMap` fans the member's zone down onto its
/// unit, so all four rows read `lan`; `stampEgressZones` sees a member that is
/// not a bare port, calls the device's ownership contested, and answers no
/// zone. Preferring the rows there re-admits the measured #6722 fail-OPEN (a
/// flow to the member unit's own subnet adjudicated in the RETH's zone).
///
/// An earlier revision of this cell used the ordinary reth fixture, whose
/// member row is UNZONED. `carried` then holds `{"", "lan"}`, no rule resolves
/// anything from it, and the mutation that prefers row agreement was measured
/// GREEN — the cell could not distinguish the branch it named.
#[test]
fn decided_empty_egress_zone_overrides_row_agreement_6722() {
    let mut snapshot = reth_member_unzoned_row_snapshot_6722();
    for iface in &mut snapshot.interfaces {
        if iface.ifindex == LAN_IFINDEX_6722 {
            iface.zone = "lan".to_string();
            iface.egress_zone = String::new();
        }
    }
    // The precondition that makes this cell binding rather than decorative.
    let carried: std::collections::BTreeSet<&str> = snapshot
        .interfaces
        .iter()
        .filter(|i| i.ifindex == LAN_IFINDEX_6722)
        .map(|i| i.zone.as_str())
        .collect();
    assert_eq!(
        carried.into_iter().collect::<Vec<_>>(),
        vec!["lan"],
        "precondition: EVERY row on this ifindex must name `lan`, or a rule that \
         resolved from the rows would answer nothing here anyway and this cell \
         would not distinguish it from one that honours the builder"
    );
    let state = build_forwarding_state(&snapshot);

    assert_eq!(
        state.ifindex_to_zone_id.get(&LAN_IFINDEX_6722).copied(),
        Some(TEST_LAN_ZONE_ID),
        "precondition: the INGRESS half still resolves `lan`, so a 0 to-zone          below is the egress decision and not an empty state"
    );
    assert!(
        !state
            .ifindex_unambiguous_zone_id
            .contains_key(&LAN_IFINDEX_6722),
        "a builder decision of \"no single zone\" must keep the ifindex out of          the ledger even though its zoned rows agree with each other"
    );

    let (_, to_id, result) =
        adjudicate_wan_to_lan_transit_6722(&state, "10.0.61.102", LAN_IFINDEX_6722);
    assert_eq!(
        to_id, 0,
        "the builder decided this ifindex identifies no zone; resolving `lan`          from the rows instead would readmit every shape the builder rejects          (a tunnel or a reth named as a member) as a fail-OPEN"
    );
    assert_eq!(result.action, PolicyAction::Deny);
    assert_eq!(
        result.policy_id,
        crate::policy::DEFAULT_POLICY_SENTINEL_ID,
        "with no to-zone the default policy decides, not `wan -> lan permit`"
    );
}

/// An UNCORROBORATED claim is refused: the helper honours a zone only where a
/// row on the ifindex literally names it.
///
/// This is the whole of the helper-boundary check on a field the helper
/// otherwise trusts (#2391/#2409/#2706). A version-drifted or hostile snapshot
/// can make the claim say anything; it cannot make it say a zone no row on that
/// ifindex named.
#[test]
fn uncorroborated_egress_zone_claim_is_refused_6722() {
    let state = build_forwarding_state(&reth_snapshot_with_claim_6722("wan"));

    assert!(
        state.zone_name_to_id.contains_key("wan"),
        "precondition: `wan` is a REAL configured zone with a nonzero id, so          this cell fails for lack of corroboration rather than for lack of a          zone table entry"
    );
    assert!(
        !state
            .ifindex_unambiguous_zone_id
            .contains_key(&LAN_IFINDEX_6722),
        "no row on this ifindex carries `wan`, so the claim is uncorroborated          and must be refused"
    );

    let (_, to_id, _) =
        adjudicate_wan_to_lan_transit_6722(&state, "10.0.61.102", LAN_IFINDEX_6722);
    assert_eq!(
        to_id, 0,
        "an uncorroborated claim must resolve the 0 sentinel; adopting it would          let a drifted snapshot CONJURE a zone the operator never put this          device in -- here `wan`, which would make WAN->LAN transit a          same-zone flow"
    );
}

/// Rows on ONE ifindex carrying DIFFERENT claims fail closed. The builder
/// stamps them identically, so a disagreement is version drift.
///
/// THE FIXTURE IS THE CELL (round 12). The obvious fixture —
/// `reth_member_unzoned_row_snapshot_6722`, whose LAN rows carry only `lan` and
/// `""` — cannot see the mechanism this cell names. Injecting a second claim of
/// `wan` there is refused by CORROBORATION, because no row on that ifindex
/// carries `wan`, and the merge is never consulted. MEASURED at 6e62cd01d:
/// replacing `EgressZoneClaim::merge`'s agreeing arm with last-write-wins
/// (`Self::Decided(_have) => Self::Decided(egress_zone.to_string())`) left the
/// whole cargo suite green — 4400 passed, rc=0 — including that spelling of this
/// cell run on its own. It named the merge and bound the corroboration.
///
/// So it runs on `reth_member_explicitly_zoned_snapshot_6722`, where the member
/// row carries `wan` and the two RETH rows carry `lan`: BOTH claimed values are
/// literally on the ifindex, so corroboration cannot refuse either one and the
/// merge is the only thing left that can. The precondition below asserts exactly
/// that, so the cell cannot silently drift back into vacuity if the fixture's
/// zones change.
///
/// FAIL-ON-REVERT: either spelling of a last-write-wins merge — replacing the
/// agreeing arm, or replacing the `_ => Self::Conflicting` arm so `Conflicting`
/// stops being sticky — resolves `wan` for the LAN ifindex, and a drifted or
/// hostile snapshot then makes WAN->LAN transit a same-zone flow.
#[test]
fn conflicting_egress_zone_claims_on_one_ifindex_fail_closed_6722() {
    let mut snapshot = reth_member_explicitly_zoned_snapshot_6722();
    let mut first = true;
    for iface in &mut snapshot.interfaces {
        if iface.ifindex == LAN_IFINDEX_6722 {
            iface.egress_zone = if first { "lan" } else { "wan" }.to_string();
            first = false;
        }
    }
    // ANTI-VACUITY PRECONDITION. Both claimed values must be CORROBORATED —
    // carried as some row's own `zone` on this ifindex — or `resolve`'s
    // corroboration check refuses the claim before the merge's answer matters,
    // and a green here says nothing about the merge.
    let carried: std::collections::BTreeSet<String> = snapshot
        .interfaces
        .iter()
        .filter(|i| i.ifindex == LAN_IFINDEX_6722)
        .map(|i| i.zone.clone())
        .collect();
    for claimed in ["lan", "wan"] {
        assert!(
            carried.contains(claimed),
            "precondition: no row on ifindex {LAN_IFINDEX_6722} carries {claimed:?} \
             (rows carry {carried:?}), so corroboration would refuse that claim on \
             its own and this cell would bind the corroboration, not the merge"
        );
    }

    let state = build_forwarding_state(&snapshot);

    assert!(
        state.zone_name_to_id.contains_key("wan"),
        "precondition: `wan` is a REAL configured zone with a nonzero id, so a 0 \
         answer below is the drift refusal and not a missing zone-table entry"
    );
    assert!(
        !state
            .ifindex_unambiguous_zone_id
            .contains_key(&LAN_IFINDEX_6722),
        "rows on one ifindex claiming different egress zones is drift, and drift          must not be resolved by preferring whichever row is walked first"
    );
    let (_, to_id, _) =
        adjudicate_wan_to_lan_transit_6722(&state, "10.0.61.102", LAN_IFINDEX_6722);
    assert_eq!(
        to_id, 0,
        "a conflicting claim resolves the 0 sentinel; adopting the last writer's \
         `wan` — which IS corroborated on this ifindex — would make WAN->LAN \
         transit a same-zone flow"
    );
}

// RETIRED in the same round that introduced it:
// `absent_egress_zone_claim_falls_back_to_row_unanimity_6722` bound the
// compatibility arm — "no row carried `egress_zone`, so fall back to row
// unanimity". The v5 protocol bump deleted that arm, because
// `apply_snapshot`'s exact-equality version gate refuses a snapshot from a
// control plane that does not carry the field, so the arm was unreachable in
// production while 54 tests still exercised it. A test that binds a path
// production cannot take is the vacuous-test class however green it looks, so
// the arm and its binder went together rather than the binder being re-pointed
// at something else.

// ---------------------------------------------------------------------------
// #6722 round 10: what the DECODER does with a snapshot from the other side of
// the field change, and why that is a decoder property rather than a
// compatibility path.
//
// This round DELETES `reth_projection` and ADDS `egress_zone`, and bumps
// CONFIG_SNAPSHOT_PROTOCOL_VERSION 4 -> 5 because of it. The bump is what makes
// the pairing safe: `apply_snapshot` and `bump_fib_generation` gate on EXACT
// equality, so a v4 control plane's snapshot never reaches the builder at all.
//
// WHY THE BUMP WAS NOT OPTIONAL, measured: feeding the v4 Go builder's rows to
// the v5 helper on the reference cluster (docs/ha-cluster-userspace.conf, node 0)
// resolves egress zone 0 for BOTH ifindex 24 and ifindex 25, where origin/master
// and the matched v5 pair resolve `lan` and `wan`. Ifindex 25 is the one that
// settles it — the mixed pairing loses a zone even the PRE-#6722 helper resolved,
// so it is strictly worse than either endpoint rather than an intermediate
// state, and under `default-policy deny-all` that is a silent transit outage
// carrying a version both halves agree on.
//
// The cell below is therefore NOT a compatibility path. It pins two decoder
// properties that must hold regardless: the retired key does not make
// deserialization fail (it would turn a version mismatch into a parse crash
// rather than the clean refusal the gate gives), and an absent `egress_zone`
// decodes to "" and answers the 0 sentinel.

/// DECODER TOLERANCE + the absent-field default. A snapshot carrying the
/// RETIRED `reth_projection` key and no `egress_zone` must deserialize (an error
/// would turn a version mismatch into a parse crash instead of the clean refusal
/// the version gate gives) and must resolve NO zone.
///
/// Not a compatibility path: at v5 such a snapshot is refused at
/// `apply_snapshot` before it reaches the builder. These are properties of the
/// decoder and of the empty-string default, which hold whatever the gate does.
#[test]
fn retired_wire_key_decodes_and_absent_egress_zone_fails_closed_6722() {
    let snapshot = reth_member_unzoned_row_snapshot_6722();
    let mut v = serde_json::to_value(&snapshot).expect("serialize");
    for row in v
        .get_mut("interfaces")
        .and_then(|i| i.as_array_mut())
        .expect("interfaces")
        .iter_mut()
    {
        let obj = row.as_object_mut().expect("row");
        // Exactly what the Go builder at c9b020695 emits for this config,
        // captured from that builder rather than hand-written: the member row
        // carries `reth_projection: true` and no row carries `egress_zone`.
        obj.remove("egress_zone");
        if obj.get("ifindex").and_then(|x| x.as_i64()) == Some(LAN_IFINDEX_6722 as i64)
            && obj.get("zone").and_then(|z| z.as_str()).unwrap_or("").is_empty()
        {
            obj.insert("reth_projection".to_string(), serde_json::json!(true));
        }
    }

    let round: crate::protocol::ConfigSnapshot = serde_json::from_value(v)
        .expect(
            "the decoder must accept a snapshot carrying the RETIRED key; an error \
             here would turn a version mismatch into a parse crash instead of the \
             clean refusal the version gate gives",
        );
    for iface in &round.interfaces {
        if iface.ifindex == LAN_IFINDEX_6722 {
            assert_eq!(
                iface.egress_zone, "",
                "precondition: no row carries the new field, so it decodes to the \
                 empty string — the same state the builder stamps when it decides \
                 an ifindex identifies no zone, which is why the field is a plain \
                 String and not an Option"
            );
        }
    }

    let state = build_forwarding_state(&round);
    assert!(
        !state
            .ifindex_unambiguous_zone_id
            .contains_key(&LAN_IFINDEX_6722),
        "an old xpfd's snapshot must not resolve a zone here: with no row \
         carrying a claim the resolver has nothing to corroborate, so the \
         ifindex is absent from the ledger and the egress row falls to 0"
    );
    let (_, to_id, result) =
        adjudicate_wan_to_lan_transit_6722(&state, "10.0.61.102", LAN_IFINDEX_6722);
    assert_eq!(
        to_id, 0,
        "a snapshot with no claim must degrade to the PRE-#6722 fail-closed \
         answer, not to a guess"
    );
    assert_ne!(
        to_id, TEST_LAN_ZONE_ID,
        "specifically NOT `lan` -- naming the value a fail-open would produce"
    );
    assert_eq!(result.action, PolicyAction::Deny);
}

/// The egress row's `zone_id` is ORDER-INVARIANT, because it comes from the
/// ledger rather than from whichever row `populate_egress` wrote last.
///
/// WHY THIS CELL EXISTS, measured rather than assumed. After the fixture
/// migration a mutation of the consumer -- sourcing `zone_id` from the row's own
/// `zone` name, which is what `origin/master` did -- was applied to the whole
/// crate. It reddened exactly ONE test tree-wide, the ambiguous-ifindex sibling
/// of this one. Every other test that touches an egress zone survived, and not
/// because the migration weakened them: for an ifindex with a single configured
/// identity the ledger answer and the row's own zone are THE SAME VALUE, so no
/// mutation swapping one for the other can be seen. Those tests bind that a zone
/// reaches the policy decision; they cannot bind WHICH mechanism supplied it.
///
/// The one surviving discriminator answered 0 -- a sentinel. So the positive
/// direction of B1, "the ledger's non-zero answer beats a dissenting row", had
/// no cell at all. This is it.
///
/// The fixture is the reference LAN shape: ifindex 24 carries `ge-0/0/1`
/// (unzoned member row), `reth1` and `reth1.0` (both `lan`), and the builder
/// stamps `lan` on all three. Emitting the UNZONED row last is what separates
/// the two mechanisms -- last-write-wins reads 0, the ledger reads `lan` -- and
/// the assertion is that both orders agree.
///
/// Fail-on-revert MEASURED, not asserted: under that consumer mutation this cell
/// fails with `left: 0, right: 1` (`TEST_LAN_ZONE_ID` is 1), and it passes on the
/// unmutated tree. The two cells were run from separate sandbox copies, each
/// asserting its own `Compiling xpf-userspace-dp` line, and their outcomes
/// DIFFER -- which is what rules out one stale binary having produced both.
#[test]
fn egress_row_zone_is_order_invariant_not_last_write_6722() {
    let forward = reth_member_unzoned_row_snapshot_6722();
    let mut reversed = forward.clone();
    reversed.interfaces.reverse();

    // Precondition: reversing really does move the unzoned row last, or the cell
    // measures nothing. Without this the fixture could be reordered later and
    // this test would keep passing for a reason it does not name.
    let last_on_ifindex = |snap: &crate::protocol::ConfigSnapshot| -> String {
        snap.interfaces
            .iter()
            .filter(|i| i.ifindex == LAN_IFINDEX_6722)
            .next_back()
            .map(|i| i.zone.clone())
            .expect("the fixture must have rows on the LAN ifindex")
    };
    assert_eq!(
        last_on_ifindex(&forward),
        "lan",
        "precondition: in emission order the LAST row on this ifindex is zoned"
    );
    assert_eq!(
        last_on_ifindex(&reversed),
        "",
        "precondition: reversed, the LAST row on this ifindex is the UNZONED \
         member -- this is the difference the two mechanisms disagree about"
    );

    for (label, snapshot) in [("emission order", &forward), ("reversed", &reversed)] {
        let state = build_forwarding_state(snapshot);
        assert_eq!(
            state
                .egress
                .get(&LAN_IFINDEX_6722)
                .map(|i| i.zone_id)
                .unwrap_or(0),
            TEST_LAN_ZONE_ID,
            "{label}: the egress row must carry the ledger's `lan`, not the zone \
             of whichever row happened to be written last"
        );

        let (_, to_id, result) =
            adjudicate_wan_to_lan_transit_6722(&state, "10.0.61.102", LAN_IFINDEX_6722);
        assert_eq!(
            to_id, TEST_LAN_ZONE_ID,
            "{label}: transit must be adjudicated in `lan`"
        );
        assert_eq!(
            result.action,
            PolicyAction::Permit,
            "{label}: the wan->lan permit must be reached; a 0 here would send \
             this to the default deny instead"
        );
    }
}

/// #7204 (A1-b7-F6): the liveness bitmask must pick the SAME member the
/// collect-based implementation did, at every fanout on both sides of the
/// 64-candidate mask boundary.
///
/// This is an EQUIVALENCE, not a validity check, and that distinction is the
/// whole point. ECMP selection is flow-consistent — a given 5-tuple must keep
/// landing on the same member — so an implementation that picked a *different*
/// live member would still look correct to a test that only asserted "the
/// result is live", while silently repinning every existing flow on upgrade.
///
/// The reference below is the pre-#7204 body verbatim. Spanning 1..=70 covers
/// the boundary in both directions: at or below 64 the mask path runs, above it
/// the collect fallback does, and a spill above the supported ceiling is
/// CORRECT behaviour rather than a defect — so the fallback is asserted to
/// still select properly instead of being pinned as unreachable.
#[test]
fn select_route_next_hop_bitmask_matches_collect_reference_7204() {
    fn reference<'a, T: Copy>(
        candidates: &'a [T],
        ip_hash: u64,
        is_live: impl Fn(&T) -> bool,
    ) -> Option<&'a T> {
        if candidates.is_empty() {
            return None;
        }
        let live: Vec<&'a T> = candidates.iter().filter(|c| is_live(c)).collect();
        if !live.is_empty() {
            let pick = (ip_hash % live.len() as u64) as usize;
            live.get(pick).copied()
        } else {
            let pick = (ip_hash % candidates.len() as u64) as usize;
            candidates.get(pick)
        }
    }

    for fanout in 1usize..=70 {
        let candidates: Vec<u32> = (0..fanout as u32).collect();
        // Several liveness shapes: all live, none live, alternating, only the
        // last live, only the first. "None live" exercises the fallback branch,
        // which a uniformly-live fixture would never reach.
        let shapes: Vec<Box<dyn Fn(&u32) -> bool>> = vec![
            Box::new(|_c: &u32| true),
            Box::new(|_c: &u32| false),
            Box::new(|c: &u32| c % 2 == 0),
            Box::new(move |c: &u32| *c as usize == fanout - 1),
            Box::new(|c: &u32| *c == 0),
        ];
        for (shape_idx, is_live) in shapes.iter().enumerate() {
            for ip_hash in [0u64, 1, 2, 7, 63, 64, 65, 1_000_003, u64::MAX] {
                let got = select_route_next_hop(&candidates, ip_hash, |c| is_live(c));
                let want = reference(&candidates, ip_hash, |c| is_live(c));
                assert_eq!(
                    got, want,
                    "fanout={fanout} shape={shape_idx} hash={ip_hash}: the bitmask \
                     picked a different member than the collect reference — ECMP is \
                     flow-consistent, so a different-but-live pick silently repins \
                     every existing flow"
                );
            }
        }
    }
}

/// #7204 (A1-b7-F6): the bitmask must not cost a second liveness evaluation.
///
/// The collect existed to call `is_live` exactly once per candidate — both call
/// sites reach `tunnel_next_hop_live`, which resolves a tunnel endpoint and
/// consults the neighbour map, so a two-pass rewrite would have traded an
/// allocation for double that work. This pins the property the collect was
/// bought for, at a fanout the old inline capacity could not hold.
#[test]
fn select_route_next_hop_bitmask_evaluates_liveness_once_7204() {
    use std::cell::Cell;

    for fanout in [1usize, 8, 9, 64, 65] {
        let candidates: Vec<u32> = (0..fanout as u32).collect();
        let calls = Cell::new(0usize);
        let _ = select_route_next_hop(&candidates, 12345, |c| {
            calls.set(calls.get() + 1);
            c % 3 != 0
        });
        assert_eq!(
            calls.get(),
            fanout,
            "fanout={fanout}: liveness must be evaluated exactly once per candidate"
        );
    }
}

/// #7204 (A1-b7-F6): the liveness mask must cover the whole supported ECMP
/// range, or the allocation this item removed comes back for the fanouts it no
/// longer reaches.
///
/// This pins a PROPERTY, not the constant's value: lowering the mask width does
/// not change which member is picked (the fallback is equivalence-tested above),
/// so no behavioural test can see it. What it changes is whether a supported
/// configuration allocates on every new-flow lookup — and the bound that makes
/// 64 the right number is the control plane's rendered `maximum-paths`, not a
/// preference.
#[test]
fn ecmp_liveness_mask_covers_the_rendered_maximum_paths_7204() {
    // pkg/frr/config_render.go resolveECMP -> ecmpMaxPaths = 64, rendered by
    // pkg/frr/protocols_render.go as `maximum-paths %d`. Junos
    // routing-options maximum-ecmp is Missing (docs/feature-gaps.md), so 64 is
    // a ceiling rather than a default an operator can raise.
    const RENDERED_MAXIMUM_PATHS: usize = 64;
    assert!(
        crate::afxdp::forwarding::fib::MAX_SUPPORTED_ECMP_FANOUT >= RENDERED_MAXIMUM_PATHS,
        "the ECMP liveness mask covers {} candidates but the control plane renders \
         maximum-paths {}; fanouts in between fall back to the heap-collecting path \
         and allocate on every new-flow FIB resolution",
        crate::afxdp::forwarding::fib::MAX_SUPPORTED_ECMP_FANOUT,
        RENDERED_MAXIMUM_PATHS,
    );
}

/// #7204 (A1-b7-F5): `canonical_route_table` must BORROW when it has nothing to
/// rewrite, and the value it returns must be unchanged either way.
///
/// The observable is `Cow::Borrowed` vs `Cow::Owned` — the direct form of "did
/// this allocate", the same role capacity played for the TX deques. Asserting
/// only the string value would pass identically before and after, because the
/// defect was never a wrong name: it was copying the argument to satisfy a
/// `'static` return on the common same-family path.
///
/// The Owned cases are asserted too, and not as an afterthought: a "fix" that
/// borrowed unconditionally would return the WRONG TABLE for a genuine family
/// rewrite, which no allocation-counting assertion would catch.
#[test]
fn canonical_route_table_borrows_when_no_rewrite_is_needed_7204() {
    use std::borrow::Cow;

    // Same family: nothing to rewrite, so nothing to allocate. This is the arm
    // that used to `to_string()` its own argument.
    for (table, is_ipv6) in [("vrf-a.inet.0", false), ("vrf-a.inet6.0", true)] {
        let got = canonical_route_table(table, is_ipv6);
        assert!(
            matches!(got, Cow::Borrowed(_)),
            "{table} (v6={is_ipv6}) needs no rewrite and must be borrowed, not copied"
        );
        assert_eq!(got, table, "...and must come back unchanged");
    }

    // Default-table cross-family: a different &'static str, still borrowed.
    assert!(matches!(
        canonical_route_table(DEFAULT_V4_TABLE, true),
        Cow::Borrowed(_)
    ));
    assert_eq!(canonical_route_table(DEFAULT_V4_TABLE, true), DEFAULT_V6_TABLE);
    assert_eq!(canonical_route_table(DEFAULT_V6_TABLE, false), DEFAULT_V4_TABLE);

    // Genuine rewrites: a NEW string, so Owned is correct here and borrowing
    // would be a wrong-table bug rather than an optimisation.
    let v6 = canonical_route_table("vrf-a.inet.0", true);
    assert!(matches!(v6, Cow::Owned(_)), "a family rewrite must produce a new string");
    assert_eq!(v6, "vrf-a.inet6.0");
    let v4 = canonical_route_table("vrf-a.inet6.0", false);
    assert!(matches!(v4, Cow::Owned(_)));
    assert_eq!(v4, "vrf-a.inet.0");
}
