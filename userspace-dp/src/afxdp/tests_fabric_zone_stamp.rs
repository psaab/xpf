// #6458: end-to-end fail-on-revert coverage for the fabric zone-encoded
// src-MAC validation, driven through the REAL
// `poll_binding_process_descriptor` control flow (not the decode helper).
//
// The exploit: an L2-adjacent host on the HA fabric segment stamps a
// synthetic source MAC `02:bf:72:fe:<hi>:<lo>` encoding
// `StableZoneID("lan")` onto a frame and picks the ingress ZONE the
// receiving node evaluates new-flow policy / screens / host-inbound under.
// Before the fix the decode checked only fabric-ingress + magic +
// zone-exists, so the stamped `lan -> wan` permit admitted the flow and
// installed a session. The fix honors the stamp only when it validates
// against the fabric link identity (unicast dst == our fabric MAC) and the
// live RG ownership (V1b claimed-zone RG not locally active at stage 9;
// V2 resolution-owner RG locally active at the session-miss zone pair).
//
// Sibling `#[path]` test module loaded from afxdp/mod.rs, mirroring the
// #4840 split; helpers come from afxdp/tests_support.rs.
#![allow(unused_imports)]

use super::test_fixtures::*;
use super::worker::WorkerTxPipeline;
use super::*;
use crate::test_zone_ids::*;
use crate::xsk_ffi::IfInfo;
use crate::{
    ClassOfServiceSnapshot, CoSDSCPClassifierEntrySnapshot, CoSDSCPClassifierSnapshot,
    CoSForwardingClassSnapshot, CoSIEEE8021ClassifierEntrySnapshot, CoSIEEE8021ClassifierSnapshot,
    CoSSchedulerMapEntrySnapshot, CoSSchedulerMapSnapshot, CoSSchedulerSnapshot,
    DestinationNATRuleSnapshot, FirewallFilterSnapshot, FirewallTermSnapshot,
    InterfaceAddressSnapshot, NeighborSnapshot, PolicyRuleSnapshot, RouteSnapshot,
    SourceNATRuleSnapshot, StaticNATRuleSnapshot, ThreeColorPolicerSnapshot, ZoneSnapshot,
};
use super::tests_support::*;

/// Control-zone id for the restrictive-fabric fixture (arbitrary test id,
/// distinct from the `test_zone_ids` constants — lan=1, wan=2).
const TEST_CONTROL_ZONE_ID: u16 = 9;

/// The fabric link in `nat_snapshot_with_fabric` (parent ifindex 21) has
/// local MAC 02:bf:72:ff:00:01; the legitimate peer unicasts the redirect
/// to it. Build a LAN→WAN TCP frame with flags `tcp_flags`, carrying the
/// zone-encoded stamp for `zone_id` in the source MAC, addressed to the fabric
/// link's MAC — byte-identical to what the legitimate sender emits, except the
/// placement decides whether it is legitimate. The destination (8.8.8.8)
/// resolves via the default route to the fixture's REACHABLE gateway
/// neighbor (172.16.80.1), so an admitted flow installs a session AND
/// queues a forward — the two observables the forged-frame pins assert
/// against (a connected-subnet dst would strand in MissingNeighbor and
/// make the deny assertions vacuous).
fn stamped_fabric_frame(zone_id: u16, tcp_flags: u8) -> Vec<u8> {
    let mut frame = build_txn_tcp_syn_frame_v4(
        Ipv4Addr::new(10, 0, 61, 102),
        Ipv4Addr::new(8, 8, 8, 8),
        12345,
        443,
        tcp_flags,
        crate::afxdp::tests_support::TEST_FABRIC_MAC,
    );
    let [hi, lo] = zone_id.to_be_bytes();
    frame[0..6].copy_from_slice(&[0x02, 0xbf, 0x72, 0xff, 0x00, 0x01]);
    frame[6..12].copy_from_slice(&[0x02, 0xbf, 0x72, FABRIC_ZONE_MAC_MAGIC, hi, lo]);
    frame
}

fn fabric_binding() -> BindingWorker {
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 21, 0);
    binding.interface = Arc::<str>::from("ge-0-0-0");
    binding
}

fn active_rg(now_secs: u64) -> HAGroupRuntime {
    HAGroupRuntime {
        active: true,
        watchdog_timestamp: now_secs,
        lease: HAGroupRuntime::active_lease_until(now_secs, now_secs),
    }
}

/// #6458 fail-on-revert, single-primary node: a forged stamp claiming
/// `lan` arrives on the fabric while lan's RG (2) is forwarding-active
/// LOCALLY. The stage-9 RG-binding check rejects the stamp, so the new
/// flow evaluates under the fabric interface's own (unzoned) zone and the
/// default-deny drops it: NO session, NO forward. Before the fix the
/// stamped `lan -> wan` permit admitted the flow and installed a session
/// with a queued forward — both assertions go RED.
#[test]
fn forged_fabric_stamp_denied_when_claimed_zone_rg_is_local_6458() {
    let forwarding = build_forwarding_state(&nat_snapshot_with_fabric());
    let now_secs = monotonic_nanos() / 1_000_000_000;
    // Single-primary placement: BOTH RGs forwarding-active locally.
    let ha_state = BTreeMap::from([(1, active_rg(now_secs)), (2, active_rg(now_secs))]);
    let frame = stamped_fabric_frame(TEST_LAN_ZONE_ID, TCP_FLAG_SYN);
    let meta = txn_meta_v4(21, TCP_FLAG_SYN, frame.len() as u16);

    let mut binding = fabric_binding();
    let mut sessions = SessionTable::new();
    txn_run_descriptor_checked(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame,
        meta,
        true,
    );

    assert_eq!(
        sessions.len(),
        0,
        "forged zone-encoded stamp must not install a session (RED on revert: \
         the stamped lan -> wan permit installs one)"
    );
    assert!(
        binding.scratch.scratch_forwards.is_empty(),
        "forged zone-encoded stamp must not queue a forward (RED on revert: \
         the admitted flow forwards toward the WAN gateway)"
    );
}

/// #6458 fail-on-revert (V2 owner binding), host-inbound variant: the
/// fabric parent sits in a RESTRICTIVE `control` zone (ping-only), so an
/// UNSTAMPED fabric-ingress packet to the firewall's own reth address is
/// denied host-inbound SSH. The attacker stamps `lan` (host-inbound `all`
/// in this fixture) to escalate. The stage-9 RG-binding check honors the
/// stamp (lan's RG 2 is not locally active — the WAN RG 1 primary is us),
/// but the session-miss V2 owner binding strips it: the local-delivery
/// target lives on reth1.0 (RG 2), which is NOT forwarding-active locally
/// either — the peer never punts host-bound traffic for an RG it owns to
/// us. The packet therefore evaluates under the restrictive control zone
/// and is denied: NO host-bound session. Before the fix the stamped `lan`
/// admit set opened SSH — the session caches and this test goes RED.
#[test]
fn forged_fabric_stamp_denied_for_host_inbound_when_owner_rg_remote_6458() {
    let mut snapshot = nat_snapshot_with_fabric();
    // A restrictive fabric zone: ping only, no SSH. Mirrors the reference
    // cluster's `control` zone containing fab0/fab1, but locked down so the
    // stamp's zone escalation is observable.
    snapshot.zones.push(ZoneSnapshot {
        name: "control".to_string(),
        id: TEST_CONTROL_ZONE_ID,
        host_inbound_configured: true,
        host_inbound_system_services: vec!["ping".to_string()],
        ..Default::default()
    });
    snapshot.interfaces[2].zone = "control".to_string(); // ge-0/0/0 (fabric parent)
    let forwarding = build_forwarding_state(&snapshot);
    let now_secs = monotonic_nanos() / 1_000_000_000;
    // Split placement: WAN RG (1) is local; LAN RG (2) is the peer's.
    let ha_state = BTreeMap::from([(1, active_rg(now_secs))]);
    let mut frame = build_txn_tcp_syn_frame_v4(
        Ipv4Addr::new(10, 0, 61, 102),
        Ipv4Addr::new(10, 0, 61, 1),
        12345,
        22,
        TCP_FLAG_SYN,
        crate::afxdp::tests_support::TEST_FABRIC_MAC,
    );
    let [hi, lo] = TEST_LAN_ZONE_ID.to_be_bytes();
    frame[0..6].copy_from_slice(&[0x02, 0xbf, 0x72, 0xff, 0x00, 0x01]);
    frame[6..12].copy_from_slice(&[0x02, 0xbf, 0x72, FABRIC_ZONE_MAC_MAGIC, hi, lo]);
    let meta = txn_meta_v4(21, TCP_FLAG_SYN, frame.len() as u16);

    let mut binding = fabric_binding();
    let mut sessions = SessionTable::new();
    txn_run_descriptor_checked(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame,
        meta,
        true,
    );

    assert_eq!(
        sessions.len(),
        0,
        "a stamped host-inbound escalation must not cache a host-bound session \
         (RED on revert: the forged lan admit set opens SSH)"
    );
    assert!(
        binding.scratch.scratch_recycle.contains(&128),
        "the denied host-inbound packet must be dropped"
    );
}

/// #6458 preservation pin, host-inbound split-RG variant: the LAN RG (2)
/// primary is US, the WAN RG (1) primary is the PEER. A remote host's SSH
/// to our reth1.0 address ingressed the peer (WAN side) and is
/// legitimately punted across the fabric stamped `wan`. The stamp
/// validates (unicast dst; claimed-zone RG 1 not local; local-delivery
/// target's RG 2 IS local), so host-inbound evaluates under `wan` (admits
/// `all` here) and the host-bound session caches — identical before and
/// after the fix.
#[test]
fn legitimate_fabric_punted_host_inbound_still_admitted_6458() {
    let forwarding = build_forwarding_state(&nat_snapshot_with_fabric());
    let now_secs = monotonic_nanos() / 1_000_000_000;
    // Split placement: LAN RG (2) is local; WAN RG (1) is the peer's.
    let ha_state = BTreeMap::from([(2, active_rg(now_secs))]);
    let mut frame = build_txn_tcp_syn_frame_v4(
        Ipv4Addr::new(172, 16, 80, 200),
        Ipv4Addr::new(10, 0, 61, 1),
        43210,
        22,
        TCP_FLAG_SYN,
        crate::afxdp::tests_support::TEST_FABRIC_MAC,
    );
    let [hi, lo] = TEST_WAN_ZONE_ID.to_be_bytes();
    frame[0..6].copy_from_slice(&[0x02, 0xbf, 0x72, 0xff, 0x00, 0x01]);
    frame[6..12].copy_from_slice(&[0x02, 0xbf, 0x72, FABRIC_ZONE_MAC_MAGIC, hi, lo]);
    let meta = txn_meta_v4(21, TCP_FLAG_SYN, frame.len() as u16);

    let mut binding = fabric_binding();
    let mut sessions = SessionTable::new();
    txn_run_descriptor_checked(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame,
        meta,
        true,
    );

    assert!(
        sessions.len() >= 1,
        "the legitimate split-RG host-inbound punt must keep caching its session"
    );
}

/// #10645: the split-RG host-inbound punt above must evaluate under the
/// CLAIMED zone (wan), not zone 0. The punt targets reth1.0's 10.0.61.1 —
/// a /24 interface address, so the pre-fix miss path attributed
/// local_ifindex 0, owner-RG attribution collapsed, and the #6458 gate
/// stripped the fabric stamp: the packet then evaluated at zone 0 into
/// the `None => true` admit, and the admit-cell above passed while
/// claiming wan-zone evaluation. Restrict wan host-inbound to ping-only:
/// a genuine wan evaluation must now DENY this SSH probe, while a zone-0
/// evaluation would still admit it. RED pre-fix (session cached), GREEN
/// post-fix (dropped, nothing cached).
#[test]
fn split_rg_host_inbound_punt_evaluates_under_the_claimed_zone_10645() {
    let mut snapshot = nat_snapshot_with_fabric();
    for zone in snapshot.zones.iter_mut() {
        if zone.id == TEST_WAN_ZONE_ID {
            zone.host_inbound_system_services = vec!["ping".to_string()];
        }
    }
    let forwarding = build_forwarding_state(&snapshot);
    let now_secs = monotonic_nanos() / 1_000_000_000;
    // Split placement: LAN RG (2) is local; WAN RG (1) is the peer's — the
    // legitimate punt shape, so the stamp validates and the only question
    // is which zone judges the host-inbound admission.
    let ha_state = BTreeMap::from([(2, active_rg(now_secs))]);
    let mut frame = build_txn_tcp_syn_frame_v4(
        Ipv4Addr::new(172, 16, 80, 200),
        Ipv4Addr::new(10, 0, 61, 1),
        43210,
        22,
        TCP_FLAG_SYN,
        crate::afxdp::tests_support::TEST_FABRIC_MAC,
    );
    let [hi, lo] = TEST_WAN_ZONE_ID.to_be_bytes();
    frame[0..6].copy_from_slice(&[0x02, 0xbf, 0x72, 0xff, 0x00, 0x01]);
    frame[6..12].copy_from_slice(&[0x02, 0xbf, 0x72, FABRIC_ZONE_MAC_MAGIC, hi, lo]);
    let meta = txn_meta_v4(21, TCP_FLAG_SYN, frame.len() as u16);

    let mut binding = fabric_binding();
    let mut sessions = SessionTable::new();
    txn_run_descriptor_checked(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame,
        meta,
        true,
    );

    assert_eq!(
        sessions.len(),
        0,
        "wan admits ping only: an SSH probe evaluated under the claimed wan \
         zone must be denied. A cached session here means the stamp was \
         stripped and the packet evaluated at zone 0 into the admit-all."
    );
    assert!(
        binding.scratch.scratch_recycle.contains(&128),
        "the zone-denied probe must be dropped"
    );
}

/// #6458 preservation pin, split-RG active/active: the LAN RG (2) primary
/// is the PEER, the WAN RG (1) primary is US. The peer legitimately punts
/// a LAN→WAN new flow across the fabric stamped `lan`; the stamp
/// validates (unicast dst, claimed-zone RG not local, resolution-owner RG
/// local), the `lan -> wan` permit admits the flow, and the session
/// installs with a queued forward — identical before and after the fix.
#[test]
fn legitimate_fabric_punted_flow_still_admitted_6458() {
    let forwarding = build_forwarding_state(&nat_snapshot_with_fabric());
    let now_secs = monotonic_nanos() / 1_000_000_000;
    // Split placement: WAN RG (1) is local; LAN RG (2) is the peer's.
    let ha_state = BTreeMap::from([(1, active_rg(now_secs))]);
    let frame = stamped_fabric_frame(TEST_LAN_ZONE_ID, TCP_FLAG_SYN);
    let meta = txn_meta_v4(21, TCP_FLAG_SYN, frame.len() as u16);

    let mut binding = fabric_binding();
    let mut sessions = SessionTable::new();
    txn_run_descriptor_checked(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame,
        meta,
        true,
    );

    assert_eq!(
        sessions.len(),
        2,
        "the legitimate split-RG fabric punt must keep installing its session \
         (forward + reverse companion for the NAT'd lan -> wan flow)"
    );
    assert_eq!(
        binding.scratch.scratch_forwards.len(),
        1,
        "the legitimate split-RG fabric punt must keep forwarding"
    );
}

const TCP_FLAG_ACK: u8 = 0x10;

/// #6478 fail-on-revert: a session-less fabric-ingress TCP SYN-ACK (a
/// forgeable "return" form) must NOT be adopted into a NAT-less
/// `SessionOrigin::ReverseFlow` seed. Before this PR the cluster-peer
/// return fast path fired for exactly this shape — a validated stamp
/// (claimed `lan`, whose RG 2 is remote in this split placement), a
/// ForwardCandidate-resolving destination — and installed the reverse
/// seed with `NatDecision::default()` and no policy evaluation. With the
/// fast path removed the packet takes the normal session-miss path:
/// zone-pair POLICY under the #6458-validated zone, source-NAT applied,
/// FORWARD-origin sessions. The lookup must therefore NEVER resolve the
/// packet tuple to a `ReverseFlow` origin.
#[test]
fn fabric_ingress_syn_ack_seeds_no_reverse_session_6478() {
    let forwarding = build_forwarding_state(&nat_snapshot_with_fabric());
    let now_secs = monotonic_nanos() / 1_000_000_000;
    // Split placement: WAN RG (1) is local; LAN RG (2) is the peer's — the
    // ONLY placement where the #6458-validated stamp survives, and where
    // the pre-fix fast path could fire.
    let ha_state = BTreeMap::from([(1, active_rg(now_secs))]);
    let src = Ipv4Addr::new(10, 0, 61, 102);
    let dst = Ipv4Addr::new(8, 8, 8, 8);
    let mut frame = build_txn_tcp_syn_frame_v4(src, dst, 12345, 443, TCP_FLAG_SYN | TCP_FLAG_ACK, crate::afxdp::tests_support::TEST_FABRIC_MAC);
    let [hi, lo] = TEST_LAN_ZONE_ID.to_be_bytes();
    frame[0..6].copy_from_slice(&[0x02, 0xbf, 0x72, 0xff, 0x00, 0x01]);
    frame[6..12].copy_from_slice(&[0x02, 0xbf, 0x72, FABRIC_ZONE_MAC_MAGIC, hi, lo]);
    let meta = txn_meta_v4(21, TCP_FLAG_SYN | TCP_FLAG_ACK, frame.len() as u16);

    let mut binding = fabric_binding();
    let mut sessions = SessionTable::new();
    txn_run_descriptor_checked(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame,
        meta,
        true,
    );

    let key = SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        src_ip: IpAddr::V4(src),
        dst_ip: IpAddr::V4(dst),
        src_port: 12345,
        dst_port: 443,
            discriminator: Default::default(),
            routing_domain: 0,
    };
    let origin = sessions
        .lookup_with_origin(&key, 123_000_000_000, TCP_FLAG_SYN | TCP_FLAG_ACK)
        .map(|(_, origin)| origin);
    assert_ne!(
        origin,
        Some(SessionOrigin::ReverseFlow),
        "RED on revert: the fast path installed a NAT-less ReverseFlow seed \
         for a session-less fabric-ingress SYN-ACK"
    );
    // Post-fix the packet is a normal asymmetric-pickup new flow (#3152):
    // policy PERMIT under the validated lan -> wan pair installs the
    // forward + reverse companion pair WITH source-NAT — never the
    // policy-less single reverse seed.
    assert_eq!(
        sessions.len(),
        2,
        "the policy-path new flow installs the forward + reverse companion pair"
    );
}

/// #6478 fail-on-revert: same residual class as the SYN-ACK form, via an
/// ICMP echo REPLY — the second forgeable "return" form the removed fast
/// path adopted. Assert the packet tuple never resolves to a
/// `ReverseFlow` origin and that any installed state is the policy-path
/// forward flow.
#[test]
fn fabric_ingress_icmp_echo_reply_seeds_no_reverse_session_6478() {
    let forwarding = build_forwarding_state(&nat_snapshot_with_fabric());
    let now_secs = monotonic_nanos() / 1_000_000_000;
    let ha_state = BTreeMap::from([(1, active_rg(now_secs))]);
    let src = Ipv4Addr::new(10, 0, 61, 102);
    let dst = Ipv4Addr::new(8, 8, 8, 8);
    let mut frame =
        build_icmp_echo_frame_v4(src, dst, 64, crate::afxdp::tests_support::TEST_FABRIC_MAC);
    // Flip the echo REQUEST (type 8) the builder emits to an echo REPLY
    // (type 0) and recompute the ICMP checksum.
    let icmp_start = 34;
    frame[icmp_start] = 0;
    frame[icmp_start + 2..icmp_start + 4].copy_from_slice(&[0, 0]);
    let icmp_csum = checksum16(&frame[icmp_start..]);
    frame[icmp_start + 2..icmp_start + 4].copy_from_slice(&icmp_csum.to_be_bytes());
    let [hi, lo] = TEST_LAN_ZONE_ID.to_be_bytes();
    frame[0..6].copy_from_slice(&[0x02, 0xbf, 0x72, 0xff, 0x00, 0x01]);
    frame[6..12].copy_from_slice(&[0x02, 0xbf, 0x72, FABRIC_ZONE_MAC_MAGIC, hi, lo]);
    let meta_len = std::mem::size_of::<UserspaceDpMeta>();
    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: meta_len as u16,
        ingress_ifindex: 21,
        l3_offset: 14,
        l4_offset: 34,
        payload_offset: 42,
        pkt_len: frame.len() as u16,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_ICMP,
        config_generation: 7,
        fib_generation: 9,
        ..UserspaceDpMeta::default()
    };

    let mut binding = fabric_binding();
    let mut sessions = SessionTable::new();
    txn_run_descriptor_checked(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame,
        meta,
        true,
    );

    let key = SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_ICMP,
        src_ip: IpAddr::V4(src),
        dst_ip: IpAddr::V4(dst),
        // parse_flow_ports keys an identifier-bearing ICMP query as
        // (identifier, 0); the builder stamps identifier 0x1234.
        src_port: 0x1234,
        dst_port: 0,
            discriminator: Default::default(),
            routing_domain: 0,
    };
    let origin = sessions
        .lookup_with_origin(&key, 123_000_000_000, 0)
        .map(|(_, origin)| origin);
    assert_ne!(
        origin,
        Some(SessionOrigin::ReverseFlow),
        "RED on revert: the fast path installed a NAT-less ReverseFlow seed \
         for a session-less fabric-ingress ICMP echo reply"
    );
}

// ---------------------------------------------------------------------------
// #5798: the ZONE-OVERRIDE dimension of `FragAuthority`, bound at its
// PRODUCTION WIRING rather than at the struct.
//
// `FragAuthority.ingress_zone` had two kinds of coverage and neither reached
// the wiring:
//
//   - `frag_assoc_every_authority_dimension_is_load_bearing` (nat64_tests.rs)
//     builds `FragAuthority` STRUCT LITERALS and hands them to the key
//     builders. It proves the key's equality is zone-sensitive. It never calls
//     `frag_ingress_authority`, so it cannot see whether production ever
//     POPULATES the field.
//   - `nat64_frag_authority_dimensions_are_threaded_end_to_end_5798`
//     (tests_nat64_tunnel.rs) drives the production resolver, but passes
//     `None` for the override — its fixture has no fabric/tunnel ingress, so
//     the zone can only move by moving the interface.
//
// Measured consequence at the time this was written: replacing BOTH override
// arguments in `poll_descriptor/mod.rs` — `frag_authority_zone_override` at
// the install site and `ingress_zone_override` at the consult site — with
// `None` compiled cleanly and the whole cargo suite stayed green. The wiring
// could be severed silently.
//
// To be precise about what that is and is not: production at the time was
// CORRECT — both sites passed the right variable. What was missing was any
// test that would notice if a later edit stopped. These tests are that notice.
//
// Why the zone specifically matters: at a fabric ingress the peer-encoded
// stamp is the ONLY thing distinguishing two fragments that arrive on the same
// physical ifindex, the same VLAN and the same routing table but belong to
// different security zones. If the stamp stops reaching the authority they
// collapse onto ONE key, and a non-first fragment inherits a NAT
// translate/forward decision cached for a different zone's flow.

/// A second zone (`dmz`) and a third (`mgmt`), each given an RG-2 member
/// interface. Both the RG BINDING and the zone entry are load-bearing:
/// `zone_encoded_fabric_stamp_valid` (V1b) honors a stamp only for a zone that
/// has at least one RG-bound member which is NOT forwarding-active locally, so
/// a zone with no RG-bound interface could never be legitimately stamped and
/// the "different domain" leg would degrade into "no stamp at all" — a
/// different, weaker scenario than the one under test.
///
/// RG 2 is deliberate: the tests below place ONLY RG 1 locally
/// (`ha_state = {1: active}`), so RG 2 is the peer's and every RG-2 zone's
/// stamp validates.
fn frag_stamp_snapshot() -> ConfigSnapshot {
    let mut snapshot = nat_snapshot_with_fabric();
    for (zone, id, ifname, linux, ifindex) in [
        ("dmz", TEST_DMZ_ZONE_ID, "reth1.1", "ge-0-0-1.1", 25i32),
        ("mgmt", TEST_MGMT_ZONE_ID, "reth1.2", "ge-0-0-1.2", 26i32),
    ] {
        snapshot.zones.push(ZoneSnapshot {
            name: zone.to_string(),
            id,
            host_inbound_configured: true,
            host_inbound_system_services: vec!["any-service".to_string()],
            ..Default::default()
        });
        snapshot.interfaces.push(InterfaceSnapshot {
            name: ifname.to_string(),
            zone: zone.to_string(),
            linux_name: linux.to_string(),
            ifindex,
            redundancy_group: 2,
            hardware_addr: "02:bf:72:01:00:02".to_string(),
            ..Default::default()
        });
    }
    snapshot
}

/// One IPv4/UDP fragment of ONE datagram, ingressing the FABRIC link with the
/// zone-encoded src-MAC stamp for `zone_id`.
///
/// `frag_word` is the raw IPv4 flags+offset field: `0x2000` = MF set, offset 0
/// (the FIRST fragment, the one that installs); `0x2001` = MF set, offset 1
/// unit (a middle fragment); `0x0002` = offset 2 units with MF clear (the last
/// fragment). Every fragment of a datagram shares IPv4 Identification `id`.
///
/// src 10.0.61.102 -> dst 8.8.8.8: the fixture interface-SNATs `lan -> wan`, so
/// a first fragment admitted under a `lan` stamp installs a same-family NAT
/// association, and 8.8.8.8 resolves via the default route to the REACHABLE
/// gateway neighbor 172.16.80.1. A connected-subnet destination would strand
/// in MissingNeighbor, install nothing, and make every assertion below vacuous.
///
/// The dst MAC is the fabric link's own `02:bf:72:ff:00:01` because the #6458
/// V1a check requires the redirect to be unicast to it — byte-identical to what
/// a legitimate cluster peer emits.
fn stamped_fabric_frag_frame(zone_id: u16, frag_word: u16, id: u16) -> Vec<u8> {
    let [hi, lo] = zone_id.to_be_bytes();
    let mut f = vec![
        0x02, 0xbf, 0x72, 0xff, 0x00, 0x01, // dst: our fabric link MAC (V1a)
        0x02, 0xbf, 0x72, FABRIC_ZONE_MAC_MAGIC, hi, lo, // src: the zone stamp
        0x08, 0x00, // ethertype IPv4
    ];
    // On a first fragment these 8 bytes are a real UDP header (sport 33333,
    // dport 443); on a non-first fragment they are payload and must never be
    // read as ports (#2344).
    let udp = [0x82, 0x35, 0x01, 0xbb, 0x00, 0x08, 0x00, 0x00];
    let mut ip = vec![0u8; 20];
    ip[0] = 0x45;
    ip[2..4].copy_from_slice(&((20 + udp.len()) as u16).to_be_bytes());
    ip[4..6].copy_from_slice(&id.to_be_bytes());
    ip[6..8].copy_from_slice(&frag_word.to_be_bytes());
    ip[8] = 64; // ttl
    ip[9] = PROTO_UDP;
    ip[12..16].copy_from_slice(&[10, 0, 61, 102]); // src (lan-side host)
    ip[16..20].copy_from_slice(&[8, 8, 8, 8]); // dst (via default route)
    f.extend_from_slice(&ip);
    f.extend_from_slice(&udp);
    f
}

/// Ingress metadata shared by EVERY fragment below. This is the load-bearing
/// half of the fixture: `ingress_ifindex`, `ingress_vlan_id` and
/// `routing_table` are IDENTICAL for the home-domain and foreign-domain
/// fragments, so the zone stamp carried in the frame's src MAC is the ONLY
/// thing that can distinguish their authorities. If a future edit varies any
/// of these, the test silently stops being a zone test — the
/// `differing == 1` assertion in the guard below exists to catch exactly that.
fn stamped_fabric_frag_meta() -> UserspaceDpMeta {
    UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        ingress_ifindex: 21, // ge-0-0-0, the fabric parent
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_UDP,
        pkt_len: 28,
        l3_offset: 14,
        l4_offset: 34,
        flow_src_port: 33333,
        flow_dst_port: 443,
        flow_src_addr: [10, 0, 61, 102, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        flow_dst_addr: [8, 8, 8, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        config_generation: 7,
        fib_generation: 9,
        ..UserspaceDpMeta::default()
    }
}

/// #5798 FAIL-ON-REVERT for the zone-override WIRING: a non-first fragment
/// whose ingress differs from the first fragment's ONLY in the fabric zone
/// stamp must NOT inherit its cached permit + SNAT + egress.
///
/// Everything here goes through `poll_binding_process_descriptor` via
/// `txn_run_descriptor`. Nothing calls `frag_ingress_authority` to DRIVE
/// behavior — the one direct call is a read-only guard asserting the fixture
/// varies exactly one dimension. That is the whole point: the pre-existing
/// coverage failed precisely because it built the authority by hand.
///
/// TWO foreign zones, not one. A single foreign zone is satisfied by any
/// accidental special-case on one zone id (or by an authority that happens to
/// differ for an unrelated reason); requiring `dmz` AND `mgmt` to both be
/// refused, with the home domain still admitted between them, makes "the zone
/// participates in the key" the only cheap way to pass. The fixture SIZE is
/// load-bearing — do not simplify it back to one.
///
/// This drives the ORDINARY same-family (interface-SNAT) association, not the
/// cross-family NAT64 one, and that is sufficient for the ARGUMENT under test:
/// each site computes `frag_authority` ONCE and hands the same value to both
/// helpers — `nat64_install_forward_fragment_assoc` and
/// `nat_install_forward_fragment_assoc` at the install site,
/// `nat64_consult_forward_fragment_assoc` and its `.or_else`
/// `nat_consult_forward_fragment_assoc` at the consult site. Severing the
/// argument therefore severs both arms together, so binding either arm binds
/// the argument. What a same-family fixture additionally buys is a REACHABLE
/// gateway and a real SNAT rewrite to observe (`nat_applied_snat`), where the
/// v6 NAT64 fixtures deliberately strip the inet6 routes.
///
/// RED on revert:
///   - both override arguments -> `None`: the foreign fragment's authority
///     collapses onto the first fragment's, it HITS, and the
///     `refused_forward == 0` assertion goes RED.
///   - EITHER site alone -> `None`: install and consult stop agreeing, so the
///     HOME-domain positive control misses and its `forward == 1` /
///     `nat_applied_snat == 1` assertions go RED. That asymmetry is why the
///     positive control is not optional.
#[test]
fn frag_assoc_authority_binds_the_fabric_zone_stamp_5798() {
    let forwarding = build_forwarding_state(&frag_stamp_snapshot());
    let now_secs = monotonic_nanos() / 1_000_000_000;
    // Split-RG active/active: WAN RG 1 is ours, RG 2 (lan / dmz / mgmt) is the
    // peer's. This is the ONLY placement in which a stamp both VALIDATES at
    // stage 9 (V1b: the claimed zone's RG is not locally active) and SURVIVES
    // the session-miss V2 owner gate (the resolved egress RG 1 is ours).
    let ha_state = BTreeMap::from([(1, active_rg(now_secs))]);
    let ident: u16 = 0x5798;
    let meta = stamped_fabric_frag_meta();

    // ---- PRECONDITION: every stamp is actually HONORED in production. -------
    // Without this the test is vacuous in the most dangerous way: if the `dmz`
    // and `mgmt` stamps were silently REJECTED (V1a/V1b), their fragments would
    // still be refused below — but for the wrong reason ("no stamp"), not the
    // reason under test ("a DIFFERENT honored stamp"). Assert the decode
    // through the production helper the poll loop itself calls at stage 9.
    for (zone, id) in [
        ("lan", TEST_LAN_ZONE_ID),
        ("dmz", TEST_DMZ_ZONE_ID),
        ("mgmt", TEST_MGMT_ZONE_ID),
    ] {
        let frame = stamped_fabric_frag_frame(id, 0x2000, ident);
        assert_eq!(
            parse_zone_encoded_fabric_ingress_from_frame(
                &frame,
                meta,
                &forwarding,
                &ha_state,
                now_secs,
            ),
            Some(id),
            "precondition: the {zone} stamp must be HONORED at stage 9, else the refusals \
             below prove only that an INVALID stamp is ignored"
        );
    }

    // ---- GUARD: the fixture varies EXACTLY the zone dimension. -------------
    // Resolved through the production authority builder, not read off the meta
    // literals, so a future fixture edit that also moved the ifindex/VLAN/table
    // fails here instead of quietly turning this into the sibling ifindex test.
    let home_authority = crate::afxdp::poll_descriptor::frag_assoc::frag_ingress_authority(
        &forwarding,
        meta,
        Some(TEST_LAN_ZONE_ID),
    );
    for (zone, id) in [("dmz", TEST_DMZ_ZONE_ID), ("mgmt", TEST_MGMT_ZONE_ID)] {
        let foreign = crate::afxdp::poll_descriptor::frag_assoc::frag_ingress_authority(
            &forwarding,
            meta,
            Some(id),
        );
        let differing = [
            home_authority.ingress_ifindex != foreign.ingress_ifindex,
            home_authority.ingress_vlan_id != foreign.ingress_vlan_id,
            home_authority.ingress_zone != foreign.ingress_zone,
            home_authority.routing_table != foreign.routing_table,
        ]
        .into_iter()
        .filter(|d| *d)
        .count();
        assert_eq!(
            differing, 1,
            "{zone}: the two ingresses must differ in EXACTLY one dimension for this to be a \
             zone guard (home {home_authority:?}, foreign {foreign:?})"
        );
        assert_ne!(
            home_authority.ingress_zone, foreign.ingress_zone,
            "{zone}: and that one dimension must be the ZONE — RED when the override stops \
             reaching frag_ingress_authority, because both authorities then fall back to the \
             fabric interface's own zone and compare EQUAL"
        );
    }

    let mut binding = fabric_binding();
    let mut sessions = SessionTable::new();

    // ---- (1) The FIRST fragment installs, under the `lan` stamp. -----------
    let first = stamped_fabric_frag_frame(TEST_LAN_ZONE_ID, 0x2000, ident);
    let (_b1, dbg1) = txn_run_descriptor_checked(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &first,
        meta,
        true,
    );
    assert_eq!(
        dbg1.nat_applied_snat, 1,
        "the stamped first fragment must be admitted under lan -> wan and interface-SNAT'd"
    );
    assert_eq!(
        forwarding.nat64.frag_assoc.len(),
        1,
        "the first fragment must publish exactly one association"
    );

    // ---- (2) Foreign domains are refused; the home domain still inherits. --
    // Interleaved deliberately: each foreign refusal is followed by a home-
    // domain hit, so a refusal can never be explained by "the entry was gone by
    // then", and the final foreign refusal happens AFTER a legitimate hit has
    // already re-stamped the entry's deadline and touched its LRU position.
    let mut offset_units = 1u16;
    for (zone, id) in [("dmz", TEST_DMZ_ZONE_ID), ("mgmt", TEST_MGMT_ZONE_ID)] {
        let foreign = stamped_fabric_frag_frame(id, 0x2000 | offset_units, ident);
        let (_bf, dbg_foreign) = txn_run_descriptor_checked(
            &mut binding,
            &mut sessions,
            &forwarding,
            &ha_state,
            &foreign,
            meta,
            true,
        );
        assert_eq!(
            dbg_foreign.forward, 0,
            "#5798: a non-first fragment stamped {zone} — same ifindex, same VLAN, same routing \
             table, DIFFERENT security domain — must not inherit the lan flow's permit + egress"
        );
        assert_eq!(
            dbg_foreign.nat_applied_snat, 0,
            "#5798: nor may it inherit the lan flow's SNAT translation"
        );
        offset_units += 1;

        // POSITIVE CONTROL, after each refusal: the HOME domain still inherits.
        // This is what fails when only ONE of the two override sites is severed
        // — install and consult then disagree and the legitimate fragment
        // misses. Without it, a build in which NOTHING ever hits would satisfy
        // every refusal assertion above.
        let home = stamped_fabric_frag_frame(TEST_LAN_ZONE_ID, 0x2000 | offset_units, ident);
        let (_bh, dbg_home) = txn_run_descriptor_checked(
            &mut binding,
            &mut sessions,
            &forwarding,
            &ha_state,
            &home,
            meta,
            true,
        );
        assert_eq!(
            dbg_home.forward, 1,
            "control after {zone}: the SAME-domain non-first fragment must still inherit and \
             forward — a fix that refuses everything is not a fix"
        );
        assert_eq!(
            dbg_home.nat_applied_snat, 1,
            "control after {zone}: and must still inherit the SNAT translation"
        );
        offset_units += 1;
    }

    // ---- NEGATIVE SPACE: what must NOT have changed. -----------------------
    // The association table still holds exactly the ONE entry the first
    // fragment published. A foreign fragment must neither evict the home
    // entry nor publish an entry of its own (it is a non-first fragment; only a
    // first fragment may install). This is the assertion that catches "the run
    // exercised a different input set than intended" — a failure which
    // otherwise looks identical to success.
    assert_eq!(
        forwarding.nat64.frag_assoc.len(),
        1,
        "the refused foreign fragments must neither evict the home association nor install \
         one of their own"
    );
}

/// #7050: an ingress_zone_override that names a zone the snapshot does not
/// carry must NOT reach `FragAuthority.ingress_zone` raw.
///
/// The defect was a disagreement between the association key and enforcement.
/// Both sibling consumers of this value validate the override against
/// `zone_id_to_name` — `prerouting_ingress_scope` resolves id->name and falls
/// through on a miss, `filter_log_ingress_zone_id` applies a `contains_key`
/// filter — so for an unknown id enforcement normalizes it away and uses the
/// logical unit's configured zone. `frag_ingress_authority` took it verbatim, so
/// two fragments of ONE datagram carrying two DIFFERENT unknown ids built two
/// DIFFERENT keys. That over-scopes: the second fragment misses the association
/// and is dropped fail-closed, for a datagram enforcement treats as one domain.
///
/// Not reachable in production today — the sole binding of the override comes
/// from `parse_zone_encoded_fabric_ingress_from_frame`, which already rejects an
/// unknown id, and every later shadow can only narrow `Some -> None`. This test
/// therefore guards the CONSUMER's own contract, so the three consumers agree by
/// construction rather than by a property of one producer that a fourth producer
/// would not have to share.
///
/// Both directions are asserted. Checking only that two unknown ids now agree
/// would pass against an implementation that ignored the override entirely, and
/// checking only that a known override still wins would pass against the
/// unvalidated code this replaces.
#[test]
fn unknown_zone_override_does_not_reach_the_frag_authority_7050() {
    let forwarding = build_forwarding_state(&frag_stamp_snapshot());
    let meta = stamped_fabric_frag_meta();

    const UNKNOWN_A: u16 = 65000;
    const UNKNOWN_B: u16 = 65001;

    // PREMISE. If either id were configured this test would be comparing two
    // honored overrides and would pass for the wrong reason.
    assert!(
        !forwarding.zone_id_to_name.contains_key(&UNKNOWN_A)
            && !forwarding.zone_id_to_name.contains_key(&UNKNOWN_B),
        "premise broken: the fixture now configures one of the ids this test needs to be \
         UNKNOWN, so it can no longer distinguish a validated override from a raw one"
    );
    // PREMISE. A known id must be present, or the positive control below is
    // vacuous and this test degenerates into "nothing is ever honored".
    assert!(
        forwarding.zone_id_to_name.contains_key(&TEST_LAN_ZONE_ID),
        "premise broken: TEST_LAN_ZONE_ID is not configured in this fixture, so the \
         positive control cannot show that a VALID override still wins"
    );

    let authority = |o: Option<u16>| {
        crate::afxdp::poll_descriptor::frag_assoc::frag_ingress_authority(&forwarding, meta, o)
    };

    let none = authority(None);
    let a = authority(Some(UNKNOWN_A));
    let b = authority(Some(UNKNOWN_B));

    // THE DEFECT: two fragments of one datagram, two unknown ids, one authority.
    assert_eq!(
        a, b,
        "two DIFFERENT unknown zone overrides still build DIFFERENT frag authorities, so the \
         second fragment of a datagram misses the association the first installed and is \
         dropped fail-closed — while enforcement, which normalizes both ids away, treats the \
         two as the same domain (a={a:?} b={b:?})"
    );
    // And the value they collapse ONTO is the fallback, not some third answer:
    // an unknown override must be indistinguishable from no override at all.
    assert_eq!(
        a, none,
        "an unknown override produced an authority differing from the no-override one, so it \
         is still contributing to the key. It must fall through to the LOGICAL unit's \
         configured zone, which is what enforcement does with it (a={a:?} none={none:?})"
    );

    // POSITIVE CONTROL, and the reason this is not simply `override.take()`: a
    // CONFIGURED override must still win. Without this row the assertions above
    // are satisfied by ignoring the parameter, which would silently undo the
    // fabric zone stamp that
    // `fabric_frag_association_is_scoped_by_the_stamped_zone` exists to protect.
    let known = authority(Some(TEST_LAN_ZONE_ID));
    assert_eq!(
        known.ingress_zone, TEST_LAN_ZONE_ID,
        "a VALID zone override no longer reaches the frag authority: the validation went too \
         far and now drops every override, collapsing the fabric zone stamp"
    );
    assert_ne!(
        known.ingress_zone, none.ingress_zone,
        "the fixture's configured ingress zone equals TEST_LAN_ZONE_ID, so the positive \
         control cannot tell an honored override from the fallback. Pick an override zone the \
         fabric interface does not already resolve to"
    );
}

// ---------------------------------------------------------------------------
// #7770: the RETURN direction of a fabric redirect, which #6478's fail-on-
// revert pair never reaches.
//
// Both #6478 cells above drive `lan -> wan` — `src = 10.0.61.102`,
// `dst = 8.8.8.8`, stamp `TEST_LAN_ZONE_ID`, `ha_state = {1: active}`. That
// zone pair carries the fixture's ONLY permit (`nat_snapshot`'s `allow-all`,
// `lan -> wan`, any/any/any), so both packets are ADMITTED and the cells can
// assert `sessions.len() == 2`. They pin that the removed cluster-peer return
// fast path does not seed a `ReverseFlow` — a real property, and not this one.
//
// The direction #7770 is about is the mirror image: a peer-owned session's
// reply, redirected across the fabric to the LAN-owning node, arriving as
// `wan -> lan` with a #6458 stamp claiming `wan`. That pair has no permit BY
// DESIGN — return traffic is admitted by a SESSION, never by policy — so the
// packet is dropped on transit default-deny. Under a sustained RG split the
// session has not synced yet when the reply arrives ~1-3 ms later, so this is
// the first packet of every new flow, indefinitely.
//
// That disposition is currently only asserted in prose, in
// `docs/fabric-cross-chassis-fwd.md`, where it is described as a drop
// "confined to the race window". These cells make it executable, so that
// whichever of the standing options eventually changes it has a red to work
// against instead of a paragraph.
//
// WHAT THIS CELL UNIQUELY COVERS, measured rather than asserted. Mutating the
// tree to implement option A — force PERMIT whenever a validated fabric-zone
// stamp is present, i.e. "skip policy for fabric-ingress packets" — reds
// EXACTLY ONE test in the whole 5187-cell suite: this one. Option A is the
// tempting fix for #7770 and the issue rules it dead precisely because it
// would upgrade #6458's accepted, bounded stamp-forgery residual into a full
// zone-policy bypass, in the window where the stamp is known to be forgeable.
// Until this cell there was nothing in the tree that would have caught it.
//
// WHY THE ASSERTIONS PIN THE EVENT'S ZONES AND NOT JUST THE COUNTERS.
// Measured: an UNSTAMPED `wan -> lan` frame produces counters IDENTICAL to a
// stamped one — `sessions=0 forwards=0 policy_deny=2` for both — because both
// land on the same default-deny verdict. Only the emitted event separates
// them: stamped gives `ingress_zone_id = wan`, unstamped gives 0 (the fabric
// parent's own unzoned id). So a cell asserting only "no session, no forward"
// could not tell which zone pair was evaluated.
//
// To be precise about what that does and does not add: dropping the stamp
// override on the miss path reds three PRE-EXISTING cells as well as this one
// (`fabric_ingress_syn_ack_seeds_no_reverse_session_6478`,
// `legitimate_fabric_punted_flow_still_admitted_6458`,
// `frag_assoc_authority_binds_the_fabric_zone_stamp_5798`), so #6458's
// validation is not this cell's to guard and this cell is not what keeps it
// honest. What the zone assertions add is that the RETURN direction
// specifically is adjudicated under the stamped pair — the direction none of
// those three exercises.

/// The `nat_snapshot_with_fabric` fixture plus a reachable neighbour for the
/// LAN host on `ge-0-0-1`.
///
/// NOT boilerplate. Without it the bare fixture drops the `wan -> lan` frame
/// TWICE — once on policy and once on MissingNeighbor (measured:
/// `policy_deny=1 missing_neigh=1`) — so a cell asserting "the packet did not
/// get through" would be partly measuring an absent connected-subnet
/// neighbour rather than the policy verdict under test. The
/// `stamped_fabric_frame` comment warns about exactly this confound.
fn fabric_snapshot_with_lan_neighbor_7770() -> ConfigSnapshot {
    let mut snapshot = nat_snapshot_with_fabric();
    // `..Default::default()` rather than an exhaustive literal: the #7689
    // additive-wire ratchet counts exhaustive `NeighborSnapshot` literals
    // across the whole crate and this one pushed it over its ceiling. Only the
    // fields this fixture depends on are named.
    snapshot.neighbors.push(NeighborSnapshot {
        interface: "reth1.0".to_string(),
        ifindex: 24,
        family: "inet".to_string(),
        ip: "10.0.61.102".to_string(),
        mac: "de:ad:be:ef:00:01".to_string(),
        state: "reachable".to_string(),
        ..Default::default()
    });
    snapshot
}

/// Stamp `frame` as a fabric punt claiming `zone_id`, the #6458 shape.
fn stamp_fabric_zone_7770(frame: &mut [u8], zone_id: u16) {
    let [hi, lo] = zone_id.to_be_bytes();
    frame[0..6].copy_from_slice(&[0x02, 0xbf, 0x72, 0xff, 0x00, 0x01]);
    frame[6..12].copy_from_slice(&[0x02, 0xbf, 0x72, FABRIC_ZONE_MAC_MAGIC, hi, lo]);
}

/// #7770 fail-on-revert: a session-less fabric-ingress RETURN packet
/// (`wan -> lan`) is dropped on transit default-deny on the LAN-owning node.
///
/// Two legs per form, and the second is what keeps the first honest:
///
///   * RETURN (`wan -> lan`, stamp `wan`, LAN RG local / WAN RG remote —
///     the split placement in which the #6458 stamp validates): DENIED.
///   * CONTROL (`lan -> wan`, stamp `lan`, the existing #6478 cells'
///     placement): ADMITTED, two sessions and a forward.
///
/// Without the control leg a fixture that had stopped forwarding anything at
/// all — a broken snapshot, an unroutable destination — would satisfy every
/// assertion in the first leg while exercising nothing.
#[test]
fn fabric_ingress_return_traffic_is_denied_on_the_lan_node_7770() {
    let forwarding = build_forwarding_state(&fabric_snapshot_with_lan_neighbor_7770());
    let now_secs = monotonic_nanos() / 1_000_000_000;
    let lan_host = Ipv4Addr::new(10, 0, 61, 102);
    let wan_peer = Ipv4Addr::new(8, 8, 8, 8);

    // --- RETURN: the #7770 shape. LAN RG (2) local, WAN RG (1) remote. -----
    for (form, mut frame, protocol, sport, dport) in [
        (
            "icmp echo reply",
            {
                let mut f = build_icmp_echo_frame_v4(wan_peer, lan_host, 64, crate::afxdp::tests_support::TEST_FABRIC_MAC);
                let icmp_start = 34;
                f[icmp_start] = 0; // echo REQUEST -> echo REPLY
                f[icmp_start + 2..icmp_start + 4].copy_from_slice(&[0, 0]);
                let csum = checksum16(&f[icmp_start..]);
                f[icmp_start + 2..icmp_start + 4].copy_from_slice(&csum.to_be_bytes());
                f
            },
            PROTO_ICMP,
            0x1234u16,
            0u16,
        ),
        (
            "tcp syn-ack",
            build_txn_tcp_syn_frame_v4(wan_peer, lan_host, 443, 12345, TCP_FLAG_SYN | TCP_FLAG_ACK, crate::afxdp::tests_support::TEST_FABRIC_MAC),
            PROTO_TCP,
            443,
            12345,
        ),
    ] {
        stamp_fabric_zone_7770(&mut frame, TEST_WAN_ZONE_ID);
        let mut meta = txn_meta_v4(21, 0, frame.len() as u16);
        meta.protocol = protocol;
        if protocol == PROTO_ICMP {
            meta.payload_offset = 42;
        } else {
            meta.tcp_flags = TCP_FLAG_SYN | TCP_FLAG_ACK;
        }

        let mut binding = fabric_binding();
        let mut sessions = SessionTable::new();
        let (_batch, dbg, _handle, event_rx) = txn_run_descriptor_capturing_events(
            &mut binding,
            &mut sessions,
            &forwarding,
            // LAN RG 2 is LOCAL; WAN RG 1 is the peer's. That placement is
            // what makes the `wan` stamp pass #6458 V1b (not all of the
            // claimed zone's RGs are locally forwarding-active) — the exact
            // window the residual is accepted in.
            &BTreeMap::from([(2, active_rg(now_secs))]),
            &frame,
            meta,
        );

        assert_eq!(
            dbg.missing_neigh, 0,
            "{form}: the fixture dropped on MissingNeighbor, so the deny \
             asserted below would be measuring the absent LAN neighbour \
             rather than the policy verdict (#7770)"
        );
        assert_eq!(
            sessions.len(),
            0,
            "{form}: a session-less fabric-ingress RETURN packet installed a \
             session. `wan -> lan` has no permit by design — return traffic is \
             admitted by a SESSION, never by policy — so admitting one here is \
             a zone-policy bypass on the forgeable-stamp window #6458 \
             documents (#7770)"
        );
        assert_eq!(
            binding.scratch.scratch_forwards.len(),
            0,
            "{form}: the denied RETURN packet was queued for forwarding"
        );
        assert!(
            dbg.policy_deny > 0,
            "{form}: the RETURN packet was neither forwarded nor policy-denied \
             — it left by some third path this cell does not describe (#7770)"
        );

        let event = event_rx
            .try_recv()
            .expect("a transit policy deny must emit an event")
            .decode_dataplane_event()
            .expect("policy deny payload");
        assert_eq!(
            event.kind,
            crate::event_stream::codec::DataplaneEventKind::PolicyDeny,
            "{form}: wrong event kind"
        );
        assert_eq!(event.action, 0, "{form}: the disposition must be DENY");
        assert_eq!(
            event.reason, 5,
            "{form}: reason 5 is the TRANSIT policy deny; 6 would mean the \
             packet was adjudicated as host-inbound instead, which is a \
             different arm with a different fix"
        );
        assert_eq!(
            event.policy_id,
            u32::MAX,
            "{form}: the deny must be the no-match DEFAULT, not a named policy \
             — a named policy denying this would mean the fixture, not the \
             design, produced the drop"
        );
        // The load-bearing pair. Counters alone cannot distinguish a validated
        // `wan` stamp from no stamp at all (measured: identical). These can.
        assert_eq!(
            event.ingress_zone_id, TEST_WAN_ZONE_ID,
            "{form}: the RETURN packet was NOT adjudicated under the \
             #6458-validated stamped zone. An unstamped frame reports \
             ingress_zone_id 0 and produces byte-identical counters, so the \
             counters above cannot tell which pair was evaluated and this is \
             the assertion that can (#7770)"
        );
        assert_eq!(
            event.egress_zone_id, TEST_LAN_ZONE_ID,
            "{form}: the egress zone is not the LAN zone, so the pair being \
             evaluated is not `wan -> lan` and this cell is describing some \
             other flow"
        );
        assert_eq!(event.src_ip, IpAddr::V4(wan_peer), "{form}: src");
        assert_eq!(event.dst_ip, IpAddr::V4(lan_host), "{form}: dst");
        assert_eq!(event.src_port, sport, "{form}: sport");
        assert_eq!(event.dst_port, dport, "{form}: dport");
    }

    // --- CONTROL: the permitted direction still works. --------------------
    // Same fixture, same fabric ingress, mirrored placement and stamp. If this
    // leg ever reds, the first leg's denials stopped being evidence about the
    // RETURN direction and became evidence about a broken fixture.
    let mut frame = build_txn_tcp_syn_frame_v4(
        lan_host,
        wan_peer,
        12345,
        443,
        TCP_FLAG_SYN | TCP_FLAG_ACK,
        crate::afxdp::tests_support::TEST_FABRIC_MAC,
    );
    stamp_fabric_zone_7770(&mut frame, TEST_LAN_ZONE_ID);
    let meta = txn_meta_v4(21, TCP_FLAG_SYN | TCP_FLAG_ACK, frame.len() as u16);
    let mut binding = fabric_binding();
    let mut sessions = SessionTable::new();
    txn_run_descriptor_checked(
        &mut binding,
        &mut sessions,
        &forwarding,
        &BTreeMap::from([(1, active_rg(now_secs))]),
        &frame,
        meta,
        true,
    );
    assert_eq!(
        sessions.len(),
        2,
        "CONTROL: the PERMITTED `lan -> wan` fabric punt stopped installing \
         its forward + reverse pair. The RETURN legs above assert an ABSENCE, \
         and an absence proves nothing once the fixture forwards nothing at \
         all (#7770)"
    );
    assert_eq!(
        binding.scratch.scratch_forwards.len(),
        1,
        "CONTROL: the permitted direction stopped forwarding"
    );
}

/// #7770: the LAN-side snapshot with the LAN neighbour, but with the
/// `lan -> wan` permit narrowed so it no longer matches the probe's source.
///
/// The DENY control leg needs this and cannot be written without it. The base
/// fixture's only policy is `allow-all` (`lan -> wan`, `any`/`any`/`any`), so a
/// cell built on it varies the punt/return axis while sampling only the
/// permitted point — mutating the `Permit` check out of
/// `fabric_punt_seed_metadata` would change nothing and come back green. This
/// narrows `source_addresses` to a subnet the probe host is not in, so the flow
/// matches no rule and falls to the `deny` default.
fn fabric_snapshot_policy_denies_the_lan_host_7770() -> ConfigSnapshot {
    let mut snapshot = fabric_snapshot_with_lan_neighbor_7770();
    for policy in &mut snapshot.policies {
        policy.source_addresses = vec!["10.0.99.0/24".to_string()];
    }
    snapshot
}

/// A binding on the LAN member, for the leg that ingresses LOCALLY rather than
/// off the fabric. `fabric_binding` is ifindex 21 (`ge-0-0-0`, the fabric
/// parent); the punt has to arrive somewhere else or it is not a punt.
fn lan_binding_7770() -> BindingWorker {
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
    binding.interface = Arc::<str>::from("ge-0-0-1");
    binding
}

/// Every session in the table, as `(origin, disposition, ingress_zone,
/// egress_zone, is_reverse)`.
fn session_shapes_7770(
    sessions: &SessionTable,
) -> Vec<(SessionOrigin, ForwardingDisposition, u16, u16, bool)> {
    let mut out = Vec::new();
    sessions.iter_with_origin(|_key, decision, metadata, origin| {
        out.push((
            origin,
            decision.resolution.disposition,
            metadata.ingress_zone,
            metadata.egress_zone,
            metadata.is_reverse,
        ));
    });
    out
}

/// Drive the `wan -> lan` fabric-ingress RETURN against `sessions` and report
/// `(policy_denies, forwards_queued)`.
fn drive_fabric_return_7770(
    forwarding: &ForwardingState,
    sessions: &mut SessionTable,
    ha_state: &BTreeMap<i32, HAGroupRuntime>,
    lan_host: Ipv4Addr,
    wan_peer: Ipv4Addr,
) -> (u64, usize) {
    let mut frame = build_txn_tcp_syn_frame_v4(
        wan_peer,
        lan_host,
        443,
        12345,
        TCP_FLAG_SYN | TCP_FLAG_ACK,
        crate::afxdp::tests_support::TEST_FABRIC_MAC,
    );
    stamp_fabric_zone_7770(&mut frame, TEST_WAN_ZONE_ID);
    let mut meta = txn_meta_v4(21, TCP_FLAG_SYN | TCP_FLAG_ACK, frame.len() as u16);
    meta.protocol = PROTO_TCP;
    let mut binding = fabric_binding();
    let (_batch, dbg) = txn_run_descriptor_checked(&mut binding, sessions, forwarding, ha_state, &frame, meta, true);
    (dbg.policy_deny, binding.scratch.scratch_forwards.len())
}

/// #7770 fail-on-revert: a flow this node PUNTS across the fabric is
/// adjudicated on the way past and seeds a local session, so the peer's RETURN
/// is a session HIT instead of the `wan -> lan` default deny that costs the
/// first packet of every new flow during a sustained RG split.
///
/// Four legs. The first two are the fix; the last two are what stop the first
/// two from being evidence about something else.
///
///   1. PUNT — a LAN-ingress new flow whose egress RG the peer owns is
///      fabric-redirected AND leaves a `FabricPuntSeed` session stamped with
///      the flow's REAL zone pair (`lan -> wan`), not the fabric parent's.
///   2. RETURN — the same 5-tuple coming back off the fabric stamped `wan` is
///      now FORWARDED with no policy deny.
///   3. NO-SEED CONTROL — the identical return frame against a table with no
///      seed is still DENIED. This is the discriminator: the ONLY difference
///      between legs 2 and 3 is a record this node minted from a packet that
///      ingressed on its own LAN member, which is what makes the admission
///      unforgeable from the fabric.
///   4. DENIED-PUNT CONTROL — with the `lan -> wan` permit narrowed so it does
///      not match, the punt installs NO seed and the return is denied again.
///      Without this leg the `Permit` check in `fabric_punt_seed_metadata`
///      could be deleted and every other assertion here would stay green.
#[test]
fn fabric_punt_seed_admits_the_peers_return_7770() {
    let forwarding = build_forwarding_state(&fabric_snapshot_with_lan_neighbor_7770());
    let now_secs = monotonic_nanos() / 1_000_000_000;
    let lan_host = Ipv4Addr::new(10, 0, 61, 102);
    let wan_peer = Ipv4Addr::new(8, 8, 8, 8);
    // The #7770 split: LAN RG 2 is LOCAL, WAN RG 1 is the peer's.
    let ha_state = BTreeMap::from([(2, active_rg(now_secs))]);

    // --- 1. PUNT ---------------------------------------------------------
    let mut sessions = SessionTable::new();
    let mut lan_binding = lan_binding_7770();
    let out_frame = build_txn_tcp_syn_frame_v4(lan_host, wan_peer, 12345, 443, TCP_FLAG_SYN, crate::afxdp::tests_support::TEST_LAN_MAC);
    let out_meta = txn_meta_v4(24, TCP_FLAG_SYN, out_frame.len() as u16);
    let (_batch, punt_dbg) = txn_run_descriptor_checked(
        &mut lan_binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &out_frame,
        out_meta,
        true,
    );
    assert_eq!(
        punt_dbg.policy_deny, 0,
        "the punt must not be denied — the seed is an ADDITION to the punt \
         path, not a new drop site (#7770)"
    );
    assert_eq!(
        lan_binding.scratch.scratch_forwards.len(),
        1,
        "the punted packet must still be queued for the fabric; if it is not, \
         the legs below are measuring a flow that never left (#7770)"
    );
    let shapes = session_shapes_7770(&sessions);
    assert_eq!(
        shapes,
        vec![(
            SessionOrigin::FabricPuntSeed,
            ForwardingDisposition::FabricRedirect,
            TEST_LAN_ZONE_ID,
            TEST_WAN_ZONE_ID,
            false,
        )],
        "the punt must leave EXACTLY one session: a FabricPuntSeed carrying the \
         flow's REAL zone pair. The egress zone is the load-bearing half — it \
         comes from the PRE-redirect resolution, and reading it off the \
         FabricRedirect resolution instead would name the fabric parent's zone \
         and adjudicate a pair that does not exist (#7770)"
    );

    // --- 2. RETURN: now a session HIT ------------------------------------
    let (denies, forwards) =
        drive_fabric_return_7770(&forwarding, &mut sessions, &ha_state, lan_host, wan_peer);
    assert_eq!(
        denies, 0,
        "the peer's RETURN was policy-denied even though this node punted the \
         flow and its own policy permitted it. That deny is the first packet of \
         every new flow during a sustained RG split (#7770)"
    );
    assert_eq!(
        forwards, 1,
        "the RETURN was not queued for forwarding to the LAN host"
    );

    // --- 3. NO-SEED CONTROL: the same frame, no punt -> still denied ------
    let mut unseeded = SessionTable::new();
    let (unseeded_denies, unseeded_forwards) =
        drive_fabric_return_7770(&forwarding, &mut unseeded, &ha_state, lan_host, wan_peer);
    assert!(
        unseeded_denies > 0,
        "an UNSOLICITED fabric-ingress `wan -> lan` frame — one with no punt \
         seed behind it — must still be denied. If this admits, the fix is not \
         a session hit but a blanket relaxation of the return direction, which \
         is the option #7770 rules dead because the fabric stamp is forgeable \
         during exactly this split (#7770)"
    );
    assert_eq!(
        unseeded_forwards, 0,
        "an unsolicited fabric-ingress return was queued for forwarding"
    );

    // --- 4. DENIED-PUNT CONTROL: no permit -> no seed -> still denied -----
    let deny_forwarding = build_forwarding_state(&fabric_snapshot_policy_denies_the_lan_host_7770());
    let mut deny_sessions = SessionTable::new();
    let mut deny_binding = lan_binding_7770();
    let deny_out = build_txn_tcp_syn_frame_v4(lan_host, wan_peer, 12345, 443, TCP_FLAG_SYN, crate::afxdp::tests_support::TEST_LAN_MAC);
    let deny_meta = txn_meta_v4(24, TCP_FLAG_SYN, deny_out.len() as u16);
    txn_run_descriptor_checked(
        &mut deny_binding,
        &mut deny_sessions,
        &deny_forwarding,
        &ha_state,
        &deny_out,
        deny_meta,
        true,
    );
    assert_eq!(
        session_shapes_7770(&deny_sessions),
        Vec::new(),
        "a punt whose flow this node's OWN policy does not permit must seed \
         nothing. The seed is minted from a permit, not from the act of \
         punting — that distinction is the whole answer to \"it would be \
         minting sessions for traffic it never authorised\" (#7770)"
    );
    let (deny_denies, deny_forwards) = drive_fabric_return_7770(
        &deny_forwarding,
        &mut deny_sessions,
        &ha_state,
        lan_host,
        wan_peer,
    );
    assert!(
        deny_denies > 0,
        "the return of an UNAUTHORISED punt must still be denied (#7770)"
    );
    assert_eq!(deny_forwards, 0, "an unauthorised return was forwarded");
}

/// #7770: a FABRIC-ingress packet can never mint a punt seed.
///
/// This is the property that keeps the admission unforgeable. An attacker on
/// the shared fabric segment — #6458's accepted residual, live during exactly
/// the RG split this issue is about — can clone a legitimate punt's stamp
/// shape, so if a fabric-ingress frame could create the record that authorises
/// a return, the fix would hand back the bypass it exists to avoid.
///
/// The guard is doubled by construction (`finalize_new_flow_ha_resolution`
/// declines to redirect a fabric-ingress packet back onto the fabric, so the
/// arm's `FabricRedirect` precondition is unreachable from the fabric anyway),
/// and it is asserted anyway: a guard whose only proof is that another guard
/// makes it unreachable is one line of refactoring away from being wrong.
#[test]
fn fabric_ingress_never_mints_a_punt_seed_7770() {
    let forwarding = build_forwarding_state(&fabric_snapshot_with_lan_neighbor_7770());
    let now_secs = monotonic_nanos() / 1_000_000_000;
    let lan_host = Ipv4Addr::new(10, 0, 61, 102);
    let wan_peer = Ipv4Addr::new(8, 8, 8, 8);
    // WAN RG 1 LOCAL. That is the placement in which a `lan -> wan` punt is
    // legitimately admitted here — #6458's V2 owner gate honours the stamp only
    // when the resolution's owner RG is forwarding-active locally, which is
    // precisely why the peer punted the flow to us — and it is the placement
    // the existing cells' CONTROL leg uses. Under the mirrored placement the
    // punt is not admitted at all and the absence below would prove nothing.
    let ha_state = BTreeMap::from([(1, active_rg(now_secs))]);

    // The peer's legitimate `lan -> wan` punt arriving here. It IS admitted and
    // DOES install sessions — so this cell is not passing because nothing
    // happened.
    // SYN-ACK, matching the CONTROL leg of
    // `fabric_ingress_return_traffic_is_denied_on_the_lan_node_7770` — that leg
    // is the measured proof this placement admits and installs, so reproducing
    // it exactly is what makes the non-empty precondition below reliable.
    let mut frame = build_txn_tcp_syn_frame_v4(
        lan_host,
        wan_peer,
        12345,
        443,
        TCP_FLAG_SYN | TCP_FLAG_ACK,
        crate::afxdp::tests_support::TEST_FABRIC_MAC,
    );
    stamp_fabric_zone_7770(&mut frame, TEST_LAN_ZONE_ID);
    let meta = txn_meta_v4(21, TCP_FLAG_SYN | TCP_FLAG_ACK, frame.len() as u16);
    let mut binding = fabric_binding();
    let mut sessions = SessionTable::new();
    txn_run_descriptor_checked(&mut binding, &mut sessions, &forwarding, &ha_state, &frame, meta, true);

    let shapes = session_shapes_7770(&sessions);
    assert!(
        !shapes.is_empty(),
        "the legitimate fabric punt was not admitted at all, so the absence \
         asserted below is about a broken fixture rather than about the gate"
    );
    assert!(
        !shapes
            .iter()
            .any(|(origin, ..)| *origin == SessionOrigin::FabricPuntSeed),
        "a FABRIC-ingress packet minted a punt seed. Nothing arriving on the \
         fabric may create the record that authorises a return, or an attacker \
         on the fabric segment can manufacture their own admission (#7770)"
    );
}

/// #7770: each of `should_seed_fabric_punt`'s three conditions, bound.
///
/// This cell exists because the conditions could not be bound where they were.
/// Measured: with the gate inline in the poll-loop arm, deleting
/// `!fabric_ingress` reds NOTHING in the suite — `finalize_new_flow_ha_resolution`
/// never hands a fabric-ingress packet a `FabricRedirect` disposition, so the
/// condition is unreachable through the loop. The end-to-end cells therefore
/// cannot speak for it, and the property it carries (an attacker on the fabric
/// segment cannot mint the record that authorises their own return) is the one
/// that most needs a red when someone removes it.
///
/// A table over the three axes, each row differing from the qualifying row in
/// exactly one, so no row can pass for another row's reason.
#[test]
fn should_seed_fabric_punt_binds_each_condition_7770() {
    let nat_free = NatDecision::default();
    let translated = NatDecision {
        rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 7))),
        ..NatDecision::default()
    };

    assert!(
        should_seed_fabric_punt(ForwardingDisposition::FabricRedirect, false, nat_free),
        "the qualifying shape — a locally ingressed, untranslated flow leaving \
         across the fabric — must seed, or every row below is vacuous"
    );
    assert!(
        !should_seed_fabric_punt(ForwardingDisposition::FabricRedirect, true, nat_free),
        "a FABRIC-ingress packet must never mint a punt seed. This is the \
         condition the end-to-end cells cannot reach: nothing arriving on the \
         shared fabric segment may create the record that authorises a return, \
         or #6458's accepted stamp-forgery residual becomes a policy bypass \
         (#7770)"
    );
    assert!(
        !should_seed_fabric_punt(ForwardingDisposition::FabricRedirect, false, translated),
        "a flow carrying an INGRESS translation must not seed: the punt sends \
         the rewritten tuple, so the return would not match the key seeded here \
         (#7770)"
    );
    for disposition in [
        ForwardingDisposition::ForwardCandidate,
        ForwardingDisposition::HAInactive,
        ForwardingDisposition::LocalDelivery,
        ForwardingDisposition::NoRoute,
        ForwardingDisposition::MissingNeighbor,
        ForwardingDisposition::PolicyDenied,
    ] {
        assert!(
            !should_seed_fabric_punt(disposition, false, nat_free),
            "{disposition:?} must not seed a punt: only a flow actually leaving \
             across the fabric is unadjudicated on this node, and a seed for \
             anything else is a session for a flow that was already installed \
             (ForwardCandidate) or dropped (#7770)"
        );
    }
}

// ---------------------------------------------------------------------------
// #9384: the FABRIC-INGRESS exemption from the live from-zone resolution.
// ---------------------------------------------------------------------------
//
// #9384 made the #8356 zone-policy re-derivation resolve the FROM-zone live from
// the interface the packet arrived on, symmetric with the to-zone. A
// fabric-punted packet must be EXEMPT and keep the session entry's recorded zone:
// it arrives on the fabric link from the peer node, so its arrival zone is
// structurally not the flow's.
//
// THIS CELL IS THE REASON THE EXEMPTION IS NOT OPTIONAL, and the fixture detail
// that makes it non-vacuous is that the fabric parent is ZONED. On the shipped
// cluster config (`docs/ha-cluster-userspace.conf`) `fab0` sits in the `control`
// zone, and `ifindex_to_zone_id` PROPAGATES a zoned child unit's zone onto its
// parent (#921/#3618) — so a fabric arrival on `ge-0-0-0` resolves live to
// `control`, for which no policy permits `-> wan`. Without the exemption the
// re-derivation would evaluate `control -> wan`, find nothing, fall to
// `default_policy: deny` and REVOKE every established cross-chassis session on
// the first packet after any commit. That is a correctness break, not a
// hardening — it is TCP death on VRRP failback, which the fabric redirect exists
// to prevent.
//
// An UNZONED fabric parent would make this cell pass either way: the live
// resolution would yield the unknown-zone sentinel 0 and the pre-existing
// `from_id == 0` DECLINE arm would return None. So the zone on the parent is
// load-bearing fixture state, not decoration.

/// `nat_snapshot_with_fabric` with the fabric parent placed in a `control` zone
/// that has no policy to `wan` — the shipped cluster's actual posture.
fn fabric_snapshot_with_zoned_parent_9384() -> ConfigSnapshot {
    let mut snapshot = nat_snapshot_with_fabric();
    snapshot.zones.push(ZoneSnapshot {
        name: "control".to_string(),
        id: TEST_SFMIX_ZONE_ID,
        host_inbound_configured: true,
        host_inbound_system_services: vec!["any-service".to_string()],
        ..Default::default()
    });
    for iface in snapshot.interfaces.iter_mut() {
        if iface.ifindex == 21 {
            iface.zone = "control".to_string();
        }
    }
    snapshot
}

/// THE CROSS-CHASSIS REGRESSION CONTROL. An established session imported from
/// the peer (entry `ingress_zone = lan`, `fabric_ingress: true`) receives another
/// fabric-punted packet. The entry's zone must win, so `lan -> wan` is still the
/// pair evaluated and nothing is revoked.
///
/// FAIL-ON-REVERT: drop the fabric exemption — resolve the from-zone live for a
/// fabric arrival too — and this goes RED with `revoked == 1`, because the
/// fabric parent resolves to `control` and nothing permits `control -> wan`.
/// Passing `false` for `packet_fabric_ingress` at the call site reds it the same
/// way, which is what binds the WIRING rather than the function.
#[test]
fn a_fabric_punted_packet_keeps_the_entrys_ingress_zone_9384() {
    let forwarding = build_forwarding_state(&fabric_snapshot_with_zoned_parent_9384());
    // Non-vacuity: the fabric parent must really resolve to a ZONE. With zone 0
    // the pre-existing unknown-zone DECLINE would carry this cell for free.
    assert_eq!(
        forwarding.ifindex_to_zone_id.get(&21).copied(),
        Some(TEST_SFMIX_ZONE_ID),
        "the fabric parent must be ZONED for this cell to distinguish the \
         exemption from the unknown-zone decline (#9384)"
    );
    let now_secs = monotonic_nanos() / 1_000_000_000;
    // Split placement: WAN RG (1) local, LAN RG (2) the peer's — the placement
    // in which a #6458-validated stamp survives.
    let ha_state = BTreeMap::from([(1, active_rg(now_secs))]);

    let mut sessions = SessionTable::new();
    let key = crate::session::SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
        src_port: 12345,
        dst_port: 443,
        discriminator: Default::default(),
        routing_domain: 0,
    };
    let metadata = SessionMetadata {
        ingress_zone: TEST_LAN_ZONE_ID,
        egress_zone: TEST_WAN_ZONE_ID,
        ingress_zone_check: 0,
        egress_zone_check: 0,
        ingress_ifindex: 21,
        ingress_vlan_id: 0,
        owner_rg_id: 1,
        // The session was imported from the peer over the fabric.
        fabric_ingress: true,
        is_reverse: false,
        nat64_reverse: None,
        log_session_init: false,
        log_session_close: false,
        policy_id: 0,
        inactivity_timeout_ns: None,
        policy_counter_idx: 0,
        policy_counter: None,
    };
    assert!(
        sessions.install_with_protocol_with_origin(
            key,
            SessionDecision {
                resolution: ForwardingResolution {
                    disposition: ForwardingDisposition::ForwardCandidate,
                    local_ifindex: 0,
                    egress_ifindex: 12,
                    tx_ifindex: 11,
                    tunnel_endpoint_id: 0,
                    next_hop: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 1))),
                    neighbor_mac: Some([0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee]),
                    src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x80, 0x08]),
                    tx_vlan_id: 80,
                },
                nat: NatDecision::default(),
                install_table_domain: 0,
                install_table_check: 0,
            },
            metadata,
            SessionOrigin::SyncImport,
            122_000_000_000,
            PROTO_TCP,
            0,
        ),
        "the imported session must install, or the assertion below is vacuous"
    );

    let mut frame = build_txn_tcp_syn_frame_v4(
        Ipv4Addr::new(10, 0, 61, 102),
        Ipv4Addr::new(8, 8, 8, 8),
        12345,
        443,
        TCP_FLAG_ACK,
        crate::afxdp::tests_support::TEST_FABRIC_MAC,
    );
    let [hi, lo] = TEST_LAN_ZONE_ID.to_be_bytes();
    frame[0..6].copy_from_slice(&[0x02, 0xbf, 0x72, 0xff, 0x00, 0x01]);
    frame[6..12].copy_from_slice(&[0x02, 0xbf, 0x72, FABRIC_ZONE_MAC_MAGIC, hi, lo]);
    let meta = txn_meta_v4(21, TCP_FLAG_ACK, frame.len() as u16);

    let mut binding = fabric_binding();
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
        dbg.session_hit, 1,
        "the fabric-punted packet must HIT the imported session, or the \
         revoke assertion is vacuous (#9384)"
    );
    assert_eq!(
        dbg.policy_revoked_sessions, 0,
        "a FABRIC-punted packet must keep the session entry's recorded ingress \
         zone. Resolving the from-zone live here evaluates (control -> wan) — the \
         fabric parent's own zone — which nothing permits, so every established \
         cross-chassis session would be revoked on the first packet after any \
         commit. That is TCP death on VRRP failback, which the fabric redirect \
         exists to prevent (#9384)"
    );
    assert_eq!(
        sessions.len(),
        1,
        "the imported cross-chassis session must survive"
    );
}

/// #10670 fail-on-revert: this receiver has an admitted LAN -> WAN session.
/// A same-zone stamped ACK models a peer-adjudicated session hit. The
/// same-tuple ACK stamped `dmz` models a peer-side session-MISS punt in the
/// split-RG sync-lag window.
///
/// This fixture keeps the WAN owner RG locally active so #6458 validates both
/// stamps and the session path honors the LAN stamp. The HA cache-validity
/// gate intentionally sends stamped fabric packets through session lookup;
/// this test pins the authority decision, not a cache hit. The foreign ACK
/// must be dropped under `dmz -> wan` default-deny without revoking the
/// owner's session, and a later LAN ACK must still forward. Reverting the
/// stamped-zone authority judgment makes the foreign ACK forward and reds the
/// drop assertions.
#[test]
fn stamped_fabric_punt_miss_is_judged_after_adjudicated_hit_10670() {
    let forwarding = build_forwarding_state(&frag_stamp_snapshot());
    let now_secs = monotonic_nanos() / 1_000_000_000;
    // WAN RG (1) is local. LAN and DMZ are on RG (2), so both zone stamps
    // validate as peer arrivals.
    let ha_state = BTreeMap::from([(1, active_rg(now_secs))]);
    let mut binding = fabric_binding();
    let mut sessions = SessionTable::new();

    let syn = stamped_fabric_frame(TEST_LAN_ZONE_ID, TCP_FLAG_SYN);
    let (_batch, admitted) = txn_run_descriptor_checked(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &syn,
        txn_meta_v4(21, TCP_FLAG_SYN, syn.len() as u16),
        true,
    );
    assert_eq!(admitted.tx, 1, "the stamped lan -> wan SYN must be admitted");
    assert_eq!(sessions.len(), 2, "admission must install the session pair");

    let owner_ack = stamped_fabric_frame(TEST_LAN_ZONE_ID, TCP_FLAG_ACK);
    let (_batch, owner) = txn_run_descriptor_checked(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &owner_ack,
        txn_meta_v4(21, TCP_FLAG_ACK, owner_ack.len() as u16),
        true,
    );
    assert_eq!(owner.session_hit, 1, "the matching-stamp ACK must hit conntrack");
    assert_eq!(owner.tx, 1, "the adjudicated-hit forward remains served");
    assert_eq!(sessions.len(), 2, "the owner session pair remains installed");

    let punted_miss = stamped_fabric_frame(TEST_DMZ_ZONE_ID, TCP_FLAG_ACK);
    let (_batch, foreign) = txn_run_descriptor_checked(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &punted_miss,
        txn_meta_v4(21, TCP_FLAG_ACK, punted_miss.len() as u16),
        true,
    );
    assert_eq!(
        foreign.session_hit, 1,
        "the dmz-stamped peer-miss punt must reach the session authority path"
    );
    assert_eq!(
        foreign.foreign_authority_drops, 1,
        "the owner must evaluate the punt under dmz's default-deny policy, not \
         trust it as a peer-adjudicated hit"
    );
    assert_eq!(foreign.tx, 0, "the unadjudicated punt must not inherit lan's permit");
    assert_eq!(
        foreign.policy_revoked_sessions, 0,
        "a foreign punt is dropped as a packet and cannot revoke the lan session"
    );
    assert_eq!(
        sessions.len(),
        2,
        "the unadjudicated punt cannot revoke the owner session pair"
    );
    let owner_ack_after_foreign = stamped_fabric_frame(TEST_LAN_ZONE_ID, TCP_FLAG_ACK);
    let (_batch, owner_after_foreign) = txn_run_descriptor_checked(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &owner_ack_after_foreign,
        txn_meta_v4(
            21,
            TCP_FLAG_ACK,
            owner_ack_after_foreign.len() as u16,
        ),
        true,
    );
    assert_eq!(
        owner_after_foreign.session_hit,
        1,
        "the same-zone adjudicated-hit packet still reaches its owner session"
    );
    assert_eq!(
        owner_after_foreign.tx, 1,
        "a denied foreign punt leaves the admitted owner flow usable"
    );
}

/// #10670 fail-on-revert for the reverse cache case: the imported reverse
/// companion retains its forward owner's RG (2), while this node's reverse
/// egress is locally active RG (1). The HA cache gate therefore accepts the
/// same-zone cache hit. A foreign zone stamp on the same tuple must preflight
/// against the reverse entry's ingress zone and fall through to session
/// authority instead of replaying that descriptor.
#[test]
fn foreign_fabric_stamp_cannot_serve_reverse_cache_10670() {
    let mut snapshot = frag_stamp_snapshot();
    for iface in &mut snapshot.interfaces {
        match iface.ifindex {
            12 => iface.redundancy_group = 2, // WAN: peer-owned forward egress
            24 => iface.redundancy_group = 1, // LAN: local reverse egress
            _ => {}
        }
    }
    snapshot.neighbors.push(NeighborSnapshot {
        interface: "ge-0-0-1".to_string(),
        ifindex: 24,
        family: "inet".to_string(),
        ip: "10.0.61.102".to_string(),
        mac: "00:22:33:44:55:66".to_string(),
        state: "reachable".to_string(),
        ..Default::default()
    });
    let forwarding = build_forwarding_state(&snapshot);
    let now_secs = monotonic_nanos() / 1_000_000_000;
    let now_ns = monotonic_nanos();
    let ha_state = BTreeMap::from([(1, active_rg(now_secs))]);

    let key = crate::session::SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        src_ip: IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)),
        src_port: 443,
        dst_port: 12345,
        discriminator: Default::default(),
        routing_domain: 0,
    };
    let metadata = SessionMetadata {
        ingress_zone: TEST_WAN_ZONE_ID,
        egress_zone: TEST_LAN_ZONE_ID,
        ingress_zone_check: 0,
        egress_zone_check: 0,
        ingress_ifindex: 0,
        ingress_vlan_id: 0,
        // Reverse companions carry the original forward egress owner RG.
        owner_rg_id: 2,
        fabric_ingress: true,
        is_reverse: true,
        nat64_reverse: None,
        log_session_init: false,
        log_session_close: false,
        policy_id: 0,
        inactivity_timeout_ns: None,
        policy_counter_idx: 0,
        policy_counter: None,
    };
    let decision = SessionDecision {
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::ForwardCandidate,
            local_ifindex: 0,
            egress_ifindex: 24,
            tx_ifindex: 24,
            tunnel_endpoint_id: 0,
            next_hop: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102))),
            neighbor_mac: Some([0x00, 0x22, 0x33, 0x44, 0x55, 0x66]),
            src_mac: Some([0x02, 0xbf, 0x72, 0x01, 0x00, 0x01]),
            tx_vlan_id: 0,
        },
        nat: NatDecision::default(),
        install_table_domain: 0,
        install_table_check: 0,
    };
    let mut sessions = SessionTable::new();
    assert!(
        sessions.install_with_protocol_with_origin(
            key,
            decision,
            metadata,
            SessionOrigin::SyncImport,
            now_ns,
            PROTO_TCP,
            TCP_FLAG_ACK,
        ),
        "the peer-imported reverse companion must install before cache assertions"
    );
    assert_eq!(sessions.len(), 1);

    let reverse_ack = |zone_id: u16| {
        let mut frame = build_txn_tcp_syn_frame_v4(
            Ipv4Addr::new(8, 8, 8, 8),
            Ipv4Addr::new(10, 0, 61, 102),
            443,
            12345,
            TCP_FLAG_ACK,
            crate::afxdp::tests_support::TEST_FABRIC_MAC,
        );
        let [hi, lo] = zone_id.to_be_bytes();
        frame[0..6].copy_from_slice(&[0x02, 0xbf, 0x72, 0xff, 0x00, 0x01]);
        frame[6..12].copy_from_slice(&[0x02, 0xbf, 0x72, FABRIC_ZONE_MAC_MAGIC, hi, lo]);
        frame
    };
    let reverse_meta = |frame: &[u8]| {
        let mut meta = txn_meta_v4(21, TCP_FLAG_ACK, frame.len() as u16);
        meta.flow_src_addr[..4].copy_from_slice(&[8, 8, 8, 8]);
        meta.flow_dst_addr[..4].copy_from_slice(&[10, 0, 61, 102]);
        meta.flow_src_port = 443;
        meta.flow_dst_port = 12345;
        meta
    };

    let owner_ack = reverse_ack(TEST_WAN_ZONE_ID);
    let owner_meta = reverse_meta(&owner_ack);
    assert_eq!(
        parse_zone_encoded_fabric_ingress_from_frame(
            &owner_ack,
            owner_meta,
            &forwarding,
            &ha_state,
            now_secs,
        ),
        Some(TEST_WAN_ZONE_ID),
        "the matching remote-RG stamp must be validated"
    );
    let mut binding = fabric_binding();
    let (_batch, owner) = txn_run_descriptor_checked(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &owner_ack,
        owner_meta,
        true,
    );
    assert_eq!(owner.session_hit, 1, "the first owner ACK hits the import");
    assert_eq!(owner.tx, 1, "the adjudicated reverse ACK forwards");
    assert_eq!(txn_flow_cache_entries(&binding), 1, "the hit seeds its descriptor");

    let (_batch, cached_owner) = txn_run_descriptor_checked(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &owner_ack,
        reverse_meta(&owner_ack),
        true,
    );
    assert_eq!(
        cached_owner.session_hit, 0,
        "the RG-mismatched reverse companion must prove a real same-zone cache hit"
    );
    assert_eq!(cached_owner.tx, 1, "the adjudicated cached ACK still forwards");
    assert_eq!(binding.flow.flow_cache.hits, 1);

    let punted_miss = reverse_ack(TEST_DMZ_ZONE_ID);
    let punted_meta = reverse_meta(&punted_miss);
    assert_eq!(
        parse_zone_encoded_fabric_ingress_from_frame(
            &punted_miss,
            punted_meta,
            &forwarding,
            &ha_state,
            now_secs,
        ),
        Some(TEST_DMZ_ZONE_ID),
        "the foreign peer-miss stamp must also be validated"
    );
    let (_batch, foreign) = txn_run_descriptor_checked(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &punted_miss,
        punted_meta,
        true,
    );
    assert_eq!(
        foreign.session_hit, 1,
        "the foreign stamp must fall through the cache to reverse-session authority"
    );
    assert_eq!(
        foreign.foreign_authority_drops, 1,
        "the punt must be judged under dmz -> lan default-deny"
    );
    assert_eq!(foreign.tx, 0, "the punt cannot inherit the peer-adjudicated cache permit");
    assert_eq!(foreign.policy_revoked_sessions, 0);
    assert_eq!(sessions.len(), 1, "a foreign punt cannot revoke the imported entry");
    assert_eq!(
        txn_flow_cache_entries(&binding),
        1,
        "the foreign stamp must not evict the matching-zone reverse descriptor"
    );
    assert_eq!(
        binding.flow.flow_cache.hits, 1,
        "the foreign stamp must not be accounted as a served cache hit"
    );

    let (_batch, owner_after_foreign) = txn_run_descriptor_checked(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &owner_ack,
        reverse_meta(&owner_ack),
        true,
    );
    assert_eq!(owner_after_foreign.session_hit, 0);
    assert_eq!(owner_after_foreign.tx, 1);
    assert_eq!(
        binding.flow.flow_cache.hits, 2,
        "the same-zone reverse cache entry remains usable after the punt"
    );
}

/// #10314 helpers: inactive RG runtime (peer-owned egress).
fn inactive_rg_10314(watchdog_timestamp: u64) -> HAGroupRuntime {
    HAGroupRuntime {
        active: false,
        watchdog_timestamp,
        lease: HAForwardingLease::Inactive,
    }
}

fn lan_binding_10314() -> BindingWorker {
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
    binding.interface = Arc::<str>::from("ge-0-0-1");
    binding
}

/// #10314 cell A (RED pre-fix): unstamped frame on the fabric PARENT with an
/// HAInactive egress must NOT be redirected back onto the fabric. Pre-fix the
/// gate keys on `!packet_fabric_ingress` (validated stamp OR overlay only),
/// so parent arrival (flag=false) redirects out the parent unstamped — the
/// TTL-bounded ping-pong. Post-fix the gate keys on parent-or-overlay
/// arrival and the frame stays HAInactive (counted, recycled, no forward).
#[test]
fn unstamped_parent_not_redirected_10314() {
    let forwarding = build_forwarding_state(&nat_snapshot_with_fabric());
    let now_secs = monotonic_nanos() / 1_000_000_000;
    // Egress RG 1 (WAN default route) inactive locally -> HAInactive.
    let ha_state = BTreeMap::from([
        (1, inactive_rg_10314(now_secs)),
        (2, active_rg(now_secs)),
    ]);
    let mut frame = build_txn_tcp_syn_frame_v4(
        Ipv4Addr::new(10, 0, 61, 102),
        Ipv4Addr::new(8, 8, 8, 8),
        12345,
        443,
        TCP_FLAG_SYN,
        crate::afxdp::tests_support::TEST_FABRIC_MAC,
    );
    // Good dst (our fabric MAC) so only the anti-loop guard is exercised;
    // unstamped src (peer MAC, not 02:bf:72:fe...) on the fabric parent.
    frame[0..6].copy_from_slice(&[0x02, 0xbf, 0x72, 0xff, 0x00, 0x01]);
    frame[6..12].copy_from_slice(&[0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee]);
    let meta = txn_meta_v4(21, TCP_FLAG_SYN, frame.len() as u16);
    let mut binding = fabric_binding();
    let mut sessions = SessionTable::new();
    txn_run_descriptor_checked(&mut binding, &mut sessions, &forwarding, &ha_state, &frame, meta, true);
    assert!(
        binding.scratch.scratch_forwards.is_empty(),
        "unstamped parent arrival must not redirect (RED pre-fix: queued {})",
        binding.scratch.scratch_forwards.len()
    );
}

/// #10314 cell B1 (guard, unchanged): overlay arrival with HAInactive never
/// redirects, pre and post (both gates already block overlay).
#[test]
fn overlay_arrival_not_redirected_10314() {
    let forwarding = build_forwarding_state(&nat_snapshot_with_fabric());
    let now_secs = monotonic_nanos() / 1_000_000_000;
    let ha_state = BTreeMap::from([
        (1, inactive_rg_10314(now_secs)),
        (2, active_rg(now_secs)),
    ]);
    let mut frame = build_txn_tcp_syn_frame_v4(
        Ipv4Addr::new(10, 0, 61, 102),
        Ipv4Addr::new(8, 8, 8, 8),
        12346,
        443,
        TCP_FLAG_SYN,
        crate::afxdp::tests_support::TEST_FABRIC_MAC,
    );
    frame[0..6].copy_from_slice(&[0x02, 0xbf, 0x72, 0xff, 0x00, 0x01]);
    frame[6..12].copy_from_slice(&[0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee]);
    let meta = txn_meta_v4(101, TCP_FLAG_SYN, frame.len() as u16);
    let mut binding = fabric_binding();
    let mut sessions = SessionTable::new();
    txn_run_descriptor_checked(&mut binding, &mut sessions, &forwarding, &ha_state, &frame, meta, true);
    assert!(
        binding.scratch.scratch_forwards.is_empty(),
        "overlay arrival must not redirect (guard: expected empty, got {})",
        binding.scratch.scratch_forwards.len()
    );
}

/// #10314 cell B2 (guard, unchanged): validated-stamp arrival with HAInactive
/// never redirects, pre and post (stamp implies fabric arrival).
#[test]
fn stamped_parent_not_redirected_10314() {
    let forwarding = build_forwarding_state(&nat_snapshot_with_fabric());
    let now_secs = monotonic_nanos() / 1_000_000_000;
    // Dual-inactive so the lan stamp validates (V1b: claimed-zone RG not
    // locally active) and the WAN egress resolves HAInactive.
    let ha_state = BTreeMap::from([
        (1, inactive_rg_10314(now_secs)),
        (2, inactive_rg_10314(now_secs)),
    ]);
    let mut frame = build_txn_tcp_syn_frame_v4(
        Ipv4Addr::new(10, 0, 61, 102),
        Ipv4Addr::new(8, 8, 8, 8),
        12347,
        443,
        TCP_FLAG_SYN,
        crate::afxdp::tests_support::TEST_FABRIC_MAC,
    );
    let [hi, lo] = TEST_LAN_ZONE_ID.to_be_bytes();
    frame[0..6].copy_from_slice(&[0x02, 0xbf, 0x72, 0xff, 0x00, 0x01]);
    frame[6..12].copy_from_slice(&[0x02, 0xbf, 0x72, FABRIC_ZONE_MAC_MAGIC, hi, lo]);
    let meta = txn_meta_v4(21, TCP_FLAG_SYN, frame.len() as u16);
    let mut binding = fabric_binding();
    let mut sessions = SessionTable::new();
    txn_run_descriptor_checked(&mut binding, &mut sessions, &forwarding, &ha_state, &frame, meta, true);
    assert!(
        binding.scratch.scratch_forwards.is_empty(),
        "stamped parent arrival must not redirect (guard: expected empty, got {})",
        binding.scratch.scratch_forwards.len()
    );
}

/// #10314 cell B3 (guard, unchanged): legitimate LAN arrival with good dst
/// MAC and HAInactive egress MUST still redirect (the fix must not break
/// the working path by blocking all redirects).
#[test]
fn lan_good_mac_still_redirects_10314() {
    let forwarding = build_forwarding_state(&nat_snapshot_with_fabric());
    let now_secs = monotonic_nanos() / 1_000_000_000;
    let ha_state = BTreeMap::from([
        (1, inactive_rg_10314(now_secs)),
        (2, active_rg(now_secs)),
    ]);
    let mut frame = build_txn_tcp_syn_frame_v4(
        Ipv4Addr::new(10, 0, 61, 102),
        Ipv4Addr::new(8, 8, 8, 8),
        12348,
        443,
        TCP_FLAG_SYN,
        crate::afxdp::tests_support::TEST_LAN_MAC,
    );
    // LAN ingress MAC (reth1.0) + LAN host src; default frame already carries
    // these, set explicitly so the test does not depend on the builder.
    frame[0..6].copy_from_slice(&[0x02, 0xbf, 0x72, 0x01, 0x00, 0x01]);
    frame[6..12].copy_from_slice(&[0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5]);
    let meta = txn_meta_v4(24, TCP_FLAG_SYN, frame.len() as u16);
    let mut binding = lan_binding_10314();
    let mut sessions = SessionTable::new();
    txn_run_descriptor_checked(&mut binding, &mut sessions, &forwarding, &ha_state, &frame, meta, true);
    assert_eq!(
        binding.scratch.scratch_forwards.len(),
        1,
        "LAN good-MAC HAInactive must still redirect (guard against over-blocking)"
    );
}

/// #10314 cell C (RED pre-fix): LAN arrival with wrong-unicast dst MAC must
/// be dropped pre-L3, never relayed. Pre-fix there is no dst-MAC check
/// (NIC filter is the only guard), so the otherhost frame redirects via the
/// HAInactive path. Post-fix the OTHERHOST drop recycles pre-L3.
#[test]
fn lan_wrong_unicast_dst_dropped_pre_l3_10314() {
    let forwarding = build_forwarding_state(&nat_snapshot_with_fabric());
    let now_secs = monotonic_nanos() / 1_000_000_000;
    let ha_state = BTreeMap::from([
        (1, inactive_rg_10314(now_secs)),
        (2, active_rg(now_secs)),
    ]);
    let mut frame = build_txn_tcp_syn_frame_v4(
        Ipv4Addr::new(10, 0, 61, 102),
        Ipv4Addr::new(8, 8, 8, 8),
        12349,
        443,
        TCP_FLAG_SYN,
        crate::afxdp::tests_support::TEST_LAN_MAC,
    );
    // Wrong unicast dst: not ours, not broadcast/multicast/VRRP.
    frame[0..6].copy_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x66]);
    frame[6..12].copy_from_slice(&[0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5]);
    let meta = txn_meta_v4(24, TCP_FLAG_SYN, frame.len() as u16);
    let mut binding = lan_binding_10314();
    let mut sessions = SessionTable::new();
    txn_run_descriptor(&mut binding, &mut sessions, &forwarding, &ha_state, &frame, meta);
    assert!(
        binding.scratch.scratch_forwards.is_empty(),
        "wrong-unicast dst must drop pre-L3 (RED pre-fix: queued {})",
        binding.scratch.scratch_forwards.len()
    );
    assert_eq!(
        sessions.len(),
        0,
        "wrong-unicast dst must not seed a session pre-L3"
    );
}

/// #10314 session-hit arm: an unstamped parent arrival must not become a
/// FabricRedirect after an inactive-owner revalidation. This specifically
/// covers the path that runs before the HAInactive safety net.
#[test]
fn unstamped_parent_session_hit_not_redirected_10314() {
    // Keep the parent in the LAN policy domain so the local-origin session
    // hit reaches HAInactive revalidation rather than a zone-policy revoke.
    let mut snapshot = nat_snapshot_with_fabric();
    for iface in &mut snapshot.interfaces {
        if iface.ifindex == 21 {
            iface.zone = "lan".to_string();
        }
    }
    let forwarding = build_forwarding_state(&snapshot);
    let now_secs = monotonic_nanos() / 1_000_000_000;
    let ha_state = BTreeMap::from([
        (1, inactive_rg_10314(now_secs)),
        (2, active_rg(now_secs)),
    ]);
    let key = crate::session::SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
        src_port: 12350,
        dst_port: 443,
        discriminator: Default::default(),
        routing_domain: 0,
    };
    let metadata = SessionMetadata {
        // Parent 21 is explicitly in LAN above; matching the arrival zone
        // keeps the session-hit authority path on the HA resolution arm.
        ingress_zone: TEST_LAN_ZONE_ID,
        egress_zone: TEST_WAN_ZONE_ID,
        ingress_zone_check: 0,
        egress_zone_check: 0,
        // Model a session whose observed ingress was the fabric parent. The
        // current packet is another frame on that same parent, but unstamped.
        ingress_ifindex: 21,
        ingress_vlan_id: 0,
        owner_rg_id: 1,
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
    let decision = SessionDecision {
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::ForwardCandidate,
            local_ifindex: 0,
            egress_ifindex: 12,
            tx_ifindex: 11,
            tunnel_endpoint_id: 0,
            next_hop: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 1))),
            neighbor_mac: Some([0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee]),
            src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x80, 0x08]),
            tx_vlan_id: 80,
        },
        nat: NatDecision::default(),
        install_table_domain: 0,
        install_table_check: 0,
    };
    let mut sessions = SessionTable::new();
    assert!(
        sessions.install_with_protocol_with_origin(
            key,
            decision,
            metadata,
            SessionOrigin::ForwardFlow,
            122_000_000_000,
            PROTO_TCP,
            0,
        ),
        "session-hit fixture must install"
    );

    let mut frame = build_txn_tcp_syn_frame_v4(
        Ipv4Addr::new(10, 0, 61, 102),
        Ipv4Addr::new(8, 8, 8, 8),
        12350,
        443,
        TCP_FLAG_ACK,
        crate::afxdp::tests_support::TEST_FABRIC_MAC,
    );
    frame[0..6].copy_from_slice(&[0x02, 0xbf, 0x72, 0xff, 0x00, 0x01]);
    frame[6..12].copy_from_slice(&[0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee]);
    let meta = txn_meta_v4(21, TCP_FLAG_ACK, frame.len() as u16);
    let mut binding = fabric_binding();
    let (_batch, dbg) = txn_run_descriptor_checked(&mut binding, &mut sessions, &forwarding, &ha_state, &frame, meta, true);
    assert_eq!(
        dbg.session_hit, 1,
        "parent frame must exercise the session-hit arm"
    );
    assert_eq!(
        dbg.ha_inactive, 1,
        "parent session hit must remain HAInactive rather than become FabricRedirect \
         (ha={}, other={}, forward={}, local={}, no_route={}, missing_neigh={}, \
          policy={}, revoked={}, foreign={})",
        dbg.ha_inactive,
        dbg.disposition_other,
        dbg.forward,
        dbg.local,
        dbg.no_route,
        dbg.missing_neigh,
        dbg.policy_deny,
        dbg.policy_revoked_sessions,
        dbg.foreign_authority_drops
    );
    assert!(
        binding.scratch.scratch_forwards.is_empty(),
        "unstamped parent session hit must not redirect back onto fabric (RED pre-fix: queued {})",
        binding.scratch.scratch_forwards.len()
    );
}
