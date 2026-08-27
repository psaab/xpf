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
/// to it. Build a LAN→WAN TCP SYN frame carrying the zone-encoded stamp
/// for `zone_id` in the source MAC, addressed to the fabric link's MAC —
/// byte-identical to what the legitimate sender emits, except the RG
/// placement decides whether it is legitimate. The destination (8.8.8.8)
/// resolves via the default route to the fixture's REACHABLE gateway
/// neighbor (172.16.80.1), so an admitted flow installs a session AND
/// queues a forward — the two observables the forged-frame pins assert
/// against (a connected-subnet dst would strand in MissingNeighbor and
/// make the deny assertions vacuous).
fn stamped_fabric_frame(zone_id: u16) -> Vec<u8> {
    let mut frame = build_txn_tcp_syn_frame_v4(
        Ipv4Addr::new(10, 0, 61, 102),
        Ipv4Addr::new(8, 8, 8, 8),
        12345,
        443,
        TCP_FLAG_SYN,
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
    let frame = stamped_fabric_frame(TEST_LAN_ZONE_ID);
    let meta = txn_meta_v4(21, TCP_FLAG_SYN, frame.len() as u16);

    let mut binding = fabric_binding();
    let mut sessions = SessionTable::new();
    txn_run_descriptor(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame,
        meta,
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
    );
    let [hi, lo] = TEST_LAN_ZONE_ID.to_be_bytes();
    frame[0..6].copy_from_slice(&[0x02, 0xbf, 0x72, 0xff, 0x00, 0x01]);
    frame[6..12].copy_from_slice(&[0x02, 0xbf, 0x72, FABRIC_ZONE_MAC_MAGIC, hi, lo]);
    let meta = txn_meta_v4(21, TCP_FLAG_SYN, frame.len() as u16);

    let mut binding = fabric_binding();
    let mut sessions = SessionTable::new();
    txn_run_descriptor(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame,
        meta,
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
    );
    let [hi, lo] = TEST_WAN_ZONE_ID.to_be_bytes();
    frame[0..6].copy_from_slice(&[0x02, 0xbf, 0x72, 0xff, 0x00, 0x01]);
    frame[6..12].copy_from_slice(&[0x02, 0xbf, 0x72, FABRIC_ZONE_MAC_MAGIC, hi, lo]);
    let meta = txn_meta_v4(21, TCP_FLAG_SYN, frame.len() as u16);

    let mut binding = fabric_binding();
    let mut sessions = SessionTable::new();
    txn_run_descriptor(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame,
        meta,
    );

    assert!(
        sessions.len() >= 1,
        "the legitimate split-RG host-inbound punt must keep caching its session"
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
    let frame = stamped_fabric_frame(TEST_LAN_ZONE_ID);
    let meta = txn_meta_v4(21, TCP_FLAG_SYN, frame.len() as u16);

    let mut binding = fabric_binding();
    let mut sessions = SessionTable::new();
    txn_run_descriptor(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame,
        meta,
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
    let mut frame = build_txn_tcp_syn_frame_v4(src, dst, 12345, 443, TCP_FLAG_SYN | TCP_FLAG_ACK);
    let [hi, lo] = TEST_LAN_ZONE_ID.to_be_bytes();
    frame[0..6].copy_from_slice(&[0x02, 0xbf, 0x72, 0xff, 0x00, 0x01]);
    frame[6..12].copy_from_slice(&[0x02, 0xbf, 0x72, FABRIC_ZONE_MAC_MAGIC, hi, lo]);
    let meta = txn_meta_v4(21, TCP_FLAG_SYN | TCP_FLAG_ACK, frame.len() as u16);

    let mut binding = fabric_binding();
    let mut sessions = SessionTable::new();
    txn_run_descriptor(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame,
        meta,
    );

    let key = SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        src_ip: IpAddr::V4(src),
        dst_ip: IpAddr::V4(dst),
        src_port: 12345,
        dst_port: 443,
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
    let mut frame = build_icmp_echo_frame_v4(src, dst, 64);
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
    txn_run_descriptor(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame,
        meta,
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
    let (_b1, dbg1) = txn_run_descriptor(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &first,
        meta,
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
        let (_bf, dbg_foreign) = txn_run_descriptor(
            &mut binding,
            &mut sessions,
            &forwarding,
            &ha_state,
            &foreign,
            meta,
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
        let (_bh, dbg_home) = txn_run_descriptor(
            &mut binding,
            &mut sessions,
            &forwarding,
            &ha_state,
            &home,
            meta,
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
