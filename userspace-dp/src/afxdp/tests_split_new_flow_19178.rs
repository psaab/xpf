//! #19178 (included in #19171's FIB-level fix): a NEW flow on a split node to a
//! destination inside a peer-owned connected prefix.
//!
//! The split node: WAN RG1 active here, LAN RG2 the peer's. #15742 withheld the
//! peer-owned LAN prefix from the transit FIB, so the admission resolved the
//! LAN server by the WAN default route. It judged the policy WAN -> WAN, and
//! where that was permitted it forwarded the flow back out the WAN (a hairpin)
//! to a LAN address.
//!
//! With the row present (#19171), the admission's FIB answer is the LAN
//! interface. HA demotes that peer-owned egress, and the flow becomes a fabric
//! redirect to the owner. A redirected new flow is not policy-judged on this
//! node: the local transit admission (`transit_admission_verdict`) runs only
//! for a ForwardCandidate. The OWNER judges it on arrival, against the zone
//! pair the fabric stamp carries (WAN, the arrival zone) and its own LAN
//! egress: WAN -> LAN, the zone the destination is in.
//!
//! Two policy configurations tell the zone pairs apart:
//! - only `wan -> lan` permits: the base judged WAN -> WAN locally and denied;
//!   the fix redirects, and the owner admits;
//! - only `wan -> wan` permits: the base admitted WAN -> WAN locally and
//!   hairpinned out the WAN; the fix redirects, and the owner denies.

use super::test_fixtures::nat_snapshot_with_fabric;
use super::tests_split_rg_failback_18531::rg;
use super::tests_support::*;
use super::*;
use crate::{NeighborSnapshot, PolicyRuleSnapshot};

const LAN_SERVER4: Ipv4Addr = Ipv4Addr::new(10, 0, 61, 102);
const WAN_CLIENT4: Ipv4Addr = Ipv4Addr::new(172, 16, 80, 200);
const LAN_SERVER6: Ipv6Addr = Ipv6Addr::new(0x2001, 0x559, 0x8585, 0xef00, 0, 0, 0, 0x102);
const WAN_CLIENT6: Ipv6Addr = Ipv6Addr::new(0x2001, 0x559, 0x8585, 0x80, 0, 0, 0, 0x200);
/// `reth0.80`'s MAC in `nat_snapshot`: what an upstream router addresses.
const WAN_UNIT_MAC: [u8; 6] = [0x02, 0xbf, 0x72, 0x00, 0x80, 0x08];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Permit {
    /// Only `wan -> lan` permits (the realistic configuration).
    WanToLan,
    /// Only `wan -> wan` permits (the hairpin probe).
    WanToWan,
}

/// The split node: `reth1.0` (LAN, RG2) is peer-owned, `reth0.80` (WAN, RG1)
/// active. `peer_owned` false gives the honest owner FIB with RG2 active.
fn snapshot(permit: Permit, peer_owned: bool) -> crate::ConfigSnapshot {
    let mut snapshot = nat_snapshot_with_fabric();
    for iface in &mut snapshot.interfaces {
        if iface.name == "reth1.0" {
            iface.connected_rg_peer_owned = peer_owned;
        }
    }
    let (from, to) = match permit {
        Permit::WanToLan => ("wan", "lan"),
        Permit::WanToWan => ("wan", "wan"),
    };
    snapshot.policies = vec![PolicyRuleSnapshot {
        name: format!("permit-{from}-{to}"),
        from_zone: from.to_string(),
        to_zone: to.to_string(),
        source_addresses: vec!["any".to_string()],
        destination_addresses: vec!["any".to_string()],
        applications: vec!["any".to_string()],
        application_terms: Vec::new(),
        action: "permit".to_string(),
        ..Default::default()
    }];
    for (ip, family) in [(LAN_SERVER4.to_string(), "inet"), (LAN_SERVER6.to_string(), "inet6")] {
        snapshot.neighbors.push(NeighborSnapshot {
            interface: "ge-0-0-1".to_string(),
            ifindex: 24,
            family: family.to_string(),
            ip,
            mac: "02:00:19:17:80:01".to_string(),
            state: "reachable".to_string(),
            router: false,
            link_local: false,
            ..Default::default()
        });
    }
    snapshot
}

/// What the admission did with one WAN-arriving SYN to the LAN server.
#[derive(Debug, PartialEq, Eq)]
struct Admission {
    policy_deny: u64,
    /// `(disposition, target_ifindex)` of each queued forward.
    forwards: Vec<(ForwardingDisposition, i32)>,
}

fn admit(v6: bool, permit: Permit, peer_owned: bool) -> Admission {
    let forwarding = build_forwarding_state(&snapshot(permit, peer_owned));
    let now_secs = monotonic_nanos() / 1_000_000_000;
    let ha_state = BTreeMap::from([(1, rg(true, now_secs)), (2, rg(!peer_owned, now_secs))]);
    let (frame, mut meta) = if v6 {
        let frame = build_txn_tcp_frame_v6(WAN_CLIENT6, LAN_SERVER6, 40000, 443, TCP_FLAG_SYN, WAN_UNIT_MAC);
        let mut meta = txn_meta_v6(12, frame.len());
        meta.flow_src_addr = WAN_CLIENT6.octets();
        meta.flow_dst_addr = LAN_SERVER6.octets();
        (frame, meta)
    } else {
        let frame =
            build_txn_tcp_syn_frame_v4(WAN_CLIENT4, LAN_SERVER4, 40000, 443, TCP_FLAG_SYN, WAN_UNIT_MAC);
        let mut meta = txn_meta_v4(12, TCP_FLAG_SYN, frame.len() as u16);
        meta.flow_src_addr[..4].copy_from_slice(&WAN_CLIENT4.octets());
        meta.flow_dst_addr[..4].copy_from_slice(&LAN_SERVER4.octets());
        (frame, meta)
    };
    meta.ingress_vlan_id = 80;
    meta.flow_src_port = 40000;
    meta.flow_dst_port = 443;
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 12, 0);
    binding.interface = Arc::<str>::from("ge-0-0-0.80");
    let mut sessions = SessionTable::new();
    let (_batch, dbg) = txn_run_descriptor(&mut binding, &mut sessions, &forwarding, &ha_state, &frame, meta);
    Admission {
        policy_deny: dbg.policy_deny,
        forwards: binding
            .scratch
            .scratch_forwards
            .iter()
            .map(|forward| (forward.decision.resolution.disposition, forward.target_ifindex))
            .collect(),
    }
}

/// RED on the base. With only `wan -> lan` permitted, the split node does not
/// policy-judge the new flow (it becomes a fabric redirect, which local transit
/// admission never judges) and sends it to the LAN owner over the fabric
/// (`ge-0/0/0`, ifindex 21); the owner judges it WAN -> LAN (the joined cells
/// below). The base judged it WAN -> WAN here and denied it.
#[test]
fn split_new_flow_to_a_peer_owned_server_is_judged_in_its_zone_and_crosses_the_fabric_19178() {
    for v6 in [false, true] {
        let got = admit(v6, Permit::WanToLan, true);
        assert_eq!(
            got,
            Admission {
                policy_deny: 0,
                forwards: vec![(ForwardingDisposition::FabricRedirect, 21)],
            },
            "v6={v6}: not denied here; fabric-redirected to the owner"
        );
    }
}

/// RED on the base: the hairpin. With only `wan -> wan` permitted, the base
/// admitted the new flow as WAN -> WAN and forwarded it back out the WAN to a
/// LAN address. The fix never sends it out the WAN: it crosses the fabric,
/// and the owner judges it (and denies it: see the owner cells below).
#[test]
fn split_new_flow_to_a_peer_owned_server_never_hairpins_out_the_wan_19178() {
    for v6 in [false, true] {
        let got = admit(v6, Permit::WanToWan, true);
        assert_eq!(
            got,
            Admission {
                policy_deny: 0,
                forwards: vec![(ForwardingDisposition::FabricRedirect, 21)],
            },
            "v6={v6}: never out the WAN; handed to the owner over the fabric"
        );
    }
}

/// The owner's half. The LAN owner (RG2 active here, the WAN RG on the peer)
/// receives the redirected SYN over the fabric, stamped with the WAN zone
/// (the split node's arrival zone). It judges WAN -> LAN: admitted and
/// delivered on the LAN when only `wan -> lan` permits, denied when only
/// `wan -> wan` permits.
fn owner_admit(v6: bool, permit: Permit) -> Admission {
    let snapshot = snapshot(permit, false);
    let forwarding = build_forwarding_state(&snapshot);
    let now_secs = monotonic_nanos() / 1_000_000_000;
    let ha_state = BTreeMap::from([(1, rg(false, now_secs)), (2, rg(true, now_secs))]);
    let fabric_mac = [0x02, 0xbf, 0x72, 0xff, 0x00, 0x01];
    let (mut frame, mut meta) = if v6 {
        let frame = build_txn_tcp_frame_v6(WAN_CLIENT6, LAN_SERVER6, 40000, 443, TCP_FLAG_SYN, fabric_mac);
        let mut meta = txn_meta_v6(21, frame.len());
        meta.flow_src_addr = WAN_CLIENT6.octets();
        meta.flow_dst_addr = LAN_SERVER6.octets();
        (frame, meta)
    } else {
        let frame =
            build_txn_tcp_syn_frame_v4(WAN_CLIENT4, LAN_SERVER4, 40000, 443, TCP_FLAG_SYN, fabric_mac);
        let mut meta = txn_meta_v4(21, TCP_FLAG_SYN, frame.len() as u16);
        meta.flow_src_addr[..4].copy_from_slice(&WAN_CLIENT4.octets());
        meta.flow_dst_addr[..4].copy_from_slice(&LAN_SERVER4.octets());
        (frame, meta)
    };
    let [_, _, hi, lo] = forwarding.zone_name_to_id["wan"].to_be_bytes();
    frame[6..12].copy_from_slice(&[0x02, 0xbf, 0x72, FABRIC_ZONE_MAC_MAGIC, hi, lo]);
    meta.flow_src_port = 40000;
    meta.flow_dst_port = 443;
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 21, 0);
    binding.interface = Arc::<str>::from("ge-0-0-0");
    let mut sessions = SessionTable::new();
    let (_batch, dbg) = txn_run_descriptor(&mut binding, &mut sessions, &forwarding, &ha_state, &frame, meta);
    Admission {
        policy_deny: dbg.policy_deny,
        forwards: binding
            .scratch
            .scratch_forwards
            .iter()
            .map(|forward| (forward.decision.resolution.disposition, forward.target_ifindex))
            .collect(),
    }
}

/// Green on both: the owner judges the redirected flow WAN -> LAN and admits
/// it when `wan -> lan` permits, delivering it on its LAN (24).
#[test]
fn owner_admits_a_redirected_new_flow_judged_wan_to_lan_19178() {
    for v6 in [false, true] {
        assert_eq!(
            owner_admit(v6, Permit::WanToLan),
            Admission {
                policy_deny: 0,
                forwards: vec![(ForwardingDisposition::ForwardCandidate, 24)],
            },
            "v6={v6}: the owner admits WAN -> LAN and delivers on its LAN"
        );
    }
}

/// Green on both: with only `wan -> wan` permitted, the owner denies the
/// redirected flow, because it judges WAN -> LAN. So the fix's hairpin
/// configuration ends in a deny at the owner, never in a WAN hairpin.
#[test]
fn owner_denies_a_redirected_new_flow_when_only_wan_to_wan_permits_19178() {
    for v6 in [false, true] {
        let got = owner_admit(v6, Permit::WanToWan);
        assert!(
            got.policy_deny > 0 && got.forwards.is_empty(),
            "v6={v6}: judged WAN -> LAN at the owner, denied, nothing forwarded: {got:?}"
        );
    }
}

/// Control, green on both: on the honest owner FIB (RG2 active here) the same
/// flow is admitted WAN -> LAN and delivered locally on the LAN (`reth1.0`,
/// ifindex 24).
#[test]
fn owner_new_flow_to_its_lan_server_is_delivered_locally_19178() {
    for v6 in [false, true] {
        let got = admit(v6, Permit::WanToLan, false);
        assert_eq!(
            got,
            Admission {
                policy_deny: 0,
                forwards: vec![(ForwardingDisposition::ForwardCandidate, 24)],
            },
            "v6={v6}: delivered locally on the LAN"
        );
    }
}

// ---------------------------------------------------------------------------
// codex-e P3-2: the two halves JOINED by the producer's real frame. The split
// node's redirected SYN is captured as transmitted and fed, unmodified, to the
// owner, so the fabric stamp it carries is what the owner judges by.
// ---------------------------------------------------------------------------

/// The fabric MAC the split node addresses its redirects to
/// (`nat_snapshot_with_fabric`'s peer): the owner's own fabric MAC.
const OWNER_FABRIC_MAC: [u8; 6] = [0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee];

fn three_bindings() -> Vec<BindingWorker> {
    let mut wan = BindingWorker::new_for_mirror_test(0, 0, 12, 0);
    wan.interface = Arc::<str>::from("ge-0-0-0.80");
    let mut fabric = BindingWorker::new_for_mirror_test(1, 0, 21, 0);
    fabric.interface = Arc::<str>::from("ge-0-0-0");
    let mut lan = BindingWorker::new_for_mirror_test(2, 0, 24, 0);
    lan.interface = Arc::<str>::from("ge-0-0-1");
    vec![wan, fabric, lan]
}

fn tx(bindings: &[BindingWorker]) -> [u64; 3] {
    let tx = |b: &BindingWorker| b.live.tx_packets.load(std::sync::atomic::Ordering::Relaxed);
    [tx(&bindings[0]), tx(&bindings[1]), tx(&bindings[2])]
}

/// The split node's redirected SYN, as transmitted on the fabric binding.
fn split_redirected_frame(v6: bool, permit: Permit) -> Vec<u8> {
    let forwarding = build_forwarding_state(&snapshot(permit, true));
    let now_secs = monotonic_nanos() / 1_000_000_000;
    let ha_state = BTreeMap::from([(1, rg(true, now_secs)), (2, rg(false, now_secs))]);
    let (frame, mut meta) = if v6 {
        let frame = build_txn_tcp_frame_v6(WAN_CLIENT6, LAN_SERVER6, 40000, 443, TCP_FLAG_SYN, WAN_UNIT_MAC);
        let mut meta = txn_meta_v6(12, frame.len());
        meta.flow_src_addr = WAN_CLIENT6.octets();
        meta.flow_dst_addr = LAN_SERVER6.octets();
        (frame, meta)
    } else {
        let frame =
            build_txn_tcp_syn_frame_v4(WAN_CLIENT4, LAN_SERVER4, 40000, 443, TCP_FLAG_SYN, WAN_UNIT_MAC);
        let mut meta = txn_meta_v4(12, TCP_FLAG_SYN, frame.len() as u16);
        meta.flow_src_addr[..4].copy_from_slice(&WAN_CLIENT4.octets());
        meta.flow_dst_addr[..4].copy_from_slice(&LAN_SERVER4.octets());
        (frame, meta)
    };
    meta.ingress_vlan_id = 80;
    meta.flow_src_port = 40000;
    meta.flow_dst_port = 443;
    let mut bindings = three_bindings();
    let mut sessions = SessionTable::new();
    let shared = Arc::new(Mutex::new(FastMap::default()));
    let (_batch, _dbg, egress) = txn_run_multi_binding_at_generations(
        &mut bindings, 0, &mut sessions, &forwarding, &ha_state, &frame, meta, &shared, 7, 1,
    );
    assert_eq!(tx(&bindings), [0, 1, 0], "v6={v6}: the split node sends it only over the fabric");
    let egress = egress.expect("the redirected frame is captured");
    let [_, _, hi, lo] = forwarding.zone_name_to_id["wan"].to_be_bytes();
    assert_eq!(
        egress[6..12],
        [0x02, 0xbf, 0x72, FABRIC_ZONE_MAC_MAGIC, hi, lo],
        "v6={v6}: the producer stamps the WAN zone, the arrival zone"
    );
    assert_eq!(egress[0..6], OWNER_FABRIC_MAC, "v6={v6}: addressed to the owner's fabric MAC");
    egress
}

/// The owner receiving that frame verbatim on its fabric binding. Its own
/// fabric MAC is the one the split node addressed. `owner_active` false is
/// the anti-loop view: the receiver does not own the LAN RG either.
fn owner_receives(frame: &[u8], v6: bool, permit: Permit, owner_active: bool) -> (u64, [u64; 3]) {
    let mut snapshot = snapshot(permit, !owner_active);
    for fabric in &mut snapshot.fabrics {
        fabric.local_mac = "00:aa:bb:cc:dd:ee".to_string();
        fabric.peer_mac = "02:bf:72:ff:00:01".to_string();
    }
    for iface in &mut snapshot.interfaces {
        if iface.ifindex == 21 {
            iface.hardware_addr = "00:aa:bb:cc:dd:ee".to_string();
        }
    }
    let forwarding = build_forwarding_state(&snapshot);
    let now_secs = monotonic_nanos() / 1_000_000_000;
    let ha_state = BTreeMap::from([(1, rg(false, now_secs)), (2, rg(owner_active, now_secs))]);
    let mut meta = if v6 {
        let mut meta = txn_meta_v6(21, frame.len());
        meta.flow_src_addr = WAN_CLIENT6.octets();
        meta.flow_dst_addr = LAN_SERVER6.octets();
        meta
    } else {
        let mut meta = txn_meta_v4(21, TCP_FLAG_SYN, frame.len() as u16);
        meta.flow_src_addr[..4].copy_from_slice(&WAN_CLIENT4.octets());
        meta.flow_dst_addr[..4].copy_from_slice(&LAN_SERVER4.octets());
        meta
    };
    meta.tcp_flags = TCP_FLAG_SYN;
    meta.flow_src_port = 40000;
    meta.flow_dst_port = 443;
    let mut bindings = three_bindings();
    let mut sessions = SessionTable::new();
    let shared = Arc::new(Mutex::new(FastMap::default()));
    let (_batch, dbg, _egress) = txn_run_multi_binding_at_generations(
        &mut bindings, 1, &mut sessions, &forwarding, &ha_state, frame, meta, &shared, 7, 1,
    );
    (dbg.policy_deny, tx(&bindings))
}

/// Joined: the owner admits the split node's real redirected SYN as WAN -> LAN
/// (only `wan -> lan` permits) and delivers it on its LAN.
#[test]
fn joined_owner_admits_the_redirected_new_flow_by_its_stamp_19178() {
    for v6 in [false, true] {
        let frame = split_redirected_frame(v6, Permit::WanToLan);
        let (deny, tx) = owner_receives(&frame, v6, Permit::WanToLan, true);
        assert_eq!((deny, tx), (0, [0, 0, 1]), "v6={v6}: admitted WAN -> LAN, delivered on the LAN");
    }
}

/// Joined: with only `wan -> wan` permitted, the owner denies the real
/// redirected SYN, because its stamp makes it WAN -> LAN.
#[test]
fn joined_owner_denies_the_redirected_new_flow_when_only_wan_to_wan_permits_19178() {
    for v6 in [false, true] {
        let frame = split_redirected_frame(v6, Permit::WanToWan);
        let (deny, tx) = owner_receives(&frame, v6, Permit::WanToWan, true);
        assert!(deny > 0 && tx == [0, 0, 0], "v6={v6}: denied, nothing sent: deny={deny} tx={tx:?}");
    }
}

/// Joined anti-loop: a receiver that does not own the LAN RG either (a
/// transient split view on both nodes) refuses the redirected SYN. It never
/// sends it back over the fabric, nor out its LAN.
#[test]
fn joined_inactive_receiver_refuses_the_redirected_new_flow_19178() {
    for v6 in [false, true] {
        let frame = split_redirected_frame(v6, Permit::WanToLan);
        let (_deny, tx) = owner_receives(&frame, v6, Permit::WanToLan, false);
        assert_eq!(tx, [0, 0, 0], "v6={v6}: refused, never bounced");
    }
}
