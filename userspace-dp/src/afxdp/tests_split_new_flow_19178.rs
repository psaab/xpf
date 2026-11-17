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
//! interface. The policy is judged WAN -> LAN, the zone the destination is in.
//! HA then demotes the peer-owned egress, and the flow crosses the fabric to
//! the owner, which judges it again.
//!
//! The admitting/denying pair proves which zone pair was evaluated:
//! - only `wan -> lan` permits: the fix admits, the base denies (WAN -> WAN);
//! - only `wan -> wan` permits: the base hairpins out the WAN, the fix denies.

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

/// RED on the base. With only `wan -> lan` permitted, the split node admits the
/// new flow (it was judged WAN -> LAN) and sends it to the LAN owner over the
/// fabric (`ge-0/0/0`, ifindex 21). The base judged it WAN -> WAN and denied it.
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
            "v6={v6}: admitted as WAN -> LAN and fabric-redirected to the owner"
        );
    }
}

/// RED on the base: the hairpin. With only `wan -> wan` permitted, the base
/// forwarded the new flow back out the WAN to the LAN address. Judged WAN ->
/// LAN, it is denied and nothing leaves.
#[test]
fn split_new_flow_to_a_peer_owned_server_never_hairpins_out_the_wan_19178() {
    for v6 in [false, true] {
        let got = admit(v6, Permit::WanToWan, true);
        assert_eq!(
            got,
            Admission { policy_deny: 1, forwards: vec![] },
            "v6={v6}: judged WAN -> LAN, denied, nothing forwarded"
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
