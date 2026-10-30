// #18174: traceroute / mtr through the HA cluster — end-to-end poll cells.
//
// Live evidence (loss cluster, 2026-10-30): every hop past the firewall was
// `???` because each upstream router's Time Exceeded, addressed to the SNAT
// address and quoting the translated probe, WAS matched and NAT-reversed
// (the deny event already names the LAN host as destination) and then died
// at the queued embedded-ICMP policy gate under `wan -> lan` default deny:
//
//   POLICY_DENY src=172.16.50.1:0 dst=10.0.61.102:0 proto=ICMP
//               policy_id=4294967295 ingress_zone=wan egress_zone=lan
//
// (same for every hop, and for ICMPv6 toward the LAN host's SLAAC address).
// #10666 had admitted only NAT'd PMTUD as RELATED; #18174 admits every
// same-family path error from the quoted session's expected arrival zone.
//
// Separately, v4 hop 1 answered as 169.254.2.1: the RETH base row's per-node
// link-local address shadowed the unit row's LAN address in the
// shared-ifindex egress merge, so the firewall's own Time Exceeded was
// sourced from it.
//
// Every cell here drives `poll_binding_process_descriptor`. The SNAT session
// is created by the REAL probe (mtr ICMP echo, or a classic traceroute / `mtr
// -u` UDP probe) entering on the LAN; the Time Exceeded quotes that probe in
// the exact translated form the session's NAT decision put on the wire.
//
// Split out as a sibling `#[path]` test module loaded from afxdp/mod.rs.
#![allow(unused_imports)]

use super::test_fixtures::*;
use super::tests_support::*;
use super::*;
use crate::test_zone_ids::*;
use crate::{InterfaceAddressSnapshot, InterfaceSnapshot, PolicyRuleSnapshot};

const LAN_IF: i32 = 24;
const WAN_IF: i32 = 12;
const FABRIC_IF: i32 = 21;
const WAN_VID: u16 = 80;
const CLIENT_MAC: [u8; 6] = [0x00, 0x25, 0x90, 0x12, 0x34, 0x56];
const UPSTREAM_MAC: [u8; 6] = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
const PROBE_ECHO_ID: u16 = 0x1234;
const PROBE_UDP_SPORT: u16 = 40001;
const PROBE_UDP_DPORT: u16 = 33434;

#[derive(Clone, Copy, Debug, PartialEq)]
enum Family {
    V4,
    V6,
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum Probe {
    /// mtr default / `traceroute -I`: ICMP(v6) echo request.
    Echo,
    /// classic `traceroute` / `mtr -u`: UDP to a high port.
    Udp,
}

/// Which error the hop sends back.
#[derive(Clone, Copy, Debug, PartialEq)]
enum ErrKind {
    /// v4 11/0, v6 3/0 — an intermediate hop.
    TimeExceeded,
    /// v4 3/3, v6 1/4 — a UDP traceroute's final hop.
    PortUnreachable,
    /// v4 5/1 — link-scoped Redirect; must stay policy-gated (#10684).
    Redirect,
}

fn client(f: Family) -> IpAddr {
    match f {
        Family::V4 => IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)),
        Family::V6 => IpAddr::V6("2001:559:8585:ef00::102".parse().unwrap()),
    }
}
fn server(f: Family) -> IpAddr {
    match f {
        Family::V4 => IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
        Family::V6 => IpAddr::V6("2001:4860:4860::8888".parse().unwrap()),
    }
}
fn hop(f: Family) -> IpAddr {
    match f {
        Family::V4 => IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)),
        Family::V6 => IpAddr::V6("2001:db8:ffff::1".parse().unwrap()),
    }
}

fn proto(f: Family, probe: Probe) -> u8 {
    match (f, probe) {
        (_, Probe::Udp) => PROTO_UDP,
        (Family::V4, Probe::Echo) => PROTO_ICMP,
        (Family::V6, Probe::Echo) => PROTO_ICMPV6,
    }
}

/// The 8 L4 bytes of a probe with the given source identity (echo id or UDP
/// source port). Checksums are left as the translated probe would carry
/// them; the error receiver never validates the quoted L4 checksum.
fn probe_l4(f: Family, probe: Probe, src_ident: u16) -> Vec<u8> {
    match probe {
        Probe::Echo => {
            let ty = if f == Family::V4 { 8 } else { 128 };
            let mut l4 = vec![ty, 0, 0, 0];
            l4.extend_from_slice(&src_ident.to_be_bytes());
            l4.extend_from_slice(&[0x00, 0x07]);
            l4
        }
        Probe::Udp => {
            let mut l4 = Vec::new();
            l4.extend_from_slice(&src_ident.to_be_bytes());
            l4.extend_from_slice(&PROBE_UDP_DPORT.to_be_bytes());
            l4.extend_from_slice(&8u16.to_be_bytes());
            l4.extend_from_slice(&[0, 0]);
            l4
        }
    }
}

/// An L3 packet (no Ethernet) — v4 header with `ttl`, or v6 with hop limit.
fn ip_packet(src: IpAddr, dst: IpAddr, ttl: u8, next: u8, payload: &[u8]) -> Vec<u8> {
    match (src, dst) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            let total = (20 + payload.len()) as u16;
            let mut p = vec![0x45, 0];
            p.extend_from_slice(&total.to_be_bytes());
            p.extend_from_slice(&[0x00, 0x2a, 0x00, 0x00, ttl, next, 0, 0]);
            p.extend_from_slice(&s.octets());
            p.extend_from_slice(&d.octets());
            let c = checksum16(&p[..20]);
            p[10..12].copy_from_slice(&c.to_be_bytes());
            p.extend_from_slice(payload);
            p
        }
        (IpAddr::V6(s), IpAddr::V6(d)) => {
            let mut p = vec![0x60, 0, 0, 0];
            p.extend_from_slice(&(payload.len() as u16).to_be_bytes());
            p.push(next);
            p.push(ttl);
            p.extend_from_slice(&s.octets());
            p.extend_from_slice(&d.octets());
            p.extend_from_slice(payload);
            p
        }
        _ => panic!("mixed-family fixture"),
    }
}

/// Fill the L4 checksum of a complete probe so the poll path's ingress
/// validation sees a well-formed packet.
fn finish_l4_checksum(f: Family, probe: Probe, src: IpAddr, dst: IpAddr, l4: &mut [u8]) {
    let off = match probe {
        Probe::Echo => 2,
        Probe::Udp => 6,
    };
    l4[off..off + 2].copy_from_slice(&[0, 0]);
    let c = match (f, probe, src, dst) {
        (Family::V4, Probe::Echo, _, _) => checksum16(l4),
        (Family::V6, _, IpAddr::V6(s), IpAddr::V6(d)) => checksum16_ipv6(s, d, proto(f, probe), l4),
        (Family::V4, Probe::Udp, IpAddr::V4(_), IpAddr::V4(_)) => 0, // UDP/IPv4 checksum optional
        _ => unreachable!(),
    };
    l4[off..off + 2].copy_from_slice(&c.to_be_bytes());
}

fn eth(dst: [u8; 6], src: [u8; 6], vid: Option<u16>, ethertype: u16) -> Vec<u8> {
    let mut e = Vec::new();
    e.extend_from_slice(&dst);
    e.extend_from_slice(&src);
    if let Some(v) = vid {
        e.extend_from_slice(&[0x81, 0x00]);
        e.extend_from_slice(&v.to_be_bytes());
    }
    e.extend_from_slice(&ethertype.to_be_bytes());
    e
}

fn ethertype(f: Family) -> u16 {
    if f == Family::V4 { 0x0800 } else { 0x86dd }
}

fn meta_for(f: Family, ingress: i32, l3: usize, protocol: u8, len: usize) -> UserspaceDpMeta {
    let l4 = l3 + if f == Family::V4 { 20 } else { 40 };
    UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        ingress_ifindex: ingress as u32,
        ingress_vlan_id: if l3 == 18 { WAN_VID } else { 0 },
        ingress_vlan_present: u8::from(l3 == 18),
        l3_offset: l3 as u16,
        l4_offset: l4 as u16,
        payload_offset: (l4 + 8) as u16,
        pkt_len: len as u16,
        addr_family: if f == Family::V4 { libc::AF_INET as u8 } else { libc::AF_INET6 as u8 },
        protocol,
        config_generation: 7,
        fib_generation: 9,
        ..UserspaceDpMeta::default()
    }
}

/// The LAN host's probe as it enters reth1.0.
fn probe_frame(f: Family, probe: Probe, ttl: u8) -> (Vec<u8>, UserspaceDpMeta) {
    let ident = if probe == Probe::Echo { PROBE_ECHO_ID } else { PROBE_UDP_SPORT };
    let mut l4 = probe_l4(f, probe, ident);
    finish_l4_checksum(f, probe, client(f), server(f), &mut l4);
    let mut frame = eth(TEST_LAN_MAC, CLIENT_MAC, None, ethertype(f));
    frame.extend_from_slice(&ip_packet(client(f), server(f), ttl, proto(f, probe), &l4));
    let meta = meta_for(f, LAN_IF, 14, proto(f, probe), frame.len());
    (frame, meta)
}

fn error_type_code(f: Family, err: ErrKind) -> (u8, u8) {
    match (f, err) {
        (Family::V4, ErrKind::TimeExceeded) => (11, 0),
        (Family::V4, ErrKind::PortUnreachable) => (3, 3),
        (Family::V4, ErrKind::Redirect) => (5, 1),
        (Family::V6, ErrKind::TimeExceeded) => (3, 0),
        (Family::V6, ErrKind::PortUnreachable) => (1, 4),
        (Family::V6, ErrKind::Redirect) => panic!("no v6 quoted-packet redirect cell"),
    }
}

/// The hop's error as it arrives on the WAN (reth0.80, VID 80), quoting the
/// probe in its TRANSLATED form: source `quoted_src` / identity
/// `quoted_ident` (the SNAT address + translated echo id / UDP port, or the
/// client itself on the non-NAT path), TTL/hop-limit 1 as it expired.
fn error_frame(
    f: Family,
    probe: Probe,
    err: ErrKind,
    sender: IpAddr,
    quoted_src: IpAddr,
    quoted_ident: u16,
) -> (Vec<u8>, UserspaceDpMeta) {
    let quote_l4 = probe_l4(f, probe, quoted_ident);
    let quote = ip_packet(quoted_src, server(f), 1, proto(f, probe), &quote_l4);
    let (ty, code) = error_type_code(f, err);
    let mut icmp = vec![ty, code, 0, 0, 0, 0, 0, 0];
    if err == ErrKind::Redirect {
        // Gateway address field.
        if let IpAddr::V4(g) = sender {
            icmp[4..8].copy_from_slice(&g.octets());
        }
    }
    icmp.extend_from_slice(&quote);
    let (outer_proto, csum) = match (sender, quoted_src) {
        (IpAddr::V4(_), IpAddr::V4(_)) => (PROTO_ICMP, checksum16(&icmp)),
        (IpAddr::V6(s), IpAddr::V6(d)) => (PROTO_ICMPV6, checksum16_ipv6(s, d, PROTO_ICMPV6, &icmp)),
        _ => unreachable!(),
    };
    icmp[2..4].copy_from_slice(&csum.to_be_bytes());
    let mut frame = eth(TEST_WAN_MAC, UPSTREAM_MAC, Some(WAN_VID), ethertype(f));
    frame.extend_from_slice(&ip_packet(sender, quoted_src, 250, outer_proto, &icmp));
    let meta = meta_for(f, WAN_IF, 18, outer_proto, frame.len());
    (frame, meta)
}

fn binding_on(ifindex: i32) -> BindingWorker {
    let mut b = BindingWorker::new_for_mirror_test(0, 0, ifindex, 0);
    b.interface = Arc::<str>::from(match ifindex {
        LAN_IF => "reth1.0",
        WAN_IF => "reth0.80",
        FABRIC_IF => "ge-0-0-0",
        _ => "unknown",
    });
    b
}

fn neighbors_with_client(forwarding: &ForwardingState, f: Family) -> Arc<ShardedNeighborMap> {
    let n = Arc::new(ShardedNeighborMap::default());
    learn_dynamic_neighbor(forwarding, &n, LAN_IF, 0, client(f), CLIENT_MAC);
    n
}

fn ha(rg1: bool, rg2: bool) -> BTreeMap<i32, HAGroupRuntime> {
    let rg = |active: bool| HAGroupRuntime {
        active,
        watchdog_timestamp: 123,
        lease: if active {
            HAGroupRuntime::active_lease_until(123, 123)
        } else {
            HAForwardingLease::Inactive
        },
    };
    BTreeMap::from([(1, rg(rg1)), (2, rg(rg2))])
}

/// What the probe's real SNAT translation put on the wire: (quoted source,
/// quoted identity). Read from the queued forward's own NAT decision — the
/// one dispatch applies — so the error quotes exactly the translated probe.
fn run_probe(
    sessions: &mut SessionTable,
    forwarding: &ForwardingState,
    neighbors: &Arc<ShardedNeighborMap>,
    f: Family,
    probe: Probe,
) -> (IpAddr, u16) {
    let (frame, meta) = probe_frame(f, probe, 5);
    let mut lan = binding_on(LAN_IF);
    let before = sessions.len();
    txn_run_descriptor_with_neighbors(&mut lan, sessions, forwarding, &ha(true, true), &frame, meta, neighbors);
    assert!(
        sessions.len() > before,
        "premise: the {f:?} {probe:?} probe must install its session through the poll path"
    );
    assert_eq!(
        lan.scratch.scratch_forwards.len(),
        1,
        "premise: the probe must be forwarded toward the WAN"
    );
    let fwd = &lan.scratch.scratch_forwards[0];
    assert_eq!(fwd.decision.resolution.egress_ifindex, WAN_IF, "premise: probe egresses reth0.80");
    let nat = fwd.decision.nat;
    let ident = if probe == Probe::Echo { PROBE_ECHO_ID } else { PROBE_UDP_SPORT };
    (
        nat.rewrite_src.unwrap_or(client(f)),
        nat.rewrite_src_port.unwrap_or(ident),
    )
}

/// The facts a delivered (un-NATed) error must carry on the LAN leg.
fn assert_delivered_to_lan_host(
    fwd: &PendingForwardRequest,
    f: Family,
    probe: Probe,
    err: ErrKind,
    sender: IpAddr,
    label: &str,
) {
    assert_eq!(fwd.target_ifindex, LAN_IF, "{label}: the error must egress toward the LAN host");
    assert!(fwd.flow_key.is_none(), "{label}: a reversed error never seeds a session/flow-cache entry");
    let bytes: &[u8] = match &fwd.frame {
        PendingForwardFrame::PrebuiltTransit { frame, .. } => frame,
        other => panic!("{label}: expected a prebuilt transit frame, got {:?}", std::mem::discriminant(other)),
    };
    assert_eq!(&bytes[0..6], &CLIENT_MAC, "{label}: L2 destination is the LAN host");
    let l3 = 14;
    let (ty, code) = error_type_code(f, err);
    match f {
        Family::V4 => {
            let l4 = l3 + 20;
            assert_eq!(checksum16(&bytes[l3..l4]), 0, "{label}: outer IPv4 header checksum");
            assert_eq!(
                IpAddr::V4(Ipv4Addr::new(bytes[l3 + 12], bytes[l3 + 13], bytes[l3 + 14], bytes[l3 + 15])),
                sender,
                "{label}: outer source stays the error's sender"
            );
            assert_eq!(&bytes[l3 + 16..l3 + 20], &[10, 0, 61, 102], "{label}: outer destination un-NATed to the LAN host");
            assert_eq!((bytes[l4], bytes[l4 + 1]), (ty, code), "{label}: error type/code preserved");
            assert_eq!(checksum16(&bytes[l4..]), 0, "{label}: ICMP checksum valid after the rewrite");
            let q = l4 + 8;
            assert_eq!(checksum16(&bytes[q..q + 20]), 0, "{label}: quoted IPv4 header checksum");
            assert_eq!(&bytes[q + 12..q + 16], &[10, 0, 61, 102], "{label}: quoted source un-NATed");
            assert_eq!(&bytes[q + 16..q + 20], &[1, 1, 1, 1], "{label}: quoted destination unchanged");
            let ql4 = q + 20;
            match probe {
                Probe::Echo => assert_eq!(
                    u16::from_be_bytes([bytes[ql4 + 4], bytes[ql4 + 5]]),
                    PROBE_ECHO_ID,
                    "{label}: quoted echo id restored to the LAN host's id"
                ),
                Probe::Udp => assert_eq!(
                    u16::from_be_bytes([bytes[ql4], bytes[ql4 + 1]]),
                    PROBE_UDP_SPORT,
                    "{label}: quoted UDP source port restored to the LAN host's port"
                ),
            }
        }
        Family::V6 => {
            let l4 = l3 + 40;
            let src = Ipv6Addr::from(<[u8; 16]>::try_from(&bytes[l3 + 8..l3 + 24]).unwrap());
            let dst = Ipv6Addr::from(<[u8; 16]>::try_from(&bytes[l3 + 24..l3 + 40]).unwrap());
            assert_eq!(IpAddr::V6(src), sender, "{label}: outer source stays the error's sender");
            assert_eq!(IpAddr::V6(dst), client(f), "{label}: outer destination un-NATed to the LAN host");
            assert_eq!((bytes[l4], bytes[l4 + 1]), (ty, code), "{label}: error type/code preserved");
            let mut icmp = bytes[l4..].to_vec();
            let stored = u16::from_be_bytes([icmp[2], icmp[3]]);
            icmp[2..4].copy_from_slice(&[0, 0]);
            assert_eq!(
                checksum16_ipv6(src, dst, PROTO_ICMPV6, &icmp),
                stored,
                "{label}: ICMPv6 checksum valid after the rewrite"
            );
            let q = l4 + 8;
            let qsrc = Ipv6Addr::from(<[u8; 16]>::try_from(&bytes[q + 8..q + 24]).unwrap());
            assert_eq!(IpAddr::V6(qsrc), client(f), "{label}: quoted source un-NATed");
            let ql4 = q + 40;
            match probe {
                Probe::Echo => assert_eq!(
                    u16::from_be_bytes([bytes[ql4 + 4], bytes[ql4 + 5]]),
                    PROBE_ECHO_ID,
                    "{label}: quoted echo id restored"
                ),
                Probe::Udp => assert_eq!(
                    u16::from_be_bytes([bytes[ql4], bytes[ql4 + 1]]),
                    PROBE_UDP_SPORT,
                    "{label}: quoted UDP source port restored"
                ),
            }
        }
    }
}

/// One single-node case: real probe through the poll path, then the hop's
/// error through the poll path, under `wan -> lan` DEFAULT DENY (the
/// reference cluster config has no such permit). `snat == false` clears the
/// source-NAT rules: the non-NAT control whose error is addressed straight
/// to the LAN host.
fn run_single_node_case(f: Family, probe: Probe, err: ErrKind, snat: bool) -> (BindingWorker, DebugPollCounters, usize, usize) {
    let mut snapshot = nat_snapshot();
    if !snat {
        snapshot.source_nat_rules.clear();
    }
    assert!(
        !snapshot.policies.iter().any(|p| p.from_zone == "wan" && p.to_zone == "lan"),
        "premise: no wan -> lan permit; delivery must come from RELATED admission"
    );
    let forwarding = build_forwarding_state(&snapshot);
    let neighbors = neighbors_with_client(&forwarding, f);
    let mut sessions = SessionTable::new();
    let (quoted_src, quoted_ident) = run_probe(&mut sessions, &forwarding, &neighbors, f, probe);
    if snat {
        assert_ne!(quoted_src, client(f), "premise: the probe was source-NATed");
    } else {
        assert_eq!(quoted_src, client(f), "premise: the non-NAT probe keeps its source");
    }
    let sender = if err == ErrKind::PortUnreachable { server(f) } else { hop(f) };
    let (frame, meta) = error_frame(f, probe, err, sender, quoted_src, quoted_ident);
    let mut wan = binding_on(WAN_IF);
    let sessions_before = sessions.len();
    let (_batch, dbg) =
        txn_run_descriptor_with_neighbors(&mut wan, &mut sessions, &forwarding, &ha(true, true), &frame, meta, &neighbors);
    (wan, dbg, sessions_before, sessions.len())
}

fn assert_case_delivered(f: Family, probe: Probe, err: ErrKind, snat: bool) {
    let label = format!("{f:?} {probe:?} {err:?} snat={snat}");
    let (wan, dbg, before, after) = run_single_node_case(f, probe, err, snat);
    // The UDP final-hop error comes from the destination itself.
    let sender = if err == ErrKind::PortUnreachable { server(f) } else { hop(f) };
    assert_eq!(dbg.policy_deny, 0, "{label}: a RELATED path error must not hit the wan->lan default deny");
    assert_eq!(
        wan.scratch.scratch_forwards.len(),
        1,
        "{label}: the hop's error must be un-NATed and queued toward the LAN host \
         (RED pre-#18174: queued gate default-denied every NAT'd Time Exceeded / unreachable)"
    );
    assert_delivered_to_lan_host(&wan.scratch.scratch_forwards[0], f, probe, err, sender, &label);
    assert_eq!(after, before, "{label}: the error must not install a session");
    assert!(wan.scratch.scratch_recycle.is_empty(), "{label}: the queued forward owns the descriptor");
}

// ---- SNAT path (the user's report) -------------------------------------

#[test]
fn snat_mtr_echo_time_exceeded_reaches_lan_host_v4_18174() {
    assert_case_delivered(Family::V4, Probe::Echo, ErrKind::TimeExceeded, true);
}

#[test]
fn snat_mtr_echo_time_exceeded_reaches_lan_host_v6_18174() {
    assert_case_delivered(Family::V6, Probe::Echo, ErrKind::TimeExceeded, true);
}

#[test]
fn snat_udp_traceroute_time_exceeded_reaches_lan_host_v4_18174() {
    assert_case_delivered(Family::V4, Probe::Udp, ErrKind::TimeExceeded, true);
}

#[test]
fn snat_udp_traceroute_time_exceeded_reaches_lan_host_v6_18174() {
    assert_case_delivered(Family::V6, Probe::Udp, ErrKind::TimeExceeded, true);
}

/// The UDP traceroute's final hop: the destination's port unreachable.
#[test]
fn snat_udp_traceroute_final_port_unreachable_reaches_lan_host_v4_18174() {
    assert_case_delivered(Family::V4, Probe::Udp, ErrKind::PortUnreachable, true);
}

#[test]
fn snat_udp_traceroute_final_port_unreachable_reaches_lan_host_v6_18174() {
    assert_case_delivered(Family::V6, Probe::Udp, ErrKind::PortUnreachable, true);
}

// ---- non-NAT controls (already RELATED via #10286/#10684) -----------------

#[test]
fn nonnat_mtr_echo_time_exceeded_reaches_lan_host_v4_18174() {
    assert_case_delivered(Family::V4, Probe::Echo, ErrKind::TimeExceeded, false);
}

#[test]
fn nonnat_udp_traceroute_time_exceeded_reaches_lan_host_v6_18174() {
    assert_case_delivered(Family::V6, Probe::Udp, ErrKind::TimeExceeded, false);
}

// ---- the #9948/#10684 gate still holds ----------------------------------

/// A Redirect quoting the live translated probe is link-scoped, not a path
/// error: it must stay under arrival-to-egress policy (default deny), so the
/// widened RELATED scope did not become "any ICMP error that matches".
#[test]
fn snat_redirect_quoting_live_probe_stays_policy_gated_18174() {
    let (wan, dbg, before, after) = run_single_node_case(Family::V4, Probe::Echo, ErrKind::Redirect, true);
    assert!(
        wan.scratch.scratch_forwards.is_empty(),
        "a NAT'd Redirect must not ride the RELATED bypass"
    );
    assert_eq!(dbg.policy_deny, 1, "the Redirect is adjudicated and default-denied");
    assert_eq!(wan.scratch.scratch_recycle.len(), 1);
    assert_eq!(after, before);
}

/// The fabric peer accepts an ALREADY-REVERSED error (outer dst = the client,
/// quote in pre-NAT form) only because it arrives on the authenticated
/// fabric. The same bytes arriving on the WAN are not an error the redirecting
/// peer produced — nothing upstream can see the client's pre-NAT tuple — so
/// they must not ride RELATED into the LAN: the forward-NAT arm declines and
/// the ordinary unmatched-error path refuses it.
#[test]
fn pre_nat_quote_off_fabric_is_not_related_18174() {
    // v4 and v6: each family's forward-NAT arm carries its own copy of the
    // fabric-ingress guard (`nat_match_v4.rs` / `nat_match_v6.rs`).
    for f in [Family::V4, Family::V6] {
        let label = format!("{f:?}");
        let forwarding = build_forwarding_state(&nat_snapshot());
        let neighbors = neighbors_with_client(&forwarding, f);
        let mut sessions = SessionTable::new();
        let (qsrc, _qid) = run_probe(&mut sessions, &forwarding, &neighbors, f, Probe::Echo);
        assert_ne!(qsrc, client(f), "{label}: premise: the probe was source-NATed");
        // Outer dst = client, quote = the PRE-NAT probe, arriving on the WAN.
        let (frame, meta) =
            error_frame(f, Probe::Echo, ErrKind::TimeExceeded, hop(f), client(f), PROBE_ECHO_ID);
        let mut wan = binding_on(WAN_IF);
        let (_b, dbg) = txn_run_descriptor_with_neighbors(
            &mut wan,
            &mut sessions,
            &forwarding,
            &ha(true, true),
            &frame,
            meta,
            &neighbors,
        );
        assert!(
            wan.scratch.scratch_forwards.is_empty(),
            "{label}: a pre-NAT quote off the fabric must not be admitted as RELATED \
             (RED when the fabric-ingress guard is dropped: the forward-NAT arm \
             matches it and the RELATED rule queues it to the LAN host)"
        );
        assert_eq!(wan.scratch.scratch_recycle.len(), 1, "{label}: the refused descriptor is recycled");
        assert_eq!(dbg.ha_inactive, 0, "{label}: the refusal is not an HA verdict (both RGs are active)");
    }
}

// ---- HA ------------------------------------------------------------------

/// A node that owns NEITHER RG (no fabric peer to hand to) must not deliver
/// the error: the RELATED bypass is scoped to ForwardCandidate and never
/// overrides HAInactive.
#[test]
fn non_owner_node_does_not_deliver_time_exceeded_18174() {
    let forwarding = build_forwarding_state(&nat_snapshot());
    let neighbors = neighbors_with_client(&forwarding, Family::V4);
    let mut sessions = SessionTable::new();
    let (qsrc, qid) = run_probe(&mut sessions, &forwarding, &neighbors, Family::V4, Probe::Echo);
    let (frame, meta) = error_frame(Family::V4, Probe::Echo, ErrKind::TimeExceeded, hop(Family::V4), qsrc, qid);
    let mut wan = binding_on(WAN_IF);
    let (_b, dbg) =
        txn_run_descriptor_with_neighbors(&mut wan, &mut sessions, &forwarding, &ha(false, false), &frame, meta, &neighbors);
    assert!(
        wan.scratch.scratch_forwards.is_empty(),
        "an inactive node must not transmit a RELATED error"
    );
    assert_eq!(dbg.policy_deny, 0, "HA suppression is not a policy verdict");
}

/// The peer node: same config, fabric MACs swapped (its own fabric parent
/// is 00:aa:bb:cc:dd:ee, the first node's is 02:bf:72:ff:00:01).
fn peer_snapshot() -> crate::ConfigSnapshot {
    let mut s = nat_snapshot_with_fabric();
    s.fabrics[0].local_mac = "00:aa:bb:cc:dd:ee".to_string();
    s.fabrics[0].peer_mac = "02:bf:72:ff:00:01".to_string();
    for iface in s.interfaces.iter_mut().filter(|i| i.ifindex == FABRIC_IF) {
        iface.hardware_addr = "00:aa:bb:cc:dd:ee".to_string();
    }
    s
}

/// The frame the LAN-RG owner's dispatch puts on the fabric for a probe whose
/// WAN egress is peer-owned: the ORIGINAL pre-NAT probe (`apply_nat_on_fabric`
/// stays false; the WAN owner translates, #4439/#4453), stamped with the LAN
/// arrival zone, addressed to the WAN owner's fabric parent.
fn fabric_probe_frame(f: Family, probe: Probe) -> (Vec<u8>, UserspaceDpMeta) {
    let (mut frame, _) = probe_frame(f, probe, 5);
    frame[0..6].copy_from_slice(&TEST_FABRIC_MAC);
    let [_, _, hi, lo] = TEST_LAN_ZONE_ID.to_be_bytes();
    frame[6..12].copy_from_slice(&[0x02, 0xbf, 0x72, FABRIC_ZONE_MAC_MAGIC, hi, lo]);
    let meta = meta_for(f, FABRIC_IF, 14, proto(f, probe), frame.len());
    (frame, meta)
}

/// WAN-RG owner leg: the hop's error arrives on the WAN quoting the probe as
/// `xlate` put it on the wire; the LAN RG is the peer's, so the reversed error
/// must leave on the fabric stamped with the zone it ARRIVED in (`wan`).
/// Returns the fabric frame.
fn wan_owner_error_leg(
    sessions: &mut SessionTable,
    forwarding: &ForwardingState,
    neighbors: &Arc<ShardedNeighborMap>,
    f: Family,
    probe: Probe,
    xlate: (IpAddr, u16),
    label: &str,
) -> Vec<u8> {
    let (frame, meta) = error_frame(f, probe, ErrKind::TimeExceeded, hop(f), xlate.0, xlate.1);
    let mut wan = binding_on(WAN_IF);
    txn_run_descriptor_with_neighbors(&mut wan, sessions, forwarding, &ha(true, false), &frame, meta, neighbors);
    assert_eq!(wan.scratch.scratch_forwards.len(), 1, "{label}: the WAN owner must queue one prebuilt");
    let redirect = &wan.scratch.scratch_forwards[0];
    assert_eq!(
        redirect.decision.resolution.disposition,
        ForwardingDisposition::FabricRedirect,
        "{label}: the LAN RG is peer-owned, so the error rides the fabric"
    );
    assert_eq!(redirect.target_ifindex, FABRIC_IF, "{label}: transmitted on the fabric parent");
    let fabric_frame: Vec<u8> = match &redirect.frame {
        PendingForwardFrame::PrebuiltTransit { frame, .. } => frame.to_vec(),
        _ => panic!("{label}: the fabric leg must carry the prebuilt reversed frame"),
    };
    let [_, _, zhi, zlo] = TEST_WAN_ZONE_ID.to_be_bytes();
    assert_eq!(
        &fabric_frame[6..12],
        &[0x02, 0xbf, 0x72, FABRIC_ZONE_MAC_MAGIC, zhi, zlo],
        "{label}: the fabric frame must claim the zone the error arrived in (wan), not the \
         quoted session's cached fabric-return stamp (lan)"
    );
    fabric_frame
}

/// LAN-RG owner leg: the fabric-carried, already-reversed error must reach
/// the LAN host under this node's own `wan -> lan` default deny.
fn lan_owner_delivers(
    sessions: &mut SessionTable,
    forwarding: &ForwardingState,
    neighbors: &Arc<ShardedNeighborMap>,
    fabric_frame: &[u8],
    f: Family,
    probe: Probe,
    label: &str,
) {
    let meta = meta_for(
        f,
        FABRIC_IF,
        14,
        if f == Family::V4 { PROTO_ICMP } else { PROTO_ICMPV6 },
        fabric_frame.len(),
    );
    let mut fab = binding_on(FABRIC_IF);
    let before = sessions.len();
    let (batch, dbg) =
        txn_run_descriptor_with_neighbors(&mut fab, sessions, forwarding, &ha(false, true), fabric_frame, meta, neighbors);
    assert_eq!(batch.invalid_fabric_stamp_drops, 0, "{label}: the LAN owner accepts the WAN stamp");
    assert_eq!(dbg.policy_deny, 0, "{label}: the LAN owner must not default-deny the RELATED error");
    assert_eq!(
        fab.scratch.scratch_forwards.len(),
        1,
        "{label}: the LAN owner must deliver the fabric-carried error to the LAN host; \
         dst_mac_dropped={} unstamped={} validated={} recycled={} ha_inactive={}",
        batch.dst_mac_dropped,
        batch.unstamped_fabric_ingress_drops,
        batch.validated_packets,
        fab.scratch.scratch_recycle.len(),
        dbg.ha_inactive,
    );
    assert_delivered_to_lan_host(&fab.scratch.scratch_forwards[0], f, probe, ErrKind::TimeExceeded, hop(f), label);
    assert_eq!(sessions.len(), before, "{label}: no session from the error");
}

/// Run one LAN probe on a node under `ha_state`; the caller reads the queued
/// request off the returned binding.
fn lan_probe_on(
    sessions: &mut SessionTable,
    forwarding: &ForwardingState,
    neighbors: &Arc<ShardedNeighborMap>,
    ha_state: &BTreeMap<i32, HAGroupRuntime>,
    f: Family,
    probe: Probe,
    ttl: u8,
) -> BindingWorker {
    let (frame, meta) = probe_frame(f, probe, ttl);
    let mut lan = binding_on(LAN_IF);
    txn_run_descriptor_with_neighbors(&mut lan, sessions, forwarding, ha_state, &frame, meta, neighbors);
    lan
}

const SPLIT_CASES: [(Family, Probe); 4] = [
    (Family::V4, Probe::Echo),
    (Family::V4, Probe::Udp),
    (Family::V6, Probe::Echo),
    (Family::V6, Probe::Udp),
];

/// Split RGs from the start — the live tcp experiment (RG1/WAN on node0,
/// RG2/LAN on node1). The probe enters node1 (LAN owner), which owns the
/// session and fabric-redirects the original pre-NAT probe; node0 (WAN
/// owner) processes it as a FABRIC-INGRESS packet, translates it and installs
/// its own session, whose reverse half production synthesis stores as a
/// "fabric return" FabricRedirect stamped with the FORWARD ingress zone
/// (`lan`). The hop's Time Exceeded comes back to node0, matches that
/// session, and the embedded arm reused the cached `lan`-stamped redirect:
/// node1 then saw a `lan` arrival, failed the RELATED arrival check and
/// default-denied it `lan -> lan` — exactly the live tcp journal
/// (`POLICY_DENY src=<hop> dst=10.0.62.102 ingress_zone=lan egress_zone=lan`).
/// RED on revert of `restamp_embedded_fabric_redirect` (leg 1 stamp).
#[test]
fn split_rg_live_shape_time_exceeded_reaches_lan_host_18174() {
    for (f, probe) in SPLIT_CASES {
        let label = format!("live split {f:?} {probe:?}");
        // node1 (LAN owner): its own session from the LAN probe.
        let n1_fwd = build_forwarding_state(&peer_snapshot());
        let n1_neighbors = neighbors_with_client(&n1_fwd, f);
        let mut n1_sessions = SessionTable::new();
        let lan = lan_probe_on(&mut n1_sessions, &n1_fwd, &n1_neighbors, &ha(false, true), f, probe, 5);
        assert_eq!(lan.scratch.scratch_forwards.len(), 1, "{label}: premise: node1 forwards the probe");
        assert_eq!(
            lan.scratch.scratch_forwards[0].decision.resolution.disposition,
            ForwardingDisposition::FabricRedirect,
            "{label}: premise: node1 hands the probe to the WAN owner over the fabric"
        );

        // node0 (WAN owner): the fabric-ingress probe installs its session.
        let n0_fwd = build_forwarding_state(&nat_snapshot_with_fabric());
        let n0_neighbors = neighbors_with_client(&n0_fwd, f);
        let mut n0_sessions = SessionTable::new();
        let (frame, meta) = fabric_probe_frame(f, probe);
        let mut fab = binding_on(FABRIC_IF);
        txn_run_descriptor_with_neighbors(&mut fab, &mut n0_sessions, &n0_fwd, &ha(true, false), &frame, meta, &n0_neighbors);
        assert_eq!(fab.scratch.scratch_forwards.len(), 1, "{label}: premise: node0 forwards the fabric probe");
        let fwd = &fab.scratch.scratch_forwards[0];
        assert_eq!(fwd.decision.resolution.egress_ifindex, WAN_IF, "{label}: premise: out the WAN");
        let nat = fwd.decision.nat;
        let ident = if probe == Probe::Echo { PROBE_ECHO_ID } else { PROBE_UDP_SPORT };
        let xlate = (nat.rewrite_src.expect("premise: node0 source-NATs"), nat.rewrite_src_port.unwrap_or(ident));

        let fabric_frame =
            wan_owner_error_leg(&mut n0_sessions, &n0_fwd, &n0_neighbors, f, probe, xlate, &label);
        lan_owner_delivers(&mut n1_sessions, &n1_fwd, &n1_neighbors, &fabric_frame, f, probe, &label);
    }
}

/// Export `key`'s forward row from `sessions` as the HA wire import would
/// hand it to the peer: ForwardCandidate out the WAN unit, the same NAT
/// decision and zones, SyncImport origin.
fn exported_forward_row(sessions: &SessionTable, key: &SessionKey) -> SyncedSessionEntry {
    let (decision, metadata, _origin) = sessions.entry_with_origin(key).expect("premise: forward row installed");
    assert!(!metadata.is_reverse, "premise: the forward row");
    SyncedSessionEntry {
        key: key.clone(),
        decision,
        metadata,
        source_nat_static: Some(false),
        leak_incarnation: 0,
        origin: crate::session::SessionOrigin::SyncImport,
        protocol: key.protocol,
        tcp_flags: 0,
        generation: 0,
        session_id: (1u64 << 48) | 18174,
        tcp_close_class: 0,
        tcp_handshake_state: 0,
        rev_packets: 1,
        fwd_packets: 1,
        pptp_call_ids: 0,
        persistent_lease_hold: None,
    }
}

/// Split AFTER the flow was established — RG2 moves to node1 while mtr runs.
/// node0 created the session while it owned both RGs; node1 holds it ONLY as
/// an HA import, installed through the production path: the forward row
/// exported as the peer import carries it, the reverse companion synthesized
/// by `synthesized_synced_reverse_entry` under node1's own HA state, both
/// applied by the worker command dispatcher (`WorkerCommand::UpsertSynced`).
/// The reversed error reaches node1 already in pre-NAT form; it matches the
/// imported row through its canonical reply alias, which the #14665 gate
/// declined (it expected the SNAT address as outer destination) until the
/// fabric-ingress arm in `nat_match_v4/v6`. RED on revert of that arm.
#[test]
fn split_rg_after_establishment_synced_import_reaches_lan_host_18174() {
    for (f, probe) in SPLIT_CASES {
        let label = format!("synced split {f:?} {probe:?}");
        // node0 while it owned both RGs.
        let n0_fwd = build_forwarding_state(&nat_snapshot_with_fabric());
        let n0_neighbors = neighbors_with_client(&n0_fwd, f);
        let mut n0_sessions = SessionTable::new();
        let lan = lan_probe_on(&mut n0_sessions, &n0_fwd, &n0_neighbors, &ha(true, true), f, probe, 5);
        assert_eq!(lan.scratch.scratch_forwards.len(), 1, "{label}: premise: node0 forwards the probe");
        let fwd = &lan.scratch.scratch_forwards[0];
        let key = fwd.flow_key.clone().expect("premise: a flow-backed forward");
        let ident = if probe == Probe::Echo { PROBE_ECHO_ID } else { PROBE_UDP_SPORT };
        let xlate = (
            fwd.decision.nat.rewrite_src.expect("premise: source-NATed"),
            fwd.decision.nat.rewrite_src_port.unwrap_or(ident),
        );
        let exported = exported_forward_row(&n0_sessions, &key);

        // node1: the HA import, through the production worker dispatcher.
        let n1_fwd = build_forwarding_state(&peer_snapshot());
        let n1_neighbors = neighbors_with_client(&n1_fwd, f);
        let mut n1_sessions = SessionTable::new();
        let n1_ha = ha(false, true);
        let reverse = crate::afxdp::shared_ops::synthesized_synced_reverse_entry(
            &n1_fwd,
            &n1_ha,
            &n1_neighbors,
            &exported,
            123,
        )
        .expect("production reverse synthesis must produce the companion");
        let queue = Arc::new(Mutex::new(VecDeque::from(vec![
            WorkerCommand::UpsertSynced(exported),
            WorkerCommand::UpsertSynced(reverse),
        ])));
        crate::afxdp::session_glue::apply_worker_commands(
            &queue,
            &mut n1_sessions,
            crate::afxdp::bpf_map::SteeringMap::unshared_for_test(-1),
            -1,
            -1,
            &n1_fwd,
            &n1_ha,
            &n1_neighbors,
            0,
            &mut VecDeque::new(),
        );
        assert!(
            n1_sessions.entry_with_origin(&key).is_some(),
            "{label}: premise: node1 holds the imported forward row"
        );

        // RG2 moved: node0 keeps only the WAN.
        let fabric_frame =
            wan_owner_error_leg(&mut n0_sessions, &n0_fwd, &n0_neighbors, f, probe, xlate, &label);
        lan_owner_delivers(&mut n1_sessions, &n1_fwd, &n1_neighbors, &fabric_frame, f, probe, &label);
    }
}

/// Split RGs, hop 1: node1 owns the LAN and hands transit to node0 over the
/// fabric, so node1 is the router that must answer an expiring probe — the
/// fabric build would decrement and refuse it, and node0 skips the decrement
/// on fabric ingress. Live on tcp every TTL-1 probe ended as
/// `fabric_redirect_build_failed` on fw1 and mtr hop 1 read `???`. The answer
/// must leave the LAN unit sourced from its own address, and the probe must not
/// leave a punt-seed session behind. RED on revert of the FabricRedirect TTL
/// check in the poll tail (the request is a FabricRedirect live forward
/// instead) and of the seed skip (one seed row).
#[test]
fn split_rg_hop_one_time_exceeded_is_answered_by_lan_owner_18174() {
    let n1_fwd = build_forwarding_state(&peer_snapshot());
    for (f, probe) in SPLIT_CASES {
        let label = format!("split hop1 {f:?} {probe:?}");
        let neighbors = neighbors_with_client(&n1_fwd, f);
        let mut sessions = SessionTable::new();
        let lan = lan_probe_on(&mut sessions, &n1_fwd, &neighbors, &ha(false, true), f, probe, 1);
        assert_eq!(
            lan.scratch.scratch_forwards.len(),
            1,
            "{label}: the expiring probe must produce exactly one reply"
        );
        // The probe never leaves this node, so it must not leave a #7770
        // punt seed (a session row and an HA sync) behind either — the
        // FabricRedirect twin of the #14643 ForwardCandidate rollback.
        assert_eq!(sessions.len(), 0, "{label}: an expiring split-RG probe installs no session");
        let te = &lan.scratch.scratch_forwards[0];
        assert_ne!(
            te.decision.resolution.disposition,
            ForwardingDisposition::FabricRedirect,
            "{label}: an expiring probe must not be handed to the fabric"
        );
        assert_eq!(te.target_ifindex, LAN_IF, "{label}: the Time Exceeded leaves the LAN unit");
        let bytes: &[u8] = match &te.frame {
            PendingForwardFrame::Prebuilt(frame) => frame,
            _ => panic!("{label}: a generated Time Exceeded is a prebuilt frame"),
        };
        assert_eq!(&bytes[0..6], &CLIENT_MAC, "{label}: back to the LAN host");
        match f {
            Family::V4 => {
                assert_eq!(bytes[14 + 20], 11, "{label}: ICMP Time Exceeded");
                assert_eq!(&bytes[14 + 12..14 + 16], &[10, 0, 61, 1], "{label}: sourced from the LAN address");
            }
            Family::V6 => {
                assert_eq!(bytes[14 + 40], 3, "{label}: ICMPv6 Time Exceeded");
                let src = Ipv6Addr::from(<[u8; 16]>::try_from(&bytes[14 + 8..14 + 24]).unwrap());
                assert_eq!(src, "2001:559:8585:ef00::1".parse::<Ipv6Addr>().unwrap(), "{label}: LAN global source");
            }
        }
    }
}

// ---- defect 2: the firewall's own hop-1 Time Exceeded source --------------

/// The RETH shape Go emits: the base row (`reth1`, per-node 169.254.2.1/32 and
/// the kernel fe80 RETH address) BEFORE the unit row on the same ifindex.
fn reth_base_row_snapshot() -> crate::ConfigSnapshot {
    let mut s = nat_snapshot();
    let unit = s
        .interfaces
        .iter()
        .position(|i| i.name == "reth1.0")
        .expect("fixture has reth1.0");
    let base = InterfaceSnapshot {
        name: "reth1".to_string(),
        zone: "lan".to_string(),
        linux_name: "ge-0-0-1".to_string(),
        ifindex: LAN_IF,
        redundancy_group: 2,
        hardware_addr: "02:bf:72:01:00:01".to_string(),
        addresses: vec![
            InterfaceAddressSnapshot {
                family: "inet".to_string(),
                address: "169.254.2.1/32".to_string(),
                scope: 253,
                ..Default::default()
            },
            InterfaceAddressSnapshot {
                family: "inet6".to_string(),
                address: "fe80::bf72:16:2/128".to_string(),
                scope: 253,
                ..Default::default()
            },
        ],
        ..Default::default()
    };
    s.interfaces.insert(unit, base);
    s
}

/// mtr hop 1: the LAN host's TTL/hop-limit-1 probe through the poll path must
/// produce the firewall's own Time Exceeded sourced from the LAN address
/// (10.0.61.1 / 2001:559:8585:ef00::1), never the RETH's link-local.
/// RED on revert of the shared-ifindex merge fix (v4: 169.254.2.1; v6:
/// fe80::bf72:16:2).
#[test]
fn hop_one_time_exceeded_is_sourced_from_lan_address_not_reth_link_local_18174() {
    let forwarding = build_forwarding_state(&reth_base_row_snapshot());
    for f in [Family::V4, Family::V6] {
        for probe in [Probe::Echo, Probe::Udp] {
            let label = format!("{f:?} {probe:?}");
            let neighbors = neighbors_with_client(&forwarding, f);
            let mut sessions = SessionTable::new();
            let (frame, meta) = probe_frame(f, probe, 1);
            let mut lan = binding_on(LAN_IF);
            txn_run_descriptor_with_neighbors(&mut lan, &mut sessions, &forwarding, &ha(true, true), &frame, meta, &neighbors);
            assert_eq!(
                lan.scratch.scratch_forwards.len(),
                1,
                "{label}: the expired probe must produce one generated Time Exceeded"
            );
            let te = &lan.scratch.scratch_forwards[0];
            let bytes: &[u8] = match &te.frame {
                PendingForwardFrame::Prebuilt(frame) => frame,
                _ => panic!("{label}: generated Time Exceeded must be a prebuilt frame"),
            };
            match f {
                Family::V4 => {
                    assert_eq!(bytes[14 + 20], 11, "{label}: ICMP Time Exceeded");
                    assert_eq!(
                        &bytes[14 + 12..14 + 16],
                        &[10, 0, 61, 1],
                        "{label}: hop 1 must answer as the LAN address, not 169.254.2.1"
                    );
                    assert_eq!(&bytes[14 + 16..14 + 20], &[10, 0, 61, 102]);
                }
                Family::V6 => {
                    assert_eq!(bytes[14 + 40], 3, "{label}: ICMPv6 Time Exceeded");
                    let src = Ipv6Addr::from(<[u8; 16]>::try_from(&bytes[14 + 8..14 + 24]).unwrap());
                    assert_eq!(
                        src,
                        "2001:559:8585:ef00::1".parse::<Ipv6Addr>().unwrap(),
                        "{label}: hop 1 must answer as the LAN global address, not the RETH fe80"
                    );
                }
            }
        }
    }
}


// ---- cross-worker: the split-RG first error on another worker ------------

/// One node's shared maps — what every worker of that node sees.
struct NodeShared {
    sessions: Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    nat: Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    wire: Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    owner_idx: SharedSessionOwnerRgIndexes,
}

impl NodeShared {
    fn new() -> Self {
        Self {
            sessions: Arc::new(Mutex::new(FastMap::default())),
            nat: Arc::new(Mutex::new(FastMap::default())),
            wire: Arc::new(Mutex::new(FastMap::default())),
            owner_idx: SharedSessionOwnerRgIndexes::default(),
        }
    }
}

/// `txn_run_descriptor_with_neighbors` with the node's shared maps held by
/// the caller, so a second worker (its own `SessionTable`) sees exactly what
/// the first worker published.
#[expect(clippy::too_many_arguments, reason = "test driver mirrors the poll entry point")]
fn run_on_worker(
    binding: &mut BindingWorker,
    sessions: &mut SessionTable,
    forwarding: &ForwardingState,
    ha_state: &BTreeMap<i32, HAGroupRuntime>,
    frame: &[u8],
    meta: UserspaceDpMeta,
    neighbors: &Arc<ShardedNeighborMap>,
    shared: &NodeShared,
) -> (BatchCounters, DebugPollCounters) {
    let meta_len = std::mem::size_of::<UserspaceDpMeta>();
    let frame_offset = 128;
    let meta_offset = frame_offset - meta_len;
    let meta_bytes = unsafe {
        std::slice::from_raw_parts((&meta as *const UserspaceDpMeta).cast::<u8>(), meta_len)
    };
    unsafe {
        binding.umem.area().slice_mut_unchecked(meta_offset, meta_len).expect("meta slice").copy_from_slice(meta_bytes);
        binding.umem.area().slice_mut_unchecked(frame_offset, frame.len()).expect("frame slice").copy_from_slice(frame);
    }
    binding.xsk.rx.push_for_test(XdpDesc { addr: frame_offset as u64, len: frame.len() as u32, options: 0 });
    let ident = binding.identity();
    let binding_lookup = WorkerBindingLookup::from_bindings(std::slice::from_ref(binding));
    let mirror_targets = MirrorTargetMap::default();
    let ike_exchanges = Arc::new(crate::afxdp::forwarding::IkeExchangeTable::new());
    let local_tunnel_deliveries = Arc::new(ArcSwap::from_pointee(BTreeMap::new()));
    let recent_exceptions = Arc::new(Mutex::new(ExceptionEventRing::new()));
    let last_resolution = Arc::new(Mutex::new(None));
    let peer_worker_commands = Vec::new();
    let rg_epochs = std::array::from_fn(|_| AtomicU32::new(0));
    let pptp = std::sync::Arc::new(crate::session::pptp_control::PptpControlInbox::default());
    let worker_ctx = WorkerContext {
        pptp_control: &pptp,
        ident: &ident,
        binding_lookup: &binding_lookup,
        mirror_targets: &mirror_targets,
        forwarding,
        ha_state,
        forwarding_active_rgs: &*EMPTY_FWD_ACTIVE_RGS_16217,
        dynamic_neighbors: neighbors,
        neighbor_resolver: None,
        shared_sessions: &shared.sessions,
        shared_nat_sessions: &shared.nat,
        shared_forward_wire_sessions: &shared.wire,
        shared_owner_rg_indexes: &shared.owner_idx,
        ike_exchanges: &ike_exchanges,
        slow_path: None,
        event_stream: None,
        local_tunnel_deliveries: &local_tunnel_deliveries,
        recent_exceptions: &recent_exceptions,
        last_resolution: &last_resolution,
        peer_worker_commands: &peer_worker_commands,
        worker_commands_by_id: crate::afxdp::empty_worker_commands_by_id(),
        rg_epochs: &rg_epochs,
        cold_path_sample_mask: 0xff,
    };
    let mut screen = ScreenState::new();
    let mut batch = BatchCounters::default();
    let mut dbg = DebugPollCounters::default();
    let mut telemetry = TelemetryContext { dbg: &mut dbg, counters: &mut batch };
    let area_handle = UmemAreaHandle::from_umem(&binding.umem);
    poll_binding_process_descriptor(
        binding,
        0,
        &area_handle,
        1,
        sessions,
        &mut screen,
        ValidationState { snapshot_installed: true, config_generation: 7, fib_generation: 9, neighbor_generation: 0 },
        123_000_000_000,
        123,
        0,
        0,
        -1,
        -1,
        &worker_ctx,
        &mut telemetry,
    );
    assert_eq!(dbg.rx, 1, "premise: the descriptor reached the poll body");
    (batch, dbg)
}

/// Live split shape, but the hop's error reaches the LAN owner on a DIFFERENT
/// worker than the one whose LAN queue saw the probe (RSS hashes the fabric
/// frame independently): that worker's own table is empty and only the node's
/// shared maps can match it. Live on tcp/udp this was the residual — the first
/// error of every new session (every UDP probe) default-denied `wan -> lan` on
/// node1 before HA sync landed. Proven here: worker A holds the #7770
/// `FabricPuntSeed` locally, the node's shared maps stay empty by design
/// (`SessionOrigin::is_transient_local_seed`), and worker B's matcher returns
/// NoMatch. Tracked by #18562; this cell is the acceptance test for it.
#[test]
#[ignore = "#18562: the #7770 punt seed is worker-local, so the first error on another worker returns NoMatch; un-ignore with the fix"]
fn split_rg_first_error_on_another_worker_reaches_lan_host_18174() {
    for (f, probe) in SPLIT_CASES {
        let label = format!("cross-worker split {f:?} {probe:?}");
        // node1, worker A: the LAN probe.
        let n1_fwd = build_forwarding_state(&peer_snapshot());
        let n1_neighbors = neighbors_with_client(&n1_fwd, f);
        let n1_shared = NodeShared::new();
        let mut n1_worker_a = SessionTable::new();
        let (frame, meta) = probe_frame(f, probe, 5);
        let mut lan = binding_on(LAN_IF);
        run_on_worker(&mut lan, &mut n1_worker_a, &n1_fwd, &ha(false, true), &frame, meta, &n1_neighbors, &n1_shared);
        assert_eq!(
            lan.scratch.scratch_forwards[0].decision.resolution.disposition,
            ForwardingDisposition::FabricRedirect,
            "{label}: premise: node1 hands the probe to the WAN owner"
        );
        // node0: fabric-ingress probe, then the hop's error (its own leg is
        // proven by the live-shape cell).
        let n0_fwd = build_forwarding_state(&nat_snapshot_with_fabric());
        let n0_neighbors = neighbors_with_client(&n0_fwd, f);
        let mut n0_sessions = SessionTable::new();
        let (pframe, pmeta) = fabric_probe_frame(f, probe);
        let mut fab0 = binding_on(FABRIC_IF);
        txn_run_descriptor_with_neighbors(&mut fab0, &mut n0_sessions, &n0_fwd, &ha(true, false), &pframe, pmeta, &n0_neighbors);
        let nat = fab0.scratch.scratch_forwards[0].decision.nat;
        let ident = if probe == Probe::Echo { PROBE_ECHO_ID } else { PROBE_UDP_SPORT };
        let xlate = (nat.rewrite_src.expect("premise: node0 source-NATs"), nat.rewrite_src_port.unwrap_or(ident));
        let fabric_frame = wan_owner_error_leg(&mut n0_sessions, &n0_fwd, &n0_neighbors, f, probe, xlate, &label);

        // node1, worker B: the reversed error, own table empty.
        let mut n1_worker_b = SessionTable::new();
        let emeta = meta_for(f, FABRIC_IF, 14, if f == Family::V4 { PROTO_ICMP } else { PROTO_ICMPV6 }, fabric_frame.len());
        let mut fab1 = binding_on(FABRIC_IF);
        let (batch, dbg) =
            run_on_worker(&mut fab1, &mut n1_worker_b, &n1_fwd, &ha(false, true), &fabric_frame, emeta, &n1_neighbors, &n1_shared);
        assert_eq!(batch.invalid_fabric_stamp_drops, 0, "{label}: stamp accepted");
        assert_eq!(dbg.policy_deny, 0, "{label}: the first error must not be default-denied on another worker");
        assert_eq!(fab1.scratch.scratch_forwards.len(), 1, "{label}: delivered to the LAN host from worker B");
        assert_delivered_to_lan_host(&fab1.scratch.scratch_forwards[0], f, probe, ErrKind::TimeExceeded, hop(f), &label);
    }
}


/// Defect 3 also moves interface source NAT: the SNAT matcher
/// (`forwarding/nat.rs`) translates an interface-mode rule to
/// `egress.primary_v4/v6` of the egress unit. On the RETH shape (base row with
/// only the per-node `169.254.<rg>.<node+1>/32` and fe80, unit row with the LAN
/// address) an interface SNAT toward that unit handed out the per-node
/// link-local — unroutable, and different on each node. Driven through the
/// matcher itself (the same `match_source_nat_for_flow` the #9956 scope cells
/// use) for a `wan -> lan` interface rule, v4 and v6. RED on revert of
/// `merge_undesignated_primary` (v4: 169.254.2.1, v6: fe80::bf72:16:2).
#[test]
fn interface_snat_toward_reth_unit_uses_unit_address_18174() {
    let mut snapshot = reth_base_row_snapshot();
    for (name, any) in [("wan-lan-snat", "0.0.0.0/0"), ("wan-lan-snat6", "::/0")] {
        snapshot.source_nat_rules.push(crate::SourceNATRuleSnapshot {
            name: name.to_string(),
            from_zone: "wan".to_string(),
            to_zone: "lan".to_string(),
            source_addresses: vec![any.to_string()],
            interface_mode: true,
            ..Default::default()
        });
    }
    let forwarding = build_forwarding_state(&snapshot);
    for f in [Family::V4, Family::V6] {
        let src = hop(f);
        let dst = client(f);
        let flow = SessionFlow {
            src_ip: src,
            dst_ip: dst,
            forward_key: SessionKey {
                addr_family: if f == Family::V4 { libc::AF_INET as u8 } else { libc::AF_INET6 as u8 },
                protocol: PROTO_UDP,
                src_ip: src,
                dst_ip: dst,
                src_port: 40001,
                dst_port: 33434,
                discriminator: Default::default(),
                routing_domain: 0,
            },
        };
        let nat = crate::afxdp::forwarding::match_source_nat_for_flow(
            &forwarding,
            WAN_IF,
            WAN_VID,
            None,
            "wan",
            "lan",
            LAN_IF,
            &flow,
        )
        .expect("premise: the wan -> lan interface rule matches");
        let want = match f {
            Family::V4 => IpAddr::V4(Ipv4Addr::new(10, 0, 61, 1)),
            Family::V6 => IpAddr::V6("2001:559:8585:ef00::1".parse().unwrap()),
        };
        assert_eq!(
            nat.rewrite_src,
            Some(want),
            "{f:?}: interface SNAT toward the RETH unit must use the unit address, not the per-node link-local"
        );
    }
}
