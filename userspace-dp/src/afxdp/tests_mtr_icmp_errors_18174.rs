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
    BTreeMap::from([
        (
            1,
            HAGroupRuntime {
                active: rg1,
                watchdog_timestamp: 123,
                lease: HAGroupRuntime::active_lease_until(123, 123),
            },
        ),
        (
            2,
            HAGroupRuntime {
                active: rg2,
                watchdog_timestamp: 123,
                lease: HAGroupRuntime::active_lease_until(123, 123),
            },
        ),
    ])
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
    let forwarding = build_forwarding_state(&nat_snapshot());
    let f = Family::V4;
    let neighbors = neighbors_with_client(&forwarding, f);
    let mut sessions = SessionTable::new();
    let (qsrc, _qid) = run_probe(&mut sessions, &forwarding, &neighbors, f, Probe::Echo);
    assert_ne!(qsrc, client(f), "premise: the probe was source-NATed");
    // Outer dst = client, quote = the PRE-NAT probe, arriving on the WAN.
    let (frame, meta) = error_frame(f, Probe::Echo, ErrKind::TimeExceeded, hop(f), client(f), PROBE_ECHO_ID);
    let mut wan = binding_on(WAN_IF);
    let (_b, dbg) =
        txn_run_descriptor_with_neighbors(&mut wan, &mut sessions, &forwarding, &ha(true, true), &frame, meta, &neighbors);
    assert!(
        wan.scratch.scratch_forwards.is_empty(),
        "a pre-NAT quote off the fabric must not be admitted as RELATED \
         (RED when the fabric-ingress guard is dropped: the forward-NAT arm \
         matches it and the RELATED rule queues it to the LAN host)"
    );
    assert_eq!(wan.scratch.scratch_recycle.len(), 1, "the refused descriptor is recycled");
    assert_eq!(dbg.ha_inactive, 0, "the refusal is not an HA verdict (both RGs are active)");
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

/// Split RGs, end to end across BOTH nodes. The WAN (RG1) owner receives
/// the hop's Time Exceeded but the LAN (RG2) is owned by the peer, so the
/// reversed error must leave on the fabric with the WAN zone stamp; the
/// peer must then deliver that exact frame to the LAN host under its own
/// `wan -> lan` default deny. Pre-#18174 the first leg already passed (a
/// FabricRedirect is adjudicated on the peer) and the PEER's queued gate
/// default-denied the error, so the chain is RED on revert at the second
/// leg.
#[test]
fn split_rg_time_exceeded_crosses_fabric_and_reaches_lan_host_18174() {
    for (f, probe) in [
        (Family::V4, Probe::Echo),
        (Family::V4, Probe::Udp),
        (Family::V6, Probe::Echo),
        (Family::V6, Probe::Udp),
    ] {
        let label = format!("{f:?} {probe:?}");
        // Leg 1: the WAN-RG owner.
        let local_fwd = build_forwarding_state(&nat_snapshot_with_fabric());
        let local_neighbors = neighbors_with_client(&local_fwd, f);
        let mut local_sessions = SessionTable::new();
        let (qsrc, qid) = run_probe(&mut local_sessions, &local_fwd, &local_neighbors, f, probe);
        let (frame, meta) = error_frame(f, probe, ErrKind::TimeExceeded, hop(f), qsrc, qid);
        let mut wan = binding_on(WAN_IF);
        txn_run_descriptor_with_neighbors(
            &mut wan,
            &mut local_sessions,
            &local_fwd,
            &ha(true, false),
            &frame,
            meta,
            &local_neighbors,
        );
        assert_eq!(wan.scratch.scratch_forwards.len(), 1, "{label}: leg 1 must queue one prebuilt");
        let redirect = &wan.scratch.scratch_forwards[0];
        assert_eq!(
            redirect.decision.resolution.disposition,
            ForwardingDisposition::FabricRedirect,
            "{label}: the LAN RG is peer-owned, so the error rides the fabric"
        );
        assert_eq!(redirect.target_ifindex, FABRIC_IF, "{label}: leg 1 transmits on the fabric parent");
        let fabric_frame: Vec<u8> = match &redirect.frame {
            PendingForwardFrame::PrebuiltTransit { frame, .. } => frame.to_vec(),
            _ => panic!("{label}: fabric leg must carry the prebuilt reversed frame"),
        };
        let [_, _, zhi, zlo] = TEST_WAN_ZONE_ID.to_be_bytes();
        assert_eq!(
            &fabric_frame[6..12],
            &[0x02, 0xbf, 0x72, FABRIC_ZONE_MAC_MAGIC, zhi, zlo],
            "{label}: the fabric frame carries the WAN arrival-zone stamp"
        );

        // Leg 2: the LAN-RG owner (the peer) holds the synced session. It is
        // installed by the same real probe so its translation is the one the
        // first node quoted.
        let peer_fwd = build_forwarding_state(&peer_snapshot());
        let peer_neighbors = neighbors_with_client(&peer_fwd, f);
        let mut peer_sessions = SessionTable::new();
        let peer_xlate = run_probe(&mut peer_sessions, &peer_fwd, &peer_neighbors, f, probe);
        assert_eq!(peer_xlate, (qsrc, qid), "{label}: premise: both nodes hold the same translation");
        let l3 = 14;
        let peer_meta = meta_for(
            f,
            FABRIC_IF,
            l3,
            if f == Family::V4 { PROTO_ICMP } else { PROTO_ICMPV6 },
            fabric_frame.len(),
        );
        let mut fab = binding_on(FABRIC_IF);
        let before = peer_sessions.len();
        let (batch, dbg) = txn_run_descriptor_with_neighbors(
            &mut fab,
            &mut peer_sessions,
            &peer_fwd,
            &ha(false, true),
            &fabric_frame,
            peer_meta,
            &peer_neighbors,
        );
        assert_eq!(batch.invalid_fabric_stamp_drops, 0, "{label}: the peer accepts the WAN stamp");
        assert_eq!(dbg.policy_deny, 0, "{label}: the peer must not default-deny the RELATED error");
        assert_eq!(
            fab.scratch.scratch_forwards.len(),
            1,
            "{label}: the peer must deliver the fabric-carried error to the LAN host \
             (RED pre-#18174: the peer's queued gate default-denied it); \
             dst_mac_dropped={} unstamped={} validated={} recycled={} ha_inactive={}",
            batch.dst_mac_dropped,
            batch.unstamped_fabric_ingress_drops,
            batch.validated_packets,
            fab.scratch.scratch_recycle.len(),
            dbg.ha_inactive,
        );
        assert_delivered_to_lan_host(&fab.scratch.scratch_forwards[0], f, probe, ErrKind::TimeExceeded, hop(f), &label);
        assert_eq!(peer_sessions.len(), before, "{label}: no session from the error");
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

