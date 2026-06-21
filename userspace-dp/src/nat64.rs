use crate::NAT64RuleSnapshot;
use crate::nat::NatDecision;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicUsize, Ordering};

/// NAT64 prefix configuration — one per `security nat nat64` rule.
#[derive(Debug)]
pub(crate) struct Nat64Prefix {
    /// First 96 bits of the NAT64 prefix (e.g. 64:ff9b::).
    pub(crate) prefix_bytes: [u8; 12],
    /// IPv4 source pool addresses for SNAT.
    pub(crate) pool_v4: Vec<Ipv4Addr>,
    /// Round-robin index for pool allocation (atomic for thread safety).
    pool_index: AtomicUsize,
}

impl Clone for Nat64Prefix {
    fn clone(&self) -> Self {
        Self {
            prefix_bytes: self.prefix_bytes,
            pool_v4: self.pool_v4.clone(),
            pool_index: AtomicUsize::new(self.pool_index.load(Ordering::Relaxed)),
        }
    }
}

/// Aggregated NAT64 state built from config snapshots.
#[derive(Clone, Debug, Default)]
pub(crate) struct Nat64State {
    pub(crate) prefixes: Vec<Nat64Prefix>,
    /// Mirrors the global `security nat natv6v4 no-v6-frag-header` option. When
    /// set, the IPv6->IPv4 translator emits a fragmentable (DF=0, non-atomic)
    /// IPv4 packet per RFC 7915 5.1 rather than the default DF=1 atomic framing.
    /// The option is configured once at the natv6v4 level; the Go side
    /// replicates it onto every NAT64 rule snapshot, so any rule carrying it
    /// enables it globally.
    pub(crate) no_v6_frag_header: bool,
}

/// Reverse-direction state stored with NAT64 sessions so IPv4 replies can be
/// translated back to IPv6.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Nat64ReverseInfo {
    pub(crate) orig_src_v6: Ipv6Addr,
    pub(crate) orig_dst_v6: Ipv6Addr,
}

/// Parse a NAT64 source-pool IPv4 address that may carry a canonical host
/// mask (`x.x.x.x/32`). Address-range expansion stamps `/32` on every pool
/// IP and `Ipv4Addr::from_str` rejects CIDR, so the mask is stripped before
/// parse (#2123). The pool holds exact host source addresses, so only a bare
/// address or the host mask (`/32`) is accepted; a non-host mask (`/24`) or
/// garbage suffix returns `None` and is filtered, surfacing a misconfigured
/// entry rather than silently coercing it to a host address.
fn parse_pool_v4(s: &str) -> Option<Ipv4Addr> {
    let mut parts = s.splitn(2, '/');
    let addr: Ipv4Addr = parts.next()?.parse().ok()?;
    match parts.next() {
        None => Some(addr),
        Some("32") => Some(addr),
        Some(_) => None,
    }
}

impl Nat64State {
    /// Build from config snapshot NAT64 rules.
    pub(crate) fn from_snapshots(snaps: &[NAT64RuleSnapshot]) -> Self {
        let mut prefixes = Vec::with_capacity(snaps.len());
        // The natv6v4 no-v6-frag-header option is global; the Go side stamps it
        // onto every rule snapshot. Treat the state as enabled if any rule
        // carries the flag (they all carry the same value in practice).
        let no_v6_frag_header = snaps.iter().any(|s| s.no_v6_frag_header);
        for snap in snaps {
            if snap.prefix.is_empty() {
                continue;
            }
            // Parse "64:ff9b::/96" — extract the prefix address and verify /96.
            let parts: Vec<&str> = snap.prefix.split('/').collect();
            let prefix_len: u8 = match parts.get(1).and_then(|s| s.parse().ok()) {
                Some(96) => 96,
                _ => continue, // Only /96 is supported.
            };
            let _ = prefix_len; // suppress warning; validated above
            let addr: Ipv6Addr = match parts[0].parse() {
                Ok(a) => a,
                Err(_) => continue,
            };
            let octets = addr.octets();
            let mut prefix_bytes = [0u8; 12];
            prefix_bytes.copy_from_slice(&octets[..12]);
            // Pool addresses may carry a canonical host mask: an
            // address-range source pool (`address A to B`) is expanded by
            // the Go compiler into per-IP `/32` entries (#2123), and
            // `Ipv4Addr::from_str` rejects CIDR notation. Strip the host mask
            // before parse so range-form pools are not silently dropped,
            // leaving pool_v4 empty and NAT64 forward translation
            // non-functional. A non-host mask (`/24`) or garbage suffix is
            // rejected rather than coerced to a host address, so a
            // misconfigured pool entry is surfaced (dropped) not silently
            // mistranslated.
            let pool_v4: Vec<Ipv4Addr> = snap
                .pool_addresses
                .iter()
                .filter_map(|s| parse_pool_v4(s))
                .collect();
            prefixes.push(Nat64Prefix {
                prefix_bytes,
                pool_v4,
                pool_index: AtomicUsize::new(0),
            });
        }
        Self {
            prefixes,
            no_v6_frag_header,
        }
    }

    /// Returns true if any NAT64 prefixes are configured.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn is_active(&self) -> bool {
        !self.prefixes.is_empty()
    }

    /// Check if an IPv6 destination matches any NAT64 prefix.
    /// Returns (prefix_index, extracted_ipv4_dest) on match.
    pub(crate) fn match_ipv6_dest(&self, dst: Ipv6Addr) -> Option<(usize, Ipv4Addr)> {
        let octets = dst.octets();
        for (idx, prefix) in self.prefixes.iter().enumerate() {
            if octets[..12] == prefix.prefix_bytes {
                let v4 = Ipv4Addr::new(octets[12], octets[13], octets[14], octets[15]);
                return Some((idx, v4));
            }
        }
        None
    }

    /// Round-robin allocation of an IPv4 source address from the pool.
    pub(crate) fn allocate_v4_source(&self, prefix_idx: usize) -> Option<Ipv4Addr> {
        let prefix = self.prefixes.get(prefix_idx)?;
        if prefix.pool_v4.is_empty() {
            return None;
        }
        let idx = prefix.pool_index.fetch_add(1, Ordering::Relaxed);
        let addr = prefix.pool_v4[idx % prefix.pool_v4.len()];
        Some(addr)
    }

    /// Create a NAT64 forward decision: IPv6 packet → IPv4 translated.
    /// `snat_v4` is the SNAT pool address, `dst_v4` is extracted from the prefix.
    pub(crate) fn forward_decision(snat_v4: Ipv4Addr, dst_v4: Ipv4Addr) -> NatDecision {
        NatDecision {
            rewrite_src: Some(IpAddr::V4(snat_v4)),
            rewrite_dst: Some(IpAddr::V4(dst_v4)),
            rewrite_src_port: None,
            rewrite_dst_port: None,
            nat64: true,
            nptv6: false,
        }
    }
}

// ---------------------------------------------------------------------------
// Packet translation functions
// ---------------------------------------------------------------------------

const ICMPV6_ECHO_REQUEST: u8 = 128;
const ICMPV6_ECHO_REPLY: u8 = 129;
const ICMP_ECHO_REQUEST: u8 = 8;
const ICMP_ECHO_REPLY: u8 = 0;
use crate::ip_proto::{PROTO_ICMP, PROTO_ICMPV6, PROTO_TCP, PROTO_UDP};
use std::sync::atomic::AtomicU32;

/// Process-global IPv4 Fragment Identification generator for translated,
/// *fragmentable* (DF=0) IPv6->IPv4 packets.
///
/// Whenever this translator emits a DF=0 (non-atomic) datagram it draws the
/// Identification from a per-translator generator, as RFC 7915 5.1 prescribes
/// for the no-Fragment-Header case. RFC 6864 4.1 then *requires* that a source
/// emitting non-atomic datagrams (DF=0) MUST NOT repeat the ID for a given
/// source/destination/protocol tuple within one Maximum Datagram Lifetime. A
/// constant ID (e.g. 0) violates that: if a downstream router fragments two
/// such datagrams between the same hosts, their fragments share an ID and
/// reassemble incorrectly. A monotonically incrementing counter is a
/// conforming, cheap generator. Atomic datagrams (DF=1) are exempt — RFC 6864
/// lets them carry any ID, so the default DF=1 path keeps ID=0.
///
/// Note this generator only governs the *Identification* value. WHEN DF is
/// cleared is a deliberate LOCAL policy (the operator-gated
/// `no-v6-frag-header` option), not the size-driven DF selection RFC 7915 5.1
/// itself describes (clear DF only when the translated IPv4 packet is <= 1260
/// bytes); see `translate_v6_to_v4`.
static NAT64_FRAG_ID: AtomicU32 = AtomicU32::new(0);

/// Return the next non-zero 16-bit Fragment Identification value for a
/// fragmentable translated datagram. The value cycles over the full non-zero
/// 16-bit space `1..=65535` with no two consecutive values equal WITHIN the
/// 65535-value cycle (the value after 65535 is 1, a jump, not a repeat).
/// Skipping 0 keeps the all-zero ID reserved (by convention) for the atomic
/// DF=1 path.
///
/// CAVEAT: at the outer `AtomicU32` counter wrap — once per 2^32 fragmentable
/// translations — two ADJACENT values do collide: `(2^32 - 1) % 65535 == 0`
/// and the wrapped `0 % 65535 == 0` both map to ID 1. This is deliberately
/// accepted (#2014 r3, Codex+AGY): IPv4's 16-bit Identification inherently
/// repeats every 65535 packets regardless, so one extra adjacent duplicate per
/// ~4.3e9 translations is operationally negligible and not worth replacing the
/// lock-free `fetch_add` with a CAS/modulo-65535 counter that would bounce a
/// cache line on this path.
fn next_frag_id() -> u16 {
    // Relaxed is sufficient: we only need a distinct, non-repeating sequence,
    // not ordering against other memory. Map the monotonic 32-bit counter onto
    // 1..=65535 via `(raw % 65535) + 1`. This is what makes the sequence
    // collision-free for RFC 6864 4.1: a naive `truncate-to-u16 then remap 0->1`
    // maps BOTH raw=0 and raw=1 to 1, so two back-to-back DF=0 translations
    // would share an Identification (and the same dup recurs at every 16-bit
    // wrap). `% 65535 + 1` instead yields 1,2,...,65535,1,2,... — every adjacent
    // pair differs.
    let raw = NAT64_FRAG_ID.fetch_add(1, Ordering::Relaxed);
    map_frag_id(raw)
}

/// Pure mapping from a monotonic 32-bit counter value to the 1..=65535
/// Identification space. Factored out of `next_frag_id` so the cycle invariant
/// (non-zero, in-range, no consecutive duplicates within the 65535-value cycle
/// — see the `next_frag_id` caveat for the accepted 2^32-boundary edge) can be
/// unit-tested deterministically without touching the process-global counter.
#[inline]
fn map_frag_id(raw: u32) -> u16 {
    (raw % 65535) as u16 + 1
}

/// Translate an IPv6 packet to IPv4 (forward direction: client→server).
///
/// Input: `packet` starts at L3 (IPv6 header), not Ethernet.
/// `snat_v4` = pool IPv4 source, `dst_v4` = extracted destination.
///
/// `no_v6_frag_header` mirrors the `security nat natv6v4 no-v6-frag-header`
/// option and selects between two DF policies. This is a deliberate LOCAL,
/// option-gated choice — NOT the literal RFC 7915 5.1 algorithm, which keys DF
/// off the *translated* IPv4 size (clear DF only when the result is <= 1260
/// bytes). The two modes are:
///   * `false` (the default): emit an *atomic* datagram — set the
///     Don't-Fragment (DF) flag and leave Identification at 0 (RFC 6864 4.1
///     permits any ID for an atomic datagram).
///   * `true`: clear DF so the packet stays fragmentable in transit (the
///     operator opts into this when downstream PMTU handling needs it).
///
/// Whichever mode clears DF, the Identification MUST stay consistent with it: a
/// DF=0 datagram is non-atomic, so RFC 6864 4.1 forbids a constant/repeated ID
/// and RFC 7915 5.1 prescribes drawing it from a per-translator generator
/// (`next_frag_id`) so a downstream fragmenter produces reassemblable fragments
/// rather than colliding on a constant ID.
///
/// Returns the translated IPv4 packet (L3 only, no Ethernet header).
pub(crate) fn translate_v6_to_v4(
    packet: &[u8],
    snat_v4: Ipv4Addr,
    dst_v4: Ipv4Addr,
    no_v6_frag_header: bool,
) -> Option<Vec<u8>> {
    if packet.len() < 40 {
        return None;
    }
    // IPv6 header fields.
    // Full 8-bit traffic class (DSCP[7:2] | ECN[1:0]) straddling bytes 0-1 of
    // the IPv6 header. Copied verbatim into the IPv4 TOS byte below per the
    // RFC 7915 §5 default (DSCP copied, ECN copied verbatim — NAT64 is
    // stateless translation, not RFC 6040 tunnel encapsulation).
    let traffic_class = ((packet[0] & 0x0f) << 4) | (packet[1] >> 4);
    let payload_len = u16::from_be_bytes([packet[4], packet[5]]) as usize;
    let next_header = packet[6];
    let hop_limit = packet[7];

    if hop_limit <= 1 {
        return None; // TTL expired
    }

    // Map protocol.
    let ipv4_protocol = match next_header {
        PROTO_ICMPV6 => PROTO_ICMP,
        PROTO_TCP | PROTO_UDP => next_header,
        _ => return None, // Unsupported protocol
    };

    let l4_payload = packet.get(40..40 + payload_len)?;
    let new_ttl = hop_limit - 1;

    // Total IPv4 packet length: 20 (header) + L4 payload.
    let ipv4_total_len = 20u16 + l4_payload.len() as u16;
    let mut out = vec![0u8; ipv4_total_len as usize];

    // Build IPv4 header.
    out[0] = 0x45; // version=4, IHL=5
    out[1] = traffic_class; // DSCP/ECN copied from IPv6 traffic class (RFC 7915 §5)
    out[2..4].copy_from_slice(&ipv4_total_len.to_be_bytes());
    // DF policy is the option-gated LOCAL choice (not the size-driven RFC 7915
    // 5.1 selection). Either way the flags+frag-offset word (bytes 6-7) and the
    // Identification field (bytes 4-5) must stay mutually consistent:
    //   * Default (DF=1, 0x4000): an *atomic* datagram (non-fragmentable).
    //     RFC 6864 4.1 permits any ID for an atomic datagram, so leave ID=0.
    //   * no-v6-frag-header (DF=0, 0x0000): a *fragmentable* (non-atomic)
    //     datagram. A non-atomic datagram MUST carry a non-zero Identification
    //     from a per-translator generator (RFC 7915 5.1 / RFC 6864 4.1) so a
    //     downstream fragmenter does not collide distinct datagrams on a
    //     constant ID. Pinning ID=0 here while clearing DF was the bug fixed in
    //     #2008 H16.
    let (frag_word, identification): (u16, u16) = if no_v6_frag_header {
        (0x0000, next_frag_id())
    } else {
        (0x4000, 0)
    };
    out[4..6].copy_from_slice(&identification.to_be_bytes()); // identification
    out[6..8].copy_from_slice(&frag_word.to_be_bytes()); // flags + frag offset
    out[8] = new_ttl;
    out[9] = ipv4_protocol;
    // Checksum = 0 (computed below)
    out[12..16].copy_from_slice(&snat_v4.octets());
    out[16..20].copy_from_slice(&dst_v4.octets());

    // Copy L4 payload.
    out[20..].copy_from_slice(l4_payload);

    // ICMP type/code translation.
    if next_header == PROTO_ICMPV6 {
        translate_icmpv6_to_icmpv4(&mut out[20..])?;
    }

    // Recompute L4 checksum (pseudo-header changes from IPv6 to IPv4).
    recompute_l4_checksum_after_nat64_v6_to_v4(&mut out, ipv4_protocol)?;

    // Compute IPv4 header checksum.
    out[10..12].copy_from_slice(&[0, 0]);
    let hdr_sum = checksum16(&out[..20]);
    out[10..12].copy_from_slice(&hdr_sum.to_be_bytes());

    Some(out)
}

/// Translate an IPv4 packet to IPv6 (reverse direction: server→client reply).
///
/// Input: `packet` starts at L3 (IPv4 header), not Ethernet.
/// `dst_v6` is the original IPv6 client source, `src_v6` is the NAT64 prefix
/// + original IPv4 server address (i.e. orig_dst_v6 for the reply src).
///
/// Returns the translated IPv6 packet (L3 only, no Ethernet header).
pub(crate) fn translate_v4_to_v6(
    packet: &[u8],
    src_v6: Ipv6Addr,
    dst_v6: Ipv6Addr,
) -> Option<Vec<u8>> {
    if packet.len() < 20 {
        return None;
    }
    let ihl = ((packet[0] & 0x0f) as usize) * 4;
    if ihl < 20 || packet.len() < ihl {
        return None;
    }
    // IPv4 TOS byte (DSCP[7:2] | ECN[1:0]) — copied verbatim into the IPv6
    // traffic class below per the RFC 7915 §4 default (DSCP copied, ECN copied
    // verbatim — NAT64 is stateless translation, not RFC 6040 encapsulation).
    let tos = packet[1];
    let ttl = packet[8];
    if ttl <= 1 {
        return None; // TTL expired
    }
    let protocol = packet[9];
    // Trim the L4 payload to the IPv4 Total Length field rather than the end
    // of the slice. The caller passes the whole L3-onward frame, which may
    // include Ethernet padding appended to reach the 60/64-byte minimum frame
    // size (common for TCP ACKs, DNS replies, short HTTP). Copying that padding
    // into the IPv6 packet inflates payload_len and poisons the recomputed L4
    // checksum, so the receiver drops the reply. This mirrors the forward path
    // (translate_v6_to_v4) which trims to the IPv6 payload_len field.
    //
    // total_len is attacker/driver-controlled, so clamp safely: a malformed
    // header could advertise a length shorter than the IPv4 header or longer
    // than the bytes we actually received.
    let ipv4_total_len = u16::from_be_bytes([packet[2], packet[3]]) as usize;
    if ipv4_total_len < ihl || ipv4_total_len > packet.len() {
        return None;
    }
    let l4_payload = packet.get(ihl..ipv4_total_len)?;

    // Map protocol.
    let next_header = match protocol {
        PROTO_ICMP => PROTO_ICMPV6,
        PROTO_TCP | PROTO_UDP => protocol,
        _ => return None,
    };

    let new_hop_limit = ttl - 1;
    let ipv6_payload_len = l4_payload.len() as u16;
    let ipv6_total_len = 40 + l4_payload.len();
    let mut out = vec![0u8; ipv6_total_len];

    // Build IPv6 header. The 8-bit traffic class straddles bytes 0-1: TC[7:4]
    // in the low nibble of byte 0 (alongside the version=6 nibble) and TC[3:0]
    // in the high nibble of byte 1 (alongside the flow-label high nibble, left
    // at 0). Mirrors apply_dscp_rewrite_to_frame in afxdp/frame/mod.rs:133-134.
    out[0] = 0x60 | (tos >> 4); // version=6 | TC[7:4]
    out[1] = (out[1] & 0x0f) | ((tos & 0x0f) << 4); // TC[3:0] | flow-label nibble (0)
    // flow label (bytes 2-3 and low nibble of byte 1) = 0
    out[4..6].copy_from_slice(&ipv6_payload_len.to_be_bytes());
    out[6] = next_header;
    out[7] = new_hop_limit;
    out[8..24].copy_from_slice(&src_v6.octets());
    out[24..40].copy_from_slice(&dst_v6.octets());

    // Copy L4 payload.
    out[40..].copy_from_slice(l4_payload);

    // ICMP type/code translation.
    if protocol == PROTO_ICMP {
        translate_icmpv4_to_icmpv6(&mut out[40..])?;
    }

    // Recompute L4 checksum (pseudo-header changes from IPv4 to IPv6).
    recompute_l4_checksum_after_nat64_v4_to_v6(&mut out, next_header)?;

    Some(out)
}

/// Translate ICMPv6 type/code to ICMPv4.
fn translate_icmpv6_to_icmpv4(icmp: &mut [u8]) -> Option<()> {
    if icmp.len() < 4 {
        return None;
    }
    let icmpv6_type = icmp[0];
    let (icmpv4_type, icmpv4_code) = match icmpv6_type {
        ICMPV6_ECHO_REQUEST => (ICMP_ECHO_REQUEST, 0u8),
        ICMPV6_ECHO_REPLY => (ICMP_ECHO_REPLY, 0u8),
        _ => return None, // Unsupported ICMPv6 type
    };
    icmp[0] = icmpv4_type;
    icmp[1] = icmpv4_code;
    // Checksum will be recomputed below.
    Some(())
}

/// Translate ICMPv4 type/code to ICMPv6.
fn translate_icmpv4_to_icmpv6(icmp: &mut [u8]) -> Option<()> {
    if icmp.len() < 4 {
        return None;
    }
    let icmpv4_type = icmp[0];
    let (icmpv6_type, icmpv6_code) = match icmpv4_type {
        ICMP_ECHO_REQUEST => (ICMPV6_ECHO_REQUEST, 0u8),
        ICMP_ECHO_REPLY => (ICMPV6_ECHO_REPLY, 0u8),
        _ => return None,
    };
    icmp[0] = icmpv6_type;
    icmp[1] = icmpv6_code;
    Some(())
}

/// Recompute L4 checksum after IPv6→IPv4 translation.
fn recompute_l4_checksum_after_nat64_v6_to_v4(packet: &mut [u8], protocol: u8) -> Option<()> {
    if packet.len() < 20 {
        return None;
    }
    // Read IP addresses before taking mutable borrow of L4 portion.
    let src = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
    let dst = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
    let l4 = &mut packet[20..];
    match protocol {
        PROTO_TCP => {
            if l4.len() < 20 {
                return None;
            }
            l4[16..18].copy_from_slice(&[0, 0]);
            let sum = checksum16_ipv4_pseudo(src, dst, protocol, l4);
            l4[16..18].copy_from_slice(&sum.to_be_bytes());
        }
        PROTO_UDP => {
            if l4.len() < 8 {
                return None;
            }
            l4[6..8].copy_from_slice(&[0, 0]);
            let sum = checksum16_ipv4_pseudo(src, dst, protocol, l4);
            l4[6..8].copy_from_slice(&sum.to_be_bytes());
        }
        PROTO_ICMP => {
            if l4.len() < 4 {
                return None;
            }
            // ICMPv4 does NOT use pseudo-header — checksum over ICMP message only.
            l4[2..4].copy_from_slice(&[0, 0]);
            let sum = checksum16(l4);
            l4[2..4].copy_from_slice(&sum.to_be_bytes());
        }
        _ => {}
    }
    Some(())
}

/// Recompute L4 checksum after IPv4→IPv6 translation.
fn recompute_l4_checksum_after_nat64_v4_to_v6(packet: &mut [u8], next_header: u8) -> Option<()> {
    let src = Ipv6Addr::from(<[u8; 16]>::try_from(packet.get(8..24)?).ok()?);
    let dst = Ipv6Addr::from(<[u8; 16]>::try_from(packet.get(24..40)?).ok()?);
    let l4 = &mut packet[40..];
    match next_header {
        PROTO_TCP => {
            if l4.len() < 20 {
                return None;
            }
            l4[16..18].copy_from_slice(&[0, 0]);
            let sum = checksum16_ipv6_pseudo(src, dst, next_header, l4);
            l4[16..18].copy_from_slice(&sum.to_be_bytes());
        }
        PROTO_UDP => {
            if l4.len() < 8 {
                return None;
            }
            l4[6..8].copy_from_slice(&[0, 0]);
            let sum = checksum16_ipv6_pseudo(src, dst, next_header, l4);
            // UDP over IPv6: zero checksum is illegal, but if it computes to 0
            // the standard says use 0xFFFF.
            let final_sum = if sum == 0 { 0xFFFF } else { sum };
            l4[6..8].copy_from_slice(&final_sum.to_be_bytes());
        }
        PROTO_ICMPV6 => {
            if l4.len() < 4 {
                return None;
            }
            // ICMPv6 DOES use pseudo-header.
            l4[2..4].copy_from_slice(&[0, 0]);
            let sum = checksum16_ipv6_pseudo(src, dst, next_header, l4);
            l4[2..4].copy_from_slice(&sum.to_be_bytes());
        }
        _ => {}
    }
    Some(())
}

// ---------------------------------------------------------------------------
// Checksum helpers
// ---------------------------------------------------------------------------

fn checksum16(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut chunks = data.chunks_exact(2);
    for chunk in &mut chunks {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    if let Some(&last) = chunks.remainder().first() {
        sum += (last as u32) << 8;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn checksum16_ipv4_pseudo(src: Ipv4Addr, dst: Ipv4Addr, protocol: u8, payload: &[u8]) -> u16 {
    let mut pseudo = Vec::with_capacity(12 + payload.len());
    pseudo.extend_from_slice(&src.octets());
    pseudo.extend_from_slice(&dst.octets());
    pseudo.push(0);
    pseudo.push(protocol);
    pseudo.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    pseudo.extend_from_slice(payload);
    checksum16(&pseudo)
}

fn checksum16_ipv6_pseudo(src: Ipv6Addr, dst: Ipv6Addr, next_header: u8, payload: &[u8]) -> u16 {
    let mut pseudo = Vec::with_capacity(40 + payload.len());
    pseudo.extend_from_slice(&src.octets());
    pseudo.extend_from_slice(&dst.octets());
    pseudo.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    pseudo.extend_from_slice(&[0, 0, 0, next_header]);
    pseudo.extend_from_slice(payload);
    checksum16(&pseudo)
}

// ---------------------------------------------------------------------------
// Frame building helpers for NAT64
// ---------------------------------------------------------------------------

/// Build a complete Ethernet + IPv4 frame from an Ethernet + IPv6 frame.
/// Used for forward NAT64 (IPv6→IPv4): frame shrinks by 20 bytes.
///
/// `eth_dst`, `eth_src` are the new L2 addresses for the forwarded frame.
/// `vlan_id` is inserted if > 0.
pub(crate) fn build_nat64_v6_to_v4_frame(
    frame: &[u8],
    snat_v4: Ipv4Addr,
    dst_v4: Ipv4Addr,
    eth_dst: [u8; 6],
    eth_src: [u8; 6],
    vlan_id: u16,
    no_v6_frag_header: bool,
) -> Option<Vec<u8>> {
    // Find L3 offset.
    let l3 = frame_l3_offset(frame)?;
    let ipv6_packet = frame.get(l3..)?;
    let ipv4_packet = translate_v6_to_v4(ipv6_packet, snat_v4, dst_v4, no_v6_frag_header)?;
    let eth_len = if vlan_id > 0 { 18 } else { 14 };
    let total = eth_len + ipv4_packet.len();
    let mut out = vec![0u8; total];
    write_eth_header(&mut out, eth_dst, eth_src, vlan_id, 0x0800)?;
    out[eth_len..].copy_from_slice(&ipv4_packet);
    Some(out)
}

/// Build a complete Ethernet + IPv6 frame from an Ethernet + IPv4 frame.
/// Used for reverse NAT64 (IPv4→IPv6): frame grows by 20 bytes.
///
/// `src_v6` and `dst_v6` are the restored IPv6 addresses.
pub(crate) fn build_nat64_v4_to_v6_frame(
    frame: &[u8],
    src_v6: Ipv6Addr,
    dst_v6: Ipv6Addr,
    eth_dst: [u8; 6],
    eth_src: [u8; 6],
    vlan_id: u16,
) -> Option<Vec<u8>> {
    let l3 = frame_l3_offset(frame)?;
    let ipv4_packet = frame.get(l3..)?;
    let ipv6_packet = translate_v4_to_v6(ipv4_packet, src_v6, dst_v6)?;
    let eth_len = if vlan_id > 0 { 18 } else { 14 };
    let total = eth_len + ipv6_packet.len();
    let mut out = vec![0u8; total];
    write_eth_header(&mut out, eth_dst, eth_src, vlan_id, 0x86dd)?;
    out[eth_len..].copy_from_slice(&ipv6_packet);
    Some(out)
}

/// Find the L3 offset by checking Ethernet type/VLAN.
fn frame_l3_offset(frame: &[u8]) -> Option<usize> {
    if frame.len() < 14 {
        return None;
    }
    let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
    if ethertype == 0x8100 {
        if frame.len() < 18 {
            return None;
        }
        Some(18)
    } else {
        Some(14)
    }
}

/// Write Ethernet header (with optional VLAN tag) into the beginning of `buf`.
fn write_eth_header(
    buf: &mut [u8],
    dst: [u8; 6],
    src: [u8; 6],
    vlan_id: u16,
    ether_type: u16,
) -> Option<()> {
    if vlan_id > 0 {
        if buf.len() < 18 {
            return None;
        }
        buf[..6].copy_from_slice(&dst);
        buf[6..12].copy_from_slice(&src);
        buf[12..14].copy_from_slice(&0x8100u16.to_be_bytes());
        buf[14..16].copy_from_slice(&vlan_id.to_be_bytes());
        buf[16..18].copy_from_slice(&ether_type.to_be_bytes());
    } else {
        if buf.len() < 14 {
            return None;
        }
        buf[..6].copy_from_slice(&dst);
        buf[6..12].copy_from_slice(&src);
        buf[12..14].copy_from_slice(&ether_type.to_be_bytes());
    }
    Some(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[path = "nat64_tests.rs"]
mod tests;
