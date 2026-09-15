use super::*;

pub(super) const FABRIC_INGRESS_FLAG: u8 = 0x80;

/// #2486: per-packet marker set by native GRE decap
/// (`try_native_gre_decap_from_frame`) so the forward-frame builder can
/// select the `security flow tcp-mss gre-in` clamp value for an inbound
/// GRE-decapped SYN. Without this marker the inner SYN was forwarded
/// unclamped — a silent full-MSS blackhole on the GRE return path.
/// Distinct bit from `FABRIC_INGRESS_FLAG` (0x80) and the TTL-skip
/// reuse of 0x80; 0x40 is otherwise unused in `meta_flags`.
/// Note: the retired-eBPF header `bpf/headers/xpf_common.h` defines
/// `META_FLAG_DNS_REPLY_FASTPATH = (1<<6) = 0x40` (the same numeric bit),
/// but it is DEAD — never written by the AF_XDP shim and never reaches
/// `UserspaceDpMeta.meta_flags` — so there is no runtime collision today;
/// a future revival of that header bit must pick a different value or
/// coordinate with this flag.
pub(super) const GRE_DECAP_INGRESS_FLAG: u8 = 0x40;

/// RFC 1812 §4.3.2.7 / RFC 792 / RFC 4443 §2.4 error-suppression gate
/// for LOCALLY GENERATED ICMP/ICMPv6 error messages (Time Exceeded,
/// Destination Unreachable). A router MUST NOT originate an ICMP error
/// in response to:
///
///   (a) an ICMP/ICMPv6 *error* message (prevents error loops /
///       amplification) — ICMPv4 types {3,4,5,11,12}, all ICMPv6 < 128
///       (the ICMPv6 error range). ICMP *query* types (echo, etc.) are
///       NOT suppressed.
///   (b) a non-first IP fragment (no transport context to quote/key —
///       RFC 1812 §4.3.2.7 "a fragment other than the first").
///   (c) a packet whose IP destination is multicast/broadcast (L3), or
///       whose L2 destination is broadcast/multicast — never reply to a
///       group/broadcast solicitation.
///   (d) a packet whose IP source is the unspecified address, loopback,
///       multicast, or (v4) broadcast — there is no legitimate unicast
///       host to send the error to.
///
/// Returns `true` when an ICMP error reply MAY be generated, `false`
/// when it MUST be suppressed (the caller fail-closes to a silent drop).
/// Hot-path: cheap field reads only, no allocation; the fragment walk is
/// the same bounded extension-header loop already used on every packet.
///
/// `protocol`/`icmp_type`/fragment status are read from the inbound
/// frame; the L4/ICMP-type read uses `meta.l4_offset`, which the shim
/// fills for ICMP, matching [`build_reject_icmp_unreachable`].
///
/// `forwarding` supplies the connected-route table for the #2411
/// directed-broadcast check (RFC 1812 §4.3.2.7): an IPv4 destination
/// that is the all-ones host address of a configured connected subnet
/// (e.g. `10.0.1.255` for `10.0.1.0/24`) is a subnet-directed broadcast
/// and must also suppress the error. This is a cold-path lookup only —
/// the gate runs solely when an error is about to be generated.
pub(super) fn can_generate_icmp_error_reply(
    frame: &[u8],
    meta: UserspaceDpMeta,
    forwarding: &ForwardingState,
) -> bool {
    let l3 = match meta.l3_offset {
        14 | 18 => meta.l3_offset as usize,
        _ => match frame_l3_offset(frame) {
            Some(off) => off,
            None => return false,
        },
    };
    let Some(packet) = frame.get(l3..) else {
        return false;
    };

    // (c) L2 destination: never reply to a broadcast/multicast frame.
    // The destination MAC is the first 6 frame bytes (present because
    // frame_l3_offset / the 14|18 match imply >= 14 bytes). Routes
    // through the shared #2325 predicate so the PTB and reject/TE paths
    // agree on the L2 group/broadcast test.
    if let Some(eth_dst) = frame.get(0..6)
        && let Ok(eth_dst) = <&[u8; 6]>::try_from(eth_dst)
        && l2_dst_is_group_or_broadcast(eth_dst)
    {
        return false;
    }

    // (b) non-first fragment: no transport header to quote/key.
    if is_non_first_fragment(packet, meta.addr_family) {
        return false;
    }

    match meta.addr_family as i32 {
        libc::AF_INET => {
            if packet.len() < 20 {
                return false;
            }
            // (d) bad source / (c) group or broadcast destination. Both
            // tests route through the shared predicates (#2367 source,
            // #2314 destination) so the PTB, reject, and Time Exceeded
            // paths agree on the disallowed source/destination sets.
            // #2411: also suppress for an IPv4 subnet-directed broadcast
            // DESTINATION (all-ones host of a connected prefix) —
            // invisible to the limited-broadcast test, needs the
            // connected subnet mask.
            // #2487: and the matching SOURCE check — a directed-broadcast
            // SOURCE would send the generated error to that directed
            // broadcast (Smurf backscatter); `source_is_invalid_for_icmp_error`
            // only catches the limited broadcast (255.255.255.255).
            if source_is_invalid_for_icmp_error(meta.addr_family, packet)
                || src_is_directed_broadcast(forwarding, packet)
                || dest_is_multicast_or_broadcast(meta.addr_family, packet)
                || dest_is_directed_broadcast(forwarding, packet)
            {
                return false;
            }
        }
        libc::AF_INET6 => {
            if packet.len() < 40 {
                return false;
            }
            // (d) bad source / (c) multicast destination. IPv6 has no
            // broadcast; multicast (ff00::/8) covers the group case. Both
            // tests route through the shared predicates (#2367 source,
            // #2314 destination).
            if source_is_invalid_for_icmp_error(meta.addr_family, packet)
                || dest_is_multicast_or_broadcast(meta.addr_family, packet)
            {
                return false;
            }
        }
        _ => return false,
    }

    // (a) never reply to an inbound ICMP/ICMPv6 error message.
    if matches!(meta.protocol, PROTO_ICMP | PROTO_ICMPV6) {
        let l4 = meta.l4_offset as usize;
        // A zero/invalid l4_offset means we could not locate the ICMP
        // header — fail closed rather than reading a stale type byte.
        if l4 <= l3 {
            return false;
        }
        let Some(&icmp_type) = frame.get(l4) else {
            return false;
        };
        if reject_icmp_reply_suppressed(meta.protocol, icmp_type) {
            return false;
        }
    }

    true
}

pub(super) fn packet_ttl_would_expire(frame: &[u8], meta: UserspaceDpMeta) -> Option<bool> {
    if (meta.meta_flags & FABRIC_INGRESS_FLAG) != 0 {
        return Some(false);
    }
    let l3 = match meta.l3_offset {
        14 | 18 => meta.l3_offset as usize,
        _ => frame_l3_offset(frame)?,
    };
    match meta.addr_family as i32 {
        libc::AF_INET => Some(*frame.get(l3 + 8)? <= 1),
        libc::AF_INET6 => Some(*frame.get(l3 + 7)? <= 1),
        _ => None,
    }
}

pub(super) fn build_local_time_exceeded_request(
    frame: &[u8],
    desc: XdpDesc,
    meta: UserspaceDpMeta,
    ingress_ident: &BindingIdentity,
    flow: &SessionFlow,
    forwarding: &ForwardingState,
    _dynamic_neighbors: &Arc<ShardedNeighborMap>,
    _ha_state: &BTreeMap<i32, HAGroupRuntime>,
    _now_secs: u64,
    counters: &mut BatchCounters,
) -> Option<PendingForwardRequest> {
    if !matches!(packet_ttl_would_expire(frame, meta), Some(true)) {
        return None;
    }
    // #2237: RFC 1812 §4.3.2.7 / RFC 4443 §2.4 suppression — do not
    // originate a Time Exceeded in reply to an ICMP error, a non-first
    // fragment, a group/broadcast destination, or a bogus source. The
    // sibling reject path enforces the same contract via this gate.
    if !can_generate_icmp_error_reply(frame, meta, forwarding) {
        return None;
    }
    // #6102: resolve the LOGICAL ingress unit ONCE. `forwarding.egress`, the
    // v4/v6 reply builders (each does `forwarding.egress.get(&ingress_ifindex)`),
    // and `classify_generated_reply` are ALL keyed by the logical unit ifindex;
    // `ingress_ident.ifindex` is the PHYSICAL AF_XDP bind port (#6046), which
    // for a VLAN sub-interface is the physical PARENT — not this unit. Keying
    // the build/classify on the physical index silently dropped the generated
    // ICMP on a tagged sub-if with no untagged parent unit (egress miss →
    // `?`-drop → traceroute `* * *` / PMTUD blackhole) and mis-classified it on
    // one with a parent (parent's CoS / DSCP-rewrite / output filter). This
    // mirrors the shipped reject (#3976) / SYN-cookie (#3035) precedent:
    // resolve logical for build+classify, keep the PHYSICAL index for the XSK
    // transmit (`target_ifindex`/`tx_ifindex`) and the #5856 per-zone rate-limit
    // bucket below. For an untagged port logical == physical, so this is a
    // literal no-op there.
    let logical_ingress = resolve_ingress_logical_ifindex(
        forwarding,
        ingress_ident.ifindex,
        meta.ingress_vlan_id,
    )
    .unwrap_or(ingress_ident.ifindex);
    // #5567: prove the reply FEASIBLE before touching the rate-limit token.
    // The egress lookup below and the v4/v6 builder each return None (a drop)
    // when the reply CANNOT be produced — no egress object for the ingress
    // unit, no primary address of the inbound family, or an unparseable
    // trigger. Building first makes the build itself the feasibility proof.
    let egress = forwarding.egress.get(&logical_ingress)?;
    let target_ifindex = if egress.bind_ifindex > 0 {
        egress.bind_ifindex
    } else {
        ingress_ident.ifindex
    };
    let prebuilt_frame = match meta.addr_family as i32 {
        libc::AF_INET => {
            build_local_time_exceeded_v4(frame, meta, logical_ingress, forwarding)
        }
        libc::AF_INET6 => {
            build_local_time_exceeded_v6(frame, meta, logical_ingress, forwarding)
        }
        _ => return None,
    }?;

    // #2472/#5567/#5856: per-reason, PER-INGRESS-ZONE token-bucket rate limit on
    // the LOCALLY-GENERATED Time Exceeded, consumed ONLY now that the reply is
    // proven feasible + built (above). A TTL=1 / hop-limit=1 flood (a routing
    // loop or a crafted low-TTL stream) would otherwise emit one generated ICMP
    // error per trigger packet, unbounded — a CPU/TX amplification + reflection
    // sink. On empty we drop the generated error and bump the observable
    // `TimeExceeded` rate-limited counter (inside the gate).
    //
    // #5856: the bucket is now PER INGRESS (from) ZONE, not a single global one
    // — resolved from the PHYSICAL ingress bind ifindex (`ingress_ident.ifindex`,
    // the fixed per-binding socket-bind port) via `ifindex_to_zone_id`. This is
    // deliberately DISTINCT from the #6102 `logical_ingress` that keys the v4/v6
    // reply build + #3026 output-classify: the rate-limit bucket stays PHYSICAL
    // (per-physical-port), while build/classify resolve the logical unit. Unlike
    // the #3618 reject path, this site does NOT call `resolve_ingress_logical_ifindex`:
    // a VLAN sub-interface resolves through its physical parent's
    // `ifindex_to_zone_id` entry (the parent inherits its first sub-interface's
    // zone), so VLAN sub-interfaces on the same physical port SHARE that port's
    // TE bucket rather than getting a per-sub-interface one. For an untagged port
    // physical == logical, so the zone is exact. Before #5856 one shared global TE
    // bucket let a low-TTL flood ingressing ONE physical port drain it and
    // suppress legitimate traceroute for EVERY other port/zone; the per-zone split
    // is still correct and strictly better (distinct physical ingress ports no
    // longer starve each other), just coarser than the reject path's
    // per-logical-unit granularity. An unzoned / unknown ingress interface (id 0)
    // falls back to the shared `TIME_EXCEEDED_FALLBACK_LIMITER` (never fail-open).
    //
    // #5567: the token was previously consumed BEFORE the egress lookup + build.
    // A flood of reply-eligible-but-UNBUILDABLE triggers on one interface
    // (missing egress object / missing family address / builder returns None)
    // then drained this shared per-reason bucket and starved buildable
    // PMTUD/traceroute diagnostics on ANOTHER interface — a cross-interface
    // false-deny DoS. Consuming after feasibility mirrors the reject path's
    // #3656 H11 build-before-consume ordering. The trigger-packet disposition is
    // unchanged: an unbuildable attempt still returns None (drop) here, exactly
    // as before, only without spending a token.
    let from_zone_id = forwarding
        .ifindex_to_zone_id
        .get(&ingress_ident.ifindex)
        .copied()
        .unwrap_or(0);
    let now_ns = monotonic_nanos();
    // #2238: classify the GENERATED ICMP/ICMPv6 error by its OWN egress
    // 5-tuple, NOT the triggering inbound packet's tuple/ingress. Pre-#2238
    // this called `resolve_cos_tx_selection_at(.., meta, flow.forward_key,
    // ..)` — the trigger — so an output filter matching the generated ICMP
    // tuple never fired, and an output filter matching the original TCP/UDP
    // flow could wrongly drop the ICMP error. A parse failure of our own
    // built bytes fails CLOSED (drop + dedicated counter, §6.2).
    //
    // #3026/#6102: classify on the LOGICAL egress ifindex (`logical_ingress`,
    // resolved above via `resolve_ingress_logical_ifindex`), NOT the physical
    // `ingress_ident.ifindex` and NOT `target_ifindex`. CoS interfaces
    // (forwarding_build/cos.rs) and output filters (filter/compiler.rs) are
    // keyed by the logical unit ifindex; on a VLAN subinterface both the
    // physical bind port (`ingress_ident.ifindex`) and `target_ifindex`
    // (`egress.bind_ifindex`) are the physical parent, so classifying by
    // either missed the subinterface's CoS queue / DSCP rewrite / output
    // filter (#6102: pre-fix this passed the physical `ingress_ident.ifindex`,
    // which the #3026 comment wrongly called "the LOGICAL egress ifindex").
    // `target_ifindex` (physical) is still used for the XSK transmit below. For
    // a non-VLAN port the logical and physical indexes coincide, so this is a
    // no-op there.
    let verdict =
        classify_generated_reply(forwarding, logical_ingress, &prebuilt_frame, now_ns);
    if verdict.drop {
        counters.touched = true;
        if verdict.parse_error {
            counters.generated_reply_classify_parse_errors += 1;
        } else {
            counters.time_exceeded_output_filter_drops += 1;
        }
        return None;
    }

    // #7174 M04: consume the rate-limit token LAST, once this reply is known to
    // be one we will actually send.
    //
    // This gate used to run before `classify_generated_reply` above, so a reply
    // an output filter was going to DISCARD still spent a token. The budget
    // exists to bound what this box EMITS, and a reply that never leaves emits
    // nothing — so charging for it lets a filtered stream starve the errors that
    // would have gone out, and does it invisibly: the drop is attributed to the
    // filter counter while the missing errors are attributed to the limiter.
    //
    // Same principle as the #3656 H11 "build-before-consume" ordering recorded
    // above, applied to the branch it did not cover — that change stopped an
    // UNBUILDABLE attempt spending a token, this stops an unsendable one. The
    // trigger-packet disposition is unchanged either way: a rate-limited attempt
    // still returns None.
    //
    // Ordering between the two drops is deliberate. A reply that is BOTH
    // filtered and over budget is attributed to the FILTER, because that
    // decision is deterministic and the limiter should only meter traffic that
    // would otherwise have gone out.
    // #9901 (F-074): key the limiter's per-source tier on the trigger's
    // source (`flow` is the pre-NAT session flow, so this is the true origin).
    if !allow_generated_error_zoned(forwarding, GeneratedErrorReason::TimeExceeded, from_zone_id, Some(flow.src_ip)) {
        counters.touched = true;
        return None;
    }

    Some(PendingForwardRequest {
        target_ifindex,
        target_binding_index: None,
        ingress_queue_id: ingress_ident.queue_id,
        desc,
        frame: PendingForwardFrame::Prebuilt(prebuilt_frame),
        meta: meta.into(),
        decision: SessionDecision {
            resolution: ForwardingResolution {
                disposition: ForwardingDisposition::ForwardCandidate,
                local_ifindex: 0,
                egress_ifindex: ingress_ident.ifindex,
                tx_ifindex: target_ifindex,
                tunnel_endpoint_id: 0,
                next_hop: None,
                neighbor_mac: None,
                src_mac: Some(egress.src_mac),
                tx_vlan_id: egress.vlan_id,
            },
            nat: NatDecision::default(),
        },
        apply_nat_on_fabric: false,
        expected_ports: None,
        flow_key: Some(flow.forward_key.clone()),
        nat64_reverse: None,
        cos_queue_id: verdict.cos_queue_id,
        dscp_rewrite: verdict.dscp_rewrite,
        cos_tx_selection_resolved: true,
        // #hb166 T-7: `filter_match_extra` removed (was write-only; the
        // deferred recompute that consumed it is deleted). TX selection is
        // already resolved above via `classify_generated_reply`.
    })
}

/// Parse the inbound L2 header for a reflected local-origin reply:
/// swapped MACs plus the full ingress 802.1Q/802.1ad tag (TPID + TCI:
/// PCP, DEI, VID). #2149: this previously returned only `vlan_id: u16`,
/// collapsing VID 0 to untagged and dropping PCP/DEI/TPID — so a
/// priority-tagged VLAN-0 frame (a real tag with VID 0 and PCP != 0,
/// used for 802.1p priority-only QoS) was reflected untagged with its
/// priority lost, and an 802.1ad (0x88a8) tag was lost entirely.
/// Returning a `TxVlanTag` preserves the full tag so the reflected
/// error carries the original priority and TPID.
fn ingress_reply_l2(frame: &[u8]) -> Option<([u8; 6], [u8; 6], TxVlanTag)> {
    if frame.len() < 14 {
        return None;
    }
    let dst_mac = <[u8; 6]>::try_from(frame.get(0..6)?).ok()?;
    let src_mac = <[u8; 6]>::try_from(frame.get(6..12)?).ok()?;
    let eth_proto = u16::from_be_bytes([frame[12], frame[13]]);
    let ingress_tag = if matches!(eth_proto, TPID_8021Q | TPID_8021AD) {
        let tci = u16::from_be_bytes([*frame.get(14)?, *frame.get(15)?]);
        // Preserve the full TCI (PCP | DEI | VID) and the original TPID.
        // `present: true` makes a priority-tagged VID-0 frame reflect
        // its tag; an all-zero TCI degrades to untagged via `emits()`.
        TxVlanTag {
            tpid: eth_proto,
            tci,
            present: true,
        }
    } else {
        TxVlanTag::NONE
    };
    Some((src_mac, dst_mac, ingress_tag))
}

pub(super) fn build_local_time_exceeded_v4(
    frame: &[u8],
    meta: UserspaceDpMeta,
    ingress_ifindex: i32,
    forwarding: &ForwardingState,
) -> Option<Vec<u8>> {
    // ICMPv4 Time Exceeded: type 11, code 0.
    build_local_icmp_error_v4(frame, meta, ingress_ifindex, forwarding, 11, 0)
}

/// Build a local-origin ICMPv4 error message of the given type/code,
/// reflecting L2 (MAC swap + ingress VLAN), sourcing the outer IP from
/// the ingress interface primary v4, and quoting the inbound IP header
/// plus the first 8 L4 bytes (RFC 792). Shared by the Time Exceeded
/// builder (type 11) and the #2089 reject Destination Unreachable
/// builder (type 3, code 13).
pub(super) fn build_local_icmp_error_v4(
    frame: &[u8],
    meta: UserspaceDpMeta,
    ingress_ifindex: i32,
    forwarding: &ForwardingState,
    icmp_type: u8,
    icmp_code: u8,
) -> Option<Vec<u8>> {
    let egress = forwarding.egress.get(&ingress_ifindex)?;
    let (dst_mac, fallback_src_mac, ingress_tag) = ingress_reply_l2(frame)?;
    let src_ip = egress.primary_v4?;
    let src_mac = egress.src_mac;
    let l3 = match meta.l3_offset {
        14 | 18 => meta.l3_offset as usize,
        _ => frame_l3_offset(frame)?,
    };
    let packet = frame.get(l3..)?;
    if packet.len() < 20 {
        return None;
    }
    let ihl = ((packet[0] & 0x0f) as usize) * 4;
    if ihl < 20 || packet.len() < ihl {
        return None;
    }
    let dst_ip = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
    let total_len = u16::from_be_bytes([packet[2], packet[3]]) as usize;
    let packet_len = total_len.min(packet.len());
    let quoted_len = packet_len.min(ihl.saturating_add(8));
    // #2149: reflect the inbound tag verbatim (TPID + PCP + DEI + VID)
    // when one was present, so a priority-tagged VLAN-0 inbound error
    // is reflected with its priority intact. Fall back to the egress
    // interface's configured VID (bare 802.1Q, PCP 0) when ingress was
    // untagged.
    let tag = if ingress_tag.emits() {
        ingress_tag
    } else {
        TxVlanTag::from(egress.vlan_id)
    };
    let eth_len = tag.header_len();
    let total_len = 20usize.checked_add(8)?.checked_add(quoted_len)?;
    let mut out = Vec::with_capacity(eth_len + total_len);
    write_eth_header_tagged(
        &mut out,
        dst_mac,
        if src_mac == [0; 6] {
            fallback_src_mac
        } else {
            src_mac
        },
        tag,
        0x0800,
    );
    // #1440: consolidated IPv4 outer builder. Sets DF=1 + computes
    // header checksum. Wire-byte change vs previous open-code:
    // ip[6..8] = 0x4000 (was 0x0000).
    let ip_start = out.len();
    out.resize(ip_start + 20, 0);
    write_ipv4_header(
        &mut out[ip_start..ip_start + 20],
        src_ip,
        dst_ip,
        PROTO_ICMP,
        /* tos */ 0,
        /* ttl */ 64,
        total_len as u16,
    )?;
    let icmp_start = out.len();
    out.extend_from_slice(&[icmp_type, icmp_code, 0, 0, 0, 0, 0, 0]);
    out.extend_from_slice(packet.get(..quoted_len)?);
    let icmp_sum = checksum16(&out[icmp_start..]);
    out[icmp_start + 2..icmp_start + 4].copy_from_slice(&icmp_sum.to_be_bytes());
    Some(out)
}

pub(super) fn build_local_time_exceeded_v6(
    frame: &[u8],
    meta: UserspaceDpMeta,
    ingress_ifindex: i32,
    forwarding: &ForwardingState,
) -> Option<Vec<u8>> {
    // ICMPv6 Time Exceeded: type 3, code 0.
    build_local_icmp_error_v6(frame, meta, ingress_ifindex, forwarding, 3, 0)
}

/// Build a local-origin ICMPv6 error message of the given type/code,
/// reflecting L2 (MAC swap + ingress VLAN), sourcing the outer IP from
/// the ingress interface primary v6, and quoting the inbound packet up
/// to the RFC 4443 minimum-MTU cap (1280 - 40 outer IPv6 - 8 ICMPv6 =
/// 1232 bytes, #2242), bounded by the invoking-packet length — so the
/// quote reaches the transport header even behind IPv6 extension
/// headers. The ICMPv6 checksum (`checksum16_ipv6`) is computed over
/// the pseudo-header and
/// is type-agnostic, so this is shared by the Time Exceeded builder
/// (type 3) and the #2089 reject Destination Unreachable builder
/// (type 1, code 1).
pub(super) fn build_local_icmp_error_v6(
    frame: &[u8],
    meta: UserspaceDpMeta,
    ingress_ifindex: i32,
    forwarding: &ForwardingState,
    icmp_type: u8,
    icmp_code: u8,
) -> Option<Vec<u8>> {
    let egress = forwarding.egress.get(&ingress_ifindex)?;
    let (dst_mac, fallback_src_mac, ingress_tag) = ingress_reply_l2(frame)?;
    let src_ip = egress.primary_v6?;
    let src_mac = egress.src_mac;
    let l3 = match meta.l3_offset {
        14 | 18 => meta.l3_offset as usize,
        _ => frame_l3_offset(frame)?,
    };
    let packet = frame.get(l3..)?;
    if packet.len() < 40 {
        return None;
    }
    let dst_ip = Ipv6Addr::from(<[u8; 16]>::try_from(packet.get(8..24)?).ok()?);
    let payload_len = u16::from_be_bytes([packet[4], packet[5]]) as usize;
    let packet_len = (40 + payload_len).min(packet.len());
    // #2242: RFC 4443 §2.4(c)/§3.1 — include as much of the invoking
    // packet as possible without the ICMPv6 error exceeding the IPv6
    // minimum MTU (1280). The total error datagram is
    //   40 (outer IPv6) + 8 (ICMPv6 header) + quoted_len <= 1280,
    // so quote up to 1280 - 40 - 8 = 1232 bytes. The previous fixed
    // 48-byte cap stopped just past the IPv6 base header and omitted the
    // transport header whenever extension headers pushed it past byte 48,
    // breaking PMTUD/traceroute diagnostics and receiver-side
    // error<->socket demux. Bounded by the actual invoking-packet length.
    const ICMP6_MIN_MTU: usize = 1280;
    const OUTER_V6_LEN: usize = 40;
    const ICMP6_HDR_LEN: usize = 8;
    const MAX_V6_QUOTE: usize = ICMP6_MIN_MTU - OUTER_V6_LEN - ICMP6_HDR_LEN; // 1232
    let quoted_len = packet_len.min(MAX_V6_QUOTE);
    // #2149: preserve the inbound tag (TPID + PCP + DEI + VID) on the
    // reflected error; fall back to the egress configured VID when
    // ingress was untagged. See the v4 builder for the rationale.
    let tag = if ingress_tag.emits() {
        ingress_tag
    } else {
        TxVlanTag::from(egress.vlan_id)
    };
    let eth_len = tag.header_len();
    let outer_payload_len = 8usize.checked_add(quoted_len)?;
    let mut out = Vec::with_capacity(eth_len + 40 + outer_payload_len);
    write_eth_header_tagged(
        &mut out,
        dst_mac,
        if src_mac == [0; 6] {
            fallback_src_mac
        } else {
            src_mac
        },
        tag,
        0x86dd,
    );
    // #1440: consolidated IPv6 outer builder.
    let ip_start = out.len();
    out.resize(ip_start + 40, 0);
    write_ipv6_header(
        &mut out[ip_start..ip_start + 40],
        src_ip,
        dst_ip,
        PROTO_ICMPV6,
        /* traffic_class */ 0,
        /* flow_label */ 0,
        /* hop_limit */ 64,
        outer_payload_len as u16,
    )?;
    let icmp_start = out.len();
    out.extend_from_slice(&[icmp_type, icmp_code, 0, 0, 0, 0, 0, 0]);
    out.extend_from_slice(packet.get(..quoted_len)?);
    let icmp_sum = checksum16_ipv6(src_ip, dst_ip, PROTO_ICMPV6, &out[icmp_start..]);
    out[icmp_start + 2..icmp_start + 4].copy_from_slice(&icmp_sum.to_be_bytes());
    Some(out)
}

/// #2089 reject-action ICMP-error suppression guard, matching the
/// retired eBPF `send_icmp_unreach_*` dispatch verbatim: never generate
/// a Destination Unreachable in reply to an inbound ICMP/ICMPv6 *error*
/// message (RFC 792 / RFC 4443). The reject guard suppresses ICMPv4 types
/// {3,4,5,11,12} and ALL ICMPv6 types < 128 (the ICMPv6 error range). ICMP
/// *query* types (echo request/reply, etc.) are NOT suppressed: a rejected
/// echo gets an unreachable, matching Junos.
///
/// #2393: the ICMPv4 set here now matches [`is_icmp_error`]
/// ({3,4,5,11,12}) — both follow the full RFC 792 quoted-datagram error
/// set. The two predicates remain separate because their ICMPv6 arms still
/// differ: this guard suppresses the entire ICMPv6 error range (`< 128`,
/// which includes types beyond the embedded-NAT set), while
/// [`is_icmp_error`] enumerates only the ICMPv6 errors that quote a
/// translatable inner packet (1/2/3/4).
///
/// Returns true when a reject reply MUST be suppressed for this inbound
/// ICMP/ICMPv6 message.
pub(super) fn reject_icmp_reply_suppressed(protocol: u8, icmp_type: u8) -> bool {
    match protocol {
        PROTO_ICMP => matches!(icmp_type, 3 | 4 | 5 | 11 | 12),
        PROTO_ICMPV6 => icmp_type < 128,
        _ => false,
    }
}

/// Build the #2089 policy-`reject` ICMP/ICMPv6 Destination Unreachable
/// (administratively prohibited) reply for a rejected non-TCP flow:
/// ICMPv4 type 3 code 13, or ICMPv6 type 1 code 1 — the codes the
/// retired eBPF reject path used ("matching Junos reject behavior").
///
/// Returns `None` (caller fail-closes to a silent drop) when the shared
/// [`can_generate_icmp_error_reply`] gate (#2237) suppresses the reply:
///   - the inbound is an ICMP/ICMPv6 *error* message
///     ([`reject_icmp_reply_suppressed`]),
///   - the inbound is a non-first fragment (no transport header to key),
///   - the inbound L2/L3 destination is broadcast/multicast, or its IP
///     source is unspecified/loopback/multicast/broadcast,
/// or when the ingress interface has no primary address of the inbound
/// family, or the frame is otherwise unparseable.
pub(super) fn build_reject_icmp_unreachable(
    frame: &[u8],
    meta: UserspaceDpMeta,
    ingress_ifindex: i32,
    forwarding: &ForwardingState,
    reject_message: crate::filter::RejectMessage,
) -> Option<Vec<u8>> {
    // #2237: shared RFC 1812 §4.3.2.7 / RFC 4443 §2.4 suppression gate.
    // Subsumes the prior inline non-first-fragment and inbound-ICMP-error
    // checks and additionally suppresses group/broadcast destinations and
    // bogus sources — the same contract the Time Exceeded path now uses.
    if !can_generate_icmp_error_reply(frame, meta, forwarding) {
        return None;
    }
    match meta.addr_family as i32 {
        // ICMPv4 Destination Unreachable (type 3). The CODE comes from the
        // term's `then reject <message-type>` (#6854); a term with no
        // message-type resolves to 13, "communication administratively
        // prohibited", which is what every reject carried before.
        libc::AF_INET => build_local_icmp_error_v4(
            frame,
            meta,
            ingress_ifindex,
            forwarding,
            3,
            reject_message.v4_code,
        ),
        // ICMPv6 Destination Unreachable (type 1). Most RFC 792 codes have no
        // ICMPv6 counterpart and deliberately resolve to 1 rather than an
        // invented code — see `RejectMessage`.
        libc::AF_INET6 => build_local_icmp_error_v6(
            frame,
            meta,
            ingress_ifindex,
            forwarding,
            1,
            reject_message.v6_code,
        ),
        _ => None,
    }
}

/// Returns true if the protocol and ICMP type indicate an ICMP error message
/// that quotes the offending datagram (an inner IP header + at least the
/// first 8 bytes of its transport header), which the embedded-ICMP-NAT
/// reversal path must translate back to the pre-NAT tuple.
///
/// #2393: the ICMPv4 arm matches the full RFC 792 error set that carries a
/// quoted datagram — Destination Unreachable (3), Source Quench (4),
/// Redirect (5), Time Exceeded (11), Parameter Problem (12) — so that a
/// NAT44 transit Redirect / Source Quench has its embedded inner addresses
/// rewritten just like types 3/11/12. All five share the same 8-byte ICMP
/// header layout (the type-specific word — Redirect's gateway address,
/// Source Quench / Dest-Unreachable's unused word — occupies bytes 4..8),
/// so the quoted IP header begins at `l4 + 8` for every one of them and the
/// type-agnostic embedded parser/builders need no per-type handling. This
/// now matches the broader [`reject_icmp_reply_suppressed`] set and Linux
/// netfilter conntrack's related-ICMP `icmp_error` (3/4/5/11/12).
///
/// Type 4 (Source Quench) is deprecated (RFC 6633) and type 5 (Redirect)
/// is normally link-scoped, so in practice a NATed transit instance is
/// rare; including them is a correctness/parity completion, not a hot path.
/// Note these two are still dropped (not mistranslated) on the NAT64
/// cross-family path — they have no IPv6 analogue (RFC 7915, see
/// `nat64.rs`); this set governs only same-family embedded-NAT reversal.
///
/// The ICMPv6 arm is the full ICMPv6 error range that carries a quoted
/// packet: Destination Unreachable (1), Packet Too Big (2), Time Exceeded
/// (3), Parameter Problem (4).
pub(super) fn is_icmp_error(protocol: u8, icmp_type: u8) -> bool {
    match protocol {
        PROTO_ICMP => matches!(icmp_type, 3 | 4 | 5 | 11 | 12),
        PROTO_ICMPV6 => matches!(icmp_type, 1 | 2 | 3 | 4),
        _ => false,
    }
}

#[cfg(test)]
#[path = "icmp_tests.rs"]
mod tests;
