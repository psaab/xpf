// HA session-sync reconstruction helpers (#6234 split out of the
// former monolithic `server/helpers.rs`).
//
// Rebuilds a `SyncedSessionEntry` from the peer's `SessionSyncRequest`
// wire fields: the forward `SessionKey`, the MAC/next-hop parsing, and
// the #4565 NAT64 cross-family reverse-translation reconstruction. Pure
// control-response reconstruction — no packet path, no allocation on the
// worker loop. Bodies byte-for-byte identical to the pre-split source.

use crate::afxdp::{self, SyncedSessionEntry, SYNCED_IMPORT_REFUSED_PREFIX};
use crate::ip_proto::PROTO_GRE;
use crate::protocol::SessionSyncRequest;
use crate::session::{TunnelDiscriminator, WireDiscriminator};

/// #4555/#6923: the second producer of a session key, and the one the packet
/// path cannot vouch for.
///
/// The AF_XDP shim's over-limit refusal rests on an invariant about the session
/// MAP, not about the packet in front of it: an IPv6 chain longer than
/// `MAX_EXT_HDRS` leaves the shim holding an extension-header type as
/// `protocol` with ports 0/0, and the refusal is that no such key can be
/// present, so the lookup misses and the packet is redirected to userspace.
/// `metadata_tuple_complete` (frame/inspect.rs) is what makes that true of the
/// PACKET path. This is the other way a key enters the map: a peer reconstructs
/// arbitrary `protocol`/`src_port`/`dst_port` off the wire, and the session map
/// is global — the shim probes one map, whoever wrote the row. A synced row for
/// an extension-header protocol therefore hands the shim a hit for exactly the
/// chain it refused, and a peer-synced `LocalDelivery` row publishes
/// `PASS_TO_KERNEL`, returning the frame to the kernel stack unfiltered.
///
/// Such a key is not producible by a correct peer — its own packet path refuses
/// to build one — so this rejects rather than sanitises, and the caller
/// surfaces the error on the control response instead of importing the row.
fn reject_unresolved_ipv6_ext_protocol(req: &SessionSyncRequest) -> Result<(), String> {
    if req.addr_family as i32 == libc::AF_INET6
        && crate::afxdp::ipv6_ext_header_is_traversable(req.protocol)
    {
        return Err(format!(
            "refusing synced session with unresolved IPv6 extension-header protocol {}: the walk \
             traverses it, so it is never an upper-layer protocol a peer resolved",
            req.protocol
        ));
    }
    Ok(())
}

/// What the reconstructed key is FOR (#7188).
///
/// The two uses want opposite answers when the peer could not state the
/// discriminator, and collapsing them is what made the aliasing silent:
///
/// * `Install` publishes an identity. Importing a protocol-47 record whose
///   discriminator the peer could not express means guessing which of two
///   tunnels it names — and `install.rs` opens with an unconditional
///   `remove_entry`, so the guess EVICTS the other tunnel. #7188 decision 2
///   says withhold: the peer misses the session and re-learns it.
/// * `Delete` retracts an identity. A key reconstructed without a
///   discriminator names the `None` class only, so at worst it matches
///   nothing — a delete can under-match but can never create or merge an
///   identity. Refusing it instead would turn every legacy peer's ordinary
///   GRE close into an error response for no gain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SyncedKeyIntent {
    Install,
    Delete,
}

/// Resolve the wire discriminator for a reconstructed key, or refuse.
///
/// The refusal carries [`SYNCED_IMPORT_REFUSED_PREFIX`] because it is the
/// CORRECT answer from a HEALTHY helper, not a transport failure: Go
/// discriminates on that token (`process_control.go`) and a transport failure
/// gates takeover-readiness (#5247), which a peer running an older build must
/// not do.
fn resolve_synced_discriminator(
    req: &SessionSyncRequest,
    intent: SyncedKeyIntent,
) -> Result<TunnelDiscriminator, String> {
    match TunnelDiscriminator::from_wire(req.tunnel_discriminator) {
        WireDiscriminator::Present(discriminator) => Ok(discriminator),
        // A delete never publishes an identity, so an unstatable one costs
        // nothing here: the key names the `None` class and under-matches.
        WireDiscriminator::Absent | WireDiscriminator::Unrecognized
            if intent == SyncedKeyIntent::Delete =>
        {
            Ok(TunnelDiscriminator::None)
        }
        // A peer that predates the field. Correct for every protocol that has
        // no discriminator concept — that is what `None` means and it is
        // bit-identical to the pre-#7188 import — but for GRE it means the peer
        // cannot tell two same-endpoint RFC 2890 tunnels apart, so importing
        // its record would alias them here.
        WireDiscriminator::Absent => {
            if req.protocol == PROTO_GRE {
                Err(format!(
                    "{SYNCED_IMPORT_REFUSED_PREFIX}gre-discriminator-not-carried"
                ))
            } else {
                Ok(TunnelDiscriminator::None)
            }
        }
        // A class this build does not define. Coercing it into a known class
        // would publish an identity we cannot reproduce, for ANY protocol.
        WireDiscriminator::Unrecognized => Err(format!(
            "{SYNCED_IMPORT_REFUSED_PREFIX}tunnel-discriminator-unrecognized"
        )),
    }
}

/// #7160 (#2387): `routing_domain` is resolved by the CALLER
/// (`Coordinator::synced_routing_domain`) from the #7095 cluster-stable
/// ingress identity this request already carries, not read off a wire field.
/// See that function for why the number is derived rather than sent.
///
/// #7188: `intent` is the OTHER identity axis, and it is NOT derived — it says
/// what the key is FOR, because install and delete want opposite answers when
/// the peer could not state the discriminator. See `SyncedKeyIntent`.
/// #7699: verify a synced PPTP record carries the association its handle was
/// derived from, and that the two nodes agree on the derivation.
///
/// Returns `Ok(Some(call))` for a verified PPTP record, `Ok(None)` for any
/// non-PPTP session, and an `Err` carrying [`SYNCED_IMPORT_REFUSED_PREFIX`] —
/// a WITHHOLD, not a transport failure — in two cases:
///
///   * **the pair was not carried.** An older peer sends the handle (or, more
///     precisely, cannot send it either) without the call ids. Importing the
///     session would leave this node holding a record whose handle it cannot
///     reproduce from a packet, so every PPTP packet for that call resolves
///     unassociated while a session for it sits in the table. Absent is better
///     than present-and-unusable.
///   * **the handle does not match the pair.** Both nodes derive the handle
///     with the same pure function, so a mismatch means they disagree about the
///     derivation — a version skew or a corrupted record. Importing it would
///     install a session under an identity this node will never compute.
///
/// Deliberately NOT a repair: recomputing the handle locally and importing
/// under it would make the two nodes' tables disagree silently, which is the
/// failure this check exists to catch.
pub(crate) fn verify_synced_pptp_association(
    req: &SessionSyncRequest,
    discriminator: TunnelDiscriminator,
    src_ip: std::net::IpAddr,
    dst_ip: std::net::IpAddr,
) -> Result<Option<crate::session::pptp::PptpCall>, String> {
    let TunnelDiscriminator::Pptp(handle) = discriminator else {
        return Ok(None);
    };
    let Some(call) = crate::session::pptp::PptpCall::from_wire_call_ids(
        req.pptp_call_ids,
        src_ip,
        dst_ip,
    ) else {
        return Err(format!(
            "{SYNCED_IMPORT_REFUSED_PREFIX}pptp-call-ids-not-carried"
        ));
    };
    if call.handle() != handle {
        return Err(format!(
            "{SYNCED_IMPORT_REFUSED_PREFIX}pptp-handle-mismatch"
        ));
    }
    Ok(Some(call))
}

pub(crate) fn build_synced_session_key(
    req: &SessionSyncRequest,
    routing_domain: u32,
    intent: SyncedKeyIntent,
) -> Result<crate::session::SessionKey, String> {
    reject_unresolved_ipv6_ext_protocol(req)?;
    let discriminator = resolve_synced_discriminator(req, intent)?;
    let src_ip = req
        .src_ip
        .parse()
        .map_err(|e| format!("parse src_ip {}: {e}", req.src_ip))?;
    let dst_ip = req
        .dst_ip
        .parse()
        .map_err(|e| format!("parse dst_ip {}: {e}", req.dst_ip))?;
    // #7699: a PPTP handle is DERIVED from the learned call-id pair, so a
    // record carrying the handle without the pair is one the receiver can never
    // match a packet against — it cannot build the association its workers
    // resolve through. Withhold rather than downgrade, the #7188 discipline.
    verify_synced_pptp_association(req, discriminator, src_ip, dst_ip)?;
    Ok(crate::session::SessionKey {
        addr_family: req.addr_family,
        protocol: req.protocol,
        src_ip,
        dst_ip,
        src_port: req.src_port,
        dst_port: req.dst_port,
        // #7188: NOT `Default::default()`. Default is `None` — the "no
        // discriminator concept for this protocol" class — so every synced GRE
        // session, keyed or not, arrived in the class reserved for non-tunnel
        // protocols and two keyed tunnels between one endpoint pair rebuilt to
        // ONE key here.
        discriminator,
        routing_domain,
    })
}

/// #4565: reconstruct the NAT64 cross-family reverse-translation state for a
/// peer-PROMOTED synced session from the forward v6 `key` + the wire-carried
/// translated pool source `nat64_snat_v4`.
///
/// Returns `Some((snat_v4, dst_v4, Nat64ReverseInfo))` when `snat_v4_str` names
/// a valid IPv4 pool source AND the forward key is IPv6 (a NAT64 forward flow is
/// always keyed on the original IPv6 5-tuple); `None` otherwise (not NAT64 / old
/// peer / malformed). The three outputs are exactly the reverse BIB the standby
/// cannot otherwise rebuild:
///   * `snat_v4`  — the translated pool source (the one wire-carried datum).
///   * `dst_v4`   — the forward v4 destination, the RFC 6052 /96-embedded low 32
///     bits of the synthetic v6 destination `key.dst_ip` (the codebase only
///     supports `<prefix>/96`, so the embedded v4 is the trailing 4 octets).
///   * `Nat64ReverseInfo { orig_src_v6, orig_dst_v6 }` — the original v6 client
///     source and synthetic v6 destination, which ARE the forward key's src/dst.
fn build_nat64_reverse_rebuild(
    key: &crate::session::SessionKey,
    snat_v4_str: &str,
) -> Option<(
    std::net::Ipv4Addr,
    std::net::Ipv4Addr,
    crate::nat64::Nat64ReverseInfo,
)> {
    if snat_v4_str.is_empty() {
        return None;
    }
    let snat_v4: std::net::Ipv4Addr = snat_v4_str.parse().ok()?;
    // A NAT64 forward session is keyed on the original IPv6 5-tuple.
    let (std::net::IpAddr::V6(orig_src_v6), std::net::IpAddr::V6(orig_dst_v6)) =
        (key.src_ip, key.dst_ip)
    else {
        return None;
    };
    // RFC 6052 /96: the embedded IPv4 destination is the low 32 bits of the
    // synthetic IPv6 destination.
    let dst_octets = orig_dst_v6.octets();
    let dst_v4 = std::net::Ipv4Addr::new(
        dst_octets[12],
        dst_octets[13],
        dst_octets[14],
        dst_octets[15],
    );
    Some((
        snat_v4,
        dst_v4,
        crate::nat64::Nat64ReverseInfo {
            orig_src_v6,
            orig_dst_v6,
        },
    ))
}

pub(crate) fn build_synced_session_entry(
    req: &SessionSyncRequest,
    zone_name_to_id: &rustc_hash::FxHashMap<String, u16>,
    routing_domain: u32,
) -> Result<SyncedSessionEntry, String> {
    let key = build_synced_session_key(req, routing_domain, SyncedKeyIntent::Install)?;
    let next_hop = if req.next_hop.is_empty() {
        None
    } else {
        Some(
            req.next_hop
                .parse()
                .map_err(|e| format!("parse next_hop {}: {e}", req.next_hop))?,
        )
    };
    let neighbor_mac = parse_session_sync_mac(&req.neighbor_mac)
        .map_err(|e| format!("parse neighbor_mac {}: {e}", req.neighbor_mac))?;
    let src_mac = parse_session_sync_mac(&req.src_mac)
        .map_err(|e| format!("parse src_mac {}: {e}", req.src_mac))?;
    let tx_ifindex = if req.tunnel_endpoint_id != 0 {
        req.tx_ifindex.max(0)
    } else if req.tx_ifindex > 0 {
        req.tx_ifindex
    } else {
        req.egress_ifindex
    };
    let nat_src = if req.nat_src_ip.is_empty() {
        None
    } else {
        Some(
            req.nat_src_ip
                .parse()
                .map_err(|e| format!("parse nat_src_ip {}: {e}", req.nat_src_ip))?,
        )
    };
    let nat_dst = if req.nat_dst_ip.is_empty() {
        None
    } else {
        Some(
            req.nat_dst_ip
                .parse()
                .map_err(|e| format!("parse nat_dst_ip {}: {e}", req.nat_dst_ip))?,
        )
    };
    let nat_src_port = if req.nat_src_port != 0 {
        Some(req.nat_src_port)
    } else {
        None
    };
    let nat_dst_port = if req.nat_dst_port != 0 {
        Some(req.nat_dst_port)
    } else {
        None
    };
    // #4565: rebuild a peer-PROMOTED NAT64 session's cross-family NAT decision +
    // reverse (v4->v6) BIB. A non-empty `nat64_snat_v4` marks a NAT64 forward
    // session (keyed on the ORIGINAL IPv6 5-tuple = `key.src_ip`/`key.dst_ip`).
    // The generic `nat_src`/`nat_dst` fields cannot carry a v4 pool source in a
    // v6 session's slot unambiguously, so on this path they are OVERRIDDEN by
    // the authoritative reconstruction:
    //   * `nat64 = true`             -> tx dispatch routes to the NAT64 frame
    //                                   builder and #4564's standby reserve arms.
    //   * `rewrite_src = snat_v4`    -> the translated pool source (wire field).
    //   * `rewrite_dst = dst_v4`     -> the /96-embedded low 32 of the v6 dst.
    //   * `rewrite_src_port`         -> the translated port (already synced via
    //                                   `nat_src_port`, kept below).
    //   * `nat64_reverse`            -> the original v6 src/dst (= the key), which
    //                                   `build_nat64_forwarded_frame` needs on the
    //                                   reverse path, and which the synthesized
    //                                   reverse companion inherits.
    // `reverse_session_key` then derives the reverse companion's v4 address
    // family + `(dst_v4 -> snat_v4)` tuple from this decision, so the server's
    // v4 reply matches after failover. When the field is empty (not NAT64, or an
    // old peer), the generic decision + `None` reverse are used, bit-identical
    // to pre-#4565 (rolling-upgrade safe).
    let nat64_rebuild = build_nat64_reverse_rebuild(&key, &req.nat64_snat_v4);
    let (nat64_flag, rewrite_src, rewrite_dst, nat64_reverse) = match nat64_rebuild {
        Some((snat_v4, dst_v4, reverse_info)) => (
            true,
            Some(std::net::IpAddr::V4(snat_v4)),
            Some(std::net::IpAddr::V4(dst_v4)),
            Some(reverse_info),
        ),
        None => (false, nat_src, nat_dst, None),
    };
    Ok(SyncedSessionEntry {
        protocol: req.protocol,
        tcp_flags: 0,
        // #9412: the owning node's close class. Applied on install, where the
        // copy gets its close bits and its close window.
        tcp_close_class: req.tcp_close_class,
        key,
        decision: crate::session::SessionDecision {
            resolution: afxdp::ForwardingResolution {
                disposition: if req.egress_ifindex > 0
                    || req.tx_ifindex > 0
                    || req.tunnel_endpoint_id != 0
                {
                    afxdp::ForwardingDisposition::ForwardCandidate
                } else {
                    afxdp::ForwardingDisposition::NoRoute
                },
                local_ifindex: 0,
                egress_ifindex: req.egress_ifindex,
                tx_ifindex,
                tunnel_endpoint_id: req.tunnel_endpoint_id,
                next_hop,
                neighbor_mac,
                src_mac,
                tx_vlan_id: req.tx_vlan_id,
            },
            nat: crate::nat::NatDecision {
                rewrite_src,
                rewrite_dst,
                rewrite_src_port: nat_src_port,
                rewrite_dst_port: nat_dst_port,
                // #4565: set the NAT64 cross-family bit for a promoted NAT64
                // session so tx dispatch reverse-translates and the reverse key
                // derives its v4 address family. `nptv6` stays default (false).
                nat64: nat64_flag,
                ..crate::nat::NatDecision::default()
            },
        },
        metadata: crate::session::SessionMetadata {
            // #4983/#7095: a peer-imported session now carries an ingress
            // identity again -- but a LOCALLY RESOLVED one.
            //
            // #6928 imported 0 here on purpose: an ifindex is NODE-LOCAL, so
            // node 0's `ge-0-0-1` and node 1's `ge-7-0-1` are different numbers
            // for one logical RETH member, and shipping the originating node's
            // value would name a different NIC here -- confidently wrong, which
            // is worse than the zone approximation.
            //
            // #7095 does not ship the ifindex. The sender ships a FOLD of the
            // reth-relative name (`reth0.50`), which both chassis agree on by
            // construction, and the Go side resolves that fold against THIS
            // node's config and ifindex table before building this request. So
            // these are this node's own numbers for the interface the peer
            // named, and storing them is safe.
            //
            // Zero still arrives and still means unknown: a legacy peer sends
            // no wire field, a session whose interface has no cluster-stable
            // name folds to 0, and a fabric-redirected session records no
            // identity at all (#7096, because the fabric stamp carries a u16
            // zone id and nothing else). All three keep the pre-#7095
            // behaviour -- the Go consumer falls back to the zone
            // approximation.
            //
            // Note this install is `is_reverse: req.is_reverse`, so a FORWARD
            // peer session lands here too -- see the scope note in
            // pkg/dataplane/types.go.
            ingress_ifindex: if req.ingress_ifindex > 0 {
                req.ingress_ifindex as u32
            } else {
                0
            },
            ingress_vlan_id: req.ingress_vlan_id,
            // #919: prefer the wire u16 IDs when populated; fall back
            // to name lookup for older peers that only sent strings.
            ingress_zone: if req.ingress_zone_id != 0 {
                req.ingress_zone_id
            } else {
                zone_name_to_id
                    .get(req.ingress_zone.as_str())
                    .copied()
                    .unwrap_or(0)
            },
            egress_zone: if req.egress_zone_id != 0 {
                req.egress_zone_id
            } else {
                zone_name_to_id
                    .get(req.egress_zone.as_str())
                    .copied()
                    .unwrap_or(0)
            },
            owner_rg_id: req.owner_rg_id,
            fabric_ingress: req.fabric_ingress,
            is_reverse: req.is_reverse,
            // #4565: the original v6 src/dst for the reverse (v4->v6) translation
            // of a peer-PROMOTED NAT64 session (Some only when nat64_snat_v4 was
            // carried). The synthesized reverse companion inherits this via
            // build_reverse_session_from_forward_match.
            nat64_reverse,
            // #2785: the per-policy `then log` selection is now carried on
            // the HA session-sync wire (open-frame flags bits 1<<3/1<<4 ->
            // SessionSyncRequest.log_session_{init,close}). A synced session
            // therefore emits the same RT_FLOW SESSION_CREATE/CLOSE records
            // after failover as the node that locally admitted it. An old
            // peer that omits the fields decodes to false (no per-policy
            // log), bit-identical to pre-#2785 behavior.
            log_session_init: req.log_session_init,
            log_session_close: req.log_session_close,
            // #3301: the admitting policy ID now rides the cross-node HA
            // session-sync wire (SessionSyncRequest.policy_id). A peer-PROMOTED
            // session's live-session row / RT_FLOW records resolve the
            // admitting policy that #3056 stamps in-process, instead of the `0`
            // sentinel (which the Go side renders as the FIRST configured
            // policy — a wrong attribution). An old peer omits the field =>
            // serde(default) 0, the legitimate "unattributed" value,
            // bit-identical to pre-#3301 (rolling-upgrade safe).
            policy_id: req.policy_id,
            // #3301: the per-application idle timeout now rides the wire in
            // SECONDS (SessionSyncRequest.inactivity_timeout). Convert to ns via
            // the shared helper (0 => None => use the global per-protocol
            // timeout, the pre-#3301 behavior). A short-timeout app session
            // therefore ages out on the app's value after failover without a
            // real-traffic refresh (#3227).
            inactivity_timeout_ns: crate::session::app_inactivity_timeout_ns(
                if req.inactivity_timeout != 0 {
                    Some(req.inactivity_timeout)
                } else {
                    None
                },
            ),
            // #3301: the per-rule hit-counter handle now rides the wire
            // (SessionSyncRequest.policy_counter_idx). HA requires identical
            // config on both nodes, so the same #3073 idx resolves the same
            // rule on the peer; the established fast path then increments the
            // correct policy hit counter on every forwarded packet after
            // failover. An old peer omits the field => serde(default) 0 ("no
            // per-rule counter"), the pre-#3301 behavior (rolling-upgrade safe).
            policy_counter_idx: req.policy_counter_idx,
            policy_counter: None,
        },
        origin: crate::session::SessionOrigin::SyncImport,
        // #2170: carry the peer's install generation onto the helper entry.
        generation: req.generation,
        // #5212: carry the ORIGINATING node's stable RT_FLOW session id off the
        // wire so this peer-synced session ADOPTS the peer's id instead of
        // minting a fresh node-local one on import (`upsert_synced_with_origin`).
        // A session that opens on the primary and closes here after a failover
        // therefore emits SESSION_CREATE/CLOSE RT_FLOW records under ONE id
        // across both nodes. An old peer omits the field => serde(default) 0,
        // which falls back to `alloc_session_id()` (rolling-upgrade safe).
        session_id: req.session_id,
    })
}

pub(crate) fn parse_session_sync_mac(value: &str) -> Result<Option<[u8; 6]>, String> {
    if value.is_empty() {
        return Ok(None);
    }
    let mut out = [0u8; 6];
    let mut count = 0usize;
    for (i, part) in value.split(':').enumerate() {
        if i >= out.len() {
            return Err("too many octets".to_string());
        }
        out[i] = u8::from_str_radix(part, 16).map_err(|e| e.to_string())?;
        count += 1;
    }
    if count != out.len() {
        return Err("expected 6 octets".to_string());
    }
    Ok(Some(out))
}
