//! HA session-sync delta frames (SessionOpen / SessionClose) and the
//! close-flags helper.
//!
//! Split out of the former single-file `codec.rs` (#4651). These frames are
//! the correctness-critical deltas that mutate peer session state on failover.

use crate::afxdp::ForwardingDisposition;
use crate::session::{
    SessionDecision, SessionDelta, SessionKey, SessionMetadata, SessionSyncAttribution,
    nat64_snat_v4_octets,
};
use rustc_hash::FxHashMap;

use super::EventFrame;
use super::wire::*;

impl EventFrame {
    /// Encode a SessionOpen (type 1) or SessionUpdate (type 3) frame.
    pub(crate) fn encode_session_open(
        seq: u64,
        key: &SessionKey,
        decision: &SessionDecision,
        metadata: &SessionMetadata,
        zone_name_to_id: &FxHashMap<String, u16>,
        fabric_redirect_sync: bool,
        session_id: u64,
        tcp_close_class: u8,
    ) -> Self {
        Self::encode_session_record(
            MSG_SESSION_OPEN,
            seq,
            key,
            decision,
            metadata,
            zone_name_to_id,
            fabric_redirect_sync,
            session_id,
            tcp_close_class,
        )
    }

    /// #9412: a close-state update. It uses the OPEN record layout on
    /// `MSG_SESSION_UPDATE`, so the Go decoder upserts the peer's copy, and it
    /// is never an RT_FLOW SESSION_CREATE.
    pub(crate) fn encode_session_update(
        seq: u64,
        key: &SessionKey,
        decision: &SessionDecision,
        metadata: &SessionMetadata,
        zone_name_to_id: &FxHashMap<String, u16>,
        fabric_redirect_sync: bool,
        session_id: u64,
        tcp_close_class: u8,
    ) -> Self {
        Self::encode_session_record(
            MSG_SESSION_UPDATE,
            seq,
            key,
            decision,
            metadata,
            zone_name_to_id,
            fabric_redirect_sync,
            session_id,
            tcp_close_class,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn encode_session_record(
        msg_type: u8,
        seq: u64,
        key: &SessionKey,
        decision: &SessionDecision,
        metadata: &SessionMetadata,
        _zone_name_to_id: &FxHashMap<String, u16>,
        fabric_redirect_sync: bool,
        session_id: u64,
        tcp_close_class: u8,
    ) -> Self {
        let mut buf = [0u8; 256];
        let mut pos = FRAME_HEADER_SIZE; // skip header, fill later

        // #6949: the HA-carried policy attribution is derived ONCE, here, and
        // the JSON RPC-fallback producer (`afxdp::session_delta_info`) derives
        // it from the same helper. The destructure is EXHAUSTIVE on purpose —
        // no `..` — so a field added to `SessionSyncAttribution` cannot be
        // carried by only one of the two legs without failing to compile.
        // Before #6949 the JSON leg silently carried none of these.
        let SessionSyncAttribution {
            policy_id,
            policy_counter_idx,
            inactivity_timeout_secs,
            nat64,
            nat64_snat_v4,
        } = SessionSyncAttribution::from_session(decision, metadata);

        // [0] AddrFamily
        let is_v6 = key.addr_family == libc::AF_INET6 as u8;
        buf[pos] = if is_v6 { 6 } else { 4 };
        pos += 1;

        // [1] Protocol
        buf[pos] = key.protocol;
        pos += 1;

        // [2:4] SrcPort LE
        buf[pos..pos + 2].copy_from_slice(&key.src_port.to_le_bytes());
        pos += 2;

        // [4:6] DstPort LE
        buf[pos..pos + 2].copy_from_slice(&key.dst_port.to_le_bytes());
        pos += 2;

        // [6:8] NATSrcPort LE
        let nat = &decision.nat;
        buf[pos..pos + 2].copy_from_slice(&nat.rewrite_src_port.unwrap_or(0).to_le_bytes());
        pos += 2;

        // [8:10] NATDstPort LE
        buf[pos..pos + 2].copy_from_slice(&nat.rewrite_dst_port.unwrap_or(0).to_le_bytes());
        pos += 2;

        // [10:14] OwnerRGID i32 LE
        // #2467: widened from i16 to i32. Linux ifindexes (the sibling fields
        // below) are a full `int` and wrap negative past 32767 on long-running
        // systems with interface churn; owner_rg_id is widened with them to
        // keep the record's three identity ints a uniform 32-bit width.
        buf[pos..pos + 4].copy_from_slice(&(metadata.owner_rg_id as i32).to_le_bytes());
        pos += 4;

        // [14:18] EgressIfindex i32 LE (#2467)
        buf[pos..pos + 4]
            .copy_from_slice(&(decision.resolution.egress_ifindex as i32).to_le_bytes());
        pos += 4;

        // [18:22] TXIfindex i32 LE (#2467)
        buf[pos..pos + 4].copy_from_slice(&(decision.resolution.tx_ifindex as i32).to_le_bytes());
        pos += 4;

        // [22:24] TunnelEndpointID u16 LE
        buf[pos..pos + 2].copy_from_slice(&decision.resolution.tunnel_endpoint_id.to_le_bytes());
        pos += 2;

        // [24:26] TXVLANID u16 LE
        buf[pos..pos + 2].copy_from_slice(&decision.resolution.tx_vlan_id.to_le_bytes());
        pos += 2;

        // [26] Flags
        let mut flags: u8 = 0;
        if fabric_redirect_sync
            || decision.resolution.disposition == ForwardingDisposition::FabricRedirect
        {
            flags |= FLAG_FABRIC_REDIRECT;
        }
        if metadata.fabric_ingress {
            flags |= FLAG_FABRIC_INGRESS;
        }
        if metadata.is_reverse {
            flags |= FLAG_IS_REVERSE;
        }
        // #2785: per-policy log selection rides the open frame so the
        // synced session logs identically on the peer after failover.
        if metadata.log_session_init {
            flags |= FLAG_LOG_SESSION_INIT;
        }
        if metadata.log_session_close {
            flags |= FLAG_LOG_SESSION_CLOSE;
        }
        // #4565: signal a NAT64 cross-family session so the peer rebuilds the
        // reverse BIB after failover (see FLAG_NAT64 doc + the trailing snat_v4).
        if nat64 {
            flags |= FLAG_NAT64;
        }
        buf[pos] = flags;
        pos += 1;

        // [27:29] IngressZoneID u16 LE (#3075: widened from u8).
        // SessionMetadata.ingress_zone is u16; the event-stream now carries the
        // full u16 so a stable name-hash zone id > 255 (#3075) round-trips
        // instead of truncating. This is same-host same-version IPC — xpfd
        // spawns the helper as a child and the #1917 STOP->FLIP->START kills the
        // helper before the new daemon starts (socket unlinked+recreated, a
        // FullResync drains the stream), so no frame straddles the width change
        // and no record-version negotiation is required.
        buf[pos..pos + 2].copy_from_slice(&metadata.ingress_zone.to_le_bytes());
        pos += 2;

        // [29:31] EgressZoneID u16 LE (#3075).
        buf[pos..pos + 2].copy_from_slice(&metadata.egress_zone.to_le_bytes());
        pos += 2;

        // [31] Disposition u8
        buf[pos] = encode_disposition(decision.resolution.disposition);
        pos += 1;

        // Addresses: 4 bytes each for v4, 16 bytes each for v6
        pos = write_ip(&mut buf, pos, key.src_ip, is_v6);
        pos = write_ip(&mut buf, pos, key.dst_ip, is_v6);
        pos = write_ip_opt(&mut buf, pos, nat.rewrite_src, is_v6);
        pos = write_ip_opt(&mut buf, pos, nat.rewrite_dst, is_v6);

        // NeighborMAC [6 bytes]
        if let Some(mac) = decision.resolution.neighbor_mac {
            buf[pos..pos + 6].copy_from_slice(&mac);
        }
        pos += 6;

        // SrcMAC [6 bytes]
        if let Some(mac) = decision.resolution.src_mac {
            buf[pos..pos + 6].copy_from_slice(&mac);
        }
        pos += 6;

        // NextHop (4 or 16 bytes)
        pos = write_ip_opt(&mut buf, pos, decision.resolution.next_hop, is_v6);

        // #3301: the admitting policy's firewall metadata rides the open frame
        // (trailing fields, additive within MSG_SESSION_OPEN) so a peer-promoted
        // session is correctly attributed, counted, and aged after failover.
        // The Go decoder length-skips these; an old daemon ignores them.
        //
        // [+0:+4] policy_id u32 LE (#3056)
        buf[pos..pos + 4].copy_from_slice(&policy_id.to_le_bytes());
        pos += 4;
        // [+4:+8] policy_counter_idx u32 LE (#3073)
        buf[pos..pos + 4].copy_from_slice(&policy_counter_idx.to_le_bytes());
        pos += 4;
        // [+8:+12] inactivity_timeout SECONDS u32 LE (#3227). The metadata
        // carries ns; the cross-node wire (Go SessionValue.AppTimeout,
        // SessionSyncRequest.inactivity_timeout) is whole seconds. The ns -> s
        // saturating conversion lives in `SessionSyncAttribution` (#6949) so
        // the JSON leg cannot round it differently.
        buf[pos..pos + 4].copy_from_slice(&inactivity_timeout_secs.to_le_bytes());
        pos += 4;

        // #4565: [+12:+16] the NAT64 translated pool SOURCE (`snat_v4`, 4 raw
        // IPv4 octets), trailing/length-gated like the #3301 fields. Written for
        // every open frame (0.0.0.0 when not NAT64); FLAG_NAT64 above is the
        // semantic gate. This is the ONE piece of the reverse BIB the standby
        // cannot reconstruct from the synced forward v6 key — the pool source is
        // chosen by `allocate_source`, not embedded in the key — so it must ride
        // the wire (the orig v6 src/dst ARE the key; `dst_v4` is the /96 low 32
        // of the key dst). An old Go decoder length-skips these 4 bytes.
        buf[pos..pos + 4].copy_from_slice(&nat64_snat_v4_octets(nat64_snat_v4));
        pos += 4;

        // #5212: [+16:+24] the ORIGINATING node's stable RT_FLOW session id (u64
        // LE), trailing/length-gated after the #4565 snat_v4 like every field
        // since #3301. Carried so a peer-synced session ADOPTS this id on import
        // (Go decodes it into SessionDeltaInfo.RTFlowSessionID ->
        // SessionValue{,V6}.RTFlowSessionID -> SessionSyncRequest.session_id ->
        // build_synced_session_entry), making its SESSION_CREATE (origin node)
        // and SESSION_CLOSE (possibly the peer, post-failover) share one
        // correlatable id. 0 = "no id" (a synthesized/no-entry emit, or a bulk
        // export of an entry that vanished); an old Go decoder length-skips
        // these 8 bytes and the standby allocs a fresh local id.
        buf[pos..pos + 8].copy_from_slice(&session_id.to_le_bytes());
        pos += 8;

        // #7188: [+24:+32] the session key's tunnel discriminator (u64 LE),
        // trailing/length-gated after the #5212 session id. GRE is protocol 47
        // and has no L4 ports, so two RFC 2890 tunnels between one pair of
        // outer endpoints share a 5-tuple; this is the only field on the record
        // that tells them apart. Without it the standby rebuilt both records as
        // ONE key and the second install evicted the first. The encoding
        // reserves 0 for "not carried" and never emits it for a real class, so
        // an old Go decoder length-skips these 8 bytes and the receiver reads
        // the peer as unable to express the identity (withhold, not alias).
        buf[pos..pos + 8].copy_from_slice(&key.discriminator.to_wire().to_le_bytes());
        pos += 8;

        // #7239 (#7160/#2387): [+32:+36] the session key's ROUTING DOMAIN (u32
        // LE), trailing/length-gated after the #7188 discriminator.
        //
        // Carried, not re-derived on the peer, and that distinction is the
        // whole point. The importing node used to resolve the domain from the
        // #7095 cluster-stable ingress fold, which `stampIngressIfaceFold`
        // computes on the SEND path against the CURRENT config — so an ifindex
        // recycled onto a sibling between install and sync folded to the
        // sibling's name, and the peer imported the session into that
        // sibling's routing domain. If the two interfaces sit in different
        // routing instances that is a cross-tenant mis-file, in the field
        // #7160 added to prevent exactly that, and it is a CONFIDENT one: the
        // two-pass preference in `find_forward_nat_match` matches a reply in
        // the wrong tenant's domain on pass 1.
        //
        // This value is stamped at INSTALL, from the interface the flow
        // actually arrived on — it is already on the key — so no later recycle
        // can change it. 0 is the default routing instance, which is also what
        // an old Go decoder length-skipping these 4 bytes reads, and what every
        // deployment with no routing-instance interface membership carries.
        buf[pos..pos + 4]
            .copy_from_slice(&crate::session::routing_domain_to_wire(key.routing_domain).to_le_bytes());
        pos += 4;

        // #9412: [+36] the session's TCP close class (u8), trailing and
        // length-gated after the #7239 routing domain, like every field since
        // #3301. `0` = open or not carried, which is also what a Go decoder that
        // predates the byte reads. Written on BOTH message types this layout
        // serves: an Update exists to carry it, and an Open carries the current
        // class so a resync re-export restores a dropped Update.
        buf[pos] = tcp_close_class;
        pos += 1;

        // Write header
        let payload_len = (pos - FRAME_HEADER_SIZE) as u32;
        write_header(&mut buf, payload_len, msg_type, seq);

        EventFrame {
            data: buf,
            len: pos as u16,
            seq,
        }
    }

    /// Encode a SessionClose (type 2) frame -- minimal payload.
    /// #919/#922: extended with ingress_zone_id + egress_zone_id after the
    /// flags byte. #3075: widened those two fields from u8 to u16 LE so a stable
    /// name-hash zone id > 255 round-trips. They are TRAILING fields, so the Go
    /// decoder length-gates them (a short frame degrades to "no zone ids").
    pub(crate) fn encode_session_close(
        seq: u64,
        key: &SessionKey,
        owner_rg_id: i32,
        close_flags: u8,
        ingress_zone_id: u16,
        egress_zone_id: u16,
    ) -> Self {
        let mut buf = [0u8; 256];
        let mut pos = FRAME_HEADER_SIZE;

        let is_v6 = key.addr_family == libc::AF_INET6 as u8;

        // [0] AddrFamily
        buf[pos] = if is_v6 { 6 } else { 4 };
        pos += 1;

        // [1] Protocol
        buf[pos] = key.protocol;
        pos += 1;

        // [2:4] SrcPort
        buf[pos..pos + 2].copy_from_slice(&key.src_port.to_le_bytes());
        pos += 2;

        // [4:6] DstPort
        buf[pos..pos + 2].copy_from_slice(&key.dst_port.to_le_bytes());
        pos += 2;

        // SrcIP, DstIP
        pos = write_ip(&mut buf, pos, key.src_ip, is_v6);
        pos = write_ip(&mut buf, pos, key.dst_ip, is_v6);

        // OwnerRGID i32 LE (#2467: widened from i16, see encode_session_open).
        buf[pos..pos + 4].copy_from_slice(&owner_rg_id.to_le_bytes());
        pos += 4;

        // Flags
        buf[pos] = close_flags;
        pos += 1;

        // #3075: IngressZoneID u16 LE, EgressZoneID u16 LE (widened from u8).
        buf[pos..pos + 2].copy_from_slice(&ingress_zone_id.to_le_bytes());
        pos += 2;
        buf[pos..pos + 2].copy_from_slice(&egress_zone_id.to_le_bytes());
        pos += 2;

        // #7188: the tunnel discriminator (u64 LE), trailing/length-gated after
        // the #3075 zone ids. A close names the session to RETRACT, and for
        // protocol 47 the 5-tuple names two tunnels at once — so a close that
        // could not carry the discriminator would retract the wrong one, or
        // (once the receiver refuses an inexpressible protocol-47 key) neither.
        // An old Go decoder length-skips these 8 bytes.
        buf[pos..pos + 8].copy_from_slice(&key.discriminator.to_wire().to_le_bytes());
        pos += 8;

        // #7239 (#7160/#2387): the ROUTING DOMAIN (u32 LE), trailing after the
        // #7188 discriminator, for the same reason #7188 needed to be here at
        // all. A close names the session to RETRACT, and two routing instances
        // sharing a 5-tuple are two sessions — so a close that could not carry
        // the domain would retract the wrong tenant's session, or none. The
        // open frame carries it, so the close must too or the two frames name
        // different keys. An old Go decoder length-skips these 4 bytes and
        // retracts in the default instance, which is what it did before the
        // field existed.
        buf[pos..pos + 4]
            .copy_from_slice(&crate::session::routing_domain_to_wire(key.routing_domain).to_le_bytes());
        pos += 4;

        let payload_len = (pos - FRAME_HEADER_SIZE) as u32;
        write_header(&mut buf, payload_len, MSG_SESSION_CLOSE, seq);

        EventFrame {
            data: buf,
            len: pos as u16,
            seq,
        }
    }
}

/// Compute the close flags byte from a SessionDelta.
pub(crate) fn close_flags(delta: &SessionDelta) -> u8 {
    let mut flags: u8 = 0;
    if delta.fabric_redirect_sync
        || delta.decision.resolution.disposition == ForwardingDisposition::FabricRedirect
    {
        flags |= FLAG_FABRIC_REDIRECT;
    }
    if delta.metadata.fabric_ingress {
        flags |= FLAG_FABRIC_INGRESS;
    }
    flags
}
