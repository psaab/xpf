//! RT_FLOW telemetry frames (the canonical `dataplane.Event` wire shape) plus
//! the dataplane-event kind enum and payload struct.
//!
//! Split out of the former single-file `codec.rs` (#4651). These frames carry
//! deny/screen/filter security events and the RT_FLOW SESSION_CREATE/CLOSE
//! records consumed by the Go NetFlow/IPFIX exporters.

use std::net::IpAddr;

use super::EventFrame;
use super::wire::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DataplaneEventKind {
    PolicyDeny,
    ScreenDrop,
    FilterLog,
    // #2512: RT_FLOW SESSION_CLOSE (type 14) and SESSION_CREATE (type 15)
    // are now first-class dataplane-event kinds so they ride the SAME
    // per-kind rate limiter, queue budget, and sent/dropped counters as
    // deny/screen/filter. Before #2512 they used a bare `try_send` side
    // channel around the producer's backpressure model. The queue-budget
    // release path on the I/O thread keys frames by their msg_type byte, so
    // both kinds MUST round-trip through `from_msg_type` to balance the
    // per-kind budget acquired at emit time.
    SessionClose,
    SessionCreate,
}

impl DataplaneEventKind {
    fn msg_type(self) -> u8 {
        match self {
            Self::PolicyDeny => MSG_POLICY_DENY,
            Self::ScreenDrop => MSG_SCREEN_DROP,
            Self::FilterLog => MSG_FILTER_LOG,
            Self::SessionClose => MSG_SESSION_CLOSE_RT_FLOW,
            Self::SessionCreate => MSG_SESSION_CREATE_RT_FLOW,
        }
    }

    pub(super) fn from_msg_type(msg_type: u8) -> Option<Self> {
        match msg_type {
            MSG_POLICY_DENY => Some(Self::PolicyDeny),
            MSG_SCREEN_DROP => Some(Self::ScreenDrop),
            MSG_FILTER_LOG => Some(Self::FilterLog),
            MSG_SESSION_CLOSE_RT_FLOW => Some(Self::SessionClose),
            MSG_SESSION_CREATE_RT_FLOW => Some(Self::SessionCreate),
            _ => None,
        }
    }

    pub(super) fn rt_flow_event_type(self) -> u8 {
        match self {
            Self::PolicyDeny => RT_FLOW_EVENT_POLICY_DENY,
            Self::ScreenDrop => RT_FLOW_EVENT_SCREEN_DROP,
            Self::FilterLog => RT_FLOW_EVENT_FILTER_LOG,
            Self::SessionClose => RT_FLOW_EVENT_SESSION_CLOSE,
            Self::SessionCreate => RT_FLOW_EVENT_SESSION_OPEN,
        }
    }

    // NOTE: from_rt_flow_event_type deliberately does NOT map the
    // SessionClose/SessionCreate event-type bytes. It backs
    // `decode_dataplane_event`, the deny/screen/filter payload decoder used
    // by the Go-parity tests; session-close/create frames have a different
    // 136-byte payload layout (their own encoders) and are never fed to that
    // decoder. The budget RELEASE path on the I/O thread keys frames by their
    // msg_type byte via `from_msg_type` above, so SessionClose/SessionCreate
    // round-trip the per-kind queue budget correctly without this mapping.
    pub(super) fn from_rt_flow_event_type(event_type: u8) -> Option<Self> {
        match event_type {
            RT_FLOW_EVENT_POLICY_DENY => Some(Self::PolicyDeny),
            RT_FLOW_EVENT_SCREEN_DROP => Some(Self::ScreenDrop),
            RT_FLOW_EVENT_FILTER_LOG => Some(Self::FilterLog),
            _ => None,
        }
    }
}

#[allow(dead_code)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct DataplaneEventPayload {
    pub(crate) kind: DataplaneEventKind,
    pub(crate) addr_family: u8,
    pub(crate) protocol: u8,
    pub(crate) action: u8,
    pub(crate) src_ip: IpAddr,
    pub(crate) dst_ip: IpAddr,
    pub(crate) src_port: u16,
    pub(crate) dst_port: u16,
    pub(crate) nat_src_ip: Option<IpAddr>,
    pub(crate) nat_dst_ip: Option<IpAddr>,
    pub(crate) nat_src_port: u16,
    pub(crate) nat_dst_port: u16,
    pub(crate) ingress_zone_id: u16,
    pub(crate) egress_zone_id: u16,
    pub(crate) ingress_ifindex: i32,
    pub(crate) policy_id: u32,
    pub(crate) rule_id: u32,
    pub(crate) term_id: u32,
    pub(crate) reason: u8,
    pub(crate) owner_rg_id: i16,
    pub(crate) application_id: u16,
    pub(crate) filter_id: u32,
    pub(crate) screen_id: u32,
    /// Config generation that evaluated a POLICY_DENY. The event encoder
    /// carries this in duplicate rule/term slots so Go can refuse to resolve
    /// its positional policy ID from another generation's name map.
    pub(crate) config_generation: u64,
    pub(crate) timestamp_ns: u64,
}

pub(super) const POLICY_CONFIG_GENERATION_MARKER: u32 = u32::from_le_bytes(*b"GEN1");

impl EventFrame {
    /// #2460: Encode an RT_FLOW SESSION_CLOSE (type 14) frame.
    ///
    /// Unlike `encode_session_close` (the minimal type-2 HA session-sync
    /// delta), this frame carries the canonical `dataplane.Event` fields plus
    /// additive RT_FLOW session extensions: stable session identity at
    /// [152:160] and the #11698 policy-generation tail at [160:168]. The base
    /// offsets are consumed by Go's `logging.DecodeRawEventRecord` /
    /// `EventReader.logEvent` (`pkg/logging/ringbuf.go`). With the event-type byte set
    /// `RT_FLOW_EVENT_SESSION_CLOSE` (2), the Go side resolves it to a
    /// `Type == "SESSION_CLOSE"` `EventRecord`, which is exactly what the
    /// NetFlow v9 / IPFIX session-close exporters gate on
    /// (`daemon_flowexport.go`).
    ///
    /// Fields populated from the close: the real forward 5-tuple, the NAT
    /// translated tuple (when present), ingress/egress zone IDs, and
    /// protocol. `owner_rg_id` is accepted for symmetry with the other
    /// frame encoders but is intentionally NOT written into this payload —
    /// for a SESSION_CLOSE the Go decoder reads the [56:64] slot (where the
    /// deny/screen/filter frames carry owner RG) as the session-packets
    /// counter, so writing owner RG there would corrupt the counter. Owner
    /// RG is carried for session sync on the type-2 HA close delta instead.
    ///
    /// The byte/packet counters (offsets 56/64/112/120) are written as 0: the
    /// userspace AF_XDP forwarding path does not yet maintain per-session
    /// byte/packet accounting. That accounting is the follow-up tracked in
    /// #2501; until it lands these stay 0, so the flow record carries an
    /// accurate tuple but zero volume.
    ///
    /// #2465: the session-creation stamp (offset 108, `created`, Unix seconds)
    /// and the record timestamp (offset 0, `timestamp_ns`, Unix nanoseconds =
    /// the close/last-seen instant) ARE now populated from the real session
    /// timestamps. `created_unix_secs` is the absolute wall-clock second at
    /// which the session was installed (converted by the caller from the
    /// monotonic `created_ns`); `close_unix_ns` is the absolute wall-clock
    /// close instant (from the monotonic `last_seen_ns`). The Go exporters use
    /// `created` as the flow StartTime directly; only when it is 0 (an old
    /// frame or a synthesized close that carried no creation instant) do they
    /// fall back to the packet-count `estimateSessionDuration` heuristic.
    /// A `created_unix_secs` of 0 keeps the legacy fallback behavior.
    ///
    /// #2853: `created_subsec_nanos` carries the sub-second nanosecond remainder
    /// of that same creation instant in the SESSION_CLOSE-unused policy_id slot
    /// (offset 44). The Go exporters combine it with `created_unix_secs` so the
    /// flow StartTime keeps millisecond resolution; before this, short flows
    /// (DNS, single HTTP requests) opened in the same second all reported one
    /// truncated integer-second start, skewing IPFIX `flowStartMilliseconds`.
    ///
    /// #3056: `policy_id` is the admitting policy's ID. Because #2853 took the
    /// [44:48] slot that every other frame uses for the policy ID, the
    /// SESSION_CLOSE frame carries it in the trailing [136:140] slot (the payload
    /// grew 136 -> 144 for this; see `SECURITY_EVENT_PAYLOAD_SIZE`). The Go
    /// decoder reads [136:140] back as PolicyID ONLY on a close, so the
    /// RT_FLOW_SESSION_CLOSE syslog record and the NetFlow/IPFIX close exporters
    /// name the admitting policy instead of policy 0. A 0 keeps the prior
    /// "no policy" rendering (host-local / seed sessions, or a peer-PROMOTED
    /// session synced from a pre-#3301 peer that omitted the policy_id wire
    /// field; #3301 now carries it on the session-sync wire, so a peer-promoted
    /// session synced from a current peer closes with the admitting policy).
    ///
    /// #11698: [140:144] carries the shared `GEN1` marker and [160:168] carries
    /// the configuration generation paired with the RE-RESOLVED policy ID. The
    /// Go reader refuses to resolve a marked policy ID through another generation's
    /// name map while preserving the numeric ID.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn encode_session_close_rt_flow(
        seq: u64,
        addr_family: u8,
        protocol: u8,
        src_ip: IpAddr,
        dst_ip: IpAddr,
        src_port: u16,
        dst_port: u16,
        nat_src_ip: Option<IpAddr>,
        nat_dst_ip: Option<IpAddr>,
        nat_src_port: u16,
        nat_dst_port: u16,
        ingress_zone_id: u16,
        egress_zone_id: u16,
        // #3056: the admitting policy's ID, stamped on the session at install
        // (`SessionMetadata.policy_id`). The SESSION_CLOSE frame carries it in the
        // trailing [136:140] slot (NOT [44:48], which #2853 repurposed for the
        // created-subsec-nanos), so the RT_FLOW_SESSION_CLOSE syslog record and
        // the NetFlow/IPFIX close exporters name the admitting policy instead of
        // policy 0. 0 stays the value for a session with no admitting policy
        // (host-local / seed) and for a peer-PROMOTED session synced from a
        // pre-#3301 peer; #3301 carries policy_id on the session-sync wire
        // (SESSION_OPEN delta + SessionSyncRequest), so a session synced from a
        // current peer closes with the admitting policy (see server/helpers.rs).
        policy_id: u32,
        // Generation of the re-resolved policy ID, stamped beside that ID on
        // the session frame for Go's policy-name attribution fence.
        policy_generation: u64,
        owner_rg_id: i16,
        log_syslog: bool,
        created_unix_secs: u32,
        // #2853: sub-second nanosecond remainder (0..=999_999_999) of the
        // creation instant. Rides the [44:48] policy_id slot (unused on a
        // SESSION_CLOSE) so the Go exporters reconstruct a millisecond-accurate
        // flow StartTime rather than one truncated to `created_unix_secs`.
        created_subsec_nanos: u32,
        close_unix_ns: u64,
        application_id: u16,
        ingress_ifindex: u32,
        // #2501: per-direction byte/packet volume harvested from the
        // closing session's worker-owned counters.
        fwd_packets: u64,
        fwd_bytes: u64,
        rev_packets: u64,
        rev_bytes: u64,
        // #2749: class-of-service / interface-attribution fields for the
        // re-introduced NetFlow v9 + IPFIX close-record fields. `src_tos` is
        // the IP ToS byte (DSCP in the high 6 bits, ECN cleared — the shim
        // meta carries only the 6-bit DSCP) observed on the forward
        // direction; `tcp_control_bits` is the OR of every TCP flag byte seen
        // over the flow's lifetime; `egress_ifindex` is the resolved output
        // interface (from the session's forwarding resolution). All ride the
        // additive [144:152] block. 0 keeps the prior "field absent" rendering.
        src_tos: u8,
        tcp_control_bits: u8,
        egress_ifindex: u32,
        // #4915: the dataplane's STABLE session id (the `SessionEntry.session_id`
        // assigned at install, threaded onto the close `SessionDelta`). Written
        // LE at the additive [152:160] slot so the Go decoder populates the
        // RT_FLOW record's SessionID with a value that (a) matches this session's
        // SESSION_CREATE record and (b) disambiguates a reused 5-tuple. 0 stays
        // the "unknown" sentinel (a synthesized close with no live entry).
        session_id: u64,
    ) -> Self {
        let mut buf = [0u8; super::EVENT_FRAME_CAPACITY];
        let base = FRAME_HEADER_SIZE;
        let wire_af = rt_flow_addr_family(addr_family, src_ip);

        // [0:8] timestamp_ns — #2465: the absolute wall-clock close instant
        // (LITTLE-endian u64, matching the Go binary.LittleEndian.Uint64 read
        // in logEvent/DecodeRawEventRecord). This is the record's EndTime. When
        // 0 the Go side stamps time.Now() instead (the legacy behavior).
        buf[base..base + 8].copy_from_slice(&close_unix_ns.to_le_bytes());
        // [8:24] src ip, [24:40] dst ip (16-byte slots, v4 left-aligned).
        write_ip_16(&mut buf, base + 8, src_ip);
        write_ip_16(&mut buf, base + 24, dst_ip);
        // [40:42] src port, [42:44] dst port — BIG-endian (matches the Go
        // `binary.BigEndian` reads in logEvent/DecodeRawEventRecord).
        buf[base + 40..base + 42].copy_from_slice(&src_port.to_be_bytes());
        buf[base + 42..base + 44].copy_from_slice(&dst_port.to_be_bytes());
        // [44:48] policy_id — unused for SESSION_CLOSE; #2853 repurposes it to
        // carry the creation instant's sub-second NANOSECOND remainder
        // (LITTLE-endian u32), which the Go SESSION_CLOSE decoder reads back as
        // `CreatedNanos` (and zeroes PolicyID, so the policy-name resolution is
        // unchanged) to build a millisecond-accurate flow StartTime.
        buf[base + 44..base + 48].copy_from_slice(&created_subsec_nanos.to_le_bytes());
        // [48:50] ingress zone, [50:52] egress zone — little-endian.
        buf[base + 48..base + 50].copy_from_slice(&ingress_zone_id.to_le_bytes());
        buf[base + 50..base + 52].copy_from_slice(&egress_zone_id.to_le_bytes());
        // [52] event type, [53] protocol, [54] action, [55] address family.
        buf[base + 52] = RT_FLOW_EVENT_SESSION_CLOSE;
        buf[base + 53] = protocol;
        // [54] action: a session close has no permit/deny/reject action
        // semantics, so this byte is intentionally 0. The Go decoder maps it
        // into EventRecord.Action, but the flow exporters do not branch on it
        // for a close, and as of #2513 the syslog/event renderers omit action
        // for SESSION_CLOSE entirely (the standard line dropped its `action=`
        // field; the structured line never carried one). Do NOT rely on the 0
        // rendering as a value — both close formatters skip it.
        buf[base + 54] = 0;
        buf[base + 55] = wire_af;
        // [56:64] session_packets (forward), [64:72] session_bytes (forward)
        // — #2501: real per-session forward volume harvested from the closing
        // entry's worker-owned counters. LITTLE-endian to match the Go
        // logging.DecodeRawEventRecord reads (data[56:64]/data[64:72]).
        buf[base + 56..base + 64].copy_from_slice(&fwd_packets.to_le_bytes());
        buf[base + 64..base + 72].copy_from_slice(&fwd_bytes.to_le_bytes());
        // [72:88] nat src ip, [88:104] nat dst ip.
        write_ip_opt_16(&mut buf, base + 72, nat_src_ip);
        write_ip_opt_16(&mut buf, base + 88, nat_dst_ip);
        // [104:106] nat src port, [106:108] nat dst port — BIG-endian.
        buf[base + 104..base + 106].copy_from_slice(&nat_src_port.to_be_bytes());
        buf[base + 106..base + 108].copy_from_slice(&nat_dst_port.to_be_bytes());
        // [108:112] created — #2465: absolute wall-clock Unix SECONDS at which
        // the session was installed (LITTLE-endian u32, matching the Go
        // binary.LittleEndian.Uint32 read). The exporters use this as the flow
        // StartTime; 0 means "unknown" and triggers the packet-count fallback.
        buf[base + 108..base + 112].copy_from_slice(&created_unix_secs.to_le_bytes());
        // [112:120] rev packets, [120:128] rev bytes — #2501: real per-session
        // reverse (reply-direction) volume. LITTLE-endian to match the Go
        // reads (data[112:120]/data[120:128]).
        buf[base + 112..base + 120].copy_from_slice(&rev_packets.to_le_bytes());
        buf[base + 120..base + 128].copy_from_slice(&rev_bytes.to_le_bytes());
        // [128:132] ingress ifindex — #2615: the closing binding's interface
        // (LITTLE-endian u32, decoded by the Go side as
        // `binary.LittleEndian.Uint32` -> resolved to the RT_FLOW
        // `packet-incoming-interface`). 0 keeps the prior "N/A" rendering for
        // a session whose ingress interface could not be resolved.
        buf[base + 128..base + 132].copy_from_slice(&ingress_ifindex.to_le_bytes());
        // [132:134] application id — #2520: the AppID resolved for the closing
        // session's 5-tuple (the caller runs the same app_catalog.lookup the
        // forwarding hot path used to stamp the conntrack entry). 0 stays the
        // UNKNOWN sentinel the Go RT_FLOW logger renders as
        // application="UNKNOWN".
        buf[base + 132..base + 134].copy_from_slice(&application_id.to_le_bytes());
        // owner_rg_id rides the [64:66] slot the deny/screen/filter frames
        // use, but for SESSION_CLOSE the Go side reads [56:64] as the
        // session-packets counter, so owner_rg_id is intentionally NOT
        // written here (it would corrupt the counter slot). The HA close
        // delta (type 2) already carries owner_rg_id for session sync.
        let _ = owner_rg_id;
        // [134] close reason.
        buf[base + 134] = RT_FLOW_CLOSE_REASON_NONE;
        // [135] #2508 per-policy SYSLOG log gate.
        buf[base + 135] = if log_syslog { RT_FLOW_LOG_SYSLOG } else { 0 };
        // [136:140] policy_id — #3056: the admitting policy's ID (LITTLE-endian
        // u32). Unlike every non-close frame (which carries policy_id in [44:48]),
        // the SESSION_CLOSE frame uses this trailing slot because [44:48] holds
        // the #2853 created-subsec-nanos. The Go decoder reads [136:140] back as
        // PolicyID ONLY on a SESSION_CLOSE, so the close record names the
        // admitting policy instead of policy 0. [140:144] carries the generation
        // marker; [160:168] carries its paired config generation.
        buf[base + 136..base + 140].copy_from_slice(&policy_id.to_le_bytes());
        buf[base + 140..base + 144]
            .copy_from_slice(&POLICY_CONFIG_GENERATION_MARKER.to_le_bytes());
        // #2749: [144] src ToS byte, [145] accumulated TCP control bits,
        // [146] flow direction (reserved — 0; a real per-flow inbound/outbound
        // classification is a deferred follow-up), [147] reserved, [148:152]
        // egress ifindex (LITTLE-endian u32). The Go decoder reads this block
        // only when the frame carries it (len >= 152) and only on a
        // SESSION_CLOSE, so a short legacy (144-byte) frame degrades to the
        // prior all-absent behavior rather than misparsing.
        buf[base + 144] = src_tos;
        buf[base + 145] = tcp_control_bits;
        buf[base + 148..base + 152].copy_from_slice(&egress_ifindex.to_le_bytes());
        // #4915: [152:160] the dataplane's stable session id (LE u64). The Go
        // decoder reads it into EventRecord.SessionID only when the frame carries
        // it (len >= 160), so a short legacy (152-byte) frame degrades to
        // SessionID 0 rather than misparsing.
        buf[base + 152..base + 160].copy_from_slice(&session_id.to_le_bytes());
        // #11698: [160:168] the configuration generation paired with the
        // re-resolved positional policy ID. The shared marker at [140:144]
        // distinguishes this new payload from legacy session frames.
        buf[base + SESSION_POLICY_GENERATION_OFFSET..base + SESSION_POLICY_GENERATION_OFFSET + 8]
            .copy_from_slice(&policy_generation.to_le_bytes());

        write_header(
            &mut buf,
            SESSION_RT_FLOW_PAYLOAD_SIZE as u32,
            MSG_SESSION_CLOSE_RT_FLOW,
            seq,
        );

        EventFrame {
            data: buf,
            len: (FRAME_HEADER_SIZE + SESSION_RT_FLOW_PAYLOAD_SIZE) as u16,
            seq,
        }
    }

    /// #2508: encode an RT_FLOW SESSION_CREATE (type 15) frame for a session
    /// admitted by a policy with `then log session-init`. Identical payload
    /// shape to `encode_session_close_rt_flow` except: the event-type byte is
    /// RT_FLOW SESSION_CREATE (1); there is no close reason; counters are 0
    /// (a create has no volume yet); and the per-policy SYSLOG gate byte
    /// (offset 135) is always set, because the helper only ever produces this
    /// frame when the gate is open (no flowexport consumer of opens — there is
    /// nothing to keep unconditional). The Go logEvent path renders it as the
    /// RT_FLOW_SESSION_CREATE syslog record.
    ///
    /// #2615: the create frame now also threads the ingress ifindex (the
    /// admitting binding's interface, written to [128:132]) and the resolved
    /// application id ([132:134]). The Go decoder already reads BOTH slots for
    /// every RT_FLOW frame (`pkg/logging/ringbuf.go`), so this is a
    /// render-only fix — no wire-format change. A 0 in either slot keeps the
    /// prior `packet-incoming-interface="N/A"` / `application="UNKNOWN"`
    /// rendering for sessions whose interface/app could not be resolved.
    ///
    /// #3056: the create frame now also carries the admitting policy's ID in the
    /// [44:48] `policy_id` slot. Unlike the SESSION_CLOSE frame — whose [44:48]
    /// was repurposed by #2853 to carry the creation instant's sub-second
    /// nanoseconds — the SESSION_CREATE frame leaves [44:48] otherwise unused,
    /// and the Go decoder already reads it as `PolicyID` for every non-close
    /// frame (`pkg/logging/ringbuf.go` logEvent / DecodeRawEventRecord) and
    /// resolves a policy name from it. So this is a render-only fix: the
    /// RT_FLOW_SESSION_CREATE syslog record now names the admitting policy
    /// instead of policy `0`. A 0 keeps the prior behavior for sessions with
    /// no admitting policy, e.g. host-local/seed sessions never emit this
    /// producer-gated frame).
    ///
    /// #11698: the create frame carries the session's admission generation at
    /// [160:168], paired with its frozen install-time policy ID at [44:48].
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn encode_session_create_rt_flow(
        seq: u64,
        addr_family: u8,
        protocol: u8,
        src_ip: IpAddr,
        dst_ip: IpAddr,
        src_port: u16,
        dst_port: u16,
        nat_src_ip: Option<IpAddr>,
        nat_dst_ip: Option<IpAddr>,
        nat_src_port: u16,
        nat_dst_port: u16,
        ingress_zone_id: u16,
        egress_zone_id: u16,
        policy_id: u32,
        // Generation paired with `policy_id` at session admission.
        policy_generation: u64,
        ingress_ifindex: u32,
        application_id: u16,
        // #4915: the dataplane's STABLE session id (the `SessionEntry.session_id`
        // assigned at install, threaded onto the open `SessionDelta`). Written LE
        // at [152:160] so the SESSION_CREATE record carries the SAME id its
        // matching SESSION_CLOSE will, letting a SIEM join the two.
        session_id: u64,
    ) -> Self {
        let mut buf = [0u8; super::EVENT_FRAME_CAPACITY];
        let base = FRAME_HEADER_SIZE;
        let wire_af = rt_flow_addr_family(addr_family, src_ip);

        // [8:24] src ip, [24:40] dst ip (16-byte slots, v4 left-aligned).
        write_ip_16(&mut buf, base + 8, src_ip);
        write_ip_16(&mut buf, base + 24, dst_ip);
        // [40:42] src port, [42:44] dst port — BIG-endian.
        buf[base + 40..base + 42].copy_from_slice(&src_port.to_be_bytes());
        buf[base + 42..base + 44].copy_from_slice(&dst_port.to_be_bytes());
        // [44:48] policy_id — #3056: the admitting policy's ID (LITTLE-endian
        // u32). The Go decoder reads this slot as PolicyID for non-close frames
        // and resolves the policy name, so the RT_FLOW_SESSION_CREATE record
        // names the admitting policy instead of policy 0. (On the SESSION_CLOSE
        // frame this slot is the #2853 created-subsec-nanos; the two frames have
        // separate encoders, so there is no collision.)
        buf[base + 44..base + 48].copy_from_slice(&policy_id.to_le_bytes());
        // [48:50] ingress zone, [50:52] egress zone — little-endian.
        buf[base + 48..base + 50].copy_from_slice(&ingress_zone_id.to_le_bytes());
        buf[base + 50..base + 52].copy_from_slice(&egress_zone_id.to_le_bytes());
        // [52] event type = SESSION_CREATE (1), [53] protocol, [54] action,
        // [55] address family.
        buf[base + 52] = RT_FLOW_EVENT_SESSION_OPEN;
        buf[base + 53] = protocol;
        // [54] action: a session open is a permit-and-create event, not a
        // forwarding decision, so this byte is intentionally 0 (same as the
        // close path). The Go decoder maps it into EventRecord.Action, but as
        // of #2593 the syslog/event renderers omit action for SESSION_OPEN
        // entirely (the standard line dropped its `action=` field; the
        // structured RT_FLOW_SESSION_CREATE line never carried one). Do NOT
        // rely on the 0 rendering as a value — both create formatters skip it.
        buf[base + 54] = 0;
        buf[base + 55] = wire_af;
        // [72:88] nat src ip, [88:104] nat dst ip.
        write_ip_opt_16(&mut buf, base + 72, nat_src_ip);
        write_ip_opt_16(&mut buf, base + 88, nat_dst_ip);
        // [104:106] nat src port, [106:108] nat dst port — BIG-endian.
        buf[base + 104..base + 106].copy_from_slice(&nat_src_port.to_be_bytes());
        buf[base + 106..base + 108].copy_from_slice(&nat_dst_port.to_be_bytes());
        // [108:112] created stamp, [112:128] rev counters — 0 (a create has
        // no volume yet).
        // [128:132] ingress ifindex — #2615: the admitting binding's
        // interface (LITTLE-endian u32, decoded by the Go side as
        // `binary.LittleEndian.Uint32` -> resolved to the RT_FLOW
        // `packet-incoming-interface`). 0 keeps the prior "N/A" rendering.
        buf[base + 128..base + 132].copy_from_slice(&ingress_ifindex.to_le_bytes());
        // [132:134] application id — #2615: the AppID resolved for the new
        // session's 5-tuple (caller runs the same app_catalog.lookup the
        // forwarding hot path used to stamp the conntrack entry, mirroring the
        // #2520 close-side fix). 0 stays the UNKNOWN sentinel.
        buf[base + 132..base + 134].copy_from_slice(&application_id.to_le_bytes());
        // [134] close reason — 0 (a create has none).
        // [135] #2508 SYSLOG gate — always set (producer-gated).
        buf[base + 135] = RT_FLOW_LOG_SYSLOG;
        // #4915: [152:160] the dataplane's stable session id (LE u64), the same
        // value the matching SESSION_CLOSE frame carries. The Go decoder reads it
        // only when the frame carries it (len >= 160).
        buf[base + 152..base + 160].copy_from_slice(&session_id.to_le_bytes());
        buf[base + 140..base + 144]
            .copy_from_slice(&POLICY_CONFIG_GENERATION_MARKER.to_le_bytes());
        buf[base + SESSION_POLICY_GENERATION_OFFSET..base + SESSION_POLICY_GENERATION_OFFSET + 8]
            .copy_from_slice(&policy_generation.to_le_bytes());

        write_header(
            &mut buf,
            SESSION_RT_FLOW_PAYLOAD_SIZE as u32,
            MSG_SESSION_CREATE_RT_FLOW,
            seq,
        );

        EventFrame {
            data: buf,
            len: (FRAME_HEADER_SIZE + SESSION_RT_FLOW_PAYLOAD_SIZE) as u16,
            seq,
        }
    }

    /// Encode a fixed-size security telemetry event using the existing
    /// RT_FLOW dataplane.Event wire shape consumed by the Go ringbuf parser.
    ///
    /// Payload layout (144 bytes) matches `pkg/dataplane.Event`: timestamp,
    /// 16-byte src/dst IP slots, big-endian ports, little-endian identities
    /// and zones, event/protocol/action/address-family bytes, NAT slots, and
    /// extended ingress-ifindex/application fields.
    #[allow(dead_code)]
    pub(crate) fn encode_dataplane_event(seq: u64, event: &DataplaneEventPayload) -> Self {
        let mut buf = [0u8; super::EVENT_FRAME_CAPACITY];
        let base = FRAME_HEADER_SIZE;
        let wire_af = rt_flow_addr_family(event.addr_family, event.src_ip);
        let policy_or_reason_id = match event.kind {
            DataplaneEventKind::PolicyDeny => event.policy_id,
            DataplaneEventKind::ScreenDrop => event.screen_id,
            DataplaneEventKind::FilterLog => event.filter_id,
            // #2512: SESSION_CLOSE / SESSION_CREATE share the per-kind budget
            // accounting but NOT this generic deny/screen/filter payload
            // encoder — they have their own `encode_session_close_rt_flow` /
            // `encode_session_create_rt_flow` builders with a distinct 144-byte
            // layout (no DataplaneEventPayload is ever constructed for them).
            DataplaneEventKind::SessionClose | DataplaneEventKind::SessionCreate => {
                debug_assert!(
                    false,
                    "encode_dataplane_event called with a session-close/create kind; \
                     use the dedicated RT_FLOW encoders"
                );
                0
            }
        };

        buf[base..base + 8].copy_from_slice(&event.timestamp_ns.to_le_bytes());
        write_ip_16(&mut buf, base + 8, event.src_ip);
        write_ip_16(&mut buf, base + 24, event.dst_ip);
        buf[base + 40..base + 42].copy_from_slice(&event.src_port.to_be_bytes());
        buf[base + 42..base + 44].copy_from_slice(&event.dst_port.to_be_bytes());
        buf[base + 44..base + 48].copy_from_slice(&policy_or_reason_id.to_le_bytes());
        buf[base + 48..base + 50].copy_from_slice(&event.ingress_zone_id.to_le_bytes());
        buf[base + 50..base + 52].copy_from_slice(&event.egress_zone_id.to_le_bytes());
        buf[base + 52] = event.kind.rt_flow_event_type();
        buf[base + 53] = event.protocol;
        buf[base + 54] = event.action;
        buf[base + 55] = wire_af;
        if event.kind == DataplaneEventKind::PolicyDeny {
            // #10978: POLICY_DENY's rule_id duplicates policy_id and term_id
            // is zero. Use those eight bytes for the producing policy-table
            // generation; the marker in reserved [140:144] distinguishes
            // these frames from older producers and eBPF records.
            buf[base + 56..base + 64].copy_from_slice(&event.config_generation.to_le_bytes());
            buf[base + 140..base + 144]
                .copy_from_slice(&POLICY_CONFIG_GENERATION_MARKER.to_le_bytes());
        } else {
            buf[base + 56..base + 60].copy_from_slice(&event.rule_id.to_le_bytes());
            buf[base + 60..base + 64].copy_from_slice(&event.term_id.to_le_bytes());
        }
        buf[base + 64..base + 66].copy_from_slice(&event.owner_rg_id.to_le_bytes());
        write_ip_opt_16(&mut buf, base + 72, event.nat_src_ip);
        write_ip_opt_16(&mut buf, base + 88, event.nat_dst_ip);
        buf[base + 104..base + 106].copy_from_slice(&event.nat_src_port.to_be_bytes());
        buf[base + 106..base + 108].copy_from_slice(&event.nat_dst_port.to_be_bytes());
        buf[base + 128..base + 132].copy_from_slice(&event.ingress_ifindex.to_le_bytes());
        buf[base + 132..base + 134].copy_from_slice(&event.application_id.to_le_bytes());
        buf[base + 134] = event.reason;

        write_header(
            &mut buf,
            SECURITY_EVENT_PAYLOAD_SIZE as u32,
            event.kind.msg_type(),
            seq,
        );

        EventFrame {
            data: buf,
            len: (FRAME_HEADER_SIZE + SECURITY_EVENT_PAYLOAD_SIZE) as u16,
            seq,
        }
    }
}
