//! RFC 2890 GRE tunnel-discriminator extraction for TRANSIT GRE (#7188).
//!
//! GRE is IP protocol 47 and has no L4 ports, so two tunnels between the same
//! pair of outer endpoints are indistinguishable by 5-tuple. Since #6837 the
//! dataplane declines to invent a tuple for them — `metadata_tuple_complete`
//! returns false for protocol 47, so transit GRE is FLOWLESS rather than sharing
//! one zero-ported `SessionKey`. What that gives up is stateful return admission
//! and session visibility, and the RFC 2890 Key is the discriminator that can
//! restore both: it is carried identically in BOTH directions of a tunnel, which
//! is what a session key requires.
//!
//! DISTINCT FROM THE DECAP WALK in `gre.rs`. That one parses GRE this box
//! TERMINATES: it validates the checksum, refuses on mismatch, and resolves an
//! inner packet. This one only classifies a packet PASSING THROUGH, so it
//! deliberately does not validate the checksum — a transit frame with a bad GRE
//! checksum is not ours to drop, and dropping it here would be a behaviour
//! change smuggled in under an identity change. It skips the field and reads on.
//!
//! The refusal discipline is shared, and deliberately: version and routing are
//! both hard refusals in `gre.rs` for reasons that apply identically here.
//!
//! THE SEAM IS CLOSED. This module's landing cut said "nothing in production
//! calls this yet"; that has not been true since `stage_parse_flow_and_learn`
//! grew `None if worker_ctx.forwarding.gre_acceleration =>
//! gre_keyed_session_flow(..)` (`afxdp/poll_stages.rs`), which is the read this
//! module was staged for. The `#![allow(dead_code)]` stays because the module
//! still carries classification helpers the single call site does not reach.
//!
//! What this classification now feeds, beyond the local key: the discriminator
//! rides the HA session-sync wire (#7188, `session/discriminator.rs`
//! `to_wire`/`from_wire`), so a misclassification here is not merely a local
//! identity error — it is the identity a peer imports after a failover. See
//! `docs/session-sync-architecture.md`, "Tunnel Session-Identity
//! Discriminator".
#![allow(dead_code)]

use super::gre::{GRE_FLAG_CHECKSUM, GRE_FLAG_KEY};
use super::types::{SessionFlow, UserspaceDpMeta};
use crate::session::TunnelDiscriminator;

/// RFC 1701 Routing Present. RFC 2890 declares the bit reserved-zero; a frame
/// that sets it carries a variable-length Source Route Entry list with no fixed
/// offset, so nothing after it can be located.
const GRE_FLAG_ROUTING: u16 = 0x4000;
/// Version lives in the low 3 bits. RFC 2784/2890 GRE is version 0; RFC 2637
/// PPTP enhanced GRE is version 1 and re-purposes the same 32 bits.
const GRE_VERSION_MASK: u16 = 0x0007;
/// RFC 2637 enhanced GRE. The version this node pairs through the association
/// table rather than through an RFC 2890 Key.
const GRE_VERSION_PPTP: u16 = 0x0001;

/// Classify a transit GRE packet's RFC 2890 discriminator.
///
/// `gre_offset` is the frame offset of the GRE header; `outer_end` is the offset
/// at which the OUTER IP datagram ends, as declared by the IP header rather than
/// by the backing slice. Bounding on the declared end rather than `frame.len()`
/// is the #2361 rule: a frame carrying trailing L2 pad or attacker-supplied
/// slack must not have an option field read out of that slack.
///
/// Every failure path returns `Unparseable`, never `Unkeyed`.
pub(in crate::afxdp) fn gre_transit_discriminator(
    frame: &[u8],
    gre_offset: usize,
    outer_end: usize,
) -> TunnelDiscriminator {
    // Bound reads by the DECLARED datagram end, and only then by the slice.
    let Some(outer) = frame.get(..outer_end.min(frame.len())) else {
        return TunnelDiscriminator::Unparseable;
    };
    let Some(base) = outer.get(gre_offset..gre_offset + 4) else {
        return TunnelDiscriminator::Unparseable;
    };
    let flags_version = u16::from_be_bytes([base[0], base[1]]);

    // Version 1 is PPTP enhanced GRE, whose 32 bits after the flags word are
    // `Payload Length | Call ID` — NOT a Key. Reading them with RFC 2890 field
    // order would promote a per-packet-varying length as if it were a stable
    // tunnel identity. PPTP call-ID pairing is directional and lands separately.
    if (flags_version & GRE_VERSION_MASK) != 0 {
        return TunnelDiscriminator::Unparseable;
    }
    // Source Route Entries have no fixed offset, so nothing behind them can be
    // located — including the Key.
    if (flags_version & GRE_FLAG_ROUTING) != 0 {
        return TunnelDiscriminator::Unparseable;
    }
    if (flags_version & GRE_FLAG_KEY) == 0 {
        return TunnelDiscriminator::Unkeyed;
    }

    // RFC 2890 field order is Checksum+Reserved1, then Key, then Sequence. The
    // checksum field is SKIPPED, not validated — see the module note.
    let mut off = gre_offset + 4;
    if (flags_version & GRE_FLAG_CHECKSUM) != 0 {
        if outer.get(off..off + 4).is_none() {
            return TunnelDiscriminator::Unparseable;
        }
        off += 4;
    }
    match outer.get(off..off + 4) {
        Some(key) => {
            let Ok(bytes) = <[u8; 4]>::try_from(key) else {
                return TunnelDiscriminator::Unparseable;
            };
            TunnelDiscriminator::Keyed(u32::from_be_bytes(bytes))
        }
        None => TunnelDiscriminator::Unparseable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a frame whose GRE header starts at `GRE_OFF`, with `flags` and the
    /// given option words appended in RFC 2890 order. `slack` bytes of trailing
    /// garbage are appended BEYOND the declared datagram end, so a test can
    /// prove a read is bounded by the declaration and not by the slice.
    const GRE_OFF: usize = 20; // a plain 20-byte IPv4 header

    fn frame(flags: u16, options: &[u32], slack: usize) -> (Vec<u8>, usize) {
        let mut f = vec![0u8; GRE_OFF];
        f.extend_from_slice(&flags.to_be_bytes());
        f.extend_from_slice(&0x0800u16.to_be_bytes()); // inner proto: IPv4
        for w in options {
            f.extend_from_slice(&w.to_be_bytes());
        }
        let outer_end = f.len();
        f.extend(std::iter::repeat(0xAA).take(slack));
        (f, outer_end)
    }

    const K: u16 = GRE_FLAG_KEY;
    const C: u16 = GRE_FLAG_CHECKSUM;
    const S: u16 = 0x1000;
    const R: u16 = GRE_FLAG_ROUTING;

    // --- #7699: the DATA-CHANNEL RESOLVE, and acceptance criterion 2 ---------

    /// A version-1 GRE frame plus the meta for it, with the outer endpoints
    /// given as parameters so a cell can send in both directions.
    fn pptp_v4_frame(
        src: [u8; 4],
        dst: [u8; 4],
        call_id: u16,
    ) -> (Vec<u8>, UserspaceDpMeta) {
        let mut f = vec![0u8; 20];
        f[0] = 0x45; // IPv4, IHL 5
        f[9] = crate::ip_proto::PROTO_GRE;
        f[12..16].copy_from_slice(&src);
        f[16..20].copy_from_slice(&dst);
        f.extend_from_slice(&(K | 0x0001).to_be_bytes()); // Key set, version 1
        f.extend_from_slice(&0x880Bu16.to_be_bytes()); // PPP
        f.extend_from_slice(&0x05DCu16.to_be_bytes()); // payload length
        f.extend_from_slice(&call_id.to_be_bytes());
        let total = f.len() as u16;
        f[2..4].copy_from_slice(&total.to_be_bytes()); // IP total_len
        let mut meta = UserspaceDpMeta {
            addr_family: libc::AF_INET as u8,
            protocol: crate::ip_proto::PROTO_GRE,
            l3_offset: 0,
            l4_offset: 20,
            ..Default::default()
        };
        meta.flow_src_addr[..4].copy_from_slice(&src);
        meta.flow_dst_addr[..4].copy_from_slice(&dst);
        (f, meta)
    }

    const PEER_A: [u8; 4] = [10, 0, 0, 1];
    const PEER_B: [u8; 4] = [10, 0, 0, 2];

    fn install_call(
        sessions: &mut crate::session::SessionTable,
        a_call_id: u16,
        b_call_id: u16,
    ) -> u32 {
        let call = crate::session::pptp::PptpCall::new(
            std::net::IpAddr::from(PEER_A),
            a_call_id,
            std::net::IpAddr::from(PEER_B),
            b_call_id,
        );
        let control = crate::session::pptp::ControlChannelId::new(
            std::net::IpAddr::from(PEER_A),
            49_152,
            std::net::IpAddr::from(PEER_B),
            1723,
        );
        sessions
            .pptp_mut()
            .install(call, control, 1_000)
            .expect("fixture: the association must install")
    }

    /// ACCEPTANCE CRITERION 2, and the reason this issue exists: two
    /// SIMULTANEOUS calls between ONE endpoint pair must not alias.
    ///
    /// Before this join a version-1 packet was flowless — `Unparseable`, which
    /// is fail-closed across classes but equal to ITSELF within one, so both
    /// calls shared a key. Everything else in the tuple is identical here (same
    /// addresses, same protocol, no ports), so the discriminator is the only
    /// thing that can separate them.
    #[test]
    fn two_simultaneous_calls_between_one_pair_do_not_alias_7699() {
        let mut sessions = crate::session::SessionTable::new();
        install_call(&mut sessions, 100, 200);
        install_call(&mut sessions, 101, 201);

        let (f1, m1) = pptp_v4_frame(PEER_A, PEER_B, 200);
        let (f2, m2) = pptp_v4_frame(PEER_A, PEER_B, 201);
        let k1 = pptp_data_session_flow(&f1, m1, &mut sessions, 2_000)
            .expect("an installed call must resolve")
            .forward_key;
        let k2 = pptp_data_session_flow(&f2, m2, &mut sessions, 2_000)
            .expect("an installed call must resolve")
            .forward_key;

        assert_eq!(k1.src_ip, k2.src_ip);
        assert_eq!(k1.dst_ip, k2.dst_ip);
        assert_ne!(
            k1, k2,
            "two simultaneous PPTP calls between one endpoint pair share a \
             SessionKey. That is the aliasing this issue exists to close, and it \
             is what a flowless version-1 packet does today (#7699)"
        );
    }

    /// The other half of the same criterion: the TWO DIRECTIONS of ONE call must
    /// resolve to the SAME handle.
    ///
    /// RFC 2637 §4.1 call ids are per-direction — each side allocates its own —
    /// so the two directions carry DIFFERENT values on the wire. That is why no
    /// symmetric reverse-key transform can pair them, and why the discriminator
    /// carries a locally derived handle rather than the id off the packet: a
    /// packet-derived discriminator would make a reply match no session at all,
    /// which is worse than the aliasing it replaces.
    ///
    /// The fixture uses 100 and 200 deliberately. Equal ids would make this pass
    /// under an implementation that keyed on the raw call id.
    #[test]
    fn both_directions_of_one_data_packet_resolve_to_one_handle_7699() {
        let mut sessions = crate::session::SessionTable::new();
        let handle = install_call(&mut sessions, 100, 200);

        // A -> B carries the id B allocated; B -> A carries the id A allocated.
        let (fwd, mfwd) = pptp_v4_frame(PEER_A, PEER_B, 200);
        let (rev, mrev) = pptp_v4_frame(PEER_B, PEER_A, 100);
        let d_fwd = pptp_data_session_flow(&fwd, mfwd, &mut sessions, 2_000)
            .expect("forward must resolve")
            .forward_key
            .discriminator;
        let d_rev = pptp_data_session_flow(&rev, mrev, &mut sessions, 2_000)
            .expect("reverse must resolve")
            .forward_key
            .discriminator;

        assert_eq!(d_fwd, TunnelDiscriminator::Pptp(handle));
        assert_eq!(
            d_fwd, d_rev,
            "the two directions of one call resolved to different identities. \
             The call ids differ per direction by RFC 2637, so anything derived \
             from the packet's own id splits one call in two — a reply that \
             matches no session at all (#7699)"
        );
    }

    /// AN UNKNOWN CALL IS FORWARDED AND COUNTED, NOT DROPPED — and the counter
    /// is what makes the condition visible.
    ///
    /// A call already up when the daemon started, or one whose control segment
    /// was not parseable, has no association. It gets no session, which is
    /// exactly what a version-1 packet gets today, so this change can only ADD
    /// identity and never remove forwarding.
    ///
    /// The counter half matters on its own: it is documented as expected
    /// non-zero during startup and after restart, and until this function
    /// existed nothing called `note_unassociated`, so it read zero forever — and
    /// a lone counter at zero cannot distinguish "nothing happened" from "this
    /// code is unreachable".
    #[test]
    fn an_unassociated_call_is_flowless_and_counted_7699() {
        let mut sessions = crate::session::SessionTable::new();
        install_call(&mut sessions, 100, 200);
        let before = sessions.pptp().unassociated_count();

        let (f, m) = pptp_v4_frame(PEER_A, PEER_B, 999);
        assert!(
            pptp_data_session_flow(&f, m, &mut sessions, 2_000).is_none(),
            "an unknown call id must stay FLOWLESS — giving it an identity of \
             its own would let it alias the next call that reuses the id"
        );
        assert_eq!(
            sessions.pptp().unassociated_count(),
            before + 1,
            "the unassociated packet was not counted. The counter is the only \
             signal that this path is reachable at all, and it reads the same \
             zero whether nothing happened or the code is dead (#7699)"
        );
    }

    /// `resolve_and_touch`, not `resolve`: the idle clock must advance on DATA.
    ///
    /// Without a data-path caller the clock only moved at install, so an
    /// association's life was bounded from when it was LEARNED — a long-lived
    /// call carrying traffic aged out on its learn time. Its expiry then frees a
    /// 16-bit call id that is REUSED, so the next call taking that id
    /// mis-attributes onto the dead handle.
    #[test]
    fn a_resolved_data_packet_refreshes_the_idle_clock_7699() {
        let mut sessions = crate::session::SessionTable::new();
        install_call(&mut sessions, 100, 200);

        let late = 1_000 + crate::session::pptp::ASSOCIATION_IDLE_TIMEOUT_NS - 1;
        let (f, m) = pptp_v4_frame(PEER_A, PEER_B, 200);
        assert!(
            pptp_data_session_flow(&f, m, &mut sessions, late).is_some(),
            "fixture: the packet must resolve, or it cannot refresh anything"
        );

        // Past the timeout measured from INSTALL, but not from that packet.
        let after_install_timeout = 1_000 + crate::session::pptp::ASSOCIATION_IDLE_TIMEOUT_NS + 1;
        let expired = sessions
            .pptp_mut()
            .expire_idle(after_install_timeout, crate::session::pptp::ASSOCIATION_IDLE_TIMEOUT_NS);
        assert_eq!(
            expired, 0,
            "an association carrying data was expired on its LEARN time. The \
             idle timeout must mean 'no traffic', not 'old' — expiring a live \
             call frees a 16-bit id that is reused, so the next call taking it \
             mis-attributes onto the dead handle (#7699)"
        );
    }

    // --- #7699: the PPTP (GRE version 1) call-id extractor -------------------

    /// A version-1 enhanced-GRE header. The 32 bits the Key bit announces are
    /// `Payload Length | Call ID`, so the two halves are given DIFFERENT values
    /// — a builder that set them equal could not tell a correct extractor from
    /// one reading the wrong half.
    fn pptp_frame(flags: u16, payload_len: u16, call_id: u16, slack: usize) -> (Vec<u8>, usize) {
        let mut f = vec![0u8; GRE_OFF];
        f.extend_from_slice(&(flags | 0x0001).to_be_bytes()); // version 1
        f.extend_from_slice(&0x880Bu16.to_be_bytes()); // PPP
        f.extend_from_slice(&payload_len.to_be_bytes());
        f.extend_from_slice(&call_id.to_be_bytes());
        let outer_end = f.len();
        f.extend(std::iter::repeat(0xAA).take(slack));
        (f, outer_end)
    }

    /// THE HALF THAT MATTERS. The high half of the repurposed word is the
    /// payload LENGTH, which varies per packet; the low half is the call id.
    ///
    /// Reading the wrong half — which is what allowing version 1 through the
    /// RFC 2890 extractor would do — gives every packet of one call a different
    /// identity, so the call would get a new session per packet. The two halves
    /// differ in this fixture precisely so that failure is visible.
    #[test]
    fn the_call_id_is_the_low_half_not_the_payload_length_7699() {
        let (f, end) = pptp_frame(K, 0x05DC, 0x2A2A, 0);
        assert_eq!(
            pptp_call_id(&f, GRE_OFF, end),
            Some(0x2A2A),
            "the extractor must read the CALL ID (low half). 0x05DC is the \
             payload length, which varies per packet — reading it would give one \
             call a new identity per packet"
        );
    }

    /// Version 0 belongs to the RFC 2890 extractor, and the split must be
    /// exclusive in BOTH directions or a packet gets two identities.
    #[test]
    fn the_two_gre_versions_do_not_overlap_7699() {
        let (v1, e1) = pptp_frame(K, 0x0010, 0x0007, 0);
        let (v0, e0) = frame(K, &[0x0000_0007], 0);
        assert_eq!(pptp_call_id(&v1, GRE_OFF, e1), Some(7));
        assert_eq!(
            pptp_call_id(&v0, GRE_OFF, e0),
            None,
            "the PPTP extractor claimed a version-0 packet, which the RFC 2890 \
             extractor also claims — one packet with two identities"
        );
        assert_eq!(
            gre_transit_discriminator(&v1, GRE_OFF, e1),
            TunnelDiscriminator::Unparseable,
            "the RFC 2890 extractor claimed a version-1 packet, which would read \
             the payload length as a Key"
        );
    }

    /// The refusals, each for its own reason rather than as a catch-all.
    #[test]
    fn the_call_id_extractor_refuses_what_it_cannot_locate_7699() {
        let (no_key, e) = pptp_frame(0, 0x0010, 0x0007, 0);
        assert_eq!(
            pptp_call_id(&no_key, GRE_OFF, e),
            None,
            "RFC 2637 requires the Key bit; without it the 32 bits are not \
             announced and reading them assumes a layout the sender did not claim"
        );

        let (routed, er) = pptp_frame(K | R, 0x0010, 0x0007, 0);
        assert_eq!(
            pptp_call_id(&routed, GRE_OFF, er),
            None,
            "a Source Route Entry list has no fixed length, so nothing behind it \
             can be located — including the call id"
        );

        // Declared end BEFORE the call id, with the bytes present in the slice.
        let (slack, end) = pptp_frame(K, 0x0010, 0x0007, 0);
        assert_eq!(
            pptp_call_id(&slack, GRE_OFF, end - 2),
            None,
            "the read is bounded by the SLICE rather than the declared datagram \
             end, so trailing L2 pad or attacker-supplied slack can be read as a \
             call id (#2361)"
        );
    }

    #[test]
    fn unkeyed_is_not_keyed_zero_7188() {
        let (unkeyed, end) = frame(0, &[], 0);
        let (keyed_zero, end0) = frame(K, &[0], 0);
        let a = gre_transit_discriminator(&unkeyed, GRE_OFF, end);
        let b = gre_transit_discriminator(&keyed_zero, GRE_OFF, end0);
        assert_eq!(a, TunnelDiscriminator::Unkeyed);
        assert_eq!(b, TunnelDiscriminator::Keyed(0));
        assert_ne!(
            a, b,
            "an UNKEYED tunnel and a tunnel whose RFC 2890 Key is literally 0 are \
             different tunnels and both are legal. Collapsing them lets an \
             unkeyed tunnel join a keyed-zero session (#7188 decision 6)"
        );
    }

    #[test]
    fn distinct_keys_are_distinct_discriminators_7188() {
        let (a, ea) = frame(K, &[0x0000_002a], 0);
        let (b, eb) = frame(K, &[0x0000_002b], 0);
        assert_eq!(
            gre_transit_discriminator(&a, GRE_OFF, ea),
            TunnelDiscriminator::Keyed(0x2a)
        );
        assert_ne!(
            gre_transit_discriminator(&a, GRE_OFF, ea),
            gre_transit_discriminator(&b, GRE_OFF, eb),
            "two RFC 2890 keys between the same endpoints must not share an identity \
             — that is the whole feature (#7188)"
        );
    }

    #[test]
    fn checksum_present_shifts_the_key_by_four_7188() {
        // Checksum+Reserved1 comes FIRST, then Key. Reading the key without
        // skipping it returns the checksum word — a value that VARIES per
        // packet, so it would split one tunnel into a new session per packet.
        let (f, end) = frame(C | K, &[0xdead_beef, 0x0000_0099], 0);
        assert_eq!(
            gre_transit_discriminator(&f, GRE_OFF, end),
            TunnelDiscriminator::Keyed(0x99),
            "the Key must be read AFTER the 4-byte Checksum+Reserved1 field"
        );
    }

    #[test]
    fn sequence_present_does_not_move_the_key_7188() {
        // Sequence comes AFTER Key, so its presence must not shift the read.
        let (f, end) = frame(K | S, &[0x0000_0077, 0x0000_0001], 0);
        assert_eq!(
            gre_transit_discriminator(&f, GRE_OFF, end),
            TunnelDiscriminator::Keyed(0x77)
        );
    }

    #[test]
    fn unsupported_version_is_unparseable_not_unkeyed_7188() {
        // PPTP enhanced GRE (version 1) re-purposes the same 32 bits as
        // `Payload Length | Call ID`. Reading them as a Key would promote a
        // per-packet length as a stable identity.
        let (f, end) = frame(K | 1, &[0x0000_0055], 0);
        assert_eq!(
            gre_transit_discriminator(&f, GRE_OFF, end),
            TunnelDiscriminator::Unparseable,
            "a version-1 header must fail CLOSED, not fall back to Unkeyed"
        );
    }

    #[test]
    fn routing_present_is_unparseable_7188() {
        let (f, end) = frame(K | R, &[0x0000_0055], 0);
        assert_eq!(
            gre_transit_discriminator(&f, GRE_OFF, end),
            TunnelDiscriminator::Unparseable,
            "a Source Route Entry list has no fixed offset, so the Key behind it \
             cannot be located and must not be guessed"
        );
    }

    #[test]
    fn truncated_key_is_unparseable_7188() {
        // K set but the key word is absent.
        let (f, end) = frame(K, &[], 0);
        assert_eq!(
            gre_transit_discriminator(&f, GRE_OFF, end),
            TunnelDiscriminator::Unparseable
        );
        // K set, checksum set, only the checksum word present.
        let (g, endg) = frame(C | K, &[0xdead_beef], 0);
        assert_eq!(
            gre_transit_discriminator(&g, GRE_OFF, endg),
            TunnelDiscriminator::Unparseable
        );
        // Not even the 4-byte base header.
        let short = vec![0u8; GRE_OFF + 2];
        assert_eq!(
            gre_transit_discriminator(&short, GRE_OFF, short.len()),
            TunnelDiscriminator::Unparseable
        );
    }

    /// #2361: the read is bounded by the DECLARED datagram end, not the slice.
    /// The key bytes exist in the backing buffer here — as trailing slack — and
    /// must still not be read.
    #[test]
    fn key_in_trailing_slack_is_not_read_7188() {
        let (f, declared_end) = frame(K, &[], 8);
        assert!(
            f.len() > declared_end,
            "fixture must actually carry slack past the declared end, or this \
             cell cannot distinguish a bounded read from an unbounded one"
        );
        assert_eq!(
            gre_transit_discriminator(&f, GRE_OFF, declared_end),
            TunnelDiscriminator::Unparseable,
            "the Key must not be read out of bytes beyond the IP-declared end"
        );
        // Control: with the declaration extended to cover them, the same bytes
        // ARE read — proving the refusal above came from the bound and not from
        // the bytes being absent.
        assert_eq!(
            gre_transit_discriminator(&f, GRE_OFF, f.len()),
            TunnelDiscriminator::Keyed(0xAAAA_AAAA)
        );
    }

    #[test]
    fn offset_past_end_is_unparseable_not_a_panic_7188() {
        let (f, end) = frame(K, &[0x1234_5678], 0);
        assert_eq!(
            gre_transit_discriminator(&f, end + 64, end),
            TunnelDiscriminator::Unparseable
        );
        assert_eq!(
            gre_transit_discriminator(&[], 0, 0),
            TunnelDiscriminator::Unparseable
        );
    }

    /// A GRE frame with a full IPv4 header, so `outer_datagram_end` and the
    /// metadata flow builder both have real material to work from.
    fn gre_v4_frame(flags: u16, options: &[u32]) -> (Vec<u8>, UserspaceDpMeta) {
        let mut f = vec![0u8; 20];
        f[0] = 0x45; // IPv4, IHL 5
        f[9] = crate::ip_proto::PROTO_GRE;
        f[12..16].copy_from_slice(&[10, 0, 0, 1]); // src
        f[16..20].copy_from_slice(&[10, 0, 0, 2]); // dst
        f.extend_from_slice(&flags.to_be_bytes());
        f.extend_from_slice(&0x0800u16.to_be_bytes());
        for w in options {
            f.extend_from_slice(&w.to_be_bytes());
        }
        let total = f.len() as u16;
        f[2..4].copy_from_slice(&total.to_be_bytes()); // IP total_len
        let mut meta = UserspaceDpMeta {
            addr_family: libc::AF_INET as u8,
            protocol: crate::ip_proto::PROTO_GRE,
            l3_offset: 0,
            l4_offset: 20,
            ..Default::default()
        };
        meta.flow_src_addr[..4].copy_from_slice(&[10, 0, 0, 1]);
        meta.flow_dst_addr[..4].copy_from_slice(&[10, 0, 0, 2]);
        (f, meta)
    }

    /// The feature: two RFC 2890 keys between the SAME outer endpoints must not
    /// share an identity. Everything else in the tuple is identical here, so the
    /// discriminator is the only thing that can separate them.
    #[test]
    fn two_keys_same_endpoints_are_distinct_flows_7188() {
        let (a, ma) = gre_v4_frame(K, &[0x0000_002a]);
        let (b, mb) = gre_v4_frame(K, &[0x0000_002b]);
        let fa = gre_keyed_session_flow(&a, ma).expect("keyed GRE must produce a flow");
        let fb = gre_keyed_session_flow(&b, mb).expect("keyed GRE must produce a flow");
        assert_eq!(fa.forward_key.src_ip, fb.forward_key.src_ip);
        assert_eq!(fa.forward_key.dst_ip, fb.forward_key.dst_ip);
        assert_ne!(
            fa.forward_key, fb.forward_key,
            "two tunnels between one endpoint pair must not share a SessionKey — \
             that is the whole feature (#7188)"
        );
    }

    /// Decision 5: the discriminator is NOT a port. Ports stay honestly zero, so
    /// every port consumer (show, RT_FLOW, clear filters, NAT alias matching)
    /// keeps reporting the truth rather than a fabricated transport port.
    #[test]
    fn keyed_gre_reports_no_fake_ports_7188() {
        let (f, m) = gre_v4_frame(K, &[0xdead_beef]);
        let flow = gre_keyed_session_flow(&f, m).expect("flow");
        assert_eq!(flow.forward_key.src_port, 0);
        assert_eq!(flow.forward_key.dst_port, 0);
        assert_eq!(
            flow.forward_key.discriminator,
            TunnelDiscriminator::Keyed(0xdead_beef)
        );
    }

    /// Unkeyed GRE still gets an identity, and it is NOT the keyed-zero one.
    #[test]
    fn unkeyed_and_keyed_zero_are_distinct_flows_7188() {
        let (u, mu) = gre_v4_frame(0, &[]);
        let (z, mz) = gre_v4_frame(K, &[0]);
        let fu = gre_keyed_session_flow(&u, mu).expect("unkeyed flow");
        let fz = gre_keyed_session_flow(&z, mz).expect("keyed-zero flow");
        assert_ne!(fu.forward_key, fz.forward_key);
    }

    /// Fail closed: a header we could not read gets NO session, so it cannot
    /// alias a legitimate one. It is also what such a packet does today.
    #[test]
    fn unparseable_stays_flowless_7188() {
        let (v1, mv1) = gre_v4_frame(K | 1, &[0x0000_0055]); // version 1
        assert!(gre_keyed_session_flow(&v1, mv1).is_none());
        let (rt, mrt) = gre_v4_frame(K | R, &[0x0000_0055]); // routing present
        assert!(gre_keyed_session_flow(&rt, mrt).is_none());
        let (tr, mtr) = gre_v4_frame(K, &[]); // truncated key
        assert!(gre_keyed_session_flow(&tr, mtr).is_none());
    }

    /// Non-GRE never reaches this arm even if called: the caller gates on the
    /// knob, and this gates on the protocol.
    #[test]
    fn non_gre_is_never_keyed_7188() {
        let (f, mut m) = gre_v4_frame(K, &[0x0000_0001]);
        m.protocol = crate::ip_proto::PROTO_TCP;
        assert!(gre_keyed_session_flow(&f, m).is_none());
    }

    /// INERTNESS with acceleration OFF, demonstrated rather than asserted.
    ///
    /// With the knob off, `stage_parse_flow_and_learn` returns exactly what
    /// `parse_session_flow_from_bytes` returned — the keyed arm is behind
    /// `None if worker_ctx.forwarding.gre_acceleration`. So the acceleration-off
    /// behaviour IS this function's behaviour, and this cell pins that #6837's
    /// flowless treatment of transit GRE is untouched by #7188.
    ///
    /// If this ever returns `Some`, the knob has stopped being a switch: GRE
    /// would be getting a session on the default path, which is the zero-ported
    /// aliasing #6837 removed.
    #[test]
    fn acceleration_off_leaves_transit_gre_flowless_7188() {
        for (label, flags, opts) in [
            ("keyed", K, &[0x0000_002a][..]),
            ("unkeyed", 0, &[][..]),
            ("keyed-zero", K, &[0][..]),
        ] {
            let (f, m) = gre_v4_frame(flags, opts);
            assert!(
                crate::afxdp::frame::parse_session_flow_from_bytes(&f, m).is_none(),
                "{label} transit GRE must stay FLOWLESS on the acceleration-off path \
                 (#6837); a Some here means the knob is not a switch and GRE is \
                 getting a session by default"
            );
            // Control: the same frame DOES yield a flow through the keyed arm,
            // so the None above is the knob's doing and not an inert fixture.
            assert!(
                gre_keyed_session_flow(&f, m).is_some(),
                "{label} fixture must be capable of producing a keyed flow, or the \
                 assertion above passes for the wrong reason"
            );
        }
    }

    #[test]
    fn default_is_none_so_existing_protocols_are_unchanged_7188() {
        assert_eq!(TunnelDiscriminator::default(), TunnelDiscriminator::None);
        assert!(TunnelDiscriminator::None.is_none());
        assert!(!TunnelDiscriminator::Unkeyed.is_none());
        assert!(!TunnelDiscriminator::Keyed(0).is_none());
        assert!(!TunnelDiscriminator::Unparseable.is_none());
    }
}

/// Build the keyed-GRE session flow for a transit packet, or `None` to leave it
/// flowless (#7188 cut 1c).
///
/// This is an ADDITIVE arm, deliberately. It does not touch
/// `metadata_tuple_complete`, which #6837 set to refuse protocol 47 and whose
/// comment warns the discriminator "must not come back as a metadata-side
/// default". The shim does not parse GRE, so the metadata side has no
/// discriminator to offer and must keep refusing; this arm supplies the identity
/// from the FRAME, which is the only side that can have read it.
///
/// With `gre-performance-acceleration` off the caller never reaches here, so the
/// packet path is bit-identical to #6837's flowless behaviour.
///
/// `Unparseable` returns `None` — flowless. A header we could not read gets no
/// session at all, which is a stronger form of decision 6's "must not merge into
/// a legitimate session" than giving it an identity of its own would be: a
/// packet with no session cannot alias anything, and this is also exactly what
/// such a packet does today.
pub(in crate::afxdp) fn gre_keyed_session_flow(
    frame: &[u8],
    meta: UserspaceDpMeta,
) -> Option<SessionFlow> {
    if meta.protocol != crate::ip_proto::PROTO_GRE {
        return None;
    }
    let outer_end = super::gre::outer_datagram_end(frame, meta)?;
    let discriminator = gre_transit_discriminator(frame, meta.l4_offset as usize, outer_end);
    match discriminator {
        TunnelDiscriminator::Unparseable | TunnelDiscriminator::None => return None,
        TunnelDiscriminator::Unkeyed | TunnelDiscriminator::Keyed(_) => {}
        TunnelDiscriminator::Ipsec(_) => return None,
        // #7699: cannot arrive from `gre_transit_discriminator`, which returns
        // `Unparseable` for any GRE version != 0 (`GRE_VERSION_MASK`, before
        // the Key read) and PPTP is version 1. A version-1 packet therefore
        // takes the `Unparseable` arm above and produces no session — which is
        // the "forward unassociated" behaviour stage 1 defines, not a drop.
        //
        // Deliberately `return None` rather than `unreachable!()`: this is the
        // AF_XDP hot path and a panic here kills the worker, so an impossible
        // input must degrade, not abort. When the PPTP data path lands it will
        // construct its flow from the association table, not from this
        // version-0 extractor.
        // #7699: cannot arrive from `gre_transit_discriminator`, which returns
        // `Unparseable` for any GRE version != 0 and PPTP is version 1. The
        // PPTP data path is `pptp_data_session_flow` below, which builds its
        // flow from the ASSOCIATION TABLE rather than from this version-0
        // extractor.
        //
        // Deliberately `return None` rather than `unreachable!()`: this is the
        // AF_XDP hot path and a panic here kills the worker, so an impossible
        // input must degrade, not abort.
        TunnelDiscriminator::Pptp(_) => return None,
    }
    let mut flow = super::frame::parse_session_flow_from_meta(meta)?;
    // GRE has no ports and never gains fake ones (#7188 decision 5): identity
    // comes from the discriminator alone, and every port consumer keeps seeing
    // the honest zero.
    flow.forward_key.src_port = 0;
    flow.forward_key.dst_port = 0;
    flow.forward_key.discriminator = discriminator;
    Some(flow)
}

/// #7699: the RFC 2637 §4.1 Call ID off an enhanced-GRE (version 1) data
/// packet, or `None` for anything this node could not pair.
///
/// Deliberately narrow, and each condition is a refusal rather than a default:
///
///   * version must be 1 — version 0 is RFC 2890 GRE and belongs to
///     [`gre_transit_discriminator`], which owns the other side of this split;
///   * the Key bit must be SET. RFC 2637 requires it, and the 32 bits it
///     announces are re-purposed as `Payload Length | Call ID`, not as a Key;
///   * Routing must be CLEAR, because a Source Route Entry list has no fixed
///     length, so nothing behind it can be located — the same reason the
///     version-0 extractor refuses it.
///
/// THE CALL ID IS THE LOW HALF. The high half is the payload length, which
/// varies per packet. Reading the word as an RFC 2890 Key — which is exactly
/// what would happen if version 1 were simply allowed through the existing
/// extractor — would promote a per-packet-varying length into a stable tunnel
/// identity, giving every packet of one call a different session. This function
/// is the other half of `gre_transit_discriminator`'s version-1 refusal, not a
/// relaxation of it.
///
/// Bounds follow the #2361 rule the sibling states: reads are bounded by the
/// DECLARED outer datagram end first and the backing slice second, so trailing
/// L2 pad or attacker-supplied slack cannot be read as a header field.
pub(in crate::afxdp) fn pptp_call_id(
    frame: &[u8],
    gre_offset: usize,
    outer_end: usize,
) -> Option<u16> {
    let outer = frame.get(..outer_end.min(frame.len()))?;
    let base = outer.get(gre_offset..gre_offset + 8)?;
    let flags_version = u16::from_be_bytes([base[0], base[1]]);
    if (flags_version & GRE_VERSION_MASK) != GRE_VERSION_PPTP {
        return None;
    }
    if (flags_version & GRE_FLAG_ROUTING) != 0 {
        return None;
    }
    if (flags_version & GRE_FLAG_KEY) == 0 {
        return None;
    }
    Some(u16::from_be_bytes([base[6], base[7]]))
}

/// #7699: THE DATA-CHANNEL RESOLVE — the join the acceptance criteria depend
/// on, and the counterpart to the control-channel dispatch.
///
/// A PPTP data packet carries the call id the DESTINATION allocated (RFC 2637
/// §4.1), so `(dst, call_id)` is exactly the key the association table is
/// indexed by, and the handle it returns is direction-symmetric — which is why
/// `reverse_direction_discriminator` returns its input for this class.
///
/// WHY IT IS HERE AND NOT IN A STAGE. `stage_parse_flow_and_learn` takes
/// `&WorkerContext`, and the association table is per-worker state on
/// `SessionTable` — deliberately per-worker, broadcast to every worker at
/// install, so the packet path takes no lock to read it. The caller in
/// `poll_descriptor` is the one point in the loop where the frame and
/// `&mut SessionTable` are both in scope.
///
/// UNASSOCIATED IS FORWARDED, NOT DROPPED. A call whose Outgoing-Call-Reply this
/// node has not seen — a call already up when the daemon started, or one whose
/// control segment was not parseable — resolves to `None`, is counted, and gets
/// no session. That is the same flowless treatment a version-1 packet gets
/// today, so this change can only ADD identity, never remove forwarding. The
/// counter is what makes the condition visible instead of silent; it is
/// documented as expected non-zero during startup and after restart, and until
/// this function existed it read zero forever because nothing called it.
pub(in crate::afxdp) fn pptp_data_session_flow(
    frame: &[u8],
    meta: UserspaceDpMeta,
    sessions: &mut crate::session::SessionTable,
    now_ns: u64,
) -> Option<SessionFlow> {
    if meta.protocol != crate::ip_proto::PROTO_GRE {
        return None;
    }
    let outer_end = super::gre::outer_datagram_end(frame, meta)?;
    let call_id = pptp_call_id(frame, meta.l4_offset as usize, outer_end)?;
    let mut flow = super::frame::parse_session_flow_from_meta(meta)?;
    // `resolve_and_touch`, not `resolve`: refreshing on use is what makes the
    // idle timeout mean "no traffic" rather than "old". Without a data-path
    // caller the clock only advanced at install, so a long-lived call carrying
    // data aged out on its LEARN time.
    let Some(handle) = sessions
        .pptp_mut()
        .resolve_and_touch(flow.forward_key.dst_ip, call_id, now_ns)
    else {
        sessions.pptp_mut().note_unassociated();
        return None;
    };
    // GRE has no ports and never gains fake ones (#7188 decision 5).
    flow.forward_key.src_port = 0;
    flow.forward_key.dst_port = 0;
    flow.forward_key.discriminator = TunnelDiscriminator::Pptp(handle);
    Some(flow)
}
