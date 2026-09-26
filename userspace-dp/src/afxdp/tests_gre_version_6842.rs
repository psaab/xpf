//! #6842: the GRE **version** field is a decap discriminator, and refusing a
//! non-zero version is what keeps RFC 2637 (PPTP) enhanced GRE out of the RFC
//! 2784/2890 parser.
//!
//! RFC 2637 §4.1 re-purposes the same 32 bits RFC 2890 defines as an opaque
//! Key:
//!
//! ```text
//!   RFC 2890 :  |                    Key (32)                   |
//!   RFC 2637 :  |  Payload Length (16)  |      Call ID (16)      |
//! ```
//!
//! and adds an Acknowledgment Number field behind an `A` bit (0x0080) that the
//! RFC 2890 fixed field order (Checksum, Key, Sequence) does not skip. Two
//! consequences, both closed by the single version check at the top of
//! `try_native_gre_decap_from_frame`:
//!
//! 1. **Identity.** The high half of a version-1 "Key" is Payload Length,
//!    which changes with every packet. Anything that reads those 32 bits as a
//!    stable tunnel discriminator gets a different value per packet. Today the
//!    only 32-bit Key read in the dataplane is the `match_tunnel_endpoint`
//!    comparison below; #7188 will add a second one on the session path, and
//!    the same version branch has to gate it.
//! 2. **Promotion.** With `A` set, the real layout is Key, Sequence,
//!    Acknowledgment, payload. An RFC 2890 reader skips Key and Sequence only,
//!    so `inner_offset` lands on the Acknowledgment Number — 4 bytes the peer
//!    chose. If those bytes open a well-formed IPv4 header the parser promotes
//!    an attacker-authored packet as the tunnel's decapsulated inner frame.
//!
//! Every test here is a PAIRED cell: the same bytes are run at version 1 and
//! at version 0. The version-0 leg is not decoration — it proves the fixture
//! satisfies every downstream check (endpoint match, inner family, trimmed
//! length, inner L4 offsets), so the version-1 refusal is attributable to the
//! version field alone and not to the fixture falling over somewhere else.
//!
//! Refusal is not the same as a drop: `try_native_gre_decap_from_frame`
//! returns `None` and the frame continues on the ordinary transit /
//! host-inbound path. That is why the counter is only bumped when the outer
//! tuple names a configured GRE endpoint — see
//! `gre_version_refusal_counter_only_counts_frames_offered_to_a_gre_endpoint`.

use super::tests_support::*;
use super::*;
use crate::afxdp::forwarding_build::build_forwarding_state;
use crate::afxdp::gre::{GRE_FLAG_KEY, GRE_FLAG_SEQUENCE, try_native_gre_decap_from_frame};

/// RFC 2637 §4.1 Acknowledgment-Present bit. Unknown to RFC 2890, which is
/// exactly why a version-blind parse mis-locates the payload.
const GRE_FLAG_ACK_V1: u16 = 0x0080;

/// Build a GRE outer frame (peer `outer_src` -> local `outer_dst`) whose
/// flags/version word is `flags | version`, carrying the optional Key and
/// Sequence fields selected by `flags` and then `tail` verbatim.
///
/// `tail` is deliberately NOT called "inner": for a genuine RFC 2637 reader
/// with `A` set its first 4 bytes are the Acknowledgment Number, while an RFC
/// 2890 reader treats them as the start of the inner packet. Handing the same
/// bytes to both readers is the whole point of the fixture.
///
/// The outer IPv4 Total Length is set to exactly cover the GRE header + tail,
/// so `outer_datagram_end` admits all of it and no trailing-pad question is
/// mixed into the result.
fn build_gre_versioned_outer_frame_v4(
    version: u16,
    flags: u16,
    key: u32,
    seq: u32,
    outer_src: [u8; 4],
    tail: &[u8],
) -> Vec<u8> {
    let mut gre = Vec::new();
    gre.extend_from_slice(&(flags | version).to_be_bytes());
    gre.extend_from_slice(&0x0800u16.to_be_bytes()); // inner proto IPv4
    if (flags & GRE_FLAG_KEY) != 0 {
        gre.extend_from_slice(&key.to_be_bytes());
    }
    if (flags & GRE_FLAG_SEQUENCE) != 0 {
        gre.extend_from_slice(&seq.to_be_bytes());
    }
    gre.extend_from_slice(tail);

    let mut frame = Vec::new();
    write_eth_header(
        &mut frame,
        [0x02, 0xbf, 0x72, 0x00, 0x80, 0x08],
        [0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5],
        0,
        0x0800,
    );
    let l3 = frame.len();
    let total = (20 + gre.len()) as u16;
    frame.extend_from_slice(&[0x45, 0x00]);
    frame.extend_from_slice(&total.to_be_bytes());
    frame.extend_from_slice(&[0x00, 0x01, 0x00, 0x00, 64, PROTO_GRE, 0x00, 0x00]);
    frame.extend_from_slice(&outer_src);
    frame.extend_from_slice(&[172, 16, 80, 8]);
    let ip_sum = checksum16(&frame[l3..l3 + 20]);
    frame[l3 + 10] = (ip_sum >> 8) as u8;
    frame[l3 + 11] = ip_sum as u8;
    frame.extend_from_slice(&gre);
    frame
}

/// The `gre_to_self_snapshot` peer — the outer source that resolves the
/// configured GRE endpoint.
const TUNNEL_PEER: [u8; 4] = [203, 0, 113, 9];
/// An outer source with NO configured GRE endpoint: the same local outer
/// destination, a different peer. Ordinary transit, not an offered decap.
const UNRELATED_PEER: [u8; 4] = [198, 51, 100, 7];

/// Inner ICMP echo whose SOURCE is off-tunnel (192.0.2.66, not the
/// 10.255.0.0/30 tunnel subnet). Used as the injected payload so a promotion
/// is visibly an attacker-authored packet rather than plausible tunnel
/// traffic.
fn build_injected_inner_v4() -> Vec<u8> {
    let mut packet = vec![
        0x45, 0x00, 0x00, 0x24, 0xbe, 0xef, 0x00, 0x00, 64, PROTO_ICMP, 0x00, 0x00, 192, 0, 2, 66,
        10, 255, 0, 1,
    ];
    let ip_sum = checksum16(&packet[0..20]);
    packet[10] = (ip_sum >> 8) as u8;
    packet[11] = ip_sum as u8;
    let mut icmp = vec![8u8, 0, 0, 0, 0x66, 0x66, 0x00, 0x01];
    icmp.extend_from_slice(&[0x49, 0x4e, 0x4a, 0x45, 0x43, 0x54, 0x45, 0x44]);
    let icmp_sum = checksum16(&icmp);
    icmp[2] = (icmp_sum >> 8) as u8;
    icmp[3] = icmp_sum as u8;
    packet.extend_from_slice(&icmp);
    packet
}

/// #6842 acceptance criterion 1: a GRE **version-1** (PPTP) frame is never
/// parsed with RFC 2890 rules — its 32-bit "Key" is never read as an opaque
/// tunnel discriminator.
///
/// The Key here is `0x0000_0000`, i.e. Payload Length 0 and Call ID 0. That is
/// the value that MATCHES the keyless test endpoint (`endpoint.key == 0` =>
/// `!key_present || key == 0`), so if the version check is removed the frame
/// resolves the tunnel and decaps. The version-0 leg proves exactly that.
#[test]
fn gre_version_1_frame_is_refused_while_the_same_bytes_at_version_0_decap() {
    let forwarding = build_forwarding_state(&gre_to_self_snapshot());
    let inner = build_gre_inner_icmp_packet_v4();

    let v1 = build_gre_versioned_outer_frame_v4(1, GRE_FLAG_KEY, 0, 0, TUNNEL_PEER, &inner);
    let meta = gre_to_self_outer_meta(0, v1.len());
    assert!(
        try_native_gre_decap_from_frame(&v1, meta, &forwarding).is_none(),
        "an RFC 2637 (PPTP) version-1 GRE frame must be refused for decap, \
         never parsed with RFC 2890 Key rules"
    );

    // Paired control: identical bytes, version field cleared. This MUST decap
    // — otherwise the assertion above would pass for a reason that has nothing
    // to do with the version field.
    let v0 = build_gre_versioned_outer_frame_v4(0, GRE_FLAG_KEY, 0, 0, TUNNEL_PEER, &inner);
    let meta = gre_to_self_outer_meta(0, v0.len());
    let decap = try_native_gre_decap_from_frame(&v0, meta, &forwarding)
        .expect("the same frame at GRE version 0 must decap (fixture reaches the endpoint match)");
    assert_eq!(
        &decap.frame[decap.meta.l3_offset as usize..],
        &inner[..],
        "the version-0 control must promote the real inner packet"
    );
}

/// #6842 acceptance criterion 4 (fail closed): the concrete harm the version
/// check prevents.
///
/// RFC 2637 with `A` set lays out Key, Sequence, **Acknowledgment**, payload.
/// The RFC 2890 field order below skips Key and Sequence only, so
/// `inner_offset` lands on the Acknowledgment Number. Here those bytes open a
/// well-formed IPv4 ICMP packet sourced from 192.0.2.66 — off-tunnel, spoofed.
///
/// The version-0 leg promotes it, which is correct for version 0 (RFC 2890 has
/// no `A` bit; 0x0080 is reserved-and-ignored, so those bytes really are the
/// payload). The version-1 leg must refuse. The pair is what shows the
/// injection is fully reachable and that the version field is the only thing
/// standing in front of it.
#[test]
fn gre_version_1_ack_field_cannot_promote_an_injected_inner_packet() {
    let forwarding = build_forwarding_state(&gre_to_self_snapshot());
    let injected = build_injected_inner_v4();
    let flags = GRE_FLAG_KEY | GRE_FLAG_SEQUENCE | GRE_FLAG_ACK_V1;

    let v1 = build_gre_versioned_outer_frame_v4(1, flags, 0, 0x0000_0001, TUNNEL_PEER, &injected);
    let meta = gre_to_self_outer_meta(0, v1.len());
    assert!(
        try_native_gre_decap_from_frame(&v1, meta, &forwarding).is_none(),
        "a version-1 GRE frame with the Acknowledgment-Present bit set must be \
         refused — parsing it with RFC 2890 offsets would promote the peer's \
         Acknowledgment Number as the inner packet"
    );

    let v0 = build_gre_versioned_outer_frame_v4(0, flags, 0, 0x0000_0001, TUNNEL_PEER, &injected);
    let meta = gre_to_self_outer_meta(0, v0.len());
    let decap = try_native_gre_decap_from_frame(&v0, meta, &forwarding).expect(
        "the same bytes at GRE version 0 must decap — this is what proves the \
         injected packet is reachable and the version field is the only guard",
    );
    assert_eq!(
        &decap.frame[decap.meta.l3_offset as usize..],
        &injected[..],
        "the version-0 control must promote the injected packet verbatim"
    );
}

/// The refusal counter must count a refusal, not GRE traffic in general.
///
/// A three-row table, because the interesting failure is a counter that is
/// bumped unconditionally at the version check: that reads identically to a
/// correct one on the first row and turns ordinary TRANSIT PPTP — which is
/// forwarded, not refused — into a permanent nonzero alarm.
///
/// | GRE version | outer tuple names a GRE endpoint | counter |
/// |-------------|----------------------------------|---------|
/// | 1           | yes                              | +1      |
/// | 1           | no (unrelated peer)              | +0      |
/// | 0           | yes                              | +0      |
#[test]
fn gre_version_refusal_counter_only_counts_frames_offered_to_a_gre_endpoint() {
    let forwarding = build_forwarding_state(&gre_to_self_snapshot());
    let inner = build_gre_inner_icmp_packet_v4();

    // Row 1: version 1 at the configured endpoint — a real refusal.
    let frame = build_gre_versioned_outer_frame_v4(1, GRE_FLAG_KEY, 0, 0, TUNNEL_PEER, &inner);
    let meta = gre_to_self_outer_meta(0, frame.len());
    let before = forwarding.gre_decap_counters.unsupported_version_refusals();
    assert!(try_native_gre_decap_from_frame(&frame, meta, &forwarding).is_none());
    assert_eq!(
        forwarding.gre_decap_counters.unsupported_version_refusals(),
        before + 1,
        "a version-1 frame offered to a configured GRE endpoint is a counted refusal"
    );

    // Row 2: version 1, no endpoint for the outer tuple — ordinary transit
    // PPTP crossing the firewall. Refusing decap here is a no-op, so counting
    // it would make the metric a traffic gauge instead of a fault signal.
    let frame = build_gre_versioned_outer_frame_v4(1, GRE_FLAG_KEY, 0, 0, UNRELATED_PEER, &inner);
    let meta = gre_to_self_outer_meta(0, frame.len());
    let before = forwarding.gre_decap_counters.unsupported_version_refusals();
    assert!(try_native_gre_decap_from_frame(&frame, meta, &forwarding).is_none());
    assert_eq!(
        forwarding.gre_decap_counters.unsupported_version_refusals(),
        before,
        "transit PPTP with no configured GRE endpoint must not be counted as a refusal"
    );

    // Row 3: version 0 at the configured endpoint — decaps, counts nothing.
    let frame = build_gre_versioned_outer_frame_v4(0, GRE_FLAG_KEY, 0, 0, TUNNEL_PEER, &inner);
    let meta = gre_to_self_outer_meta(0, frame.len());
    let before = forwarding.gre_decap_counters.unsupported_version_refusals();
    assert!(try_native_gre_decap_from_frame(&frame, meta, &forwarding).is_some());
    assert_eq!(
        forwarding.gre_decap_counters.unsupported_version_refusals(),
        before,
        "an ordinary RFC 2890 GRE frame must not touch the version-refusal counter"
    );
}

/// #2327 kind segregation, carried into the refusal counter: a version-1 frame
/// whose outer tuple resolves ONLY a non-GRE (WireGuard) tunnel row is not a
/// refused GRE decap — that row would never have decapped as GRE at any
/// version. Mirrors `gre_decap_does_not_match_wireguard_row_with_same_outer_tuple`.
///
/// Without this row, dropping the kind re-check from the counting path is
/// invisible: every other test uses a GRE-mode endpoint.
#[test]
fn gre_version_refusal_counter_ignores_a_non_gre_row_with_the_same_outer_tuple() {
    let mut forwarding = build_forwarding_state(&gre_to_self_snapshot());
    for endpoint in forwarding.tunnel_endpoints.values_mut() {
        endpoint.mode = "wireguard".to_string();
    }
    let inner = build_gre_inner_icmp_packet_v4();
    let frame = build_gre_versioned_outer_frame_v4(1, GRE_FLAG_KEY, 0, 0, TUNNEL_PEER, &inner);
    let meta = gre_to_self_outer_meta(0, frame.len());
    let before = forwarding.gre_decap_counters.unsupported_version_refusals();
    assert!(try_native_gre_decap_from_frame(&frame, meta, &forwarding).is_none());
    assert_eq!(
        forwarding.gre_decap_counters.unsupported_version_refusals(),
        before,
        "a WireGuard row with the same outer tuple is not a refused GRE decap"
    );
}

/// #8291: the cumulative total SURVIVES a config apply.
///
/// This is the load-bearing half of moving the counter off a `static` and onto
/// `ForwardingState`, and the one whose failure is invisible in normal use: a
/// fresh box reads zero anyway, so a total that silently resets on every commit
/// looks exactly like a quiet network. An operator would only notice by never
/// seeing the alarm they were told to watch for.
///
/// FAIL-ON-REVERT: delete the `state.gre_decap_counters = previous...` carry in
/// `forwarding_build::attach_zone_counters` and this reds — the rebuilt state
/// gets a fresh `Arc` at zero. Measured, not assumed.
#[test]
fn the_refusal_total_survives_a_config_apply_8291() {
    use crate::afxdp::forwarding_build::build_forwarding_state_with_policy_counters_and_previous;
    use crate::policy::PolicyCounterStore;

    let snapshot = gre_to_self_snapshot();
    let policy = PolicyCounterStore::default();
    let nat = crate::nat::NatCounterStore::default();

    let first =
        build_forwarding_state_with_policy_counters_and_previous(&snapshot, &policy, &nat, None)
            .expect("first apply builds");
    assert_eq!(
        first.gre_decap_counters.unsupported_version_refusals(),
        0,
        "a first apply starts the total at zero, or the carry below is \
         indistinguishable from a fresh counter"
    );

    // Drive a real refusal through the decap path, not a direct bump: the
    // property is that what the PACKET PATH counts survives, and a direct
    // increment would pass even if the path stopped counting.
    let inner = build_gre_inner_icmp_packet_v4();
    let frame = build_gre_versioned_outer_frame_v4(1, GRE_FLAG_KEY, 0, 0, TUNNEL_PEER, &inner);
    let meta = gre_to_self_outer_meta(0, frame.len());
    assert!(try_native_gre_decap_from_frame(&frame, meta, &first).is_none());
    assert_eq!(
        first.gre_decap_counters.unsupported_version_refusals(),
        1,
        "precondition: the refusal must be counted on the first state, or this \
         cell asserts the survival of nothing"
    );

    // The second apply — the config commit whose rebuild used to reset it.
    let second = build_forwarding_state_with_policy_counters_and_previous(
        &snapshot,
        &policy,
        &nat,
        Some(&first),
    )
    .expect("second apply builds");
    assert_eq!(
        second.gre_decap_counters.unsupported_version_refusals(),
        1,
        "the cumulative GRE refusal total must survive a config apply. A \
         rebuilt ForwardingState that drops the carry hands the operator a \
         counter that silently returns to zero on every commit (#8291)"
    );

    // And it is the SAME cell, not an equal copy: a further refusal counted
    // through the new state must be visible through the old handle too.
    assert!(try_native_gre_decap_from_frame(&frame, meta, &second).is_none());
    assert_eq!(
        first.gre_decap_counters.unsupported_version_refusals(),
        2,
        "carry must SHARE the Arc, not copy its value — a copy diverges the \
         moment either side counts again"
    );
}

/// #10865: PT/nibble mismatch refusals survive config rebuilds and reach the
/// coordinator's operator-visible status surface.
#[test]
fn pt_nibble_mismatch_refusal_total_survives_apply_and_reaches_status_10865() {
    use crate::afxdp::forwarding_build::build_forwarding_state_with_policy_counters_and_previous;
    use crate::policy::PolicyCounterStore;

    let snapshot = gre_to_self_snapshot();
    let policy = PolicyCounterStore::default();
    let nat = crate::nat::NatCounterStore::default();
    let first =
        build_forwarding_state_with_policy_counters_and_previous(&snapshot, &policy, &nat, None)
            .expect("first apply builds");

    // Same endpoint/key as the version tests, but a valid v4 header whose
    // version nibble disagrees with the GRE Protocol Type's IPv4 claim.
    let mut inner = build_gre_inner_icmp_packet_v4();
    inner[0] = 0x65;
    inner[10] = 0;
    inner[11] = 0;
    let ip_sum = checksum16(&inner[0..20]);
    inner[10] = (ip_sum >> 8) as u8;
    inner[11] = ip_sum as u8;
    let frame = build_gre_versioned_outer_frame_v4(0, GRE_FLAG_KEY, 0, 0, TUNNEL_PEER, &inner);
    let meta = gre_to_self_outer_meta(0, frame.len());
    assert!(try_native_gre_decap_from_frame(&frame, meta, &first).is_none());
    assert_eq!(
        first.gre_decap_counters.pt_nibble_mismatch_refusals(),
        1,
        "precondition: the packet path must count the mismatch refusal"
    );

    let second = build_forwarding_state_with_policy_counters_and_previous(
        &snapshot,
        &policy,
        &nat,
        Some(&first),
    )
    .expect("second apply builds");
    assert_eq!(
        second.gre_decap_counters.pt_nibble_mismatch_refusals(),
        1,
        "the cumulative mismatch-refusal total survives config apply"
    );

    let mut coordinator = crate::afxdp::Coordinator::new();
    coordinator.set_forwarding_for_test(second);
    assert_eq!(
        coordinator.gre_decap_pt_nibble_mismatch_refusals_total(),
        1,
        "the status surface reports the carried PT/nibble refusal total"
    );
    assert!(try_native_gre_decap_from_frame(&frame, meta, &coordinator.forwarding).is_none());
    assert_eq!(
        coordinator.gre_decap_pt_nibble_mismatch_refusals_total(),
        2,
        "the coordinator status remains attached to the live cumulative counter"
    );
}

/// #8291: the operator-visible surface still reports the number it reported
/// before the counter moved off the `static`.
///
/// Reading through `self.forwarding` instead of a process global is a
/// BEHAVIOUR change on the status path, not plumbing, so it gets its own
/// assertion rather than riding on the isolation work.
#[test]
fn the_status_surface_reports_the_forwarding_states_total_8291() {
    let mut coordinator = crate::afxdp::Coordinator::new();
    coordinator.set_forwarding_for_test(build_forwarding_state(&gre_to_self_snapshot()));
    assert_eq!(
        coordinator.gre_decap_unsupported_version_refusals_total(),
        0,
        "a coordinator with no refusals reports zero"
    );

    let inner = build_gre_inner_icmp_packet_v4();
    let frame = build_gre_versioned_outer_frame_v4(1, GRE_FLAG_KEY, 0, 0, TUNNEL_PEER, &inner);
    let meta = gre_to_self_outer_meta(0, frame.len());
    assert!(try_native_gre_decap_from_frame(&frame, meta, &coordinator.forwarding).is_none());

    assert_eq!(
        coordinator.gre_decap_unsupported_version_refusals_total(),
        1,
        "the status surface must report the refusal the dataplane counted. If \
         this reds, the metric and the counter have been split apart and the \
         operator's number stopped tracking the thing it names (#8291)"
    );
}
