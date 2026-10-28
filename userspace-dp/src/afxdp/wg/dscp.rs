//! DSCP and ECN handling for the WG outer header.
//!
//! `UserspaceDpMeta::dscp` is 6-bit right-justified in xpf (matches
//! the existing dataplane convention — see `forwarding/mod.rs` for
//! the same placement on the GRE encap). The outer IP TOS byte
//! holds DSCP in the high 6 bits and ECN in the low 2 bits.
//!
//! Conversion is `dscp << 2`. This helper CLEARS the ECN bits and is
//! used only where the source is a 6-bit DSCP value (no ECN context).
//!
//! NOTE (#2303, #7758): the production WG/GRE encap paths do NOT use
//! this helper for outer-header DSCP/ECN. They copy the FULL inner TOS
//! byte (DSCP + ECN) via `crate::afxdp::gre::inner_tos_byte`, so the
//! inner ECN is COPIED to the outer per RFC 6040 normal-mode ingress.
//! This helper remains for the DSCP-only case (a config-set DSCP value
//! with no inner-packet ECN to carry).
//!
//! "Paths" is plural and load-bearing. WireGuard has TWO encap sites and
//! #2303 wired only one: the TRANSIT path (`frame/wg.rs`). The
//! HOST-ORIGINATED path (`wg_control::encap_and_send`, inner read from
//! the wgN TUN) sent an unmarked outer until #7758, so one inner marking
//! produced two different outer DSCPs depending on the path taken. Both
//! now read the same `inner_tos_byte`, which is what keeps them from
//! drifting on what "the inner DS byte" means.
//!
//! NOTE (#2315/#2317): the complementary DECAP-side RFC 6040 §4.2 ECN
//! *combine* (outer ECN → inner ECN — the half that reflects a CE mark
//! back to the inner endpoints) is implemented for BOTH tunnel paths via
//! the shared `crate::afxdp::gre::apply_decap_ecn_combine`. The GRE path
//! reads the outer ECN from the still-present outer IP header in the
//! frame (#2315). The WG control thread reads transport records from a
//! kernel `UdpSocket`, which strips the outer IP header (and its ECN)
//! before userspace sees the datagram; #2317 captures the outer ECN
//! out-of-band via `recvmsg` + `IP_RECVTOS` (v4 / v4-mapped) /
//! `IPV6_RECVTCLASS` (v6) ancillary data and feeds it into the same
//! combine after WG-decrypt, before the inner packet is written to the
//! wgN TUN (see `crate::afxdp::coordinator::wg_control`). The two
//! tunnel families keep independent illegal-combination drop counters
//! (`GRE_DECAP_ECN_ILLEGAL_DROPS` / `WG_DECAP_ECN_ILLEGAL_DROPS`).

/// Build the outer IPv4 TOS / IPv6 Traffic Class byte from a
/// 6-bit DSCP value. ECN bits are cleared (use
/// `gre::inner_tos_byte` when an inner ECN must propagate, #2303).
///
/// Test-only (#17212): production encap copies the full inner TOS byte.
#[cfg(test)]
#[inline]
pub(crate) fn tos_from_dscp(dscp: u8) -> u8 {
    // Defensive mask: callers should pass 6-bit values, but a
    // stray high bit would corrupt the ECN field, which is the
    // sort of bug that's invisible in unit tests and shows up as
    // mysterious congestion behavior on the wire.
    (dscp & 0x3F) << 2
}

#[cfg(test)]
mod dscp_tests {
    use super::*;

    #[test]
    fn dscp_shifted_two_left() {
        // CS0 / EF / AF41 sanity checks.
        assert_eq!(tos_from_dscp(0), 0); // CS0
        assert_eq!(tos_from_dscp(46), 46 << 2); // EF = 0xB8 = 184
        assert_eq!(tos_from_dscp(34), 34 << 2); // AF41 = 0x88 = 136
    }

    #[test]
    fn ecn_bits_always_clear() {
        // Even with a max-valued DSCP, the low 2 bits (ECN) must
        // be zero. This is the property the RFC 6040 follow-up
        // will lift.
        for d in 0u8..=63u8 {
            assert_eq!(tos_from_dscp(d) & 0x03, 0);
        }
    }

    #[test]
    fn rejects_overflow_into_ecn() {
        // If a caller mistakenly passes an 8-bit value with bits
        // in positions 6-7, those must NOT bleed into the TOS
        // byte. (Equivalent: ECN is preserved at zero.)
        assert_eq!(tos_from_dscp(0xFF), 0x3F << 2);
        assert_eq!(tos_from_dscp(0xC0), 0); // upper bits only
    }
}
