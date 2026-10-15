//! #10662: IPv6 declared-payload end arithmetic shared with host tests.
//!
//! The XDP shim must leave `parse_l4`'s capture-bound parse unchanged: using a
//! second symbolic bound inside that heavy parser exploded verifier states
//! beyond the kernel's 1,000,000-instruction cap. Instead, the shim computes
//! the declared end after parsing and compares the consumed L4 offset once.
//! This pure helper keeps the wire-length arithmetic executable in the
//! host-side boundary cells without pulling in `aya`, a BPF map, or `std`.
//!
//! Payload length counts every byte AFTER the 40-byte IPv6 base header:
//! extension chain, L4 header and payload.
//!
//! Nothing in here may take a dependency on `aya`, on a BPF map, or on `std` —
//! that is what keeps it host-compilable, and it is the whole point.
//!
//! Sharing: userspace-dp cannot link this crate (it targets BPF), so its
//! host-side boundary cells compile THIS FILE and exercise the same declared
//! end arithmetic used by the shim. The Go shim regression executes the
//! complete packet path against the generated object.

/// The fixed IPv6 base-header length (RFC 8200 §3).
pub const IPV6_FIXED_HDR_LEN: usize = 40;

/// Declared IPv6 datagram end as a packet-relative offset.
///
/// `l3_offset` comes from a u16 frame offset and `payload_len` is a u16, so
/// this sum cannot overflow `usize` on the shim's supported 64-bit target.
#[inline(always)]
pub fn ipv6_declared_end(l3_offset: usize, payload_len: u16) -> usize {
    l3_offset + IPV6_FIXED_HDR_LEN + payload_len as usize
}

/// The UDP header length: the 9-byte WireGuard-classification read in
/// `parse_l4` covers this header plus the first payload byte.
pub const UDP_HDR_LEN: usize = 8;

/// Whether the declared datagram covers the first UDP payload byte at
/// `l4_offset` — the byte `parse_l4`'s 9-byte read classifies.
///
/// #13084: `parse_ipv6` deliberately parses L4 against the CAPTURE bound (see
/// the #10662 note there) and reconciles against the declared end afterward.
/// Its truncation check compares `payload_offset` (`l4_offset + UDP_HDR_LEN`)
/// against the declared end, so a datagram declaring exactly a bare UDP header
/// passes while the 9th (first payload) byte came from L2 padding/slack past
/// the datagram. That byte must not steer WireGuard classification: the shim
/// keeps the parsed packet but clears the transport-data claim unless this
/// gate holds. `l4_offset` is the extension-walk result (not necessarily
/// `l3_offset + IPV6_FIXED_HDR_LEN`), so it is taken as given.
#[inline(always)]
pub fn ipv6_udp_first_payload_byte_in_datagram(l4_offset: usize, declared_end: usize) -> bool {
    declared_end >= l4_offset + UDP_HDR_LEN + 1
}
