//! Shared Ethernet / VLAN / EtherType constants.
//!
//! Single source of truth for L2 magic numbers used across the
//! AF_XDP fast path. Previously these were defined privately in
//! `tx.rs` (`ETH_HDR_LEN`, `VLAN_TAG_LEN`) and `parser.rs`
//! (`ETHERTYPE_*`). Extracted per Gemini review of #947 to avoid
//! drift between modules.
//!
//! These are `pub(super)` so any sibling submodule of `afxdp` can
//! import via `use super::ethernet::*;` (or by-name).

/// Size of a bare Ethernet header (6 dst MAC + 6 src MAC + 2 ethertype).
pub(super) const ETH_HDR_LEN: usize = 14;

/// Size of a single 802.1Q / 802.1ad VLAN tag (TPID + TCI).
pub(super) const VLAN_TAG_LEN: usize = 4;
/// Test-only normalized result for an Ethernet L3-offset reader. Keeping the
/// adapter type in the shared Ethernet module lets each private reader expose
/// a tiny `#[cfg(test)]` view without widening its production API.
#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct L2View {
    pub(crate) l3_offset: Option<usize>,
}

/// EtherType constants.
pub(super) const ETHERTYPE_ARP: u16 = 0x0806;
pub(super) const ETHERTYPE_IPV6: u16 = 0x86DD;
/// 802.1Q VLAN tag protocol identifier.
pub(super) const ETHERTYPE_VLAN: u16 = 0x8100;
/// 802.1ad (Q-in-Q / provider-bridging) service VLAN tag protocol
/// identifier. A single 0x88a8 tag carries the same 4-byte TPID+TCI
/// layout as 0x8100, so the L3 header sits at the same offset (18). The
/// canonical L2 contract (see `frame/inspect.rs::frame_l3_offset` and
/// `cos/ecn.rs::ethernet_l3`) treats both the same; the learning parser
/// here must agree (#2150).
pub(super) const ETHERTYPE_VLAN_8021AD: u16 = 0x88A8;
