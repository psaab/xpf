//! WG control-thread MTU math (#2300): the pad-aware encapped-size
//! formula and the single outer-MTU guard predicate the TUN-read
//! egress applies per peer. `pad_to_16` itself lives in
//! `crate::afxdp::wg` (the wire-format SSOT, #6438); the
//! transit-egress mirror of this formula is
//! `frame::wg::wg_encapped_size`.

use crate::afxdp::wg::{POLY1305_TAG_LEN, WG_DATA_HEADER_LEN, padded_len_capped};

/// Fallback outer (underlay) MTU for the WG transport path when the
/// real egress MTU cannot be resolved at spawn (#2300). The control
/// thread is now handed the resolved underlay-egress MTU
/// (`resolve_wg_outer_mtu` in tunnel_supervision.rs), so this constant
/// is ONLY the last-resort default for an unconfigured / unroutable
/// endpoint — it is no longer the hardcoded outer MTU. The exact
/// pad-aware guard in `encap_and_send` drops any inner packet whose
/// encapped size would exceed the threaded value, mirroring the
/// transit-egress guard in frame/wg.rs (plan §4.3, §7 — the guard must
/// hold in BOTH directions, against the SAME MTU model).
pub(in crate::afxdp::coordinator) const WG_DEFAULT_OUTER_MTU: usize = 1500;

/// Inner budget for `outer_mtu`: the largest inner length whose capped
/// record fits. Equals `outer_mtu - overhead` exactly (no worst-pad
/// subtraction): with the pad capped at this budget, a full-budget inner
/// packet encapps to exactly `outer_mtu` (#16499, reference behaviour).
#[inline]
pub(super) fn wg_inner_budget(outer_mtu: usize, outer_v6: bool) -> usize {
    let overhead = WG_DATA_HEADER_LEN + POLY1305_TAG_LEN + if outer_v6 { 40 } else { 20 } + 8;
    outer_mtu.saturating_sub(overhead)
}

/// Exact encapped wire size for an `inner_len`-byte inner packet plus
/// the outer L3/L4, with the §5.4.6 pad capped at the inner budget for
/// `outer_mtu` (Linux/wireguard-go behaviour, #16499). Mirrors
/// `frame::wg::wg_encapped_size`.
#[inline]
pub(super) fn wg_encapped_size(inner_len: usize, outer_v6: bool) -> usize {
    wg_encapped_size_with_outer_mtu(inner_len, outer_v6, usize::MAX)
}

#[inline]
pub(super) fn wg_encapped_size_with_outer_mtu(inner_len: usize, outer_v6: bool, outer_mtu: usize) -> usize {
    let outer_ip_len = if outer_v6 { 40 } else { 20 };
    let budget = wg_inner_budget(outer_mtu, outer_v6);
    WG_DATA_HEADER_LEN + padded_len_capped(inner_len, budget) + POLY1305_TAG_LEN + outer_ip_len + 8
}

/// Whether an `inner_len`-byte inner packet fits the outer MTU once
/// WG-encapped (pad capped at the inner budget). The single guard
/// predicate the control-thread egress uses, against the THREADED
/// `outer_mtu` (#2300) — extracted so the "real underlay MTU, not a
/// 1500 constant" behavior is unit-testable without a live socket.
#[inline]
pub(super) fn wg_inner_fits_outer_mtu(inner_len: usize, outer_v6: bool, outer_mtu: usize) -> bool {
    inner_len <= wg_inner_budget(outer_mtu, outer_v6)
        && wg_encapped_size_with_outer_mtu(inner_len, outer_v6, outer_mtu) <= outer_mtu
}
