//! Orchestrator for `apply_rewrite_descriptor`.
//!
//! Validates the rewrite descriptor's L2 parameters via
//! `rewrite_prepare_eth_from_parts` (NAT64/NPTv6 early-return; eth
//! header write + apply_nat / skip_ttl / ip_start computation), then
//! dispatches to the address-family helper.
//!
//! Codegen contract (see docs/pr/1352-frame-build-rewrite-split/plan.md):
//!   - This orchestrator is `#[inline]` (standard hint). It has
//!     exactly ONE caller (`poll_descriptor.rs:746` inside the
//!     per-packet SIMD descriptor loop). Transitive duplication is
//!     impossible with one caller; LLVM may inline fully or keep
//!     ONE standalone definition. Both are acceptable.
//!   - Per-family helpers (`rewrite/ipv4.rs`, `rewrite/ipv6.rs`) are
//!     `#[inline(always)]` to fold into this orchestrator's body.

mod ipv4;
mod ipv6;

use ipv4::{apply_rewrite_descriptor_ipv4, validate_rewrite_descriptor_ipv4};
use ipv6::{apply_rewrite_descriptor_ipv6, validate_rewrite_descriptor_ipv6};

use super::{
    is_non_first_fragment, rewrite_commit_eth_from_plan, rewrite_plan_eth_from_parts,
    verify_built_frame_checksums, InPlaceRewriteResult, RewriteEthParams,
};
use crate::afxdp::{MmapArea, RewriteDescriptor, UserspaceDpMeta, XdpDesc};

/// Apply a precomputed `RewriteDescriptor` to a frame in-place inside
/// a UMEM-resident packet. Mirrors the byte-level rewrite semantics of
/// the generic in-place rewrite (`rewrite_forwarded_frame_in_place`)
/// but uses the descriptor's precomputed checksum deltas instead of
/// recomputing the L4 checksum from scratch. Since the
/// #1838/#1839/#1840 trio fix this mirroring is BYTE-EXACT on the
/// shared success domain and is permanently guarded by the unmasked
/// descriptor-vs-generic differential in `frame/prop_tests/rewrite.rs`
/// (P-N3, empty exclusion mask).
///
/// **Returns** `Some(InPlaceRewriteResult)` on success, `None` when the
/// frame fails any validation (TTL expired, header too short, port
/// mismatch — caller falls back to generic rewrite).
///
/// **Scope**: IPv4/IPv6 TCP and UDP only (flow cache gates on
/// ACK-only TCP + UDP). Does NOT handle: ICMP identifier repair,
/// NAT64 (header-size change — always falls back to the generic frame
/// builder). NPTv6 IS handled (#2652): it is a same-family IPv6 address
/// byte-rewrite that is checksum-neutral by RFC 6296, so the IPv6 arm
/// reproduces the slow path exactly — it writes the new address(es) and,
/// because the descriptor's `l4_csum_delta` is 0 for NPTv6
/// (`compute_l4_csum_delta` short-circuits on `nat.nptv6`), it leaves the
/// L4 checksum untouched, matching `apply_nat_ipv6`'s `skip_l4_csum`.
#[inline]
pub(in crate::afxdp) fn apply_rewrite_descriptor(
    area: &MmapArea,
    desc: XdpDesc,
    meta: UserspaceDpMeta,
    rd: &RewriteDescriptor,
    expected_ports: Option<(u16, u16)>,
) -> Option<InPlaceRewriteResult> {
    // NAT64 is a version-changing translation (IPv6 40B <-> IPv4 20B header
    // rebuild, fragment handling) built by the generic NAT64 frame builder —
    // the in-place descriptor byte-write path cannot express it, so fall back.
    if rd.nat64 {
        return None;
    }
    // #2652 defense-in-depth: NPTv6 is IPv6-only. A descriptor flagged nptv6
    // with a non-v6 ether_type is a malformed/inconsistent cache entry; fall
    // back to the generic path rather than misapply a v4 rewrite.
    if rd.nptv6 && rd.ether_type != 0x86dd {
        return None;
    }

    let eth_params = RewriteEthParams {
        dst_mac: rd.dst_mac,
        src_mac: rd.src_mac,
        vlan_id: rd.tx_vlan_id,
        ether_type: rd.ether_type,
        apply_nat: !rd.fabric_redirect || rd.apply_nat_on_fabric,
    };

    // #5466: make the descriptor rewrite transactional. Compute the eth
    // rewrite plan WITHOUT mutating UMEM, then run every bail gate
    // (non-first-fragment, header length, TTL/hop-limit, DMA-race port
    // mismatch) against the PRISTINE frame. `rewrite_commit_eth_from_plan`
    // mutates the buffer (eth-header write + VLAN-push memmove), so any gate
    // that can still return `None` MUST run before the commit — otherwise
    // the caller's `.or_else(generic-rewrite)` fallback reprocesses a frame
    // we already clobbered (corrupt eth header / shifted payload). The gates
    // read the ORIGINAL L3 payload at `plan.l3`; because the commit's memmove
    // is a pure relocation and the eth-header write never touches the L3/L4
    // region, these decisions are byte-identical to the post-commit checks
    // they replace, and `validate_*` returns the L4 offset the infallible
    // `apply_*` mutation half needs.
    let plan = rewrite_plan_eth_from_parts(area, desc, meta.into(), &eth_params)?;
    // GPT-5: cohere the offsets for the gates + apply below (see the
    // in-place path: a corrected L3 with a stale L4 mis-drives the v6
    // transport rewrites).
    let mut meta = meta;
    meta.l3_offset = plan.l3 as u16;
    if !plan.stamp_trusted {
        meta.l4_offset = plan.l3 as u16;
    }
    let skip_ttl = plan.prep.skip_ttl;
    let apply_nat = plan.prep.apply_nat;

    let rel_l4 = {
        let frame = area.slice(desc.addr as usize, desc.len as usize)?;
        let l3_end = plan.l3.checked_add(plan.payload_len)?;
        let l3_payload = frame.get(plan.l3..l3_end)?;
        // #1852: the descriptor fast path applies a precomputed L4-checksum
        // delta and inline port writes at the L4 offset, both of which would
        // corrupt a non-first fragment's payload. Defer to the generic path
        // (`rewrite_forwarded_frame_in_place` via the caller's
        // `.or_else(...)`), which carries the leaf-level fragment gate. This
        // preserves the #1838 P-N3 descriptor-vs-generic byte parity (the
        // generic path is the single source of truth for fragments).
        if !l3_payload.is_empty() && is_non_first_fragment(l3_payload, meta.addr_family) {
            return None;
        }
        match rd.ether_type {
            0x0800 => {
                validate_rewrite_descriptor_ipv4(l3_payload, skip_ttl, meta, expected_ports)?
            }
            0x86dd => {
                validate_rewrite_descriptor_ipv6(l3_payload, skip_ttl, meta, expected_ports)?
            }
            _ => return None,
        }
    };

    // All gates cleared: commit the eth rewrite (first UMEM mutation). From
    // here NO path returns None — the commit's remaining fallible checks are
    // frame-geometry checks decided by the plan, and the `apply_*` halves are
    // infallible (validation already proved the byte layout).
    rewrite_commit_eth_from_plan(area, desc, &plan, &eth_params)?;
    let packet = unsafe {
        area.slice_mut_unchecked(plan.prep.tx_offset as usize, plan.prep.frame_len)?
    };
    let frame_len = plan.prep.frame_len;
    let ip = plan.prep.ip_start;

    match rd.ether_type {
        0x0800 => apply_rewrite_descriptor_ipv4(packet, ip, rel_l4, skip_ttl, apply_nat, meta, rd),
        0x86dd => apply_rewrite_descriptor_ipv6(packet, ip, rel_l4, skip_ttl, apply_nat, meta, rd),
        // Unreachable: `rd.ether_type` was validated above before the commit.
        _ => return None,
    }

    // Checksum verification for descriptor path (debug only).
    if cfg!(feature = "debug-log") {
        verify_built_frame_checksums(&packet[..frame_len]);
    }
    Some(InPlaceRewriteResult {
        offset: plan.prep.tx_offset,
        len: frame_len as u32,
        l2_rewrite: plan.prep.l2_rewrite,
    })
}
