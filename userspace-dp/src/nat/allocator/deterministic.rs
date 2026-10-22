//! #16135: deterministic CGNAT math, split out of nat/allocator.rs as
//! PURE CODE MOTION (deterministic first, per the issue order). This
//! module is stateless: subscriber -> (pool address, port block) forward
//! mapping and the stateless reverse mapping, with no allocator state.
//! Visibility bill for this move: ZERO widenings. Every item below was
//! already pub(crate) in allocator.rs (DeterministicV4 + its 4 fields,
//! deterministic_indices_v4, PoolReverseIndex, build_pool_reverse_index,
//! reverse_deterministic_v4, DeterministicV6 + its 5 fields,
//! deterministic_indices_v6, reverse_deterministic_v6);
//! deterministic_v6_word_offset was private and stays private.
//! allocator/mod.rs re-exports the pub(crate) items, so every existing
//! path (crate::nat::DeterministicV4, super::allocator::
//! deterministic_indices_v4, ...) resolves exactly as before.
//! Machine-checked by scripts/verify-nat-allocator-split-16135.py.

use rustc_hash::FxHashMap;
use std::net::{Ipv4Addr, Ipv6Addr};

/// #4559: IPv4 deterministic CGNAT (mode 1) block-allocation parameters,
/// precomputed by the Go compiler and carried on the source-NAT rule. The
/// mapping is `subscriber internal IPv4 -> fixed (external pool IP, port
/// block)`, reversible from `(external IP, port)` back to the subscriber with
/// NO per-flow state (the whole point of deterministic NAT: lawful-intercept /
/// CGN audit without per-connection logging). Reproduces the retired-eBPF
/// `nat_pool_alloc_deterministic_v4` logic (pkg/dataplane/compiler_nat.go /
/// the deleted bpf/xdp/xdp_policy.c) in the userspace dataplane.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct DeterministicV4 {
    /// Ports per subscriber block (Junos `block-size`).
    pub(crate) block_size: u16,
    /// Blocks each external pool address carries
    /// (`(port_high - port_low + 1) / block_size`).
    pub(crate) blocks_per_ip: u16,
    /// Subscriber-CIDR network address, host-order u32.
    pub(crate) host_base: u32,
    /// Subscriber count in the host CIDR (`1 << (32 - prefix_len)`).
    pub(crate) host_count: u32,
}

/// #4559: map a subscriber IPv4 to its deterministic `(ip_idx, block_idx)`.
/// `ip_idx` selects the external pool address; `block_idx` selects the port
/// block within that address. Returns `None` when the subscriber is outside the
/// configured host range or the parameters are degenerate (`blocks_per_ip == 0`
/// / `block_size == 0`) — the caller fails the allocation closed rather than
/// silently round-robining a subscriber that has no reserved block.
pub(crate) fn deterministic_indices_v4(
    params: &DeterministicV4,
    src: Ipv4Addr,
) -> Option<(usize, u32)> {
    let bpi = params.blocks_per_ip as u32;
    if bpi == 0 || params.block_size == 0 {
        return None;
    }
    let src_h = u32::from(src);
    if src_h < params.host_base {
        return None;
    }
    let sub_idx = src_h - params.host_base;
    if sub_idx >= params.host_count {
        return None;
    }
    let ip_idx = (sub_idx / bpi) as usize;
    let block_idx = sub_idx % bpi;
    Some((ip_idx, block_idx))
}

/// #5660: O(1) reverse index for a deterministic-NAT external pool. Maps each
/// external pool IPv4 address to its position in the ordered `pool_v4` list —
/// the SAME index the forward path selects with `pool_v4[ip_idx]`. It replaces
/// the reverse path's `pool_v4.iter().position()` linear scan (up to
/// `MAX_POOL_PREFIX_HOSTS` = 65536 addresses) with a single hash lookup.
///
/// The pool is an ARBITRARY, possibly non-contiguous ordered address list (the
/// NAT64 path builds it by parsing configured pool strings, and a source-NAT
/// pool may span several disjoint ranges), so `ip_idx` is a POSITION in the
/// list, not an arithmetic offset from a base — a direct `translated_ip -
/// pool_base` subtraction would be wrong. Build this ONCE at prefix/rule build
/// time with [`build_pool_reverse_index`] and reuse it for every reverse
/// lookup; rebuilding it per lookup is O(N) again (and allocates). First
/// occurrence of a (pathologically) duplicated pool address wins, exactly
/// mirroring the `position()` first-match semantics it replaces.
pub(crate) type PoolReverseIndex = FxHashMap<Ipv4Addr, u32>;

/// #5660: build the [`PoolReverseIndex`] from an ordered deterministic-NAT
/// external pool. First-match wins for a duplicated address (matches the
/// `position()` scan this replaces).
pub(crate) fn build_pool_reverse_index(pool_v4: &[Ipv4Addr]) -> PoolReverseIndex {
    let mut index = FxHashMap::default();
    index.reserve(pool_v4.len());
    for (idx, &addr) in pool_v4.iter().enumerate() {
        index.entry(addr).or_insert(idx as u32);
    }
    index
}

/// #4559: reverse a deterministic translated `(external pool IP, port)` back to
/// the subscriber's internal IPv4 with NO per-flow state — the CGN-compliance
/// property that motivates deterministic NAT. `pool_index` is the pool's O(1)
/// reverse index ([`build_pool_reverse_index`], keyed by the same ordered
/// external-address list the forward path indexes); `port_low` is the pool's
/// low port. Returns `None` when the tuple does not fall in the deterministic
/// space (unknown external IP, port below `port_low`, or a block/subscriber
/// index out of range).
pub(crate) fn reverse_deterministic_v4(
    params: &DeterministicV4,
    pool_index: &PoolReverseIndex,
    port_low: u16,
    translated_ip: Ipv4Addr,
    translated_port: u16,
) -> Option<Ipv4Addr> {
    if params.block_size == 0 {
        return None;
    }
    let ip_idx = *pool_index.get(&translated_ip)?;
    if translated_port < port_low {
        return None;
    }
    let offset = (translated_port - port_low) as u32;
    let block_idx = offset / params.block_size as u32;
    if block_idx >= params.blocks_per_ip as u32 {
        return None;
    }
    let sub_idx = ip_idx
        .checked_mul(params.blocks_per_ip as u32)?
        .checked_add(block_idx)?;
    if sub_idx >= params.host_count {
        return None;
    }
    let host = params.host_base.checked_add(sub_idx)?;
    Some(Ipv4Addr::from(host))
}

/// #4559: IPv6-subscriber deterministic CGNAT (mode 2, NAPT64) block-allocation
/// parameters. An IPv6 subscriber deterministically maps to a fixed external
/// IPv4 pool address + port block, reversible from `(external IPv4, port)` back
/// to the subscriber's IPv6 prefix with NO per-flow state — the same
/// lawful-intercept / CGN-audit property as mode 1, but for the v6→v4 (NAT64)
/// direction. Reproduces the retired-eBPF `nat_pool_alloc_deterministic_v6`
/// logic (the deleted bpf/xdp/xdp_policy.c). The difference from mode 1 is the
/// subscriber-index derivation: the 32-bit word AFTER the configured IPv6
/// prefix (`/32` → octet offset 4, `/64` → octet offset 8) is the subscriber
/// index, not an IPv4 host offset.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct DeterministicV6 {
    /// Ports per subscriber block (Junos `block-size`).
    pub(crate) block_size: u16,
    /// Blocks each external pool address carries
    /// (`(port_high - port_low + 1) / block_size`), computed against the
    /// pool's translated-port range so block boundaries align with the allocator.
    pub(crate) blocks_per_ip: u16,
    /// IPv6 subscriber-prefix length: 32 or 64. Selects the subscriber-index
    /// word offset (32 → octets[4..8], 64 → octets[8..12]).
    pub(crate) host_prefix_len: u8,
    /// IPv6 subscriber-CIDR network base, network-order octets. Forward
    /// extraction reads the subscriber word off `src` at the prefix-selected
    /// offset relative to this base; the reverse path reconstructs it.
    pub(crate) host_base: [u8; 16],
    /// Maximum subscriber index the pool can serve
    /// (`pool_v4.len() * blocks_per_ip`). An IPv6 subscriber word extends far
    /// beyond pool capacity, so — unlike mode 1's CIDR-derived count — this is
    /// bounded by the pool, computed at `Nat64Prefix` build time from the parsed
    /// pool. A subscriber beyond it fails the allocation closed.
    pub(crate) host_count: u32,
}

/// #4559: byte offset of the 32-bit subscriber-index word for a mode-2 prefix
/// length. `/64` → octets[8..12] (the word after a /64 prefix), everything else
/// (only `/32` is otherwise built) → octets[4..8]. Mirrors the retired-eBPF
/// `host_prefix_len == 64 ? +8 : +4` split.
fn deterministic_v6_word_offset(host_prefix_len: u8) -> usize {
    if host_prefix_len == 64 { 8 } else { 4 }
}

/// #4559: map an IPv6 subscriber to its deterministic `(ip_idx, block_idx)` for
/// mode 2 (NAPT64). `ip_idx` selects the external IPv4 pool address; `block_idx`
/// selects the port block within it. The subscriber index is the host-order
/// 32-bit word AFTER the configured prefix minus the base's same word. Returns
/// `None` when the subscriber is below the base, beyond the pool-bounded
/// `host_count`, or the parameters are degenerate — the caller fails the
/// allocation closed rather than silently round-robining.
///
/// #4863: the source MUST lie inside the configured subscriber prefix. The
/// subscriber index is derived only from the 32-bit word at `off`, so a source
/// in a DIFFERENT prefix that happens to share that word would otherwise be
/// accepted and mapped into the in-prefix subscriber's fixed block — and the
/// stateless `reverse_deterministic_v6` (which reconstructs from `host_base`)
/// would then attribute the external `(IPv4, port)` to the WRONG subscriber
/// (cross-tenant block assignment + a lying reverse map). Reject any source
/// whose prefix bytes before the subscriber word differ from `host_base`. For
/// a /32 the checked prefix is `octets[0..4]`, for a /64 `octets[0..8]` — the
/// bytes at `off` are exactly the configured prefix length. This is a
/// drop-only tightening: an in-prefix source is unaffected.
pub(crate) fn deterministic_indices_v6(
    params: &DeterministicV6,
    src: Ipv6Addr,
) -> Option<(usize, u32)> {
    let bpi = params.blocks_per_ip as u32;
    if bpi == 0 || params.block_size == 0 {
        return None;
    }
    let off = deterministic_v6_word_offset(params.host_prefix_len);
    let src_octets = src.octets();
    // #4863: fail closed for any source outside the configured subscriber
    // prefix. The subscriber word alone does not identify the tenant — the
    // prefix bytes before it must match the configured base exactly, else a
    // colliding subscriber word in a different prefix would steal an in-prefix
    // subscriber's block and be reverse-mapped to the wrong subscriber.
    if src_octets[..off] != params.host_base[..off] {
        return None;
    }
    let src_word = u32::from_be_bytes([
        src_octets[off],
        src_octets[off + 1],
        src_octets[off + 2],
        src_octets[off + 3],
    ]);
    let base_word = u32::from_be_bytes([
        params.host_base[off],
        params.host_base[off + 1],
        params.host_base[off + 2],
        params.host_base[off + 3],
    ]);
    if src_word < base_word {
        return None;
    }
    let sub_idx = src_word - base_word;
    if sub_idx >= params.host_count {
        return None;
    }
    let ip_idx = (sub_idx / bpi) as usize;
    let block_idx = sub_idx % bpi;
    Some((ip_idx, block_idx))
}

/// #4559: reverse a deterministic translated `(external IPv4 pool address,
/// port)` back to the subscriber's IPv6 prefix with NO per-flow state — the
/// CGN-compliance property that motivates deterministic NAPT64. `pool_index` is
/// the prefix's O(1) reverse index ([`build_pool_reverse_index`], keyed by the
/// same ordered external-address list the forward path indexes); `port_low` is
/// the allocator's low port. The recovered address is the subscriber PREFIX
/// (network base + subscriber word, trailing interface-identifier bytes left as
/// the base's — zero for a network base): the deterministic unit is the
/// subscriber prefix, not the full /128 host. Returns `None` when the tuple
/// does not fall in the deterministic space.
pub(crate) fn reverse_deterministic_v6(
    params: &DeterministicV6,
    pool_index: &PoolReverseIndex,
    port_low: u16,
    translated_ip: Ipv4Addr,
    translated_port: u16,
) -> Option<Ipv6Addr> {
    if params.block_size == 0 {
        return None;
    }
    let ip_idx = *pool_index.get(&translated_ip)?;
    if translated_port < port_low {
        return None;
    }
    let offset = (translated_port - port_low) as u32;
    let block_idx = offset / params.block_size as u32;
    if block_idx >= params.blocks_per_ip as u32 {
        return None;
    }
    let sub_idx = ip_idx
        .checked_mul(params.blocks_per_ip as u32)?
        .checked_add(block_idx)?;
    if sub_idx >= params.host_count {
        return None;
    }
    let off = deterministic_v6_word_offset(params.host_prefix_len);
    let base_word = u32::from_be_bytes([
        params.host_base[off],
        params.host_base[off + 1],
        params.host_base[off + 2],
        params.host_base[off + 3],
    ]);
    let sub_word = base_word.checked_add(sub_idx)?;
    let mut octets = params.host_base;
    octets[off..off + 4].copy_from_slice(&sub_word.to_be_bytes());
    Some(Ipv6Addr::from(octets))
}
