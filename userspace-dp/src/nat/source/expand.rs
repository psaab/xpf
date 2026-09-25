//! Pool address expansion.
//!
//! `expand_pool_address` and its canonical-prefix parser. The cleanest seam in
//! the file: ZERO in-file dependencies in either direction, and its only imports
//! are `std::net`.
//!
//! #6988 PURE CODE MOTION: every line below was moved verbatim from
//! `nat/source.rs` lines 1094-1267. The only edits are the visibility
//! widenings enumerated in `source/mod.rs`; no logic, no ordering and no
//! signature changed.

use super::*;

/// Upper bound on how many host addresses a single source-NAT pool prefix is
/// expanded into (#3049). Realistic SNAT pools are far smaller; the cap bounds
/// memory and the allocator's per-address port table for an over-broad prefix
/// (an unbounded `/8` would be ~16M entries, and any v6 prefix shorter than
/// `/112` is astronomically large). A prefix whose host count exceeds this is
/// rejected as an invalid pool so the operator gets a clear commit/runtime
/// signal rather than a silently clamped pool.
pub(crate) const MAX_POOL_PREFIX_HOSTS: u64 = 65536;

/// Parse a CIDR mask field in the CANONICAL decimal spelling, or `None`
/// (#6812 F1 round 3).
///
/// Canonical means: 1-3 ASCII digits, no leading zero unless the field is the
/// single digit `0`, value `<= max`. That is exactly what Go's
/// `netip.ParsePrefix` accepts, so the two sides agree on the mask field by
/// construction.
///
/// `ipnet` instead reads the field with `read_number(10, 2, 33)` for IPv4 and
/// `read_number(10, 3, 129)` for IPv6 — a DIGIT-COUNT cap, not a canonical-form
/// rule. It therefore refuses `/032` (3 digits, v4) but accepts `/064` as `/64`
/// (3 digits, v6). Neither spelling changes any pool's disposition today
/// (every leading-zero-expressible prefix length is over `MAX_POOL_PREFIX_HOSTS`
/// anyway, so both sides refuse the pool either way), but that agreement is a
/// coincidence of two unrelated bounds, not a property. Raising
/// `MAX_POOL_PREFIX_HOSTS` would turn it into a live divergence, so the mask
/// grammar is pinned here rather than left to arithmetic.
fn parse_canonical_prefix_len(mask: &str, max: u32) -> Option<u32> {
    // No length cap: a 4+ digit field either carries a leading zero (refused
    // below) or exceeds `max` (refused at the end), and an absurdly long one
    // fails the `parse` itself. A `mask.len() > 3` clause was measured to
    // change 0 of 137,879 differential verdicts — it read like a bound guard
    // and was not one.
    if mask.is_empty() || !mask.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    if mask.len() > 1 && mask.starts_with('0') {
        return None;
    }
    let value: u32 = mask.parse().ok()?;
    if value > max {
        return None;
    }
    Some(value)
}

/// Expand one source-NAT pool address entry into its constituent host
/// addresses (#3049). A pool entry is either a bare IP, a host CIDR
/// (`/32`, `/128`), or a subnet CIDR (e.g. `203.0.113.0/28`). Junos uses the
/// FULL prefix range for a source-NAT pool, so a subnet must enumerate every
/// address in the prefix (network..=broadcast inclusive) rather than collapse
/// to the single network host — the pre-#3049 bug that stripped the mask and
/// kept only one address. A single-host prefix yields exactly one address.
///
/// Returns `false` if the entry does not parse or expands beyond
/// `MAX_POOL_PREFIX_HOSTS` (caller marks the pool invalid).
///
/// # One address grammar for both forms (#6812 F1 round 3)
///
/// The CIDR branch parses its address half with the SAME `std::net::IpAddr`
/// parser the bare branch uses, and its mask half with
/// `parse_canonical_prefix_len` — it deliberately does NOT call
/// `IpNet::from_str`. `ipnet` hand-rolls its own address parser
/// (`ipnet::parser`, a fork of an old `std` implementation) whose octet reader
/// is `read_number(10, 3, 0x100)`: any 1-3 digit decimal below 256, **leading
/// zeros included**. `std` (since Rust 1.53) and Go's `netip.ParseAddr` both
/// reject a leading-zero octet, because `010` is octal 8 to some resolvers and
/// the ambiguity is a spoofing vector.
///
/// That made this function self-inconsistent and made it disagree with the Go
/// control plane: `010.0.0.1` (bare) was refused here, while `010.0.0.1/32`
/// (CIDR) was accepted as `10.0.0.1`, and the shared Go predicate
/// (`sourceNATPoolAddressReason`, pkg/config/compiler_validate_strict_nat.go)
/// refused both — so the STRICT commit gate has rejected the spelling since
/// #5627 while this function installed it. That commit-vs-apply divergence is
/// what the narrowing closes.
///
/// # What moved, stated correctly (#6812 B1)
///
/// Two earlier revisions of this comment claimed the narrowing "changes no
/// config's disposition", and described the pre-fix state as an over-rejection
/// on the tolerant path. **Both are wrong, and the second inverts the
/// direction.** At the merge base the tolerant path did NOT poison this class:
/// `config.SourceNATPoolUnusableReason` does not exist there, and the
/// membership-grammar clause that stamps `invalid_pool` was added mid-branch by
/// this PR. So master had a commit-vs-apply divergence (strict rejects, runtime
/// installs), not an over-rejection — and a pool carrying `010.0.0.0/24` really
/// did translate at the merge base and really does fail closed now.
///
/// The blast radius is exactly the leading-zero-octet CIDR family. Every other
/// shape the membership clause catches was already fail-closed at the merge
/// base: a mixed pool with an unparseable member and an over-capacity `/15`
/// were both refused by this function, and a bare `%zone` member was poisoned
/// by the #5875 builder check.
///
/// The disposition change is kept deliberately, on the #5875 precedent (reject
/// a non-representable literal, never silently rewrite it). Declining to poison
/// it on the tolerant path is not an alternative — the runtime refuses the
/// member on its own, so the pool fails closed either way; that is measured by
/// `declining_to_poison_a_leading_zero_member_does_not_restore_it_6812`. The
/// operator-facing half of the decision is `leadingZeroPoolAddressReason`,
/// which names the canonical spelling, and the upgrade / peer-sync regression
/// tests in pkg/dataplane/userspace/nat_pool_leading_zero_upgrade_6812_test.go.
///
/// `nat_pool_grammar_parity_fixture`
/// (tests_aggregate_budget.rs) pins the agreement over
/// `tests/fixtures/snat_pool_grammar_v1.json` — the SAME file
/// `TestPoolAddressGrammarMatchesDataplane_6812` reads on the Go side, so
/// neither side keeps a copy of the table — and
/// `nat_pool_bare_and_host_cidr_grammars_agree` drives the bare-vs-CIDR
/// invariant directly.
///
/// Scope: `expand_pool_address` has exactly one production caller (the
/// source-NAT pool parse loop below), so this is the source-NAT pool
/// membership grammar only. Rule-set MATCH prefixes still parse via `IpNet`
/// and are a separate question.
// #6988-note: spelled ABSOLUTELY rather than relatively, and that is a
// #6988-note: visibility PRESERVATION, not a widening. In the pre-split file
// #6988-note: this item was `pub(super)` inside `nat::source`, i.e. visible in
// #6988-note: `nat` — which is how `nat/tests_aggregate_budget.rs` reaches it.
// #6988-note: Moved one level deeper, the SAME keyword would mean
// #6988-note: `pub(in crate::nat::source)` and silence that caller; it did,
// #6988-note: with E0603 on the first build. The absolute form is exactly the
// #6988-note: visibility the file had before the split.
pub(in crate::nat) fn expand_pool_address(
    addr_str: &str,
    out_v4: &mut Vec<Ipv4Addr>,
    out_v6: &mut Vec<Ipv6Addr>,
    seen_v4: &mut rustc_hash::FxHashSet<Ipv4Addr>,
    seen_v6: &mut rustc_hash::FxHashSet<Ipv6Addr>,
) -> bool {
    expand_pool_address_inner(addr_str, out_v4, out_v6, Some(seen_v4), Some(seen_v6))
}

#[cfg(test)]
pub(in crate::nat) fn expand_pool_address_member(
    addr_str: &str,
    out_v4: &mut Vec<Ipv4Addr>,
    out_v6: &mut Vec<Ipv6Addr>,
) -> bool {
    expand_pool_address_inner(addr_str, out_v4, out_v6, None, None)
}

fn expand_pool_address_inner(
    addr_str: &str,
    out_v4: &mut Vec<Ipv4Addr>,
    out_v6: &mut Vec<Ipv6Addr>,
    mut seen_v4: Option<&mut rustc_hash::FxHashSet<Ipv4Addr>>,
    mut seen_v6: Option<&mut rustc_hash::FxHashSet<Ipv6Addr>>,
) -> bool {
    if let Some((addr_part, mask_part)) = addr_str.split_once('/') {
        // CIDR form: enumerate every address in the prefix range.
        match addr_part.parse::<IpAddr>() {
            Ok(IpAddr::V4(ip)) => {
                let Some(prefix_len) = parse_canonical_prefix_len(mask_part, 32) else {
                    return false;
                };
                let host_bits = 32 - prefix_len;
                let count = 1u64 << host_bits; // 1 for /32
                if count > MAX_POOL_PREFIX_HOSTS {
                    return false;
                }
                // Mask to the network base. `count` is <= MAX_POOL_PREFIX_HOSTS
                // (65536) here, so the `as u32` narrowing cannot truncate; the
                // over-cap prefixes that would overflow returned above.
                let base = u32::from(ip) & !(count as u32 - 1);
                for i in 0..count {
                    let addr = Ipv4Addr::from(base.wrapping_add(i as u32));
                    if seen_v4.as_mut().map_or(true, |seen| seen.insert(addr)) {
                        out_v4.push(addr);
                    }
                }
                true
            }
            Ok(IpAddr::V6(ip)) => {
                let Some(prefix_len) = parse_canonical_prefix_len(mask_part, 128) else {
                    return false;
                };
                let host_bits = 128 - prefix_len;
                // host_bits >= 17 already exceeds the cap; avoid 1u128 << 64+.
                if host_bits >= 64 || (1u128 << host_bits) > MAX_POOL_PREFIX_HOSTS as u128 {
                    return false;
                }
                let count = 1u128 << host_bits; // 1 for /128
                let base = u128::from(ip) & !(count - 1);
                for i in 0..count {
                    let addr = Ipv6Addr::from(base.wrapping_add(i));
                    if seen_v6.as_mut().map_or(true, |seen| seen.insert(addr)) {
                        out_v6.push(addr);
                    }
                }
                true
            }
            Err(_) => false,
        }
    } else {
        // Bare IP (no mask): exactly one host.
        match addr_str.parse::<IpAddr>() {
            Ok(IpAddr::V4(v4)) => {
                if seen_v4.as_mut().map_or(true, |seen| seen.insert(v4)) {
                    out_v4.push(v4);
                }
                true
            }
            Ok(IpAddr::V6(v6)) => {
                if seen_v6.as_mut().map_or(true, |seen| seen.insert(v6)) {
                    out_v6.push(v6);
                }
                true
            }
            Err(_) => false,
        }
    }
}
