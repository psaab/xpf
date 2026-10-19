//! #923: adaptive IP prefix set for policy address matching.
//!
//! Replaces the linear `nets.iter().any(|net| net.contains(ip))`
//! scan in `policy.rs` with a three-variant enum:
//!
//! - `MatchAny` — covers every address. Constructed when the input
//!   prefix list is empty (legacy `source_addresses: ["any"]`,
//!   `destination_addresses: []`, or all-malformed-input cases all
//!   collapse here) OR when any input prefix has length 0 (`/0`,
//!   `::/0`).
//! - `Linear(Vec)` — 1..=16 prefixes; cache-friendly linear scan.
//! - `Ranges(Vec)` — >16 prefixes; sorted, merged, non-overlapping
//!   `[lo, hi]` inclusive ranges with binary search (#15091).
//!
//! The semantics are exactly the legacy `nets_match_v4/v6`:
//! "match if any prefix in the set covers the IP". No
//! longest-prefix tiebreak is performed; this is a boolean-only
//! membership test.
//!
//! #15091: the previous representation for >16 prefixes was an
//! uncompressed one-`Box`-per-bit binary trie. A feed-backed book
//! at the #3934 caps (1<<20 prefixes, random /128s) materialised
//! ~2.9 GB of 24-byte nodes in the helper and was deep-cloned on
//! every forwarding publish. Sorted merged ranges cost 32 B per
//! retained v6 range (8 B per v4 range), need no per-bit nodes,
//! and collapse covered/overlapping prefixes at build time.

use crate::prefix::{PrefixV4, PrefixV6};
use std::net::{Ipv4Addr, Ipv6Addr};

/// Threshold below which a `Linear` variant is used. See
/// `docs/pr/923-policy-prefix-set/plan.md` \u00a7"Threshold rationale".
/// 16 is a starting tunable. A threshold-sweep + lookup-cost
/// microbench is a follow-up if the constant turns out to be
/// poorly tuned in production traces.
pub(crate) const PREFIX_SET_LINEAR_MAX: usize = 16;

/// #15091: helper-side prefix/memory budget. Mirrors the Go feed
/// cap (`config.MaxDynamicAddressFeedPrefixes` = 1<<20 in
/// `pkg/config/schema_security_dynamic_address.go`, aliased as
/// `maxFeedPrefixes` in `pkg/feeds/feeds.go`): a single feed may
/// legally carry 1<<20 prefixes, so any in-cap book, literal set,
/// or rule side at or below this count compiles. The budget is
/// enforced on the MERGED range count (the retained, disjoint
/// ranges after covered prefixes collapse), which is the
/// representation actually stored: a set that merges above this
/// many disjoint ranges exceeds the memory the cap was sized for
/// and the snapshot build must fail closed. See
/// `PrefixSetV4::try_from_prefixes` / `try_from_v3_literals`.
pub(crate) const MAX_PREFIX_SET_RANGES: usize = 1 << 20;

/// #15091: a prefix set whose merged range count exceeds
/// [`MAX_PREFIX_SET_RANGES`]. Callers that build policy state map
/// this to `SnapshotIntegrityError` so the whole snapshot is
/// rejected (fail closed, previous good state retained) rather
/// than materialising an unbounded representation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PrefixSetBudgetExceeded {
    /// Merged disjoint ranges the set would retain.
    pub ranges: usize,
    /// The budget that was exceeded ([`MAX_PREFIX_SET_RANGES`]).
    pub limit: usize,
}

/// IPv4 prefix membership set. See module docs.
///
/// `MatchNone` (#1606) is distinct from `MatchAny`: it means
/// "no criteria specified; the address-side of the rule does not
/// match any IP". `from_prefixes(empty)` returns `MatchAny`
/// (legacy convention preserved for back-compat), while the new
/// `from_v3_literals(empty)` returns `MatchNone`.
#[derive(Debug, Clone)]
pub(crate) enum PrefixSetV4 {
    MatchAny,
    MatchNone,
    Linear(Vec<PrefixV4>),
    /// Sorted merged ranges plus the distinct-prefix count
    /// (`prefix_count` keeps its pre-#15091 cardinality meaning:
    /// covered prefixes still count, exact duplicates do not).
    Ranges(Vec<(u32, u32)>, usize),
}

#[derive(Debug, Clone)]
pub(crate) enum PrefixSetV6 {
    MatchAny,
    MatchNone,
    Linear(Vec<PrefixV6>),
    Ranges(Vec<(u128, u128)>, usize),
}

/// #15091: build sorted, merged, disjoint inclusive ranges from
/// v4 prefixes. Returns `Err` when the merged count exceeds the
/// budget; the caller fails the snapshot closed.
fn merged_ranges_v4(
    prefixes: &[PrefixV4],
) -> Result<(Vec<(u32, u32)>, usize), PrefixSetBudgetExceeded> {
    let mut distinct: Vec<(u32, u8)> = prefixes
        .iter()
        .map(|p| (u32::from(p.addr()), p.prefix_len()))
        .collect();
    distinct.sort_unstable();
    distinct.dedup();
    let distinct_count = distinct.len();
    let mut ranges: Vec<(u32, u32)> = Vec::with_capacity(prefixes.len());
    for p in prefixes {
        let lo = u32::from(p.addr());
        let host = if p.prefix_len() == 0 {
            u32::MAX
        } else if p.prefix_len() >= 32 {
            0
        } else {
            (1u32 << (32 - p.prefix_len())) - 1
        };
        ranges.push((lo, lo.wrapping_add(host)));
    }
    ranges.sort_unstable();
    let mut out: Vec<(u32, u32)> = Vec::with_capacity(ranges.len());
    for (lo, hi) in ranges {
        match out.last_mut() {
            Some((_, prev_hi)) if lo <= prev_hi.saturating_add(1) => {
                if hi > *prev_hi {
                    *prev_hi = hi;
                }
            }
            _ => {
                out.push((lo, hi));
                if out.len() > MAX_PREFIX_SET_RANGES {
                    return Err(PrefixSetBudgetExceeded {
                        ranges: out.len(),
                        limit: MAX_PREFIX_SET_RANGES,
                    });
                }
            }
        }
    }
    Ok((out, distinct_count))
}

/// #15091: v6 mirror of `merged_ranges_v4`.
fn merged_ranges_v6(
    prefixes: &[PrefixV6],
) -> Result<(Vec<(u128, u128)>, usize), PrefixSetBudgetExceeded> {
    let mut distinct: Vec<(u128, u8)> = prefixes
        .iter()
        .map(|p| (u128::from(p.addr()), p.prefix_len()))
        .collect();
    distinct.sort_unstable();
    distinct.dedup();
    let distinct_count = distinct.len();
    let mut ranges: Vec<(u128, u128)> = Vec::with_capacity(prefixes.len());
    for p in prefixes {
        let lo = u128::from(p.addr());
        let host = if p.prefix_len() == 0 {
            u128::MAX
        } else if p.prefix_len() >= 128 {
            0
        } else {
            (1u128 << (128 - p.prefix_len())) - 1
        };
        ranges.push((lo, lo.wrapping_add(host)));
    }
    ranges.sort_unstable();
    let mut out: Vec<(u128, u128)> = Vec::with_capacity(ranges.len());
    for (lo, hi) in ranges {
        match out.last_mut() {
            Some((_, prev_hi)) if lo <= prev_hi.saturating_add(1) => {
                if hi > *prev_hi {
                    *prev_hi = hi;
                }
            }
            _ => {
                out.push((lo, hi));
                if out.len() > MAX_PREFIX_SET_RANGES {
                    return Err(PrefixSetBudgetExceeded {
                        ranges: out.len(),
                        limit: MAX_PREFIX_SET_RANGES,
                    });
                }
            }
        }
    }
    Ok((out, distinct_count))
}

impl PrefixSetV4 {
    /// Legacy factory: empty input collapses to `MatchAny`. Used by
    /// the non-v3-shaped fallback path that parses fully-expanded
    /// `source_addresses` from old-Go snapshots. Infallible
    /// wrapper over `try_from_prefixes`: an over-budget set (only
    /// reachable from a corrupt/hand-built snapshot, since the Go
    /// producer is capped) degrades to `MatchNone` rather than
    /// panicking \u2014 never `MatchAny`, so it cannot widen a deny.
    pub(crate) fn from_prefixes(prefixes: Vec<PrefixV4>) -> Self {
        Self::try_from_prefixes(prefixes).unwrap_or(Self::MatchNone)
    }

    /// #15091 fallible legacy factory.
    pub(crate) fn try_from_prefixes(prefixes: Vec<PrefixV4>) -> Result<Self, PrefixSetBudgetExceeded> {
        if prefixes.is_empty() {
            return Ok(Self::MatchAny);
        }
        if prefixes.iter().any(|p| p.prefix_len() == 0) {
            return Ok(Self::MatchAny);
        }
        if prefixes.len() <= PREFIX_SET_LINEAR_MAX {
            Ok(Self::Linear(prefixes))
        } else {
            {
                let (r, n) = merged_ranges_v4(&prefixes)?;
                Ok(Self::Ranges(r, n))
            }
        }
    }

    /// #1606 v3 factory: empty input collapses to `MatchNone`,
    /// breaking the legacy "empty Vec = MatchAny" coupling for
    /// v3-shaped rule sides + book entries. Used when the rule
    /// is v3-shaped on this side, and when building book entries.
    /// Infallible wrapper over `try_from_v3_literals` (see
    /// `from_prefixes` for the over-budget posture).
    pub(crate) fn from_v3_literals(prefixes: Vec<PrefixV4>) -> Self {
        Self::try_from_v3_literals(prefixes).unwrap_or(Self::MatchNone)
    }

    /// #15091 fallible v3 factory.
    pub(crate) fn try_from_v3_literals(prefixes: Vec<PrefixV4>) -> Result<Self, PrefixSetBudgetExceeded> {
        if prefixes.is_empty() {
            return Ok(Self::MatchNone);
        }
        if prefixes.iter().any(|p| p.prefix_len() == 0) {
            return Ok(Self::MatchAny);
        }
        if prefixes.len() <= PREFIX_SET_LINEAR_MAX {
            Ok(Self::Linear(prefixes))
        } else {
            {
                let (r, n) = merged_ranges_v4(&prefixes)?;
                Ok(Self::Ranges(r, n))
            }
        }
    }

    /// Returns true iff some prefix in the set covers `ip`.
    #[inline]
    pub(crate) fn contains(&self, ip: Ipv4Addr) -> bool {
        match self {
            Self::MatchAny => true,
            Self::MatchNone => false,
            Self::Linear(v) => v.iter().any(|p| p.contains(ip)),
            Self::Ranges(r, _) => {
                let x = u32::from(ip);
                let idx = r.partition_point(|&(_, hi)| hi < x);
                matches!(r.get(idx), Some(&(lo, _)) if lo <= x)
            }
        }
    }

    #[inline]
    pub(crate) fn is_match_any(&self) -> bool {
        matches!(self, Self::MatchAny)
    }

    #[inline]
    pub(crate) fn is_match_none(&self) -> bool {
        matches!(self, Self::MatchNone)
    }

    /// Retained disjoint range/prefix count. For `Ranges` this is
    /// the merged range count (covered duplicates collapse), for
    /// `Linear` the literal count. Debug/logging only.
    pub(crate) fn prefix_count(&self) -> usize {
        match self {
            Self::MatchAny | Self::MatchNone => 0,
            Self::Linear(v) => v.len(),
            Self::Ranges(_, n) => *n,
        }
    }

    /// #15091: heap bytes retained by this set (variant payload
    /// only, excluding the enum itself). `Ranges` costs 8 B/range
    /// (v4) with no per-bit nodes.
    pub(crate) fn heap_bytes(&self) -> usize {
        match self {
            Self::MatchAny | Self::MatchNone => 0,
            Self::Linear(v) => v.capacity() * std::mem::size_of::<PrefixV4>(),
            Self::Ranges(r, _) => r.capacity() * std::mem::size_of::<(u32, u32)>(),
        }
    }
}

impl PrefixSetV6 {
    pub(crate) fn from_prefixes(prefixes: Vec<PrefixV6>) -> Self {
        Self::try_from_prefixes(prefixes).unwrap_or(Self::MatchNone)
    }

    /// #15091 fallible legacy factory.
    pub(crate) fn try_from_prefixes(prefixes: Vec<PrefixV6>) -> Result<Self, PrefixSetBudgetExceeded> {
        if prefixes.is_empty() {
            return Ok(Self::MatchAny);
        }
        if prefixes.iter().any(|p| p.prefix_len() == 0) {
            return Ok(Self::MatchAny);
        }
        if prefixes.len() <= PREFIX_SET_LINEAR_MAX {
            Ok(Self::Linear(prefixes))
        } else {
            {
                let (r, n) = merged_ranges_v6(&prefixes)?;
                Ok(Self::Ranges(r, n))
            }
        }
    }

    pub(crate) fn from_v3_literals(prefixes: Vec<PrefixV6>) -> Self {
        Self::try_from_v3_literals(prefixes).unwrap_or(Self::MatchNone)
    }

    /// #15091 fallible v3 factory.
    pub(crate) fn try_from_v3_literals(prefixes: Vec<PrefixV6>) -> Result<Self, PrefixSetBudgetExceeded> {
        if prefixes.is_empty() {
            return Ok(Self::MatchNone);
        }
        if prefixes.iter().any(|p| p.prefix_len() == 0) {
            return Ok(Self::MatchAny);
        }
        if prefixes.len() <= PREFIX_SET_LINEAR_MAX {
            Ok(Self::Linear(prefixes))
        } else {
            {
                let (r, n) = merged_ranges_v6(&prefixes)?;
                Ok(Self::Ranges(r, n))
            }
        }
    }

    #[inline]
    pub(crate) fn contains(&self, ip: Ipv6Addr) -> bool {
        match self {
            Self::MatchAny => true,
            Self::MatchNone => false,
            Self::Linear(v) => v.iter().any(|p| p.contains(ip)),
            Self::Ranges(r, _) => {
                let x = u128::from(ip);
                let idx = r.partition_point(|&(_, hi)| hi < x);
                matches!(r.get(idx), Some(&(lo, _)) if lo <= x)
            }
        }
    }

    #[inline]
    pub(crate) fn is_match_any(&self) -> bool {
        matches!(self, Self::MatchAny)
    }

    #[inline]
    pub(crate) fn is_match_none(&self) -> bool {
        matches!(self, Self::MatchNone)
    }

    pub(crate) fn prefix_count(&self) -> usize {
        match self {
            Self::MatchAny | Self::MatchNone => 0,
            Self::Linear(v) => v.len(),
            Self::Ranges(_, n) => *n,
        }
    }

    /// #15091: v6 `Ranges` costs 32 B/range. See v4 `heap_bytes`.
    pub(crate) fn heap_bytes(&self) -> usize {
        match self {
            Self::MatchAny | Self::MatchNone => 0,
            Self::Linear(v) => v.capacity() * std::mem::size_of::<PrefixV6>(),
            Self::Ranges(r, _) => r.capacity() * std::mem::size_of::<(u128, u128)>(),
        }
    }
}

/// `MatchAny`, and that is FAIL-OPEN by construction — a defaulted prefix set
/// matches every address (#7745, from the #6907 re-verification).
///
/// REACHABILITY, measured rather than assumed. No production path reaches
/// `PrefixSetV4::default()`:
///
///   - the only production references are inside `impl Default for PolicyRule`
///     (`policy.rs`), and the real rule constructor names EVERY field
///     explicitly. `policy.rs:2127` records why: the `..PolicyRule::default()`
///     tail was deliberately dropped so a future field addition is a compile
///     error, "eliminating the silent-zero-default hazard" (#1632).
///   - so `PolicyRule::default()` itself is never called on a packet path; the
///     `impl` survives as a type-level convenience.
///
/// WHY IT IS NOT FLIPPED TO `MatchNone`. Inside that same `Default` impl the
/// sibling fields are `source_v4_match_any: true`, `destination_v4_match_any:
/// true`, and so on. A defaulted `PolicyRule` is deliberately a match-anything
/// rule; making the prefix sets match NOTHING would leave it internally
/// inconsistent — the booleans saying "any", the sets saying "none" — which is
/// a worse hazard than the one being removed, and it would land on whichever
/// caller relies on the current shape.
///
/// This is therefore a LATENT hazard recorded in place, not a defect to fix:
/// the fail-open direction is real, and nothing can reach it today. If a
/// `..Default::default()` tail is ever reintroduced to a rule constructor, this
/// becomes live and the fix is at that call site, not here.
impl Default for PrefixSetV4 {
    fn default() -> Self {
        Self::MatchAny
    }
}

/// See `impl Default for PrefixSetV4` for the reachability measurement and why
/// this stays `MatchAny` (#7745).
impl Default for PrefixSetV6 {
    fn default() -> Self {
        Self::MatchAny
    }
}


#[cfg(test)]
#[path = "prefix_set_tests.rs"]
mod tests;
