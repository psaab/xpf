//! NPTv6 (RFC 6296) stateless IPv6-to-IPv6 prefix translation.
//!
//! Each rule maps an internal /48 or /64 prefix to an external prefix.
//! A precomputed *adjustment* value ensures checksum neutrality so that
//! no L4 checksum update is required after translation.
//!
//! Translation algorithm:
//! - Rewrite the prefix words (3 for /48, 4 for /64).
//! - For /48, reject an internal 0xFFFF subnet (RFC 6296 §3.2).
//! - For /64, inspect IID words 4..7 in order and adjust the first word
//!   that was not initially 0xFFFF (RFC 6296 §3.5).
//! - Reject an all-zero IID (an explicit RFC 6296 §3.7 MUST) and a /64 IID
//!   with no adjustable word (the scoped reviewer edge).
//! - Use ones-complement arithmetic to maintain checksum neutrality.
//! - If the adjusted word becomes 0xFFFF, replace with 0x0000.
//! - **#3233 corner:** when the internal and external prefixes have EQUAL
//!   ones-complement sums (a *checksum-neutral* prefix pair), the precomputed
//!   adjustment is ones-complement zero, so NO interface-ID word fixup is
//!   required — the translation is a pure prefix swap. The fixup is SKIPPED
//!   in that case ([`adjust_word`] is not applied). Applying it anyway would
//!   fold a host whose adjustment word is 0xFFFF down to 0x0000 (and the
//!   inbound side never restores it), collapsing that host onto the 0x0000
//!   host. Note that `compute_adjustment` represents ones-complement zero as
//!   `0xFFFF` (NOT `0x0000`) for a checksum-neutral pair — see
//!   [`is_zero_adjustment`]. This neutral-pair behavior is distinct from the
//!   RFC 6296 §3.7 all-zero-IID MUST.
//!
//! A translation that cannot satisfy a scoped RFC discard rule or the
//! reviewer-scoped all-ones-IID edge returns
//! [`Nptv6Translation::Untranslatable`]; packet callers must drop it rather
//! than treating it as a prefix miss and forwarding unchanged.
//!
//! Two module invariants the rest of the crate relies on:
//!
//! * **Fail CLOSED on an unparseable config rule (#2240).**
//!   [`Nptv6State::try_from_snapshots`] rejects the whole snapshot (returning a
//!   [`crate::policy::SnapshotIntegrityError`]) on an empty/malformed prefix, an
//!   unsupported prefix length (not /48 or /64), a mismatched internal/external
//!   prefix-length pair, or host bits set beyond the prefix length (#4519) — one
//!   bad rule fails the snapshot rather than being silently filtered. The
//!   pre-fix parser silently `continue`d past a bad rule, and the Go dataplane
//!   compiler then deleted stale entries over only the VALID subset, so editing
//!   one previously-good rule into an invalid one tore down its working
//!   translation with no replacement. **Host bits (#4519):** [`parse_prefix`]
//!   used to `debug_assert!` (compiled out in release) then MASK the host bits
//!   and return `Some`, so a leniently-loaded / peer-synced pre-#2380 rule with
//!   host bits (`...:2::/48`) INSTALLED the silently-widened (`...::/48`)
//!   over-broad prefix in release — directly contradicting the Go lenient-load
//!   warning that promises the helper rejects the snapshot and keeps the prior
//!   state. `parse_prefix` now returns `None` on host bits so the snapshot is
//!   genuinely rejected and the warning's promise holds. The apply preflight
//!   keeps the previous live forwarding state on this Err. This is the
//!   helper-boundary backstop to the Go commit-time gate
//!   (`pkg/config/compiler_nat.go`, #2240/#2380), consistent with the
//!   #2124/#2142/#2173/#2212 fail-closed family.
//! * **Reject overlapping prefixes — deterministic translation (#2241).**
//!   `translate_inbound`/`translate_outbound` resolve a match by FIRST hit in
//!   insertion order with no longest-prefix-match. Two rules whose prefixes
//!   overlap in the same direction (e.g. a /48 and a nested /64) would make the
//!   translation identity depend purely on rule order. `try_from_snapshots`
//!   rejects an overlapping pair so resolution stays deterministic. The Go
//!   commit-time gate (#2241) is primary; this is the helper-boundary backstop.
//!   **#5176 zone partitioning:** the overlap is checked only between rules
//!   whose static-NAT rule-set `from_zone` scopes can BOTH match a single
//!   packet (either scope empty = wildcard, or the two scopes equal). Two
//!   same-prefix rules with DIFFERENT non-empty `from_zone`s are legitimate
//!   per-zone split-horizon (no packet matches both), so they are admitted —
//!   they are not an order-dependent overlap.
//! * **Match ONLY within the rule-set zone scope (#5176, security).**
//!   A static-NAT rule-set is scoped by `from zone` (Go `rs.FromZone`, carried
//!   on [`Nptv6Rule::from_zone`]). An NPTv6 rule matches a packet ONLY when its
//!   `from_zone` is empty (wildcard) OR equals the packet's relevant security
//!   zone — the INGRESS zone for [`Nptv6State::translate_inbound`] and the
//!   EGRESS zone for [`Nptv6State::translate_outbound`]. Before #5176 both
//!   lookups selected purely by prefix, so a rule scoped `from zone untrust`
//!   translated (and thus routed) NPTv6 traffic sourced from EVERY zone — a
//!   security-domain crossing — and the overlap gate wrongly rejected
//!   legitimate per-zone split-horizon.

use crate::Nptv6RuleSnapshot;
use crate::policy::SnapshotIntegrityError;
use std::net::Ipv6Addr;

/// A parsed NPTv6 rule with precomputed adjustment.
#[derive(Clone, Debug)]
pub(crate) struct Nptv6Rule {
    /// #5176: the static-NAT rule-set `from zone` scope (Go `rs.FromZone`,
    /// serialized on the snapshot as `from_zone`). Empty = wildcard (matches
    /// any zone). A rule matches a packet only when this is empty or equals the
    /// packet's relevant security zone (ingress for inbound, egress for
    /// outbound) — see [`Nptv6Rule::zone_matches`].
    pub(crate) from_zone: String,
    /// Prefix words to write into the address (3 for /48, 4 for /64).
    pub(crate) internal_prefix: [u16; 4],
    pub(crate) external_prefix: [u16; 4],
    /// Precomputed checksum-neutral adjustment (RFC 6296 Section 3.1).
    pub(crate) adjustment: u16,
    /// Number of prefix words to rewrite: 3 for /48, 4 for /64.
    pub(crate) prefix_words: usize,
}

impl Nptv6Rule {
    /// #5176: does this rule's `from_zone` scope admit a packet whose relevant
    /// security zone is `zone`? An empty `from_zone` is a wildcard that matches
    /// any zone; otherwise the zone must match exactly. The caller supplies the
    /// ingress zone for inbound translation and the egress zone for outbound.
    #[inline]
    fn zone_matches(&self, zone: &str) -> bool {
        self.from_zone.is_empty() || self.from_zone == zone
    }
}

/// `Untranslatable` is distinct from `NoMatch`: §3.2 directs discard for an
/// unmapped internal subnet, and §3.7 contains the explicit all-zero-IID MUST.
/// The all-ones-IID outcome is the scoped reviewer reading of §3.5's
/// first-available-word selection plus §3.7's reserved-anycast note. Packet
/// callers must not let any of these outcomes fall through to ordinary
/// forwarding or a different NAT rule.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Nptv6Translation {
    /// No configured rule matched the address.
    NoMatch,
    /// A configured rule matched and rewrote the address in place.
    Translated,
    /// A configured rule matched, but the scoped mapping rules refuse it.
    Untranslatable,
}

impl Nptv6Translation {
    #[inline]
    pub(crate) fn is_translated(self) -> bool {
        matches!(self, Self::Translated)
    }
}

/// Aggregated NPTv6 state built from config snapshots.
#[derive(Clone, Debug, Default)]
pub(crate) struct Nptv6State {
    /// Rules for inbound translation (external dst -> internal dst).
    /// Indexed by external prefix.
    inbound: Vec<Nptv6Rule>,
    /// Rules for outbound translation (internal src -> external src).
    /// Indexed by internal prefix.
    outbound: Vec<Nptv6Rule>,
}

/// Compute the RFC 6296 adjustment value.
///
/// `adjustment = ones_complement_sum(internal_prefix) - ones_complement_sum(external_prefix)`
///
/// This matches the BPF implementation in `xpf_nat.h`.
fn compute_adjustment(internal: &[u16], external: &[u16], prefix_words: usize) -> u16 {
    let mut isum: u32 = 0;
    let mut esum: u32 = 0;
    for i in 0..prefix_words {
        isum += internal[i] as u32;
        esum += external[i] as u32;
    }
    // Fold to 16-bit ones-complement
    while isum > 0xFFFF {
        isum = (isum & 0xFFFF) + (isum >> 16);
    }
    while esum > 0xFFFF {
        esum = (esum & 0xFFFF) + (esum >> 16);
    }
    // adjustment = internal_sum - external_sum (ones-complement subtraction)
    // In ones-complement: a - b = a + ~b
    let mut adj: u32 = isum + (!esum & 0xFFFF);
    while adj > 0xFFFF {
        adj = (adj & 0xFFFF) + (adj >> 16);
    }
    adj as u16
}

/// Apply an adjustment to a 16-bit word using ones-complement arithmetic.
/// Returns the adjusted word, with 0xFFFF mapped to 0x0000 per RFC 6296.
#[inline]
fn adjust_word(word: u16, adj: u16) -> u16 {
    let mut sum: u32 = word as u32 + adj as u32;
    // Fold carry
    sum = (sum & 0xFFFF) + (sum >> 16);
    sum = (sum & 0xFFFF) + (sum >> 16);
    let result = sum as u16;
    if result == 0xFFFF { 0x0000 } else { result }
}

/// #3233: is the precomputed RFC 6296 adjustment ones-complement ZERO?
///
/// A *checksum-neutral* prefix pair (internal and external prefixes with equal
/// ones-complement sums) needs no interface-ID word fixup — the translation is a
/// pure prefix swap. [`compute_adjustment`] represents that zero as `0xFFFF`
/// (negative zero in ones-complement: `S + !S = 0xFFFF`), and it never produces
/// the positive-zero `0x0000` representation, but both are accepted defensively.
///
/// For the #3233 neutral-pair invariant, this implementation skips
/// [`adjust_word`]: applying it would fold a host whose adjustment word is
/// `0xFFFF` to `0x0000` outbound and never restore it inbound, collapsing the
/// `0xFFFF` host onto the `0x0000` host. The RFC-6296-mandated
/// `0xFFFF -> 0x0000` fold is preserved for the general (non-neutral,
/// adjustment != ones-complement-zero) case.
#[inline]
fn is_zero_adjustment(adj: u16) -> bool {
    adj == 0x0000 || adj == 0xFFFF
}

/// Return the first RFC 6296 §3.5 adjustment word for a /64 IID.
///
/// The caller must inspect the original address before rewriting its prefix.
/// The scoped reviewer reading treats a /64 IID made entirely of 0xFFFF words
/// as having no usable adjustment word and therefore no stateless mapping.
#[inline]
fn first_non_ffff_iid_word(words: &[u16; 8], prefix_words: usize) -> Option<usize> {
    if prefix_words < 4 {
        return Some(3);
    }
    (4..8).find(|&index| words[index] != 0xFFFF)
}

/// RFC 6296 §3.7 rejects an all-zero IID for mappings with a longer prefix.
#[inline]
fn iid_is_all_zero(words: &[u16; 8], prefix_words: usize) -> bool {
    prefix_words >= 4 && words[4..8].iter().all(|&word| word == 0)
}

/// Extract 16-bit words from an Ipv6Addr.
fn ipv6_to_words(addr: &Ipv6Addr) -> [u16; 8] {
    let octets = addr.octets();
    let mut words = [0u16; 8];
    for i in 0..8 {
        words[i] = u16::from_be_bytes([octets[i * 2], octets[i * 2 + 1]]);
    }
    words
}

/// Reconstruct an Ipv6Addr from 16-bit words.
fn words_to_ipv6(words: &[u16; 8]) -> Ipv6Addr {
    let mut octets = [0u8; 16];
    for i in 0..8 {
        let bytes = words[i].to_be_bytes();
        octets[i * 2] = bytes[0];
        octets[i * 2 + 1] = bytes[1];
    }
    Ipv6Addr::from(octets)
}

/// Parse a prefix string like "2001:db8:1::/48" into ([u16; 4], prefix_len).
/// Returns None if parsing fails, the prefix length is not /48 or /64, OR host
/// bits are set beyond the prefix length (#4519 — fail closed, do NOT mask).
fn parse_prefix(s: &str) -> Option<([u16; 4], usize)> {
    let parts: Vec<&str> = s.split('/').collect();
    if parts.len() != 2 {
        return None;
    }
    // #7077: DIGITS ONLY. `u8::from_str` accepts a leading `+`, so this
    // parsed "2001:db8::/+48" as prefix_len 48 while Go's net.ParseCIDR --
    // whose mask goes through `dtoi`, digits only -- rejects the same string.
    // The two planes therefore disagreed about whether a rule installs, in the
    // direction that matters: the Go pre-pass refused a config the helper would
    // have accepted, and #6894 r9 had inferred "the helper rejects this" from
    // "Go cannot parse this".
    //
    // Tightened HERE rather than loosened on the Go side because Go's grammar
    // is the one an operator's config is written against and the one Junos
    // parity is measured by. `+48` is not a mask length anyone means to write.
    //
    // Rejecting non-digits also settles the neighbouring shapes the same way
    // Go already does: `-48`, `48+`, whitespace, `_` separators, `0x30`, and
    // non-ASCII digits. Only the leading `+` actually changed behaviour; the
    // rest were already refused by `u8::from_str` and are now refused one step
    // earlier, by the same rule.
    if parts[1].is_empty() || !parts[1].bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let prefix_len: u8 = parts[1].parse().ok()?;
    let prefix_words = match prefix_len {
        48 => 3,
        64 => 4,
        _ => return None,
    };
    let addr: Ipv6Addr = parts[0].parse().ok()?;
    let words = ipv6_to_words(&addr);
    // #4519: fail CLOSED on host bits set beyond the prefix length — do NOT
    // mask-and-accept. The Go commit-time validator (validateNPTv6Strict in
    // pkg/config/compiler_nat.go, #2380) hard-rejects a prefix with any bit set
    // beyond its length, but the LENIENT tolerant-load / peer-sync path
    // (compiler.go lenientNPTv6, for a config committed before that gate existed
    // or synced from a peer) only WARNS — and that warning literally promises
    // "the helper rejects the whole NPTv6 snapshot and the previous state is
    // kept". Returning `Some` after masking `words[prefix_words..]` would make
    // that promise FALSE: `try_from_snapshots` would INSTALL the silently-
    // widened (masked) prefix, over-translating a broader range than the
    // operator authored (e.g. `...:2::/48` -> the wider `...::/48`). Returning
    // `None` makes `try_from_snapshots` reject the WHOLE snapshot so the apply
    // preflight keeps the previous live forwarding state exactly as the warning
    // claims — the helper-boundary backstop in the #2124/#2142/#2173/#2212
    // fail-closed family. This `None`-return is the SOLE enforcement now (the
    // prior `debug_assert!` was compiled out in release, leaving no runtime
    // enforcement); it fails closed uniformly in both debug and release builds.
    if words[prefix_words..8].iter().any(|&w| w != 0) {
        return None;
    }
    let mut prefix = [0u16; 4];
    for i in 0..prefix_words {
        prefix[i] = words[i];
    }
    Some((prefix, prefix_words))
}

impl Nptv6State {
    /// Build from config snapshot NPTv6 rules, failing CLOSED on an
    /// unparseable / unsupported / mismatched rule (#2240) and on overlapping
    /// prefixes (#2241).
    ///
    /// In a retired-eBPF world (#1373) the userspace helper is the enforcement
    /// plane. The pre-fix parser silently `continue`d past a bad rule, and the
    /// Go dataplane compiler then called `DeleteStaleNPTv6(written)` over only
    /// the VALID subset — so editing one previously-good rule into an invalid
    /// one removed its working translation entry with no replacement installed,
    /// silently disabling a working translation. The primary gate is the Go
    /// commit-time validation (`pkg/config/compiler_nat.go`, #2240); this is the
    /// helper-boundary backstop, consistent with the #2124/#2142/#2173/#2212
    /// fail-closed family.
    ///
    /// On any unparseable rule or overlapping pair this returns a
    /// `SnapshotIntegrityError`; the apply preflight
    /// (`forwarding_build`/`reconcile`/`refresh`) then keeps the previous live
    /// forwarding state rather than installing a narrower / nondeterministic
    /// NPTv6 config.
    pub(crate) fn try_from_snapshots(
        snaps: &[Nptv6RuleSnapshot],
    ) -> Result<Self, SnapshotIntegrityError> {
        let mut state = Nptv6State::default();
        // Track (prefix, prefix_words, rule_name, from_zone) to reject overlaps
        // (#2241), partitioned by zone scope (#5176): only rules whose zone
        // scopes can both match a single packet count as an overlap.
        let mut internal_seen: Vec<([u16; 4], usize, String, String)> =
            Vec::with_capacity(snaps.len());
        let mut external_seen: Vec<([u16; 4], usize, String, String)> =
            Vec::with_capacity(snaps.len());
        for snap in snaps {
            let (internal_prefix, iwords) = match parse_prefix(&snap.internal_prefix) {
                Some(v) => v,
                None => {
                    return Err(SnapshotIntegrityError::Nptv6UnparseableRule {
                        rule_name: snap.name.clone(),
                        field: format!(
                            "internal/nptv6 prefix {:?} (must be a valid IPv6 /48 or /64 with host bits clear)",
                            snap.internal_prefix
                        ),
                    });
                }
            };
            let (external_prefix, ewords) = match parse_prefix(&snap.external_prefix) {
                Some(v) => v,
                None => {
                    return Err(SnapshotIntegrityError::Nptv6UnparseableRule {
                        rule_name: snap.name.clone(),
                        field: format!(
                            "external/match prefix {:?} (must be a valid IPv6 /48 or /64 with host bits clear)",
                            snap.external_prefix
                        ),
                    });
                }
            };
            // Both prefixes must have the same length.
            if iwords != ewords {
                return Err(SnapshotIntegrityError::Nptv6UnparseableRule {
                    rule_name: snap.name.clone(),
                    field: format!(
                        "prefix lengths must match (internal {:?} vs external {:?})",
                        snap.internal_prefix, snap.external_prefix
                    ),
                });
            }
            // #2241: reject overlapping prefixes in either direction so the
            // first-match dataplane resolution stays deterministic. Outbound
            // matches on the internal prefix; inbound matches on the external
            // prefix; check each independently. #5176: two rules only conflict
            // when their `from_zone` scopes can both match one packet — a
            // same-prefix pair with different non-empty zones is legitimate
            // per-zone split-horizon, not an order-dependent overlap.
            if let Some(prev) =
                find_overlap(&internal_seen, &internal_prefix, iwords, &snap.from_zone)
            {
                return Err(SnapshotIntegrityError::Nptv6OverlappingPrefix {
                    first_rule: prev,
                    second_rule: snap.name.clone(),
                    direction: "outbound (internal)",
                });
            }
            if let Some(prev) =
                find_overlap(&external_seen, &external_prefix, ewords, &snap.from_zone)
            {
                return Err(SnapshotIntegrityError::Nptv6OverlappingPrefix {
                    first_rule: prev,
                    second_rule: snap.name.clone(),
                    direction: "inbound (external)",
                });
            }
            internal_seen.push((
                internal_prefix,
                iwords,
                snap.name.clone(),
                snap.from_zone.clone(),
            ));
            external_seen.push((
                external_prefix,
                ewords,
                snap.name.clone(),
                snap.from_zone.clone(),
            ));

            let adjustment = compute_adjustment(&internal_prefix, &external_prefix, iwords);

            let rule = Nptv6Rule {
                from_zone: snap.from_zone.clone(),
                internal_prefix,
                external_prefix,
                adjustment,
                prefix_words: iwords,
            };

            // Inbound: match external prefix on dst, rewrite to internal.
            state.inbound.push(rule.clone());
            // Outbound: match internal prefix on src, rewrite to external.
            state.outbound.push(rule);
        }
        Ok(state)
    }

    /// Infallible test convenience wrapper over [`try_from_snapshots`] (#2240).
    /// Panics on a snapshot integrity error, which valid test snapshots never
    /// produce. Production builds the state through `try_from_snapshots` so an
    /// unparseable rule or an overlapping pair rejects the snapshot and keeps
    /// the previous live state.
    #[cfg(test)]
    pub(crate) fn from_snapshots(snaps: &[Nptv6RuleSnapshot]) -> Self {
        Self::try_from_snapshots(snaps)
            .expect("test snapshot must not produce an NPTv6 integrity error")
    }

    /// Translate an inbound packet's destination address.
    ///
    /// This compatibility wrapper preserves the historical boolean API for
    /// helper callers that only need to know whether a rule translated. Packet
    /// paths that must distinguish a prefix miss from a scoped untranslatable
    /// outcome use [`Self::translate_inbound_result`].
    #[inline]
    pub(crate) fn translate_inbound(&self, dst: &mut Ipv6Addr, ingress_zone: &str) -> bool {
        self.translate_inbound_result(dst, ingress_zone).is_translated()
    }

    /// Translate an inbound packet and expose scoped untranslatable
    /// addresses as a distinct outcome.
    ///
    /// #5176: `ingress_zone` is the packet's ingress security zone. A rule
    /// matches only when its `from_zone` scope is empty (wildcard) or equals
    /// `ingress_zone` — a rule scoped `from zone X` must NOT translate traffic
    /// arriving from a different zone (security-domain crossing).
    pub(crate) fn translate_inbound_result(
        &self,
        dst: &mut Ipv6Addr,
        ingress_zone: &str,
    ) -> Nptv6Translation {
        let mut words = ipv6_to_words(dst);
        for rule in &self.inbound {
            if rule.zone_matches(ingress_zone)
                && prefix_matches(&words, &rule.external_prefix, rule.prefix_words)
            {
                // RFC 6296 §3.7 explicitly says an all-zero IID MUST be
                // dropped. The all-ones/no-available-word refusal is the
                // scoped reviewer edge, not an RFC2119 MUST.
                if iid_is_all_zero(&words, rule.prefix_words) {
                    return Nptv6Translation::Untranslatable;
                }
                let adj_word = match first_non_ffff_iid_word(&words, rule.prefix_words) {
                    Some(index) => index,
                    None => return Nptv6Translation::Untranslatable,
                };
                // Rewrite prefix words to internal prefix.
                for i in 0..rule.prefix_words {
                    words[i] = rule.internal_prefix[i];
                }
                // Adjust the selected word after the prefix: inbound uses
                // !adjustment. #3233 skips the fixup for a neutral pair, but
                // still selects a stable word so the mapping remains explicit.
                if !is_zero_adjustment(rule.adjustment) {
                    let inv_adj = !rule.adjustment; // ones-complement NOT
                    words[adj_word] = adjust_word(words[adj_word], inv_adj);
                }
                *dst = words_to_ipv6(&words);
                return Nptv6Translation::Translated;
            }
        }
        Nptv6Translation::NoMatch
    }

    /// Translate an outbound packet's source address.
    ///
    /// This compatibility wrapper preserves the historical boolean API.
    #[inline]
    pub(crate) fn translate_outbound(&self, src: &mut Ipv6Addr, egress_zone: &str) -> bool {
        self.translate_outbound_result(src, egress_zone).is_translated()
    }

    /// Translate an outbound packet and expose scoped untranslatable
    /// addresses as a distinct outcome.
    ///
    /// #5176: `egress_zone` is the packet's egress security zone. A rule
    /// matches only when its `from_zone` scope is empty (wildcard) or equals
    /// `egress_zone` — a rule scoped `from zone X` must NOT translate the
    /// source of traffic leaving via a different zone (security-domain
    /// crossing).
    pub(crate) fn translate_outbound_result(
        &self,
        src: &mut Ipv6Addr,
        egress_zone: &str,
    ) -> Nptv6Translation {
        let mut words = ipv6_to_words(src);
        for rule in &self.outbound {
            if rule.zone_matches(egress_zone)
                && prefix_matches(&words, &rule.internal_prefix, rule.prefix_words)
            {
                // RFC 6296 §3.2 says to discard a non-neutral internal /48
                // subnet of 0xFFFF because it has no one-to-one mapping
                // (the section does not use RFC2119 MUST language). A neutral
                // pair is a pure prefix swap, so 0xFFFF remains representable
                // there (#3233). §3.7's all-zero IID discard is an explicit
                // MUST; the all-ones edge is the scoped reviewer reading.
                if (rule.prefix_words == 3
                    && words[3] == 0xFFFF
                    && !is_zero_adjustment(rule.adjustment))
                    || iid_is_all_zero(&words, rule.prefix_words)
                {
                    return Nptv6Translation::Untranslatable;
                }
                let adj_word = match first_non_ffff_iid_word(&words, rule.prefix_words) {
                    Some(index) => index,
                    None => return Nptv6Translation::Untranslatable,
                };
                // Rewrite prefix words to external prefix.
                for i in 0..rule.prefix_words {
                    words[i] = rule.external_prefix[i];
                }
                // Adjust the selected word after the prefix: outbound uses
                // `adjustment` directly. #3233 skips the fixup for a neutral
                // pair, whose prefix swap is already checksum-neutral.
                if !is_zero_adjustment(rule.adjustment) {
                    words[adj_word] = adjust_word(words[adj_word], rule.adjustment);
                }
                *src = words_to_ipv6(&words);
                return Nptv6Translation::Translated;
            }
        }
        Nptv6Translation::NoMatch
    }

    /// Returns true if there are any NPTv6 rules configured.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn is_empty(&self) -> bool {
        self.inbound.is_empty()
    }

    /// Returns all external prefixes as (prefix_addr, prefix_len) pairs.
    #[allow(dead_code)]
    pub(crate) fn external_prefixes(&self) -> Vec<(Ipv6Addr, u8)> {
        self.inbound
            .iter()
            .map(|rule| {
                let mut words = [0u16; 8];
                for i in 0..rule.prefix_words {
                    words[i] = rule.external_prefix[i];
                }
                let prefix_len = (rule.prefix_words * 16) as u8;
                (words_to_ipv6(&words), prefix_len)
            })
            .collect()
    }
}

/// Check if the first `prefix_words` 16-bit words of `addr_words` match `prefix`.
#[inline]
fn prefix_matches(addr_words: &[u16; 8], prefix: &[u16; 4], prefix_words: usize) -> bool {
    for i in 0..prefix_words {
        if addr_words[i] != prefix[i] {
            return false;
        }
    }
    true
}

/// #2241: returns the name of an already-seen rule whose prefix OVERLAPS the
/// candidate prefix, or `None` if there is no overlap. Two prefixes overlap
/// when one is a prefix of the other — i.e. their first `min(words_a, words_b)`
/// 16-bit words are equal. This covers identical /48-/48, identical /64-/64, and
/// a /48 nesting a /64 (the case that makes first-match resolution
/// order-dependent). Each direction (internal for outbound, external for
/// inbound) is checked independently by the caller.
///
/// #5176: an overlap is only order-dependent when the two rules' `from_zone`
/// scopes can BOTH match a single packet — [`zones_conflict`]. A same-prefix
/// pair scoped to two different non-empty zones is legitimate per-zone
/// split-horizon (no packet matches both), so it is NOT reported as an overlap.
fn find_overlap(
    seen: &[([u16; 4], usize, String, String)],
    candidate: &[u16; 4],
    candidate_words: usize,
    candidate_zone: &str,
) -> Option<String> {
    for (prefix, words, name, from_zone) in seen {
        let common = candidate_words.min(*words);
        if candidate[..common] == prefix[..common]
            && zones_conflict(candidate_zone, from_zone)
        {
            return Some(name.clone());
        }
    }
    None
}

/// #5176: can two static-NAT `from_zone` scopes both match a single packet? A
/// packet carries exactly one relevant zone, so two rules conflict only when
/// either scope is a wildcard (empty) or both name the same zone. Two distinct
/// non-empty zones are disjoint — legitimate split-horizon.
///
/// #4339 fail-closed note: the `a == b` arm also rejects a degenerate
/// same-name/same-prefix duplicate that a Go scope-expansion (#4339) could emit
/// lowering to the SAME zone — there is no name-identity skip. That is a
/// fail-CLOSED config rejection (the snapshot is dropped and the previous live
/// state kept), never a translation bypass.
#[inline]
fn zones_conflict(a: &str, b: &str) -> bool {
    a.is_empty() || b.is_empty() || a == b
}

#[cfg(test)]
#[path = "nptv6_tests.rs"]
mod tests;

