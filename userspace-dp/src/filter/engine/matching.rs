// Per-term match predicates extracted from engine.rs by #1546. The hot
// per-packet path keeps #[inline(always)] so it folds through
// `cargo build --release`.
//
// #2362 added the per-packet L4 match conditions (tcp-flags, is-fragment,
// icmp-type, icmp-code). They are carried in `TermMatchExtra`, computed once
// per packet at the evaluate call site, and applied via `per_packet_l4_matches`
// after the 5-tuple checks. They are family-agnostic, so the v4/v6 leaves share
// the same helper.

use super::super::*;
use crate::ip_proto::{PROTO_ICMP, PROTO_ICMPV6, PROTO_TCP};

/// Apply the #2362 per-packet L4 match conditions. Returns `false` (no match)
/// if any configured condition fails. A condition that constrains a protocol
/// the packet is not (e.g. a tcp-flags term against a UDP packet, or an
/// icmp-type term against a TCP packet) fails closed — the term must NOT match,
/// matching Junos semantics where `from tcp-flags ...` implies the TCP
/// protocol family. Empty (`None` / false) conditions are no-ops.
///
/// #2362 fold A (Copilot): every L4-header-derived constraint (tcp-flags,
/// icmp-type, icmp-code) additionally requires `extra.l4_present`. A NON-FIRST
/// fragment carries no L4 header at `l4_offset` (its bytes are payload), so
/// `l4_present` is false for it and those terms MUST NOT match. Keying off the
/// byte VALUE alone is insufficient: 0 is a valid icmp-type (echo-reply) and a
/// valid icmp-code, so a zeroed byte on a non-first fragment would still
/// spuriously match `from { icmp-type 0 }` / `from { icmp-code 0 }`. The
/// `is-fragment` constraint is L3-derived (every fragment carries the IP
/// header) and is therefore NOT gated by `l4_present` — a non-first fragment
/// still matches `from { is-fragment }`.
#[inline(always)]
fn per_packet_l4_matches(term: &FilterTerm, protocol: u8, extra: TermMatchExtra<'_>) -> bool {
    if term.tcp_flags_mask.is_some() || term.tcp_flags_forbidden.is_some() {
        // A tcp-flags constraint (required and/or forbidden, #3076) only matches
        // a TCP segment that actually has an L4 header. A non-TCP packet, or a
        // non-first fragment (no L4 header), never matches.
        if !extra.l4_present || protocol != PROTO_TCP {
            return false;
        }
        // Required bits: all must be set — (flags & required) == required.
        if let Some(required) = term.tcp_flags_mask {
            if (extra.tcp_flags & required) != required {
                return false;
            }
        }
        // Forbidden bits: none may be set — (flags & forbidden) == 0. This is
        // the negated half of an expression like `syn & !ack`; without it the
        // `!ack` constraint was silently dropped and the term matched regardless
        // of the ACK bit (the pre-#3076 fail-open).
        if let Some(forbidden) = term.tcp_flags_forbidden {
            if (extra.tcp_flags & forbidden) != 0 {
                return false;
            }
        }
    }
    if term.is_fragment && !extra.is_fragment {
        return false;
    }
    let is_icmp = protocol == PROTO_ICMP || protocol == PROTO_ICMPV6;
    if term.icmp_type_match_enabled {
        // #2545: SET membership (match-ANY). Gate on l4_present, NOT just the
        // value: icmp-type 0 (echo-reply) is a real term, so a non-first
        // fragment with a forced-0 type byte must NOT match it. A non-ICMP
        // packet never matches a term constraining icmp-type.
        let t = extra.icmp_type;
        let in_set = (term.icmp_type_bitmap[(t / 64) as usize] & (1u64 << (t % 64))) != 0;
        if !extra.l4_present || !is_icmp || !in_set {
            return false;
        }
    }
    if term.icmp_code_match_enabled {
        // icmp-code 0 is the most common code — same l4_present gate.
        let c = extra.icmp_code;
        let in_set = (term.icmp_code_bitmap[(c / 64) as usize] & (1u64 << (c % 64))) != 0;
        if !extra.l4_present || !is_icmp || !in_set {
            return false;
        }
    }
    // #3077 flexible-match-range: a byte-offset match against the L3 header
    // (match-start layer-3) or, since #3232, the L4 header (match-start
    // layer-4). The base slice is selected by the term's `flex_match_start`.
    if !flex_matches(term, extra.flex_l3, extra.flex_l4) {
        return false;
    }
    true
}

/// #3077/#3232: evaluate a term's flexible-match-range byte-offset condition. A
/// term without the constraint (`flex_enabled == false`) is a no-op (returns
/// true). Otherwise the match reads `flex_length` bytes (compiler-bounded to
/// 1..=4) at `flex_offset` from the START of the base header selected by the
/// term's `flex_match_start`:
///   - `Layer3` (match-start layer-3, the #3077 default): from `flex_l3`, the
///     start of the L3/IP header.
///   - `Layer4` (match-start layer-4, #3232): from `flex_l4`, the start of the
///     L4/transport header (`meta.l4_offset`).
///   - `Unsupported` (an unrecognized match-start, e.g. `payload`, that slipped
///     past the Go commit gate on the tolerant peer-sync path): always FALSE —
///     fail closed rather than evaluate at the wrong base.
/// The chosen bytes are assembled big-endian (network order) into a u32, ANDed
/// with `flex_mask`, and required to equal `flex_value` (pre-masked).
///
/// FAIL-CLOSED contract (the #3077 fix, extended by #3232): the term matches
/// ONLY when the window fully lies within the available base bytes. If the base
/// slice is `None` (no frame on this path; or, for layer-4, a non-first fragment
/// or meta-only path with no L4 header) or the packet is too short to hold
/// `offset + length` bytes, the condition is FALSE — the term does not match.
/// This is the opposite of the pre-#3077 behavior, where the constraint was
/// dropped on the wire and the term matched every packet (fail-open), and of the
/// pre-#3232 behavior, where a layer-4/payload match was silently evaluated at
/// the L3 base (wrong-offset match). Bounds are checked before indexing, so a
/// truncated/short packet can never read out of bounds or panic.
#[inline(always)]
fn flex_matches(term: &FilterTerm, flex_l3: Option<&[u8]>, flex_l4: Option<&[u8]>) -> bool {
    if !term.flex_enabled {
        return true;
    }
    let len = term.flex_length as usize;
    // The compiler only enables flex for len in 1..=4, but re-check so a stray
    // value can never under/over-read; a bad length fails closed.
    if !(1..=4).contains(&len) {
        return false;
    }
    // #3232: select the base slice for the configured match-start. An
    // unsupported start (e.g. payload, on the tolerant peer-sync path) fails
    // closed — never evaluated at the wrong base.
    let base = match term.flex_match_start {
        FlexMatchStart::Layer3 => flex_l3,
        FlexMatchStart::Layer4 => flex_l4,
        FlexMatchStart::Unsupported => return false,
    };
    let Some(bytes) = base else {
        // No base bytes on this path — cannot evaluate the constraint, so it
        // must NOT match (fail closed), never silently pass.
        return false;
    };
    let off = term.flex_offset as usize;
    let Some(end) = off.checked_add(len) else {
        return false;
    };
    if end > bytes.len() {
        // Packet too short to reach the match window — fail closed.
        return false;
    }
    let mut val: u32 = 0;
    for &b in &bytes[off..end] {
        val = (val << 8) | u32::from(b);
    }
    (val & term.flex_mask) == term.flex_value
}

/// Check whether a single filter term matches the given packet fields.
/// All specified criteria must match (AND logic). Empty criteria = match any.
#[inline(always)]
pub(super) fn term_matches(
    term: &FilterTerm,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    protocol: u8,
    src_port: u16,
    dst_port: u16,
    dscp: u8,
    extra: TermMatchExtra<'_>,
) -> bool {
    match (src_ip, dst_ip) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => {
            term_matches_v4(term, src, dst, protocol, src_port, dst_port, dscp, extra)
        }
        (IpAddr::V6(src), IpAddr::V6(dst)) => {
            term_matches_v6(term, src, dst, protocol, src_port, dst_port, dscp, extra)
        }
        _ => false,
    }
}
/// The XDP shim uses 255 when a fragment has no usable L4 header. It means
/// "unknown protocol", not protocol 255, so protocol-constrained terms match
/// it without recovering a value from fragment payload bytes.
#[inline(always)]
fn protocol_bitmap_matches(term: &FilterTerm, protocol: u8) -> bool {
    !term.protocol_match_enabled
        || protocol == crate::session::SHIM_PROTO_FRAGMENT_NO_L4
        || (term.protocol_bitmap[(protocol / 64) as usize] & (1u64 << (protocol % 64))) != 0
}


#[inline(always)]
#[allow(clippy::too_many_arguments)]
pub(super) fn term_matches_v4(
    term: &FilterTerm,
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    protocol: u8,
    src_port: u16,
    dst_port: u16,
    dscp: u8,
    extra: TermMatchExtra<'_>,
) -> bool {
    if !protocol_bitmap_matches(term, protocol) {
        return false;
    }
    if !nets_match_v4(
        term.source_addr_constrained,
        term.source_except,
        &term.source_v4,
        src_ip,
    ) {
        return false;
    }
    if !nets_match_v4(
        term.dest_addr_constrained,
        term.dest_except,
        &term.dest_v4,
        dst_ip,
    ) {
        return false;
    }
    if !port_terms_match(term, extra, src_port, dst_port) {
        return false;
    }
    if term.dscp_match_enabled && (term.dscp_bitmap & (1u64 << dscp)) == 0 {
        return false;
    }
    if !per_packet_l4_matches(term, protocol, extra) {
        return false;
    }
    true
}

/// #2400 (032-18) + #2506: match a v4 IP against a filter term's address set.
///
/// - `constrained == false` (the term wrote no source/dest scope — no literal
///   address and no prefix-list ref): match any IP — unchanged unscoped
///   behavior. `except` is irrelevant: there is no scope to invert.
/// - `constrained == true` but `nets` empty for THIS family: the operator wrote
///   a scope that yielded no prefixes for this family. Return `except` — the
///   Junos empty-set semantic:
///     * positive (`except == false`): "match addresses in {}" = match NOTHING
///       (fail closed). This is the #2400 all-malformed / #2506 empty-positive
///       (defined-empty or lenient-unresolved prefix-list) case — never the
///       pre-#2400 collapse to match-any.
///     * `except == true`: "match addresses NOT in {}" = match ALL. This also
///       gives the correct CROSS-FAMILY answer: a v4-only `... except` list has
///       an empty v6 vec, and a v6 source is trivially "not in" a v4 list, so a
///       v6 packet matches the except term (the v4 list does not constrain v6).
///   The `constrained` input is derived in the compiler from the EXPLICIT
///   `source_constrained` / `destination_constrained` snapshot flag (OR'd with
///   the address-length test), so an empty-resolving prefix-list still counts as
///   constrained and does not fall through to the `!constrained` match-any arm.
/// - otherwise: membership XOR `except`. `except == false` is the plain
///   `addr ∈ prefixes`; `except == true` is "match every address NOT in the
///   set".
///
/// Mirrors `nat::source::nets_match_v4` (#2398).
#[inline(always)]
fn nets_match_v4(constrained: bool, except: bool, nets: &[PrefixV4], ip: Ipv4Addr) -> bool {
    if !constrained {
        return true;
    }
    if nets.is_empty() {
        return except;
    }
    nets.iter().any(|net| net.contains(ip)) ^ except
}

/// #2400 (032-18) + #2506: v6 sibling of `nets_match_v4` (same empty-set and
/// `except` inversion semantics).
#[inline(always)]
fn nets_match_v6(constrained: bool, except: bool, nets: &[PrefixV6], ip: Ipv6Addr) -> bool {
    if !constrained {
        return true;
    }
    if nets.is_empty() {
        return except;
    }
    nets.iter().any(|net| net.contains(ip)) ^ except
}

/// #2400 (032-19) + #2622: match a port against a filter term's port matcher
/// with fail-closed semantics for an all-malformed list, and optional `except`
/// inversion for the negated `source-port-except` / `destination-port-except`
/// match.
///
/// - `constrained == false` (the term carried no real port spec): the matcher
///   is `PortMatcher::Any` and matches any port — unchanged unscoped behavior.
///   `except` is irrelevant: there is no port scope to invert.
/// - `constrained == true` but the matcher is `PortMatcher::Any` (every
///   configured port spec was a non-empty token that FAILED to parse, leaving
///   zero ranges): FAIL CLOSED in BOTH directions — `#3205` (agy-070 #08).
///   Unlike the address path, a port scope has no prefix-list indirection: a
///   real listed port (numeric or a resolved service name) always yields a
///   range, so `constrained && Any` can ONLY mean every token was unparseable
///   (e.g. an unresolved symbolic port name). A positive match returns NOTHING
///   (#2400); an `except` match must NOT invert empty into match-ALL — that was
///   the fail-OPEN hole where `destination-port-except domain` accepted every
///   port including the one meant to be excluded. The Go commit gate
///   (validateFilterMatchValuesStrict) now rejects such a term, so this is
///   defense-in-depth on the tolerant load / peer-sync path. (The Junos
///   "empty-except = match all" semantic still applies to the ADDRESS path —
///   `nets_match_v4`/`nets_match_v6` — where an empty prefix-list scope is
///   reachable and legitimate.)
/// - otherwise: `matcher.matches(port) XOR except`. `except == false` is the
///   plain positive membership; `except == true` matches every port NOT in the
///   set.
#[inline(always)]
/// #7174 (C19): a port constraint must not be evaluated against the SYNTHETIC
/// ports of a non-first fragment.
///
/// A non-first fragment carries no L4 header and its ports arrive as 0. Matching
/// that against a real `source-port` / `destination-port` term was already
/// dubious; against a `*-port-except` term it INVERTED the verdict, because
/// `port_match` is `matcher.matches(port) ^ except` — port 0 is not in the set,
/// so the `except` arm returned TRUE and the fragment spuriously MATCHED.
/// Concretely, `from destination-port-except 22; then discard;` discarded every
/// non-first fragment of a port-22 flow.
///
/// THE GATE IS `is_fragment && !l4_present`, NOT `!l4_present` ALONE, AND THAT
/// IS THE WHOLE DESIGN. `term_matches_v4/v6` is shared by two callers with
/// different contracts:
///
///   - the COLD path builds `TermMatchExtra` from a real packet, so
///     `l4_present` genuinely means "this packet has an L4 header";
///   - the FLOW-CACHE path (`filter/engine/cache_sensitive.rs`) evaluates real
///     cached flows with `TermMatchExtra::default()`, i.e. `l4_present: false`
///     unconditionally, because the ports it passes come from the flow's
///     5-tuple SessionKey and are real. `FilterTerm::has_per_packet_l4_match`
///     spells out why ports are not in the cache-sensitive set: those conditions
///     are the ones "not part of the 5-tuple SessionKey", and ports ARE part of
///     it.
///
/// So gating on `!l4_present` alone would stop every port-constrained term
/// matching on every cached flow — a large silent forwarding change. Measured:
/// it reds 11+ tests across `cos_classify`, `frame` and `tests_bind_forward`.
///
/// `is_fragment` discriminates because it is L3-derived and valid regardless of
/// `l4_present`: a non-first fragment carries `is_fragment: true, l4_present:
/// false`, while a cached flow carries `false, false`. That pair is the only
/// thing that separates "ports are synthetic" from "ports came from the key".
///
/// SCOPE: the `is_fragment && !l4_present` half fixes the fragment case. The
/// other L4-absent shapes evaluated on this path — flowless packets whose
/// ports are 0-substituted by construction (an L3-only enforcement context)
/// — carry `is_fragment: false` and are indistinguishable from a cached flow
/// BY THESE TWO FLAGS, so this half does not cover them. They ARE covered by
/// the `ports_unknown` half instead (#9894): the flowless input-filter/PBR
/// sites set it explicitly, which only they can do soundly — the cold
/// builder never sees the flow, so it cannot know whether the evaluated
/// ports are real (a cached tuple survives a DMA-mutated slice). That is the
/// measurement this paragraph used to defer.
fn port_terms_match(
    term: &FilterTerm,
    extra: TermMatchExtra<'_>,
    src_port: u16,
    dst_port: u16,
) -> bool {
    if (term.source_port_constrained || term.dest_port_constrained)
        && ((extra.is_fragment && !extra.l4_present) || extra.ports_unknown)
    {
        return false;
    }
    port_match(
        term.source_port_constrained,
        term.source_port_except,
        &term.source_ports,
        src_port,
    ) && port_match(
        term.dest_port_constrained,
        term.dest_port_except,
        &term.dest_ports,
        dst_port,
    )
}

fn port_match(constrained: bool, except: bool, matcher: &PortMatcher, port: u16) -> bool {
    if constrained && matches!(matcher, PortMatcher::Any) {
        // Constrained but no range survived parsing (every token unparseable).
        // Fail CLOSED both ways: positive -> match nothing; except -> do NOT
        // invert empty into match-all (the #3205 fail-open).
        return false;
    }
    matcher.matches(port) ^ except
}

#[inline(always)]
#[allow(clippy::too_many_arguments)]
pub(super) fn term_matches_v6(
    term: &FilterTerm,
    src_ip: Ipv6Addr,
    dst_ip: Ipv6Addr,
    protocol: u8,
    src_port: u16,
    dst_port: u16,
    dscp: u8,
    extra: TermMatchExtra<'_>,
) -> bool {
    if !protocol_bitmap_matches(term, protocol) {
        return false;
    }
    if !nets_match_v6(
        term.source_addr_constrained,
        term.source_except,
        &term.source_v6,
        src_ip,
    ) {
        return false;
    }
    if !nets_match_v6(
        term.dest_addr_constrained,
        term.dest_except,
        &term.dest_v6,
        dst_ip,
    ) {
        return false;
    }
    if !port_terms_match(term, extra, src_port, dst_port) {
        return false;
    }
    if term.dscp_match_enabled && (term.dscp_bitmap & (1u64 << dscp)) == 0 {
        return false;
    }
    if !per_packet_l4_matches(term, protocol, extra) {
        return false;
    }
    true
}
