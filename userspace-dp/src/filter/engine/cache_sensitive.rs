// Cache-sensitive evaluation helpers extracted from engine.rs by #1546. Bodies
// byte-identical with the pre-split versions; `term_matches*` invocations route
// through `super::matching::*`.
//
// Module responsibility (#6237 split): this parent holds the two products of the
// same seed/replay descriptor workflow —
//   1. the cached/snapshot TX-selection rebuild path (flow-cache hit fast path);
//   2. the input `then count` descriptor capture replayed on cache hits.
// The cold filter-rotation semantic-comparison domain (the structural-equality
// predicates that decide when cached decisions must be INVALIDATED on a config
// rotation) lives in the `rotation` submodule and is re-exported below so the
// engine/mod.rs surface and all consumers stay untouched. Splitting rotation out
// is safe because the #5293 compile-time exhaustive FilterTerm destructure (now
// in rotation.rs) — not file co-location — is the anti-drift guard that replaced
// the original #1546 "keep the predicates and the rebuild path in one file"
// motivation.

use super::super::*;
use super::eval::filter_log_match;
use super::matching::{term_matches_v4, term_matches_v6};

mod rotation;

pub(crate) use rotation::{
    input_dscp_filter_families_changed, input_per_packet_l4_filter_families_changed,
    interface_input_filter_has_dscp_match, interface_input_filter_has_per_packet_l4_match,
    interface_input_filter_varies_per_packet, interface_output_filter_has_dscp_match,
    interface_output_filter_has_per_packet_l4_match,
};

pub(crate) fn evaluate_filter_ref_tx_selection_cached(
    filter: &Filter,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    protocol: u8,
    src_port: u16,
    dst_port: u16,
    dscp: u8,
) -> CachedTxSelectionFilterResult {
    match (src_ip, dst_ip) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => evaluate_filter_ref_tx_selection_cached_v4(
            filter, src, dst, protocol, src_port, dst_port, dscp, false,
        ),
        (IpAddr::V6(src), IpAddr::V6(dst)) => evaluate_filter_ref_tx_selection_cached_v6(
            filter, src, dst, protocol, src_port, dst_port, dscp, false,
        ),
        _ => CachedTxSelectionFilterResult::default(),
    }
}

fn evaluate_filter_ref_tx_selection_cached_v4(
    filter: &Filter,
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    protocol: u8,
    src_port: u16,
    dst_port: u16,
    dscp: u8,
    ports_unknown: bool,
) -> CachedTxSelectionFilterResult {
    // #2544: accumulate modifiers across fall-through terms; return on the first
    // terminating matched term. See merge_matched_cached_modifiers.
    let mut acc = CachedTxSelectionFilterResult::default();
    for term in &filter.terms {
        if !term_matches_v4(
            term,
            src_ip,
            dst_ip,
            protocol,
            src_port,
            dst_port,
            dscp,
            TermMatchExtra {
                ports_unknown,
                ..Default::default()
            },
        ) {
            continue;
        }
        merge_matched_cached_modifiers(&mut acc, filter, term);
        if !term.continue_term {
            acc.action = term.action;
            return acc;
        }
    }
    acc
}

/// #2544: merge a matched term's modifiers into the cached TX-selection result.
/// Used for both fall-through and terminating matches. Latest matched term wins
/// for forwarding-class, dscp-rewrite, and log; three-color policers AND
/// `then count` term counters accumulate so a counter/policer on every matched
/// term still records on the cached rebuild path. The action is set only by the
/// caller for a terminating term.
///
/// #2573: `counters` accumulates EVERY matched `then count` term (deduped by
/// counter identity), not just the last. With #2544 fall-through a single packet
/// can match multiple `then count` terms; the old single-Arc slot kept only the
/// last, so the earlier fall-through count terms were silently under-counted on
/// the cached replay path while the uncached full-eval path counted each.
#[inline]
fn merge_matched_cached_modifiers(
    acc: &mut CachedTxSelectionFilterResult,
    filter: &Filter,
    term: &FilterTerm,
) {
    if !term.forwarding_class.is_empty() {
        acc.forwarding_class = Some(term.forwarding_class.clone());
    }
    if term.dscp_rewrite.is_some() {
        acc.dscp_rewrite = term.dscp_rewrite;
    }
    if term.has_count {
        acc.counters.push(term.counter.clone());
    }
    acc.three_color_policers
        .extend(CachedThreeColorPolicers::from_option(
            term.three_color_policer.clone(),
        ));
    if let Some(lm) = filter_log_match(filter, term) {
        acc.log_match = Some(lm);
    }
}

fn evaluate_filter_ref_tx_selection_cached_v6(
    filter: &Filter,
    src_ip: Ipv6Addr,
    dst_ip: Ipv6Addr,
    protocol: u8,
    src_port: u16,
    dst_port: u16,
    dscp: u8,
    ports_unknown: bool,
) -> CachedTxSelectionFilterResult {
    // #2544: see evaluate_filter_ref_tx_selection_cached_v4.
    let mut acc = CachedTxSelectionFilterResult::default();
    for term in &filter.terms {
        if !term_matches_v6(
            term,
            src_ip,
            dst_ip,
            protocol,
            src_port,
            dst_port,
            dscp,
            TermMatchExtra {
                ports_unknown,
                ..Default::default()
            },
        ) {
            continue;
        }
        merge_matched_cached_modifiers(&mut acc, filter, term);
        if !term.continue_term {
            acc.action = term.action;
            return acc;
        }
    }
    acc
}

/// #3777: capture the interface INPUT filter `then count` term handles matched
/// by an established (cacheable) flow's 5-tuple, for replay on every flow-cache
/// HIT. Output/TX `then count` terms are already replayed on the cached path
/// (#2573 via [`evaluate_filter_ref_tx_selection_cached`]); INPUT `then count`
/// terms were not, so an interface input filter with `then count` reported only
/// the seed (first) packet of an N-packet cacheable flow.
///
/// The walk mirrors the `Always`-policy walk of
/// `evaluate_filter_ref_non_routing_counted` (the non-PBR / session-HIT
/// per-packet counter): it captures every matched non-routing `then count` term
/// up to AND INCLUDING the terminal action term, and DEFERS at a matched
/// routing-instance (PBR) term — returning the counters accumulated before it —
/// so the PBR term's counter stays owned by the routing-instance evaluator
/// (which counts it on the session-miss packet). This preserves the #2620
/// `NonRoutingCountPolicy` count-ownership split on the cached path (a naive
/// "capture every matched term" walk would double/under-count a filter that
/// mixes routing-affecting and count terms).
///
/// This only COLLECTS `Arc<FilterTermCounter>` handles; it never calls
/// `record_filter_counter`. The seed path charges the handles exactly once —
/// the cold evaluator for a miss, or the insert arm for an uncounted
/// established-hit ACCEPT. Cache-declined DSCP / per-packet-L4 input filters
/// never reach a cached flow, so their matched set is irrelevant to seeding;
/// `TermMatchExtra::default()` remains the capture convention.
pub(crate) fn evaluate_interface_input_filter_counters_cached(
    state: &FilterState,
    ifindex: i32,
    is_v6: bool,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    protocol: u8,
    src_port: u16,
    dst_port: u16,
    dscp: u8,
) -> CachedFilterCounters {
    let filter = if is_v6 {
        state.iface_filter_v6_fast.get(&ifindex).map(Arc::as_ref)
    } else {
        state.iface_filter_v4_fast.get(&ifindex).map(Arc::as_ref)
    };
    let Some(filter) = filter else {
        return CachedFilterCounters::default();
    };
    // Common case: no `then count` term on this input filter — skip the walk.
    if !filter.has_counter_terms {
        return CachedFilterCounters::default();
    }
    match (src_ip, dst_ip) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => {
            capture_input_filter_counters_v4(filter, src, dst, protocol, src_port, dst_port, dscp)
        }
        (IpAddr::V6(src), IpAddr::V6(dst)) => {
            capture_input_filter_counters_v6(filter, src, dst, protocol, src_port, dst_port, dscp)
        }
        _ => CachedFilterCounters::default(),
    }
}

#[inline]
fn capture_input_filter_counters_v4(
    filter: &Filter,
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    protocol: u8,
    src_port: u16,
    dst_port: u16,
    dscp: u8,
) -> CachedFilterCounters {
    let mut counters = CachedFilterCounters::default();
    for term in &filter.terms {
        if !term_matches_v4(
            term,
            src_ip,
            dst_ip,
            protocol,
            src_port,
            dst_port,
            dscp,
            TermMatchExtra::default(),
        ) {
            continue;
        }
        // A matched routing-instance (PBR) term defers to the routing-instance
        // evaluator — mirror evaluate_filter_ref_non_routing_counted's early
        // return so the PBR term's count is not re-attributed to the cached
        // input replay (#2620 ownership).
        if !term.routing_instance.is_empty() {
            return counters;
        }
        if term.has_count {
            counters.push(term.counter.clone());
        }
        if !term.continue_term {
            return counters;
        }
    }
    counters
}
/// #7992: the cache-replay evaluator for a caller that has NO PORTS AT ALL.
///
/// It takes no port arguments, which is the point: the FLOWLESS arm of
/// `resolve_cached_cos_tx_selection_impl` used to call the ported entry point
/// with literal `0, 0`, and literal zero is not "no port" — it is a port value
/// that a term can match on. `destination-port-except 22` matches everything
/// that is not 22, and 0 is not 22, so the exception matched and an egress
/// `then discard` fired on a packet whose real port was excepted (#7174 C19,
/// second reachability path).
///
/// The arm's own comment argued this was safe because "a port-BEARING term never
/// matches (no spurious drop)". That is true of `from destination-port 22` and
/// FALSE of the except form — a claim correct for the case its author had in
/// mind that silently generalised to the case where it inverts.
///
/// Removing the parameters rather than passing a flag is deliberate: it makes
/// the defect unrepresentable at this call site instead of relying on the next
/// caller to pass the right bool.
pub(crate) fn evaluate_filter_ref_tx_selection_cached_portless(
    filter: &Filter,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    protocol: u8,
    dscp: u8,
) -> CachedTxSelectionFilterResult {
    match (src_ip, dst_ip) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => {
            evaluate_filter_ref_tx_selection_cached_v4(filter, src, dst, protocol, 0, 0, dscp, true)
        }
        (IpAddr::V6(src), IpAddr::V6(dst)) => {
            evaluate_filter_ref_tx_selection_cached_v6(filter, src, dst, protocol, 0, 0, dscp, true)
        }
        _ => CachedTxSelectionFilterResult::default(),
    }
}


#[inline]
fn capture_input_filter_counters_v6(
    filter: &Filter,
    src_ip: Ipv6Addr,
    dst_ip: Ipv6Addr,
    protocol: u8,
    src_port: u16,
    dst_port: u16,
    dscp: u8,
) -> CachedFilterCounters {
    let mut counters = CachedFilterCounters::default();
    for term in &filter.terms {
        if !term_matches_v6(
            term,
            src_ip,
            dst_ip,
            protocol,
            src_port,
            dst_port,
            dscp,
            TermMatchExtra::default(),
        ) {
            continue;
        }
        if !term.routing_instance.is_empty() {
            return counters;
        }
        if term.has_count {
            counters.push(term.counter.clone());
        }
        if !term.continue_term {
            return counters;
        }
    }
    counters
}
