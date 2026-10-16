// TX-selection evaluation extracted from engine.rs by #1546.
// Bodies byte-identical with the pre-split versions; `term_matches*`
// invocations go through `super::matching::*` and policer application
// through `super::policer::apply_term_three_color_policer`.
//
// Hot path on the userspace-dp dataplane:
//   evaluate_filter_ref_tx_selection_counted_v{4,6}
//     -> term_matches_v{4,6}                (super::matching, inline(always))
//     -> apply_term_three_color_policer     (super::policer, inline)
//     -> TxSelectionFilterResult::default() | construct return
//
// `policer_action.dscp_rewrite.or(term.dscp_rewrite)` precedence is
// preserved exactly — policer-imposed rewrite wins over the term's
// configured rewrite.

use super::super::*;
use super::eval::filter_log_match;
use super::matching::{term_matches_v4, term_matches_v6};
use super::policer::apply_term_three_color_policer;

#[inline]
pub(crate) fn evaluate_filter_ref_tx_selection_counted<'a>(
    filter: &'a Filter,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    protocol: u8,
    src_port: u16,
    dst_port: u16,
    dscp: u8,
    extra: TermMatchExtra<'_>,
    packet_bytes: u64,
) -> TxSelectionFilterResult<'a> {
    evaluate_filter_ref_tx_selection_runtime(
        filter,
        src_ip,
        dst_ip,
        protocol,
        src_port,
        dst_port,
        dscp,
        extra,
        packet_bytes,
        None,
        true,
    )
}

/// #4085: TX-selection walk that extracts forwarding-class / dscp-rewrite /
/// three-color-policer modifiers but does NOT record `then count` term
/// counters. Used for the INGRESS input filter's tx-selection leg
/// (`resolve_cos_tx_selection_internal`) — that filter's `then count`
/// counters are already recorded once by the input-filter ACTION evaluation
/// (`evaluate_non_pbr_input_filter`, `poll_descriptor`), so a second increment
/// here double-counted every packet of a non-cacheable flow (and the seed
/// packet of a cacheable one). The three-color policer METER still runs (it is
/// metered nowhere else); only the counter increment is suppressed.
#[inline]
pub(crate) fn evaluate_filter_ref_tx_selection_uncounted<'a>(
    filter: &'a Filter,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    protocol: u8,
    src_port: u16,
    dst_port: u16,
    dscp: u8,
    extra: TermMatchExtra<'_>,
    packet_bytes: u64,
) -> TxSelectionFilterResult<'a> {
    evaluate_filter_ref_tx_selection_runtime(
        filter,
        src_ip,
        dst_ip,
        protocol,
        src_port,
        dst_port,
        dscp,
        extra,
        packet_bytes,
        None,
        false,
    )
}

pub(crate) fn evaluate_filter_ref_tx_selection_runtime_counted<'a>(
    filter: &'a Filter,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    protocol: u8,
    src_port: u16,
    dst_port: u16,
    dscp: u8,
    extra: TermMatchExtra<'_>,
    packet_bytes: u64,
    now_ns: u64,
) -> TxSelectionFilterResult<'a> {
    evaluate_filter_ref_tx_selection_runtime(
        filter,
        src_ip,
        dst_ip,
        protocol,
        src_port,
        dst_port,
        dscp,
        extra,
        packet_bytes,
        Some(now_ns),
        true,
    )
}

/// #4085: three-color-policer-metered but counter-suppressed sibling of
/// [`evaluate_filter_ref_tx_selection_runtime_counted`]. See
/// [`evaluate_filter_ref_tx_selection_uncounted`] for why the ingress leg must
/// not re-record `then count` — this variant threads `now_ns` so the ingress
/// three-color policer still meters, while suppressing the double count.
pub(crate) fn evaluate_filter_ref_tx_selection_runtime_uncounted<'a>(
    filter: &'a Filter,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    protocol: u8,
    src_port: u16,
    dst_port: u16,
    dscp: u8,
    extra: TermMatchExtra<'_>,
    packet_bytes: u64,
    now_ns: u64,
) -> TxSelectionFilterResult<'a> {
    evaluate_filter_ref_tx_selection_runtime(
        filter,
        src_ip,
        dst_ip,
        protocol,
        src_port,
        dst_port,
        dscp,
        extra,
        packet_bytes,
        Some(now_ns),
        false,
    )
}

#[inline]
#[allow(clippy::too_many_arguments)]
fn evaluate_filter_ref_tx_selection_runtime<'a>(
    filter: &'a Filter,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    protocol: u8,
    src_port: u16,
    dst_port: u16,
    dscp: u8,
    extra: TermMatchExtra<'_>,
    packet_bytes: u64,
    now_ns: Option<u64>,
    // #4085: when false, matched `then count` terms are NOT recorded (the
    // policer meter + fc/dscp/log modifiers still apply). The ingress
    // tx-selection leg passes false — the input-filter action-eval owns that
    // count.
    count_terms: bool,
) -> TxSelectionFilterResult<'a> {
    evaluate_filter_ref_tx_selection_runtime_bearing(
        filter,
        src_ip,
        dst_ip,
        protocol,
        src_port,
        dst_port,
        dscp,
        extra,
        packet_bytes,
        now_ns,
        count_terms,
        false,
    )
}

#[inline]
#[allow(clippy::too_many_arguments)]
fn evaluate_filter_ref_tx_selection_runtime_bearing<'a>(
    filter: &'a Filter,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    protocol: u8,
    src_port: u16,
    dst_port: u16,
    dscp: u8,
    extra: TermMatchExtra<'_>,
    packet_bytes: u64,
    now_ns: Option<u64>,
    count_terms: bool,
    // #14120: when true, a matched routing-instance term does NOT stop the
    // walk (its policer still meters); when false the walk defers there,
    // mirroring the non-routing evaluator.
    routing_bearing: bool,
) -> TxSelectionFilterResult<'a> {
    match (src_ip, dst_ip) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => evaluate_filter_ref_tx_selection_counted_v4(
            filter,
            src,
            dst,
            protocol,
            src_port,
            dst_port,
            dscp,
            extra,
            packet_bytes,
            now_ns,
            count_terms,
            routing_bearing,
        ),
        (IpAddr::V6(src), IpAddr::V6(dst)) => evaluate_filter_ref_tx_selection_counted_v6(
            filter,
            src,
            dst,
            protocol,
            src_port,
            dst_port,
            dscp,
            extra,
            packet_bytes,
            now_ns,
            count_terms,
            routing_bearing,
        ),
        _ => TxSelectionFilterResult::default(),
    }
}

#[inline]
#[allow(clippy::too_many_arguments)]
fn evaluate_filter_ref_tx_selection_counted_v4<'a>(
    filter: &'a Filter,
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    protocol: u8,
    src_port: u16,
    dst_port: u16,
    dscp: u8,
    extra: TermMatchExtra<'_>,
    packet_bytes: u64,
    now_ns: Option<u64>,
    count_terms: bool,
    routing_bearing: bool,
) -> TxSelectionFilterResult<'a> {
    // #2544: accumulate modifiers across fall-through terms (forwarding-class,
    // dscp-rewrite, policer metering + drop, log). A matched fall-through term
    // applies its modifiers and continues; a matched terminating term applies
    // its action+modifiers and returns. The policer meter is a side effect that
    // must run for a fall-through term too, so it is invoked on every match.
    let mut acc = TxSelectionFilterResult::default();
    for term in &filter.terms {
        if !term_matches_v4(
            term, src_ip, dst_ip, protocol, src_port, dst_port, dscp, extra,
        ) {
            continue;
        }
        // #4085: skip the counter on the ingress tx-selection leg (count_terms
        // == false) — the input-filter action-eval already recorded it once.
        if count_terms && term.has_count {
            record_filter_counter(&term.counter, packet_bytes);
        }
        if !routing_bearing && !term.routing_instance.is_empty() {
            return acc;
        }
        merge_matched_tx_modifiers(&mut acc, filter, term, now_ns, packet_bytes);
        if !term.continue_term {
            acc.action = term.action;
            return acc;
        }
    }
    acc
}

/// #2544: merge a matched term's TX-selection modifiers into the running result.
/// Invokes the three-color policer meter (a side effect that must run on every
/// matched term, fall-through or terminating) and folds forwarding-class,
/// dscp-rewrite, policer drop, and the log diagnostic. Latest matched term wins
/// for forwarding-class and dscp-rewrite; `policer_drop` is OR'd so any matched
/// term whose policer drops the packet forces the drop. The
/// `policer_action.dscp_rewrite.or(term.dscp_rewrite)` precedence (policer wins
/// over the term's configured rewrite) is preserved per matched term. The action
/// is set only by the caller for a terminating term.
#[inline]
fn merge_matched_tx_modifiers<'a>(
    acc: &mut TxSelectionFilterResult<'a>,
    filter: &'a Filter,
    term: &'a FilterTerm,
    now_ns: Option<u64>,
    packet_bytes: u64,
) {
    let policer_action = apply_term_three_color_policer(term, now_ns, packet_bytes);
    if !term.forwarding_class.is_empty() {
        acc.forwarding_class = Some(term.forwarding_class.as_ref());
    }
    if let Some(rewrite) = policer_action.dscp_rewrite.or(term.dscp_rewrite) {
        acc.dscp_rewrite = Some(rewrite);
    }
    acc.policer_drop |= policer_action.drop;
    if let Some(lm) = filter_log_match(filter, term) {
        acc.log_match = Some(lm);
    }
}

#[inline]
#[allow(clippy::too_many_arguments)]
fn evaluate_filter_ref_tx_selection_counted_v6<'a>(
    filter: &'a Filter,
    src_ip: Ipv6Addr,
    dst_ip: Ipv6Addr,
    protocol: u8,
    src_port: u16,
    dst_port: u16,
    dscp: u8,
    extra: TermMatchExtra<'_>,
    packet_bytes: u64,
    now_ns: Option<u64>,
    count_terms: bool,
    routing_bearing: bool,
) -> TxSelectionFilterResult<'a> {
    // #2544: see evaluate_filter_ref_tx_selection_counted_v4.
    let mut acc = TxSelectionFilterResult::default();
    for term in &filter.terms {
        if !term_matches_v6(
            term, src_ip, dst_ip, protocol, src_port, dst_port, dscp, extra,
        ) {
            continue;
        }
        // #4085: skip the counter on the ingress tx-selection leg (count_terms
        // == false) — the input-filter action-eval already recorded it once.
        if count_terms && term.has_count {
            record_filter_counter(&term.counter, packet_bytes);
        }
        if !routing_bearing && !term.routing_instance.is_empty() {
            return acc;
        }
        merge_matched_tx_modifiers(&mut acc, filter, term, now_ns, packet_bytes);
        if !term.continue_term {
            acc.action = term.action;
            return acc;
        }
    }
    acc
}

/// #14120: routing-bearing TX-selection walk — like
/// [`evaluate_filter_ref_tx_selection_runtime_uncounted`] (counter-suppressed,
/// policer-metered) but does NOT stop at a matched routing-instance term: the
/// non-routing walk defers there, so without this walk a policer on or after
/// such a term would meter nowhere on the host-bound / Stage-11 paths. The
/// caller owns the PBR verdict separately; only the meter (and the folded
/// drop) is consumed from the result.
/// #14120: the uncounted TX-selection walk with its DEFER-AT-PBR-TERM
/// behavior exposed: `false` (transit) stops before a routing-instance term
/// so the routing evaluator owns that term's policer; `true` (host-bound /
/// Stage-11 remainder) meters through it, because no routing evaluator's
/// TX-selection leg follows on those paths.
#[inline]
pub(crate) fn evaluate_filter_ref_tx_selection_runtime_uncounted_bearing<'a>(
    filter: &'a Filter,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    protocol: u8,
    src_port: u16,
    dst_port: u16,
    dscp: u8,
    extra: TermMatchExtra<'_>,
    packet_bytes: u64,
    now_ns: u64,
    routing_bearing: bool,
) -> TxSelectionFilterResult<'a> {
    evaluate_filter_ref_tx_selection_runtime_bearing(
        filter,
        src_ip,
        dst_ip,
        protocol,
        src_port,
        dst_port,
        dscp,
        extra,
        packet_bytes,
        Some(now_ns),
        false,
        routing_bearing,
    )
}

#[inline]
pub(crate) fn evaluate_filter_ref_tx_selection_runtime_routing_bearing<'a>(
    filter: &'a Filter,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    protocol: u8,
    src_port: u16,
    dst_port: u16,
    dscp: u8,
    extra: TermMatchExtra<'_>,
    packet_bytes: u64,
    now_ns: u64,
) -> TxSelectionFilterResult<'a> {
    evaluate_filter_ref_tx_selection_runtime_bearing(
        filter,
        src_ip,
        dst_ip,
        protocol,
        src_port,
        dst_port,
        dscp,
        extra,
        packet_bytes,
        Some(now_ns),
        false,
        true,
    )
}

pub(crate) fn evaluate_interface_filter_tx_selection_counted<'a>(
    state: &'a FilterState,
    ifindex: i32,
    is_v6: bool,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    protocol: u8,
    src_port: u16,
    dst_port: u16,
    dscp: u8,
    extra: TermMatchExtra<'_>,
    packet_bytes: u64,
) -> TxSelectionFilterResult<'a> {
    let filter = if is_v6 {
        state.iface_filter_v6_fast.get(&ifindex).map(Arc::as_ref)
    } else {
        state.iface_filter_v4_fast.get(&ifindex).map(Arc::as_ref)
    };
    let Some(filter) = filter else {
        return TxSelectionFilterResult::default();
    };
    evaluate_filter_ref_tx_selection_counted(
        filter,
        src_ip,
        dst_ip,
        protocol,
        src_port,
        dst_port,
        dscp,
        extra,
        packet_bytes,
    )
}

pub(crate) fn evaluate_interface_output_filter_tx_selection_counted<'a>(
    state: &'a FilterState,
    ifindex: i32,
    is_v6: bool,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    protocol: u8,
    src_port: u16,
    dst_port: u16,
    dscp: u8,
    extra: TermMatchExtra<'_>,
    packet_bytes: u64,
) -> TxSelectionFilterResult<'a> {
    let filter = if is_v6 {
        state
            .iface_filter_out_v6_fast
            .get(&ifindex)
            .map(Arc::as_ref)
    } else {
        state
            .iface_filter_out_v4_fast
            .get(&ifindex)
            .map(Arc::as_ref)
    };
    let Some(filter) = filter else {
        return TxSelectionFilterResult::default();
    };
    evaluate_filter_ref_tx_selection_counted(
        filter,
        src_ip,
        dst_ip,
        protocol,
        src_port,
        dst_port,
        dscp,
        extra,
        packet_bytes,
    )
}

/// #6236 PR-2C: test-only reference implementing the OLD independent two-step
/// lookup — its OWN `.get()` on the per-interface output fast map, then
/// `Filter::needs_tx_eval()` on the borrow. Every production consumer now takes
/// the folded borrow accessor [`interface_output_filter_needing_tx_eval`]
/// directly, so this bool has no runtime caller — it survives only as the
/// INDEPENDENT reference the accessor-equivalence tests (`filter/tests.rs`)
/// compare the folded path against. A delegating `.is_some()` view over the
/// borrow accessor would make that comparison tautological (`X == X`), so the
/// reference deliberately re-derives the flag by an independent lookup.
/// `#[cfg(test)]` keeps it out of the shipped binary.
#[cfg(test)]
pub(crate) fn interface_output_filter_needs_tx_eval(
    state: &FilterState,
    ifindex: i32,
    is_v6: bool,
) -> bool {
    let filter = if is_v6 {
        state.iface_filter_out_v6_fast.get(&ifindex)
    } else {
        state.iface_filter_out_v4_fast.get(&ifindex)
    };
    filter.is_some_and(|f| f.needs_tx_eval())
}

/// #6236 PR-2C: single-lookup borrow of the per-interface OUTPUT filter for this
/// family, gated on `Filter::needs_tx_eval()`. This is the SOLE lookup+gate —
/// every `cos_classify` TX arm borrows the returned `&Filter` straight into the
/// tx-selection evaluator so the needs-tx-eval gate and the walk share ONE
/// `.get()` (PR-2B ran the gate and the fetch as two separate lookups of the
/// same ifindex, then re-checked `needs_tx_eval()` on the borrow). The
/// test-only [`interface_output_filter_needs_tx_eval`] bool is `.is_some()` of
/// this same lookup+gate.
///
/// The PR-2A family-wide `has_output_needs_tx_eval_*` aggregate still
/// short-circuits the whole `cos_classify` TX path upstream
/// (`tx_selection_enabled_v{4,6}`), BEFORE this per-interface lookup ever runs —
/// this fold does not touch that gate.
pub(crate) fn interface_output_filter_needing_tx_eval(
    state: &FilterState,
    ifindex: i32,
    is_v6: bool,
) -> Option<&Filter> {
    let filter = if is_v6 {
        state.iface_filter_out_v6_fast.get(&ifindex)
    } else {
        state.iface_filter_out_v4_fast.get(&ifindex)
    };
    filter.map(Arc::as_ref).filter(|filter| filter.needs_tx_eval())
}

#[inline]
pub(crate) fn filter_state_has_input_tx_selection(state: &FilterState, is_v6: bool) -> bool {
    if is_v6 {
        state.has_input_tx_selection_v6
    } else {
        state.has_input_tx_selection_v4
    }
}

// #6236 PR-2B: `filter_state_has_output_tx_selection` (and the
// `has_output_tx_selection_v*` fields it read) are deleted. PR-2A already
// rewired the global TX gate onto `has_output_needs_tx_eval_*`, which subsumes
// the old `affects_tx_selection`-only aggregate; the accessor had no production
// consumer left.
