// Filter evaluation (non-TX-selection) extracted from engine.rs by #1546.
// Bodies byte-identical with the pre-split versions; `term_matches*` calls
// now go through `super::matching::*` (same crate, `#[inline(always)]`
// preserved on the callees).
//
// Module responsibility: input/output filter evaluation against a packet,
// including lo0 host-bound filter, per-interface input filter, per-interface
// output filter, the non-routing-instance variants (filter PBR rejects),
// the log-match diagnostic, and the routing-instance overrides. Also holds
// the precheck `interface_filter_affects_route_lookup` because it belongs with
// the routing-instance evaluation it gates.
//
// #7053: an earlier revision said the precheck "is paired with
// `evaluate_interface_filter_routing_instance_event_counted` at its external
// call sites". That symbol is `#[cfg(test)]` (see its own note above the
// definition) and has never been on a production path, so the sentence sent a
// reader after the production contract to a test-only wrapper. PR #6835 then
// EDITED it — "the only external call site" became "each of its external call
// sites" — which turned one wrong reference into three without noticing the
// symbol.
//
// What production actually runs, and it is two distinct pairings rather than
// one:
//
//   * PBR route override: `ingress_route_table_override`
//     (afxdp/forwarding/pbr.rs) borrows the route-lookup-affecting filter with
//     `interface_filter_route_lookup_affecting` — whose `.is_some()` IS the
//     precheck there, folded into the same lookup (#6236 PR-2C) — and evaluates
//     off that borrow with the `&Filter` core
//     `evaluate_filter_ref_routing_instance_event_counted`.
//   * Counter ownership: the bool `interface_filter_affects_route_lookup` has
//     its own production caller at poll_descriptor/filter.rs, deciding
//     `routing_eval_follows` for the #2620 policy below — not the evaluation.
//
// The #6835 r2 observation that survives is about the ARMS, not the symbol: the
// routing walk now follows on the session-miss, fragment-association-HIT and
// flowless-miss arms alike (poll_descriptor/mod.rs), where it used to follow on
// one.

use super::super::*;
use super::matching::{term_matches, term_matches_v4, term_matches_v6};
// #5857: the lo0 host-bound filter meters its three-color policer on the same
// runtime the interface TX-selection leg uses (`merge_matched_tx_modifiers`).
use super::policer::apply_term_three_color_policer;

/// Evaluate a named filter against a packet flow. First matching term wins.
/// If no term matches, the implicit action is Accept.
pub(crate) fn evaluate_filter(
    state: &FilterState,
    filter_key: &str,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    protocol: u8,
    src_port: u16,
    dst_port: u16,
    dscp: u8,
    extra: TermMatchExtra<'_>,
) -> FilterResult {
    evaluate_filter_counted(
        state, filter_key, src_ip, dst_ip, protocol, src_port, dst_port, dscp, extra, 0,
    )
}

pub(crate) fn evaluate_filter_counted(
    state: &FilterState,
    filter_key: &str,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    protocol: u8,
    src_port: u16,
    dst_port: u16,
    dscp: u8,
    extra: TermMatchExtra<'_>,
    packet_bytes: u64,
) -> FilterResult {
    let Some(filter) = state.filters.get(filter_key) else {
        return FilterResult::default();
    };
    evaluate_filter_ref_counted(
        filter,
        src_ip,
        dst_ip,
        protocol,
        src_port,
        dst_port,
        dscp,
        extra,
        packet_bytes,
        // #5857: interface input/output filters meter their three-color policer
        // in the tx-selection walk, not in this action-eval — pass None so this
        // walk does NOT meter (metering here would double-meter).
        None,
    )
}

/// #5857: `now_ns` selects whether matched terms meter their three-color
/// policer. `Some(now_ns)` — the lo0 host-bound path — meters every matched
/// term (drop + color/DSCP decision) exactly like the interface TX-selection
/// leg. `None` — the interface input/output filter action-eval and the PBR
/// prechecks — does NOT meter here: those filters meter their policer in the
/// separate tx-selection walk (`evaluate_filter_ref_tx_selection_*`), so
/// metering in this action-eval too would DOUBLE-meter. With `None` the walk is
/// byte-for-byte identical to the pre-#5857 behavior (no drop, term dscp-rewrite
/// precedence unchanged).
#[inline]
pub(super) fn evaluate_filter_ref_counted(
    filter: &Filter,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    protocol: u8,
    src_port: u16,
    dst_port: u16,
    dscp: u8,
    extra: TermMatchExtra<'_>,
    packet_bytes: u64,
    now_ns: Option<u64>,
) -> FilterResult {
    match (src_ip, dst_ip) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => evaluate_filter_ref_counted_v4(
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
        ),
        (IpAddr::V6(src), IpAddr::V6(dst)) => evaluate_filter_ref_counted_v6(
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
        ),
        _ => FilterResult::default(),
    }
}

#[inline]
fn evaluate_filter_ref_counted_v4(
    filter: &Filter,
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    protocol: u8,
    src_port: u16,
    dst_port: u16,
    dscp: u8,
    extra: TermMatchExtra<'_>,
    packet_bytes: u64,
    now_ns: Option<u64>,
) -> FilterResult {
    // #2544: accumulate modifiers across fall-through terms. A matched
    // fall-through term (continue_term) applies its modifiers and continues; a
    // matched terminating term applies its action+modifiers and returns. If no
    // term terminates, the accumulated modifiers ride the default Accept.
    let mut acc = FilterResult::default();
    for term in &filter.terms {
        if !term_matches_v4(
            term, src_ip, dst_ip, protocol, src_port, dst_port, dscp, extra,
        ) {
            continue;
        }
        if term.has_count {
            record_filter_counter(&term.counter, packet_bytes);
        }
        merge_matched_modifiers(&mut acc, filter, term, now_ns, packet_bytes);
        if !term.continue_term {
            acc.action = term.action;
            normalize_log_match_action(&mut acc);
            return acc;
        }
    }
    normalize_log_match_action(&mut acc);
    acc
}

/// #2616: the RT_FLOW log action must report the verdict the packet actually
/// received, not the placeholder Accept a fall-through (`then { log; next term; }`)
/// logging term carries in its `action` field. The accumulated `log_match`
/// tracks the latest matched logging term's identity (filter_id/term_id), but
/// its action is the term's own — which is the Accept placeholder for a
/// fall-through term. Before the result leaves the evaluator, rewrite the
/// log_match action to the final `acc.action` so a `log; next term` ahead of a
/// terminal `discard`/`reject` logs DENY, not permit. For a terminating logging
/// term `term.action == acc.action` already, so this is a no-op there.
#[inline]
fn normalize_log_match_action(acc: &mut FilterResult) {
    if let Some(lm) = acc.log_match.as_mut() {
        lm.action = acc.action;
    }
}

/// #2544: merge a matched term's modifiers into the running result. Used by both
/// the fall-through and terminating cases: count/policer side effects are
/// recorded by the caller; here we carry the term's dscp-rewrite, policer name,
/// routing-instance, forwarding-class, and log signal forward. Latest matched
/// term wins for each scalar modifier (Junos applies modifiers as terms are
/// traversed); `log` is OR'd so any matched term with `then log` lights it. The
/// log_match diagnostic tracks the latest matched logging term. The action is
/// NOT set here — the caller sets it only for a terminating term, and
/// `normalize_log_match_action` (#2616) rewrites the stored log_match action to
/// the final verdict before the result is returned.
///
/// #5857: `now_ns` gates the three-color policer METER — a side effect that
/// (like the tx-selection leg's `merge_matched_tx_modifiers`) must run on EVERY
/// matched term, fall-through or terminating, exactly once. `Some(now_ns)` (the
/// lo0 host-bound path) meters `term.three_color_policer` and folds its drop
/// (OR-accumulated so a later permit cannot erase an earlier drop) and its
/// color/DSCP rewrite (policer rewrite wins over the term's configured rewrite,
/// matching the tx-selection precedence). `None` (interface input/output
/// action-eval + PBR prechecks, which meter their policer in the tx-selection
/// walk) skips the meter and is byte-for-byte identical to pre-#5857.
#[inline]
fn merge_matched_modifiers(
    acc: &mut FilterResult,
    filter: &Filter,
    term: &FilterTerm,
    now_ns: Option<u64>,
    packet_bytes: u64,
) {
    // #5857: meter the three-color policer once per matched term when the caller
    // requested metering (lo0). `now_ns == None` returns the default no-op action
    // (drop=false, dscp_rewrite=None), preserving the non-metered paths exactly.
    let policer_action = apply_term_three_color_policer(term, now_ns, packet_bytes);
    // #5857: policer color/DSCP rewrite takes precedence over the term's
    // configured rewrite; otherwise the term's rewrite carries forward (a `None`
    // policer action + no term rewrite leaves any earlier term's rewrite intact,
    // matching the pre-#5857 `if term.dscp_rewrite.is_some()` assignment).
    if let Some(rewrite) = policer_action.dscp_rewrite.or(term.dscp_rewrite) {
        acc.dscp_rewrite = Some(rewrite);
    }
    acc.policer_drop |= policer_action.drop;
    // #5444: `policer_name`/`routing_instance` are `Arc<str>` (interned at
    // compile time), so these writes are refcount bumps — NOT per-packet String
    // heap allocations. Mirrors the `forwarding_class` clone below (#5151); the
    // Arc clone only runs when a term ACTUALLY sets the modifier, and `None` on
    // the default/reset preserves the old empty-`""` "unset" meaning.
    if !term.policer_name.is_empty() {
        acc.policer_name = Some(term.policer_name.clone());
    }
    if !term.routing_instance.is_empty() {
        acc.routing_instance = Some(term.routing_instance.clone());
    }
    if !term.forwarding_class.is_empty() {
        // #5151: clone the Arc only when a term ACTUALLY sets a forwarding-class
        // (the allocation happens on a match, not on every default). `None` on
        // the default preserves the old empty-`""` "no forwarding-class" meaning.
        acc.forwarding_class = Some(term.forwarding_class.clone());
    }
    if term.log {
        acc.log = true;
    }
    if let Some(lm) = filter_log_match(filter, term) {
        acc.log_match = Some(lm);
    }
}

#[inline]
fn evaluate_filter_ref_counted_v6(
    filter: &Filter,
    src_ip: Ipv6Addr,
    dst_ip: Ipv6Addr,
    protocol: u8,
    src_port: u16,
    dst_port: u16,
    dscp: u8,
    extra: TermMatchExtra<'_>,
    packet_bytes: u64,
    now_ns: Option<u64>,
) -> FilterResult {
    // #2544: see evaluate_filter_ref_counted_v4 — accumulate fall-through
    // modifiers; return on the first terminating matched term.
    let mut acc = FilterResult::default();
    for term in &filter.terms {
        if !term_matches_v6(
            term, src_ip, dst_ip, protocol, src_port, dst_port, dscp, extra,
        ) {
            continue;
        }
        if term.has_count {
            record_filter_counter(&term.counter, packet_bytes);
        }
        merge_matched_modifiers(&mut acc, filter, term, now_ns, packet_bytes);
        if !term.continue_term {
            acc.action = term.action;
            normalize_log_match_action(&mut acc);
            return acc;
        }
    }
    normalize_log_match_action(&mut acc);
    acc
}

/// #2620: counter ownership policy for the non-routing input-filter evaluator.
///
/// The session-miss path runs this precheck for the verdict AND — only on its
/// Accept/defer exit (`poll_descriptor/mod.rs` does `continue` on a non-Accept
/// verdict, never reaching the routing evaluator) — the routing-instance
/// evaluator — `evaluate_filter_ref_routing_instance_event_counted`, reached
/// through `ingress_route_table_override` (afxdp/forwarding/pbr.rs) — which
/// counts every matched term itself. (#7053: this named the `#[cfg(test)]`
/// two-lookup wrapper `evaluate_interface_filter_routing_instance_event_counted`
/// until the production symbol was checked; the wrapper's only callers are
/// filter/tests.rs and the sibling test-only wrapper above.)
/// So WHO owns the count depends on the per-packet exit, not just on whether
/// the filter has a routing-instance term:
///
/// * `Always` — this precheck is the SOLE counter for the packet. Used when no
///   routing-instance term exists in the filter (the routing evaluator returns
///   early at the `affects_route_lookup` guard and counts nothing) AND on the
///   DSCP/L4-sensitive SESSION-HIT re-eval path (`evaluate_dscp_sensitive_input_filter_on_session_hit`),
///   which never invokes the routing evaluator. Counts every matched `then
///   count` term on every exit — bit-identical to pre-#2620 behavior.
/// * `OnlyTerminalNonAccept` — used on the session-MISS path when the filter IS
///   route-lookup-affecting. The routing evaluator runs and counts on the
///   Accept/defer exit, so this precheck must NOT count there (else the
///   fall-through `then count` ahead of the routing-instance term double-counts,
///   the #2620 bug). But on a terminal `discard`/`reject` exit BEFORE the
///   routing-instance term the poll path `continue`s and the routing evaluator
///   never runs — so this precheck IS the sole counter on that exit and must
///   count every matched `then count` term up to and including the terminal one
///   (else those terms under-count to zero, the regression the coarse boolean
///   gate introduced).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NonRoutingCountPolicy {
    Always,
    OnlyTerminalNonAccept,
}

#[inline]
fn evaluate_filter_ref_non_routing_counted(
    filter: &Filter,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    protocol: u8,
    src_port: u16,
    dst_port: u16,
    dscp: u8,
    extra: TermMatchExtra<'_>,
    packet_bytes: u64,
    count_policy: NonRoutingCountPolicy,
) -> FilterResult {
    match (src_ip, dst_ip) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => evaluate_filter_ref_non_routing_counted_v4(
            filter,
            src,
            dst,
            protocol,
            src_port,
            dst_port,
            dscp,
            extra,
            packet_bytes,
            count_policy,
        ),
        (IpAddr::V6(src), IpAddr::V6(dst)) => evaluate_filter_ref_non_routing_counted_v6(
            filter,
            src,
            dst,
            protocol,
            src_port,
            dst_port,
            dscp,
            extra,
            packet_bytes,
            count_policy,
        ),
        _ => FilterResult::default(),
    }
}

#[inline]
fn evaluate_filter_ref_non_routing_counted_v4(
    filter: &Filter,
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    protocol: u8,
    src_port: u16,
    dst_port: u16,
    dscp: u8,
    extra: TermMatchExtra<'_>,
    packet_bytes: u64,
    count_policy: NonRoutingCountPolicy,
) -> FilterResult {
    // #2544: accumulate fall-through modifiers (count/log/fc/dscp). A matched
    // term that points at a routing-instance defers to the routing-instance
    // evaluator (returns default here, unchanged); such a term is never a
    // fall-through (continue_term is false when routing_instance is set).
    //
    // #2620: counting follows `count_policy` (see NonRoutingCountPolicy). Under
    // `Always` every matched `then count` term records inline. Under
    // `OnlyTerminalNonAccept` we do NOT count during the walk — the routing
    // evaluator owns the count on the Accept/defer exit — and instead replay the
    // count over the matched terms ONLY when this evaluator reaches a terminal
    // `discard`/`reject` (the exit on which the poll path `continue`s and the
    // routing evaluator never runs), so those fall-through counters are recorded
    // exactly once and never drop to zero.
    let always_count = count_policy == NonRoutingCountPolicy::Always;
    let mut acc = FilterResult::default();
    for term in &filter.terms {
        if !term_matches_v4(
            term, src_ip, dst_ip, protocol, src_port, dst_port, dscp, extra,
        ) {
            continue;
        }
        if !term.routing_instance.is_empty() {
            return FilterResult::default();
        }
        if always_count && term.has_count {
            record_filter_counter(&term.counter, packet_bytes);
        }
        // #5857: the non-routing input-filter evaluator does NOT meter its
        // policer here (it is metered in the tx-selection walk); pass None.
        merge_matched_modifiers(&mut acc, filter, term, None, packet_bytes);
        // This loop variant never carries a routing-instance through the
        // result (it defers to the routing-instance evaluator); keep that.
        acc.routing_instance = None;
        if !term.continue_term {
            acc.action = term.action;
            if !always_count && term.action != FilterAction::Accept {
                count_matched_non_routing_terms_v4(
                    filter,
                    src_ip,
                    dst_ip,
                    protocol,
                    src_port,
                    dst_port,
                    dscp,
                    extra,
                    packet_bytes,
                    term,
                );
            }
            normalize_log_match_action(&mut acc);
            return acc;
        }
    }
    normalize_log_match_action(&mut acc);
    acc
}

/// #2620: replay the matched-term walk under `OnlyTerminalNonAccept` once the
/// caller has resolved that the verdict is a terminal `discard`/`reject`,
/// recording each matched `then count` term up to AND INCLUDING `terminal`
/// exactly once. The routing evaluator never runs on this exit, so this
/// evaluator is the sole counter. Walk order is identical to the main loop so
/// the recorded set matches.
#[inline]
#[allow(clippy::too_many_arguments)]
fn count_matched_non_routing_terms_v4(
    filter: &Filter,
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    protocol: u8,
    src_port: u16,
    dst_port: u16,
    dscp: u8,
    extra: TermMatchExtra<'_>,
    packet_bytes: u64,
    terminal: &FilterTerm,
) {
    for term in &filter.terms {
        if !term_matches_v4(
            term, src_ip, dst_ip, protocol, src_port, dst_port, dscp, extra,
        ) {
            continue;
        }
        // A routing-instance term would have made the main loop return default
        // before reaching the terminal; it can never precede `terminal` here.
        if term.has_count {
            record_filter_counter(&term.counter, packet_bytes);
        }
        if std::ptr::eq(term, terminal) {
            return;
        }
    }
}

#[inline]
fn evaluate_filter_ref_non_routing_counted_v6(
    filter: &Filter,
    src_ip: Ipv6Addr,
    dst_ip: Ipv6Addr,
    protocol: u8,
    src_port: u16,
    dst_port: u16,
    dscp: u8,
    extra: TermMatchExtra<'_>,
    packet_bytes: u64,
    count_policy: NonRoutingCountPolicy,
) -> FilterResult {
    // #2544/#2620: see evaluate_filter_ref_non_routing_counted_v4.
    let always_count = count_policy == NonRoutingCountPolicy::Always;
    let mut acc = FilterResult::default();
    for term in &filter.terms {
        if !term_matches_v6(
            term, src_ip, dst_ip, protocol, src_port, dst_port, dscp, extra,
        ) {
            continue;
        }
        if !term.routing_instance.is_empty() {
            return FilterResult::default();
        }
        if always_count && term.has_count {
            record_filter_counter(&term.counter, packet_bytes);
        }
        // #5857: the non-routing input-filter evaluator does NOT meter its
        // policer here (it is metered in the tx-selection walk); pass None.
        merge_matched_modifiers(&mut acc, filter, term, None, packet_bytes);
        acc.routing_instance = None;
        if !term.continue_term {
            acc.action = term.action;
            if !always_count && term.action != FilterAction::Accept {
                count_matched_non_routing_terms_v6(
                    filter,
                    src_ip,
                    dst_ip,
                    protocol,
                    src_port,
                    dst_port,
                    dscp,
                    extra,
                    packet_bytes,
                    term,
                );
            }
            normalize_log_match_action(&mut acc);
            return acc;
        }
    }
    normalize_log_match_action(&mut acc);
    acc
}

/// #2620: v6 counterpart of `count_matched_non_routing_terms_v4`.
#[inline]
#[allow(clippy::too_many_arguments)]
fn count_matched_non_routing_terms_v6(
    filter: &Filter,
    src_ip: Ipv6Addr,
    dst_ip: Ipv6Addr,
    protocol: u8,
    src_port: u16,
    dst_port: u16,
    dscp: u8,
    extra: TermMatchExtra<'_>,
    packet_bytes: u64,
    terminal: &FilterTerm,
) {
    for term in &filter.terms {
        if !term_matches_v6(
            term, src_ip, dst_ip, protocol, src_port, dst_port, dscp, extra,
        ) {
            continue;
        }
        if term.has_count {
            record_filter_counter(&term.counter, packet_bytes);
        }
        if std::ptr::eq(term, terminal) {
            return;
        }
    }
}

#[inline]
pub(super) fn filter_log_match(filter: &Filter, term: &FilterTerm) -> Option<FilterLogMatch> {
    term.log.then_some(FilterLogMatch {
        filter_id: filter.id,
        term_id: term.id,
        action: term.action,
    })
}

#[inline]
fn evaluate_filter_ref_routing_instance_counted_v4<'a>(
    filter: &'a Filter,
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    protocol: u8,
    src_port: u16,
    dst_port: u16,
    dscp: u8,
    extra: TermMatchExtra<'_>,
    packet_bytes: u64,
) -> Option<FilterRoutingInstanceResult<'a>> {
    let mut acc_log: Option<FilterLogMatch> = None;
    for term in &filter.terms {
        if !term_matches_v4(
            term, src_ip, dst_ip, protocol, src_port, dst_port, dscp, extra,
        ) {
            continue;
        }
        if term.has_count {
            record_filter_counter(&term.counter, packet_bytes);
        }
        // #2544: a matched fall-through term (no terminating action, no
        // routing-instance) applies its count modifier above and must NOT halt
        // the search for a routing-instance term — keep scanning. A matched
        // TERMINATING term without a routing-instance still halts (returns None
        // via the `?` below): once a packet is accepted/discarded there is no
        // routing-instance override to find.
        // #2619: capture a fall-through `then log` term's log_match before we
        // continue past it — the PBR path previously dropped these. Latest
        // matched logging term wins, mirroring the full evaluator.
        if term.continue_term {
            if let Some(lm) = filter_log_match(filter, term) {
                acc_log = Some(lm);
            }
            continue;
        }
        let routing_instance =
            (!term.routing_instance.is_empty()).then_some(&*term.routing_instance)?;
        // The routing-instance term itself may also carry `then log`; latest
        // matched wins so it supersedes any earlier fall-through log.
        if let Some(lm) = filter_log_match(filter, term) {
            acc_log = Some(lm);
        }
        // #2616: the routing-instance term is terminating on the PBR path; stamp
        // its action onto the accumulated log_match so a fall-through log ahead
        // of it reports the verdict the packet actually receives.
        if let Some(lm) = acc_log.as_mut() {
            lm.action = term.action;
        }
        return Some(FilterRoutingInstanceResult {
            routing_instance,
            log: term.log,
            action: term.action,
            filter_id: filter.id,
            term_id: term.id,
            log_match: acc_log,
        });
    }
    None
}

#[inline]
fn evaluate_filter_ref_routing_instance_counted_v6<'a>(
    filter: &'a Filter,
    src_ip: Ipv6Addr,
    dst_ip: Ipv6Addr,
    protocol: u8,
    src_port: u16,
    dst_port: u16,
    dscp: u8,
    extra: TermMatchExtra<'_>,
    packet_bytes: u64,
) -> Option<FilterRoutingInstanceResult<'a>> {
    let mut acc_log: Option<FilterLogMatch> = None;
    for term in &filter.terms {
        if !term_matches_v6(
            term, src_ip, dst_ip, protocol, src_port, dst_port, dscp, extra,
        ) {
            continue;
        }
        if term.has_count {
            record_filter_counter(&term.counter, packet_bytes);
        }
        // #2544: see the v4 variant — a matched fall-through term keeps scanning.
        // #2619: capture its log_match before continuing (latest wins).
        if term.continue_term {
            if let Some(lm) = filter_log_match(filter, term) {
                acc_log = Some(lm);
            }
            continue;
        }
        let routing_instance =
            (!term.routing_instance.is_empty()).then_some(&*term.routing_instance)?;
        if let Some(lm) = filter_log_match(filter, term) {
            acc_log = Some(lm);
        }
        // #2616: stamp the routing-instance term's verdict onto the log_match.
        if let Some(lm) = acc_log.as_mut() {
            lm.action = term.action;
        }
        return Some(FilterRoutingInstanceResult {
            routing_instance,
            log: term.log,
            action: term.action,
            filter_id: filter.id,
            term_id: term.id,
            log_match: acc_log,
        });
    }
    None
}

/// Evaluate the lo0 (host-bound) filter for a given address family.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn evaluate_lo0_filter(
    state: &FilterState,
    is_v6: bool,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    protocol: u8,
    src_port: u16,
    dst_port: u16,
    dscp: u8,
    extra: TermMatchExtra<'_>,
) -> FilterResult {
    // #5857: the test convenience wrapper does NOT meter (now_ns = None); it is
    // used only by tests that assert the verdict/counters, not policer metering.
    evaluate_lo0_filter_counted(
        state, is_v6, src_ip, dst_ip, protocol, src_port, dst_port, dscp, extra, 0, None,
    )
}

/// #5857: `now_ns` threads the poll-iteration monotonic timestamp so the lo0
/// host-bound filter METERS each matched term's three-color policer (the same
/// runtime the interface TX-selection leg meters). `Some(now_ns)` — the live
/// local-delivery path — enforces the configured control-plane rate limit;
/// `None` — the `evaluate_lo0_filter` test convenience wrapper — evaluates the
/// verdict/counters without metering. lo0 has no separate tx-selection leg, so
/// this is the ONLY place its policer is metered (no double-meter risk).
pub(crate) fn evaluate_lo0_filter_counted(
    state: &FilterState,
    is_v6: bool,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    protocol: u8,
    src_port: u16,
    dst_port: u16,
    dscp: u8,
    extra: TermMatchExtra<'_>,
    packet_bytes: u64,
    now_ns: Option<u64>,
) -> FilterResult {
    let filter = if is_v6 {
        state.lo0_filter_v6_fast.as_deref()
    } else {
        state.lo0_filter_v4_fast.as_deref()
    };
    let Some(filter) = filter else {
        return FilterResult::default();
    };
    evaluate_filter_ref_counted(
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
    )
}

pub(crate) fn evaluate_lo0_filter_log_match(
    state: &FilterState,
    is_v6: bool,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    protocol: u8,
    src_port: u16,
    dst_port: u16,
    dscp: u8,
    extra: TermMatchExtra<'_>,
) -> Option<FilterLogMatch> {
    let filter = if is_v6 {
        state.lo0_filter_v6_fast.as_deref()
    } else {
        state.lo0_filter_v4_fast.as_deref()
    }?;
    evaluate_filter_ref_log_match(
        filter, src_ip, dst_ip, protocol, src_port, dst_port, dscp, extra, false,
    )
}

/// Evaluate the per-interface input filter for a given address family.
pub(crate) fn evaluate_interface_filter(
    state: &FilterState,
    ifindex: i32,
    is_v6: bool,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    protocol: u8,
    src_port: u16,
    dst_port: u16,
    dscp: u8,
    extra: TermMatchExtra<'_>,
) -> FilterResult {
    evaluate_interface_filter_counted(
        state, ifindex, is_v6, src_ip, dst_ip, protocol, src_port, dst_port, dscp, extra, 0,
    )
}

pub(crate) fn evaluate_interface_filter_counted(
    state: &FilterState,
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
) -> FilterResult {
    let filter = if is_v6 {
        state.iface_filter_v6_fast.get(&ifindex).map(Arc::as_ref)
    } else {
        state.iface_filter_v4_fast.get(&ifindex).map(Arc::as_ref)
    };
    let Some(filter) = filter else {
        return FilterResult::default();
    };
    evaluate_filter_ref_counted(
        filter,
        src_ip,
        dst_ip,
        protocol,
        src_port,
        dst_port,
        dscp,
        extra,
        packet_bytes,
        // #5857: interface input/output filters meter their three-color policer
        // in the tx-selection walk, not in this action-eval — pass None so this
        // walk does NOT meter (metering here would double-meter).
        None,
    )
}

/// Evaluate the per-interface input filter for the session-miss / session-hit
/// decision, deferring any routing-instance (PBR) term to the routing-instance
/// evaluator. `count_policy` selects who owns the per-packet count — see
/// [`NonRoutingCountPolicy`] (#2620). The caller picks:
///
/// * `OnlyTerminalNonAccept` on the session-MISS path when the filter is
///   route-lookup-affecting (the routing evaluator runs on the Accept exit and
///   counts there; this evaluator counts only on the terminal discard/reject
///   exit the routing evaluator can't reach), and
/// * `Always` otherwise — a plain non-PBR filter, or the DSCP/L4 session-HIT
///   re-eval, where this evaluator is the SOLE counter.
pub(crate) fn evaluate_interface_filter_non_routing_counted(
    state: &FilterState,
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
    count_policy: NonRoutingCountPolicy,
) -> FilterResult {
    let filter = if is_v6 {
        state.iface_filter_v6_fast.get(&ifindex).map(Arc::as_ref)
    } else {
        state.iface_filter_v4_fast.get(&ifindex).map(Arc::as_ref)
    };
    let Some(filter) = filter else {
        return FilterResult::default();
    };
    evaluate_filter_ref_non_routing_counted(
        filter,
        src_ip,
        dst_ip,
        protocol,
        src_port,
        dst_port,
        dscp,
        extra,
        packet_bytes,
        count_policy,
    )
}

pub(crate) fn evaluate_interface_filter_log_match(
    state: &FilterState,
    ifindex: i32,
    is_v6: bool,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    protocol: u8,
    src_port: u16,
    dst_port: u16,
    dscp: u8,
    extra: TermMatchExtra<'_>,
    skip_routing_instance: bool,
) -> Option<FilterLogMatch> {
    let filter = if is_v6 {
        state.iface_filter_v6_fast.get(&ifindex).map(Arc::as_ref)
    } else {
        state.iface_filter_v4_fast.get(&ifindex).map(Arc::as_ref)
    }?;
    evaluate_filter_ref_log_match(
        filter,
        src_ip,
        dst_ip,
        protocol,
        src_port,
        dst_port,
        dscp,
        extra,
        skip_routing_instance,
    )
}

// #6236 PR-2C: this `(state, ifindex, ..)` map-lookup wrapper is now test-only —
// production (afxdp/forwarding/pbr.rs) shares the borrow from
// `interface_filter_route_lookup_affecting` into the `&Filter` core
// `evaluate_filter_ref_routing_instance_event_counted` (one lookup). `#[cfg(test)]`
// keeps the wrapper out of the shipped binary.
#[cfg(test)]
pub(crate) fn evaluate_interface_filter_routing_instance_counted<'a>(
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
) -> Option<&'a str> {
    evaluate_interface_filter_routing_instance_event_counted(
        state,
        ifindex,
        is_v6,
        src_ip,
        dst_ip,
        protocol,
        src_port,
        dst_port,
        dscp,
        extra,
        packet_bytes,
    )
    .map(|result| result.routing_instance)
}

// #6236 PR-2C: test-only map-lookup wrapper (see
// `evaluate_interface_filter_routing_instance_counted` above); production shares
// the borrow into the `&Filter` core below. `#[cfg(test)]` keeps it out of the
// shipped binary.
#[cfg(test)]
pub(crate) fn evaluate_interface_filter_routing_instance_event_counted<'a>(
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
) -> Option<FilterRoutingInstanceResult<'a>> {
    let filter = if is_v6 {
        state.iface_filter_v6_fast.get(&ifindex).map(Arc::as_ref)
    } else {
        state.iface_filter_v4_fast.get(&ifindex).map(Arc::as_ref)
    };
    let filter = filter?;
    evaluate_filter_ref_routing_instance_event_counted(
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

/// #6236 PR-2C: `&Filter`-taking core of the routing-instance evaluator — the
/// `(src, dst)`-family dispatch, extracted so the PBR call site
/// (`afxdp/forwarding/pbr.rs`) can share the SAME borrow the
/// `affects_route_lookup` precheck already took
/// ([`interface_filter_route_lookup_affecting`]) instead of re-looking-up the
/// ifindex. The map-lookup wrapper above and the folded PBR site both funnel
/// through this one body, so the precheck-then-evaluate pair pays a single
/// `.get()`.
pub(crate) fn evaluate_filter_ref_routing_instance_event_counted<'a>(
    filter: &'a Filter,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    protocol: u8,
    src_port: u16,
    dst_port: u16,
    dscp: u8,
    extra: TermMatchExtra<'_>,
    packet_bytes: u64,
) -> Option<FilterRoutingInstanceResult<'a>> {
    match (src_ip, dst_ip) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => evaluate_filter_ref_routing_instance_counted_v4(
            filter,
            src,
            dst,
            protocol,
            src_port,
            dst_port,
            dscp,
            extra,
            packet_bytes,
        ),
        (IpAddr::V6(src), IpAddr::V6(dst)) => evaluate_filter_ref_routing_instance_counted_v6(
            filter,
            src,
            dst,
            protocol,
            src_port,
            dst_port,
            dscp,
            extra,
            packet_bytes,
        ),
        _ => None,
    }
}

fn evaluate_filter_ref_log_match(
    filter: &Filter,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    protocol: u8,
    src_port: u16,
    dst_port: u16,
    dscp: u8,
    extra: TermMatchExtra<'_>,
    skip_routing_instance: bool,
) -> Option<FilterLogMatch> {
    if !filter.has_log_terms {
        return None;
    }
    // #2544: a matched fall-through term (`then next term` / modifier-only) with
    // `then log` fires its log even though evaluation continues to later terms.
    // #2618: this log-only helper must share the FULL evaluator's
    // latest-matched-logging-term semantics — it previously returned on the
    // FIRST matched logging fall-through term, so two `log; next term` terms made
    // the cached input-filter log point at a different term than live evaluation.
    // Walk all terms: a matched logging fall-through term records its log_match
    // and keeps scanning (latest wins); a matched fall-through term without `log`
    // is skipped; the first matched TERMINATING term ends the scan, recording its
    // own log_match (when it has `log`) and resolving the final verdict.
    //
    // #2616: the recorded log action must follow the FINAL verdict, not the
    // Accept placeholder a fall-through logging term carries — track the terminal
    // action and stamp it onto the accumulated log_match before returning so a
    // `log; next term` ahead of a terminal discard/reject logs DENY, not permit.
    let mut acc_log: Option<FilterLogMatch> = None;
    let mut final_action = FilterAction::Accept;
    for term in &filter.terms {
        if !term_matches(
            term, src_ip, dst_ip, protocol, src_port, dst_port, dscp, extra,
        ) {
            continue;
        }
        if term.continue_term {
            if let Some(lm) = filter_log_match(filter, term) {
                acc_log = Some(lm);
            }
            continue;
        }
        if skip_routing_instance && !term.routing_instance.is_empty() {
            // The route-lookup-affecting PBR term is handled by the
            // routing-instance evaluator; its log is not emitted on this path.
            // Any earlier fall-through log_match still carries the verdict the
            // packet receives here (default Accept on the non-PBR path).
            break;
        }
        final_action = term.action;
        if let Some(lm) = filter_log_match(filter, term) {
            acc_log = Some(lm);
        }
        break;
    }
    if let Some(lm) = acc_log.as_mut() {
        lm.action = final_action;
    }
    acc_log
}

/// Evaluate the per-interface output filter for a given address family.
pub(crate) fn evaluate_interface_output_filter(
    state: &FilterState,
    ifindex: i32,
    is_v6: bool,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    protocol: u8,
    src_port: u16,
    dst_port: u16,
    dscp: u8,
    extra: TermMatchExtra<'_>,
) -> FilterResult {
    evaluate_interface_output_filter_counted(
        state, ifindex, is_v6, src_ip, dst_ip, protocol, src_port, dst_port, dscp, extra, 0,
    )
}

pub(crate) fn evaluate_interface_output_filter_counted(
    state: &FilterState,
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
) -> FilterResult {
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
        return FilterResult::default();
    };
    evaluate_filter_ref_counted(
        filter,
        src_ip,
        dst_ip,
        protocol,
        src_port,
        dst_port,
        dscp,
        extra,
        packet_bytes,
        // #5857: interface input/output filters meter their three-color policer
        // in the tx-selection walk, not in this action-eval — pass None so this
        // walk does NOT meter (metering here would double-meter).
        None,
    )
}

/// Whether the per-interface input filter for the given family carries terms
/// that override the route lookup with a routing-instance pointer. This is
/// the precheck for the routing-instance override. It lives next to the
/// routing-instance evaluator rather than in cache_sensitive.rs because it is
/// not a cache-coherency predicate.
///
/// #7053: it is NOT "paired with
/// `evaluate_interface_filter_routing_instance_event_counted` at each of its
/// external call sites" — that symbol is `#[cfg(test)]`. This bool has ONE
/// production caller, poll_descriptor/filter.rs, where it decides
/// `routing_eval_follows` for the #2620 counter-ownership policy. The PBR path
/// does not call it at all: `ingress_route_table_override` folds precheck and
/// evaluation into a single lookup via
/// `interface_filter_route_lookup_affecting` (#6236 PR-2C), so there the
/// precheck is `.is_some()` of that borrow and the evaluator is the `&Filter`
/// core `evaluate_filter_ref_routing_instance_event_counted`.
///
/// The arms claim from #6835 r2 stands on its own: the routing walk follows on
/// the session-miss, fragment-association-HIT and flowless-miss arms alike
/// (poll_descriptor/mod.rs), where it used to follow on one.
pub(crate) fn interface_filter_affects_route_lookup(
    state: &FilterState,
    ifindex: i32,
    is_v6: bool,
) -> bool {
    // #6236 PR-2C: independent single lookup — its OWN `.get()` on the
    // per-interface input fast map, then the `affects_route_lookup` flag.
    // Retained for the poll-descriptor session-miss counter-policy precheck
    // (`evaluate_non_pbr_input_filter`), which needs only the bool, not the
    // filter — AND as the INDEPENDENT reference the accessor-equivalence tests
    // compare the folded borrow accessor `interface_filter_route_lookup_affecting`
    // against. Delegating to that accessor would make the comparison tautological
    // (`X == X`); this re-derives the flag by its own lookup. Same single-lookup
    // cost either way.
    let filter = if is_v6 {
        state.iface_filter_v6_fast.get(&ifindex)
    } else {
        state.iface_filter_v4_fast.get(&ifindex)
    };
    filter.is_some_and(|f| f.affects_route_lookup)
}

/// #6236 PR-2C: single-lookup borrow of the per-interface input filter for this
/// family, gated on `affects_route_lookup`. This is the SOLE lookup+gate — the
/// bool precheck [`interface_filter_affects_route_lookup`] is `.is_some()` of
/// it, and the PBR call site (`afxdp/forwarding/pbr.rs`) borrows the returned
/// `&Filter` straight into [`evaluate_filter_ref_routing_instance_event_counted`]
/// so the precheck and the routing-instance evaluation share ONE `.get()`
/// instead of looking the same ifindex up twice (the PR-2B two-lookup shape).
///
/// Behavior is identical to the two-lookup path: for a unique ifindex the borrow
/// is the same `Arc<Filter>` the evaluator's own lookup would return; for a
/// duplicate ifindex the fast map is the last-wins SSOT, so the precheck agrees
/// with the filter the evaluator walks.
pub(crate) fn interface_filter_route_lookup_affecting(
    state: &FilterState,
    ifindex: i32,
    is_v6: bool,
) -> Option<&Filter> {
    let filter = if is_v6 {
        state.iface_filter_v6_fast.get(&ifindex)
    } else {
        state.iface_filter_v4_fast.get(&ifindex)
    };
    filter
        .map(Arc::as_ref)
        .filter(|filter| filter.affects_route_lookup)
}
