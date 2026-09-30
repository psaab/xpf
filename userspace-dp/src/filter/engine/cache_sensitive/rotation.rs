// Cold filter-rotation semantic comparison (#6237, extracted verbatim from
// cache_sensitive.rs). This is the control-plane / worker-loop change-detection
// domain: the family-level structural-equality predicates that decide when
// cached per-session filter decisions must be INVALIDATED on a config rotation.
// Bodies are byte-identical with the pre-split cache_sensitive.rs; only the
// module-level `use` prefix shifts +1 `super::` because this submodule sits one
// level deeper (engine::cache_sensitive::rotation).
//
// The #5293 EXHAUSTIVE FilterTerm destructure in filter_term_semantics_match
// (no `..` rest pattern) is the compile-time anti-drift guard that makes this
// physical separation from the cached rebuild path safe: adding a FilterTerm
// field fails to compile here until it is classified as match-relevant or
// deliberately excluded.

use super::super::super::*;

fn three_color_policer_semantics_match(
    old: &Option<Arc<ThreeColorPolicerRuntime>>,
    new: &Option<Arc<ThreeColorPolicerRuntime>>,
) -> bool {
    match (old.as_ref(), new.as_ref()) {
        (None, None) => true,
        (Some(old), Some(new)) => Arc::ptr_eq(old, new) || old.same_runtime_shape_as(new),
        _ => false,
    }
}

fn filter_term_semantics_match(old: &FilterTerm, new: &FilterTerm) -> bool {
    // #5293: derive this change-detector from an EXHAUSTIVE destructure of the
    // FilterTerm with NO `..` rest pattern. Every field is bound either to a
    // name (and compared against `old` below) or explicitly to `_` (a field
    // that is deliberately NOT part of match semantics). Adding a new field to
    // FilterTerm therefore FAILS TO COMPILE here until the author classifies it
    // — making it impossible to silently omit a match-relevant field from the
    // per-worker session-purge change detector, the way the six `flex_*` fields
    // were omitted originally.
    //
    // The bug this closes: the flexible-match-range fields (#3077, #3232) were
    // absent from the comparison, so a filter/PBR rotation that changed ONLY a
    // flex value/mask/offset/length/enable/match-start compared EQUAL here. The
    // worker then skipped its per-packet-L4 session purge, and an established
    // session kept its stale (pre-rotation) routing-instance / forwarding
    // decision until timeout — a cross-VRF policy-coherency failure (stranded
    // reachability / egress / zone-path / NAT), not merely stale telemetry.
    //
    // Fields intentionally EXCLUDED from match semantics (bound to `_`):
    //   id      — synthetic per-term identity, never a match/action criterion.
    //   counter — runtime hit-counter Arc (shared handle), not config state.
    let FilterTerm {
        id: _,
        name,
        source_v4,
        source_v6,
        dest_v4,
        dest_v6,
        // #2400: the *_constrained flags change match semantics (fail-closed vs
        // match-any) WITHOUT changing the parsed vecs/matcher in the
        // unscoped<->all-malformed transition (both leave empty vecs /
        // PortMatcher::Any), so they MUST be compared or a flow-cache rebuild
        // would keep stale match-any decisions.
        source_addr_constrained,
        dest_addr_constrained,
        // #2506: the except inversion flips the address decision without
        // changing the parsed prefix vecs, so it must be compared too — a
        // snapshot toggling `except` on/off otherwise keeps stale decisions.
        source_except,
        dest_except,
        protocol_bitmap,
        protocol_match_enabled,
        source_ports,
        dest_ports,
        source_port_constrained,
        dest_port_constrained,
        // #2622: the port-except inversion flips the port decision without
        // changing the parsed port matcher, so it must be compared too — a
        // snapshot toggling `*-port-except` on/off otherwise keeps stale
        // flow-cache decisions (sibling of source_except/dest_except above).
        source_port_except,
        dest_port_except,
        dscp_bitmap,
        dscp_match_enabled,
        tcp_flags_mask,
        tcp_flags_forbidden,
        is_fragment,
        icmp_type_bitmap,
        icmp_type_match_enabled,
        icmp_code_bitmap,
        icmp_code_match_enabled,
        // #5293: flexible-match-range (#3077, #3232). All six fields change
        // WHICH packets the term matches (byte-offset window, value/mask,
        // enable, and the L3/L4 base), yet none are part of the 5-tuple
        // SessionKey — so a rotation touching any of them must invalidate
        // cached per-session decisions here.
        flex_enabled,
        flex_offset,
        flex_length,
        flex_value,
        flex_mask,
        flex_match_start,
        action,
        // #2544: continue_term flips a matched term between terminate-here and
        // apply-modifiers-and-fall-through WITHOUT changing the parsed match
        // vecs, so toggling `then next term` on/off must rebuild flow-cache
        // decisions — compare it here.
        continue_term,
        count,
        has_count,
        log,
        policer_name,
        three_color_policer,
        routing_instance,
        forwarding_class,
        dscp_rewrite,
        counter: _,
    } = new;

    old.name == *name
        && old.source_v4 == *source_v4
        && old.source_v6 == *source_v6
        && old.dest_v4 == *dest_v4
        && old.dest_v6 == *dest_v6
        && old.source_addr_constrained == *source_addr_constrained
        && old.dest_addr_constrained == *dest_addr_constrained
        && old.source_except == *source_except
        && old.dest_except == *dest_except
        && old.protocol_bitmap == *protocol_bitmap
        && old.protocol_match_enabled == *protocol_match_enabled
        && old.source_ports == *source_ports
        && old.dest_ports == *dest_ports
        && old.source_port_constrained == *source_port_constrained
        && old.dest_port_constrained == *dest_port_constrained
        && old.source_port_except == *source_port_except
        && old.dest_port_except == *dest_port_except
        && old.dscp_bitmap == *dscp_bitmap
        && old.dscp_match_enabled == *dscp_match_enabled
        && old.tcp_flags_mask == *tcp_flags_mask
        && old.tcp_flags_forbidden == *tcp_flags_forbidden
        && old.is_fragment == *is_fragment
        && old.icmp_type_bitmap == *icmp_type_bitmap
        && old.icmp_type_match_enabled == *icmp_type_match_enabled
        && old.icmp_code_bitmap == *icmp_code_bitmap
        && old.icmp_code_match_enabled == *icmp_code_match_enabled
        && old.flex_enabled == *flex_enabled
        && old.flex_offset == *flex_offset
        && old.flex_length == *flex_length
        && old.flex_value == *flex_value
        && old.flex_mask == *flex_mask
        && old.flex_match_start == *flex_match_start
        && old.action == *action
        && old.continue_term == *continue_term
        && old.count == *count
        && old.has_count == *has_count
        && old.log == *log
        && old.policer_name == *policer_name
        && three_color_policer_semantics_match(&old.three_color_policer, three_color_policer)
        && old.routing_instance == *routing_instance
        && old.forwarding_class == *forwarding_class
        && old.dscp_rewrite == *dscp_rewrite
}

fn dscp_sensitive_filter_semantics_match(old: &Filter, new: &Filter) -> bool {
    old.name == new.name
        && old.family == new.family
        && old.affects_tx_selection == new.affects_tx_selection
        && old.affects_route_lookup == new.affects_route_lookup
        && old.has_counter_terms == new.has_counter_terms
        && old.has_log_terms == new.has_log_terms
        && old.has_terminal_action_terms == new.has_terminal_action_terms
        && old.has_dscp_match_terms == new.has_dscp_match_terms
        && old.has_per_packet_l4_match_terms == new.has_per_packet_l4_match_terms
        && old.has_three_color_policer_terms == new.has_three_color_policer_terms
        && old.terms.len() == new.terms.len()
        && old
            .terms
            .iter()
            .zip(new.terms.iter())
            .all(|(old, new)| filter_term_semantics_match(old, new))
}

fn input_dscp_filter_family_changed(
    old_filters: &rustc_hash::FxHashMap<i32, Arc<Filter>>,
    new_filters: &rustc_hash::FxHashMap<i32, Arc<Filter>>,
) -> bool {
    old_filters
        .iter()
        .filter(|(_, filter)| filter.has_dscp_match_terms)
        .any(|(ifindex, old)| {
            new_filters
                .get(ifindex)
                .is_none_or(|new| !dscp_sensitive_filter_semantics_match(old, new))
        })
        || new_filters
            .iter()
            .filter(|(_, filter)| filter.has_dscp_match_terms)
            .any(|(ifindex, new)| {
                old_filters
                    .get(ifindex)
                    .is_none_or(|old| !dscp_sensitive_filter_semantics_match(old, new))
            })
}

pub(crate) fn input_dscp_filter_families_changed(
    old: &FilterState,
    new: &FilterState,
) -> (bool, bool) {
    (
        input_dscp_filter_family_changed(&old.iface_filter_v4_fast, &new.iface_filter_v4_fast),
        input_dscp_filter_family_changed(&old.iface_filter_v6_fast, &new.iface_filter_v6_fast),
    )
}

/// #11330: compares the optional lo0 filters semantically so a rebuild that
/// only creates fresh `Arc`s or changes a positional filter ID does not trigger
/// a session-table scan.
fn lo0_filter_family_changed(old: &Option<Arc<Filter>>, new: &Option<Arc<Filter>>) -> bool {
    match (old.as_ref(), new.as_ref()) {
        (None, None) => false,
        (Some(old), Some(new)) => !dscp_sensitive_filter_semantics_match(old, new),
        _ => true,
    }
}

pub(crate) fn lo0_filter_families_changed(old: &FilterState, new: &FilterState) -> (bool, bool) {
    (
        lo0_filter_family_changed(&old.lo0_filter_v4_fast, &new.lo0_filter_v4_fast),
        lo0_filter_family_changed(&old.lo0_filter_v6_fast, &new.lo0_filter_v6_fast),
    )
}

pub(crate) fn interface_input_filter_has_dscp_match(
    state: &FilterState,
    ifindex: i32,
    is_v6: bool,
) -> bool {
    // #6236 PR-2B: read `has_dscp_match_terms` off the fast map (mirrors the
    // OUTPUT accessor below), replacing the parallel
    // `iface_filter_v*_has_dscp_match` set. #1430 cache-sensitivity is preserved
    // bit-for-bit: the set was populated iff `filter.has_dscp_match_terms`.
    let filter = if is_v6 {
        state.iface_filter_v6_fast.get(&ifindex)
    } else {
        state.iface_filter_v4_fast.get(&ifindex)
    };
    filter.is_some_and(|filter| filter.has_dscp_match_terms)
}

pub(crate) fn interface_output_filter_has_dscp_match(
    state: &FilterState,
    ifindex: i32,
    is_v6: bool,
) -> bool {
    let filter = if is_v6 {
        state.iface_filter_out_v6_fast.get(&ifindex)
    } else {
        state.iface_filter_out_v4_fast.get(&ifindex)
    };
    filter.is_some_and(|filter| filter.has_dscp_match_terms)
}

// ---------------------------------------------------------------------------
// #2362 per-packet L4 match (tcp-flags / is-fragment / icmp-type / icmp-code).
// These vary per packet within a 5-tuple flow exactly like DSCP, so they get
// the same cache-coherency treatment: a flow-cache decline (flow_cache.rs), a
// per-packet re-evaluation on session hit (poll_descriptor/filter.rs), and a
// config-rotation purge (worker/loop_body) when the per-packet-L4 filter set
// changes. The structural equality test reuses dscp_sensitive_filter_semantics_match
// (which now also compares the per-packet term fields).
// ---------------------------------------------------------------------------

fn input_per_packet_l4_filter_family_changed(
    old_filters: &rustc_hash::FxHashMap<i32, Arc<Filter>>,
    new_filters: &rustc_hash::FxHashMap<i32, Arc<Filter>>,
) -> bool {
    old_filters
        .iter()
        .filter(|(_, filter)| filter.has_per_packet_l4_match_terms)
        .any(|(ifindex, old)| {
            new_filters
                .get(ifindex)
                .is_none_or(|new| !dscp_sensitive_filter_semantics_match(old, new))
        })
        || new_filters
            .iter()
            .filter(|(_, filter)| filter.has_per_packet_l4_match_terms)
            .any(|(ifindex, new)| {
                old_filters
                    .get(ifindex)
                    .is_none_or(|old| !dscp_sensitive_filter_semantics_match(old, new))
            })
}

pub(crate) fn input_per_packet_l4_filter_families_changed(
    old: &FilterState,
    new: &FilterState,
) -> (bool, bool) {
    (
        input_per_packet_l4_filter_family_changed(
            &old.iface_filter_v4_fast,
            &new.iface_filter_v4_fast,
        ),
        input_per_packet_l4_filter_family_changed(
            &old.iface_filter_v6_fast,
            &new.iface_filter_v6_fast,
        ),
    )
}

pub(crate) fn interface_input_filter_has_per_packet_l4_match(
    state: &FilterState,
    ifindex: i32,
    is_v6: bool,
) -> bool {
    // #6236 PR-2B: read `has_per_packet_l4_match_terms` off the fast map,
    // replacing the parallel `iface_filter_v*_has_per_packet_l4_match` set
    // (mirrors the OUTPUT accessor below). #1430/#2362 cache-sensitivity is
    // preserved bit-for-bit for a unique ifindex.
    let filter = if is_v6 {
        state.iface_filter_v6_fast.get(&ifindex)
    } else {
        state.iface_filter_v4_fast.get(&ifindex)
    };
    filter.is_some_and(|filter| filter.has_per_packet_l4_match_terms)
}

pub(crate) fn interface_output_filter_has_per_packet_l4_match(
    state: &FilterState,
    ifindex: i32,
    is_v6: bool,
) -> bool {
    let filter = if is_v6 {
        state.iface_filter_out_v6_fast.get(&ifindex)
    } else {
        state.iface_filter_out_v4_fast.get(&ifindex)
    };
    filter.is_some_and(|filter| filter.has_per_packet_l4_match_terms)
}

/// #6236 PR-2C: single-lookup fold of the #1430 DSCP + #2362 per-packet-L4
/// INPUT-filter "verdict varies per packet" gate. Reads
/// `Filter::varies_per_packet_within_flow()` (the SOLE `has_dscp_match_terms ||
/// has_per_packet_l4_match_terms` OR) off ONE `iface_filter_v{4,6}_fast.get(&
/// ifindex)`, replacing the two separate lookups the folded session-hit re-eval
/// gate (`afxdp/poll_descriptor/filter.rs`) used to pay
/// (`interface_input_filter_has_dscp_match` + `..._has_per_packet_l4_match`).
/// Equal by construction to the OR of those two per-flag accessors — which the
/// flow-cache decline gate (`afxdp/flow_cache.rs`) still consults individually,
/// keeping them live.
pub(crate) fn interface_input_filter_varies_per_packet(
    state: &FilterState,
    ifindex: i32,
    is_v6: bool,
) -> bool {
    let filter = if is_v6 {
        state.iface_filter_v6_fast.get(&ifindex)
    } else {
        state.iface_filter_v4_fast.get(&ifindex)
    };
    filter.is_some_and(|filter| filter.varies_per_packet_within_flow())
}

#[cfg(test)]
mod cache_sensitive_2400_tests {
    use super::super::super::super::*;

    // Compile a single-term filter from one snapshot and return its sole term.
    fn term_from(snap: FirewallTermSnapshot) -> FilterTerm {
        let state = parse_filter_state(
            &[FirewallFilterSnapshot {
                name: "f".into(),
                family: "inet".into(),
                terms: vec![snap],
            }],
            &[],
            &[],
            "",
            "",
        )
        .expect("filter state compiles");
        state
            .filters
            .get("inet:f")
            .expect("filter compiled")
            .terms
            .first()
            .expect("one term")
            .clone()
    }

    /// #2400 (hostile reviewer MINOR): the unscoped <-> all-malformed ADDRESS
    /// flip changes match semantics (match-any vs fail-closed) WITHOUT changing
    /// any parsed vec/matcher — both leave `source_v4`/`source_v6` empty. The
    /// ONLY difference is `source_addr_constrained`. `filter_term_semantics_match`
    /// MUST report them as NOT equal so a flow-cache rebuild invalidates the
    /// stale match-any verdict. REVERT (dropping the `*_constrained` comparisons
    /// from `filter_term_semantics_match`) makes this assert FAIL.
    #[test]
    fn unscoped_vs_all_malformed_source_address_is_not_cache_equal() {
        let unscoped = term_from(FirewallTermSnapshot {
            name: "t".into(),
            action: "discard".into(),
            ..Default::default()
        });
        let all_malformed = term_from(FirewallTermSnapshot {
            name: "t".into(),
            source_addresses: vec!["not-an-ip".into()],
            action: "discard".into(),
            ..Default::default()
        });
        // Precondition: the parsed match state is otherwise identical — the only
        // distinguishing bit is the constrained flag.
        assert!(unscoped.source_v4.is_empty() && unscoped.source_v6.is_empty());
        assert!(all_malformed.source_v4.is_empty() && all_malformed.source_v6.is_empty());
        assert!(!unscoped.source_addr_constrained);
        assert!(all_malformed.source_addr_constrained);

        assert!(
            !super::filter_term_semantics_match(&unscoped, &all_malformed),
            "unscoped vs all-malformed address must NOT be cache-equal \
             (the *_constrained flip must invalidate cached verdicts)"
        );
        // A term compared with itself stays equal (no spurious invalidation).
        assert!(super::filter_term_semantics_match(&unscoped, &unscoped));
        assert!(super::filter_term_semantics_match(&all_malformed, &all_malformed));
    }

    /// Same flip for the PORT match set: unscoped (PortMatcher::Any,
    /// unconstrained) vs all-malformed (PortMatcher::Any, constrained) — the
    /// matcher is byte-identical, only `source_port_constrained` differs.
    #[test]
    fn unscoped_vs_all_malformed_source_port_is_not_cache_equal() {
        let unscoped = term_from(FirewallTermSnapshot {
            name: "t".into(),
            action: "discard".into(),
            ..Default::default()
        });
        let all_malformed = term_from(FirewallTermSnapshot {
            name: "t".into(),
            source_ports: vec!["70000".into()], // out of range -> no parsed range
            action: "discard".into(),
            ..Default::default()
        });
        assert_eq!(unscoped.source_ports, PortMatcher::Any);
        assert_eq!(all_malformed.source_ports, PortMatcher::Any);
        assert!(!unscoped.source_port_constrained);
        assert!(all_malformed.source_port_constrained);

        assert!(
            !super::filter_term_semantics_match(&unscoped, &all_malformed),
            "unscoped vs all-malformed port must NOT be cache-equal"
        );
    }

    /// #5293: the six flexible-match-range fields (`flex_enabled`,
    /// `flex_offset`, `flex_length`, `flex_value`, `flex_mask`,
    /// `flex_match_start`) change WHICH packets a term matches but are NOT part
    /// of the 5-tuple SessionKey. A filter/PBR rotation that touches ONLY a flex
    /// field must be reported as NOT cache-equal so the per-worker session purge
    /// runs — otherwise an established session strands on its stale (pre-
    /// rotation) routing-instance / forwarding decision until timeout.
    ///
    /// Each case clones one compiled base term and mutates exactly ONE flex
    /// field, so the ONLY distinguishing bit is that field. REVERT (dropping the
    /// `flex_*` comparisons from `filter_term_semantics_match`) makes every
    /// "changed flex field" assertion FAIL — the comparator would wrongly return
    /// `true` (equal) and skip the purge.
    #[test]
    fn flex_field_change_is_not_cache_equal() {
        let base = term_from(FirewallTermSnapshot {
            name: "t".into(),
            action: "discard".into(),
            ..Default::default()
        });

        // Control: a term compared with an untouched clone stays cache-equal
        // (no spurious invalidation for a no-op rotation).
        let identical = base.clone();
        assert!(
            super::filter_term_semantics_match(&base, &identical),
            "an identical term must be cache-equal (no spurious purge)"
        );

        // Each mutated clone differs from `base` in EXACTLY one flex field.
        let mut flex_enabled = base.clone();
        flex_enabled.flex_enabled = !base.flex_enabled;

        let mut flex_offset = base.clone();
        flex_offset.flex_offset = base.flex_offset.wrapping_add(1);

        let mut flex_length = base.clone();
        flex_length.flex_length = base.flex_length.wrapping_add(1);

        let mut flex_value = base.clone();
        flex_value.flex_value = base.flex_value ^ 0xA5A5_A5A5;

        let mut flex_mask = base.clone();
        flex_mask.flex_mask = base.flex_mask ^ 0xA5A5_A5A5;

        let mut flex_match_start = base.clone();
        // Pick a variant strictly different from the base's (default Layer3).
        flex_match_start.flex_match_start = match base.flex_match_start {
            FlexMatchStart::Layer3 => FlexMatchStart::Layer4,
            _ => FlexMatchStart::Layer3,
        };

        for (label, mutated) in [
            ("flex_enabled", &flex_enabled),
            ("flex_offset", &flex_offset),
            ("flex_length", &flex_length),
            ("flex_value", &flex_value),
            ("flex_mask", &flex_mask),
            ("flex_match_start", &flex_match_start),
        ] {
            assert!(
                !super::filter_term_semantics_match(&base, mutated),
                "a change to `{label}` must NOT be cache-equal (the rotation \
                 purge must run so sessions do not strand on stale decisions)"
            );
        }
    }
}
