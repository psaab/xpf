// Per-packet filter evaluation engine. Split into responsibility-scoped
// submodules by #1546 (pure code motion — function bodies byte-identical
// with the pre-split engine.rs). Visibility tightened from pub(crate)
// engine-wide flat to pub(super) for engine-local helpers; the surface
// re-exported below matches the prior engine.rs `pub(crate) fn` set.

mod cache_sensitive;
mod eval;
mod matching;
mod policer;
mod tx_selection;

pub(crate) use cache_sensitive::{
    evaluate_filter_ref_tx_selection_cached, evaluate_filter_ref_tx_selection_cached_portless,
    evaluate_interface_input_filter_counters_cached,
    input_dscp_filter_families_changed, input_per_packet_l4_filter_families_changed,
    interface_input_filter_has_dscp_match, interface_input_filter_has_per_packet_l4_match,
    interface_input_filter_varies_per_packet, interface_output_filter_has_dscp_match,
    interface_output_filter_has_per_packet_l4_match, lo0_filter_families_changed,
};
pub(crate) use eval::{
    evaluate_filter, evaluate_filter_counted, evaluate_filter_ref_routing_instance_event_counted,
    evaluate_filter_ref_routing_instance_uncounted,
    evaluate_interface_filter, evaluate_interface_filter_counted,
    evaluate_interface_filter_log_match, evaluate_interface_filter_non_routing_counted,
    evaluate_interface_output_filter, evaluate_interface_output_filter_counted, evaluate_lo0_filter,
    evaluate_lo0_filter_counted, evaluate_lo0_filter_log_match, filter_ref_static_verdict,
    interface_filter_affects_route_lookup, interface_filter_route_lookup_affecting,
    interface_input_filter, NonRoutingCountPolicy,
};
// #6236 PR-2C: the `(state, ifindex, ..)` routing-instance map-lookup wrappers
// are test-only now — production shares the `interface_filter_route_lookup_affecting`
// borrow into the `&Filter` core `evaluate_filter_ref_routing_instance_event_counted`.
#[cfg(test)]
pub(crate) use eval::{
    evaluate_interface_filter_routing_instance_counted,
    evaluate_interface_filter_routing_instance_event_counted,
};
pub(crate) use policer::{
    apply_cached_three_color_policers, filter_state_has_input_three_color_policer,
};
pub(crate) use tx_selection::{
    evaluate_filter_ref_tx_selection_counted, evaluate_filter_ref_tx_selection_runtime_counted,
    evaluate_filter_ref_tx_selection_runtime_uncounted, evaluate_filter_ref_tx_selection_uncounted,
    evaluate_interface_filter_tx_selection_counted,
    evaluate_interface_output_filter_tx_selection_counted, filter_state_has_input_tx_selection,
    interface_output_filter_needing_tx_eval,
};
// #6236 PR-2C: the `needs_tx_eval` bool is a test-only `.is_some()` view over
// `interface_output_filter_needing_tx_eval` (production takes the borrow).
#[cfg(test)]
pub(crate) use tx_selection::interface_output_filter_needs_tx_eval;
