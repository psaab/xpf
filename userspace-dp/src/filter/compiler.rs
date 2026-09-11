// Snapshot/AST → typed Filter compiler extracted from filter.rs (#1049 P2 structural split).
// #6434: `parse_filter_state_with_three_color_preserving` and `parse_term`
// are decomposed into single-responsibility phase helpers (policer runtime
// loading / filter-table build / interface assignment / aggregate recompute /
// lo0 resolution; marker preflight / value-range preflight / address /
// protocol / cross-field / port / action / flex lowering + term assembly).
// Pure code motion — the compiled `FilterState` is bit-identical.

use super::*;

/// Build the complete FilterState from snapshot data.
///
/// #2505: returns `Err(SnapshotIntegrityError)` when a filter term carries a
/// NON-EMPTY `from protocol` list with a token `ip_proto::proto_number` cannot
/// resolve. Silently dropping it (the pre-fix `filter_map`) was a fail-WIDE
/// security bug — an all-dropped list disabled the protocol match so the term
/// matched every protocol.
pub(crate) fn parse_filter_state(
    filters: &[FirewallFilterSnapshot],
    policers: &[PolicerSnapshot],
    interfaces: &[crate::InterfaceSnapshot],
    lo0_filter_v4: &str,
    lo0_filter_v6: &str,
) -> Result<FilterState, SnapshotIntegrityError> {
    parse_filter_state_with_three_color(
        filters,
        policers,
        &[],
        interfaces,
        lo0_filter_v4,
        lo0_filter_v6,
    )
}

/// Build the complete FilterState from snapshot data, including stable
/// three-color policer runtimes.
pub(crate) fn parse_filter_state_with_three_color(
    filters: &[FirewallFilterSnapshot],
    policers: &[PolicerSnapshot],
    three_color_policers: &[ThreeColorPolicerSnapshot],
    interfaces: &[crate::InterfaceSnapshot],
    lo0_filter_v4: &str,
    lo0_filter_v6: &str,
) -> Result<FilterState, SnapshotIntegrityError> {
    parse_filter_state_with_three_color_preserving(
        filters,
        policers,
        three_color_policers,
        interfaces,
        lo0_filter_v4,
        lo0_filter_v6,
        None,
    )
}

/// Build the complete FilterState while preserving compatible three-color
/// policer token/counter state across snapshot refreshes.
pub(crate) fn parse_filter_state_with_three_color_preserving(
    filters: &[FirewallFilterSnapshot],
    policers: &[PolicerSnapshot],
    three_color_policers: &[ThreeColorPolicerSnapshot],
    interfaces: &[crate::InterfaceSnapshot],
    lo0_filter_v4: &str,
    lo0_filter_v6: &str,
    previous: Option<&FilterState>,
) -> Result<FilterState, SnapshotIntegrityError> {
    let mut state = FilterState::default();
    let mut used_runtime_ids = rustc_hash::FxHashSet::default();
    load_three_color_policer_runtimes(
        &mut state,
        three_color_policers,
        previous,
        &mut used_runtime_ids,
    );
    lower_single_rate_policer_runtimes(&mut state, policers, previous, &mut used_runtime_ids);
    // #6540: the set of policer names this snapshot DEFINES, across both
    // stanzas. Built from the wire slices rather than
    // `state.three_color_policer_by_name` on purpose — the #4514 single-rate
    // lowering above deliberately SKIPS a degenerate zero-rate meter-only
    // policer (it has no action to enforce), so that policer is defined but
    // absent from the runtime map. Rejecting on absence from the MAP would
    // refuse a config that boots today; rejecting on absence from this SET is
    // the same question the Go strict gate asks.
    let defined_policers: rustc_hash::FxHashSet<&str> = policers
        .iter()
        .map(|p| p.name.as_str())
        .chain(three_color_policers.iter().map(|p| p.name.as_str()))
        .collect();
    parse_filter_table(&mut state, filters, &defined_policers)?;
    assign_interface_filters(&mut state, interfaces)?;
    recompute_fast_map_aggregates(&mut state);
    state.lo0_filter_v4_fast = resolve_lo0_filter(&state.filters, "inet", lo0_filter_v4)?;
    state.lo0_filter_v6_fast = resolve_lo0_filter(&state.filters, "inet6", lo0_filter_v6)?;

    Ok(state)
}

/// Parse three-color policers by stable name order. Runtime IDs are
/// name-derived so inserting a lower-sorted policer does not reset
/// unchanged existing runtimes.
fn load_three_color_policer_runtimes(
    state: &mut FilterState,
    three_color_policers: &[ThreeColorPolicerSnapshot],
    previous: Option<&FilterState>,
    used_runtime_ids: &mut rustc_hash::FxHashSet<u32>,
) {
    let mut three_color = three_color_policers.iter().collect::<Vec<_>>();
    three_color.sort_by(|a, b| a.name.cmp(&b.name));
    for snap in three_color {
        let id = unique_three_color_policer_runtime_id(&snap.name, used_runtime_ids);
        let Some(runtime) = parse_three_color_policer(snap, id, previous) else {
            continue;
        };
        state
            .three_color_policer_by_name
            .insert(runtime.name.to_string(), runtime.clone());
        state.three_color_policers.push(runtime);
    }
}

/// #4514: lower legacy single-rate `firewall policer` token buckets into the
/// SAME metered three-color runtime the terms already resolve against, by
/// name. Before #4514 these policers were parsed into a `state.policers`
/// map that NOTHING consumed — `PolicerState::consume` had zero non-test
/// call sites — so a configured `then policer X` (e.g. a DoS-mitigation
/// rate-limit) was silently UNENFORCED (a fail-open of the rate limit) even
/// though the capability doc claimed support. A single-rate token bucket
/// with `then discard` is exactly an srTCM committed bucket (CIR=bandwidth,
/// CBS=burst) where only in-rate (green) packets pass and everything above
/// the bucket drops; reusing the three-color runtime gives it metering,
/// drop-on-exceed, flow-cache handle+replay, and status export for free.
/// Sorted for the same stable-ID property as the three-color loop.
fn lower_single_rate_policer_runtimes(
    state: &mut FilterState,
    policers: &[PolicerSnapshot],
    previous: Option<&FilterState>,
    used_runtime_ids: &mut rustc_hash::FxHashSet<u32>,
) {
    let mut single_rate = policers.iter().collect::<Vec<_>>();
    single_rate.sort_by(|a, b| a.name.cmp(&b.name));
    for snap in single_rate {
        // A three-color policer of the same name already claimed this name and
        // takes precedence (distinct config stanzas; collision only on drift).
        if state.three_color_policer_by_name.contains_key(&snap.name) {
            continue;
        }
        let id = unique_runtime_id(single_rate_policer_runtime_id(&snap.name), used_runtime_ids);
        let Some(runtime) = parse_single_rate_policer_runtime(snap, id, previous) else {
            continue;
        };
        state
            .three_color_policer_by_name
            .insert(runtime.name.to_string(), runtime.clone());
        state.three_color_policers.push(runtime);
    }
}

/// Parse every filter snapshot into a compiled `Filter` keyed by
/// `family:name`. Term compilation fails closed (see `parse_term`), so one
/// unrepresentable term rejects the whole snapshot.
fn parse_filter_table(
    state: &mut FilterState,
    filters: &[FirewallFilterSnapshot],
    defined_policers: &rustc_hash::FxHashSet<&str>,
) -> Result<(), SnapshotIntegrityError> {
    for (filter_idx, snap) in filters.iter().enumerate() {
        let key = qualify_filter_key(&snap.family, &snap.name);
        let terms = snap
            .terms
            .iter()
            .enumerate()
            .map(|(term_idx, t)| {
                parse_term(
                    t,
                    term_idx as u32,
                    &snap.family,
                    &snap.name,
                    &state.three_color_policer_by_name,
                    defined_policers,
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        let filter = Filter {
            id: filter_idx as u32,
            name: snap.name.clone(),
            family: snap.family.clone(),
            affects_tx_selection: terms
                .iter()
                .any(|term| !term.forwarding_class.is_empty() || term.dscp_rewrite.is_some()),
            affects_route_lookup: terms.iter().any(|term| !term.routing_instance.is_empty()),
            has_counter_terms: terms.iter().any(|term| term.has_count),
            has_log_terms: terms.iter().any(|term| term.log),
            has_terminal_action_terms: terms.iter().any(|term| term.action != FilterAction::Accept),
            has_dscp_match_terms: terms.iter().any(|term| term.dscp_match_enabled),
            has_per_packet_l4_match_terms: terms.iter().any(|term| term.has_per_packet_l4_match()),
            has_three_color_policer_terms: terms
                .iter()
                .any(|term| term.three_color_policer.is_some()),
            terms,
        };
        state.filters.insert(key, Arc::new(filter));
    }
    Ok(())
}

/// Build per-interface filter assignments: each of the four hooks
/// (inet/inet6 x input/output) resolves its named filter against the
/// compiled table and installs it into the per-ifindex fast map.
fn assign_interface_filters(
    state: &mut FilterState,
    interfaces: &[crate::InterfaceSnapshot],
) -> Result<(), SnapshotIntegrityError> {
    for iface in interfaces {
        if iface.ifindex <= 0 {
            continue;
        }
        if !iface.filter_input_v4.is_empty() {
            resolve_interface_filter(
                &state.filters,
                &mut state.iface_filter_v4_fast,
                iface,
                "inet",
                "input",
                &iface.filter_input_v4,
            )?;
        }
        if !iface.filter_output_v4.is_empty() {
            resolve_interface_filter(
                &state.filters,
                &mut state.iface_filter_out_v4_fast,
                iface,
                "inet",
                "output",
                &iface.filter_output_v4,
            )?;
        }
        if !iface.filter_input_v6.is_empty() {
            resolve_interface_filter(
                &state.filters,
                &mut state.iface_filter_v6_fast,
                iface,
                "inet6",
                "input",
                &iface.filter_input_v6,
            )?;
        }
        if !iface.filter_output_v6.is_empty() {
            resolve_interface_filter(
                &state.filters,
                &mut state.iface_filter_out_v6_fast,
                iface,
                "inet6",
                "output",
                &iface.filter_output_v6,
            )?;
        }
    }
    Ok(())
}

/// Resolve one interface filter hook into its fast map.
///
/// #3296: the hook may name a filter that is not in the compiled table.
/// Leaving no _fast entry would fall through to the default Accept (and, for
/// an output hook, skip the TX evaluator entirely — no _fast entry AND no
/// needs_tx_eval flag) — a fail-open on a typo'd security hook. Refuse the
/// snapshot instead (the reconcile preflight preserves prior good state).
///
/// #6236 PR-2A: the family-wide aggregates
/// (has_input_tx_selection_v4 / has_input_three_color_policer_v4 /
/// has_output_needs_tx_eval_*) are recomputed from the FINAL fast maps by
/// `recompute_fast_map_aggregates` after the assignment loop, so a
/// duplicate-ifindex last-wins overwrite cannot strand a stale-true
/// aggregate. Do not OR them in here.
///
/// #6236 PR-2B: the per-interface capability sets
/// (affects_route_lookup / has_dscp_match / has_per_packet_l4_match /
/// iface_filter_out_*_needs_tx_eval) are gone — the accessors read the flag
/// off the fast map entry (`Filter::needs_tx_eval()` for the output hooks),
/// so populating the fast map here is the only per-interface work.
fn resolve_interface_filter(
    filters: &rustc_hash::FxHashMap<String, Arc<Filter>>,
    fast_map: &mut rustc_hash::FxHashMap<i32, Arc<Filter>>,
    iface: &crate::InterfaceSnapshot,
    family: &'static str,
    direction: &'static str,
    filter_name: &str,
) -> Result<(), SnapshotIntegrityError> {
    let key = qualify_filter_key(family, filter_name);
    if let Some(filter) = filters.get(&key) {
        fast_map.insert(iface.ifindex, filter.clone());
        return Ok(());
    }
    Err(SnapshotIntegrityError::MissingFilterRef {
        interface: iface.name.clone(),
        family: family.to_string(),
        direction: direction.to_string(),
        filter: filter_name.to_string(),
    })
}

/// #6236 PR-2A: recompute the family-wide aggregates from the FINAL fast
/// maps, NOT monotonically inside the assignment loop. The fast maps
/// overwrite last-wins on a duplicate ifindex, so a positive filter followed
/// by a non-sensitive filter at the same ifindex must NOT leave a stale-true
/// aggregate. Deriving every aggregate from `values().any(..)` over the final
/// map makes it agree with the filter the hot path actually evaluates (the
/// last-wins entry). For the common unique-ifindex case this is bit-identical
/// to the old in-loop OR. `has_output_needs_tx_eval_*` is the aggregate that
/// subsumes both `has_output_tx_selection_*` and the
/// `iface_filter_out_*_needs_tx_eval` set non-emptiness for the global gate.
fn recompute_fast_map_aggregates(state: &mut FilterState) {
    state.has_input_tx_selection_v4 = state
        .iface_filter_v4_fast
        .values()
        .any(|f| f.affects_tx_selection);
    state.has_input_tx_selection_v6 = state
        .iface_filter_v6_fast
        .values()
        .any(|f| f.affects_tx_selection);
    state.has_input_three_color_policer_v4 = state
        .iface_filter_v4_fast
        .values()
        .any(|f| f.has_three_color_policer_terms);
    state.has_input_three_color_policer_v6 = state
        .iface_filter_v6_fast
        .values()
        .any(|f| f.has_three_color_policer_terms);
    // #6236 PR-2B: `has_output_tx_selection_v*` is deleted — the global TX gate
    // reads only `has_output_needs_tx_eval_*` (which is a superset), so the
    // `affects_tx_selection`-only aggregate is no longer computed.
    state.has_output_needs_tx_eval_v4 = state
        .iface_filter_out_v4_fast
        .values()
        .any(|f| f.needs_tx_eval());
    state.has_output_needs_tx_eval_v6 = state
        .iface_filter_out_v6_fast
        .values()
        .any(|f| f.needs_tx_eval());
}

/// Resolve one lo0 host-bound input filter hook. Returns `Ok(None)` when the
/// hook is unconfigured.
///
/// #3296: a configured hook that names a filter not in the table is refused.
/// Falling through to the default Accept would leave the routing-engine
/// protect filter unarmed (the canonical lo0 lockout hook) — fail-open.
///
/// #6236 PR-1: the qualified lo0 key is a compiler intermediate only — it
/// exists solely to resolve the fast filter and was never read on the packet
/// path, so it stays a local here; the struct retains only the fast
/// Option<Arc<Filter>>.
fn resolve_lo0_filter(
    filters: &rustc_hash::FxHashMap<String, Arc<Filter>>,
    family: &'static str,
    filter_name: &str,
) -> Result<Option<Arc<Filter>>, SnapshotIntegrityError> {
    if filter_name.is_empty() {
        return Ok(None);
    }
    let key = qualify_filter_key(family, filter_name);
    if let Some(filter) = filters.get(&key) {
        return Ok(Some(filter.clone()));
    }
    Err(SnapshotIntegrityError::MissingFilterRef {
        interface: "lo0".to_string(),
        family: family.to_string(),
        direction: "input".to_string(),
        filter: filter_name.to_string(),
    })
}

fn parse_three_color_policer(
    snap: &ThreeColorPolicerSnapshot,
    id: u32,
    previous: Option<&FilterState>,
) -> Option<Arc<ThreeColorPolicerRuntime>> {
    let state = build_three_color_policer_state(snap)
        .unwrap_or_else(|| ThreeColorPolicerState::fail_closed(snap.color_blind));
    if let Some(previous_runtime) =
        previous.and_then(|prev| prev.three_color_policer_by_name.get(&snap.name))
    {
        if previous_runtime.reusable_for(id, &state) {
            return Some(Arc::clone(previous_runtime));
        }
    }
    Some(Arc::new(ThreeColorPolicerRuntime::new(
        id,
        snap.name.clone(),
        state,
    )))
}

fn unique_three_color_policer_runtime_id(
    name: &str,
    used_ids: &mut rustc_hash::FxHashSet<u32>,
) -> u32 {
    unique_runtime_id(three_color_policer_runtime_id(name), used_ids)
}

/// Ensure `id` is not already taken in `used_ids`, probing forward (skipping 0)
/// until a free slot is found, then reserving it. Shared by the three-color and
/// #4514 single-rate lowering loops so their name-derived runtime IDs never
/// collide with one another.
fn unique_runtime_id(mut id: u32, used_ids: &mut rustc_hash::FxHashSet<u32>) -> u32 {
    while !used_ids.insert(id) {
        id = id.wrapping_add(1);
        if id == 0 {
            id = 1;
        }
    }
    id
}

fn fnv_runtime_id(namespace: &[u8], name: &str) -> u32 {
    const FNV_OFFSET_BASIS: u32 = 0x811c_9dc5;
    const FNV_PRIME: u32 = 0x0100_0193;

    let mut hash = FNV_OFFSET_BASIS;
    for byte in namespace.iter().chain(name.as_bytes()) {
        hash ^= u32::from(*byte);
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    if hash == 0 { 1 } else { hash }
}

pub(crate) fn three_color_policer_runtime_id(name: &str) -> u32 {
    fnv_runtime_id(b"xpf-three-color-policer-v1:", name)
}

/// #4514: single-rate policers live in a DISTINCT ID namespace from
/// three-color policers so a same-named policer of each kind (only reachable via
/// snapshot drift) cannot alias to one runtime handle.
fn single_rate_policer_runtime_id(name: &str) -> u32 {
    fnv_runtime_id(b"xpf-single-rate-policer-v1:", name)
}

/// #4514: build the metered three-color runtime that enforces a legacy
/// single-rate `firewall policer`, preserving compatible token/counter state
/// across snapshot refreshes exactly like `parse_three_color_policer`. Returns
/// `None` only when the policer has nothing to enforce (a degenerate non-discard
/// meter-only policer with zero rate/burst — see `build_single_rate_policer_state`).
fn parse_single_rate_policer_runtime(
    snap: &PolicerSnapshot,
    id: u32,
    previous: Option<&FilterState>,
) -> Option<Arc<ThreeColorPolicerRuntime>> {
    let state = match build_single_rate_policer_state(snap) {
        Some(state) => state,
        // A `then discard` policer with a degenerate (zero) rate/burst admits no
        // traffic — fail CLOSED (drop all) rather than leave the rate-limit
        // silently unenforced, mirroring the three-color unsupported-snapshot
        // backstop. A degenerate non-discard (meter-only) policer has no action
        // to enforce, so skip it.
        None if snap.discard_excess => ThreeColorPolicerState::fail_closed(true),
        None => return None,
    };
    if let Some(previous_runtime) =
        previous.and_then(|prev| prev.three_color_policer_by_name.get(&snap.name))
    {
        if previous_runtime.reusable_for(id, &state) {
            return Some(Arc::clone(previous_runtime));
        }
    }
    Some(Arc::new(ThreeColorPolicerRuntime::new(
        id,
        snap.name.clone(),
        state,
    )))
}

/// #4514: map a legacy single-rate token-bucket policer to an srTCM state.
///
/// `bandwidth-limit` is bits/sec (the pre-#4514 `PolicerState` bits/sec
/// constructor contract); the srTCM committed bucket is bytes/sec, so divide by
/// 8. The committed bucket (CIR=bandwidth, CBS=burst) IS the single-rate token
/// bucket. For `then discard`, only in-rate GREEN packets pass — YELLOW and RED
/// both drop, so the (required, non-zero) excess bucket is irrelevant to the
/// pass/drop decision and CBS is reused as EBS. `color-blind` is always true: a
/// single-rate policer has no notion of inherited packet color.
///
/// A non-discard policer (`then loss-priority` / `then forwarding-class`) is
/// METERED but not acted upon — the marking action is not wired here (same
/// limitation as three-color `then loss-priority`, documented in the module
/// README). Returns `None` for a zero rate/burst so the caller can fail-closed
/// (discard) or skip (meter-only).
fn build_single_rate_policer_state(snap: &PolicerSnapshot) -> Option<ThreeColorPolicerState> {
    let committed_rate_bytes_per_sec = snap.bandwidth_bps / 8;
    let burst_bytes = snap.burst_bytes;
    if committed_rate_bytes_per_sec == 0 || burst_bytes == 0 {
        return None;
    }
    let treatments = if snap.discard_excess {
        ThreeColorTreatments {
            green: ColorTreatment::default(),
            yellow: ColorTreatment::drop(),
            red: ColorTreatment::drop(),
        }
    } else {
        ThreeColorTreatments::default()
    };
    ThreeColorPolicerState::sr_tcm_with_treatments(
        committed_rate_bytes_per_sec,
        burst_bytes,
        burst_bytes,
        true,
        treatments,
    )
    .ok()
}

fn build_three_color_policer_state(
    snap: &ThreeColorPolicerSnapshot,
) -> Option<ThreeColorPolicerState> {
    if !snapshot_three_color_shape_supported(snap) {
        return None;
    }

    let treatments = treatments_from_then_action(&snap.then_action);
    match snap.mode.as_str() {
        "single-rate" => ThreeColorPolicerState::sr_tcm_with_treatments(
            snap.committed_rate_bytes_per_sec,
            snap.committed_burst_bytes,
            snap.peak_or_excess_burst_bytes,
            snap.color_blind,
            treatments,
        )
        .ok(),
        "two-rate" => ThreeColorPolicerState::tr_tcm_with_treatments(
            snap.committed_rate_bytes_per_sec,
            snap.committed_burst_bytes,
            snap.peak_or_excess_rate_bytes_per_sec,
            snap.peak_or_excess_burst_bytes,
            snap.color_blind,
            treatments,
        )
        .ok(),
        _ => None,
    }
}

/// #9503: `loss-priority <level>` is admitted as METER-ONLY:
/// `treatments_from_then_action` gives it the no-drop default, the same
/// posture a plain policer's marking action has. Refusing it here failed the
/// referencing terms closed (every packet dropped), and on the Go side the
/// matching capability refusal disarmed forwarding on every binding. An
/// action neither side knows still fails closed, as a drift guard; the Go
/// mirror is `threeColorThenActionSupported`.
fn snapshot_three_color_shape_supported(snap: &ThreeColorPolicerSnapshot) -> bool {
    snap.color_blind
        && (snap.then_action.is_empty()
            || snap.then_action == "discard"
            || snap.then_action.starts_with("loss-priority "))
}

fn treatments_from_then_action(action: &str) -> ThreeColorTreatments {
    if action.is_empty() || action == "discard" {
        return ThreeColorTreatments {
            red: ColorTreatment::drop(),
            ..ThreeColorTreatments::default()
        };
    }
    ThreeColorTreatments::default()
}

fn qualify_filter_key(family: &str, filter_name: &str) -> String {
    format!("{family}:{filter_name}")
}

/// #6540 fail-closed backstop for `then policer <name>`: reject the whole
/// snapshot when a term references a policer the snapshot never defines, rather
/// than resolving it to `None` and silently forwarding unpoliced. See
/// `SnapshotIntegrityError::MissingPolicerRef` for why this asks about
/// DEFINEDNESS and not about the compiled runtime map.
fn preflight_term_policer_ref(
    snap: &FirewallTermSnapshot,
    filter_family: &str,
    filter_name: &str,
    defined_policers: &rustc_hash::FxHashSet<&str>,
) -> Result<(), SnapshotIntegrityError> {
    if snap.policer.is_empty() || defined_policers.contains(snap.policer.as_str()) {
        return Ok(());
    }
    Err(SnapshotIntegrityError::MissingPolicerRef {
        family: filter_family.to_string(),
        filter: filter_name.to_string(),
        term: snap.name.clone(),
        policer: snap.policer.clone(),
    })
}

fn parse_term(
    snap: &FirewallTermSnapshot,
    id: u32,
    filter_family: &str,
    filter_name: &str,
    three_color_policers: &rustc_hash::FxHashMap<String, Arc<ThreeColorPolicerRuntime>>,
    defined_policers: &rustc_hash::FxHashSet<&str>,
) -> Result<FilterTerm, SnapshotIntegrityError> {
    // Non-mutating preflight first: every guard rejects the WHOLE snapshot
    // (the reconcile preflight keeps the previous good filter state), so all
    // of them run before any lowering begins.
    preflight_term_markers(snap, filter_family, filter_name)?;
    preflight_term_value_ranges(snap, filter_family, filter_name)?;
    preflight_term_policer_ref(snap, filter_family, filter_name, defined_policers)?;
    let addresses = parse_term_addresses(snap);
    let protocols = resolve_term_protocols(snap, filter_family, filter_name)?;
    check_cross_field_satisfiability(snap, &protocols, filter_family, filter_name)?;
    let ports = parse_term_ports(snap);
    let action = resolve_term_action(snap);
    Ok(build_filter_term(
        snap,
        id,
        action,
        addresses,
        protocols,
        ports,
        three_color_policers,
    ))
}

/// Fail-closed preflight over the Go control plane's "unrepresentable" wire
/// markers. Each marker means the builder could not resolve a match token but
/// still emitted the term; the pre-fix compiler dropped the bad token (or
/// left the field absent), which the matcher reads as "no constraint" —
/// silently WIDENING a `then discard`/`reject` term, or enforcing a NARROWER
/// set than the operator wrote with the remainder falling through to the
/// implicit accept. Every guard rejects the whole snapshot, mirroring the
/// #2505 UnrepresentableFilterProtocol backstop. Checked first so the
/// preflight stays non-mutating.
fn preflight_term_markers(
    snap: &FirewallTermSnapshot,
    filter_family: &str,
    filter_name: &str,
) -> Result<(), SnapshotIntegrityError> {
    // #3367: the Go control plane sets `tcp_flags_unparseable` when it could not
    // parse the term's tcp-flags expression into required/forbidden masks. Leaving
    // the masks None (the pre-fix behavior) makes the matcher treat the term as
    // having NO tcp-flags constraint — silently widening a `then discard`/`reject`
    // term to match every TCP segment (fail-WIDE). Fail the whole snapshot closed
    // instead, mirroring the #2505 UnrepresentableFilterProtocol backstop. Checked
    // first so the preflight stays non-mutating.
    if snap.tcp_flags_unparseable {
        return Err(SnapshotIntegrityError::UnrepresentableFilterTCPFlags {
            family: filter_family.to_string(),
            filter: filter_name.to_string(),
            term: snap.name.clone(),
        });
    }
    // #3406: the Go control plane sets these markers when it could not resolve a
    // `from icmp-type`/`icmp-code` token to a byte in 0..255, or a `from dscp`
    // match token to a code-point/0..63. The pre-fix builder dropped the bad token
    // and emitted only the resolved values; an all-unresolvable list emitted an
    // EMPTY vector, which the matcher reads as "no constraint" — silently widening
    // the term (fail-WIDE for a `then discard`/`reject`). Fail the whole snapshot
    // closed instead, mirroring the #2505/#3367 backstops. Checked before any
    // mutation so the preflight stays non-mutating.
    if snap.icmp_type_unrepresentable {
        return Err(SnapshotIntegrityError::UnrepresentableFilterICMP {
            family: filter_family.to_string(),
            filter: filter_name.to_string(),
            term: snap.name.clone(),
            dimension: "icmp-type",
        });
    }
    if snap.icmp_code_unrepresentable {
        return Err(SnapshotIntegrityError::UnrepresentableFilterICMP {
            family: filter_family.to_string(),
            filter: filter_name.to_string(),
            term: snap.name.clone(),
            dimension: "icmp-code",
        });
    }
    if snap.dscp_match_unrepresentable {
        return Err(SnapshotIntegrityError::UnrepresentableFilterDSCP {
            family: filter_family.to_string(),
            filter: filter_name.to_string(),
            term: snap.name.clone(),
        });
    }
    // #6459: the Go control plane sets `ports_unrepresentable` when a
    // `from {source,destination}-port[-except]` token could not be resolved to
    // a number (an unknown service name, a malformed range, or a non-canonical
    // token such as "+80" — recorded on term.UnknownPorts; the strict commit
    // gate validateFilterMatchValuesStrict rejects it, so a committed config
    // never sets this). The token is kept VERBATIM in the wire port lists, and
    // the pre-fix compiler dropped it PER-TOKEN below
    // (`filter_map(parse_port_spec)`): a PARTIALLY-unresolvable list then built
    // a matcher over only the surviving subset, so a `then discard`/`reject`
    // term silently enforced a NARROWER port set than the operator wrote — the
    // traffic meant for the dropped ports fell through to the implicit accept
    // (fail-OPEN). (An ALL-unresolvable list already failed closed at
    // match-time via `constrained && PortMatcher::Any`, #2400/#3205.) Fail the
    // whole snapshot closed instead, mirroring the #2505/#3367/#3406
    // backstops. Checked before any mutation so the preflight stays
    // non-mutating.
    if snap.ports_unrepresentable {
        return Err(SnapshotIntegrityError::UnrepresentableFilterPorts {
            family: filter_family.to_string(),
            filter: filter_name.to_string(),
            term: snap.name.clone(),
        });
    }
    // #6463: the Go control plane sets `address_unrepresentable` when a
    // literal `from source-address` / `destination-address` token is not a
    // parseable IP/CIDR (classifyFilterAddrFamily rejects it; the strict
    // commit gate validateFilterAddressLiteralsStrict rejects it, so a
    // committed config never sets this). The pre-fix `parse_address` dropped
    // such a token PER-TOKEN (its `Err(_)` arm pushed nothing): a
    // PARTIALLY-malformed list then matched only the surviving prefixes, so a
    // `then discard`/`reject` term silently enforced a NARROWER address set
    // than the operator wrote — a host in the dropped range was accepted by
    // fall-through (fail-OPEN). (An ALL-malformed direction already failed
    // closed at match-time via `constrained && empty`, #2400.) Fail the whole
    // snapshot closed instead, same shape as the port marker above.
    if snap.address_unrepresentable {
        return Err(SnapshotIntegrityError::UnrepresentableFilterAddress {
            family: filter_family.to_string(),
            filter: filter_name.to_string(),
            term: snap.name.clone(),
        });
    }
    Ok(())
}

/// Fail-closed preflight over raw wire VALUES the Go gates already bound: a
/// value outside the representable range can only arrive from a corrupt /
/// hand-built / version-drifted snapshot. Checked before any mutation so the
/// preflight stays non-mutating.
fn preflight_term_value_ranges(
    snap: &FirewallTermSnapshot,
    filter_family: &str,
    filter_name: &str,
) -> Result<(), SnapshotIntegrityError> {
    // #3715: DSCP is a 6-bit field (0..=63). A raw wire value >= 64 can only
    // arrive from a corrupt / hand-built / version-drifted snapshot — the Go
    // commit gate (validateFilterDSCPStrict) and the snapshot builder both bound
    // DSCP to a code-point name or 0..63. A `dscp_values` entry >= 64 is silently
    // SKIPPED by build_u6_match_bitmap (its `value < 64` guard) while
    // dscp_match_enabled stays true — the term then matches only the in-range
    // subset (fail-WIDE / silently-wrong); a `dscp_rewrite` >= 64 was MASKED with
    // & 0x3f below, turning e.g. 110 into 46 (EF) and marking traffic with a code
    // point the operator never authored. Range-check both here, in the
    // non-mutating preflight, and fail the snapshot closed (the reconcile preflight
    // keeps the previous good filter state), mirroring the #3406 flex_match length
    // check above.
    if let Some(&value) = snap.dscp_values.iter().find(|&&v| v > 63) {
        return Err(SnapshotIntegrityError::FilterDSCPOutOfRange {
            family: filter_family.to_string(),
            filter: filter_name.to_string(),
            term: snap.name.clone(),
            dimension: "match",
            value,
        });
    }
    if let Some(value) = snap.dscp_rewrite {
        if value > 63 {
            return Err(SnapshotIntegrityError::FilterDSCPOutOfRange {
                family: filter_family.to_string(),
                filter: filter_name.to_string(),
                term: snap.name.clone(),
                dimension: "rewrite",
                value,
            });
        }
    }
    // #3406: a present flex_match whose byte length is outside 1..=4 is
    // unrepresentable (the value/mask wire fields are u32). The pre-fix Go builder
    // capped an oversized width to 4 and still emitted the term, so only the
    // truncated window was compared and the match BROADENED (fail-open); the
    // matcher's `flex_enabled` derivation below would also silently disable an
    // out-of-range flex (no constraint = match-any). Fail the snapshot closed.
    if let Some(fm) = snap.flex_match.as_ref() {
        if !(1..=4).contains(&fm.length) {
            return Err(SnapshotIntegrityError::UnrepresentableFilterFlexMatch {
                family: filter_family.to_string(),
                filter: filter_name.to_string(),
                term: snap.name.clone(),
                length: fm.length,
            });
        }
    }
    Ok(())
}

/// The address half of a term's match scope: per-family prefix vectors plus
/// the per-direction constrained flags (#2400/#2506).
struct TermAddressMatch {
    source_v4: Vec<PrefixV4>,
    source_v6: Vec<PrefixV6>,
    dest_v4: Vec<PrefixV4>,
    dest_v6: Vec<PrefixV6>,
    source_constrained: bool,
    dest_constrained: bool,
}

/// Lower the snapshot's `from {source,destination}-address` lists into
/// per-family prefix vectors and derive the per-direction constrained flags.
///
/// #2400 (032-18): a term is ADDRESS-CONSTRAINED when it has at least one
/// REAL `from { source-address / destination-address }` entry — `addr_is_real`
/// EXCLUDES the empty string and the literal `any` (the placeholders
/// `parse_address` already drops), so an explicit `from { source-address
/// any; }` stays UNCONSTRAINED (match-any) rather than degrading to
/// fail-closed. When the term is constrained but every real entry failed to
/// parse, the per-family vecs are empty and the matcher fails closed (see
/// engine/matching.rs).
///
/// #2506 (Copilot): OR in the EXPLICIT `source_constrained` /
/// `destination_constrained` snapshot signal. The address-length derivation
/// alone is insufficient for prefix-list scopes that resolve EMPTY: a `from
/// source-prefix-list X` whose X is defined-but-empty or lenient-unresolved
/// produces an empty `source_addresses` list, so the length test yields
/// `false` and the direction would wrongly collapse to match-any. The Go side
/// sets the explicit flag whenever the term wrote ANY scope (literal address
/// OR prefix-list ref), so the OR makes the matcher fail closed (positive) /
/// match-all (except) per the Junos empty-set semantics. An older Go control
/// plane that omits the flag (false) falls back to the length derivation —
/// unchanged for the non-prefix-list cases that have no empty-resolution gap.
fn parse_term_addresses(snap: &FirewallTermSnapshot) -> TermAddressMatch {
    let mut source_v4 = Vec::new();
    let mut source_v6 = Vec::new();
    for addr in &snap.source_addresses {
        parse_address(addr, &mut source_v4, &mut source_v6);
    }
    let mut dest_v4 = Vec::new();
    let mut dest_v6 = Vec::new();
    for addr in &snap.destination_addresses {
        parse_address(addr, &mut dest_v4, &mut dest_v6);
    }
    TermAddressMatch {
        source_v4,
        source_v6,
        dest_v4,
        dest_v6,
        source_constrained: snap.source_constrained
            || snap.source_addresses.iter().any(|a| addr_is_real(a)),
        dest_constrained: snap.destination_constrained
            || snap.destination_addresses.iter().any(|a| addr_is_real(a)),
    }
}

/// Resolve every `from protocol` token to its IANA number.
///
/// #2505: resolve via the SHARED, normalizing resolver
/// `ip_proto::proto_number` (trim + lowercase + the full
/// appid.ProtocolNumber acceptance set: esp/ah/sctp/vrrp/igmp/pim/egp +
/// the junos-* aliases), NOT the stale local parser this function used to
/// carry (tcp/udp/icmp/icmpv6/gre/ospf/ipip + bare numeric, no
/// normalization). An EMPTY input list is the legitimate "no protocol
/// constraint" case -> empty `protocols` -> `protocol_match_enabled` false
/// (match-any, preserved by the caller). A NON-EMPTY list with any
/// UNRESOLVABLE token is a snapshot-integrity error: silently dropping it
/// (the pre-fix `filter_map`) collapses the list to empty and disables the
/// protocol match, so a `from protocol esp; then discard` term would match
/// EVERY protocol (fail-WIDE). Fail closed by rejecting the whole snapshot —
/// the reconcile preflight keeps the previous good filter state.
fn resolve_term_protocols(
    snap: &FirewallTermSnapshot,
    filter_family: &str,
    filter_name: &str,
) -> Result<Vec<u8>, SnapshotIntegrityError> {
    let mut protocols: Vec<u8> = Vec::with_capacity(snap.protocols.len());
    for token in &snap.protocols {
        // An empty / whitespace-only entry is a placeholder, never a real
        // constraint (the Go side only emits `protocols` when `term.Protocol
        // != ""`); treat it as "no protocol" rather than an integrity error,
        // mirroring the pre-fix `parse_protocol("")` -> None drop.
        if token.trim().is_empty() {
            continue;
        }
        match proto_number(token) {
            Some(n) => protocols.push(n),
            None => {
                return Err(SnapshotIntegrityError::UnrepresentableFilterProtocol {
                    family: filter_family.to_string(),
                    filter: filter_name.to_string(),
                    term: snap.name.clone(),
                    token: token.clone(),
                });
            }
        }
    }
    Ok(protocols)
}

/// #3723: cross-field satisfiability backstop. A term whose resolved protocol
/// constraint is PRESENT but INCOMPATIBLE with a co-configured L4 predicate is
/// a NEVER-MATCH: the matcher (engine/matching.rs) keys ports on the extracted
/// L4 port (0 for a non-port protocol — only TCP/UDP carry ports per
/// ip_proto::has_l4_ports), gates tcp-flags on protocol==TCP, and gates
/// icmp-type/code on ICMP/ICMPv6. Because a filter falls through to the implicit
/// ACCEPT on no-match, a `then discard`/`reject` term over such a pair silently
/// fails OPEN. The Go commit gate (validateFilterCrossFieldStrict, #3723) is the
/// primary defense — a committed config never carries such a term — so this is
/// the helper-boundary backstop for a corrupt / hand-built / version-drifted or
/// leniently-loaded snapshot, consistent with the #2505/#3367/#3406 fail-closed
/// family. Rejecting the whole snapshot (the reconcile preflight keeps the
/// previous good filter state) is action-agnostic.
fn check_cross_field_satisfiability(
    snap: &FirewallTermSnapshot,
    protocols: &[u8],
    filter_family: &str,
    filter_name: &str,
) -> Result<(), SnapshotIntegrityError> {
    // An EMPTY protocol list is the legitimate "no protocol constraint" case:
    // a port / tcp-flags / icmp predicate with no protocol is enforceable for
    // a FILTER (the matcher matches the port on whatever port-bearing packet
    // arrives, and the tcp-flags/icmp arms self-gate on the packet protocol),
    // so it is NOT an error.
    if protocols.is_empty() {
        return Ok(());
    }
    let ports_present = snap.source_ports.iter().any(|p| port_is_real(p))
        || snap.destination_ports.iter().any(|p| port_is_real(p))
        || snap.source_ports_except.iter().any(|p| port_is_real(p))
        || snap.destination_ports_except.iter().any(|p| port_is_real(p));
    if ports_present {
        if let Some(&proto) = protocols
            .iter()
            .find(|&&p| !crate::ip_proto::has_l4_ports(p))
        {
            return Err(SnapshotIntegrityError::UnsatisfiableFilterCrossField {
                family: filter_family.to_string(),
                filter: filter_name.to_string(),
                term: snap.name.clone(),
                predicate: "port",
                protocol: proto,
            });
        }
    }
    let tcp_flags_present =
        snap.tcp_flags.is_some_and(|m| m != 0) || snap.tcp_flags_forbidden.is_some_and(|m| m != 0);
    if tcp_flags_present {
        if let Some(&proto) = protocols
            .iter()
            .find(|&&p| p != crate::ip_proto::PROTO_TCP)
        {
            return Err(SnapshotIntegrityError::UnsatisfiableFilterCrossField {
                family: filter_family.to_string(),
                filter: filter_name.to_string(),
                term: snap.name.clone(),
                predicate: "tcp-flags",
                protocol: proto,
            });
        }
    }
    let icmp_present = !snap.icmp_types.is_empty() || !snap.icmp_codes.is_empty();
    if icmp_present {
        if let Some(&proto) = protocols
            .iter()
            .find(|&&p| p != crate::ip_proto::PROTO_ICMP && p != crate::ip_proto::PROTO_ICMPV6)
        {
            return Err(SnapshotIntegrityError::UnsatisfiableFilterCrossField {
                family: filter_family.to_string(),
                filter: filter_name.to_string(),
                term: snap.name.clone(),
                predicate: "icmp-type/code",
                protocol: proto,
            });
        }
    }
    Ok(())
}

/// The port half of a term's match scope: per-direction range vectors plus
/// the except-inversion and constrained flags (#2400/#2622/#3716).
struct TermPortMatch {
    source_ports: Vec<PortRange>,
    dest_ports: Vec<PortRange>,
    source_except: bool,
    dest_except: bool,
    source_constrained: bool,
    dest_constrained: bool,
}

/// Lower the snapshot's port lists into per-direction range vectors.
///
/// #2622: a direction's port scope is either the positive `source-port` /
/// `destination-port` list OR the negated `source-port-except` /
/// `destination-port-except` list (Junos treats them as mutually exclusive,
/// and the Go commit gate `validateFilterPortExceptStrict` — #3297 — rejects
/// a term that carries both). Build ONE range set per direction from
/// whichever list carries entries, and set `*_except` when the except list is
/// the source.
///
/// #3716 positive-wins boundary contract: because #3297 rejects both-present
/// at commit, this only fires for a hand-built / version-drifted / leniently
/// loaded snapshot. When it does, the positive list builds the matcher and
/// the except list is IGNORED (positive wins) — the except flag stays false
/// so the positive set is honored verbatim. That is a deliberate NARROWING
/// (the term matches only the positive ports, strictly tighter than the
/// operator-authored except would have been), never a widening, so it is
/// fail-safe at the Rust boundary even without a SnapshotIntegrityError. The
/// status is pinned by `port_both_positive_and_except_positive_wins_3716` in
/// tests.rs so a future change to this selection is caught.
///
/// #2400 (032-19): mirror of the address constraint for the port match sets.
/// `port_is_real` ignores the empty-string placeholder (which `parse_port_spec`
/// treats as "no port range") so an empty entry never trips fail-closed. A
/// constrained port set whose entries ALL failed to parse yields zero ranges
/// -> `PortMatcher::Any`; the `*_constrained` flag lets the matcher tell
/// that apart from a genuinely unscoped term and fail closed. The constraint
/// is derived from the SELECTED spec list (positive or except), so an
/// except-only term is correctly constrained (#2622).
fn parse_term_ports(snap: &FirewallTermSnapshot) -> TermPortMatch {
    let source_except = snap.source_ports.iter().all(|p| !port_is_real(p))
        && snap.source_ports_except.iter().any(|p| port_is_real(p));
    let dest_except = snap.destination_ports.iter().all(|p| !port_is_real(p))
        && snap.destination_ports_except.iter().any(|p| port_is_real(p));
    let source_specs: &[String] = if source_except {
        &snap.source_ports_except
    } else {
        &snap.source_ports
    };
    let dest_specs: &[String] = if dest_except {
        &snap.destination_ports_except
    } else {
        &snap.destination_ports
    };
    TermPortMatch {
        source_ports: source_specs
            .iter()
            .filter_map(|p| parse_port_spec(p))
            .flatten()
            .collect(),
        dest_ports: dest_specs
            .iter()
            .filter_map(|p| parse_port_spec(p))
            .flatten()
            .collect(),
        source_except,
        dest_except,
        source_constrained: source_specs.iter().any(|p| port_is_real(p)),
        dest_constrained: dest_specs.iter().any(|p| port_is_real(p)),
    }
}

/// Map the snapshot action string to a `FilterAction`.
///
/// #2399 (032-16) / #2544: an EMPTY action is the legitimate "no
/// terminating action" case — the term carries only modifiers
/// (count/log/forwarding-class/policer/dscp) and falls through to the
/// next term. Map it to Accept as a PLACEHOLDER (the action field is
/// never returned for a matched fall-through term — see `continue_term`
/// in `build_filter_term`), but the real semantic is carried by
/// FilterTerm.continue_term: the evaluator applies the modifiers and
/// CONTINUES rather than short-circuiting to a terminating decision. A
/// NON-EMPTY but unrecognized action string can only arrive from a
/// mixed-version snapshot (the Go commit gate validateFilterActionsStrict
/// rejects an unknown `then` token before it is persisted). For a FIREWALL
/// FILTER an unknown terminating action must fail CLOSED, never silently
/// permit — map it to Discard rather than Accept.
#[cfg(test)]
pub(crate) fn resolve_term_action_for_test(snap: &FirewallTermSnapshot) -> FilterAction {
    resolve_term_action(snap)
}

fn resolve_term_action(snap: &FirewallTermSnapshot) -> FilterAction {
    match snap.action.as_str() {
        "accept" => FilterAction::Accept,
        "reject" => FilterAction::Reject(super::resolve_reject_message(&snap.reject_message_type)),
        "discard" => FilterAction::Discard,
        "" => FilterAction::Accept,
        other => {
            eprintln!(
                "xpf-filter: term {:?} carries an unknown action {:?}; \
                 failing closed (discard) — snapshot/version drift",
                snap.name, other
            );
            FilterAction::Discard
        }
    }
}

/// The lowered flexible-match-range fields of a term (#3077/#3232).
struct TermFlexMatch {
    enabled: bool,
    offset: u8,
    length: u8,
    value: u32,
    mask: u32,
    match_start: FlexMatchStart,
}

/// #3077 flexible-match-range. Lower the wire snapshot into the per-term
/// match fields. A flex match is only enabled when the length is a sane
/// 1..=4 bytes (the wire value is a u32); a 0 or out-of-range length is
/// treated as "no constraint" rather than a degenerate always-fail match,
/// mirroring the Go side which already caps length to 4 and drops 0. The
/// value is pre-masked by the Go control plane; we re-AND defensively so
/// a hand-built snapshot with value bits outside the mask cannot match.
///
/// #3232: the match-start base. "" / "layer-3" => L3 base (the #3077
/// default); "layer-4" => transport-header base. The Go control plane
/// rejects payload/unknown at commit, but the tolerant peer-sync path
/// could still deliver one, so an unrecognized value lowers to
/// Unsupported and the matcher fails the term closed (never the
/// pre-#3232 silent L3-base mis-match).
fn lower_flex_match(flex_match: Option<&FlexMatchSnapshot>) -> TermFlexMatch {
    TermFlexMatch {
        enabled: flex_match.is_some_and(|f| (1..=4).contains(&f.length)),
        offset: flex_match.map_or(0, |f| f.offset),
        length: flex_match.map_or(0, |f| f.length),
        value: flex_match.map_or(0, |f| f.value & f.mask),
        mask: flex_match.map_or(0, |f| f.mask),
        match_start: match flex_match.map(|f| f.match_start.as_str()) {
            None | Some("") | Some("layer-3") => FlexMatchStart::Layer3,
            Some("layer-4") => FlexMatchStart::Layer4,
            Some(_) => FlexMatchStart::Unsupported,
        },
    }
}

/// Assemble the `FilterTerm` from the lowered match scope, action, and
/// modifiers. Pure construction — every fail-closed validation already ran
/// in the preflight helpers above.
fn build_filter_term(
    snap: &FirewallTermSnapshot,
    id: u32,
    action: FilterAction,
    addresses: TermAddressMatch,
    protocols: Vec<u8>,
    ports: TermPortMatch,
    three_color_policers: &rustc_hash::FxHashMap<String, Arc<ThreeColorPolicerRuntime>>,
) -> FilterTerm {
    let flex = lower_flex_match(snap.flex_match.as_ref());
    // #3715: no `& 0x3f` mask — the preflight already rejected any
    // dscp_rewrite >= 64, so the value is a valid 0..=63 code point verbatim.
    // Masking would silently turn a corrupt byte (e.g. 110) into a DIFFERENT
    // valid code point (46 = EF).
    let dscp_rewrite = snap.dscp_rewrite;
    FilterTerm {
        id,
        name: snap.name.clone(),
        source_v4: addresses.source_v4,
        source_v6: addresses.source_v6,
        dest_v4: addresses.dest_v4,
        dest_v6: addresses.dest_v6,
        source_addr_constrained: addresses.source_constrained,
        dest_addr_constrained: addresses.dest_constrained,
        // #2506: carry the per-direction `except` inversion flag from the
        // snapshot. The Go control plane only sets it when the address set is an
        // `except` prefix-list (the inversion is meaningful only against a
        // non-empty constrained set; see resolvePrefixListAddrs).
        source_except: snap.source_except,
        dest_except: snap.destination_except,
        protocol_bitmap: build_u8_match_bitmap(&protocols),
        protocol_match_enabled: !protocols.is_empty(),
        source_ports: build_port_matcher(ports.source_ports),
        dest_ports: build_port_matcher(ports.dest_ports),
        source_port_constrained: ports.source_constrained,
        dest_port_constrained: ports.dest_constrained,
        // #2622: carry the negated-port inversion flag (Junos `*-port-except`).
        source_port_except: ports.source_except,
        dest_port_except: ports.dest_except,
        dscp_bitmap: build_u6_match_bitmap(&snap.dscp_values),
        dscp_match_enabled: !snap.dscp_values.is_empty(),
        // #2362 per-packet L4 match conditions. A zero tcp_flags mask means
        // "no constraint" (would match every packet), so fold it to None — the
        // Go side already omits a 0 mask; this is a guard against a
        // hand-crafted snapshot.
        tcp_flags_mask: snap.tcp_flags.filter(|&m| m != 0),
        // #3076 forbidden-bits mask (negated tcp-flags operands). Same 0->None
        // fold as the required mask: a 0 forbidden mask is "no constraint", and
        // the Go side already omits a 0; this guards a hand-crafted snapshot.
        tcp_flags_forbidden: snap.tcp_flags_forbidden.filter(|&m| m != 0),
        is_fragment: snap.is_fragment,
        // #2545: icmp-type / icmp-code are SET membership (match-ANY). An empty
        // list = no constraint (`*_match_enabled` false → match any), preserving
        // the prior scalar-None behavior.
        icmp_type_bitmap: build_u8_match_bitmap(&snap.icmp_types),
        icmp_type_match_enabled: !snap.icmp_types.is_empty(),
        icmp_code_bitmap: build_u8_match_bitmap(&snap.icmp_codes),
        icmp_code_match_enabled: !snap.icmp_codes.is_empty(),
        flex_enabled: flex.enabled,
        flex_offset: flex.offset,
        flex_length: flex.length,
        flex_value: flex.value,
        flex_mask: flex.mask,
        flex_match_start: flex.match_start,
        action,
        // #2544: this term falls through (applies modifiers, continues to the
        // next term) when it carries no terminating action. The Go control
        // plane sets next_term for both the explicit `then next term` and the
        // modifier-only case. A term with an empty action falls through; a
        // routing-instance (PBR) term takes its own routing decision and is
        // NOT a fall-through even with an empty action.
        //
        // #5142 (fail-CLOSED): a term that carries a REAL terminating action
        // (accept/reject/discard) MUST terminate and apply that action, EVEN IF
        // next_term is also set. `then discard; next term;` is a contradiction:
        // the deny is a terminal, and a fall-through bit must NEVER suppress it
        // (vSRX filter semantics). Before #5142 this read `(snap.next_term ||
        // snap.action.is_empty()) && routing_instance.is_empty()`, so a
        // discard/reject term carrying next_term=true fell through and left the
        // `FilterResult::default()` implicit Accept in place — the deny was
        // silently dropped (fail-OPEN). The Go commit gate
        // (validateFilterTerminalConflictStrict) now rejects that contradiction,
        // but the tolerant peer-sync path could still deliver one, so the
        // runtime fails closed on its own: fall through ONLY when the action is
        // empty. An empty action stays a fall-through whether or not next_term
        // was set (belt-and-suspenders for an older Go control plane that omits
        // next_term but sends a modifier-only term).
        continue_term: snap.action.is_empty() && snap.routing_instance.is_empty(),
        count: snap.count.clone(),
        has_count: !snap.count.is_empty(),
        log: snap.log,
        // #5444: intern the modifier strings into `Arc<str>` once at compile
        // time (mirrors `forwarding_class`) so per-packet propagation into the
        // FilterResult accumulator is a refcount bump, not a String heap copy.
        policer_name: Arc::<str>::from(snap.policer.as_str()),
        three_color_policer: three_color_policers.get(&snap.policer).cloned(),
        routing_instance: Arc::<str>::from(snap.routing_instance.as_str()),
        forwarding_class: Arc::<str>::from(snap.forwarding_class.as_str()),
        dscp_rewrite,
        counter: Arc::new(FilterTermCounter::default()),
    }
}

/// #2400: whether an address entry imposes a real scope. `parse_address` drops
/// the empty string and the literal `any` as "no constraint" placeholders, so
/// they must NOT make a term address-constrained (otherwise `from {
/// source-address any; }` would fail closed). Every other entry — valid OR
/// malformed — is a real scope; an all-malformed list is exactly the fail-open
/// case #2400 closes.
fn addr_is_real(entry: &str) -> bool {
    !entry.is_empty() && entry != "any"
}

/// #2400: whether a port entry imposes a real scope. `parse_port_spec` treats
/// the empty string as "no port range", so an empty placeholder must NOT make a
/// term port-constrained. Every other entry — valid OR malformed — is a real
/// scope.
fn port_is_real(entry: &str) -> bool {
    !entry.is_empty()
}

fn parse_address(prefix: &str, out_v4: &mut Vec<PrefixV4>, out_v6: &mut Vec<PrefixV6>) {
    if prefix.is_empty() || prefix == "any" {
        return;
    }
    match prefix.parse::<IpNet>() {
        Ok(IpNet::V4(net)) => out_v4.push(PrefixV4::from_net(net)),
        Ok(IpNet::V6(net)) => out_v6.push(PrefixV6::from_net(net)),
        Err(_) => {
            if let Ok(ip) = prefix.parse::<Ipv4Addr>() {
                out_v4.push(PrefixV4::from_net(
                    ipnet::Ipv4Net::new(ip, 32).expect("v4 /32"),
                ));
            } else if let Ok(ip) = prefix.parse::<Ipv6Addr>() {
                out_v6.push(PrefixV6::from_net(
                    ipnet::Ipv6Net::new(ip, 128).expect("v6 /128"),
                ));
            }
        }
    }
}

fn parse_port_spec(spec: &str) -> Option<Vec<PortRange>> {
    if spec.is_empty() {
        return Some(Vec::new());
    }
    let normalized = match spec {
        "http" => "80",
        "https" => "443",
        "ssh" => "22",
        "telnet" => "23",
        "ftp" => "21",
        "ftp-data" => "20",
        "smtp" => "25",
        "dns" => "53",
        "pop3" => "110",
        "imap" => "143",
        "snmp" => "161",
        "ntp" => "123",
        "bgp" => "179",
        "ldap" => "389",
        "syslog" => "514",
        other => other,
    };
    if let Some((low, high)) = normalized.split_once('-') {
        // #6477: route through the SHARED digit-only `parse_port_u16`
        // (policy.rs, #3606) — Rust's u16 FromStr accepts a leading '+'
        // ("+80" -> Ok(80)), which the Go commit gate and the policy-side
        // parser both reject. This parser accepting "+80" while the other
        // three reject it is the #3606 agreement-invariant residual: a
        // tolerant-path `from destination-port +80` survived verbatim and was
        // enforced as port 80 HERE only. One helper keeps all four parsers in
        // agreement.
        let low = crate::policy::parse_port_u16(low)?;
        let high = crate::policy::parse_port_u16(high)?;
        if low == 0 || low > high {
            return None;
        }
        return Some(vec![PortRange { low, high }]);
    }
    let port = crate::policy::parse_port_u16(normalized)?;
    if port == 0 {
        return None;
    }
    Some(vec![PortRange {
        low: port,
        high: port,
    }])
}

fn build_port_matcher(mut ranges: Vec<PortRange>) -> PortMatcher {
    match ranges.len() {
        0 => PortMatcher::Any,
        1 => {
            let range = ranges.pop().expect("single range");
            if range.low == range.high {
                PortMatcher::Single(range.low)
            } else {
                PortMatcher::Range(range)
            }
        }
        _ => PortMatcher::Set(ranges.into_boxed_slice()),
    }
}

fn build_u8_match_bitmap(values: &[u8]) -> [u64; 4] {
    let mut bitmap = [0u64; 4];
    for value in values {
        bitmap[(value / 64) as usize] |= 1u64 << (value % 64);
    }
    bitmap
}

fn build_u6_match_bitmap(values: &[u8]) -> u64 {
    let mut bitmap = 0u64;
    for value in values {
        if *value < 64 {
            bitmap |= 1u64 << value;
        }
    }
    bitmap
}
