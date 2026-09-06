//! `ConfigSnapshot → ForwardingState` translation.
//!
//! Decomposed (#1342) from the original 1162-LOC
//! `forwarding_build.rs` into per-entity sibling files. This mod
//! file is the orchestrator — a linear, easy-to-audit sequence of
//! sub-builder calls — plus small helpers
//! ([`build_screen_profiles`], [`parse_syn_cookie_master_key`])
//! and the late-stage static-NAT / DNAT local-delivery passes that
//! MUST stay after every other writer of `state.local_v[46]`.
//!
//! Sibling modules:
//!
//! - [`zones`] — `populate_zones`
//! - [`tunnels`] — `populate_tunnel_endpoints`
//! - [`interfaces`] — `populate_interfaces` (returns `IfaceIndex`),
//!   `populate_egress`, `pick_interface_v[46]`
//! - [`fib`] — `sort_connected`, `populate_routes`, `sort_routes`,
//!   `populate_neighbors`, `populate_fabrics`,
//!   `resolve_route_target_v[46]`, `parse_route_next_hop[_v6]`,
//!   `resolve_ifindex`, `infer_connected_route_target_v[46]`
//! - [`cos`] — `build_cos_state` (split into
//!   `build_cos_classifier_tables` + `build_cos_iface_config` +
//!   orchestrator).
//! - [`validated`] — #2410 checked narrowing newtypes
//!   (`VlanId`/`TunnelTtl`/`QueueId`) decoded once with `try_from_snapshot`
//!   so an out-of-range control-plane integer fails the snapshot CLOSED
//!   rather than wrapping (`as` cast) or being silently dropped.

use super::*;

mod cos;
mod fib;
mod interfaces;
mod tunnels;
mod validated;
mod wg;
mod zones;

#[cfg(test)]
mod tests;

// Re-exports for cross-afxdp-sibling consumers reached via
// `use self::forwarding_build::*;` in `afxdp/mod.rs`.
pub(in crate::afxdp) use fib::{
    infer_connected_route_target_v4, infer_connected_route_target_v6, parse_route_next_hop,
    parse_route_next_hop_v6, resolve_ifindex, resolve_route_next_hops_v4, resolve_route_next_hops_v6,
};
pub(in crate::afxdp) use interfaces::{pick_interface_v4, pick_interface_v6};
// #1866: WG row-identity hydration shared with the coordinator's
// tombstone-respawn coherence check + defer-branch prune. (The
// `WgRowIdentity` type itself is only named inside `tunnels`.)
pub(in crate::afxdp) use tunnels::hydrate_wg_identity;
// #2327: typed tunnel-kind classifier shared with the GRE decap path
// (`gre.rs`) and the egress encap dispatcher (`frame/mod.rs`) so the
// kind-segregation and fail-closed `_ =>` arm have one source of truth.
pub(in crate::afxdp) use tunnels::{tunnel_mode_kind, TunnelKind};

// #2410: `build_cos_state` is now fallible (it fails the snapshot
// closed on an out-of-range CoS queue id or an unresolved scheduler-map
// class). The production orchestrator calls `cos::build_cos_state(..)?`
// by path. The test suite (`tests.rs`, `use super::*`) keeps calling an
// infallible `build_cos_state(..) -> CoSState` — provided by this
// `#[cfg(test)]` wrapper that `.expect()`s the valid snapshots the CoS
// tests build (mirrors the `build_forwarding_state` infallible wrapper).
#[cfg(test)]
fn build_cos_state(snapshot: &ConfigSnapshot) -> CoSState {
    cos::build_cos_state(snapshot).expect("test CoS snapshot must not produce integrity error")
}

// Test-only imports. `default_cos_burst_bytes` is reached by
// `forwarding_build/tests.rs` (loaded as `mod tests;` below) via
// `use super::*;`. `build_cos_classifier_tables`,
// `build_cos_iface_config`, and `IfaceIndex` are not referenced
// outside their defining sub-modules in production but are
// surfaced for test assertions and future intra-module use.
#[cfg(test)]
#[allow(unused_imports)]
use cos::{build_cos_classifier_tables, build_cos_iface_config, default_cos_burst_bytes};
#[cfg(test)]
#[allow(unused_imports)]
use interfaces::IfaceIndex;

pub(super) fn build_screen_profiles(snapshot: &ConfigSnapshot) -> FxHashMap<String, ScreenProfile> {
    let mut profiles = FxHashMap::default();
    for sp in &snapshot.screens {
        if sp.zone.is_empty() {
            continue;
        }
        profiles.insert(
            sp.zone.clone(),
            ScreenProfile {
                land: sp.land,
                syn_fin: sp.syn_fin,
                no_flag: sp.tcp_no_flag,
                fin_no_ack: sp.fin_no_ack,
                winnuke: sp.winnuke,
                ping_death: sp.ping_death,
                teardrop: sp.teardrop,
                icmp_fragment: sp.icmp_fragment,
                syn_frag: sp.syn_frag,
                source_route: sp.source_route,
                icmp_flood_threshold: sp.icmp_flood_threshold,
                udp_flood_threshold: sp.udp_flood_threshold,
                syn_flood_threshold: sp.syn_flood_threshold,
                syn_cookie: sp.syn_cookie,
                syn_flood_alarm_threshold: sp.syn_flood_alarm_threshold,
                syn_flood_dst_threshold: sp.syn_flood_dst_threshold,
                syn_flood_src_threshold: sp.syn_flood_src_threshold,
                session_limit_src: sp.session_limit_src,
                session_limit_dst: sp.session_limit_dst,
                port_scan_threshold: sp.port_scan_threshold,
                ip_sweep_threshold: sp.ip_sweep_threshold,
                alarm_without_drop: sp.alarm_without_drop,
            },
        );
    }
    profiles
}

/// #3082: build the zone → missing-screen-profile-name map from the snapshot's
/// `screen_missing_profile_zones`. These are zones that REFERENCE a screen
/// profile undefined at snapshot-build time (lenient/HA-sync path). The
/// dataplane uses this to distinguish "no screen configured" (Pass) from
/// "references a missing screen" (Pass + rate-limited runtime WARN).
pub(super) fn build_screen_missing_profiles(
    snapshot: &ConfigSnapshot,
) -> FxHashMap<String, String> {
    let mut out = FxHashMap::default();
    for r in &snapshot.screen_missing_profile_zones {
        if r.zone.is_empty() {
            continue;
        }
        out.insert(r.zone.clone(), r.profile.clone());
    }
    out
}

/// #7888: build the zone -> screen-profile-name map for zones whose profile IS
/// DEFINED but enables no check (the #7059 third state). Mirrors
/// `build_screen_missing_profiles` exactly; the two maps stay separate so the
/// runtime WARN can name the right cause, and so the `Pass` arm can be "in
/// neither map" rather than a flag inside one.
pub(super) fn build_screen_inert_profiles(
    snapshot: &ConfigSnapshot,
) -> FxHashMap<String, String> {
    let mut out = FxHashMap::default();
    for r in &snapshot.screen_inert_profile_zones {
        if r.zone.is_empty() {
            continue;
        }
        out.insert(r.zone.clone(), r.profile.clone());
    }
    out
}

fn parse_syn_cookie_master_key(key: &str) -> Option<[u8; 16]> {
    if key.len() != 32 {
        return None;
    }
    let mut out = [0u8; 16];
    for (idx, byte) in out.iter_mut().enumerate() {
        let start = idx * 2;
        let part = key.get(start..start + 2)?;
        *byte = u8::from_str_radix(part, 16).ok()?;
    }
    Some(out)
}

/// Test/legacy entry point — infallible; panics on snapshot
/// integrity error (which test snapshots never hit). Production
/// code uses `try_build_forwarding_state_*` instead.
pub(super) fn build_forwarding_state(snapshot: &ConfigSnapshot) -> ForwardingState {
    try_build_forwarding_state_with_policy_counters(snapshot, &PolicyCounterStore::default())
        .expect("test snapshot must not produce policy integrity error")
}

pub(super) fn build_forwarding_state_with_policy_counters(
    snapshot: &ConfigSnapshot,
    policy_counters: &PolicyCounterStore,
) -> ForwardingState {
    try_build_forwarding_state_with_policy_counters(snapshot, policy_counters)
        .expect("test snapshot must not produce policy integrity error")
}

pub(super) fn try_build_forwarding_state_with_policy_counters(
    snapshot: &ConfigSnapshot,
    policy_counters: &PolicyCounterStore,
) -> Result<ForwardingState, crate::policy::SnapshotIntegrityError> {
    // #2218: the policy-only wrappers default the NAT counter store; the
    // resulting `Arc`s are throwaway (a fresh default store per call), used
    // by tests and any caller that does not yet own a `NatCounterStore`.
    build_forwarding_state_with_policy_counters_and_previous(
        snapshot,
        policy_counters,
        &crate::nat::NatCounterStore::default(),
        None,
    )
}

/// #2218: test/build entry point that threads BOTH counter stores so a
/// test can hold the `NatCounterStore` and read back hit counts after a
/// flow. Mirrors `build_forwarding_state` (infallible).
#[cfg(test)]
pub(super) fn build_forwarding_state_with_counters(
    snapshot: &ConfigSnapshot,
    policy_counters: &PolicyCounterStore,
    nat_counters: &crate::nat::NatCounterStore,
) -> ForwardingState {
    build_forwarding_state_with_policy_counters_and_previous(
        snapshot,
        policy_counters,
        nat_counters,
        None,
    )
    .expect("test snapshot must not produce policy integrity error")
}

/// Build a candidate `ForwardingState`, then — and only then — bind it to the
/// carried-forward per-zone counter stores (traffic, and since #3651's flood
/// half, flood-event as well, and since #8291 the GRE decap refusal total;
/// `attach_zone_counters` binds all three).
///
/// #5716: that two-step shape is the load-bearing part. `ZoneCounterStore` is
/// `Arc`-backed, so the carry-forward `clone()` is a HANDLE ON THE LIVE STORE
/// the running workers are folding into, not a copy — and binding a candidate
/// to it mutates it two ways: [`ZoneCounterSlotMap::build`] GET-OR-CREATES a
/// block per SLOT-ASSIGNED zone (a SUBSET of the configured set — it skips zone
/// id 0 and stops at [`ZONE_COUNTER_ASSIGNABLE_SLOTS`]), and `reconcile` DROPS
/// the blocks for zones the candidate no longer configures. A snapshot rejected by one of the fallible
/// integrity belts is discarded by the reconcile/refresh preflight, which keeps
/// the previous forwarding state — so neither mutation may have happened.
///
/// Keeping every fallible step inside [`build_fallible_forwarding_state`] and
/// doing the binding out here, after the `?`, makes that STRUCTURAL rather than
/// positional. A fallible step added anywhere in the inner builder is above the
/// `?` by construction, so it cannot be the "step below the prune" that
/// reintroduces the bug. The earlier shape — one function with the prune as its
/// last statement — relied on a source-order comment instead, and a source-order
/// comment is not a guard: moving the NPTv6 `?` step below the prune left the
/// entire pre-existing suite green (measured, #6832 fold r2 — 4280 of 4281, the
/// one failure being this round's new zone-block assertion, a different defect).
///
/// `rejected_build_does_not_prune_live_zone_counters` /
/// `rejected_build_does_not_create_zone_blocks_in_the_live_store` in
/// `forwarding_build/tests.rs` drive this over FOUR belts, chosen by POSITION,
/// not over all ten of the inner builder's `?` sites: the first `?` (#3719
/// duplicate zone id), the last (#2410 CoS queue id — no fallible step follows
/// it), and #2240 NPTv6 / #3367 filter in between. Span, not count. Every
/// STRAIGHT-LINE statement position a relocated [`attach_zone_counters`] could
/// occupy and still be a DEFECT is one with a `?` below it, and every such
/// position is above the last belt — so the last row observes all of them. (A
/// hoist BELOW the last `?` would stay green, and correctly: nothing after it
/// can reject.) The quantifier is over straight-line positions on purpose:
/// a relocation INTO a conditionally-evaluated sub-expression that a given
/// row's snapshot never enters — a closure such as the one building
/// `session_opening_overrides`, which runs only for a snapshot configuring a
/// screen with a non-zero `syn-flood timeout` — escapes that row. Contrived
/// for a refactor of this shape, but not excluded by the argument, so it is
/// stated rather than assumed away.
///
/// The first row is what makes "the last" a checkable bracket rather than an
/// arbitrary pick, and it is not a passive marker: hoisting the binding ABOVE
/// it, to the top of the fallible region, reds the dup-zone row of BOTH zone
/// tests (measured, #6832 fold r4 — `left: 1, right: 2` on the prune test and
/// `left: [100, 300], right: [100, 200]` on the create test, each reported
/// against the `#3719 duplicate zone id (first fallible step)` label). It is
/// green only for relocations strictly BELOW it, which are exactly the ones
/// the CoS row catches. Six more rows would only widen the second, weaker
/// class — a single BELT moved below the binding, which is caught by that
/// belt's own row and by no other.
pub(super) fn build_forwarding_state_with_policy_counters_and_previous(
    snapshot: &ConfigSnapshot,
    policy_counters: &PolicyCounterStore,
    nat_counters: &crate::nat::NatCounterStore,
    previous: Option<&ForwardingState>,
) -> Result<ForwardingState, crate::policy::SnapshotIntegrityError> {
    // #6995: capture both live counter registries BEFORE the fallible build.
    //
    // `build_fallible_forwarding_state` resolves per-rule counter handles out of
    // these two `Arc`-shared stores — `PolicyCounterStore::rule_hit_counter`
    // get-or-creates, `NatCounterStore::rule_counter` get-or-inserts — and it
    // does so AHEAD of its last three belts (NPTv6, filter, CoS). A build those
    // belts reject therefore left a block per candidate-only rule behind in the
    // LIVE stores, keyed by the rejected snapshot's own ids.
    //
    // The NAT half was operator-visible: `NatCounterStore::snapshots()` emits a
    // row per stored id regardless of value, and that feeds
    // `ProcessStatus.nat_rule_counters`, so a refused commit put phantom NAT
    // rule rows on the status surface until the next successful commit evicted
    // them. The policy half is memory-only (`Coordinator::policy_rule_counters`
    // reads the PUBLISHED state, not the store) but grows the registry by one
    // block per rejected commit.
    //
    // Rolled back rather than deferred. Deferring the binding the way #6832
    // deferred the ZONE binding is not available here: the handles are embedded
    // in `PolicyState`/the NAT tables at construction, so moving them would mean
    // a second pass over already-built structures. A retain to the pre-build set
    // is exact, restores the property completely rather than narrowing a window,
    // and cannot destroy a live row — it evicts only ids this build created.
    let policy_ids_before = policy_counters.tracked_rule_ids();
    let nat_ids_before = nat_counters.tracked_ids();
    let mut state = match build_fallible_forwarding_state(
        snapshot,
        policy_counters,
        nat_counters,
        previous,
    ) {
        Ok(state) => state,
        Err(err) => {
            policy_counters.retain_rule_ids(&policy_ids_before);
            nat_counters.reconcile_ids(&nat_ids_before);
            return Err(err);
        }
    };
    attach_zone_counters(&mut state, snapshot, previous);
    Ok(state)
}

/// Carry every cumulative counter store forward across a config apply.
///
/// NAME. It is still `attach_zone_counters` though #8291 added a store that is
/// NOT per-zone. Renaming it would have broken ten rustdoc intra-doc links
/// across five files that this change does not otherwise touch, and a widened
/// diff is how an unrelated change rides in unreviewed. The name describes the
/// majority of what it binds; this paragraph describes the rest.
///
/// #3651 per-zone counters — BOTH families: carry each cumulative store forward
/// from the previous state (first apply creates it) so totals survive config
/// commits, then build this snapshot's slot maps against them. The traffic
/// family (`zone_counters`) and the flood-event family (`flood_counters`) are
/// bound here together; see the body for why they share one call site rather
/// than getting an `attach_flood_counters` of their own.
///
/// INFALLIBLE, and called only after the fallible builder has returned `Ok` —
/// see [`build_forwarding_state_with_policy_counters_and_previous`].
///
/// This function is now ADDITIVE ONLY. It resolves (get-or-creates) one block
/// per SLOT-ASSIGNED zone out of the live, `Arc`-shared store, and does not
/// remove anything. The destructive half — dropping the blocks for zones the
/// candidate no longer configures — moved to [`commit_zone_counter_prune`],
/// which each apply path calls at ITS OWN commit point (#6832 fold r5). The
/// reason is measured, not stylistic: a build can succeed and the apply STILL be
/// rejected afterwards, by a worker-thread spawn failure (#4952) or an
/// incomplete queue bind (#5143). Pruning here destroyed a removed zone's
/// cumulative totals for a configuration that never brought up a single worker.
///
/// The residue this still leaves — a block for a candidate-only zone on a build
/// whose apply is later rejected — is bounded (one block per rejected apply that
/// adds or renumbers a zone), invisible to the sparse snapshot, and evicted by
/// the next committed apply's prune. It is the same class as the pre-existing
/// `PolicyCounterStore` / `NatCounterStore` residue tracked as #6995, and is
/// unavoidable while the slot map caches real `Arc` handles at build time.
///
/// A zone present in both the old and new config keeps its SAME atomic block,
/// which is what stops the #5163 lock-free per-slot fold resetting or
/// double-counting across a slot renumber.
fn attach_zone_counters(
    state: &mut ForwardingState,
    snapshot: &ConfigSnapshot,
    previous: Option<&ForwardingState>,
) {
    use crate::afxdp::flood_counters::{FloodCounterSlotMap, FloodCounterStore};
    use crate::afxdp::zone_counters::{ZoneCounterSlotMap, ZoneCounterStore};
    let zone_ids: Vec<u16> = snapshot.zones.iter().map(|z| z.id).collect();
    let store = previous
        .map(|p| p.zone_counter_store.clone())
        .unwrap_or_else(ZoneCounterStore::default);
    state.zone_counter_slot_map = std::sync::Arc::new(ZoneCounterSlotMap::build(&zone_ids, &store));
    state.zone_counter_store = store;
    // #3651 flood half: the SECOND per-zone counter family, bound here rather
    // than in its own function ON PURPOSE. Both families slot from the SAME
    // `zone_ids` list in the same order, and a `const _: () = assert!(
    // FLOOD_COUNTER_SLOTS == ZONE_COUNTER_SLOTS)` in `flood_counters.rs` pins
    // their capacities equal precisely so a zone is slotted for BOTH or
    // NEITHER. A separate attach function could be moved, reordered, or dropped
    // independently of this one, which would make that assert claim a coupling
    // the code no longer has; sharing one call site makes divergence
    // unrepresentable instead of merely tested for.
    let flood_store = previous
        .map(|p| p.flood_counter_store.clone())
        .unwrap_or_else(FloodCounterStore::default);
    state.flood_counter_slot_map =
        std::sync::Arc::new(FloodCounterSlotMap::build(&zone_ids, &flood_store));
    state.flood_counter_store = flood_store;
    // #8291 GRE decap refusals: a THIRD cumulative store, NOT per-zone and not
    // slot-mapped, carried here for the reason the flood half gives above — a
    // separate attach function could be
    // moved, reordered or dropped independently, and a cumulative
    // operator-visible total that silently resets on every config commit is
    // invisible in normal use, because a fresh box reads zero anyway. Sharing
    // one call site makes that divergence unrepresentable rather than merely
    // tested for. Not slot-mapped: it is process-wide, not per-zone, so it
    // carries the store and nothing else.
    state.gre_decap_counters = previous
        .map(|p| p.gre_decap_counters.clone())
        .unwrap_or_default();
}

/// Drop the per-zone counter blocks for zones `snapshot` no longer configures.
///
/// DESTRUCTIVE, and therefore callable only once an apply is COMMITTED — the
/// point past which no further step can reject it. There are two such points and
/// they are not the same as "the build returned `Ok`":
///
/// * the full reconcile commits only after `bring_up_workers` returns `Ok`
///   (`coordinator/reconcile/mod.rs`). A published forwarding state whose worker
///   bring-up then failed is NOT committed: the `WorkerSpawn` arm leaves
///   `coord.forwarding` in place, so `show security zones` keeps reporting from
///   this store while no worker is running.
/// * the same-plan refresh commits at its `self.forwarding = new_forwarding`
///   swap (`coordinator/snapshot_refresh.rs`); nothing fallible follows it.
///
/// Deferring the prune costs nothing on the success path — it runs microseconds
/// later, before any reader can observe the difference — and on the failure path
/// it is exactly what preserves a removed zone's totals for the retry or the
/// revert. The store is `Arc`-shared, so pruning through `state` prunes the map
/// every generation's handle sees.
///
/// `rejected_apply_does_not_prune_live_zone_counters` (`coordinator/tests.rs`)
/// drives the worker-spawn arm and reds when this call is hoisted back into
/// [`attach_zone_counters`].
///
/// # The bill for this split, stated where the code is rather than in a review
///
/// Moving the prune out of the build traded a STRUCTURAL guarantee for a
/// PER-CALL-SITE OBLIGATION. While the prune rode inside the builder, every
/// apply path got it for free by construction: there was no way to add an apply
/// path that forgot it. Now a third apply path inherits the additive half
/// automatically — it falls out of `attach_zone_counters`, which the build
/// always runs — and inherits the prune ONLY if its author remembers to call
/// this function at their commit point. Nothing enforces that: no type, no
/// compile-time check, and no test that fails for the mere existence of an
/// unpruned path.
///
/// The symptom, if it is ever forgotten: a zone deleted and later re-added
/// RESURRECTS its pre-deletion totals, because its block was never dropped and
/// the store is keyed by stable zone id. Operator-visible as a counter that
/// jumps rather than starting from zero.
///
/// What guards it today is exactly two named tests —
/// `committed_reconcile_prunes_zone_counters_for_removed_zones_6832` and
/// `committed_refresh_prunes_zone_counters_for_removed_zones_6832`, one per
/// existing call site. They bind the sites that EXIST; they cannot bind a site
/// that does not exist yet. If you add an apply path, add its row.
pub(in crate::afxdp) fn commit_zone_counter_prune(
    state: &ForwardingState,
    snapshot: &ConfigSnapshot,
) {
    let configured: rustc_hash::FxHashSet<u16> = snapshot.zones.iter().map(|z| z.id).collect();
    state.zone_counter_store.reconcile(&configured);
    // #3651 flood half: same commit point, same `configured` set, same
    // function — for the reason spelled out in `attach_zone_counters`. A
    // separate `commit_flood_counter_prune` would need adding at every apply
    // path this one is already called from, and the failure mode of forgetting
    // one is silent: the flood store would retain a removed zone's blocks
    // forever while the traffic store pruned them, so `show security zones` and
    // `show security screen ids-option statistics` would disagree about which
    // zones exist.
    state.flood_counter_store.reconcile(&configured);
}

/// #7010: the DESTRUCTIVE half of the policy / NAT hit-counter reconcile —
/// `commit_zone_counter_prune`'s twin, and deliberately its neighbour.
///
/// The additive half — `PolicyCounterStore::rule_hit_counter` and
/// `NatCounterStore::rule_counter` get-or-creating a block per rule — stays in
/// the fallible builder, where #6995 rolls it back on a rejected build. This
/// half must NOT run there: a build can succeed and the apply still be rejected
/// afterwards by a worker-thread spawn failure (#4952) or an incomplete queue
/// bind (#5143), and pruning at build time destroyed the removed rules'
/// cumulative hit counts for a configuration that never brought up a worker.
///
/// STRICTLY WORSE EXPOSURE than the #6832 zone case this copies, which is why it
/// needed its own fix rather than riding along. `stop_inner(false)` defaults
/// `coord.forwarding`, so the zone store lost its publisher on the
/// `WorkerBindIncomplete` arm and only the `WorkerSpawn` arm was
/// operator-visible. `policy_counters` and `nat_counters` are Coordinator fields
/// `stop_inner` never touches, so BOTH arms leaked and `nat_rule_counters()`
/// kept serving from the pruned store. Measured on the pre-fix head, both arms:
/// `policy=["default-policy", "zone100->zone200/live-rule"] nat=[7]` — the
/// removed rule's block already gone, and it stays gone.
///
/// Takes the two stores rather than the Coordinator so it can live beside its
/// zone twin: a reader looking for "where the destructive halves commit" finds
/// both in one place, which is the property that let the reconcile path drift
/// from the refresh path in the first place.
///
/// What guards it is exactly three named tests, one per direction —
/// `rejected_spawn_apply_does_not_prune_live_rule_counters_7010`,
/// `rejected_bind_apply_does_not_prune_live_rule_counters_7010` and
/// `committed_reconcile_prunes_rule_counters_for_removed_rules_7010`. They bind
/// the call sites that EXIST; if you add an apply path, add its row.
pub(in crate::afxdp) fn commit_rule_counter_prune(
    policy_counters: &crate::policy::PolicyCounterStore,
    nat_counters: &crate::nat::NatCounterStore,
    snapshot: &ConfigSnapshot,
) {
    policy_counters.reconcile_rules(&snapshot.policies);
    // #2218: drop hit counters for NAT rules removed by this config.
    nat_counters
        .reconcile_ids(&crate::afxdp::coordinator::snapshot_active_nat_counter_ids(snapshot));
}

/// Every fallible step of the forwarding build. Returns `Err` on any snapshot
/// integrity violation, having touched no live ZONE-COUNTER state — see the
/// caller for why the per-zone counter binding is deliberately not done here.
///
/// That scope is exact, and it is narrower than "no live shared state". Two
/// OTHER `Arc`-shared stores are mutated inside this function, above the last
/// three belts: `PolicyCounterStore::rule_hit_counter` GET-OR-CREATES a block
/// per policy rule plus one for the reserved default-policy id (store at
/// `policy.rs`, callers in `parse_policy_state_with_counters` below), and
/// `NatCounterStore::rule_counter` GET-OR-INSERTS one per NAT rule (the
/// source / static / destination NAT calls below). Both run ahead of the
/// NPTv6, filter and CoS `?`s.
///
/// #6995: those mutations still happen, but they no longer SURVIVE a rejection.
/// The CALLER
/// ([`build_forwarding_state_with_policy_counters_and_previous`]) captures both
/// registries before invoking this function and retains them back to the
/// captured sets on the `Err` path, so a rejected build leaves neither store
/// changed. Read this function's contract as "may mutate the policy and NAT
/// counter stores; its caller undoes that on `Err`" — NOT as "touches no live
/// shared state", which is the absolute that hid the defect for two releases.
fn build_fallible_forwarding_state(
    snapshot: &ConfigSnapshot,
    policy_counters: &PolicyCounterStore,
    nat_counters: &crate::nat::NatCounterStore,
    previous: Option<&ForwardingState>,
) -> Result<ForwardingState, crate::policy::SnapshotIntegrityError> {
    let mut state = ForwardingState::default();
    let (excluded_local_v4, excluded_local_v6) = nat_translated_local_exclusions(snapshot);

    // #3719 (H03): fail CLOSED if two security zones share a numeric id before
    // any id-keyed map is populated — populate_zones would otherwise let the
    // later zone overwrite the earlier's reverse name / host-inbound set /
    // tcp-rst bit, merging two zones. The Go control plane quarantines a
    // StableZoneID collision on the lenient path, so a clean snapshot never
    // trips this; this is the helper-boundary backstop.
    zones::reject_duplicate_zone_ids(snapshot)?;
    zones::populate_zones(snapshot, &mut state);
    // #2410: fail CLOSED on a tunnel TTL outside 0..=255 instead of
    // narrowing it with an unchecked `as u8` cast that would wrap
    // (256→0 blackholes the tunnel).
    tunnels::populate_tunnel_endpoints(snapshot, &mut state)?;
    // #1432 S2a: instantiate one WgEngine per mode=="wireguard" endpoint,
    // reusing the previous state's engine Arc when the endpoint config is
    // unchanged (TAI64N + live sessions survive the commit) and seeding a
    // fresh engine's TAI64N high-water from the prior engine otherwise.
    wg::populate_wg_engines(&mut state, previous);

    let iface_ctx = interfaces::populate_interfaces(
        snapshot,
        &mut state,
        &excluded_local_v4,
        &excluded_local_v6,
    )?;
    interfaces::populate_egress(snapshot, &mut state, &iface_ctx)?;
    // #6458: zone -> RG-bound-member map for the fabric-ingress zone-stamp
    // validation; needs both ifindex_to_zone_id and egress final.
    interfaces::populate_zone_to_rgs(&mut state);

    fib::sort_connected(&mut state);
    // #3771: fail the snapshot CLOSED on a route whose `family` contradicts its
    // destination prefix (M4) or that carries a negative preference (L1) — the
    // apply preflight then keeps the previous live forwarding state rather than
    // mis-placing the route in the FIB or letting it hijack the preference
    // tie-break.
    fib::populate_routes(snapshot, &mut state, &iface_ctx)?;
    fib::sort_routes(&mut state);
    // #3771 (M11): fail the snapshot CLOSED on a neighbor whose `family`
    // contradicts its IP; unknown/failed states are skipped inside.
    fib::populate_neighbors(snapshot, &mut state)?;
    fib::populate_fabrics(snapshot, &mut state, &iface_ctx);

    state.policy = parse_policy_state_with_counters(
        &snapshot.default_policy,
        &snapshot.policies,
        &state.zone_name_to_id,
        &snapshot.address_books,
        policy_counters,
    )?;
    // #3534: thread the implicit-default-policy RT_FLOW log selection into the
    // policy state. Set here (not in the parser) so the parser's many test
    // callers and the discard-only preflight call sites are untouched; the
    // default-verdict result reads these to stamp a default-PERMIT session.
    state.policy.default_log_session_init = snapshot.default_log_session_init;
    state.policy.default_log_session_close = snapshot.default_log_session_close;
    state.allow_dns_reply = snapshot.flow.allow_dns_reply;
    state.allow_embedded_icmp = snapshot.flow.allow_embedded_icmp;
    state.alg_disable_flags = snapshot.flow.alg_disable_flags;
    // #2008 M5: compile the application-identification catalog so session
    // create can stamp app_id from the 5-tuple.
    state.app_catalog = crate::policy::AppCatalog::from_snapshot(&snapshot.app_catalog);
    // #2008 H14: thread `security flow power-mode-disable` into ForwardingState
    // for config truth/parity (single forwarding path; no behavior switch).
    state.power_mode_disable = snapshot.flow.power_mode_disable;
    // #3360: thread `security flow gre-performance-acceleration` into
    // ForwardingState for config truth/parity. The bit lands in ForwardingState
    // but is not yet read by any packet/forwarding path: the userspace dataplane
    // keys GRE flows on the 5-tuple only, and the consumer (GRE key/call-id
    // extraction into the session tuple) is a deferred feature. Carried here so
    // `show security flow` reflects real plumbed state, not a phantom field.
    state.gre_acceleration = snapshot.flow.gre_acceleration;
    // #9054: a TOP-LEVEL snapshot field, not a `flow` one — it describes the
    // route set in this snapshot, not a flow-processing option.
    state.learned_route_import_capped = snapshot.learned_route_import_capped;
    // #7342: the three `security flow tcp-session` windows #6539 documented as
    // accepted-only now arrive on the wire. Named fields rather than three more
    // positional `u64`s — see `TcpSessionWindowSecs`. Each `0` leaves its window
    // at the dataplane default, so an unset leaf, and a snapshot from a Go
    // binary that predates #7342, both reap exactly as before.
    state.session_timeouts = crate::session::SessionTimeouts::from_seconds(
        snapshot.flow.tcp_session_timeout,
        snapshot.flow.udp_session_timeout,
        snapshot.flow.icmp_session_timeout,
    )
    .with_tcp_session_windows(crate::session::TcpSessionWindowSecs {
        initial: snapshot.flow.tcp_initial_timeout,
        closing: snapshot.flow.tcp_closing_timeout,
        time_wait: snapshot.flow.tcp_time_wait_timeout,
    });
    // #3527: per-screened-zone half-open (`tcp_opening_ns`) overrides from each
    // zone's `syn-flood timeout`. The leaf maps to the Junos
    // half-completed-connection queue window, NOT the screen-rate substrate
    // (#3315 D5), so it is enforced at the session layer: a bare-SYN session in
    // a screened zone reaps on this window instead of the 20 s default. Keyed
    // by zone id (the same namespace `SessionMetadata.ingress_zone` carries),
    // resolved via `zone_name_to_id` (built above). A timeout for a zone with no
    // resolvable id (never assigned to an interface) is silently dropped — the
    // override could never match a session anyway. Built only when at least one
    // zone configures a non-zero timeout, so the common case is an empty map.
    state.session_opening_overrides = snapshot
        .screens
        .iter()
        .filter(|sp| sp.syn_flood_timeout > 0 && !sp.zone.is_empty())
        .filter_map(|sp| {
            state
                .zone_name_to_id
                .get(&sp.zone)
                .copied()
                .map(|zone_id| {
                    (
                        zone_id,
                        crate::session::secs_to_ns_saturating(u64::from(sp.syn_flood_timeout)),
                    )
                })
        })
        .collect();
    // #6751: CARRY the interface-mode identity registry across the apply.
    // It is node-lifetime state, not snapshot-derived: it holds the translated
    // identity every LIVE interface-SNAT session owns, and the releases for
    // those sessions arrive long after this build. Constructing a fresh one
    // here would drop all of it, so the first post-commit flow could preserve
    // a source port an established session is still using on the wire — the
    // #6751 ambiguity, reintroduced once per commit. `previous` is `Some` on
    // both production build sites (`snapshot_refresh.rs`,
    // `reconcile/snapshot.rs`); the only `None` caller is
    // `validate_forwarding_buildable`, whose build is discarded.
    state.iface_nat_allocators = previous
        .map(|prev| std::sync::Arc::clone(&prev.iface_nat_allocators))
        .unwrap_or_default();
    // Reclaim allocators for addresses that are no longer an egress address
    // AND hold no live records, so a node that churns egress addressing does
    // not walk into the retained-allocator cap. `state.egress` is populated
    // earlier in this build, so this reads the NEW egress set.
    let live_egress: rustc_hash::FxHashSet<std::net::IpAddr> = state
        .egress
        .values()
        .flat_map(|e| {
            e.primary_v4
                .map(std::net::IpAddr::V4)
                .into_iter()
                .chain(e.primary_v6.map(std::net::IpAddr::V6))
        })
        .collect();
    state.iface_nat_allocators.reclaim_absent(&live_egress);
    state.source_nat_rules = parse_source_nat_rules_with_previous(
        &snapshot.source_nat_rules,
        previous.map(|state| state.source_nat_rules.as_slice()),
        nat_counters,
        // #6765: the monotonic clock the retained-address re-seed threads down
        // to `reserve_flow`. Read once per apply, not per rule.
        crate::afxdp::neighbor::monotonic_nanos(),
    );
    state.static_nat = StaticNatTable::from_snapshots(&snapshot.static_nat_rules, nat_counters);
    state.dnat_table = DnatTable::from_snapshots(&snapshot.destination_nat_rules, nat_counters);
    // #3888: fail SCOPED on an unparseable NAT64 rule — `from_snapshots` is
    // infallible and SKIPS the offending rule (logging a loud warning),
    // publishing the remaining NAT64 rules and every other rule type. Pre-#3888
    // this returned a `SnapshotIntegrityError` that propagated via `?` and
    // aborted the WHOLE forwarding rebuild, freezing the dataplane on one bad
    // NAT64 rule from a mixed-version peer-sync or corrupt snapshot. The Go
    // commit-time gate (#2173/#3886) remains the primary defense; this scopes
    // the helper-boundary backstop's blast radius to the one NAT64 rule.
    // #4518: thread the previous live NAT64 state so a same-node config reload
    // REUSES each unchanged prefix's Arc-backed port allocator — pre-reload
    // NAT64 sessions keep owning their translated ports, so post-commit flows do
    // not collide at port-offset 0 and mis-demux the (1:N) reverse index. A
    // changed pool resets to a fresh allocator inside `reuse_allocator`. Mirrors
    // the source-NAT `parse_source_nat_rules_with_previous` reuse above. The
    // complementary HA cross-node failover reservation sync is #4512.
    // #5624: thread the config-snapshot generation so each NAT64 fragment
    // association is stamped with the generation it was installed under. The
    // Arc-shared frag-association cache survives this reload (in-flight
    // datagrams keep translating), but an association minted under a PRIOR
    // generation is rejected on lookup once the generation advances — a commit
    // that changed deny/NAT64 rules no longer keeps forwarding stale fragments.
    state.nat64 = Nat64State::from_snapshots_with_previous(
        &snapshot.nat64_rules,
        previous.map(|p| &p.nat64),
        snapshot.generation,
        // #6765: monotonic clock for the retained-address re-seed.
        crate::afxdp::neighbor::monotonic_nanos(),
    );
    // #2240: fail CLOSED on an unparseable / unsupported / mismatched NPTv6
    // rule. The preflight in the reconcile/refresh apply paths catches this
    // Err and keeps the previous live forwarding state rather than installing a
    // silently-narrower NPTv6 config (the helper-boundary backstop to the Go
    // commit-time gate).
    // #8115 R3: NAT64 prefixes are their own occupancy domains, and the
    // source-NAT peer index was built above — inside
    // `parse_source_nat_rules_with_previous`, where `state.nat64` did not exist
    // yet. This is the second pass that makes NAT64 a MEMBER of that index and
    // hands the combined view to both features. It must run AFTER both are
    // assigned, and it fast-outs before any work when no prefix contributes a
    // domain.
    crate::nat::wire_nat64_overlap_peers(&mut state.source_nat_rules, &mut state.nat64.prefixes);
    state.nptv6 = Nptv6State::try_from_snapshots(&snapshot.nptv6_rules)?;
    state.screen_profiles = build_screen_profiles(snapshot);
    state.screen_missing_profiles = build_screen_missing_profiles(snapshot);
    state.screen_inert_profiles = build_screen_inert_profiles(snapshot);
    state.syn_cookie_master_key =
        SynCookieMasterKey(parse_syn_cookie_master_key(&snapshot.syn_cookie_master_key));
    state.tcp_mss_all_tcp = snapshot.flow.tcp_mss_all_tcp;
    state.tcp_mss_ipsec_vpn = snapshot.flow.tcp_mss_ipsec_vpn;
    state.tcp_mss_gre_in = snapshot.flow.tcp_mss_gre_in;
    state.tcp_mss_gre_out = snapshot.flow.tcp_mss_gre_out;
    // #1620: cold-path latency histogram sample mask. Default to 0xff
    // (1-in-256) when the field is absent on the wire (Option::None ⇒
    // older Go daemon or daemon launched without --cold-path-sample-mask).
    // The Go side validates the mask (powers-of-two minus one, plus
    // explicit --enable-cold-path-1-in-1-sampling for mask=0).
    state.cold_path_sample_mask = snapshot.cold_path_sample_mask.unwrap_or(0xff);
    // #1635: build the direct cold-path histogram slot map from the
    // configured policy zone-pairs, reusing the previous map's slot
    // assignments so retained pairs keep their accumulated histogram.
    // The worker derives its own slot zero-out set by diffing the old
    // and new map inverses at the ArcSwap point (Copilot code-r2:
    // generation-independent, unlike a coordinator-computed list), so
    // the build's `slots_to_zero` return is unused here — only the map
    // is stored.
    {
        use crate::afxdp::cold_path_hist::ColdPathSlotMap;
        let pairs = state.policy.configured_zone_pairs();
        let prev_map = previous.map(|p| p.cold_path_slot_map.as_ref());
        let (slot_map, _slots_to_zero) = ColdPathSlotMap::build(prev_map, &pairs);
        state.cold_path_slot_map = std::sync::Arc::new(slot_map);
    }
    // #3651 per-zone traffic counters — and, since the flood half landed, the
    // per-zone FLOOD-event counters with them — are NOT built here. Binding a
    // candidate to either carried-forward store mutates the LIVE, `Arc`-shared
    // store (get-or-create per slot-assigned zone, plus the destructive prune),
    // so it happens in `attach_zone_counters` after this fallible builder has
    // returned `Ok` — see the doc comment on
    // `build_forwarding_state_with_policy_counters_and_previous`.
    //
    // Build filter state from snapshot. #2505: this is fallible — an
    // unresolvable `from protocol` token raises a SnapshotIntegrityError that
    // propagates here, aborting the reconcile preflight (before teardown /
    // publish) so the prior good filter state stays live rather than
    // installing a fail-wide match-all term.
    state.filter_state = crate::filter::parse_filter_state_with_three_color_preserving(
        &snapshot.filters,
        &snapshot.policers,
        &snapshot.three_color_policers,
        &snapshot.interfaces,
        &snapshot.flow.lo0_filter_input_v4,
        &snapshot.flow.lo0_filter_input_v6,
        previous.map(|state| &state.filter_state),
    )?;
    // #2410/#2409: fail CLOSED on a CoS forwarding-class queue id outside
    // 0..=255 (pre-fix: silently dropped), or a scheduler-map entry
    // referencing a forwarding-class absent from the class-to-queue table
    // (pre-fix: silently skipped → a partially-installed scheduler).
    state.cos = cos::build_cos_state(snapshot)?;
    let has_cos_interfaces = !state.cos.interfaces.is_empty();
    // #6236 PR-2A: the output clause is now the single `has_output_needs_tx_eval`
    // aggregate. It subsumes BOTH the old `has_output_tx_selection` clause AND the
    // old `iface_filter_out_*_needs_tx_eval` set non-emptiness, because
    // `needs_tx_eval ⊇ affects_tx_selection` (it also covers counter/log/terminal/
    // policer). Recomputed from the FINAL output fast map, so it cannot fail open
    // on a duplicate-ifindex last-wins overwrite and cannot drop enforcement for a
    // counter/log/terminal/policer-only output filter.
    state.tx_selection_enabled_v4 = has_cos_interfaces
        || state.filter_state.has_input_tx_selection_v4
        || state.filter_state.has_input_three_color_policer_v4
        || state.filter_state.has_output_needs_tx_eval_v4;
    state.tx_selection_enabled_v6 = has_cos_interfaces
        || state.filter_state.has_input_tx_selection_v6
        || state.filter_state.has_input_three_color_policer_v6
        || state.filter_state.has_output_needs_tx_eval_v6;
    // #2130: flow export (NetFlow v9 / IPFIX) is owned entirely by the
    // Go control plane (pkg/flowexport), driven by SESSION_CLOSE events.
    // The dataplane never emitted flow records; the Rust FlowExporter and
    // the flow_export_config field were dead code and have been removed.
    // The flow_export wire field is retained as reserved/ignored (see
    // protocol/snapshot.rs) to preserve the #1977 decode-safety tests and
    // avoid a wire-protocol break.
    for mirror in &snapshot.mirror_configs {
        if mirror.ingress_ifindex <= 0 || mirror.output_ifindex <= 0 {
            continue;
        }
        state.mirror_configs.insert(
            mirror.ingress_ifindex,
            MirrorRuntimeConfig {
                output_ifindex: mirror.output_ifindex,
                rate: mirror.rate,
            },
        );
    }

    // === Late-stage local-delivery additions ===========================
    // These two loops APPEND to `state.local_v[46]` AFTER every other
    // writer. They MUST stay here in `forwarding_build/mod.rs` and MUST
    // NOT be moved into `interfaces.rs` — moving them earlier would
    // execute before `state.static_nat` and `state.dnat_table` are
    // populated, silently emptying the NAT local-delivery set and
    // breaking inbound firewall delivery for all NAT traffic. (#1342
    // AGY r1 finding #2.)

    // Add static NAT external IPs and DNAT destination IPs as local-delivery
    // targets so inbound traffic destined to those IPs is recognized by the
    // firewall. #3769: each IP carries its owning rule's `from
    // routing-instance` scope. A NAMED instance records the specific canonical
    // route table (via `connected_route_tables`) in `local_tables_v*` so the
    // local-delivery shortcut is gated on the RESOLVING table — a packet in
    // VRF A to a NAT/DNAT address owned only in VRF B no longer short-circuits
    // to LocalDelivery. An EMPTY instance is a WILDCARD (`scope_ok` matches it
    // against any ingress routing-instance, and `from zone`/`from interface`
    // rules leave it empty); attributing it to `inet.0` only would over-isolate
    // an external IP whose zone lives in a non-default VRF, so it goes into the
    // table-agnostic `local_nat_any_table_v*` set instead. The scoped IPs are
    // collected into an owned buffer first so the immutable borrow of the NAT
    // tables ends before the mutable `state.local_*` inserts.
    let mut nat_local_targets: Vec<(std::net::IpAddr, String)> = Vec::new();
    for (ip, instance) in state.static_nat.external_ips_scoped() {
        nat_local_targets.push((ip, instance.to_string()));
    }
    for (ip, instance) in state.dnat_table.destination_ips_scoped() {
        nat_local_targets.push((ip, instance.to_string()));
    }
    for (ip, instance) in nat_local_targets {
        let wildcard = instance.is_empty();
        let (table_v4, table_v6) = interfaces::connected_route_tables(&instance);
        match ip {
            std::net::IpAddr::V4(v4) => {
                state.local_v4.insert(v4);
                if wildcard {
                    state.local_nat_any_table_v4.insert(v4);
                } else {
                    state.local_tables_v4.entry(v4).or_default().insert(table_v4);
                }
            }
            std::net::IpAddr::V6(v6) => {
                state.local_v6.insert(v6);
                if wildcard {
                    state.local_nat_any_table_v6.insert(v6);
                } else {
                    state.local_tables_v6.entry(v6).or_default().insert(table_v6);
                }
            }
        }
    }

    // Debug: dump zone mappings and policy rules
    #[cfg(feature = "debug-log")]
    {
        // #921: ifindex_to_zone_id is u16 — render with names via
        // zone_id_to_name for log readability.
        let ifindex_to_zone_named: Vec<(i32, &str)> = state
            .ifindex_to_zone_id
            .iter()
            .map(|(&ifidx, id)| {
                let name = state
                    .zone_id_to_name
                    .get(id)
                    .map(|s| s.as_str())
                    .unwrap_or("");
                (ifidx, name)
            })
            .collect();
        debug_log!("FWD_STATE: ifindex_to_zone={:?}", ifindex_to_zone_named);
        debug_log!(
            "FWD_STATE: egress keys={:?}",
            state.egress.keys().collect::<Vec<_>>()
        );
        for (ifidx, eg) in &state.egress {
            // #921: render eg.zone_id back to name for debug.
            let zone_name = state
                .zone_id_to_name
                .get(&eg.zone_id)
                .map(|s| s.as_str())
                .unwrap_or("");
            debug_log!(
                "FWD_STATE: egress[{}] bind={} zone={} vlan={} mtu={}",
                ifidx,
                eg.bind_ifindex,
                zone_name,
                eg.vlan_id,
                eg.mtu,
            );
        }
        debug_log!(
            "FWD_STATE: policy default={:?} rules={}",
            state.policy.default_action,
            state.policy.rules.len(),
        );
        for (i, rule) in state.policy.rules.iter().enumerate() {
            // #1606: aggregate prefix count across the rule's
            // literal set + every cited book's dense entry.
            let src_v4_count = rule.source_literal_v4.prefix_count()
                + rule
                    .source_book_idxs
                    .iter()
                    .map(|&idx| state.policy.books[idx as usize].v4.prefix_count())
                    .sum::<usize>();
            let dst_v4_count = rule.destination_literal_v4.prefix_count()
                + rule
                    .destination_book_idxs
                    .iter()
                    .map(|&idx| state.policy.books[idx as usize].v4.prefix_count())
                    .sum::<usize>();
            debug_log!(
                "FWD_STATE: policy[{}] {}->{}  action={:?} src_v4={} dst_v4={} apps={}",
                i,
                rule.from_zone,
                rule.to_zone,
                rule.action,
                src_v4_count,
                dst_v4_count,
                rule.applications.len(),
            );
        }
        debug_log!(
            "FWD_STATE: local_v4={:?} interface_nat_v4={:?}",
            state.local_v4,
            state.interface_nat_v4,
        );
        debug_log!(
            "FWD_STATE: snat_rules={} static_nat={} dnat_table={} nptv6={} connected_v4={} routes_v4={}",
            state.source_nat_rules.len(),
            if state.static_nat.is_empty() {
                0
            } else {
                state.static_nat.external_ips().count()
            },
            if state.dnat_table.is_empty() {
                0
            } else {
                state.dnat_table.destination_ips().count()
            },
            if state.nptv6.is_empty() {
                0
            } else {
                state.nptv6.external_prefixes().len()
            },
            state.connected_v4.len(),
            state.routes_v4.values().map(|v| v.len()).sum::<usize>(),
        );
    }

    // Install nftables rules to suppress kernel TCP RSTs from SNAT IPs.
    //
    // When the AF_XDP fill ring momentarily runs dry under high load,
    // the mlx5 driver falls back to the regular RX path. Those leaked
    // packets reach the kernel TCP stack which — having no matching
    // socket — sends RSTs to the server, killing the connection.
    // Blocking outgoing RSTs for SNAT-managed IPs is a targeted fix:
    // the DP handles all TCP state for those addresses.
    install_kernel_rst_suppression(&state);

    // #1636 option D: compute the pending-neighbor drop timeout from the
    // live kernel retrans_time_ms sysctls. Re-evaluated every snapshot so
    // a runtime sysctl change (e.g. an admin reverting PR-1) is picked up
    // on the next apply and propagated atomically via the ha.runtime view.
    state.pending_neigh_timeout_ns =
        compute_pending_neigh_timeout_ns(&state.ifindex_to_name, &RealSysctlReader);

    Ok(state)
}

/// #1636 option D: PENDING_NEIGH_TIMEOUT value (ns) when the kernel
/// `retrans_time_ms` is confirmed <= 250 on every dataplane interface
/// (v4 AND v6) plus the `default` template. Dropping a queued SYN at
/// 800ms re-drives it (via the client's first TCP RTO at ~1000ms)
/// against a kernel that has already resolved or is one fast retransmit
/// from resolving, instead of stalling to the 2000ms default.
pub(in crate::afxdp) const PENDING_NEIGH_TIMEOUT_FAST_NS: u64 = 800_000_000;

/// Threshold (ms) at/below which the kernel retrans timer is fast enough
/// to admit the 800ms timeout. The daemon writes 250ms
/// (neighRetransTargetMs in pkg/daemon/host_tunables.go) but the kernel
/// rounds retrans_time_ms to its internal jiffy resolution — a write of
/// 250 reads back as 252 on HZ=100 hosts. The threshold is therefore set
/// above the rounded value while staying far below the 1000ms default,
/// so the jiffy-rounded fast value is still admitted but a host left at
/// the default fails closed.
const NEIGH_RETRANS_FAST_THRESHOLD_MS: u32 = 300;

/// Reads a u32 from a sysctl-style file path. Abstracted so the
/// timeout-compute logic is unit-testable without touching real /proc.
pub(in crate::afxdp) trait SysctlReader {
    fn read_u32(&self, path: &str) -> Option<u32>;
}

struct RealSysctlReader;

impl SysctlReader for RealSysctlReader {
    fn read_u32(&self, path: &str) -> Option<u32> {
        std::fs::read_to_string(path)
            .ok()?
            .trim()
            .parse::<u32>()
            .ok()
    }
}

/// Fail-closed computation of the pending-neighbor drop timeout.
///
/// Returns `PENDING_NEIGH_TIMEOUT_FAST_NS` (800ms) only if EVERY checked
/// `retrans_time_ms` sysctl reads <= `NEIGH_RETRANS_FAST_THRESHOLD_MS`
/// (300ms — the daemon writes 250 but the kernel jiffy-rounds it to 252
/// on HZ=100; v4 AND v6, every dataplane interface plus the `default`
/// template). Any read failure or any value above the threshold falls
/// back to `super::PENDING_NEIGH_TIMEOUT_NS` (2000ms) and emits a
/// transition-gated operator warning — if the sysctl never applied
/// (restricted container, sysctl namespace, admin override), dropping at
/// 800ms before the kernel's first 1000ms wire solicit would REGRESS the
/// baseline, so we keep the safe default.
pub(in crate::afxdp) fn compute_pending_neigh_timeout_ns<R: SysctlReader>(
    ifindex_to_name: &FastMap<i32, String>,
    reader: &R,
) -> u64 {
    // AGY r1 #4: this runs on EVERY snapshot build, so an un-gated
    // eprintln in the fallback path would flood stderr on every route
    // churn when option B is unapplied. Log only on the false->true
    // transition into the fallback state (and re-arm on recovery so a
    // revert→fix→revert cycle re-warns once). Process-global because the
    // sysctl state is process-global.
    static IN_FALLBACK: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    let fallback = || -> u64 {
        if !IN_FALLBACK.swap(true, Ordering::Relaxed) {
            eprintln!(
                "xpf-userspace-dp: WARNING: kernel retrans_time_ms not <= {}ms on all dataplane \
                 interfaces (v4 AND v6) — using PENDING_NEIGH_TIMEOUT_NS={}ms (option D inactive). \
                 Apply the #1636 sysctl drop-in to enable.",
                NEIGH_RETRANS_FAST_THRESHOLD_MS,
                super::PENDING_NEIGH_TIMEOUT_NS / 1_000_000,
            );
        }
        super::PENDING_NEIGH_TIMEOUT_NS
    };
    // Per-interface tables first (an interface created from a stale
    // template before PR-1 applied could still carry the old 1000ms).
    for name in ifindex_to_name.values() {
        for family in ["ipv4", "ipv6"] {
            let path = format!("/proc/sys/net/{family}/neigh/{name}/retrans_time_ms");
            match reader.read_u32(&path) {
                Some(v) if v <= NEIGH_RETRANS_FAST_THRESHOLD_MS => {}
                _ => return fallback(),
            }
        }
    }
    // The `default` template covers interfaces created post-snapshot.
    for family in ["ipv4", "ipv6"] {
        let path = format!("/proc/sys/net/{family}/neigh/default/retrans_time_ms");
        match reader.read_u32(&path) {
            Some(v) if v <= NEIGH_RETRANS_FAST_THRESHOLD_MS => {}
            _ => return fallback(),
        }
    }
    // Recovered (or always-fast): re-arm the warning so a later revert
    // logs again exactly once.
    IN_FALLBACK.store(false, Ordering::Relaxed);
    PENDING_NEIGH_TIMEOUT_FAST_NS
}
