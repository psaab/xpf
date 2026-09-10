use crate::prefix::{PrefixV4, PrefixV6};
use crate::prefix_set::{PrefixSetV4, PrefixSetV6};
use crate::{
    AddressBookSnapshot, PolicyApplicationSnapshot, PolicyRuleCounterStatus, PolicyRuleSnapshot,
    ZoneSnapshot,
};
use ipnet::IpNet;
use rustc_hash::{FxHashMap, FxHashSet};
use smallvec::SmallVec;
use std::borrow::Cow;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

#[path = "policy_snapshot_error.rs"]
mod snapshot_error;
pub(crate) use snapshot_error::SnapshotIntegrityError;

/// #3261: reserved address literal the Go capability gate emits for a policy
/// whose source/destination address it cannot represent. Detected in the
/// integrity preflight to reject the whole snapshot (fail closed). Must stay in
/// lock-step with the Go `unsupportedAddressSentinel`. It is deliberately not a
/// parseable CIDR/IP, so even an older helper that lacks the preflight arm
/// drops it to `MatchNone` and never matches real traffic.
pub(crate) const UNREPRESENTABLE_ADDRESS_SENTINEL: &str = "__unsupported_address__";

/// #3261: true iff any of the rule's address fields (v3 literals or the legacy
/// expanded lists, source or destination) carries the unrepresentable-address
/// sentinel. The Go side stamps it onto BOTH shapes for the failed side, so a
/// scan of all four lists catches it regardless of which shape the matcher uses.
fn rule_has_unrepresentable_address_sentinel(snap: &PolicyRuleSnapshot) -> bool {
    let hit = |list: &[String]| list.iter().any(|a| a == UNREPRESENTABLE_ADDRESS_SENTINEL);
    hit(&snap.source_literals)
        || hit(&snap.destination_literals)
        || hit(&snap.source_addresses)
        || hit(&snap.destination_addresses)
}

/// #1606: one row of the deduplicated address-book table.
#[derive(Clone, Debug, Default)]
pub(crate) struct BookEntry {
    pub(crate) v4: PrefixSetV4,
    pub(crate) v6: PrefixSetV6,
}

/// #922: zone-pair key packed as u32 (`from_id << 16 | to_id`).
/// Replaces the previous `(String, String)` key that allocated two
/// `String`s on every `evaluate_policy` call.
pub(crate) type ZonePairKey = u32;

#[inline]
pub(crate) fn zone_pair_key(from_id: u16, to_id: u16) -> ZonePairKey {
    ((from_id as u32) << 16) | (to_id as u32)
}

/// #919/#922: sentinel for `junos-global` policy rules. Reserved at
/// the top of the u16 space; `forwarding_build` rejects any zone
/// snapshot with id ≥ ZONE_ID_RESERVED_MIN.
pub(crate) const JUNOS_GLOBAL_ZONE_ID: u16 = u16::MAX;
pub(crate) const ZONE_ID_RESERVED_MIN: u16 = u16::MAX - 1;

/// #3019: synthetic reserved zone id for the Junos `junos-host` self-traffic
/// zone (`to-zone junos-host` / `from-zone junos-host` security policies). It
/// lives at the BOTTOM of the reserved range (`ZONE_ID_RESERVED_MIN`), so a
/// configured zone can never collide: `forwarding_build::populate_zones`
/// already skips any snapshot zone whose id is `>= ZONE_ID_RESERVED_MIN`, and
/// `configured_zone_pairs` excludes both sentinels from the cold-path
/// histogram. The id is never put on the wire (it sits in the reserved range a
/// configured zone can never occupy); it exists only as the in-runtime key so a `junos-host`
/// rule is INDEXED in `zone_pair_index` and reachable by the LocalDelivery
/// policy gate. The Go control plane emits the `junos-host` zone NAME string
/// in the rule snapshot; `parse_policy_state_with_counters` resolves that name
/// to this id (Go↔Rust agreement is on the reserved name, not a wire id).
pub(crate) const JUNOS_HOST_ZONE_ID: u16 = u16::MAX - 1;

/// #3402: build the policy-zone resolution map (`zone name → zone id`) from a
/// snapshot's zone list, applying the SAME #919/#922 validity rules
/// `forwarding_build::populate_zones` uses for the live forwarding table: an id
/// of 0, an empty name, or an id in the reserved range (`>= ZONE_ID_RESERVED_MIN`)
/// is not addressable and is skipped (silently — `populate_zones` emits the
/// per-reason diagnostics on the real build path). #3075 widened the
/// event-stream zone field to u16, so the former >u8::MAX skip is retired.
///
/// The apply-time snapshot-integrity preflight MUST resolve a rule's zones
/// against the INCOMING snapshot's own zones, NOT the live forwarding table.
/// On a fresh boot — and on a new-zone commit or an HA standby's first config
/// sync — the live table is empty/stale, and `populate_zones(snapshot)` only
/// runs LATER inside `build_forwarding_state`. Validating a concrete-zone policy
/// against the empty live table would flag it as `UnresolvableZoneReference`
/// (#3402) and reject the WHOLE snapshot, bricking essentially every real boot
/// config. This helper is the single source of truth for the map: the three
/// preflight sites (snapshot apply, reconcile, runtime refresh) call it on the
/// incoming snapshot, and `populate_zones` reuses it for `state.zone_name_to_id`
/// so the preflight and the real build resolve the identical set. A policy
/// referencing a zone genuinely ABSENT from `snapshot.zones` still fails closed
/// (the real #3402 fix).
pub(crate) fn zone_name_to_id_from_snapshot(zones: &[ZoneSnapshot]) -> FxHashMap<String, u16> {
    let mut map = FxHashMap::default();
    for zone in zones {
        if zone.id == 0 || zone.name.is_empty() {
            continue;
        }
        // Reserved-range ids are unaddressable (mirrors populate_zones; the
        // build path logs the diagnostic). #3075 widened the event-stream zone
        // field to u16, so the former >u8::MAX skip is retired and a stable
        // name-hash id in [1, ZONE_ID_RESERVED_MIN-1] is addressable.
        if zone.id >= ZONE_ID_RESERVED_MIN {
            continue;
        }
        map.insert(zone.name.clone(), zone.id);
    }
    map
}

/// #3019: reserved Junos self-traffic zone name, recognized in policy
/// from/to zone resolution and mapped to [`JUNOS_HOST_ZONE_ID`].
pub(crate) const JUNOS_HOST_ZONE_NAME: &str = "junos-host";

use crate::ip_proto::{
    PROTO_AH, PROTO_EGP, PROTO_ESP, PROTO_GRE, PROTO_ICMP, PROTO_ICMPV6, PROTO_IGMP, PROTO_IPIP,
    PROTO_OSPF, PROTO_PIM, PROTO_SCTP, PROTO_TCP, PROTO_UDP, PROTO_VRRP,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PolicyAction {
    Permit,
    Deny,
    Reject,
}

impl Default for PolicyAction {
    fn default() -> Self {
        Self::Deny
    }
}

/// #3057: reserved sentinel policy ID for the IMPLICIT default-policy
/// (deny-all / permit-all) result returned when a flow matches no configured
/// zone-pair or `junos-global` policy.
///
/// A real configured policy ID is `policy_set_id * MAX_RULES_PER_POLICY +
/// rule_index` (see `pkg/dataplane/userspace/policies.go`), where `rule_index`
/// is capped strictly below MAX_RULES_PER_POLICY (256) and `policy_set_id` is
/// the number of configured zone-pair policy blocks (plus one for the global
/// set) — far below 16,777,216 in any real config. Reaching `u32::MAX`
/// (=0xFFFF_FFFF) as a real ID would require ~16.7M zone-pair policy sets, which
/// is impossible, so this sentinel can never collide with a configured policy's
/// ID. Emitting it (instead of the old `0`, which aliased the FIRST configured
/// policy) lets the Go log/display planes render the implicit default as
/// `default-policy` rather than mis-attributing the deny to the first rule.
///
/// The value travels in the existing `policy_id` u32 field on the wire — NO
/// wire-layout/size change. The Go side mirrors it as
/// `dataplane.DefaultPolicySentinelID`; the two MUST stay byte-identical (pinned
/// by a cross-language contract test in pkg/dataplane/userspace).
pub(crate) const DEFAULT_POLICY_SENTINEL_ID: u32 = u32::MAX;

/// #6682: transit flows refused because their INGRESS interface is in no
/// security zone.
///
/// Zone id 0 is the "unknown / no zone" sentinel — `StableZoneID` folds every
/// CONFIGURED zone into [1, 65533], so 0 is never a real zone. The #3110 guard
/// below already refuses to match ANY rule tier for such a flow, including
/// `from-zone any to-zone any` and `junos-global`. What it did not do was stop
/// the flow from falling through to the IMPLICIT DEFAULT policy, and with
/// `set security policies default-policy permit-all` that default is a PERMIT —
/// so transit on an interface the operator never put in a zone was forwarded,
/// with screen/IDS checks already skipped (an unresolvable ingress zone returns
/// `ScreenCheckOutcome::Pass`, there being no per-zone screen profile to apply).
///
/// Junos does not forward transit on an unzoned interface at all, so the
/// disposition is a deny rather than a default.
///
/// It is counted HERE rather than on `default_counter` so the two causes stay
/// distinguishable: a rising default-deny count means policy is working as
/// configured, whereas a rising count here means an interface fell out of its
/// zone, which is a configuration fault the operator wants to see.
///
/// The RT_FLOW `policy_id` still carries `DEFAULT_POLICY_SENTINEL_ID`, so the
/// deny LOGS as `default-policy`. That is deliberate scope, not an oversight: a
/// dedicated sentinel is a wire-visible value mirrored across ~10 Go call sites
/// (display maps, counter readers, the #4342 invalidation sweep, gRPC/CLI/API)
/// and interacts with the #4626 policy-id-0 handling, which is far more surface
/// than this fix needs. `default-policy` is honest — no rule matched — just
/// less specific than this counter. A distinct log reason is worth doing on its
/// own, not folded in here.
pub(crate) static UNZONED_INGRESS_DENIED: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

/// #3363: stable rule identity under which the IMPLICIT default-policy hit
/// counter is reported in [`PolicyState::counter_snapshots`] (and persisted in
/// the [`PolicyCounterStore`] across snapshot rebuilds). The real per-rule
/// identity format is `from->to/name` (`stable_policy_rule_id`); this reserved
/// name contains no `->` or `/`, so it can never collide with a configured
/// rule's id. This string MUST equal the Go `dataplane.DefaultPolicyName`
/// ("default-policy") — the Go control plane reads this counter by resolving
/// the reserved `DefaultPolicySentinelID` handle to that name (see
/// `pkg/dataplane/userspace/policycounters.go`).
pub(crate) const DEFAULT_POLICY_COUNTER_RULE_ID: &str = "default-policy";

/// #3363: reserved 1-based hit-counter handle for the IMPLICIT default-policy
/// result. The matched-rule path stamps `rule_index + 1` (1..=rules.len());
/// `0` means "no per-rule counter". This sentinel (`u32::MAX`) is distinct from
/// both — it routes [`PolicyState::hit_counter_by_idx`] to the reserved
/// `default_counter` so a default-PERMIT session re-counts every packet of the
/// flow on the established fast path (mirroring #3073 for configured rules). A
/// real handle can never reach it: that would require ~4.29e9 configured rules.
/// The default-DENY path counts on the cold path alone (a denied flow installs
/// no session), so this handle only ever does work for default-permit.
pub(crate) const DEFAULT_POLICY_COUNTER_IDX: u32 = u32::MAX;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct PolicyEvaluationResult {
    pub(crate) action: PolicyAction,
    pub(crate) policy_id: u32,
    /// #2508: the matched policy's per-policy RT_FLOW SYSLOG log
    /// selection, carried so the session-install path can stamp it onto
    /// the session metadata.
    pub(crate) log_session_init: bool,
    pub(crate) log_session_close: bool,
    /// #3227: the matched application term's per-application inactivity (idle)
    /// timeout in SECONDS, carried so the session-install path can stamp it so
    /// the conntrack GC ages the session out on the app's value instead of the
    /// global per-protocol timeout. `None` means "use the global timeout"
    /// (the default-action path and any non-app-timeout match), which is
    /// byte-identical to pre-#3227 behavior.
    pub(crate) inactivity_timeout: Option<u32>,
    /// #3073: a stable 1-based handle to the admitting rule's per-rule hit
    /// counter (`PolicyState::rules[idx-1].hit_counter`), carried so the
    /// session-install path can stamp it onto the session metadata. The
    /// established fast path then resolves the counter via
    /// [`PolicyState::hit_counter_by_idx`] and counts every packet of the
    /// flow (not just the first). `0` is reserved for "no counter" — every
    /// non-policy-forwarded session (firewall-local / neighbor-seed / fabric /
    /// tunnel) — so those flows keep counting nothing on the fast path. The
    /// implicit default-policy is NOT `0`: #3363 binds it to the reserved
    /// `DEFAULT_POLICY_COUNTER_IDX` (`u32::MAX`) sentinel, which
    /// `hit_counter_by_idx` resolves to `PolicyState::default_counter` so a
    /// default-PERMIT session re-counts every packet on the fast path. A
    /// 1-based handle is used so `0` is an unambiguous sentinel distinct from
    /// rule index 0 (the FIRST configured rule, which also carries `policy_id`
    /// 0).
    pub(crate) policy_counter_idx: u32,
}

/// #3148: the optional from-zone/to-zone match context of a GLOBAL policy.
/// A Junos global policy may narrow which zone pairs it applies to with
/// `match { from-zone <z>; to-zone <z>; }`. The rule stays in the global tier
/// (`PolicyState::global_indices`) and the global config order is preserved;
/// this scope is consulted as an extra predicate inside the global-tier loop
/// before `try_match_rule`. A non-global (zone-pair / wildcard) rule always
/// carries `Any` on both sides, so the scope check is a no-op for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum GlobalZoneScope {
    /// No constraint — the global policy applies to every defined zone on this
    /// side (the historical all-zones behaviour, and the value for every
    /// non-global rule).
    Any,
    /// #4626 M03: constrained to a SET of resolved zone ids — the side matches
    /// only these zones. A Junos global policy scope is a zone LIST, so a side
    /// carries every configured zone. The inline capacity of 2 covers the
    /// common ≤2-zone scope with no heap allocation (a single-zone scope is a
    /// 1-element set, bit-identical to the pre-#4626 `Zone(id)`); a larger scope
    /// spills to the heap once at build time (a cold path). The Go compiler
    /// sorts + de-duplicates the set, so membership is order-insensitive.
    Zones(SmallVec<[u16; 2]>),
}

impl Default for GlobalZoneScope {
    fn default() -> Self {
        GlobalZoneScope::Any
    }
}

impl GlobalZoneScope {
    /// Whether a flow whose zone (ingress for from, egress for to) is `id`
    /// satisfies this scope. `Any` matches every zone; a `Zones` set matches iff
    /// `id` is a member (O(k), k = scope size ≈ 1-2, no allocation).
    #[inline]
    pub(crate) fn matches(&self, id: u16) -> bool {
        match self {
            GlobalZoneScope::Any => true,
            GlobalZoneScope::Zones(zs) => zs.contains(&id),
        }
    }

    /// #4626 M03/A6: whether this TO-zone scope is the reserved host-inbound
    /// scope — exactly the single junos-host id. `Any` is never a host scope;
    /// a `Zones` set is a host scope iff it is exactly `[JUNOS_HOST_ZONE_ID]`.
    /// This replaces the pre-#4626 `== Zone(JUNOS_HOST_ZONE_ID)` equality test
    /// (the Go strict commit gate rejects a to-zone list mixing junos-host with
    /// any other zone, so a host-inbound global always resolves to exactly this
    /// singleton).
    #[inline]
    pub(crate) fn is_host_scope(&self) -> bool {
        match self {
            GlobalZoneScope::Any => false,
            GlobalZoneScope::Zones(zs) => zs.as_slice() == [JUNOS_HOST_ZONE_ID],
        }
    }
}

/// #3148: resolve a global policy's `match from-zone`/`to-zone` name into a
/// [`GlobalZoneScope`].
///
///   - Empty (omitted list) → `Any` (all zones — the Junos implicit default).
///   - Any `"any"` element → `Any` as well: an explicit `match from-zone any` is
///     the Junos all-zones default, identical to omitting the leaf. This MUST
///     agree with the Go commit gate, which exempts `"any"` (a valid commit) —
///     resolving `"any"` through `resolve_policy_zone_id` would return `None`
///     (no zone is named `any`), so a `permit` global silently over-restricts
///     and a `deny` global silently no-ops. The contains-`any` short-circuit
///     eliminates that commit-vs-dataplane divergence AND acts as the tolerant
///     backstop for a corrupt/old-peer snapshot that mixes `any` with concrete
///     zones (the Go strict commit gate rejects such a mix, so it never emits
///     one, but a mixed set still degrades safely to all-zones here).
///   - Any other element resolves through [`resolve_policy_zone_id`]; an
///     unresolvable element fails the WHOLE snapshot closed
///     ([`SnapshotIntegrityError::UnresolvableZoneReference`], #3402) rather
///     than silently producing a matches-nothing scope, mirroring the
///     zone-pair path's reject. The Go commit gate
///     (`validatePolicyZoneReferencesStrict`, #2401) hard-rejects an undefined
///     match-zone, so a clean commit never reaches here; this is the
///     helper-boundary backstop for the lenient / upgrade-state / corrupt
///     snapshot path. (`from-zone junos-host` is hard-rejected at commit; a
///     tolerant-path `to-zone junos-host` resolves to the reserved host id,
///     which never matches a transit flow — inert fail-closed for transit and
///     the intended host-scope for the host-inbound tier.)
///   - #6464: an EMPTY-STRING element fails closed the same way
///     (`UnresolvableZoneReference`). The Go emit paths strip blanks
///     (`sortDedupZones`, `firewallMatchValues`), so only a corrupt /
///     hand-built / mixed-version-HA-peer snapshot can carry one — the same
///     reachability class the #3402 backstop covers. Before #6464 the empty
///     element took the `Any` short-circuit and silently WIDENED a scoped
///     PERMIT global to every zone pair (fail open); the identical corruption
///     with a garbage name rejects the snapshot. Empty is not `any`: the
///     `== "any"` token stays the genuine all-zones wildcard.
///
/// #4626 M03: `names` is the resolved scope LIST (the plural
/// `match_from_zones`/`match_to_zones`, or `[singular]` when only the legacy
/// field is present). Every element is resolved and collected into a sorted,
/// de-duplicated `Zones` set.
fn build_global_zone_scope(
    zone_name_to_id: &FxHashMap<String, u16>,
    names: &[String],
    rule_id: &str,
) -> Result<GlobalZoneScope, SnapshotIntegrityError> {
    if names.is_empty() || names.iter().any(|n| n == "any") {
        return Ok(GlobalZoneScope::Any);
    }
    let mut ids: SmallVec<[u16; 2]> = SmallVec::with_capacity(names.len());
    for name in names {
        // #6464: an empty scope element is not the `any` wildcard — the Go
        // emit paths strip blanks, so only a corrupt / hand-built /
        // mixed-version-HA-peer snapshot can carry one. Fail closed exactly
        // like an unresolvable zone name (#3402) instead of widening the
        // scope to all zones. (Explicit, rather than relying on
        // `resolve_policy_zone_id` missing "" — the map never holds an empty
        // name, but that invariant belongs to `zone_name_to_id_from_snapshot`
        // and must not be load-bearing here.)
        if name.is_empty() {
            return Err(SnapshotIntegrityError::UnresolvableZoneReference {
                rule_id: rule_id.to_string(),
                zone: name.clone(),
            });
        }
        match resolve_policy_zone_id(zone_name_to_id, name) {
            Some(id) => ids.push(id),
            None => {
                return Err(SnapshotIntegrityError::UnresolvableZoneReference {
                    rule_id: rule_id.to_string(),
                    zone: name.to_string(),
                })
            }
        }
    }
    ids.sort_unstable();
    ids.dedup();
    Ok(GlobalZoneScope::Zones(ids))
}

/// #4626 M03: resolve the EFFECTIVE scoped-global zone list from a snapshot's
/// additive wire fields — prefer the plural `match_*_zones` (the full set) and
/// fall back to the singular `match_*_zone` for an old-Go snapshot that omits
/// the plural (rolling-upgrade safety). An unscoped rule yields an empty slice.
fn effective_match_zones<'a>(plural: &'a [String], singular: &'a str) -> Cow<'a, [String]> {
    if !plural.is_empty() {
        Cow::Borrowed(plural)
    } else if !singular.is_empty() {
        Cow::Owned(vec![singular.to_string()])
    } else {
        Cow::Borrowed(&[])
    }
}

#[derive(Debug)]
pub(crate) struct PolicyRule {
    pub(crate) rule_id: String,
    pub(crate) policy_id: u32,
    pub(crate) from_zone: String,
    pub(crate) to_zone: String,
    /// #3148: optional global-policy zone match context (Any for every
    /// non-global rule). See [`GlobalZoneScope`].
    pub(crate) global_from_zone: GlobalZoneScope,
    pub(crate) global_to_zone: GlobalZoneScope,
    pub(crate) scheduler_name: String,
    pub(crate) inactive: bool,
    /// #1606: literal CIDRs inlined in the rule (renamed from
    /// `source_v4`). For v3-shaped rules, built via
    /// `PrefixSetV4::from_v3_literals` (empty → MatchNone). For
    /// non-v3-shaped (legacy) rules, built via the legacy
    /// `from_prefixes` (empty → MatchAny).
    pub(crate) source_literal_v4: PrefixSetV4,
    pub(crate) source_literal_v6: PrefixSetV6,
    pub(crate) destination_literal_v4: PrefixSetV4,
    pub(crate) destination_literal_v6: PrefixSetV6,
    /// #1606: dense indices into `PolicyState::books`. Inline cap
    /// of 8 covers the realistic case (≤8 books per rule); spills
    /// to heap above that.
    pub(crate) source_book_idxs: SmallVec<[u32; 8]>,
    pub(crate) destination_book_idxs: SmallVec<[u32; 8]>,
    /// #1606: precomputed match-any short-circuit flags. True iff
    /// the union of literal + cited books matches every address.
    pub(crate) source_v4_match_any: bool,
    pub(crate) source_v6_match_any: bool,
    pub(crate) destination_v4_match_any: bool,
    pub(crate) destination_v6_match_any: bool,
    /// #2008 H2: invert the per-side address match. When set, the
    /// side matches iff the address is NOT in the configured set
    /// (Junos `source-address-excluded` / `destination-address-
    /// excluded`). The match-any short-circuit is intentionally NOT
    /// applied when excluded — see `try_match_rule`.
    pub(crate) source_excluded: bool,
    pub(crate) destination_excluded: bool,
    /// #2008 (fail-open hardening): per-side, per-family flag that is
    /// true iff the configured address set matches NOTHING for that
    /// family (literal is MatchNone, not match-any, and every cited
    /// book's family set is MatchNone). Used ONLY on the `*_excluded`
    /// path: inverting an empty excluded set would evaluate to
    /// match-ALL (a silent fail-open if a typo'd address was dropped),
    /// so when excluded AND empty the side is forced to NOT match
    /// (fail-closed). See `try_match_rule`.
    pub(crate) source_v4_empty: bool,
    pub(crate) source_v6_empty: bool,
    pub(crate) destination_v4_empty: bool,
    pub(crate) destination_v6_empty: bool,
    pub(crate) applications: Vec<ApplicationMatch>,
    /// Precompiled application matcher (protocol-indexed, exact-port sets).
    compiled_apps: CompiledApplications,
    pub(crate) action: PolicyAction,
    /// #2508: per-policy Junos `then log session-init`/`session-close`
    /// selection. Stamped onto session metadata at install so the
    /// per-policy RT_FLOW SYSLOG records gate on the admitting policy.
    pub(crate) log_session_init: bool,
    pub(crate) log_session_close: bool,
    pub(crate) hit_counter: Arc<PolicyRuleCounter>,
}

impl Default for PolicyRule {
    fn default() -> Self {
        Self {
            rule_id: String::new(),
            policy_id: 0,
            from_zone: String::new(),
            to_zone: String::new(),
            global_from_zone: GlobalZoneScope::Any,
            global_to_zone: GlobalZoneScope::Any,
            scheduler_name: String::new(),
            inactive: false,
            source_literal_v4: PrefixSetV4::default(),
            source_literal_v6: PrefixSetV6::default(),
            destination_literal_v4: PrefixSetV4::default(),
            destination_literal_v6: PrefixSetV6::default(),
            source_book_idxs: SmallVec::new(),
            destination_book_idxs: SmallVec::new(),
            source_v4_match_any: true,
            source_v6_match_any: true,
            destination_v4_match_any: true,
            destination_v6_match_any: true,
            source_excluded: false,
            destination_excluded: false,
            source_v4_empty: false,
            source_v6_empty: false,
            destination_v4_empty: false,
            destination_v6_empty: false,
            applications: Vec::new(),
            compiled_apps: CompiledApplications {
                match_any: true,
                by_protocol: FxHashMap::default(),
            },
            action: PolicyAction::Deny,
            log_session_init: false,
            log_session_close: false,
            hit_counter: Arc::new(PolicyRuleCounter::default()),
        }
    }
}

impl Clone for PolicyRule {
    fn clone(&self) -> Self {
        Self {
            rule_id: self.rule_id.clone(),
            policy_id: self.policy_id,
            from_zone: self.from_zone.clone(),
            to_zone: self.to_zone.clone(),
            global_from_zone: self.global_from_zone.clone(),
            global_to_zone: self.global_to_zone.clone(),
            scheduler_name: self.scheduler_name.clone(),
            inactive: self.inactive,
            source_literal_v4: self.source_literal_v4.clone(),
            source_literal_v6: self.source_literal_v6.clone(),
            destination_literal_v4: self.destination_literal_v4.clone(),
            destination_literal_v6: self.destination_literal_v6.clone(),
            source_book_idxs: self.source_book_idxs.clone(),
            destination_book_idxs: self.destination_book_idxs.clone(),
            source_v4_match_any: self.source_v4_match_any,
            source_v6_match_any: self.source_v6_match_any,
            destination_v4_match_any: self.destination_v4_match_any,
            destination_v6_match_any: self.destination_v6_match_any,
            source_excluded: self.source_excluded,
            destination_excluded: self.destination_excluded,
            source_v4_empty: self.source_v4_empty,
            source_v6_empty: self.source_v6_empty,
            destination_v4_empty: self.destination_v4_empty,
            destination_v6_empty: self.destination_v6_empty,
            applications: self.applications.clone(),
            compiled_apps: self.compiled_apps.clone(),
            action: self.action,
            log_session_init: self.log_session_init,
            log_session_close: self.log_session_close,
            hit_counter: self.hit_counter.clone(),
        }
    }
}

/// Per-rule policy hit counter: cumulative `packets`/`bytes` admitted (or
/// denied, for an explicit deny rule) under one security-policy rule, surfaced
/// by [`PolicyState::counter_snapshots`] for `show security policies
/// hit-count`, the REST `/metrics`-counter path, and Prometheus.
///
/// #3451 — relaxed-pair / eventual-consistency semantics (deliberate, do NOT
/// "fix" with a lock or seqcount). `packets` and `bytes` are two INDEPENDENT
/// relaxed [`AtomicU64`]s. Each [`add`](Self::add) / [`add_batch`](Self::add_batch)
/// accumulation is correct in isolation — a relaxed `fetch_add` never loses an
/// increment, so the running TOTAL of each field is always exact, even under
/// many concurrent worker threads sharing the same `Arc`. What is NOT atomic is
/// the *pair*: [`snapshot`](Self::snapshot) loads the two fields with separate
/// relaxed loads, and the hot path stores them with separate relaxed adds, so a
/// reader can observe `packets` and `bytes` taken at slightly different logical
/// instants (e.g. a freshly bumped packet count next to a byte count that has
/// not yet absorbed that packet's length). The skew is bounded by the in-flight
/// update(s) — at most one `add` per concurrent worker, or one coalesced
/// `add_batch` of up to `POLICY_HIT_FLUSH_PACKETS` per worker (#3073).
///
/// This matches the codebase-wide telemetry-counter convention
/// (`filter::FilterTermCounter`, `ThreeColorPolicerCounter`, the NAT and
/// WireGuard counters). It is intentional because the read side is a low-rate
/// poll (~1/s) while the write side is per-packet across every worker: a
/// seqcount or lock would reintroduce shared-cacheline contention on the write
/// side — exactly what the #3073 batched-`add_batch` design exists to avoid —
/// and a 128-bit combined atomic is not portably lock-free on the baseline
/// x86-64 target. Counters are advisory telemetry, so eventual consistency is
/// accepted. CONSUMER CONTRACT: monitoring code MUST treat a single snapshot's
/// `bytes/packets` ratio as approximate at sub-poll granularity; over any poll
/// interval the two fields reconcile (each total is exact). Do not assert an
/// exact `bytes == packets * frame_len` relationship on one instantaneous
/// snapshot.
#[derive(Debug, Default)]
pub(crate) struct PolicyRuleCounter {
    packets: AtomicU64,
    bytes: AtomicU64,
    /// #3395: the stable rule identity (`stable_policy_rule_id`, the
    /// `from->to/name` string, or `DEFAULT_POLICY_COUNTER_RULE_ID` for the
    /// implicit default-policy counter) this counter belongs to. Set once at
    /// creation in `PolicyCounterStore::rule_hit_counter` and never mutated, so
    /// a session that BOUND this `Arc` at install (`SessionMetadata::
    /// policy_counter`, #3322) can recover the stable identity of its admitting
    /// rule from the bound handle alone — without a new per-session field. Used
    /// by `PolicyState::reresolve_session_policy_id` to re-resolve the CURRENT
    /// positional `policy_id` (#3056) of an established session at the local
    /// publish surfaces (live-row refresh + RT_FLOW SESSION_CLOSE), so a live
    /// mid-list policy insert/delete no longer mis-attributes the session
    /// (#3395). The placeholder `Default` counters (`PolicyRule::default()` /
    /// `PolicyState::default()`) carry an empty id; production counters always
    /// flow through `rule_hit_counter` and carry the real id.
    rule_id: Box<str>,
    /// #3448: clear epoch. `clear security policies hit-count` resets the
    /// shared `packets`/`bytes` atomics but cannot reach the per-worker
    /// pending hit-count batches buffered by `record_policy_hit_counter`
    /// (up to `POLICY_HIT_FLUSH_PACKETS`). Without an epoch, a pending batch
    /// recorded before the clear would `add_batch` its stale pre-clear counts
    /// onto the freshly-zeroed counter at the next RX-batch flush, so the
    /// clear appeared to fail or to invent traffic. `reset()` bumps this
    /// generation; each pending batch records the generation it was captured
    /// under and is DISCARDED (not flushed) if the generation has advanced.
    ///
    /// #3782: bumping the generation BEFORE zeroing opened the inverse race —
    /// a POST-clear batch (captured under the new generation, admitted by the
    /// guard) could be clobbered by a `store(0)` running after the bump. So
    /// `reset()` no longer stores zero; it `fetch_sub`s the observed pre-clear
    /// total (see [`PolicyRuleCounter::reset`]), which cannot overwrite a
    /// concurrent post-clear increment.
    generation: AtomicU64,
}

impl PolicyRuleCounter {
    /// #3395: construct a counter that remembers the stable `rule_id` it
    /// belongs to. Used by `PolicyCounterStore::rule_hit_counter` at first
    /// creation; the store re-hands the same `Arc` for a surviving id across
    /// snapshot rebuilds, so the id stays valid for the life of any session
    /// that bound the handle.
    fn with_rule_id(rule_id: &str) -> Self {
        Self {
            packets: AtomicU64::new(0),
            bytes: AtomicU64::new(0),
            rule_id: Box::from(rule_id),
            generation: AtomicU64::new(0),
        }
    }

    /// #5445 (test-only): the shared packet total, for asserting that the
    /// established-session hit-count still increments when the bound counter is
    /// resolved BY BORROW from the session table (`bound_policy_counter_for`)
    /// after the per-packet `SessionLookup` stopped cloning the counter `Arc`.
    #[cfg(test)]
    pub(crate) fn test_packet_count(&self) -> u64 {
        self.packets.load(Ordering::Relaxed)
    }

    /// #6304 (test-only): the shared byte total. Needed to bind the `packet_bytes`
    /// ARGUMENT at a call site, not merely that some packet was counted — the
    /// flow-cache-hit replay passes `meta.pkt_len`, and a call site that passed a
    /// stripped or zero length would still advance `test_packet_count`.
    ///
    /// The struct doc's "do not assert an exact `bytes == packets * frame_len`
    /// relationship on one instantaneous snapshot" is a CONCURRENT-reader
    /// caveat: the two fields are separate atomics, so a monitor sampling a live
    /// counter can catch the pair mid-update. A single-threaded test that
    /// records a known number of packets and reads afterwards observes both
    /// increments, so the exact relationship holds there.
    #[cfg(test)]
    pub(crate) fn test_byte_count(&self) -> u64 {
        self.bytes.load(Ordering::Relaxed)
    }

    /// #3395: the stable rule identity this counter belongs to (empty for a
    /// `Default` placeholder). See the `rule_id` field doc.
    pub(crate) fn rule_id(&self) -> &str {
        &self.rule_id
    }

    fn add(&self, packet_len: u64) {
        self.packets.fetch_add(1, Ordering::Relaxed);
        if packet_len != 0 {
            self.bytes.fetch_add(packet_len, Ordering::Relaxed);
        }
    }

    /// #9385: `add` with the count POLICY applied. Note the zero-length gate in
    /// `add` covers BYTES only — the packet increment is unconditional — so a
    /// caller passing `packet_len = 0` to mean "do not count me" was still
    /// bumping `packets`. That is the whole defect: `#6304`'s own doc relies on
    /// the zero-length-still-counts behaviour as a distinguisher, so `add` cannot
    /// be changed; the decision has to be threaded instead.
    #[inline]
    fn add_if(&self, packet_len: u64, hit_count: PolicyHitCount) {
        if hit_count.enabled() {
            self.add(packet_len);
        }
    }

    /// #3073: coalesced multi-packet add used by the per-worker hit-count
    /// flush (`flush_recorded_policy_hit_counters`). Folds a whole batch of
    /// established-session fast-path packets into ONE pair of relaxed
    /// `fetch_add`s on the shared counter, so the hot path never hammers the
    /// shared cacheline per packet (mirrors `filter::FilterTermCounter`).
    fn add_batch(&self, packets: u64, bytes: u64) {
        if packets != 0 {
            self.packets.fetch_add(packets, Ordering::Relaxed);
        }
        if bytes != 0 {
            self.bytes.fetch_add(bytes, Ordering::Relaxed);
        }
    }

    fn reset(&self) {
        // #3448: bump the clear epoch FIRST so any per-worker pending batch
        // still holding pre-clear counts (recorded under the previous
        // generation) is discarded at its next flush instead of replaying
        // onto the counter. The generation only ever increases.
        self.generation.fetch_add(1, Ordering::Relaxed);
        // #3782: observe the current (pre-clear) totals, then remove EXACTLY
        // that amount with an atomic `fetch_sub` rather than `store(0)`.
        //
        // A `store(0)` unconditionally overwrites the field, so a legitimate
        // POST-clear hit recorded by a worker in the tiny window between the
        // epoch bump above and the zero below (the worker captures the NEW
        // generation, reaches a flush boundary, and `add_batch`es — the
        // generation guard correctly admits it) would be clobbered by the
        // store: the clear silently ate a real post-clear packet. #3448 closed
        // the inverse race (a pre-clear batch replaying post-clear) but opened
        // this one, because it bumps the generation before zeroing.
        //
        // `fetch_sub(observed)` subtracts only the pre-clear amount we read:
        // whatever a concurrent worker `fetch_add`s survives, because both are
        // atomic RMWs on the same location and serialize in the modification
        // order (no lost update). Every pre-clear direct count is in `observed`
        // and is removed; any concurrent post-clear increment is preserved. The
        // only residual is a bounded ns-scale attribution skew for a count that
        // lands exactly at the clear instant (a legitimately pre/post-ambiguous
        // packet) — the same eventual-consistency contract the
        // `PolicyRuleCounter` type doc already accepts, NOT a destructive wipe
        // of a durably-recorded hit.
        let observed_packets = self.packets.load(Ordering::Relaxed);
        let observed_bytes = self.bytes.load(Ordering::Relaxed);
        self.subtract_observed(observed_packets, observed_bytes);
    }

    /// #3782: remove exactly `observed_*` from the shared totals with atomic
    /// `fetch_sub`s (see [`reset`](Self::reset) for why this is not a
    /// `store(0)`). Split out as the clear's subtraction step so the
    /// reset/record interleaving can be driven deterministically in tests: the
    /// invariant is that a concurrent post-clear increment applied between the
    /// observation in `reset` and this call is preserved, not wiped.
    ///
    /// `observed_*` is always `<=` the current total — increments are monotonic
    /// (`add`/`add_batch` only `fetch_add`) and resets are serialized per
    /// counter by the `PolicyCounterStore` mutex — so neither `fetch_sub`
    /// underflows.
    #[inline]
    fn subtract_observed(&self, observed_packets: u64, observed_bytes: u64) {
        if observed_packets != 0 {
            self.packets.fetch_sub(observed_packets, Ordering::Relaxed);
        }
        if observed_bytes != 0 {
            self.bytes.fetch_sub(observed_bytes, Ordering::Relaxed);
        }
    }

    /// #3448: current clear epoch. Stamped onto a per-worker pending batch
    /// when it is captured and re-checked at flush time to drop stale
    /// pre-clear counts.
    fn generation(&self) -> u64 {
        self.generation.load(Ordering::Relaxed)
    }

    /// #3451: loads the two fields with INDEPENDENT relaxed loads — see the
    /// `PolicyRuleCounter` type doc. Each field's total is exact; the pair is
    /// eventual-consistent (the snapshot may straddle one in-flight update), so
    /// the returned `bytes/packets` ratio is approximate at sub-poll
    /// granularity. `packets` always maps to `packets` and `bytes` to `bytes`
    /// (no swap) — pinned by `policy_rule_counter_snapshot_pairs_totals` in
    /// `policy_tests.rs`.
    fn snapshot(&self, rule_id: &str) -> PolicyRuleCounterStatus {
        PolicyRuleCounterStatus {
            rule_id: rule_id.to_string(),
            packets: self.packets.load(Ordering::Relaxed),
            bytes: self.bytes.load(Ordering::Relaxed),
        }
    }
}

type PolicyCounterRegistry = FxHashMap<String, Arc<PolicyRuleCounter>>;

#[derive(Clone, Debug, Default)]
pub(crate) struct PolicyCounterStore {
    counters: Arc<Mutex<PolicyCounterRegistry>>,
}

impl PolicyCounterStore {
    pub(crate) fn reconcile_rules(&self, rules: &[PolicyRuleSnapshot]) {
        let mut active_rule_ids: FxHashSet<String> =
            rules.iter().map(stable_policy_rule_id).collect();
        // #3363: the implicit default-policy counter has no PolicyRuleSnapshot,
        // so retain its reserved id explicitly — otherwise every reconcile
        // would evict it and reset the default-deny hit count to zero.
        active_rule_ids.insert(DEFAULT_POLICY_COUNTER_RULE_ID.to_string());
        if let Ok(mut counters) = self.counters.lock() {
            counters.retain(|rule_id, _| active_rule_ids.contains(rule_id));
        }
    }

    pub(crate) fn clear(&self) {
        if let Ok(counters) = self.counters.lock() {
            for counter in counters.values() {
                counter.reset();
            }
        }
    }

    /// #6995: the stored rule ids, for the rejected-build rollback in
    /// `forwarding_build`.
    ///
    /// `rule_hit_counter` below GET-OR-CREATES, and it runs inside the fallible
    /// builder AHEAD of the NPTv6, filter and CoS belts — so a build those
    /// belts reject used to leave a block per candidate-only rule behind in
    /// this live, `Arc`-shared store. The builder captures this set before it
    /// starts and hands it back to `retain_rule_ids` on the `Err` path.
    pub(crate) fn tracked_rule_ids(&self) -> Vec<String> {
        let Ok(counters) = self.counters.lock() else {
            return Vec::new();
        };
        let mut ids: Vec<String> = counters.keys().cloned().collect();
        ids.sort();
        ids
    }

    /// #6995: restore the registry to a previously captured id set.
    ///
    /// Deliberately NOT `clear()`. The rollback must leave every block that
    /// existed before the rejected build exactly where it was — those carry the
    /// cumulative totals of the RUNNING configuration, and dropping them would
    /// reset `show security policies detail` hit counts on a commit that never
    /// applied, which is the #5716 defect in a new place. Retaining a superset
    /// is the safe direction: it can only fail to evict, never destroy.
    pub(crate) fn retain_rule_ids(&self, keep: &[String]) {
        let keep: FxHashSet<&str> = keep.iter().map(String::as_str).collect();
        if let Ok(mut counters) = self.counters.lock() {
            counters.retain(|rule_id, _| keep.contains(rule_id.as_str()));
        }
    }

    fn rule_hit_counter(&self, rule_id: &str) -> Arc<PolicyRuleCounter> {
        let mut counters = self.counters.lock().expect("policy counter store poisoned");
        if let Some(counter) = counters.get(rule_id) {
            return counter.clone();
        }

        // #3395: stamp the stable rule id onto the counter at creation so a
        // session that binds this Arc can later recover its admitting rule's
        // identity from the handle alone (see PolicyRuleCounter::rule_id).
        let counter = Arc::new(PolicyRuleCounter::with_rule_id(rule_id));
        counters.insert(rule_id.to_string(), counter.clone());
        counter
    }

    /// #6832 fold r6: the stored rule ids, sorted. There is no production
    /// reader for this registry — `PolicyState::counter_snapshots` reads the
    /// PUBLISHED state's rules, not the store — so a rejected build's policy
    /// residue is invisible to operators and, until this accessor existed, to
    /// tests as well. Mirrors `NatCounterStore::snapshots()` in emitting an
    /// entry per stored id regardless of its value, which is what lets a test
    /// distinguish "block never created" from "store empty".
    #[cfg(test)]
    pub(crate) fn tracked_rule_ids_for_test(&self) -> Vec<String> {
        // #6995: an ALIAS of the production accessor, not a second
        // implementation. Single-sourcing it keeps the #6832 zone-era tests that
        // call this name guarding the SAME registry view the rollback uses; two
        // copies could drift and the older tests would silently stop covering
        // what their names claim.
        self.tracked_rule_ids()
    }
}

// ── #3073: per-worker established-session policy hit-count coalescer ──
//
// Before #3073 the policy packet/byte hit counter was incremented exactly
// ONCE per flow — on the cold (session-miss) path inside `try_match_rule`.
// A permitted TCP session moving millions of packets therefore reported
// `packets=1` and only the first frame's bytes, defeating audits and vSRX
// parity. The established fast path (`poll_descriptor` session-hit and the
// flow-cache hit replay) now increments the admitting policy's counter on
// EVERY packet via `record_policy_hit_counter`.
//
// To keep the hot path off the shared counter cacheline, increments are
// coalesced in a thread-local (per-worker) accumulator and folded into the
// shared `PolicyRuleCounter` in batches — the SAME technique
// `filter::record_filter_counter` uses for `then count` term counters. The
// accumulator holds the current rule's counter `Arc`; a different rule (or
// the per-batch `flush_recorded_policy_hit_counters` call at the end of the
// RX batch) flushes the pending tally first. `Arc::ptr_eq` keeps the common
// run of same-flow packets on a pure thread-local add.
struct PendingPolicyHitRecord {
    counter: Option<Arc<PolicyRuleCounter>>,
    /// #3448: clear epoch the buffered `packets`/`bytes` were recorded under.
    /// Compared against the counter's current generation at flush time so a
    /// `clear` that happened after this batch was captured discards the
    /// pre-clear counts instead of replaying them.
    generation: u64,
    packets: u64,
    bytes: u64,
}

impl Default for PendingPolicyHitRecord {
    fn default() -> Self {
        Self {
            counter: None,
            generation: 0,
            packets: 0,
            bytes: 0,
        }
    }
}

#[cfg(not(test))]
const POLICY_HIT_FLUSH_PACKETS: u64 = 64;

#[cfg(not(test))]
thread_local! {
    static PENDING_POLICY_HIT_RECORD: std::cell::RefCell<PendingPolicyHitRecord> =
        std::cell::RefCell::new(PendingPolicyHitRecord::default());
}

// Not gated on `#[cfg(not(test))]`: the generation-discard logic is the
// load-bearing part of the #3448 fix and is unit-tested directly (the
// per-worker thread-local coalescer itself is bypassed under `#[cfg(test)]`).
#[inline(always)]
fn flush_pending_policy_hit_record(record: &mut PendingPolicyHitRecord) {
    let Some(counter) = record.counter.take() else {
        return;
    };
    // #3448: only fold the pending batch into the shared counter if it was
    // recorded under the counter's CURRENT clear epoch. If a
    // `clear security policies hit-count` bumped the generation between
    // capture and this flush, these are pre-clear hits — discard them so the
    // clear is durable and the freshly-zeroed counter does not snap back.
    if record.generation == counter.generation() {
        counter.add_batch(record.packets, record.bytes);
    }
    record.packets = 0;
    record.bytes = 0;
}

/// #3073: record one established-session packet against the admitting
/// policy's hit counter, coalesced per worker. Called from the
/// `poll_descriptor` session-hit fast path and the flow-cache hit replay —
/// NOT the cold path, which already counts the first packet in
/// `try_match_rule`, so every packet is counted exactly once.
#[cfg(not(test))]
#[inline(always)]
pub(crate) fn record_policy_hit_counter(counter: &Arc<PolicyRuleCounter>, packet_bytes: u64) {
    PENDING_POLICY_HIT_RECORD.with(|pending| {
        let mut pending = pending.borrow_mut();
        let generation = counter.generation();
        // #3448: continue the current batch only when it is the SAME counter
        // AND the SAME clear epoch. A `clear` mid-batch advances the
        // generation; the else branch then flushes (and discards, via the
        // generation guard) the stale pre-clear tally and re-captures the
        // counter under the new generation, so post-clear packets are counted
        // fresh from zero instead of being dropped with the pre-clear batch.
        if pending
            .counter
            .as_ref()
            .is_some_and(|current| Arc::ptr_eq(current, counter))
            && pending.generation == generation
        {
            pending.packets = pending.packets.saturating_add(1);
            pending.bytes = pending.bytes.saturating_add(packet_bytes);
        } else {
            flush_pending_policy_hit_record(&mut pending);
            pending.counter = Some(counter.clone());
            pending.generation = generation;
            pending.packets = 1;
            pending.bytes = packet_bytes;
        }
        if pending.packets >= POLICY_HIT_FLUSH_PACKETS {
            flush_pending_policy_hit_record(&mut pending);
        }
    });
}

// In tests the coalescer is bypassed so a single recorded packet is
// immediately visible in `counter_snapshots()` (deterministic assertions).
#[cfg(test)]
#[inline(always)]
pub(crate) fn record_policy_hit_counter(counter: &Arc<PolicyRuleCounter>, packet_bytes: u64) {
    counter.add(packet_bytes);
}

/// #3073: flush this worker's pending policy hit-count tally to the shared
/// counters. Called once per RX batch (alongside
/// `filter::flush_recorded_filter_counters`) so `show security policies
/// hit-count` converges within one poll tick.
#[cfg(not(test))]
pub(crate) fn flush_recorded_policy_hit_counters() {
    PENDING_POLICY_HIT_RECORD.with(|pending| {
        flush_pending_policy_hit_record(&mut pending.borrow_mut());
    });
}

#[cfg(test)]
pub(crate) fn flush_recorded_policy_hit_counters() {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PortRange {
    pub(crate) low: u16,
    pub(crate) high: u16,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ApplicationMatch {
    pub(crate) protocol: u8,
    pub(crate) source_ports: Vec<PortRange>,
    pub(crate) destination_ports: Vec<PortRange>,
    /// #3020: optional ICMP/ICMPv6 type constraint. `Some(t)` restricts the
    /// term to ICMP messages of type `t` (e.g. junos-ping = type 8); `None`
    /// leaves the term unconstrained on type (the all-ICMP aliases). Only
    /// meaningful when `protocol` is ICMP/ICMPv6; ignored for TCP/UDP terms.
    pub(crate) icmp_type: Option<u8>,
    /// #3020: optional ICMP/ICMPv6 code constraint, paired with `icmp_type`.
    /// `None` matches any code of the constrained type.
    pub(crate) icmp_code: Option<u8>,
    /// #3227: optional per-application inactivity (idle) timeout in SECONDS.
    /// `Some(t)` (t > 0) overrides the global per-protocol session timeout for a
    /// flow admitted by this term; `None` (or 0) leaves the global timeout in
    /// effect (back-compat). Carried from the matched term into the session at
    /// install so the conntrack GC ages the session out on the app's value.
    pub(crate) inactivity_timeout: Option<u32>,
}

/// Pre-indexed application matcher: groups terms by protocol for O(1) lookup.
/// For exact single-port rules (the common case), stores them in a set
/// for O(1) hit instead of linear range scan.
#[derive(Clone, Debug)]
struct CompiledApplications {
    /// If true, matches any protocol/port (application "any").
    match_any: bool,
    /// Grouped by protocol for fast lookup. Key = protocol number.
    by_protocol: FxHashMap<u8, ProtoTerms>,
}

#[derive(Clone, Debug, Default)]
struct ProtoTerms {
    /// Exact destination port set (single-port terms compiled for O(1) lookup).
    /// #3227: the value carries the term's per-application inactivity timeout
    /// (`None` = use the global per-protocol timeout). #3346: the value also
    /// carries the term's CONFIG-ORDER index (`u32`) so cross-class precedence
    /// can honor Junos first-term-wins instead of always probing exact before
    /// range/icmp. First writer wins on an overlapping port (the lower config
    /// index, matching the catalog "first match wins" convention).
    exact_dst_ports: FxHashMap<u16, (u32, Option<u32>)>, // port -> (order, timeout)
    /// Port range terms that need linear scan (multi-port ranges). #3346: the
    /// leading `u32` is the term's config-order index; the trailing element is
    /// the #3227 inactivity timeout. Pushed in config order, so the first
    /// matching entry in the vector is the lowest-order matching range.
    range_terms: Vec<(u32, Vec<PortRange>, Vec<PortRange>, Option<u32>)>, // (order, src, dst, timeout)
    /// #3020: ICMP/ICMPv6 type[,code] constraints for icmp-constrained terms
    /// (e.g. junos-ping = type 8). #3346: each entry is `(config-order index,
    /// type, optional code, inactivity timeout)`. A packet matches this protocol
    /// via the icmp path iff its type (and code, when the entry constrains it)
    /// equals one of these entries. An UNCONSTRAINED ICMP term (junos-icmp-all)
    /// does NOT land here — it stays a `range_terms` entry with empty ranges,
    /// which matches every ICMP packet, so a rule citing both still matches all
    /// ICMP. Pushed in config order. #3227 added the timeout.
    icmp_constraints: Vec<(u32, u8, Option<u8>, Option<u32>)>, // (order, type, code, timeout)
}

impl CompiledApplications {
    fn from_matches(apps: &[ApplicationMatch]) -> Self {
        if apps.is_empty() {
            return Self {
                match_any: true,
                by_protocol: FxHashMap::default(),
            };
        }
        let mut by_protocol: FxHashMap<u8, ProtoTerms> = FxHashMap::default();
        // #3346: stamp each term with its CONFIG-ORDER index (the order the
        // operator listed the applications, preserved by the Go emit path —
        // capabilities.go resolveUserspaceApplicationNames, #3298). The index is
        // assigned across ALL terms of the rule; since matching is per-protocol,
        // the relative order WITHIN a protocol is what `matches` compares, and
        // that relative order is preserved by a single monotonic counter.
        for (order, app) in (0u32..).zip(apps.iter()) {
            let entry = by_protocol.entry(app.protocol).or_default();
            // #3020: an ICMP/ICMPv6 term with a type constraint (junos-ping)
            // is steered to `icmp_constraints` so it matches ONLY that type
            // (and code, when set) instead of every ICMP message. A term with
            // NO icmp_type constraint falls through to the existing port path —
            // an unconstrained ICMP term (junos-icmp-all) has empty ports and
            // lands as a `range_terms` entry with empty ranges (match-all), so a
            // rule citing both junos-ping AND junos-icmp-all still matches all
            // ICMP. (ICMP terms never carry ports in practice; the type
            // constraint takes precedence so a stray port is irrelevant here.)
            if app.icmp_type.is_some() {
                entry.icmp_constraints.push((
                    order,
                    app.icmp_type.expect("icmp_type is Some"),
                    app.icmp_code,
                    // #3227: carry the term's idle timeout onto the constraint.
                    app.inactivity_timeout,
                ));
            } else if app.source_ports.is_empty()
                && app.destination_ports.len() == 1
                && app.destination_ports[0].low == app.destination_ports[0].high
            {
                // #3227: store the term timeout keyed by exact port. #3346: also
                // store the config-order index. First writer wins on an
                // overlapping port (the lower order) so precedence is stable.
                entry
                    .exact_dst_ports
                    .entry(app.destination_ports[0].low)
                    .or_insert((order, app.inactivity_timeout));
            } else {
                entry.range_terms.push((
                    order,
                    app.source_ports.clone(),
                    app.destination_ports.clone(),
                    // #3227: carry the term's idle timeout onto the range entry.
                    app.inactivity_timeout,
                ));
            }
        }
        Self {
            match_any: false,
            by_protocol,
        }
    }

    /// #3020: `packet_icmp` carries the packet's ICMP/ICMPv6 `(type, code)` when
    /// the protocol is ICMP-family AND the bytes were safely readable (not a
    /// truncated frame or non-first fragment); `None` otherwise. It gates the
    /// icmp-type-constrained terms (junos-ping): a constrained term matches only
    /// when the type/code is known and equal, so an unknown type/code (or a
    /// non-ICMP packet) fails closed for those terms. Port/range terms are
    /// unaffected, so non-ICMP applications and the all-ICMP aliases behave
    /// exactly as before.
    ///
    /// #3227: the return type carries the matched term's per-application
    /// inactivity timeout so the install path can stamp it on the session:
    ///   - `None`              → no application term matched (rule does not apply)
    ///   - `Some(None)`        → matched, no custom timeout (use the global one)
    ///   - `Some(Some(secs))`  → matched, use this per-app idle timeout
    /// #3346: precedence among a rule's terms is CONFIG ORDER — the FIRST term
    /// the operator listed that matches supplies the timeout (Junos
    /// first-term-wins), regardless of which class (exact-port / range / icmp)
    /// it lands in. Each term carries its config-order index; this gathers the
    /// best (lowest-index) match across all three classes. The O(1) exact-port
    /// map is retained purely as a lookup accelerator for the common
    /// single-port term, NOT as a precedence tier — before #3346 it always beat
    /// a range/icmp term listed earlier, which diverged from vSRX. The match-any
    /// short-circuit yields `Some(None)` (use-global), so an `application any`
    /// rule is byte-identical to today. The boolean "does the rule apply?"
    /// verdict (`Some` vs `None`) is unchanged — only WHICH matched term's
    /// timeout is returned.
    /// #3291: `l4_present` is `false` for a flowless / no-L4 packet (a non-first
    /// fragment, whose post-IP bytes are payload — #2344). With no L4 header the
    /// caller cannot supply real ports (`src_port`/`dst_port` are 0), so a
    /// PORT-BEARING application term MUST fail closed (it can neither be
    /// confirmed nor allowed to spuriously match `port == 0`, e.g. a custom
    /// `destination-port 0-1023` range). A PROTOCOL-ONLY term (empty port
    /// ranges, e.g. an `application any`-of-this-protocol alias / junos-icmp-all)
    /// still matches on the known protocol so legitimately-permitted protocol/
    /// address policy keeps forwarding the fragment. Every flow-backed caller
    /// passes `l4_present = true`, so the L4 path is byte-identical to before.
    #[inline]
    fn matches(
        &self,
        protocol: u8,
        src_port: u16,
        dst_port: u16,
        packet_icmp: Option<(u8, u8)>,
        l4_present: bool,
    ) -> Option<Option<u32>> {
        if self.match_any {
            return Some(None);
        }
        let terms = self.by_protocol.get(&protocol)?;
        // #3346: track the lowest-config-order matching term across all classes.
        // `best` holds `(order, timeout)`; a smaller order wins (first listed).
        let mut best: Option<(u32, Option<u32>)> = None;
        // Exact dst-port term — O(1) accelerator for the common single-port case.
        // #3291: a known L4 port is required; a flowless packet (port 0) never
        // matches a port-specific term.
        if l4_present {
            if let Some(&(order, timeout)) = terms.exact_dst_ports.get(&dst_port) {
                best = Some((order, timeout));
            }
        }
        // Range terms (an unconstrained ICMP term, e.g. junos-icmp-all, lives
        // here as an empty-range entry → match-all). Pushed in config order, so
        // the first match in the vector is the lowest-order matching range.
        // #3291: an empty-range (protocol-only) term matches regardless of L4
        // presence — we know the protocol; a port-bearing range requires a known
        // L4 port and so fails closed for a flowless packet.
        if let Some(&(order, _, _, timeout)) = terms.range_terms.iter().find(
            |(_, src_ranges, dst_ranges, _)| {
                if src_ranges.is_empty() && dst_ranges.is_empty() {
                    true
                } else {
                    l4_present
                        && port_ranges_match(src_ranges, src_port)
                        && port_ranges_match(dst_ranges, dst_port)
                }
            },
        ) {
            if best.map_or(true, |(b, _)| order < b) {
                best = Some((order, timeout));
            }
        }
        // #3020: ICMP/ICMPv6 type[,code]-constrained terms (junos-ping). Match
        // only when the packet's type/code is known and equals a constraint.
        // When `packet_icmp` is None (non-ICMP packet, truncated frame, or
        // non-first fragment) the constrained term does NOT match — fail closed.
        if !terms.icmp_constraints.is_empty() {
            if let Some((ptype, pcode)) = packet_icmp {
                if let Some(&(order, _, _, timeout)) = terms.icmp_constraints.iter().find(
                    |&&(_, ctype, ccode, _)| ctype == ptype && ccode.map_or(true, |c| c == pcode),
                ) {
                    if best.map_or(true, |(b, _)| order < b) {
                        best = Some((order, timeout));
                    }
                }
            }
        }
        best.map(|(_, timeout)| timeout)
    }

    /// #4569: does this app set carry at least one term for `protocol` whose
    /// match is GATED by L4 presence — i.e. a term that `matches(..)` fails
    /// closed for a flowless / no-L4 packet (a non-first fragment, l4_present
    /// == false)? These are: an exact destination-port term, a port-RANGE term
    /// (non-empty src or dst ranges), or an ICMP/ICMPv6 type[,code] constraint.
    /// A PROTOCOL-ONLY term (empty ranges) and `application any` are NOT gated
    /// (they still match a flowless packet on the known protocol), so they
    /// return `false`.
    ///
    /// This is the discriminator the fragment-association fail-closed guard
    /// (`rule_is_skipped_frag_ambiguous_deny`) uses to tell a DENY that was
    /// SKIPPED for a flowless fragment ONLY because its L4-constrained term is
    /// inapplicable (→ fail closed the fragment) from a DENY that genuinely
    /// does not apply to this protocol at all (→ let the fragment proceed).
    /// #8618: does this app set carry an ICMP/ICMPv6 TYPE-constrained term for
    /// `protocol` — i.e. a junos-ping-style term (#3020) whose match depends on
    /// the PACKET's icmp type/code rather than on the flow's 5-tuple?
    ///
    /// This is deliberately NARROWER than `has_l4_constrained_term`, which also
    /// answers true for port-bearing terms. The question here is specifically
    /// "can a verdict for this protocol change with the icmp type", because that
    /// is the only thing `packet_icmp` influences: `matches()` reads it in
    /// exactly one arm, the `icmp_constraints` arm below.
    ///
    /// `match_any` returns FALSE on purpose. `application any` matches every
    /// ICMP message regardless of type, so a verdict resting on it is a flow
    /// property, not a packet property.
    fn has_icmp_type_constrained_term(&self, protocol: u8) -> bool {
        if self.match_any {
            return false;
        }
        self.by_protocol
            .get(&protocol)
            .is_some_and(|terms| !terms.icmp_constraints.is_empty())
    }

    fn has_l4_constrained_term(&self, protocol: u8) -> bool {
        if self.match_any {
            return false;
        }
        match self.by_protocol.get(&protocol) {
            None => false,
            Some(terms) => {
                !terms.exact_dst_ports.is_empty()
                    || terms
                        .range_terms
                        .iter()
                        .any(|(_, src, dst, _)| !(src.is_empty() && dst.is_empty()))
                    || !terms.icmp_constraints.is_empty()
            }
        }
    }
}

/// #2008 M5: the L3/L4 application-identification catalog. Resolves a session's
/// 5-tuple to the numeric `app_id` the dataplane stamps on the conntrack
/// session so `show security flow session` reports a real application name. The
/// `app_id` values are assigned on the Go side (`appid.BuildCatalog`) in
/// lock-step with `CompileResult.AppNames`, which the show path consumes — so a
/// stamped id round-trips to the correct name.
///
/// This is the read-the-id sibling of [`CompiledApplications`] (which only
/// answers a boolean "does this 5-tuple match the policy's app set?"). Lookup is
/// grouped by protocol, with exact single-destination-port entries in an O(1)
/// map and everything else (ranges, port-0/"protocol-only" entries) in a
/// per-protocol scan list. On overlap the winner is chosen by SPECIFICITY first
/// (a port-constrained entry beats a bare protocol-only one), then by lowest
/// `app_id` within a tier (#3612). Lowest id == the alphabetically-first name
/// because the Go builder emits entries in sorted-name / ascending-id order, so
/// the result is deterministic and stable across reloads and matches the
/// AppID-disabled Go fallback (`resolveTupleFallback`, #2578).
#[derive(Clone, Debug, Default)]
pub(crate) struct AppCatalog {
    by_protocol: FxHashMap<u8, AppProtoEntries>,
}

#[derive(Clone, Debug, Default)]
struct AppProtoEntries {
    /// app_id keyed by exact destination port, for single-port entries with no
    /// source-port constraint (the common case).
    exact_dst: FxHashMap<u16, u16>,
    /// Entries needing a scan: a port range, a source-port constraint, or no
    /// destination-port constraint at all (port-0 protocol-only entries). Each
    /// entry is tagged `port_constrained` so `lookup_directional` can rank a
    /// port-constrained overlap above a protocol-only one before falling back to
    /// lowest app_id within a tier (#3612).
    scan: Vec<AppScanEntry>,
}

#[derive(Clone, Debug)]
struct AppScanEntry {
    app_id: u16,
    dst_low: u16,
    dst_high: u16,
    src_low: u16,
    src_high: u16,
    /// #3612: true iff this entry carries a destination AND/OR source port
    /// constraint (i.e. it is NOT a bare protocol-only entry). Mirrors the
    /// AppID-disabled Go fallback's `portBased` predicate
    /// (`resolveTupleFallback`: `DestinationPort != "" || SourcePort != ""`)
    /// so `lookup_directional` can rank a port-constrained overlap above a
    /// protocol-only one identically to that path.
    port_constrained: bool,
}

impl AppCatalog {
    pub(crate) fn from_snapshot(entries: &[crate::AppCatalogEntry]) -> Self {
        let mut by_protocol: FxHashMap<u8, AppProtoEntries> = FxHashMap::default();
        for e in entries {
            // app_id 0 is the reserved "unknown" sentinel; never index it.
            if e.app_id == 0 {
                continue;
            }
            let bucket = by_protocol.entry(e.protocol).or_default();
            let single_dst = e.dst_port_low != 0
                && e.dst_port_low == e.dst_port_high
                && e.src_port_low == 0
                && e.src_port_high == 0;
            if single_dst {
                // First writer wins (lowest app_id) — matches the scan-list
                // "first match wins" rule for overlapping configs.
                bucket.exact_dst.entry(e.dst_port_low).or_insert(e.app_id);
            } else {
                // #3612: a scan entry is port-constrained unless ALL four port
                // bounds are zero (a bare protocol-only entry). This is the wire
                // mirror of the Go fallback's `portBased` — a `source-port`-only
                // app (dst (0,0), src set) is port-constrained on both sides.
                let port_constrained = !(e.dst_port_low == 0
                    && e.dst_port_high == 0
                    && e.src_port_low == 0
                    && e.src_port_high == 0);
                bucket.scan.push(AppScanEntry {
                    app_id: e.app_id,
                    dst_low: e.dst_port_low,
                    dst_high: e.dst_port_high,
                    src_low: e.src_port_low,
                    src_high: e.src_port_high,
                    port_constrained,
                });
            }
        }
        Self { by_protocol }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.by_protocol.is_empty()
    }

    /// Resolve the app_id for a session 5-tuple, honouring flow DIRECTION.
    ///
    /// The well-known service port is the DESTINATION on a forward-keyed
    /// session and the SOURCE on a reverse-keyed session. `is_reverse` selects
    /// which slot carries the service port, so the catalog's destination-port
    /// constraint is matched against the real service side ONLY — the lookup
    /// does not probe both slots. Both directions of one session still resolve
    /// to the same app_id because the caller passes the matching `is_reverse`
    /// for each direction (and the publisher stamps the forward + reverse
    /// conntrack entries from one resolution). Returns 0 (unknown) when nothing
    /// matches; 0 is the existing default the show path treats as "no AppID".
    ///
    /// #3321: the previous directionless probe matched the service port on
    /// EITHER slot. A forward flow whose CLIENT source port coincidentally
    /// equalled a service port (e.g. tcp `src=443, dst=ephemeral`) was then
    /// mislabeled as that service in session display / RT_FLOW create+close /
    /// policy-deny / filter-log records — log-integrity pollution during
    /// incident response. Matching on the directional service slot fixes it.
    #[inline]
    pub(crate) fn lookup_directional(
        &self,
        protocol: u8,
        src_port: u16,
        dst_port: u16,
        is_reverse: bool,
    ) -> u16 {
        let Some(bucket) = self.by_protocol.get(&protocol) else {
            return 0;
        };
        // Service port = destination on a forward flow, source on a reverse-
        // keyed flow; the client port is the other slot.
        let (service_port, client_port) = if is_reverse {
            (src_port, dst_port)
        } else {
            (dst_port, src_port)
        };
        // Exact single-port entries carry no source constraint by construction
        // (`from_snapshot` only routes src-unconstrained single-dst entries to
        // `exact_dst`), so an exact hit needs only the service port.
        let exact = bucket.exact_dst.get(&service_port).copied();
        // Scan entries (ranges / source-constrained / protocol-only).
        //
        // #3612: resolve overlaps by SPECIFICITY TIER first — a port-constrained
        // entry (a destination and/or source port constraint) outranks a bare
        // protocol-only entry — then by lowest app_id WITHIN a tier. This is the
        // exact binary-specificity rule the AppID-disabled Go fallback already
        // uses (`resolveTupleFallback`, #2578: `portBased` beats protocol-only,
        // ties broken by name == lowest id in sorted-name order), so the same
        // 5-tuple resolves to the same application label whether AppID is ON
        // (this catalog) or OFF (the Go fallback). `exact_dst` entries are always
        // port-constrained, so they participate in the port-constrained tier.
        //
        // Before #3612 the final tiebreak was a flat `exact.min(scan_hit)` —
        // lowest app_id regardless of tier. Because ids are assigned in
        // sorted-name order, that meant the alphabetically-first name won an
        // overlap, letting a broad protocol-only `aaa-tcp` shadow a specific
        // `zzz-https` on tcp/443. Within a single tier the result is unchanged
        // (still the lowest id), so this is strictly additive for same-tier
        // configs.
        let in_range = |low: u16, high: u16, p: u16| -> bool {
            // (0,0) means "no constraint".
            (low == 0 && high == 0) || (p >= low && p <= high)
        };
        let mut port_scan_hit: Option<u16> = None;
        let mut proto_only_scan_hit: Option<u16> = None;
        for s in &bucket.scan {
            // Destination constraint is matched against the service slot and
            // the source constraint against the client slot — directional, no
            // cross-slot probing.
            let dst_ok = in_range(s.dst_low, s.dst_high, service_port);
            let src_ok = in_range(s.src_low, s.src_high, client_port);
            if !(dst_ok && src_ok) {
                continue;
            }
            let slot = if s.port_constrained {
                &mut port_scan_hit
            } else {
                &mut proto_only_scan_hit
            };
            // Keep the lowest app_id per tier. The Go builder emits entries in
            // ascending-id order, but taking the min makes the tiebreak
            // independent of scan order.
            *slot = Some(slot.map_or(s.app_id, |cur| cur.min(s.app_id)));
        }
        // Port-constrained tier wins: combine the always-port-constrained exact
        // hit with the port-constrained scan hit and take the lowest id. Fall
        // back to the protocol-only tier only when no port-constrained entry
        // matched the flow.
        let port_based = match (exact, port_scan_hit) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (Some(a), None) | (None, Some(a)) => Some(a),
            (None, None) => None,
        };
        port_based.or(proto_only_scan_hit).unwrap_or(0)
    }

    /// Forward-keyed convenience wrapper: the service port is the destination.
    /// This is the common case for cold-path RT_FLOW / filter-log / policy-deny
    /// resolution where the 5-tuple is the received (forward) packet and there
    /// is no session-direction flag at the call site.
    #[inline]
    pub(crate) fn lookup_forward(&self, protocol: u8, src_port: u16, dst_port: u16) -> u16 {
        self.lookup_directional(protocol, src_port, dst_port, false)
    }

    /// #3416: resolve the AppID a session was ADMITTED under for the permit-side
    /// audit surfaces (RT_FLOW `SESSION_CREATE`/`SESSION_CLOSE` and the
    /// BPF-compatible conntrack publish). A forward DNAT / static-DNAT /
    /// inbound-NPTv6 flow has its policy evaluated against the POST-translation
    /// destination port (poll_descriptor `policy_dst_port`, #2345), so the
    /// permitted-flow audit AppID must use that same translated port — not the
    /// pre-NAT forward-key destination — or a port-forwarded service (public
    /// `:2222` -> internal `:22` admitted by `junos-ssh`) renders as
    /// UNKNOWN/the public-port app. This mirrors the deny-side fix that resolves
    /// from the post-translation `policy_dst_port` (`resolve_policy_deny_app_id`,
    /// #3058/#3185), making the permit side symmetric.
    ///
    /// `is_reverse` selects the service slot exactly as `lookup_directional`.
    /// The post-translation rewrite is applied ONLY to the FORWARD service slot
    /// (the destination). A reverse-keyed entry keeps its received service slot:
    /// the reverse key already carries the real internal service port, and the
    /// reverse NAT decision's `rewrite_dst_port` un-translates a destination
    /// back toward the client side, so applying it there would re-introduce the
    /// very mislabel this fixes. For a non-translated flow `rewrite_dst_port` is
    /// `None`, so the result is byte-identical to `lookup_directional`.
    #[inline]
    pub(crate) fn lookup_admitted(
        &self,
        protocol: u8,
        src_port: u16,
        dst_port: u16,
        is_reverse: bool,
        rewrite_dst_port: Option<u16>,
    ) -> u16 {
        let service_dst_port = if is_reverse {
            dst_port
        } else {
            rewrite_dst_port.unwrap_or(dst_port)
        };
        self.lookup_directional(protocol, src_port, service_dst_port, is_reverse)
    }
}

#[derive(Clone, Debug)]
pub(crate) struct PolicyState {
    pub(crate) default_action: PolicyAction,
    /// All rules in original order (kept for hit-counter reporting).
    pub(crate) rules: Vec<PolicyRule>,
    /// Zone-pair index: maps `(from_id, to_id)` packed u32 →
    /// indices into `rules`. Avoids scanning unrelated zone-pairs.
    zone_pair_index: FxHashMap<ZonePairKey, Vec<usize>>,
    /// #3090: wildcard `from-zone any` index — key = the concrete to-zone id,
    /// value = indices (config order) of rules whose from-zone is the Junos
    /// wildcard `any` and whose to-zone is that concrete zone. Such a rule
    /// matches a flow into that to-zone REGARDLESS of ingress zone. Consulted
    /// in the single-wildcard precedence tier (after the exact zone pair,
    /// before both-any and global).
    from_any_index: FxHashMap<u16, Vec<usize>>,
    /// #3090: wildcard `to-zone any` index — key = the concrete from-zone id,
    /// value = indices (config order) of rules whose to-zone is `any` and whose
    /// from-zone is that concrete zone. Matches a flow OUT of that from-zone
    /// regardless of egress zone.
    to_any_index: FxHashMap<u16, Vec<usize>>,
    /// #3090: `from-zone any to-zone any` rules (the least-specific wildcard
    /// tier), in config order. Matches every defined zone pair. Consulted after
    /// the single-wildcard tier and before global rules.
    both_any_indices: Vec<usize>,
    /// Indices of global rules (from_zone AND to_zone = "junos-global"; #9570
    /// narrowed this from "or").
    global_indices: Vec<usize>,
    /// #3783: the concrete (interface-assignable) zone-id universe for THIS
    /// snapshot — every non-zero, non-reserved id in `zone_name_to_id`, sorted
    /// and deduplicated. A wildcard (`from-zone any` / `to-zone any`) or an
    /// unscoped `junos-global` policy has no EXACT `(from,to)` pair, so the
    /// concrete pair a packet actually traverses would have no cold-path
    /// latency histogram slot; `configured_zone_pairs` materializes those pairs
    /// from this universe constrained by each wildcard/global scope so the
    /// #1635 histogram is not dark for the common vSRX catch-all design.
    /// Config-derived and deterministic, so both HA nodes derive the identical
    /// slot map from the identical config (the histogram is local per-node
    /// telemetry — not wire-synced — but its slot layout stays symmetric).
    concrete_zone_ids: Vec<u16>,
    /// #1606: deduplicated address-book table. Rules reference
    /// books by dense `u32` index (`PolicyRule::source_book_idxs`).
    pub(crate) books: Vec<BookEntry>,
    /// #1606: wire-ID → dense-index map used at parse time only.
    book_id_to_idx: FxHashMap<u32, u32>,
    /// #3019: true iff at least one rule names `junos-host` as its from OR to
    /// zone. The LocalDelivery junos-host policy gate is a NO-OP unless this is
    /// set, so a config with no junos-host policy keeps pre-#3019 host-bound
    /// behavior exactly (no risk of newly denying management traffic).
    has_junos_host_rules: bool,
    /// #8618: does ANY active PERMIT rule in this snapshot carry an ICMP /
    /// ICMPv6 type-constrained application term (junos-ping and its #3348
    /// aliases)? Indexed [0] = ICMP, [1] = ICMPv6.
    ///
    /// This is a WHOLE-SNAPSHOT predicate over `rules`, not a per-zone-pair one,
    /// and that is a deliberate choice rather than laziness. Answering it per
    /// zone pair means reproducing the five-tier applicability selection
    /// (`zone_pair_index`, from-any, to-any, `both_any_indices`,
    /// `global_indices`) at a second site. A tier added later and missed here
    /// would under-report, and under-reporting is the UNSAFE direction: it lets
    /// `policy_revalidation` act on a DENY that a type-constrained permit would
    /// have overturned, tearing down a flow the policy allows. Scanning `rules`
    /// wholesale cannot miss a tier, because every rule is in it. The cost of
    /// the coarser answer is over-declining — which is exactly the behaviour
    /// #8356 shipped for all ICMP — so the failure mode is "no worse than
    /// today" rather than "revokes a permitted flow".
    icmp_type_constrained_permit: [bool; 2],
    /// #3363: reserved hit counter for the IMPLICIT default-policy verdict
    /// (the result returned when a flow matches no configured zone-pair,
    /// wildcard, or `junos-global` policy). Before #3363 the default path
    /// returned `policy_counter_idx: 0` and incremented nothing, so an
    /// operator could not answer "how many packets are hitting the implicit
    /// default deny?". The counter is incremented on the cold path for every
    /// default verdict and (for default-permit) re-counted on the established
    /// fast path via [`DEFAULT_POLICY_COUNTER_IDX`]. Persisted in the
    /// `PolicyCounterStore` under [`DEFAULT_POLICY_COUNTER_RULE_ID`] so it
    /// survives snapshot rebuilds, and reported as that rule id in
    /// [`PolicyState::counter_snapshots`].
    pub(crate) default_counter: Arc<PolicyRuleCounter>,
    /// #3534: RT_FLOW session-log selection for the IMPLICIT default-policy
    /// verdict (`security policies default-policy-log session-init|
    /// session-close`). Stamped onto the default-verdict
    /// [`PolicyEvaluationResult`] so a default-PERMIT session carries the flags
    /// in its metadata and emits RT_FLOW_SESSION_CREATE/CLOSE like a named
    /// policy. Inert for a default-DENY/REJECT verdict (no session installed —
    /// the deny is already logged via the policy-deny record). Sourced from the
    /// snapshot at build time (see `build_forwarding_state_*`); the parser does
    /// not read it, so the legacy infallible test helper keeps them false.
    pub(crate) default_log_session_init: bool,
    pub(crate) default_log_session_close: bool,
    /// #3395: O(1) re-resolution map from a rule's stable `rule_id`
    /// (`stable_policy_rule_id`, or `DEFAULT_POLICY_COUNTER_RULE_ID` for the
    /// implicit default policy) to its CURRENT positional `policy_id` (#3056)
    /// in THIS snapshot. Built ONCE per snapshot in
    /// `parse_policy_state_with_counters` (not per session), so
    /// `reresolve_session_policy_id` is O(1) per lookup — the CLAUDE.md
    /// control-socket-contention rule forbids an O(sessions × rules) refresh.
    /// A bound session whose admitting rule survives the edit re-resolves to
    /// that rule's NEW positional id; a rule that was DELETED is absent from the
    /// map and falls back to the unattributed default-policy sentinel (#3395 /
    /// AGY catch — never the frozen positional id a later reorder could reassign
    /// to a different rule).
    rule_id_to_policy_id: FxHashMap<String, u32>,
}

impl Default for PolicyState {
    fn default() -> Self {
        Self {
            default_action: PolicyAction::Deny,
            rules: Vec::new(),
            zone_pair_index: FxHashMap::default(),
            from_any_index: FxHashMap::default(),
            to_any_index: FxHashMap::default(),
            both_any_indices: Vec::new(),
            global_indices: Vec::new(),
            // #3783: the Default state carries no zones, so the wildcard/global
            // histogram-slot expansion has an empty concrete-zone universe.
            concrete_zone_ids: Vec::new(),
            books: Vec::new(),
            book_id_to_idx: FxHashMap::default(),
            has_junos_host_rules: false,
            // #8618: armed in the rule loop; Default carries no rules.
            icmp_type_constrained_permit: [false; 2],
            default_counter: Arc::new(PolicyRuleCounter::default()),
            default_log_session_init: false,
            default_log_session_close: false,
            // #3395: empty map — the Default state carries no rules, so there
            // is nothing to re-resolve.
            rule_id_to_policy_id: FxHashMap::default(),
        }
    }
}

impl PolicyState {
    /// #8618: may an ICMP-family zone-policy verdict for `protocol` depend on
    /// the PACKET's icmp type/code, rather than on the flow alone?
    ///
    /// True when some active PERMIT rule carries a type-constrained term
    /// (junos-ping, #3020). A type-blind evaluation — `packet_icmp = None`,
    /// which is what every frame-independent caller supplies — cannot match such
    /// a term, so a DENY it returns may be an artefact of the missing type
    /// rather than the policy's real answer. A caller that acts on DENY must
    /// decline when this is true.
    ///
    /// False is the common case and the useful one. #9386 CORRECTS WHAT IT
    /// GUARANTEES, because the previous wording claimed VERDICT EQUIVALENCE and
    /// that is false: it said that with no type-constrained permit anywhere,
    /// `None` "yields exactly the verdict a fully-informed evaluation would,
    /// because `packet_icmp` is read in exactly one arm of
    /// `CompiledApplications::matches` ... and that arm is inert when no term
    /// populates it". The arm is not action-scoped — a type-constrained term on a
    /// **DENY** rule populates it too, and `matches` then fails that term closed
    /// for `packet_icmp = None` exactly as it does for a permit. This predicate
    /// tests only for a constrained PERMIT, so a constrained DENY leaves it
    /// false and the type-blind walk SKIPS that deny.
    ///
    /// What is actually guaranteed, and it is the property the gate exists for:
    /// **a type-blind evaluation can never manufacture a false DENY.** Skipping a
    /// constrained term can only make the walk fall through to a LATER rule, i.e.
    /// more permissive. So acting on a DENY returned here is safe; acting on a
    /// PERMIT is not an assertion that a fully-informed walk would agree.
    ///
    /// The ACCEPTED CONSEQUENCE, pinned by
    /// `a_type_constrained_deny_is_skipped_and_the_session_survives_9386`: on the
    /// established-session path a type-constrained DENY placed ahead of a broader
    /// permit is not enforced — the walk falls through to the permit and the
    /// session survives. Arming this predicate on a constrained DENY as well
    /// would NOT change that outcome (the derivation would decline instead of
    /// deriving Permit, and either way the session lives); it would only give up
    /// #8356 coverage for every ICMP flow on any box that has a constrained deny
    /// anywhere, because the predicate is whole-snapshot. Closing the residual
    /// means supplying the packet's type/code to that derivation, which its own
    /// contract forbids: it is deliberately frame-INDEPENDENT, because one
    /// packet's type is not the flow's property.
    pub(crate) fn icmp_verdict_may_depend_on_type(&self, protocol: u8) -> bool {
        match protocol {
            PROTO_ICMP => self.icmp_type_constrained_permit[0],
            PROTO_ICMPV6 => self.icmp_type_constrained_permit[1],
            // Not an ICMP family protocol: `packet_icmp` cannot influence it.
            _ => false,
        }
    }

    pub(crate) fn counter_snapshots(&self) -> Vec<PolicyRuleCounterStatus> {
        let mut snapshots: Vec<PolicyRuleCounterStatus> = self
            .rules
            .iter()
            .map(|rule| rule.hit_counter.snapshot(&rule.rule_id))
            .collect();
        // #3363: surface the implicit default-policy hit counter under its
        // reserved rule id so the Go control plane can read it (via the
        // reserved `DefaultPolicyCounterID` handle) and render a `Default
        // policy` row separated from the configured-rule totals.
        snapshots.push(
            self.default_counter
                .snapshot(DEFAULT_POLICY_COUNTER_RULE_ID),
        );
        snapshots
    }

    /// #3073: resolve the 1-based hit-counter handle stamped onto a session at
    /// install (`SessionMetadata::policy_counter_idx`) back to the admitting
    /// rule's shared counter, so the established fast path can re-count every
    /// packet of the flow. `0` (no counter) and any stale handle past the
    /// current rule table (a config reload shrank the policy set) resolve to
    /// `None` and are silently skipped — never a panic, never a wrong-rule
    /// increment past the table end. A handle that still points within the
    /// table after an unrelated config change may briefly attribute packets to
    /// whatever rule now sits at that index; counters are advisory and this
    /// only affects in-flight sessions across a live policy edit.
    pub(crate) fn hit_counter_by_idx(&self, idx: u32) -> Option<&Arc<PolicyRuleCounter>> {
        if idx == 0 {
            return None;
        }
        // #3363: the reserved default-policy handle routes to the reserved
        // counter (not into `rules`), so a default-PERMIT session binds it at
        // install and re-counts every packet on the established fast path.
        if idx == DEFAULT_POLICY_COUNTER_IDX {
            return Some(&self.default_counter);
        }
        self.rules
            .get((idx - 1) as usize)
            .map(|rule| &rule.hit_counter)
    }

    /// #3322: resolve the hit counter to increment for an ESTABLISHED-session
    /// packet. Prefers the reorder-stable BOUND handle stamped on the session
    /// at install (`SessionMetadata::policy_counter`) over re-resolving the
    /// positional `policy_counter_idx` against the CURRENT rule table.
    ///
    /// The positional index is only valid relative to the rule table that was
    /// live when the session was admitted. After a live policy insert/reorder
    /// the same index points at whatever rule now occupies that slot, so the
    /// pre-#3322 `hit_counter_by_idx(idx)` resolution attributed an in-flight
    /// session's packets to the wrong rule (the original admitting rule stopped
    /// counting). The bound Arc is captured once at install (when the index is
    /// still correct) and is the same instance the persistent
    /// `PolicyCounterStore` re-hands for the rule's stable `rule_id` across
    /// snapshot rebuilds, so it follows the admitting rule through reorders.
    ///
    /// `bound == None` (idx-0 sessions, peer-synced sessions carrying only the
    /// wire index) falls back to `hit_counter_by_idx`, preserving pre-#3322
    /// behavior. A `None` result (no per-rule counter / stale index past a
    /// shrunk table) is silently skipped by the caller — never a panic.
    #[inline]
    pub(crate) fn resolve_session_hit_counter<'a>(
        &'a self,
        bound: Option<&'a Arc<PolicyRuleCounter>>,
        idx: u32,
    ) -> Option<&'a Arc<PolicyRuleCounter>> {
        bound.or_else(|| self.hit_counter_by_idx(idx))
    }

    /// #3395: re-resolve the CURRENT positional `policy_id` (#3056) for an
    /// ESTABLISHED session at a local publish surface (the ~1s live-row refresh
    /// and the RT_FLOW SESSION_CLOSE emit), so a live mid-list policy
    /// insert/delete no longer mis-attributes the session.
    ///
    /// `policy_id` is span-accumulated in config order (`walkPolicyRuleSlots`),
    /// frozen onto the session at install. A live policy edit that perturbs
    /// earlier positions renumbers every later rule, so the frozen id resolves
    /// to a DIFFERENT policy's name afterwards. This is the display/forensic
    /// sibling of the #3322 hit-counter misattribution, fixed by the same
    /// bound-handle re-resolution pattern — `policy_id` itself MUST stay
    /// positional (the #3063 `show security policies` Index contract), so
    /// stability comes from re-resolving at read time, NOT from making the
    /// scalar content-stable.
    ///
    /// Resolution:
    /// - `bound = Some(counter)` with a non-empty stable `rule_id` that is still
    ///   present in this snapshot → the rule's NEW current positional id (#3063
    ///   Index↔RT_FLOW equality preserved for the re-resolved value).
    /// - `bound = Some(counter)` whose admitting rule was DELETED (its `rule_id`
    ///   is absent from the current map) → the unattributed default-policy
    ///   sentinel ([`DEFAULT_POLICY_SENTINEL_ID`], rendered `default-policy` by
    ///   the Go log/display planes). Resolving to the FROZEN positional id here
    ///   would be unsafe: a later reorder can shift a different extant rule into
    ///   that index, so the session would log under the WRONG policy name (the
    ///   AGY correctness catch). An honest "no longer attributable to an extant
    ///   rule" beats a confidently-wrong name.
    /// - `bound = None` (idx-0 non-policy sessions: host-local / neighbor-seed /
    ///   fabric / tunnel; or a peer-synced session carrying only the wire
    ///   scalar) → keep the frozen `stamped` id. There is no local stable
    ///   identity to re-resolve from, so this preserves pre-#3395 behavior. For
    ///   a peer-synced session this is the documented, deferred HA-peer-after-
    ///   reorder residual (P2 — the #3322 "rule-id-on-wire" follow-up).
    /// - `bound = Some(counter)` with an EMPTY `rule_id` (a `Default`
    ///   placeholder that never flowed through `rule_hit_counter`; not produced
    ///   on any production path) → keep the frozen `stamped` id (safe guard).
    #[inline]
    pub(crate) fn reresolve_session_policy_id(
        &self,
        bound: Option<&Arc<PolicyRuleCounter>>,
        stamped: u32,
    ) -> u32 {
        match bound {
            Some(counter) => {
                let rule_id = counter.rule_id();
                if rule_id.is_empty() {
                    return stamped;
                }
                self.rule_id_to_policy_id
                    .get(rule_id)
                    .copied()
                    .unwrap_or(DEFAULT_POLICY_SENTINEL_ID)
            }
            None => stamped,
        }
    }

    /// #1635/#3783: the set of concrete `(from_zone_id, to_zone_id)` pairs the
    /// configured policy can distinguish, used to build the cold-path
    /// histogram's direct slot map. The recording site
    /// (`poll_descriptor::lookup_slot`) keys on the CONCRETE ingress/egress
    /// zone-ids a packet traverses, so every concrete pair a configured policy
    /// can match MUST appear here or its first-packet latency sample is
    /// silently dropped on a slot-map miss.
    ///
    /// Two tiers, in slot-priority order:
    ///
    ///   1. EXACT `zone_pair_index` pairs (the historical set). Emitted FIRST
    ///      so a mixed config never starves an explicitly-named pair of its
    ///      slot behind a large wildcard expansion.
    ///   2. #3783 wildcard/global expansion — the concrete pairs implied by the
    ///      `from-zone any` / `to-zone any` / `from-zone any to-zone any`
    ///      tiers (#3090) and by `junos-global` rules (#3148), each constrained
    ///      by its scope and materialized against `concrete_zone_ids`. Without
    ///      this a catch-all-only deployment (`from-zone any to-zone <z>` /
    ///      `security policies global`) produced ZERO exact pairs, so the
    ///      histogram was dark for exactly the common vSRX catch-all design.
    ///
    /// Reserved sentinels (`junos-host` / `junos-global`, id
    /// `>= ZONE_ID_RESERVED_MIN`) and the id-0 unknown-zone are excluded on both
    /// tiers — they never form a transit zone-pair the histogram measures. The
    /// two tiers are each individually sorted and mutually disjoint, so slot
    /// assignment is deterministic (HA-symmetric — both nodes derive the
    /// identical slot map from the identical config). If the union exceeds the
    /// 255-slot capacity the surplus is dropped by `ColdPathSlotMap::build`
    /// (its `overflow_active` flag surfaces the starvation to operators) —
    /// exact pairs win because they are assigned first.
    pub(crate) fn configured_zone_pairs(&self) -> Vec<(u16, u16)> {
        use std::collections::BTreeSet;

        // A concrete, addressable transit zone id: non-zero and outside the
        // reserved sentinel range.
        #[inline]
        fn is_concrete(id: u16) -> bool {
            id != 0 && id < ZONE_ID_RESERVED_MIN
        }

        // Tier 1: exact configured pairs (historical behavior).
        let exact: BTreeSet<(u16, u16)> = self
            .zone_pair_index
            .keys()
            .map(|&key| (((key >> 16) & 0xffff) as u16, (key & 0xffff) as u16))
            .filter(|&(from, to)| is_concrete(from) && is_concrete(to))
            .collect();

        // The concrete-zone universe a wildcard `any` / unscoped-global side
        // can resolve to at runtime.
        let concrete: Vec<u16> = self
            .concrete_zone_ids
            .iter()
            .copied()
            .filter(|&z| is_concrete(z))
            .collect();

        // Tier 2: expand the wildcard/global scopes into the concrete pairs
        // they match. Kept in a separate set so tier-1 retains slot priority.
        let mut wildcard: BTreeSet<(u16, u16)> = BTreeSet::new();

        // `from-zone any to-zone <Z>`: any concrete ingress zone -> Z.
        for &to_id in self.from_any_index.keys() {
            if !is_concrete(to_id) {
                continue;
            }
            for &from in &concrete {
                wildcard.insert((from, to_id));
            }
        }
        // `to-zone any from-zone <F>`: F -> any concrete egress zone.
        for &from_id in self.to_any_index.keys() {
            if !is_concrete(from_id) {
                continue;
            }
            for &to in &concrete {
                wildcard.insert((from_id, to));
            }
        }
        // `from-zone any to-zone any`: every concrete pair.
        if !self.both_any_indices.is_empty() {
            for &from in &concrete {
                for &to in &concrete {
                    wildcard.insert((from, to));
                }
            }
        }
        // `junos-global` rules, each scoped by its optional `match from-zone` /
        // `match to-zone` context (#3148/#4626). `Any` expands to the full
        // concrete universe; a `Zones` SET expands to each of its CONCRETE
        // members (a reserved id like junos-host contributes no transit pair).
        for &idx in &self.global_indices {
            let rule = &self.rules[idx];
            let expand_side = |scope: &GlobalZoneScope| -> Vec<u16> {
                match scope {
                    GlobalZoneScope::Any => concrete.clone(),
                    GlobalZoneScope::Zones(zs) => {
                        zs.iter().copied().filter(|&z| is_concrete(z)).collect()
                    }
                }
            };
            let from_ids = expand_side(&rule.global_from_zone);
            let to_ids = expand_side(&rule.global_to_zone);
            for &from in &from_ids {
                for &to in &to_ids {
                    wildcard.insert((from, to));
                }
            }
        }

        // Exact pairs first (slot priority), then the additional wildcard/global
        // pairs not already covered by an exact pair. Both halves are sorted
        // (BTreeSet), so the whole assignment is deterministic and HA-symmetric.
        let mut pairs: Vec<(u16, u16)> = Vec::with_capacity(exact.len() + wildcard.len());
        pairs.extend(exact.iter().copied());
        pairs.extend(wildcard.into_iter().filter(|p| !exact.contains(p)));
        pairs
    }
}

/// Legacy infallible wrapper used by unit tests with hand-built rules and a
/// matching zone table. It passes NO address books, so the book-ID integrity
/// errors cannot fire; but it CAN still panic on a rule-level integrity error
/// (an unknown action #3365, an unrepresentable address/application, or — since
/// #3402 — a zone name absent from `zone_name_to_id`). Tests that exercise those
/// rejection paths must call `parse_policy_state_with_counters` and match the
/// `Err`. Callers here are expected to pass only well-formed rules whose zones
/// resolve.
pub(crate) fn parse_policy_state(
    default_policy: &str,
    rules: &[PolicyRuleSnapshot],
    zone_name_to_id: &FxHashMap<String, u16>,
) -> PolicyState {
    let counter_store = PolicyCounterStore::default();
    parse_policy_state_with_counters(default_policy, rules, zone_name_to_id, &[], &counter_store)
        .expect("parse_policy_state: rules must be well-formed (no books; zones must resolve)")
}

/// #1606: fallible policy-state parser. Returns
/// `SnapshotIntegrityError` for duplicate/zero/unknown book IDs.
/// Callers MUST run this as a preflight before any side-effecting
/// snapshot mutation (see `server/handlers/snapshot.rs::apply`).
pub(crate) fn parse_policy_state_with_counters(
    default_policy: &str,
    rules: &[PolicyRuleSnapshot],
    zone_name_to_id: &FxHashMap<String, u16>,
    address_books: &[AddressBookSnapshot],
    counter_store: &PolicyCounterStore,
) -> Result<PolicyState, SnapshotIntegrityError> {
    // #3365: an EMPTY default_policy is the legitimate `omitempty`/unspecified
    // wire state and decodes to the default-deny posture. A NON-EMPTY string
    // that is not permit/reject/deny is rejected (fail closed) rather than
    // silently collapsing to Deny.
    let default_action = if default_policy.is_empty() {
        PolicyAction::Deny
    } else {
        parse_action(default_policy).ok_or_else(|| SnapshotIntegrityError::UnknownPolicyAction {
            context: "default-policy".to_string(),
            action: default_policy.to_string(),
        })?
    };
    // #3713: preflight rule-identity uniqueness BEFORE allocating any per-rule
    // hit counter (`counter_store.rule_hit_counter`) or building a PolicyRule
    // entry. The Rust parser is the ONLY enforcement plane in the retired-eBPF
    // world; a corrupt / hand-built / mixed-version-HA-peer snapshot can carry
    // two rules that resolve to an identical stable `rule_id` (an identical
    // explicit wire rule_id, or an identical synthesized `from->to/name` key
    // from a duplicate policy name in a zone pair) or an identical positional
    // `policy_id`. Both alias the runtime identity: the rule_id is the
    // get-or-insert key for `rule_hit_counter` (two rules would SHARE one
    // `Arc<PolicyRuleCounter>` and collapse their totals onto one row), and the
    // policy_id is the RT_FLOW / SESSION_CLOSE / display join key AND the
    // last-writer-wins value in `rule_id_to_policy_id` (a duplicate lets an
    // existing session re-resolve to the WRONG policy). Rejecting the WHOLE
    // snapshot (this preflight is non-mutating, so the store keeps the previous
    // good state; a fresh boot keeps the default-deny PolicyState) mirrors
    // `DuplicateAddressBookId` and the #2124/#3261/#3367/#3711 fail-closed
    // family. Run FIRST so no transient counter is observed for a snapshot that
    // is then rejected (L14). The policy_id check (M01) excludes the reserved
    // implicit-default sentinel (`DEFAULT_POLICY_SENTINEL_ID`) and the
    // `omitempty` zero-value 0 (both the valid first-policy id AND the
    // "unspecified" value an older/pre-policy_id producer leaves on every rule);
    // see the per-value rationale at the check below.
    {
        let mut seen_rule_ids: FxHashSet<String> = FxHashSet::default();
        seen_rule_ids.reserve(rules.len());
        let mut seen_policy_ids: FxHashSet<u32> = FxHashSet::default();
        seen_policy_ids.reserve(rules.len());
        for snap in rules {
            let rule_id = stable_policy_rule_id(snap);
            if !seen_rule_ids.insert(rule_id.clone()) {
                return Err(SnapshotIntegrityError::DuplicateRuleId { rule_id });
            }
            // M01: only a real, ASSIGNED positional policy_id is checked for
            // uniqueness. Two values are excluded:
            //   - DEFAULT_POLICY_SENTINEL_ID (u32::MAX): the implicit default,
            //     never carried by a configured rule.
            //   - 0: the `omitempty` wire zero-value. It is simultaneously the
            //     valid FIRST-policy id AND the "unspecified" value a
            //     pre-policy_id (pre-#3056/#3057) producer or an older HA peer
            //     leaves on EVERY rule. Rejecting a duplicate 0 would fail-close
            //     a legitimate older-peer / hand-built snapshot that simply
            //     omits policy_id (all-zero) — an availability regression during
            //     a rolling upgrade, not the aliasing corruption this guards.
            // A genuine collision of two DISTINCT rules on a real assigned
            // (non-zero) positional policy_id is still caught: that is the
            // RT_FLOW / SESSION_CLOSE / display join-key aliasing M01 targets.
            if snap.policy_id != 0
                && snap.policy_id != DEFAULT_POLICY_SENTINEL_ID
                && !seen_policy_ids.insert(snap.policy_id)
            {
                return Err(SnapshotIntegrityError::DuplicatePolicyId {
                    policy_id: snap.policy_id,
                });
            }
        }
    }
    // #3783: capture the concrete (interface-assignable) zone-id universe from
    // the incoming snapshot's zone table so `configured_zone_pairs` can
    // materialize the concrete pairs that a wildcard/global-only policy will
    // actually match — otherwise those pairs get no cold-path histogram slot
    // and their first-packet latency samples are silently dropped. Reserved
    // sentinels (junos-host / junos-global, id >= ZONE_ID_RESERVED_MIN) and the
    // id-0 "unknown zone" are excluded — they never form a transit zone-pair.
    let mut concrete_zone_ids: Vec<u16> = zone_name_to_id
        .values()
        .copied()
        .filter(|&id| id != 0 && id < ZONE_ID_RESERVED_MIN)
        .collect();
    concrete_zone_ids.sort_unstable();
    concrete_zone_ids.dedup();

    let mut state = PolicyState {
        default_action,
        rules: Vec::with_capacity(rules.len()),
        zone_pair_index: FxHashMap::default(),
        from_any_index: FxHashMap::default(),
        to_any_index: FxHashMap::default(),
        both_any_indices: Vec::new(),
        global_indices: Vec::new(),
        // #3783: the concrete-zone universe backing the wildcard/global
        // histogram-slot expansion (computed above from `zone_name_to_id`).
        concrete_zone_ids,
        books: Vec::with_capacity(address_books.len()),
        book_id_to_idx: FxHashMap::default(),
        // #3019: armed below if any rule names the `junos-host` self zone.
        has_junos_host_rules: false,
        // #8618: armed in the same rule loop, same shape.
        icmp_type_constrained_permit: [false; 2],
        // #3363: persistent reserved counter for the implicit default-policy
        // verdict. Re-handed from the store under the reserved rule id so the
        // Arc instance is stable across snapshot rebuilds (an in-flight
        // default-permit session's bound counter keeps pointing at it).
        default_counter: counter_store.rule_hit_counter(DEFAULT_POLICY_COUNTER_RULE_ID),
        // #3534: set by the snapshot build site (build_forwarding_state_*) from
        // ConfigSnapshot.default_log_session_init/close. Not derived from the
        // policy rules, so the parser leaves them false here; the legacy
        // infallible test helper (parse_policy_state) therefore keeps them off.
        default_log_session_init: false,
        default_log_session_close: false,
        // #3395: populated after the rule loop below (the rules carry both the
        // stable rule_id and the positional policy_id).
        rule_id_to_policy_id: FxHashMap::default(),
    };

    // #1606: build the dense book table first. Hard-fail on
    // integrity errors (id=0, duplicate ids).
    for snap in address_books {
        if snap.id == 0 {
            return Err(SnapshotIntegrityError::AddressBookIdZero);
        }
        if state.book_id_to_idx.contains_key(&snap.id) {
            return Err(SnapshotIntegrityError::DuplicateAddressBookId(snap.id));
        }
        // Parse v4 / v6 literals using the v3 factory: empty
        // collapses to MatchNone (NOT MatchAny). A v4-only book
        // gets entry.v6 = MatchNone, etc.
        //
        // #3711: fail the whole snapshot CLOSED on a malformed OR wrong-family
        // book prefix. The pre-fix builder used the family-agnostic
        // non-reporting parser, which (a) silently dropped an unparseable token
        // — an all-dropped family then collapsed to MatchNone via
        // `from_v3_literals`, so a book-backed `deny` matched nothing and fell
        // through to a later permit / default-permit (fail-OPEN, the v3 sibling
        // of #3367), and (b) routed a wrong-family token into the opposite
        // family's set (M02, contradicting the family-named wire contract).
        // `parse_book_prefix_into` enforces the declared family and reports
        // both failures. Checked in the book loop (before the rule loop) so the
        // whole preflight stays non-mutating and keeps the previous good state.
        let mut v4: Vec<PrefixV4> = Vec::with_capacity(snap.prefixes_v4.len());
        let mut v6: Vec<PrefixV6> = Vec::with_capacity(snap.prefixes_v6.len());
        for s in &snap.prefixes_v4 {
            if !parse_book_prefix_into(s, true, &mut v4, &mut v6) {
                return Err(SnapshotIntegrityError::UnrepresentableAddressBookPrefix {
                    book_id: snap.id,
                    book_name: snap.name.clone(),
                    family: "v4",
                    address: s.clone(),
                });
            }
        }
        for s in &snap.prefixes_v6 {
            if !parse_book_prefix_into(s, false, &mut v4, &mut v6) {
                return Err(SnapshotIntegrityError::UnrepresentableAddressBookPrefix {
                    book_id: snap.id,
                    book_name: snap.name.clone(),
                    family: "v6",
                    address: s.clone(),
                });
            }
        }
        let entry = BookEntry {
            v4: PrefixSetV4::from_v3_literals(v4),
            v6: PrefixSetV6::from_v3_literals(v6),
        };
        let dense_idx = state.books.len() as u32;
        state.books.push(entry);
        state.book_id_to_idx.insert(snap.id, dense_idx);
    }

    for snap in rules {
        let source_is_v3_shaped =
            !snap.source_book_ids.is_empty() || !snap.source_literals.is_empty();
        let destination_is_v3_shaped = !snap.destination_book_ids.is_empty()
            || !snap.destination_literals.is_empty();

        // Build literal prefix sets per side using the appropriate
        // factory. #3367 (legacy path) / #3711 (v3 path): BOTH shapes report a
        // malformed literal (an unparseable token that is not `any` / a family
        // wildcard / the sentinel) so the rule can be failed closed below
        // instead of silently collapsing the side — MatchAny on the empty
        // legacy path (widening a deny), or MatchNone on the v3 path (letting a
        // deny fall through to default-permit).
        let mut legacy_malformed: Option<String> = None;
        let mut v3_malformed: Option<String> = None;
        let (source_literal_v4, source_literal_v6) = if source_is_v3_shaped {
            let (v4, v6, malformed) = parse_v3_literal_set(&snap.source_literals);
            if v3_malformed.is_none() {
                v3_malformed = malformed;
            }
            (v4, v6)
        } else {
            let (v4, v6, malformed) = parse_legacy_address_set(&snap.source_addresses);
            if legacy_malformed.is_none() {
                legacy_malformed = malformed;
            }
            (v4, v6)
        };
        let (destination_literal_v4, destination_literal_v6) = if destination_is_v3_shaped {
            let (v4, v6, malformed) = parse_v3_literal_set(&snap.destination_literals);
            if v3_malformed.is_none() {
                v3_malformed = malformed;
            }
            (v4, v6)
        } else {
            let (v4, v6, malformed) = parse_legacy_address_set(&snap.destination_addresses);
            if legacy_malformed.is_none() {
                legacy_malformed = malformed;
            }
            (v4, v6)
        };

        let rule_id = stable_policy_rule_id(snap);

        // #3261: reject the WHOLE snapshot if the rule carries the
        // unrepresentable-address sentinel (undefined book name, or a defined
        // book whose value is a non-literal dns-name/wildcard/range). Mirrors
        // the application-term `dropped_any` reject below. Without it the
        // address side would silently collapse to MatchNone and a
        // `deny <unrepresentable-address>` rule would fall through to a later
        // permit / default-permit (deny fail-open). Checked BEFORE book
        // resolution and the malformed-literal rejects below; the v3/legacy
        // literal parses above are non-mutating local scratch (#3729 review).
        //
        // #3367/#3711: checked BEFORE the malformed-literal rejects below — the
        // sentinel is the more specific cause (an undefined book / non-literal
        // value the Go gate already flagged), and it parses as malformed too on
        // the v3 path, so the sentinel diagnostic would otherwise be masked by
        // the generic unparseable-literal error.
        if rule_has_unrepresentable_address_sentinel(snap) {
            return Err(SnapshotIntegrityError::UnrepresentableAddress { rule_id });
        }

        // #3711: a malformed v3 address literal (an unparseable token on the
        // `source_literals`/`destination_literals` field that is not `any` / a
        // family wildcard / the sentinel) is a snapshot-integrity error. Without
        // this the side would silently drop the token and collapse to MatchNone
        // (the v3 factory), so a `deny <malformed>` rule would match nothing and
        // fall through to a later permit / default-permit (deny fail-OPEN).
        // Checked BEFORE book resolution so the preflight stays non-mutating.
        if let Some(address) = v3_malformed {
            return Err(SnapshotIntegrityError::UnrepresentableV3Address { rule_id, address });
        }

        // #3367: a malformed legacy address literal (an unparseable token on the
        // `source_addresses`/`destination_addresses` field that is not the
        // sentinel) is a snapshot-integrity error. Without this the side would
        // silently drop the token and collapse to MatchAny on the empty->match-any
        // legacy path, widening a deny rule. Checked BEFORE any book resolution so
        // the preflight stays non-mutating and keeps the previous good state.
        if let Some(address) = legacy_malformed {
            return Err(SnapshotIntegrityError::UnrepresentableLegacyAddress { rule_id, address });
        }

        // Resolve book IDs to dense indices. Sort + dedup + hard
        // fail on unknown.
        let source_book_idxs =
            resolve_book_idxs(&state.book_id_to_idx, &snap.source_book_ids, &rule_id)?;
        let destination_book_idxs =
            resolve_book_idxs(&state.book_id_to_idx, &snap.destination_book_ids, &rule_id)?;

        // Precompute match-any flags. True iff EITHER the literal
        // set OR any cited book's v4/v6 is MatchAny.
        let source_v4_match_any = source_literal_v4.is_match_any()
            || source_book_idxs
                .iter()
                .any(|&i| state.books[i as usize].v4.is_match_any());
        let source_v6_match_any = source_literal_v6.is_match_any()
            || source_book_idxs
                .iter()
                .any(|&i| state.books[i as usize].v6.is_match_any());
        let destination_v4_match_any = destination_literal_v4.is_match_any()
            || destination_book_idxs
                .iter()
                .any(|&i| state.books[i as usize].v4.is_match_any());
        let destination_v6_match_any = destination_literal_v6.is_match_any()
            || destination_book_idxs
                .iter()
                .any(|&i| state.books[i as usize].v6.is_match_any());

        // #2008 fail-open hardening: a side's family set is "empty"
        // (matches nothing) iff it is not match-any, its literal is
        // MatchNone, and every cited book's family set is MatchNone.
        // This is the structural complement used to fail-CLOSED an
        // empty *_excluded set (see try_match_rule) instead of
        // inverting it into match-all.
        let source_v4_empty = !source_v4_match_any
            && source_literal_v4.is_match_none()
            && source_book_idxs
                .iter()
                .all(|&i| state.books[i as usize].v4.is_match_none());
        let source_v6_empty = !source_v6_match_any
            && source_literal_v6.is_match_none()
            && source_book_idxs
                .iter()
                .all(|&i| state.books[i as usize].v6.is_match_none());
        let destination_v4_empty = !destination_v4_match_any
            && destination_literal_v4.is_match_none()
            && destination_book_idxs
                .iter()
                .all(|&i| state.books[i as usize].v4.is_match_none());
        let destination_v6_empty = !destination_v6_match_any
            && destination_literal_v6.is_match_none()
            && destination_book_idxs
                .iter()
                .all(|&i| state.books[i as usize].v6.is_match_none());

        // Pre-declare applications + compiled_apps as locals so the
        // struct literal can name every field explicitly — this
        // drops the `..PolicyRule::default()` tail entirely and
        // forces a compile error on any future field addition until
        // the constructor is updated, eliminating the silent-zero-
        // default hazard (originally raised by AGY r2 D on #1632).
        // #2124: parse the application terms and FAIL CLOSED if a rule cites
        // application terms and ANY of them is unrepresentable (unparseable
        // protocol or port). Dropping a term silently is the security fail-open
        // this fixes: an all-dropped rule would collapse to match-any (a permit
        // over-matching), and a PARTIALLY-dropped rule would NARROW the match —
        // for a deny rule that narrowing lets traffic the deny meant to block
        // fall through to a later permit / default-permit. Rejecting on
        // `dropped_any` (not just all-dropped) is action-agnostic for permit
        // and deny alike. The Go capability gate rejects any unrepresentable
        // term before publish (and emits a `__unsupported__` sentinel for the
        // failed-expansion case), so a normal Go snapshot never trips this; it
        // is the backstop for that sentinel and for any corrupt/non-Go
        // snapshot. Genuinely-empty terms (`application any`) drop nothing, so
        // `dropped_any == false` and the rule stays match-any.
        let parsed = parse_applications(&snap.application_terms);
        if parsed.dropped_any {
            return Err(SnapshotIntegrityError::UnrepresentableApplicationProtocol {
                rule_id: rule_id.clone(),
            });
        }
        // #3712: fail the whole snapshot closed when an application term carries a
        // semantically-invalid ICMP field combination (icmp-code without
        // icmp-type → match-all-ICMP fail-open; icmp-type/code on a non-ICMP
        // protocol → never-match, letting a deny fall through to default-permit).
        // The Go strict commit gate (#3348) is the primary defense; this is the
        // helper-boundary backstop for the lenient / peer-sync / corrupt-snapshot
        // path, consistent with the #2124/#3367/#3711 fail-closed family.
        if let Some((application, reason)) = parsed.invalid_icmp {
            return Err(SnapshotIntegrityError::InvalidApplicationIcmpFields {
                rule_id: rule_id.clone(),
                application,
                reason,
            });
        }
        let applications = parsed.matches;
        let compiled_apps = CompiledApplications::from_matches(&applications);

        let rule = PolicyRule {
            rule_id: rule_id.clone(),
            policy_id: snap.policy_id,
            from_zone: snap.from_zone.clone(),
            to_zone: snap.to_zone.clone(),
            // #3148/#4626 M03: resolve the optional global-policy zone SCOPE
            // SET. The effective list prefers the plural match_*_zones wire
            // field and falls back to the singular match_*_zone (rolling-upgrade
            // safety). Empty → Any (all zones). Inert for non-global rules (both
            // empty). #3402: an unresolvable element fails the whole snapshot
            // closed.
            global_from_zone: build_global_zone_scope(
                zone_name_to_id,
                &effective_match_zones(&snap.match_from_zones, &snap.match_from_zone),
                &rule_id,
            )?,
            global_to_zone: build_global_zone_scope(
                zone_name_to_id,
                &effective_match_zones(&snap.match_to_zones, &snap.match_to_zone),
                &rule_id,
            )?,
            scheduler_name: snap.scheduler_name.clone(),
            inactive: snap.inactive,
            source_literal_v4,
            source_literal_v6,
            destination_literal_v4,
            destination_literal_v6,
            source_book_idxs,
            destination_book_idxs,
            source_v4_match_any,
            source_v6_match_any,
            destination_v4_match_any,
            destination_v6_match_any,
            source_excluded: snap.source_address_excluded,
            destination_excluded: snap.destination_address_excluded,
            source_v4_empty,
            source_v6_empty,
            destination_v4_empty,
            destination_v6_empty,
            applications,
            compiled_apps,
            // #3365: every configured rule carries a concrete action; an unknown
            // (or empty) action is rejected fail-closed rather than silently
            // mapped to Deny (which would fail-OPEN an unrecognized reject).
            action: parse_action(&snap.action).ok_or_else(|| {
                SnapshotIntegrityError::UnknownPolicyAction {
                    context: format!("rule {:?}", rule_id),
                    action: snap.action.clone(),
                }
            })?,
            // #2508: carry the per-policy SYSLOG log selection.
            log_session_init: snap.log_session_init,
            log_session_close: snap.log_session_close,
            hit_counter: counter_store.rule_hit_counter(&rule_id),
        };
        let idx = state.rules.len();
        // #9570: a rule is GLOBAL only when BOTH structural sides carry the
        // `junos-global` sentinel, which is the only shape the Go builder emits
        // for a `security policies global` rule (walkPolicyRuleSlots). This was
        // `||`, so a HALF-sentinel rule (a leniently-loaded zone-pair stanza
        // `from-zone junos-global to-zone trust`, or its to-side mirror) was
        // indexed into the global tier with an `Any` scope and enforced for
        // EVERY zone pair, while the Go #9410 mirror, which already used `&&`,
        // reported the snapshot refused. A half-sentinel rule now takes the
        // zone-pair arm below, where `junos-global` resolves to no zone and the
        // snapshot fails closed with `UnresolvableZoneReference` (#3402), the
        // verdict the Go mirror already reported. The BOTH-sided zone-pair
        // spelling is wire-identical to a real global rule and cannot be told
        // apart here; the Go snapshot builder poisons it instead
        // (pkg/dataplane/userspace/policies_reject_global_sentinel_9570.go).
        let is_global = rule.from_zone == "junos-global" && rule.to_zone == "junos-global";
        state.rules.push(rule);

        // #3019: arm the LocalDelivery junos-host policy gate iff a rule
        // actually names the reserved self zone on either side.
        //
        // #3639/#4626: a GLOBAL policy carries its junos-host context out-of-band
        // in the `match to-zone` SCOPE (its structural `to_zone` stays
        // "junos-global"), so a `global policy ... match to-zone junos-host` must
        // ALSO arm the gate — otherwise `evaluate_junos_host_policy_l3_aware`
        // short-circuits on `!has_junos_host_rules` and the global-tier host
        // consult below never runs. Read the gate from the RESOLVED
        // `global_to_zone` (`is_host_scope()`), NOT the raw singular
        // `snap.match_to_zone`: the scope build above PREFERS the plural
        // `match_to_zones`, so a plural-only snapshot (`match_to_zones =
        // ["junos-host"]`, empty singular) resolves to a host scope but the
        // singular field is empty — arming off the singular there would silently
        // fail the host-inbound global OPEN. `is_host_scope()` is Any-false, so a
        // plain zone-pair rule (empty scope → Any) can never fire it.
        if snap.from_zone == JUNOS_HOST_ZONE_NAME
            || snap.to_zone == JUNOS_HOST_ZONE_NAME
            || state.rules[idx].global_to_zone.is_host_scope()
        {
            state.has_junos_host_rules = true;
        }

        // #8618: arm the ICMP type-constrained PERMIT gate. Only a PERMIT
        // matters: the question this answers is "could a type-constrained term
        // have ADMITTED a flow that a type-blind evaluation denies", and only a
        // permit can overturn a deny in that direction. An `inactive` rule is
        // excluded because it cannot match at all.
        if !state.rules[idx].inactive
            && matches!(state.rules[idx].action, PolicyAction::Permit)
        {
            for (slot, proto) in [PROTO_ICMP, PROTO_ICMPV6].into_iter().enumerate() {
                if state.rules[idx]
                    .compiled_apps
                    .has_icmp_type_constrained_term(proto)
                {
                    state.icmp_type_constrained_permit[slot] = true;
                }
            }
        }

        if is_global {
            state.global_indices.push(idx);
        } else {
            // #3090: classify the rule by its wildcard-zone shape. A from-zone
            // / to-zone literal `any` is the Junos wildcard; it is routed to a
            // dedicated index list so `evaluate_policy_result_with_icmp` can
            // consult it in most-specific-first precedence without an N×N
            // expansion. A concrete zone can never be named `any` (the Go
            // strict validator rejects such a zone definition), so the literal
            // is unambiguously the wildcard. `junos-global` is already handled
            // above; `junos-host` resolves to its reserved id via
            // `resolve_policy_zone_id`.
            let from_any = snap.from_zone == "any";
            let to_any = snap.to_zone == "any";
            match (from_any, to_any) {
                (true, true) => {
                    state.both_any_indices.push(idx);
                }
                (true, false) => match resolve_policy_zone_id(zone_name_to_id, &snap.to_zone) {
                    Some(to_id) => {
                        state.from_any_index.entry(to_id).or_default().push(idx);
                    }
                    // #3402: an unresolvable to-zone fails the whole snapshot
                    // closed (was a stderr-only "rule kept, but not indexed"
                    // drop → silent fall-through to default-policy).
                    None => {
                        return Err(SnapshotIntegrityError::UnresolvableZoneReference {
                            rule_id: rule_id.clone(),
                            zone: snap.to_zone.clone(),
                        });
                    }
                },
                (false, true) => match resolve_policy_zone_id(zone_name_to_id, &snap.from_zone) {
                    Some(from_id) => {
                        state.to_any_index.entry(from_id).or_default().push(idx);
                    }
                    // #3402: an unresolvable from-zone fails closed (see above).
                    None => {
                        return Err(SnapshotIntegrityError::UnresolvableZoneReference {
                            rule_id: rule_id.clone(),
                            zone: snap.from_zone.clone(),
                        });
                    }
                },
                (false, false) => {
                    match (
                        resolve_policy_zone_id(zone_name_to_id, &snap.from_zone),
                        resolve_policy_zone_id(zone_name_to_id, &snap.to_zone),
                    ) {
                        (Some(from_id), Some(to_id)) => {
                            let key = zone_pair_key(from_id, to_id);
                            state.zone_pair_index.entry(key).or_default().push(idx);
                        }
                        // #3402: either side unresolvable → fail closed. Report
                        // the from-zone first (matches the Go strict gate order
                        // in validatePolicyZoneReferencesStrict).
                        (None, _) => {
                            return Err(SnapshotIntegrityError::UnresolvableZoneReference {
                                rule_id: rule_id.clone(),
                                zone: snap.from_zone.clone(),
                            });
                        }
                        (_, None) => {
                            return Err(SnapshotIntegrityError::UnresolvableZoneReference {
                                rule_id: rule_id.clone(),
                                zone: snap.to_zone.clone(),
                            });
                        }
                    }
                }
            }
        }
    }

    // #3395: build the O(1) `rule_id → current positional policy_id` map once
    // per snapshot. Each rule carries BOTH its stable `rule_id` and its
    // positional `policy_id` (#3056), so re-resolution at the live-row refresh
    // and the RT_FLOW SESSION_CLOSE emit is a single hash lookup per session
    // (never an O(sessions × rules) scan). The implicit default policy maps to
    // its reserved sentinel so a bound default-PERMIT session (#3363) re-resolves
    // stably to `default-policy` instead of falling into the deleted-rule arm.
    state.rule_id_to_policy_id.reserve(state.rules.len() + 1);
    for rule in &state.rules {
        state
            .rule_id_to_policy_id
            .insert(rule.rule_id.clone(), rule.policy_id);
    }
    state.rule_id_to_policy_id.insert(
        DEFAULT_POLICY_COUNTER_RULE_ID.to_string(),
        DEFAULT_POLICY_SENTINEL_ID,
    );

    Ok(state)
}

/// #2008 H11: parse the legacy (non-v3-shaped) `source_addresses` /
/// `destination_addresses` field with family-safe wildcard handling.
///
/// The legacy convention is "empty input = no address constraint =
/// MatchAny" (preserved via `PrefixSetV4::from_prefixes`). But a
/// FAMILY-SCOPED wildcard (`any-ipv4` / `any-ipv6`) is a constraint:
/// it must match all of ITS family and NONE of the opposite family.
/// The naive `from_prefixes(v4), from_prefixes(v6)` pair leaks
/// cross-family, because once `any-ipv4` populates v4 the v6 Vec is
/// still empty and `from_prefixes(empty)` returns MatchAny — so the
/// rule would still match v6 (and the reverse for `any-ipv6`).
///
/// Fix: track per-family wildcards exactly like `parse_v3_literal_set`.
/// If a family-scoped wildcard is present anywhere in the token list,
/// the OPPOSITE family that received no prefixes is MatchNone (the
/// family is explicitly excluded), NOT MatchAny. Only when NO
/// family-scoped wildcard appears does the legacy "empty = MatchAny"
/// convention apply (via `from_prefixes`), preserving back-compat for
/// the unconstrained / all-malformed cases.
///
/// #3947: a bare `any` token now sets BOTH per-family any-flags
/// (mirroring `parse_v3_literal_set`) instead of being a no-op that
/// relied on the empty→MatchAny convention. The old no-op arm only
/// yielded MatchAny when the list was otherwise empty; a list mixing
/// `any` with a literal (`[ any 10.0.0.0/8 ]`) dropped the `any` and
/// NARROWED to the literal — a fail-OPEN for a deny term. An `any`
/// anywhere in the list is match-all for both families regardless of
/// any accompanying literals or family-scoped wildcards.
///
/// #3367: the returned `Option<String>` carries the FIRST token that was
/// non-empty, non-`any`, non-family-wildcard, and unparseable as an IP/CIDR.
/// The pre-fix code silently dropped such a token, so an all-malformed list on
/// the empty→MatchAny path collapsed to an unconstrained MatchAny (broadening a
/// deny). The caller fails the whole snapshot closed when this is `Some`.
fn parse_legacy_address_set(addresses: &[String]) -> (PrefixSetV4, PrefixSetV6, Option<String>) {
    let mut any_v4 = false;
    let mut any_v6 = false;
    let mut v4: Vec<PrefixV4> = Vec::new();
    let mut v6: Vec<PrefixV6> = Vec::new();
    let mut malformed: Option<String> = None;
    for tok in addresses {
        match tok.as_str() {
            // #3947: a bare `any` is the both-families match-all wildcard.
            // Mirror `parse_v3_literal_set` EXACTLY — set BOTH per-family
            // any-flags. The pre-fix no-op arm leaned on the legacy
            // empty→MatchAny convention below, which only holds when the list
            // is otherwise EMPTY: a list MIXING `any` with a literal (e.g.
            // `[ any 10.0.0.0/8 ]`) then DROPPED the `any` and NARROWED the
            // match to just the literal — a fail-OPEN for a deny term (the
            // deny that should match every source matched only the listed
            // one). Setting the flags here keeps the set match-all regardless
            // of any accompanying literals.
            "any" => {
                any_v4 = true;
                any_v6 = true;
            }
            // The empty token contributes nothing to either family; it stays a
            // no-op (matches `parse_v3_literal_set`). It is NOT `any`: an
            // otherwise-empty list still collapses to MatchAny via the legacy
            // `from_prefixes` convention below, but a mixed `[ "" 10.0.0.0/8 ]`
            // keeps the literal scoping rather than widening to match-all.
            "" => {}
            "any-ipv4" => any_v4 = true,
            "any-ipv6" => any_v6 = true,
            s => {
                if !parse_address(s, &mut v4, &mut v6) && malformed.is_none() {
                    malformed = Some(s.to_string());
                }
            }
        }
    }
    let any_family_scoped = any_v4 || any_v6;
    let v4_set = if any_v4 {
        PrefixSetV4::MatchAny
    } else if any_family_scoped {
        // A same-family-only wildcard excludes this family. An empty
        // v4 here means "v4 was deliberately not named" → MatchNone,
        // NOT the legacy empty→MatchAny.
        PrefixSetV4::from_v3_literals(v4)
    } else {
        // No family-scoped wildcard anywhere → legacy convention:
        // empty = no constraint = MatchAny.
        PrefixSetV4::from_prefixes(v4)
    };
    let v6_set = if any_v6 {
        PrefixSetV6::MatchAny
    } else if any_family_scoped {
        PrefixSetV6::from_v3_literals(v6)
    } else {
        PrefixSetV6::from_prefixes(v6)
    };
    (v4_set, v6_set, malformed)
}

/// #1606: parse the v3 `source_literals` / `destination_literals`
/// field. "any" token forces MatchAny on BOTH families (Codex r5
/// F-r5-1 fix); empty input or no-any → MatchNone (via
/// `from_v3_literals`).
///
/// #3711: the returned `Option<String>` carries the FIRST token that was
/// non-empty, non-`any`/`any4`/`any6`/`any-ipv4`/`any-ipv6`, and unparseable
/// as an IP/CIDR. The pre-fix code called a non-reporting family-agnostic
/// parser, which silently DROPPED such a token; because the v3 side uses
/// `from_v3_literals` (empty -> MatchNone), an all-dropped side collapsed to
/// MatchNone and a `deny <malformed>` rule fell through to a later permit /
/// default-permit (fail-OPEN). The caller fails the whole snapshot closed when
/// this is `Some`. Mirrors the #3367 legacy path exactly, reusing the reporting
/// `parse_address` helper (whose per-token semantics — empty / `any` / family
/// wildcard = OK, everything else must parse — match the pre-fix drop set). The
/// `__unsupported_address__` sentinel is caught earlier by the caller's
/// sentinel preflight, so it never reaches here.
fn parse_v3_literal_set(literals: &[String]) -> (PrefixSetV4, PrefixSetV6, Option<String>) {
    let mut any_v4 = false;
    let mut any_v6 = false;
    let mut v4: Vec<PrefixV4> = Vec::new();
    let mut v6: Vec<PrefixV6> = Vec::new();
    let mut malformed: Option<String> = None;
    for tok in literals {
        match tok.as_str() {
            "any" => {
                any_v4 = true;
                any_v6 = true;
            }
            // `any4`/`any6` are the internal short forms; `any-ipv4`/
            // `any-ipv6` are the Junos config keywords. The Go
            // compiler normalizes the latter to `0.0.0.0/0`/`::/0`,
            // but accept them here too so any path that bypasses that
            // normalization still matches (#2008 H11).
            "any4" | "any-ipv4" => any_v4 = true,
            "any6" | "any-ipv6" => any_v6 = true,
            "" => {}
            s => {
                if !parse_address(s, &mut v4, &mut v6) && malformed.is_none() {
                    malformed = Some(s.to_string());
                }
            }
        }
    }
    let v4_set = if any_v4 {
        PrefixSetV4::MatchAny
    } else {
        PrefixSetV4::from_v3_literals(v4)
    };
    let v6_set = if any_v6 {
        PrefixSetV6::MatchAny
    } else {
        PrefixSetV6::from_v3_literals(v6)
    };
    (v4_set, v6_set, malformed)
}

/// #3711: parse an address-book prefix token that MUST belong to the declared
/// family (`expect_v4` selects the `prefixes_v4` vs `prefixes_v6` array).
/// Returns `true` if the token parsed into the EXPECTED family or is a legit
/// empty / bare-`any` placeholder; `false` if it is malformed OR belongs to the
/// WRONG family (M02: an IPv6 token in `prefixes_v4` is rejected, not silently
/// routed into the v6 set — and vice versa). This is the reporting,
/// family-enforcing replacement for the pre-fix family-agnostic parser: the
/// book builder fails the whole snapshot CLOSED on `false` rather than dropping
/// the token (which collapsed a book-backed deny to match-none — a fail-OPEN).
/// The per-token acceptance set (empty / `any` no-op; `any-ipv4`/`any-ipv6`
/// same-family wildcards; IP/CIDR of the expected family) matches what the Go
/// side emits after its family split; a wrong-family wildcard or literal is a
/// wire-contract violation and is rejected.
fn parse_book_prefix_into(
    prefix: &str,
    expect_v4: bool,
    out_v4: &mut Vec<PrefixV4>,
    out_v6: &mut Vec<PrefixV6>,
) -> bool {
    // Legit no-op placeholders contribute nothing to either family. The Go side
    // never emits them into a family array (it emits concrete family-split
    // CIDRs), but accept them so a degenerate snapshot does not hard-fail on a
    // semantically empty token.
    if prefix.is_empty() || prefix == "any" {
        return true;
    }
    // #2008 H11: the Junos family-scoped wildcards expand to the concrete
    // all-addresses prefix of their family. Only the wildcard MATCHING the
    // declared array is accepted (family enforcement — M02).
    if prefix == "any-ipv4" {
        if !expect_v4 {
            return false;
        }
        out_v4.push(PrefixV4::from_net(
            ipnet::Ipv4Net::new(Ipv4Addr::UNSPECIFIED, 0).expect("v4 /0"),
        ));
        return true;
    }
    if prefix == "any-ipv6" {
        if expect_v4 {
            return false;
        }
        out_v6.push(PrefixV6::from_net(
            ipnet::Ipv6Net::new(Ipv6Addr::UNSPECIFIED, 0).expect("v6 /0"),
        ));
        return true;
    }
    match prefix.parse::<IpNet>() {
        Ok(IpNet::V4(net)) => {
            if !expect_v4 {
                return false;
            }
            out_v4.push(PrefixV4::from_net(net));
            true
        }
        Ok(IpNet::V6(net)) => {
            if expect_v4 {
                return false;
            }
            out_v6.push(PrefixV6::from_net(net));
            true
        }
        Err(_) => {
            if let Ok(ip) = prefix.parse::<Ipv4Addr>() {
                if !expect_v4 {
                    return false;
                }
                out_v4.push(PrefixV4::from_net(
                    ipnet::Ipv4Net::new(ip, 32).expect("v4 /32"),
                ));
                true
            } else if let Ok(ip) = prefix.parse::<Ipv6Addr>() {
                if expect_v4 {
                    return false;
                }
                out_v6.push(PrefixV6::from_net(
                    ipnet::Ipv6Net::new(ip, 128).expect("v6 /128"),
                ));
                true
            } else {
                false
            }
        }
    }
}

fn resolve_book_idxs(
    book_id_to_idx: &FxHashMap<u32, u32>,
    ids: &[u32],
    rule_id: &str,
) -> Result<SmallVec<[u32; 8]>, SnapshotIntegrityError> {
    let mut sorted = ids.to_vec();
    sorted.sort_unstable();
    sorted.dedup();
    let mut out: SmallVec<[u32; 8]> = SmallVec::new();
    for id in sorted {
        let Some(&idx) = book_id_to_idx.get(&id) else {
            return Err(SnapshotIntegrityError::UnknownAddressBookId {
                rule_id: rule_id.to_string(),
                book_id: id,
            });
        };
        out.push(idx);
    }
    Ok(out)
}

pub(crate) fn evaluate_policy(
    state: &PolicyState,
    from_id: u16,
    to_id: u16,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    protocol: u8,
    src_port: u16,
    dst_port: u16,
) -> PolicyAction {
    evaluate_policy_result_with_len(
        state, from_id, to_id, src_ip, dst_ip, protocol, src_port, dst_port, 0,
    )
    .action
}

pub(crate) fn evaluate_policy_with_len(
    state: &PolicyState,
    from_id: u16,
    to_id: u16,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    protocol: u8,
    src_port: u16,
    dst_port: u16,
    packet_len: u64,
) -> PolicyAction {
    evaluate_policy_result_with_len(
        state, from_id, to_id, src_ip, dst_ip, protocol, src_port, dst_port, packet_len,
    )
    .action
}

/// Back-compat entry point with no ICMP type/code awareness (#3020): delegates
/// to [`evaluate_policy_result_with_icmp`] with `packet_icmp = None`, so an
/// icmp-type-constrained application term (junos-ping) does not match (fail
/// closed) when the caller has no type/code. Non-ICMP flows are unaffected.
pub(crate) fn evaluate_policy_result_with_len(
    state: &PolicyState,
    from_id: u16,
    to_id: u16,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    protocol: u8,
    src_port: u16,
    dst_port: u16,
    packet_len: u64,
) -> PolicyEvaluationResult {
    evaluate_policy_result_with_icmp(
        state, from_id, to_id, src_ip, dst_ip, protocol, src_port, dst_port, None, packet_len,
    )
}

/// #9385: whether a policy evaluation may BUMP the per-rule and
/// implicit-default hit counters it walks past.
///
/// The filter engine already carries this distinction as `NonRoutingCountPolicy`
/// (#2620/#7212) and the rationale transfers verbatim: a re-derivation on the
/// ESTABLISHED-session path is not a new arrival at the policy — it was counted
/// when the flow was admitted — so counting it again inflates
/// `show security policies hit-count` by up to one packet per live session per
/// config generation, and hit-count is exactly what an operator watches to
/// confirm a narrowing took effect.
///
/// An exhaustive `match` rather than a bare `bool`: a third variant added later
/// has to classify itself instead of inheriting whichever answer a negated
/// comparison happened to give it. That is the failure
/// `NonRoutingCountPolicy::counting` records for its own third variant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PolicyHitCount {
    /// The ordinary forwarding path: this packet is a new arrival at the policy
    /// and is counted exactly once, here or on the established fast path.
    Count,
    /// A side-effect-free derivation — #8356's established-session zone-policy
    /// re-derivation. Bumps nothing.
    Never,
}

impl PolicyHitCount {
    #[inline]
    fn enabled(self) -> bool {
        match self {
            Self::Count => true,
            Self::Never => false,
        }
    }
}

/// #3020: ICMP-aware policy evaluation. `packet_icmp` is the packet's
/// ICMP/ICMPv6 `(type, code)` for ICMP-family flows whose L4 header was safely
/// readable, else `None`. It gates the icmp-type-constrained application terms
/// (junos-ping = echo-request only); non-ICMP flows pass `None` and are
/// unaffected. The forwarding path (poll_descriptor) calls this directly with
/// the per-packet type/code; the back-compat `evaluate_policy_result_with_len`
/// and the `evaluate_policy*` test/legacy wrappers pass `None`.
#[allow(clippy::too_many_arguments)]
pub(crate) fn evaluate_policy_result_with_icmp(
    state: &PolicyState,
    from_id: u16,
    to_id: u16,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    protocol: u8,
    src_port: u16,
    dst_port: u16,
    packet_icmp: Option<(u8, u8)>,
    packet_len: u64,
) -> PolicyEvaluationResult {
    // Flow-backed callers always carry a real L4 header (the 5-tuple ports are
    // authoritative), so delegate with `l4_present = true` — byte-identical to
    // the pre-#3291 behavior.
    evaluate_policy_result_l3_aware(
        state, from_id, to_id, src_ip, dst_ip, protocol, src_port, dst_port, packet_icmp,
        packet_len, true,
    )
}

/// #3291: L4-presence-aware policy evaluation. `l4_present = false` marks a
/// flowless / no-L4 packet (a non-first IPv4/IPv6 fragment, #2344) whose post-IP
/// bytes are payload, so `src_port`/`dst_port` are 0 and MUST NOT be trusted:
/// port-bearing application terms fail closed (`try_match_rule` → `matches`),
/// while address/protocol/`any` terms still evaluate on the L3 identity the
/// fragment does carry. This is the zone-policy half of the flowless transit
/// enforcement gate (the input-filter and PBR halves live in the forwarding
/// path). The synthetic L3 tuple this is called with is used ONLY for evaluation
/// + logging and is NEVER installed as a session.
#[allow(clippy::too_many_arguments)]
pub(crate) fn evaluate_policy_result_l3_aware(
    state: &PolicyState,
    from_id: u16,
    to_id: u16,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    protocol: u8,
    src_port: u16,
    dst_port: u16,
    packet_icmp: Option<(u8, u8)>,
    packet_len: u64,
    l4_present: bool,
) -> PolicyEvaluationResult {
    evaluate_policy_result_counted(
        state,
        from_id,
        to_id,
        src_ip,
        dst_ip,
        protocol,
        src_port,
        dst_port,
        packet_icmp,
        packet_len,
        l4_present,
        PolicyHitCount::Count,
    )
}

/// #9385: evaluate WITHOUT bumping any hit counter.
///
/// The entry point for #8356's established-session zone-policy re-derivation,
/// whose contract is side-effect freedom. The module header used to claim that
/// freedom was STRUCTURAL — that `evaluate_policy_result_with_icmp` "takes
/// `&PolicyState` and RETURNS a counter handle ...; it cannot count, log or meter
/// by itself". That is true of the HANDLE and false of the EVALUATION: the
/// counters are atomics behind shared references, so `&PolicyState` is not a
/// guarantee, and the walk bumped `rule.hit_counter` / `state.default_counter`
/// internally on whatever it matched. The freedom is a property of the CALL, and
/// this is how the call expresses it.
#[allow(clippy::too_many_arguments)]
pub(crate) fn evaluate_policy_result_without_counting(
    state: &PolicyState,
    from_id: u16,
    to_id: u16,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    protocol: u8,
    src_port: u16,
    dst_port: u16,
    packet_icmp: Option<(u8, u8)>,
) -> PolicyEvaluationResult {
    evaluate_policy_result_counted(
        state,
        from_id,
        to_id,
        src_ip,
        dst_ip,
        protocol,
        src_port,
        dst_port,
        packet_icmp,
        // Bytes are meaningless for a derivation that counts nothing, and the
        // byte field is separately gated on a non-zero length anyway.
        0,
        true,
        PolicyHitCount::Never,
    )
}

#[allow(clippy::too_many_arguments)]
fn evaluate_policy_result_counted(
    state: &PolicyState,
    from_id: u16,
    to_id: u16,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    protocol: u8,
    src_port: u16,
    dst_port: u16,
    packet_icmp: Option<(u8, u8)>,
    packet_len: u64,
    l4_present: bool,
    hit_count: PolicyHitCount,
) -> PolicyEvaluationResult {
    // #3110: zone id 0 is the reserved "unknown / no zone" sentinel
    // (assigned to interfaces not bound to any security zone, and to the
    // over-cap-zone collapse-to-0 path, #2391). A flow whose ingress OR
    // egress zone is unknown does not belong to any DEFINED zone pair, so
    // it must NOT be eligible for zone-pair policies OR `junos-global`
    // policies — global rules apply to all *defined* zone pairs, never to
    // unzoned transit. Fall straight through to the default action so an
    // operator's permit-global cannot leak transit on an unzoned
    // ingress/egress interface. Composes with the default-policy
    // fail-closed (#3065) and wildcard-zone work (#3018); the
    // `junos-global` sentinel (u16::MAX) is a DEFINED global zone, distinct
    // from 0 (unknown), and is unaffected by this guard.
    //
    // #4569: fragment-association fail-closed. On the FLOWLESS path
    // (l4_present == false) a non-first fragment's post-IP bytes are payload,
    // not an L4 header, so a port-bearing DENY term is gated OFF (matches() ->
    // None, #3291) and the first-match walk can fall through to a LATER permit
    // -> the fragment is forwarded, bypassing a DENY the first fragment (with
    // the real port) WOULD hit. Junos associates a non-first fragment with the
    // first-fragment's verdict; approximate that secure default: while walking
    // rules in first-match precedence order below, remember the FIRST
    // port-bearing DENY whose L3 (zone fixed by the tier bucket + src/dst
    // address) OVERLAPS this fragment but was skipped ONLY because l4_present ==
    // false (`note_skipped_frag_deny`). If the walk then lands on a PERMIT (or a
    // default-permit), OVERRIDE it to DROP and attribute the drop to that DENY
    // (`apply_frag_deny_override`). Scoped narrowly: a fragment with NO
    // overlapping skipped DENY still forwards normally, and the L4 path
    // (l4_present == true) is byte-identical (the note/override are inert). The
    // documented trade-off is over-drop: a legitimate non-denied-port fragment
    // from the SAME L3 as an overlapping port-bearing DENY is dropped (the Junos
    // security-over-availability default). A fragment-association cache keyed on
    // (src, dst, frag-id) that remembers the first-fragment's exact verdict is
    // the deferred principled fix (#4569).
    let mut skipped_frag_deny: Option<SkippedFragDeny> = None;
    if from_id != 0 && to_id != 0 {
        let key = zone_pair_key(from_id, to_id);
        if let Some(indices) = state.zone_pair_index.get(&key) {
            for &idx in indices {
                match try_match_rule(
                    &state.rules[idx],
                    state,
                    src_ip,
                    dst_ip,
                    protocol,
                    src_port,
                    dst_port,
                    packet_icmp,
                    packet_len,
                    l4_present,
                    hit_count,
                ) {
                    Some(mut result) => {
                        // #3073: 1-based handle so the fast path can re-count
                        // every packet of this flow against the same counter.
                        result.policy_counter_idx = (idx as u32).saturating_add(1);
                        return apply_frag_deny_override(result, skipped_frag_deny);
                    }
                    // #4569: remember a port-bearing DENY skipped for this
                    // flowless fragment so a later PERMIT is failed closed.
                    None => note_skipped_frag_deny(
                        &mut skipped_frag_deny,
                        l4_present,
                        &state.rules[idx],
                        idx,
                        state,
                        src_ip,
                        dst_ip,
                        protocol,
                        packet_icmp,
                    ),
                }
            }
        }
        // #3090: wildcard-zone tiers, in Junos most-specific-first precedence
        // AFTER the exact zone pair and BEFORE global/default.
        //
        //  Tier 1 — single wildcard: `from-zone any` (keyed by to_id) and
        //  `to-zone any` (keyed by from_id). The two lists are merged in
        //  config (ascending rule-index) order so a rule's relative position
        //  is honored regardless of which wildcard side it used — e.g. a
        //  `from-zone any to-zone trust deny` configured before a `from-zone
        //  untrust to-zone any permit` wins for an untrust->trust flow.
        //
        //  Tier 2 — both-any: `from-zone any to-zone any` in config order.
        //
        // Each tier is a single FxHashMap O(1) lookup (or a Vec scan only when
        // such rules exist), so a config with no wildcard policy pays only two
        // empty-slice probes per cold-path evaluation — no N×N materialization.
        let from_any = state
            .from_any_index
            .get(&to_id)
            .map(Vec::as_slice)
            .unwrap_or(&[]);
        let to_any = state
            .to_any_index
            .get(&from_id)
            .map(Vec::as_slice)
            .unwrap_or(&[]);
        let mut i = 0usize;
        let mut j = 0usize;
        while i < from_any.len() || j < to_any.len() {
            // Both slices are ascending (rules are appended in config order),
            // so a two-pointer merge yields global config order. Indices are
            // unique across the buckets (each rule lands in exactly one), so no
            // dedup is needed.
            let idx = if j >= to_any.len() || (i < from_any.len() && from_any[i] <= to_any[j]) {
                let v = from_any[i];
                i += 1;
                v
            } else {
                let v = to_any[j];
                j += 1;
                v
            };
            match try_match_rule(
                &state.rules[idx],
                state,
                src_ip,
                dst_ip,
                protocol,
                src_port,
                dst_port,
                packet_icmp,
                packet_len,
                l4_present,
                hit_count,
            ) {
                Some(mut result) => {
                    result.policy_counter_idx = (idx as u32).saturating_add(1);
                    return apply_frag_deny_override(result, skipped_frag_deny);
                }
                None => note_skipped_frag_deny(
                    &mut skipped_frag_deny,
                    l4_present,
                    &state.rules[idx],
                    idx,
                    state,
                    src_ip,
                    dst_ip,
                    protocol,
                    packet_icmp,
                ),
            }
        }
        for &idx in &state.both_any_indices {
            match try_match_rule(
                &state.rules[idx],
                state,
                src_ip,
                dst_ip,
                protocol,
                src_port,
                dst_port,
                packet_icmp,
                packet_len,
                l4_present,
                hit_count,
            ) {
                Some(mut result) => {
                    result.policy_counter_idx = (idx as u32).saturating_add(1);
                    return apply_frag_deny_override(result, skipped_frag_deny);
                }
                None => note_skipped_frag_deny(
                    &mut skipped_frag_deny,
                    l4_present,
                    &state.rules[idx],
                    idx,
                    state,
                    src_ip,
                    dst_ip,
                    protocol,
                    packet_icmp,
                ),
            }
        }
        for &idx in &state.global_indices {
            let rule = &state.rules[idx];
            // #3148: a global policy may carry optional from-zone/to-zone match
            // context. When present it matches only the configured zone(s);
            // when absent (Any) it applies to every defined zone pair as
            // before. The scope check runs in the GLOBAL tier (after the exact
            // zone-pair and #3090 from-any/to-any/both-any wildcard tiers), in
            // global config order, so a zone-scoped global policy stays a
            // global policy — it does not get promoted ahead of the wildcard
            // tiers. A typo'd (unresolvable) match-zone never reaches here: it
            // fails the whole snapshot closed at parse time (#3402,
            // SnapshotIntegrityError::UnresolvableZoneReference), so a live
            // scope is only ever Any or a resolved Zone(id).
            if !rule.global_from_zone.matches(from_id) || !rule.global_to_zone.matches(to_id) {
                continue;
            }
            match try_match_rule(
                rule,
                state,
                src_ip,
                dst_ip,
                protocol,
                src_port,
                dst_port,
                packet_icmp,
                packet_len,
                l4_present,
                hit_count,
            ) {
                Some(mut result) => {
                    // #3073: 1-based handle (see zone-pair branch above).
                    result.policy_counter_idx = (idx as u32).saturating_add(1);
                    return apply_frag_deny_override(result, skipped_frag_deny);
                }
                None => note_skipped_frag_deny(
                    &mut skipped_frag_deny,
                    l4_present,
                    rule,
                    idx,
                    state,
                    src_ip,
                    dst_ip,
                    protocol,
                    packet_icmp,
                ),
            }
        }
    }
    // #6682: an unzoned INGRESS must not reach the implicit default policy.
    //
    // The #3110 block above is skipped entirely when either zone id is 0, which
    // correctly stops every rule tier — zone-pair, from-any, to-any, both-any
    // and junos-global — from matching. The flow then landed on the implicit
    // default, and `default-policy permit-all` made that a PERMIT: transit
    // forwarded on an interface in no zone, with screens already skipped. An
    // operator asking for permit-all is asking what to do with traffic that
    // matched no policy, not asking to forward traffic that had no zone to be
    // adjudicated in.
    //
    // Scoped to the INGRESS side deliberately. An unzoned ingress is
    // unambiguous — Junos does not pass transit on an interface that is in no
    // zone. A zero EGRESS zone has historically had causes that were bugs
    // elsewhere rather than genuine unzoned-ness (#6713: an xfrmi tunnel egress
    // resolved to 0 because `populate_egress` needed a link-layer address a
    // MAC-less interface does not have), so denying on `to_id` would risk
    // black-holing a correctly-configured path to fix a case that has not been
    // shown to occur. It still falls through to the default below.
    //
    // Host-inbound is NOT affected: the LocalDelivery arm adjudicates through
    // `evaluate_junos_host_policy_l3_aware`, which already declines `from_id ==
    // 0` on its own, and both production callers of this function are transit
    // (`ForwardCandidate` and the flowless MissingNeighbor arm). Management on
    // an unzoned fxp0 cannot be locked out by this.
    if from_id == 0 {
        UNZONED_INGRESS_DENIED.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        return PolicyEvaluationResult {
            action: PolicyAction::Deny,
            policy_id: DEFAULT_POLICY_SENTINEL_ID,
            ..PolicyEvaluationResult::default()
        };
    }
    // #4569: a flowless fragment that reaches the implicit default policy still
    // fails closed against a port-bearing DENY it skipped. If the default is
    // PERMIT and an overlapping DENY was skipped for l4_present == false, drop
    // and attribute to that DENY rather than counting a default-permit. A
    // default-DENY/REJECT already drops, so the override only matters for
    // default-permit; when no deny was skipped this is inert (the L4 path never
    // records one).
    if let Some(deny) = skipped_frag_deny
        && matches!(state.default_action, PolicyAction::Permit)
    {
        return frag_associated_deny_result(deny);
    }
    // #3363: count the implicit default-policy verdict on the cold path. For
    // default-DENY this is the ONLY count (a denied flow installs no session,
    // so every dropped packet re-evaluates here); for default-PERMIT this is
    // the first-packet count and the established fast path re-counts the rest
    // via the reserved handle below. Mirrors the per-rule `rule.hit_counter.add`
    // in `try_match_rule`.
    state.default_counter.add_if(packet_len, hit_count);
    PolicyEvaluationResult {
        action: state.default_action,
        // #3057: the implicit default-policy carries a reserved sentinel ID,
        // NOT 0. Emitting 0 here aliased the FIRST configured policy (also ID
        // 0), so a default-policy deny logged as that rule's name — actively
        // misleading when the first rule is a permit. The sentinel is rendered
        // as `default-policy` by the Go log/display planes.
        policy_id: DEFAULT_POLICY_SENTINEL_ID,
        // #3534 (was #2508 "no selection"): the implicit default policy now
        // carries the operator's `security policies default-policy-log
        // session-init|session-close` selection. For a default-PERMIT verdict
        // these flags are stamped onto the installed session's metadata (the
        // session-create hot path reads PolicyEvaluationResult.log_session_*),
        // so the default-permit session emits RT_FLOW_SESSION_CREATE/CLOSE like
        // a named policy's `then log`. A default-DENY/REJECT verdict installs no
        // session, so the flags are inert there (the deny is already logged via
        // the unconditional policy-deny RT_FLOW record). Stamping them
        // unconditionally is correct: the deny path never reads these fields.
        log_session_init: state.default_log_session_init,
        log_session_close: state.default_log_session_close,
        // #3227: the implicit default policy carries no per-app timeout; the
        // session ages on the global per-protocol timeout (today's behavior).
        inactivity_timeout: None,
        // #3363: reserved default-policy hit-counter handle (was 0 = "no
        // counter"). Stamped onto a default-PERMIT session at install so the
        // established fast path re-counts every packet against `default_counter`.
        policy_counter_idx: DEFAULT_POLICY_COUNTER_IDX,
    }
}

/// #3019: resolve a policy rule's from/to zone NAME to a numeric id, mapping
/// the reserved `junos-host` self zone to [`JUNOS_HOST_ZONE_ID`]. A configured
/// zone can never be named `junos-host` (the Go strict validator + definition
/// gate reject it), so this never shadows a real zone. All other names resolve
/// through `zone_name_to_id` exactly as before.
fn resolve_policy_zone_id(
    zone_name_to_id: &FxHashMap<String, u16>,
    name: &str,
) -> Option<u16> {
    if name == JUNOS_HOST_ZONE_NAME {
        Some(JUNOS_HOST_ZONE_ID)
    } else {
        zone_name_to_id.get(name).copied()
    }
}

/// #3019: evaluate a configured `to-zone junos-host` security policy for a
/// host-bound (LocalDelivery) flow whose ingress (from) zone id is `from_id`.
/// Consulted in Junos most-specific-first precedence: the exact `from-zone
/// <ingress> to-zone junos-host` pair, then the `from-zone any to-zone
/// junos-host` wildcard (#3090), then a GLOBAL policy `match to-zone
/// junos-host` (#3639, least-specific — a scoped global stays a global and is
/// never promoted ahead of a zone-pair rule).
///
/// Junos ordering: host-inbound-traffic admission runs FIRST in the caller; a
/// packet only reaches this gate after host-inbound has admitted it, so a
/// `then permit` here can never override a host-inbound reject.
///
/// CONSERVATIVE / FAIL-SAFE semantics, by design (#3019 brief): enforcement is
/// strictly MATCH-DRIVEN. Returns:
///   - `None` when no `junos-host` policy is configured at all
///     (`has_junos_host_rules == false`), when the ingress zone is unknown
///     (id 0, mirroring the #3110 unzoned guard), or when no `junos-host` rule
///     MATCHES the flow.
///   - `Some(result)` only when a `to-zone junos-host` rule MATCHES.
///
/// Crucially there is NO implicit default-deny here: an unmatched host-bound
/// flow falls through to today's behavior (local delivery proceeds). This is
/// the deliberate lifeline guarantee — configuring some junos-host policy
/// cannot silently brick management/host traffic that does not match a deny
/// rule. The stricter Junos "configured zone-pair implies default-deny"
/// posture is intentionally deferred (see docs/junos-cli-reference.md).
///
/// `from-zone junos-host` (host-ORIGINATED) rules — whether the zone-pair
/// `from-zone junos-host to-zone <z>` form or the GLOBAL
/// `match from-zone junos-host` form — are NOT consulted here: locally
/// generated traffic egresses via the kernel TX path and does not traverse the
/// ingress LocalDelivery path. BOTH forms are rejected at STRICT commit (the
/// global form since #3611 Piece A; the zone-pair form since #4230 — earlier it
/// committed clean and was silently inert); the lenient load / peer-sync path
/// downgrades either to a warning so an already-persisted config still boots.
/// Actually wiring host-originated policy against the kernel TX path is a
/// documented follow-up.
#[allow(clippy::too_many_arguments)]
pub(crate) fn evaluate_junos_host_policy(
    state: &PolicyState,
    from_id: u16,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    protocol: u8,
    src_port: u16,
    dst_port: u16,
    packet_icmp: Option<(u8, u8)>,
    packet_len: u64,
) -> Option<PolicyEvaluationResult> {
    // #3292: flow-backed and test callers carry a real L4 header — delegate
    // with `l4_present = true`, byte-identical to pre-#3292. Only the flowless
    // LocalDelivery arm calls `evaluate_junos_host_policy_l3_aware` directly
    // (mirrors the #3291 `evaluate_policy_result_with_icmp` wrapper split).
    evaluate_junos_host_policy_l3_aware(
        state, from_id, src_ip, dst_ip, protocol, src_port, dst_port, packet_icmp,
        packet_len, true,
    )
}

/// #3292: L4-presence-aware `junos-host` policy evaluation. `l4_present = false`
/// marks a flowless / no-L4 packet (a non-first fragment on the flowless
/// LocalDelivery arm); port-bearing application terms then fail closed while
/// `application any` / address / protocol terms still match. The
/// `evaluate_junos_host_policy` wrapper delegates here with `l4_present = true`,
/// so the L4 (flow-backed / test) path is byte-identical to before.
///
/// #6465: the #4569 fragment-association deny override applies here too. A
/// host-bound non-first fragment cannot be classified into a port-bearing
/// junos-host DENY (the term fails closed for `l4_present == false`, #3292),
/// so first-match could fall through to a LATER junos-host PERMIT — or to the
/// no-match `None` fall-through, which the caller treats as deliver — and the
/// fragment would reach the host stack even though the FIRST fragment (with
/// the real port) is denied. Mirror the transit gate: while walking the tiers
/// in precedence order, remember the FIRST port-bearing DENY whose L3 overlaps
/// the fragment but was skipped only for `l4_present == false`
/// (`note_skipped_frag_deny`); override a later PERMIT to that DROP
/// (`apply_frag_deny_override`), and convert the deliver-on-no-match
/// fall-through into `Some(frag_associated_deny_result)` when a deny was
/// skipped — the junos-host "no implicit default-deny" lifeline is a
/// deliver-on-no-match posture, i.e. permit-like, so it takes the same
/// override the transit default-PERMIT takes. The override can only fire when
/// an overlapping port-bearing DENY is actually configured, so the lifeline
/// guarantee (an unmatched host-bound flow is never newly denied) is
/// unaffected for every flow that does not overlap a deny. The L4 path never
/// records a skip, so it stays byte-identical.
#[allow(clippy::too_many_arguments)]
/// #9385: this walker passes `PolicyHitCount::Count` at each `try_match_rule`
/// site and that is correct, not an oversight. It is the `to-zone junos-host`
/// (host-inbound) evaluation, and #3706 deliberately makes it the counting site
/// for a host-bound packet — the established-hit path SKIPS its own re-count for
/// LocalDelivery precisely because this re-eval already counted the packet. Only
/// #8356's zone-policy re-derivation is side-effect-free, and it does not come
/// through here.
pub(crate) fn evaluate_junos_host_policy_l3_aware(
    state: &PolicyState,
    from_id: u16,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    protocol: u8,
    src_port: u16,
    dst_port: u16,
    packet_icmp: Option<(u8, u8)>,
    packet_len: u64,
    l4_present: bool,
) -> Option<PolicyEvaluationResult> {
    if !state.has_junos_host_rules || from_id == 0 {
        return None;
    }
    // #6465: fragment-association fail-closed, mirroring
    // `evaluate_policy_result_l3_aware` (#4569) — inert on the L4 path.
    let mut skipped_frag_deny: Option<SkippedFragDeny> = None;
    // Most-specific first: an exact `from-zone <ingress> to-zone junos-host`
    // pair before the `from-zone any to-zone junos-host` wildcard.
    let key = zone_pair_key(from_id, JUNOS_HOST_ZONE_ID);
    if let Some(indices) = state.zone_pair_index.get(&key) {
        for &idx in indices {
            match try_match_rule(
                &state.rules[idx],
                state,
                src_ip,
                dst_ip,
                protocol,
                src_port,
                dst_port,
                packet_icmp,
                packet_len,
                // #3292: `l4_present` is false only on the flowless
                // LocalDelivery arm (a non-first fragment); port-bearing
                // application terms then fail closed.
                l4_present,
                PolicyHitCount::Count,
            ) {
                Some(mut result) => {
                    // #3073: 1-based handle (see `evaluate_policy_result_with_icmp`).
                    result.policy_counter_idx = (idx as u32).saturating_add(1);
                    return Some(apply_frag_deny_override(result, skipped_frag_deny));
                }
                // #6465: remember a port-bearing DENY skipped for this flowless
                // fragment so a later PERMIT / deliver fall-through fails closed.
                None => note_skipped_frag_deny(
                    &mut skipped_frag_deny,
                    l4_present,
                    &state.rules[idx],
                    idx,
                    state,
                    src_ip,
                    dst_ip,
                    protocol,
                    packet_icmp,
                ),
            }
        }
    }
    // #3090: a `from-zone any to-zone junos-host` wildcard governs host-bound
    // traffic from EVERY ingress zone. It MUST be consulted here — once the
    // #3018 interim commit reject is lifted such a rule commits, and leaving it
    // unindexed on the host path would re-introduce the exact silent fail-open
    // #3018 closed. `to-zone any` / `from-zone any to-zone any` are deliberately
    // NOT pulled into the host path: the junos-host gate stays conservative and
    // strictly match-driven (no implicit default-deny — see this function's doc
    // comment), mirroring the existing rule that global policies are not applied
    // to host-bound traffic, so a broad `to any` rule cannot silently brick the
    // management lifeline.
    if let Some(indices) = state.from_any_index.get(&JUNOS_HOST_ZONE_ID) {
        for &idx in indices {
            match try_match_rule(
                &state.rules[idx],
                state,
                src_ip,
                dst_ip,
                protocol,
                src_port,
                dst_port,
                packet_icmp,
                packet_len,
                // #3292: `l4_present` is false only on the flowless
                // LocalDelivery arm (a non-first fragment); port-bearing
                // application terms then fail closed.
                l4_present,
                PolicyHitCount::Count,
            ) {
                Some(mut result) => {
                    result.policy_counter_idx = (idx as u32).saturating_add(1);
                    return Some(apply_frag_deny_override(result, skipped_frag_deny));
                }
                None => note_skipped_frag_deny(
                    &mut skipped_frag_deny,
                    l4_present,
                    &state.rules[idx],
                    idx,
                    state,
                    src_ip,
                    dst_ip,
                    protocol,
                    packet_icmp,
                ),
            }
        }
    }
    // #3639: a GLOBAL policy `match to-zone junos-host` (host-INBOUND) governs
    // host-bound traffic in the GLOBAL tier — evaluated LAST here, AFTER the
    // exact `from-zone <ingress> to-zone junos-host` pair and the `from-zone any
    // to-zone junos-host` wildcard, mirroring transit-policy precedence (a
    // global policy is least-specific and is never promoted ahead of a
    // zone-pair rule; see evaluate_policy_result_l3_aware). Only globals scoped
    // to the junos-host EGRESS side are consulted; the optional `match
    // from-zone` scope still restricts by ingress zone (Any = every zone, the
    // `from-zone any to-zone junos-host` global the #3639 commit-reject lift
    // enables). This is the enforcement half the reject lift is coupled with —
    // lifting the commit reject without consulting here would re-open the exact
    // silent fail-open the #3018/#3148 reject closed. A `from-zone junos-host`
    // global (host-ORIGINATED) is NOT consulted: that direction never traverses
    // the RX LocalDelivery gate and is rejected at commit (#3611 Piece A).
    for &idx in &state.global_indices {
        let rule = &state.rules[idx];
        if !rule.global_to_zone.is_host_scope() || !rule.global_from_zone.matches(from_id) {
            continue;
        }
        match try_match_rule(
            rule,
            state,
            src_ip,
            dst_ip,
            protocol,
            src_port,
            dst_port,
            packet_icmp,
            packet_len,
            l4_present,
            PolicyHitCount::Count,
        ) {
            Some(mut result) => {
                result.policy_counter_idx = (idx as u32).saturating_add(1);
                return Some(apply_frag_deny_override(result, skipped_frag_deny));
            }
            None => note_skipped_frag_deny(
                &mut skipped_frag_deny,
                l4_present,
                rule,
                idx,
                state,
                src_ip,
                dst_ip,
                protocol,
                packet_icmp,
            ),
        }
    }
    // #6465: the junos-host fall-through is "no implicit default-deny" — an
    // unmatched host-bound flow returns None and the caller DELIVERS it (the
    // lifeline guarantee). That posture is permit-like, so a flowless fragment
    // that skipped an overlapping port-bearing DENY must fail closed exactly as
    // it would against a transit default-PERMIT (#4569): deliver the
    // fragment-associated DROP (attributed to the skipped DENY) instead of
    // None. When no deny was skipped this is inert — and the L4 path never
    // records one, so the lifeline is byte-identical there.
    if let Some(deny) = skipped_frag_deny {
        return Some(frag_associated_deny_result(deny));
    }
    None
}

/// Does `rule`'s L3 source+destination address match evaluate to true for this
/// `(src_ip, dst_ip)` pair? Extracted verbatim from `try_match_rule` so the
/// fragment-association fail-closed overlap check
/// (`rule_is_skipped_frag_ambiguous_deny`, #4569) uses the EXACT same address
/// logic the real match uses.
///
/// #2008 H2: when a side is `*-excluded`, the rule matches every address EXCEPT
/// those in the configured set, so the match-any short-circuit must NOT apply
/// (it would always-match and the inversion would always-FAIL the side).
/// Compute the raw "address is in the set" predicate, then XOR with the
/// excluded flag: matched != excluded.
///
/// #2008 fail-open hardening: an `*-excluded` side whose configured set is
/// EMPTY would invert into match-ALL — a silent security bypass (a rule meant
/// to exclude one address matches everything). Fail CLOSED only when the set is
/// empty across BOTH families: that is the genuine typo/parse-drop signal.
/// #3023: when the packet's family list is empty but the OTHER family is
/// populated, the operator legitimately listed only one family — an address in
/// the packet's family is then trivially NOT in the excluded set, so the side
/// matches. Fail-closing on the per-family empty flag alone over-blocked that
/// legitimate cross-family case (a v6-only exclusion silently dropped all v4
/// traffic on a permit rule).
#[inline]
fn rule_l3_matches(rule: &PolicyRule, state: &PolicyState, src_ip: IpAddr, dst_ip: IpAddr) -> bool {
    let (src_ok, dst_ok) = match (src_ip, dst_ip) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => {
            let src_ok = if rule.source_excluded {
                !(rule.source_v4_empty && rule.source_v6_empty)
                    && !(rule.source_literal_v4.contains(src)
                        || rule
                            .source_book_idxs
                            .iter()
                            .any(|&i| state.books[i as usize].v4.contains(src)))
            } else {
                rule.source_v4_match_any
                    || rule.source_literal_v4.contains(src)
                    || rule
                        .source_book_idxs
                        .iter()
                        .any(|&i| state.books[i as usize].v4.contains(src))
            };
            let dst_ok = if rule.destination_excluded {
                !(rule.destination_v4_empty && rule.destination_v6_empty)
                    && !(rule.destination_literal_v4.contains(dst)
                        || rule
                            .destination_book_idxs
                            .iter()
                            .any(|&i| state.books[i as usize].v4.contains(dst)))
            } else {
                rule.destination_v4_match_any
                    || rule.destination_literal_v4.contains(dst)
                    || rule
                        .destination_book_idxs
                        .iter()
                        .any(|&i| state.books[i as usize].v4.contains(dst))
            };
            (src_ok, dst_ok)
        }
        (IpAddr::V6(src), IpAddr::V6(dst)) => {
            let src_ok = if rule.source_excluded {
                !(rule.source_v4_empty && rule.source_v6_empty)
                    && !(rule.source_literal_v6.contains(src)
                        || rule
                            .source_book_idxs
                            .iter()
                            .any(|&i| state.books[i as usize].v6.contains(src)))
            } else {
                rule.source_v6_match_any
                    || rule.source_literal_v6.contains(src)
                    || rule
                        .source_book_idxs
                        .iter()
                        .any(|&i| state.books[i as usize].v6.contains(src))
            };
            let dst_ok = if rule.destination_excluded {
                !(rule.destination_v4_empty && rule.destination_v6_empty)
                    && !(rule.destination_literal_v6.contains(dst)
                        || rule
                            .destination_book_idxs
                            .iter()
                            .any(|&i| state.books[i as usize].v6.contains(dst)))
            } else {
                rule.destination_v6_match_any
                    || rule.destination_literal_v6.contains(dst)
                    || rule
                        .destination_book_idxs
                        .iter()
                        .any(|&i| state.books[i as usize].v6.contains(dst))
            };
            (src_ok, dst_ok)
        }
        // #2358: cross-family NAT64 inbound tuple — IPv6 source (the v6
        // client) with the POST-translation IPv4 destination (the real
        // internal server the synthetic NAT64 address was extracted to).
        // Junos/SRX evaluates the inbound security policy AFTER destination
        // translation, so a NAT64 policy is authored against the real IPv4
        // host + its destination zone, with the source matched in the IPv6
        // ingress zone. The forwarding path (poll_descriptor) feeds this
        // mixed tuple ONLY for NAT64 (the source stays v6, the dst is the
        // extracted v4); no other flow produces a (V6 src, V4 dst) tuple,
        // so this arm is inert for non-NAT64 traffic. The source side
        // matches the rule's IPv6 source set; the destination side matches
        // the rule's IPv4 destination set. The `*-excluded` empty-set
        // fail-closed and per-family any-match semantics mirror the
        // same-family arms above.
        (IpAddr::V6(src), IpAddr::V4(dst)) => {
            let src_ok = if rule.source_excluded {
                !(rule.source_v4_empty && rule.source_v6_empty)
                    && !(rule.source_literal_v6.contains(src)
                        || rule
                            .source_book_idxs
                            .iter()
                            .any(|&i| state.books[i as usize].v6.contains(src)))
            } else {
                rule.source_v6_match_any
                    || rule.source_literal_v6.contains(src)
                    || rule
                        .source_book_idxs
                        .iter()
                        .any(|&i| state.books[i as usize].v6.contains(src))
            };
            let dst_ok = if rule.destination_excluded {
                !(rule.destination_v4_empty && rule.destination_v6_empty)
                    && !(rule.destination_literal_v4.contains(dst)
                        || rule
                            .destination_book_idxs
                            .iter()
                            .any(|&i| state.books[i as usize].v4.contains(dst)))
            } else {
                rule.destination_v4_match_any
                    || rule.destination_literal_v4.contains(dst)
                    || rule
                        .destination_book_idxs
                        .iter()
                        .any(|&i| state.books[i as usize].v4.contains(dst))
            };
            (src_ok, dst_ok)
        }
        // (V4 src, V6 dst) has no inbound translation that produces it
        // (NAT46 is not supported), so it never matches — fail closed.
        _ => return false,
    };
    src_ok && dst_ok
}

/// #4569: a port-bearing DENY that a flowless non-first fragment SKIPPED,
/// remembered while walking rules in first-match precedence order so a later
/// PERMIT verdict can be overridden to DROP (Junos fragment-association: a
/// non-first fragment inherits the first-fragment's deny). `policy_id` +
/// `policy_counter_idx` attribute the resulting DROP to the DENY rule for the
/// emitted `PolicyDeny` event / hit accounting.
#[derive(Clone, Copy)]
struct SkippedFragDeny {
    policy_id: u32,
    policy_counter_idx: u32,
}

/// #4569: is `rule` a port-bearing (L4-constrained) DENY that a FLOWLESS
/// non-first fragment SKIPPED ONLY because `l4_present == false`, and whose L3
/// identity OVERLAPS the fragment? (The zone side of the L3 identity is already
/// fixed by the caller's bucket iteration — this rule is in the zone-pair /
/// wildcard / global tier being walked for this fragment's zone pair — so only
/// the source/destination ADDRESS overlap is checked here.)
///
/// Returns true iff ALL hold:
///   - the rule is active and its action is DENY or REJECT (a permit is not a
///     fail-open risk — first-match would forward it anyway);
///   - it carries an L4-constrained term for the fragment's protocol
///     (`has_l4_constrained_term`), so it is a term the fragment cannot be
///     classified into rather than a rule for a different protocol;
///   - it does NOT already match this flowless fragment
///     (`matches(.., false).is_none()`) — a protocol-only / `any` DENY term
///     matches a fragment directly and is handled as a real deny by
///     `try_match_rule`, never "skipped";
///   - its source+destination address set OVERLAPS the fragment
///     (`rule_l3_matches`).
///
/// A non-overlapping DENY, a different-protocol DENY, or a permit therefore
/// leaves the fragment on its normal (forward) path — the guard is scoped to
/// exactly the fail-open case.
fn rule_is_skipped_frag_ambiguous_deny(
    rule: &PolicyRule,
    state: &PolicyState,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    protocol: u8,
    packet_icmp: Option<(u8, u8)>,
) -> bool {
    if rule.inactive {
        return false;
    }
    if !matches!(rule.action, PolicyAction::Deny | PolicyAction::Reject) {
        return false;
    }
    if !rule.compiled_apps.has_l4_constrained_term(protocol) {
        return false;
    }
    // A protocol-only / `any` term would already match flowlessly → the rule is
    // a real deny match handled by `try_match_rule`, not a skip. Only treat it
    // as skipped when it does NOT match with l4_present == false.
    if rule
        .compiled_apps
        .matches(protocol, 0, 0, packet_icmp, false)
        .is_some()
    {
        return false;
    }
    rule_l3_matches(rule, state, src_ip, dst_ip)
}

/// #4569: while walking a flowless fragment through the first-match precedence
/// tiers, record the FIRST port-bearing DENY with overlapping L3 that was
/// skipped (see `rule_is_skipped_frag_ambiguous_deny`). No-op when
/// `l4_present == true` (the L4 path is unaffected) or once a deny is already
/// recorded (first-match precedence — the earliest shadowing deny wins).
#[inline]
#[allow(clippy::too_many_arguments)]
fn note_skipped_frag_deny(
    skipped: &mut Option<SkippedFragDeny>,
    l4_present: bool,
    rule: &PolicyRule,
    idx: usize,
    state: &PolicyState,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    protocol: u8,
    packet_icmp: Option<(u8, u8)>,
) {
    if l4_present || skipped.is_some() {
        return;
    }
    if rule_is_skipped_frag_ambiguous_deny(rule, state, src_ip, dst_ip, protocol, packet_icmp) {
        *skipped = Some(SkippedFragDeny {
            policy_id: rule.policy_id,
            policy_counter_idx: (idx as u32).saturating_add(1),
        });
    }
}

/// #4569: build the fail-closed DENY verdict a flowless fragment inherits from
/// the port-bearing DENY it skipped. A dropped fragment installs no session, so
/// the log-selection / timeout fields are inert; `policy_id` attributes the
/// `PolicyDeny` event to the DENY rule. The DENY rule's own hit counter is left
/// untouched — the fragment did not match that rule's L4 criteria; the drop is
/// counted by the caller's `telemetry.dbg.policy_deny`.
fn frag_associated_deny_result(deny: SkippedFragDeny) -> PolicyEvaluationResult {
    PolicyEvaluationResult {
        action: PolicyAction::Deny,
        policy_id: deny.policy_id,
        log_session_init: false,
        log_session_close: false,
        inactivity_timeout: None,
        policy_counter_idx: deny.policy_counter_idx,
    }
}

/// #4569: override a PERMIT verdict to the fragment-associated DENY when a
/// port-bearing DENY with overlapping L3 was skipped for this flowless
/// fragment. Any non-PERMIT verdict (an explicit deny/reject already denies) or
/// the absence of a skipped deny returns `result` unchanged.
#[inline]
fn apply_frag_deny_override(
    result: PolicyEvaluationResult,
    skipped: Option<SkippedFragDeny>,
) -> PolicyEvaluationResult {
    match skipped {
        Some(deny) if matches!(result.action, PolicyAction::Permit) => {
            frag_associated_deny_result(deny)
        }
        _ => result,
    }
}

/// Try to match a single policy rule against packet fields.
/// #1606: walks the literal set + every cited book's dense entry
/// via `state.books[idx]`. Match-any flags short-circuit the
/// common "any" case.
#[inline]
fn try_match_rule(
    rule: &PolicyRule,
    state: &PolicyState,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    protocol: u8,
    src_port: u16,
    dst_port: u16,
    packet_icmp: Option<(u8, u8)>,
    packet_len: u64,
    l4_present: bool,
    // #9385: threaded rather than inferred from `packet_len`. A zero length means
    // "no bytes", not "no packet" -- `HitCounter::add` bumps `packets`
    // unconditionally and #6304's doc depends on that.
    hit_count: PolicyHitCount,
) -> Option<PolicyEvaluationResult> {
    if rule.inactive {
        return None;
    }
    // #3227: `matches` now returns the matched application term's optional
    // inactivity timeout (`None` outer = no app match → rule does not apply).
    // #3291: `l4_present` fails port-bearing application terms closed for a
    // flowless / no-L4 packet (a non-first fragment) — see `matches`.
    let app_inactivity_timeout =
        rule.compiled_apps
            .matches(protocol, src_port, dst_port, packet_icmp, l4_present)?;
    // The rule's L3 (source + destination address) match, including `*-excluded`
    // inversion, per-family fail-closed, book membership, and the NAT64
    // cross-family arm — see `rule_l3_matches`.
    if rule_l3_matches(rule, state, src_ip, dst_ip) {
        rule.hit_counter.add_if(packet_len, hit_count);
        Some(PolicyEvaluationResult {
            action: rule.action,
            policy_id: rule.policy_id,
            // #2508: surface the matched rule's per-policy SYSLOG log
            // selection so the install path can stamp the session.
            log_session_init: rule.log_session_init,
            log_session_close: rule.log_session_close,
            // #3227: surface the matched application term's idle timeout so the
            // install path can stamp it onto the admitted session.
            inactivity_timeout: app_inactivity_timeout,
            // #3073: set by the caller (`evaluate_policy_result_with_icmp`),
            // which knows this rule's stable index. `try_match_rule` itself
            // has only `&rule`, so it leaves the sentinel here.
            policy_counter_idx: 0,
        })
    } else {
        None
    }
}

fn stable_policy_rule_id(snap: &PolicyRuleSnapshot) -> String {
    if !snap.rule_id.is_empty() {
        return snap.rule_id.clone();
    }
    format!("{}->{}/{}", snap.from_zone, snap.to_zone, snap.name)
}

/// #3365: parse a wire action token into a `PolicyAction`. Returns `None` for
/// any string that is not one of the three known tokens so the caller can fail
/// the snapshot closed instead of silently collapsing an unrecognized action
/// (e.g. a future `reject-*` variant, a typo, or a corrupt token) to Deny. The
/// empty string is intentionally NOT recognized here; callers decide whether an
/// empty value is a legitimate unspecified state (snapshot `default_policy`,
/// `omitempty` on the wire) or a hard error (a per-rule action).
fn parse_action(action: &str) -> Option<PolicyAction> {
    match action {
        "permit" => Some(PolicyAction::Permit),
        "reject" => Some(PolicyAction::Reject),
        "deny" => Some(PolicyAction::Deny),
        _ => None,
    }
}

/// Parse one legacy address literal into the per-family prefix vectors. Returns
/// `true` when the token was represented (a placeholder `any`/empty, a
/// family-scoped wildcard, or a successfully-parsed IP/CIDR literal) and `false`
/// when a NON-placeholder token failed to parse as an IP or CIDR. #3367: the
/// caller (`parse_legacy_address_set`) propagates a `false` up so the policy
/// builder can fail the snapshot closed rather than silently dropping the token
/// (which on the empty->match-any legacy path widens a deny rule to match-any).
fn parse_address(prefix: &str, out_v4: &mut Vec<PrefixV4>, out_v6: &mut Vec<PrefixV6>) -> bool {
    if prefix.is_empty() || prefix == "any" {
        return true;
    }
    // #2008 H11: family-scoped wildcards (see parse_book_prefix_into).
    if prefix == "any-ipv4" {
        out_v4.push(PrefixV4::from_net(
            ipnet::Ipv4Net::new(Ipv4Addr::UNSPECIFIED, 0).expect("v4 /0"),
        ));
        return true;
    }
    if prefix == "any-ipv6" {
        out_v6.push(PrefixV6::from_net(
            ipnet::Ipv6Net::new(Ipv6Addr::UNSPECIFIED, 0).expect("v6 /0"),
        ));
        return true;
    }
    match prefix.parse::<IpNet>() {
        Ok(IpNet::V4(net)) => {
            out_v4.push(PrefixV4::from_net(net));
            true
        }
        Ok(IpNet::V6(net)) => {
            out_v6.push(PrefixV6::from_net(net));
            true
        }
        Err(_) => {
            if let Ok(ip) = prefix.parse::<Ipv4Addr>() {
                out_v4.push(PrefixV4::from_net(
                    ipnet::Ipv4Net::new(ip, 32).expect("v4 /32"),
                ));
                true
            } else if let Ok(ip) = prefix.parse::<Ipv6Addr>() {
                out_v6.push(PrefixV6::from_net(
                    ipnet::Ipv6Net::new(ip, 128).expect("v6 /128"),
                ));
                true
            } else {
                // #3367: a non-empty, non-placeholder token that is neither an IP
                // nor a CIDR. Signal the malformed literal to the caller.
                false
            }
        }
    }
}

/// #2124: outcome of parsing a rule's application terms. `dropped_any` records
/// whether at least one configured term failed to parse (unparseable protocol
/// or port). The caller fails the rule closed via `SnapshotIntegrityError`
/// whenever `dropped_any` is set, rather than letting a dropped term collapse
/// the rule to match-any (all-dropped) or silently narrow it (partial-drop).
/// A genuinely-empty input (`application any` / no match application) drops
/// nothing, so `dropped_any == false` and the rule stays match-any.
struct ParsedApplications {
    matches: Vec<ApplicationMatch>,
    dropped_any: bool,
    /// #3712: the FIRST application term found with a semantically-invalid ICMP
    /// field combination — `(application name, reason)`. `None` when every term
    /// is well-formed. The caller fails the whole snapshot closed via
    /// `SnapshotIntegrityError::InvalidApplicationIcmpFields`, naming the rule
    /// (which `parse_applications` does not have). Detected regardless of
    /// `dropped_any` so a rule mixing a bad-ICMP term with an unparseable one
    /// still surfaces the ICMP diagnostic when protocol/port parse.
    invalid_icmp: Option<(String, &'static str)>,
}

fn parse_applications(terms: &[PolicyApplicationSnapshot]) -> ParsedApplications {
    let mut out = Vec::with_capacity(terms.len());
    let mut dropped_any = false;
    let mut invalid_icmp: Option<(String, &'static str)> = None;
    for term in terms {
        let Some(protocol) = parse_protocol(&term.protocol) else {
            dropped_any = true;
            continue;
        };
        let Some(source_ports) = parse_port_spec(&term.source_port) else {
            dropped_any = true;
            continue;
        };
        let Some(destination_ports) = parse_port_spec(&term.destination_port) else {
            dropped_any = true;
            continue;
        };
        // #3712: reject the two semantically-invalid ICMP field combinations the
        // compiled matcher (`from_matches`/`matches`) would otherwise turn into a
        // wrong-behaving term. Record the FIRST offender; the caller rejects the
        // whole snapshot fail-closed (see `InvalidApplicationIcmpFields`). The
        // non-ICMP-protocol case is checked first because on a non-ICMP protocol
        // ANY icmp field is meaningless (the term can never match), whereas the
        // code-without-type case is only relevant once the protocol is ICMP.
        if invalid_icmp.is_none() {
            let icmp_family = protocol == PROTO_ICMP || protocol == PROTO_ICMPV6;
            if (term.icmp_type.is_some() || term.icmp_code.is_some()) && !icmp_family {
                invalid_icmp = Some((
                    term.name.clone(),
                    "icmp-type/icmp-code set on a non-ICMP protocol",
                ));
            } else if term.icmp_code.is_some() && term.icmp_type.is_none() {
                invalid_icmp = Some((term.name.clone(), "icmp-code set without icmp-type"));
            }
        }
        out.push(ApplicationMatch {
            protocol,
            source_ports,
            destination_ports,
            // #3020: carry the optional ICMP type/code constraint through to the
            // compiled matcher. A non-ICMP term simply has these as None.
            icmp_type: term.icmp_type,
            icmp_code: term.icmp_code,
            // #3227: carry the per-application inactivity timeout through to the
            // compiled matcher so a session admitted by this term can stamp it.
            // A 0 seconds value collapses to None (use-global) so the override
            // is only set when the operator configured a positive timeout.
            // #3714: the upper bound (86400 s, mirroring the Go `appTimeoutMax`
            // commit gate) is enforced at the single seconds→ns conversion
            // authority `session::app_inactivity_timeout_ns`, which every value
            // that persists on a session or rides the sync wire funnels through
            // — so a corrupt/mixed-version `4294967295` here is clamped before
            // it can stamp a never-expiring idle timeout.
            inactivity_timeout: term.inactivity_timeout.filter(|&t| t > 0),
        });
    }
    ParsedApplications {
        matches: out,
        dropped_any,
        invalid_icmp,
    }
}

/// Resolve a policy application term's protocol token to its IANA number.
///
/// #2124: extended to map the named IANA protocols Junos / the Go
/// `validateProtocol` accept (`sctp`/`esp`/`ah`/`vrrp`/`igmp`/`pim`/`egp`) to
/// their numbers, so a policy that matches only those protocols is honored
/// instead of silently failing OPEN to match-any. Returning `None` for an
/// unparseable token records a dropped term in `parse_applications`; a rule with
/// ANY dropped term is then rejected as a `SnapshotIntegrityError` (fail closed)
/// rather than collapsing to match-any (all-dropped) or silently narrowing
/// (partial-drop) — see `parse_applications` / `parse_policy_state_with_counters`.
///
/// The numeric `_ => parse::<u8>()` arm is preserved, so a config that names a
/// protocol numerically (e.g. `protocol 132`) still parses. Numbers MUST match
/// `crate::ip_proto` / the centralized Go `appid.ProtocolNumber` table.
fn parse_protocol(protocol: &str) -> Option<u8> {
    match protocol {
        "" => None,
        "tcp" => Some(PROTO_TCP),
        "udp" => Some(PROTO_UDP),
        "icmp" => Some(PROTO_ICMP),
        "icmp6" | "icmpv6" => Some(PROTO_ICMPV6),
        "gre" => Some(PROTO_GRE),
        "89" | "ospf" => Some(PROTO_OSPF),
        "4" | "ipip" => Some(PROTO_IPIP),
        "esp" => Some(PROTO_ESP),
        "ah" => Some(PROTO_AH),
        "sctp" => Some(PROTO_SCTP),
        "vrrp" => Some(PROTO_VRRP),
        "igmp" => Some(PROTO_IGMP),
        "pim" => Some(PROTO_PIM),
        "egp" => Some(PROTO_EGP),
        _ => protocol.parse::<u8>().ok(),
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
        let low = parse_port_u16(low)?;
        let high = parse_port_u16(high)?;
        if low == 0 || low > high {
            return None;
        }
        return Some(vec![PortRange { low, high }]);
    }
    let port = parse_port_u16(normalized)?;
    if port == 0 {
        return None;
    }
    Some(vec![PortRange {
        low: port,
        high: port,
    }])
}

// parse_port_u16 parses a canonical unsigned decimal port token. Rust's u16
// FromStr accepts a leading '+' ("+80" -> Ok(80)), but Junos and the Go commit
// gate (validatePortSpec -> parseCanonicalPort) reject a signed / non-canonical
// port, and the Go capability gate userspacePortSpecRepresentable parses with
// strconv.ParseUint (which also rejects the sign). Accepting "+80" here left
// parse_port_spec MORE lenient than both Go gates — a parser divergence on a
// security leaf (#3606). Reject any token that is not a bare run of ASCII
// decimal digits so all three parsers agree.
//
// #6477: this is the SHARED digit-only helper — the firewall-filter compiler
// (filter/compiler.rs `parse_port_spec`) routes through it too, so all FOUR
// port parsers (Go commit gate, Go capability gate, policy-side Rust,
// filter-side Rust) agree on the same canonical-token acceptance set. Keep it
// the single source of truth for "is this token a canonical port number".
pub(crate) fn parse_port_u16(tok: &str) -> Option<u16> {
    if tok.is_empty() || !tok.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    tok.parse::<u16>().ok()
}

fn port_ranges_match(ranges: &[PortRange], port: u16) -> bool {
    ranges.is_empty()
        || ranges
            .iter()
            .any(|range| port >= range.low && port <= range.high)
}

#[cfg(test)]
#[path = "policy_tests.rs"]
mod tests;

// #9167: the Rust half of the shared policy-verdict corpus differential. Kept a
// sibling submodule of policy.rs (not of policy_tests.rs) so it reaches the
// pub(crate) evaluator directly, the same way policy_tests.rs does.
#[cfg(test)]
#[path = "policy_verdict_corpus_9167.rs"]
mod policy_verdict_corpus_9167;

#[cfg(test)]
#[path = "policy_junos_global_9570_tests.rs"]
mod policy_junos_global_9570_tests;
