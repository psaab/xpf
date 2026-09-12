//! Interface-state population for `build_forwarding_state`.
//!
//! Two passes:
//!
//! 1. [`populate_interfaces`] — walks `snapshot.interfaces`,
//!    populates `state.ifindex_to_*`, `state.ifindex_to_zone_id`,
//!    `state.ifindex_unambiguous_zone_id` (#6722 — the Go builder's
//!    `egress_zone` for that ifindex, admitted only when a row on it
//!    literally names that zone; the helper corroborates rather than
//!    adjudicates, see `ForwardingState::egress_zone_id` and the flush
//!    below),
//!    `state.tunnel_interfaces`, `state.local_v[46]`,
//!    `state.interface_nat_v[46]`, `state.connected_v[46]`. Returns
//!    an [`IfaceIndex`] context with `name_to_ifindex` /
//!    `linux_to_ifindex` / `mac_by_ifindex` carried across the
//!    later egress, route, and fabric passes.
//! 2. [`populate_egress`] — walks `snapshot.interfaces` a second
//!    time to build per-interface `EgressInterface` entries with
//!    the resolved `bind_ifindex`, MAC, and zone_id.

use super::super::*;
use ipnet::IpNet;
use std::collections::BTreeMap;
use std::net::{Ipv4Addr, Ipv6Addr};

/// Carry context built by [`populate_interfaces`] for downstream
/// passes (egress / fib / fabrics). Owned by the orchestrator;
/// passed by `&` to consumers.
pub(super) struct IfaceIndex {
    pub name_to_ifindex: BTreeMap<String, i32>,
    pub linux_to_ifindex: BTreeMap<String, i32>,
    pub mac_by_ifindex: BTreeMap<i32, [u8; 6]>,
}

/// What the snapshot rows on ONE ifindex say about that ifindex's EGRESS zone
/// (#6722).
///
/// The Go builder (`stampEgressZones`, `pkg/dataplane/userspace/interfaces.go`)
/// decides the answer and stamps it on every row of an ifindex, so a well-formed
/// snapshot yields `Decided` with one value. `Conflicting` is the only other
/// state, and it is version drift or a hostile snapshot.
///
/// There is deliberately NO "the field was absent" variant. `egress_zone`
/// carries `#[serde(default)]`, so an absent key decodes to `""` — the same
/// state as a builder that decided the ifindex identifies no zone, and the same
/// answer. That collapse is what the v5 protocol bump bought: an old control
/// plane's snapshot is refused at `apply_snapshot`'s exact-equality version gate
/// and never reaches this builder, so "absent" and "decided none" no longer need
/// to be told apart. Round 10 briefly carried an `Option` and an `Absent` arm
/// that fell back to row unanimity; the bump made that arm production-
/// unreachable (measured: every non-test path here is behind the version gate,
/// and the helper never replays a persisted snapshot — `write_state` is
/// write-only), so it was removed rather than left as dead code that 54 tests
/// pretended to cover.
#[derive(Clone, Debug, PartialEq, Eq)]
enum EgressZoneClaim {
    /// Every row on the ifindex carried this value. Empty means no zone.
    Decided(String),
    /// Rows on one ifindex carried DIFFERENT values. The builder stamps them
    /// identically, so this is drift or a hostile snapshot; it fails closed.
    Conflicting,
}

/// What the LOGICAL UNIT rows on ONE ifindex say about that ifindex's zone
/// (#7509).
///
/// Several configured identities land on one netdev — `snapshotLinuxName`
/// (`pkg/dataplane/userspace/interfaces.go`) collapses a non-VLAN unit 0 onto
/// its base, and an interface-level tunnel maps EVERY unit onto the tunnel
/// device — so an ifindex carries at most one base row but can carry several
/// unit rows. Of those rows only the UNIT rows are traffic identities: a packet
/// arriving on `st0` is a packet on `st0.0`, and the base row exists to describe
/// the interface, not to receive frames.
///
/// That is what recovers the AUTHORED-vs-INHERITED fact #6727 said was missing.
/// A base row's zone can be an inheritance — `InterfaceZoneMap`
/// (`pkg/config/host_inbound_effective_view.go`) writes `out[base]` for a
/// unit-suffixed reference, so zoning `st0.1` zones `st0` — and the row itself
/// cannot say which it is. Its UNIT SIBLINGS on the same ifindex can: the same
/// map fans a BARE reference DOWN onto every configured unit, so a base whose
/// zone was authored has unit rows carrying that same zone, while a base whose
/// zone was inherited from a sibling on ANOTHER ifindex has unit rows that do
/// not. Provenance is not on the row; it is in the agreement.
///
/// `Agreed("")` is a statement, not an absence: every unit row on the ifindex
/// was left out of every zone, so the ifindex has no zone and no derivation may
/// give it one.
#[derive(Clone, Debug, PartialEq, Eq)]
enum UnitZoneClaim {
    /// Every logical-unit row on the ifindex carried this zone name.
    Agreed(String),
    /// Unit rows on one ifindex carried DIFFERENT zone names.
    Disagree,
}

/// True for a snapshot row that names a LOGICAL UNIT (`st0.0`, `reth1.0`,
/// `ge-0/0/9.100`) rather than an interface (`st0`, `reth1`, `ge-0/0/9`).
///
/// Mirrors the Go builder's `egressRowIdentity.isUnit`, which is set exactly on
/// the rows emitted from the per-unit loop and named `fmt.Sprintf("%s.%d", ...)`.
/// A Junos interface name never contains `.` — the separator is `/` — so the
/// numeric suffix test is a spelling of the same fact rather than a heuristic,
/// and requiring the suffix to be digits keeps a hypothetical dotted interface
/// name from being read as a unit.
fn is_logical_unit_row(name: &str) -> bool {
    match name.rsplit_once('.') {
        Some((base, unit)) => {
            !base.is_empty() && !unit.is_empty() && unit.bytes().all(|b| b.is_ascii_digit())
        }
        None => false,
    }
}

/// ifindex -> [`UnitZoneClaim`] for every ifindex that carries at least one
/// logical-unit row. An ifindex absent here carries no unit row at all, and its
/// zone is decided exactly as it was before #7509 — that absence is what keeps
/// the #921/#3618 trunk-parent inheritance intact for a parent whose units all
/// have netdevs of their own.
fn unit_zone_claims(snapshot: &ConfigSnapshot) -> BTreeMap<i32, UnitZoneClaim> {
    let mut out: BTreeMap<i32, UnitZoneClaim> = BTreeMap::new();
    for iface in &snapshot.interfaces {
        if iface.ifindex <= 0 || !is_logical_unit_row(&iface.name) {
            continue;
        }
        match out.entry(iface.ifindex) {
            std::collections::btree_map::Entry::Vacant(slot) => {
                slot.insert(UnitZoneClaim::Agreed(iface.zone.clone()));
            }
            std::collections::btree_map::Entry::Occupied(mut slot) => {
                if slot.get() != &UnitZoneClaim::Agreed(iface.zone.clone()) {
                    slot.insert(UnitZoneClaim::Disagree);
                }
            }
        }
    }
    out
}

/// Whether the unit rows on `ifindex` admit `zone` as that ifindex's INGRESS
/// zone (#7509).
///
/// `true` when no unit row sits on the ifindex (nothing to contradict, the
/// pre-#7509 answer stands) or when every unit row on it names exactly `zone`.
/// `false` when the unit rows agree on a DIFFERENT zone, when they agree on NO
/// zone, or when they disagree among themselves.
fn unit_rows_admit(claims: &BTreeMap<i32, UnitZoneClaim>, ifindex: i32, zone: &str) -> bool {
    match claims.get(&ifindex) {
        None => true,
        Some(UnitZoneClaim::Agreed(claimed)) => claimed == zone,
        Some(UnitZoneClaim::Disagree) => false,
    }
}

impl EgressZoneClaim {
    fn merge(&self, egress_zone: &str) -> Self {
        match self {
            Self::Decided(have) if have == egress_zone => self.clone(),
            _ => Self::Conflicting,
        }
    }

    /// The zone name this ifindex egresses into, or `None` for the 0 sentinel.
    /// `carried` is the set of zone names the ifindex's rows literally hold; a
    /// nonempty answer is honoured only if one of them names it.
    fn resolve(&self, carried: Option<&std::collections::BTreeSet<String>>) -> Option<String> {
        let carried = carried?;
        match self {
            Self::Conflicting => None,
            Self::Decided(zone) if zone.is_empty() => None,
            // CORROBORATION: honour the builder's answer only where a row on the
            // ifindex literally names that zone.
            Self::Decided(zone) if carried.contains(zone) => Some(zone.clone()),
            Self::Decided(_) => None,
        }
    }
}

pub(super) fn populate_interfaces(
    snapshot: &ConfigSnapshot,
    state: &mut ForwardingState,
    excluded_local_v4: &FastSet<Ipv4Addr>,
    excluded_local_v6: &FastSet<Ipv6Addr>,
) -> Result<IfaceIndex, crate::policy::SnapshotIntegrityError> {
    let mut name_to_ifindex = BTreeMap::new();
    let mut linux_to_ifindex = BTreeMap::new();
    let mut mac_by_ifindex = BTreeMap::new();
    // #6722: ifindex → the EGRESS zone name the Go builder stamped on its rows,
    // or `None` once two rows on one ifindex claimed different ones (drift; Go
    // stamps them identically). Flushed into
    // `state.ifindex_unambiguous_zone_id` after the walk, alongside
    // `zones_carried` — ifindex → the zone names its rows literally carry, which
    // is what corroborates the claim.
    let mut egress_zone_claim: BTreeMap<i32, EgressZoneClaim> = BTreeMap::new();
    let mut zones_carried: BTreeMap<i32, std::collections::BTreeSet<String>> = BTreeMap::new();

    // #7509: parent ifindexes whose zoned child units DISAGREE. Tracked for the
    // whole walk so a later row carrying the first zone cannot resurrect a guess
    // a second row already contested, and reported after the walk so an operator
    // can get from "my traffic stopped" to the contested ifindex in one place.
    let mut contested_parent_ifindexes: std::collections::BTreeSet<i32> =
        std::collections::BTreeSet::new();
    let mut contested_parent_zones: std::collections::BTreeMap<
        i32,
        std::collections::BTreeSet<u16>,
    > = std::collections::BTreeMap::new();

    // #7509: what the LOGICAL UNIT rows on each ifindex say about its zone,
    // computed BEFORE the walk because the Go builder emits an interface's base
    // row ahead of its unit rows (pinned by
    // `TestZonedTrunkEmitsUnzonedUnit0OnTheSharedIfindex_6722`), so the base
    // row's insert has to be able to consult a unit row it has not reached yet.
    let unit_claims = unit_zone_claims(snapshot);
    // #7509: ifindexes whose zone a unit row REFUSED, with the zone ids that
    // were refused. Reported after the walk for the same reason the contest is
    // — a silent unzoning is a blackhole with no error anywhere on the box.
    let mut unit_refused_zones: std::collections::BTreeMap<
        i32,
        std::collections::BTreeSet<u16>,
    > = std::collections::BTreeMap::new();

    for iface in &snapshot.interfaces {
        if iface.ifindex <= 0 {
            continue;
        }
        let label = if iface.linux_name.is_empty() {
            iface.name.clone()
        } else {
            iface.linux_name.clone()
        };
        state.ifindex_to_name.insert(iface.ifindex, label);
        state
            .ifindex_to_config_name
            .insert(iface.ifindex, iface.name.clone());
        // #3096: record the interface's routing instance for NAT rule-set
        // `from`/`to routing-instance` scope matching ("" = default VRF).
        state
            .ifindex_to_routing_instance
            .insert(iface.ifindex, iface.routing_instance.clone());
        // #7160 (#2387): record the numeric routing DOMAIN alongside the name.
        // Go decides the number (`routingInstanceDomain`); 0 is the default
        // instance and is what an old Go binary's snapshot yields for every
        // interface. Only a non-zero domain is stored, so the map holds exactly
        // the routing-instance MEMBER interfaces and an absent ifindex reads as
        // domain 0 — the same "absent = default" convention the name map above
        // uses, and what keeps `has_routing_domains` a truthful gate.
        if iface.routing_domain != 0 {
            state
                .ifindex_to_routing_domain
                .insert(iface.ifindex, iface.routing_domain);
            state.has_routing_domains = true;
        }
        name_to_ifindex.insert(iface.name.clone(), iface.ifindex);
        if !iface.linux_name.is_empty() {
            linux_to_ifindex.insert(iface.linux_name.clone(), iface.ifindex);
        }
        // #6710: an xfrmi has no link-layer address, so an egress to it can
        // never resolve a neighbor. Record the ifindex so the dead-host
        // negative cache is not armed against a device that has nothing to
        // answer with — see ForwardingState::lladdrless_egress. The flag is
        // read, never re-derived: `secure_tunnel` is the same authoritative
        // bit `userspace_unbindable_netdev` uses for binding planning.
        if iface.secure_tunnel {
            state.lladdrless_egress.insert(iface.ifindex);
        }
        // #921: resolve zone NAME → u16 once at config build, so every read on
        // the hot path is one HashMap lookup (ifindex → u16). An unzoned row
        // resolves to 0, the "no zone" sentinel.
        // #2391: a non-empty zone NAME that is not in the zone table
        // (dropped at populate_zones for a u8-overflow id, or a
        // version-drifted/hostile snapshot) must FAIL CLOSED instead of
        // collapsing to zone 0 — collapsing bypasses every zone-pair policy
        // (fail-open under a permit default). The Go commit-time cap is the
        // primary gate; this is the helper-boundary backstop.
        let row_zone_id: u16 = if iface.zone.is_empty() {
            0
        } else {
            match state.zone_name_to_id.get(&iface.zone).copied() {
                Some(id) => id,
                None => {
                    return Err(
                        crate::policy::SnapshotIntegrityError::InterfaceUnknownZone {
                            interface: iface.name.clone(),
                            zone: iface.zone.clone(),
                        },
                    );
                }
            }
        };
        // #6722: record the Go builder's EGRESS answer for this ifindex, and
        // (separately) the zone this row literally carries.
        //
        // The helper does not adjudicate. `stampEgressZones`
        // (`pkg/dataplane/userspace/interfaces.go`) decides which zone an
        // ifindex egresses into, because that decision needs two things the
        // rows do not carry: the operator's AUTHORED
        // `security-zone <z> interfaces <ref>` bindings before
        // `buildInterfaceZoneMap` fanned them UP to bases (a bare reference's
        // fan-DOWN onto its units is kept — that is what the reference means),
        // and `snapshotLinuxName`, the function that collapses several
        // configured identities onto one netdev. A row's `zone` is the OUTCOME
        // of that derivation, and the outcome does not say whether the operator
        // zoned THIS identity or whether the row inherited another's words.
        //
        // That is why the row-classifying ledger this replaced kept getting
        // holed. It asked "do the rows sharing this ifindex agree?" and then
        // grew an exemption list for the rows whose agreement or dissent was an
        // artefact rather than an observation — a RETH member's projection row,
        // then a multi-unit base row carrying a fanned-up zone, then an authored
        // dotted name aliasing another interface's VLAN unit. Nine spellings
        // across #6722's life, each closed by adding a case. Provenance is not
        // reconstructible from the outcome, so it is carried instead.
        //
        // What remains here is a CORROBORATION, not a decision, and it needs no
        // predicate over rows: an ifindex takes `egress_zone` only if some row
        // on it literally names that zone. A drifted or hostile snapshot can
        // therefore never conjure a zone no row on the ifindex named — the
        // helper-boundary property (#2391/#2409/#2706) the previous mark
        // argued for, now with nothing left to disagree about. `None` means the
        // rows disagreed about the answer itself (Go stamps every row on an
        // ifindex identically, so this is drift) and fails closed.
        match egress_zone_claim.entry(iface.ifindex) {
            std::collections::btree_map::Entry::Vacant(slot) => {
                slot.insert(EgressZoneClaim::Decided(iface.egress_zone.clone()));
            }
            std::collections::btree_map::Entry::Occupied(mut slot) => {
                let merged = slot.get().merge(&iface.egress_zone);
                slot.insert(merged);
            }
        }
        zones_carried
            .entry(iface.ifindex)
            .or_default()
            .insert(iface.zone.clone());
        // `row_zone_id != 0` is EXACTLY the pre-#6722 `!iface.zone.is_empty()`
        // condition, not a narrowing of it: `zone_name_to_id_from_snapshot`
        // (`policy.rs`) skips `zone.id == 0` outright, so a zone NAME that
        // resolves at all resolves nonzero, and one that does not resolve
        // already returned `InterfaceUnknownZone` above. `ifindex_to_zone_id`
        // therefore receives the identical entries it did before this change.
        if row_zone_id != 0 {
            // #7509: the SAME-IFINDEX contest. Two rows can carry one ifindex
            // directly — the Go builder's `out[base]` write puts `st0.0` and
            // `st0.1` on one base ifindex — and this insert was unconditional,
            // so the LAST row walked won. That is the case #7509 actually
            // reports, and it is a different arm from the parent fan-UP below
            // (which was FIRST-wins). Both are guesses; both are now refused.
            //
            // Caught by retargeting `unzoned_macless_unit_does_not_inherit_a_
            // zoned_siblings_zone_6722`: fixing only the fan-UP left this arm
            // handing out a sibling's zone, and the retarget is what exposed it.
            if contested_parent_ifindexes.contains(&iface.ifindex) {
                // Already contested by an earlier row: stay unzoned. Re-inserting
                // would make the outcome depend on walk order again.
            } else if !unit_rows_admit(&unit_claims, iface.ifindex, &iface.zone) {
                // #7509, the zoned-vs-UNZONED half. A BASE row's zone can be an
                // inheritance from a unit on ANOTHER ifindex — zoning `st0.1`
                // zones `st0` — while the unit that actually receives frames on
                // this ifindex, `st0.0`, was deliberately left in no zone. The
                // unit rows are the traffic identities, so they decide; the base
                // row's derived zone does not get to overrule them.
                //
                // Nothing is REMOVED here: a row this predicate refuses never
                // wrote the entry in the first place, because the same predicate
                // refused every earlier row carrying that zone on this ifindex.
                unit_refused_zones
                    .entry(iface.ifindex)
                    .or_default()
                    .insert(row_zone_id);
            } else if let Some(existing) = state.ifindex_to_zone_id.get(&iface.ifindex).copied() {
                if existing != row_zone_id {
                    contested_parent_ifindexes.insert(iface.ifindex);
                    let entry = contested_parent_zones.entry(iface.ifindex).or_default();
                    entry.insert(existing);
                    entry.insert(row_zone_id);
                    state.ifindex_to_zone_id.remove(&iface.ifindex);
                }
            } else {
                state.ifindex_to_zone_id.insert(iface.ifindex, row_zone_id);
            }
            // Propagate a zoned child unit's zone onto its parent's ifindex so
            // a packet ARRIVING on a trunk parent with no zone of its own is
            // attributed to its unit's zone (#921/#3618). This is REACHABLE for
            // a Go-produced snapshot even though `buildInterfaceZoneMap`
            // (`pkg/dataplane/userspace/zones.go`) writes `out[base]` for a
            // unit-suffixed zone reference: the StableZoneID quarantine
            // (`pkg/dataplane/userspace/zones_quarantine.go`) runs AFTER
            // `buildInterfaceSnapshots` and blanks `Zone` on every row bound to
            // a quarantined zone, so a base whose zone lost a collision arrives
            // UNZONED beside a surviving zoned child and this arm fires.
            //
            // #6722: that is exactly why `egress_zone_id` must not read
            // `ifindex_to_zone_id` — the quarantine unzoned those interfaces to
            // make them fail CLOSED, and propagating a survivor's zone onto the
            // parent would hand the egress half a zone the operator never
            // configured there. The egress half reads
            // `ifindex_unambiguous_zone_id` instead, which this arm never
            // touches.
            if iface.parent_ifindex > 0 {
                // #7509: a CONTESTED parent ifindex is UNZONED, not guessed.
                //
                // This arm used to keep the first zoned child's answer and
                // silently ignore a sibling that disagreed
                // (`Some(existing) if *existing != row_zone_id => {}`). On a
                // shared base ifindex — an interface-level tunnel maps every
                // unit onto one netdev via `TunnelNameMap` — that adjudicates a
                // packet on `st0.0` against `st0.1`'s policies: a policy set the
                // operator never wrote for that unit, chosen by row order.
                //
                // The dataplane sees an IFINDEX, not a unit, so it cannot tell
                // the two apart with anything on the wire today. When it cannot
                // know which zone a packet belongs to, the firewall must decline
                // to pick one rather than guess. Declining = no entry, so
                // adjudication falls to the default policy.
                //
                // This also collapses an asymmetry rather than adding a second
                // mechanism: the egress half already resolves a contested
                // ifindex to nothing (`EgressZoneClaim::Conflicting` ->
                // `resolve` -> `None`, `ifindex_unambiguous_zone_id` gets no
                // entry). Ingress now matches it, which is the #6727 symmetry.
                //
                // A contested parent stays unzoned for the REST of the walk:
                // `contested_parent_ifindexes` is checked before every insert,
                // so a third row carrying the first zone cannot resurrect the
                // guess after a second row contested it. Without that the
                // outcome would depend on row order again, just less obviously.
                //
                // WHAT WOULD INVALIDATE THIS (#4308). The rationale above rests
                // on untagged traffic having no principled unit attribution
                // today: `native-vlan-id` is accepted-only and NOT enforced
                // (`schema_interfaces.go`, and `compiler_validate_warn_routing.go`
                // emits a commit advisory saying so). If #4308 is ever
                // implemented, untagged frames on a trunk acquire a DEFINED unit
                // — the native VLAN — and declining to zone them becomes wrong
                // for that unit specifically, though it stays right for every
                // other contested case. A future implementer of #4308 will not
                // think to look here, so this is written down rather than left
                // to be re-derived.
                //
                // SCOPE, wider than the issue's framing. #7509 describes
                // interface-level TUNNEL units sharing a netdev. The condition
                // is any parent whose units span different zones, which includes
                // an ordinary VLAN trunk — `poll_stages_tests.rs`'s #3021
                // fixture is exactly that shape. The affected traffic stays
                // narrow: a tagged frame resolves to its own logical unit
                // ifindex first (#3021), so only traffic that resolves to the
                // RAW PARENT changes behaviour.
                //
                // Accepted cost, stated because it is a real regression for a
                // configured case: where two units with different zones share a
                // base ifindex, the one that happened to win the old race worked
                // and is now denied. It worked by accident of ordering, its
                // sibling was being misadjudicated the whole time, and both are
                // now reported (see the warn! below).
                if !unit_rows_admit(&unit_claims, iface.parent_ifindex, &iface.zone) {
                    // #7509: the parent ifindex carries a unit row of its own —
                    // a non-VLAN unit 0 collapsed onto the base netdev — and
                    // that unit does not name this zone. Untagged traffic on the
                    // parent IS that unit's traffic, so a zoned child on its own
                    // netdev may not zone it. Scoped to parents that carry a
                    // unit row: a trunk whose units all have netdevs of their
                    // own still inherits (#921/#3618), which is the case this
                    // propagation exists to serve.
                    unit_refused_zones
                        .entry(iface.parent_ifindex)
                        .or_default()
                        .insert(row_zone_id);
                } else if !contested_parent_ifindexes.contains(&iface.parent_ifindex) {
                    match state.ifindex_to_zone_id.get(&iface.parent_ifindex) {
                        Some(existing) if *existing != row_zone_id => {
                            contested_parent_ifindexes.insert(iface.parent_ifindex);
                            contested_parent_zones
                                .entry(iface.parent_ifindex)
                                .or_insert_with(std::collections::BTreeSet::new)
                                .insert(*existing);
                            contested_parent_zones
                                .entry(iface.parent_ifindex)
                                .or_insert_with(std::collections::BTreeSet::new)
                                .insert(row_zone_id);
                            state.ifindex_to_zone_id.remove(&iface.parent_ifindex);
                        }
                        _ => {
                            state
                                .ifindex_to_zone_id
                                .insert(iface.parent_ifindex, row_zone_id);
                        }
                    }
                }
            }
        }
        // #3362: per-interface host-inbound OVERRIDE. When the control plane
        // marked this interface host-inbound-configured, classify its EFFECTIVE
        // token set — resolved in Go, where the interface stanza REPLACES the
        // zone one (#6515) — and key it by ifindex so the
        // local-delivery admit path prefers it over the from-zone's set. A
        // present-but-empty override classifies to an empty ZoneHostInbound =
        // fail-closed deny-all (matching the zone-level semantics and the nft
        // primary path's per-interface drop).
        if iface.host_inbound_configured {
            state.ifindex_host_inbound.insert(
                iface.ifindex,
                crate::afxdp::forwarding::zone_host_inbound_from_tokens(
                    &iface.host_inbound_system_services,
                    &iface.host_inbound_protocols,
                ),
            );
        }
        if iface.tunnel {
            state.tunnel_interfaces.insert(iface.ifindex);
        }
        if let Some(mac) = parse_mac(&iface.hardware_addr) {
            mac_by_ifindex.insert(iface.ifindex, mac);
        }
        let tunnel_endpoint_id = state
            .tunnel_endpoint_by_ifindex
            .get(&iface.ifindex)
            .copied()
            .unwrap_or(0);
        // #2388: canonical connected-route table names for this interface's
        // routing-instance. "" (default instance) → inet.0 / inet6.0; a
        // named instance → "<ri>.inet.0" / "<ri>.inet6.0". The lookup
        // filters connected routes by the canonical table it is resolving
        // in, so a per-VRF / next-table lookup never matches a connected
        // prefix owned by a different routing-instance.
        let (connected_table_v4, connected_table_v6) =
            connected_route_tables(&iface.routing_instance);
        // #5659: track whether this interface registered at least one
        // local-delivery target (an address that landed in local_v4/local_v6,
        // NOT one routed into interface_nat_*). Only such an addressed
        // local-delivery target is a host-inbound exposure worth the empty-zone
        // fail-closed sentinel installed after this loop.
        let mut registered_local = false;
        for addr in &iface.addresses {
            // #2409: fail CLOSED on an unparseable interface address rather
            // than silently `continue`-ing past it. The pre-fix skip lost the
            // connected route / local-address / interface-NAT material for
            // that address while the apply still succeeded — silent
            // connectivity loss in a retired-eBPF world. The Go commit-time
            // validation is the primary gate; this is the helper-boundary
            // backstop (the preflight keeps the previous good state).
            let net = addr.address.parse::<IpNet>().map_err(|_| {
                crate::policy::SnapshotIntegrityError::InterfaceAddressUnparseable {
                    interface: iface.name.clone(),
                    address: addr.address.clone(),
                }
            })?;
            match net {
                IpNet::V4(v4) => {
                    // #3182: record EVERY configured interface IP in the
                    // NAT-decoupled set BEFORE the NAT-exclusion branch, so the
                    // anti-poison `owns_configured_ip` gate protects the
                    // SNAT/WAN interface IP that the exclusion routes into
                    // `interface_nat_v4` (out of `local_v4`).
                    state.configured_iface_v4.insert(v4.addr());
                    if excluded_local_v4.contains(&v4.addr()) {
                        state.interface_nat_v4.insert(v4.addr(), iface.ifindex);
                    } else {
                        state.local_v4.insert(v4.addr());
                        registered_local = true;
                        // #3769: record the interface host address's owning
                        // table for the table-scoped local-delivery DECISION.
                        // Keyed by the HOST `.addr()`, NOT the (masked)
                        // connected prefix, so a non-/32 interface IP is
                        // recognised as locally-owned in its own VRF.
                        state
                            .local_tables_v4
                            .entry(v4.addr())
                            .or_default()
                            .insert(connected_table_v4.clone());
                    }
                    state.connected_v4.push(ConnectedRouteV4 {
                        prefix: PrefixV4::from_net(v4),
                        ifindex: iface.ifindex,
                        tunnel_endpoint_id,
                        table: connected_table_v4.clone(),
                    });
                }
                IpNet::V6(v6) => {
                    // #3182: NAT-decoupled full interface-IP set (see the V4
                    // arm above) — protects the SNAT/WAN IPv6 interface IP too.
                    state.configured_iface_v6.insert(v6.addr());
                    if excluded_local_v6.contains(&v6.addr()) {
                        state.interface_nat_v6.insert(v6.addr(), iface.ifindex);
                    } else {
                        state.local_v6.insert(v6.addr());
                        registered_local = true;
                        // #3769: record the interface host address's owning
                        // table (see the v4 arm).
                        state
                            .local_tables_v6
                            .entry(v6.addr())
                            .or_default()
                            .insert(connected_table_v6.clone());
                    }
                    state.connected_v6.push(ConnectedRouteV6 {
                        prefix: PrefixV6::from_net(v6),
                        ifindex: iface.ifindex,
                        tunnel_endpoint_id,
                        table: connected_table_v6.clone(),
                    });
                }
            }
        }
        // #5659: empty-zone host-inbound fail-closed backstop — SYMMETRY with
        // the #2391 non-empty-unknown-zone backstop above. That backstop is
        // guarded by `!iface.zone.is_empty()`, so an ADDRESSED interface with an
        // EMPTY security-zone string is skipped: no `ifindex_to_zone_id` entry ->
        // ingress resolves to zone_id 0, while its IP is STILL registered into
        // local_v4/local_v6 as a local-delivery target. `host_inbound_admits(0)`
        // then hits the `None => true` global-zone admit arm and would admit
        // every host-bound service (SSH/NETCONF/BGP/SNMP...), breaking the
        // fail-closed symmetry #2391/#3405 established.
        //
        // Fix: insert an EMPTY `ZoneHostInbound` sentinel keyed by this
        // interface's LOGICAL ifindex, so the ingress-interface-keyed
        // `host_inbound_admits_iface` (the local-delivery poll path's entry
        // point) DENIES host-bound services for a packet ingressing on it. The
        // global ICMP/ND/PMTUD accepts (`is_icmp_host_inbound_global_accept`,
        // checked BEFORE the set in `host_inbound_admits_iface`) still deliver
        // control traffic. Keying by ifindex — NOT by inserting zone_host_inbound
        // at id 0 — deliberately leaves the genuinely-global zone_id 0 path
        // (`host_inbound_admits` with no matching ifindex override) untouched, so
        // a legitimately-zoneless NON-addressed control interface keeps its admit
        // default.
        //
        // Scope guards:
        //   - registered_local: only an interface that actually registered a
        //     local_v4/local_v6 target is a host-inbound exposure. A fully
        //     NAT-excluded (interface_nat only) or address-less interface is not.
        //     #9941: that reasoning holds for an ORDINARY interface and fails for
        //     a TUNNEL. A decapped inner packet re-ingresses on the tunnel's
        //     LOGICAL ifindex (logical_ingress::build_logical_ingress_packet,
        //     reached from gre.rs and wg/decap.rs) and is delivered to a local
        //     address registered by some OTHER interface — so a tunnel is a
        //     host-inbound exposure WITHOUT ever being addressed itself. An
        //     unzoned tunnel is absent from ifindex_to_zone_id (the insert is
        //     gated on row_zone_id != 0), so it resolves to zone 0 and takes the
        //     `None => true` global admit arm. `iface.tunnel` therefore joins
        //     registered_local as a reason to arm the sentinel.
        //   - !iface.host_inbound_configured: an explicit per-interface override
        //     already inserted its own (possibly deny-all) `ifindex_host_inbound`
        //     entry above; never clobber the operator's configured admit set.
        //   - !is_host_inbound_lifeline: fxp0/em0/fab* are served UNCONDITIONALLY
        //     (kernel path, excluded from the AF_XDP deny sets). Never arm a deny
        //     sentinel for a lifeline — doing so would strand management / break
        //     HA heartbeat the moment a future change bound one.
        //
        // Reachability today is bind-gated (`buildUserspaceBindNetdevs` skips a
        // zoneless interface), so this is a fail-closed-SYMMETRY / defense-in-
        // depth hardening, not a live bypass: it closes the asymmetry so any
        // future change that binds a zoneless-addressed interface (or a quarantine
        // path, cf. #3719, that keeps an interface bound while stripping its zone)
        // cannot silently become a host-inbound bypass.
        if iface.zone.is_empty()
            && (registered_local || iface.tunnel)
            && !iface.host_inbound_configured
            && !is_host_inbound_lifeline(&iface.name)
        {
            state.ifindex_host_inbound.entry(iface.ifindex).or_default();
        }
    }

    // #6722: flush the Go builder's egress answer, admitting an ifindex only
    // when a row on it CORROBORATES the claim by literally naming that zone.
    //
    // Every failure resolves the 0 sentinel — the pre-#6713 answer, against
    // which `evaluate_policy_result_l3_aware` matches no rule and the default
    // policy decides:
    //
    //   - `Decided("")`: the Go builder decided the ifindex identifies no single
    //     zone (contested ownership, conflicting authored bindings, or none).
    //   - `Conflicting`: rows on ONE ifindex disagreed about the answer itself.
    //     The builder stamps every row on an ifindex identically, so this is
    //     version drift or a hostile snapshot.
    //   - uncorroborated: no row on the ifindex carries that zone name. This is
    //     the whole of the helper-side check on a field it otherwise trusts, and
    //     it is what keeps a drifted claim from CONJURING a zone.
    //   - unknown name: `zone_name_to_id` has no entry, so the zone was dropped
    //     at `populate_zones` (u8-overflow id) or never existed. Corroboration
    //     makes this unreachable in practice — a row carrying an unresolvable
    //     zone already returned `InterfaceUnknownZone` above — but a failed
    //     lookup must not default to a real zone id.
    // #7509 Condition 1: the deny must be OBSERVABLE. A contested ifindex that
    // silently unzones is a blackhole with no error anywhere on the box — the
    // #8296 failure mode, where a config committed clean, rendered back
    // verbatim, and reached no consumer while traffic died with no log line.
    //
    // One line per contested ifindex per build, naming the ifindex and every
    // zone id that claimed it, so an operator whose traffic stopped can reach
    // "these units share a base ifindex and disagree about their zone" without
    // reading source. Emitted once per build rather than per row: the condition
    // is a property of the snapshot, and a per-row line would scale with
    // interface count for one fact.
    for (ifindex, zones) in &contested_parent_zones {
        let ids: Vec<String> = zones.iter().map(|z| z.to_string()).collect();
        eprintln!(
            "xpf-userspace-dp: WARNING zone contest on shared base ifindex {}: units \
             claim zone ids [{}] — the ingress zone is UNSET for it and its traffic \
             falls to the default policy in BOTH directions (#7509). The dataplane \
             sees an ifindex, not a unit, so it cannot tell which unit a packet \
             arrived on; give the units distinct netdevs or put them in one zone.",
            ifindex,
            ids.join(", ")
        );
    }

    // #7509 (zoned-vs-UNZONED): same observability requirement, different
    // refusal. Here the rows do not disagree with each other — a BASE row
    // carries a zone it INHERITED from a unit on another ifindex, and the unit
    // row that actually receives frames on this ifindex names a different zone
    // or none at all. One line per ifindex per build, naming the zone ids the
    // unit rows refused, so an operator whose untagged trunk or unit-0 tunnel
    // traffic starts hitting the default policy can reach the cause without
    // reading source. The commit-time advisory
    // (`pkg/config/contested_trunk_zone_advisory_7509.go`) is the one that can
    // name the INTERFACE; this one is the runtime corroboration.
    for (ifindex, zones) in &unit_refused_zones {
        if contested_parent_zones.contains_key(ifindex) {
            // Already reported above as a contest; do not say it twice.
            continue;
        }
        let ids: Vec<String> = zones.iter().map(|z| z.to_string()).collect();
        eprintln!(
            "xpf-userspace-dp: WARNING ifindex {} carries a logical unit the operator \
             left out of zone ids [{}]: that unit is what receives frames on the \
             device, so the zone its base interface INHERITED from a sibling unit is \
             refused and the ifindex is UNZONED (#7509). Traffic arriving on it falls \
             to the default policy. Zone the unit explicitly if it must forward.",
            ifindex,
            ids.join(", ")
        );
    }

    for (ifindex, claim) in egress_zone_claim {
        let Some(zone) = claim.resolve(zones_carried.get(&ifindex)) else {
            continue;
        };
        match state.zone_name_to_id.get(&zone).copied() {
            Some(zone_id) if zone_id != 0 => {
                state.ifindex_unambiguous_zone_id.insert(ifindex, zone_id);
            }
            _ => {}
        }
    }

    // #7160 (#2387): zone -> routing DOMAIN, for the fabric-ingress path where
    // the arriving interface is the fabric link and the peer's zone encoding is
    // the only ingress identity available. Derived AFTER the walk from the two
    // per-ifindex maps it is a join of, so it cannot disagree with either.
    //
    // A zone is only recorded when EVERY member interface with a zone agrees on
    // one domain; a zone spanning two routing instances is left ABSENT and
    // reads as domain 0, the pre-#7160 answer. That is the #6722
    // `ifindex_unambiguous_zone_id` discipline: identify exactly one, or
    // nothing. Assigning the first-seen domain to a straddling zone would hand
    // a fabric-redirected packet a confidently wrong domain, which is strictly
    // worse than the undifferentiated one.
    if state.has_routing_domains {
        let mut ambiguous: FastSet<u16> = FastSet::default();
        for (ifindex, zone_id) in state.ifindex_to_zone_id.iter() {
            if *zone_id == 0 {
                continue;
            }
            let domain = state
                .ifindex_to_routing_domain
                .get(ifindex)
                .copied()
                .unwrap_or(0);
            match state.zone_routing_domain.get(zone_id).copied() {
                Some(seen) if seen == domain => {}
                Some(_) => {
                    ambiguous.insert(*zone_id);
                }
                None => {
                    state.zone_routing_domain.insert(*zone_id, domain);
                }
            }
        }
        for zone_id in ambiguous {
            state.zone_routing_domain.remove(&zone_id);
        }
    }

    Ok(IfaceIndex {
        name_to_ifindex,
        linux_to_ifindex,
        mac_by_ifindex,
    })
}

pub(super) fn populate_egress(
    snapshot: &ConfigSnapshot,
    state: &mut ForwardingState,
    iface_ctx: &IfaceIndex,
) -> Result<(), crate::policy::SnapshotIntegrityError> {
    for iface in &snapshot.interfaces {
        if iface.ifindex <= 0 {
            continue;
        }
        let bind_ifindex = if iface.parent_ifindex > 0 {
            iface.parent_ifindex
        } else {
            iface.ifindex
        };
        // #2410: validate the VLAN id ONCE here instead of narrowing it with
        // an unchecked `iface.vlan_id.max(0) as u16` at both the ingress-key
        // and the EgressInterface.vlan_id site. An out-of-range value
        // (> 65535) fails the snapshot closed rather than wrapping to a
        // different VLAN (a different L2 domain).
        let vlan_id =
            super::validated::VlanId::try_from_snapshot(iface.vlan_id, &iface.name)?.get();
        // #2706: validate the MTU ONCE here instead of narrowing it with an
        // unchecked `iface.mtu.max(0) as usize`. A NEGATIVE value fails the
        // snapshot closed rather than collapsing to 0 — which the egress MTU
        // guard treats as "unknown; forward", silently disabling PTB/drop
        // enforcement. 0 (the legitimate "unknown MTU" sentinel) stays
        // permissive.
        let mtu = super::validated::InterfaceMtu::try_from_snapshot(iface.mtu, &iface.name)?.get();
        let ingress_key = (bind_ifindex, vlan_id);
        if iface.parent_ifindex > 0 {
            state
                .ingress_logical_ifindex
                .insert(ingress_key, iface.ifindex);
        } else {
            state
                .ingress_logical_ifindex
                .entry(ingress_key)
                .or_insert(iface.ifindex);
        }
        let src_mac = match parse_mac(&iface.hardware_addr)
            .or_else(|| iface_ctx.mac_by_ifindex.get(&bind_ifindex).copied())
            .or_else(|| iface.tunnel.then_some([0; 6]))
        {
            Some(mac) => mac,
            None => continue,
        };
        // #921: resolve zone name → u16 at build time.
        // #2391: a non-empty zone name absent from the zone table fails CLOSED
        // (consistent with populate_interfaces); an empty zone (unzoned
        // interface) maps to 0, the legitimate "no zone" case. Kept as the
        // integrity check even though the value below comes from the ledger:
        // an unresolvable zone NAME must still reject the snapshot here.
        if !iface.zone.is_empty() && !state.zone_name_to_id.contains_key(&iface.zone) {
            return Err(
                crate::policy::SnapshotIntegrityError::InterfaceUnknownZone {
                    interface: iface.name.clone(),
                    zone: iface.zone.clone(),
                },
            );
        }
        // #6722: take the row's zone from the LEDGER, not from the row itself.
        // `state.egress` is keyed by ifindex and written last-write-wins, so
        // several identities sharing one ifindex each overwrite the previous
        // row's zone and the FINAL row decides. Sourcing it from the row would
        // let whichever identity sorts last name the zone — which is how
        // `origin/master` behaved, and why its answers here were a function of
        // interface NAMING (measured: for `ge-0/0/1` with unit 0 in `lan` and
        // unit 1 in `dmz`, master's egress zone is unit 0's `lan` only because
        // "ge-0/0/1.0" sorts after "ge-0/0/1").
        //
        // The ledger is absent for an ifindex Go declared no single zone for,
        // and for one whose claim no row corroborated; both must resolve 0, so a
        // plain `unwrap_or(0)` is exactly right.
        let zone_id = state
            .ifindex_unambiguous_zone_id
            .get(&iface.ifindex)
            .copied()
            .unwrap_or(0);
        state.egress.insert(
            iface.ifindex,
            EgressInterface {
                bind_ifindex,
                vlan_id,
                mtu,
                src_mac,
                zone_id,
                redundancy_group: iface.redundancy_group,
                primary_v4: pick_interface_v4(iface),
                primary_v6: pick_interface_v6(iface),
            },
        );
    }
    Ok(())
}

/// #6458: build `state.zone_to_rgs` — zone ID → deduplicated
/// redundancy-group IDs (> 0) of the zone's member interfaces. Runs after
/// [`populate_egress`] so both inputs (`ifindex_to_zone_id` and
/// `EgressInterface.redundancy_group`) are final. A zone whose members are
/// all RG-unbound (mgmt/fxp0, control/em0+fab, node-specific physical
/// interfaces) or that has no members is ABSENT from the map; the
/// fabric-ingress zone-stamp validation
/// (`forwarding::fabric::zone_encoded_fabric_stamp_valid`) treats an absent
/// zone as "can never be legitimately stamped" — a zone-encoded stamp
/// claims the packet ingressed the PEER in that zone, which is only
/// possible when the zone participates in RG ownership.
pub(super) fn populate_zone_to_rgs(state: &mut ForwardingState) {
    for (ifindex, zone_id) in state.ifindex_to_zone_id.iter() {
        if *zone_id == 0 {
            continue;
        }
        let rg = state
            .egress
            .get(ifindex)
            .map(|iface| iface.redundancy_group)
            .unwrap_or(0);
        if rg <= 0 {
            continue;
        }
        let rgs = state.zone_to_rgs.entry(*zone_id).or_default();
        if !rgs.contains(&rg) {
            rgs.push(rg);
        }
    }
}

/// #2388: canonical (v4, v6) connected-route table names for a routing
/// instance. The empty instance name is the default instance
/// (inet.0 / inet6.0); a named instance maps to "<ri>.inet.0" /
/// "<ri>.inet6.0". These match the names the lookup canonicalizes the
/// queried table to (`canonical_route_table`), so a connected entry is
/// only matched when the lookup is resolving in the owning table.
pub(in crate::afxdp) fn connected_route_tables(routing_instance: &str) -> (String, String) {
    if routing_instance.is_empty() {
        ("inet.0".to_string(), "inet6.0".to_string())
    } else {
        (
            format!("{routing_instance}.inet.0"),
            format!("{routing_instance}.inet6.0"),
        )
    }
}

/// #5659: base-name lifeline match, mirroring the NAME/prefix exclusions of the
/// authoritative Go SSOT `userspaceSkipsIngressInterface`
/// (pkg/dataplane/userspace/maps_sync.go): the `fxp*` / `em*` / `fab*` prefixes
/// plus `lo0`. A lifeline interface's host-bound traffic is served
/// UNCONDITIONALLY by the kernel path (excluded from the AF_XDP host-inbound
/// deny sets), so the empty-zone fail-closed backstop in [`populate_interfaces`]
/// must never arm a deny sentinel for one — that would strand management / break
/// the HA heartbeat the moment a future change bound it.
///
/// The earlier form matched only the exact `fxp0` / `em0` names, which was
/// NARROWER than the SSOT and would arm a deny sentinel on an unzoned+addressed
/// `lo0` (a router-id / BGP `update-source` loopback) or an `fxp1` / `em1` in
/// the exact future case this backstop hardens — reintroducing a
/// management-strand. The remaining arms of `userspaceSkipsIngressInterface` are
/// handled elsewhere or moot here:
///   - the mgmt/control-ZONE arm is unreachable — the sentinel branch already
///     requires an EMPTY zone;
///   - the `LocalFabric != ""` (fabric parent) arm is subsumed by the `fab*`
///     prefix, so a fabric parent that gains an L3 address stays exempt;
///   - the `Tunnel` arm is inert — a tunnel interface is likewise excluded from
///     the AF_XDP ingress-ifindex map by the same SSOT, so a sentinel on one is
///     never consulted.
///
/// The config-derived control/fabric names (#3277: a renamed `control-interface`
/// / non-default fabric) are still NOT mirrored here because the snapshot does
/// not carry them; that stays safe only because such a renamed lifeline is
/// zoneless and thus not AF_XDP-bound today (`buildUserspaceBindNetdevs` skips a
/// zoneless interface), so a missed match leaves an INERT sentinel that is never
/// consulted. If a future change binds a zoneless interface, this predicate MUST
/// be reconciled with `userspaceSkipsIngressInterface` (add a parity test). The
/// unit suffix is stripped so `em0.0` / `fab1.0` / `lo0.0` match too.
fn is_host_inbound_lifeline(name: &str) -> bool {
    let base = match name.split_once('.') {
        Some((b, _)) => b,
        None => name,
    }
    .trim();
    base.starts_with("fxp") || base.starts_with("em") || base.starts_with("fab") || base == "lo0"
}

pub(in crate::afxdp) fn pick_interface_v4(iface: &InterfaceSnapshot) -> Option<Ipv4Addr> {
    let mut fallback = None;
    for addr in &iface.addresses {
        if addr.family != "inet" {
            continue;
        }
        let Ok(net) = addr.address.parse::<ipnet::Ipv4Net>() else {
            continue;
        };
        let ip = net.addr();
        if fallback.is_none() {
            fallback = Some(ip);
        }
        if !ip.is_link_local() {
            return Some(ip);
        }
    }
    fallback
}

pub(in crate::afxdp) fn pick_interface_v6(iface: &InterfaceSnapshot) -> Option<Ipv6Addr> {
    let mut fallback = None;
    for addr in &iface.addresses {
        if addr.family != "inet6" {
            continue;
        }
        let Ok(net) = addr.address.parse::<ipnet::Ipv6Net>() else {
            continue;
        };
        let ip = net.addr();
        if fallback.is_none() {
            fallback = Some(ip);
        }
        if !ip.is_unicast_link_local() {
            return Some(ip);
        }
    }
    fallback
}

// #7160 (#2387) — the routing-domain half of the interface build.
//
// These cells guard the two maps `forwarding::ingress_routing_domain` reads
// and the single-bool gate that keeps a deployment with no routing-instance
// interface membership from probing either. All three are invisible to every
// pre-existing forwarding_build test because they all run in the default
// instance, where the domain is 0.
#[cfg(test)]
mod routing_domain_7160_tests {
    use super::*;
    use crate::afxdp::forwarding::ingress_routing_domain;
    use crate::protocol::{ConfigSnapshot, InterfaceSnapshot, ZoneSnapshot};

    const DOMAIN_A: u32 = 100_001;
    const DOMAIN_B: u32 = 100_002;

    fn build(snapshot: &ConfigSnapshot) -> ForwardingState {
        let mut state = ForwardingState::default();
        // Zones must be registered first — `populate_interfaces` resolves each
        // row's zone NAME through `zone_name_to_id` and fails the snapshot
        // closed on an unknown one. This mirrors the real builder's order
        // (`forwarding_build/mod.rs`).
        crate::afxdp::forwarding_build::zones::populate_zones(snapshot, &mut state);
        populate_interfaces(
            snapshot,
            &mut state,
            &FastSet::default(),
            &FastSet::default(),
        )
        .expect("populate_interfaces");
        state
    }

    fn iface(name: &str, ifindex: i32, zone: &str, ri: &str, domain: u32) -> InterfaceSnapshot {
        InterfaceSnapshot {
            name: name.into(),
            linux_name: name.into(),
            ifindex,
            zone: zone.into(),
            routing_instance: ri.into(),
            routing_domain: domain,
            ..Default::default()
        }
    }

    fn zone(name: &str, id: u16) -> ZoneSnapshot {
        ZoneSnapshot {
            name: name.into(),
            id,
            ..Default::default()
        }
    }

    /// A config with no routing-instance interface membership must leave BOTH
    /// maps empty and the gate false, so `ingress_routing_domain` returns 0
    /// without a single map probe. This is what makes #7160 bit-identical to
    /// pre-#7160 for the overwhelming majority of deployments.
    #[test]
    fn no_membership_leaves_the_gate_false_and_the_maps_empty() {
        let snapshot = ConfigSnapshot {
            interfaces: vec![
                iface("ge-0-0-0", 10, "trust", "", 0),
                iface("ge-0-0-1", 11, "untrust", "", 0),
            ],
            zones: vec![zone("trust", 1), zone("untrust", 2)],
            ..Default::default()
        };
        let state = build(&snapshot);
        assert!(
            !state.has_routing_domains,
            "has_routing_domains must stay false with no routing-instance member \
             interfaces — it is the gate that keeps the packet path from probing \
             the map at all"
        );
        assert!(state.ifindex_to_routing_domain.is_empty());
        assert!(state.zone_routing_domain.is_empty());
        assert_eq!(ingress_routing_domain(&state, 10, 0, None), 0);
    }

    /// The map is keyed on the ifindex the snapshot row carries, and only a
    /// NON-ZERO domain is stored — so an absent ifindex reads as domain 0, the
    /// same "absent = default" convention `ifindex_to_routing_instance` uses.
    #[test]
    fn member_interfaces_resolve_their_domain_and_others_resolve_zero() {
        let snapshot = ConfigSnapshot {
            interfaces: vec![
                iface("ge-0-0-0", 10, "tenant-a-lan", "tenant-a", DOMAIN_A),
                iface("ge-0-0-1", 11, "tenant-b-lan", "tenant-b", DOMAIN_B),
                iface("ge-0-0-2", 12, "untrust", "", 0),
            ],
            zones: vec![
                zone("tenant-a-lan", 1),
                zone("tenant-b-lan", 2),
                zone("untrust", 3),
            ],
            ..Default::default()
        };
        let state = build(&snapshot);
        assert!(state.has_routing_domains);
        assert_eq!(ingress_routing_domain(&state, 10, 0, None), DOMAIN_A);
        assert_eq!(ingress_routing_domain(&state, 11, 0, None), DOMAIN_B);
        assert_eq!(
            ingress_routing_domain(&state, 12, 0, None),
            0,
            "an interface in no routing instance must be the default domain"
        );
        assert_eq!(
            ingress_routing_domain(&state, 999, 0, None),
            0,
            "an unknown ifindex must be the default domain, not a panic or a \
             borrowed neighbour's domain"
        );
    }

    /// A zone whose member interfaces all agree gets a domain; a zone that
    /// STRADDLES two routing instances is left ABSENT and reads as 0.
    ///
    /// This map is read only on the fabric-ingress path, where the arriving
    /// interface is the fabric link and the peer's zone encoding is the only
    /// ingress identity available. Assigning a straddling zone the first-seen
    /// domain would hand a fabric-redirected packet a CONFIDENTLY WRONG domain,
    /// which is strictly worse than the undifferentiated one — the #6722
    /// `ifindex_unambiguous_zone_id` discipline.
    ///
    /// FAIL-ON-REVERT: drop the ambiguity sweep and the straddling zone starts
    /// resolving whichever member the iteration happened to see first.
    #[test]
    fn a_zone_straddling_two_routing_instances_resolves_no_domain() {
        let snapshot = ConfigSnapshot {
            interfaces: vec![
                // `clean` is wholly inside tenant-a.
                iface("ge-0-0-0", 10, "clean", "tenant-a", DOMAIN_A),
                iface("ge-0-0-1", 11, "clean", "tenant-a", DOMAIN_A),
                // `straddle` has one interface in tenant-b and one in the
                // default instance.
                iface("ge-0-0-2", 12, "straddle", "tenant-b", DOMAIN_B),
                iface("ge-0-0-3", 13, "straddle", "", 0),
            ],
            zones: vec![zone("clean", 1), zone("straddle", 2)],
            ..Default::default()
        };
        let state = build(&snapshot);
        assert_eq!(
            state.zone_routing_domain.get(&1).copied(),
            Some(DOMAIN_A),
            "a zone whose members all sit in one routing instance must resolve it"
        );
        assert_eq!(
            state.zone_routing_domain.get(&2).copied(),
            None,
            "a zone straddling two routing instances must resolve NOTHING; a \
             first-seen answer is a confidently wrong domain for every \
             fabric-redirected packet stamped with that zone"
        );
        // And that is what the fabric-ingress read produces.
        assert_eq!(ingress_routing_domain(&state, 10, 0, Some(1)), DOMAIN_A);
        assert_eq!(ingress_routing_domain(&state, 10, 0, Some(2)), 0);
    }

    /// A fabric-ingress frame must NOT take the arriving interface's domain.
    /// It arrived on the fabric link, not on the flow's real ingress, so the
    /// fabric link's own membership is a wrong answer rather than a missing
    /// one — the peer's zone encoding is the identity to resolve from.
    ///
    /// FAIL-ON-REVERT: make the fabric zone advisory (fall through to the
    /// ifindex map) and this goes red.
    #[test]
    fn a_fabric_ingress_frame_resolves_from_the_encoded_zone_not_the_link() {
        let snapshot = ConfigSnapshot {
            interfaces: vec![
                // The fabric link itself happens to be a tenant-b member.
                iface("ge-0-0-0", 10, "fabric", "tenant-b", DOMAIN_B),
                iface("ge-0-0-1", 11, "tenant-a-lan", "tenant-a", DOMAIN_A),
            ],
            zones: vec![zone("fabric", 1), zone("tenant-a-lan", 2)],
            ..Default::default()
        };
        let state = build(&snapshot);
        assert_eq!(
            ingress_routing_domain(&state, 10, 0, Some(2)),
            DOMAIN_A,
            "the peer-encoded ORIGINAL ingress zone decides the domain, not the \
             fabric link the frame physically arrived on"
        );
        assert_eq!(
            ingress_routing_domain(&state, 10, 0, None),
            DOMAIN_B,
            "without a zone encoding the same interface is an ordinary ingress \
             and keeps its own domain"
        );
    }
}
