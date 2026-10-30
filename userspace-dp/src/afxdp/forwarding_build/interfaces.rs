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
use std::collections::{BTreeMap, BTreeSet};
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
/// What the LOGICAL UNIT rows on ONE ifindex say about that ifindex's
/// EFFECTIVE per-interface host-inbound override (#16057, #16501).
///
/// A flat `ifindex → ZoneHostInbound` map cannot carry two distinct unit
/// overrides: the AF_XDP ingress descriptor names the netdev, not the unit.
/// When the unit rows on one ifindex disagree, inserting the last one would
/// hand every unit a sibling's management admission. `Disagree` therefore
/// refuses to keep any unit override for the ifindex; the caller installs
/// the empty fail-closed sentinel instead.
///
/// On an ifindex carrying a configured override, an UNCONFIGURED unit
/// row votes with its EFFECTIVE zone signature (#16501) — the set it
/// would have fallen back to per-unit, canonicalised exactly as for a
/// configured row. Before #16501 it cast no vote there, so a configured
/// sibling's override governed the whole shared netdev: the
/// unconfigured unit's peers gained the sibling's services and lost its
/// zone services, and authoring an explicit (even empty) override was
/// safer than authoring none. An unconfigured unit whose zone set
/// EQUALS the sibling's override still agrees, so that shape keeps the
/// agreed override; on an ifindex with no configured row it casts no
/// vote at all, preserving every pre-#16501 unconfigured-only verdict.
/// Different zones are also not, by themselves, a dispute — Go resolves
/// each unit's effective set per unit NAME (`#3362`/`#3720`), so
/// same-zone provenance is not required; only the effective token sets
/// are compared. This mirrors the Go `claimNetdev` signature
/// (`pkg/dataplane/userspace/zones_host_inbound.go`), which claims every
/// unit netdev with its effective (zone-fallback) signature and treats
/// more than one signature on a netdev as ambiguous.
/// The `Agreed` payload is the CANONICAL effective-admission signature,
/// not the raw ordered token vectors: sorted/deduped service and protocol
/// token sets (the Rust classifier is order- and duplicate-insensitive)
/// plus the ND-withdrawn bit. Raw non-ND `protocols_except` provenance is
/// deliberately excluded — the consumer reads only `ndp` out of that list
/// (`ndp_excluded`, host_inbound.rs), mirroring Go's
/// `CanonicalHostInboundTokenSigExcept` SSOT
/// (`pkg/config/dup_host_local_address.go`). Comparing raw ordered vectors
/// would falsely dispute two units whose authored tokens merely differ in
/// order, duplicates, or non-ND exclusion provenance and deny both.
#[derive(Clone, Debug, PartialEq, Eq)]
enum UnitHostInboundClaim {
    /// Every logical-unit row on the ifindex carried this canonical
    /// effective-admission signature.
    Agreed(std::collections::BTreeSet<String>, std::collections::BTreeSet<String>, bool),
    /// Logical-unit rows on one ifindex carried DIFFERENT canonical
    /// effective-admission signatures.
    Disagree,
}


#[derive(Clone, Debug, PartialEq, Eq)]
enum UnitZoneClaim {
    /// Every logical-unit row on the ifindex carried this zone name.
    Agreed(String),
    /// Unit rows on one ifindex carried DIFFERENT zone names.
    Disagree,
}

const UNIT_REFUSED_TRANSIT_FULL_10520: &str = "Transit arriving there is DENIED as unattributed before any policy is consulted \
     (#6682); default-policy permit-all does not admit it, and the deny logs as \
     unattributed (#9989, counter UNZONED_INGRESS_DENIED).";
const UNIT_REFUSED_TRANSIT_RETAINED_10520: &str = "Transit is evaluated under the retained zone's policy (zone-gated; the #6682 \
     unzoned-ingress deny does not apply), so its verdict follows that policy.";
const UNIT_REFUSED_HOST_BOUND_SENTINEL_10520: &str = "Host-bound traffic to the firewall itself is denied by the per-ifindex \
     empty host-inbound sentinel (#5659/#10556; ICMP errors/PMTUD/ND control \
     messages remain admitted; an explicit per-interface host-inbound stanza \
     still takes precedence).";
const UNIT_REFUSED_HOST_BOUND_CONTESTED_10520: &str = "Host-bound traffic to the firewall itself is denied by the contested-parent \
     host-inbound sentinel (#10503; ICMP errors/PMTUD/ND control messages remain \
     admitted; an explicit per-interface host-inbound override still takes \
     precedence).";
const UNIT_REFUSED_HOST_BOUND_RETAINED_10520: &str = "Host-bound traffic follows the retained sibling zone policy (zone-gated unless \
     an explicit per-interface host-inbound override takes precedence).";
const UNIT_REFUSED_HOST_BOUND_LIFELINE_10520: &str = "Host-bound traffic on this lifeline remains admitted; the #5659/#10556 \
     guards deliberately do not arm an empty-zone host-inbound sentinel.";
const UNIT_REFUSED_HOST_BOUND_GATED_10520: &str = "Host-bound traffic on this AF_XDP bind-excluded interface remains zone-gated by \
     applicable zone policy; this prefix-only/lo0 name follows the applicable \
     zone's host-inbound rules.";
const UNIT_REFUSED_HOST_BOUND_CONTESTED_LIFELINE_10520: &str = "Host-bound traffic on this lifeline remains admitted; #10503 deliberately \
     does not arm a contested-parent sentinel.";
const UNIT_REFUSED_HOST_BOUND_CONTESTED_GATED_10520: &str = "Host-bound traffic on this AF_XDP bind-excluded interface remains zone-gated by \
     applicable zone policy; this prefix-only/lo0 name follows the applicable \
     zone's host-inbound rules.";

const UNIT_REFUSED_HOST_BOUND_CONTESTED_OVERRIDE_10520: &str = "Host-bound traffic follows the explicit per-interface host-inbound override; \
     that stanza takes precedence over the contested-parent default.";
const UNIT_REFUSED_HOST_BOUND_OVERRIDE_10520: &str = "Host-bound traffic follows the explicit per-interface host-inbound override; \
     that stanza takes precedence over the empty-zone default.";
const UNIT_REFUSED_HOST_BOUND_ADMIT_10520: &str = "Host-bound traffic remains admitted: this ifindex has no per-ifindex empty \
     host-inbound sentinel, so the global None => true path applies; this \
     includes address-less non-tunnel refusals.";

fn unit_refused_transit_warning_10520(retained_zone: bool) -> &'static str {
    if retained_zone {
        UNIT_REFUSED_TRANSIT_RETAINED_10520
    } else {
        UNIT_REFUSED_TRANSIT_FULL_10520
    }
}

fn unit_refused_host_bound_warning_10520(
    retained_zone: bool,
    host_sentinel: bool,
    host_override: bool,
    config_name: Option<&str>,
) -> &'static str {
    if retained_zone {
        UNIT_REFUSED_HOST_BOUND_RETAINED_10520
    } else if host_sentinel {
        UNIT_REFUSED_HOST_BOUND_SENTINEL_10520
    } else if host_override {
        UNIT_REFUSED_HOST_BOUND_OVERRIDE_10520
    } else if config_name.is_some_and(is_narrow_host_inbound_lifeline) {
        UNIT_REFUSED_HOST_BOUND_LIFELINE_10520
    } else if config_name.is_some_and(is_zone_gated_host_inbound_name) {
        UNIT_REFUSED_HOST_BOUND_GATED_10520
    } else {
        UNIT_REFUSED_HOST_BOUND_ADMIT_10520
    }
}

fn contested_host_bound_warning_10520(
    empty_zone_sentinel: bool,
    contested_sentinel: bool,
    host_override: bool,
    config_name: Option<&str>,
) -> &'static str {
    if empty_zone_sentinel {
        UNIT_REFUSED_HOST_BOUND_SENTINEL_10520
    } else if contested_sentinel {
        UNIT_REFUSED_HOST_BOUND_CONTESTED_10520
    } else if host_override {
        UNIT_REFUSED_HOST_BOUND_CONTESTED_OVERRIDE_10520
    } else if config_name.is_some_and(is_narrow_host_inbound_lifeline) {
        UNIT_REFUSED_HOST_BOUND_CONTESTED_LIFELINE_10520
    } else if config_name.is_some_and(is_zone_gated_host_inbound_name) {
        UNIT_REFUSED_HOST_BOUND_CONTESTED_GATED_10520
    } else {
        UNIT_REFUSED_HOST_BOUND_ADMIT_10520
    }
}

#[cfg(test)]
mod warning_text_tests_10520 {
    use super::*;

    #[test]
    fn refusal_warning_text_pins_full_partial_and_lifeline_mechanisms_10520() {
        assert_eq!(
            unit_refused_transit_warning_10520(true),
            UNIT_REFUSED_TRANSIT_RETAINED_10520
        );
        assert_eq!(
            unit_refused_transit_warning_10520(false),
            UNIT_REFUSED_TRANSIT_FULL_10520
        );
        assert!(UNIT_REFUSED_TRANSIT_FULL_10520.contains("#6682"));
        assert!(UNIT_REFUSED_TRANSIT_FULL_10520.contains("#9989"));
        assert!(UNIT_REFUSED_TRANSIT_FULL_10520.contains("UNZONED_INGRESS_DENIED"));
        assert!(UNIT_REFUSED_TRANSIT_RETAINED_10520.contains("zone-gated"));
        assert!(UNIT_REFUSED_TRANSIT_RETAINED_10520.contains("does not apply"));

        assert!(UNIT_REFUSED_HOST_BOUND_SENTINEL_10520.contains("#5659"));
        assert!(UNIT_REFUSED_HOST_BOUND_SENTINEL_10520.contains("ICMP"));
        assert!(UNIT_REFUSED_HOST_BOUND_SENTINEL_10520.contains("#10556"));
        assert!(UNIT_REFUSED_HOST_BOUND_RETAINED_10520.contains("zone-gated"));
        assert!(UNIT_REFUSED_HOST_BOUND_RETAINED_10520.contains("override"));
        assert!(UNIT_REFUSED_HOST_BOUND_LIFELINE_10520.contains("#5659"));
        assert!(UNIT_REFUSED_HOST_BOUND_LIFELINE_10520.contains("#10556"));
        assert!(UNIT_REFUSED_HOST_BOUND_LIFELINE_10520.contains("admitted"));
        assert!(UNIT_REFUSED_HOST_BOUND_GATED_10520.contains("zone-gated"));
        assert!(!UNIT_REFUSED_HOST_BOUND_GATED_10520.contains("admitted"));
        assert!(!UNIT_REFUSED_HOST_BOUND_GATED_10520.contains("denied"));
        assert!(UNIT_REFUSED_HOST_BOUND_OVERRIDE_10520.contains("override"));
        assert!(UNIT_REFUSED_HOST_BOUND_ADMIT_10520.contains("None => true"));
        assert!(!UNIT_REFUSED_HOST_BOUND_ADMIT_10520.contains("all-zoned tunnel"));
        assert!(!UNIT_REFUSED_HOST_BOUND_LIFELINE_10520.contains("#10503"));

        assert!(UNIT_REFUSED_HOST_BOUND_CONTESTED_10520.contains("#10503"));
        assert!(UNIT_REFUSED_HOST_BOUND_CONTESTED_10520.contains("override"));
        assert!(UNIT_REFUSED_HOST_BOUND_CONTESTED_LIFELINE_10520.contains("#10503"));
        assert!(!UNIT_REFUSED_HOST_BOUND_CONTESTED_LIFELINE_10520.contains("#5659"));
        assert!(UNIT_REFUSED_HOST_BOUND_CONTESTED_GATED_10520.contains("zone-gated"));
        assert!(!UNIT_REFUSED_HOST_BOUND_CONTESTED_GATED_10520.contains("admitted"));
        assert!(!UNIT_REFUSED_HOST_BOUND_CONTESTED_GATED_10520.contains("denied"));
        assert!(UNIT_REFUSED_HOST_BOUND_CONTESTED_OVERRIDE_10520.contains("contested-parent"));
        for name in ["fxp0", "em0", "fab0", "fab10", "fab0.0"] {
            assert!(
                is_narrow_host_inbound_lifeline(name),
                "{name} must be narrow"
            );
            assert!(!is_zone_gated_host_inbound_name(name));
        }
        for name in ["fxp1", "em1", "fab-foo", "lo0", "lo0.0"] {
            assert!(is_host_inbound_lifeline(name), "{name} must remain broad");
            assert!(
                is_zone_gated_host_inbound_name(name),
                "{name} must be gated"
            );
            assert!(!is_narrow_host_inbound_lifeline(name));
        }
        let disagree = UnitZoneClaim::Disagree;
        let agreed = UnitZoneClaim::Agreed("trust".into());
        assert!(unit_refused_rows_are_all_zoned_10520(
            Some(&disagree),
            false
        ));
        assert!(!unit_refused_rows_are_all_zoned_10520(
            Some(&disagree),
            true
        ));
        assert!(!unit_refused_rows_are_all_zoned_10520(Some(&agreed), false));
        assert_eq!(
            unit_refused_host_bound_warning_10520(true, true, true, Some("fab0.0")),
            UNIT_REFUSED_HOST_BOUND_RETAINED_10520
        );
        assert_eq!(
            unit_refused_host_bound_warning_10520(false, true, false, Some("reth0.0")),
            UNIT_REFUSED_HOST_BOUND_SENTINEL_10520
        );
        assert_eq!(
            unit_refused_host_bound_warning_10520(false, false, false, Some("fab0.0")),
            UNIT_REFUSED_HOST_BOUND_LIFELINE_10520
        );
        assert_eq!(
            unit_refused_host_bound_warning_10520(false, false, false, Some("em1")),
            UNIT_REFUSED_HOST_BOUND_GATED_10520
        );
        assert_eq!(
            unit_refused_host_bound_warning_10520(false, false, true, Some("reth0.0")),
            UNIT_REFUSED_HOST_BOUND_OVERRIDE_10520
        );
        assert_eq!(
            unit_refused_host_bound_warning_10520(false, false, false, Some("st0.0")),
            UNIT_REFUSED_HOST_BOUND_ADMIT_10520
        );
        assert_eq!(
            contested_host_bound_warning_10520(false, false, true, Some("reth0.0")),
            UNIT_REFUSED_HOST_BOUND_CONTESTED_OVERRIDE_10520
        );
        assert_eq!(
            contested_host_bound_warning_10520(true, true, true, Some("em1")),
            UNIT_REFUSED_HOST_BOUND_SENTINEL_10520
        );
        assert_eq!(
            contested_host_bound_warning_10520(false, true, false, Some("reth0.0")),
            UNIT_REFUSED_HOST_BOUND_CONTESTED_10520
        );
        assert_eq!(
            contested_host_bound_warning_10520(false, false, false, Some("fab0.0")),
            UNIT_REFUSED_HOST_BOUND_CONTESTED_LIFELINE_10520
        );
        assert_eq!(
            contested_host_bound_warning_10520(false, false, false, Some("em1")),
            UNIT_REFUSED_HOST_BOUND_CONTESTED_GATED_10520
        );
        assert_eq!(
            contested_host_bound_warning_10520(false, false, false, Some("st0.0")),
            UNIT_REFUSED_HOST_BOUND_ADMIT_10520
        );
    }
}
/// True for a snapshot row that names a LOGICAL UNIT (`st0.0`, `reth1.0`,
/// `ge-0/0/9.100`) rather than an interface (`st0`, `reth1`, `ge-0/0/9`).
///
/// #9821: the answer is STRUCTURAL, not a spelling. The Go builder states
/// which loop emitted the row in `is_unit`, and `Some` is authoritative —
/// a declared interface may itself contain a dot (`ge-0/0/5.0`), so the old
/// "A Junos interface name never contains `.`" premise was false and its
/// numeric-suffix test read a dotted base row as a unit row. `None` (old
/// Go, tests, fixtures) falls back to that same suffix test, which is
/// old-Go behavior exactly.
fn is_logical_unit_row(name: &str, is_unit: Option<bool>) -> bool {
    if let Some(structural) = is_unit {
        return structural;
    }
    match name.rsplit_once('.') {
        Some((base, unit)) => {
            !base.is_empty() && !unit.is_empty() && unit.bytes().all(|b| b.is_ascii_digit())
        }
        None => false,
    }
}

/// #16063: logical ifindex -> configured unit number, for unit rows
/// whose logical identity the ingress resolution can actually produce.
/// A unit row contributes only when no sibling unit row shares its
/// (bind_ifindex, VID): tunnel units on one netdev (wg0.0/wg0.1, both
/// VID 0 on the shared ifindex) are ambiguous there — the poll path's
/// packet metadata is (ifindex, VID) only and decap rebinds to the
/// tunnel's single logical ifindex — so they are omitted, and the Go
/// builder refuses mirroring any one of them. VLAN units (distinct
/// logical ifindex per VID) and a lone unit 0 are unambiguous.
pub(super) fn ingress_unit_by_logical(
    snapshot: &ConfigSnapshot,
) -> Result<FastMap<i32, i32>, crate::policy::SnapshotIntegrityError> {
    // #17206: key on the DECODED VlanId, not the raw i32 — a negative
    // "no VLAN" row and VID 0 are the same VLAN, so counting them apart
    // would keep an ambiguous row the decoder treats as one identity.
    let mut rows_by_key: std::collections::BTreeMap<(i32, super::validated::VlanId), i32> =
        std::collections::BTreeMap::new();
    for iface in &snapshot.interfaces {
        if iface.ifindex <= 0 || !is_logical_unit_row(&iface.name, iface.is_unit) {
            continue;
        }
        let bind_ifindex = if iface.parent_ifindex > 0 {
            iface.parent_ifindex
        } else {
            iface.ifindex
        };
        let row = super::validated::RowIds::try_from_row(iface)?;
        *rows_by_key.entry((bind_ifindex, row.vlan)).or_default() += 1;
    }
    let mut out = FastMap::default();
    for iface in &snapshot.interfaces {
        if iface.ifindex <= 0 || !is_logical_unit_row(&iface.name, iface.is_unit) {
            continue;
        }
        let bind_ifindex = if iface.parent_ifindex > 0 {
            iface.parent_ifindex
        } else {
            iface.ifindex
        };
        let row = super::validated::RowIds::try_from_row(iface)?;
        if rows_by_key.get(&(bind_ifindex, row.vlan)).copied() != Some(1) {
            continue;
        }
        let Some(unit) = iface
            .name
            .rsplit_once('.')
            .and_then(|(_, unit)| unit.parse::<i32>().ok())
        else {
            continue;
        };
        out.insert(iface.ifindex, unit);
    }
    Ok(out)
}

/// ifindex -> [`UnitZoneClaim`] for every ifindex that carries at least one
/// logical-unit row. An ifindex absent here carries no unit row at all, and its
/// zone is decided exactly as it was before #7509 — that absence is what keeps
/// the #921/#3618 trunk-parent inheritance intact for a parent whose units all
/// have netdevs of their own.
fn unit_zone_claims(snapshot: &ConfigSnapshot) -> BTreeMap<i32, UnitZoneClaim> {
    let mut out: BTreeMap<i32, UnitZoneClaim> = BTreeMap::new();
    for iface in &snapshot.interfaces {
        if iface.ifindex <= 0 || !is_logical_unit_row(&iface.name, iface.is_unit) {
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

/// The ifindexes whose logical-unit rows include an explicitly UNZONED row.
/// `UnitZoneClaim::Disagree` covers both `zone` versus `""` and two distinct
/// nonempty zones; warning text must distinguish those operator actions.
fn unit_rows_with_empty_zone_10520(snapshot: &ConfigSnapshot) -> std::collections::BTreeSet<i32> {
    let mut out = std::collections::BTreeSet::new();
    for iface in &snapshot.interfaces {
        if iface.ifindex > 0
            && is_logical_unit_row(&iface.name, iface.is_unit)
            && iface.zone.is_empty()
        {
            out.insert(iface.ifindex);
        }
    }
    out
}

/// The canonical effective-admission signature one row votes with
/// (#16057 fold): sorted/deduped service+protocol token SETS (matching the
/// classifier's order/duplicate insensitivity and its trim+lowercase
/// normalisation) plus the ND-withdrawn bit. The bit is the EFFECTIVE
/// withdrawal, mirroring the consumer: `ndp` in `protocols_except` sets
/// `ndp_excluded`, but a surviving positive ND admission (an explicit
/// `ndp` protocol token, or `all`, whose expansion includes it) still
/// admits ND — via the token in `host_inbound_admits_iface_for_destination`'s unicast
/// default arm, and via `ndp_positive`/types 133-136 in
/// `host_inbound_admits_iface_for_destination` — so the raw except token
/// alone is stale/alias noise there, exactly as Go's
/// `effectiveNDPWithdrawn` rules. Every other `protocols_except` token is
/// inert for this consumer and casts no part of the vote.
fn unit_host_inbound_vote(
    services: &[String],
    protocols: &[String],
    protocols_except: &[String],
) -> UnitHostInboundClaim {
    let tokens = |raw: &[String]| -> std::collections::BTreeSet<String> {
        raw.iter()
            .map(|t| t.trim().to_ascii_lowercase())
            .filter(|t| !t.is_empty())
            .collect()
    };
    let svc = tokens(services);
    let proto = tokens(protocols);
    let ndp_positive = proto.contains("ndp") || proto.contains("all");
    let ndp_withdrawn = !ndp_positive
        && protocols_except
            .iter()
            .any(|t| t.trim().eq_ignore_ascii_case("ndp"));
    UnitHostInboundClaim::Agreed(svc, proto, ndp_withdrawn)
}

/// ifindex -> [`UnitHostInboundClaim`] for every ifindex carrying at least
/// one CONFIGURED logical-unit host-inbound override row (#16057), plus
/// the #16501 disputes: an ifindex where a configured row's override
/// differs from a sibling UNCONFIGURED row's EFFECTIVE zone signature
/// (the tokens of the zone named on that row, or the empty deny-all
/// signature when it names no known zone, mirroring the consumer's zone
/// fallback — a no-stanza zone arrives with empty token sets, #3405).
/// Unconfigured-only ifindexes stay absent: their zone vote is
/// uncontested, needs no sentinel, and must not let a base row's
/// differing override lose to it (pre-#16501 behaviour). An unconfigured
/// unit whose zone set EQUALS the sibling's override agrees, so that
/// shape keeps the agreed override. Computed BEFORE the walk, like
/// [`unit_zone_claims`], so the base row's write and each unit row's
/// write consult the same precomputed verdict regardless of snapshot
/// row order.
fn unit_host_inbound_claims(snapshot: &ConfigSnapshot) -> BTreeMap<i32, UnitHostInboundClaim> {
    // First pass: the configured rows alone, exactly as #16057.
    let mut out: BTreeMap<i32, UnitHostInboundClaim> = BTreeMap::new();
    for iface in &snapshot.interfaces {
        if iface.ifindex <= 0
            || !iface.host_inbound_configured
            || !is_logical_unit_row(&iface.name, iface.is_unit)
        {
            continue;
        }
        let vote = unit_host_inbound_vote(
            &iface.host_inbound_system_services,
            &iface.host_inbound_protocols,
            &iface.host_inbound_protocols_except,
        );
        match out.entry(iface.ifindex) {
            std::collections::btree_map::Entry::Vacant(slot) => {
                slot.insert(vote);
            }
            std::collections::btree_map::Entry::Occupied(mut slot) => {
                if slot.get() != &vote {
                    slot.insert(UnitHostInboundClaim::Disagree);
                }
            }
        }
    }
    // #16501: an unconfigured unit row on an ifindex that already carries
    // a configured claim votes with its effective zone signature; a
    // mismatch disputes the ifindex. Rows on unclaimed ifindexes cast
    // no vote, preserving every pre-#16501 unconfigured-only verdict.
    for iface in &snapshot.interfaces {
        if iface.ifindex <= 0
            || iface.host_inbound_configured
            || !is_logical_unit_row(&iface.name, iface.is_unit)
        {
            continue;
        }
        let Some(slot) = out.get_mut(&iface.ifindex) else {
            continue;
        };
        if *slot == UnitHostInboundClaim::Disagree {
            continue;
        }
        let vote = match snapshot.zones.iter().find(|zone| zone.name == iface.zone) {
            Some(zone) => unit_host_inbound_vote(
                &zone.host_inbound_system_services,
                &zone.host_inbound_protocols,
                &zone.host_inbound_protocols_except,
            ),
            None => unit_host_inbound_vote(&[], &[], &[]),
        };
        if *slot != vote {
            *slot = UnitHostInboundClaim::Disagree;
        }
    }
    out
}

/// Whether the unit rows on `ifindex` admit the override spelled by
/// `services`/`protocols`/`protocols_except` as that ifindex's
/// per-interface host-inbound set (#16057, #16501). Mirrors
/// [`unit_rows_admit`]: `true` when no unit row sits on the ifindex, or
/// when every unit row's EFFECTIVE signature (override, or zone set for
/// an unconfigured row) equals this row's; `false` when they disagree
/// among themselves (this row's signature is then one of the disputed
/// sets, or a base row's differing set that must lose to the units).
fn unit_host_inbound_claims_admit(
    claims: &BTreeMap<i32, UnitHostInboundClaim>,
    ifindex: i32,
    services: &[String],
    protocols: &[String],
    protocols_except: &[String],
) -> bool {
    match claims.get(&ifindex) {
        None => true,
        Some(UnitHostInboundClaim::Agreed(..)) => {
            claims.get(&ifindex)
                == Some(&unit_host_inbound_vote(services, protocols, protocols_except))
        }
        Some(UnitHostInboundClaim::Disagree) => false,
    }
}

fn unit_refused_rows_are_all_zoned_10520(
    claim: Option<&UnitZoneClaim>,
    has_empty_zone: bool,
) -> bool {
    matches!(claim, Some(UnitZoneClaim::Disagree)) && !has_empty_zone
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

/// #16130: pure precompute extracted from `populate_interfaces` — the
/// ifindexes carrying at least one configured logical-unit host-inbound
/// row (#12646). Pure over the snapshot: no `ForwardingState` access, so
/// the walk consults exactly the set the inline computation produced.
fn unit_host_inbound_ifindexes_precompute(snapshot: &ConfigSnapshot) -> BTreeSet<i32> {
    snapshot
        .interfaces
        .iter()
        .filter(|iface| iface.ifindex > 0 && iface.host_inbound_configured)
        .filter(|iface| is_logical_unit_row(&iface.name, iface.is_unit))
        .map(|iface| iface.ifindex)
        .collect()
}

/// #16130: pure precompute extracted from `populate_interfaces` — the
/// ifindexes whose unit rows DISAGREE on their effective host-inbound
/// signature (#16057, #16501), derived from the precomputed claims.
fn disputed_host_inbound_ifindexes_precompute(
    claims: &BTreeMap<i32, UnitHostInboundClaim>,
) -> BTreeSet<i32> {
    claims
        .iter()
        .filter(|(_, claim)| **claim == UnitHostInboundClaim::Disagree)
        .map(|(ifindex, _)| *ifindex)
        .collect()
}

/// #16130: pure post-walk flush extracted from `populate_interfaces` —
/// admit an ifindex's corroborated egress zone (#6722) into
/// `state.ifindex_unambiguous_zone_id`. Consumes only the two claim maps
/// the walk accumulated plus `state.zone_name_to_id`; the walk's own
/// ordering relative to the other post-walk phases is unchanged (this
/// runs at exactly the site the inline loop occupied).
fn flush_egress_zone_claims(
    state: &mut ForwardingState,
    egress_zone_claim: BTreeMap<i32, EgressZoneClaim>,
    zones_carried: &BTreeMap<i32, BTreeSet<String>>,
) {
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
}

/// #16130: pure post-walk phase extracted from `populate_interfaces` —
/// the #16057 disputed host-inbound sentinel install. Consumes only the
/// disputed set plus `state`; returns the ifindexes it armed so the
/// caller emits the warning at exactly the original site/order.
fn install_disputed_host_inbound_sentinels(
    state: &mut ForwardingState,
    disputed: &BTreeSet<i32>,
) -> BTreeSet<i32> {
    let mut armed: BTreeSet<i32> = BTreeSet::new();
    for ifindex in disputed {
        if let Some(name) = state.ifindex_to_config_name.get(ifindex) {
            if is_host_inbound_lifeline(name) {
                continue;
            }
        }
        if let std::collections::hash_map::Entry::Vacant(slot) =
            state.ifindex_host_inbound.entry(*ifindex)
        {
            armed.insert(*ifindex);
            slot.insert(crate::afxdp::types::ZoneHostInbound { ndp_excluded: true, ..Default::default() });
        }
    }
    armed
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
    excluded_local_v4: &FastMap<String, FastSet<Ipv4Addr>>,
    excluded_local_v6: &FastMap<String, FastSet<Ipv6Addr>>,
) -> Result<IfaceIndex, crate::policy::SnapshotIntegrityError> {
    let mut name_to_ifindex = BTreeMap::new();
    let mut linux_to_ifindex = BTreeMap::new();
    let mut mac_by_ifindex = BTreeMap::new();
    // #6722: ifindex → the EGRESS zone name the Go builder stamped on its rows,
    // or `None` once two rows on one ifindex claimed different ones (drift; Go
    // stamps them identically). Flushed into
    // `state.ifindex_unambiguous_zone_id` after the walk, alongside
    // `zones_carried` — ifindex → the zone names its rows literally carry, which
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
        std::collections::BTreeSet<u32>,
    > = std::collections::BTreeMap::new();

    // #7509: what the LOGICAL UNIT rows on each ifindex say about its zone,
    // computed BEFORE the walk because the Go builder emits an interface's base
    // row ahead of its unit rows (pinned by
    // `TestZonedTrunkEmitsUnzonedUnit0OnTheSharedIfindex_6722`), so the base
    // row's insert has to be able to consult a unit row it has not reached yet.
    let unit_claims = unit_zone_claims(snapshot);
    let unit_empty_zone_ifindexes = unit_rows_with_empty_zone_10520(snapshot);
    // #7509: ifindexes whose zone a unit row REFUSED, with the zone ids that
    // were refused. Reported after the walk for the same reason the contest is
    // — a silent unzoning is a blackhole with no error anywhere on the box.
    let mut unit_refused_zones: std::collections::BTreeMap<i32, std::collections::BTreeSet<u32>> =
        std::collections::BTreeMap::new();
    // #10556: only ifindexes with the same local-target/tunnel exposure that
    // makes #5659 meaningful may receive the refused-ifindex sentinel.
    let mut host_inbound_exposure_ifindexes: std::collections::BTreeSet<i32> =
        std::collections::BTreeSet::new();
    // #10644: trunk-parent ifindexes (a unit row names them as its parent) and
    // unzoned child-unit ifindexes (an empty-zone unit row with a parent).
    // Both feed the post-walk unzoned-unit sentinel below.
    let mut trunk_parent_ifindexes: std::collections::BTreeSet<i32> =
        std::collections::BTreeSet::new();
    let mut unzoned_child_unit_ifindexes: std::collections::BTreeSet<i32> =
        std::collections::BTreeSet::new();
    // #5659/#10556: distinguish the per-ifindex empty host-inbound sentinel
    // from an explicit per-interface host-inbound override. Both occupy
    // `ifindex_host_inbound`, but only this set may select the sentinel warning
    // sentence.
    let mut empty_zone_host_inbound_sentinels: std::collections::BTreeSet<i32> =
        std::collections::BTreeSet::new();
    // #10520: the #10503 contested-parent sentinel also shares the map with
    // explicit overrides; retain its origin for the operator-facing sentence.
    let mut contested_host_inbound_sentinels: std::collections::BTreeSet<i32> =
        std::collections::BTreeSet::new();
    // #16061: the config name claimed by logical-unit rows per ifindex, and
    // the ifindexes where distinct unit rows claimed different names. A
    // contested ifindex keeps NO `ifindex_to_config_name` entry at all (see
    // the per-row write below), mirroring how #7509 refuses a contested zone
    // rather than guessing one.
    let mut unit_config_names: BTreeMap<i32, String> = BTreeMap::new();
    let mut contested_config_name_ifindexes: std::collections::BTreeSet<i32> =
        std::collections::BTreeSet::new();

    // #12646: Go merges physical + unit overrides into an effective per-unit
    // set, keyed by the logical unit name. A unit-0 row shares its ifindex with
    // the base row, so preserve the more-specific unit's set even if snapshot
    // row order changes.
    let unit_host_inbound_ifindexes = unit_host_inbound_ifindexes_precompute(snapshot);
    // #16057/#16501: ifindexes whose unit rows carry DIFFERENT effective
    // host-inbound signatures (a configured row's override, or an
    // unconfigured row's zone set). Precomputed before the walk so the
    // refusal is row-order independent; the disputed override is refused
    // in the walk and the empty fail-closed sentinel is installed after
    // it (plus a warning), mirroring the #10503 contested-zone backstop.
    let unit_host_inbound_claim_map = unit_host_inbound_claims(snapshot);
    let disputed_host_inbound_ifindexes =
        disputed_host_inbound_ifindexes_precompute(&unit_host_inbound_claim_map);
    for iface in &snapshot.interfaces {
        if iface.ifindex <= 0 {
            continue;
        }
        if iface.link_up == Some(false) {
            state.egress_link_down.insert(iface.ifindex);
        }
        if iface.parent_ifindex > 0 && is_logical_unit_row(&iface.name, iface.is_unit) {
            // #10644: remember the trunk parent and, for an empty-zone unit
            // row, the child unit itself, for the post-walk unzoned-unit
            // sentinel. The parent half keys on ANY unit row naming a parent
            // (zoned or not): a quarantined trunk keeps its netdevs bound
            // while every zone is blanked, so requiring a zoned child would
            // miss exactly the fail-closed case.
            trunk_parent_ifindexes.insert(iface.parent_ifindex);
            if iface.zone.is_empty() {
                unzoned_child_unit_ifindexes.insert(iface.ifindex);
            }
        }
        let label = if iface.linux_name.is_empty() {
            iface.name.clone()
        } else {
            iface.linux_name.clone()
        };
        state.ifindex_to_name.insert(iface.ifindex, label);
        // #16061: distinct logical-unit rows can collapse onto one netdev
        // ifindex (interface-level tunnels via `TunnelNameMap`, unit 0 on its
        // base). A single ifindex-keyed config name cannot name two units, so
        // keep the name only while every logical-unit row on the ifindex
        // agrees; a later sibling with a different name withdraws it (both
        // row orders fail closed the same way). Base rows are aliases of the
        // device, not traffic identities, and never contest the name — the
        // ordinary base+unit-0 pair keeps the unit's name exactly as today.
        // An absent name reads as "" at every NAT-scope consumer, so a
        // `from interface` / `to interface` rule scoped to either sibling
        // simply never matches traffic on the shared ifindex instead of
        // matching whichever sibling happened to be written last.
        if is_logical_unit_row(&iface.name, iface.is_unit) {
            match unit_config_names.entry(iface.ifindex) {
                std::collections::btree_map::Entry::Vacant(slot) => {
                    slot.insert(iface.name.clone());
                    state
                        .ifindex_to_config_name
                        .insert(iface.ifindex, iface.name.clone());
                }
                std::collections::btree_map::Entry::Occupied(slot) => {
                    if slot.get() != &iface.name {
                        contested_config_name_ifindexes.insert(iface.ifindex);
                        state.ifindex_to_config_name.remove(&iface.ifindex);
                    }
                }
            }
        } else if !contested_config_name_ifindexes.contains(&iface.ifindex)
            && !unit_config_names.contains_key(&iface.ifindex)
        {
            state
                .ifindex_to_config_name
                .insert(iface.ifindex, iface.name.clone());
        }
        // #10313: a tagged logical-unit row can be the only surviving
        // snapshot row for its physical parent (the base row was unresolved
        // or skipped). Keep the parent config identity available for the
        // fallback `from interface` scope even though the parent has no own
        // row. This is deliberately guarded by structural unit detection:
        // dotted base interface names must not be mistaken for units.
        if iface.parent_ifindex > 0 && is_logical_unit_row(&iface.name, iface.is_unit) {
            if let Some((base_name, _unit)) = iface.name.rsplit_once('.') {
                // #16061: a unit row whose OWN ifindex is config-name
                // contested must not publish even its base name onto the
                // parent slot. When the unit collapses onto its parent
                // (parent_ifindex == ifindex, e.g. wg0.0/wg0.1 on wg0), that
                // slot IS the contested ifindex; filling it would resurrect
                // a name the contest just withdrew — and `wg0` is a prefix
                // sibling rules must never match through.
                if !contested_config_name_ifindexes.contains(&iface.parent_ifindex) {
                    state
                        .ifindex_to_config_name
                        .entry(iface.parent_ifindex)
                        .or_insert_with(|| base_name.to_string());
                }
            }
        }
        // #9821 (#12): (routing_instance, routing_domain) recorded for an
        // ifindex always come from ONE row. A nonzero-domain (member) row
        // claims the ifindex for both maps; a zero-domain row writes its
        // name only while NO member row has claimed it (domain-map probe,
        // not name-map: a zero-domain row may still carry a NAME — (name,0)
        // is the #4446/old-Go compat shape, and its name must keep reaching
        // NAT scope exactly as today).
        // Delta vs the old code exists ONLY for member-row-before-zero-row
        // on one ifindex (the bug order: zero no longer clobbers the member
        // name). (name,0) rows, ("",0) rows, member-last, and
        // member-vs-member last-wins are byte-identical.
        // #3096: the instance name feeds NAT rule-set `from`/`to
        // routing-instance` scope matching ("" = default VRF). #7160
        // (#2387): Go decides the domain number (`routingInstanceDomain`);
        // 0 is the default instance. Only a non-zero domain is stored, so
        // the map holds exactly the MEMBER ifindexes and an absent ifindex
        // reads as domain 0 — and `has_routing_domains` is sticky (set on
        // claim, never cleared: membership, once observed, is not lost to
        // row order).
        // #9956 GPT-2: a quarantine-sentinel row ("", 2) is NOT a member
        // claim — it must never overwrite a surviving member's claim on a
        // shared ifindex (collapsed unit rows sort ascending, so the survivor
        // row comes first and the quarantine row later). Member rows keep
        // unconditional last-wins; sentinel rows are fill-only like
        // zero-domain rows, except they also claim the sentinel domain when
        // the ifindex is otherwise unclaimed (that claim IS the F-032 fix —
        // and `has_routing_domains` must be set for it, or the ingress
        // resolver short-circuits quarantined traffic back to domain 0).
        // Either row order leaves the survivor owning the ifindex.
        if iface.routing_domain != 0
            && iface.routing_domain != crate::session::QUARANTINED_ROUTING_DOMAIN
        {
            state
                .ifindex_to_routing_instance
                .insert(iface.ifindex, iface.routing_instance.clone());
            state
                .ifindex_to_routing_domain
                .insert(iface.ifindex, iface.routing_domain);
            state.has_routing_domains = true;
        } else if !state.ifindex_to_routing_domain.contains_key(&iface.ifindex) {
            state
                .ifindex_to_routing_instance
                .insert(iface.ifindex, iface.routing_instance.clone());
            if iface.routing_domain == crate::session::QUARANTINED_ROUTING_DOMAIN {
                state
                    .ifindex_to_routing_domain
                    .insert(iface.ifindex, iface.routing_domain);
                state.has_routing_domains = true;
            }
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
        // #921: resolve zone NAME → u32 once at config build, so every read on
        // the hot path is one HashMap lookup (ifindex → u32). An unzoned row
        // resolves to 0, the "no zone" sentinel.
        // #2391: a non-empty zone NAME that is not in the zone table
        // (dropped at populate_zones for a u8-overflow id, or a
        // version-drifted/hostile snapshot) must FAIL CLOSED instead of
        // collapsing to zone 0 — collapsing bypasses every zone-pair policy
        // (fail-open under a permit default). The Go commit-time cap is the
        // primary gate; this is the helper-boundary backstop.
        let row_zone_id: u32 = if iface.zone.is_empty() {
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
                // to pick one rather than guess. Transit is denied as unattributed
                // before the implicit default policy (#6682). An ordinary
                // non-lifeline contest denies host-bound traffic with the
                // contested-parent host-inbound sentinel (#10503), while a
                // lifeline contest remains admitted. Refused-but-not-contested
                // all-zoned interface-level tunnel Disagrees are covered by the
                // #10556 refused-ifindex sentinel below.
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
                // #11297 rejects VID 0 at the common poll head on tagged-only
                // binds rather than changing this shared parent-zone derivation.
                // #11434 adds a narrower native-VLAN mapping only when exactly
                // one matching logical unit is present; the resolver then uses
                // that unit's identity. A missing or ambiguous match remains
                // rejected. Simply permitting VID 0 here would lend sibling
                // zone rights to ambiguous traffic.
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
        // #3362 per-interface host-inbound OVERRIDE. The control plane carries
        // the effective token set resolved for this interface.
        // #16057/#16501: a DISPUTED unit override (unit rows on this
        // ifindex carrying different canonical effective signatures — a
        // configured row's override versus a sibling's override or an
        // unconfigured sibling's zone set) is refused for every row,
        // base included — keeping any one would
        // hand the sibling's admission to the whole netdev. The empty
        // fail-closed sentinel is installed after the walk. Unit rows
        // whose signatures AGREE keep the #12646 unit-wins behaviour
        // byte-identically (one agreed signature, written by each unit
        // row); a base row whose signature differs from the agreed unit
        // signature still loses, exactly as #12646 pinned.
        if iface.host_inbound_configured
            && unit_host_inbound_claims_admit(
                &unit_host_inbound_claim_map,
                iface.ifindex,
                &iface.host_inbound_system_services,
                &iface.host_inbound_protocols,
                &iface.host_inbound_protocols_except,
            )
            && (is_logical_unit_row(&iface.name, iface.is_unit)
                || !unit_host_inbound_ifindexes.contains(&iface.ifindex))
        {
            // #12646: unit 0 shares its netdev ifindex with the base. The
            // unit override is more specific than the base row's set and must
            // win regardless of snapshot row order. Skip the base's write when
            // a configured unit row exists; retain the unit's existing
            // last-write behaviour for any additional unit aliases whose
            // signatures agree (#16057 refuses only a genuine disagreement).
            empty_zone_host_inbound_sentinels.remove(&iface.ifindex);
            state.ifindex_host_inbound.insert(
                iface.ifindex,
                crate::afxdp::forwarding::zone_host_inbound_from_tokens_except(
                    &iface.host_inbound_system_services,
                    &iface.host_inbound_protocols,
                    &iface.host_inbound_protocols_except,
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
        // #5659/#14662: track whether this interface registered at least one
        // local-delivery target in EITHER map (`local_*` or the table-scoped
        // `interface_nat_*`). A NAT-diverted address still delivers locally
        // via `interface_nat_local_resolution_on_session_miss` /
        // `flowless_local_resolution`, so it is the same host-inbound
        // exposure worth the empty-zone fail-closed sentinel installed after
        // this loop; counting only `local_*` left a diverted unzoned
        // interface with no sentinel while packets still reached it.
        let mut registered_local = false;
        for addr in &iface.addresses {
            if iface.admin_disabled {
                continue;
            }
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
                    // #12119: WG listener ownership is configured-address
                    // ownership, independent of the NAT local-delivery
                    // exclusion. Interface SNAT moves the primary WAN IP out
                    // of local_v4, but it remains the listener's owner zone.
                    let zone_id = state.zone_name_to_id.get(&iface.zone).copied().unwrap_or(0);
                    match state.wg_local_address_zone_v4.entry(v4.addr()) {
                        std::collections::hash_map::Entry::Vacant(entry) => {
                            entry.insert(zone_id);
                        }
                        std::collections::hash_map::Entry::Occupied(mut entry) => {
                            if *entry.get() != zone_id {
                                entry.insert(0);
                            }
                        }
                    }
                    if excluded_local_v4
                        .get(&connected_table_v4)
                        .is_some_and(|set| set.contains(&v4.addr()))
                    {
                        state
                            .interface_nat_v4
                            .entry(v4.addr())
                            .or_default()
                            .insert(connected_table_v4.clone(), iface.ifindex);
                        registered_local = true;
                        state
                            .interface_nat_tables_v4
                            .entry(v4.addr())
                            .or_default()
                            .insert(connected_table_v4.clone());
                    } else {
                        // #16208: paired insert via the ForwardingState
                        // method (local_v4 + owning table atomically);
                        // #3769: keyed by the HOST `.addr()`, NOT the
                        // (masked) connected prefix, so a non-/32 interface
                        // IP is recognised as locally-owned in its own VRF.
                        state.insert_local_iface_addr(
                            std::net::IpAddr::V4(v4.addr()),
                            connected_table_v4.clone(),
                        );
                        registered_local = true;
                    }
                    let prefix = PrefixV4::from_net(v4);
                    if prefix.prefix_len() < 31 {
                        let directed_broadcast = prefix.directed_broadcast();
                        state
                            .connected_v4_directed_broadcasts
                            .insert((iface.routing_domain, directed_broadcast));
                        state
                            .connected_v4_directed_broadcast_neighbor_keys
                            .insert((iface.ifindex, directed_broadcast));
                    }
                    state
                        .connected_v4_by_ifindex
                        .entry(iface.ifindex)
                        .or_default()
                        .push(prefix);
                    // #18517: a peer-owned row is withheld from transit
                    // (#15742) but recorded with its own table, so the FIB
                    // build can bind a bare gateway to it and to nothing else.
                    let row = ConnectedRouteV4 {
                        prefix,
                        host: v4.addr(),
                        ifindex: iface.ifindex,
                        tunnel_endpoint_id,
                        table: connected_table_v4.clone(),
                    };
                    if iface.connected_rg_peer_owned {
                        state.connected_v4_peer_owned.push(row);
                    } else {
                        state.connected_v4.push(row);
                    }
                }
                IpNet::V6(v6) => {
                    // #3182: NAT-decoupled full interface-IP set (see the V4
                    // arm above) — protects the SNAT/WAN IPv6 interface IP too.
                    state.configured_iface_v6.insert(v6.addr());
                    // #12119: WG listener ownership is configured-address
                    // ownership, independent of the NAT local-delivery
                    // exclusion (see the V4 arm).
                    let zone_id = state.zone_name_to_id.get(&iface.zone).copied().unwrap_or(0);
                    match state.wg_local_address_zone_v6.entry(v6.addr()) {
                        std::collections::hash_map::Entry::Vacant(entry) => {
                            entry.insert(zone_id);
                        }
                        std::collections::hash_map::Entry::Occupied(mut entry) => {
                            if *entry.get() != zone_id {
                                entry.insert(0);
                            }
                        }
                    }
                    if excluded_local_v6
                        .get(&connected_table_v6)
                        .is_some_and(|set| set.contains(&v6.addr()))
                    {
                        state
                            .interface_nat_v6
                            .entry(v6.addr())
                            .or_default()
                            .insert(connected_table_v6.clone(), iface.ifindex);
                        registered_local = true;
                        state
                            .interface_nat_tables_v6
                            .entry(v6.addr())
                            .or_default()
                            .insert(connected_table_v6.clone());
                    } else {
                        // #16208: paired insert via the ForwardingState
                        // method (see the v4 arm).
                        state.insert_local_iface_addr(
                            std::net::IpAddr::V6(v6.addr()),
                            connected_table_v6.clone(),
                        );
                        registered_local = true;
                    }
                    let prefix = PrefixV6::from_net(v6);
                    state
                        .connected_v6_by_ifindex
                        .entry(iface.ifindex)
                        .or_default()
                        .push(prefix);
                    // #18517: see the v4 arm.
                    let row = ConnectedRouteV6 {
                        prefix,
                        host: v6.addr(),
                        scope: addr.scope,
                        ifindex: iface.ifindex,
                        tunnel_endpoint_id,
                        table: connected_table_v6.clone(),
                    };
                    if iface.connected_rg_peer_owned {
                        state.connected_v6_peer_owned.push(row);
                    } else {
                        state.connected_v6.push(row);
                    }
                }
            }
        }
        if registered_local || iface.tunnel {
            host_inbound_exposure_ifindexes.insert(iface.ifindex);
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
        // `host_inbound_admits_iface_for_destination` (the local-delivery poll path's entry
        // point) DENIES host-bound services for a packet ingressing on it. The
        // global ICMP/ND/PMTUD accepts (`is_icmp_host_inbound_global_accept`,
        // checked BEFORE the set in `host_inbound_admits_iface_for_destination`) still deliver
        // control traffic. Keying by ifindex — NOT by inserting zone_host_inbound
        // at id 0 — deliberately leaves the genuinely-global zone_id 0 path
        // (`host_inbound_admits` with no matching ifindex override) untouched, so
        // a legitimately-zoneless NON-addressed control interface keeps its admit
        // default.
        //
        // Scope guards:
        //   - registered_local: only an interface that actually registered a
        //     local-delivery target (`local_*` or the table-scoped
        //     `interface_nat_*`, #14662) is a host-inbound exposure. An
        //     address-less interface is not.
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
        //   - !is_host_inbound_lifeline: the broad fxp*/em*/fab* and lo0
        //     predicate is the bind-exclusion/sentinel-SKIP mirror. Only the
        //     narrow names receive unconditional lifeline wording; prefix-only
        //     names and lo0 are zone-gated in diagnostics. For an unbound
        //     interface this skip is inert, but it keeps a future bind or
        //     quarantine path from arming a sentinel for an excluded name.
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
            if let std::collections::hash_map::Entry::Vacant(slot) =
                state.ifindex_host_inbound.entry(iface.ifindex)
            {
                empty_zone_host_inbound_sentinels.insert(iface.ifindex);
                slot.insert(crate::afxdp::types::ZoneHostInbound { ndp_excluded: true, ..Default::default() });
            }
        }
    }
    // An unzoned sibling row may have armed an empty-zone host-inbound
    // sentinel before another row on the same ifindex establishes a valid
    // zone. In that case host-bound traffic must use the retained zone's
    // admission policy, not the sibling row's deny-all sentinel.
    empty_zone_host_inbound_sentinels.retain(|ifindex| {
        if state.ifindex_to_zone_id.contains_key(ifindex) {
            state.ifindex_host_inbound.remove(ifindex);
            false
        } else {
            true
        }
    });

    // #16057/#16501: disputed unit host-inbound override fail-closed
    // backstop — SYMMETRY with #10503. Units on one ifindex carried
    // DIFFERENT effective signatures (configured overrides, or a
    // configured override versus an unconfigured unit's zone set); the
    // walk refused every one, so without
    // this entry the ifindex would fall back to its ZONE set (or, when
    // unzoned, the `None => true` global admit) — either way a sibling's
    // broader admission would govern the whole netdev, the exact leak the
    // issue reports. Insert the same EMPTY sentinel the contested-zone
    // backstop uses, so `host_inbound_admits_iface_for_destination` DENIES host-bound
    // services there in both row orders. The AF_XDP descriptor cannot
    // distinguish units on one netdev, so no narrower verdict exists.
    // Guards mirror #10503: never clobber an existing entry (defensive —
    // the walk refused every disputed write, and the empty-zone sentinel
    // bookkeeping is left untouched), never arm a lifeline, and warn once
    // per disputed ifindex per build so the deny is observable (#8296).
    let disputed_host_inbound_sentinels =
        install_disputed_host_inbound_sentinels(state, &disputed_host_inbound_ifindexes);
    for ifindex in &disputed_host_inbound_sentinels {
        eprintln!(
            "xpf-userspace-dp: WARNING host-inbound override contest on shared ifindex {}: \
             logical units on the same netdev carry different effective \
             host-inbound signatures (per-unit overrides, or an override versus an \
             unconfigured unit's zone set), so no unit's override is honoured and host-bound \
             services are DENIED by the per-ifindex empty host-inbound sentinel \
             (#16057/#16501; ICMP error/PMTUD control messages remain admitted, but ND \
             (ICMPv6 types 133-136) is denied with the sentinel, as on the #10503 \
             contested-zone sentinel). The dataplane sees an ifindex, not a unit, \
             so it cannot tell which unit a packet arrived on; give the units the \
             same host-inbound override, distinct netdevs, or rely on the \
             zone-level host-inbound set by removing the per-unit overrides.",
            ifindex
        );
    }

    // #10503: contested-ifindex host-inbound fail-closed backstop — SYMMETRY
    // with the #5659 addressed-empty-zone backstop above. Despite its historical
    // `contested_parent_ifindexes` name, the finalized #7509 set includes both
    // fan-UP parent conflicts and same-ifindex row conflicts: neither can be
    // attributed to one security zone. A trunk parent whose units span zones
    // has its `ifindex_to_zone_id` entry REMOVED (the #7509 contest arms), so
    // untagged ingress on it resolves to zone 0 and `host_inbound_admits(0)`
    // takes the `None => true` global admit arm — every host-bound service
    // admitted, then Trusted -> xpf-usp0 -> kernel ACCEPT ahead of every drop,
    // while the same ifindex's TRANSIT is denied via
    // `UNZONED_INGRESS_DENIED` (policy.rs). The per-row #5659 sentinel cannot
    // cover an ordinary address-less contest: its rows carry conflicting zones,
    // so `iface.zone.is_empty()` misses too. A refused all-zoned tunnel reaches
    // the #10556 refused-ifindex sentinel below; the contest set is only
    // complete after the walk, so it is closed here rather than per row.
    //
    // Fix: insert an EMPTY `ZoneHostInbound` sentinel keyed by each eligible
    // contested parent's ifindex, so the ingress-interface-keyed
    // `host_inbound_admits_iface_for_destination` DENIES host-bound services there. Keying by
    // ifindex — NOT by inserting at zone id 0 — leaves the genuinely-global
    // zone-0 path untouched, exactly as #5659 does. An existing entry
    // (explicit per-interface override) is never clobbered, and a lifeline name
    // is never armed. Refused-but-not-contested all-zoned tunnel Disagrees reach
    // `unit_refused_zones` below and receive the #10556 per-row sentinel; this
    // loop remains the existing contest backstop.
    for ifindex in &contested_parent_ifindexes {
        if state.ifindex_host_inbound.contains_key(ifindex) {
            continue;
        }
        if let Some(name) = state.ifindex_to_config_name.get(ifindex) {
            if is_host_inbound_lifeline(name) {
                continue;
            }
        }
        if let std::collections::hash_map::Entry::Vacant(slot) =
            state.ifindex_host_inbound.entry(*ifindex)
        {
            contested_host_inbound_sentinels.insert(*ifindex);
            slot.insert(crate::afxdp::types::ZoneHostInbound { ndp_excluded: true, ..Default::default() });
        }
    }

    // #10556: refused-but-not-contested host-inbound fail-closed backstop —
    // SYMMETRY with #10503. `unit_refused_zones` ifindexes are unzoned by
    // refusal (not contest), miss #5659 split across two rows (the zoned base
    // row fails `zone.is_empty()`, the unzoned unit row fails
    // `registered_local || tunnel`), and miss #10503 (not in the contested
    // set) → zone-0 None=>true admit. Same per-ifindex empty sentinel, with
    // retained-zone and exposure guards plus the override/lifeline guards.
    // No `ifindex_to_zone_id` entry: the ifindex stays unzoned and transit
    // stays UNZONED_INGRESS_DENIED.
    for ifindex in unit_refused_zones.keys() {
        if state.ifindex_to_zone_id.contains_key(ifindex) {
            // The final ifindex retained a valid zone; host-bound traffic must
            // remain governed by that zone's admission set.
            continue;
        }
        if !host_inbound_exposure_ifindexes.contains(ifindex) {
            // Mirror #5659: an address-less, non-tunnel refusal has no
            // local-delivery exposure to protect.
            continue;
        }
        if contested_parent_ifindexes.contains(ifindex) {
            // Already armed by #10503 above.
            continue;
        }
        if state.ifindex_host_inbound.contains_key(ifindex) {
            continue;
        }
        if let Some(name) = state.ifindex_to_config_name.get(ifindex) {
            if is_host_inbound_lifeline(name) {
                continue;
            }
        }
        empty_zone_host_inbound_sentinels.insert(*ifindex);
        state.ifindex_host_inbound.entry(*ifindex).or_insert_with(|| crate::afxdp::types::ZoneHostInbound { ndp_excluded: true, ..Default::default() });
    }

    // #10644: unzoned trunk-unit host-inbound fail-closed backstop — SYMMETRY
    // with #10556. Two unzoned address-less unit shapes survive every earlier
    // arm and resolve to zone 0 with no per-ifindex entry, so
    // `host_inbound_admits_iface_for_destination` falls back to `host_inbound_admits(0)` and
    // the `None => true` global admit arm admits every host-bound service:
    //
    //   (a) a refused-not-contested trunk parent: native unit 0 collapsed on
    //   the parent netdev refuses the fan-UP zone of a sibling on its own
    //   netdev (`unit_refused_zones`, #7509 arm), the parent stays unzoned,
    //   and the #10556 exposure guard skips the sentinel for lack of
    //   address/tunnel. Reachable because the sibling keeps the parent netdev
    //   bound (always on RETH trunks).
    //   (b) a configured-but-unzoned tagged child unit: its own ifindex, a
    //   logical-map hit, no refusal (its row is empty-zoned), no contest, no
    //   address/tunnel exposure, no advisory. Reachable on RETH trunks, and
    //   on non-RETH trunks after the ordinary "remove a VLAN from its zone"
    //   workflow, via tagged frames on the still-bound parent.
    //
    // Fix: the same per-ifindex EMPTY `ZoneHostInbound` sentinel #5659/#10503/
    // #10556 install, with the same guards — final-unzoned only (a retained
    // zone stays zone-gated), never clobber an existing entry (an explicit
    // per-interface override or an earlier sentinel), never arm a lifeline,
    // contested ifindexes stay with #10503. Shape (a) additionally requires
    // the refused ifindex to be a trunk parent (a unit row names it as its
    // parent): a collapsed same-ifindex refusal with no sibling (the #10520
    // address-less pin) shares no netdev with a live unit, is bind-gated
    // dark, and keeps the global admit default. Keying by ifindex leaves the
    // genuinely-global zone-0 path untouched, exactly as #5659 does; transit
    // stays UNZONED_INGRESS_DENIED (#6682). Shape (a) is reported through the
    // shared `empty_zone_host_inbound_sentinels` set, so the refused warning
    // below flips its host-bound sentence from global-admit to sentinel-deny.
    for ifindex in unit_refused_zones.keys() {
        if state.ifindex_to_zone_id.contains_key(ifindex) {
            // The final ifindex retained a valid zone; host-bound traffic must
            // remain governed by that zone's admission set.
            continue;
        }
        if !trunk_parent_ifindexes.contains(ifindex) {
            // Not a trunk parent: a collapsed same-ifindex refusal with no
            // sibling unit (the #10520 address-less shape) is bind-gated
            // dark, so the global admit default stays inert there.
            continue;
        }
        if contested_parent_ifindexes.contains(ifindex) {
            // Already armed by #10503 above.
            continue;
        }
        if state.ifindex_host_inbound.contains_key(ifindex) {
            // Already armed by #5659/#10556 above, or carries an explicit
            // per-interface override — never clobber.
            continue;
        }
        if let Some(name) = state.ifindex_to_config_name.get(ifindex) {
            if is_host_inbound_lifeline(name) {
                continue;
            }
        }
        empty_zone_host_inbound_sentinels.insert(*ifindex);
        state.ifindex_host_inbound.entry(*ifindex).or_insert_with(|| crate::afxdp::types::ZoneHostInbound { ndp_excluded: true, ..Default::default() });
    }
    for ifindex in &unzoned_child_unit_ifindexes {
        if state.ifindex_to_zone_id.contains_key(ifindex) {
            // Zonally attributed after all; host-bound traffic must remain
            // governed by that zone's admission set.
            continue;
        }
        if contested_parent_ifindexes.contains(ifindex) {
            // Already armed by #10503 above.
            continue;
        }
        if state.ifindex_host_inbound.contains_key(ifindex) {
            // Already armed by #5659 above, or carries an explicit
            // per-interface override — never clobber.
            continue;
        }
        if let Some(name) = state.ifindex_to_config_name.get(ifindex) {
            if is_host_inbound_lifeline(name) {
                continue;
            }
        }
        empty_zone_host_inbound_sentinels.insert(*ifindex);
        state.ifindex_host_inbound.entry(*ifindex).or_insert_with(|| crate::afxdp::types::ZoneHostInbound { ndp_excluded: true, ..Default::default() });
    }

    // #16061: the config-name refusal must be OBSERVABLE for the same reason
    // the #7509 zone contest below is (#8296): without a line, a NAT rule
    // scoped `from interface <unit>` on a shared ifindex silently stops
    // matching with no error anywhere on the box. One line per contested
    // ifindex per build, naming every unit that claimed it.
    for ifindex in &contested_config_name_ifindexes {
        let names: Vec<&str> = snapshot
            .interfaces
            .iter()
            .filter(|row| {
                row.ifindex == *ifindex && is_logical_unit_row(&row.name, row.is_unit)
            })
            .map(|row| row.name.as_str())
            .collect();
        eprintln!(
            "xpf-userspace-dp: WARNING config-name contest on shared ifindex {}: \
             logical units [{}] share one netdev, so the ifindex carries NO \
             interface name (#16061). NAT rules scoped `from interface` / \
             `to interface` to any of these units do not match traffic on this \
             ifindex; the dataplane sees an ifindex, not a unit, so it cannot \
             tell which unit a packet arrived on. Give the units distinct \
             netdevs or scope the NAT rules by zone / routing-instance instead.",
            ifindex,
            names.join(", ")
        );
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
        let empty_zone_sentinel = empty_zone_host_inbound_sentinels.contains(ifindex);
        let contested_sentinel = contested_host_inbound_sentinels.contains(ifindex);
        let host_override = state.ifindex_host_inbound.contains_key(ifindex)
            && !empty_zone_sentinel
            && !contested_sentinel;
        let host_bound = contested_host_bound_warning_10520(
            empty_zone_sentinel,
            contested_sentinel,
            host_override,
            state
                .ifindex_to_config_name
                .get(ifindex)
                .map(String::as_str),
        );
        eprintln!(
            "xpf-userspace-dp: WARNING zone contest on shared base ifindex {}: units \
             claim zone ids [{}] — the ingress zone is UNSET for it (#7509). Transit \
             arriving there is DENIED as unattributed before any policy is consulted \
             (#6682); default-policy permit-all does not admit it, and the deny logs \
             as unattributed (#9989, counter UNZONED_INGRESS_DENIED). {host_bound} \
             The dataplane sees an ifindex, not a unit, so it cannot tell which unit \
             a packet arrived on; give the units distinct netdevs or put them in one \
             zone.",
            ifindex,
            ids.join(", ")
        );
    }

    // #7509 (zoned-vs-UNZONED): same observability requirement, different
    // refusal. Here the rows do not disagree with each other — a BASE row
    // carries a zone it INHERITED from a unit on another ifindex, and the unit
    // row that actually receives frames on this ifindex names a different zone
    // or none at all. One line per ifindex per build, naming the zone ids the
    // unit rows refused. A FULL refusal leaves no ingress-zone entry and takes
    // the #6682 unattributed deny; a retained zone is policy-evaluated instead.
    // Host-bound selection follows built state: a retained zone is zone-gated,
    // an installed #5659/#10556/#10644 sentinel denies host-bound services
    // with control carve-outs, and a full refusal without that sentinel
    // remains on the global admit path unless the config name identifies a
    // narrow lifeline;
    // broad prefix-only/lo0 names remain zone-gated in the warning text.
    // The commit-time advisory
    // (`pkg/config/contested_trunk_zone_advisory_7509.go`) is the one that can
    // name the INTERFACE; this one is the runtime corroboration.
    for (ifindex, zones) in &unit_refused_zones {
        if contested_parent_zones.contains_key(ifindex) {
            // Already reported above as a contest; do not say it twice.
            continue;
        }
        let ids: Vec<String> = zones.iter().map(|z| z.to_string()).collect();
        let retained_zone = state.ifindex_to_zone_id.contains_key(ifindex);
        let host_sentinel = empty_zone_host_inbound_sentinels.contains(ifindex);
        let host_override = state.ifindex_host_inbound.contains_key(ifindex) && !host_sentinel;
        let config_name = state
            .ifindex_to_config_name
            .get(ifindex)
            .map(String::as_str);
        let host_bound = unit_refused_host_bound_warning_10520(
            retained_zone,
            host_sentinel,
            host_override,
            config_name,
        );
        let transit = unit_refused_transit_warning_10520(retained_zone);
        if unit_refused_rows_are_all_zoned_10520(
            unit_claims.get(ifindex),
            unit_empty_zone_ifindexes.contains(ifindex),
        ) {
            eprintln!(
                "xpf-userspace-dp: WARNING ifindex {} carries logical-unit rows \
                 whose zone ids disagree [{}]: the same device represents multiple \
                 unit identities, so the ingress zone is refused (#7509). {transit} \
                 {host_bound} Put the units in one zone or give them distinct \
                 netdevs if they must be forwarded independently.",
                ifindex,
                ids.join(", ")
            );
        } else {
            eprintln!(
                "xpf-userspace-dp: WARNING ifindex {} carries a logical unit the \
                 operator left out of zone ids [{}]: that unit is what receives \
                 frames on the device, so the zone its base interface INHERITED \
                 from a sibling unit is refused (#7509). {transit} {host_bound} \
                 Zone the unit explicitly if it must forward.",
                ifindex,
                ids.join(", ")
            );
        }
    }

    flush_egress_zone_claims(state, egress_zone_claim, &zones_carried);

    // #7160 (#2387): zone -> routing DOMAIN, for fabric-ingress packets where
    // the peer's encoded zone is the only ingress identity available. A zone
    // is recorded only when its real member interfaces agree on one domain.
    //
    // `ifindex_to_zone_id` also carries zoned trunk-parent aliases propagated
    // from VLAN children. When a parent has no routing-domain entry of its own,
    // attribute that alias to its child contributors instead of inventing a
    // default-domain member; the child rows are independently walked below.
    if state.has_routing_domains {
        let mut parent_zone_domains: FastMap<(i32, u32), FastSet<u32>> = FastMap::default();
        for iface in &snapshot.interfaces {
            if iface.parent_ifindex <= 0 || iface.zone.is_empty() {
                continue;
            }
            let Some(zone_id) = state.zone_name_to_id.get(&iface.zone).copied() else {
                continue;
            };
            if zone_id != 0 {
                parent_zone_domains
                    .entry((iface.parent_ifindex, zone_id))
                    .or_default()
                    .insert(iface.routing_domain);
            }
        }

        let mut ambiguous: FastSet<u32> = FastSet::default();
        for (ifindex, zone_id) in state.ifindex_to_zone_id.iter() {
            if *zone_id == 0 {
                continue;
            }
            let parent_domain = parent_zone_domains
                .get(&(*ifindex, *zone_id))
                .filter(|domains| domains.len() == 1)
                .and_then(|domains| domains.iter().next())
                .copied();
            let domain = state
                .ifindex_to_routing_domain
                .get(ifindex)
                .copied()
                .or(parent_domain)
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
        state.ambiguous_fabric_zone_ids = ambiguous.clone();
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

fn ensure_shared_ifindex_value<T: PartialEq + std::fmt::Debug>(
    ifindex: i32,
    interface: &str,
    attribute: &'static str,
    first: &T,
    second: &T,
) -> Result<(), crate::policy::SnapshotIntegrityError> {
    if first == second {
        return Ok(());
    }
    Err(
        crate::policy::SnapshotIntegrityError::InterfaceSharedIfindexAttributeConflict {
            ifindex,
            attribute,
            first_value: format!("{first:?}"),
            second_value: format!("{second:?}"),
            interface: interface.to_string(),
        },
    )
}

pub(super) fn populate_egress(
    snapshot: &ConfigSnapshot,
    state: &mut ForwardingState,
    iface_ctx: &IfaceIndex,
) -> Result<(), crate::policy::SnapshotIntegrityError> {
    let mut tagged_only_ingress_ifindexes = FastSet::default();
    let mut untagged_unit_ifindexes = FastSet::default();
    let mut row_zone_by_ifindex = BTreeMap::<i32, Option<u32>>::new();
    for iface in &snapshot.interfaces {
        if iface.ifindex <= 0 {
            continue;
        }
        let zone_id = state
            .zone_name_to_id
            .get(&iface.zone)
            .copied()
            .filter(|zone_id| *zone_id != 0);
        match row_zone_by_ifindex.entry(iface.ifindex) {
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(zone_id);
            }
            std::collections::btree_map::Entry::Occupied(mut entry) if *entry.get() != zone_id => {
                entry.insert(None);
            }
            std::collections::btree_map::Entry::Occupied(_) => {}
        }
    }
    let consistent_zoned_ifindexes: BTreeSet<i32> = row_zone_by_ifindex
        .into_iter()
        .filter_map(|(ifindex, zone_id)| {
            let zone_id = zone_id?;
            (state.ifindex_unambiguous_zone_id.get(&ifindex) == Some(&zone_id)).then_some(ifindex)
        })
        .collect();

    // #11434: preserve the base interface's native VLAN selection so VID 0
    // can resolve to the matching logical unit instead of inheriting unit 0's
    // or the parent's zone.
    let mut native_vlan_by_parent = BTreeMap::<i32, u16>::new();
    let mut ambiguous_native_parents = BTreeSet::<i32>::new();
    let mut parent_bound_ingress_owners = BTreeMap::<(i32, u16), (i32, &str)>::new();
    for iface in &snapshot.interfaces {
        if iface.ifindex <= 0 || is_logical_unit_row(&iface.name, iface.is_unit) {
            continue;
        }
        // #17206: decode native VLAN through RowIds (the single
        // VlanId decoder) — the inline 4094 cap is deleted; 4095 is
        // wire-representable and now follows the same verdict as
        // vlan_id, while >4095 fails closed via the decoder.
        let row = super::validated::RowIds::try_from_row(iface)?;
        let Some(native_vlan) = row.native_vlan else {
            continue;
        };
        let native_vlan_id = native_vlan.get();
        if let Some(previous) = native_vlan_by_parent.insert(iface.ifindex, native_vlan_id) {
            if previous != native_vlan_id {
                ambiguous_native_parents.insert(iface.ifindex);
            }
        }
    }

    for iface in &snapshot.interfaces {
        if iface.ifindex <= 0 {
            continue;
        }
        let bind_ifindex = if iface.parent_ifindex > 0 {
            iface.parent_ifindex
        } else {
            iface.ifindex
        };
        // #2410/#17206: validate the VLAN id ONCE here via RowIds
        // instead of narrowing it with an unchecked
        // `iface.vlan_id.max(0) as u16` at both the ingress-key
        // and the EgressInterface.vlan_id site. An out-of-range value
        // fails the snapshot closed rather than wrapping to a
        // different VLAN (a different L2 domain).
        let vlan_id = super::validated::RowIds::try_from_row(iface)?.vlan.get();
        if iface.parent_ifindex > 0 && vlan_id > 0 {
            // Generic XDP on a VLAN child runs after Linux strips the wire
            // tag. VID 0 there is the child's configured VLAN, not untagged
            // parent ingress, so only the bind parent is tagged-only.
            tagged_only_ingress_ifindexes.insert(bind_ifindex);
        }
        // The base interface row is not a logical untagged identity. Unit 0
        // without a VLAN id is explicit and keeps its existing VID-0 fallback.
        // Old Go and fixture snapshots may omit `is_unit`; use the shared
        // structural/fallback detector, then parse the terminal unit number
        // once for both the unit-0 fallback and the nonzero-unit skip below.
        let logical_unit_number = if is_logical_unit_row(&iface.name, iface.is_unit) {
            iface
                .name
                .rsplit_once('.')
                .and_then(|(_, unit)| unit.parse::<u32>().ok())
        } else {
            None
        };
        // #14334: a disabled or unzoned unit 0 owns no VID-0 identity and
        // must not clear tagged-only. Legacy rows (`is_unit: None`) carry
        // no zone/admin metadata to judge, so preserve #11297 ownership.
        let legacy_row = iface.is_unit.is_none();
        if logical_unit_number == Some(0)
            && vlan_id == 0
            && (legacy_row || (!iface.admin_disabled && !iface.zone.is_empty()))
        {
            untagged_unit_ifindexes.insert(bind_ifindex);
        }

        // #2706: validate the MTU ONCE here instead of narrowing it with an
        // unchecked `iface.mtu.max(0) as usize`. A NEGATIVE value fails the
        // snapshot closed rather than collapsing to 0 — which the egress MTU
        // guard treats as "unknown; forward", silently disabling PTB/drop
        // enforcement. 0 (the legitimate "unknown MTU" sentinel) stays
        // permissive.
        let mtu = super::validated::InterfaceMtu::try_from_snapshot(iface.mtu, &iface.name)?.get();
        let ingress_key = (bind_ifindex, vlan_id);
        // An untagged nonzero logical unit does not own the parent's VID-0
        // ingress key. A MAC-less tunnel unit can carry `parent_ifindex`
        // for its base while receiving traffic on a distinct ifindex;
        // mapping the parent key to that sibling would reject a valid
        // snapshot and misidentify untagged traffic on the base.
        let untagged_nonzero_unit =
            vlan_id == 0 && logical_unit_number.is_some_and(|unit| unit != 0);
        if iface.parent_ifindex > 0 {
            if !untagged_nonzero_unit {
                if let Some((first_ifindex, first_interface)) =
                    parent_bound_ingress_owners.get(&ingress_key)
                {
                    if *first_ifindex != iface.ifindex {
                        return Err(
                            crate::policy::SnapshotIntegrityError::InterfaceDuplicateIngressKey {
                                bind_ifindex,
                                vlan_id,
                                first_ifindex: *first_ifindex,
                                second_ifindex: iface.ifindex,
                                first_interface: (*first_interface).to_string(),
                                second_interface: iface.name.clone(),
                            },
                        );
                    }
                } else {
                    parent_bound_ingress_owners
                        .insert(ingress_key, (iface.ifindex, iface.name.as_str()));
                }
                // Parent-bound units with a real VID own the parent/VLAN key;
                // unit 0 owns the untagged key. Keep rejecting distinct
                // logical ifindexes that collide on either identity.
                // Parent-bound rows use `insert` so they take precedence
                // over a base-interface row, while the base row below uses
                // `or_insert` so the intentional base-row fallback remains
                // intact when no parent-bound unit claims the key.
                state
                    .ingress_logical_ifindex
                    .insert(ingress_key, iface.ifindex);
            }
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
        // #921: resolve zone name → u32 at build time.
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
        let primary_v4 = pick_interface_v4(iface);
        let primary_v6 = pick_interface_v6(iface);
        // #16513: was this row's pick the operator's DESIGNATED primary
        // (a marked address on the row), as opposed to the fallback
        // first-in-order pick? The helpers re-scan for the marked
        // address so the merge below can tell a designation (which must
        // win the shared-ifindex merge) from an order-based pick (which
        // must not veto a designation on a sibling row). Two different
        // designated picks on one ifindex are a genuine config conflict
        // and keep the #13181 fail-closed gate.
        let designated_v4 = designated_interface_v4(iface);
        let designated_v6 = designated_interface_v6(iface);
        if let Some(existing) = state.egress.get_mut(&iface.ifindex) {
            if existing.redundancy_group != 0
                && iface.redundancy_group != 0
                && existing.redundancy_group != iface.redundancy_group
            {
                return Err(
                    crate::policy::SnapshotIntegrityError::InterfaceSharedIfindexRedundancyGroup {
                        ifindex: iface.ifindex,
                        first_group: existing.redundancy_group,
                        second_group: iface.redundancy_group,
                        interface: iface.name.clone(),
                    },
                );
            }
            if consistent_zoned_ifindexes.contains(&iface.ifindex) {
                ensure_shared_ifindex_value(
                    iface.ifindex,
                    &iface.name,
                    "bind_ifindex",
                    &existing.bind_ifindex,
                    &bind_ifindex,
                )?;
                ensure_shared_ifindex_value(
                    iface.ifindex,
                    &iface.name,
                    "vlan_id",
                    &existing.vlan_id,
                    &vlan_id,
                )?;
            }
            if existing.mtu != 0 && mtu != 0 {
                if consistent_zoned_ifindexes.contains(&iface.ifindex) {
                    ensure_shared_ifindex_value(
                        iface.ifindex,
                        &iface.name,
                        "mtu",
                        &existing.mtu,
                        &mtu,
                    )?;
                }
            } else if existing.mtu == 0 {
                existing.mtu = mtu;
            }
            if existing.src_mac != [0; 6] && src_mac != [0; 6] {
                if existing.src_mac != src_mac {
                    if consistent_zoned_ifindexes.contains(&iface.ifindex) {
                        return Err(
                            crate::policy::SnapshotIntegrityError::InterfaceSharedIfindexAttributeConflict {
                                ifindex: iface.ifindex,
                                attribute: "src_mac",
                                first_value: format!("{:02x?}", existing.src_mac),
                                second_value: format!("{:02x?}", src_mac),
                                interface: iface.name.clone(),
                            },
                        );
                    }
                    existing.src_mac = src_mac;
                }
            } else if existing.src_mac == [0; 6] {
                existing.src_mac = src_mac;
            }
            // #16513: a DESIGNATED primary wins the shared-ifindex
            // merge. The Go builder marks the designation only on the
            // unit row; the base row it collapses onto (same ifindex,
            // kernel addresses, unmarked) picks by order, so comparing
            // per-row picks as #13181 did refused every snapshot whose
            // designated address was not the string-first one, and on
            // non-consistently-zoned shapes the first-row-wins merge
            // silently dropped the designation. Now: a designated pick
            // replaces an undesignated incumbent and beats a later
            // undesignated row; only two DIFFERENT designated picks on
            // one non-tunnel ifindex are a genuine conflict and keep
            // the fail-closed gate. Tunnel rows keep the #13181
            // exemption (they legitimately carry different primaries).
            let incumbent_v4_designated =
                state.egress_primary_v4_designated.contains(&iface.ifindex);
            let incumbent_v6_designated =
                state.egress_primary_v6_designated.contains(&iface.ifindex);
            if consistent_zoned_ifindexes.contains(&iface.ifindex) && !iface.tunnel {
                if let (Some(first), Some(second)) = (existing.primary_v4, designated_v4) {
                    if incumbent_v4_designated {
                        ensure_shared_ifindex_value(
                            iface.ifindex,
                            &iface.name,
                            "primary_v4",
                            &first,
                            &second,
                        )?;
                    }
                }
                if let (Some(first), Some(second)) = (existing.primary_v6, designated_v6) {
                    if incumbent_v6_designated {
                        ensure_shared_ifindex_value(
                            iface.ifindex,
                            &iface.name,
                            "primary_v6",
                            &first,
                            &second,
                        )?;
                    }
                }
            }
            // Merge: designated wins over undesignated; otherwise the
            // first available family address is kept and a row without
            // a family cannot erase it.
            match (designated_v4, primary_v4) {
                (Some(d), _) => {
                    existing.primary_v4 = Some(d);
                    state.egress_primary_v4_designated.insert(iface.ifindex);
                }
                (None, Some(p)) if !incumbent_v4_designated => {
                    existing.primary_v4 = existing.primary_v4.or(Some(p));
                }
                _ => {}
            }
            match (designated_v6, primary_v6) {
                (Some(d), _) => {
                    existing.primary_v6 = Some(d);
                    state.egress_primary_v6_designated.insert(iface.ifindex);
                }
                (None, Some(p)) if !incumbent_v6_designated => {
                    existing.primary_v6 = existing.primary_v6.or(Some(p));
                }
                _ => {}
            }
            if existing.redundancy_group == 0 {
                existing.redundancy_group = iface.redundancy_group;
            }
            existing.zone_id = zone_id;
            continue;
        }
        state.egress.insert(
            iface.ifindex,
            EgressInterface {
                bind_ifindex,
                vlan_id,
                mtu,
                src_mac,
                zone_id,
                redundancy_group: iface.redundancy_group,
                primary_v4,
                primary_v6,
            },
        );
        // #16513: seed the designated-incumbent flags for the first
        // row so a later row's designation/conflict is judged against
        // the right incumbent kind.
        if designated_v4.is_some() {
            state.egress_primary_v4_designated.insert(iface.ifindex);
        }
        if designated_v6.is_some() {
            state.egress_primary_v6_designated.insert(iface.ifindex);
        }
    }
    // Resolve each configured native VLAN only when exactly one logical unit
    // on that parent has the selected VID. A missing or conflicting unit must
    // not fall back to the parent's / unit-0 identity: leave VID 0 rejected.
    let mut native_unit_by_parent = BTreeMap::<i32, i32>::new();
    for iface in &snapshot.interfaces {
        // #14334: only a zoned, enabled native unit owns VID 0; legacy
        // rows (`is_unit: None`) have no metadata to judge (#11297).
        if iface.ifindex <= 0
            || iface.parent_ifindex <= 0
            || !is_logical_unit_row(&iface.name, iface.is_unit)
            || (iface.is_unit.is_some() && (iface.admin_disabled || iface.zone.is_empty()))
        {
            continue;
        }
        let Some(native_vlan_id) = native_vlan_by_parent.get(&iface.parent_ifindex) else {
            continue;
        };
        let vlan_id = super::validated::RowIds::try_from_row(iface)?.vlan.get();
        if vlan_id != *native_vlan_id {
            continue;
        }
        if let Some(previous) = native_unit_by_parent.insert(iface.parent_ifindex, iface.ifindex) {
            if previous != iface.ifindex {
                ambiguous_native_parents.insert(iface.parent_ifindex);
            }
        }
    }

    let mut native_vlan_without_unit = BTreeSet::new();
    for (&parent_ifindex, _) in &native_vlan_by_parent {
        if ambiguous_native_parents.contains(&parent_ifindex) {
            state.ingress_logical_ifindex.remove(&(parent_ifindex, 0));
            native_vlan_without_unit.insert(parent_ifindex);
            continue;
        }
        match native_unit_by_parent.get(&parent_ifindex).copied() {
            Some(native_unit_ifindex) => {
                state
                    .ingress_logical_ifindex
                    .insert((parent_ifindex, 0), native_unit_ifindex);
                state
                    .native_vlan_egress_ifindexes
                    .insert(native_unit_ifindex);
                tagged_only_ingress_ifindexes.remove(&parent_ifindex);
            }
            None => {
                state.ingress_logical_ifindex.remove(&(parent_ifindex, 0));
                native_vlan_without_unit.insert(parent_ifindex);
            }
        }
    }
    // #14334: VID-0 keys whose only owner is a disabled/unzoned unit 0 or
    // native unit must not resolve; unknown_ingress_vlan drops them at the
    // poll head, and removing the stale key keeps downstream resolvers from
    // observing the non-owner. Valid owners re-inserted theirs above
    // (native) or via the main loop (unit 0); native-without-unit already
    // removed its key in the loop above.
    for iface in &snapshot.interfaces {
        if iface.is_unit.is_some() && (iface.admin_disabled || iface.zone.is_empty()) {
            // #17206: prune comparisons use the decoded VlanId, not raw.
            let row_vlan = super::validated::RowIds::try_from_row(iface)?.vlan.get();
            let is_unit0 = is_logical_unit_row(&iface.name, iface.is_unit)
                && iface
                    .name
                    .rsplit_once('.')
                    .and_then(|(_, unit)| unit.parse::<u32>().ok())
                    == Some(0);
            let bind_ifindex = if iface.parent_ifindex > 0 {
                iface.parent_ifindex
            } else {
                iface.ifindex
            };
            // Scope: only a parent that a tagged unit nominated (tagged-only
            // candidate) can lose its VID-0 key here; an ordinary untagged
            // port's unit 0 (e.g. st0.0, #12250) is not in this builder's
            // tagged-only scope and its key is left to the general logic.
            if is_unit0
                && row_vlan == 0
                && bind_ifindex > 0
                && tagged_only_ingress_ifindexes.contains(&bind_ifindex)
            {
                // Only prune when this excluded row is the recorded owner;
                // a surviving zoned/enabled owner on the same key stays.
                if state.ingress_logical_ifindex.get(&(bind_ifindex, 0)) == Some(&iface.ifindex) {
                    let has_surviving_owner = snapshot.interfaces.iter().any(|other| {
                        !other.admin_disabled
                            && !other.zone.is_empty()
                            && other.ifindex == iface.ifindex
                            && is_logical_unit_row(&other.name, other.is_unit)
                    });
                    if !has_surviving_owner {
                        state.ingress_logical_ifindex.remove(&(bind_ifindex, 0));
                    }
                }
            }
            // Native: if this excluded unit was the native VID for its
            // parent, ensure no (parent,0) key points at it.
            if iface.parent_ifindex > 0
                && tagged_only_ingress_ifindexes.contains(&iface.parent_ifindex)
                && row_vlan > 0
                && native_vlan_by_parent.get(&iface.parent_ifindex).copied() == Some(row_vlan)
            {
                if state
                    .ingress_logical_ifindex
                    .get(&(iface.parent_ifindex, 0))
                    == Some(&iface.ifindex)
                {
                    state
                        .ingress_logical_ifindex
                        .remove(&(iface.parent_ifindex, 0));
                }
                state.native_vlan_egress_ifindexes.remove(&iface.ifindex);
            }
        }
    }
    tagged_only_ingress_ifindexes.retain(|ifindex| !untagged_unit_ifindexes.contains(ifindex));
    tagged_only_ingress_ifindexes.extend(native_vlan_without_unit);
    state.tagged_only_ingress_ifindexes = tagged_only_ingress_ifindexes;
    Ok(())
}

/// #6458/#13181: build `state.zone_to_rgs` from admitted interface rows,
/// not ingress `ifindex_to_zone_id`, which also contains inherited parent
/// aliases. Shared-ifindex logical units each contribute their own RG.
///
/// #15742f: a blank NON-UNIT row must not veto by itself — the physical
/// member row (`ge-0/0/1`, zone="", is_unit=false) sharing a RETH's
/// netdev is legitimately unzoned (the Go zone map fans a bare RETH
/// reference DOWN to its unit, never UP to the member), yet
/// `reth1`/`reth1.0` carry the zone on the same ifindex. Treating the
/// blank as a conflicting claim zeroed every RETH zone's RG
/// attribution live, so `zone_encoded_fabric_stamp_valid` rejected
/// every fabric punt as Invalid and split-RG transit blackholed at
/// receiver. The veto therefore applies only to a blank row that
/// aliases a unit on the same ifindex (its name is that unit's base,
/// e.g. `st0` beside `st0.0` — the #13181 unzoned-alias shape), while
/// the RETH member (no unit bears its name) does not vote.
/// claim, and the second pass's `ifindex_unambiguous_zone_id` gate
/// (built from the Go-stamped `egress_zone`, which the member row
/// shares) remains the authority.
pub(super) fn populate_zone_to_rgs(snapshot: &ConfigSnapshot, state: &mut ForwardingState) {
    let mut row_zone_by_ifindex = BTreeMap::<i32, Option<u32>>::new();
    for iface in &snapshot.interfaces {
        if iface.ifindex <= 0 {
            continue;
        }
        // #15742f: blank rows veto only when they alias a zoned unit on
        // this ifindex (name is that unit's base, e.g. `st0` beside
        // `st0.0`); a blank physical member (`ge-0/0/1` beside
        // `reth1.0`) does not vote. A resolved zone claims directly.
        let zone_id = if iface.zone.is_empty() {
            let aliases_unit = snapshot.interfaces.iter().any(|unit| {
                unit.ifindex == iface.ifindex
                    && is_logical_unit_row(&unit.name, unit.is_unit)
                    && unit
                        .name
                        .strip_prefix(iface.name.as_str())
                        .is_some_and(|rest| rest.starts_with('.'))
            });
            if aliases_unit {
                None
            } else {
                continue;
            }
        } else {
            state
                .zone_name_to_id
                .get(&iface.zone)
                .copied()
                .filter(|zone_id| *zone_id != 0)
        };
        match row_zone_by_ifindex.entry(iface.ifindex) {
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(zone_id);
            }
            std::collections::btree_map::Entry::Occupied(mut entry) if *entry.get() != zone_id => {
                entry.insert(None);
            }
            std::collections::btree_map::Entry::Occupied(_) => {}
        }
    }

    for iface in &snapshot.interfaces {
        if iface.ifindex <= 0 {
            continue;
        }
        let Some(zone_id) = state.zone_name_to_id.get(&iface.zone).copied() else {
            continue;
        };
        if zone_id == 0
            || row_zone_by_ifindex.get(&iface.ifindex) != Some(&Some(zone_id))
            || state.ifindex_unambiguous_zone_id.get(&iface.ifindex) != Some(&zone_id)
        {
            continue;
        }
        let rg = iface.redundancy_group;
        if rg <= 0 {
            continue;
        }
        let rgs = state.zone_to_rgs.entry(zone_id).or_default();
        if !rgs.contains(&rg) {
            rgs.push(rg);
        }
    }
}

/// #11337: build peer-stable NAT scope ids from configured identity, never
/// Linux ifindex. If a 24-bit hash collides, both identities are omitted so a
/// fabric packet can never be scoped to the wrong interface or routing instance.
pub(super) fn populate_fabric_nat_scope_ids(state: &mut ForwardingState) {
    let mut scope_by_id: BTreeMap<u32, (u32, String, String, i32, i32)> = BTreeMap::new();
    let mut ambiguous = BTreeSet::new();

    for (ifindex, zone_id) in &state.ifindex_to_zone_id {
        if *zone_id == 0 {
            continue;
        }
        let ifname = state
            .ifindex_to_config_name
            .get(ifindex)
            .map(String::as_str)
            .unwrap_or("");
        let routing_instance = state
            .ifindex_to_routing_instance
            .get(ifindex)
            .map(String::as_str)
            .unwrap_or("");
        let redundancy_group = state
            .egress
            .get(ifindex)
            .map_or(0, |egress| egress.redundancy_group);
        let id =
            super::super::forwarding::fabric_nat_scope_stamp_id(*zone_id, ifname, routing_instance);

        match scope_by_id.get_mut(&id) {
            Some((old_zone, old_ifname, old_ri, old_ifindex, old_rg)) => {
                if *old_zone != *zone_id
                    || old_ifname != ifname
                    || old_ri != routing_instance
                    || *old_rg != redundancy_group
                {
                    ambiguous.insert(id);
                } else {
                    *old_ifindex = (*old_ifindex).min(*ifindex);
                }
            }
            None => {
                scope_by_id.insert(
                    id,
                    (
                        *zone_id,
                        ifname.to_string(),
                        routing_instance.to_string(),
                        *ifindex,
                        redundancy_group,
                    ),
                );
            }
        }
    }

    state.ifindex_to_fabric_nat_scope_id.clear();
    state.fabric_nat_scope_id_to_identity.clear();
    for (ifindex, zone_id) in &state.ifindex_to_zone_id {
        if *zone_id == 0 {
            continue;
        }
        let ifname = state
            .ifindex_to_config_name
            .get(ifindex)
            .map(String::as_str)
            .unwrap_or("");
        let routing_instance = state
            .ifindex_to_routing_instance
            .get(ifindex)
            .map(String::as_str)
            .unwrap_or("");
        let id =
            super::super::forwarding::fabric_nat_scope_stamp_id(*zone_id, ifname, routing_instance);
        if !ambiguous.contains(&id) {
            state.ifindex_to_fabric_nat_scope_id.insert(*ifindex, id);
        }
    }
    for (id, (zone_id, _, _, ifindex, redundancy_group)) in scope_by_id {
        if !ambiguous.contains(&id) {
            state.fabric_nat_scope_id_to_identity.insert(
                id,
                FabricNatScopeIdentity {
                    zone_id,
                    ifindex,
                    redundancy_group,
                },
            );
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
/// plus `lo0`. This broad predicate is for bind-exclusion and sentinel-SKIP
/// parity, not for every warning's unconditional-admit text. Prefix-only names
/// and `lo0` are not narrow kernel lifelines in warning text, so those branches
/// remain zone-gated.
///
/// The broad skip is intentionally inert for an unbound interface today:
/// `buildUserspaceBindNetdevs` does not bind a zoneless interface, so no packet
/// can consult its sentinel. Keeping the broad predicate here still prevents a
/// future bind or quarantine path from arming a sentinel for a bind-excluded
/// name. Only exact `fxp0`, exact `em0`, and canonical `fab` plus digits receive
/// unconditional lifeline wording.
///
/// The config-derived control/fabric names (#3277: a renamed `control-interface`
/// / non-default fabric) are still NOT mirrored here because the snapshot does
/// not carry them; that stays safe only because such a renamed lifeline is
/// zoneless and thus not AF_XDP-bound today. If a future change binds a zoneless
/// interface, this predicate MUST be reconciled with
/// `userspaceSkipsIngressInterface` (add a parity test). The unit suffix is
/// stripped so `em0.0` / `fab1.0` / `lo0.0` match too.
fn host_inbound_base_name(name: &str) -> &str {
    match name.split_once('.') {
        Some((base, _)) => base.trim(),
        None => name.trim(),
    }
}

pub(in crate::afxdp) fn is_host_inbound_lifeline(name: &str) -> bool {
    let base = host_inbound_base_name(name);
    base.starts_with("fxp") || base.starts_with("em") || base.starts_with("fab") || base == "lo0"
}

fn is_narrow_host_inbound_lifeline(name: &str) -> bool {
    let base = host_inbound_base_name(name);
    base == "fxp0" || base == "em0" || is_canonical_fabric_name(base)
}

fn is_canonical_fabric_name(base: &str) -> bool {
    let Some(suffix) = base.strip_prefix("fab") else {
        return false;
    };
    !suffix.is_empty() && suffix.bytes().all(|byte| byte.is_ascii_digit())
}

fn is_zone_gated_host_inbound_name(name: &str) -> bool {
    is_host_inbound_lifeline(name) && !is_narrow_host_inbound_lifeline(name)
}

/// The interface's primary IPv4: the address the operator designated
/// `primary` when the snapshot marks one (#15155), else the first
/// non-link-local address in snapshot order, else the first address
/// of the family. An unmarked snapshot behaves exactly as before.
/// #16130: diff-verified twin — `pick_interface_v4`/`_v6` differ only in
/// the family string, the address type, and the link-local predicate
/// (`is_link_local` vs `is_unicast_link_local`), folded here as the
/// parameters. Bodies were verbatim after that folding (see PR diff).
fn pick_interface_generic<A: Copy>(
    iface: &InterfaceSnapshot,
    family: &str,
    parse: fn(&str) -> Option<A>,
    is_link_local: fn(A) -> bool,
) -> Option<A> {
    if iface.admin_disabled {
        return None;
    }
    let mut fallback = None;
    let mut first_non_link_local = None;
    for addr in &iface.addresses {
        if addr.family != family {
            continue;
        }
        let Some(ip) = parse(&addr.address) else {
            continue;
        };
        if addr.primary {
            return Some(ip);
        }
        if fallback.is_none() {
            fallback = Some(ip);
        }
        if first_non_link_local.is_none() && !is_link_local(ip) {
            first_non_link_local = Some(ip);
        }
    }
    first_non_link_local.or(fallback)
}

pub(in crate::afxdp) fn pick_interface_v4(iface: &InterfaceSnapshot) -> Option<Ipv4Addr> {
    pick_interface_generic(
        iface,
        "inet",
        |address| address.parse::<ipnet::Ipv4Net>().ok().map(|net| net.addr()),
        |ip| ip.is_link_local(),
    )
}

pub(in crate::afxdp) fn pick_interface_v6(iface: &InterfaceSnapshot) -> Option<Ipv6Addr> {
    pick_interface_generic(
        iface,
        "inet6",
        |address| address.parse::<ipnet::Ipv6Net>().ok().map(|net| net.addr()),
        |ip| ip.is_unicast_link_local(),
    )
}

/// #16513: the address the operator DESIGNATED `primary` on this row
/// (a marked address), or None when the row carries no marker. Unlike
/// `pick_interface_*`, there is no fallback: an unmarked row has no
/// designation to contribute to the shared-ifindex merge, and its
/// order-based pick must neither veto nor override a sibling row's
/// designation. A disabled row designates nothing (mirrors the pick).
fn designated_interface_generic<A: Copy>(
    iface: &InterfaceSnapshot,
    family: &str,
    parse: fn(&str) -> Option<A>,
) -> Option<A> {
    if iface.admin_disabled {
        return None;
    }
    for addr in &iface.addresses {
        if addr.family != family || !addr.primary {
            continue;
        }
        if let Some(ip) = parse(&addr.address) {
            return Some(ip);
        }
    }
    None
}

fn designated_interface_v4(iface: &InterfaceSnapshot) -> Option<Ipv4Addr> {
    designated_interface_generic(iface, "inet", |address| {
        address.parse::<ipnet::Ipv4Net>().ok().map(|net| net.addr())
    })
}

fn designated_interface_v6(iface: &InterfaceSnapshot) -> Option<Ipv6Addr> {
    designated_interface_generic(iface, "inet6", |address| {
        address.parse::<ipnet::Ipv6Net>().ok().map(|net| net.addr())
    })
}

#[cfg(test)]
mod populate_extract_16130_tests {
    use super::*;

    fn unit_row(name: &str, ifindex: i32, configured: bool) -> InterfaceSnapshot {
        InterfaceSnapshot {
            name: name.into(),
            ifindex,
            is_unit: Some(true),
            host_inbound_configured: configured,
            ..Default::default()
        }
    }

    // FAIL-ON-REVERT: inlining these precomputes back into the walk with
    // (say) the `ifindex > 0` or configured filter dropped reds here.
    #[test]
    fn precomputes_filter_exactly_16130() {
        let snapshot = ConfigSnapshot {
            interfaces: vec![
                unit_row("ge-0/0/0.0", 10, true),
                unit_row("ge-0/0/0.1", 10, true),
                unit_row("ge-0/0/1.0", 0, true),
                unit_row("ge-0/0/2.0", 12, false),
                InterfaceSnapshot {
                    name: "ge-0/0/3".into(),
                    ifindex: 13,
                    is_unit: Some(false),
                    host_inbound_configured: true,
                    ..Default::default()
                },
            ],
            ..Default::default()
        };
        assert_eq!(
            unit_host_inbound_ifindexes_precompute(&snapshot),
            BTreeSet::from([10])
        );
        let mut claims: BTreeMap<i32, UnitHostInboundClaim> = BTreeMap::new();
        claims.insert(10, UnitHostInboundClaim::Disagree);
        claims.insert(
            11,
            UnitHostInboundClaim::Agreed(BTreeSet::new(), BTreeSet::new(), false),
        );
        assert_eq!(
            disputed_host_inbound_ifindexes_precompute(&claims),
            BTreeSet::from([10])
        );
    }

    #[test]
    fn flush_egress_zone_claims_corroborates_16130() {
        let mut state = ForwardingState::default();
        state.zone_name_to_id.insert("trust".into(), 7);
        state.zone_name_to_id.insert("untrust".into(), 9);
        let mut claims: BTreeMap<i32, EgressZoneClaim> = BTreeMap::new();
        claims.insert(10, EgressZoneClaim::Decided("trust".into()));
        claims.insert(11, EgressZoneClaim::Decided("untrust".into()));
        claims.insert(12, EgressZoneClaim::Conflicting);
        claims.insert(13, EgressZoneClaim::Decided("".into()));
        let mut carried: BTreeMap<i32, BTreeSet<String>> = BTreeMap::new();
        carried.insert(10, BTreeSet::from(["trust".into()]));
        // 11 claims untrust but no row carries it: must NOT be admitted.
        carried.insert(11, BTreeSet::from(["trust".into()]));
        carried.insert(12, BTreeSet::from(["trust".into()]));
        flush_egress_zone_claims(&mut state, claims, &carried);
        assert_eq!(state.ifindex_unambiguous_zone_id.get(&10), Some(&7));
        assert!(!state.ifindex_unambiguous_zone_id.contains_key(&11));
        assert!(!state.ifindex_unambiguous_zone_id.contains_key(&12));
        assert!(!state.ifindex_unambiguous_zone_id.contains_key(&13));
    }

    #[test]
    fn install_disputed_sentinels_never_clobbers_or_arms_lifeline_16130() {
        let mut state = ForwardingState::default();
        state.ifindex_to_config_name.insert(10, "ge-0/0/0.0".into());
        state.ifindex_to_config_name.insert(11, "fxp0".into());
        state.ifindex_to_config_name.insert(12, "ge-0/0/1.0".into());
        state.ifindex_host_inbound.insert(
            12,
            crate::afxdp::types::ZoneHostInbound::default(),
        );
        let armed = install_disputed_host_inbound_sentinels(&mut state, &BTreeSet::from([10, 11, 12]));
        assert_eq!(armed, BTreeSet::from([10]));
        assert!(state.ifindex_host_inbound[&10].ndp_excluded);
        assert!(!state.ifindex_host_inbound.contains_key(&11), "lifeline unarmed");
    }

    #[test]
    fn pick_generic_primary_and_link_local_16130() {
        // Parity is pinned end-to-end by primary_address_15155; here the
        // generic body itself: primary wins even when link-local, else
        // first non-link-local, else first.
        let iface = InterfaceSnapshot {
            name: "ge-0/0/0".into(),
            addresses: vec![
                crate::protocol::snapshot::InterfaceAddressSnapshot {
                    family: "inet".into(),
                    address: "169.254.1.1/16".into(),
                    ..Default::default()
                },
                crate::protocol::snapshot::InterfaceAddressSnapshot {
                    family: "inet".into(),
                    address: "192.0.2.1/24".into(),
                    ..Default::default()
                },
            ],
            ..Default::default()
        };
        assert_eq!(
            pick_interface_v4(&iface),
            Some(Ipv4Addr::new(192, 0, 2, 1))
        );
        assert_eq!(pick_interface_v6(&iface), None);
    }
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
            &FastMap::default(),
            &FastMap::default(),
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

    fn zone(name: &str, id: u32) -> ZoneSnapshot {
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
    /// STRADDLES two routing instances is left ABSENT. An encoded fabric ingress
    /// for an absent zone gets a per-zone sentinel, not domain 0 / MAIN.
    ///
    /// Assigning a straddling zone the first-seen domain would hand a
    /// fabric-redirected packet a CONFIDENTLY WRONG domain — worse than dropping
    /// because the correct member domain is unknowable at fabric ingress.
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
            "a zone straddling two routing instances must have no selected domain"
        );
        assert_eq!(state.ambiguous_fabric_zone_ids.len(), 1);
        assert!(state.ambiguous_fabric_zone_ids.contains(&2));
        let ambiguous_domain = ingress_routing_domain(&state, 10, 0, Some(2));
        assert_ne!(
            ambiguous_domain, 0,
            "an ambiguous encoded zone must not alias the default session domain"
        );
        assert_ne!(ambiguous_domain, DOMAIN_A);
        assert_ne!(ambiguous_domain, DOMAIN_B);
        assert_eq!(
            ingress_routing_domain(&state, 10, 0, Some(0)),
            DOMAIN_A,
            "zone id 0 is not a validated fabric stamp and must not produce a sentinel"
        );
    }
    /// A zone inherited onto a trunk parent from a single-RI VLAN child keeps
    /// that child's domain; the propagated parent alias is not a second default
    /// instance member.
    #[test]
    fn a_single_ri_trunk_parent_alias_does_not_make_its_zone_ambiguous_11061() {
        let mut parent = iface("ge-0-0-5", 10, "tenant-a-lan", "", 0);
        parent.unit_count = 1;
        let mut child = iface("ge-0-0-5.50", 11, "tenant-a-lan", "tenant-a", DOMAIN_A);
        child.parent_ifindex = 10;
        let snapshot = ConfigSnapshot {
            interfaces: vec![parent, child],
            zones: vec![zone("tenant-a-lan", 1)],
            ..Default::default()
        };
        let state = build(&snapshot);
        assert_eq!(
            state.ifindex_to_zone_id.get(&10).copied(),
            Some(1),
            "the zone must be propagated to the trunk parent"
        );
        assert_eq!(
            state.zone_routing_domain.get(&1).copied(),
            Some(DOMAIN_A),
            "a parent alias must inherit its sole member's domain, not invent a \
             default-domain member"
        );
        assert_eq!(
            ingress_routing_domain(&state, 21, 0, Some(1)),
            DOMAIN_A,
            "fabric ingress must retain the unambiguous zone domain"
        );
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
    // Red matrix for the four same-ifindex cells below (measured on the
    // pre-guard implementation via scratch worktree): exactly ONE reds —
    // this one. The other three pin preserved behavior (member-vs-member
    // last-wins, order-insensitivity, zeros naming) and stay green on both
    // implementations by construction.

    /// A member claim survives a trailing zero-domain row (#9821 #12).
    ///
    /// The member-claimed guard (not recency) decides the pair: a
    /// nonzero-domain (member) row claims the ifindex for BOTH maps, and a
    /// later zero-domain row writes nothing while the claim stands. Here the
    /// base row carries tenant-a and the trailing unit row carries the
    /// default instance: the merged pair stays the member's (instance +
    /// domain), and the gate stays true — membership, once observed, is not
    /// lost to row order. (This replaces an earlier revision that pinned
    /// last-row-wins clearing; the settled design is the guard — pair
    /// atomicity was never the invariant, membership survival is.)
    ///
    /// `ifindex_to_config_name` takes the unit row's name here: the base row
    /// is an alias, so base+unit-0 keeps the unit's name (#16061); only
    /// distinct UNIT rows contest the name (pinned in
    /// `config_name_16061_tests` below).
    ///
    /// FAIL-ON-REVERT: let a zero row overwrite and the domain is lost while
    /// the name flips to the trailing row.
    #[test]
    fn same_ifindex_member_claim_survives_trailing_default_row() {
        let snapshot = ConfigSnapshot {
            interfaces: vec![
                iface("ge-0-0-5", 10, "trust", "tenant-a", DOMAIN_A),
                iface("ge-0-0-5.0", 10, "trust", "", 0),
            ],
            zones: vec![zone("trust", 1)],
            ..Default::default()
        };
        let state = build(&snapshot);
        assert_eq!(
            state.ifindex_to_routing_instance.get(&10).cloned(),
            Some("tenant-a".to_string()),
            "the member's instance survives the trailing zero row"
        );
        assert_eq!(
            state.ifindex_to_routing_domain.get(&10).copied(),
            Some(DOMAIN_A),
            "the member's domain survives the trailing zero row"
        );
        assert!(
            state.has_routing_domains,
            "the gate is sticky: a claim, once observed, is never lost to row order"
        );
        assert_eq!(ingress_routing_domain(&state, 10, 0, None), DOMAIN_A);
        assert_eq!(
            state.ifindex_to_config_name.get(&10).cloned(),
            Some("ge-0-0-5.0".to_string()),
            "the unit row's name wins over its base alias (#16061)"
        );
    }

    /// Member-vs-member last-wins is preserved, and agreeing rows are
    /// unaffected (#9821 #12).
    ///
    /// Two CLAIMED rows contend: the last member wins both maps (the guard
    /// protects a claim against ZERO rows only, never against another
    /// claim). The Go builder emits a base row ahead of its unit rows, so in
    /// the ordinary order this is unit-row-wins — the unit row is the
    /// traffic identity (#7509). The agreeing ifindex pins that the guard is
    /// a no-op where there was no disagreement (the entire strict corpus).
    ///
    /// FAIL-ON-REVERT: first-member-wins (or any order-insensitivity across
    /// claims) resolves the disagreeing ifindex to DOMAIN_A.
    #[test]
    fn same_ifindex_disagreeing_domains_resolve_to_the_last_rows_pair() {
        let snapshot = ConfigSnapshot {
            interfaces: vec![
                iface("ge-0-0-5", 10, "trust", "tenant-a", DOMAIN_A),
                iface("ge-0-0-5.0", 10, "trust", "tenant-b", DOMAIN_B),
                iface("ge-0-0-6", 11, "trust", "tenant-a", DOMAIN_A),
                iface("ge-0-0-6.0", 11, "trust", "tenant-a", DOMAIN_A),
            ],
            zones: vec![zone("trust", 1)],
            ..Default::default()
        };
        let state = build(&snapshot);
        assert_eq!(ingress_routing_domain(&state, 10, 0, None), DOMAIN_B);
        assert_eq!(
            state.ifindex_to_routing_instance.get(&10).cloned(),
            Some("tenant-b".to_string()),
            "instance and domain must come from ONE row"
        );
        assert_eq!(ingress_routing_domain(&state, 11, 0, None), DOMAIN_A);
        assert!(state.has_routing_domains);
    }

    /// A member claim overwrites a zero row's name regardless of order
    /// (#9821 #12): zero-first is not special — the claim wins both maps
    /// whenever it appears.
    ///
    /// FAIL-ON-REVERT: first-row-wins keeps the zero row's empty instance.
    #[test]
    fn same_ifindex_member_overwrites_zero_row_in_any_order() {
        let snapshot = ConfigSnapshot {
            interfaces: vec![
                iface("ge-0-0-5.0", 10, "trust", "", 0),
                iface("ge-0-0-5", 10, "trust", "tenant-a", DOMAIN_A),
            ],
            zones: vec![zone("trust", 1)],
            ..Default::default()
        };
        let state = build(&snapshot);
        assert_eq!(
            state.ifindex_to_routing_instance.get(&10).cloned(),
            Some("tenant-a".to_string())
        );
        assert_eq!(
            state.ifindex_to_routing_domain.get(&10).copied(),
            Some(DOMAIN_A)
        );
        assert!(state.has_routing_domains);
    }

    /// Zero-only rows keep last-zero-wins naming with no domain (#9821 #12):
    /// the (name,0) compat shape (#4446/old-Go) still reaches NAT scope by
    /// name while the domain map holds exactly member ifindexes and the
    /// gate stays false.
    ///
    /// FAIL-ON-REVERT: storing explicit zeros (or dropping the name) breaks
    /// absent==default or the compat naming, respectively.
    #[test]
    fn same_ifindex_zero_rows_keep_name_without_domain() {
        let snapshot = ConfigSnapshot {
            interfaces: vec![
                iface("ge-0-0-5", 10, "trust", "first", 0),
                iface("ge-0-0-5.0", 10, "trust", "second", 0),
            ],
            zones: vec![zone("trust", 1)],
            ..Default::default()
        };
        let state = build(&snapshot);
        assert_eq!(
            state.ifindex_to_routing_instance.get(&10).cloned(),
            Some("second".to_string()),
            "last zero row's name wins (byte-identical to the old unconditional insert)"
        );
        assert_eq!(
            state.ifindex_to_routing_domain.get(&10).copied(),
            None,
            "no explicit zeros: the map holds exactly member ifindexes"
        );
        assert!(
            !state.has_routing_domains,
            "no claim observed, gate stays false"
        );
        assert_eq!(ingress_routing_domain(&state, 10, 0, None), 0);
    }
}

// #16061 (SI-4-name): `ifindex_to_config_name` last-write mis-scopes
// from-interface NAT on a shared ifindex.
//
// Distinct logical units can collapse onto one netdev ifindex — an
// interface-level tunnel maps EVERY unit onto the tunnel device
// (`TunnelNameMap`, `pkg/dataplane/userspace/interfaces.go`), and unit 0
// collapses onto its base. The map holds ONE name per ifindex, so the old
// unconditional insert named whichever unit row was walked LAST, and a NAT
// rule scoped `from interface <sibling>` then matched traffic that arrived
// on the shared device — traffic the dataplane cannot attribute to either
// unit. The settled answer mirrors #7509's zone discipline: the ifindex
// keeps a config name only while its logical-unit rows agree on one;
// distinct unit names contest it and the entry is withdrawn, so scoped NAT
// fails closed (no match) instead of matching the wrong sibling. Base rows
// are device aliases, not traffic identities, and never contest.
#[cfg(test)]
mod config_name_16061_tests {
    use super::*;
    use crate::protocol::{ConfigSnapshot, InterfaceSnapshot, ZoneSnapshot};

    fn build(snapshot: &ConfigSnapshot) -> ForwardingState {
        let mut state = ForwardingState::default();
        crate::afxdp::forwarding_build::zones::populate_zones(snapshot, &mut state);
        populate_interfaces(
            snapshot,
            &mut state,
            &FastMap::default(),
            &FastMap::default(),
        )
        .expect("populate_interfaces");
        state
    }

    fn unit(name: &str, ifindex: i32, zone: &str) -> InterfaceSnapshot {
        InterfaceSnapshot {
            name: name.into(),
            linux_name: "wg0".into(),
            ifindex,
            zone: zone.into(),
            is_unit: Some(true),
            tunnel: true,
            ..Default::default()
        }
    }

    fn zone(name: &str, id: u32) -> ZoneSnapshot {
        ZoneSnapshot {
            name: name.into(),
            id,
            ..Default::default()
        }
    }

    fn shared_snapshot(rows: Vec<InterfaceSnapshot>) -> ConfigSnapshot {
        ConfigSnapshot {
            interfaces: rows,
            zones: vec![zone("vpn", 1), zone("lan", 2)],
            ..Default::default()
        }
    }

    /// Two distinct units on one ifindex contest the config name in BOTH row
    /// orders: the ifindex carries no name, so a `from interface` rule scoped
    /// to either sibling can never match traffic on the shared device.
    ///
    /// FAIL-ON-REVERT: restore the unconditional last-write insert and the
    /// map names the last-walked sibling (`wg0.1` forward, `wg0.0` reversed).
    #[test]
    fn distinct_units_sharing_an_ifindex_carry_no_config_name_16061() {
        for (label, rows) in [
            (
                "unit0-first",
                vec![unit("wg0.0", 42, "vpn"), unit("wg0.1", 42, "vpn")],
            ),
            (
                "unit1-first",
                vec![unit("wg0.1", 42, "vpn"), unit("wg0.0", 42, "vpn")],
            ),
        ] {
            let state = build(&shared_snapshot(rows));
            assert_eq!(
                state.ifindex_to_config_name.get(&42),
                None,
                "{label}: distinct units on one ifindex must not let either \
                 name claim the device (#16061)"
            );
        }
    }

    /// The end-to-end NAT consequence through the real builder + scope
    /// resolver: traffic resolving to the shared ifindex reports an EMPTY
    /// ingress interface name, so a rule scoped `from interface wg0.0` (or
    /// `wg0.1`) cannot match it — regardless of which sibling the rule names
    /// and regardless of row order.
    ///
    /// FAIL-ON-REVERT: with last-write naming the scope reports the
    /// last-walked sibling and that sibling's scoped rule matches.
    #[test]
    fn nat_scope_on_a_contested_ifindex_names_no_interface_16061() {
        for rows in [
            vec![unit("wg0.0", 42, "vpn"), unit("wg0.1", 42, "vpn")],
            vec![unit("wg0.1", 42, "vpn"), unit("wg0.0", 42, "vpn")],
        ] {
            let state = build(&shared_snapshot(rows));
            let scope =
                crate::afxdp::forwarding::nat_scope_ctx_for_flow(&state, 42, 0, None, 24, 0);
            assert_eq!(
                scope.ingress_ifname, "",
                "a contested shared ifindex must scope to no interface, so \
                 neither sibling's `from interface` NAT rule matches (#16061)"
            );
        }
    }

    /// Positive controls: the shapes that legitimately share an ifindex keep
    /// their name byte-identically.
    ///
    /// - base + unit 0 (the ordinary collapsed pair): the unit's name wins
    ///   over its base alias in either order;
    /// - duplicate rows naming the SAME unit agree, so the name stands;
    /// - a lone base row keeps its own name (the #10313-era parent fallback
    ///   consumers read).
    #[test]
    fn agreeing_and_alias_rows_keep_their_config_name_16061() {
        let base = InterfaceSnapshot {
            name: "wg0".into(),
            linux_name: "wg0".into(),
            ifindex: 42,
            zone: "vpn".into(),
            is_unit: Some(false),
            tunnel: true,
            ..Default::default()
        };
        for (label, rows) in [
            ("base-first", vec![base.clone(), unit("wg0.0", 42, "vpn")]),
            ("unit-first", vec![unit("wg0.0", 42, "vpn"), base.clone()]),
            (
                "same-unit-twice",
                vec![unit("wg0.0", 42, "vpn"), unit("wg0.0", 42, "vpn")],
            ),
        ] {
            let state = build(&shared_snapshot(rows));
            assert_eq!(
                state.ifindex_to_config_name.get(&42).map(String::as_str),
                Some("wg0.0"),
                "{label}: the collapsed base+unit-0 pair keeps the unit's name"
            );
        }
        let state = build(&shared_snapshot(vec![base]));
        assert_eq!(
            state.ifindex_to_config_name.get(&42).map(String::as_str),
            Some("wg0"),
            "a lone base row keeps its own name"
        );
    }
}

// #9821 (#22) — structural row identity.
//
// `is_unit: Some` is authoritative: a dotted base row (`ge-0/0/5.0`,
// `Some(false)`) is excluded from the unit claims even though its name has
// a numeric suffix, and unit rows (`Some(true)`) drive them. `None` (old
// Go, tests, fixtures) falls back to the legacy name parse — old-Go
// behavior exactly, including the dotted misread it preserves (pinned as a
// COMPAT characterization, not as approval).
#[cfg(test)]
mod row_identity_9821_tests {
    use super::*;
    use crate::protocol::{ConfigSnapshot, InterfaceSnapshot, ZoneSnapshot};

    const DOMAIN_A: u32 = 100_001;

    fn build(snapshot: &ConfigSnapshot) -> ForwardingState {
        let mut state = ForwardingState::default();
        crate::afxdp::forwarding_build::zones::populate_zones(snapshot, &mut state);
        populate_interfaces(
            snapshot,
            &mut state,
            &FastMap::default(),
            &FastMap::default(),
        )
        .expect("populate_interfaces");
        state
    }

    fn iface(
        name: &str,
        ifindex: i32,
        zone: &str,
        domain: u32,
        is_unit: Option<bool>,
    ) -> InterfaceSnapshot {
        InterfaceSnapshot {
            name: name.into(),
            linux_name: name.into(),
            ifindex,
            zone: zone.into(),
            routing_instance: "tenant-a".into(),
            routing_domain: domain,
            is_unit,
            ..Default::default()
        }
    }

    fn zone(name: &str, id: u32) -> ZoneSnapshot {
        ZoneSnapshot {
            name: name.into(),
            id,
            ..Default::default()
        }
    }

    /// `Some(false)` + numeric suffix is excluded from the unit claims: the
    /// dotted base row's inherited zone is REFUSED and the unit row's zone
    /// is admitted (#7509 on a dotted shape), and the zone→domain join
    /// follows the admitted zone.
    ///
    /// FAIL-ON-REVERT: parse names instead of reading the bit and the base
    /// row joins the claims, the ifindex disagrees, and nothing is admitted.
    #[test]
    fn some_false_base_excluded_and_unit_admitted_on_dotted_shape() {
        let snapshot = ConfigSnapshot {
            interfaces: vec![
                iface("ge-0/0/5.0", 10, "untrust", DOMAIN_A, Some(false)),
                iface("ge-0/0/5.0.0", 10, "trust", DOMAIN_A, Some(true)),
            ],
            zones: vec![zone("trust", 1), zone("untrust", 2)],
            ..Default::default()
        };
        let state = build(&snapshot);
        assert_eq!(
            state.ifindex_to_zone_id.get(&10).copied(),
            Some(1),
            "the unit row's zone must be admitted; the base row's inherited \
             zone must be refused, not disagreed into silence"
        );
        assert_eq!(
            state.zone_routing_domain.get(&1).copied(),
            Some(DOMAIN_A),
            "the zone→domain join follows the admitted zone"
        );
    }

    /// `None` falls back to the legacy name parse EXACTLY — including
    /// reading a dotted base row as a unit row. This pins old-Go behavior
    /// for old snapshots; it is a COMPAT characterization, not approval of
    /// the misread (which the bumped contract no longer ships).
    ///
    /// NOT fail-on-revert for the structural branch: it takes the fallback
    /// path by construction and stays green whatever `Some` does.
    #[test]
    fn none_falls_back_to_legacy_parse_including_dotted_misread() {
        let snapshot = ConfigSnapshot {
            interfaces: vec![
                iface("ge-0/0/5.0", 10, "untrust", DOMAIN_A, None),
                iface("ge-0/0/5.0.0", 10, "trust", DOMAIN_A, None),
            ],
            zones: vec![zone("trust", 1), zone("untrust", 2)],
            ..Default::default()
        };
        let state = build(&snapshot);
        assert_eq!(
            state.ifindex_to_zone_id.get(&10).copied(),
            None,
            "legacy parse reads the dotted base as a unit, the ifindex \
             disagrees, and nothing is admitted — old behavior, preserved"
        );
    }
}
