//! #9752: installing-table registry build — stable domain id → the instance's
//! canonical per-family route tables + owner check.
//!
//! Runs once per config at the end of `build_fallible_forwarding_state`,
//! after the late-stage NAT append (the last table-string writer). Pure
//! derivation from the built maps: infallible, reads no snapshot state
//! beyond what the builders already normalized.

use super::*;
use crate::session::install_table_identity;

/// Strip a per-instance table suffix, either family. Returns the instance
/// name, or `None` when the string names no per-instance table:
/// - default tables (`"inet.0"`/`"inet6.0"`) strip to `""` and are filtered —
///   domain 0 is by rule, never a registry row (hashing `""` would key a row
///   at an in-band domain no `#3855` gate covers);
/// - non-conforming keys (no suffix) are skipped — PBR always forms
///   `"{ri}.inet[6].0"` (`forwarding/pbr.rs`), so a lookup for a stamped
///   session can never name them; skipping matches lookup behavior (a miss
///   under the canonical string) without inventing presence.
/// Either suffix is accepted regardless of the source family (a v4 key
/// carrying a v6 suffix is a stale-emitter shape (#3768-H6); the key is
/// still evidence the instance exists — presence follows the SOURCE
/// family, extraction follows the string).
fn strip_instance_name(table: &str) -> Option<&str> {
    table
        .strip_suffix(".inet.0")
        .or_else(|| table.strip_suffix(".inet6.0"))
        .filter(|name| !name.is_empty())
}

/// Collect the instance names with dataplane presence per family: every
/// table string the FIB can resolve in — route keys, connected tables,
/// local attributions. Sorted + deduped so the registry build below is
/// deterministic (first-wins on collision).
fn instance_names_with_presence(state: &ForwardingState) -> (Vec<String>, Vec<String>) {
    fn collect<'a, I>(tables: I) -> Vec<String>
    where
        I: IntoIterator<Item = &'a str>,
    {
        let mut names: Vec<String> = tables
            .into_iter()
            .filter_map(strip_instance_name)
            .map(str::to_string)
            .collect();
        names.sort_unstable();
        names.dedup();
        names
    }
    let v4 = collect(
        state
            .routes_v4
            .keys()
            .map(String::as_str)
            .chain(state.leak_rules_v4.keys().map(String::as_str))
            .chain(state.connected_v4.iter().map(|entry| entry.table.as_str()))
            .chain(
                state
                    .local_tables_v4
                    .values()
                    .flat_map(|tables| tables.iter().map(String::as_str)),
            ),
    );
    let v6 = collect(
        state
            .routes_v6
            .keys()
            .map(String::as_str)
            .chain(state.leak_rules_v6.keys().map(String::as_str))
            .chain(state.connected_v6.iter().map(|entry| entry.table.as_str()))
            .chain(
                state
                    .local_tables_v6
                    .values()
                    .flat_map(|tables| tables.iter().map(String::as_str)),
            ),
    );
    (v4, v6)
}

/// Build `state.install_tables` from the finished FIB maps. MUST run after
/// every table-string writer (routes, connected, the late-stage NAT append).
///
/// One row per instance name with presence in either family: both canonical
/// strings preformed from the name (`"{name}.inet.0"`, `"{name}.inet6.0"`)
/// so re-resolve borrows with zero allocation; per-family `None` marks a
/// family with no presence (absent-family path, never a wrong-table
/// lookup); `h2` is the owner check, verified on every use. Sorted input +
/// first-wins makes a within-config hash collision deterministic (and such
/// a config is refused at commit by `#3855` anyway).
pub(super) fn build_install_table_registry(state: &mut ForwardingState) {
    let (v4_names, v6_names) = instance_names_with_presence(state);
    let mut names: Vec<String> = v4_names.iter().cloned().collect();
    names.extend(v6_names.iter().cloned());
    names.sort_unstable();
    names.dedup();
    debug_assert!(
        state.install_tables.is_empty(),
        "install_tables rebuilt over a populated registry — the scan runs once per build"
    );
    for name in &names {
        let (domain, h2) = install_table_identity(name);
        // First-wins: entry API skips an occupied row, so the surviving row
        // is deterministic in the sorted name order.
        state
            .install_tables
            .entry(domain)
            .or_insert_with(|| InstallTables {
                v4: v4_names
                    .binary_search(&name)
                    .is_ok()
                    .then(|| format!("{name}.inet.0")),
                v6: v6_names
                    .binary_search(&name)
                    .is_ok()
                    .then(|| format!("{name}.inet6.0")),
                h2,
            });
    }
}

#[cfg(test)]
mod tests {
    use super::super::build_forwarding_state;
    use super::*;
    use crate::protocol::snapshot::InterfaceAddressSnapshot;

    fn blue_iface() -> crate::InterfaceSnapshot {
        crate::InterfaceSnapshot {
            name: "ge-0/0/0".into(),
            ifindex: 101,
            routing_instance: "blue".into(),
            hardware_addr: "02:00:00:00:00:01".into(),
            addresses: vec![InterfaceAddressSnapshot {
                family: "inet".into(),
                address: "172.16.50.1/24".into(),
                ..Default::default()
            }],
            ..Default::default()
        }
    }

    fn blue_route() -> crate::RouteSnapshot {
        crate::RouteSnapshot {
            table: "blue.inet.0".into(),
            family: "inet".into(),
            destination: "10.0.0.0/8".into(),
            next_hops: vec!["172.16.50.254".into()],
            ..Default::default()
        }
    }

    /// The registry carries every instance with presence, with preformed
    /// canonical strings and the owner check — the values re-resolve borrows.
    #[test]
    fn registry_carries_present_instances_with_preformed_tables_9752() {
        let snapshot = crate::ConfigSnapshot {
            interfaces: vec![blue_iface()],
            routes: vec![blue_route()],
            ..Default::default()
        };
        let state = build_forwarding_state(&snapshot);
        let (domain, h2) = crate::session::install_table_identity("blue");
        assert_eq!(domain, 525590, "fixture: blue must keep its Go vector");
        let row = state
            .install_tables
            .get(&domain)
            .expect("blue must have a registry row");
        assert_eq!(row.v4.as_deref(), Some("blue.inet.0"));
        assert_eq!(row.v6, None, "no v6 presence anywhere for blue");
        assert_eq!(row.h2, h2);
    }

    /// Default tables are excluded: `inet.0`/`inet6.0` keys hash `""` into
    /// the band (106945), and no `#3855` gate covers that value — so the scan
    /// skips defaults before extraction. Domain 0 is by rule, never a row.
    #[test]
    fn registry_excludes_default_tables_9752() {
        let snapshot = crate::ConfigSnapshot {
            interfaces: vec![blue_iface()],
            routes: vec![
                blue_route(),
                crate::RouteSnapshot {
                    table: "inet.0".into(),
                    family: "inet".into(),
                    destination: "0.0.0.0/0".into(),
                    next_hops: vec!["172.16.50.254".into()],
                    ..Default::default()
                },
            ],
            ..Default::default()
        };
        let state = build_forwarding_state(&snapshot);
        assert!(
            state.routes_v4.contains_key("inet.0"),
            "premise: the default table must exist for the exclusion to mean anything"
        );
        assert_eq!(
            state.install_tables.len(),
            1,
            "only blue may have a row; got {:?}",
            state.install_tables.keys().collect::<Vec<_>>()
        );
        assert!(
            !state.install_tables.contains_key(&106945),
            "hash(\"\") must never be a key (GLM-r1 finding 2)"
        );
        assert!(
            !state.install_tables.contains_key(&0),
            "domain 0 is by rule, never a row"
        );
    }

    /// Per-family presence is independent: v4-only presence yields
    /// `v4: Some, v6: None` (absent-family path), not a fabricated v6 string.
    #[test]
    fn registry_tracks_per_family_presence_9752() {
        let snapshot = crate::ConfigSnapshot {
            interfaces: vec![blue_iface()],
            routes: vec![blue_route()],
            ..Default::default()
        };
        let state = build_forwarding_state(&snapshot);
        let (domain, _) = crate::session::install_table_identity("blue");
        let row = state.install_tables.get(&domain).expect("blue row");
        assert!(row.v4.is_some(), "v4 route + connected give v4 presence");
        assert_eq!(
            row.v6, None,
            "nothing v6 mentions blue: no v6 presence may be recorded"
        );
    }

    /// A within-config H1 collision is deterministic (sorted first-wins):
    /// ri7/ri116 both fold to 957120 (#9657 pair); the earlier name wins.
    /// Such a config is refused at commit (#3855) — determinism is the
    /// backstop, and re-resolve still verifies H2.
    #[test]
    fn registry_collision_is_sorted_first_wins_9752() {
        let mut snapshot = crate::ConfigSnapshot {
            interfaces: vec![],
            routes: vec![
                crate::RouteSnapshot {
                    table: "ri7.inet.0".into(),
                    family: "inet".into(),
                    destination: "10.7.0.0/16".into(),
                    next_hops: vec!["192.0.2.1".into()],
                    ..Default::default()
                },
                crate::RouteSnapshot {
                    table: "ri116.inet.0".into(),
                    family: "inet".into(),
                    destination: "10.116.0.0/16".into(),
                    next_hops: vec!["192.0.2.2".into()],
                    ..Default::default()
                },
            ],
            ..Default::default()
        };
        // Determinism across input orders, not just one lucky order.
        snapshot.routes.reverse();
        let state = build_forwarding_state(&snapshot);
        let rows: Vec<_> = state.install_tables.iter().collect();
        assert_eq!(rows.len(), 1, "one domain, one row; got {rows:?}");
        let (domain, row) = rows[0];
        assert_eq!(*domain, 957120);
        // "ri116" < "ri7" lexicographically, so it wins first-wins.
        assert_eq!(row.v4.as_deref(), Some("ri116.inet.0"));
        assert_eq!(row.h2, crate::session::install_table_identity("ri116").1);
    }

    /// An instance with zero presence (no routes, connected, or locals) gets
    /// no row — re-resolve terminals on it instead of guessing a table.
    #[test]
    fn registry_omits_instances_without_presence_9752() {
        let snapshot = crate::ConfigSnapshot {
            interfaces: vec![blue_iface()],
            routes: vec![blue_route()],
            ..Default::default()
        };
        let state = build_forwarding_state(&snapshot);
        let (ghost, _) = crate::session::install_table_identity("ghost");
        assert!(
            !state.install_tables.contains_key(&ghost),
            "an instance with no dataplane presence must have no row"
        );
    }
}
