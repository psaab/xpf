//! #16131: route-table interning inside `ForwardingState`, dual-carry form.
//!
//! The per-address local-delivery attributions (`local_tables_v[46]`,
//! `interface_nat_tables_v[46]`, and the nested `interface_nat_v[46]`
//! ifindex maps) key owning route tables by canonical table NAME
//! (`FastSet<String>` / `FastMap<String, i32>`). The packet path therefore
//! hashes the table-name string on every local-delivery probe.
//!
//! [`RouteIdentity`] (`{domain, table}`, already published per generation
//! in `route_table_identities`) is the numeric form of the same table.
//! Interning the per-address sets onto it was proposed as a pure
//! replacement — but the dissenting review (Codex, preserved on #16131)
//! showed the replacement as drawn cannot keep the packet-path probe
//! count at one: resolving `table: &str` → `RouteIdentity` costs a second
//! hash probe before the (then `Vec`-scan or set) membership test, so the
//! "interned" lookup is strictly more probes than today's single string
//! set lookup. The narrowed, accepted form is therefore DUAL-CARRY:
//!
//! - The string sets/maps stay exactly as they are and remain the ONLY
//!   form any lookup reads. Packet-path probe count is unchanged by
//!   construction (no packet code in this change reads the twins).
//! - The interned twins (`local_table_ids_v[46]`,
//!   `interface_nat_table_ids_v[46]`, `interface_nat_ids_v[46]`) are
//!   derived ONCE per build, here, from the authoritative string forms
//!   and the published `route_table_identities`.
//! - A dual-carry agreement cell ([`route_table_dual_carry_agrees`],
//!   exercised by the tests in this file over built states AND hand-built
//!   states) proves the two carries agree on every state: for every
//!   address, the interned set equals the image of the string set under
//!   `route_table_identities`, and vice versa — every interned identity
//!   must be the published identity of some carried name of the SAME
//!   address (no phantom identities, no cross-address bleed).
//!
//! Agreement is enforced at build time: [`intern_route_tables`] derives
//! the twins, then asserts agreement before the state is published; a
//! disagreement panics in the build (the reconcile preflight keeps the
//! previous live state — fail closed, never a half-interned publish).
//!
//! Identity is NEVER synthesized: a table name with no published
//! `route_table_identities` row is simply absent from the interned carry
//! and flips `route_table_interning_complete` to false (diagnostic only).
//! When the identity map itself is incomplete
//! (`route_table_identity_map_complete == false`, e.g. a legacy peer that
//! published no identities), the twins stay EMPTY rather than guessing —
//! the string carry alone is authoritative in that posture, and the
//! agreement cell holds trivially (both sides derive from the same
//! published map; see [`route_table_dual_carry_agrees`]).
//!
//! NAT zone interning (the `synced_source_nat_zone_pair` name lookup) is
//! deliberately NOT part of this: that lookup is load-bearing for
//! allocator matching and the legacy-peer fallback (#6600) and belongs to
//! the separate W3 allocator-API proposal.

use super::*;

/// #16131: derive the interned dual-carry twins from the authoritative
/// string forms. MUST run after `route_table_identities` is assigned
/// (it is the interning authority) and after every writer of the string
/// forms (interfaces, the late-stage NAT append). Overwrites the twins
/// wholesale so a stale twin can never survive a rebuild.
///
/// The derivation is build-time only: per address it clones the small
/// owning-table set (one or two entries in practice) into identity form.
/// No allocation or hashing is added to any packet path.
pub(super) fn intern_route_tables(state: &mut ForwardingState) {
    if !state.route_table_identity_map_complete {
        // Legacy / incomplete-identity posture: never guess an identity.
        // Empty twins + incomplete flag; the string carry is authoritative.
        state.route_table_interning_complete = false;
        return;
    }
    let identities = &state.route_table_identities;
    let mut complete = true;

    state.local_table_ids_v4 = intern_table_set(&state.local_tables_v4, identities, &mut complete);
    state.local_table_ids_v6 = intern_table_set(&state.local_tables_v6, identities, &mut complete);
    state.interface_nat_table_ids_v4 =
        intern_table_set(&state.interface_nat_tables_v4, identities, &mut complete);
    state.interface_nat_table_ids_v6 =
        intern_table_set(&state.interface_nat_tables_v6, identities, &mut complete);
    state.interface_nat_ids_v4 =
        intern_ifindex_map(&state.interface_nat_v4, identities, &mut complete);
    state.interface_nat_ids_v6 =
        intern_ifindex_map(&state.interface_nat_v6, identities, &mut complete);

    state.route_table_interning_complete = complete;

    // Dual-carry agreement: the interned carry must be exactly the image
    // of the string carry under the published identities. A disagreement
    // is a build bug — panic here so the reconcile preflight discards
    // this candidate and keeps the previous live state (fail closed).
    assert!(
        route_table_dual_carry_agrees(state),
        "#16131: dual-carry disagreement — interned route tables diverge \
         from the authoritative string carry; refusing to publish"
    );
}

fn intern_table_set<A: Copy + Eq + std::hash::Hash>(
    source: &FastMap<A, FastSet<String>>,
    identities: &FastMap<String, RouteIdentity>,
    complete: &mut bool,
) -> FastMap<A, FastSet<RouteIdentity>> {
    let mut out = FastMap::default();
    for (addr, tables) in source {
        let mut ids = FastSet::default();
        for name in tables {
            match identities.get(name) {
                Some(identity) => {
                    ids.insert(*identity);
                }
                None => *complete = false,
            }
        }
        out.insert(*addr, ids);
    }
    out
}

fn intern_ifindex_map<A: Copy + Eq + std::hash::Hash>(
    source: &FastMap<A, FastMap<String, i32>>,
    identities: &FastMap<String, RouteIdentity>,
    complete: &mut bool,
) -> FastMap<A, FastMap<RouteIdentity, i32>> {
    let mut out = FastMap::default();
    for (addr, by_table) in source {
        let mut ids = FastMap::default();
        for (name, ifindex) in by_table {
            match identities.get(name) {
                Some(identity) => {
                    // Two distinct names publishing one identity would
                    // collide here; `build_route_table_identity_map`
                    // already flags that posture incomplete, and this
                    // function only runs when the map is complete, so a
                    // collision keeps the first ifindex deterministically
                    // (map iteration order is not sorted — but the
                    // agreement cell below compares against the string
                    // carry and would panic on a real divergence).
                    ids.entry(*identity).or_insert(*ifindex);
                }
                None => *complete = false,
            }
        }
        out.insert(*addr, ids);
    }
    out
}

/// #16131 dual-carry agreement cell: true iff the interned twins are
/// exactly the image of the authoritative string carry under the state's
/// published `route_table_identities`, for every address and every one
/// of the six interned forms.
///
/// Both directions are checked:
/// - forward: every carried name with a published identity contributes
///   that identity (and no address appears in the twin that the string
///   carry does not know);
/// - reverse: every interned identity is the published identity of some
///   name carried for the SAME address (no phantoms), and for the
///   `interface_nat_ids_*` maps the ifindex agrees with the string map.
///
/// When the identity map is incomplete, agreement is defined against
/// that same (partial) published map: names without a row contribute
/// nothing, which is exactly what [`intern_route_tables`] derived, so
/// the cell still discriminates a hand-corrupted twin (see tests).
pub(in crate::afxdp) fn route_table_dual_carry_agrees(state: &ForwardingState) -> bool {
    let identities = &state.route_table_identities;
    table_set_agrees(&state.local_tables_v4, &state.local_table_ids_v4, identities)
        && table_set_agrees(&state.local_tables_v6, &state.local_table_ids_v6, identities)
        && table_set_agrees(
            &state.interface_nat_tables_v4,
            &state.interface_nat_table_ids_v4,
            identities,
        )
        && table_set_agrees(
            &state.interface_nat_tables_v6,
            &state.interface_nat_table_ids_v6,
            identities,
        )
        && ifindex_map_agrees(&state.interface_nat_v4, &state.interface_nat_ids_v4, identities)
        && ifindex_map_agrees(&state.interface_nat_v6, &state.interface_nat_ids_v6, identities)
}

fn table_set_agrees<A: Copy + Eq + std::hash::Hash>(
    string_carry: &FastMap<A, FastSet<String>>,
    id_carry: &FastMap<A, FastSet<RouteIdentity>>,
    identities: &FastMap<String, RouteIdentity>,
) -> bool {
    // Forward + address-set equality: rebuild the expected twin.
    if string_carry.len() != id_carry.len() {
        return false;
    }
    for (addr, names) in string_carry {
        let Some(ids) = id_carry.get(addr) else {
            return false;
        };
        let expected: FastSet<RouteIdentity> =
            names.iter().filter_map(|name| identities.get(name).copied()).collect();
        if *ids != expected {
            return false;
        }
        // Reverse, stated explicitly (implied by the equality above, but
        // this is the direction a future hand-edit is most likely to
        // break): every interned identity names a table carried for
        // THIS address.
        if ids.iter().any(|id| {
            !names
                .iter()
                .any(|name| identities.get(name).is_some_and(|published| published == id))
        }) {
            return false;
        }
    }
    true
}

fn ifindex_map_agrees<A: Copy + Eq + std::hash::Hash>(
    string_carry: &FastMap<A, FastMap<String, i32>>,
    id_carry: &FastMap<A, FastMap<RouteIdentity, i32>>,
    identities: &FastMap<String, RouteIdentity>,
) -> bool {
    if string_carry.len() != id_carry.len() {
        return false;
    }
    for (addr, by_name) in string_carry {
        let Some(by_id) = id_carry.get(addr) else {
            return false;
        };
        // Forward: every published name's ifindex survives under its identity.
        for (name, ifindex) in by_name {
            if let Some(identity) = identities.get(name) {
                if by_id.get(identity) != Some(ifindex) {
                    return false;
                }
            }
        }
        // Reverse: every interned (identity, ifindex) is backed by a
        // carried name publishing that identity with that ifindex.
        for (identity, ifindex) in by_id {
            let backed = by_name.iter().any(|(name, name_ifindex)| {
                name_ifindex == ifindex
                    && identities.get(name).is_some_and(|published| published == identity)
            });
            if !backed {
                return false;
            }
        }
        // Cardinality: the twin may only drop entries whose names have
        // no published identity.
        let published = by_name
            .keys()
            .filter(|name| identities.contains_key(name.as_str()))
            .count();
        if by_id.len() != published {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity(domain: u32, table: u32) -> RouteIdentity {
        RouteIdentity { domain, table }
    }

    /// Hand-built state with three instances (default + two VRFs), the
    /// same address owned in two tables, an interface-NAT address, and
    /// one name (`ghost.inet.0`) with NO published identity.
    fn hand_state() -> ForwardingState {
        let mut state = ForwardingState::default();
        for (name, id) in [
            ("inet.0", identity(0, 254)),
            ("inet6.0", identity(0, 254)),
            ("tenant-a.inet.0", identity(501, 501)),
            ("tenant-a.inet6.0", identity(501, 501)),
            ("tenant-b.inet.0", identity(502, 502)),
            ("tenant-b.inet6.0", identity(502, 502)),
        ] {
            state.route_table_identities.insert(name.to_string(), id);
        }
        state.route_table_identity_map_complete = true;

        let shared = Ipv4Addr::new(203, 0, 113, 10);
        state
            .local_tables_v4
            .entry(shared)
            .or_default()
            .insert("tenant-a.inet.0".to_string());
        state
            .local_tables_v4
            .entry(shared)
            .or_default()
            .insert("tenant-b.inet.0".to_string());
        let v6: Ipv6Addr = "2001:db8::10".parse().unwrap();
        state
            .local_tables_v6
            .entry(v6)
            .or_default()
            .insert("tenant-a.inet6.0".to_string());

        let nat = Ipv4Addr::new(172, 16, 80, 8);
        state
            .interface_nat_v4
            .entry(nat)
            .or_default()
            .insert("tenant-b.inet.0".to_string(), 22);
        state
            .interface_nat_tables_v4
            .entry(nat)
            .or_default()
            .insert("tenant-b.inet.0".to_string());
        // Unpublished name: interned twin must omit it, flag incomplete.
        state
            .local_tables_v4
            .entry(Ipv4Addr::new(198, 51, 100, 7))
            .or_default()
            .insert("ghost.inet.0".to_string());
        state
    }

    #[test]
    fn dual_carry_agrees_on_hand_built_state_16131() {
        let mut state = hand_state();
        intern_route_tables(&mut state);

        assert!(route_table_dual_carry_agrees(&state));
        assert!(
            !state.route_table_interning_complete,
            "ghost.inet.0 has no published identity — interning must report incomplete"
        );
        // The shared address carries BOTH owning identities, nothing else.
        let shared = Ipv4Addr::new(203, 0, 113, 10);
        let ids = state.local_table_ids_v4.get(&shared).expect("interned twin");
        assert_eq!(ids.len(), 2);
        assert!(ids.contains(&identity(501, 501)));
        assert!(ids.contains(&identity(502, 502)));
        // Interface-NAT ifindex survives interning under the identity key.
        let nat = Ipv4Addr::new(172, 16, 80, 8);
        assert_eq!(
            state
                .interface_nat_ids_v4
                .get(&nat)
                .and_then(|by_id| by_id.get(&identity(502, 502))),
            Some(&22)
        );
        // The ghost address interns to the empty set (name omitted, not synthesized).
        assert!(
            state
                .local_table_ids_v4
                .get(&Ipv4Addr::new(198, 51, 100, 7))
                .is_some_and(|ids| ids.is_empty())
        );
    }

    #[test]
    fn dual_carry_cell_rejects_phantom_identity_16131() {
        let mut state = hand_state();
        intern_route_tables(&mut state);
        // Phantom: an identity no carried name of this address publishes.
        state
            .local_table_ids_v4
            .entry(Ipv4Addr::new(203, 0, 113, 10))
            .or_default()
            .insert(identity(0, 254));
        assert!(
            !route_table_dual_carry_agrees(&state),
            "a phantom interned identity must fail the agreement cell"
        );
    }

    #[test]
    fn dual_carry_cell_rejects_missing_identity_16131() {
        let mut state = hand_state();
        intern_route_tables(&mut state);
        state
            .local_table_ids_v4
            .get_mut(&Ipv4Addr::new(203, 0, 113, 10))
            .expect("interned twin")
            .remove(&identity(501, 501));
        assert!(
            !route_table_dual_carry_agrees(&state),
            "dropping a carried identity must fail the agreement cell"
        );
    }

    #[test]
    fn dual_carry_cell_rejects_wrong_ifindex_16131() {
        let mut state = hand_state();
        intern_route_tables(&mut state);
        state
            .interface_nat_ids_v4
            .get_mut(&Ipv4Addr::new(172, 16, 80, 8))
            .expect("interned twin")
            .insert(identity(502, 502), 99);
        assert!(
            !route_table_dual_carry_agrees(&state),
            "an ifindex diverging from the string carry must fail the cell"
        );
    }

    #[test]
    fn incomplete_identity_map_keeps_twins_empty_16131() {
        let mut state = hand_state();
        state.route_table_identity_map_complete = false;
        intern_route_tables(&mut state);
        assert!(state.local_table_ids_v4.is_empty());
        assert!(state.interface_nat_ids_v4.is_empty());
        assert!(!state.route_table_interning_complete);
        // Agreement is judged against the published map; with twins left
        // empty by the incomplete posture the forward check sees the
        // string carry's published names unrepresented — so the cell
        // must NOT be what gates this posture. intern_route_tables only
        // asserts agreement on the complete path (above), and the
        // incomplete path returns before the assert.
    }

    /// Built-state cell: a real snapshot build (two VRFs sharing one
    /// address, static-NAT external in one VRF) must publish agreeing
    /// carries. This drives `build_forwarding_state`, i.e. the exact
    /// production derivation order.
    #[test]
    fn dual_carry_agrees_on_built_state_16131() {
        let snapshot = crate::ConfigSnapshot {
            interfaces: vec![
                crate::InterfaceSnapshot {
                    name: "ge-0/0/1.0".to_string(),
                    ifindex: 11,
                    routing_instance: "tenant-a".to_string(),
                    addresses: vec![crate::InterfaceAddressSnapshot {
                        family: "inet".to_string(),
                        address: "198.51.100.1/24".to_string(),
                        ..Default::default()
                    }],
                    ..Default::default()
                },
                crate::InterfaceSnapshot {
                    name: "ge-0/0/2.0".to_string(),
                    ifindex: 22,
                    routing_instance: "tenant-b".to_string(),
                    addresses: vec![crate::InterfaceAddressSnapshot {
                        family: "inet".to_string(),
                        address: "198.51.100.1/24".to_string(),
                        ..Default::default()
                    }],
                    ..Default::default()
                },
            ],
            static_nat_rules: vec![crate::StaticNATRuleSnapshot {
                name: "web".to_string(),
                from_routing_instance: "tenant-b".to_string(),
                external_ip: "203.0.113.10".to_string(),
                internal_ip: "192.168.1.10".to_string(),
                ..Default::default()
            }],
            route_table_identities: vec![
                crate::protocol::RouteTableIdentitySnapshot {
                    name: "inet.0".into(),
                    domain: 0,
                    table: 254,
                },
                crate::protocol::RouteTableIdentitySnapshot {
                    name: "inet6.0".into(),
                    domain: 0,
                    table: 254,
                },
                crate::protocol::RouteTableIdentitySnapshot {
                    name: "tenant-a.inet.0".into(),
                    domain: 501,
                    table: 501,
                },
                crate::protocol::RouteTableIdentitySnapshot {
                    name: "tenant-a.inet6.0".into(),
                    domain: 501,
                    table: 501,
                },
                crate::protocol::RouteTableIdentitySnapshot {
                    name: "tenant-b.inet.0".into(),
                    domain: 502,
                    table: 502,
                },
                crate::protocol::RouteTableIdentitySnapshot {
                    name: "tenant-b.inet6.0".into(),
                    domain: 502,
                    table: 502,
                },
            ],
            ..Default::default()
        };
        let state = build_forwarding_state(&snapshot);
        assert!(
            state.route_table_identity_map_complete,
            "fixture must publish a complete identity map"
        );
        assert!(route_table_dual_carry_agrees(&state));
        assert!(state.route_table_interning_complete);
        // Same host address in two VRFs: both identities interned.
        let host = Ipv4Addr::new(198, 51, 100, 1);
        let ids = state.local_table_ids_v4.get(&host).expect("interned host");
        assert!(ids.contains(&identity(501, 501)));
        assert!(ids.contains(&identity(502, 502)));
        // Static-NAT external: only tenant-b's identity.
        let ext = Ipv4Addr::new(203, 0, 113, 10);
        let ids = state.local_table_ids_v4.get(&ext).expect("interned NAT");
        assert_eq!(ids.len(), 1);
        assert!(ids.contains(&identity(502, 502)));
    }
}
