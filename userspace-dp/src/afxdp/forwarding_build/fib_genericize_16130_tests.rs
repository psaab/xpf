// #16130 genericize parity cells, moved out of `fib.rs` unchanged (#18517:
// the split-node binding pushed `fib.rs` past the 2000-LOC modularity
// floor). Declared from `fib.rs` with `#[path]`, so the module path and
// every test name are unchanged.
use super::*;

// Decisive parity for the genericized merge: duplicate terminals sum
// saturating, distinct keys stay separate and sorted by key.
// FAIL-ON-REVERT: reverting `merge_recursive_targets` to per-family
// bodies that (say) overwrite instead of saturating-add, or dropping
// the sort, reds this in both families via the one generic body.
#[test]
fn merge_recursive_targets_sums_saturating_and_sorts_16130() {
    let gw = Ipv4Addr::new(192, 0, 2, 1);
    let merged = merge_recursive_targets(vec![
        (gw, 7, 0u16, u32::MAX),
        (gw, 7, 0u16, 5),
        (gw, 3, 0u16, 2),
        (Ipv4Addr::new(192, 0, 2, 2), 7, 0u16, 1),
    ]);
    assert_eq!(
        merged,
        vec![
            (gw, 3, 0, 2),
            (gw, 7, 0, u32::MAX),
            (Ipv4Addr::new(192, 0, 2, 2), 7, 0, 1),
        ]
    );
    let gw6: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let merged6 = merge_recursive_targets(vec![(gw6, 7, 0u16, 3), (gw6, 7, 0u16, 4)]);
    assert_eq!(merged6, vec![(gw6, 7, 0, 7)]);
}

#[test]
fn parse_route_next_hop_generic_matches_family_shapes_16130() {
    assert_eq!(
        parse_route_next_hop_generic::<Ipv4Addr>("192.0.2.1@ge-0-0-0"),
        (Some(Ipv4Addr::new(192, 0, 2, 1)), Some("ge-0-0-0".into()))
    );
    assert_eq!(
        parse_route_next_hop_generic::<Ipv4Addr>("@ge-0-0-0"),
        (None, Some("ge-0-0-0".into()))
    );
    assert_eq!(
        parse_route_next_hop_generic::<Ipv6Addr>("2001:db8::1"),
        (Some("2001:db8::1".parse::<Ipv6Addr>().unwrap()), None)
    );
    // Cross-family literal fails closed to (None, None), as before.
    assert_eq!(
        parse_route_next_hop_generic::<Ipv4Addr>("2001:db8::1"),
        (None, None)
    );
    assert_eq!(parse_route_next_hop_generic::<Ipv6Addr>(""), (None, None));
}

// The v6-only branches must NOT be folded into the generic: a v6
// link-local gateway stays ifindex-0 unresolved, and the v4
// counterparts resolve through their own explicit bodies.
#[test]
fn v6_link_local_branches_stay_explicit_16130() {
    let state = ForwardingState::default();
    let snapshot = ConfigSnapshot::default();
    let routes = RecursiveGatewayRoutes::from_snapshot(&snapshot);
    let route = RouteSnapshot::default();
    let ll: Ipv6Addr = "fe80::1".parse().unwrap();
    assert_eq!(
        resolve_next_hop_target_v6(
            Some(ll),
            None,
            false,
            &BTreeMap::new(),
            &BTreeMap::new(),
            &state,
            "inet6.0",
            &routes,
            &route,
        ),
        vec![(Some(ll), 0, 0, 1)],
        "v6 link-local must not recurse globally (#12398 B1)"
    );
    // v6 link-local recursion entry refuses immediately.
    let mut work = MAX_RECURSIVE_STATIC_WORK;
    let mut excluded = [None; MAX_RECURSIVE_STATIC_DEPTH];
    assert!(recursive_static_target_v6(
        &state,
        &routes,
        ll,
        "inet6.0",
        &BTreeMap::new(),
        &BTreeMap::new(),
        &mut excluded,
        &mut [None; MAX_RECURSIVE_STATIC_DEPTH],
        0,
        &mut work,
    )
    .is_empty());
}

#[test]
fn leak_incarnation_retained_only_on_exact_identity_16130() {
    let mut state = ForwardingState::default();
    let mut prev = ForwardingState::default();
    let leak = |prefix: &str, table: &str, prio: u32, inc: u64| LeakRuleV4 {
        prefix: PrefixV4::from_net(prefix.parse().unwrap()),
        next_table: table.into(),
        rule_priority: prio,
        post_table: false,
        incarnation: inc,
    };
    prev.leak_rules_v4.insert(
        "inet.0".into(),
        vec![leak("10.0.0.0/8", "tenant.inet.0", 100, 4242)],
    );
    state.leak_rules_v4.insert(
        "inet.0".into(),
        vec![
            leak("10.0.0.0/8", "tenant.inet.0", 100, 0),
            leak("10.0.0.0/8", "tenant.inet.0", 200, 0),
        ],
    );
    assign_leak_incarnations(&mut state, Some(&prev));
    let leaks = &state.leak_rules_v4["inet.0"];
    assert_eq!(leaks[0].incarnation, 4242, "exact identity retains");
    assert_ne!(leaks[1].incarnation, 4242, "different priority is fresh");
    assert_ne!(leaks[1].incarnation, 0);
}

#[test]
fn leak_incarnation_retained_only_on_exact_identity_v6_16130() {
    let mut state = ForwardingState::default();
    let mut prev = ForwardingState::default();
    let leak = |prefix: &str, table: &str, prio: u32, inc: u64| LeakRuleV6 {
        prefix: PrefixV6::from_net(prefix.parse().unwrap()),
        next_table: table.into(),
        rule_priority: prio,
        post_table: false,
        incarnation: inc,
    };
    prev.leak_rules_v6.insert(
        "inet6.0".into(),
        vec![leak("2001:db8::/32", "tenant.inet6.0", 100, 4242)],
    );
    state.leak_rules_v6.insert(
        "inet6.0".into(),
        vec![
            leak("2001:db8::/32", "tenant.inet6.0", 100, 0),
            leak("2001:db8::/32", "tenant.inet6.0", 200, 0),
        ],
    );
    assign_leak_incarnations(&mut state, Some(&prev));
    let leaks = &state.leak_rules_v6["inet6.0"];
    assert_eq!(leaks[0].incarnation, 4242, "exact identity retains");
    assert_ne!(leaks[1].incarnation, 4242, "different priority is fresh");
    assert_ne!(leaks[1].incarnation, 0);
}
