//! #11327: the helper FIB uses the less-specific route when the Go producer
//! excludes a static row with no forwarding disposition.

use super::super::forwarding_build::build_forwarding_state;

use super::*;
use crate::test_zone_ids::{TEST_LAN_ZONE_ID, TEST_WAN_ZONE_ID};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

#[test]
fn zero_disposition_route_falls_through_under_both_default_policies_11327() {
    for (default_policy, want_action) in [
        ("deny", crate::policy::PolicyAction::Deny),
        ("permit", crate::policy::PolicyAction::Permit),
    ] {
        let snapshot = crate::ConfigSnapshot {
            interfaces: vec![crate::InterfaceSnapshot {
                name: "wan".into(),
                ifindex: 12,
                addresses: vec![crate::InterfaceAddressSnapshot {
                    family: "inet".into(),
                    address: "192.0.2.2/24".into(),
                    ..Default::default()
                }],
                ..Default::default()
            }],
            routes: vec![crate::RouteSnapshot {
                table: "inet.0".into(),
                family: "inet".into(),
                destination: "0.0.0.0/0".into(),
                next_hops: vec!["192.0.2.1".into()],
                ..Default::default()
            }],
            neighbors: vec![crate::NeighborSnapshot {
                ifindex: 12,
                family: "inet".into(),
                ip: "192.0.2.1".into(),
                mac: "02:00:00:00:00:0c".into(),
                state: "reachable".into(),
                ..Default::default()
            }],
            default_policy: default_policy.into(),
            ..Default::default()
        };
        let state = build_forwarding_state(&snapshot);
        assert_eq!(
            state.policy.default_action, want_action,
            "fixture must carry the {default_policy} default policy"
        );

        let resolution = lookup_forwarding_resolution_in_table_with_dynamic(
            &state,
            &Arc::new(ShardedNeighborMap::new()),
            IpAddr::V4(Ipv4Addr::new(10, 1, 0, 20)),
            Some("inet.0"),
        );
        assert_eq!(
            resolution.disposition,
            ForwardingDisposition::ForwardCandidate,
            "{default_policy}: zero-disposition /24 must not shadow the installable /0"
        );
        assert_eq!(
            resolution.egress_ifindex, 12,
            "{default_policy}: /0 gateway must resolve through the connected WAN"
        );

        let policy_action = crate::policy::evaluate_policy(
            &state.policy,
            TEST_LAN_ZONE_ID,
            TEST_WAN_ZONE_ID,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 1, 0, 20)),
            6,
            12345,
            443,
        );
        assert_eq!(
            policy_action, want_action,
            "{default_policy}: dropping the empty FIB row must not alter default policy"
        );
    }
}
