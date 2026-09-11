//! #7480: the `NoRoute` slow-path adjudication.
//!
//! Before this, a `NoRoute` frame was slow-path eligible and got reinjected to
//! the kernel FIB with no zone policy, session, NAT or screen — and nothing
//! downstream re-checks it. The destination is attacker-chosen.
//!
//! These cells cover `noroute_policy_denial`, which exists as a function
//! precisely so this is testable: the call site is the `NoRoute` arm of
//! `poll_binding_process_descriptor`, which no test in this crate can drive (it
//! needs a live binding, a UMEM and a descriptor ring — the same reason #6664
//! had to use a source guard). The wiring is guarded separately; the semantics
//! are guarded here.

use super::noroute_policy_denial;
use crate::policy::{PolicyAction, PolicyState, parse_policy_state};
use crate::{PolicyApplicationSnapshot, PolicyRuleSnapshot};
use rustc_hash::FxHashMap;
use std::net::IpAddr;

const LAN: u16 = 11;
const WAN: u16 = 12;
/// The #3110 "unknown / no zone" sentinel. Every NoRoute resolution carries
/// `egress_ifindex: 0` (both constructors in `fib.rs`), so the caller always
/// resolves this as the to-zone.
const UNZONED: u16 = 0;

fn zones() -> FxHashMap<String, u16> {
    let mut m = FxHashMap::default();
    m.insert("lan".to_string(), LAN);
    m.insert("wan".to_string(), WAN);
    m
}

fn src() -> IpAddr {
    "10.0.61.100".parse().expect("src")
}
fn dst() -> IpAddr {
    "172.16.80.200".parse().expect("dst")
}

fn permit_lan_to_wan(application_terms: Vec<PolicyApplicationSnapshot>) -> PolicyRuleSnapshot {
    PolicyRuleSnapshot {
        name: "permit-lan-wan".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["any".to_string()],
        destination_addresses: vec!["any".to_string()],
        applications: vec!["any".to_string()],
        application_terms,
        action: "permit".to_string(),
        ..Default::default()
    }
}

/// A port-bearing TCP/443 term. `applications: ["any"]` alone is `match_any`,
/// which short-circuits the L4-presence check — an inline term is what actually
/// constrains a port, and using the wrong one is why the first version of the
/// flowless cell below passed for the wrong reason.
fn tcp_443_term() -> PolicyApplicationSnapshot {
    PolicyApplicationSnapshot {
        name: "tcp-443".to_string(),
        protocol: "tcp".to_string(),
        source_port: String::new(),
        destination_port: "443".to_string(),
        icmp_type: None,
        icmp_code: None,
        inactivity_timeout: None,
    }
}

/// THE SECURITY CELL. A default-deny box must now refuse to delegate a NoRoute
/// frame to the kernel.
///
/// FAIL-ON-REVERT: make `noroute_policy_denial` return `None` unconditionally
/// (i.e. restore the pre-#7480 "always delegate") and this reds.
#[test]
fn noroute_is_denied_on_a_default_deny_box_7480() {
    let state = PolicyState::default();
    assert_eq!(
        state.default_action,
        PolicyAction::Deny,
        "fixture premise: the default PolicyState is deny"
    );

    let verdict = noroute_policy_denial(
        &state,
        LAN,
        UNZONED,
        src(),
        dst(),
        6,
        Some((40000, 443)),
        None,
        64,
    );

    assert!(
        verdict.is_some(),
        "a NoRoute frame on a default-deny box must be DENIED, not handed to the \
         kernel FIB. Delegating it is the #6664 policy bypass: the kernel forwards \
         with no zone policy, session, NAT or screen, and there is no nftables \
         `hook forward` drop while kernel transit is open, ip_forward is 1 then, and \
         rp_filter is 0 on the TUN — nothing downstream catches it."
    );
}

/// THE AVAILABILITY CELL, and the reason this is an adjudication rather than a
/// drop. A permitted flow must still reach the kernel, because #7409's importer
/// BOUNDS the FIB divergence without closing it: routes learned between snapshot
/// pushes, and everything before the first push on a fresh boot, still resolve
/// NoRoute and must still be delegated.
///
/// FAIL-ON-REVERT: make the helper return `Some(..)` unconditionally and this
/// reds — which is the black-hole #6664 was warned off.
#[test]
fn noroute_is_delegated_when_the_default_permits_7480() {
    let state = parse_policy_state("permit", &[], &zones());

    let verdict = noroute_policy_denial(
        &state,
        LAN,
        UNZONED,
        src(),
        dst(),
        6,
        Some((40000, 443)),
        None,
        64,
    );

    assert!(
        verdict.is_none(),
        "a NoRoute frame under a default-PERMIT policy must still be delegated to \
         the kernel. Denying it black-holes every destination the kernel learned \
         since the last snapshot push, and everything on a fresh boot until the \
         first push."
    );
}

/// THE OPERATOR-SURPRISE CELL, and the one worth reading before an upgrade.
///
/// A NoRoute resolution always carries `egress_ifindex: 0`, so the to-zone is the
/// #3110 unzoned sentinel — which makes the flow ineligible for zone-pair AND
/// `junos-global` policies. So an explicit `permit` for the ingress zone pair
/// does NOT rescue a NoRoute frame: only the DEFAULT action decides.
///
/// This is not a bug to fix by relaxing #3110; #3110 exists so a permit-global
/// cannot leak transit on an unzoned interface. It is pinned because it is
/// surprising, and because someone will otherwise "fix" the reported drop by
/// adding a zone-pair permit and find it changes nothing.
#[test]
fn a_zone_pair_permit_does_not_rescue_noroute_7480() {
    let state = parse_policy_state(
        "deny",
        &[permit_lan_to_wan(Vec::new())],
        &zones(),
    );

    // Sanity: the rule DOES permit when the egress zone actually resolves. If
    // this half ever fails the cell below proves nothing.
    assert!(
        noroute_policy_denial(&state, LAN, WAN, src(), dst(), 6, Some((40000, 443)), None, 64)
            .is_none(),
        "fixture premise: permit-lan-wan must permit a fully zoned lan->wan flow"
    );

    assert!(
        noroute_policy_denial(
            &state,
            LAN,
            UNZONED,
            src(),
            dst(),
            6,
            Some((40000, 443)),
            None,
            64,
        )
        .is_some(),
        "with an UNZONED egress (#3110) the lan->wan permit must NOT apply — the \
         default action decides. If this ever permits, a NoRoute frame would be \
         delegated to the kernel on the strength of a zone-pair rule that was \
         never evaluated against the real egress zone."
    );
}

/// The `ports` contract. This is NOT exercised by today's only call path — a
/// NoRoute frame always has an unzoned egress, so the default action decides and
/// the ports never change the outcome. It is pinned anyway because the helper's
/// signature offers the distinction, and an untested option is a claim.
///
/// `None` means a flowless packet (non-first fragment / no L4): port-bearing
/// application terms must fail CLOSED, matching the #3291 flowless
/// ForwardCandidate gate and the #4024 MissingNeighbor arm.
#[test]
fn flowless_ports_fail_closed_against_a_port_bearing_term_7480() {
    let state = parse_policy_state(
        "deny",
        &[permit_lan_to_wan(vec![tcp_443_term()])],
        &zones(),
    );

    assert!(
        noroute_policy_denial(&state, LAN, WAN, src(), dst(), 6, Some((40000, 443)), None, 64)
            .is_none(),
        "fixture premise: a flow-backed 443 flow must match the junos-https term"
    );

    assert!(
        noroute_policy_denial(&state, LAN, WAN, src(), dst(), 6, None, None, 64).is_some(),
        "a FLOWLESS packet has no readable port, so a port-bearing application term \
         must fail closed rather than match on the zeroed ports"
    );
}
