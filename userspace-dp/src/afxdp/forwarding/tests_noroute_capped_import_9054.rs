//! #9054: what a `NoRoute` frame must do when the daemon WITHHELD the kernel
//! route table.
//!
//! #8355 capped the learned-route import at ~65,000 routes and documented the
//! degradation as "traffic still forwards through the kernel, just not on the
//! fast path". #7480, landed separately, made a `NoRoute` frame get adjudicated
//! against the #3110 unzoned egress sentinel — which no zone-pair or
//! `junos-global` permit can match — so the verdict is the DEFAULT action and a
//! Junos-default deny box DROPS it. Each is defensible alone. Composed, the cap
//! turns the entire dynamic FIB into a blackhole and the operator log states the
//! opposite.
//!
//! The cells below are written against `noroute_policy_denial_gated`, the same
//! function the arm calls. The arm itself is not drivable from this crate (it
//! needs a live binding, a UMEM and a descriptor ring), which is why #7480 also
//! reaches it through a function and why `slow_path_admit_single_site_6664.rs`
//! guards the WIRING by reading source.

use super::noroute_policy_denial_gated;
use crate::afxdp::types::ForwardingState;
use crate::policy::{PolicyAction, parse_policy_state};
use rustc_hash::FxHashMap;
use std::net::IpAddr;

const LAN: u16 = 11;
/// The #3110 "unknown / no zone" sentinel. Every NoRoute resolution carries
/// `egress_ifindex: 0`, so the caller always resolves this as the to-zone.
const UNZONED: u16 = 0;

fn src() -> IpAddr {
    "10.0.61.100".parse().expect("src")
}
fn dst() -> IpAddr {
    "172.16.80.200".parse().expect("dst")
}

/// A default-deny forwarding state, i.e. the Junos default and the shipped
/// posture on every cluster in this repo.
fn deny_state(capped: bool) -> ForwardingState {
    let mut state = ForwardingState::default();
    // PIN THE FIXTURE TO GROUND TRUTH FIRST. If the default action were ever
    // Permit, every cell below would pass for a reason unrelated to the subject
    // — the delegate/drop distinction only exists on a deny box.
    assert_eq!(
        state.policy.default_action,
        PolicyAction::Deny,
        "PolicyState::default() is no longer deny; these cells assume the Junos default"
    );
    state.learned_route_import_capped = capped;
    state
}

fn verdict(state: &ForwardingState) -> Option<crate::policy::PolicyEvaluationResult> {
    noroute_policy_denial_gated(
        state,
        LAN,
        UNZONED,
        src(),
        dst(),
        6,
        Some((40000, 443)),
        None,
        64,
    )
}

/// THE DEFECT CELL. A capped import must NOT black-hole the learned table.
///
/// FAIL-ON-REVERT: delete the `learned_route_import_capped` early return from
/// `noroute_policy_denial_gated` and this reds — which is exactly the master
/// behaviour this issue reports.
#[test]
fn a_capped_import_delegates_noroute_instead_of_dropping_it_9054() {
    let capped = deny_state(true);
    assert!(
        verdict(&capped).is_none(),
        "a NoRoute frame was adjudicated (and therefore DROPPED on this deny box) while the \
         daemon had declined the entire learned-route import. NoRoute does not mean \"no route \
         exists\" in that state — it means the daemon withheld the table — so this is a silent \
         total blackhole of the dynamic FIB, and #8355's own log line tells the operator that \
         traffic still forwards through the kernel."
    );
}

/// THE CONTROL THAT KEEPS #7480 INTACT. Same state, same packet, same deny
/// default — only the flag differs.
///
/// Without this cell, "returns None" is satisfiable by deleting the
/// adjudication outright, which would revert #7480's security fix under the
/// banner of an availability fix. The pair is the assertion; neither half is.
#[test]
fn an_uncapped_import_still_adjudicates_and_denies_9054() {
    let uncapped = deny_state(false);
    let got = verdict(&uncapped);
    assert!(
        got.is_some(),
        "a NoRoute frame was delegated to the kernel on a default-deny box with a COMPLETE \
         learned-route import. That is #7480's subject: the destination is attacker-chosen and \
         the kernel path has no zone policy, session, NAT or screen."
    );
    assert_ne!(
        got.expect("verdict").action,
        PolicyAction::Permit,
        "noroute_policy_denial only returns Some for a non-permit verdict"
    );
}

/// The gate is keyed on the CAP, not on the policy. A permit-default box
/// delegates either way — so a cell that only tested a permit box would report
/// the fix working while it did nothing.
#[test]
fn a_permit_default_box_delegates_with_or_without_the_cap_9054() {
    for capped in [false, true] {
        let mut state = ForwardingState::default();
        state.policy = parse_policy_state("permit", &[], &FxHashMap::default());
        state.learned_route_import_capped = capped;
        assert!(
            verdict(&state).is_none(),
            "a permit-default box must delegate NoRoute regardless of the cap (capped={capped})"
        );
    }
}

/// The bound is NARROW: the flag suspends the NoRoute adjudication and nothing
/// else. A frame whose zone pair is fully resolved is still judged normally.
///
/// This is the cell that stops "fix the blackhole" from drifting into "stop
/// evaluating policy while capped".
#[test]
fn the_cap_flag_does_not_reach_ordinary_policy_evaluation_9054() {
    let capped = deny_state(true);
    let result = crate::policy::evaluate_policy_result_l3_aware(
        &capped.policy,
        LAN,
        12, // a REAL egress zone, not the unzoned sentinel
        src(),
        dst(),
        6,
        40000,
        443,
        None,
        64,
        true,
    );
    assert_eq!(
        result.action,
        PolicyAction::Deny,
        "the #9054 flag changed an ordinary zone-pair verdict; it must only suspend the NoRoute \
         adjudication, which is the one decision taken against a FIB the daemon deliberately \
         left incomplete"
    );
}
