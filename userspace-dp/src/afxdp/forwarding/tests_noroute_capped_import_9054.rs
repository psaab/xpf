//! #9522: what a `NoRoute` frame must do when the daemon WITHHELD the kernel
//! route table — SUPERSEDES #9054, with an owner.
//!
//! #9054 restored the pre-#7480 slow-path delegation for `NoRoute` while
//! `learned_route_import_capped` is set, trading #7480's adjudication for the
//! availability of the dynamic FIB. That tradeoff was accepted with no owner,
//! and #9522 found what it costs: above the cap, every destination the kernel
//! can route and userspace did not import transits with no zone policy,
//! session, NAT or screen — a permitted-by-absence path that does not exist
//! under an uncapped import. Both availability-preserving redesigns (a
//! kernel-assisted adjudication and a chunked route verb) were plan-killed,
//! so this issue OWNS the fail-closed horn instead:
//!
//! A capped route miss and an uncapped route miss now produce the SAME policy
//! result. On a default-deny box a capped `NoRoute` frame is DROPPED as a
//! policy denial — downgraded to `PolicyDenied` by the arm, counted in
//! `policy_denied_packets` (`xpf_policy_denies_total`), and visible against
//! the capped state in `xpf_learned_route_import_capped` — not forwarded. A
//! default-permit box still delegates either way, so the availability cost
//! lands only where the operator's own default says deny.
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

/// THE DEFECT CELL. A capped import must NOT suspend the NoRoute adjudication.
///
/// FAIL-ON-REVERT: restore the `learned_route_import_capped` early return in
/// `noroute_policy_denial_gated` and this reds — which is exactly the #9522
/// bypass: a `None` here keeps the `NoRoute` disposition, the trailing
/// chokepoint reinjects the frame, and the kernel forwards it with no zone
/// policy, session, NAT or screen.
#[test]
fn a_capped_import_adjudicates_noroute_instead_of_delegating_it_9522() {
    let capped = deny_state(true);
    let got = verdict(&capped);
    assert!(
        got.is_some(),
        "a NoRoute frame was DELEGATED to the kernel while the daemon had \
         declined the entire learned-route import. That is the unowned #9054 \
         tradeoff #9522 closes: above the cap, every destination the kernel \
         can route transits with no adjudication. On this deny box the frame \
         must be DENIED and counted as a policy denial instead."
    );
    assert_eq!(
        got.expect("verdict").action,
        PolicyAction::Deny,
        "a capped NoRoute frame on a default-deny box must deny, not merely \
         return a non-permit — the arm downgrades on Some(..) and the denial \
         is what the operator counts"
    );
}

/// THE PARITY CELL. #9522's acceptance: a capped route miss and an uncapped
/// route miss produce the SAME policy result, so a full-table cap crossing
/// cannot silently change the posture.
///
/// FAIL-ON-REVERT: same as the defect cell — the early return makes the capped
/// verdict `None` while the uncapped verdict stays `Some(deny)`.
#[test]
fn capped_and_uncapped_noroute_verdicts_are_identical_9522() {
    let capped = deny_state(true);
    let uncapped = deny_state(false);
    assert_eq!(
        verdict(&capped),
        verdict(&uncapped),
        "the cap changed the NoRoute policy result: the capped verdict and the \
         uncapped verdict differ for the same packet on the same policy"
    );
}

/// THE CONTROL THAT KEEPS #7480 INTACT. Same state, same packet, same deny
/// default — only the flag differs. (Lineage: the #9054 control of the same
/// name; the assertion is unchanged, only the issue tag moved.)
///
/// Without this cell, "returns Some" is satisfiable by denying unconditionally
/// in a way that no longer answers the policy question — e.g. a hardcoded
/// deny that ignores the policy state. The pair is the assertion; neither
/// half is.
#[test]
fn an_uncapped_import_still_adjudicates_and_denies_9522() {
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

/// The disposition is keyed on the POLICY, not on the cap. A permit-default
/// box delegates either way — so the #9522 fail-closed cost lands only where
/// the operator's own default says deny, and a cell that only tested a permit
/// box would report the fix working while it did nothing. (Lineage: #9054.)
#[test]
fn a_permit_default_box_delegates_with_or_without_the_cap_9522() {
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

/// The bound is NARROW: the flag never reaches an ordinary zone-pair verdict.
/// A frame whose zone pair is fully resolved is still judged normally.
///
/// This is the cell that stops "adjudicate while capped" from drifting into
/// "the cap changes policy evaluation". (Lineage: #9054; the assertion is
/// unchanged — post-#9522 the flag reaches no policy verdict at all, ordinary
/// or NoRoute.)
#[test]
fn the_cap_flag_does_not_reach_ordinary_policy_evaluation_9522() {
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
        "the cap flag changed an ordinary zone-pair verdict; it must reach no \
         policy evaluation — the NoRoute adjudication answers the operator's \
         policy identically whether or not the daemon withheld the table"
    );
}
