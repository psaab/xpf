// #8356: fail-on-revert coverage for ZONE-POLICY re-derivation on the
// established-session hit path, driven through the REAL
// `poll_binding_process_descriptor` via `txn_run_descriptor`.
//
// Sibling of `tests_filter_revocation_7212.rs`, which does the same for the
// input FILTER. Read them together: this file exists because #7323 closed on
// accepting the ZONE-POLICY half as a residual, and the asymmetry — the tree
// tears down a live flow when a commit narrows a FILTER but not when it narrows
// POLICY — is what #8356 removes.
//
// WHY THESE DRIVE A REAL DESCRIPTOR. A direct call to
// `revalidate_zone_policy_on_session_hit` cannot see the stage deleted from the
// poll loop, and a packet-path change that is never called leaves every cell
// green and the box unchanged. That has cost this board an issue's worth of
// rework twice, most recently #8274.
//
// THE CELL THAT MATTERS MOST is `..._leaves_the_reverse_companion_alone_8356`,
// and it is the one place this feature deliberately does NOT mirror #7212.
// #7212's stamp is per-DIRECTION, correctly: an input filter is a per-interface
// object and each direction is judged against the interface its packet actually
// arrived on. Copying that here is catastrophic. The reverse companion is built
// with SWAPPED zones (`afxdp/shared_ops.rs`, `afxdp/poll_descriptor/mod.rs`),
// and this is a STATEFUL firewall: a reply is permitted because the session
// exists, not because a policy admits (to_zone -> from_zone). Re-derived
// per-direction it evaluates the reversed pair, matches nothing, hits
// `default_policy: deny`, and revokes — so EVERY established session in the box
// dies on the first packet after ANY commit.
//
// That cell only has power because the fixture's policy is ASYMMETRIC.
// `policy_deny_snapshot` permits dmz -> wan and denies by default, so the
// reversed pair genuinely has no rule. A symmetric or allow-all policy set
// would make the cell pass whether the gate exists or not — the "fixture that
// varies an axis but samples only the passing point" failure.
#![allow(unused_imports)]

use super::test_fixtures::*;
use super::tests_support::*;
use super::*;
use crate::session::{SessionDecision, SessionMetadata, SessionOrigin};
use crate::test_zone_ids::*;
use crate::{
    FirewallFilterSnapshot, FirewallTermSnapshot, InterfaceSnapshot, PolicyRuleSnapshot,
    RouteSnapshot,
};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use crate::tcp_flags::TCP_ACK;

const LAN_IFINDEX: i32 = 24;
const WAN_IFINDEX: i32 = 12;
/// A MAC-less egress: routable, but absent from the unambiguous zone ledger.
const MACLESS_IFINDEX: i32 = 77;
const SRC: Ipv4Addr = Ipv4Addr::new(10, 0, 61, 102);
const DST: Ipv4Addr = Ipv4Addr::new(172, 16, 80, 200);
const SPORT: u16 = 12345;
const DPORT: u16 = 443;

/// `policy_deny_snapshot` permits `dmz -> wan` only, with `default_policy:
/// deny`. Adding a `lan -> wan` permit is the "policy admits this flow" state;
/// leaving it out is the "a commit narrowed policy" state. The ASYMMETRY is
/// load-bearing — see the header.
///
/// #9381: the rule's ACTION is a parameter, not a bool. `None` = no `lan -> wan`
/// rule at all (the narrowed-to-nothing state); `Some(action)` = the rule is
/// present carrying exactly that action. The bool form sampled the
/// TERMINAL-ACTION axis at two points — *present as `permit`* and *absent* — and
/// both agree with a revoke arm spelled `!matches!(.., Deny)`. `reject` is the
/// third point, and it is the one the collapsed arm got wrong: a non-forwarding
/// verdict that was re-stamped as revalidated and kept forwarding.
fn forwarding_with_lan_rule(lan_action: Option<&str>) -> ForwardingState {
    let mut snapshot = policy_deny_snapshot();
    snapshot.generation = 7;
    snapshot.fib_generation = 9;
    // #6722: `egress_zone_id` reads `ifindex_unambiguous_zone_id`, which
    // `populate_egress` fills only for interfaces with a resolvable link-layer
    // address. A MAC-less interface (the canonical case is an IPsec xfrmi
    // secure tunnel) is therefore ABSENT from it and its to-zone resolves to the
    // unknown sentinel 0 — the reachable form of "the egress does not resolve to
    // a zone".
    snapshot.interfaces.push(InterfaceSnapshot {
        name: "st0.0".into(),
        zone: "wan".into(),
        linux_name: "st0".into(),
        ifindex: MACLESS_IFINDEX,
        mtu: 1400,
        tunnel: true,
        ..Default::default()
    });
    snapshot.routes.push(RouteSnapshot {
        table: "inet.0".into(),
        family: "inet".into(),
        destination: "198.51.100.0/24".into(),
        next_hops: vec!["st0.0".into()],
        discard: false,
        next_table: String::new(),
        preference: 0,
    });
    if let Some(action) = lan_action {
        snapshot.policies.push(PolicyRuleSnapshot {
            name: "lan-out".into(),
            from_zone: "lan".into(),
            to_zone: "wan".into(),
            source_addresses: vec!["any".into()],
            destination_addresses: vec!["any".into()],
            applications: vec!["any".into()],
            application_terms: Vec::new(),
            action: action.into(),
            ..Default::default()
        });
    }
    build_forwarding_state(&snapshot)
}

fn flow_key_to(dst: Ipv4Addr) -> crate::session::SessionKey {
    crate::session::SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        src_ip: IpAddr::V4(SRC),
        dst_ip: IpAddr::V4(dst),
        src_port: SPORT,
        dst_port: DPORT,
        discriminator: Default::default(),
        routing_domain: 0,
    }
}

/// `egress_ifindex` is what the re-derivation resolves the TO-zone from. `0`
/// models the unresolvable case (a peer-synced import for an inactive RG keeps
/// `NoRoute`/0).
fn decision(egress_ifindex: i32) -> SessionDecision {
    SessionDecision {
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::ForwardCandidate,
            local_ifindex: 0,
            egress_ifindex,
            tx_ifindex: egress_ifindex,
            tunnel_endpoint_id: 0,
            next_hop: Some(IpAddr::V4(DST)),
            neighbor_mac: Some([0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee]),
            src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x80, 0x08]),
            tx_vlan_id: 80,
        },
        nat: NatDecision::default(),
    }
}

/// `is_reverse` and the zone pair are the two axes these cells vary. A REVERSE
/// companion carries the zones SWAPPED, which is the whole point of the trap
/// cell.
fn metadata(is_reverse: bool) -> SessionMetadata {
    let (ingress_zone, egress_zone) = if is_reverse {
        (TEST_WAN_ZONE_ID, TEST_LAN_ZONE_ID)
    } else {
        (TEST_LAN_ZONE_ID, TEST_WAN_ZONE_ID)
    };
    SessionMetadata {
        ingress_zone,
        egress_zone,
        ingress_ifindex: LAN_IFINDEX as u32,
        ingress_vlan_id: 0,
        owner_rg_id: 0,
        fabric_ingress: false,
        is_reverse,
        nat64_reverse: None,
        log_session_init: false,
        log_session_close: false,
        policy_id: 0,
        inactivity_timeout_ns: None,
        policy_counter_idx: 0,
        policy_counter: None,
    }
}

struct Outcome {
    sessions: SessionTable,
    revoked: u64,
}

/// Pre-install ONE established session — stamped UNVALIDATED, exactly what an
/// operator's commit leaves behind — then drive one packet of it through the
/// real poll body.
fn drive_one_packet(permit_lan: bool, is_reverse: bool, egress_ifindex: i32) -> Outcome {
    drive_one_packet_to(permit_lan, is_reverse, egress_ifindex, DST)
}

fn drive_one_packet_to(
    permit_lan: bool,
    is_reverse: bool,
    egress_ifindex: i32,
    dst: Ipv4Addr,
) -> Outcome {
    drive_one_packet_with_action(permit_lan.then_some("permit"), is_reverse, egress_ifindex, dst)
}

/// #9381: the same driver, taking the `lan -> wan` rule's ACTION rather than a
/// present/absent bool, so the three terminal actions are reachable from one
/// path through the REAL poll body.
fn drive_one_packet_with_action(
    lan_action: Option<&str>,
    is_reverse: bool,
    egress_ifindex: i32,
    dst: Ipv4Addr,
) -> Outcome {
    let forwarding = forwarding_with_lan_rule(lan_action);
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, LAN_IFINDEX, 0);
    binding.interface = Arc::<str>::from("reth1.0");
    let ha_state = txn_ha_state();

    let mut sessions = SessionTable::new();
    assert!(
        sessions.install_with_protocol_with_origin(
            flow_key_to(dst),
            decision(egress_ifindex),
            metadata(is_reverse),
            SessionOrigin::ForwardFlow,
            122_000_000_000,
            PROTO_TCP,
            0,
        ),
        "the fixture must install the session, or every assertion below is vacuous"
    );

    let frame = build_txn_tcp_syn_frame_v4(SRC, dst, SPORT, DPORT, TCP_ACK);
    let meta = txn_meta_v4(LAN_IFINDEX as u32, TCP_ACK, frame.len() as u16);
    let (_batch, dbg) = txn_run_descriptor(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame,
        meta,
    );
    Outcome {
        sessions,
        revoked: dbg.policy_revoked_sessions,
    }
}

/// #9513 case iv: a fixture with NO route to the driven destination at all, so
/// the poll path's re-resolution cannot supply an egress ifindex.
///
/// `forwarding_with_lan_rule` adds a `198.51.100.0/24` route via `st0.0`, which
/// is exactly why the cell that thought it was testing an unresolvable egress was
/// not. This one REMOVES that route, which is the difference between "resolves to
/// an unzoned interface" (cases i-iii) and "does not resolve" (case iv).
fn drive_one_packet_no_route_9513() -> Outcome {
    let mut snapshot = policy_deny_snapshot();
    snapshot.generation = 7;
    snapshot.fib_generation = 9;
    // No `st0.0`, no `198.51.100.0/24` route, and no `lan -> wan` permit — so if
    // the derivation were reached it would revoke, which is what makes the
    // `revoked == 0` assertion meaningful rather than incidental.
    let forwarding = build_forwarding_state(&snapshot);
    let dst = Ipv4Addr::new(198, 51, 100, 77);
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, LAN_IFINDEX, 0);
    binding.interface = Arc::<str>::from("reth1.0");
    let ha_state = txn_ha_state();
    let mut sessions = SessionTable::new();
    assert!(
        sessions.install_with_protocol_with_origin(
            flow_key_to(dst),
            // Installed with NO egress ifindex, the shape `upsert_synced` leaves
            // on a peer-synced import for an inactive RG.
            decision(0),
            metadata(false),
            SessionOrigin::ForwardFlow,
            122_000_000_000,
            PROTO_TCP,
            0,
        ),
        "the fixture must install the session, or the assertion is vacuous"
    );
    let frame = build_txn_tcp_syn_frame_v4(SRC, dst, SPORT, DPORT, TCP_ACK);
    let meta = txn_meta_v4(LAN_IFINDEX as u32, TCP_ACK, frame.len() as u16);
    let (_batch, dbg) = txn_run_descriptor(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame,
        meta,
    );
    assert_eq!(
        dbg.session_hit, 1,
        "the packet must HIT the session, or the revoke assertion is vacuous"
    );
    Outcome {
        sessions,
        revoked: dbg.policy_revoked_sessions,
    }
}

fn session_count(sessions: &SessionTable) -> usize {
    let mut n = 0;
    sessions.iter_with_origin(|_k, _d, _m, _o| n += 1);
    n
}

/// THE FEATURE, AND THE WIRING. A session established under an older policy must
/// be revoked on its next packet once policy no longer permits the flow.
///
/// Dies if the re-derivation is built but never called from the poll loop.
#[test]
fn a_narrowed_zone_policy_revokes_the_established_session_8356() {
    let out = drive_one_packet(false, false, WAN_IFINDEX);
    assert_eq!(
        out.revoked, 1,
        "an established lan -> wan session must be revoked once policy stops \
         permitting it. 0 means the poll loop never called the re-derivation — \
         the state in which every direct-call cell is still green (#8356)"
    );
    assert_eq!(
        session_count(&out.sessions),
        0,
        "revocation must actually remove the session, not merely count itself"
    );
}

/// THE CONTROL that gives the cell above its aim. The SAME packet, the SAME
/// path, policy PERMITTING: nothing may be revoked.
///
/// Without this, a re-derivation that revoked unconditionally would satisfy the
/// deny cell perfectly.
#[test]
fn a_still_permitted_flow_survives_the_re_derivation_8356() {
    let out = drive_one_packet(true, false, WAN_IFINDEX);
    assert_eq!(
        out.revoked, 0,
        "policy still permits lan -> wan, so nothing may be revoked. A \
         re-derivation that denied unconditionally would pass the deny cell and \
         fail here (#8356)"
    );
    assert_eq!(
        session_count(&out.sessions),
        1,
        "the permitted session — and its NAT translation, since a \
         purged-and-recreated permitted SNAT flow reinstalls on a DIFFERENT \
         translated port and breaks — must be untouched"
    );
}

/// THE TRAP. A REVERSE companion carries SWAPPED zones, so re-deriving policy on
/// it evaluates (wan -> lan), which this asymmetric fixture does not permit and
/// `default_policy: deny` therefore denies.
///
/// Policy here PERMITS the flow's real direction. Nothing may be revoked.
/// Deleting the `is_reverse` gate reds this and nothing else — and on a real box
/// that deletion kills every established session on the first packet after any
/// commit.
#[test]
fn a_re_derivation_leaves_the_reverse_companion_alone_8356() {
    let out = drive_one_packet(true, true, WAN_IFINDEX);
    assert_eq!(
        out.revoked, 0,
        "the reverse companion must NEVER be independently policy-adjudicated. \
         Its zones are SWAPPED, so evaluating it asks whether policy permits \
         (wan -> lan) — which no ordinary one-way policy set does. This is a \
         STATEFUL firewall: the reply is permitted because the session exists. \
         A non-zero count here means every established session in the box dies \
         on the first packet after any commit (#8356)"
    );
    assert_eq!(
        session_count(&out.sessions),
        1,
        "the reverse companion must survive"
    );
}

/// #9381: THE THIRD TERMINAL ACTION. `PolicyAction` is `Permit`/`Deny`/`Reject`,
/// and the revoke arm used to be spelled `!matches!(result.action, Deny)` — so a
/// `Reject` verdict took the PERMIT exit, re-stamped the session as revalidated,
/// and every established session admitted by the rule the operator just narrowed
/// to `reject` kept forwarding in both directions until idle timeout.
///
/// Its control is the cell BELOW, not the `permit` cell above: `permit` and
/// *absent* are the two points the old bool fixture already sampled, and both
/// agree with the collapsed arm. The pair that binds the DIRECTION is
/// `reject` -> revoked and `permit` -> survives, driven through the SAME
/// `drive_one_packet_with_action` path so the only thing that differs between
/// them is the rule's action string.
///
/// Reverting to `!matches!(.., Deny)` reds this cell and nothing else.
#[test]
fn a_narrowed_to_reject_zone_policy_revokes_the_established_session_9381() {
    let out = drive_one_packet_with_action(Some("reject"), false, WAN_IFINDEX, DST);
    assert_eq!(
        out.revoked, 1,
        "a `reject` verdict is TERMINAL NON-FORWARDING, exactly as admission \
         treats it (`reject_reply.rs` drops the first packet). 0 here means the \
         revoke arm collapsed `Reject` into the permit exit and RE-STAMPED the \
         session, so every flow admitted by a rule the operator just narrowed \
         `permit` -> `reject` keeps forwarding until idle timeout and no later \
         packet of the generation re-asks (#9381)"
    );
    assert_eq!(
        session_count(&out.sessions),
        0,
        "a reject-narrowed session must actually be torn down, not merely counted"
    );
}

/// THE CONTROL for the cell above, and the one that has to stay green: the SAME
/// driver, the SAME packet, the rule present as `permit`.
///
/// Without it, widening the arm to "revoke on anything that is not Deny" — or to
/// "revoke unconditionally" — would satisfy the `reject` cell perfectly while
/// tearing down every permitted session in the box on the first packet after any
/// commit. That is a strictly worse bug than the one #9381 fixes, so the pair is
/// what makes the fix falsifiable rather than the reject cell alone.
#[test]
fn a_permit_rule_still_survives_the_widened_revoke_predicate_9381() {
    let out = drive_one_packet_with_action(Some("permit"), false, WAN_IFINDEX, DST);
    assert_eq!(
        out.revoked, 0,
        "the rule is `permit`; widening the revoke predicate must not touch it. \
         A non-zero count means the predicate now revokes on a PERMIT, i.e. every \
         established session dies on the first packet after any commit (#9381)"
    );
    assert_eq!(
        session_count(&out.sessions),
        1,
        "the permitted session and its NAT translation must be untouched"
    );
}

/// The `deny` point of the same three-way axis, driven through the action-taking
/// path rather than the bool one.
///
/// It is not redundant with `a_narrowed_zone_policy_revokes_the_established_
/// session_8356`: that cell narrows the rule to ABSENT and revokes via the
/// implicit `default_policy: deny`, which is a different code path through
/// `evaluate_policy_result_with_icmp` (the default-counter exit, not
/// `try_match_rule`). This one revokes on an EXPLICIT matched `deny` rule, so the
/// three actions are all sampled on the matched-rule path.
#[test]
fn an_explicit_deny_rule_revokes_the_established_session_9381() {
    let out = drive_one_packet_with_action(Some("deny"), false, WAN_IFINDEX, DST);
    assert_eq!(
        out.revoked, 1,
        "an explicitly matched `deny` rule must revoke, the same as the \
         implicit default-deny does"
    );
    assert_eq!(session_count(&out.sessions), 0);
}

/// #9513 RE-ANCHORED, and the rename is the point: this cell never tested an
/// unresolvable egress. It was called
/// `an_unresolvable_egress_declines_rather_than_denying_8356` and its comment
/// said "198.51.100.77 ... has no route, so the egress genuinely does not
/// resolve". MEASURED at this base, through the same helper the poll path uses:
///
/// ```text
/// re-resolve 198.51.100.77: disposition=ForwardCandidate egress_ifindex=77
///                           -> egress_zone_id=0
/// ```
///
/// The egress resolves perfectly well, to `st0.0` (ifindex 77), because the
/// fixture adds a `198.51.100.0/24` route through it. What is zero is the ZONE,
/// and it is zero because the fixture leaves `egress_zone` at its `Default` of
/// `""` — NOT because the interface is MAC-less, which is what both this cell's
/// comment and the arm's comment claimed. `ifindex_to_zone_id[77]` is `Some(wan)`
/// while `egress_zone_id(77)` is 0, which is exactly the split.
///
/// That `(zone: "wan", egress_zone: "")` pair is a REAL production state — what a
/// contested ifindex produces under `stampEgressZones` rule 1 / #7509 — so the
/// cell is not vacuous and is not deleted. It is renamed to say what it
/// exercises, and its expectation is INVERTED, because #9513 is precisely the
/// decision that this state must be re-judged rather than skipped: new flows out
/// of an unzoned egress already fall to the default policy.
///
/// The two contradictory comments in the tree are also settled by that
/// measurement. The ARM said "the established-hit arm never sees an unresolved
/// decision, because the poll path re-resolves it"; the CELL said "the egress
/// genuinely does not resolve". The arm was right.
#[test]
fn an_unzoned_egress_is_re_judged_rather_than_skipped_9513() {
    let out = drive_one_packet_to(false, false, MACLESS_IFINDEX, Ipv4Addr::new(198, 51, 100, 77));
    assert_eq!(
        out.revoked, 1,
        "the egress RESOLVES (to st0.0) but the box puts it in no zone, so a new \
         flow through it would fall to `default_policy: deny`. An established one \
         must be judged the same way. 0 here is the #9513 defect: a de-zoned \
         egress keeps carrying live sessions indefinitely while new ones are \
         denied (#9513)"
    );
    assert_eq!(
        session_count(&out.sessions),
        0,
        "the session through the unzoned egress must be torn down"
    );
}

/// THE CONTROL THAT KEEPS #9513 FROM BEING A MASS TEARDOWN, and the case the old
/// blanket arm was actually protecting: a genuine LOOKUP FAILURE — no egress
/// ifindex at all.
///
/// This is the state `tests_policy_revocation_8356`'s own fixture comment names:
/// "a peer-synced import for an INACTIVE redundancy group keeps `NoRoute`/0",
/// because `upsert_synced` overwrites the resolution only when the re-resolved
/// disposition is not `HAInactive`. Revoking there would tear down the entire
/// standby population at the moment of promotion — the mass-teardown-at-failover
/// #7323 chose option B to avoid.
///
/// It is driven with a destination the fixture has NO route to at all, so the
/// re-resolution cannot rescue an ifindex the way it does for the cell above.
/// Deleting the `egress_ifindex == 0` half of the #9513 split reds this and
/// nothing else.
#[test]
fn an_egress_that_does_not_resolve_at_all_still_declines_9513() {
    let out = drive_one_packet_no_route_9513();
    assert_eq!(
        out.revoked, 0,
        "there is no egress ifindex at all, which is a LOOKUP FAILURE and not a \
         verdict. #9513 re-judges an UNZONED egress; it must not re-judge an \
         UNRESOLVED one, or every peer-synced import on an inactive RG is torn \
         down at promotion (#9513)"
    );
    assert_eq!(
        session_count(&out.sessions),
        1,
        "the unresolved-egress session must survive"
    );
}

// ---------------------------------------------------------------------------
// #8618: the ICMP half of the #7323 residual.
//
// #8356 declined ICMP outright: a zone policy can match icmp type/code via a
// junos-ping-style application term (#3020), so where such a term exists the
// verdict is a property of the PACKET and a frame-independent derivation has no
// type to offer. #8618 narrows that decline to the case the reasoning describes
// — `packet_icmp` is read in exactly ONE arm of `CompiledApplications::matches`
// (`icmp_constraints`), so with no type-constrained PERMIT in the snapshot a
// type-blind evaluation is not a guess, it is the same answer.
//
// THE PAIR THAT MATTERS is `..._revokes_an_established_icmp_session_8618` and
// `..._a_type_constrained_permit_declines_8618`. Their fixtures are IDENTICAL
// but for one junos-ping permit, so together they bind the gate's DIRECTION.
// Either alone is satisfied by a constant: "always revoke" passes the first,
// "always decline" (i.e. #8356 unchanged, the revert) passes the second.
//
// The first is also the POSITIVE CONTROL for the whole group: if the ICMP
// session key or meta were wrong the packet would never find the session, and
// every "declines" assertion below would pass vacuously on a session that was
// never a candidate.

use crate::PolicyApplicationSnapshot;

const ICMP_ID: u16 = 0x1234;

/// `parse_flow_ports` keys an identifier-bearing ICMP query as (identifier, 0);
/// `build_icmp_echo_frame_v4` stamps identifier 0x1234.
fn icmp_flow_key() -> crate::session::SessionKey {
    crate::session::SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_ICMP,
        src_ip: IpAddr::V4(SRC),
        dst_ip: IpAddr::V4(DST),
        src_port: ICMP_ID,
        dst_port: 0,
        discriminator: Default::default(),
        routing_domain: 0,
    }
}

/// A junos-ping-shaped PERMIT: an ICMP application term carrying an echo-request
/// TYPE constraint, which is what `icmp_constraints` (#3020) is populated from.
///
/// Deliberately on a DIFFERENT zone pair (`dmz -> wan`) than the flow under
/// test. The #8618 predicate is whole-snapshot, so this documents the
/// coarseness as a property rather than leaving it to be discovered: one
/// type-constrained permit anywhere declines ICMP box-wide. That is #8356's
/// behaviour, i.e. the conservative direction.
fn junos_ping_permit() -> PolicyRuleSnapshot {
    PolicyRuleSnapshot {
        name: "ping-elsewhere".into(),
        from_zone: "dmz".into(),
        to_zone: "wan".into(),
        source_addresses: vec!["any".into()],
        destination_addresses: vec!["any".into()],
        applications: vec!["junos-ping".into()],
        application_terms: vec![PolicyApplicationSnapshot {
            name: "junos-ping".into(),
            protocol: "icmp".into(),
            source_port: String::new(),
            destination_port: String::new(),
            icmp_type: Some(8),
            icmp_code: None,
            inactivity_timeout: None,
        }],
        action: "permit".into(),
        ..Default::default()
    }
}

fn drive_one_icmp_packet(permit_lan: bool, with_type_constrained_permit: bool) -> Outcome {
    let mut snapshot = policy_deny_snapshot();
    snapshot.generation = 7;
    snapshot.fib_generation = 9;
    if permit_lan {
        snapshot.policies.push(PolicyRuleSnapshot {
            name: "lan-out".into(),
            from_zone: "lan".into(),
            to_zone: "wan".into(),
            source_addresses: vec!["any".into()],
            destination_addresses: vec!["any".into()],
            // `application any` matches every ICMP message regardless of type,
            // so a verdict resting on it is a FLOW property.
            applications: vec!["any".into()],
            application_terms: Vec::new(),
            action: "permit".into(),
            ..Default::default()
        });
    }
    if with_type_constrained_permit {
        snapshot.policies.push(junos_ping_permit());
    }
    let forwarding = build_forwarding_state(&snapshot);

    let mut binding = BindingWorker::new_for_mirror_test(0, 0, LAN_IFINDEX, 0);
    binding.interface = Arc::<str>::from("reth1.0");
    let ha_state = txn_ha_state();

    let mut sessions = SessionTable::new();
    assert!(
        sessions.install_with_protocol_with_origin(
            icmp_flow_key(),
            decision(WAN_IFINDEX),
            metadata(false),
            SessionOrigin::ForwardFlow,
            122_000_000_000,
            PROTO_ICMP,
            0,
        ),
        "the fixture must install the ICMP session, or every assertion is vacuous"
    );

    let frame = build_icmp_echo_frame_v4(SRC, DST, 64);
    let mut meta = txn_meta_v4(LAN_IFINDEX as u32, 0, frame.len() as u16);
    meta.protocol = PROTO_ICMP;
    meta.payload_offset = 42;
    let (_batch, dbg) = txn_run_descriptor(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame,
        meta,
    );
    Outcome {
        sessions,
        revoked: dbg.policy_revoked_sessions,
    }
}

/// THE FEATURE. An established ICMP session whose flow the live policy no longer
/// permits is revoked — the half of #7323's residual #8356 left open.
///
/// Also the POSITIVE CONTROL for this group: a wrong ICMP key or meta shows up
/// here as revoked == 0, rather than silently making the "declines" cells pass
/// on a session the packet never reached.
#[test]
fn a_narrowed_zone_policy_revokes_an_established_icmp_session_8618() {
    let out = drive_one_icmp_packet(false, false);
    assert_eq!(
        out.revoked, 1,
        "an ICMP session the live policy denies must be revoked once no \
         type-constrained permit makes the verdict packet-dependent"
    );
    assert_eq!(
        session_count(&out.sessions),
        0,
        "the revoked ICMP session must be torn down, not merely counted"
    );
}

/// THE HONESTY GATE, and the direction that must never regress. Same fixture as
/// above plus ONE junos-ping permit: the type-blind derivation could now be
/// wrong, so it must decline rather than revoke.
///
/// If this ever fails, the box is tearing down live ICMP flows on a verdict it
/// could not derive — strictly worse than the residual #8618 set out to close.
#[test]
fn a_type_constrained_permit_declines_the_icmp_re_derivation_8618() {
    let out = drive_one_icmp_packet(false, true);
    assert_eq!(
        out.revoked, 0,
        "with a junos-ping permit in the snapshot the verdict may depend on the \
         icmp type, which this derivation does not have — it must decline"
    );
    assert_eq!(
        session_count(&out.sessions),
        1,
        "the declined ICMP session must survive, exactly as under #8356"
    );
}

/// A still-permitted ICMP flow is not revoked. Guards the blanket-revocation
/// failure the reverse-companion cell guards for TCP.
#[test]
fn a_still_permitted_icmp_flow_survives_the_re_derivation_8618() {
    let out = drive_one_icmp_packet(true, false);
    assert_eq!(
        out.revoked, 0,
        "policy still permits this ICMP flow; re-deriving must not revoke it"
    );
    assert_eq!(session_count(&out.sessions), 1);
}

/// The predicate is PER PROTOCOL, and this is the only cell that can see it.
/// The three above all run over ICMPv4, so swapping the two slots — or collapsing
/// them to one bool — leaves every one of them green while an ICMPv6 flow starts
/// declining (or, worse, stops declining) for a v4-only junos-ping permit.
#[test]
fn the_type_constrained_predicate_is_per_protocol_8618() {
    let mut snapshot = policy_deny_snapshot();
    snapshot.policies.push(junos_ping_permit()); // protocol "icmp" = v4 only
    let forwarding = build_forwarding_state(&snapshot);
    assert!(
        forwarding
            .policy
            .icmp_verdict_may_depend_on_type(PROTO_ICMP),
        "a v4 junos-ping permit must make the ICMPv4 verdict type-dependent"
    );
    assert!(
        !forwarding
            .policy
            .icmp_verdict_may_depend_on_type(PROTO_ICMPV6),
        "an ICMPv4-only constraint must NOT decline ICMPv6 — the slots are \
         independent"
    );
    assert!(
        !forwarding.policy.icmp_verdict_may_depend_on_type(PROTO_TCP),
        "a non-ICMP protocol can never be type-dependent"
    );
}

/// A `lan -> wan` junos-ping-shaped DENY, optionally with a broader `lan -> wan`
/// permit BEHIND it.
///
/// #9386: the zone pair is the load-bearing detail. The cell below used to copy
/// its deny from `junos_ping_permit()`, which is `dmz -> wan`, while driving a
/// `lan -> wan` session — so the deny could not participate in the walk at all
/// and the flow revoked by DEFAULT-DENY whether or not the deny was consulted.
/// Putting the deny on the DRIVEN pair is what makes it observable, and adding a
/// broader permit behind it is what makes the two outcomes distinguishable.
fn ping_deny_on_the_driven_pair_9386(with_broader_permit: bool) -> ForwardingState {
    let mut snapshot = policy_deny_snapshot();
    snapshot.generation = 7;
    snapshot.fib_generation = 9;
    let mut ping_deny = junos_ping_permit();
    ping_deny.name = "ping-deny".into();
    ping_deny.action = "deny".into();
    // THE DRIVEN PAIR, not `dmz -> wan`.
    ping_deny.from_zone = "lan".into();
    snapshot.policies.push(ping_deny);
    if with_broader_permit {
        // Pushed AFTER the deny, so the deny is first in the zone-pair chain and
        // a fully-informed walk would match it. `application any` matches every
        // ICMP message regardless of type, so this permit is type-BLIND.
        snapshot.policies.push(PolicyRuleSnapshot {
            name: "lan-out-any".into(),
            from_zone: "lan".into(),
            to_zone: "wan".into(),
            source_addresses: vec!["any".into()],
            destination_addresses: vec!["any".into()],
            applications: vec!["any".into()],
            application_terms: Vec::new(),
            action: "permit".into(),
            ..Default::default()
        });
    }
    build_forwarding_state(&snapshot)
}

fn drive_icmp_against_9386(forwarding: &ForwardingState) -> u64 {
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, LAN_IFINDEX, 0);
    binding.interface = Arc::<str>::from("reth1.0");
    let ha_state = txn_ha_state();
    let mut sessions = SessionTable::new();
    assert!(sessions.install_with_protocol_with_origin(
        icmp_flow_key(),
        decision(WAN_IFINDEX),
        metadata(false),
        SessionOrigin::ForwardFlow,
        122_000_000_000,
        PROTO_ICMP,
        0,
    ));
    // An echo REQUEST, type 8 — the type the junos-ping term constrains on, so a
    // fully-informed evaluation WOULD match the deny.
    let frame = build_icmp_echo_frame_v4(SRC, DST, 64);
    let mut meta = txn_meta_v4(LAN_IFINDEX as u32, 0, frame.len() as u16);
    meta.protocol = PROTO_ICMP;
    meta.payload_offset = 42;
    let (_batch, dbg) = txn_run_descriptor(
        &mut binding,
        &mut sessions,
        forwarding,
        &ha_state,
        &frame,
        meta,
    );
    assert_eq!(
        dbg.session_hit, 1,
        "the ICMP packet must HIT the installed session, or every assertion \
         about the re-derivation is vacuous (#9386)"
    );
    dbg.policy_revoked_sessions
}

/// Binds the `PolicyAction::Permit` filter on the #8618 arming, which an
/// escaped mutation showed nothing else could see.
///
/// Only a PERMIT can overturn a type-blind DENY. A type-constrained DENY that
/// `packet_icmp = None` gates OFF can only make the walk fall through to a
/// later permit — i.e. more permissive, "do not revoke". It can never manufacture
/// the false DENY the gate exists to prevent, so arming on it would decline for
/// no reason and leave #7323's residual open on configs that never needed it.
///
/// #9386 MOVED THE DENY ONTO THE DRIVEN ZONE PAIR. It used to be copied from
/// `junos_ping_permit()`, i.e. `dmz -> wan`, while the driven session is
/// `lan -> wan` — so the second half of this cell revoked by DEFAULT-DENY
/// regardless of the deny, and bound nothing. Only the predicate assertion was
/// doing work.
///
/// WHAT THE SECOND HALF BINDS NOW, stated so it is not over-read: it binds the
/// ARMING, not enforcement. With no broader permit behind the deny, an ARMED gate
/// declines (0) and an UNARMED gate runs and revokes by default-deny (1), so the
/// two outcomes differ. It is NOT evidence that the constrained deny itself was
/// enforced — that is the residual, and
/// `a_type_constrained_deny_is_skipped_and_the_session_survives_9386` is where it
/// is pinned.
///
/// Dropping `&& matches!(.., Permit)` from the arming loop reds BOTH halves.
#[test]
fn a_type_constrained_deny_does_not_suppress_the_icmp_re_derivation_8618() {
    let forwarding = ping_deny_on_the_driven_pair_9386(false);
    assert!(
        !forwarding
            .policy
            .icmp_verdict_may_depend_on_type(PROTO_ICMP),
        "a type-constrained DENY cannot manufacture a false DENY, so it must \
         NOT make the verdict type-dependent"
    );
    assert_eq!(
        drive_icmp_against_9386(&forwarding),
        1,
        "a type-constrained DENY must not suppress the re-derivation: with the \
         gate UNARMED the walk runs, skips the type-constrained deny, finds no \
         other rule and revokes by default-deny. 0 here means the gate ARMED on a \
         constrained DENY and declined, which leaves #7323's residual open for \
         every ICMP flow on any box carrying a constrained deny anywhere — the \
         predicate is whole-snapshot (#8618/#9386)"
    );
}

/// THE ACCEPTED RESIDUAL, and the cell that replaces the vacuous half. Same zone
/// pair, the type-constrained DENY FIRST, a type-blind broader permit BEHIND it.
///
/// A fully-informed walk matches the deny (the packet IS an echo request, type 8)
/// and would revoke. The type-blind walk this derivation performs fails the
/// constrained term closed for `packet_icmp = None`, falls through to the permit,
/// and the session SURVIVES. That is the residual #9386 names, and it is accepted
/// rather than closed — see `PolicyState::icmp_verdict_may_depend_on_type` for
/// why, in one line: arming the gate on a constrained DENY would not change this
/// outcome (the derivation would decline instead of deriving Permit, and either
/// way the session lives) and would cost #8356 coverage for every ICMP flow on
/// the box, while closing it properly needs the packet's type/code — which this
/// derivation's frame-INDEPENDENCE contract forbids, because one packet's type is
/// not the flow's property.
///
/// SO THIS IS A CHANGE DETECTOR, NOT A DEFECT GUARD, and the distinction is
/// deliberate. Together with the cell above it is TOTAL over the three candidate
/// contracts: accept (predicate false, 1, 0 — today), arm on any constrained term
/// (the cell above reds twice), supply the packet type (THIS cell reds, because
/// the deny would then match and revoke).
#[test]
fn a_type_constrained_deny_is_skipped_and_the_session_survives_9386() {
    let forwarding = ping_deny_on_the_driven_pair_9386(true);
    // Non-vacuity: the gate must be UNARMED, or the derivation declines for a
    // different reason and this cell stops measuring the skip.
    assert!(
        !forwarding
            .policy
            .icmp_verdict_may_depend_on_type(PROTO_ICMP),
        "the snapshot carries no type-constrained PERMIT, so the gate must be \
         unarmed and the re-derivation must RUN — otherwise this cell measures a \
         decline rather than the skip (#9386)"
    );
    assert_eq!(
        drive_icmp_against_9386(&forwarding),
        0,
        "the type-blind walk fails the constrained deny closed and falls through \
         to the broader permit, so the session survives. This is the ACCEPTED \
         residual: a type-constrained ICMP DENY is not enforced on the \
         established-session path. 1 here means the derivation became \
         frame-DEPENDENT for ICMP, which is a contract change and must be a \
         deliberate one (#9386)"
    );
}

// ---------------------------------------------------------------------------
// #9382: the re-derivation must judge the POST-TRANSLATION destination, the
// same tuple admission judges (#2345/#2358).
//
// Admission evaluates zone policy on `policy_dst_ip` / `policy_dst_port` —
// `effective_resolution_target` plus the pre-routing DNAT's rewritten port —
// whose own comment states it "carries the correct post-translation tuple for
// all inbound destination translations (DNAT/static-DNAT/NPTv6/NAT64)". The
// re-derivation evaluated `flow.dst_ip` / `flow.forward_key.dst_port`, i.e. the
// WIRE tuple, because the forward session is installed on the WIRE key. For any
// session with an inbound destination translation the two sites therefore asked
// DIFFERENT QUESTIONS about the same session.
//
// The dominant consequence is FAIL-CLOSED and needs no crafted config: a
// published service whose permit names the real server is revoked and its packet
// dropped on the first flow-cache miss, with the policy completely unchanged.
// Flow-cache misses are not rare — `PublishRouteOverlaySnapshot` bumps the
// config generation for a ROUTE-ONLY publish, and the rtnetlink route listener
// calls it on kernel route changes, so ordinary BGP/OSPF churn is enough. A
// session also installs with `policy_revalidated_gen: 0`, so an eviction alone
// suffices with no generation change at all.
//
// WHY THESE ARE TWO-PHASE. The pre/post-translation distinction only exists for
// a session that HAS a translation, and the only honest way to get one is to let
// the production path admit it: phase 1 drives the real SYN through
// `txn_run_descriptor` (session MISS -> policy -> NAT -> forward+reverse
// install), phase 2 drives one more packet of that same flow on a FRESH binding.
// A fresh binding is an EMPTY FLOW CACHE, which is exactly what a generation
// bump leaves behind, and it is what makes phase 2 reach the session-hit path at
// all rather than replaying a cached descriptor.
//
// WHY THE SHIPPED #8356 CELLS COULD NOT SEE IT: every one of them installs
// `NatDecision::default()` and writes `destination_addresses: vec!["any"]`, so
// the pre/post-translation destination is unobservable twice over. The survival
// cell even asserts it is "preserving NAT" in a fixture with no translation to
// preserve.

struct TranslatedOutcome {
    revoked: u64,
    sessions: usize,
    session_hit_phase2: u64,
    tx_phase2: u64,
}

/// Phase 1 admits the translated flow through the production path. Phase 2
/// drives one more packet of the SAME flow, under `snapshot_phase2`, on a FRESH
/// binding.
///
/// `snapshot_phase2` is the whole point of the shape: passing the SAME snapshot
/// models "nothing about the policy changed", which is the state in which this
/// derivation must do NOTHING, and passing a different one models a real commit.
fn admit_then_one_more_packet(
    snapshot_phase1: crate::ConfigSnapshot,
    snapshot_phase2: crate::ConfigSnapshot,
    ifindex: i32,
    iface: &str,
    frame_admit: &[u8],
    meta_admit: UserspaceDpMeta,
    frame_established: &[u8],
    meta_established: UserspaceDpMeta,
) -> TranslatedOutcome {
    let ha_state = txn_ha_state();
    let mut sessions = SessionTable::new();

    let forwarding1 = build_forwarding_state(&snapshot_phase1);
    let mut binding1 = BindingWorker::new_for_mirror_test(0, 0, ifindex, 0);
    binding1.interface = Arc::<str>::from(iface);
    let (_b1, dbg1) = txn_run_descriptor(
        &mut binding1,
        &mut sessions,
        &forwarding1,
        &ha_state,
        frame_admit,
        meta_admit,
    );
    assert_eq!(
        dbg1.tx, 1,
        "PHASE 1 must ADMIT and forward the translated flow, or every phase-2 \
         assertion is vacuous — nothing would be installed to re-derive (#9382)"
    );
    assert_eq!(
        session_count(&sessions),
        2,
        "PHASE 1 must install the forward + reverse pair (#9382)"
    );

    // A FRESH binding: an empty flow cache, which is what a generation bump
    // leaves behind and what makes phase 2 take the session-hit path.
    let forwarding2 = build_forwarding_state(&snapshot_phase2);
    let mut binding2 = BindingWorker::new_for_mirror_test(0, 0, ifindex, 0);
    binding2.interface = Arc::<str>::from(iface);
    let (_b2, dbg2) = txn_run_descriptor(
        &mut binding2,
        &mut sessions,
        &forwarding2,
        &ha_state,
        frame_established,
        meta_established,
    );
    TranslatedOutcome {
        revoked: dbg2.policy_revoked_sessions,
        sessions: session_count(&sessions),
        session_hit_phase2: dbg2.session_hit,
        tx_phase2: dbg2.tx,
    }
}

const DNAT_CLIENT: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 10);
const DNAT_VIP: Ipv4Addr = Ipv4Addr::new(172, 16, 80, 8);
/// The DNAT fixture translates `172.16.80.8:443` -> `10.0.61.102:8443`, so BOTH
/// the address and the PORT differ pre/post translation. That matters: a fix
/// that carried the translated ADDRESS but left the wire PORT would pass an
/// address-only cell.
const DNAT_REAL: &str = "10.0.61.102/32";
const DNAT_VIP_CIDR: &str = "172.16.80.8/32";
const WAN_INGRESS_IFINDEX: i32 = 12;

/// #9560 round 3: the poll path's REVERSE install publishes entry-level, so a same-key
/// predecessor's rows are released.
///
/// `install_with_protocol_with_origin` silently removes a same-key prior entry. The
/// reverse install used to publish its row through the ROW-level call, which claims the
/// new row and releases nothing — so a predecessor's extra rows stayed claimed by a
/// worker that will never name them again, and nothing could delete them.
///
/// Driven through the REAL poll body (`txn_run_descriptor`) on a session MISS, because
/// that is the only path that reaches the reverse install; the registry assertions are on
/// the owner counts, which is the channel that moves (a recorder-only map records a
/// delete but cannot show a claim that merely persists).
#[test]
/// #9560 round 3, R12: the poll path's FORWARD install must release a predecessor's
/// rows too.
///
/// Measured as a gap before this cell existed: the mutant reverting the forward call
/// site to `publish_live_session_key` SURVIVED a 71-cell run with nothing failing. The
/// forward and reverse installs are two call sites of the same function with DIFFERENT
/// arguments (`&flow.forward_key`/`decision.nat`/`false` vs
/// `&reverse_key`/`reverse_decision.nat`/`true`), not twins — so the reverse cell says
/// nothing about this one, and neither would a cell written against only one of them.
///
/// The assertion is a DECREASE from the seeded count, not an absolute count. What a
/// forward entry-level publish claims is not known here and is deliberately not
/// guessed: an earlier attempt at the reverse site asserted a count I had inferred
/// rather than observed and failed at base. A decrease expresses the release itself,
/// needs no row arithmetic, and does not rot if that arithmetic changes.
#[test]
fn the_poll_paths_forward_install_releases_a_seeded_predecessors_rows_9560() {
    use crate::afxdp::bpf_map::{
        RECORDER_ONLY_MAP_FD, SteeringHolder, SteeringMapRef, SteeringRowOwners,
        publish_live_session_entry,
    };

    // PASS 1 exists only to learn the FORWARD key this flow installs under.
    let forward_key = {
        let owners = std::sync::Arc::new(SteeringRowOwners::default());
        let (syn, meta_syn, _ack, _meta_ack) = dnat_frames();
        let snapshot = inbound_dnat_snapshot(wan_to_lan_permit(DNAT_REAL, "permit-internal"));
        let forwarding = build_forwarding_state(&snapshot);
        let ha_state = txn_ha_state();
        let mut sessions = SessionTable::new();
        let mut binding = BindingWorker::new_for_mirror_test(0, 0, WAN_INGRESS_IFINDEX, 0);
        binding.interface = Arc::<str>::from("reth0.80");
        binding.bpf_maps.session_map = SteeringMapRef::new(
            RECORDER_ONLY_MAP_FD,
            std::sync::Arc::clone(&owners),
            SteeringHolder::Worker(0),
        );
        let (_batch, dbg) = txn_run_descriptor(
            &mut binding,
            &mut sessions,
            &forwarding,
            &ha_state,
            &syn,
            meta_syn,
        );
        assert_eq!(dbg.tx, 1, "FIXTURE: pass 1 must admit the SYN to derive a forward key");
        let mut found: Option<SessionKey> = None;
        sessions.iter_with_origin(|key, _decision, metadata, _origin| {
            if !metadata.is_reverse {
                found = Some(key.clone());
            }
        });
        found.expect("FIXTURE: pass 1 must install a forward session")
    };

    // PASS 2: a PREDECESSOR holds a wider row set at that forward key when the poll
    // path installs over it.
    let owners = std::sync::Arc::new(SteeringRowOwners::default());
    let (syn, meta_syn, _ack, _meta_ack) = dnat_frames();
    let snapshot = inbound_dnat_snapshot(wan_to_lan_permit(DNAT_REAL, "permit-internal"));
    let forwarding = build_forwarding_state(&snapshot);
    let ha_state = txn_ha_state();
    let mut sessions = SessionTable::new();
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, WAN_INGRESS_IFINDEX, 0);
    binding.interface = Arc::<str>::from("reth0.80");
    binding.bpf_maps.session_map = SteeringMapRef::new(
        RECORDER_ONLY_MAP_FD,
        std::sync::Arc::clone(&owners),
        SteeringHolder::Worker(0),
    );

    let _ = publish_live_session_entry(
        binding.bpf_maps.session_map.handle(),
        &forward_key,
        crate::nat::NatDecision {
            rewrite_src: Some(std::net::IpAddr::V4(std::net::Ipv4Addr::new(203, 0, 113, 11))),
            rewrite_src_port: Some(51_009),
            ..crate::nat::NatDecision::default()
        },
        false,
    );
    let seeded = owners.held_row_count(&forward_key, 0);
    assert!(
        seeded > 1,
        "FIXTURE: the predecessor must claim MORE than one row, or a DECREASE below is \
         not observable (held {seeded})"
    );

    let (_batch, dbg) = txn_run_descriptor(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &syn,
        meta_syn,
    );
    assert_eq!(dbg.tx, 1, "FIXTURE: pass 2 must admit the SYN, or nothing installs over the seed");

    let after = owners.held_row_count(&forward_key, 0);
    assert!(
        after < seeded,
        "the poll path's FORWARD install kept every one of the predecessor's claims \
         ({seeded} before, {after} after). An entry-level publish releases the rows its \
         decision does not name; a key-level one claims its own row and leaves the rest \
         owned by a session that no longer exists (#9560 round 3, R12)"
    );
}

/// #9560 round 3, R9: the poll path's reverse install must RELEASE what a same-key
/// PREDECESSOR held — asserted on the release itself, not on a row count.
///
/// The count was only ever a PROXY, and a proxy has a failure mode a direct assertion
/// does not: even where the counts differ they differ INCIDENTALLY, so a later change
/// to how many rows a DNAT reverse entry names would make the cell vacuous again with
/// nobody touching it. Measured on the way here: a reverse entry-level publish claims
/// exactly ONE row, the same as a key-level publish, so no count assertion at this call
/// site can separate the arms at all — which is why the sibling cell below documents
/// that it cannot detect this and defers to here.
///
/// The predecessor is seeded BEFORE the poll path installs, so the release is performed
/// by the CALL SITE. The sibling cell's direct calls to `publish_live_session_entry`
/// exercise the function while bypassing the wiring — testing the transform while the
/// defect lives in the feed.
#[test]
fn the_poll_paths_reverse_install_releases_a_seeded_predecessors_rows_9560() {
    use crate::afxdp::bpf_map::{
        RECORDER_ONLY_MAP_FD, SteeringHolder, SteeringMapRef, SteeringRowOwners,
        publish_live_session_entry,
    };

    // PASS 1 exists only to learn the reverse key this flow derives.
    let reverse_key = {
        let owners = std::sync::Arc::new(SteeringRowOwners::default());
        let (syn, meta_syn, _ack, _meta_ack) = dnat_frames();
        let snapshot = inbound_dnat_snapshot(wan_to_lan_permit(DNAT_REAL, "permit-internal"));
        let forwarding = build_forwarding_state(&snapshot);
        let ha_state = txn_ha_state();
        let mut sessions = SessionTable::new();
        let mut binding = BindingWorker::new_for_mirror_test(0, 0, WAN_INGRESS_IFINDEX, 0);
        binding.interface = Arc::<str>::from("reth0.80");
        binding.bpf_maps.session_map = SteeringMapRef::new(
            RECORDER_ONLY_MAP_FD,
            std::sync::Arc::clone(&owners),
            SteeringHolder::Worker(0),
        );
        let (_batch, dbg) = txn_run_descriptor(
            &mut binding,
            &mut sessions,
            &forwarding,
            &ha_state,
            &syn,
            meta_syn,
        );
        assert_eq!(dbg.tx, 1, "FIXTURE: pass 1 must admit the SYN to derive a reverse key");
        let mut found: Option<SessionKey> = None;
        sessions.iter_with_origin(|key, _decision, metadata, _origin| {
            if metadata.is_reverse {
                found = Some(key.clone());
            }
        });
        found.expect("FIXTURE: pass 1 must install a reverse companion")
    };

    // PASS 2: the same flow, but a PREDECESSOR already holds a WIDER row set at that
    // reverse key when the poll path installs over it.
    let owners = std::sync::Arc::new(SteeringRowOwners::default());
    let (syn, meta_syn, _ack, _meta_ack) = dnat_frames();
    let snapshot = inbound_dnat_snapshot(wan_to_lan_permit(DNAT_REAL, "permit-internal"));
    let forwarding = build_forwarding_state(&snapshot);
    let ha_state = txn_ha_state();
    let mut sessions = SessionTable::new();
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, WAN_INGRESS_IFINDEX, 0);
    binding.interface = Arc::<str>::from("reth0.80");
    binding.bpf_maps.session_map = SteeringMapRef::new(
        RECORDER_ONLY_MAP_FD,
        std::sync::Arc::clone(&owners),
        SteeringHolder::Worker(0),
    );

    let _ = publish_live_session_entry(
        binding.bpf_maps.session_map.handle(),
        &reverse_key,
        crate::nat::NatDecision {
            rewrite_src: Some(std::net::IpAddr::V4(std::net::Ipv4Addr::new(203, 0, 113, 9))),
            rewrite_src_port: Some(51_001),
            ..crate::nat::NatDecision::default()
        },
        false,
    );
    let seeded = owners.held_row_count(&reverse_key, 0);
    assert!(
        seeded > 1,
        "FIXTURE: the predecessor must claim MORE rows than a reverse entry names, or \
         the release below has nothing to observe (held {seeded})"
    );

    let (_batch, dbg) = txn_run_descriptor(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &syn,
        meta_syn,
    );
    assert_eq!(dbg.tx, 1, "FIXTURE: pass 2 must admit the SYN, or nothing installs over the seed");

    assert_eq!(
        owners.held_row_count(&reverse_key, 0),
        1,
        "the poll path's reverse install KEPT the predecessor's extra claims. An \
         entry-level publish releases the rows its decision does not name; a key-level \
         one claims its own row and leaves the rest owned by a session that no longer \
         exists, so nothing will ever release them (#9560 round 3)"
    );
}

fn the_poll_paths_reverse_install_releases_a_predecessors_rows_9560() {
    use crate::afxdp::bpf_map::{
        RECORDER_ONLY_MAP_FD, SteeringHolder, SteeringMapRef, SteeringRowOwners,
        publish_live_session_entry, session_map_row,
    };

    let owners = std::sync::Arc::new(SteeringRowOwners::default());
    let (syn, meta_syn, _ack, _meta_ack) = dnat_frames();
    let snapshot = inbound_dnat_snapshot(wan_to_lan_permit(DNAT_REAL, "permit-internal"));
    let forwarding = build_forwarding_state(&snapshot);
    let ha_state = txn_ha_state();
    let mut sessions = SessionTable::new();

    let mut binding = BindingWorker::new_for_mirror_test(0, 0, WAN_INGRESS_IFINDEX, 0);
    binding.interface = Arc::<str>::from("reth0.80");
    binding.bpf_maps.session_map = SteeringMapRef::new(
        RECORDER_ONLY_MAP_FD,
        std::sync::Arc::clone(&owners),
        SteeringHolder::Worker(0),
    );

    let (_batch, dbg) = txn_run_descriptor(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &syn,
        meta_syn,
    );
    assert_eq!(
        dbg.tx, 1,
        "fixture: the SYN must be admitted and forwarded, or no reverse companion is \
         installed and every assertion below is vacuous"
    );
    assert_eq!(
        session_count(&sessions),
        2,
        "fixture: admission must install the forward AND its reverse companion"
    );

    // The reverse companion's key, as the poll path derived it: the one row a reverse
    // entry names. Its claim is what the entry-level publish records.
    let mut reverse_key: Option<SessionKey> = None;
    sessions.iter_with_origin(|key, _decision, metadata, _origin| {
        if metadata.is_reverse {
            reverse_key = Some(key.clone());
        }
    });
    let reverse_key = reverse_key.expect("fixture: the reverse companion must be in the table");
    // KNOWN GAP, stated rather than papered over (#9560 round 3, R9).
    //
    // This assertion CANNOT detect a revert of the poll path's reverse install to a
    // key-level publish, and neither can any other assertion in this cell. Measured
    // twice: the mutant survives, and an attempt to strengthen this to `> 1` FAILED AT
    // BASE — a reverse entry-level publish claims exactly ONE row, which is also what a
    // key-level publish claims. Row count is the wrong observable here; the two arms
    // agree on it by construction.
    //
    // The only property that separates them is the RELEASE of a predecessor's rows, and
    // the rest of this cell exercises that through DIRECT calls to
    // publish_live_session_entry, which bypass the call site entirely — it tests the
    // transform while the defect lives in the feed.
    //
    // CLOSED by a different cell rather than a stronger assertion here:
    // `the_poll_paths_reverse_install_releases_a_seeded_predecessors_rows_9560` seeds a
    // WIDER claim at the reverse key BEFORE the poll path installs, then asserts the
    // install released the rows its decision does not name. That is the release
    // semantics themselves rather than a count standing in for them — a count would
    // have been a proxy that could rot silently if the row arithmetic ever changed.
    assert!(
        owners.held_row_count(&reverse_key, 0) >= 1,
        "the reverse install claimed nothing, so its row is unowned and an aliased \
         session's teardown deletes it while this session still needs it (#9560)"
    );

    // A predecessor at the SAME key with a wider row set: publishing the reverse entry
    // over it must RELEASE what the new decision does not name.
    let extra = SessionKey {
        src_port: reverse_key.src_port.wrapping_add(7),
        ..reverse_key.clone()
    };
    let _ = publish_live_session_entry(
        binding.bpf_maps.session_map.handle(),
        &reverse_key,
        crate::nat::NatDecision {
            rewrite_src: Some(std::net::IpAddr::V4(std::net::Ipv4Addr::new(203, 0, 113, 9))),
            rewrite_src_port: Some(51_001),
            ..crate::nat::NatDecision::default()
        },
        false,
    );
    let widened = owners.held_row_count(&reverse_key, 0);
    assert!(
        widened > 1,
        "fixture: the predecessor publish must claim MORE rows than a reverse entry \
         names, or the release below has nothing to observe (held {widened})"
    );
    let _ = extra;

    let _ = publish_live_session_entry(
        binding.bpf_maps.session_map.handle(),
        &reverse_key,
        crate::nat::NatDecision::default(),
        true,
    );
    assert_eq!(
        owners.held_row_count(&reverse_key, 0),
        1,
        "a same-key reverse publish kept claims on rows its decision does not name; \
         nothing will ever name them again (#9560 round 3). Row: {:?}",
        session_map_row(&reverse_key)
    );
}

fn dnat_frames() -> (Vec<u8>, UserspaceDpMeta, Vec<u8>, UserspaceDpMeta) {
    let syn = build_txn_tcp_syn_frame_v4(DNAT_CLIENT, DNAT_VIP, 54321, 443, TCP_FLAG_SYN);
    let meta_syn = txn_meta_v4(WAN_INGRESS_IFINDEX as u32, TCP_FLAG_SYN, syn.len() as u16);
    let ack = build_txn_tcp_syn_frame_v4(DNAT_CLIENT, DNAT_VIP, 54321, 443, TCP_ACK);
    let meta_ack = txn_meta_v4(WAN_INGRESS_IFINDEX as u32, TCP_ACK, ack.len() as u16);
    (syn, meta_syn, ack, meta_ack)
}

/// THE DOMINANT, ORDINARY-OPERATIONS CASE, and it is FAIL-CLOSED. The policy is
/// byte-identical across the generation bump — the SAME permit that admitted the
/// flow, naming the real server — so nothing may be revoked.
///
/// Before the fix this revoked and dropped the packet: the re-derivation asked
/// whether policy permits traffic to the VIP `172.16.80.8:443`, which is
/// precisely the rule admission REFUSES to match
/// (`policy_inbound_dnat_denies_when_only_original_dst_permitted`), found
/// nothing, and fell to `default_policy: deny`. Every published DNAT service on
/// the box lost its live sessions on the next route event.
#[test]
fn an_unchanged_dnat_policy_does_not_revoke_the_established_session_9382() {
    let (syn, meta_syn, ack, meta_ack) = dnat_frames();
    let out = admit_then_one_more_packet(
        inbound_dnat_snapshot(wan_to_lan_permit(DNAT_REAL, "permit-internal")),
        inbound_dnat_snapshot(wan_to_lan_permit(DNAT_REAL, "permit-internal")),
        WAN_INGRESS_IFINDEX,
        "reth0.80",
        &syn,
        meta_syn,
        &ack,
        meta_ack,
    );
    assert_eq!(
        out.session_hit_phase2, 1,
        "phase 2 must HIT the installed session, or the revoke assertion below \
         is vacuous (#9382)"
    );
    assert_eq!(
        out.revoked, 0,
        "the policy is UNCHANGED and names the real server 10.0.61.102 — the \
         same rule that admitted this flow. A non-zero count means the \
         re-derivation judged the PRE-translation VIP 172.16.80.8, which is the \
         rule admission refuses, so it found nothing and fell to default-deny: \
         every published DNAT/NPTv6 service loses its live sessions on the next \
         route event, with the policy untouched (#9382)"
    );
    assert_eq!(
        out.sessions, 2,
        "the forward + reverse pair must survive an unchanged policy"
    );
    assert_eq!(out.tx_phase2, 1, "and the packet must still be forwarded");
}

/// THE LOAD-BEARING CONTROL. Same phase 1, but phase 2's policy genuinely no
/// longer covers the flow — the permit now names an unrelated internal host.
///
/// Without this cell, "never revoke a session that has a destination
/// translation" passes the cell above perfectly while silently exempting every
/// DNAT'd service from zone-policy re-derivation altogether. That is a worse bug
/// than the one #9382 fixes, and this is the only cell that can see it.
#[test]
fn a_genuinely_narrowed_dnat_policy_still_revokes_9382() {
    let (syn, meta_syn, ack, meta_ack) = dnat_frames();
    let out = admit_then_one_more_packet(
        inbound_dnat_snapshot(wan_to_lan_permit(DNAT_REAL, "permit-internal")),
        inbound_dnat_snapshot(wan_to_lan_permit("10.0.61.200/32", "permit-someone-else")),
        WAN_INGRESS_IFINDEX,
        "reth0.80",
        &syn,
        meta_syn,
        &ack,
        meta_ack,
    );
    assert_eq!(out.session_hit_phase2, 1, "phase 2 must hit the session");
    assert_eq!(
        out.revoked, 1,
        "the live policy no longer covers 10.0.61.102, so the session MUST be \
         revoked. 0 here means the translated-destination fix degenerated into \
         'translated sessions are never re-derived' (#9382)"
    );
    assert_eq!(out.sessions, 0, "the revoked pair must be torn down");
}

/// THE FAIL-OPEN DIRECTION, closed. A DENY naming the REAL server, ahead of a
/// permit-any, must revoke.
///
/// Before the fix this was missed: the re-derivation compared the VIP against a
/// deny written for `10.0.61.102`, did not match, fell through to the permit-any
/// and kept the session — so an operator's deny against a published service's
/// real address did not take effect on live traffic.
#[test]
fn a_deny_naming_the_translated_destination_revokes_9382() {
    let (syn, meta_syn, ack, meta_ack) = dnat_frames();
    let mut deny_real = wan_to_lan_permit(DNAT_REAL, "deny-internal");
    deny_real.action = "deny".to_string();
    let mut phase2 = inbound_dnat_snapshot(deny_real);
    // A trailing permit-any so the ONLY thing that can revoke is the deny
    // matching the POST-translation destination — not the default policy.
    phase2.policies.push(wan_to_lan_permit("any", "permit-rest"));
    let out = admit_then_one_more_packet(
        inbound_dnat_snapshot(wan_to_lan_permit(DNAT_REAL, "permit-internal")),
        phase2,
        WAN_INGRESS_IFINDEX,
        "reth0.80",
        &syn,
        meta_syn,
        &ack,
        meta_ack,
    );
    assert_eq!(out.session_hit_phase2, 1, "phase 2 must hit the session");
    assert_eq!(
        out.revoked, 1,
        "a deny naming the REAL server 10.0.61.102, ahead of a permit-any, must \
         revoke. 0 means the derivation compared the VIP, missed the deny and \
         fell through to the permit — the fail-OPEN half of #9382"
    );
    assert_eq!(out.sessions, 0, "the denied pair must be torn down");
}

/// THE CELL THAT PINS THE EVALUATED TUPLE EXACTLY, and it is the inverse of the
/// one above. A DENY naming ONLY the PRE-translation VIP must NOT revoke,
/// because the VIP is not the address policy judges — admission refuses a rule
/// written against it, so a deny written against it must be equally inert.
///
/// This is the sharpest cell in the group: it fails in OPPOSITE directions
/// before and after the fix (before: revoked 1, because the wire dst IS the VIP;
/// after: revoked 0), so it cannot be satisfied by any constant.
#[test]
fn a_deny_naming_only_the_pre_translation_vip_does_not_revoke_9382() {
    let (syn, meta_syn, ack, meta_ack) = dnat_frames();
    let mut deny_vip = wan_to_lan_permit(DNAT_VIP_CIDR, "deny-public-vip");
    deny_vip.action = "deny".to_string();
    let mut phase2 = inbound_dnat_snapshot(deny_vip);
    phase2
        .policies
        .push(wan_to_lan_permit(DNAT_REAL, "permit-internal"));
    let out = admit_then_one_more_packet(
        inbound_dnat_snapshot(wan_to_lan_permit(DNAT_REAL, "permit-internal")),
        phase2,
        WAN_INGRESS_IFINDEX,
        "reth0.80",
        &syn,
        meta_syn,
        &ack,
        meta_ack,
    );
    assert_eq!(out.session_hit_phase2, 1, "phase 2 must hit the session");
    assert_eq!(
        out.revoked, 0,
        "a deny naming only the PRE-translation VIP must be inert, exactly as \
         admission treats a permit written against it. A non-zero count means \
         the evaluated destination is still the wire tuple (#9382)"
    );
    assert_eq!(out.sessions, 2, "the session must survive an inert deny");
}

/// A SECOND TRANSLATION KIND and a second address family: NPTv6 maps the
/// external prefix `2602:fd41:70::/48` to the internal `fd35:1940:27::/48`. The
/// policy is unchanged and names the INTERNAL prefix — the one admission
/// matches — so nothing may be revoked.
///
/// Not redundant with the DNAT cells: NPTv6 arrives at `decision.nat` by a
/// different route (`nptv6_nat`, a prefix rewrite with NO port rewrite), so a fix
/// that read only the DNAT decision would pass the DNAT cells and fail here.
#[test]
fn an_unchanged_nptv6_policy_does_not_revoke_the_established_session_9382() {
    let src: Ipv6Addr = "2001:559:8585:80::200".parse().expect("ext client");
    let dst: Ipv6Addr = "2602:fd41:70:100::102".parse().expect("external prefix dst");
    let syn = build_txn_tcp_frame_v6(src, dst, 54321, 443, TCP_FLAG_SYN);
    let mut meta_syn = txn_meta_v6(WAN_INGRESS_IFINDEX as u32, syn.len());
    meta_syn.tcp_flags = TCP_FLAG_SYN;
    let ack = build_txn_tcp_frame_v6(src, dst, 54321, 443, TCP_ACK);
    let mut meta_ack = txn_meta_v6(WAN_INGRESS_IFINDEX as u32, ack.len());
    meta_ack.tcp_flags = TCP_ACK;

    let out = admit_then_one_more_packet(
        inbound_nptv6_snapshot(wan_to_lan_permit("fd35:1940:27::/48", "permit-internal-prefix")),
        inbound_nptv6_snapshot(wan_to_lan_permit("fd35:1940:27::/48", "permit-internal-prefix")),
        WAN_INGRESS_IFINDEX,
        "reth0.80",
        &syn,
        meta_syn,
        &ack,
        meta_ack,
    );
    assert_eq!(out.session_hit_phase2, 1, "phase 2 must hit the session");
    assert_eq!(
        out.revoked, 0,
        "the policy is unchanged and names the INTERNAL prefix admission \
         matches. A non-zero count means the re-derivation judged the EXTERNAL \
         prefix the packet carried on the wire (#9382)"
    );
    assert_eq!(out.sessions, 2, "the NPTv6 pair must survive");
}

/// NAT64, AND IT MUST BE THE MIXED-FAMILY DESTINATION SET. This is the cell the
/// issue insists on, because the v4-only shape passes TODAY FOR THE WRONG
/// REASON: a destination set with no IPv6 member compiles to IPv6-match-any (the
/// legacy address-set convention), so the synthetic v6 wire destination matches
/// on the match-any path and the broken derivation looks correct.
///
/// Giving the rule a v6 member that does NOT cover `64:ff9b::/96` removes that
/// accident. The rule then names the REAL IPv4 server `8.8.8.8` — which is
/// exactly what #2358 tells operators to write — so admission matches it on the
/// cross-family (V6 src, V4 dst) arm, and the re-derivation must reach the same
/// verdict through `decision.nat.rewrite_dst`, the extracted IPv4 target.
#[test]
fn an_unchanged_nat64_policy_with_a_mixed_family_destination_set_does_not_revoke_9382() {
    let src: Ipv6Addr = "2001:559:8585:ef00::102".parse().expect("v6 client");
    let dst: Ipv6Addr = "64:ff9b::808:808".parse().expect("nat64 synthetic dst");
    let syn = build_txn_tcp_frame_v6(src, dst, 12345, 443, TCP_FLAG_SYN);
    let mut meta_syn = txn_meta_v6(LAN_IFINDEX as u32, syn.len());
    meta_syn.tcp_flags = TCP_FLAG_SYN;
    let ack = build_txn_tcp_frame_v6(src, dst, 12345, 443, TCP_ACK);
    let mut meta_ack = txn_meta_v6(LAN_IFINDEX as u32, ack.len());
    meta_ack.tcp_flags = TCP_ACK;

    let mixed = || {
        let mut rule = lan_to_wan_permit("8.8.8.8/32", "permit-real-v4-server");
        // The v6 member is what defeats the IPv6-match-any accident. It must
        // NOT cover 64:ff9b::/96 — if it did, the synthetic wire destination
        // would match it and the cell would pass whether the fix exists or not.
        rule.destination_addresses
            .push("2001:db8::/32".to_string());
        nat64_snapshot(rule)
    };
    let out = admit_then_one_more_packet(
        mixed(),
        mixed(),
        LAN_IFINDEX,
        "reth1.0",
        &syn,
        meta_syn,
        &ack,
        meta_ack,
    );
    assert_eq!(out.session_hit_phase2, 1, "phase 2 must hit the session");
    assert_eq!(
        out.revoked, 0,
        "the rule names the REAL IPv4 server 8.8.8.8 — the tuple #2358 has \
         admission match — and carries a v6 member so the destination set is no \
         longer IPv6-match-any. A non-zero count means the re-derivation judged \
         the SYNTHETIC v6 destination, which matches nothing here (#9382)"
    );
    assert_eq!(out.sessions, 2, "the NAT64 pair must survive");
}

// ---------------------------------------------------------------------------
// #9384: the FROM-zone is resolved LIVE from this packet's arrival interface.
// ---------------------------------------------------------------------------
//
// The re-derivation used to be handed `Some(metadata.ingress_zone)` as the
// from-zone override, which WINS over the live ingress map
// (`forwarding/mod.rs`). So it resolved the to-zone live and the from-zone from
// the ENTRY, and the module header's coverage claim — "a commit that moves an
// interface BETWEEN ZONES is caught" — was true of the EGRESS half only. An
// operator moving an interface OUT of a permitted zone to cut off access got the
// new verdict for NEW flows while every live session kept being judged under the
// zone it was admitted in, was stamped fresh, and kept forwarding.
//
// The generation question is settled and is not what was missing: every commit
// goes through `Compile`, which takes its generation from `m.bumpGeneration()`
// unconditionally, so a zone-membership edit DOES bump the generation and the
// re-derivation DOES run — with the stale from-zone. Go's commit-time
// invalidation cannot cover it either: it compares policy match/action text and
// referenced-object fingerprints and never diffs zone MEMBERSHIP.
//
// WHY THE SHIPPED #8356 CELLS COULD NOT SEE IT. `metadata(is_reverse)` hard-codes
// `ingress_zone: TEST_LAN_ZONE_ID` AND leaves `reth1.0` in `lan` in the snapshot.
// Entry zone and live interface zone were never allowed to DISAGREE, so the
// override was unobservable.
//
// THE SHAPE OF THE GROUP. Two axes, varied independently: where the ENTRY says
// the session came from, and where the live config says the arrival interface
// now is. The cell that matters is the one where they DISAGREE and the live zone
// is not permitted. The two cells where they AGREE are what stop the fix from
// degenerating into "always revoke", and the cell where they disagree but the
// live zone IS permitted is what stops it degenerating into "revoke on any
// disagreement".

/// `policy_deny_snapshot` with its built-in `dmz -> wan` permit REMOVED, the
/// ingress interface `reth1.0` placed in `ingress_zone`, and `lan -> wan`
/// permitted iff `permit_lan`.
///
/// The built-in `dmz -> wan` permit has to go: with it, moving `reth1.0` into
/// `dmz` lands in a zone that IS permitted, so the live pair would be admitted
/// and the cell could not observe the move at all. Removing it is what makes
/// `dmz` the "moved somewhere with no permit" zone.
fn forwarding_with_ingress_zone_9384(ingress_zone: &str, permit_lan: bool) -> ForwardingState {
    let mut snapshot = policy_deny_snapshot();
    snapshot.generation = 7;
    snapshot.fib_generation = 9;
    snapshot.policies.clear();
    for iface in snapshot.interfaces.iter_mut() {
        if iface.ifindex == LAN_IFINDEX {
            iface.zone = ingress_zone.to_string();
        }
    }
    if permit_lan {
        snapshot.policies.push(PolicyRuleSnapshot {
            name: "lan-out".into(),
            from_zone: "lan".into(),
            to_zone: "wan".into(),
            source_addresses: vec!["any".into()],
            destination_addresses: vec!["any".into()],
            applications: vec!["any".into()],
            application_terms: Vec::new(),
            action: "permit".into(),
            ..Default::default()
        });
    }
    build_forwarding_state(&snapshot)
}

/// Install ONE established session whose ENTRY records `entry_ingress_zone`, then
/// drive one packet of it arriving on `reth1.0` — which the live config now
/// places in `live_ingress_zone`.
fn drive_moved_interface_9384(
    entry_ingress_zone: u16,
    live_ingress_zone: &str,
    permit_lan: bool,
) -> Outcome {
    let forwarding = forwarding_with_ingress_zone_9384(live_ingress_zone, permit_lan);
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, LAN_IFINDEX, 0);
    binding.interface = Arc::<str>::from("reth1.0");
    let ha_state = txn_ha_state();

    let mut sessions = SessionTable::new();
    let metadata = SessionMetadata {
        ingress_zone: entry_ingress_zone,
        egress_zone: TEST_WAN_ZONE_ID,
        ..metadata(false)
    };
    assert!(
        sessions.install_with_protocol_with_origin(
            flow_key_to(DST),
            decision(WAN_IFINDEX),
            metadata,
            SessionOrigin::ForwardFlow,
            122_000_000_000,
            PROTO_TCP,
            0,
        ),
        "the fixture must install the session, or every assertion below is vacuous"
    );

    let frame = build_txn_tcp_syn_frame_v4(SRC, DST, SPORT, DPORT, TCP_ACK);
    let meta = txn_meta_v4(LAN_IFINDEX as u32, TCP_ACK, frame.len() as u16);
    let (_batch, dbg) = txn_run_descriptor(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame,
        meta,
    );
    assert_eq!(
        dbg.session_hit, 1,
        "the packet must HIT the installed session, or the revoke assertion is \
         vacuous (#9384)"
    );
    Outcome {
        sessions,
        revoked: dbg.policy_revoked_sessions,
    }
}

/// THE DEFECT. The session was admitted when `reth1.0` was in `lan`; the operator
/// has since MOVED it into `dmz`, and only `lan -> wan` is permitted.
///
/// Before #9384 the entry's `lan` won as the from-zone override, the pair
/// evaluated was still `lan -> wan`, the session was judged permitted and
/// re-stamped, and it kept forwarding — so a security-intent operation silently
/// did not take effect on live traffic.
#[test]
fn an_ingress_side_interface_zone_move_revokes_the_established_session_9384() {
    let out = drive_moved_interface_9384(TEST_LAN_ZONE_ID, "dmz", true);
    assert_eq!(
        out.revoked, 1,
        "the arrival interface now lives in `dmz` and only `lan -> wan` is \
         permitted, so the live pair `dmz -> wan` is not admitted and the session \
         MUST be revoked. 0 means the from-zone still came from the session ENTRY, \
         so an operator who moved an interface out of a permitted zone to cut off \
         access cut off new flows only (#9384)"
    );
    assert_eq!(
        session_count(&out.sessions),
        0,
        "the moved interface's session must be torn down, not merely counted"
    );
}

/// CONTROL 1, and it is the one that stops "revoke on any disagreement". The
/// interface moved, entry and live zone DISAGREE exactly as above, but the zone
/// it moved INTO is permitted — `lan -> wan` is gone and `dmz -> wan` is the
/// permit. Nothing may be revoked.
#[test]
fn a_move_into_a_still_permitted_zone_does_not_revoke_9384() {
    let forwarding = {
        let mut snapshot = policy_deny_snapshot();
        snapshot.generation = 7;
        snapshot.fib_generation = 9;
        snapshot.policies.clear();
        for iface in snapshot.interfaces.iter_mut() {
            if iface.ifindex == LAN_IFINDEX {
                iface.zone = "dmz".to_string();
            }
        }
        snapshot.policies.push(PolicyRuleSnapshot {
            name: "dmz-out".into(),
            from_zone: "dmz".into(),
            to_zone: "wan".into(),
            source_addresses: vec!["any".into()],
            destination_addresses: vec!["any".into()],
            applications: vec!["any".into()],
            application_terms: Vec::new(),
            action: "permit".into(),
            ..Default::default()
        });
        build_forwarding_state(&snapshot)
    };
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, LAN_IFINDEX, 0);
    binding.interface = Arc::<str>::from("reth1.0");
    let ha_state = txn_ha_state();
    let mut sessions = SessionTable::new();
    // The ENTRY still says `lan` — the session predates the move.
    let metadata = SessionMetadata {
        ingress_zone: TEST_LAN_ZONE_ID,
        egress_zone: TEST_WAN_ZONE_ID,
        ..metadata(false)
    };
    assert!(sessions.install_with_protocol_with_origin(
        flow_key_to(DST),
        decision(WAN_IFINDEX),
        metadata,
        SessionOrigin::ForwardFlow,
        122_000_000_000,
        PROTO_TCP,
        0,
    ));
    let frame = build_txn_tcp_syn_frame_v4(SRC, DST, SPORT, DPORT, TCP_ACK);
    let meta = txn_meta_v4(LAN_IFINDEX as u32, TCP_ACK, frame.len() as u16);
    let (_batch, dbg) = txn_run_descriptor(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame,
        meta,
    );
    assert_eq!(dbg.session_hit, 1, "the packet must hit the session");
    assert_eq!(
        dbg.policy_revoked_sessions, 0,
        "the interface moved, so entry and live zone DISAGREE — but the zone it \
         moved into IS permitted, so the live pair `dmz -> wan` is admitted and \
         nothing may be revoked. A non-zero count means the fix revokes on \
         DISAGREEMENT rather than on the live VERDICT (#9384)"
    );
    assert_eq!(
        session_count(&sessions),
        1,
        "a session whose new zone is still permitted must survive"
    );
}

/// CONTROL 2: entry and live zone AGREE and the pair is permitted. Nothing may be
/// revoked. This is what "always revoke" fails.
#[test]
fn an_unmoved_interface_in_a_permitted_zone_survives_9384() {
    let out = drive_moved_interface_9384(TEST_LAN_ZONE_ID, "lan", true);
    assert_eq!(
        out.revoked, 0,
        "entry and live zone agree and `lan -> wan` is permitted; nothing may be \
         revoked. A non-zero count means the live-from-zone resolution revokes \
         unconditionally (#9384)"
    );
    assert_eq!(session_count(&out.sessions), 1);
}

/// CONTROL 3, the harness control: entry and live zone AGREE on a zone that is
/// NOT permitted. This is the row that proves the fixture and the harness can
/// observe a revocation for this zone pair at all — without it, the defect cell's
/// `revoked == 1` could be read as "something else in this fixture revokes".
#[test]
fn an_unmoved_interface_in_an_unpermitted_zone_revokes_9384() {
    let out = drive_moved_interface_9384(TEST_DMZ_ZONE_ID, "dmz", true);
    assert_eq!(
        out.revoked, 1,
        "entry and live zone agree on `dmz`, which is not permitted — the \
         harness must see a revocation for this pair"
    );
    assert_eq!(session_count(&out.sessions), 0);
}

/// #9513 RE-ANCHORED — and this cell did the job it was written for. #9384 landed
/// it as an explicit CHANGE DETECTOR pinning a residual: an interface moved out
/// of EVERY zone DECLINED rather than revoking, because the arm treated a zero
/// zone as a lookup failure. Its doc said "a future change to it is deliberate
/// and visible". #9513 is that change, and this is the cell that made it visible.
///
/// The #9384 rationale it recorded is now RETRACTED as too pessimistic, and the
/// retraction is scoped to the half that was wrong. It claimed closing the
/// residual "would mean distinguishing 'this interface is deliberately unzoned'
/// from 'the ledger has no row yet', which the snapshot does not currently
/// express". The snapshot does not need to: the poll path already carries the
/// distinction as `arrival_logical == 0` versus a resolved ifindex whose zone is
/// 0. The other half of that rationale — that revoking on a genuine lookup
/// failure is a mass-teardown risk — was right, and is now carried by
/// `an_egress_that_does_not_resolve_at_all_still_declines_9513` and by the cell
/// below.
#[test]
fn an_ingress_moved_to_no_zone_is_re_judged_rather_than_skipped_9513() {
    let out = drive_moved_interface_9384(TEST_LAN_ZONE_ID, "", true);
    assert_eq!(
        out.revoked, 1,
        "the arrival interface RESOLVES but the box puts it in no zone, so a new \
         flow arriving on it would fall to the default policy — #6682 refuses to \
         admit transit from an unzoned ingress at all. An established flow must be \
         judged the same way. 0 here means #9384's live from-zone is still being \
         swallowed by the zero-zone decline on exactly the operator action #9384 \
         exists to catch (#9513)"
    );
    assert_eq!(
        session_count(&out.sessions),
        0,
        "the session arriving on the de-zoned interface must be torn down"
    );
}

/// THE INGRESS-SIDE lookup-failure control, symmetric with the egress one. A
/// packet with NO arrival interface identity at all must still DECLINE.
///
/// `meta.ingress_ifindex == 0` makes `arrival_logical` 0, which is the ingress
/// half of the #9513 split. Deleting that half reds this and nothing else, and
/// without it "re-judge a zero ingress zone" would be indistinguishable from
/// "revoke whenever the arrival cannot be identified".
#[test]
fn an_arrival_with_no_interface_identity_still_declines_9513() {
    let forwarding = forwarding_with_ingress_zone_9384("lan", true);
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, LAN_IFINDEX, 0);
    binding.interface = Arc::<str>::from("reth1.0");
    let ha_state = txn_ha_state();
    let mut sessions = SessionTable::new();
    // The ENTRY records a zone, so a derivation that reached evaluation would
    // have a pair to judge; only the ARRIVAL identity is missing.
    let metadata = SessionMetadata {
        ingress_zone: TEST_LAN_ZONE_ID,
        egress_zone: TEST_WAN_ZONE_ID,
        ..metadata(false)
    };
    assert!(sessions.install_with_protocol_with_origin(
        flow_key_to(DST),
        decision(WAN_IFINDEX),
        metadata,
        SessionOrigin::ForwardFlow,
        122_000_000_000,
        PROTO_TCP,
        0,
    ));
    let frame = build_txn_tcp_syn_frame_v4(SRC, DST, SPORT, DPORT, TCP_ACK);
    // ifindex 0: no arrival interface identity at all.
    let meta = txn_meta_v4(0, TCP_ACK, frame.len() as u16);
    let (_batch, dbg) = txn_run_descriptor(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame,
        meta,
    );
    assert_eq!(
        dbg.policy_revoked_sessions, 0,
        "an arrival with no interface identity is a LOOKUP FAILURE, not an \
         unzoned interface, and must DECLINE (#9513)"
    );
    assert_eq!(session_count(&sessions), 1, "the session must survive");
}

// ---------------------------------------------------------------------------
// #9381 relay: does `default-policy reject` make the revoke arm INERT?
// ---------------------------------------------------------------------------
//
// A concern was raised on #9381 that the defect might be WIDER than its title —
// that a box configured `set security policies default-policy reject` could make
// the whole revoke arm inert appliance-wide — with the counter-intuition that
// under default-reject one would expect OVER-revocation, not inertness.
//
// Both halves of that are right, about different tenses, and the cell below is
// what settles it rather than arguing it:
//
//   * `default_policy` is parsed by the SAME `parse_action` as a rule's action
//     (`policy.rs`), so `"reject"` yields `PolicyAction::Reject` as
//     `state.default_action`. Every flow matching no rule therefore gets a
//     REJECT verdict, not a DENY one.
//   * PRE-#9381, the arm read `!matches!(result.action, Deny)`, so every one of
//     those sessions took the PERMIT exit and was STAMPED revalidated. On a
//     default-reject box that is the entire default-verdict population — which
//     IS strictly wider than #9381's title, which named only a rule narrowed
//     `permit` -> `reject`.
//   * POST-#9381 the predicate is `matches!(.., Permit)`, so the same sessions
//     revoke exactly as they do under default-DENY. That is the over-revocation
//     the counter-intuition expected, and it is the correct verdict: nothing
//     permits those flows.
//
// So the concern describes a real, larger consequence of the SAME one-token
// defect, already closed by #9381 — not a residual and not a separate defect.
// This cell exists because #9381's own cells sampled the terminal-action axis
// only through an explicit RULE, and the default-verdict path reaches
// `evaluate_policy_result_with_icmp`'s default-counter exit rather than
// `try_match_rule`. Those are two different code paths to the same predicate.

/// The `default-policy reject` shape. No `lan -> wan` rule at all, and the
/// implicit default is REJECT rather than DENY, so the live verdict for this
/// established session is a default-policy `Reject`.
///
/// FAIL-ON-REVERT for #9381 through the DEFAULT path: restore
/// `!matches!(result.action, PolicyAction::Deny)` and this goes red alongside
/// the explicit-rule cell, which is the measurement that says the two paths
/// share one predicate.
#[test]
fn a_default_policy_of_reject_still_revokes_the_established_session_9381() {
    let forwarding = {
        let mut snapshot = policy_deny_snapshot();
        snapshot.generation = 7;
        snapshot.fib_generation = 9;
        // The whole point: the IMPLICIT default is reject, not deny.
        snapshot.default_policy = "reject".to_string();
        snapshot.policies.clear();
        build_forwarding_state(&snapshot)
    };
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, LAN_IFINDEX, 0);
    binding.interface = Arc::<str>::from("reth1.0");
    let ha_state = txn_ha_state();
    let mut sessions = SessionTable::new();
    assert!(sessions.install_with_protocol_with_origin(
        flow_key_to(DST),
        decision(WAN_IFINDEX),
        metadata(false),
        SessionOrigin::ForwardFlow,
        122_000_000_000,
        PROTO_TCP,
        0,
    ));
    let frame = build_txn_tcp_syn_frame_v4(SRC, DST, SPORT, DPORT, TCP_ACK);
    let meta = txn_meta_v4(LAN_IFINDEX as u32, TCP_ACK, frame.len() as u16);
    let (_batch, dbg) = txn_run_descriptor(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame,
        meta,
    );
    assert_eq!(
        dbg.session_hit, 1,
        "the packet must HIT the session, or the assertion below is vacuous"
    );
    assert_eq!(
        dbg.policy_revoked_sessions, 1,
        "an IMPLICIT default-policy verdict of `reject` is terminal \
         non-forwarding exactly as an explicit rule's `reject` is, and must \
         revoke. 0 here is the pre-#9381 state, and on a `default-policy reject` \
         box that is not one rule's worth of sessions — it is the whole \
         default-verdict population, which is strictly wider than #9381's title \
         claimed (#9381)"
    );
    assert_eq!(
        session_count(&sessions),
        0,
        "the session must be torn down, not merely counted"
    );
}

/// The CONTROL for the cell above. Same `default-policy reject` snapshot, but
/// `lan -> wan` IS permitted, so the default is never reached.
///
/// Without it, "revoked == 1" above is satisfied by a box that revokes every
/// session whenever the default action is non-permit, regardless of whether a
/// rule admits the flow — which would tear down every permitted session on a
/// default-reject appliance.
#[test]
fn a_default_policy_of_reject_does_not_revoke_a_permitted_flow_9381() {
    let forwarding = {
        let mut snapshot = policy_deny_snapshot();
        snapshot.generation = 7;
        snapshot.fib_generation = 9;
        snapshot.default_policy = "reject".to_string();
        snapshot.policies.clear();
        snapshot.policies.push(PolicyRuleSnapshot {
            name: "lan-out".into(),
            from_zone: "lan".into(),
            to_zone: "wan".into(),
            source_addresses: vec!["any".into()],
            destination_addresses: vec!["any".into()],
            applications: vec!["any".into()],
            application_terms: Vec::new(),
            action: "permit".into(),
            ..Default::default()
        });
        build_forwarding_state(&snapshot)
    };
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, LAN_IFINDEX, 0);
    binding.interface = Arc::<str>::from("reth1.0");
    let ha_state = txn_ha_state();
    let mut sessions = SessionTable::new();
    assert!(sessions.install_with_protocol_with_origin(
        flow_key_to(DST),
        decision(WAN_IFINDEX),
        metadata(false),
        SessionOrigin::ForwardFlow,
        122_000_000_000,
        PROTO_TCP,
        0,
    ));
    let frame = build_txn_tcp_syn_frame_v4(SRC, DST, SPORT, DPORT, TCP_ACK);
    let meta = txn_meta_v4(LAN_IFINDEX as u32, TCP_ACK, frame.len() as u16);
    let (_batch, dbg) = txn_run_descriptor(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame,
        meta,
    );
    assert_eq!(dbg.session_hit, 1, "the packet must hit the session");
    assert_eq!(
        dbg.policy_revoked_sessions, 0,
        "an explicit permit matches, so the `reject` default is never reached \
         and nothing may be revoked. A non-zero count means a default-reject \
         appliance tears down every established session on the first packet \
         after any commit (#9381)"
    );
    assert_eq!(session_count(&sessions), 1);
}

// ---------------------------------------------------------------------------
// #9385: the re-derivation records NO policy hit.
// ---------------------------------------------------------------------------
//
// The module header used to state side-effect freedom as a STRUCTURAL property:
// `evaluate_policy_result_with_icmp` "takes `&PolicyState` and RETURNS a counter
// handle ...; it cannot count, log or meter by itself." True of the HANDLE,
// false of the EVALUATION. `try_match_rule` calls `rule.hit_counter.add` on
// every match and the implicit-default path calls `state.default_counter.add`,
// and `&PolicyState` does not prevent either: the counters are ATOMICS behind
// shared references, so an immutable borrow is not the guarantee the claim
// rested on. Passing `packet_len = 0` did not help — the zero-length gate in
// `HitCounter::add` covers BYTES only and the packet increment is
// unconditional.
//
// So every re-derivation recorded a PHANTOM hit on whichever rule (or the
// implicit default) it matched: up to one packet per live session per config
// generation, bytes unchanged. No forwarding effect, and it is kept visible for
// two reasons — hit-count is exactly what an operator watches to confirm a
// narrowing took effect, so the noise arrives at the worst moment; and a stated
// structural guarantee that is not structural invites the next side effect into
// this path.
//
// WHY EACH CELL HAS A POSITIVE CONTROL. "Assert a zero counter delta" is
// satisfied perfectly by a counter nobody ever bumps — by a broken fixture, a
// rule that never matched, or a handle read off the wrong rule. Every cell below
// therefore pairs its zero-delta assertion with a run of the ORDINARY admission
// path over the same fixture, which must move the same counter. Without that,
// this whole group is the "negative cell that fails to a healthy value" shape.

/// Read the per-rule hit counters and the implicit-default counter out of a
/// built snapshot, by rule NAME so a reorder cannot re-point the assertion.
fn policy_hit_counts_9385(forwarding: &ForwardingState) -> (u64, u64) {
    named_policy_hit_counts_9385(forwarding, "lan-out")
}

/// The same reader, for a rule named something else — the positive controls
/// below run on a different fixture and therefore a different rule.
fn named_policy_hit_counts_9385(forwarding: &ForwardingState, name: &str) -> (u64, u64) {
    let rule = forwarding
        .policy
        .rules
        .iter()
        .find(|r| r.rule_id.contains(name))
        .map(|r| r.hit_counter.test_packet_count())
        .unwrap_or(u64::MAX);
    (rule, forwarding.policy.default_counter.test_packet_count())
}

/// THE CELL. Drive one ESTABLISHED-session packet whose live policy still
/// PERMITS it — so the re-derivation runs to completion, matches the `lan-out`
/// rule, and takes the re-stamp exit — and assert the matched rule's packet
/// count did not move.
///
/// Its POSITIVE CONTROL is the second half: a session-MISS packet of a different
/// flow through the same snapshot, which must move that same counter. If the
/// control does not move it, the zero delta above measured a counter nothing can
/// bump and says nothing about the re-derivation.
#[test]
fn the_re_derivation_records_no_hit_on_the_matched_rule_9385() {
    let forwarding = forwarding_with_lan_rule(Some("permit"));
    let (rule_before, default_before) = policy_hit_counts_9385(&forwarding);
    assert_ne!(
        rule_before,
        u64::MAX,
        "the `lan-out` rule must exist in the built snapshot, or the delta below \
         is measured on a counter that is not there (#9385)"
    );

    let mut binding = BindingWorker::new_for_mirror_test(0, 0, LAN_IFINDEX, 0);
    binding.interface = Arc::<str>::from("reth1.0");
    let ha_state = txn_ha_state();
    let mut sessions = SessionTable::new();
    assert!(sessions.install_with_protocol_with_origin(
        flow_key_to(DST),
        decision(WAN_IFINDEX),
        metadata(false),
        SessionOrigin::ForwardFlow,
        122_000_000_000,
        PROTO_TCP,
        0,
    ));
    let frame = build_txn_tcp_syn_frame_v4(SRC, DST, SPORT, DPORT, TCP_ACK);
    let meta = txn_meta_v4(LAN_IFINDEX as u32, TCP_ACK, frame.len() as u16);
    let (_batch, dbg) = txn_run_descriptor(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame,
        meta,
    );
    assert_eq!(
        dbg.session_hit, 1,
        "the packet must HIT the session so the RE-DERIVATION is what ran — a \
         session MISS would count legitimately and the delta would be about \
         admission, not about #9385"
    );
    assert_eq!(
        dbg.policy_revoked_sessions, 0,
        "the flow is still permitted; the re-derivation must take the re-stamp \
         exit, which is the exit that matched a rule and therefore the exit that \
         used to count"
    );

    let (rule_after, default_after) = policy_hit_counts_9385(&forwarding);
    assert_eq!(
        rule_after, rule_before,
        "the re-derivation matched `lan-out` and must NOT have bumped its hit \
         counter. A +1 is the phantom hit: up to one packet per live session per \
         config generation on `show security policies hit-count`, arriving \
         exactly when an operator is watching it to confirm a narrowing took \
         effect (#9385)"
    );
    assert_eq!(
        default_after, default_before,
        "and the implicit-default counter must not move either — the walk did not \
         reach it, and a fix that only gated the per-rule bump would pass the \
         assertion above and fail here on the default-verdict path (#9385)"
    );
}

/// THE POSITIVE CONTROL for the cell above, and it is not optional.
///
/// WHY IT USES A DIFFERENT FIXTURE, stated plainly because it is a real
/// weakening. The obvious control — a session MISS through
/// `forwarding_with_lan_rule` — DOES NOT WORK, and that is measured, not
/// assumed: it was written that way first, and on BASE code it read a delta of
/// 0 and failed. `policy_deny_snapshot` has never had a MISS driven through it
/// (every other cell in this file PRE-INSTALLS a decision carrying a
/// `neighbor_mac`), so such a packet never reaches the counting
/// `try_match_rule` walk at all — `tx == 0` and `policy_deny == 0`. Adding a
/// neighbour to that snapshot was tried and did not fix it; the instrument
/// caught that attempt too.
///
/// So the control runs on `inbound_dnat_snapshot`, which is PROVEN to admit and
/// forward: `tests_policy_inbound_nat`'s shipped cells and the #9382 two-phase
/// cells both assert `tx == 1` on exactly this fixture and pass. Building a
/// positive control on measured ground beats building it on a fixture that
/// merely looks equivalent.
///
/// WHAT IT DOES AND DOES NOT ESTABLISH. It establishes that the counter-reading
/// instrument observes a bump when the ordinary admission path runs, i.e. that a
/// zero delta above means "the re-derivation did not count" rather than "nothing
/// in this harness can count". It does NOT establish that on the SAME rule in
/// the SAME fixture, which a same-fixture control would. That gap is the price
/// of the fixture limitation above and is recorded rather than papered over.
#[test]
fn the_ordinary_admission_path_does_record_a_hit_9385() {
    let snapshot = inbound_dnat_snapshot(wan_to_lan_permit("10.0.61.102/32", "permit-internal"));
    let forwarding = build_forwarding_state(&snapshot);
    let (rule_before, _) = named_policy_hit_counts_9385(&forwarding, "permit-internal");
    assert_ne!(
        rule_before,
        u64::MAX,
        "the `permit-internal` rule must exist, or the delta is read off nothing"
    );
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 12, 0);
    binding.interface = Arc::<str>::from("reth0.80");
    let ha_state = txn_ha_state();
    // An EMPTY session table: this packet is a session MISS and takes admission.
    let mut sessions = SessionTable::new();
    let frame = build_txn_tcp_syn_frame_v4(
        Ipv4Addr::new(198, 51, 100, 10),
        Ipv4Addr::new(172, 16, 80, 8),
        54321,
        443,
        TCP_FLAG_SYN,
    );
    let meta = txn_meta_v4(12, TCP_FLAG_SYN, frame.len() as u16);
    let (_batch, dbg) = txn_run_descriptor(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame,
        meta,
    );
    assert_eq!(
        dbg.session_hit, 0,
        "this packet must be a session MISS, or it is not exercising admission"
    );
    // THE INSTRUMENT THAT WAS MISSING THE FIRST TIME. `session_hit == 0` says the
    // packet missed; it does NOT say the miss reached the counting policy walk.
    // Without this, a control that silently stops reaching the site it controls
    // for reads a zero and looks like a real measurement.
    assert_eq!(
        dbg.tx, 1,
        "the control must ADMIT and forward, or it never reached the counting \
         policy walk and its delta says nothing (#9385)"
    );
    let (rule_after, _) = named_policy_hit_counts_9385(&forwarding, "permit-internal");
    assert_eq!(
        rule_after,
        rule_before + 1,
        "the ORDINARY admission path must still count exactly one packet against \
         the admitting rule. If this is 0, the #9385 change suppressed counting \
         everywhere and `show security policies hit-count` is dead — and the \
         zero-delta cell above would be passing vacuously (#9385)"
    );
}

/// The DEFAULT-VERDICT path, which is a different exit from `try_match_rule` and
/// is the one a per-rule-only fix would miss. No `lan -> wan` rule at all, so the
/// re-derivation falls to the implicit default, DENIES, and revokes — and must
/// still not bump the default counter.
#[test]
fn the_re_derivation_records_no_hit_on_the_implicit_default_9385() {
    let forwarding = forwarding_with_lan_rule(None);
    let (_, default_before) = policy_hit_counts_9385(&forwarding);
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, LAN_IFINDEX, 0);
    binding.interface = Arc::<str>::from("reth1.0");
    let ha_state = txn_ha_state();
    let mut sessions = SessionTable::new();
    assert!(sessions.install_with_protocol_with_origin(
        flow_key_to(DST),
        decision(WAN_IFINDEX),
        metadata(false),
        SessionOrigin::ForwardFlow,
        122_000_000_000,
        PROTO_TCP,
        0,
    ));
    let frame = build_txn_tcp_syn_frame_v4(SRC, DST, SPORT, DPORT, TCP_ACK);
    let meta = txn_meta_v4(LAN_IFINDEX as u32, TCP_ACK, frame.len() as u16);
    let (_batch, dbg) = txn_run_descriptor(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame,
        meta,
    );
    assert_eq!(dbg.session_hit, 1, "the packet must hit the session");
    assert_eq!(
        dbg.policy_revoked_sessions, 1,
        "no rule permits this flow, so the re-derivation must reach the IMPLICIT
         DEFAULT and revoke — that is the exit whose counter this cell measures"
    );
    let (_, default_after) = policy_hit_counts_9385(&forwarding);
    assert_eq!(
        default_after, default_before,
        "the implicit default-policy counter must NOT move for a re-derivation. \
         A +1 here inflates the `default-policy` row of \
         `show security policies hit-count`, which is the row an operator reads \
         to see what the fallback is catching (#9385)"
    );
}

/// THE POSITIVE CONTROL for the default-counter cell, on the same PROVEN fixture
/// as the control above and for the same reason.
///
/// A policy covering only the PRE-translation VIP does not cover the post-DNAT
/// destination, so this MISS falls to the implicit default and is DENIED — the
/// shape the shipped `policy_inbound_dnat_denies_when_only_original_dst_permitted`
/// already asserts reaches `policy_deny >= 1`. `tx` is the wrong instrument for a
/// denied packet; `policy_deny` is the positive statement that the walk reached
/// the implicit-default exit, which is the exit whose counter this measures.
#[test]
fn the_ordinary_admission_path_does_record_a_default_hit_9385() {
    let snapshot =
        inbound_dnat_snapshot(wan_to_lan_permit("172.16.80.8/32", "permit-public-vip"));
    let forwarding = build_forwarding_state(&snapshot);
    let default_before = forwarding.policy.default_counter.test_packet_count();
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 12, 0);
    binding.interface = Arc::<str>::from("reth0.80");
    let ha_state = txn_ha_state();
    let mut sessions = SessionTable::new();
    let frame = build_txn_tcp_syn_frame_v4(
        Ipv4Addr::new(198, 51, 100, 10),
        Ipv4Addr::new(172, 16, 80, 8),
        54322,
        443,
        TCP_FLAG_SYN,
    );
    let meta = txn_meta_v4(12, TCP_FLAG_SYN, frame.len() as u16);
    let (_batch, dbg) = txn_run_descriptor(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame,
        meta,
    );
    assert_eq!(dbg.session_hit, 0, "this packet must be a session MISS");
    assert!(
        dbg.policy_deny >= 1,
        "the default-verdict control must reach the implicit-default DENY exit, \
         or its delta says nothing (#9385)"
    );
    assert!(
        forwarding.policy.default_counter.test_packet_count() > default_before,
        "the ordinary admission path must still count the implicit-default \
         verdict. If it does not, the zero-delta cell above is vacuous (#9385)"
    );
}
