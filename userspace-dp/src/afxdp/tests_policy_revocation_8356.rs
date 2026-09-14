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
use crate::nat::NatDecision;
use crate::session::{SessionDecision, SessionKey, SessionMetadata, SessionOrigin};
use crate::test_zone_ids::*;
use crate::{
    FirewallFilterSnapshot, FirewallTermSnapshot, InterfaceSnapshot, NeighborSnapshot,
    PolicyRuleSnapshot, RouteSnapshot, SourceNATRuleSnapshot,
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

// #9560 round 3, R12 — MEASURED GAP, and the reason is specific.
//
// The poll path's FORWARD install (`&flow.forward_key`, `decision.nat`, `false`) has no
// cell that can detect a revert to a key-level publish. The mutant SURVIVED a 71-cell
// run with ALL_FAILED empty.
//
// A cell asserting ROW COUNT cannot close it, in EITHER form. An absolute count fails
// because an entry-level publish leaves the owner holding exactly the rows its decision
// names, and a key-level one also ends up holding rows — the numbers need not differ. A
// DELTA fails for a sharper reason, measured: seeding a predecessor with 4 rows and
// letting the install run gives "4 before, 4 after", because the real decision also
// names 4. A count cannot distinguish "released the old set and claimed a same-size new
// one" from "kept everything".
//
// Closing it needs ROW IDENTITY, not arity: seed a row the real decision provably cannot
// name and assert THAT row's owner count falls to zero. `held_row_count` only counts, and
// there is no row-listing API on the registry today, so this is a different cell plus a
// small accessor — not a stronger assertion here.
//
// Recorded rather than closed with something that cannot fail. R12's driver row is
// declared UNCOVERED so every matrix run re-announces the gap.

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

/// #9560 R12: the poll path's FORWARD install must release the rows a predecessor holds
/// that its own decision does not name.
///
/// A SEPARATE cell from the reverse one above, not a copy of it. The two are different
/// call sites of the same function with different arguments — `&flow.forward_key` /
/// `decision.nat` / `false` against `&reverse_key` / `reverse_decision.nat` / `true` —
/// so a cell covering one says nothing about the other, and R12 SURVIVED a 71-cell run
/// confirming the forward site was undefended.
///
/// **This asserts row IDENTITY, and that is the entire point.** The first cell written to
/// close R12 failed at base with "4 before, 4 after". The real forward decision names as
/// many rows as the seeded predecessor did, so an absolute count is satisfied by both
/// arms and so is a DELTA — a delta of zero is what "released the old set and claimed a
/// same-size new one" and "kept everything" both produce. Those two outcomes differ only
/// in WHICH rows are held, so naming them is the only dimension that can separate them.
/// A count here is not a weak observable; it is the wrong one.
///
/// The premise "rows the real decision cannot name" is MEASURED, not asserted: pass 1
/// runs the real flow alone and records its exact row set, so pass 2's claim is a fact
/// about this fixture rather than a belief about how NAT derives rows.
#[test]
fn the_poll_paths_forward_install_releases_a_seeded_predecessors_unnamed_rows_9560() {
    use crate::afxdp::bpf_map::{
        RECORDER_ONLY_MAP_FD, SteeringHolder, SteeringMapRef, SteeringRowOwners,
        publish_live_session_entry,
    };

    fn forward_key_of(sessions: &SessionTable) -> Option<SessionKey> {
        let mut found: Option<SessionKey> = None;
        sessions.iter_with_origin(|key, _decision, metadata, _origin| {
            if !metadata.is_reverse {
                found = Some(key.clone());
            }
        });
        found
    }

    // PASS 1 exists only to LEARN what the real forward decision names.
    let (forward_key, real_rows) = {
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
        assert_eq!(dbg.tx, 1, "FIXTURE: pass 1 must admit the SYN to derive the forward rows");
        let key = forward_key_of(&sessions).expect("FIXTURE: pass 1 must install a forward entry");
        let rows = owners.held_rows_for(&key, SteeringHolder::Worker(0));
        assert!(
            !rows.is_empty(),
            "FIXTURE: the real forward install must claim rows, or 'cannot name' is vacuous"
        );
        (key, rows)
    };

    // PASS 2: a predecessor already holds a set at that SAME forward key which includes
    // rows the decision measured above does not name.
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
            rewrite_src: Some(std::net::IpAddr::V4(std::net::Ipv4Addr::new(203, 0, 113, 9))),
            rewrite_src_port: Some(51_001),
            ..crate::nat::NatDecision::default()
        },
        false,
    );

    let seeded = owners.held_rows_for(&forward_key, SteeringHolder::Worker(0));
    let unnameable: Vec<_> = seeded
        .iter()
        .copied()
        .filter(|row| !real_rows.contains(row))
        .collect();
    assert!(
        !unnameable.is_empty(),
        "FIXTURE: the seed must claim at least one row the real decision does NOT name, or \
         the assertion below cannot fail under either arm — this is the pinned-parameter \
         trap the count-based version of this cell fell into (seeded {} rows, real names {})",
        seeded.len(),
        real_rows.len()
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

    let still_owned: Vec<_> = unnameable
        .iter()
        .filter(|row| owners.owner_count(row) != 0)
        .collect();
    assert!(
        still_owned.is_empty(),
        "the poll path's FORWARD install KEPT {} of {} rows its own decision does not name. \
         An entry-level publish releases them; a key-level one claims its own row and leaves \
         the rest owned by a session that no longer exists, so nothing will ever release \
         them and a later aliasing session inherits rows it does not own (#9560 R12)",
        still_owned.len(),
        unnameable.len()
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
// ---------------------------------------------------------------------------
// #9604: a stale REVERSE hit is judged by its FORWARD companion.
// ---------------------------------------------------------------------------
//
// The #8356 re-derivation was forward-only, so a flow that sent no forward
// packet after a commit kept its old verdict until idle expiry. These cells
// drive genuine reverse-direction packets (server→client tuple, owner arrival
// on the flow's to-zone side) through the real poll body and assert the
// forward-companion judgment: revoke-both on deny/reject, keep on permit,
// never adjudicate the reverse pair as its own pair.
//
// EVERY cell asserts `hit == 1` (a misrouted packet that never reaches the
// session would satisfy every revoke-zero assertion vacuously) and
// `loud == 0` (no invariant-violating decline fired spuriously — the loud
// counter exists for populations that should not occur, so any nonzero here
// is a fixture or implementation bug, not background noise).
use crate::session::PolicyRevalidationTarget;
use crate::session::reverse_session_key;

/// Second destination port, for the cells that pin port sourcing: 443 vs 8443
/// distinguishes "judged the forward wire ports" from "judged the reply tuple
/// or ignored ports".
const DPORT2_9604: u16 = 8443;
const SRC6_9604: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0x61, 0, 0, 0, 0x102);
const DST6_9604: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0x80, 0, 0, 0, 0x200);

/// Production-shape reverse metadata: zones SWAPPED relative to the forward
/// flow, and NO ingress identity of its own — the reply's ingress has not been
/// observed at install (#4983).
fn reverse_metadata_for_9604(fwd_ingress_zone: u16, fwd_egress_zone: u16) -> SessionMetadata {
    SessionMetadata {
        ingress_zone: fwd_egress_zone,
        egress_zone: fwd_ingress_zone,
        ingress_ifindex: 0,
        ingress_vlan_id: 0,
        owner_rg_id: 0,
        fabric_ingress: false,
        is_reverse: true,
        nat64_reverse: None,
        log_session_init: false,
        log_session_close: false,
        policy_id: 0,
        inactivity_timeout_ns: None,
        policy_counter_idx: 0,
        policy_counter: None,
    }
}

/// Install a production-shape pair: the forward entry as given, plus its
/// reverse companion keyed by `reverse_session_key` with the reversed nat,
/// swapped zones and zero ingress identity. Both install UNVALIDATED
/// (`policy_revalidated_gen: 0`), exactly what an operator's commit leaves
/// behind. Returns the reverse wire key — the tuple the reply carries.
fn install_pair_9604(
    sessions: &mut SessionTable,
    fwd_key: &SessionKey,
    fwd_decision: SessionDecision,
    fwd_metadata: SessionMetadata,
    fwd_origin: SessionOrigin,
    rev_origin: SessionOrigin,
) -> SessionKey {
    let rev_key = reverse_session_key(fwd_key, fwd_decision.nat);
    let rev_decision = SessionDecision {
        resolution: fwd_decision.resolution,
        nat: fwd_decision.nat.reverse(
            fwd_key.src_ip,
            fwd_key.dst_ip,
            fwd_key.src_port,
            fwd_key.dst_port,
        ),
    };
    let rev_metadata =
        reverse_metadata_for_9604(fwd_metadata.ingress_zone, fwd_metadata.egress_zone);
    assert!(
        sessions.install_with_protocol_with_origin(
            fwd_key.clone(),
            fwd_decision,
            fwd_metadata,
            fwd_origin,
            122_000_000_000,
            fwd_key.protocol,
            0,
        ),
        "9604 fixture must install the forward entry"
    );
    assert!(
        sessions.install_with_protocol_with_origin(
            rev_key.clone(),
            rev_decision,
            rev_metadata,
            rev_origin,
            122_000_000_000,
            rev_key.protocol,
            0,
        ),
        "9604 fixture must install the reverse companion"
    );
    rev_key
}

/// A forward wire key with explicit ports (the file's `flow_key_to` hard-codes
/// `SPORT`/`DPORT`).
fn flow_key_port_9604(dst: Ipv4Addr, sport: u16, dport: u16) -> SessionKey {
    SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        src_ip: IpAddr::V4(SRC),
        dst_ip: IpAddr::V4(dst),
        src_port: sport,
        dst_port: dport,
        discriminator: Default::default(),
        routing_domain: 0,
    }
}

/// A reverse-direction TCP frame off an installed reverse key, with arrival
/// meta for `arrival_ifindex`. The tuple is read off the KEY, never
/// hand-built, so a key the lookup cannot resolve fails the `hit == 1`
/// assertion instead of silently testing another path.
fn reverse_tcp_frame_v4_9604(
    rev_key: &SessionKey,
    arrival_ifindex: i32,
) -> (Vec<u8>, UserspaceDpMeta) {
    let (src, dst) = match (rev_key.src_ip, rev_key.dst_ip) {
        (IpAddr::V4(s), IpAddr::V4(d)) => (s, d),
        _ => panic!("9604 v4 driver handed a non-v4 reverse key"),
    };
    let frame =
        build_txn_tcp_syn_frame_v4(src, dst, rev_key.src_port, rev_key.dst_port, TCP_ACK);
    let meta = txn_meta_v4(arrival_ifindex as u32, TCP_ACK, frame.len() as u16);
    (frame, meta)
}

/// v6 twin of the above.
fn reverse_tcp_frame_v6_9604(
    rev_key: &SessionKey,
    arrival_ifindex: i32,
) -> (Vec<u8>, UserspaceDpMeta) {
    let (src, dst) = match (rev_key.src_ip, rev_key.dst_ip) {
        (IpAddr::V6(s), IpAddr::V6(d)) => (s, d),
        _ => panic!("9604 v6 driver handed a non-v6 reverse key"),
    };
    let frame = build_txn_tcp_frame_v6(src, dst, rev_key.src_port, rev_key.dst_port, TCP_ACK);
    let mut meta = txn_meta_v6(arrival_ifindex as u32, frame.len());
    meta.tcp_flags = TCP_ACK;
    (frame, meta)
}

struct ReverseOutcome {
    revoked: u64,
    hit: u64,
    tx: u64,
    foreign_drops: u64,
}

/// Drive one packet through the real poll body on the CALLER's binding (so
/// multi-drive cells control flow-cache accumulation explicitly).
fn drive_packet_9604(
    sessions: &mut SessionTable,
    forwarding: &ForwardingState,
    binding: &mut BindingWorker,
    frame: &[u8],
    meta: UserspaceDpMeta,
) -> ReverseOutcome {
    let ha_state = txn_ha_state();
    let (_batch, dbg) = txn_run_descriptor(binding, sessions, forwarding, &ha_state, frame, meta);
    ReverseOutcome {
        revoked: dbg.policy_revoked_sessions,
        hit: dbg.session_hit,
        tx: dbg.tx,
        foreign_drops: dbg.foreign_authority_drops,
    }
}

/// A fresh mirror binding arriving on `arrival_ifindex` as `iface`.
fn binding_for_9604(arrival_ifindex: i32, iface: &str) -> BindingWorker {
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, arrival_ifindex, 0);
    binding.interface = Arc::<str>::from(iface);
    binding
}

/// Both primary slots must be gone after a revoke — the teardown half of the
/// key/nat pairing contract (the eviction half is covered by the
/// post-revoke miss+drop cell).
fn assert_slots_gone_9604(sessions: &SessionTable, fwd: &SessionKey, rev: &SessionKey) {
    assert!(
        sessions.entry_with_origin(fwd).is_none(),
        "the forward slot must be gone after revocation"
    );
    assert!(
        sessions.entry_with_origin(rev).is_none(),
        "the reverse companion slot must be gone after revocation — a \
         teardown that deletes only the judged half strands the companion"
    );
}

/// Two-phase driver for translated flows: phase 1 admits through the
/// production path (real pair, real NAT reservation), phase 2 drives the
/// REVERSE packet on a fresh binding under a second snapshot. Returns the
/// table (for stamp/slot assertions) and both installed keys.
struct AdmitReverseOutcome {
    sessions: SessionTable,
    fwd_key: SessionKey,
    rev_key: SessionKey,
    revoked: u64,
    hit: u64,
    tx: u64,
}

fn admit_then_reverse_9604(
    snapshot_phase1: crate::ConfigSnapshot,
    snapshot_phase2: crate::ConfigSnapshot,
    admit_ifindex: i32,
    admit_iface: &str,
    frame_admit: &[u8],
    meta_admit: UserspaceDpMeta,
    rev_arrival: i32,
    rev_iface: &str,
) -> AdmitReverseOutcome {
    let ha_state = txn_ha_state();
    let mut sessions = SessionTable::new();
    let forwarding1 = build_forwarding_state(&snapshot_phase1);
    let mut binding1 = binding_for_9604(admit_ifindex, admit_iface);
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
        "9604 phase 1 must ADMIT and forward, or the pair under test was never \
         installed by the production path"
    );
    assert_eq!(
        session_count(&sessions),
        2,
        "9604 phase 1 must install the forward + reverse pair"
    );
    let mut fwd_key = None;
    let mut rev_key = None;
    sessions.iter_with_origin(|key, _decision, metadata, _origin| {
        if metadata.is_reverse {
            rev_key = Some(key.clone());
        } else {
            fwd_key = Some(key.clone());
        }
    });
    let fwd_key = fwd_key.expect("9604 phase 1 must install a forward entry");
    let rev_key = rev_key.expect("9604 phase 1 must install a reverse companion");
    let forwarding2 = build_forwarding_state(&snapshot_phase2);
    let mut binding2 = binding_for_9604(rev_arrival, rev_iface);
    let (frame_rev, meta_rev) = reverse_tcp_frame_v4_9604(&rev_key, rev_arrival);
    let out = drive_packet_9604(&mut sessions, &forwarding2, &mut binding2, &frame_rev, meta_rev);
    AdmitReverseOutcome {
        sessions,
        fwd_key,
        rev_key,
        revoked: out.revoked,
        hit: out.hit,
        tx: out.tx,
    }
}

/// `policy_deny_snapshot` plus a `wan -> lan` permit and NO `lan -> wan` rule:
/// the asymmetric fixture that separates forward-pair judgment (deny →
/// revoke) from reverse-pair judgment (permit → keep).
fn forwarding_asymmetric_9604() -> ForwardingState {
    let mut snapshot = policy_deny_snapshot();
    snapshot.generation = 7;
    snapshot.fib_generation = 9;
    snapshot.policies.push(wan_to_lan_permit("any", "rev-permit"));
    build_forwarding_state(&snapshot)
}

/// A `lan -> wan` permit constrained to one application port (or source port),
/// for the cells that pin tuple/port sourcing through the reverse path.
fn port_scoped_permit_9604(dst_port: &str, src_port: &str) -> PolicyRuleSnapshot {
    PolicyRuleSnapshot {
        name: "port-out".into(),
        from_zone: "lan".into(),
        to_zone: "wan".into(),
        source_addresses: vec!["any".into()],
        destination_addresses: vec!["any".into()],
        applications: vec!["svc-constrained".into()],
        application_terms: vec![PolicyApplicationSnapshot {
            name: "svc-constrained".into(),
            protocol: "tcp".into(),
            source_port: src_port.into(),
            destination_port: dst_port.into(),
            icmp_type: None,
            icmp_code: None,
            inactivity_timeout: None,
        }],
        action: "permit".into(),
        ..Default::default()
    }
}
/// THE FEATURE, reverse-fed. A session established under an older policy must
/// be revoked on its next REVERSE packet once policy no longer permits the
/// flow — the #9604 half of #7323's residual.
///
/// Dies if the reverse branch is deleted (GATE-1 `None` restored): the reverse
/// hit never re-derives and both halves survive on companion keep-alive.
#[test]
fn reverse_only_stream_across_permit_to_deny_revokes_both_halves_9604() {
    let forwarding = forwarding_with_lan_rule(None);
    let mut sessions = SessionTable::new();
    let fwd_key = flow_key_to(DST);
    let rev_key = install_pair_9604(
        &mut sessions,
        &fwd_key,
        decision(WAN_IFINDEX),
        metadata(false),
        SessionOrigin::ForwardFlow,
        SessionOrigin::ReverseFlow,
    );
    let mut binding = binding_for_9604(WAN_IFINDEX, "reth0.80");
    let (frame, meta) = reverse_tcp_frame_v4_9604(&rev_key, WAN_IFINDEX);
    let out = drive_packet_9604(&mut sessions, &forwarding, &mut binding, &frame, meta);
    assert_eq!(
        out.hit, 1,
        "the reply must HIT the reverse companion, or the revoke assertion is \
         vacuous (#9604)"
    );
    assert_eq!(
        out.revoked, 1,
        "no rule permits lan -> wan anymore, so a reverse-fed flow must be \
         revoked exactly like a forward-fed one. 0 is the #9604 residual: the \
         reverse hit never re-derived and the pair survived on companion \
         keep-alive"
    );
    assert_slots_gone_9604(&sessions, &fwd_key, &rev_key);
    assert_eq!(
        sessions.policy_revalidation_loud_declines(),
        0,
        "no invariant-violating decline may fire on a production-shape pair"
    );
}

/// #9381 through the reverse path: a `reject` verdict is terminal
/// non-forwarding for reverse-fed flows too, and tears down silently like a
/// deny (the next packet of the tuple takes admission and emits the reject
/// reply from `reject_reply.rs`).
#[test]
fn reverse_only_stream_across_permit_to_reject_revokes_both_halves_9604() {
    let forwarding = forwarding_with_lan_rule(Some("reject"));
    let mut sessions = SessionTable::new();
    let fwd_key = flow_key_to(DST);
    let rev_key = install_pair_9604(
        &mut sessions,
        &fwd_key,
        decision(WAN_IFINDEX),
        metadata(false),
        SessionOrigin::ForwardFlow,
        SessionOrigin::ReverseFlow,
    );
    let mut binding = binding_for_9604(WAN_IFINDEX, "reth0.80");
    let (frame, meta) = reverse_tcp_frame_v4_9604(&rev_key, WAN_IFINDEX);
    let out = drive_packet_9604(&mut sessions, &forwarding, &mut binding, &frame, meta);
    assert_eq!(out.hit, 1, "the reply must hit the reverse companion");
    assert_eq!(
        out.revoked, 1,
        "a `reject` verdict must revoke a reverse-fed session exactly as a \
         forward-fed one (#9381 via #9604)"
    );
    assert_slots_gone_9604(&sessions, &fwd_key, &rev_key);
    assert_eq!(sessions.policy_revalidation_loud_declines(), 0);
}

/// THE HARD-CONSTRAINT PIN. The policy permits `wan -> lan` (the reverse
/// pair) but denies `lan -> wan` (the forward pair the session was admitted
/// under). A reverse hit must still revoke: the judgment is FOR the forward
/// tuple, never for the reverse pair.
///
/// An implementation that adjudicates the reverse entry as its own pair
/// returns PERMIT here and keeps — this cell reds exactly that shape, which
/// no other cell can see (every other deny cell also denies the reverse pair).
#[test]
fn a_reverse_pair_permit_does_not_save_a_denied_forward_flow_9604() {
    let forwarding = forwarding_asymmetric_9604();
    let mut sessions = SessionTable::new();
    let fwd_key = flow_key_to(DST);
    let rev_key = install_pair_9604(
        &mut sessions,
        &fwd_key,
        decision(WAN_IFINDEX),
        metadata(false),
        SessionOrigin::ForwardFlow,
        SessionOrigin::ReverseFlow,
    );
    let mut binding = binding_for_9604(WAN_IFINDEX, "reth0.80");
    let (frame, meta) = reverse_tcp_frame_v4_9604(&rev_key, WAN_IFINDEX);
    let out = drive_packet_9604(&mut sessions, &forwarding, &mut binding, &frame, meta);
    assert_eq!(out.hit, 1, "the reply must hit the reverse companion");
    assert_eq!(
        out.revoked, 1,
        "the FORWARD pair lan -> wan is denied: a `wan -> lan` permit must not \
         save it. 0 means the reverse entry was adjudicated as its own pair, \
         which is GATE 1's catastrophe in miniature — on a real box that shape \
         keeps every reverse-fed denied flow (#9604)"
    );
    assert_slots_gone_9604(&sessions, &fwd_key, &rev_key);
    assert_eq!(sessions.policy_revalidation_loud_declines(), 0);
}

/// v6 mirror of the deny detector: guards the AF-specific companion-key math
/// through the reverse path.
#[test]
fn reverse_only_v6_stream_across_permit_to_deny_revokes_both_halves_9604() {
    let forwarding = forwarding_with_lan_rule(None);
    let mut sessions = SessionTable::new();
    let fwd_key = SessionKey {
        addr_family: libc::AF_INET6 as u8,
        protocol: PROTO_TCP,
        src_ip: IpAddr::V6(SRC6_9604),
        dst_ip: IpAddr::V6(DST6_9604),
        src_port: SPORT,
        dst_port: DPORT,
        discriminator: Default::default(),
        routing_domain: 0,
    };
    let rev_key = install_pair_9604(
        &mut sessions,
        &fwd_key,
        decision(WAN_IFINDEX),
        metadata(false),
        SessionOrigin::ForwardFlow,
        SessionOrigin::ReverseFlow,
    );
    let mut binding = binding_for_9604(WAN_IFINDEX, "reth0.80");
    let (frame, meta) = reverse_tcp_frame_v6_9604(&rev_key, WAN_IFINDEX);
    let out = drive_packet_9604(&mut sessions, &forwarding, &mut binding, &frame, meta);
    assert_eq!(out.hit, 1, "the v6 reply must hit the reverse companion");
    assert_eq!(
        out.revoked, 1,
        "a reverse-fed v6 flow the live policy denies must be revoked (#9604)"
    );
    assert_slots_gone_9604(&sessions, &fwd_key, &rev_key);
    assert_eq!(sessions.policy_revalidation_loud_declines(), 0);
}
/// SNAT through the reverse path, with the production pool reservation. Phase 1
/// admits a pool-SNAT flow (real translated port, real reservation); phase 2
/// narrows the policy and drives the REVERSE packet (pool -> client tuple).
///
/// This is the cell the key/nat pairing section of the plan calls load-bearing:
/// the teardown and the eviction set both derive the companion from the carried
/// nat, and the old caller shape (`resolved.decision`, the REVERSE nat) is a
/// trap for exactly this. A wrong pairing strands the reverse half and its
/// flow-cache slot — and leaks the pool port.
#[test]
fn snat_pair_reverse_triggered_deny_revokes_both_halves_9604() {
    use crate::nat::source_nat_pool_statuses;

    let mut snap1 = nat_snapshot();
    snap1.generation = 7;
    snap1.fib_generation = 9;
    snap1.source_nat_rules = vec![SourceNATRuleSnapshot {
        name: "snat-pool".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["0.0.0.0/0".to_string()],
        pool_name: "pool-a".to_string(),
        pool_addresses: vec!["172.16.80.100".to_string()],
        port_low: 20000,
        port_high: 20999,
        ..Default::default()
    }];
    let mut snap2 = snap1.clone();
    snap2.policies.clear();
    snap2.generation = 8;

    let ha_state = txn_ha_state();
    let mut sessions = SessionTable::new();
    let forwarding1 = build_forwarding_state(&snap1);
    let mut binding1 = binding_for_9604(LAN_IFINDEX, "reth1.0");
    // Via the default route (172.16.80.1 has a neighbor entry): DST sits in the
    // connected WAN subnet with no neighbor entry, so a SYN to it installs but
    // never forwards — the wrong server for an admit-then-revoke cell.
    let syn = build_txn_tcp_syn_frame_v4(
        SRC,
        Ipv4Addr::new(8, 8, 8, 8),
        SPORT,
        DPORT,
        TCP_FLAG_SYN,
    );
    let meta_syn = txn_meta_v4(LAN_IFINDEX as u32, TCP_FLAG_SYN, syn.len() as u16);
    let (_b1, dbg1) = txn_run_descriptor(
        &mut binding1,
        &mut sessions,
        &forwarding1,
        &ha_state,
        &syn,
        meta_syn,
    );
    assert_eq!(dbg1.tx, 1, "9604 SNAT phase 1 must admit");
    assert_eq!(session_count(&sessions), 2, "9604 phase 1 must install the pair");
    assert_eq!(
        source_nat_pool_statuses(&forwarding1.source_nat_rules)[0].used_ports,
        1,
        "9604 phase 1 must hold exactly one pool port — otherwise the release \
         assertion below is vacuous"
    );
    let mut rev_key = None;
    let mut fwd_key = None;
    sessions.iter_with_origin(|key, _decision, metadata, _origin| {
        if metadata.is_reverse {
            rev_key = Some(key.clone());
        } else {
            fwd_key = Some(key.clone());
        }
    });
    let (fwd_key, rev_key) = (
        fwd_key.expect("9604 SNAT phase 1 must install forward"),
        rev_key.expect("9604 SNAT phase 1 must install reverse"),
    );

    let forwarding2 = build_forwarding_state(&snap2);
    let mut binding2 = binding_for_9604(WAN_IFINDEX, "reth0.80");
    let (frame_rev, meta_rev) = reverse_tcp_frame_v4_9604(&rev_key, WAN_IFINDEX);
    let out = drive_packet_9604(&mut sessions, &forwarding2, &mut binding2, &frame_rev, meta_rev);
    assert_eq!(out.hit, 1, "the SNAT reply must hit the reverse companion");
    assert_eq!(
        out.revoked, 1,
        "the narrowed policy denies lan -> wan: the SNAT pair must be revoked \
         through the reverse hit. 0 is the #9604 residual for translated flows"
    );
    assert_slots_gone_9604(&sessions, &fwd_key, &rev_key);
    // NO pool-release assertion here, deliberately. Pool allocator state is
    // per-`ForwardingState` build in this harness (measured: a fresh narrowed
    // build reads `used_ports == 0` while the admitting build still reads 1),
    // so a cross-build release is invisible by construction — AND the
    // pre-existing FORWARD revoke reads back identically under the same setup
    // (measured: forward hit=1 revoked=1 with the admitting build still
    // showing 1). The reservation release itself is covered from BOTH
    // `delete_terminal_filtered_session_releases_companion_and_allocator_5622`
    // (`hit_reverse` in {false, true}); this cell pins the end-to-end
    // key/nat pairing (both halves actually torn down) instead.
    assert_eq!(sessions.policy_revalidation_loud_declines(), 0);
}

/// DNAT through the reverse path. Phase 1 admits `client -> VIP:443`
/// (translated to `real:8443`); phase 2 narrows to an unrelated host and
/// drives the reply (`real:8443 -> client`).
#[test]
fn dnat_pair_reverse_triggered_narrowing_revokes_9604() {
    let (syn, meta_syn, _ack, _meta_ack) = dnat_frames();
    let out = admit_then_reverse_9604(
        inbound_dnat_snapshot(wan_to_lan_permit(DNAT_REAL, "permit-internal")),
        inbound_dnat_snapshot(wan_to_lan_permit("10.0.61.200/32", "permit-someone-else")),
        WAN_INGRESS_IFINDEX,
        "reth0.80",
        &syn,
        meta_syn,
        LAN_IFINDEX,
        "reth1.0",
    );
    assert_eq!(out.hit, 1, "the DNAT reply must hit the reverse companion");
    assert_eq!(
        out.revoked, 1,
        "the live policy no longer covers the real server, so the DNAT pair \
         must be revoked through the reverse hit (#9604 via #9382)"
    );
    assert_slots_gone_9604(&out.sessions, &out.fwd_key, &out.rev_key);
    assert_eq!(out.sessions.policy_revalidation_loud_declines(), 0);
}

/// DNAT with DISTINCT VIP/backend ports (VIP:443 -> real:8443, the fixture's
/// own shape). Phase 2 permits only the real address at the WRONG port
/// (real:443): the judgment must read `rewrite_dst_port`, not the wire port.
///
/// An implementation that carries the translated ADDRESS but leaves the wire
/// PORT matches real:443 and keeps — this cell reds exactly that shape.
#[test]
fn dnat_distinct_ports_reverse_triggered_narrowing_revokes_9604() {
    let (syn, meta_syn, _ack, _meta_ack) = dnat_frames();
    let mut rule = wan_to_lan_permit(DNAT_REAL, "permit-real-wrong-port");
    rule.applications = vec!["svc-443".into()];
    rule.application_terms = vec![PolicyApplicationSnapshot {
        name: "svc-443".into(),
        protocol: "tcp".into(),
        source_port: String::new(),
        destination_port: "443".into(),
        icmp_type: None,
        icmp_code: None,
        inactivity_timeout: None,
    }];
    let out = admit_then_reverse_9604(
        inbound_dnat_snapshot(wan_to_lan_permit(DNAT_REAL, "permit-internal")),
        inbound_dnat_snapshot(rule),
        WAN_INGRESS_IFINDEX,
        "reth0.80",
        &syn,
        meta_syn,
        LAN_IFINDEX,
        "reth1.0",
    );
    assert_eq!(out.hit, 1, "the DNAT reply must hit the reverse companion");
    assert_eq!(
        out.revoked, 1,
        "the only permit names real:443 but the flow serves real:8443 — the \
         judgment must read the translated PORT as well as the address. 0 means \
         the wire port rode along and matched (#9604 via #9382)"
    );
    assert_slots_gone_9604(&out.sessions, &out.fwd_key, &out.rev_key);
    assert_eq!(out.sessions.policy_revalidation_loud_declines(), 0);
}

/// A 443-only permit must actually constrain the destination port on the
/// reverse path: a session to 8443 revokes. The positive-only control stays
/// green when ports are ignored (the rule still matches on L3), so without
/// this cell "ports are evaluated" is unproven.
#[test]
fn port_constraint_enforced_on_reverse_9604() {
    let mut snapshot = policy_deny_snapshot();
    snapshot.generation = 7;
    snapshot.fib_generation = 9;
    snapshot.policies.clear();
    snapshot
        .policies
        .push(port_scoped_permit_9604("443", ""));
    let forwarding = build_forwarding_state(&snapshot);
    let mut sessions = SessionTable::new();
    let fwd_key = flow_key_port_9604(DST, SPORT, DPORT2_9604);
    let rev_key = install_pair_9604(
        &mut sessions,
        &fwd_key,
        decision(WAN_IFINDEX),
        metadata(false),
        SessionOrigin::ForwardFlow,
        SessionOrigin::ReverseFlow,
    );
    let mut binding = binding_for_9604(WAN_IFINDEX, "reth0.80");
    let (frame, meta) = reverse_tcp_frame_v4_9604(&rev_key, WAN_IFINDEX);
    let out = drive_packet_9604(&mut sessions, &forwarding, &mut binding, &frame, meta);
    assert_eq!(out.hit, 1, "the reply must hit the reverse companion");
    assert_eq!(
        out.revoked, 1,
        "the only permit covers dst-port 443 and this flow serves 8443 — the \
         reverse judgment must enforce the port constraint. 0 means ports are \
         not evaluated on this path"
    );
    assert_slots_gone_9604(&sessions, &fwd_key, &rev_key);
    assert_eq!(sessions.policy_revalidation_loud_declines(), 0);
}
/// An ICMPv4 echo-REPLY frame (type 0) carrying `ident`, mirroring
/// `build_icmp_echo_frame_v4` (which emits only requests). The reply parses to
/// `(ident, 0)` off the wire, i.e. the reverse tuple of an echo session.
fn build_icmp_echo_reply_frame_v4_9604(src: Ipv4Addr, dst: Ipv4Addr, ident: u16) -> Vec<u8> {
    let mut frame = Vec::new();
    write_eth_header(
        &mut frame,
        [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
        [0x00, 0x25, 0x90, 0x12, 0x34, 0x56],
        0,
        0x0800,
    );
    frame.extend_from_slice(&[
        0x45, 0x00, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, 64, PROTO_ICMP, 0x00, 0x00,
    ]);
    frame.extend_from_slice(&src.octets());
    frame.extend_from_slice(&dst.octets());
    let ip_csum = checksum16(&frame[14..34]);
    frame[24..26].copy_from_slice(&ip_csum.to_be_bytes());
    let icmp_start = frame.len();
    frame.extend_from_slice(&[0, 0, 0x00, 0x00]);
    frame.extend_from_slice(&ident.to_be_bytes());
    frame.extend_from_slice(&[0x00, 0x01]);
    let icmp_csum = checksum16(&frame[icmp_start..]);
    frame[icmp_start + 2..icmp_start + 4].copy_from_slice(&icmp_csum.to_be_bytes());
    frame
}

/// A junos-ping-shaped PERMIT for ICMPv6 (echo request, type 128), the v6 twin
/// of `junos_ping_permit`. Deliberately on `dmz -> wan`: the gate predicate is
/// whole-snapshot, so the pair is irrelevant to arming.
fn junos_ping_v6_permit_9604() -> PolicyRuleSnapshot {
    PolicyRuleSnapshot {
        name: "ping6-elsewhere".into(),
        from_zone: "dmz".into(),
        to_zone: "wan".into(),
        source_addresses: vec!["any".into()],
        destination_addresses: vec!["any".into()],
        applications: vec!["junos-ping6".into()],
        application_terms: vec![PolicyApplicationSnapshot {
            name: "junos-ping6".into(),
            protocol: "icmpv6".into(),
            source_port: String::new(),
            destination_port: String::new(),
            icmp_type: Some(128),
            icmp_code: None,
            inactivity_timeout: None,
        }],
        action: "permit".into(),
        ..Default::default()
    }
}

const NAT64_CLIENT_V6_9604: &str = "2001:559:8585:ef00::100";
const NAT64_SYNTH_V6_9604: &str = "64:ff9b::c000:0207";
const NAT64_MAPPED_V4_9604: [u8; 4] = [192, 0, 2, 1];
const NAT64_SERVER_V4_9604: [u8; 4] = [203, 0, 113, 7];

/// A production-shape NAT64 ICMP pair, installed manually: v6 echo forward key,
/// v4 companion derived by `reverse_session_key` (AF + ICMPv6→ICMP remap),
/// swapped zones, trusted LAN admitting identity on the forward half.
fn install_nat64_icmp_pair_9604(sessions: &mut SessionTable) -> (SessionKey, SessionKey) {
    let fwd_key = SessionKey {
        addr_family: libc::AF_INET6 as u8,
        protocol: PROTO_ICMPV6,
        src_ip: NAT64_CLIENT_V6_9604.parse().expect("v6 client"),
        dst_ip: NAT64_SYNTH_V6_9604.parse().expect("synthetic dst"),
        src_port: ICMP_ID,
        dst_port: 0,
        discriminator: Default::default(),
        routing_domain: 0,
    };
    let nat = crate::nat::NatDecision {
        rewrite_src: Some(IpAddr::V4(Ipv4Addr::from(NAT64_MAPPED_V4_9604))),
        rewrite_dst: Some(IpAddr::V4(Ipv4Addr::from(NAT64_SERVER_V4_9604))),
        nat64: true,
        ..crate::nat::NatDecision::default()
    };
    let fwd_decision = SessionDecision {
        resolution: decision(WAN_IFINDEX).resolution,
        nat,
    };
    let rev_key = install_pair_9604(
        sessions,
        &fwd_key,
        fwd_decision,
        metadata(false),
        SessionOrigin::ForwardFlow,
        SessionOrigin::ReverseFlow,
    );
    (fwd_key, rev_key)
}

/// Drive the v4 echo reply for an installed NAT64 ICMP pair.
fn drive_nat64_icmp_reply_9604(
    sessions: &mut SessionTable,
    forwarding: &ForwardingState,
) -> ReverseOutcome {
    let frame = build_icmp_echo_reply_frame_v4_9604(
        Ipv4Addr::from(NAT64_SERVER_V4_9604),
        Ipv4Addr::from(NAT64_MAPPED_V4_9604),
        ICMP_ID,
    );
    let mut meta = txn_meta_v4(WAN_IFINDEX as u32, 0, frame.len() as u16);
    meta.protocol = PROTO_ICMP;
    meta.payload_offset = 42;
    let mut binding = binding_for_9604(WAN_IFINDEX, "reth0.80");
    drive_packet_9604(sessions, forwarding, &mut binding, &frame, meta)
}

/// THE GATE PIN, decline direction. The snapshot arms ONLY the ICMPv6
/// predicate; the v4 reply must therefore decline (kept, stamps stale) rather
/// than evaluate the v6 tuple type-blind — which would miss the type-specific
/// permit and manufacture a false DENY.
///
/// A packet-family gate (reading the reply's v4 protocol) finds its own family
/// unarmed, proceeds to evaluate, misses the v6 permit and REVOKES — this cell
/// reds exactly that shape.
#[test]
fn nat64_v6_armed_decline_keeps_flow_and_stamps_stale_9604() {
    let mut snapshot = policy_deny_snapshot();
    snapshot.generation = 7;
    snapshot.fib_generation = 9;
    snapshot.policies.push(junos_ping_v6_permit_9604());
    let forwarding = build_forwarding_state(&snapshot);
    assert!(
        forwarding.policy.icmp_verdict_may_depend_on_type(PROTO_ICMPV6),
        "9604 fixture must arm the v6 predicate, or the decline is vacuous"
    );
    assert!(
        !forwarding.policy.icmp_verdict_may_depend_on_type(PROTO_ICMP),
        "9604 fixture must leave the v4 predicate unarmed"
    );
    let mut sessions = SessionTable::new();
    let (fwd_key, rev_key) = install_nat64_icmp_pair_9604(&mut sessions);
    let out = drive_nat64_icmp_reply_9604(&mut sessions, &forwarding);
    assert_eq!(out.hit, 1, "the v4 reply must hit the reverse companion");
    assert_eq!(
        out.revoked, 0,
        "the v6 verdict may depend on type, which this derivation does not \
         have — it must decline, exactly as the forward path does (#8618 via \
         #9604)"
    );
    assert_eq!(session_count(&sessions), 2, "the declined pair must survive");
    assert_eq!(
        sessions.policy_revalidation_target(&fwd_key),
        PolicyRevalidationTarget::Stale(fwd_key.clone()),
        "a decline stamps nothing: the forward half must still be stale"
    );
    assert_eq!(
        sessions.policy_revalidation_target(&rev_key),
        PolicyRevalidationTarget::Stale(rev_key.clone()),
        "and the reverse half must still be stale, so the next packet re-derives"
    );
    let out2 = drive_nat64_icmp_reply_9604(&mut sessions, &forwarding);
    assert_eq!((out2.hit, out2.revoked), (1, 0), "the re-derivation must decline again");
    assert_eq!(session_count(&sessions), 2);
    assert_eq!(sessions.policy_revalidation_loud_declines(), 0);
}

/// THE GATE PIN, revoke direction: only the v4 predicate is armed, while the
/// v6 judgment is a plain non-permit (no lan -> wan rule). The v6 family gate
/// is unarmed, so the walk must run and revoke.
///
/// An extra packet-family gate (declining because v4 IS armed) keeps here —
/// this cell reds exactly that shape, complementing the decline cell above.
#[test]
fn nat64_v4_armed_nonpermit_revokes_on_reverse_9604() {
    let mut snapshot = policy_deny_snapshot();
    snapshot.generation = 7;
    snapshot.fib_generation = 9;
    snapshot.policies.push(junos_ping_permit());
    let forwarding = build_forwarding_state(&snapshot);
    assert!(
        forwarding.policy.icmp_verdict_may_depend_on_type(PROTO_ICMP),
        "9604 fixture must arm the v4 predicate"
    );
    assert!(
        !forwarding.policy.icmp_verdict_may_depend_on_type(PROTO_ICMPV6),
        "9604 fixture must leave the v6 predicate unarmed, or the walk never runs"
    );
    let mut sessions = SessionTable::new();
    let (fwd_key, rev_key) = install_nat64_icmp_pair_9604(&mut sessions);
    let out = drive_nat64_icmp_reply_9604(&mut sessions, &forwarding);
    assert_eq!(out.hit, 1, "the v4 reply must hit the reverse companion");
    assert_eq!(
        out.revoked, 1,
        "the JUDGED family is v6 (unarmed) and the v6 pair is denied: the walk \
         must run and revoke. 0 means a packet-family gate declined on the \
         armed v4 predicate — the wrong family's answer (#9604)"
    );
    assert_slots_gone_9604(&sessions, &fwd_key, &rev_key);
    assert_eq!(sessions.policy_revalidation_loud_declines(), 0);
}
use crate::session::SessionInstall;

/// Install a pair through the synced-import path: both halves `SyncImport`,
/// recorded zones lan -> wan, no locally-authored ingress identity (the peer's
/// number never crosses, #6928). This is the #7323 imported population — the
/// one the feature most needs to reach, since `upsert_synced` stamps
/// generation 0.
fn install_synced_pair_9604(sessions: &mut SessionTable) -> (SessionKey, SessionKey) {
    let fwd_key = flow_key_to(DST);
    let rev_key = reverse_session_key(&fwd_key, NatDecision::default());
    let rev_nat = NatDecision::default().reverse(SRC.into(), DST.into(), SPORT, DPORT);
    assert!(
        sessions.upsert_synced(
            fwd_key.clone(),
            decision(WAN_IFINDEX),
            metadata(false),
            122_000_000_000,
            PROTO_TCP,
            0,
            true,
        ),
        "9604 fixture must import the forward half"
    );
    let mut rev_metadata =
        reverse_metadata_for_9604(TEST_LAN_ZONE_ID, TEST_WAN_ZONE_ID);
    rev_metadata.policy_id = 0;
    assert!(
        sessions.upsert_synced(
            rev_key.clone(),
            SessionDecision {
                resolution: decision(WAN_IFINDEX).resolution,
                nat: rev_nat,
            },
            rev_metadata,
            122_000_000_000,
            PROTO_TCP,
            0,
            true,
        ),
        "9604 fixture must import the reverse half"
    );
    (fwd_key, rev_key)
}

/// The imported population revokes through the reverse path: a `SyncImport`
/// pair takes the recorded-zone arm (no live resolution of a peer identity)
/// and judges the recorded pair.
#[test]
fn peer_synced_pair_reverse_triggered_deny_revokes_9604() {
    let forwarding = forwarding_with_lan_rule(None);
    let mut sessions = SessionTable::new();
    let (fwd_key, rev_key) = install_synced_pair_9604(&mut sessions);
    let mut binding = binding_for_9604(WAN_IFINDEX, "reth0.80");
    let (frame, meta) = reverse_tcp_frame_v4_9604(&rev_key, WAN_IFINDEX);
    let out = drive_packet_9604(&mut sessions, &forwarding, &mut binding, &frame, meta);
    assert_eq!(out.hit, 1, "the reply must hit the synced reverse companion");
    assert_eq!(
        out.revoked, 1,
        "the recorded pair lan -> wan is denied: an imported flow must revoke \
         through the reverse hit, not keep its peer's verdict (#9604 closes the \
         #7323 residual for reverse-fed imports)"
    );
    assert_slots_gone_9604(&sessions, &fwd_key, &rev_key);
    assert_eq!(sessions.policy_revalidation_loud_declines(), 0);
}

/// `SharedPromote` entries retain no locally-authored ingress identity
/// (promotion clones without re-stamping), so they take the recorded-zone arm
/// like every other imported provenance. A `SyncImport`-only cell cannot
/// detect a live-resolution regression for promoted entries.
#[test]
fn shared_promote_pair_reverse_triggered_deny_revokes_9604() {
    let forwarding = forwarding_with_lan_rule(None);
    let mut sessions = SessionTable::new();
    let fwd_key = flow_key_to(DST);
    let rev_key = reverse_session_key(&fwd_key, NatDecision::default());
    for (key, decision, mut md) in [
        (fwd_key.clone(), decision(WAN_IFINDEX), metadata(false)),
        (
            rev_key.clone(),
            SessionDecision {
                resolution: decision(WAN_IFINDEX).resolution,
                nat: NatDecision::default(),
            },
            reverse_metadata_for_9604(TEST_LAN_ZONE_ID, TEST_WAN_ZONE_ID),
        ),
    ] {
        md.owner_rg_id = 1;
        assert!(
            sessions.upsert_synced_with_origin(
                SessionInstall {
                    key,
                    decision,
                    metadata: md,
                    origin: SessionOrigin::SharedPromote,
                    now_ns: 122_000_000_000,
                    protocol: PROTO_TCP,
                    tcp_flags: 0,
                    session_id: 0,
                    tcp_close_class: 0,
                },
                true,
            ),
            "9604 fixture must promote the pair"
        );
    }
    let mut binding = binding_for_9604(WAN_IFINDEX, "reth0.80");
    let (frame, meta) = reverse_tcp_frame_v4_9604(&rev_key, WAN_IFINDEX);
    let out = drive_packet_9604(&mut sessions, &forwarding, &mut binding, &frame, meta);
    assert_eq!(out.hit, 1, "the reply must hit the promoted reverse companion");
    assert_eq!(
        out.revoked, 1,
        "the recorded pair lan -> wan is denied: a promoted flow must revoke \
         through the reverse hit (#9604)"
    );
    assert_slots_gone_9604(&sessions, &fwd_key, &rev_key);
    assert_eq!(sessions.policy_revalidation_loud_declines(), 0);
}

/// The collision shape: a `SharedPromote` forward entry whose node-valid
/// ifindex resolves LOCALLY to a denying zone, but whose recorded (peer-)
/// zone permits. Recorded-zone handling keeps it; live-resolving the
/// recorded identity revokes — this cell reds exactly that regression.
#[test]
fn shared_promote_collision_kept_on_reverse_9604() {
    let forwarding = forwarding_with_lan_rule(Some("permit"));
    let mut sessions = SessionTable::new();
    let fwd_key = flow_key_to(DST);
    let rev_key = reverse_session_key(&fwd_key, NatDecision::default());
    // Recorded identity: an interface number that is live-resolvable on THIS
    // node to the `wan` zone (which admits nothing back), while the recorded
    // zone is the permitting `lan`.
    let mut fwd_metadata = metadata(false);
    fwd_metadata.ingress_ifindex = WAN_IFINDEX as u32;
    fwd_metadata.ingress_zone = TEST_LAN_ZONE_ID;
    assert!(
        sessions.upsert_synced_with_origin(
            SessionInstall {
                key: fwd_key.clone(),
                decision: decision(WAN_IFINDEX),
                metadata: fwd_metadata,
                origin: SessionOrigin::SharedPromote,
                now_ns: 122_000_000_000,
                protocol: PROTO_TCP,
                tcp_flags: 0,
                session_id: 0,
                tcp_close_class: 0,
            },
            true,
        ),
        "9604 fixture must promote the forward half"
    );
    assert!(
        sessions.upsert_synced_with_origin(
            SessionInstall {
                key: rev_key.clone(),
                decision: SessionDecision {
                    resolution: decision(WAN_IFINDEX).resolution,
                    nat: NatDecision::default(),
                },
                metadata: reverse_metadata_for_9604(TEST_LAN_ZONE_ID, TEST_WAN_ZONE_ID),
                origin: SessionOrigin::SharedPromote,
                now_ns: 122_000_000_000,
                protocol: PROTO_TCP,
                tcp_flags: 0,
                session_id: 0,
                tcp_close_class: 0,
            },
            true,
        ),
        "9604 fixture must promote the reverse half"
    );
    let mut binding = binding_for_9604(WAN_IFINDEX, "reth0.80");
    let (frame, meta) = reverse_tcp_frame_v4_9604(&rev_key, WAN_IFINDEX);
    let out = drive_packet_9604(&mut sessions, &forwarding, &mut binding, &frame, meta);
    assert_eq!(out.hit, 1, "the reply must hit the promoted reverse companion");
    assert_eq!(
        out.revoked, 0,
        "the RECORDED pair lan -> wan is permitted: a promoted identity must \
         never be live-resolved locally, where its number names an unrelated \
         zone. A non-zero count means the provenance table resolves \
         non-locally-authored identities (#9604)"
    );
    assert_eq!(session_count(&sessions), 2, "the promoted pair must survive");
    assert_eq!(sessions.policy_revalidation_loud_declines(), 0);
}

/// Recorded zone 0 declines: a synced entry that was never zone-adjudicated
/// has no verdict to re-derive. Evaluating zone 0 would fall to the default
/// policy and revoke — this cell reds that shape.
#[test]
fn recorded_zone_zero_declines_on_reverse_9604() {
    let forwarding = forwarding_with_lan_rule(None);
    let mut sessions = SessionTable::new();
    let fwd_key = flow_key_to(DST);
    let rev_key = reverse_session_key(&fwd_key, NatDecision::default());
    let mut fwd_metadata = metadata(false);
    fwd_metadata.ingress_zone = 0;
    assert!(
        sessions.upsert_synced(
            fwd_key.clone(),
            decision(WAN_IFINDEX),
            fwd_metadata,
            122_000_000_000,
            PROTO_TCP,
            0,
            true,
        ),
        "9604 fixture must import the forward half"
    );
    assert!(
        sessions.upsert_synced(
            rev_key.clone(),
            SessionDecision {
                resolution: decision(WAN_IFINDEX).resolution,
                nat: NatDecision::default(),
            },
            reverse_metadata_for_9604(0, TEST_WAN_ZONE_ID),
            122_000_000_000,
            PROTO_TCP,
            0,
            true,
        ),
        "9604 fixture must import the reverse half"
    );
    let mut binding = binding_for_9604(WAN_IFINDEX, "reth0.80");
    let (frame, meta) = reverse_tcp_frame_v4_9604(&rev_key, WAN_IFINDEX);
    let out = drive_packet_9604(&mut sessions, &forwarding, &mut binding, &frame, meta);
    assert_eq!(out.hit, 1, "the reply must hit the reverse companion");
    assert_eq!(
        out.revoked, 0,
        "a recorded zone of 0 is a LOOKUP FAILURE, not an unzoned interface: \
         it must decline, not evaluate to default-deny and revoke (#9513 via \
         #9604)"
    );
    assert_eq!(session_count(&sessions), 2, "the pair must survive the decline");
    assert_eq!(sessions.policy_revalidation_loud_declines(), 0);
}
/// Snapshots for the zone-move detector: generation G leaves `reth1.0` in
/// `lan` with a `lan -> wan` permit; generation G+1 (same table) moves only
/// that interface into `live_zone`. Models the commit transition, not just
/// live-ledger sourcing: the pair is stamped under G first.
fn zone_move_snapshots_9604(live_zone: &str) -> (ForwardingState, ForwardingState) {
    let mut snap_g = policy_deny_snapshot();
    snap_g.generation = 7;
    snap_g.fib_generation = 9;
    snap_g.policies.clear();
    snap_g.policies.push(PolicyRuleSnapshot {
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
    let mut snap_moved = snap_g.clone();
    snap_moved.generation = 8;
    for iface in snap_moved.interfaces.iter_mut() {
        if iface.ifindex == LAN_IFINDEX {
            iface.zone = live_zone.to_string();
        }
    }
    (
        build_forwarding_state(&snap_g),
        build_forwarding_state(&snap_moved),
    )
}

/// Drive a forward packet (LAN arrival) then a reverse packet (WAN arrival)
/// across a zone move, asserting the G-transition stamps in between.
fn drive_move_then_reverse_9604(live_zone: &str) -> (SessionTable, SessionKey, SessionKey, ReverseOutcome) {
    let (forwarding_g, forwarding_moved) = zone_move_snapshots_9604(live_zone);
    let mut sessions = SessionTable::new();
    let fwd_key = flow_key_to(DST);
    let rev_key = install_pair_9604(
        &mut sessions,
        &fwd_key,
        decision(WAN_IFINDEX),
        metadata(false),
        SessionOrigin::ForwardFlow,
        SessionOrigin::ReverseFlow,
    );
    // Under G the forward judgment permits and stamps the forward half — the
    // transition model: the pair is judged, not merely installed, before the move.
    let mut binding_fwd = binding_for_9604(LAN_IFINDEX, "reth1.0");
    let frame_fwd = build_txn_tcp_syn_frame_v4(SRC, DST, SPORT, DPORT, TCP_ACK);
    let meta_fwd = txn_meta_v4(LAN_IFINDEX as u32, TCP_ACK, frame_fwd.len() as u16);
    let out_fwd = drive_packet_9604(&mut sessions, &forwarding_g, &mut binding_fwd, &frame_fwd, meta_fwd);
    assert_eq!(out_fwd.hit, 1, "9604 move fixture: the forward packet must hit");
    assert_eq!(out_fwd.revoked, 0, "9604 move fixture: G still permits lan -> wan");
    assert_eq!(
        sessions.policy_revalidation_target(&fwd_key),
        PolicyRevalidationTarget::Fresh,
        "9604 move fixture: the forward half must be stamped under G, or the \
         cell models an install rather than a commit transition"
    );
    assert_eq!(
        sessions.policy_revalidation_target(&rev_key),
        PolicyRevalidationTarget::Stale(rev_key.clone()),
        "9604 move fixture: hit-only stamping leaves the reverse half stale"
    );
    let mut binding_rev = binding_for_9604(WAN_IFINDEX, "reth0.80");
    let (frame_rev, meta_rev) = reverse_tcp_frame_v4_9604(&rev_key, WAN_IFINDEX);
    let out = drive_packet_9604(&mut sessions, &forwarding_moved, &mut binding_rev, &frame_rev, meta_rev);
    (sessions, fwd_key, rev_key, out)
}

/// THE MOVE DETECTOR. The interface moved `lan -> dmz` between generations;
/// only `lan -> wan` is permitted. A reverse-only flow must revoke: the
/// from-zone is live-resolved from the forward entry's recorded admitting
/// identity, not replayed from its recorded zone.
///
/// An implementation that judges `RecordedZone` everywhere keeps here — the
/// recorded `lan` still permits — so this cell reds exactly that shape.
#[test]
fn zone_membership_move_reaches_reverse_only_flow_9604() {
    let (sessions, fwd_key, rev_key, out) = drive_move_then_reverse_9604("dmz");
    assert_eq!(out.hit, 1, "the reply must hit the reverse companion");
    assert_eq!(
        out.revoked, 1,
        "the admitting interface now lives in `dmz`, which admits nothing to \
         wan: the reverse-fed flow must revoke on the LIVE pair. 0 means the \
         from-zone was replayed from the entry's recorded zone (#9384 via #9604)"
    );
    assert_slots_gone_9604(&sessions, &fwd_key, &rev_key);
    assert_eq!(sessions.policy_revalidation_loud_declines(), 0);
}

/// THE ZERO-EVALUATES TWIN of the move detector. The interface moved out of
/// EVERY zone: a nonzero identity resolving to zone 0 EVALUATES under the
/// default policy (default deny → revoke), it does not decline.
///
/// Redundancy is deliberate: the `dmz` cell above also revokes, but through a
/// zoned-but-unpermitted pair — an implementation that conflates "zone 0"
/// with "no identity" keeps HERE while passing there.
#[test]
fn unzoned_ingress_evaluates_default_on_reverse_9604() {
    let (sessions, fwd_key, rev_key, out) = drive_move_then_reverse_9604("");
    assert_eq!(out.hit, 1, "the reply must hit the reverse companion");
    assert_eq!(
        out.revoked, 1,
        "the admitting interface resolves but sits in NO zone: a new flow \
         would fall to default-deny, and the reverse-fed established flow must \
         be judged the same way. 0 conflates an unzoned interface with a lookup \
         failure (#9513 via #9604)"
    );
    assert_slots_gone_9604(&sessions, &fwd_key, &rev_key);
    assert_eq!(sessions.policy_revalidation_loud_declines(), 0);
}

/// THE ZERO-IDENTITY DECLINE. A trusted-origin forward entry with NO recorded
/// ingress identity (a fabric-installed forward half stamps none) declines —
/// there is nothing live to resolve and no recorded zone to fall back to on
/// the live arm.
///
/// An implementation that feeds 0 through the ledger evaluates zone 0 and
/// revokes under default-deny — this cell reds exactly that shape.
#[test]
fn trusted_zero_ifindex_declines_on_reverse_9604() {
    let forwarding = forwarding_with_lan_rule(None);
    let mut sessions = SessionTable::new();
    let fwd_key = flow_key_to(DST);
    let mut fwd_metadata = metadata(false);
    fwd_metadata.ingress_ifindex = 0;
    let rev_key = install_pair_9604(
        &mut sessions,
        &fwd_key,
        decision(WAN_IFINDEX),
        fwd_metadata,
        SessionOrigin::ForwardFlow,
        SessionOrigin::ReverseFlow,
    );
    let mut binding = binding_for_9604(WAN_IFINDEX, "reth0.80");
    let (frame, meta) = reverse_tcp_frame_v4_9604(&rev_key, WAN_IFINDEX);
    let out = drive_packet_9604(&mut sessions, &forwarding, &mut binding, &frame, meta);
    assert_eq!(out.hit, 1, "the reply must hit the reverse companion");
    assert_eq!(
        out.revoked, 0,
        "no recorded ingress identity means no live resolution is possible: \
         the judgment must decline, not evaluate a zero identity to \
         default-deny (#9513 via #9604)"
    );
    assert_eq!(session_count(&sessions), 2, "the pair must survive the decline");
    assert_eq!(
        sessions.policy_revalidation_target(&fwd_key),
        PolicyRevalidationTarget::Stale(fwd_key.clone()),
        "a decline stamps nothing"
    );
    assert_eq!(sessions.policy_revalidation_loud_declines(), 0);
}
/// THE CONTROL that gives every deny cell above its aim — and doubles as a
/// forward-pair-judgment proof. Same packet, same path, policy PERMITTING:
/// nothing may be revoked. Under this asymmetric fixture (no `wan -> lan`
/// rule) a broken reverse-pair evaluation denies and revokes, so this also
/// reds adjudicating the reverse entry as its own pair.
#[test]
fn a_still_permitted_reverse_fed_flow_is_kept_9604() {
    let forwarding = forwarding_with_lan_rule(Some("permit"));
    let mut sessions = SessionTable::new();
    let fwd_key = flow_key_to(DST);
    let rev_key = install_pair_9604(
        &mut sessions,
        &fwd_key,
        decision(WAN_IFINDEX),
        metadata(false),
        SessionOrigin::ForwardFlow,
        SessionOrigin::ReverseFlow,
    );
    let mut binding = binding_for_9604(WAN_IFINDEX, "reth0.80");
    let (frame, meta) = reverse_tcp_frame_v4_9604(&rev_key, WAN_IFINDEX);
    let out = drive_packet_9604(&mut sessions, &forwarding, &mut binding, &frame, meta);
    assert_eq!(out.hit, 1, "the reply must hit the reverse companion");
    assert_eq!(
        out.revoked, 0,
        "policy still permits lan -> wan, so nothing may be revoked. A \
         re-derivation that denied unconditionally — or that adjudicated the \
         reverse pair (wan -> lan, unpermitted here) — would revoke (#9604)"
    );
    assert_eq!(
        session_count(&sessions),
        2,
        "the permitted pair — and its translation — must be untouched"
    );
    assert_eq!(sessions.policy_revalidation_loud_declines(), 0);
}

/// DNAT kept through the reverse path: the rule names the REAL server, the
/// wire carries the VIP, and only a post-translation judgment matches.
#[test]
fn dnat_pair_permit_names_real_server_kept_on_reverse_9604() {
    let (syn, meta_syn, _ack, _meta_ack) = dnat_frames();
    let out = admit_then_reverse_9604(
        inbound_dnat_snapshot(wan_to_lan_permit(DNAT_REAL, "permit-internal")),
        inbound_dnat_snapshot(wan_to_lan_permit(DNAT_REAL, "permit-internal")),
        WAN_INGRESS_IFINDEX,
        "reth0.80",
        &syn,
        meta_syn,
        LAN_IFINDEX,
        "reth1.0",
    );
    assert_eq!(out.hit, 1, "the DNAT reply must hit the reverse companion");
    assert_eq!(
        out.revoked, 0,
        "the policy is unchanged and names the real server: judging the wire \
         VIP would miss the permit and revoke every published service on every \
         route event (#9382 via #9604)"
    );
    assert_eq!(session_count(&out.sessions), 2, "the pair must survive");
    assert_eq!(out.sessions.policy_revalidation_loud_declines(), 0);
}

/// Port order through the reverse path: the 443-only permit matches the
/// forward wire ports. A reply-tuple judgment (src 443, dst 12345) misses and
/// revokes — this cell reds exactly that shape.
#[test]
fn port_scoped_permit_kept_on_reverse_9604() {
    let mut snapshot = policy_deny_snapshot();
    snapshot.generation = 7;
    snapshot.fib_generation = 9;
    snapshot.policies.clear();
    snapshot
        .policies
        .push(port_scoped_permit_9604("443", ""));
    let forwarding = build_forwarding_state(&snapshot);
    let mut sessions = SessionTable::new();
    let fwd_key = flow_key_to(DST);
    let rev_key = install_pair_9604(
        &mut sessions,
        &fwd_key,
        decision(WAN_IFINDEX),
        metadata(false),
        SessionOrigin::ForwardFlow,
        SessionOrigin::ReverseFlow,
    );
    let mut binding = binding_for_9604(WAN_IFINDEX, "reth0.80");
    let (frame, meta) = reverse_tcp_frame_v4_9604(&rev_key, WAN_IFINDEX);
    let out = drive_packet_9604(&mut sessions, &forwarding, &mut binding, &frame, meta);
    assert_eq!(out.hit, 1, "the reply must hit the reverse companion");
    assert_eq!(
        out.revoked, 0,
        "the flow serves dst-port 443, which the only permit covers. A \
         non-zero count means the judgment read the reply tuple's ports \
         (dst 12345) instead of the forward pair's (#9604)"
    );
    assert_eq!(session_count(&sessions), 2, "the pair must survive");
    assert_eq!(sessions.policy_revalidation_loud_declines(), 0);
}

/// Source-port sourcing through the reverse path: the term constrains the
/// CLIENT source port (12345), which no reply-tuple slot carries. An
/// implementation supplying any other slot's port misses and revokes.
#[test]
fn source_port_scoped_permit_kept_on_reverse_9604() {
    let mut snapshot = policy_deny_snapshot();
    snapshot.generation = 7;
    snapshot.fib_generation = 9;
    snapshot.policies.clear();
    snapshot
        .policies
        .push(port_scoped_permit_9604("", "12345"));
    let forwarding = build_forwarding_state(&snapshot);
    let mut sessions = SessionTable::new();
    let fwd_key = flow_key_to(DST);
    let rev_key = install_pair_9604(
        &mut sessions,
        &fwd_key,
        decision(WAN_IFINDEX),
        metadata(false),
        SessionOrigin::ForwardFlow,
        SessionOrigin::ReverseFlow,
    );
    let mut binding = binding_for_9604(WAN_IFINDEX, "reth0.80");
    let (frame, meta) = reverse_tcp_frame_v4_9604(&rev_key, WAN_IFINDEX);
    let out = drive_packet_9604(&mut sessions, &forwarding, &mut binding, &frame, meta);
    assert_eq!(out.hit, 1, "the reply must hit the reverse companion");
    assert_eq!(
        out.revoked, 0,
        "the flow's source port is 12345, which the only permit constrains on. \
         A non-zero count means `src_port` was sourced from any slot but the \
         forward pair's (#9604)"
    );
    assert_eq!(session_count(&sessions), 2, "the pair must survive");
    assert_eq!(sessions.policy_revalidation_loud_declines(), 0);
}

/// SNAT kept under a source-scoped permit: the rule names the PRE-translation
/// client subnet. A translated-source judgment (the pool address) misses and
/// revokes — this cell reds exactly that shape.
#[test]
fn snat_src_scoped_permit_kept_on_reverse_9604() {
    let mut snap = nat_snapshot();
    snap.generation = 7;
    snap.fib_generation = 9;
    snap.source_nat_rules = vec![SourceNATRuleSnapshot {
        name: "snat-pool".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["0.0.0.0/0".to_string()],
        pool_name: "pool-a".to_string(),
        pool_addresses: vec!["172.16.80.100".to_string()],
        port_low: 20000,
        port_high: 20999,
        ..Default::default()
    }];
    snap.policies.clear();
    snap.policies.push(PolicyRuleSnapshot {
        name: "lan-out-scoped".into(),
        from_zone: "lan".into(),
        to_zone: "wan".into(),
        source_addresses: vec!["10.0.61.0/24".into()],
        destination_addresses: vec!["any".into()],
        applications: vec!["any".into()],
        application_terms: Vec::new(),
        action: "permit".into(),
        ..Default::default()
    });
    // Via the default route — see the deny cell: DST has no neighbor entry.
    let syn = build_txn_tcp_syn_frame_v4(
        SRC,
        Ipv4Addr::new(8, 8, 8, 8),
        SPORT,
        DPORT,
        TCP_FLAG_SYN,
    );
    let meta_syn = txn_meta_v4(LAN_IFINDEX as u32, TCP_FLAG_SYN, syn.len() as u16);
    let out = admit_then_reverse_9604(
        snap.clone(),
        snap,
        LAN_IFINDEX,
        "reth1.0",
        &syn,
        meta_syn,
        WAN_IFINDEX,
        "reth0.80",
    );
    assert_eq!(out.hit, 1, "the SNAT reply must hit the reverse companion");
    assert_eq!(
        out.revoked, 0,
        "the rule names the PRE-translation client subnet 10.0.61.0/24, which \
         covers this flow: Junos evaluates before source NAT, and so must this \
         derivation. A non-zero count means the translated pool address was \
         judged as the source (#9604)"
    );
    assert_eq!(session_count(&out.sessions), 2, "the SNAT pair must survive");
    assert_eq!(out.sessions.policy_revalidation_loud_declines(), 0);
}

/// THE GENUINE LONE-REVERSE DECLINE. Unlike the 8356 trap cell (which never
/// reaches revalidation — it is foreign-dropped), this installs a lone
/// reverse entry under its REVERSE key and drives an owner-arriving reply, so
/// the missing-companion decline is what keeps it.
#[test]
fn lone_reverse_companion_reaching_revalidation_is_declined_9604() {
    let forwarding = forwarding_with_lan_rule(None);
    let mut sessions = SessionTable::new();
    let fwd_key = flow_key_to(DST);
    let rev_key = reverse_session_key(&fwd_key, NatDecision::default());
    assert!(
        sessions.install_with_protocol_with_origin(
            rev_key.clone(),
            SessionDecision {
                resolution: decision(WAN_IFINDEX).resolution,
                nat: NatDecision::default(),
            },
            reverse_metadata_for_9604(TEST_LAN_ZONE_ID, TEST_WAN_ZONE_ID),
            SessionOrigin::ReverseFlow,
            122_000_000_000,
            PROTO_TCP,
            0,
        ),
        "9604 fixture must install the lone reverse entry"
    );
    let mut binding = binding_for_9604(WAN_IFINDEX, "reth0.80");
    let (frame, meta) = reverse_tcp_frame_v4_9604(&rev_key, WAN_IFINDEX);
    let out = drive_packet_9604(&mut sessions, &forwarding, &mut binding, &frame, meta);
    assert_eq!(
        out.hit, 1,
        "the reply must HIT the lone reverse entry — arrival wan equals the \
         recorded wan ingress, so this is an owner packet that REACHES \
         revalidation (unlike the 8356 trap, which is foreign-dropped)"
    );
    assert_eq!(
        out.revoked, 0,
        "with no forward companion there is no forward pair to judge: the \
         derivation must decline, not synthesize authority from swapped zones \
         (#9604)"
    );
    assert_eq!(session_count(&sessions), 1, "the lone companion must survive");
    assert_eq!(
        sessions.policy_revalidation_target(&rev_key),
        PolicyRevalidationTarget::Stale(rev_key.clone()),
        "a decline stamps nothing"
    );
    assert_eq!(sessions.policy_revalidation_loud_declines(), 0);
}

/// A reverse packet from a NON-owning zone is foreign: dropped, and the
/// session is neither torn down nor stamped. The reply tuple arrives on LAN
/// while the reverse entry records a WAN ingress.
#[test]
fn foreign_reverse_packet_neither_revokes_nor_stamps_9604() {
    let forwarding = forwarding_with_lan_rule(None);
    let mut sessions = SessionTable::new();
    let fwd_key = flow_key_to(DST);
    let rev_key = install_pair_9604(
        &mut sessions,
        &fwd_key,
        decision(WAN_IFINDEX),
        metadata(false),
        SessionOrigin::ForwardFlow,
        SessionOrigin::ReverseFlow,
    );
    let mut binding = binding_for_9604(LAN_IFINDEX, "reth1.0");
    let (frame, meta) = reverse_tcp_frame_v4_9604(&rev_key, LAN_IFINDEX);
    let out = drive_packet_9604(&mut sessions, &forwarding, &mut binding, &frame, meta);
    assert_eq!(out.hit, 1, "the spoofed reply must still HIT the session entry");
    assert_eq!(
        out.foreign_drops, 1,
        "a reply arriving outside the flow's to-zone is FOREIGN and must drop \
         without acting on the session (#9519)"
    );
    assert_eq!(out.revoked, 0, "a foreign packet must never revoke");
    assert_eq!(session_count(&sessions), 2, "the pair must survive");
    assert_eq!(
        sessions.policy_revalidation_target(&rev_key),
        PolicyRevalidationTarget::Stale(rev_key.clone()),
        "a foreign packet must not stamp"
    );
    assert_eq!(
        sessions.policy_revalidation_target(&fwd_key),
        PolicyRevalidationTarget::Stale(fwd_key.clone()),
        "and neither half may be re-stamped by it"
    );
    assert_eq!(sessions.policy_revalidation_loud_declines(), 0);
}

/// HIT-ONLY STAMPING, observed. A reverse permit stamps the reverse half only;
/// the same-generation forward packet then re-derives (rather than coasting
/// on a cross-direction stamp) and stamps the forward half. Verdict-only
/// assertions would pass under dual-stamp too; the stamp probes carry the proof.
#[test]
fn same_generation_reverse_then_forward_kept_9604() {
    let forwarding = forwarding_with_lan_rule(Some("permit"));
    let mut sessions = SessionTable::new();
    let fwd_key = flow_key_to(DST);
    let rev_key = install_pair_9604(
        &mut sessions,
        &fwd_key,
        decision(WAN_IFINDEX),
        metadata(false),
        SessionOrigin::ForwardFlow,
        SessionOrigin::ReverseFlow,
    );
    let mut binding_rev = binding_for_9604(WAN_IFINDEX, "reth0.80");
    let (frame_rev, meta_rev) = reverse_tcp_frame_v4_9604(&rev_key, WAN_IFINDEX);
    let out_rev = drive_packet_9604(&mut sessions, &forwarding, &mut binding_rev, &frame_rev, meta_rev);
    assert_eq!((out_rev.hit, out_rev.revoked), (1, 0), "the reverse packet must hit and keep");
    assert_eq!(
        sessions.policy_revalidation_target(&rev_key),
        PolicyRevalidationTarget::Fresh,
        "the reverse permit stamps the hit half"
    );
    assert_eq!(
        sessions.policy_revalidation_target(&fwd_key),
        PolicyRevalidationTarget::Stale(fwd_key.clone()),
        "hit-only stamping writes NO forward stamp from the reverse path — a \
         dual-stamp would read Fresh here (#9604)"
    );
    let mut binding_fwd = binding_for_9604(LAN_IFINDEX, "reth1.0");
    let frame_fwd = build_txn_tcp_syn_frame_v4(SRC, DST, SPORT, DPORT, TCP_ACK);
    let meta_fwd = txn_meta_v4(LAN_IFINDEX as u32, TCP_ACK, frame_fwd.len() as u16);
    let out_fwd = drive_packet_9604(&mut sessions, &forwarding, &mut binding_fwd, &frame_fwd, meta_fwd);
    assert_eq!((out_fwd.hit, out_fwd.revoked), (1, 0), "the forward packet must hit and keep");
    assert_eq!(
        sessions.policy_revalidation_target(&fwd_key),
        PolicyRevalidationTarget::Fresh,
        "the forward packet re-derived (rather than coasting) and stamped"
    );
    assert_eq!(session_count(&sessions), 2);
    assert_eq!(sessions.policy_revalidation_loud_declines(), 0);
}

/// Side-effect freedom through the reverse path: a reverse-fed permit matches
/// `lan-out` and must not bump its hit counter (nor the default's). The
/// positive control is the shipped #9385 admission cell — a zero delta is
/// meaningless without proof the instrument can move.
#[test]
fn reverse_re_derivation_records_no_hit_9604() {
    let forwarding = forwarding_with_lan_rule(Some("permit"));
    let (rule_before, default_before) = policy_hit_counts_9385(&forwarding);
    assert_ne!(rule_before, u64::MAX, "the `lan-out` rule must exist");
    let mut sessions = SessionTable::new();
    let rev_key = install_pair_9604(
        &mut sessions,
        &flow_key_to(DST),
        decision(WAN_IFINDEX),
        metadata(false),
        SessionOrigin::ForwardFlow,
        SessionOrigin::ReverseFlow,
    );
    let mut binding = binding_for_9604(WAN_IFINDEX, "reth0.80");
    let (frame, meta) = reverse_tcp_frame_v4_9604(&rev_key, WAN_IFINDEX);
    let out = drive_packet_9604(&mut sessions, &forwarding, &mut binding, &frame, meta);
    assert_eq!((out.hit, out.revoked), (1, 0), "the reverse packet must hit and keep");
    let (rule_after, default_after) = policy_hit_counts_9385(&forwarding);
    assert_eq!(
        rule_after, rule_before,
        "the reverse-triggered walk matched `lan-out` and must NOT have bumped \
         it — same phantom-hit contract as the forward path (#9385 via #9604)"
    );
    assert_eq!(
        default_after, default_before,
        "and the implicit-default counter must not move either"
    );
    assert_eq!(sessions.policy_revalidation_loud_declines(), 0);
}

/// THE #6457 CONTRACT for reverse-triggered revocation. A DNAT admit seeds the
/// flow-cache slot (asserted); after the narrowed generation revokes the pair
/// through the reverse hit, NEITHER tuple may forward again — no cached
/// RewriteDescriptor may outlive the session it was seeded from.
///
/// The post-revoke redrives keep the ORIGINAL meta on purpose: the txn
/// harness pins `ValidationState` at generation 7 (`classify_metadata`
/// drops anything else before any lookup, and both the cache stamp and the
/// cache lookup follow `validation`, never the meta), so a slot the revoke
/// failed to evict still matches and forwards — generation invalidation
/// cannot save it in here, only EXPLICIT eviction passes. The kill drive
/// reaches the session path anyway: the reverse tuple keys differently from
/// the seeded forward slot, so it cache-misses into the session
/// re-derivation, which judges the gen-8 snapshot.
#[test]
fn post_revoke_both_tuples_miss_and_drop_9604() {
    let mut snap_permit =
        inbound_dnat_snapshot(wan_to_lan_permit(DNAT_REAL, "permit-internal"));
    snap_permit.generation = 7;
    snap_permit.fib_generation = 9;
    let forwarding_permit = build_forwarding_state(&snap_permit);
    let mut sessions = SessionTable::new();
    let mut binding = binding_for_9604(WAN_INGRESS_IFINDEX, "reth0.80");
    let (_syn, _meta_syn, ack, meta_ack) = dnat_frames();
    // ACK-first: only an eligible packet seeds the flow-cache slot.
    // `should_cache` admits a pure-ACK TCP (or UDP) packet to a cacheable
    // disposition — a SYN admit installs the pair but seeds nothing, which
    // would leave the eviction assertions below vacuous.
    let admit = drive_packet_9604(&mut sessions, &forwarding_permit, &mut binding, &ack, meta_ack);
    assert_eq!((admit.hit, admit.revoked, admit.tx), (0, 0, 1), "phase 1 must MISS, admit and forward");
    assert_eq!(session_count(&sessions), 2, "phase 1 must install the pair");
    let mut fwd_key = None;
    let mut rev_key = None;
    sessions.iter_with_origin(|key, _decision, metadata, _origin| {
        if metadata.is_reverse {
            rev_key = Some(key.clone());
        } else {
            fwd_key = Some(key.clone());
        }
    });
    let (fwd_key, rev_key) = (
        fwd_key.expect("admit must install forward"),
        rev_key.expect("admit must install reverse"),
    );
    assert!(
        txn_flow_cache_entries(&binding) >= 1,
        "admission must seed the flow-cache slot — otherwise the miss+drop \
         assertions below cannot distinguish eviction from an empty cache \
         (got {})",
        txn_flow_cache_entries(&binding)
    );
    // The kill drive IS the first post-install hit, deliberately. Installs
    // stamp `policy_revalidated_gen: 0` while the harness pins the table's
    // live generation at validation 7, so exactly the first hit re-derives
    // (and re-stamps Fresh) — a keep drive here would consume that one
    // re-derivation under permit AND seed a reverse-tuple slot the pinned
    // validation can never invalidate, shielding the kill from the session
    // path (measured: keep moves entries 1 -> 2, the kill then cache-hits
    // (0,0,1)). Reachability from the reply tuple is proved inline by the
    // kill's hit == 1; keep-under-permit is covered by the kept-cells (e.g.
    // `a_still_permitted_reverse_fed_flow_is_kept_9604`).
    let (frame_rev, meta_rev) = reverse_tcp_frame_v4_9604(&rev_key, LAN_IFINDEX);
    // The narrowed post-commit snapshot: the re-derivation judges THIS
    // policy, not the admitting one. (In-harness staleness comes from the
    // install stamp vs the pinned live 7, not from the 7 -> 8 bump — the
    // bump marks the post-commit shape, as in the sibling cells.)
    let mut snap_narrow =
        inbound_dnat_snapshot(wan_to_lan_permit("10.0.61.200/32", "permit-someone-else"));
    snap_narrow.generation = 8;
    snap_narrow.fib_generation = 9;
    let forwarding_narrowed8 = build_forwarding_state(&snap_narrow);
    // Drive the kill with the ORIGINAL meta: the harness pins validation at
    // generation 7, so a re-stamped meta dies in `classify_metadata`
    // (`ConfigGenerationMismatch`) before any lookup. No re-stamp is needed
    // anyway — the reverse tuple cache-misses (its 5-tuple differs from the
    // seeded forward slot) straight into the session re-derivation.
    let kill = drive_packet_9604(&mut sessions, &forwarding_narrowed8, &mut binding, &frame_rev, meta_rev);
    assert_eq!((kill.hit, kill.revoked, kill.tx), (1, 1, 0), "the narrowed drive must hit and revoke");
    assert_slots_gone_9604(&sessions, &fwd_key, &rev_key);
    // The txn driver runs one descriptor per pass WITHOUT the worker loop's
    // end-of-poll drain (`drain_revoked_flow_cache_keys`), so the collected
    // keys sit in scratch and the seeded slot is still present here. That is
    // a driver boundary, not a product gap: in production the same tick
    // walks these keys over every binding of the worker. Assert the eviction
    // SET first — a key/nat mispairing strands the slot (the #9604 pairing
    // contract) — then perform that same-tick walk explicitly through the
    // production per-binding primitive and prove the behavioral contract on
    // the redrives below.
    let evict_keys = binding.scratch.scratch_filter_revoked_keys.clone();
    assert!(
        evict_keys.contains(&fwd_key),
        "the eviction set must cover the seeded forward slot's key, or the \
         same-tick drain leaves the descriptor live (got {} keys)",
        evict_keys.len()
    );
    assert!(
        evict_keys.contains(&rev_key),
        "the eviction set must cover the reverse companion too, or its slot \
         survives on a flow the table just deleted (got {} keys)",
        evict_keys.len()
    );
    for key in &evict_keys {
        binding.flow.flow_cache.invalidate_slot(key, binding.ifindex);
    }
    assert_eq!(
        txn_flow_cache_entries(&binding),
        0,
        "the same-tick drain must empty the cache — otherwise the redrives \
         below cannot distinguish eviction from a broken walk"
    );
    // Both tuples re-driven at the OLD generation: a slot the revoke failed to
    // evict would still match its gen-7 stamp and forward off a stale
    // descriptor with no session row (#6457). Generation invalidation cannot
    // save it — the stamps agree — so only EXPLICIT eviction passes this.
    let again_rev = drive_packet_9604(&mut sessions, &forwarding_narrowed8, &mut binding, &frame_rev, meta_rev);
    assert_eq!(
        (again_rev.hit, again_rev.tx), (0, 0),
        "the revoked reverse tuple must miss and drop, not forward off a \
         surviving cache slot"
    );
    let again_fwd = drive_packet_9604(&mut sessions, &forwarding_narrowed8, &mut binding, &ack, meta_ack);
    assert_eq!(
        (again_fwd.hit, again_fwd.tx), (0, 0),
        "the revoked forward tuple must miss and drop, not forward off a \
         surviving cache slot"
    );
    assert_eq!(sessions.policy_revalidation_loud_declines(), 0);
}

/// #9604 review fold (GPT HIGH): production-admitted fabric-ingress flows.
///
/// A flow this node admits off the fabric installs as `ForwardFlow` with
/// `fabric_ingress: true` and ingress identity (0, 0) — origin alone cannot
/// select the from-zone source, so the pre-fold code live-resolved the zero
/// identity, declined in the cold body, and left every fabric-admitted
/// reverse-only flow on its old verdict. These cells admit through the
/// production path (stamped `lan` frame on the fabric parent, split-RG
/// ha_state so the stamp validates and the flow forwards locally) and pin
/// the installed shape before driving the reverse packet under the
/// narrowed/unchanged generation.
const FABRIC_PARENT_9604: i32 = 21;
const FABRIC_WAN_PEER_9604: Ipv4Addr = Ipv4Addr::new(8, 8, 8, 8);

/// Phase-1 snapshot: fabric links + lan neighbor (the #7770 fixture shape),
/// allow-all `lan -> wan` (from `nat_snapshot`), NO source NAT — a pure
/// forward flow keeps the key math direct (pool NAT through the reverse path
/// has its own cells) — pinned generations.
fn fabric_admit_snapshot_9604() -> crate::ConfigSnapshot {
    let mut snap = nat_snapshot_with_fabric();
    snap.neighbors.push(NeighborSnapshot {
        interface: "reth1.0".to_string(),
        ifindex: 24,
        family: "inet".to_string(),
        ip: "10.0.61.102".to_string(),
        mac: "de:ad:be:ef:00:01".to_string(),
        state: "reachable".to_string(),
        ..Default::default()
    });
    snap.source_nat_rules.clear();
    snap.generation = 7;
    snap.fib_generation = 9;
    snap
}

/// The #7770 stamp shape, claiming `zone`: peer fabric MAC as dst (V1a),
/// magic + zone id as src.
fn stamp_fabric_zone_9604(frame: &mut [u8], zone: u16) {
    let [hi, lo] = zone.to_be_bytes();
    frame[0..6].copy_from_slice(&[0x02, 0xbf, 0x72, 0xff, 0x00, 0x01]);
    frame[6..12].copy_from_slice(&[0x02, 0xbf, 0x72, FABRIC_ZONE_MAC_MAGIC, hi, lo]);
}

/// Split-RG ha_state for the admit leg: RG1 (wan) forwarding-active so the
/// flow installs `ForwardCandidate` and forwards locally; RG2 (lan) NOT
/// active so the `lan` stamp validates (V1b: not ALL bound RGs local) — the
/// shape the peer punts from.
fn ha_state_fabric_admit_9604(now_secs: u64) -> BTreeMap<i32, HAGroupRuntime> {
    BTreeMap::from([
        (
            1,
            HAGroupRuntime {
                active: true,
                watchdog_timestamp: now_secs,
                lease: HAGroupRuntime::active_lease_until(now_secs, now_secs),
            },
        ),
        (2, HAGroupRuntime { active: false, ..Default::default() }),
    ])
}

/// The phase-1 admit frame: `lan -> wan` ACK stamped `lan`, arriving on the
/// fabric parent. ACK (not SYN) so admission seeds the flow-cache slot —
/// otherwise the post-revoke eviction assertions below cannot distinguish
/// eviction from an empty cache (the #6457 contract, as in
/// `post_revoke_both_tuples_miss_and_drop_9604`).
fn fabric_admit_frame_9604() -> (Vec<u8>, UserspaceDpMeta) {
    let mut frame =
        build_txn_tcp_syn_frame_v4(SRC, FABRIC_WAN_PEER_9604, SPORT, DPORT, TCP_ACK);
    stamp_fabric_zone_9604(&mut frame, TEST_LAN_ZONE_ID);
    let meta = txn_meta_v4(FABRIC_PARENT_9604 as u32, TCP_ACK, frame.len() as u16);
    (frame, meta)
}

struct FabricAdmitOutcome {
    sessions: SessionTable,
    binding: BindingWorker,
    fwd_key: SessionKey,
    rev_key: SessionKey,
}

/// Shared phase 1: admit a `lan -> wan` flow off the fabric through the
/// production path and pin the installed shape — `ForwardFlow` origin with
/// `fabric_ingress` provenance and zero ingress identity is the exact shape
/// the from-zone selection keys on.
fn admit_fabric_flow_9604() -> FabricAdmitOutcome {
    let forwarding = build_forwarding_state(&fabric_admit_snapshot_9604());
    let now_secs = monotonic_nanos() / 1_000_000_000;
    let ha_state = ha_state_fabric_admit_9604(now_secs);
    let mut binding = binding_for_9604(FABRIC_PARENT_9604, "ge-0-0-0");
    let (frame, meta) = fabric_admit_frame_9604();
    let mut sessions = SessionTable::new();
    let (_batch, dbg) =
        txn_run_descriptor(&mut binding, &mut sessions, &forwarding, &ha_state, &frame, meta);
    assert_eq!(
        (dbg.session_hit, dbg.policy_revoked_sessions, dbg.tx),
        (0, 0, 1),
        "phase 1 must MISS, admit off the fabric stamp, and forward"
    );
    assert_eq!(
        session_count(&sessions),
        2,
        "phase 1 must install the forward + reverse pair"
    );
    assert!(
        txn_flow_cache_entries(&binding) >= 1,
        "admission must seed the flow-cache slot — otherwise the post-revoke \
         miss+drop assertions below cannot distinguish eviction from an empty \
         cache"
    );
    let mut fwd_key = None;
    let mut rev_key = None;
    let mut fwd_shape = None;
    sessions.iter_with_origin(|key, _decision, metadata, origin| {
        if metadata.is_reverse {
            rev_key = Some(key.clone());
        } else {
            fwd_key = Some(key.clone());
            fwd_shape = Some((metadata.clone(), origin));
        }
    });
    let fwd_key = fwd_key.expect("admit must install a forward entry");
    let rev_key = rev_key.expect("admit must install a reverse companion");
    let (fwd_metadata, fwd_origin) =
        fwd_shape.expect("admit must install a forward entry");
    assert_eq!(
        fwd_origin,
        SessionOrigin::ForwardFlow,
        "a fabric-admitted flow installs as ForwardFlow — origin alone must \
         not select the from-zone source (#9604 review fold)"
    );
    assert!(
        fwd_metadata.fabric_ingress,
        "the admitted entry must carry fabric-ingress provenance"
    );
    assert_eq!(
        (fwd_metadata.ingress_ifindex, fwd_metadata.ingress_vlan_id),
        (0, 0),
        "a fabric-admitted entry stamps NO ingress identity (#7096)"
    );
    assert_eq!(
        (fwd_metadata.ingress_zone, fwd_metadata.egress_zone),
        (TEST_LAN_ZONE_ID, TEST_WAN_ZONE_ID),
        "the admitted entry records the peer-adjudicated pair"
    );
    FabricAdmitOutcome {
        sessions,
        binding,
        fwd_key,
        rev_key,
    }
}

/// The narrowed phase-2 snapshot over the admit fixture: no `lan -> wan`
/// rule at all (default deny), generation bumped to mark the post-commit
/// shape.
fn fabric_narrowed_snapshot_9604() -> crate::ConfigSnapshot {
    let mut snap = fabric_admit_snapshot_9604();
    snap.policies.clear();
    snap.generation = 8;
    snap
}

/// Same, but the `lan -> wan` rule survives as `reject` (#9381 through the
/// fabric-ingress reverse path).
fn fabric_reject_snapshot_9604() -> crate::ConfigSnapshot {
    let mut snap = fabric_narrowed_snapshot_9604();
    snap.policies.push(PolicyRuleSnapshot {
        name: "lan-out".into(),
        from_zone: "lan".into(),
        to_zone: "wan".into(),
        source_addresses: vec!["any".into()],
        destination_addresses: vec!["any".into()],
        applications: vec!["any".into()],
        application_terms: Vec::new(),
        action: "reject".into(),
        ..Default::default()
    });
    snap
}

/// Post-revoke eviction half, mirrored from
/// `post_revoke_both_tuples_miss_and_drop_9604`: the eviction set must cover
/// both keys, the same-tick drain runs explicitly (the txn driver skips it),
/// and both tuples re-driven at the old generation must miss and drop.
fn assert_fabric_evicted_9604(
    outcome: &mut FabricAdmitOutcome,
    forwarding: &ForwardingState,
    frame_rev: &[u8],
    meta_rev: UserspaceDpMeta,
) {
    let FabricAdmitOutcome {
        sessions,
        binding,
        fwd_key,
        rev_key,
    } = outcome;
    let evict_keys = binding.scratch.scratch_filter_revoked_keys.clone();
    assert!(
        evict_keys.contains(fwd_key),
        "the eviction set must cover the seeded forward slot's key (got {} keys)",
        evict_keys.len()
    );
    assert!(
        evict_keys.contains(rev_key),
        "the eviction set must cover the reverse companion too (got {} keys)",
        evict_keys.len()
    );
    for key in &evict_keys {
        binding.flow.flow_cache.invalidate_slot(key, binding.ifindex);
    }
    assert_eq!(
        txn_flow_cache_entries(binding),
        0,
        "the same-tick drain must empty the cache"
    );
    let again_rev = drive_packet_9604(sessions, forwarding, binding, frame_rev, meta_rev);
    assert_eq!(
        (again_rev.hit, again_rev.tx),
        (0, 0),
        "the revoked reverse tuple must miss and drop, not forward off a \
         surviving cache slot"
    );
    let (frame_fwd, meta_fwd) = fabric_admit_frame_9604();
    let again_fwd = drive_packet_9604(sessions, forwarding, binding, &frame_fwd, meta_fwd);
    assert_eq!(
        (again_fwd.hit, again_fwd.tx),
        (0, 0),
        "the revoked forward tuple must miss and drop, not forward off a \
         surviving cache slot"
    );
}

/// THE GPT-HIGH DETECTOR. A fabric-admitted flow whose policy is narrowed to
/// nothing must be revoked on its first reverse packet, judging the recorded
/// forward zone — not declined on the zero ingress identity.
///
/// Dies if the fabric-ingress override is removed: the judgment declines in
/// the cold body and both halves survive.
#[test]
fn fabric_ingress_forward_flow_reverse_triggered_deny_revokes_both_halves_9604() {
    let mut outcome = admit_fabric_flow_9604();
    let forwarding = build_forwarding_state(&fabric_narrowed_snapshot_9604());
    let (frame_rev, meta_rev) =
        reverse_tcp_frame_v4_9604(&outcome.rev_key, WAN_IFINDEX);
    let out = drive_packet_9604(
        &mut outcome.sessions,
        &forwarding,
        &mut outcome.binding,
        &frame_rev,
        meta_rev,
    );
    assert_eq!(
        out.hit, 1,
        "the reply must HIT the reverse companion, or the revoke assertion \
         is vacuous"
    );
    assert_eq!(
        out.revoked, 1,
        "no rule permits lan -> wan anymore: a fabric-admitted reverse-fed \
         flow must be revoked. 0 is the pre-fold shape — the judgment \
         declined on the zero ingress identity instead of evaluating the \
         recorded forward zone"
    );
    assert_slots_gone_9604(&outcome.sessions, &outcome.fwd_key, &outcome.rev_key);
    assert_fabric_evicted_9604(&mut outcome, &forwarding, &frame_rev, meta_rev);
    assert_eq!(outcome.sessions.policy_revalidation_loud_declines(), 0);
}

/// #9381 through the fabric-ingress reverse path: a narrowed-to-`reject`
/// verdict revokes exactly like a deny.
#[test]
fn fabric_ingress_forward_flow_reverse_triggered_reject_revokes_both_halves_9604() {
    let mut outcome = admit_fabric_flow_9604();
    let forwarding = build_forwarding_state(&fabric_reject_snapshot_9604());
    let (frame_rev, meta_rev) =
        reverse_tcp_frame_v4_9604(&outcome.rev_key, WAN_IFINDEX);
    let out = drive_packet_9604(
        &mut outcome.sessions,
        &forwarding,
        &mut outcome.binding,
        &frame_rev,
        meta_rev,
    );
    assert_eq!(out.hit, 1, "the reply must hit the reverse companion");
    assert_eq!(
        out.revoked, 1,
        "a `reject` verdict must revoke a fabric-admitted reverse-fed session \
         exactly as a forward-fed one (#9381 via #9604)"
    );
    assert_slots_gone_9604(&outcome.sessions, &outcome.fwd_key, &outcome.rev_key);
    assert_fabric_evicted_9604(&mut outcome, &forwarding, &frame_rev, meta_rev);
    assert_eq!(outcome.sessions.policy_revalidation_loud_declines(), 0);
}

/// Preservation control: an unchanged permit keeps a fabric-admitted flow on
/// its reverse packet — and hit-only stamping writes no forward stamp from
/// the reverse path.
#[test]
fn fabric_ingress_forward_flow_permit_kept_on_reverse_9604() {
    let mut snap = fabric_admit_snapshot_9604();
    snap.generation = 8;
    let forwarding = build_forwarding_state(&snap);
    let mut outcome = admit_fabric_flow_9604();
    let (frame_rev, meta_rev) =
        reverse_tcp_frame_v4_9604(&outcome.rev_key, WAN_IFINDEX);
    let out = drive_packet_9604(
        &mut outcome.sessions,
        &forwarding,
        &mut outcome.binding,
        &frame_rev,
        meta_rev,
    );
    assert_eq!(
        (out.hit, out.revoked, out.tx),
        (1, 0, 1),
        "a still-permitted fabric-admitted flow must hit, keep, and forward \
         on its reverse packet"
    );
    assert!(
        outcome.sessions.entry_with_origin(&outcome.fwd_key).is_some(),
        "the forward half must survive a permit judgment"
    );
    assert!(
        outcome.sessions.entry_with_origin(&outcome.rev_key).is_some(),
        "the reverse half must survive a permit judgment"
    );
    assert_eq!(
        outcome.sessions.policy_revalidation_target(&outcome.rev_key),
        PolicyRevalidationTarget::Fresh,
        "the reverse permit stamps the hit half"
    );
    assert_eq!(
        outcome.sessions.policy_revalidation_target(&outcome.fwd_key),
        PolicyRevalidationTarget::Stale(outcome.fwd_key.clone()),
        "hit-only stamping writes NO forward stamp from the reverse path"
    );
    assert_eq!(outcome.sessions.policy_revalidation_loud_declines(), 0);
}
