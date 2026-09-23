// #8356: the ZONE-POLICY revalidation STAMP's lifecycle, at the session-table
// layer. The verdict half — which flows are revoked, and the reverse-companion
// trap — lives in `afxdp/tests_policy_revocation_8356.rs`, driven through the
// real poll body.
//
// Sibling of `filter_revalidation_7212_tests.rs`. The stamps are deliberately
// SEPARATE: sharing one would let a filter ACCEPT re-stamp suppress a pending
// policy re-derivation and vice versa, so the last cell here pins their
// independence directly.
#![allow(unused_imports)]

use super::*;
use std::net::{IpAddr, Ipv4Addr};

const IF_A: i32 = 24;

fn key(dst_port: u16) -> SessionKey {
    let src = IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102));
    let dst = IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200));
    SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        src_ip: src,
        dst_ip: dst,
        src_port: 12345,
        dst_port,
        discriminator: Default::default(),
        routing_domain: 0,
    }
}

fn metadata() -> SessionMetadata {
    SessionMetadata {
        ingress_zone: crate::test_zone_ids::TEST_LAN_ZONE_ID,
        egress_zone: crate::test_zone_ids::TEST_WAN_ZONE_ID,
        ingress_ifindex: IF_A as u32,
        ingress_vlan_id: 0,
        owner_rg_id: 1,
        fabric_ingress: false,
        is_reverse: false,
        nat64_reverse: None,
        log_session_init: false,
        log_session_close: false,
        policy_id: 0,
        inactivity_timeout_ns: None,
        policy_counter_idx: 0,
        policy_counter: None,
    }
}

fn decision() -> SessionDecision {
    SessionDecision { resolution: crate::afxdp::ForwardingResolution {
        disposition: crate::afxdp::ForwardingDisposition::ForwardCandidate,
        local_ifindex: 0,
        egress_ifindex: 12,
        tx_ifindex: 12,
        tunnel_endpoint_id: 0,
        next_hop: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 50, 1))),
        neighbor_mac: Some([0, 1, 2, 3, 4, 5]),
        src_mac: None,
        tx_vlan_id: 0,
    }, nat: crate::nat::NatDecision::default(), install_table_domain: 0, install_table_check: 0 }
}

fn table_with_one_session(live_gen: u64) -> (SessionTable, SessionKey) {
    let mut table = SessionTable::new();
    table.set_policy_revalidation_gen(live_gen);
    let k = key(443);
    assert!(table.install_with_protocol_with_origin(
        k.clone(),
        decision(),
        metadata(),
        SessionOrigin::ForwardFlow,
        122_000_000_000,
        PROTO_TCP,
        0,
    ));
    (table, k)
}

/// A freshly installed session is STALE for policy: `install` stamps `0`, which
/// is never a live generation. So the first packet it forwards re-derives.
///
/// This is also the peer-synced failover fence — `upsert_synced` takes the same
/// `0` — obtained from the import default rather than from cross-node plumbing.
#[test]
fn a_new_session_starts_unvalidated_for_policy_8356() {
    let (table, k) = table_with_one_session(41);
    assert_eq!(
        table.policy_revalidation_target(&k),
        PolicyRevalidationTarget::Stale(k.clone()),
        "install must stamp UNVALIDATED (0), so the first packet re-derives \
         zone policy against THIS node's state. A live stamp at install would \
         mean a peer-synced import never re-asks its own policy — the residual \
         #7323 accepted and #8356 closes"
    );
}

/// The steady state: re-stamped once, then FRESH for the rest of the
/// generation. This is what makes the feature once-per-session-per-commit
/// rather than per-packet.
#[test]
fn a_re_stamped_session_is_fresh_until_the_generation_moves_8356() {
    let (mut table, k) = table_with_one_session(41);
    table.mark_policy_revalidated(&k, PolicyRevalidationKind::LiveEgress);
    assert_eq!(
        table.policy_revalidation_target(&k),
        PolicyRevalidationTarget::Fresh,
        "after a PERMIT re-derivation the entry must read fresh, or every \
         later packet of this generation re-walks the policy terms"
    );

    // The operator commits something — anything. `config_generation` is a
    // deliberate SUPERSET trigger: it advances on every commit, not only on
    // policy edits.
    table.set_policy_revalidation_gen(42);
    assert_eq!(
        table.policy_revalidation_target(&k),
        PolicyRevalidationTarget::Stale(k.clone()),
        "a generation bump must make the verdict stale again, or a commit that \
         narrows zone policy never reaches the sessions it denies"
    );
}

/// The stamp is keyed on the GENERATION ALONE, unlike the filter's, which is
/// keyed `(generation, logical ingress ifindex)`.
///
/// This cell used to justify that by saying the verdict's zones "both come from
/// the ENTRY — never from the interface a given packet arrived on". #9384 made
/// the from-zone come from the arrival interface and nothing re-checked the
/// sentence. By then it was false in the way that mattered: a packet from
/// ANOTHER zone reached the re-derivation, revoked the entry on a deny, and
/// re-stamped it fresh on a permit (#9519).
///
/// Generation-only is still right, for a reason that now holds by
/// construction. Only an OWNER reaches the re-derivation
/// (`afxdp/poll_descriptor/session_hit_authority.rs`), and an owner arrived IN
/// the entry's admitting zone (or over the fabric, which keeps the entry's
/// zone). Every packet that can read or write this stamp therefore judges from
/// the same from-zone within a generation, and an ifindex in the key would only
/// re-walk terms for a LAG member or an ECMP path in that zone. What varies with
/// the arrival interface is the authority check, not the stamp.
#[test]
fn the_policy_stamp_does_not_vary_with_the_arrival_interface_8356() {
    let (mut table, k) = table_with_one_session(41);
    table.mark_policy_revalidated(&k, PolicyRevalidationKind::LiveEgress);
    // The FILTER stamp would read stale for a different ingress here. The
    // policy stamp must not.
    assert_eq!(
        table.policy_revalidation_target(&k),
        PolicyRevalidationTarget::Fresh,
        "the policy stamp must be generation-only"
    );
    assert!(
        table.filter_revalidation_stale(&k, IF_A + 1),
        "CONTROL: the FILTER stamp on the same entry IS interface-keyed and \
         reads stale for a different ingress. If this ever stops being true the \
         cell above is asserting a distinction that no longer exists"
    );
}

/// The two verdicts are INDEPENDENT. Re-stamping one must not silence the
/// other's re-derivation — which is the whole reason they are separate fields
/// rather than one shared stamp.
#[test]
fn the_policy_and_filter_stamps_do_not_suppress_each_other_8356() {
    let (mut table, k) = table_with_one_session(41);
    table.set_filter_revalidation_gen(41);

    table.mark_filter_revalidated(&k, IF_A);
    assert_eq!(
        table.policy_revalidation_target(&k),
        PolicyRevalidationTarget::Stale(k.clone()),
        "a FILTER accept re-stamp must NOT mark the policy verdict judged — a \
         shared stamp would let an accepted filter suppress the policy \
         re-derivation for the rest of the generation (#8356)"
    );

    table.mark_policy_revalidated(&k, PolicyRevalidationKind::LiveEgress);
    assert!(
        !table.filter_revalidation_stale(&k, IF_A),
        "and the filter stamp keeps its own state"
    );

    let (mut table2, k2) = table_with_one_session(41);
    table2.set_filter_revalidation_gen(41);
    table2.mark_policy_revalidated(&k2, PolicyRevalidationKind::LiveEgress);
    assert!(
        table2.filter_revalidation_stale(&k2, IF_A),
        "symmetrically, a POLICY re-stamp must not mark the FILTER verdict \
         judged"
    );
}

/// A key naming no entry is `NoLocalEntry`, not `Stale` — there is nothing to
/// stamp and nothing to tear down, and a teardown handed a tuple that names no
/// entry would delete nothing while the caller believed it had revoked.
#[test]
fn a_tuple_with_no_entry_is_not_reported_stale_8356() {
    let (table, _k) = table_with_one_session(41);
    assert_eq!(
        table.policy_revalidation_target(&key(8443)),
        PolicyRevalidationTarget::NoLocalEntry,
        "an absent entry must be NoLocalEntry — reporting it Stale would send \
         the caller into a revocation for a session it does not hold"
    );
}

/// A reused slab handle is a sessionless miss, not a stale canonical row. The
/// shared-hit materializer refreshes this mapping before policy revalidation;
/// this cell pins the guard that makes a pre-refresh lookup fail closed.
#[test]
fn stale_handle_policy_target_is_no_local_entry_10582_t5() {
    let mut table = SessionTable::new();
    let stale_key = key(443);
    let live_key = key(8443);
    assert!(table.install_with_protocol_with_origin(
        stale_key.clone(),
        decision(),
        metadata(),
        SessionOrigin::ForwardFlow,
        122_000_000_000,
        PROTO_TCP,
        0,
    ));
    assert!(table.install_with_protocol_with_origin(
        live_key.clone(),
        decision(),
        metadata(),
        SessionOrigin::ForwardFlow,
        122_000_000_000,
        PROTO_TCP,
        0,
    ));
    let live_handle = table
        .debug_handle_for_key(&live_key)
        .expect("live row handle");
    table.debug_force_handle(&stale_key, live_handle);
    assert_eq!(
        table.policy_revalidation_target(&stale_key),
        PolicyRevalidationTarget::NoLocalEntry,
        "a reused slab slot must not make the wrong row look stale"
    );
}

/// #10507 gate: Fresh Live + would-forward with egress keeps the fast path.
/// No force, no fail-closed — this is the once-per-generation steady state.
#[test]
fn fresh_live_local_coasts_10507() {
    let (mut table, k) = table_with_one_session(41);
    table.mark_policy_revalidated(&k, PolicyRevalidationKind::LiveEgress);
    let gate = table.policy_revalidation_gate(&k, PolicyGateCurrent::LocalForwarding);
    assert_eq!(gate.target, PolicyRevalidationTarget::Fresh);
    assert_eq!(gate.kind, PolicyRevalidationKind::LiveEgress);
    assert!(!gate.force_cold, "Fresh Live + local must coast, not cold-walk");
    assert!(!gate.fail_closed_decline, "no forced walk, no fail-closed Decline");
    assert!(!gate.fail_closed_icmp, "Live keeps the #8618 type-sensitive Decline");
}

/// #10507 gate rule 4: Fresh Live + would-forward WITHOUT egress fails
/// closed, even though the stamp is live. A no-egress disposition is never a
/// fast-path coast.
#[test]
fn fresh_live_noegress_fails_closed_10507() {
    let (mut table, k) = table_with_one_session(41);
    table.mark_policy_revalidated(&k, PolicyRevalidationKind::LiveEgress);
    let gate =
        table.policy_revalidation_gate(&k, PolicyGateCurrent::LocalForwardingNoEgress);
    assert_eq!(gate.target, PolicyRevalidationTarget::Fresh);
    assert!(gate.force_cold, "Fresh + no-egress must cold-walk even when live");
    assert!(gate.fail_closed_decline, "Fresh + no-egress Decline must revoke");
    assert!(gate.fail_closed_icmp, "Fresh + no-egress ICMP must revoke");
}

/// #10507 gate rule 4 is unconditional: Stale Live + no-egress also fails
/// closed. `force_cold` stays false only because a stale row already runs
/// cold via the `Stale` arm — the fail-closed bits still fire.
#[test]
fn stale_live_noegress_fails_closed_10507() {
    let (mut table, k) = table_with_one_session(41);
    table.mark_policy_revalidated(&k, PolicyRevalidationKind::LiveEgress);
    table.set_policy_revalidation_gen(42);
    let gate =
        table.policy_revalidation_gate(&k, PolicyGateCurrent::LocalForwardingNoEgress);
    assert_eq!(gate.target, PolicyRevalidationTarget::Stale(k.clone()));
    assert!(!gate.force_cold, "stale already runs cold; no force bit needed");
    assert!(gate.fail_closed_decline, "stale + no-egress Decline must revoke");
    assert!(gate.fail_closed_icmp, "stale + no-egress ICMP must revoke");
}

/// #10507 gate rule 4 + Recorded fence: Stale Recorded + no-egress fails
/// closed on both exits. Recorded authorization exists to fence whether
/// fresh or stale; no-egress is unconditionally fail-closed.
#[test]
fn stale_recorded_noegress_fails_closed_10507() {
    let (mut table, k) = table_with_one_session(41);
    table.mark_policy_revalidated(&k, PolicyRevalidationKind::RecordedEgress);
    table.set_policy_revalidation_gen(42);
    let gate =
        table.policy_revalidation_gate(&k, PolicyGateCurrent::LocalForwardingNoEgress);
    assert_eq!(gate.target, PolicyRevalidationTarget::Stale(k.clone()));
    assert!(!gate.force_cold, "stale already runs cold; no force bit needed");
    assert!(gate.fail_closed_decline, "stale Recorded + no-egress Decline must revoke");
    assert!(gate.fail_closed_icmp, "stale Recorded + no-egress ICMP must revoke");
}

/// #10507 gate rule 3: Fresh Recorded + local forces a live re-judge.
/// The recorded Permit never authorizes local forwarding.
#[test]
fn fresh_recorded_local_forces_cold_10507() {
    let (mut table, k) = table_with_one_session(41);
    table.mark_policy_revalidated(&k, PolicyRevalidationKind::RecordedEgress);
    let gate = table.policy_revalidation_gate(&k, PolicyGateCurrent::LocalForwarding);
    assert_eq!(gate.target, PolicyRevalidationTarget::Fresh);
    assert!(gate.force_cold, "Fresh Recorded + local must cold-walk");
    assert!(gate.fail_closed_decline, "forced walk Decline must revoke");
    assert!(gate.fail_closed_icmp, "recorded + local + type-armed must revoke");
}

/// #10507 gate: Stale Recorded + local fails closed on both exits.
/// Recorded authorization exists to fence whether fresh or stale; only
/// never-validated stale `Unvalidated` keeps Decline (#8618).
#[test]
fn stale_recorded_local_fails_closed_10507() {
    let (mut table, k) = table_with_one_session(41);
    table.mark_policy_revalidated(&k, PolicyRevalidationKind::RecordedEgress);
    table.set_policy_revalidation_gen(42);
    let gate = table.policy_revalidation_gate(&k, PolicyGateCurrent::LocalForwarding);
    assert_eq!(gate.target, PolicyRevalidationTarget::Stale(k.clone()));
    assert!(!gate.force_cold, "stale already runs cold");
    assert!(
        gate.fail_closed_decline,
        "stale Recorded + local Decline must revoke — recorded authorization fences regardless of freshness"
    );
    assert!(
        gate.fail_closed_icmp,
        "recorded + local + type-armed revokes even when stale"
    );
}

/// #10507 gate #8618 carve-out: a never-validated stale entry (install 0,
/// kind Unvalidated) + local keeps Decline. It carries no derived Permit,
/// so no recorded authorization exists to fence.
#[test]
fn stale_unvalidated_local_keeps_decline_10507() {
    let (table, k) = table_with_one_session(41);
    let gate = table.policy_revalidation_gate(&k, PolicyGateCurrent::LocalForwarding);
    assert_eq!(gate.target, PolicyRevalidationTarget::Stale(k.clone()));
    assert_eq!(gate.kind, PolicyRevalidationKind::Unvalidated);
    assert!(!gate.force_cold);
    assert!(!gate.fail_closed_decline, "never-validated stale keeps Decline");
    assert!(!gate.fail_closed_icmp, "never-validated stale keeps #8618 Decline");
}

/// #10507 gate A1/A2 shape: Fresh Unvalidated (generation-equal, provenance
/// revoked) + local forces cold and fails closed. A prior verdict existed
/// and was distrusted.
#[test]
fn fresh_unvalidated_local_forces_cold_10507() {
    let (mut table, k) = table_with_one_session(41);
    table.mark_policy_revalidated(&k, PolicyRevalidationKind::Unvalidated);
    let gate = table.policy_revalidation_gate(&k, PolicyGateCurrent::LocalForwarding);
    assert_eq!(gate.target, PolicyRevalidationTarget::Fresh);
    assert!(gate.force_cold, "Fresh Unvalidated + local must cold-walk");
    assert!(gate.fail_closed_decline, "reset-shape Decline must revoke");
    assert!(gate.fail_closed_icmp, "reset-shape ICMP must revoke");
}

/// #10507 gate rule 4 overrides the #8618 carve-out for no-egress: Stale
/// Unvalidated + no-egress fails closed. The carve-out survives only for
/// with-egress packets that cannot forward-locally-bypass.
#[test]
fn stale_unvalidated_noegress_fails_closed_10507() {
    let (table, k) = table_with_one_session(41);
    let gate =
        table.policy_revalidation_gate(&k, PolicyGateCurrent::LocalForwardingNoEgress);
    assert_eq!(gate.target, PolicyRevalidationTarget::Stale(k.clone()));
    assert!(!gate.force_cold, "stale already runs cold");
    assert!(gate.fail_closed_decline, "no-egress Decline must revoke even when stale");
    assert!(gate.fail_closed_icmp, "no-egress ICMP must revoke even when stale");
}

/// #10507 gate: Fresh Recorded + non-local coasts (no local intent, no
/// force). Standby/seed retention lives here; the recorded Permit never
/// authorizes a local TX it cannot reach.
#[test]
fn fresh_recorded_nonlocal_coasts_10507() {
    let (mut table, k) = table_with_one_session(41);
    table.mark_policy_revalidated(&k, PolicyRevalidationKind::RecordedEgress);
    let gate = table.policy_revalidation_gate(&k, PolicyGateCurrent::NonLocal);
    assert_eq!(gate.target, PolicyRevalidationTarget::Fresh);
    assert!(!gate.force_cold, "non-local must not force a local walk");
    assert!(!gate.fail_closed_decline);
    assert!(!gate.fail_closed_icmp);
}

/// #10507 gate: an absent entry answers NoLocalEntry with all fail-closed
/// bits clear. Nothing to judge, nothing to revoke.
#[test]
fn gate_nolocalentry_is_inert_10507() {
    let (table, _k) = table_with_one_session(41);
    let gate =
        table.policy_revalidation_gate(&key(8443), PolicyGateCurrent::LocalForwarding);
    assert_eq!(gate.target, PolicyRevalidationTarget::NoLocalEntry);
    assert_eq!(gate.kind, PolicyRevalidationKind::Unvalidated);
    assert!(!gate.force_cold);
    assert!(!gate.fail_closed_decline);
    assert!(!gate.fail_closed_icmp);
}

/// #10507 A1 boundary (Fresh): peer-to-local promotion of a Fresh row
/// revokes provenance to Unvalidated, forcing the next local packet to
/// cold-judge. This pin proves Fresh behavior is bit-identical to the
/// pre-deviation unconditional reset.
#[test]
fn a1_promotion_resets_fresh_provenance_10507() {
    let mut table = SessionTable::new();
    table.set_policy_revalidation_gen(41);
    let k = key(443);
    assert!(table.upsert_synced(k.clone(), decision(), metadata(), 122_000_000_000, PROTO_TCP, 0, true));
    table.mark_policy_revalidated(&k, PolicyRevalidationKind::RecordedEgress);
    assert_eq!(table.policy_revalidation_target(&k), PolicyRevalidationTarget::Fresh);
    assert!(table.promote_synced_with_origin(SessionUpdate {
        key: &k,
        decision: decision(),
        metadata: metadata(),
        origin: SessionOrigin::SharedPromote,
        now_ns: 123_000_000_000,
        protocol: PROTO_TCP,
        tcp_flags: 0,
    }));
    assert_eq!(
        table.policy_revalidation_kind(&k),
        PolicyRevalidationKind::Unvalidated,
        "A1 must reset Fresh provenance on peer-to-local promote"
    );
    assert_eq!(
        table.policy_revalidation_target(&k),
        PolicyRevalidationTarget::Fresh,
        "A1 resets kind only; the numeric generation stays Fresh"
    );
}

/// #10507 A1 boundary (Stale): promotion preserves a Stale row's kind so
/// Stale Recorded keeps fencing through the transition instead of being
/// laundered into the never-validated carve-out.
#[test]
fn a1_promotion_preserves_stale_provenance_10507() {
    let mut table = SessionTable::new();
    table.set_policy_revalidation_gen(41);
    let k = key(443);
    assert!(table.upsert_synced(k.clone(), decision(), metadata(), 122_000_000_000, PROTO_TCP, 0, true));
    table.mark_policy_revalidated(&k, PolicyRevalidationKind::RecordedEgress);
    table.set_policy_revalidation_gen(42);
    assert_eq!(
        table.policy_revalidation_target(&k),
        PolicyRevalidationTarget::Stale(k.clone())
    );
    assert!(table.promote_synced_with_origin(SessionUpdate {
        key: &k,
        decision: decision(),
        metadata: metadata(),
        origin: SessionOrigin::SharedPromote,
        now_ns: 123_000_000_000,
        protocol: PROTO_TCP,
        tcp_flags: 0,
    }));
    assert_eq!(
        table.policy_revalidation_kind(&k),
        PolicyRevalidationKind::RecordedEgress,
        "A1 must preserve Stale Recorded through promote (fence retained)"
    );
}

/// #10507 A2 boundary (Fresh): activation/demotion refresh of a Fresh row
/// revokes provenance. Bit-identical to unconditional for Fresh.
#[test]
fn a2_refresh_resets_fresh_provenance_10507() {
    let (mut table, k) = table_with_one_session(41);
    table.mark_policy_revalidated(&k, PolicyRevalidationKind::RecordedEgress);
    assert!(table.refresh_for_ha_transition(&k, decision(), metadata(), 123_000_000_000));
    assert_eq!(
        table.policy_revalidation_kind(&k),
        PolicyRevalidationKind::Unvalidated,
        "A2 must reset Fresh provenance on refresh"
    );
    assert_eq!(
        table.policy_revalidation_target(&k),
        PolicyRevalidationTarget::Fresh,
        "A2 resets kind only; the generation stays Fresh"
    );
}

/// #10507 A2 boundary (Stale): refresh preserves a Stale row's kind.
#[test]
fn a2_refresh_preserves_stale_provenance_10507() {
    let (mut table, k) = table_with_one_session(41);
    table.mark_policy_revalidated(&k, PolicyRevalidationKind::RecordedEgress);
    table.set_policy_revalidation_gen(42);
    assert!(table.refresh_for_ha_transition(&k, decision(), metadata(), 123_000_000_000));
    assert_eq!(
        table.policy_revalidation_kind(&k),
        PolicyRevalidationKind::RecordedEgress,
        "A2 must preserve Stale Recorded through refresh (fence retained)"
    );
}

/// #10507 Cell 7b gate pin: Fresh Live + non-local coasts (retention).
/// A redirect/seed/terminal packet never forces a local walk and never
/// fails closed — the recorded/live authorization is simply not consulted
/// for non-local forwarding. Poll-level NoRoute retention rides on the
/// existing #9513 no-route cell (Stale Unvalidated + NoRoute → Decline);
/// this pins the Fresh-Live corner the poll cell cannot reach (a NoRoute
/// row can never earn Live, so only the gate unit can state it).
#[test]
fn fresh_live_nonlocal_coasts_10507() {
    let (mut table, k) = table_with_one_session(41);
    table.mark_policy_revalidated(&k, PolicyRevalidationKind::LiveEgress);
    let gate = table.policy_revalidation_gate(&k, PolicyGateCurrent::NonLocal);
    assert_eq!(gate.target, PolicyRevalidationTarget::Fresh);
    assert!(!gate.force_cold, "non-local must not force a local walk");
    assert!(!gate.fail_closed_decline, "non-local never fails Decline closed");
    assert!(!gate.fail_closed_icmp, "non-local never fails ICMP closed");
}

/// #10507 Cell 8 (accepted reimport resets): an accepted `upsert_synced`
/// builds a fresh entry stamped generation 0 / Unvalidated — it never
/// trusts a receiver stamp (there is none on the wire; `SyncedSessionEntry`
/// carries no policy stamp). The first packet therefore cold-judges live.
#[test]
fn accepted_reimport_starts_unvalidated_10507() {
    let mut table = SessionTable::new();
    table.set_policy_revalidation_gen(41);
    let k = key(443);
    assert!(table.upsert_synced(k.clone(), decision(), metadata(), 122_000_000_000, PROTO_TCP, 0, true));
    assert_eq!(
        table.policy_revalidation_target(&k),
        PolicyRevalidationTarget::Stale(k.clone()),
        "reimport must stamp generation 0 (stale)"
    );
    assert_eq!(
        table.policy_revalidation_kind(&k),
        PolicyRevalidationKind::Unvalidated,
        "reimport must stamp Unvalidated provenance (never trust remote)"
    );
}

/// #10507 Cell 8 CONTROL (rejected overwrite preserves local): a rejected
/// `upsert_synced` (unauthorized local overwrite, `allow_replace_local`
/// false) leaves the local entry — including its Live stamp — untouched.
/// A rejection must never clobber a local verdict.
#[test]
fn rejected_reimport_preserves_local_live_10507() {
    let (mut table, k) = table_with_one_session(41);
    table.mark_policy_revalidated(&k, PolicyRevalidationKind::LiveEgress);
    assert_eq!(table.policy_revalidation_target(&k), PolicyRevalidationTarget::Fresh);
    assert!(!table.upsert_synced(k.clone(), decision(), metadata(), 123_000_000_000, PROTO_TCP, 0, false));
    assert_eq!(
        table.policy_revalidation_target(&k),
        PolicyRevalidationTarget::Fresh,
        "a rejected overwrite must not disturb the local Fresh stamp"
    );
    assert_eq!(
        table.policy_revalidation_kind(&k),
        PolicyRevalidationKind::LiveEgress,
        "a rejected overwrite must not disturb local Live provenance"
    );
}

/// #10635 fold cross-pin: `policy_revalidation_fenced` must equal the gate's
/// fail-closed bits under `LocalForwarding` intent, over every kind ×
/// fresh/stale plus the missing-key arm. The reverse fence's no-companion
/// positions consult `fenced()` on a DIFFERENT key than the gate probed, so
/// any drift between the two spellings reopens either the b03-F1
/// manufactured DENY or a fail-open coast. Absolute expectations (not just
/// relative equality) so a joint drift still fails.
#[test]
fn fenced_matches_gate_fail_closed_bits_10635() {
    // (kind, stale, expect_fenced). Stale-Unvalidated installs gen-0 and is
    // never marked — the never-validated (#8618) shape, not an aged stamp.
    let cases = [
        (PolicyRevalidationKind::Unvalidated, false, true),
        (PolicyRevalidationKind::Unvalidated, true, false),
        (PolicyRevalidationKind::LiveEgress, false, false),
        (PolicyRevalidationKind::LiveEgress, true, false),
        (PolicyRevalidationKind::RecordedEgress, false, true),
        (PolicyRevalidationKind::RecordedEgress, true, true),
    ];
    for (kind, stale, expect_fenced) in cases {
        let (mut table, k) = table_with_one_session(41);
        if !(matches!(kind, PolicyRevalidationKind::Unvalidated) && stale) {
            table.mark_policy_revalidated(&k, kind);
        }
        if stale {
            table.set_policy_revalidation_gen(42);
        }
        let fenced = table.policy_revalidation_fenced(&k);
        let gate = table.policy_revalidation_gate(&k, PolicyGateCurrent::LocalForwarding);
        assert_eq!(
            fenced, expect_fenced,
            "fenced({kind:?}, stale={stale}) must be {expect_fenced}"
        );
        assert_eq!(
            fenced, gate.fail_closed_decline,
            "fenced() must equal the gate Decline bit ({kind:?}, stale={stale})"
        );
        assert_eq!(
            fenced, gate.fail_closed_icmp,
            "fenced() must equal the gate ICMP bit ({kind:?}, stale={stale})"
        );
    }
    // Missing key: unfenced, and the gate answers all-false.
    let (table, _) = table_with_one_session(41);
    let missing = key(999);
    assert!(
        !table.policy_revalidation_fenced(&missing),
        "a missing key is unfenced"
    );
    let gate = table.policy_revalidation_gate(&missing, PolicyGateCurrent::LocalForwarding);
    assert!(
        !gate.fail_closed_decline,
        "a missing key never fails Decline closed"
    );
    assert!(
        !gate.fail_closed_icmp,
        "a missing key never fails ICMP closed"
    );
}
