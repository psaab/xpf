//! #19153: the materialize core's outcomes, and the one identity rule it
//! shares with #18552's promotion.
//!
//! `materialize_current_shared_under_permit` is called here directly, under
//! permits claimed on the pair a resolve's capture names (as the poll path's
//! wrapper claims them). The fixture is `materialize_permit_19153_tests.rs`'s.
//!
//! - a completed removal is `SharedAbsent`;
//! - a superseded capture is `Superseded` for a new session id AND for a new
//!   translation under the same id (not `InstallRefused`: the NAT decision is
//!   part of the identity, not only of the companion-witness check);
//! - an unleased current row is `Installed`, and a locally owned one
//!   `SharedLocal`;
//! - a current row whose zone vanished is `StaleReplayFenced`, and a live
//!   local incumbent makes the install `InstallRefused` (fold 1);
//! - the #10582 clobber refusal is judged before any claim: it allocates
//!   nothing (fold 1, D2);
//! - the predicate `promote::same_synced_incarnation`, as a table;
//! - its #18552 consumer (`synced_row_incarnation`) on a NAT-only change
//!   under the zero-id sentinel;
//! - fold 2, classify before apply (v4 and v6): a current row that differs
//!   from the capture is installed with none of this packet's state (an RST
//!   or FIN leaves its close state and timeout as an import would set them;
//!   fabric adoption does not let it replace a local incumbent) and reports
//!   `Drop`; an equal row takes the packet's FIN as before; and the
//!   classification table: every authority field drops, every refresh field
//!   (generation, counters, packet clocks, origin, flags) does not.

use super::materialize_permit_19153_tests::{
    ID_A, ID_B, NOW_NS, Shared, flow_key, peer_row, snat,
};
use super::*;
use crate::afxdp::bpf_map::global_tuple_gate;

/// The core's outcome for a resolve's capture, under permits claimed on the
/// pair the capture names.
fn core_outcome(
    sessions: &mut SessionTable,
    shared: &Shared,
    forwarding: &ForwardingState,
    captured: &SyncedSessionEntry,
) -> MaterializeOutcome {
    let companion = reverse_session_key(&captured.key, captured.decision.nat);
    let permits = global_tuple_gate()
        .try_acquire_installs([captured.key.clone(), companion])
        .expect("premise: the pair is unleased");
    let (outcome, divergence) = materialize_current_shared_under_permit(
        sessions,
        &shared.sessions,
        forwarding,
        &captured.key,
        Some(CapturedIncarnation::of(captured)),
        None,
        MaterializeInstall {
            now_ns: NOW_NS,
            tcp_flags: crate::tcp_flags::TCP_ACK,
            fabric_adopted: false,
        },
        &permits,
    );
    assert_eq!(
        divergence,
        MaterializeDivergence::None,
        "an identity-only caller classifies nothing"
    );
    outcome
}

fn outcome_name(outcome: &MaterializeOutcome) -> &'static str {
    match outcome {
        MaterializeOutcome::Installed(_) => "Installed",
        MaterializeOutcome::SharedLocal(_) => "SharedLocal",
        MaterializeOutcome::SharedAbsent => "SharedAbsent",
        MaterializeOutcome::Superseded => "Superseded",
        MaterializeOutcome::StaleReplayFenced => "StaleReplayFenced",
        MaterializeOutcome::InstallRefused => "InstallRefused",
    }
}

/// A zone-validated forwarding view naming the fixture's zones (1 lan, 2 wan),
/// so the #10612 fence is live: a row naming any other zone is stale.
fn zone_validated_forwarding() -> ForwardingState {
    let mut forwarding = ForwardingState::default();
    forwarding.zone_id_to_name.insert(1, "lan".to_string());
    forwarding.zone_id_to_name.insert(2, "wan".to_string());
    forwarding.zone_set_validated = true;
    forwarding
}

/// All six outcomes the core owes a caller (#19153 fold 1, Codex gap: the
/// fence and the refused install too), and the table each leaves: only
/// `Installed` and `SharedLocal` install; `InstallRefused` leaves the local
/// incumbent exactly as it was.
#[test]
fn the_materialize_core_reports_each_outcome_19153() {
    let shared = Shared::new();
    let forwarding = zone_validated_forwarding();

    // Removed: the capture's row is gone.
    let removed_key = flow_key(42_001);
    shared.publish(&peer_row(removed_key.clone(), ID_A, snat(40_201)));
    let removed_capture = shared.capture(&removed_key);
    shared.remove(&removed_key);

    // Superseded: a new id under the same translation, and the same id under
    // a new translation.
    let new_id_key = flow_key(42_002);
    shared.publish(&peer_row(new_id_key.clone(), ID_A, snat(40_202)));
    let new_id_capture = shared.capture(&new_id_key);
    shared.remove(&new_id_key);
    shared.publish(&peer_row(new_id_key.clone(), ID_B, snat(40_202)));
    let new_nat_key = flow_key(42_003);
    shared.publish(&peer_row(new_nat_key.clone(), ID_A, snat(40_203)));
    let new_nat_capture = shared.capture(&new_nat_key);
    shared.remove(&new_nat_key);
    shared.publish(&peer_row(new_nat_key.clone(), ID_A, snat(40_303)));

    // Installed, and SharedLocal (a sibling worker's local publish).
    let current_key = flow_key(42_004);
    shared.publish(&peer_row(current_key.clone(), ID_A, snat(40_204)));
    let current_capture = shared.capture(&current_key);
    let local_key = flow_key(42_005);
    let mut local = peer_row(local_key.clone(), ID_B, snat(40_205));
    local.origin = SessionOrigin::ForwardFlow;
    shared.publish(&local);
    let local_capture = shared.capture(&local_key);

    // StaleReplayFenced: the capture was live, the current row (same
    // incarnation) names a zone this node no longer has.
    let stale_key = flow_key(42_008);
    shared.publish(&peer_row(stale_key.clone(), ID_A, snat(40_208)));
    let stale_capture = shared.capture(&stale_key);
    let mut stale = peer_row(stale_key.clone(), ID_A, snat(40_208));
    stale.metadata.egress_zone = 9;
    shared.publish(&stale);

    // InstallRefused: a live LOCAL incumbent under the key (#10582).
    let incumbent_key = flow_key(42_009);
    shared.publish(&peer_row(incumbent_key.clone(), ID_A, snat(40_209)));
    let incumbent_capture = shared.capture(&incumbent_key);

    let cases: [(&str, &SyncedSessionEntry, bool, &str, Option<SessionOrigin>); 7] = [
        ("removed", &removed_capture, false, "SharedAbsent", None),
        ("new session id", &new_id_capture, false, "Superseded", None),
        ("new translation", &new_nat_capture, false, "Superseded", None),
        ("current", &current_capture, false, "Installed", Some(SessionOrigin::SharedMaterialize)),
        ("locally owned", &local_capture, false, "SharedLocal", Some(SessionOrigin::WorkerLocalImport)),
        ("stale current row", &stale_capture, false, "StaleReplayFenced", None),
        ("local incumbent", &incumbent_capture, true, "InstallRefused", Some(SessionOrigin::ForwardFlow)),
    ];
    for (case, capture, local_incumbent, expected, row) in cases {
        let mut sessions = SessionTable::new();
        if local_incumbent {
            assert!(
                sessions.install_with_protocol(
                    capture.key.clone(),
                    capture.decision,
                    capture.metadata.clone(),
                    NOW_NS,
                    PROTO_TCP,
                    crate::tcp_flags::TCP_ACK,
                ),
                "premise ({case}): the local incumbent installs"
            );
        }
        let outcome = core_outcome(&mut sessions, &shared, &forwarding, capture);
        assert_eq!(outcome_name(&outcome), expected, "{case}: outcome");
        assert_eq!(
            sessions.entry_with_origin(&capture.key).map(|(_, _, origin)| origin),
            row,
            "{case}: the row the table holds afterwards"
        );
        assert_eq!(sessions.len(), usize::from(row.is_some()), "{case}: rows");
    }
}

/// The one identity rule, as a table. NAT equality is mandatory; the session
/// id is compared only when the shared row's id is non-zero.
#[test]
fn the_synced_incarnation_predicate_table_19153() {
    let key = flow_key(42_006);
    let nat = snat(40_206);
    let other_nat = snat(40_306);
    let rows: [(&str, NatDecision, u64, SyncedSessionEntry, bool); 5] = [
        ("same", nat, ID_A, peer_row(key.clone(), ID_A, nat), true),
        ("nat differs", nat, ID_A, peer_row(key.clone(), ID_A, other_nat), false),
        ("id differs", nat, ID_A, peer_row(key.clone(), ID_B, nat), false),
        ("shared id 0, nat equal", nat, ID_A, peer_row(key.clone(), 0, nat), true),
        ("shared id 0, nat differs", nat, ID_A, peer_row(key.clone(), 0, other_nat), false),
    ];
    for (row, nat, session_id, entry, expected) in rows {
        assert_eq!(
            super::promote::same_synced_incarnation(nat, session_id, &entry),
            expected,
            "same_synced_incarnation: {row}"
        );
    }
}

/// #18552's consumer of the same rule. A worker row (non-zero id, as the
/// worker always stores) against a shared row with the zero-id sentinel: only
/// the NAT decision is compared, so a translation change is `Superseded`. The
/// same translation is `Unproven`, never `Current` (#18552 cycle 2, Codex P2):
/// a zero id cannot prove the worker row is shared's incarnation.
#[test]
fn promotion_identity_supersedes_a_zero_id_translation_change_18552_19153() {
    let key = flow_key(42_007);
    let mut sessions = SessionTable::new();
    assert!(
        sessions.upsert_synced_with_origin(
            peer_row(key.clone(), ID_A, snat(40_207)).into_session_install(NOW_NS),
            false,
        ),
        "premise: the worker row installs"
    );
    let shared = Shared::new();
    shared.publish(&peer_row(key.clone(), 0, snat(40_307)));
    let changed = super::promote::synced_row_incarnation(&sessions, &shared.sessions, &key);
    shared.remove(&key);
    shared.publish(&peer_row(key.clone(), 0, snat(40_207)));
    let same = super::promote::synced_row_incarnation(&sessions, &shared.sessions, &key);

    assert_eq!(
        changed,
        super::promote::SyncedRowIncarnation::Superseded,
        "a zero-id shared row under a different translation must be Superseded"
    );
    assert_eq!(
        same,
        super::promote::SyncedRowIncarnation::Unproven,
        "a zero-id shared row under the same translation is Unproven, never Current"
    );
}

/// #19153 fold 1 (D2, r24 P3-1): a non-adopted materialize over a live LOCAL
/// incumbent (#10582) is refused on this worker's own table before any claim.
/// That refusal lasts as long as the incumbent, so every packet of the flow
/// meets it: it must not build a permit set (two Vecs, an admission `Arc`, gate
/// entries) or re-read shared. Zero heap allocations is the observable.
#[test]
fn a_local_incumbent_refusal_claims_nothing_19153() {
    let shared = Shared::new();
    let key = flow_key(42_010);
    shared.publish(&peer_row(key.clone(), ID_A, snat(40_210)));
    let captured = shared.capture(&key);
    let mut sessions = SessionTable::new();
    assert!(
        sessions.install_with_protocol(
            key.clone(),
            captured.decision,
            captured.metadata.clone(),
            NOW_NS,
            PROTO_TCP,
            crate::tcp_flags::TCP_ACK,
        ),
        "premise: the local incumbent installs"
    );
    // This thread's gate exists before counting (#18834 per-thread gates).
    let _ = global_tuple_gate();
    let forwarding = ForwardingState::default();
    let mut resolved = ResolvedSessionLookup::shared(captured.clone());
    let ((_, install_failed), allocations) = crate::test_alloc::count_allocs(|| {
        materialize_shared_session_hit(
            &mut sessions,
            &shared.sessions,
            &mut resolved,
            &forwarding,
            NOW_NS + 1,
            crate::tcp_flags::TCP_ACK,
        )
    });
    assert!(install_failed, "the local incumbent must refuse the materialize");
    assert_eq!(
        sessions.entry_with_origin(&key).map(|(_, _, origin)| origin),
        Some(SessionOrigin::ForwardFlow),
        "the local incumbent must survive"
    );
    assert_eq!(
        allocations, 0,
        "a worker-local #10582 refusal must be judged before the claim, not pay the permit set \
         and the shared re-read on every packet"
    );
}

// ---------------------------------------------------------------------------
// #19153 fold 2 (Codex P2-1, the lead's rule): classify BEFORE apply.
// ---------------------------------------------------------------------------

/// A family twin of the fixture's tuple: v4 is `flow_key`, v6 a documentation
/// prefix tuple of the cell's own.
fn family_key(v6: bool, src_port: u16) -> SessionKey {
    if !v6 {
        return flow_key(src_port);
    }
    SessionKey {
        addr_family: libc::AF_INET6 as u8,
        protocol: PROTO_TCP,
        src_ip: IpAddr::V6("2001:db8:192:2::153".parse().unwrap()),
        dst_ip: IpAddr::V6("2001:db8:198:51::153".parse().unwrap()),
        src_port,
        dst_port: 443,
        discriminator: Default::default(),
        routing_domain: 0,
    }
}

fn family_snat(v6: bool, port: u16) -> NatDecision {
    if !v6 {
        return snat(port);
    }
    NatDecision {
        rewrite_src: Some(IpAddr::V6("2001:db8:203:113::153".parse().unwrap())),
        rewrite_src_port: Some(port),
        ..NatDecision::default()
    }
}

/// The capture-classifying core, as the poll path's `materialize_capture`
/// runs it: under permits on the capture's pair, with this packet's flags and
/// adoption.
fn core_classified(
    sessions: &mut SessionTable,
    shared: &Shared,
    forwarding: &ForwardingState,
    captured: &SyncedSessionEntry,
    tcp_flags: u8,
    fabric_adopted: bool,
) -> (MaterializeOutcome, MaterializeDivergence) {
    let companion = reverse_session_key(&captured.key, captured.decision.nat);
    let permits = global_tuple_gate()
        .try_acquire_installs([captured.key.clone(), companion])
        .expect("premise: the pair is unleased");
    materialize_current_shared_under_permit(
        sessions,
        &shared.sessions,
        forwarding,
        &captured.key,
        Some(CapturedIncarnation::of(captured)),
        Some(captured),
        MaterializeInstall {
            now_ns: NOW_NS,
            tcp_flags,
            fabric_adopted,
        },
        &permits,
    )
}

/// The close state and timeout an HA import (`UpsertSynced`) gives `row`:
/// its own carried flags, no packet. What a clean install must equal.
fn imported_close_state(row: &SyncedSessionEntry) -> (bool, bool, bool, bool, u64) {
    let mut reference = SessionTable::new();
    let mut install = synced_replica_entry(row).into_session_install(NOW_NS);
    install.origin = SessionOrigin::SharedMaterialize;
    assert!(
        reference.upsert_synced_with_origin(install, false),
        "premise: the reference import installs"
    );
    reference
        .close_state_for_test(&row.key)
        .expect("premise: the reference row is live")
}

/// Codex P2-1. An RST (or FIN) resolved against capture A; before the claim,
/// shared became B: the same incarnation and translation, open and
/// established, with a different but valid ingress zone. The core must judge
/// B against A before installing, then install B with B's own carried flags:
/// B's close state and timeout are exactly an import's, not reset or closing
/// by a packet the caller is about to drop. v4 and v6, RST and FIN.
#[test]
fn a_differing_row_installs_without_the_packets_rst_or_fin_19153() {
    let forwarding = zone_validated_forwarding();
    for v6 in [false, true] {
        for (name, flags) in [
            ("RST", crate::tcp_flags::TCP_RST),
            ("FIN", crate::tcp_flags::TCP_FIN | crate::tcp_flags::TCP_ACK),
        ] {
            let cell = format!("v6={v6} {name}");
            let shared = Shared::new();
            let key = family_key(v6, 42_101);
            let a = peer_row(key.clone(), ID_A, family_snat(v6, 40_101));
            shared.publish(&a);
            let captured = shared.capture(&key);
            let mut b = a.clone();
            b.metadata.ingress_zone = 2;
            assert!(
                forwarding.zone_id_to_name.contains_key(&b.metadata.ingress_zone),
                "premise ({cell}): B's ingress zone is valid, so the #10612 fence does not fire"
            );
            shared.publish(&b);
            let mut sessions = SessionTable::new();

            let (outcome, divergence) =
                core_classified(&mut sessions, &shared, &forwarding, &captured, flags, false);

            let installed_zone = match &outcome {
                MaterializeOutcome::Installed(lookup) => Some(lookup.metadata.ingress_zone),
                _ => None,
            };
            assert_eq!(
                (outcome_name(&outcome), installed_zone, divergence),
                ("Installed", Some(2), MaterializeDivergence::Drop),
                "{cell}: B must be installed (current content) and the packet classified Drop"
            );
            let close = sessions.close_state_for_test(&key).expect("B is installed");
            assert_eq!(
                (close.0, close.1, close.2),
                (false, false, false),
                "{cell}: the dropped packet closed or reset B (closing, reset, fin_own)"
            );
            assert_eq!(
                close,
                imported_close_state(&b),
                "{cell}: B's close state and timeout must be exactly what an import of B sets"
            );
        }
    }
}

/// The equal-path control: the current row is the capture, so the install
/// takes the packet's FIN exactly as before fold 2 (closing, fin_own, the
/// close window), and the classification is `None`. v4 and v6.
#[test]
fn an_equal_row_installs_with_the_packets_fin_19153() {
    let forwarding = zone_validated_forwarding();
    for v6 in [false, true] {
        let shared = Shared::new();
        let key = family_key(v6, 42_102);
        let a = peer_row(key.clone(), ID_A, family_snat(v6, 40_102));
        shared.publish(&a);
        let captured = shared.capture(&key);
        let mut sessions = SessionTable::new();

        let (outcome, divergence) = core_classified(
            &mut sessions,
            &shared,
            &forwarding,
            &captured,
            crate::tcp_flags::TCP_FIN | crate::tcp_flags::TCP_ACK,
            false,
        );

        assert_eq!(
            (outcome_name(&outcome), divergence),
            ("Installed", MaterializeDivergence::None),
            "v6={v6}: an unchanged row installs and the packet stands"
        );
        let close = sessions.close_state_for_test(&key).expect("A is installed");
        assert_eq!(
            (close.0, close.1, close.2),
            (true, false, true),
            "v6={v6}: the FIN on an unchanged row must set closing and fin_own, as today"
        );
        assert_ne!(
            close.4,
            imported_close_state(&a).4,
            "v6={v6}: the FIN must select the close window, not the established one"
        );
    }
}

/// The other packet-derived install input: #16217 fabric adoption lets the
/// install replace a local incumbent. The adoption gate judged this packet
/// against the shared state it read, so a row that differs from the capture
/// must not get it: the incumbent survives and the packet drops. Control: an
/// equal row is adopted and replaces it. v4 and v6.
#[test]
fn a_differing_row_never_takes_the_packets_fabric_adoption_19153() {
    let forwarding = zone_validated_forwarding();
    for v6 in [false, true] {
        for differs in [true, false] {
            let cell = format!("v6={v6} differs={differs}");
            let shared = Shared::new();
            let key = family_key(v6, 42_103);
            let a = peer_row(key.clone(), ID_A, family_snat(v6, 40_103));
            shared.publish(&a);
            let captured = shared.capture(&key);
            if differs {
                let mut b = a.clone();
                b.metadata.owner_rg_id = 2;
                shared.publish(&b);
            }
            let mut sessions = SessionTable::new();
            assert!(
                sessions.install_with_protocol(
                    key.clone(),
                    a.decision,
                    a.metadata.clone(),
                    NOW_NS,
                    PROTO_TCP,
                    crate::tcp_flags::TCP_ACK,
                ),
                "premise ({cell}): the local incumbent installs"
            );

            let (outcome, divergence) = core_classified(
                &mut sessions,
                &shared,
                &forwarding,
                &captured,
                crate::tcp_flags::TCP_ACK,
                true,
            );
            let row = sessions.entry_with_origin(&key).map(|(_, _, origin)| origin);
            if differs {
                assert_eq!(
                    (outcome_name(&outcome), divergence, row),
                    ("InstallRefused", MaterializeDivergence::Drop, Some(SessionOrigin::ForwardFlow)),
                    "{cell}: the differing row replaced the local incumbent on this packet's adoption"
                );
            } else {
                assert_eq!(
                    (outcome_name(&outcome), divergence, row),
                    ("Installed", MaterializeDivergence::None, Some(SessionOrigin::SharedMaterialize)),
                    "{cell}: control: an equal adopted row must replace the incumbent"
                );
            }
        }
    }
}

/// The classification, field by field, on a forwarding view with no route
/// leak (the live incarnation is 0). Every authority field of the row drops;
/// every field a normal refresh rewrites (and nothing in this packet's
/// handling reads) does not. The leak cells with a live leak, including the
/// zero-to-live derivation, are in `leak_revoke_9951_tests.rs`.
#[test]
fn the_classification_compares_authority_not_refresh_state_19153() {
    let forwarding = zone_validated_forwarding();
    let key = flow_key(42_104);
    let mut base = peer_row(key, ID_A, snat(40_104));
    base.tcp_handshake_state = crate::session::TcpHandshakeState::Established.to_wire();
    let counter = || Some(Arc::new(crate::policy::PolicyRuleCounter::with_rule_id("19153/rule")));
    let reverse_info = crate::nat64::Nat64ReverseInfo {
        orig_src_v6: "2001:db8::1".parse().unwrap(),
        orig_dst_v6: "64:ff9b::c633:6499".parse().unwrap(),
    };
    type Change = Box<dyn Fn(&mut SyncedSessionEntry)>;
    let drops: Vec<(&str, Change)> = vec![
        ("nat", Box::new(|row| row.decision.nat.rewrite_src_port = Some(40_204))),
        ("egress", Box::new(|row| row.decision.resolution.egress_ifindex = 13)),
        ("next hop", Box::new(|row| row.decision.resolution.next_hop = None)),
        ("install table", Box::new(|row| row.decision.install_table_domain = 9)),
        ("ingress zone", Box::new(|row| row.metadata.ingress_zone = 2)),
        ("egress zone", Box::new(|row| row.metadata.egress_zone = 1)),
        ("ingress vintage", Box::new(|row| row.metadata.ingress_zone_check = 7)),
        ("egress vintage", Box::new(|row| row.metadata.egress_zone_check = 7)),
        ("ingress ifindex", Box::new(|row| row.metadata.ingress_ifindex = 9)),
        ("ingress vlan", Box::new(|row| row.metadata.ingress_vlan_id = 80)),
        ("forward ingress vlan", Box::new(|row| row.metadata.forward_ingress_vlan_id = Some(80))),
        ("nat scope", Box::new(|row| row.metadata.nat_scope_ifindex = Some(12))),
        ("owner rg", Box::new(|row| row.metadata.owner_rg_id = 2)),
        ("fabric ingress", Box::new(|row| row.metadata.fabric_ingress = true)),
        ("direction", Box::new(|row| row.metadata.is_reverse = true)),
        ("alias provenance", Box::new(|row| row.metadata.forward_wire_alias_origin = true)),
        ("nat64 reverse", Box::new(move |row| row.metadata.nat64_reverse = Some(reverse_info))),
        ("log init", Box::new(|row| row.metadata.log_session_init = true)),
        ("log close", Box::new(|row| row.metadata.log_session_close = true)),
        ("policy id", Box::new(|row| row.metadata.policy_id = 9)),
        ("idle timeout", Box::new(|row| row.metadata.inactivity_timeout_ns = Some(1_000))),
        ("policy counter index", Box::new(|row| row.metadata.policy_counter_idx = 3)),
        ("policy counter", Box::new(move |row| row.metadata.policy_counter = counter())),
        ("snat provenance", Box::new(|row| row.source_nat_static = Some(true))),
        ("close class", Box::new(|row| row.tcp_close_class = crate::session::TcpCloseClass::Reset.to_wire())),
        (
            "handshake stage",
            Box::new(|row| row.tcp_handshake_state = crate::session::TcpHandshakeState::Opening.to_wire()),
        ),
        ("revoked leak stamp", Box::new(|row| row.leak_incarnation = 0x1915_3bad)),
    ];
    let refreshes: Vec<(&str, Change)> = vec![
        ("generation", Box::new(|row| row.generation += 5)),
        ("publisher flags", Box::new(|row| row.tcp_flags = crate::tcp_flags::TCP_FIN)),
        ("origin", Box::new(|row| row.origin = SessionOrigin::SharedPromote)),
        ("forward packets", Box::new(|row| row.fwd_packets = 40)),
        ("reverse packets", Box::new(|row| row.rev_packets = 41)),
        ("sibling clock", Box::new(|row| row.sibling_last_seen_ns = 42)),
        ("served clock", Box::new(|row| row.last_served_ns = 43)),
        ("pptp call ids", Box::new(|row| row.pptp_call_ids = 44)),
        ("session id (the identity rule's)", Box::new(|row| row.session_id = 0)),
        ("legacy handshake byte", Box::new(|row| row.tcp_handshake_state = 0)),
        ("unknown close byte", Box::new(|row| row.tcp_close_class = 0xee)),
    ];
    for (expected, rows) in [
        (MaterializeDivergence::Drop, &drops),
        (MaterializeDivergence::None, &refreshes),
    ] {
        for (field, change) in rows.iter() {
            let mut current = base.clone();
            change(&mut current);
            assert_eq!(
                materialize_divergence(&forwarding, &base, &current, &mut None),
                expected,
                "{field}: classification"
            );
        }
    }
    // Close and handshake bytes are TCP state: a UDP row installs neither, so
    // a difference in them is not a difference in what is installed.
    let mut udp = base.clone();
    udp.key.protocol = PROTO_UDP;
    udp.protocol = PROTO_UDP;
    let mut udp_current = udp.clone();
    udp_current.tcp_close_class = crate::session::TcpCloseClass::Reset.to_wire();
    assert_eq!(
        materialize_divergence(&forwarding, &udp, &udp_current, &mut None),
        MaterializeDivergence::None,
        "UDP close byte: classification"
    );
}
