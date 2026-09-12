// #9526: the helper-side purge of a deleted (or renamed) FIRST policy's
// sessions. Loaded from session_glue/mod.rs via `#[path]`.
//
// The daemon's commit sweep cannot clear these sessions: the first policy's
// positional id is 0, the value host-local, neighbor-seed, fabric, tunnel and
// older-peer sessions also carry, so `deletedPolicyRuntimeIDs` skips it. The
// helper can, because a session the policy admitted binds the rule's counter
// handle. These cells bind the choice of rule, the discriminator and the full
// pair teardown. The worker-loop wiring is bound BEHAVIOURALLY, through a real
// `worker_loop` rotation, in worker/loop_body/first_policy_purge_rotation_9526_tests.rs.
use super::*;
use crate::policy::{
    parse_policy_state_with_counters, PolicyCounterStore, PolicyRuleCounter, PolicyState,
    DEFAULT_POLICY_COUNTER_IDX, DEFAULT_POLICY_SENTINEL_ID,
};
use rustc_hash::FxHashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

const ACK: u8 = 0x10;

fn rule(name: &str, policy_id: u32) -> crate::PolicyRuleSnapshot {
    crate::PolicyRuleSnapshot {
        name: name.to_string(),
        policy_id,
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["any".to_string()],
        destination_addresses: vec!["any".to_string()],
        applications: vec![format!("app-{name}")],
        application_terms: vec![crate::PolicyApplicationSnapshot {
            name: format!("app-{name}"),
            protocol: "tcp".to_string(),
            source_port: String::new(),
            destination_port: String::new(),
            icmp_type: None,
            icmp_code: None,
            inactivity_timeout: None,
        }],
        action: "permit".to_string(),
        ..Default::default()
    }
}

fn policy(rules: &[crate::PolicyRuleSnapshot]) -> PolicyState {
    let zones: FxHashMap<String, u16> = [("lan".to_string(), 1u16), ("wan".to_string(), 2u16)]
        .into_iter()
        .collect();
    parse_policy_state_with_counters("deny", rules, &zones, &[], &PolicyCounterStore::default())
        .expect("fixture policy must parse")
}

fn key(src_port: u16) -> SessionKey {
    SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
        src_port,
        dst_port: 5201,
        discriminator: Default::default(),
        routing_domain: 0,
    }
}

fn decision() -> SessionDecision {
    SessionDecision {
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::ForwardCandidate,
            local_ifindex: 0,
            egress_ifindex: 12,
            tx_ifindex: 12,
            tunnel_endpoint_id: 0,
            next_hop: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 50, 1))),
            neighbor_mac: Some([0, 1, 2, 3, 4, 5]),
            src_mac: Some([6, 7, 8, 9, 10, 11]),
            tx_vlan_id: 0,
        },
        nat: NatDecision::default(),
    }
}

fn metadata(
    is_reverse: bool,
    policy_id: u32,
    counter: Option<Arc<PolicyRuleCounter>>,
) -> SessionMetadata {
    SessionMetadata {
        ingress_zone: 1,
        egress_zone: 2,
        ingress_ifindex: 0,
        ingress_vlan_id: 0,
        owner_rg_id: 1,
        fabric_ingress: false,
        is_reverse,
        nat64_reverse: None,
        log_session_init: false,
        log_session_close: false,
        policy_id,
        inactivity_timeout_ns: None,
        policy_counter_idx: 0,
        policy_counter: counter,
    }
}

/// Installs a forward entry and its reverse companion, both bound to `counter`,
/// and returns the reverse key.
fn install_pair(
    sessions: &mut SessionTable,
    fwd: &SessionKey,
    policy_id: u32,
    counter: Option<Arc<PolicyRuleCounter>>,
) -> SessionKey {
    let rev = reverse_session_key(fwd, NatDecision::default());
    assert!(sessions.install_with_protocol_with_origin(
        fwd.clone(),
        decision(),
        metadata(false, policy_id, counter.clone()),
        SessionOrigin::ForwardFlow,
        1,
        PROTO_TCP,
        ACK,
    ));
    assert!(sessions.install_with_protocol_with_origin(
        rev.clone(),
        decision(),
        metadata(true, policy_id, counter),
        SessionOrigin::ReverseFlow,
        1,
        PROTO_TCP,
        ACK,
    ));
    rev
}

fn purge(sessions: &mut SessionTable, rule_id: &str) -> usize {
    let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
    let peer_worker_commands: Vec<Arc<Mutex<VecDeque<WorkerCommand>>>> = Vec::new();
    purge_sessions_bound_to_deleted_first_policy(
        sessions,
        SteeringMap::unshared_for_test(-1),
        -1,
        -1,
        &shared_sessions,
        &shared_nat_sessions,
        &shared_forward_wire_sessions,
        &shared_owner_rg_indexes,
        &peer_worker_commands,
        crate::afxdp::empty_worker_commands_by_id(),
        &ForwardingState::default(),
        rule_id,
        2,
        0,
    )
}

#[test]
fn first_policy_rule_id_names_only_a_single_policy_id_zero_rule_9526() {
    let two = policy(&[rule("p-first", 0), rule("p-web", 1)]);
    assert_eq!(two.first_policy_rule_id(), Some("lan->wan/p-first"));
    // Every rule at 0 is a snapshot whose producer assigned no ids: it names no
    // first policy, so nothing may be purged on its account.
    let legacy = policy(&[rule("a", 0), rule("b", 0)]);
    assert_eq!(legacy.first_policy_rule_id(), None);
    assert_eq!(policy(&[]).first_policy_rule_id(), None);
    assert!(two.has_rule_id("lan->wan/p-web"));
    assert!(!two.has_rule_id("lan->wan/p-gone"));
}

#[test]
fn deleted_first_policy_rule_id_fires_on_delete_and_rename_only_9526() {
    let old = policy(&[rule("p-first", 0), rule("p-web", 1)]);
    let first = Some("lan->wan/p-first".to_string());
    assert_eq!(
        deleted_first_policy_rule_id(&old, &policy(&[rule("p-web", 0)])),
        first,
        "deleted: the survivor moves into position 0"
    );
    assert_eq!(
        deleted_first_policy_rule_id(&old, &policy(&[rule("p-first-v2", 0), rule("p-web", 1)])),
        first,
        "renamed: a new stable id takes position 0"
    );
    assert_eq!(deleted_first_policy_rule_id(&old, &old), None, "unchanged");
    assert_eq!(
        deleted_first_policy_rule_id(&old, &policy(&[rule("p-first", 0)])),
        None,
        "a LATER policy deleted is the daemon sweep's job, not this purge's"
    );
    assert_eq!(
        deleted_first_policy_rule_id(&old, &policy(&[rule("p-web", 0), rule("p-first", 1)])),
        None,
        "reordered: the first policy still exists"
    );
    assert_eq!(
        deleted_first_policy_rule_id(&policy(&[rule("a", 0), rule("b", 0)]), &policy(&[rule("b", 0)])),
        None,
        "an all-zero old snapshot names no first policy"
    );
}

#[test]
fn purge_removes_both_halves_of_the_deleted_first_policys_sessions_only_9526() {
    let old = policy(&[rule("p-first", 0), rule("p-web", 1)]);
    let first_counter = old.hit_counter_by_idx(1).cloned();
    let web_counter = old.hit_counter_by_idx(2).cloned();
    let default_counter = old.hit_counter_by_idx(DEFAULT_POLICY_COUNTER_IDX).cloned();
    assert_eq!(
        first_counter.as_ref().map(|c| c.rule_id()),
        Some("lan->wan/p-first"),
        "fixture: counter idx 1 is the first rule's handle"
    );
    assert_eq!(web_counter.as_ref().map(|c| c.rule_id()), Some("lan->wan/p-web"));
    assert!(default_counter.is_some(), "fixture: the default-policy handle exists");

    let mut sessions = SessionTable::new();
    let first_fwd = key(40001);
    let first_rev = install_pair(&mut sessions, &first_fwd, 0, first_counter);
    let web_fwd = key(40002);
    let web_rev = install_pair(&mut sessions, &web_fwd, 1, web_counter);
    // Stand-in for a host-local / neighbor-seed / fabric / tunnel / peer-synced
    // session: the same wire policy_id 0, and no bound rule handle.
    let unbound_fwd = key(40003);
    let unbound_rev = install_pair(&mut sessions, &unbound_fwd, 0, None);
    let default_fwd = key(40004);
    let default_rev =
        install_pair(&mut sessions, &default_fwd, DEFAULT_POLICY_SENTINEL_ID, default_counter);
    let _ = sessions.drain_deltas(64);

    let new = policy(&[rule("p-web", 0)]);
    let rule_id = deleted_first_policy_rule_id(&old, &new).expect("the first policy was deleted");
    assert_eq!(purge(&mut sessions, &rule_id), 1, "exactly the first policy's one forward session");

    assert!(
        sessions.entry_with_origin(&first_fwd).is_none(),
        "the forward half of the deleted first policy's session survived"
    );
    assert!(
        sessions.entry_with_origin(&first_rev).is_none(),
        "the REVERSE half survived: a one-way reverse flow keeps transiting (#9526)"
    );
    for (what, k) in [
        ("second policy, forward", &web_fwd),
        ("second policy, reverse", &web_rev),
        ("unbound id-0, forward", &unbound_fwd),
        ("unbound id-0, reverse", &unbound_rev),
        ("default policy, forward", &default_fwd),
        ("default policy, reverse", &default_rev),
    ] {
        assert!(sessions.entry_with_origin(k).is_some(), "{what} session was purged");
    }
    let deltas = sessions.drain_deltas(64);
    assert_eq!(deltas.len(), 1, "one close delta; the reverse half's is suppressed");
    assert_eq!(deltas[0].kind, SessionDeltaKind::Close);
    assert_eq!(deltas[0].key, first_fwd);
}
