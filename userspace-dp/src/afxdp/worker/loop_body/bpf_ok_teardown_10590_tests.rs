// #10590: bind the CALLER's `!bpf_ok` teardown branch in
// `rebind_policy_sessions_from_snapshot` (loop_body/mod.rs), which was dead
// in every test.
//
// Mechanism. The callee `restamp_bpf_conntrack_policy` reports failure in
// three shapes — family/address mismatch, live lookup miss, live update
// failure — plus an `fd < 0 -> true` gate for builds without a pinned map.
// The caller restamps both rebound halves and tears the pair down unless
// every half reports ok. But the mismatch shape is unreachable through the
// caller (the record parser enforces family/address agreement), and every
// rotation cell runs `worker_loop` with an empty plan, so every conntrack fd
// is `-1` and every restamp reports success. No test called the rebind entry
// point directly at all. Deleting the teardown, flipping `all` to `any`, or
// gutting the live-update arm all stayed green — the pair kept its new
// policy identity while the BPF rows kept the old one (split identity).
//
// Fault injection. These cells call `rebind_policy_sessions_from_snapshot`
// directly with a conntrack fd that is valid-looking but never a map
// (`i32::MAX`, the `NOT_A_MAP_FD` precedent from
// `routing_domain_publish_9517_tests.rs`): non-negative, so the `fd < 0`
// early-true does not fire; never open, so the lookup fails deterministically
// with EBADF and the restamp reports `false` — no privileges, no map, no
// flakes. A `-1` control beside each bogus-fd cell proves the fixture itself
// rebinds.
//
// What a bogus fd cannot express is exactly-one-false: same-family halves
// share one conntrack fd, so both halves fail together. The T5 cell covers
// that gap with the `fail_restamp_attempt_on` hook in `bpf_map` (an `all` ->
// `any` mutant publishes there and only there).
//
// T0 seam hygiene. The `RESTAMP_ATTEMPTS` recorder and the fail hook are
// thread-local, like `SESSION_MAP_WRITES` (#8105: a process-global counter
// races every parallel test driving a restamp, and production code cannot
// take a lock). The hook defaults to off. Every cell clears the seam first:
// `cargo test` reuses pool threads across cells, so a hook armed by T5 would
// otherwise still be armed when a later cell runs on the same thread; T5
// also clears after sampling so it never leaks an armed hook. Every drive is
// a synchronous direct call, so each cell's attempts land on its own thread.
//
// Clause 1 (privileged cell): infeasible today. There is no CAP_BPF-gated
// Rust cell anywhere in the tree, the hosts run
// `kernel.unprivileged_bpf_disabled=2`, and there is no privileged CI runner
// to execute one. A live-map restamp failure is therefore proven here by
// fault injection (bogus fd / fail hook) rather than by a real BPF map; if a
// privileged runner ever exists, the cell to add is a T1-shaped drive
// against a real map whose row was deleted out from under the rebind.
//
// Cells: T1 bogus-v4-fd teardown proof; T2 `-1` control; T3 v6 mirror (+ v6
// control); T4 both-halves-attempted wiring via the attempt recorder; T5
// fail-on-2nd-call kills `all` -> `any`. Loaded from loop_body/mod.rs via
// `#[path]`, beside the #9526 rotation cells.
use super::*;
use crate::afxdp::bpf_map::{clear_restamp_attempts, fail_restamp_attempt_on, restamp_attempts};
use crate::policy::{
    PolicyCounterStore, PolicyRuleCounter, PolicyState, parse_policy_state_with_counters,
};
use rustc_hash::FxHashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

/// Not negative, so the restamp does not take its `fd < 0` early-true; never
/// an open BPF map, so the lookup fails deterministically (EBADF) and the
/// restamp reports `false`. The `NOT_A_MAP_FD` precedent from #9517.
const NOT_A_MAP_FD: libc::c_int = i32::MAX;

const ACK: u8 = 0x10;
const NOW_NS: u64 = 2;

fn rule(name: &str, policy_id: u32) -> crate::PolicyRuleSnapshot {
    rule_with_zones(name, policy_id, "lan", "wan")
}

fn rule_with_zones(
    name: &str,
    policy_id: u32,
    from_zone: &str,
    to_zone: &str,
) -> crate::PolicyRuleSnapshot {
    crate::PolicyRuleSnapshot {
        name: name.to_string(),
        policy_id,
        from_zone: from_zone.to_string(),
        to_zone: to_zone.to_string(),
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
    let zones: FxHashMap<String, u16> = [
        ("lan".to_string(), 1u16),
        ("wan".to_string(), 2u16),
        ("dmz".to_string(), 3u16),
    ]
    .into_iter()
    .collect();
    parse_policy_state_with_counters("deny", rules, &zones, &[], &PolicyCounterStore::default())
        .expect("fixture policy must parse")
}

fn forwarding_with(new_rules: &[crate::PolicyRuleSnapshot]) -> ForwardingState {
    let mut forwarding = ForwardingState::default();
    forwarding.policy = policy(new_rules);
    forwarding.policy_rematch_extensive = true;
    forwarding.zone_name_to_id.insert("lan".to_string(), 1);
    forwarding.zone_name_to_id.insert("wan".to_string(), 2);
    forwarding.zone_name_to_id.insert("dmz".to_string(), 3);
    forwarding.zone_id_to_name.insert(1, "lan".to_string());
    forwarding.zone_id_to_name.insert(2, "wan".to_string());
    forwarding.zone_id_to_name.insert(3, "dmz".to_string());
    forwarding.zone_set_validated = true;
    forwarding.ingress_logical_ifindex.insert((11, 0), 11);
    let ingress_zone = new_rules
        .first()
        .and_then(|rule| forwarding.zone_name_to_id.get(&rule.from_zone))
        .copied()
        .unwrap_or(0);
    forwarding.ifindex_to_zone_id.insert(11, ingress_zone);
    forwarding
}

fn key_v4(src_port: u16) -> SessionKey {
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

fn key_v6(src_port: u16) -> SessionKey {
    SessionKey {
        addr_family: libc::AF_INET6 as u8,
        protocol: PROTO_TCP,
        src_ip: IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0x61, 0x102)),
        dst_ip: IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0x80, 0x200)),
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
        install_table_domain: 0,
        install_table_check: 0,
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
        ingress_ifindex: 11,
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

/// Installs a forward entry and its reverse companion, both bound to
/// `counter`, and returns the reverse key.
fn install_pair(
    sessions: &mut crate::session::SessionTable,
    fwd: &SessionKey,
    policy_id: u32,
    counter: Option<Arc<PolicyRuleCounter>>,
) -> SessionKey {
    let rev = reverse_session_key(fwd, NatDecision::default());
    assert_ne!(rev, *fwd, "fixture: the pair halves must be distinct keys");
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

fn record_for(
    key: &SessionKey,
    rule_id: &str,
    policy_id: u32,
    ingress_zone: u16,
    egress_zone: u16,
) -> crate::protocol::PolicySessionRebind {
    crate::protocol::PolicySessionRebind {
        family: if key.addr_family as i32 == libc::AF_INET6 {
            "v6".to_string()
        } else {
            "v4".to_string()
        },
        src_ip: key.src_ip.to_string(),
        dst_ip: key.dst_ip.to_string(),
        src_port: key.src_port,
        dst_port: key.dst_port,
        protocol: key.protocol,
        routing_domain: key.routing_domain,
        policy_id,
        rule_id: rule_id.to_string(),
        ingress_zone,
        egress_zone,
        tunnel_discriminator: 0,
    }
}

/// One bound pair plus one unbound id-0 pair, and the rebind record for the
/// bound pair's forward key. The rename mirrors the #10511 extensive cell:
/// `lan->wan/p-first` becomes `dmz->wan/p-new`, keeping policy id 0 with a
/// new counter and zones dmz -> wan.
struct Fixture {
    sessions: crate::session::SessionTable,
    forwarding: ForwardingState,
    fwd: SessionKey,
    rev: SessionKey,
    unbound_fwd: SessionKey,
    unbound_rev: SessionKey,
    old_counter: Option<Arc<PolicyRuleCounter>>,
    record: crate::protocol::PolicySessionRebind,
}

fn fixture_with_keys(fwd: SessionKey, unbound_fwd: SessionKey) -> Fixture {
    let old = policy(&[rule("p-first", 0), rule("p-web", 1)]);
    let old_counter = old.hit_counter_by_idx(1).cloned();
    assert_eq!(
        old_counter.as_ref().map(|c| c.rule_id()),
        Some("lan->wan/p-first"),
        "fixture: counter idx 1 is the first rule's handle"
    );
    let forwarding =
        forwarding_with(&[rule_with_zones("p-new", 0, "dmz", "wan"), rule("p-web", 1)]);
    let mut sessions = crate::session::SessionTable::new();
    let rev = install_pair(&mut sessions, &fwd, 0, old_counter.clone());
    let unbound_rev = install_pair(&mut sessions, &unbound_fwd, 0, None);
    let record = record_for(&fwd, "dmz->wan/p-new", 0, 3, 2);
    Fixture {
        sessions,
        forwarding,
        fwd,
        rev,
        unbound_fwd,
        unbound_rev,
        old_counter,
        record,
    }
}

fn v4_fixture() -> Fixture {
    fixture_with_keys(key_v4(40001), key_v4(40003))
}

fn v6_fixture() -> Fixture {
    fixture_with_keys(key_v6(40011), key_v6(40013))
}

fn drive(
    sessions: &mut crate::session::SessionTable,
    forwarding: &ForwardingState,
    record: &crate::protocol::PolicySessionRebind,
    conntrack_v4_fd: libc::c_int,
    conntrack_v6_fd: libc::c_int,
) -> usize {
    let session_map = crate::afxdp::bpf_map::SteeringMapRef::unbound();
    let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
    let peer_worker_commands: Vec<Arc<Mutex<VecDeque<WorkerCommand>>>> = Vec::new();
    rebind_policy_sessions_from_snapshot(
        sessions,
        forwarding,
        std::slice::from_ref(record),
        &session_map,
        conntrack_v4_fd,
        conntrack_v6_fd,
        &shared_sessions,
        &shared_nat_sessions,
        &shared_forward_wire_sessions,
        &shared_owner_rg_indexes,
        &peer_worker_commands,
        crate::afxdp::empty_worker_commands_by_id(),
        0,
        NOW_NS,
    )
}

fn assert_pair_absent(sessions: &crate::session::SessionTable, fwd: &SessionKey, rev: &SessionKey) {
    assert!(
        sessions.entry_with_origin(fwd).is_none(),
        "the forward half survived a failed restamp: split policy identity"
    );
    assert!(
        sessions.entry_with_origin(rev).is_none(),
        "the REVERSE half survived a failed restamp: split policy identity"
    );
}

fn assert_unbound_untouched(
    sessions: &crate::session::SessionTable,
    unbound_fwd: &SessionKey,
    unbound_rev: &SessionKey,
) {
    for (what, k) in [
        ("unbound forward", unbound_fwd),
        ("unbound reverse", unbound_rev),
    ] {
        let (_, meta, _) = sessions
            .entry_with_origin(k)
            .unwrap_or_else(|| panic!("{what} was torn down with the rebound pair"));
        assert_eq!(meta.policy_id, 0, "{what} policy_id moved");
        assert!(
            meta.policy_counter.is_none(),
            "{what} gained a bound rule handle"
        );
        assert_eq!(
            (meta.ingress_zone, meta.egress_zone),
            (1, 2),
            "{what} zones moved"
        );
    }
}

fn assert_pair_rebound_to_new_rule(fx: &Fixture) {
    let (new_idx, _) = fx
        .forwarding
        .policy
        .rule_binding_by_stable_id("dmz->wan/p-new")
        .expect("fixture: the new rule binds");
    let (_, fwd_meta, _) = fx
        .sessions
        .entry_with_origin(&fx.fwd)
        .expect("the forward half is missing after a successful rebind");
    let (_, rev_meta, _) = fx
        .sessions
        .entry_with_origin(&fx.rev)
        .expect("the reverse half is missing after a successful rebind");
    assert_eq!(fwd_meta.policy_id, 0);
    assert_eq!(rev_meta.policy_id, 0);
    assert_eq!(fwd_meta.policy_counter_idx, new_idx);
    assert_eq!(rev_meta.policy_counter_idx, new_idx);
    let fwd_counter = fwd_meta
        .policy_counter
        .as_ref()
        .expect("the forward half must carry the new counter Arc");
    let rev_counter = rev_meta
        .policy_counter
        .as_ref()
        .expect("the reverse half must carry the new counter Arc");
    assert_eq!(fwd_counter.rule_id(), "dmz->wan/p-new");
    assert_eq!(rev_counter.rule_id(), "dmz->wan/p-new");
    assert!(Arc::ptr_eq(fwd_counter, rev_counter));
    assert!(
        !Arc::ptr_eq(
            fwd_counter,
            fx.old_counter
                .as_ref()
                .expect("fixture must expose the old counter"),
        ),
        "the rebind must replace, not reuse, the old policy counter Arc"
    );
    assert_eq!(
        (fwd_meta.ingress_zone, fwd_meta.egress_zone),
        (3, 2),
        "the forward half must carry the new zones"
    );
    assert_eq!(
        (rev_meta.ingress_zone, rev_meta.egress_zone),
        (2, 3),
        "the reverse half must carry the swapped new zones"
    );
}

/// T1: a restamp failure on a live fd tears the rebound pair down instead of
/// publishing it with a split policy identity. RED: delete or invert the
/// `!bpf_ok` teardown -> the pair survives with the new identity and this
/// cell fails on presence.
#[test]
fn bogus_v4_fd_tears_down_the_rebound_pair_10590() {
    clear_restamp_attempts();
    let mut fx = v4_fixture();
    let rebound = drive(
        &mut fx.sessions,
        &fx.forwarding,
        &fx.record,
        NOT_A_MAP_FD,
        -1,
    );
    assert_pair_absent(&fx.sessions, &fx.fwd, &fx.rev);
    assert_eq!(
        rebound, 0,
        "a restamp failure on a live fd must rebound nothing"
    );
    assert_eq!(
        fx.sessions.len(),
        2,
        "only the unbound pair may remain after the teardown"
    );
    assert_unbound_untouched(&fx.sessions, &fx.unbound_fwd, &fx.unbound_rev);
}

/// T2: the control that makes T1 mean something — the same fixture with
/// unmapped fds rebinds the pair with the new rule identity. RED: flip the
/// teardown polarity (`if bpf_ok`) -> the control tears down and rebounds 0.
#[test]
fn unmapped_fd_rebinds_the_pair_10590() {
    clear_restamp_attempts();
    let mut fx = v4_fixture();
    let rebound = drive(&mut fx.sessions, &fx.forwarding, &fx.record, -1, -1);
    assert_eq!(
        rebound, 1,
        "control: the fixture must rebind with unmapped fds"
    );
    assert_pair_rebound_to_new_rule(&fx);
    assert_eq!(
        fx.sessions.len(),
        4,
        "control: the rebind must drop nothing"
    );
    assert_unbound_untouched(&fx.sessions, &fx.unbound_fwd, &fx.unbound_rev);
}

/// T3: the v6 mirror of T1 — a restamp failure on the v6 fd tears the pair
/// down. RED: gut the v6 live arm (unconditional true) -> the pair publishes
/// and this cell fails with rebound 1.
#[test]
fn bogus_v6_fd_tears_down_the_rebound_pair_10590() {
    clear_restamp_attempts();
    let mut fx = v6_fixture();
    let rebound = drive(
        &mut fx.sessions,
        &fx.forwarding,
        &fx.record,
        -1,
        NOT_A_MAP_FD,
    );
    assert_eq!(
        rebound, 0,
        "a restamp failure on the live v6 fd must rebound nothing"
    );
    assert_pair_absent(&fx.sessions, &fx.fwd, &fx.rev);
    assert_eq!(
        fx.sessions.len(),
        2,
        "only the unbound pair may remain after the teardown"
    );
    assert_unbound_untouched(&fx.sessions, &fx.unbound_fwd, &fx.unbound_rev);
}

/// T3 control: the v6 fixture rebinds with unmapped fds.
#[test]
fn unmapped_fd_rebinds_the_v6_pair_10590() {
    clear_restamp_attempts();
    let mut fx = v6_fixture();
    let rebound = drive(&mut fx.sessions, &fx.forwarding, &fx.record, -1, -1);
    assert_eq!(
        rebound, 1,
        "control: the v6 fixture must rebind with unmapped fds"
    );
    assert_pair_rebound_to_new_rule(&fx);
    assert_eq!(
        fx.sessions.len(),
        4,
        "control: the v6 rebind must drop nothing"
    );
    assert_unbound_untouched(&fx.sessions, &fx.unbound_fwd, &fx.unbound_rev);
}

/// T4: both halves are ATTEMPTED before the rebind seam — the wiring proof,
/// not just the outcome. The control fd `-1` returns true for each half, so
/// `all` must visit both entries and the pair rebinds. RED: remove the
/// restamp call from the caller -> zero attempts and this cell fails on the
/// delta.
#[test]
fn unmapped_fd_attempts_both_halves_before_rebind_10590() {
    clear_restamp_attempts();
    let mut fx = v4_fixture();
    let rebound = drive(&mut fx.sessions, &fx.forwarding, &fx.record, -1, -1);
    assert_eq!(rebound, 1, "the unmapped-fd control must rebind the pair");
    let attempts = restamp_attempts();
    assert_eq!(
        attempts.len(),
        2,
        "both halves must be attempted before the rebind"
    );
    for attempt in &attempts {
        assert_eq!(
            attempt.addr_family,
            libc::AF_INET as u8,
            "the v4 drive must attempt v4 restamps"
        );
        assert_eq!(attempt.fd, -1, "the control must carry the unmapped fd");
    }
    assert_pair_rebound_to_new_rule(&fx);
    assert_unbound_untouched(&fx.sessions, &fx.unbound_fwd, &fx.unbound_rev);
}

/// T5: exactly-one-false tears the pair down — the `all` (not `any`) proof.
/// A bogus fd fails both halves (same-family halves share one fd), so the
/// second attempt is failed by hook while the first succeeds for real. RED:
/// `all` -> `any` -> the pair publishes and this cell fails with rebound 1.
#[test]
fn second_half_failure_tears_down_despite_first_half_success_10590() {
    clear_restamp_attempts();
    fail_restamp_attempt_on(2);
    let mut fx = v4_fixture();
    let rebound = drive(&mut fx.sessions, &fx.forwarding, &fx.record, -1, -1);
    let attempts = restamp_attempts();
    clear_restamp_attempts();
    assert_eq!(
        rebound, 0,
        "exactly-one-false must tear the pair down (all, not any)"
    );
    assert_eq!(
        attempts.len(),
        2,
        "both halves must be attempted before the teardown"
    );
    assert_pair_absent(&fx.sessions, &fx.fwd, &fx.rev);
    assert_eq!(
        fx.sessions.len(),
        2,
        "only the unbound pair may remain after the teardown"
    );
    assert_unbound_untouched(&fx.sessions, &fx.unbound_fwd, &fx.unbound_rev);
}
