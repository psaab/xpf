//! #10591: per-shape production-window sweep quantification for #10509.
//!
//! The sibling #10509 matrix deliberately remains a three-packet mechanism
//! test. These cells reuse its shape builders, packet tuples, binding fixture,
//! session counter, and real poll path, then add the production clock boundary:
//! fake `now_ns`, one real GC tick per declared tick, the exact worker-loop
//! expire+reap pair, and the commit-time removed-zone purge.
//!
//! MAX values below are LOOSE ceilings derived from production cadence
//! inputs (GC interval, wheel tick/buckets, assumed 1s Go slack, session
//! capacity), not measured windows. Operative regression teeth are the
//! terminal pins (terminal tick/purged/rows). C7 in the Go daemon suite pins
//! the independent arm→apply→sweep ordering; commit-delay itself is assumed
//! slack, not measured (prod tail unbounded per daemon.go:681-685).
//!
//! Disposition: #10591 closes on ceiling+terminal (LOOSE-CEILING bounds plus
//! terminal pins plus the Go ordering guard); commit-delay parameterization
//! is follow-up #10624, blocked on a production numeric bound.

#![allow(clippy::type_complexity)]

use super::tests_session_hit_authority_9519::{
    MATRIX_SHAPES, binding, matrix_forward_observation, matrix_forwarding, matrix_packet,
    session_count,
};
use super::tests_support::{
    TEST_LAN_MAC, build_txn_tcp_syn_frame_v4, txn_ha_state, txn_meta_v4, txn_run_descriptor_at,
};
use super::*;
use crate::afxdp::worker::{production_rotation_purge_for_test, production_sweep_for_test};
use crate::session::{
    SESSION_GC_INTERVAL_NS_FOR_TEST, SessionOrigin, SessionTable, WHEEL_BUCKETS_FOR_TEST,
    WHEEL_TICK_NS_FOR_TEST,
};
use crate::tcp_flags::{TCP_ACK, TCP_RST, TCP_SYN};
use crate::test_zone_ids::{TEST_DMZ_ZONE_ID, TEST_LAN_ZONE_ID};
use std::collections::BTreeSet;
use std::net::Ipv4Addr;

const T0_NS: u64 = 1_000_000_000_000;
const WINDOW_PPS: u64 = 1;

// Production inputs: `SESSION_GC_INTERVAL_NS` (`session/mod.rs:88`) gates
// `expire_stale_entries_ha` (`session/expire.rs:143-172`); `WHEEL_TICK_NS`
// (`session/wheel.rs:19-24`) advances the `WHEEL_BUCKETS` (`wheel.rs:14-17`)
// horizon. The Go commit stamp is CLOCK_MONOTONIC seconds
// (`pkg/daemon/daemon.go:669-696`), and capture is deliberately before the
// dataplane publish (`pkg/daemon/daemon_apply_dataplane.go:160-196`), while
// the sweep follows the apply (`pkg/daemon/daemon_apply_commit.go:314-359`).
// One assumed activation-second of boundary slack plus a full wheel horizon
// is the independently-derived LOOSE-CEILING bound; it is not the
// packet-loop count and not a measured commit delay.
const GO_POLICY_ACTIVATION_SECONDS: u64 = 1;
const GO_POLICY_ACTIVATION_NS: u64 = GO_POLICY_ACTIVATION_SECONDS * 1_000_000_000;
const GC_TICK_NS: u64 = SESSION_GC_INTERVAL_NS_FOR_TEST;
const PRODUCTION_BOUND_TICKS: u64 = WHEEL_BUCKETS_FOR_TEST as u64
    + (GO_POLICY_ACTIVATION_NS + SESSION_GC_INTERVAL_NS_FOR_TEST - 1)
        / SESSION_GC_INTERVAL_NS_FOR_TEST;
// Controls run through the independently-derived production horizon. Drop
// cells terminate earlier when the real rotation purge fires.
const OBSERVATION_TICKS: u64 = PRODUCTION_BOUND_TICKS;

// LOOSE-CEILING formula: one offered packet per production GC tick, bounded
// by the full wheel + assumed Go activation-second formula above. This is
// repeated independently of the observed terminal packet count so a
// production-input mutation moves the MAX even when rotation still
// terminates on tick one. Tight operative bounds live in the terminal pins
// and the M1 worst-case cells, not here.
const MAX_DROPS_PER_RENAME_SINGLE_ZONE_DEFAULT_DENY: u64 = (WHEEL_BUCKETS_FOR_TEST as u64
    + (GO_POLICY_ACTIVATION_NS + SESSION_GC_INTERVAL_NS_FOR_TEST - 1)
        / SESSION_GC_INTERVAL_NS_FOR_TEST)
    * WINDOW_PPS;
const MAX_DROPS_PER_RENAME_DEAD_EGRESS_DEFAULT_DENY: u64 = (WHEEL_BUCKETS_FOR_TEST as u64
    + (GO_POLICY_ACTIVATION_NS + SESSION_GC_INTERVAL_NS_FOR_TEST - 1)
        / SESSION_GC_INTERVAL_NS_FOR_TEST)
    * WINDOW_PPS;
// The fixture population is intentionally separate from the production bound:
// C4 drives four rows, while the real per-worker SessionTable ceiling is the
// independent session-per-rename maximum (`session/mod.rs:3840-3841`).
const FIXTURE_SESSION_COUNT: usize = 4;
const MAX_SESSIONS_AFFECTED: usize = crate::session::default_max_sessions();
const MAX_TOTAL_DROPS_PER_RENAME: u64 =
    MAX_SESSIONS_AFFECTED as u64 * MAX_DROPS_PER_RENAME_SINGLE_ZONE_DEFAULT_DENY;
// Provenance: `policy_revoked_sessions` counts one pair teardown, not packets;
// its packet observation bound is one activation-second plus one wheel tick.
const MAX_REVOKES_PER_RENAME: u64 = 1;
const MAX_REVOKE_TICKS: u64 =
    ((GO_POLICY_ACTIVATION_NS + WHEEL_TICK_NS_FOR_TEST - 1) / WHEEL_TICK_NS_FOR_TEST) + 1;

// M1 worst-case: bounded commit delay. One activation-second tick of Go
// publish→sweep slack (the same assumed-slack input as the ceiling,
// `pkg/daemon/daemon.go:681-685`) plus one worker tick to observe the new
// snapshot and run the rotation purge. N=2 is deliberately decoupled from
// the 257-tick loop cap: the worst-case cells below offer exactly N packets
// and pin drops to N*PPS, so +1 tick or +1 drop REDs them.
const COMMIT_DELAY_TICKS: u64 = (GO_POLICY_ACTIVATION_NS + SESSION_GC_INTERVAL_NS_FOR_TEST - 1)
    / SESSION_GC_INTERVAL_NS_FOR_TEST
    + 1;
const MAX_DROPS_WORST_CASE_PER_RENAME: u64 = COMMIT_DELAY_TICKS * WINDOW_PPS;
const MAX_TOTAL_DROPS_WORST_CASE: u64 =
    FIXTURE_SESSION_COUNT as u64 * MAX_DROPS_WORST_CASE_PER_RENAME;

const LAN_IFINDEX: i32 = 24;
const DMZ_IFINDEX: i32 = 26;
const REAL: Ipv4Addr = Ipv4Addr::new(10, 0, 61, 102);
const PEER: Ipv4Addr = Ipv4Addr::new(172, 16, 80, 200);
const REAL_PORT: u16 = 8443;
const PEER_BASE_PORT: u16 = 5201;
/// Fresh stable zone ID the renamed `lan` carries in the NEW snapshot. A
/// production rename assigns a new StableZoneID hash, so the old ID (1) has
/// no entry in the new map (the `None` arm of
/// `removed_zone_ids_for_rotation`).
const RENAMED_LAN_ZONE_ID: u16 = 101;

fn drive_at(
    binding: &mut BindingWorker,
    sessions: &mut SessionTable,
    forwarding: &ForwardingState,
    packet: (Vec<u8>, UserspaceDpMeta),
    now_ns: u64,
) -> DebugPollCounters {
    let (batch, dbg) = txn_run_descriptor_at(
        binding,
        sessions,
        forwarding,
        &txn_ha_state(),
        &packet.0,
        packet.1,
        now_ns,
    );
    assert_eq!(
        batch.validated_packets, 1,
        "10591: packet must pass descriptor validation"
    );
    dbg
}

fn slot_packet(arrival: i32, flags: u8, slot: u16) -> (Vec<u8>, UserspaceDpMeta) {
    // The shared matrix tuple is slot 0. Distinct source ports make C4's
    // affected-session attribution observable without manufacturing keys.
    if slot == 0 {
        return matrix_packet(arrival, flags);
    }
    let dst_mac = match arrival {
        LAN_IFINDEX => TEST_LAN_MAC,
        DMZ_IFINDEX => [0x02, 0xbf, 0x72, 0x02, 0x00, 0x01],
        other => panic!("10591: unsupported ingress ifindex {other}"),
    };
    let frame =
        build_txn_tcp_syn_frame_v4(REAL, PEER, REAL_PORT, PEER_BASE_PORT + slot, flags, dst_mac);
    let meta = txn_meta_v4(arrival as u32, flags, frame.len() as u16);
    (frame, meta)
}

fn row_for_slot(sessions: &SessionTable, slot: u16) -> usize {
    let port = PEER_BASE_PORT + slot;
    let mut rows = 0;
    sessions.iter_with_origin(|key, _decision, _metadata, _origin| {
        if key.src_port == port || key.dst_port == port {
            rows += 1;
        }
    });
    rows
}

fn forward_record(
    sessions: &SessionTable,
) -> (crate::session::SessionKey, SessionDecision, SessionMetadata) {
    let mut record = None;
    sessions.iter_with_origin(|key, decision, metadata, _origin| {
        if !metadata.is_reverse && record.is_none() {
            record = Some((key.clone(), decision, metadata.clone()));
        }
    });
    record.expect("10591: expected one forward session row")
}

fn forward_observation_at(sessions: &SessionTable, now_ns: u64) -> (u64, u32) {
    let mut observation = None;
    sessions.iter_with_idle(now_ns, |_, _, metadata, idle_ns, _| {
        if !metadata.is_reverse && observation.is_none() {
            observation = Some((idle_ns, metadata.policy_id));
        }
    });
    observation.expect("10591: expected one forward session observation")
}

fn cache_seed(
    binding: &mut BindingWorker,
    key: &crate::session::SessionKey,
    decision: SessionDecision,
    metadata: SessionMetadata,
) {
    binding.flow.flow_cache.insert(FlowCacheEntry {
        key: key.clone(),
        ingress_ifindex: LAN_IFINDEX,
        logical_ingress_ifindex: LAN_IFINDEX,
        descriptor: RewriteDescriptor {
            dst_mac: [0; 6],
            src_mac: [0; 6],
            fabric_redirect: false,
            tx_vlan_id: 0,
            ether_type: 0x0800,
            rewrite_src_ip: decision.nat.rewrite_src,
            rewrite_dst_ip: decision.nat.rewrite_dst,
            rewrite_src_port: decision.nat.rewrite_src_port,
            rewrite_dst_port: decision.nat.rewrite_dst_port,
            ip_csum_delta: 0,
            l4_csum_delta: 0,
            egress_ifindex: decision.resolution.egress_ifindex,
            tx_ifindex: decision.resolution.tx_ifindex,
            target_binding_index: None,
            input_filter_log: None,
            input_filter_counters: crate::filter::CachedFilterCounters::default(),
            tx_selection: CachedTxSelectionDescriptor::default(),
            nat64: false,
            nptv6: false,
            apply_nat_on_fabric: false,
        },
        decision,
        metadata: metadata.clone(),
        stamp: FlowCacheStamp {
            config_generation: 7,
            fib_generation: 9,
            owner_rg_id: metadata.owner_rg_id,
            owner_rg_epoch: 0,
            owner_rg_lease_until: 0,
        },
        observed_bytes: 0,
        last_used_epoch: 0,
        neighbor_mac_epoch: 0,
        neighbor_shard: crate::afxdp::flow_cache::NEIGHBOR_SHARD_NONE,
    });
}

fn cache_hits(binding: &mut BindingWorker, key: &crate::session::SessionKey) -> bool {
    let rg_epochs = std::array::from_fn(|_| std::sync::atomic::AtomicU32::new(0));
    binding
        .flow
        .flow_cache
        .lookup(
            key,
            FlowCacheLookup {
                ingress_ifindex: LAN_IFINDEX,
                logical_ingress_ifindex: LAN_IFINDEX,
                config_generation: 7,
                fib_generation: 9,
            },
            0,
            &rg_epochs,
        )
        .is_some()
}

fn admit_local_pair(
    install: &ForwardingState,
    sessions: &mut SessionTable,
    binding: &mut BindingWorker,
    slot: u16,
    now_ns: u64,
) {
    let dbg = drive_at(
        binding,
        sessions,
        install,
        slot_packet(LAN_IFINDEX, TCP_SYN, slot),
        now_ns,
    );
    assert_eq!(dbg.tx, 1, "slot {slot}: pre-rename admission must forward");
    assert_eq!(
        row_for_slot(sessions, slot),
        2,
        "slot {slot}: admission pair"
    );
}

/// Reinstall an admitted pair as a peer-synced pair. The real poll admission
/// supplies key, decision, and both companion metadata records; only origin,
/// policy-id, and counter binding are changed to the wire shape that the
/// production removed-zone purge is designed to clear.
fn admit_synced_pair(
    install: &ForwardingState,
    sessions: &mut SessionTable,
    slot: u16,
    now_ns: u64,
) {
    let mut probe = SessionTable::new();
    let mut probe_binding = binding(LAN_IFINDEX);
    admit_local_pair(install, &mut probe, &mut probe_binding, slot, now_ns);
    let mut records = Vec::new();
    probe.iter_with_origin(|key, decision, metadata, _origin| {
        let mut metadata = metadata.clone();
        metadata.policy_id = 0;
        metadata.policy_counter = None;
        records.push((key.clone(), decision, metadata));
    });
    assert_eq!(
        records.len(),
        2,
        "slot {slot}: probe must expose both halves"
    );
    for (key, decision, metadata) in records {
        assert!(sessions.install_with_protocol_with_origin(
            key,
            decision,
            metadata,
            SessionOrigin::SyncImport,
            now_ns,
            PROTO_TCP,
            TCP_ACK,
        ));
    }
    assert_eq!(row_for_slot(sessions, slot), 2, "slot {slot}: synced pair");
}

fn rotation_states(live: &ForwardingState) -> (ForwardingState, ForwardingState) {
    let mut old = matrix_forwarding(true, false, false);
    let mut new = live.clone();
    old.zone_set_validated = true;
    new.zone_set_validated = true;
    // A production StableZoneID rename is old-ID disappearance: the Go
    // control plane assigns a fresh stable hash for the new name, so the old
    // ID has no entry in the new map. `removed_zone_ids_for_rotation`
    // (`session_glue/mod.rs:702-725`) reports it via the `None` arm
    // (`get(zone_id).is_none_or(...)`), and the purge attributes sessions
    // stamped with the vanished ID before the new snapshot publishes.
    old.zone_id_to_name.insert(TEST_LAN_ZONE_ID, "lan".into());
    new.zone_id_to_name.remove(&TEST_LAN_ZONE_ID);
    new.zone_id_to_name
        .insert(RENAMED_LAN_ZONE_ID, "lan".into());
    (old, new)
}

fn run_ticks(
    sessions: &mut SessionTable,
    binding: &mut BindingWorker,
    live: &ForwardingState,
    arrival: i32,
    slot: u16,
    revoke_lane: bool,
    terminal_rotation: Option<(&ForwardingState, &ForwardingState)>,
) -> (u64, u64, u64, u64, u64) {
    let mut drops = 0;
    let mut revokes = 0;
    let mut forwards = 0;
    let mut packets = 0;
    let mut terminal_purged = 0;
    for tick in 1..=OBSERVATION_TICKS {
        let now_ns = T0_NS + tick * GC_TICK_NS;
        let dbg = drive_at(
            binding,
            sessions,
            live,
            slot_packet(arrival, TCP_ACK, slot),
            now_ns,
        );
        assert_eq!(
            dbg.session_hit, 1,
            "tick {tick}: packet must hit retained row"
        );
        drops += dbg.foreign_authority_drops;
        revokes += dbg.policy_revoked_sessions;
        forwards += dbg.tx;
        packets += 1;
        let expired =
            production_sweep_for_test(sessions, std::slice::from_mut(binding), live, now_ns, None);
        assert!(
            expired.is_empty(),
            "tick {tick}: continuously driven window row must not expire before commit sweep"
        );
        if !revoke_lane {
            assert_eq!(
                row_for_slot(sessions, slot),
                2,
                "tick {tick}: Drop row retention"
            );
        }
        if let Some((old, new)) = terminal_rotation {
            let (_, purged) =
                production_rotation_purge_for_test(sessions, binding, old, new, now_ns);
            if purged > 0 {
                terminal_purged = purged as u64;
                break;
            }
        }
        if revoke_lane && row_for_slot(sessions, slot) == 0 {
            break;
        }
    }
    (drops, revokes, forwards, packets, terminal_purged)
}

#[test]
fn c1_drop_window_has_per_shape_upper_bounds_and_commit_terminal_10591() {
    for shape in MATRIX_SHAPES {
        if shape.permit_control {
            continue;
        }
        let install = matrix_forwarding(true, false, false);
        let live = matrix_forwarding(shape.dmz_permit, shape.dead_egress, shape.default_permit);
        let mut sessions = SessionTable::new();
        let mut binding = binding(LAN_IFINDEX);
        admit_synced_pair(&install, &mut sessions, 0, T0_NS);
        let (old, new) = rotation_states(&live);
        let (drops, revokes, forwards, packets, terminal_purged) = run_ticks(
            &mut sessions,
            &mut binding,
            &live,
            DMZ_IFINDEX,
            0,
            false,
            Some((&old, &new)),
        );
        assert_eq!(revokes, 0, "{}/drop: Drop lane must not Revoke", shape.name);
        assert_eq!(
            forwards, 0,
            "{}/drop: deny lane must not forward",
            shape.name
        );
        assert_eq!(
            packets, 1,
            "{}/drop: production rotation terminal tick",
            shape.name
        );
        assert!(
            packets <= OBSERVATION_TICKS,
            "{}/drop: terminal exceeds bound",
            shape.name
        );
        assert_eq!(
            terminal_purged, 1,
            "{}/drop: commit sweep terminal forward row",
            shape.name
        );
        let max_drops = if shape.dead_egress {
            MAX_DROPS_PER_RENAME_DEAD_EGRESS_DEFAULT_DENY
        } else {
            MAX_DROPS_PER_RENAME_SINGLE_ZONE_DEFAULT_DENY
        };
        assert!(drops >= 1, "{}/drop: positive Drop control", shape.name);
        assert!(
            drops <= max_drops,
            "{}/drop: drops={drops} > MAX={max_drops}",
            shape.name
        );
        assert_eq!(
            session_count(&sessions),
            0,
            "{}/drop: terminal by sweep",
            shape.name
        );
    }
}

#[test]
fn c1_worst_case_delayed_purge_bounds_drops_10591() {
    // M1: worst case — the rotation purge lands COMMIT_DELAY_TICKS late
    // (bounded Go publish→sweep slack + one worker rotation tick) while
    // traffic keeps arriving. Drops must stay within N*PPS. The 257-tick
    // loop cap is not the bound: offering +1 tick or inflating drops by
    // one REDs the tight asserts below (mutant-verified), while the 257
    // loose ceiling cannot catch either.
    assert_eq!(
        COMMIT_DELAY_TICKS, 2,
        "M1 delay must stay a small credible N"
    );
    assert_eq!(MAX_DROPS_WORST_CASE_PER_RENAME, 2);
    assert!(
        MAX_DROPS_WORST_CASE_PER_RENAME <= MAX_DROPS_PER_RENAME_SINGLE_ZONE_DEFAULT_DENY,
        "worst-case bound must sit under the loose ceiling"
    );
    for shape in MATRIX_SHAPES {
        if shape.permit_control {
            continue;
        }
        let install = matrix_forwarding(true, false, false);
        let live = matrix_forwarding(shape.dmz_permit, shape.dead_egress, shape.default_permit);
        let mut sessions = SessionTable::new();
        let mut binding = binding(LAN_IFINDEX);
        admit_synced_pair(&install, &mut sessions, 0, T0_NS);
        let (old, new) = rotation_states(&live);
        let mut drops = 0;
        for tick in 1..=COMMIT_DELAY_TICKS {
            let now_ns = T0_NS + tick * GC_TICK_NS;
            let dbg = drive_at(
                &mut binding,
                &mut sessions,
                &live,
                slot_packet(DMZ_IFINDEX, TCP_ACK, 0),
                now_ns,
            );
            assert_eq!(
                dbg.session_hit, 1,
                "{}/worst: tick {tick} must hit",
                shape.name
            );
            assert_eq!(
                dbg.policy_revoked_sessions, 0,
                "{}/worst: no Revoke",
                shape.name
            );
            assert_eq!(
                dbg.tx, 0,
                "{}/worst: deny lane must not forward",
                shape.name
            );
            drops += dbg.foreign_authority_drops;
            let expired = production_sweep_for_test(
                &mut sessions,
                std::slice::from_mut(&mut binding),
                &live,
                now_ns,
                None,
            );
            assert!(
                expired.is_empty(),
                "{}/worst: row must survive the delay",
                shape.name
            );
            assert_eq!(
                row_for_slot(&sessions, 0),
                2,
                "{}/worst: retention through delay",
                shape.name
            );
        }
        assert_eq!(
            drops, COMMIT_DELAY_TICKS,
            "{}/worst: one Drop per delay tick",
            shape.name
        );
        assert!(
            drops <= MAX_DROPS_WORST_CASE_PER_RENAME,
            "{}/worst: drops={drops} exceeds N*PPS",
            shape.name
        );
        let purge_ns = T0_NS + COMMIT_DELAY_TICKS * GC_TICK_NS;
        let (removed, purged) =
            production_rotation_purge_for_test(&mut sessions, &binding, &old, &new, purge_ns);
        assert!(
            removed > 0,
            "{}/worst: rename must derive removed zone",
            shape.name
        );
        assert_eq!(
            purged, 1,
            "{}/worst: delayed purge terminal forward row",
            shape.name
        );
        assert_eq!(
            session_count(&sessions),
            0,
            "{}/worst: terminal by sweep",
            shape.name
        );
    }
}

#[test]
fn c2_revoke_window_has_per_shape_bound_10591() {
    for shape in MATRIX_SHAPES {
        if shape.permit_control {
            continue;
        }
        let install = matrix_forwarding(true, false, false);
        let live = {
            let mut state =
                matrix_forwarding(shape.dmz_permit, shape.dead_egress, shape.default_permit);
            state
                .ifindex_to_zone_id
                .insert(LAN_IFINDEX, TEST_DMZ_ZONE_ID);
            state
        };
        let mut sessions = SessionTable::new();
        let mut binding = binding(LAN_IFINDEX);
        admit_local_pair(&install, &mut sessions, &mut binding, 0, T0_NS);
        let (drops, revokes, forwards, packets, _terminal_purged) = run_ticks(
            &mut sessions,
            &mut binding,
            &live,
            LAN_IFINDEX,
            0,
            true,
            None,
        );
        assert_eq!(drops, 0, "{}/revoke: Revoke lane must not Drop", shape.name);
        assert_eq!(
            forwards, 0,
            "{}/revoke: deny lane must not forward",
            shape.name
        );
        assert!(
            revokes >= 1,
            "{}/revoke: positive Revoke control",
            shape.name
        );
        assert!(
            revokes <= MAX_REVOKES_PER_RENAME,
            "{}/revoke: revokes={revokes}",
            shape.name
        );
        assert!(
            packets <= MAX_REVOKE_TICKS,
            "{}/revoke: ticks={packets}",
            shape.name
        );
        assert_eq!(
            session_count(&sessions),
            0,
            "{}/revoke: terminal immediately",
            shape.name
        );
    }
}

#[test]
fn c3_forward_control_survives_full_window_per_permit_shape_10591() {
    for shape in MATRIX_SHAPES {
        if !shape.permit_control {
            continue;
        }
        let install = matrix_forwarding(true, false, false);
        let live = matrix_forwarding(shape.dmz_permit, shape.dead_egress, shape.default_permit);
        let mut sessions = SessionTable::new();
        let mut binding = binding(LAN_IFINDEX);
        admit_local_pair(&install, &mut sessions, &mut binding, 0, T0_NS);
        let (drops, revokes, forwards, packets, _terminal_purged) = run_ticks(
            &mut sessions,
            &mut binding,
            &live,
            DMZ_IFINDEX,
            0,
            false,
            None,
        );
        assert_eq!(
            packets, OBSERVATION_TICKS,
            "{}/permit: full window",
            shape.name
        );
        assert_eq!(
            forwards, OBSERVATION_TICKS,
            "{}/permit: forward every tick",
            shape.name
        );
        assert_eq!(drops, 0, "{}/permit: no Drop", shape.name);
        assert_eq!(revokes, 0, "{}/permit: no Revoke", shape.name);
        assert_eq!(
            session_count(&sessions),
            2,
            "{}/permit: pair retained",
            shape.name
        );
        let (old, new) = rotation_states(&live);
        let (removed, purged) = production_rotation_purge_for_test(
            &mut sessions,
            &binding,
            &old,
            &new,
            T0_NS + OBSERVATION_TICKS * GC_TICK_NS,
        );
        assert!(
            removed > 0,
            "{}/permit: rename must derive removed zone",
            shape.name
        );
        assert_eq!(
            purged, 0,
            "{}/permit: commit sweep must retain local permit row",
            shape.name
        );
        assert_eq!(
            session_count(&sessions),
            2,
            "{}/permit: pair retained after sweep",
            shape.name
        );
    }
}

#[test]
fn c4_multi_session_drop_bound_attributes_distinct_rows_10591() {
    let shape = MATRIX_SHAPES
        .iter()
        .find(|shape| shape.name == "multi-zone-dead-egress-default-deny")
        .copied()
        .expect("dead-egress deny shape");
    let install = matrix_forwarding(true, false, false);
    let live = matrix_forwarding(shape.dmz_permit, shape.dead_egress, shape.default_permit);
    let mut sessions = SessionTable::new();
    let mut bindings: Vec<BindingWorker> = (0..FIXTURE_SESSION_COUNT)
        .map(|_| binding(LAN_IFINDEX))
        .collect();
    for slot in 0..FIXTURE_SESSION_COUNT as u16 {
        admit_synced_pair(&install, &mut sessions, slot, T0_NS);
    }
    let mut drops = 0;
    let mut affected = BTreeSet::new();
    let (old, new) = rotation_states(&live);
    let mut terminal_tick = 0;
    let mut purged = 0;
    'window: for tick in 1..=OBSERVATION_TICKS {
        let now_ns = T0_NS + tick * GC_TICK_NS;
        for (slot, worker_binding) in bindings.iter_mut().enumerate() {
            let slot = slot as u16;
            let dbg = drive_at(
                worker_binding,
                &mut sessions,
                &live,
                slot_packet(DMZ_IFINDEX, TCP_ACK, slot),
                now_ns,
            );
            assert_eq!(dbg.session_hit, 1, "slot {slot}/tick {tick}: hit");
            drops += dbg.foreign_authority_drops;
            if dbg.foreign_authority_drops > 0 {
                affected.insert(slot);
            }
        }
        let expired = production_sweep_for_test(&mut sessions, &mut bindings, &live, now_ns, None);
        assert!(
            expired.is_empty(),
            "multi-session Drop rows must refresh before purge"
        );
        let (_, tick_purged) =
            production_rotation_purge_for_test(&mut sessions, &bindings[0], &old, &new, now_ns);
        if tick_purged > 0 {
            terminal_tick = tick;
            purged = tick_purged;
            break 'window;
        }
    }
    assert_eq!(terminal_tick, 1, "C4 production rotation terminal tick");
    assert_eq!(
        affected.len(),
        FIXTURE_SESSION_COUNT,
        "C4 distinct attribution"
    );
    assert!(affected.len() <= MAX_SESSIONS_AFFECTED);
    assert!(
        drops <= MAX_TOTAL_DROPS_PER_RENAME,
        "C4 total drops={drops}"
    );
    assert_eq!(
        purged, FIXTURE_SESSION_COUNT,
        "C4 pair attribution at purge"
    );
    assert_eq!(
        session_count(&sessions),
        0,
        "C4 terminal after commit boundary"
    );
}

#[test]
fn c4_worst_case_delayed_purge_bounds_total_drops_10591() {
    // M1 multi-row twin: four distinct synced rows each absorb the full
    // N-tick delay before the single rotation purge. Total drops pin to
    // exactly rows*N; +1 tick or +1 drop REDs the asserts below.
    let shape = MATRIX_SHAPES
        .iter()
        .find(|shape| shape.name == "multi-zone-dead-egress-default-deny")
        .copied()
        .expect("dead-egress deny shape");
    let install = matrix_forwarding(true, false, false);
    let live = matrix_forwarding(shape.dmz_permit, shape.dead_egress, shape.default_permit);
    let mut sessions = SessionTable::new();
    let mut bindings: Vec<BindingWorker> = (0..FIXTURE_SESSION_COUNT)
        .map(|_| binding(LAN_IFINDEX))
        .collect();
    for slot in 0..FIXTURE_SESSION_COUNT as u16 {
        admit_synced_pair(&install, &mut sessions, slot, T0_NS);
    }
    let (old, new) = rotation_states(&live);
    let mut drops = 0;
    let mut affected = BTreeSet::new();
    for tick in 1..=COMMIT_DELAY_TICKS {
        let now_ns = T0_NS + tick * GC_TICK_NS;
        for (slot, worker_binding) in bindings.iter_mut().enumerate() {
            let slot = slot as u16;
            let dbg = drive_at(
                worker_binding,
                &mut sessions,
                &live,
                slot_packet(DMZ_IFINDEX, TCP_ACK, slot),
                now_ns,
            );
            assert_eq!(dbg.session_hit, 1, "slot {slot}/tick {tick}: hit");
            drops += dbg.foreign_authority_drops;
            if dbg.foreign_authority_drops > 0 {
                affected.insert(slot);
            }
        }
        let expired = production_sweep_for_test(&mut sessions, &mut bindings, &live, now_ns, None);
        assert!(expired.is_empty(), "C4/worst: rows must survive the delay");
        for slot in 0..FIXTURE_SESSION_COUNT as u16 {
            assert_eq!(
                row_for_slot(&sessions, slot),
                2,
                "C4/worst: slot {slot} retained"
            );
        }
    }
    assert_eq!(
        affected.len(),
        FIXTURE_SESSION_COUNT,
        "C4/worst: distinct attribution"
    );
    assert_eq!(
        drops,
        FIXTURE_SESSION_COUNT as u64 * COMMIT_DELAY_TICKS,
        "C4/worst: one Drop per row per delay tick"
    );
    assert!(
        drops <= MAX_TOTAL_DROPS_WORST_CASE,
        "C4/worst: total drops={drops}"
    );
    assert!(
        drops <= MAX_TOTAL_DROPS_PER_RENAME,
        "C4/worst: total under loose ceiling"
    );
    let purge_ns = T0_NS + COMMIT_DELAY_TICKS * GC_TICK_NS;
    let (removed, purged) =
        production_rotation_purge_for_test(&mut sessions, &bindings[0], &old, &new, purge_ns);
    assert!(removed > 0, "C4/worst: rename set must be non-empty");
    assert_eq!(
        purged, FIXTURE_SESSION_COUNT,
        "C4/worst: pair attribution at purge"
    );
    assert_eq!(
        session_count(&sessions),
        0,
        "C4/worst: terminal after purge"
    );
}

#[test]
fn c5_last_seen_and_policy_id_persist_until_commit_sweep_10591() {
    let install = matrix_forwarding(true, false, false);
    let live = matrix_forwarding(false, false, false);
    let mut sessions = SessionTable::new();
    let mut binding = binding(LAN_IFINDEX);
    admit_synced_pair(&install, &mut sessions, 0, T0_NS);
    let mut previous_idle = None;
    let mut policy_id = None;
    for tick in 1..=OBSERVATION_TICKS {
        let now_ns = T0_NS + tick * GC_TICK_NS;
        let before = matrix_forward_observation(&sessions);
        let dbg = drive_at(
            &mut binding,
            &mut sessions,
            &live,
            matrix_packet(DMZ_IFINDEX, TCP_ACK),
            now_ns,
        );
        assert_eq!(
            dbg.foreign_authority_drops, 1,
            "C5 Drop control at tick {tick}"
        );
        let after = matrix_forward_observation(&sessions);
        assert!(
            after.0 < before.0,
            "C5 last_seen must refresh at tick {tick}"
        );
        if let Some(id) = policy_id {
            assert_eq!(after.1, id, "C5 policy id changed at tick {tick}");
        } else {
            policy_id = Some(after.1);
        }
        if let Some(idle) = previous_idle {
            assert!(
                after.0 < idle,
                "C5 idle must strictly decrease at tick {tick}"
            );
        }
        previous_idle = Some(after.0);
        let expired = production_sweep_for_test(
            &mut sessions,
            std::slice::from_mut(&mut binding),
            &live,
            now_ns,
            None,
        );
        assert!(
            expired.is_empty(),
            "C5 active Drop row must not idle-expire"
        );
    }
    assert_eq!(
        row_for_slot(&sessions, 0),
        2,
        "C5 row persists until commit sweep"
    );
    let (old, new) = rotation_states(&live);
    let (_removed, purged) = production_rotation_purge_for_test(
        &mut sessions,
        &binding,
        &old,
        &new,
        T0_NS + OBSERVATION_TICKS * GC_TICK_NS,
    );
    assert_eq!(purged, 1, "C5 commit sweep must terminate the forward row");
    assert_eq!(session_count(&sessions), 0, "C5 terminal after sweep");
}

#[test]
fn c6_sweep_wiring_requires_real_expire_reap_and_clock_10591() {
    let install = matrix_forwarding(true, false, false);
    let mut sessions = SessionTable::new();
    let mut binding = binding(LAN_IFINDEX);
    admit_local_pair(&install, &mut sessions, &mut binding, 0, T0_NS);
    // A real RST hit moves both halves to the production 2s RST-close window
    // (`session/mod.rs:127`); this is the canary that a direct row-count
    // assertion cannot provide.
    let rst = drive_at(
        &mut binding,
        &mut sessions,
        &install,
        matrix_packet(LAN_IFINDEX, TCP_RST | TCP_ACK),
        T0_NS + 1,
    );
    assert_eq!(rst.session_hit, 1, "C6 RST canary must hit the pair");
    assert_eq!(row_for_slot(&sessions, 0), 2);
    let (cache_key, cache_decision, cache_metadata) = forward_record(&sessions);
    cache_seed(&mut binding, &cache_key, cache_decision, cache_metadata);
    assert!(
        cache_hits(&mut binding, &cache_key),
        "C6 precondition: the RST row's cached descriptor must hit before the sweep"
    );
    let early = production_sweep_for_test(
        &mut sessions,
        std::slice::from_mut(&mut binding),
        &install,
        T0_NS + 1,
        None,
    );
    assert!(early.is_empty(), "C6: pre-timeout sweep must be gated");
    let expired = production_sweep_for_test(
        &mut sessions,
        std::slice::from_mut(&mut binding),
        &install,
        T0_NS + 4 * GC_TICK_NS + 1,
        None,
    );
    assert!(
        !expired.is_empty(),
        "C6: real expire path must classify the RST canary"
    );
    assert_eq!(
        row_for_slot(&sessions, 0),
        0,
        "C6: real sweep must remove both halves"
    );
    assert!(
        !cache_hits(&mut binding, &cache_key),
        "C6: reap must evict the reaped flow-cache descriptor; expire-only is not enough"
    );
}

#[test]
fn c6_expire_ha_context_covers_hold_and_self_heal_10591() {
    let hold_forwards = |_rg: i32| false;
    let hold_epoch = |_rg: i32| 0;
    let hold = crate::session::ExpireHaContext {
        node_active: false,
        forwards_rg: &hold_forwards,
        epoch_of: &hold_epoch,
        ceiling_mult: crate::session::STALE_SYNCED_CEILING_MULT,
        ceiling_abs_ns: crate::session::STALE_SYNCED_CEILING_ABS_NS,
    };
    let self_heal_forwards = |_rg: i32| true;
    let self_heal_epoch = |_rg: i32| 1;
    let self_heal = crate::session::ExpireHaContext {
        node_active: true,
        forwards_rg: &self_heal_forwards,
        epoch_of: &self_heal_epoch,
        ceiling_mult: crate::session::STALE_SYNCED_CEILING_MULT,
        ceiling_abs_ns: crate::session::STALE_SYNCED_CEILING_ABS_NS,
    };
    let install = matrix_forwarding(true, false, false);
    let mut sessions = SessionTable::new();
    let mut binding = binding(LAN_IFINDEX);
    admit_synced_pair(&install, &mut sessions, 0, T0_NS);
    let (forward_key, _decision, _metadata) = forward_record(&sessions);
    // A standard established TCP row expires after the production 300s
    // timeout (`session/mod.rs:104`). The first idle-crossed pass is a
    // genuine standby HOLD.
    let hold_now = T0_NS + 301 * GC_TICK_NS;
    let held = production_sweep_for_test(
        &mut sessions,
        std::slice::from_mut(&mut binding),
        &install,
        hold_now,
        Some(&hold),
    );
    assert!(held.is_empty(), "HOLD must retain the peer-synced row");
    assert_eq!(
        row_for_slot(&sessions, 0),
        2,
        "HOLD must retain both halves"
    );
    assert!(
        sessions.first_held_ns_for(&forward_key).unwrap_or(0) > 0,
        "HOLD must arm the first-held ceiling clock"
    );
    // The next real wheel tick observes the activation edge: the same synced
    // row now forwards and the epoch changed, so SELF-HEAL re-stamps it once.
    let healed = production_sweep_for_test(
        &mut sessions,
        std::slice::from_mut(&mut binding),
        &install,
        hold_now + GC_TICK_NS,
        Some(&self_heal),
    );
    assert!(
        healed.is_empty(),
        "SELF-HEAL must retain and re-bucket the row"
    );
    assert_eq!(
        row_for_slot(&sessions, 0),
        2,
        "SELF-HEAL must retain both halves"
    );
    let (idle, _policy_id) = forward_observation_at(&sessions, hold_now + GC_TICK_NS);
    assert!(
        idle < 2 * GC_TICK_NS,
        "SELF-HEAL must re-stamp last_seen at activation"
    );
}

#[test]
fn c6_worker_loop_wiring_orders_expire_before_reap_10591() {
    // Bounded to `worker_loop`'s body: from its definition through the next
    // top-level `fn` (`retire_expired_missing_neighbor_seeds`). Excludes the
    // `fn reap_expired_sessions` definition and the
    // `production_sweep_for_test` seam below, so only the production call
    // pair inside the loop can satisfy this guard.
    let source = include_str!("worker/loop_body/mod.rs");
    let body_start = source
        .find("pub(crate) fn worker_loop(")
        .expect("worker loop definition must exist");
    let body_end = source[body_start..]
        .find("\nfn retire_expired_missing_neighbor_seeds(")
        .map(|offset| body_start + offset)
        .expect("worker loop body must end at the next fn");
    let body = &source[body_start..body_end];
    let expire_matches: Vec<_> = body
        .match_indices("sessions.expire_stale_entries_ha(loop_now_ns")
        .collect();
    assert_eq!(
        expire_matches.len(),
        1,
        "worker loop body must contain exactly one production expiry call"
    );
    let reap_matches: Vec<_> = body.match_indices("reap_expired_sessions(").collect();
    assert_eq!(
        reap_matches.len(),
        1,
        "worker loop body must contain exactly one production reap call"
    );
    assert!(
        reap_matches[0].0 > expire_matches[0].0,
        "production sweep order must be expire then reap"
    );
}

// C7's Rust-side cadence citation is a compile-time/test-time invariant: the
// loose ceiling is an integral number of real wheel ticks, never a fake
// sub-tick delay. The Go test owns the arm→apply→sweep ordering boundary.
#[test]
fn c7_window_delay_is_an_integral_gc_wheel_bound_10591() {
    assert_eq!(GC_TICK_NS, SESSION_GC_INTERVAL_NS_FOR_TEST);
    assert_eq!(GC_TICK_NS, WHEEL_TICK_NS_FOR_TEST);
    assert_eq!(PRODUCTION_BOUND_TICKS, WHEEL_BUCKETS_FOR_TEST as u64 + 1);
    assert_eq!(OBSERVATION_TICKS, PRODUCTION_BOUND_TICKS);
    assert_eq!(
        MAX_DROPS_PER_RENAME_SINGLE_ZONE_DEFAULT_DENY,
        PRODUCTION_BOUND_TICKS * WINDOW_PPS
    );
    assert_eq!(MAX_DROPS_PER_RENAME_SINGLE_ZONE_DEFAULT_DENY, 257);
    assert_eq!(MAX_DROPS_PER_RENAME_DEAD_EGRESS_DEFAULT_DENY, 257);
}
