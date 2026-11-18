// #19173 fold (r24 P3-1) MEASUREMENT: flow-cache churn caused by periodic
// IDENTICAL re-imports of the rows that back cached flows.
//
// 5c7154090a minted a new install epoch on every replacement, so each
// identical re-import (primary liveness, every 1-10 s per live session; an
// `UpsertLocal` refresh) evicted every cached flow it backed once per
// interval, and the next packet paid a full slow-path revalidation. The fold
// carries the epoch across an identical re-import. This file counts, per
// re-import round, the cached flows that stop hitting.
//
// It uses no API the fix introduced, so it compiles unchanged on ebb32e817b
// (master), 5c7154090a and the fold; the numbers go in docs/log/19173.md.
// Every packet goes through the production poll function and every
// re-import through the production worker-command dispatcher.
//
// Shapes:
// - split_rg: fw1 of the captured loss-cluster split snapshot holds the LAN
//   RG and not the WAN RG. N established SNAT flows imported from the WAN
//   owner (`SyncImport` pairs); every LAN packet is fabric-redirected and
//   the redirect is cached. Each round re-imports every pair as a
//   primary-liveness frame (`SyncLiveness`, same wire id, same content).
// - upsert_local: N cache-backed rows refreshed through `UpsertLocal` with no
//   wire session id (the local-tunnel refresh shape). Production TUN-origin
//   rows back no cache entry (their forward leg leaves through the tunnel TX
//   plan, never the RX poll; their reverse leg is LocalDelivery, which is not
//   cacheable), so this shape measures the UpsertLocal mechanism on rows
//   that do back cached flows.
#![allow(unused_imports)]

use super::test_fixtures::*;
use super::tests_split_rg_failback_18531::{
    Family, LAN, LAN_HOST, LAN_IFINDEX as SPLIT_LAN_IFINDEX, TCP_ACK, WAN_HOST, DPORT, SPORT,
    apply_commands, bindings, exported_forward, fw1_owner_forwarding, split_ha,
};
use super::tests_support::*;
use super::*;
use crate::afxdp::flow_cache::FlowCacheEvictionArm as Arm;
use crate::session::{SessionKey, SessionOrigin, SessionTable};
use crate::test_zone_ids::*;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

const FLOWS: u16 = 64;
const ROUNDS: usize = 5;

/// Per-round tallies on the ingress binding's flow cache.
#[derive(Debug, Default, Clone, Copy)]
struct Round {
    packets: u64,
    hits: u64,
    no_record_evictions: u64,
    evictions: u64,
}

fn tallies(cache: &FlowCache) -> (u64, u64, u64) {
    (
        cache.hits,
        cache.evictions_by_arm[Arm::PostHitSessionDeadNoRecord as usize],
        cache.evictions_by_arm.iter().sum::<u64>(),
    )
}

fn report(shape: &str, control: Round, rounds: &[Round]) {
    let total: u64 = rounds.iter().map(|r| r.no_record_evictions).sum();
    let per_round: Vec<String> = rounds
        .iter()
        .map(|r| format!("{}/{}/{}", r.hits, r.packets, r.no_record_evictions))
        .collect();
    eprintln!(
        "#19173-churn shape={shape} flows={FLOWS} rounds={} control_hits={}/{} \
         control_no_record={} per_round(hits/packets/no_record)=[{}] \
         no_record_per_round={:.1} all_arm_evictions={}",
        rounds.len(),
        control.hits,
        control.packets,
        control.no_record_evictions,
        per_round.join(" "),
        total as f64 / rounds.len() as f64,
        rounds.iter().map(|r| r.evictions).sum::<u64>(),
    );
}

// ---------------------------------------------------------------------------
// split_rg
// ---------------------------------------------------------------------------

fn split_forward(forwarding: &ForwardingState, i: u16) -> SyncedSessionEntry {
    let mut entry = exported_forward(forwarding, Family::V4);
    entry.key.src_port = SPORT + i;
    entry.session_id = (1u64 << 48) | (19173 << 8) | u64::from(i);
    entry
}

fn split_pair(
    forwarding: &ForwardingState,
    ha: &BTreeMap<i32, HAGroupRuntime>,
    i: u16,
    origin: SessionOrigin,
) -> [SyncedSessionEntry; 2] {
    let mut forward = split_forward(forwarding, i);
    // A liveness frame's reverse is synthesized from the liveness forward,
    // as the coordinator does (`synthesized_synced_reverse_entry` keeps
    // `SyncLiveness`).
    forward.origin = origin;
    let reverse = crate::afxdp::shared_ops::synthesized_synced_reverse_entry(
        forwarding,
        ha,
        &Arc::new(ShardedNeighborMap::default()),
        &forward,
        monotonic_nanos() / 1_000_000_000,
    )
    .expect("production reverse synthesis");
    [forward, reverse]
}

fn split_lan_ack(
    bindings: &mut Vec<BindingWorker>,
    sessions: &mut SessionTable,
    forwarding: &ForwardingState,
    ha: &BTreeMap<i32, HAGroupRuntime>,
    i: u16,
) -> u64 {
    let sport = SPORT + i;
    let frame = build_txn_tcp_syn_frame_v4(
        LAN_HOST,
        WAN_HOST,
        sport,
        DPORT,
        TCP_ACK,
        [0x02, 0xbf, 0x72, 0x16, 0x02, 0x03],
    );
    let mut meta = txn_meta_v4(SPLIT_LAN_IFINDEX as u32, TCP_ACK, frame.len() as u16);
    meta.flow_src_addr[..4].copy_from_slice(&LAN_HOST.octets());
    meta.flow_dst_addr[..4].copy_from_slice(&WAN_HOST.octets());
    meta.flow_src_port = sport;
    meta.flow_dst_port = DPORT;
    let shared = Arc::new(Mutex::new(FastMap::default()));
    let (_batch, dbg, _egress) = txn_run_multi_binding_at_generations(
        bindings, LAN, sessions, forwarding, ha, &frame, meta, &shared, 7, 0,
    );
    assert_eq!(dbg.rx, 1, "anti-vacuity: the descriptor reached the poll body");
    bindings[super::tests_split_rg_failback_18531::FABRIC]
        .live
        .tx_packets
        .load(std::sync::atomic::Ordering::Relaxed)
}

#[test]
#[ignore = "MEASUREMENT: #19173 re-import churn, split-RG non-owner; prints only"]
fn reimport_churn_split_rg_19173() {
    let forwarding = fw1_owner_forwarding();
    let ha = split_ha(monotonic_nanos() / 1_000_000_000);
    let mut sessions = SessionTable::new();
    sessions.set_forwarding_revalidation_gen(7, 9);
    let mut commands = Vec::new();
    for i in 0..FLOWS {
        commands.extend(split_pair(&forwarding, &ha, i, SessionOrigin::SyncImport));
    }
    apply_commands(
        &mut sessions,
        &forwarding,
        &ha,
        commands.into_iter().map(WorkerCommand::UpsertSynced).collect(),
    );
    assert_eq!(sessions.len(), 2 * FLOWS as usize, "fixture: every pair imported");
    let mut bindings = bindings();
    // Seed: the first LAN packet of each flow is fabric-redirected (TX on the
    // fabric binding) and seeds the cache.
    let mut fabric_tx = 0;
    for i in 0..FLOWS {
        let tx = split_lan_ack(&mut bindings, &mut sessions, &forwarding, &ha, i);
        assert!(tx > fabric_tx, "premise: flow {i} is fabric-redirected");
        fabric_tx = tx;
    }
    let run_round = |sessions: &mut SessionTable, bindings: &mut Vec<BindingWorker>| {
        let (hits0, nr0, ev0) = tallies(&bindings[LAN].flow.flow_cache);
        for i in 0..FLOWS {
            split_lan_ack(bindings, sessions, &forwarding, &ha, i);
        }
        let (hits1, nr1, ev1) = tallies(&bindings[LAN].flow.flow_cache);
        Round {
            packets: u64::from(FLOWS),
            hits: hits1 - hits0,
            no_record_evictions: nr1 - nr0,
            evictions: ev1 - ev0,
        }
    };
    // Control: no re-import, every flow is served from the cache.
    let control = run_round(&mut sessions, &mut bindings);
    assert_eq!(control.hits, u64::from(FLOWS), "premise: steady state is cache-served: {control:?}");
    let mut rounds = Vec::new();
    for _ in 0..ROUNDS {
        let mut liveness = Vec::new();
        for i in 0..FLOWS {
            liveness.extend(split_pair(&forwarding, &ha, i, SessionOrigin::SyncLiveness));
        }
        apply_commands(
            &mut sessions,
            &forwarding,
            &ha,
            liveness.into_iter().map(WorkerCommand::UpsertSynced).collect(),
        );
        assert_eq!(sessions.len(), 2 * FLOWS as usize, "re-import keeps every pair");
        rounds.push(run_round(&mut sessions, &mut bindings));
    }
    report("split_rg", control, &rounds);
}

// ---------------------------------------------------------------------------
// upsert_local
// ---------------------------------------------------------------------------

const CLIENT: Ipv4Addr = Ipv4Addr::new(10, 0, 61, 102);
const SERVER: Ipv4Addr = Ipv4Addr::new(8, 8, 8, 8);
const CLIENT_PORT: u16 = 41_000;
const SERVER_PORT: u16 = 443;
/// `nat_snapshot`'s LAN unit (reth1.0); its main table forwards SERVER out
/// reth0.80.
const LOCAL_LAN_IFINDEX: u32 = 24;

fn local_key(i: u16) -> SessionKey {
    SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        src_ip: IpAddr::V4(CLIENT),
        dst_ip: IpAddr::V4(SERVER),
        src_port: CLIENT_PORT + i,
        dst_port: SERVER_PORT,
        discriminator: Default::default(),
        routing_domain: 0,
    }
}

fn local_send(
    binding: &mut BindingWorker,
    sessions: &mut SessionTable,
    forwarding: &ForwardingState,
    now_ns: u64,
    i: u16,
) {
    let frame = build_txn_tcp_syn_frame_v4(
        CLIENT,
        SERVER,
        CLIENT_PORT + i,
        SERVER_PORT,
        0x10,
        TEST_LAN_MAC,
    );
    let meta = txn_meta_v4(LOCAL_LAN_IFINDEX, 0x10, frame.len() as u16);
    binding.scratch.scratch_forwards.clear();
    binding.tx_pipeline.pending_tx_prepared.clear();
    let (_batch, dbg) =
        txn_run_descriptor_at(binding, sessions, forwarding, &txn_ha_state(), &frame, meta, now_ns);
    assert_eq!(dbg.rx, 1, "anti-vacuity: the segment reached the poll body");
}

fn local_apply(sessions: &mut SessionTable, forwarding: &ForwardingState, commands: Vec<WorkerCommand>) {
    let queue = Arc::new(Mutex::new(VecDeque::from(commands)));
    crate::afxdp::session_glue::apply_worker_commands(
        &queue,
        sessions,
        crate::afxdp::bpf_map::SteeringMap::unshared_for_test(-1),
        -1,
        -1,
        forwarding,
        &restamped_ha_state(&txn_ha_state(), monotonic_nanos()),
        &Arc::new(ShardedNeighborMap::new()),
        0,
        &mut VecDeque::new(),
    );
}

#[test]
#[ignore = "MEASUREMENT: #19173 re-import churn, UpsertLocal refresh; prints only"]
fn reimport_churn_upsert_local_19173() {
    let forwarding = build_forwarding_state(&nat_snapshot());
    let mut sessions = SessionTable::new();
    sessions.set_forwarding_revalidation_gen(7, 9);
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, LOCAL_LAN_IFINDEX as i32, 0);
    binding.interface = Arc::<str>::from("reth1.0");
    let mut now_ns = monotonic_nanos();
    for i in 0..FLOWS {
        let key = local_key(i);
        let flow = SessionFlow {
            src_ip: key.src_ip,
            dst_ip: key.dst_ip,
            forward_key: key.clone(),
        };
        let decision = SessionDecision {
            resolution: crate::afxdp::session_glue::lookup_forwarding_resolution_for_session_without_cache(
                &forwarding,
                &Arc::new(ShardedNeighborMap::new()),
                &flow,
                SessionDecision {
                    resolution: ForwardingResolution {
                        disposition: ForwardingDisposition::NoRoute,
                        local_ifindex: 0,
                        egress_ifindex: 0,
                        tx_ifindex: 0,
                        tunnel_endpoint_id: 0,
                        next_hop: None,
                        neighbor_mac: None,
                        src_mac: None,
                        tx_vlan_id: 0,
                        source_ifindex: 0,
                        route_mtu: 0,
                        transport_route_mtu: 0,
                    },
                    nat: NatDecision::default(),
                    install_table_domain: 0,
                    install_table_check: 0,
                },
            )
            .resolution,
            nat: NatDecision::default(),
            install_table_domain: 0,
            install_table_check: 0,
        };
        assert_eq!(
            decision.resolution.disposition,
            ForwardingDisposition::ForwardCandidate,
            "premise: the main table forwards flow {i}"
        );
        let metadata = crate::session::SessionMetadata {
            forward_wire_alias_origin: false,
            ingress_zone: TEST_LAN_ZONE_ID,
            egress_zone: TEST_WAN_ZONE_ID,
            ingress_zone_check: 0,
            egress_zone_check: 0,
            ingress_ifindex: LOCAL_LAN_IFINDEX,
            ingress_vlan_id: 0,
            forward_ingress_vlan_id: None,
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
            nat_scope_ifindex: None,
        };
        assert!(sessions.install_with_protocol_with_origin(
            key,
            decision,
            metadata,
            SessionOrigin::WorkerLocalImport,
            now_ns,
            PROTO_TCP,
            0x10,
        ));
    }
    // Seed: first segment per flow takes the slow path and seeds.
    for i in 0..FLOWS {
        now_ns += 1_000_000;
        local_send(&mut binding, &mut sessions, &forwarding, now_ns, i);
    }
    let run_round = |binding: &mut BindingWorker, sessions: &mut SessionTable, now_ns: &mut u64| {
        let (hits0, nr0, ev0) = tallies(&binding.flow.flow_cache);
        for i in 0..FLOWS {
            *now_ns += 1_000_000;
            local_send(binding, sessions, &forwarding, *now_ns, i);
        }
        let (hits1, nr1, ev1) = tallies(&binding.flow.flow_cache);
        Round {
            packets: u64::from(FLOWS),
            hits: hits1 - hits0,
            no_record_evictions: nr1 - nr0,
            evictions: ev1 - ev0,
        }
    };
    let control = run_round(&mut binding, &mut sessions, &mut now_ns);
    assert_eq!(control.hits, u64::from(FLOWS), "premise: steady state is cache-served: {control:?}");
    let mut rounds = Vec::new();
    for _ in 0..ROUNDS {
        let refresh: Vec<WorkerCommand> = (0..FLOWS)
            .map(|i| {
                let mut entry = sessions.synced_entry_for(&local_key(i)).expect("row");
                // The local-tunnel refresh carries no wire session id.
                entry.session_id = 0;
                WorkerCommand::UpsertLocal(entry)
            })
            .collect();
        local_apply(&mut sessions, &forwarding, refresh);
        assert_eq!(sessions.len(), FLOWS as usize, "refresh keeps every row");
        rounds.push(run_round(&mut binding, &mut sessions, &mut now_ns));
    }
    report("upsert_local", control, &rounds);
}
