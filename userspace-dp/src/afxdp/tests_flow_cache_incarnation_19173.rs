// #19173: a same-key in-place session replacement must not leave a flow-cache
// slot serving the decision seeded from the OLD row.
//
// Shape (issue #19173 "Repro sketch"): the destination routes via E1 in the
// main table and via E2 in routing-instance table T. Row A for key K is a
// non-promotable `WorkerLocalImport` replica with the default installing
// table, so the slow path forwards K via E1 and seeds the cache with that.
// `UpsertSynced(B)` (or `UpsertLocal(B)`) then replaces A under the same key
// and the same (absent) NAT, but B carries T's installing-table stamp, so
// the worker row now resolves via E2. Nothing a cache hit validates moves:
// the config and FIB generations, the RG epochs and leases, the neighbor
// shard epochs and the live HA verdict on the cached decision are all
// unchanged. Before the fix the next packet hit the cache and left via E1.
//
// What the slow path does with row B on THIS node is not "forward via E2":
// B arrives with an unvalidated filter stamp, so its first slow-path hit runs
// the #7212/#10467 route revalidation, which re-derives the installing table
// from this node's own ingress filter (none here, so the default table) and
// revokes a forward row whose stamp disagrees. Before the fix the cache hid
// that verdict and kept forwarding the replaced flow via E1. The red cells
// assert the slow path's verdict (no E1 forward, one filter revocation).
// The revalidation also bounds what an accepted replacement can do on this
// path: it accepts B only if B's table is this node's choice, and row A was
// accepted only under the same rule, so an accepted replacement resolves
// the egress A did (the identical re-import control below).
//
// Every cell here drives the production poll function
// (`poll_binding_process_descriptor`) for the packets and the production
// worker-command dispatcher (`apply_worker_commands`) for the replacement,
// and uses no API the fix introduced, so this file compiles unchanged on the
// pre-fix tree. That is how the red was taken (docs/log/19173.md).
#![allow(unused_imports)]

use super::test_fixtures::*;
use super::tests_support::*;
use super::*;
use crate::session::{SessionKey, SessionMetadata, SessionOrigin, SessionTable};
use crate::test_zone_ids::*;
use crate::{InterfaceAddressSnapshot, InterfaceSnapshot, NeighborSnapshot, RouteSnapshot};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

const CLIENT: Ipv4Addr = Ipv4Addr::new(10, 0, 61, 102);
const SERVER: Ipv4Addr = Ipv4Addr::new(8, 8, 8, 8);
const CLIENT_PORT: u16 = 40_173;
const SERVER_PORT: u16 = 443;
/// The LAN ingress unit (`reth1.0`) of `nat_snapshot`.
pub(super) const LAN_IFINDEX: u32 = 24;
/// E1: `reth0.80`, the main table's default route via 172.16.80.1.
pub(super) const E1: i32 = 12;
/// E2: `reth0.50`, added here, the egress of table T's route to SERVER.
pub(super) const E2: i32 = 13;
const E2_GATEWAY: Ipv4Addr = Ipv4Addr::new(172, 16, 50, 1);
const E2_GATEWAY_MAC: [u8; 6] = [0x00, 0x19, 0x17, 0x30, 0x00, 0x02];
/// Routing-instance name whose `inet.0` is table T.
const TABLE_T_INSTANCE: &str = "t19173";

pub(super) fn key() -> SessionKey {
    SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        src_ip: IpAddr::V4(CLIENT),
        dst_ip: IpAddr::V4(SERVER),
        src_port: CLIENT_PORT,
        dst_port: SERVER_PORT,
        discriminator: Default::default(),
        routing_domain: 0,
    }
}

fn forward_metadata() -> SessionMetadata {
    SessionMetadata {
        forward_wire_alias_origin: false,
        ingress_zone: TEST_LAN_ZONE_ID,
        egress_zone: TEST_WAN_ZONE_ID,
        ingress_zone_check: 0,
        egress_zone_check: 0,
        ingress_ifindex: LAN_IFINDEX,
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
    }
}

/// `nat_snapshot` plus E2 (`reth0.50`, RG1, zone `wan`, like E1) and table
/// T's route to SERVER via E2's gateway. The main table keeps its default
/// via E1, so the installing-table stamp alone selects the egress.
fn forwarding() -> ForwardingState {
    let mut snapshot = nat_snapshot();
    snapshot.interfaces.push(InterfaceSnapshot {
        name: "reth0.50".to_string(),
        zone: "wan".to_string(),
        // A member of the instance, so its connected /24 (the gateway's
        // subnet) is in table T, where T's route resolves its next hop.
        routing_instance: TABLE_T_INSTANCE.to_string(),
        linux_name: "ge-0-0-0.50".to_string(),
        ifindex: E2,
        parent_ifindex: 11,
        redundancy_group: 1,
        vlan_id: 50,
        hardware_addr: "02:bf:72:00:50:08".to_string(),
        addresses: vec![InterfaceAddressSnapshot {
            family: "inet".to_string(),
            address: "172.16.50.8/24".to_string(),
            scope: 0,
            ..Default::default()
        }],
        ..Default::default()
    });
    snapshot.routes.push(RouteSnapshot {
        table: format!("{TABLE_T_INSTANCE}.inet.0"),
        family: "inet".to_string(),
        destination: "8.8.8.0/24".to_string(),
        next_hops: vec![format!("{E2_GATEWAY}@reth0.50")],
        ..Default::default()
    });
    snapshot.neighbors.push(NeighborSnapshot {
        interface: "ge-0-0-0.50".to_string(),
        ifindex: E2,
        family: "inet".to_string(),
        ip: E2_GATEWAY.to_string(),
        mac: "00:19:17:30:00:02".to_string(),
        state: "reachable".to_string(),
        router: true,
        link_local: false,
        ..Default::default()
    });
    let mut forwarding = build_forwarding_state(&snapshot);
    let (domain, check) = table_t_stamp();
    forwarding.install_tables.insert(
        domain,
        crate::afxdp::types::InstallTables {
            v4: Some(format!("{TABLE_T_INSTANCE}.inet.0")),
            v6: None,
            h2: check,
        },
    );
    forwarding
}

/// `(install_table_domain, install_table_check)` naming table T.
fn table_t_stamp() -> (u32, u32) {
    crate::session::install_table_identity(TABLE_T_INSTANCE)
}

/// The live FIB's answer for K under the installing-table stamp `stamp`.
fn resolve(forwarding: &ForwardingState, stamp: (u32, u32)) -> ForwardingResolution {
    let flow = SessionFlow {
        src_ip: IpAddr::V4(CLIENT),
        dst_ip: IpAddr::V4(SERVER),
        forward_key: key(),
    };
    let decision = SessionDecision {
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
        install_table_domain: stamp.0,
        install_table_check: stamp.1,
    };
    crate::afxdp::session_glue::lookup_forwarding_resolution_for_session_without_cache(
        forwarding,
        &Arc::new(ShardedNeighborMap::new()),
        &flow,
        decision,
    )
    .resolution
}

/// One LAN -> SERVER TCP segment: a pure ACK, or a PSH+ACK carrying
/// `payload` bytes (IPv4 total length and header checksum fixed up).
fn segment(payload: usize) -> (Vec<u8>, UserspaceDpMeta) {
    let flags = if payload == 0 { 0x10 } else { 0x18 };
    let mut frame = build_txn_tcp_syn_frame_v4(
        CLIENT,
        SERVER,
        CLIENT_PORT,
        SERVER_PORT,
        flags,
        TEST_LAN_MAC,
    );
    if payload > 0 {
        frame.extend(std::iter::repeat_n(0x5a, payload));
        let total = (frame.len() - 14) as u16;
        frame[16..18].copy_from_slice(&total.to_be_bytes());
        frame[24..26].copy_from_slice(&[0, 0]);
        let sum = checksum16(&frame[14..34]);
        frame[24..26].copy_from_slice(&sum.to_be_bytes());
    }
    let meta = txn_meta_v4(LAN_IFINDEX, flags, frame.len() as u16);
    (frame, meta)
}

/// What one packet did: whether the flow cache served it, and the egress of
/// the forward it queued (`None` if it queued none).
#[derive(Debug, PartialEq, Eq)]
pub(super) struct Sent {
    pub(super) cache_hit: bool,
    pub(super) egress: Option<i32>,
}

pub(super) struct Fixture {
    pub(super) forwarding: ForwardingState,
    pub(super) binding: BindingWorker,
    pub(super) sessions: SessionTable,
    pub(super) now_ns: u64,
    /// `filter_revoked_sessions` of the last segment: the #7212 route
    /// revalidation revoked the row it hit.
    last_filter_revoked: u64,
}

impl Fixture {
    /// Row A: K as a non-promotable `WorkerLocalImport` replica, default
    /// installing table, stored resolution = the live main-table answer
    /// (E1). Times are on the monotonic clock because the worker-command
    /// dispatcher samples it for the replacement's row.
    fn with_row_a() -> Self {
        let forwarding = forwarding();
        let via_e1 = resolve(&forwarding, (0, 0));
        let via_e2 = resolve(&forwarding, table_t_stamp());
        assert_eq!(
            (via_e1.disposition, via_e1.egress_ifindex),
            (ForwardingDisposition::ForwardCandidate, E1),
            "premise: the main table forwards K via E1: {via_e1:?}"
        );
        assert_eq!(
            (via_e2.disposition, via_e2.egress_ifindex, via_e2.neighbor_mac),
            (ForwardingDisposition::ForwardCandidate, E2, Some(E2_GATEWAY_MAC)),
            "premise: table T forwards K via E2: {via_e2:?}"
        );
        let mut binding = BindingWorker::new_for_mirror_test(0, 0, LAN_IFINDEX as i32, 0);
        binding.interface = Arc::<str>::from("reth1.0");
        let mut sessions = SessionTable::new();
        sessions.set_forwarding_revalidation_gen(7, 9);
        let now_ns = monotonic_nanos();
        assert!(sessions.install_with_protocol_with_origin(
            key(),
            SessionDecision {
                resolution: via_e1,
                nat: NatDecision::default(),
                install_table_domain: 0,
                install_table_check: 0,
            },
            forward_metadata(),
            SessionOrigin::WorkerLocalImport,
            now_ns,
            PROTO_TCP,
            0x10,
        ));
        Self {
            forwarding,
            binding,
            sessions,
            now_ns,
            last_filter_revoked: 0,
        }
    }

    /// Push one segment through the production poll function.
    pub(super) fn send(&mut self, payload: usize) -> Sent {
        self.now_ns += 1_000_000;
        self.binding.scratch.scratch_forwards.clear();
        self.binding.tx_pipeline.pending_tx_prepared.clear();
        let hits_before = self.binding.flow.flow_cache.hits;
        let (frame, meta) = segment(payload);
        let (_batch, dbg) = txn_run_descriptor_at(
            &mut self.binding,
            &mut self.sessions,
            &self.forwarding,
            &txn_ha_state(),
            &frame,
            meta,
            self.now_ns,
        );
        assert_eq!(dbg.rx, 1, "anti-vacuity: the segment reached the poll body");
        // Shown only when a cell fails: the slow-path verdict counters.
        eprintln!(
            "#19173 segment: session_hit={} session_miss={} no_route={} missing_neigh={} \
             policy_deny={} filter_revoked={} policy_revoked={} snat_revoked={} \
             foreign_drop={} ha_inactive={} no_egress_binding={} build_fail={} \
             disposition_other={} local={} forward={} evictions_by_arm={:?}",
            dbg.session_hit,
            dbg.session_miss,
            dbg.no_route,
            dbg.missing_neigh,
            dbg.policy_deny,
            dbg.filter_revoked_sessions,
            dbg.policy_revoked_sessions,
            dbg.snat_revoked_sessions,
            dbg.foreign_authority_drops,
            dbg.ha_inactive,
            dbg.no_egress_binding,
            dbg.build_fail,
            dbg.disposition_other,
            dbg.local,
            dbg.forward,
            self.binding.flow.flow_cache.evictions_by_arm,
        );
        self.last_filter_revoked = dbg.filter_revoked_sessions;
        let egress = self
            .binding
            .scratch
            .scratch_forwards
            .last()
            .map(|request| request.decision.resolution.egress_ifindex)
            .or_else(|| {
                self.binding
                    .tx_pipeline
                    .pending_tx_prepared
                    .back()
                    .map(|prepared| prepared.egress_ifindex)
            });
        Sent {
            cache_hit: self.binding.flow.flow_cache.hits > hits_before,
            egress,
        }
    }

    /// Row B: row A's own wire entry, re-stamped and re-identified.
    fn replacement(&self, stamp: (u32, u32), session_id: u64) -> SyncedSessionEntry {
        let mut entry = self
            .sessions
            .synced_entry_for(&key())
            .expect("fixture: row A present");
        entry.decision.install_table_domain = stamp.0;
        entry.decision.install_table_check = stamp.1;
        entry.session_id = session_id;
        entry
    }

    pub(super) fn row_a_session_id(&self) -> u64 {
        self.sessions.session_id_for(&key())
    }

    /// Apply worker commands through the production dispatcher.
    pub(super) fn apply(&mut self, commands: Vec<WorkerCommand>) -> Vec<SessionKey> {
        let queue = Arc::new(Mutex::new(VecDeque::from(commands)));
        crate::afxdp::session_glue::apply_worker_commands(
            &queue,
            &mut self.sessions,
            crate::afxdp::bpf_map::SteeringMap::unshared_for_test(-1),
            -1,
            -1,
            &self.forwarding,
            &restamped_ha_state(&txn_ha_state(), monotonic_nanos()),
            &Arc::new(ShardedNeighborMap::new()),
            0,
            &mut VecDeque::new(),
        )
        .deleted_synced_keys
    }

    /// The stored row's egress and installing-table stamp.
    fn row(&self) -> (i32, (u32, u32)) {
        let (decision, _, _) = self
            .sessions
            .entry_with_origin(&key())
            .expect("the row for K is present");
        (
            decision.resolution.egress_ifindex,
            (decision.install_table_domain, decision.install_table_check),
        )
    }

    /// Seed from row A (slow path, E1), then one steady-state hit.
    pub(super) fn seeded() -> Self {
        let mut fx = Self::with_row_a();
        assert_eq!(
            fx.send(0),
            Sent { cache_hit: false, egress: Some(E1) },
            "premise: the first segment takes the slow path on row A via E1"
        );
        assert_eq!(
            fx.binding.flow.flow_cache.entries.iter().flatten().count(),
            1,
            "premise: that segment seeded the flow cache"
        );
        assert_eq!(
            fx.send(0),
            Sent { cache_hit: true, egress: Some(E1) },
            "premise: the second segment is a cache hit via E1"
        );
        fx
    }
}

/// Replace row A with B and check the premises: the dispatcher reports no
/// deleted key (so nothing invalidates the slot explicitly) and the live row
/// resolves in table T, via E2. `local` selects `UpsertLocal`, which
/// installs the decision as given; otherwise `UpsertSynced`, which
/// re-resolves it from the local FIB in B's installing table.
pub(super) fn replace_with_table_t_row(fx: &mut Fixture, local: bool) {
    let mut b = fx.replacement(table_t_stamp(), fx.row_a_session_id() + 1);
    let command = if local {
        b.decision.resolution = resolve(&fx.forwarding, table_t_stamp());
        WorkerCommand::UpsertLocal(b)
    } else {
        WorkerCommand::UpsertSynced(b)
    };
    let deleted = fx.apply(vec![command]);
    assert!(
        deleted.is_empty(),
        "premise: a replacement reports no deleted key, so no explicit \
         flow-cache invalidation runs for it: {deleted:?}"
    );
    assert_eq!(
        fx.row(),
        (E2, table_t_stamp()),
        "premise: the replacing row resolves in table T, via E2"
    );
}

/// THE defect, `UpsertSynced` arm (issue #19173 repro). After a same-key
/// replacement the next segment must take the slow path's verdict on the
/// live row, not the E1 decision the cache seeded from row A. Here that
/// verdict is a #7212 revocation (B's table is not this node's choice).
/// RED on ebb32e817b: the segment is a cache hit and leaves via E1.
#[test]
fn upsert_synced_replacement_is_not_served_the_old_rows_cached_egress_19173() {
    let mut fx = Fixture::seeded();
    replace_with_table_t_row(&mut fx, false);
    let after = fx.send(0);
    assert_eq!(
        after,
        Sent { cache_hit: false, egress: None },
        "#19173: the first segment after UpsertSynced replaced K's row was \
         served from the cache entry seeded from the OLD row (E1); the slow \
         path must judge the live row instead"
    );
    assert_eq!(
        fx.last_filter_revoked, 1,
        "the slow path judged row B: its installing table is not this \
         node's choice for the flow, so the #7212 revalidation revokes it"
    );
}

/// The same defect through `UpsertLocal` (local-tunnel replicas,
/// `upsert_synced_with_origin(.., true)`). RED on ebb32e817b.
#[test]
fn upsert_local_replacement_is_not_served_the_old_rows_cached_egress_19173() {
    let mut fx = Fixture::seeded();
    replace_with_table_t_row(&mut fx, true);
    let after = fx.send(0);
    assert_eq!(
        after,
        Sent { cache_hit: false, egress: None },
        "#19173: UpsertLocal replaced K's row and the next segment was served \
         from the old row's cache entry (E1)"
    );
    assert_eq!(fx.last_filter_revoked, 1, "the slow path judged row B");
}

/// Control twin (the issue's): B is A re-imported as is (default stamp,
/// same session id). The row still resolves via E1 and so does every
/// segment. At 50aa029860 every replacement was a new incarnation and cost
/// the flow ONE slow-path segment (the re-seed); since the fold an identical
/// re-import keeps the incarnation and costs none (pinned strictly by
/// `identical_reimport_keeps_the_cache_hit_19173`). "At most once" holds on
/// every tree. GREEN on ebb32e817b (there, the slot is simply kept).
#[test]
fn identical_reimport_keeps_the_egress_and_re_seeds_at_most_once_19173() {
    let mut fx = Fixture::seeded();
    let b = fx.replacement((0, 0), fx.row_a_session_id());
    fx.apply(vec![WorkerCommand::UpsertSynced(b)]);
    assert_eq!(fx.row(), (E1, (0, 0)), "premise: the re-import still resolves via E1");
    let first = fx.send(0);
    assert_eq!(first.egress, Some(E1), "control: no divergence ({first:?})");
    for n in 0..3 {
        assert_eq!(
            fx.send(0),
            Sent { cache_hit: true, egress: Some(E1) },
            "segment {n} after the re-seed must be a cache hit via E1"
        );
    }
}

/// No spurious miss: ordinary segments update the backing row IN PLACE
/// (byte/packet counters, `last_packet_seen_ns`, the keepalive, observed
/// TCP flags, a data segment's TCP state) and must keep hitting the same
/// entry. Pure ACKs and PSH+ACK data, ten segments after the seed.
#[test]
fn in_place_row_updates_keep_the_cache_entry_19173() {
    let mut fx = Fixture::seeded();
    let entries_before = fx.binding.flow.flow_cache.entries.iter().flatten().count();
    let evictions_before = fx.binding.flow.flow_cache.evictions;
    for n in 0..10 {
        let payload = if n % 2 == 0 { 0 } else { 64 };
        assert_eq!(
            fx.send(payload),
            Sent { cache_hit: true, egress: Some(E1) },
            "segment {n} (payload {payload}) must be served from the cache"
        );
    }
    assert_eq!(
        fx.binding.flow.flow_cache.evictions, evictions_before,
        "an in-place row update must not evict the entry"
    );
    assert_eq!(
        fx.binding.flow.flow_cache.entries.iter().flatten().count(),
        entries_before
    );
}
