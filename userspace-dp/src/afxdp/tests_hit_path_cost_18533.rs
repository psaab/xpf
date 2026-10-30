// #18533 round 2: MEASUREMENT of the whole per-packet cost of an established
// TCP flow-cache hit through `poll_binding_process_descriptor` — the RX
// prologue, every pre-cache stage, `stage_flow_cache_hit`, the rewrite and the
// TX hand-off — in 32-descriptor batches on a clustered node (RG1/RG2 active,
// so the HA validator's destination-owner arm runs). The flow is installed by
// a real SYN through the poll path, completed on the session table (SYN-ACK
// and completing ACK, as the reverse worker and the slow path would), then
// seeded by a real ACK, so every timed packet is a steady-state cache hit.
//
// One binding only (the harness's): the hit takes the PendingForwardRequest
// fallback rather than the cross-binding in-place push the loss cluster's
// shared UMEM allows, so TX-side struct moves are not in these numbers.
//
// Split out as a sibling `#[path]` test module loaded from afxdp/mod.rs.
#![allow(unused_imports)]

use super::test_fixtures::*;
use super::tests_support::*;
use super::*;

const BATCH: u32 = 32;
const FRAME_BASE: usize = 256;

#[test]
#[ignore = "MEASUREMENT: #18533 round 2 per-packet ns of an established cache hit through the whole poll function; prints only"]
fn established_cache_hit_poll_ns_18533() {
    #[allow(unused_mut)]
    let mut forwarding = build_forwarding_state(&nat_snapshot());
    // A published snapshot, as every worker-visible one is (#18534).
    forwarding.publish_epoch = 1;
    let ha_state = txn_ha_state();
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
    binding.interface = Arc::<str>::from("reth1.0");
    let mut sessions = SessionTable::new();
    let client = Ipv4Addr::new(10, 0, 61, 102);
    let server = Ipv4Addr::new(8, 8, 8, 8);
    let syn = build_txn_tcp_syn_frame_v4(client, server, 12345, 443, TCP_FLAG_SYN, TEST_LAN_MAC);
    txn_run_descriptor_checked(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &syn,
        txn_meta_v4(24, TCP_FLAG_SYN, syn.len() as u16),
        true,
    );
    let fwd = crate::session::SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        src_ip: IpAddr::V4(client),
        dst_ip: IpAddr::V4(server),
        src_port: 12345,
        dst_port: 443,
        discriminator: Default::default(),
        routing_domain: 0,
    };
    let now_ns = 123_000_000_000u64;
    let (lookup, _) = sessions
        .lookup_with_origin(&fwd, now_ns, 0x10)
        .expect("premise: the SYN installed the forward session");
    let rev = crate::session::reverse_session_key(&fwd, lookup.decision.nat);
    assert!(sessions.lookup_with_origin(&rev, now_ns, TCP_FLAG_SYN | 0x10).is_some());
    assert!(sessions.lookup_with_origin(&fwd, now_ns, 0x10).is_some());
    assert_eq!(
        sessions.handshake_state_wire_for(&fwd),
        crate::session::TcpHandshakeState::Established.to_wire(),
        "premise: the pair is Established before the timed hits"
    );
    let ack = build_txn_tcp_syn_frame_v4(client, server, 12345, 443, 0x10, TEST_LAN_MAC);
    // The shim stamps the flow tuple into the metadata; the poll path's
    // flow parse takes its metadata fast path on it, as in production.
    let mut meta = txn_meta_v4(24, 0x10, ack.len() as u16);
    meta.flow_src_addr[..4].copy_from_slice(&client.octets());
    meta.flow_dst_addr[..4].copy_from_slice(&server.octets());
    meta.flow_src_port = 12345;
    meta.flow_dst_port = 443;
    txn_run_descriptor_checked(&mut binding, &mut sessions, &forwarding, &ha_state, &ack, meta, true);
    assert_eq!(txn_flow_cache_entries(&binding), 1, "premise: the ACK seeded the cache");

    let ident = binding.identity();
    let binding_lookup = WorkerBindingLookup::from_bindings(std::slice::from_ref(&binding));
    let mirror_targets = MirrorTargetMap::default();
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
    let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
    let ike_exchanges = Arc::new(crate::afxdp::forwarding::IkeExchangeTable::new());
    let local_tunnel_deliveries = Arc::new(ArcSwap::from_pointee(BTreeMap::new()));
    let recent_exceptions = Arc::new(Mutex::new(ExceptionEventRing::new()));
    let last_resolution = Arc::new(Mutex::new(None));
    let peer_worker_commands = Vec::new();
    let rg_epochs = std::array::from_fn(|_| AtomicU32::new(0));
    let pptp_control = Arc::new(crate::session::pptp_control::PptpControlInbox::default());
    let worker_ctx = WorkerContext {
        pptp_control: &pptp_control,
        ident: &ident,
        binding_lookup: &binding_lookup,
        mirror_targets: &mirror_targets,
        forwarding: &forwarding,
        ha_state: &ha_state,
        forwarding_active_rgs: &*EMPTY_FWD_ACTIVE_RGS_16217,
        dynamic_neighbors: &dynamic_neighbors,
        neighbor_resolver: None,
        shared_sessions: &shared_sessions,
        shared_nat_sessions: &shared_nat_sessions,
        shared_forward_wire_sessions: &shared_forward_wire_sessions,
        shared_owner_rg_indexes: &shared_owner_rg_indexes,
        ike_exchanges: &ike_exchanges,
        slow_path: None,
        event_stream: None,
        local_tunnel_deliveries: &local_tunnel_deliveries,
        recent_exceptions: &recent_exceptions,
        last_resolution: &last_resolution,
        peer_worker_commands: &peer_worker_commands,
        worker_commands_by_id: crate::afxdp::empty_worker_commands_by_id(),
        rg_epochs: &rg_epochs,
        cold_path_sample_mask: 0xff,
    };
    let mut screen = ScreenState::new();
    let meta_len = std::mem::size_of::<UserspaceDpMeta>();
    let meta_bytes = unsafe {
        std::slice::from_raw_parts((&meta as *const UserspaceDpMeta).cast::<u8>(), meta_len)
    };
    let validation = ValidationState {
        snapshot_installed: true,
        config_generation: 7,
        fib_generation: 9,
        neighbor_generation: 0,
    };
    let area_handle = UmemAreaHandle::from_umem(&binding.umem);
    let mut run_batch = |binding: &mut BindingWorker, sessions: &mut SessionTable, now_ns: u64| {
        for i in 0..BATCH as usize {
            let frame_offset = i * crate::afxdp::UMEM_FRAME_SIZE as usize + FRAME_BASE;
            unsafe {
                let area = binding.umem.area();
                area.slice_mut_unchecked(frame_offset - meta_len, meta_len)
                    .expect("meta slice")
                    .copy_from_slice(meta_bytes);
                area.slice_mut_unchecked(frame_offset, ack.len())
                    .expect("frame slice")
                    .copy_from_slice(&ack);
            }
            binding.xsk.rx.push_for_test(XdpDesc {
                addr: frame_offset as u64,
                len: ack.len() as u32,
                options: 0,
            });
        }
        let mut batch = BatchCounters::default();
        let mut dbg = DebugPollCounters::default();
        let mut telemetry = TelemetryContext {
            dbg: &mut dbg,
            counters: &mut batch,
        };
        poll_binding_process_descriptor(
            binding,
            0,
            &area_handle,
            BATCH,
            sessions,
            &mut screen,
            validation,
            now_ns,
            now_ns / 1_000_000_000,
            0,
            0,
            -1,
            -1,
            &worker_ctx,
            &mut telemetry,
        );
        binding.tx_pipeline.pending_tx_prepared.clear();
        binding.scratch.scratch_forwards.clear();
        binding.scratch.scratch_recycle.clear();
        dbg.rx
    };
    let hits_before = binding.flow.flow_cache.hits;
    let received = run_batch(&mut binding, &mut sessions, now_ns + 1_000);
    assert_eq!(received, u64::from(BATCH), "premise: the whole batch was received");
    assert_eq!(
        binding.flow.flow_cache.hits - hits_before,
        u64::from(BATCH),
        "premise: every timed packet is a cache hit"
    );
    const ROUNDS: u64 = 20_000;
    const REPS: usize = 7;
    let mut samples = Vec::with_capacity(REPS);
    let mut now = now_ns + 2_000;
    for _ in 0..REPS {
        let started = std::time::Instant::now();
        for _ in 0..ROUNDS {
            now += 10_000;
            std::hint::black_box(run_batch(&mut binding, &mut sessions, now));
        }
        samples.push(started.elapsed().as_nanos() as f64 / (ROUNDS * u64::from(BATCH)) as f64);
    }
    // #18534 fold: the timed loop measured cache hits, not a fall-through
    // that a later round started taking.
    assert_eq!(
        binding.flow.flow_cache.hits - hits_before,
        u64::from(BATCH) * (1 + REPS as u64 * ROUNDS),
        "every timed packet is a cache hit"
    );
    samples.sort_by(|a, b| a.partial_cmp(b).expect("finite"));
    eprintln!(
        "#18533 full poll, established cache hit: min {:.1} ns/packet, median {:.1} ns/packet ({REPS} reps x {} packets, batch {BATCH}; frame refill included)",
        samples[0],
        samples[REPS / 2],
        ROUNDS * u64::from(BATCH)
    );
}

/// #18534 fold: the cache entry's size and field layout, for the round-2
/// note on what the destination-owner memo costs per entry and which cache
/// line it shares. Prints only.
#[test]
#[ignore = "MEASUREMENT: #18534 FlowCacheEntry layout; prints only"]
fn flow_cache_entry_layout_18534() {
    use crate::afxdp::flow_cache::FlowCacheEntry;
    let mut fields: Vec<(usize, usize, &str)> = Vec::new();
    macro_rules! field {
        ($name:ident, $ty:ty) => {
            fields.push((
                std::mem::offset_of!(FlowCacheEntry, $name),
                std::mem::size_of::<$ty>(),
                stringify!($name),
            ))
        };
    }
    field!(key, crate::session::SessionKey);
    field!(ingress_ifindex, i32);
    field!(logical_ingress_ifindex, i32);
    field!(descriptor, RewriteDescriptor);
    field!(decision, SessionDecision);
    field!(policy_deny, Option<crate::afxdp::flow_cache::CachedPolicyDeny>);
    field!(deny_expires_at_secs, u64);
    field!(cluster_terminal_source_ifindex, i32);
    field!(cluster_terminal_stamp_owner_rg, i32);
    field!(metadata, SessionMetadata);
    field!(stamp, crate::afxdp::flow_cache::FlowCacheStamp);
    field!(observed_bytes, u64);
    field!(last_used_epoch, u16);
    field!(neighbor_mac_epoch, u32);
    field!(neighbor_shard, u16);
    field!(fabric_established, bool);
    field!(dest_owner_memo, crate::afxdp::flow_cache::DestOwnerMemo);
    fields.sort();
    let slot = std::mem::size_of::<Option<FlowCacheEntry>>();
    let slots = crate::afxdp::flow_cache::FlowCache::new().entries.len();
    eprintln!(
        "#18534 FlowCacheEntry: size {} align {}; Option slot {slot} B x {slots} slots = {} KiB per cache",
        std::mem::size_of::<FlowCacheEntry>(),
        std::mem::align_of::<FlowCacheEntry>(),
        slot * slots / 1024
    );
    for (offset, size, name) in fields {
        eprintln!(
            "  {offset:>4}..{:>4} line {}..{} {name}",
            offset + size,
            offset / 64,
            (offset + size - 1) / 64
        );
    }
}
