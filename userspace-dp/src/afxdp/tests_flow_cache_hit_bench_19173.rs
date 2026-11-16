// #19173 MEASUREMENT: nanoseconds per flow-cache hit for the two calls the
// incarnation check touches: the flow-cache lookup
// (`lookup_counted_with_scheduler_expiry`) and the fused cache-hit probe
// (`probe_hit_deferring_state_update_with_ack_rollback_verdict_lazy`) on a
// live, established row, plus the admission emit, in a tight loop. One flow,
// so both the cache entry and the session record stay in L1: this prices the
// added instructions (one field read, one argument, one compare), not a
// cache miss on a cold line.
//
// The same file runs on the pre-fix tree for the baseline: the three lines
// that name fix-only API carry a trailing fix-only marker comment and are
// deleted there (`grep -v`); nothing else changes. Run with
//   cargo test --release --bins flow_cache_hit_lookup_and_probe_ns_19173 -- --ignored --nocapture
#![allow(unused_imports)]

use super::test_fixtures::*;
use super::tests_support::*;
use super::*;
use crate::session::{SessionKey, SessionMetadata, SessionTable};
use crate::test_zone_ids::*;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

#[test]
#[ignore = "MEASUREMENT: #19173 ns per flow-cache hit (lookup + fused probe); prints only"]
fn flow_cache_hit_lookup_and_probe_ns_19173() {
    let forwarding = build_forwarding_state(&nat_snapshot());
    let key = SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
        src_port: 40_173,
        dst_port: 443,
        discriminator: Default::default(),
        routing_domain: 0,
    };
    let flow = SessionFlow {
        src_ip: key.src_ip,
        dst_ip: key.dst_ip,
        forward_key: key.clone(),
    };
    let mut decision = SessionDecision {
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
    };
    decision.resolution =
        crate::afxdp::session_glue::lookup_forwarding_resolution_for_session_without_cache(
            &forwarding,
            &Arc::new(ShardedNeighborMap::new()),
            &flow,
            decision,
        )
        .resolution;
    assert_eq!(
        decision.resolution.disposition,
        ForwardingDisposition::ForwardCandidate,
        "premise: the main table forwards the flow"
    );
    let metadata = SessionMetadata {
        forward_wire_alias_origin: false,
        ingress_zone: TEST_LAN_ZONE_ID,
        egress_zone: TEST_WAN_ZONE_ID,
        ingress_zone_check: 0,
        egress_zone_check: 0,
        ingress_ifindex: 24,
        ingress_vlan_id: 0,
        forward_ingress_vlan_id: None,
        owner_rg_id: 0,
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
    let mut now_ns = 123_000_000_000u64;
    let mut sessions = SessionTable::new();
    sessions.set_forwarding_revalidation_gen(7, 9);
    assert!(sessions.install_with_protocol(key.clone(), decision, metadata, now_ns, PROTO_TCP, 0x10));
    let meta = txn_meta_v4(24, 0x10, 1514);
    let validation = ValidationState {
        snapshot_installed: true,
        config_generation: 7,
        fib_generation: 9,
        neighbor_generation: 0,
    };
    let rg_epochs: [std::sync::atomic::AtomicU32; MAX_RG_EPOCHS] =
        std::array::from_fn(|_| std::sync::atomic::AtomicU32::new(0));
    // Standalone: no runtime lease to validate against.
    let ha_state = BTreeMap::new();
    #[allow(unused_mut)]
    let mut entry = crate::afxdp::flow_cache::FlowCacheEntry::from_forward_decision(
        &flow,
        meta,
        validation,
        decision,
        0,
        Some(TEST_LAN_ZONE_ID),
        None,
        None,
        Default::default(),
        &forwarding,
        &ha_state,
        false,
        &rg_epochs,
        0,
    )
    .expect("premise: an established TCP forward is cacheable");
    entry.backing_install_epoch = sessions.backing_install_epoch_for_cache_hit(&key, now_ns).expect("row"); // 19173-FIX-ONLY
    let mut cache = crate::afxdp::flow_cache::FlowCache::new();
    cache.insert(entry);
    let lookup = crate::afxdp::flow_cache::FlowCacheLookup::for_packet(meta, validation, &forwarding);

    let hit = |cache: &mut crate::afxdp::flow_cache::FlowCache,
                   sessions: &mut SessionTable,
                   now_ns: u64|
     -> bool {
        let entry = cache
            .lookup_counted_with_scheduler_expiry(
                &key,
                lookup,
                now_ns / 1_000_000_000,
                &rg_epochs,
                meta.pkt_len,
                &forwarding.policy,
                false,
                &ha_state,
                &forwarding,
            )
            .expect("every timed lookup is a hit");
        let expected = entry.backing_install_epoch; // 19173-FIX-ONLY
        // Ends the entry borrow on both trees (the baseline reads nothing).
        let _ = &entry;
        let mut wire_canonical = None;
        let verdict = sessions.probe_hit_deferring_state_update_with_ack_rollback_verdict_lazy(
            &key,
            expected, // 19173-FIX-ONLY
            now_ns,
            1514,
            0x10,
            0,
            0,
            || None,
            false,
            &mut wire_canonical,
        );
        sessions.emit_probe_hit_state_update(&key);
        verdict.is_live()
    };

    // Warm up, and prove the loop measures served hits.
    for _ in 0..100_000 {
        now_ns += 1_000;
        assert!(hit(&mut cache, &mut sessions, now_ns), "premise: a live hit");
    }
    const ROUNDS: u64 = 2_000_000;
    const REPS: usize = 9;
    let hits_before = cache.hits;
    let mut samples = Vec::with_capacity(REPS);
    for _ in 0..REPS {
        let started = std::time::Instant::now();
        let mut live = 0u64;
        for _ in 0..ROUNDS {
            now_ns += 1_000;
            live += u64::from(std::hint::black_box(hit(&mut cache, &mut sessions, now_ns)));
        }
        samples.push(started.elapsed().as_nanos() as f64 / ROUNDS as f64);
        assert_eq!(live, ROUNDS, "every timed probe was live");
    }
    assert_eq!(cache.hits - hits_before, ROUNDS * REPS as u64, "every timed lookup hit");
    let mut sorted = samples.clone();
    sorted.sort_by(|a, b| a.partial_cmp(b).expect("finite"));
    eprintln!(
        "#19173 lookup+probe ns/hit: min {:.2} median {:.2} max {:.2} ({REPS} reps x {ROUNDS} hits) samples={:?}",
        sorted[0],
        sorted[REPS / 2],
        sorted[REPS - 1],
        samples.iter().map(|s| format!("{s:.2}")).collect::<Vec<_>>()
    );
}
