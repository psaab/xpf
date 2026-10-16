// #13075 (D4-12) — inline `#[cfg(test)]` modules extracted verbatim from
// loop_body/mod.rs. Declared as `#[cfg(test)] #[path = "tests.rs"] mod tests;`
// in mod.rs, so every module here keeps its original name, visibility, and
// `use super::*` resolution (which now chains tests.rs -> loop_body ->
// worker). Pure code motion: no test body, assertion, or fixture changed.

#[allow(unused_imports)]
use super::*;

mod flow_cache_invalidation_tests {
    //! #3776: the GC reap path must invalidate the per-worker flow-cache
    //! slot(s) backing every session it reaps, so a packet that resumes on the
    //! same 5-tuple after the idle timeout MISSES the cache and re-runs full
    //! session lookup/creation + policy — instead of being forwarded via a
    //! stale `RewriteDescriptor` with no live session (stateful-firewall
    //! bypass) and a SNAT port that may now belong to a different flow
    //! (NAT-port reuse). These tests drive the production `reap_expired_sessions`
    //! helper the expiry loop calls; deleting its `invalidate_slot` loop turns
    //! `reaped_session_flow_cache_slot_is_invalidated` and
    //! `reaped_snat_descriptor_is_not_reused` RED.
    //!
    //! #6457: the control-plane delete path (operator `clear security flow
    //! session`, cluster-stale sweep, HA DeleteSynced — all funnelled through
    //! `WorkerCommand::DeleteSynced`) must invalidate the same slot(s) for the
    //! revoked key. Those tests drive the production
    //! `invalidate_flow_cache_slots_for_deleted_sessions` helper the worker
    //! loop calls with `WorkerCommandResults.deleted_synced_keys`; deleting
    //! its `invalidate_slot` loop turns `delete_synced_flow_cache_slot_is_
    //! invalidated` and `delete_synced_snat_descriptor_is_not_reused` RED.
    //! (The `handle_delete_synced` half — recording the key unconditionally —
    //! is pinned in `afxdp/session_glue/tests.rs`.)
    use super::*;
    use crate::nat::NatDecision;
    use crate::session::{
        ExpiredSession, SessionDecision, SessionKey, SessionMetadata, SessionOrigin,
    };
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::atomic::{AtomicU32, Ordering};

    const REAP_INGRESS_IF: i32 = 24;

    fn reap_rg_epochs() -> [AtomicU32; MAX_RG_EPOCHS] {
        std::array::from_fn(|_| AtomicU32::new(0))
    }

    fn reap_key(src_port: u16) -> SessionKey {
        SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            src_port,
            dst_port: 443,
            discriminator: Default::default(),
            routing_domain: 0,
        }
    }

    fn reap_metadata() -> SessionMetadata {
        SessionMetadata {
            ingress_zone: 1,
            egress_zone: 2,
            ingress_zone_check: 0,
            egress_zone_check: 0,
            ingress_ifindex: 0,
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
        }
    }

    fn reap_resolution() -> ForwardingResolution {
        ForwardingResolution {
            disposition: ForwardingDisposition::ForwardCandidate,
            local_ifindex: 0,
            egress_ifindex: 12,
            tx_ifindex: 12,
            tunnel_endpoint_id: 0,
            next_hop: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 50, 1))),
            neighbor_mac: Some([0, 1, 2, 3, 4, 5]),
            src_mac: Some([6, 7, 8, 9, 10, 11]),
            tx_vlan_id: 0,
            route_mtu: 0,
            transport_route_mtu: 0,
        }
    }

    fn reap_decision(snat_port: Option<u16>) -> SessionDecision {
        SessionDecision {
            resolution: reap_resolution(),
            nat: NatDecision {
                rewrite_src: snat_port.map(|_| IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
                rewrite_src_port: snat_port,
                ..NatDecision::default()
            },
            install_table_domain: 0,
            install_table_check: 0,
        }
    }

    fn insert_cache_entry(binding: &mut BindingWorker, key: &SessionKey, snat_port: Option<u16>) {
        insert_cache_entry_on_if(binding, key, snat_port, REAP_INGRESS_IF);
    }

    fn insert_cache_entry_on_if(
        binding: &mut BindingWorker,
        key: &SessionKey,
        snat_port: Option<u16>,
        ingress_ifindex: i32,
    ) {
        let decision = reap_decision(snat_port);
        binding.flow.flow_cache.insert(FlowCacheEntry {
            key: key.clone(),
            ingress_ifindex,
            logical_ingress_ifindex: ingress_ifindex,
            descriptor: RewriteDescriptor {
                last_queue_id: None,
                dst_mac: [0; 6],
                src_mac: [0; 6],
                fabric_redirect: false,
                tx_vlan_id: 0,
                ether_type: 0x0800,
                rewrite_src_ip: decision.nat.rewrite_src,
                rewrite_dst_ip: None,
                rewrite_src_port: decision.nat.rewrite_src_port,
                rewrite_dst_port: None,
                ip_csum_delta: 0,
                l4_csum_delta: 0,
                egress_ifindex: 12,
                tx_ifindex: 12,
                target_binding_index: None,
                input_filter_log: None,
                input_filter_counters: crate::filter::CachedFilterCounters::default(),
                tx_selection: CachedTxSelectionDescriptor::default(),
                nat64: false,
                nptv6: false,
                apply_nat_on_fabric: false,
            },
            decision,
            metadata: reap_metadata(),
            stamp: FlowCacheStamp {
                config_generation: 1,
                fib_generation: 1,
                owner_rg_id: 1,
                owner_rg_epoch: 0,
                owner_rg_lease_until: 0,
            },
            policy_deny: None,
            deny_expires_at_secs: 0,
            observed_bytes: 0,
            last_used_epoch: 0,
            neighbor_mac_epoch: 0,
            // #5147: no dynamic-neighbor dependency in this test entry.
            neighbor_shard: crate::afxdp::flow_cache::NEIGHBOR_SHARD_NONE,
        });
    }

    fn cache_hits(
        binding: &mut BindingWorker,
        key: &SessionKey,
        rg_epochs: &[AtomicU32; MAX_RG_EPOCHS],
    ) -> bool {
        cache_hits_on_if(binding, key, rg_epochs, REAP_INGRESS_IF)
    }

    fn cache_hits_on_if(
        binding: &mut BindingWorker,
        key: &SessionKey,
        rg_epochs: &[AtomicU32; MAX_RG_EPOCHS],
        ingress_ifindex: i32,
    ) -> bool {
        binding
            .flow
            .flow_cache
            .lookup(
                key,
                FlowCacheLookup {
                    ingress_ifindex,
                    logical_ingress_ifindex: ingress_ifindex,
                    config_generation: 1,
                    fib_generation: 1,
                },
                0,
                rg_epochs,
            )
            .is_some()
    }

    fn expired(key: SessionKey, snat_port: Option<u16>) -> ExpiredSession {
        ExpiredSession {
            key,
            decision: reap_decision(snat_port),
            metadata: reap_metadata(),
            origin: SessionOrigin::ForwardFlow,
            session_id: 0,
            close_class: 0,
            install_epoch: 0,
            overflow_close: None,
        }
    }

    // #3776 H1: a packet that resumes on a reaped flow's 5-tuple must MISS the
    // cache. Without the GC-path `invalidate_slot` the descriptor survives the
    // reap and the resumed packet is forwarded with no live session — the
    // stateful-firewall bypass. RED on revert (the entry survives, `cache_hits`
    // stays true after the reap).
    #[test]
    fn reaped_session_flow_cache_slot_is_invalidated() {
        let rg_epochs = reap_rg_epochs();
        let forwarding = ForwardingState::default();
        let mut binding = BindingWorker::new_for_mirror_test(0, 0, REAP_INGRESS_IF, 0);
        let key = reap_key(12345);
        insert_cache_entry(&mut binding, &key, None);
        assert!(
            cache_hits(&mut binding, &key, &rg_epochs),
            "precondition: an active flow's descriptor is cached and hits"
        );

        reap_expired_sessions(
            std::slice::from_mut(&mut binding),
            &[expired(key.clone(), None)],
            &forwarding,
            SteeringMap::unshared_for_test(-1),
            -1,
            -1,
            1_000_000_000,
            0,
        );

        assert!(
            !cache_hits(&mut binding, &key, &rg_epochs),
            "#3776: a packet on a reaped flow's tuple must MISS the cache so it \
             re-runs full session lookup + policy (no sessionless forward)"
        );
        assert_eq!(
            binding.flow.flow_cache.entries.iter().flatten().count(),
            0,
            "#3776: the reaped flow's cache slot must be evicted"
        );
    }

    // #3776 H2: the SNAT-bearing descriptor of a reaped flow must not survive to
    // re-drive a translation whose port `release_source_nat_allocation` just
    // returned to the pool. RED on revert (the SNAT descriptor keeps hitting).
    #[test]
    fn reaped_snat_descriptor_is_not_reused() {
        let rg_epochs = reap_rg_epochs();
        let forwarding = ForwardingState::default();
        let mut binding = BindingWorker::new_for_mirror_test(0, 0, REAP_INGRESS_IF, 0);
        let key = reap_key(23456);
        insert_cache_entry(&mut binding, &key, Some(20001));
        assert!(cache_hits(&mut binding, &key, &rg_epochs));

        reap_expired_sessions(
            std::slice::from_mut(&mut binding),
            &[expired(key.clone(), Some(20001))],
            &forwarding,
            SteeringMap::unshared_for_test(-1),
            -1,
            -1,
            1_000_000_000,
            0,
        );

        assert!(
            !cache_hits(&mut binding, &key, &rg_epochs),
            "#3776: a released-SNAT descriptor must not survive the reap and \
             re-SNAT to a port now owned by a different flow"
        );
    }

    // A flow that is NOT reaped this sweep must keep hitting the cache — the
    // #2220 keepalive fast path is preserved, the reap targets only the reaped
    // key, and there is no collateral invalidation.
    #[test]
    fn live_flow_survives_reap_of_a_different_flow() {
        let rg_epochs = reap_rg_epochs();
        let forwarding = ForwardingState::default();
        let mut binding = BindingWorker::new_for_mirror_test(0, 0, REAP_INGRESS_IF, 0);
        let reaped = reap_key(30001);
        let live = reap_key(30002);
        insert_cache_entry(&mut binding, &reaped, None);
        insert_cache_entry(&mut binding, &live, None);
        assert!(cache_hits(&mut binding, &reaped, &rg_epochs));
        assert!(cache_hits(&mut binding, &live, &rg_epochs));

        reap_expired_sessions(
            std::slice::from_mut(&mut binding),
            &[expired(reaped.clone(), None)],
            &forwarding,
            SteeringMap::unshared_for_test(-1),
            -1,
            -1,
            1_000_000_000,
            0,
        );

        assert!(
            !cache_hits(&mut binding, &reaped, &rg_epochs),
            "the reaped flow's slot is evicted"
        );
        assert!(
            cache_hits(&mut binding, &live, &rg_epochs),
            "a still-live flow's slot must survive the reap of a different flow \
             (no keepalive/hot-path regression, no collateral invalidation)"
        );
    }

    // #6457 H1: a control-plane session delete (operator `clear security flow
    // session`, cluster-stale sweep `BatchDeleteSessions`, HA DeleteSynced
    // propagation — all funnelled through `WorkerCommand::DeleteSynced`) must
    // evict the flow-cache slot backing the revoked session. None of those
    // paths bumps config/fib generation, RG epoch, or RG lease, so without
    // the explicit eviction the revoked-but-still-active 5-tuple keeps
    // HITTING its cached RewriteDescriptor and forwards with no live
    // session — the operator's revocation primitive silently defeated
    // (fail-open). Drives the production
    // `invalidate_flow_cache_slots_for_deleted_sessions` the worker loop
    // calls with `WorkerCommandResults.deleted_synced_keys`. RED on revert
    // (the entry survives, `cache_hits` stays true after the delete).
    #[test]
    fn delete_synced_flow_cache_slot_is_invalidated() {
        let rg_epochs = reap_rg_epochs();
        let mut binding = BindingWorker::new_for_mirror_test(0, 0, REAP_INGRESS_IF, 0);
        let key = reap_key(34567);
        insert_cache_entry(&mut binding, &key, None);
        assert!(
            cache_hits(&mut binding, &key, &rg_epochs),
            "precondition: an active flow's descriptor is cached and hits"
        );

        invalidate_flow_cache_slots_for_deleted_sessions(
            std::slice::from_mut(&mut binding),
            &[key.clone()],
        );

        assert!(
            !cache_hits(&mut binding, &key, &rg_epochs),
            "#6457: a packet on a revoked flow's tuple must MISS the cache so \
             it re-runs full session lookup + policy (no sessionless forward \
             under a stale cached permit)"
        );
        assert_eq!(
            binding.flow.flow_cache.entries.iter().flatten().count(),
            0,
            "#6457: the revoked flow's cache slot must be evicted"
        );
    }

    // #6457 H2: the SNAT-bearing descriptor of a revoked flow must not
    // survive the delete to re-drive a translation whose pool port
    // `handle_delete_synced` just returned to the allocator (the port may
    // already belong to a different flow). RED on revert (the SNAT
    // descriptor keeps hitting).
    #[test]
    fn delete_synced_snat_descriptor_is_not_reused() {
        let rg_epochs = reap_rg_epochs();
        let mut binding = BindingWorker::new_for_mirror_test(0, 0, REAP_INGRESS_IF, 0);
        let key = reap_key(45678);
        insert_cache_entry(&mut binding, &key, Some(21000));
        assert!(cache_hits(&mut binding, &key, &rg_epochs));

        invalidate_flow_cache_slots_for_deleted_sessions(
            std::slice::from_mut(&mut binding),
            &[key.clone()],
        );

        assert!(
            !cache_hits(&mut binding, &key, &rg_epochs),
            "#6457: a revoked SNAT descriptor must not survive the delete and \
             re-SNAT to a port now owned by a different flow"
        );
    }

    // #6457: a deleted session carries no ingress ifindex, so the eviction
    // must walk EVERY binding of the worker — the flow may have been pinned
    // to any queue. Seed the revoked flow's descriptor in the SECOND
    // binding's cache (keyed on that binding's ingress ifindex) and assert
    // the walk reaches it; the first binding's still-live flow must survive
    // (no collateral invalidation of an unrelated key).
    #[test]
    fn delete_synced_invalidation_walks_every_binding() {
        let rg_epochs = reap_rg_epochs();
        let other_if = REAP_INGRESS_IF + 1;
        let mut binding_a = BindingWorker::new_for_mirror_test(0, 0, REAP_INGRESS_IF, 0);
        let mut binding_b = BindingWorker::new_for_mirror_test(1, 0, other_if, 0);
        let revoked = reap_key(56789);
        let live = reap_key(56790);
        insert_cache_entry_on_if(&mut binding_b, &revoked, None, other_if);
        insert_cache_entry(&mut binding_a, &live, None);
        assert!(cache_hits_on_if(
            &mut binding_b,
            &revoked,
            &rg_epochs,
            other_if
        ));
        assert!(cache_hits(&mut binding_a, &live, &rg_epochs));

        let mut bindings = [binding_a, binding_b];
        invalidate_flow_cache_slots_for_deleted_sessions(&mut bindings, &[revoked.clone()]);
        let [binding_a, binding_b] = &mut bindings;

        assert!(
            !cache_hits_on_if(binding_b, &revoked, &rg_epochs, other_if),
            "#6457: the revoked flow's slot must be evicted even when it \
             lives on a non-first binding (the delete carries no ifindex)"
        );
        assert!(
            cache_hits(binding_a, &live, &rg_epochs),
            "#6457: an unrelated live flow must survive the delete of a \
             different flow (no collateral invalidation)"
        );
    }
    // #12042 RED-before: the decap path replaces `meta.ingress_ifindex` with
    // the tunnel LOGICAL ifindex, while removal paths pass the PHYSICAL
    // `binding.ifindex`. Before the fix, insert and lookup used the logical
    // value for set placement, so invalidation by the physical binding could
    // not reach the tunnel entry; it survived reap and the reopened flow's
    // first ACK HIT the stale descriptor.
    const TUNNEL_LOGICAL_IF: i32 = 400;

    #[test]
    fn reaped_tunnel_flow_cache_slot_is_invalidated_12042() {
        let rg_epochs = reap_rg_epochs();
        let forwarding = ForwardingState::default();
        // The physical underlay binding that received the outer packet: its
        // `binding.ifindex` is what every removal path passes to
        // `invalidate_slot` today.
        let mut binding = BindingWorker::new_for_mirror_test(0, 0, REAP_INGRESS_IF, 0);
        let key = reap_key(61001);
        insert_cache_entry_on_if(&mut binding, &key, None, TUNNEL_LOGICAL_IF);
        let cached = binding
            .flow
            .flow_cache
            .entries
            .iter()
            .flatten()
            .next()
            .expect("precondition: tunnel flow's descriptor is cached");
        assert_eq!(cached.ingress_ifindex, REAP_INGRESS_IF);
        assert_eq!(cached.logical_ingress_ifindex, TUNNEL_LOGICAL_IF);
        // `FlowCache::insert` receives the tunnel logical identity from the
        // decap-rebound packet metadata, but must retain the owning binding's
        // physical identity for set placement and removal-path invalidation.
        assert!(
            cache_hits_on_if(&mut binding, &key, &rg_epochs, TUNNEL_LOGICAL_IF),
            "precondition: the tunnel flow's descriptor is cached and hits"
        );

        reap_expired_sessions(
            std::slice::from_mut(&mut binding),
            &[expired(key.clone(), None)],
            &forwarding,
            SteeringMap::unshared_for_test(-1),
            -1,
            -1,
            1_000_000_000,
            0,
        );

        assert!(
            !cache_hits_on_if(&mut binding, &key, &rg_epochs, TUNNEL_LOGICAL_IF),
            "#12042: a re-opened tunnel flow's first ACK must MISS the cache so \
             it re-runs full session lookup + policy (no stale-descriptor HIT)"
        );
        assert_eq!(
            binding.flow.flow_cache.entries.iter().flatten().count(),
            0,
            "#12042: the reaped tunnel flow's cache slot must be evicted \
             (entries_after_reap == 0)"
        );
    }

    #[test]
    fn delete_synced_tunnel_flow_cache_slot_is_invalidated_12042() {
        let rg_epochs = reap_rg_epochs();
        let mut binding = BindingWorker::new_for_mirror_test(0, 0, REAP_INGRESS_IF, 0);
        let key = reap_key(61002);
        insert_cache_entry_on_if(&mut binding, &key, None, TUNNEL_LOGICAL_IF);
        assert!(
            cache_hits_on_if(&mut binding, &key, &rg_epochs, TUNNEL_LOGICAL_IF),
            "precondition: the tunnel flow's descriptor is cached and hits"
        );

        invalidate_flow_cache_slots_for_deleted_sessions(
            std::slice::from_mut(&mut binding),
            &[key.clone()],
        );

        assert!(
            !cache_hits_on_if(&mut binding, &key, &rg_epochs, TUNNEL_LOGICAL_IF),
            "#12042: a revoked tunnel flow's next ACK must MISS the cache so \
             it re-runs full session lookup + policy (no stale-descriptor HIT)"
        );
        assert_eq!(
            binding.flow.flow_cache.entries.iter().flatten().count(),
            0,
            "#12042: the revoked tunnel flow's cache slot must be evicted"
        );
    }
    #[test]
    fn conntrack_delete_refusal_is_retained_and_revalidated_13671() {
        use crate::afxdp::bpf_map::{
            CONNTRACK_TEST_MAP_FD, conntrack_row_for_test,
            publish_bpf_conntrack_entry_with_source_nat,
        };
        use crate::afxdp::bpf_map::global_tuple_gate;
        use crate::session::SessionTable;
        use std::sync::{Arc, Mutex};
        use crate::afxdp::worker::SyncedSessionEntry;

        for (port, old_id, replacement_id) in [(62001, 71001, None), (62002, 71002, Some(71003))] {
            crate::afxdp::bpf_map::clear_conntrack_rows_for_test();
            let key = reap_key(port);
            assert_eq!(
                publish_bpf_conntrack_entry_with_source_nat(
                    CONNTRACK_TEST_MAP_FD,
                    CONNTRACK_TEST_MAP_FD,
                    &key,
                    reap_decision(None),
                    &reap_metadata(),
                    &FastMap::default(),
                    0,
                    0,
                    old_id,
                    300,
                    SessionOrigin::ForwardFlow,
                    None,
                ),
                crate::afxdp::bpf_map::ConntrackPublishResult::Written
            );
            let held = global_tuple_gate()
                .try_acquire_install(&key)
                .expect("test holds exclusive same-bare-tuple admission");
            let mut expired = expired(key.clone(), None);
            expired.key.routing_domain = 77;
            expired.session_id = old_id;
            let mut binding = BindingWorker::new_for_mirror_test(0, 0, REAP_INGRESS_IF, 0);
            let mut deferred = reap_expired_sessions(
                std::slice::from_mut(&mut binding),
                &[expired],
                &ForwardingState::default(),
                SteeringMap::unshared_for_test(-1),
                CONNTRACK_TEST_MAP_FD,
                CONNTRACK_TEST_MAP_FD,
                1_000_000_000,
                0,
            );
            assert_eq!(deferred.len(), 1, "GateBusy must retain the delete");
            assert_eq!(
                conntrack_row_for_test(&key).unwrap().session_id,
                old_id,
                "the held row must remain untouched"
            );
            let mut sessions = SessionTable::new();
            sessions.defer_conntrack_deletes(std::mem::take(&mut deferred));
            let mut shared_sessions_map = FastMap::default();
            shared_sessions_map.insert(
                key.clone(),
                SyncedSessionEntry {
                    key: key.clone(),
                    decision: reap_decision(None),
                    metadata: reap_metadata(),
                    source_nat_static: None,
                    leak_incarnation: 0,
                    origin: SessionOrigin::ForwardFlow,
                    protocol: PROTO_TCP,
                    tcp_flags: crate::tcp_flags::TCP_ACK,
                    generation: 0,
                    session_id: 0,
                    tcp_close_class: 0,
                    tcp_handshake_state: 0,
                },
            );
            let shared_sessions = Arc::new(Mutex::new(shared_sessions_map));
            let unrelated_key = if replacement_id.is_none() {
                let unrelated_key = reap_key(port + 100);
                assert_eq!(
                    publish_bpf_conntrack_entry_with_source_nat(
                        CONNTRACK_TEST_MAP_FD,
                        CONNTRACK_TEST_MAP_FD,
                        &unrelated_key,
                        reap_decision(None),
                        &reap_metadata(),
                        &FastMap::default(),
                        0,
                        0,
                        old_id + 100,
                        300,
                        SessionOrigin::ForwardFlow,
                        None,
                    ),
                    crate::afxdp::bpf_map::ConntrackPublishResult::Written
                );
                sessions.defer_conntrack_delete(crate::session::DeferredConntrackDelete {
                    key: unrelated_key.clone(),
                    session_id: old_id + 100,
                });
                Some(unrelated_key)
            } else {
                None
            };
            crate::afxdp::worker::retry_deferred_conntrack_deletes(
                &mut sessions,
                CONNTRACK_TEST_MAP_FD,
                CONNTRACK_TEST_MAP_FD,
                &shared_sessions,
            );
            assert_eq!(
                conntrack_row_for_test(&key).unwrap().session_id,
                old_id,
                "a busy tuple remains deferred"
            );
            if let Some(unrelated_key) = unrelated_key {
                assert!(
                    conntrack_row_for_test(&unrelated_key).is_none(),
                    "one busy tuple must not block unrelated deferred deletes"
                );
            }
            let pending = sessions.take_deferred_conntrack_deletes();
            assert_eq!(pending.len(), 1, "only the busy tuple remains queued");
            assert_eq!(pending[0].key.bare_tuple(), key.bare_tuple());
            sessions.defer_conntrack_deletes(pending);
            drop(held);
            if let Some(replacement_id) = replacement_id {
                let mut replacement_key = key.clone();
                replacement_key.routing_domain = 99;
                assert_eq!(
                    publish_bpf_conntrack_entry_with_source_nat(
                        CONNTRACK_TEST_MAP_FD,
                        CONNTRACK_TEST_MAP_FD,
                        &replacement_key,
                        reap_decision(None),
                        &reap_metadata(),
                        &FastMap::default(),
                        0,
                        0,
                        replacement_id,
                        300,
                        SessionOrigin::ForwardFlow,
                        None,
                    ),
                    crate::afxdp::bpf_map::ConntrackPublishResult::Written
                );
            }
            crate::afxdp::worker::retry_deferred_conntrack_deletes(
                &mut sessions,
                CONNTRACK_TEST_MAP_FD,
                CONNTRACK_TEST_MAP_FD,
                &shared_sessions,
            );
            assert!(
                sessions.take_deferred_conntrack_deletes().is_empty(),
                "completed or superseded deletes clear their retained work"
            );
            match replacement_id {
                Some(replacement_id) => assert_eq!(
                    conntrack_row_for_test(&key).unwrap().session_id,
                    replacement_id,
                    "retry must not delete a replacement incarnation"
                ),
                None => assert!(
                    conntrack_row_for_test(&key).is_none(),
                    "retry removes the original conntrack row after admission"
                ),
            }
        }
        crate::afxdp::bpf_map::clear_conntrack_rows_for_test();
    }
}

mod expiry_count_tests {
    use super::super::count_local_session_expiries;
    use crate::session::SessionOrigin;

    #[test]
    fn local_origin_expiries_are_counted() {
        let origins = [
            SessionOrigin::ForwardFlow,
            SessionOrigin::ReverseFlow,
            SessionOrigin::LocalMiss,
            SessionOrigin::MissingNeighborSeed,
        ];
        assert_eq!(count_local_session_expiries(origins.into_iter()), 4);
    }

    #[test]
    fn synced_derived_expiries_are_not_counted() {
        // #2428: the standby (and any node) reaps synced-derived sessions it
        // never create-counted. None of these may bump session_expires, or
        // the Go-derived `session_creates - session_expires` underflows to a
        // wrapped u64. ALL FIVE uncounted origins must be excluded —
        // including SharedPromote, whose is_peer_synced() returns false,
        // and TunOrigin (#10038 item 5: publish bumps nothing).
        let origins = [
            SessionOrigin::SyncImport,
            SessionOrigin::SharedMaterialize,
            SessionOrigin::WorkerLocalImport,
            SessionOrigin::SharedPromote,
            SessionOrigin::TunOrigin,
        ];
        assert_eq!(
            count_local_session_expiries(origins.into_iter()),
            0,
            "synced-derived expiries must not bump session_expires (would \
             underflow the Current-sessions gauge)"
        );
    }

    #[test]
    fn shared_promote_expiry_is_not_counted() {
        // #2428 review fold: SharedPromote is a re-tag of an already-synced
        // (uncounted) entry — promote_synced_with_origin does NOT bump
        // session_creates. is_peer_synced() returns FALSE for it, so the
        // earlier `!is_peer_synced()` filter wrongly COUNTED a promote
        // expiry, re-introducing the underflow on a promoting node.
        // fail-on-revert: restoring `!o.is_peer_synced()` makes this case
        // return 1 instead of 0.
        assert_eq!(
            count_local_session_expiries([SessionOrigin::SharedPromote].into_iter()),
            0,
            "a SharedPromote expiry must NOT bump session_expires (never \
             create-counted)"
        );
    }

    #[test]
    fn mixed_batch_counts_only_create_counted_locals() {
        let origins = [
            SessionOrigin::ForwardFlow,       // local: +1
            SessionOrigin::SyncImport,        // synced: 0
            SessionOrigin::ReverseFlow,       // local: +1
            SessionOrigin::SharedMaterialize, // synced: 0
            SessionOrigin::WorkerLocalImport, // synced: 0
            SessionOrigin::SharedPromote,     // synced: 0
            SessionOrigin::TunOrigin,         // tun-local: 0
        ];
        assert_eq!(count_local_session_expiries(origins.into_iter()), 2);
    }

    #[test]
    fn taxonomy_is_nine_variants() {
        // #2428: pin the SessionOrigin taxonomy at 9 (#10038 item 5 adds
        // TunOrigin). The exhaustive match in count_local_session_expiries
        // (no wildcard) already forces a compile-time decision on a new
        // variant; this enumerates every variant and asserts it classifies
        // exactly once into local (4) or uncounted (5). A 10th variant
        // breaks BOTH the match (compile error) and this count (9 -> 10)
        // — a loud double signal.
        let all = [
            SessionOrigin::ForwardFlow,
            SessionOrigin::ReverseFlow,
            SessionOrigin::LocalMiss,
            SessionOrigin::MissingNeighborSeed,
            SessionOrigin::SyncImport,
            SessionOrigin::SharedMaterialize,
            SessionOrigin::SharedPromote,
            SessionOrigin::WorkerLocalImport,
            SessionOrigin::TunOrigin,
        ];
        assert_eq!(all.len(), 9, "SessionOrigin taxonomy is 9 variants");
        // Exactly the four create-counted locals are counted.
        assert_eq!(count_local_session_expiries(all.into_iter()), 4);
    }
}

mod snapshot_refresh_ordering_tests {
    use super::*;

    /// A published `(generation, forwarding)` fixture. Holding every `Arc`
    /// alive for the whole test is load-bearing: `Arc::ptr_eq` is the only way
    /// to map an observed forwarding allocation back to the generation it was
    /// published with, and a dropped allocation could be recycled by the next
    /// `Arc::new` and fool it.
    struct PublishedGenerations {
        views: Vec<(u64, Arc<ForwardingState>)>,
    }

    impl PublishedGenerations {
        fn new() -> Self {
            Self { views: Vec::new() }
        }

        /// Mint a fresh forwarding allocation stamped with `generation`, and
        /// return the `RuntimeView` the coordinator would publish for it.
        fn mint(&mut self, generation: u64) -> Arc<RuntimeView> {
            let forwarding = Arc::new(ForwardingState::default());
            self.views.push((generation, forwarding.clone()));
            Arc::new(RuntimeView::new(
                // runtime-view-canary: test-local
                ValidationState {
                    snapshot_installed: true,
                    config_generation: generation,
                    fib_generation: generation as u32,
                },
                forwarding,
            ))
        }

        /// The generation `forwarding` was published with.
        fn generation_of(&self, forwarding: &Arc<ForwardingState>) -> u64 {
            self.views
                .iter()
                .find(|(_, published)| Arc::ptr_eq(published, forwarding))
                .map(|(generation, _)| *generation)
                .expect("every forwarding allocation under test is minted here")
        }
    }

    /// #6592 pairing regression (deterministic fail-on-revert), CONSUMER half.
    ///
    /// A worker's per-tick refresh must take validation AND forwarding from ONE
    /// `ArcSwap` load, so the pair it ends up holding is always the pair the
    /// coordinator published. Two separate loads — in EITHER order — let a
    /// coordinator publish land between them and tear the pair:
    /// - validation loaded first → `(old validation, new forwarding)`. A packet
    ///   stamped at the OLD generation passes `classify_metadata` and is then
    ///   forwarded under the NEW tables. (#6291.)
    /// - forwarding loaded first → `(new validation, old forwarding)`. Once Go
    ///   writes the new generation to `userspace_ctrl` the shim stamps NEW;
    ///   those packets pass `classify_metadata` against the new validation and
    ///   are forwarded under the STALE tables — a withdrawn route still
    ///   resolves, a new deny is not applied. (#6592.) This is the orientation
    ///   #6291's reorder left behind, and it is the COMMON one.
    ///
    /// The test drives `refresh_runtime_view` with a coordinator publish
    /// injected through the `between` seam — deterministically reproducing the
    /// ≤1-tick interleaving with NO thread race — and asserts the returned pair
    /// is COHERENT: the observed validation is the generation the observed
    /// forwarding was published with. That single assertion catches BOTH
    /// orientations, because both produce a mismatch. Splitting
    /// `refresh_runtime_view` back into two `ArcSwap` loads in either order
    /// turns it RED.
    ///
    /// Note what is deliberately NOT asserted: that the worker observes the
    /// NEW generation. Observing the OLD view is a legitimate, SAFE outcome —
    /// a worker that has not refreshed drops new-stamped packets, the intended
    /// fail-closed behaviour. #6592 closes INCOHERENT pairs, not stale coherent
    /// ones. Case 3 covers convergence separately.
    #[test]
    fn snapshot_refresh_runtime_view_pair_is_atomic_6592() {
        let mut published = PublishedGenerations::new();

        // Drive the REAL publish/read split: a coordinator-side channel and a
        // worker-side read-only handle. The worker literally cannot publish
        // here — `RuntimeViewReader` has no store — so the test exercises the
        // same capability boundary production does.
        let channel = RuntimeViewChannel::default();
        channel.publish(published.mint(1));
        let shared_runtime = channel.reader();

        // Assert the returned pair is internally coherent, and report which
        // torn orientation a failure represents so a revert names its own bug.
        let assert_coherent = |published: &PublishedGenerations,
                               cached: &Arc<ForwardingState>,
                               new_forwarding_opt: &Option<Arc<ForwardingState>>,
                               observed: ValidationState,
                               case: &str| {
            // The pair the worker actually ends the tick holding: the adopted
            // Arc if forwarding rotated, otherwise its unchanged cached one.
            let effective = new_forwarding_opt.as_ref().unwrap_or(cached);
            let forwarding_generation = published.generation_of(effective);
            let orientation = if observed.config_generation > forwarding_generation {
                "(new validation, old forwarding) — the #6592 mirror: \
                 new-stamped packets classify Valid and forward under STALE tables"
            } else {
                "(old validation, new forwarding) — the #6291 orientation: \
                 old-stamped packets classify Valid and forward under NEW tables"
            };
            assert_eq!(
                observed.config_generation, forwarding_generation,
                "#6592 [{case}]: worker holds a TORN pair {orientation}. \
                 Both halves must come from ONE view load",
            );
        };

        // --- Case 1: the worker is UP TO DATE and a publish lands mid-refresh.
        // Its cached forwarding is the currently-published one, so with a
        // single load nothing rotates (#1188 short-circuit) and it keeps the
        // whole old pair — coherent, and safe.
        let cached = shared_runtime.load().forwarding().clone();
        let view2 = published.mint(2);
        let (new_forwarding_opt, observed) = refresh_runtime_view(&cached, &shared_runtime, |_| {
            channel.publish(view2);
        });
        assert_coherent(
            &published,
            &cached,
            &new_forwarding_opt,
            observed,
            "publish during refresh, worker up to date",
        );

        // --- Case 2: the worker is BEHIND (a publish already landed before its
        // load) and ANOTHER publish lands mid-refresh. Now the refresh really
        // does adopt a new forwarding Arc, so the coherence assert above is not
        // satisfiable by simply never adopting anything.
        let view3 = published.mint(3);
        let (new_forwarding_opt, observed) = refresh_runtime_view(&cached, &shared_runtime, |_| {
            channel.publish(view3);
        });
        assert!(
            new_forwarding_opt.is_some(),
            "a worker behind by a generation must adopt the published \
             forwarding — otherwise the coherence assert is vacuous",
        );
        assert_coherent(
            &published,
            &cached,
            &new_forwarding_opt,
            observed,
            "publish during refresh, worker behind",
        );

        // --- Case 3: with no concurrent publish the worker CONVERGES on the
        // latest published pair. This is what makes cases 1 and 2 non-vacuous:
        // the injected publishes were real and reachable, they just were not
        // observable by a load that had already happened.
        let (new_forwarding_opt, observed) = refresh_runtime_view(&cached, &shared_runtime, |_| {});
        let adopted = new_forwarding_opt
            .clone()
            .expect("the worker must adopt the latest published forwarding");
        assert_coherent(
            &published,
            &cached,
            &new_forwarding_opt,
            observed,
            "quiescent refresh",
        );
        assert_eq!(
            observed.config_generation, 3,
            "a quiescent refresh must converge on the newest published pair",
        );
        assert!(
            Arc::ptr_eq(&adopted, shared_runtime.load().forwarding()),
            "the adopted forwarding must be the published allocation",
        );

        // --- Case 4 (#1188): a VALIDATION-ONLY publish — what
        // `Coordinator::republish_runtime_validation` does for a FIB bump —
        // advances the stamps while REUSING the forwarding Arc, so the worker
        // sees the new validation with no rotation and skips its expensive
        // forwarding-rotation branch. The pair stays coherent because it is
        // still one view.
        let unrotated = shared_runtime.load().forwarding().clone();
        channel.publish(Arc::new(RuntimeView::new(
            // runtime-view-canary: test-local
            ValidationState {
                snapshot_installed: true,
                config_generation: 3,
                fib_generation: 99,
            },
            unrotated.clone(),
        )));
        let (new_forwarding_opt, observed) =
            refresh_runtime_view(&adopted, &shared_runtime, |_| {});
        assert!(
            new_forwarding_opt.is_none(),
            "#1188: a validation-only publish must NOT rotate the worker's \
             forwarding Arc — rotating it drags every worker through the \
             expensive rotation branch for a change that touched no table",
        );
        assert_eq!(
            observed.fib_generation, 99,
            "the validation-only publish must still be observed",
        );
        assert_coherent(
            &published,
            &adopted,
            &new_forwarding_opt,
            observed,
            "validation-only publish",
        );
    }
}

mod gc_reap_source_nat_release_tests_6901 {
    //! #6901: the GC reap's `release_source_nat_allocation_for_worker` call was
    //! UNBOUND — deleting it left the whole crate green (measured: 4670
    //! collected, 0 failed, both with and without the call).
    //!
    //! `reap_expired_sessions` is the ordinary inactivity-timeout teardown, the
    //! path that frees a source-NAT pool port for the overwhelming majority of
    //! sessions — they age out rather than being explicitly deleted. Without the
    //! call, every reaped translated session leaks a pool port until
    //! `AllocatorExhausted`, and nothing in the suite noticed.
    //!
    //! TWO cells, because "the reap calls release" and "the reap releases the
    //! port THIS session holds" are different claims and only the first is
    //! bound by a count going to zero. A release that freed the wrong pool
    //! would satisfy a single-pool fixture.
    use super::*;
    use crate::nat::NatDecision;
    use crate::session::{
        ExpiredSession, SessionDecision, SessionKey, SessionMetadata, SessionOrigin,
    };
    use std::net::{IpAddr, Ipv4Addr};

    const POOL_A: Ipv4Addr = Ipv4Addr::new(172, 16, 80, 8);
    const POOL_B: Ipv4Addr = Ipv4Addr::new(172, 16, 90, 9);

    fn rule_snapshot(name: &str, from: &str, pool_addr: Ipv4Addr) -> crate::SourceNATRuleSnapshot {
        crate::SourceNATRuleSnapshot {
            name: name.to_string(),
            from_zone: from.to_string(),
            to_zone: "wan".to_string(),
            source_addresses: vec!["0.0.0.0/0".to_string()],
            pool_name: name.to_string(),
            pool_addresses: vec![format!("{pool_addr}/32")],
            port_low: 1024,
            port_high: 65535,
            ..crate::SourceNATRuleSnapshot::default()
        }
    }

    fn key_for(src_port: u16) -> SessionKey {
        SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            src_port,
            dst_port: 443,
            discriminator: Default::default(),
            routing_domain: 0,
        }
    }

    fn nat_for(pool_addr: Ipv4Addr, port: u16) -> NatDecision {
        NatDecision {
            rewrite_src: Some(IpAddr::V4(pool_addr)),
            rewrite_src_port: Some(port),
            ..NatDecision::default()
        }
    }

    fn metadata() -> SessionMetadata {
        SessionMetadata {
            ingress_zone: 1,
            egress_zone: 2,
            ingress_zone_check: 0,
            egress_zone_check: 0,
            ingress_ifindex: 0,
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
        }
    }

    fn expired_for(src_port: u16, pool_addr: Ipv4Addr, snat_port: u16) -> ExpiredSession {
        ExpiredSession {
            key: key_for(src_port),
            decision: SessionDecision {
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
                    route_mtu: 0,
                    transport_route_mtu: 0,
                },
                nat: nat_for(pool_addr, snat_port),
                install_table_domain: 0,
                install_table_check: 0,
            },
            origin: SessionOrigin::ForwardFlow,
            session_id: 0,
            close_class: 0,
            install_epoch: 0,
            metadata: metadata(),
            overflow_close: None,
        }
    }

    fn used(forwarding: &ForwardingState, pool: &str) -> u64 {
        crate::nat::source_nat_pool_statuses(&forwarding.source_nat_rules)
            .into_iter()
            .find(|s| s.pool_name == pool)
            .unwrap_or_else(|| panic!("no pool status for {pool}"))
            .used_ports
    }

    /// The reap returns the pool port. Fail-on-revert: delete the
    /// `release_source_nat_allocation_for_worker` call in `reap_expired_sessions`
    /// and this goes RED — before #6901 that deletion left the crate green.
    #[test]
    fn gc_reap_releases_the_source_nat_pool_port_6901() {
        let mut forwarding = ForwardingState::default();
        forwarding.source_nat_rules =
            crate::nat::parse_source_nat_rules(&[rule_snapshot("pool-a", "lan", POOL_A)]);

        crate::nat::reserve_synced_source_nat_allocation(
            &forwarding.iface_nat_allocators,
            &forwarding.source_nat_rules,
            &key_for(1111),
            nat_for(POOL_A, 40000),
            false,
            None,
            0,
        );
        assert_eq!(
            used(&forwarding, "pool-a"),
            1,
            "precondition: the translated flow must hold one pool port, or the \
             assertion below passes against a pool that was never allocated from",
        );

        reap_expired_sessions(
            &mut [],
            &[expired_for(1111, POOL_A, 40000)],
            &forwarding,
            SteeringMap::unshared_for_test(-1),
            -1,
            -1,
            1_000_000_000,
            0,
        );

        assert_eq!(
            used(&forwarding, "pool-a"),
            0,
            "the GC reap must return the pool port. Without this the ordinary \
             inactivity teardown leaks one port per reaped translated session \
             until AllocatorExhausted (#6901)",
        );
    }

    /// It releases the port THIS session holds, not merely some port. A single
    /// pool cannot tell those apart: a release that freed the wrong allocator
    /// would still drive one count to zero.
    #[test]
    fn gc_reap_releases_only_the_reaped_flows_pool_6901() {
        let mut forwarding = ForwardingState::default();
        forwarding.source_nat_rules = crate::nat::parse_source_nat_rules(&[
            rule_snapshot("pool-a", "lan", POOL_A),
            rule_snapshot("pool-b", "dmz", POOL_B),
        ]);

        for (key_port, pool, snat_port) in [(1111u16, POOL_A, 40000u16), (2222, POOL_B, 40001)] {
            crate::nat::reserve_synced_source_nat_allocation(
                &forwarding.iface_nat_allocators,
                &forwarding.source_nat_rules,
                &key_for(key_port),
                nat_for(pool, snat_port),
                false,
                None,
                0,
            );
        }
        assert_eq!(
            (used(&forwarding, "pool-a"), used(&forwarding, "pool-b")),
            (1, 1),
            "precondition: both pools hold one port",
        );

        // Reap ONLY the pool-a flow.
        reap_expired_sessions(
            &mut [],
            &[expired_for(1111, POOL_A, 40000)],
            &forwarding,
            SteeringMap::unshared_for_test(-1),
            -1,
            -1,
            1_000_000_000,
            0,
        );

        assert_eq!(
            used(&forwarding, "pool-a"),
            0,
            "the reaped flow's own pool must be released",
        );
        assert_eq!(
            used(&forwarding, "pool-b"),
            1,
            "the OTHER pool must be untouched — a release that freed by count \
             rather than by the reaped flow's own (pool, port) would free a \
             port another live session is still forwarding through",
        );
    }
}

mod gc_reap_nat64_release_tests_7740 {
    //! #7740: the GC reap's `release_nat64_allocation_for_worker` call is
    //! UNBOUND — the sibling of the source-NAT release #6901 bound, two lines
    //! below it in the same loop. Measured: neutering it leaves the crate green
    //! at the full collection.
    //!
    //! There ARE NAT64 release tests (`nat64_tests.rs`), but they call
    //! `release_nat64_allocation` DIRECTLY. The function is bound; its reap
    //! call site is not — which is the same shape as #6901 in a different
    //! allocator, and the reason "the function has tests" is not an answer to
    //! "the call site is unbound".
    //!
    //! TWO cells, mirroring #6901: that the reap releases at all, and that it
    //! releases the allocation THIS session holds. The second is what a
    //! single-flow fixture cannot see.
    use super::*;
    use crate::nat64::Nat64State;
    use crate::session::{ExpiredSession, SessionDecision, SessionKey, SessionOrigin};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    const DST_V4: Ipv4Addr = Ipv4Addr::new(8, 8, 8, 8);

    fn prefix() -> crate::NAT64RuleSnapshot {
        crate::NAT64RuleSnapshot {
            name: "nat64-single".to_string(),
            prefix: "64:ff9b::/96".to_string(),
            // One address, so only the translated PORT can disambiguate two
            // flows — which is what makes the second cell meaningful.
            pool_addresses: vec!["198.51.100.1".to_string()],
            no_v6_frag_header: false,
            ..Default::default()
        }
    }

    fn client(n: u16) -> Ipv6Addr {
        format!("2001:db8::{n}").parse().unwrap()
    }

    fn key_for(c: Ipv6Addr, src_port: u16) -> SessionKey {
        SessionKey {
            addr_family: libc::AF_INET6 as u8,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V6(c),
            dst_ip: IpAddr::V6("64:ff9b::0808:0808".parse().unwrap()),
            src_port,
            dst_port: 443,
            discriminator: Default::default(),
            routing_domain: 0,
        }
    }

    fn metadata() -> crate::session::SessionMetadata {
        crate::session::SessionMetadata {
            ingress_zone: 1,
            egress_zone: 2,
            ingress_zone_check: 0,
            egress_zone_check: 0,
            ingress_ifindex: 0,
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
        }
    }

    fn expired(key: SessionKey, nat: crate::nat::NatDecision) -> ExpiredSession {
        ExpiredSession {
            key,
            decision: SessionDecision {
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
                    route_mtu: 0,
                    transport_route_mtu: 0,
                },
                nat,
                install_table_domain: 0,
                install_table_check: 0,
            },
            metadata: metadata(),
            session_id: 0,
            close_class: 0,
            install_epoch: 0,
            origin: SessionOrigin::ForwardFlow,
            overflow_close: None,
        }
    }

    fn reap(forwarding: &ForwardingState, entries: &[ExpiredSession]) {
        reap_expired_sessions(
            &mut [],
            entries,
            forwarding,
            SteeringMap::unshared_for_test(-1),
            -1,
            -1,
            1_000_000_000,
            0,
        );
    }

    /// The reap returns the NAT64 translated port. The observable is the one
    /// `nat64_4381_release_untracks_flow` already uses: while the flow is live
    /// a re-allocation is IDEMPOTENT, and after release a fresh port is issued.
    ///
    /// Fail-on-revert: neuter `release_nat64_allocation_for_worker` in
    /// `reap_expired_sessions` and this goes RED — before #7740 that left the
    /// crate green.
    #[test]
    fn gc_reap_releases_the_nat64_allocation_7740() {
        let mut forwarding = ForwardingState::default();
        forwarding.nat64 = Nat64State::from_snapshots(&[prefix()]);
        let c = client(1);

        let (snat, port) = forwarding
            .nat64
            .allocate_source(0, PROTO_TCP, c, DST_V4, 5000, 443, 1)
            .expect("allocate");
        assert_eq!(
            forwarding
                .nat64
                .allocate_source(0, PROTO_TCP, c, DST_V4, 5000, 443, 1)
                .expect("re-allocate"),
            (snat, port),
            "precondition: while live the mapping is idempotent, so a DIFFERENT \
             port after the reap is the release and nothing else",
        );

        reap(
            &forwarding,
            &[expired(
                key_for(c, 5000),
                Nat64State::forward_decision(snat, DST_V4, port),
            )],
        );

        let (snat2, port2) = forwarding
            .nat64
            .allocate_source(0, PROTO_TCP, c, DST_V4, 5000, 443, 3)
            .expect("post-reap allocate");
        assert_eq!(snat2, snat, "same one-address pool");
        assert_ne!(
            port2, port,
            "the GC reap must release the NAT64 translated port. An idempotent \
             re-allocation means the flow is still live — the reaped session \
             leaked its port (#7740)",
        );
    }

    /// It releases the allocation THIS session holds. With a one-address pool
    /// only the port disambiguates, so a release that freed by count — or freed
    /// the wrong flow — would still let the first cell pass.
    #[test]
    fn gc_reap_releases_only_the_reaped_nat64_flow_7740() {
        let mut forwarding = ForwardingState::default();
        forwarding.nat64 = Nat64State::from_snapshots(&[prefix()]);
        let (c1, c2) = (client(1), client(2));

        let (snat1, port1) = forwarding
            .nat64
            .allocate_source(0, PROTO_TCP, c1, DST_V4, 5000, 443, 1)
            .expect("allocate c1");
        let (snat2, port2) = forwarding
            .nat64
            .allocate_source(0, PROTO_TCP, c2, DST_V4, 5001, 443, 1)
            .expect("allocate c2");
        assert_ne!(
            port1, port2,
            "precondition: two live flows hold two distinct translated ports",
        );

        // Reap ONLY the first flow.
        reap(
            &forwarding,
            &[expired(
                key_for(c1, 5000),
                Nat64State::forward_decision(snat1, DST_V4, port1),
            )],
        );

        let fresh1 = forwarding
            .nat64
            .allocate_source(0, PROTO_TCP, c1, DST_V4, 5000, 443, 3)
            .expect("post-reap allocate c1");
        assert_ne!(
            fresh1.1, port1,
            "the reaped flow's own allocation must be released",
        );

        let still2 = forwarding
            .nat64
            .allocate_source(0, PROTO_TCP, c2, DST_V4, 5001, 443, 3)
            .expect("allocate c2 again");
        assert_eq!(
            still2,
            (snat2, port2),
            "the OTHER flow must still be live and idempotent — a release keyed \
             on anything but the reaped flow's own (client, port) would free a \
             translation another live session is still forwarding through",
        );
    }

    mod loop_body_modularity_13075_tests {
        //! #13075 (D4-12) regression guard: `loop_body/mod.rs` must stay below
        //! the 2,000-LOC `[REFACTOR]` ceiling in docs/refactoring-audit.md.
        //! This test reads the production file (not this test file) from disk,
        //! so reverting the reconcile/gc_teardown/tests extraction — pasting
        //! the ~2,200 moved lines back into mod.rs — turns it RED, while the
        //! split tree stays GREEN. Source-reading is the only seam for a
        //! file-size invariant (the #7201/#9720 pattern in worker_queue_tests).

        #[test]
        fn loop_body_mod_stays_below_refactor_ceiling() {
            let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("src/afxdp/worker/loop_body/mod.rs");
            let src = std::fs::read_to_string(&path).expect("read loop_body/mod.rs");
            let loc = src.lines().count();
            assert!(
                loc < 2000,
                "loop_body/mod.rs is {loc} LOC, at/above the 2,000-LOC [REFACTOR] \
             ceiling (docs/refactoring-audit.md); move cold code into \
             loop_body/reconcile.rs or loop_body/gc_teardown.rs and tests \
             into loop_body/tests.rs instead of growing mod.rs (#13075)"
            );
            // The extraction targets must exist and actually hold the moved
            // code — an empty sibling that silences the count by deleting the
            // reconciliation/GC helpers would fail here (and fail to compile).
            for sibling in ["reconcile.rs", "gc_teardown.rs"] {
                let sibling_path = path.with_file_name(sibling);
                let body = std::fs::read_to_string(&sibling_path)
                    .unwrap_or_else(|e| panic!("read {sibling}: {e}"));
                assert!(
                    body.lines().count() > 100,
                    "{sibling} is suspiciously small ({} LOC); the #13075 split \
                 must move the cold helpers there, not delete them",
                    body.lines().count()
                );
            }
            assert!(
                src.contains("mod reconcile;") && src.contains("mod gc_teardown;"),
                "loop_body/mod.rs no longer declares the #13075 reconcile / \
             gc_teardown split; worker_loop would lose its cold helpers"
            );
        }
    }
}
