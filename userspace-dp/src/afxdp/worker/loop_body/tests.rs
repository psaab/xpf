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
    use std::sync::atomic::AtomicU32;

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
        SessionMetadata { forward_wire_alias_origin: false, ingress_zone: 1,
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
        nat_scope_ifindex: None, }
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
            source_ifindex: 0,
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
            cluster_terminal_source_ifindex: 0,
            cluster_terminal_stamp_owner_rg: 0,
            observed_bytes: 0,
            last_used_epoch: 0,
            neighbor_mac_epoch: 0,
            // #5147: no dynamic-neighbor dependency in this test entry.
            neighbor_shard: crate::afxdp::flow_cache::NEIGHBOR_SHARD_NONE,
            fabric_established: false,
            dest_owner_memo: Default::default(),
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
        persistent_lease_hold: None,
            origin: SessionOrigin::ForwardFlow,
            session_id: 0,
            close_class: 0,
            install_epoch: 0,
            overflow_close: None,
        }
    }

    fn expired_replica(key: SessionKey, session_id: u64) -> ExpiredSession {
        ExpiredSession {
            origin: SessionOrigin::WorkerLocalImport,
            session_id,
            ..expired(key, None)
        }
    }

    fn serving_shared_entry(key: &SessionKey, session_id: u64) -> SyncedSessionEntry {
        SyncedSessionEntry { sibling_last_seen_ns: 0, key: key.clone(),
        decision: reap_decision(None),
        metadata: reap_metadata(),
        persistent_lease_hold: None,
        source_nat_static: None,
        leak_incarnation: 0,
        origin: SessionOrigin::ForwardFlow,
        protocol: PROTO_TCP,
        tcp_flags: 0,
        generation: 0,
        session_id,
        tcp_close_class: 0, tcp_handshake_state: crate::session::TcpHandshakeState::Established.to_wire(), rev_packets: 0u64, fwd_packets: 0, pptp_call_ids: 0, }
    }

    // #18742 F1 (seat L): a LIVE flow's established SyncImport replica on a
    // worker that serves neither direction must never reach the replica
    // teardown, which (unfenced for SyncImport) deletes the conntrack mirror
    // row (`delete_session_map_entry_for_removed_session_with_origin_and_id`)
    // and evicts the flow-cache descriptor under the live flow. Asserted
    // DIRECTLY on the mirror row through the hermetic conntrack test map
    // (`CONNTRACK_TEST_MAP_FD`: publish inserts, the teardown's delete
    // removes), and on the descriptor as a second observable. The serving
    // worker's ct-slice restamps the shared row (production
    // `restamp_shared_packet_counts_batch`) and the expiry pass reads it
    // through the production closure (`shared_node_served_evidence`).
    // Control in the same cell: once the restamps stop, the dead replica
    // expires and the teardown DOES delete the mirror row and evict the
    // descriptor, so both observables can see a teardown. RED at 1981f3299e
    // (the replica reaps at window 1 while live).
    #[test]
    fn live_flow_replica_never_reaches_teardown_18722() {
        const SEC: u64 = 1_000_000_000;
        let rg_epochs = reap_rg_epochs();
        let forwarding = ForwardingState::default();
        let key = reap_key(40100);
        let reverse = crate::session::reverse_session_key(&key, NatDecision::default());
        let t0 = 1_000 * SEC;
        let mut table = crate::session::SessionTable::new();
        for (k, is_reverse, id) in [(&key, false, 0x4_8722u64), (&reverse, true, 0x5_8722u64)] {
            let mut metadata = reap_metadata();
            metadata.is_reverse = is_reverse;
            assert!(table.upsert_synced_with_origin(
                crate::session::SessionInstall {
                    key: k.clone(),
                    decision: reap_decision(None),
                    metadata,
                    source_nat_static: None,
                    origin: SessionOrigin::SyncImport,
                    now_ns: t0,
                    protocol: PROTO_TCP,
                    tcp_flags: 0,
                    session_id: id,
                    tcp_close_class: 0,
                    tcp_handshake_state: crate::session::TcpHandshakeState::Established.to_wire(),
                    persistent_lease_hold: None,
                    fwd_packets: 0,
                    rev_packets: 0,
                },
                false,
            ));
        }
        let window = 1_800 * SEC;
        assert_eq!(table.timeout_secs_for(&key), 1_800, "premise: established replica");
        let mut binding = BindingWorker::new_for_mirror_test(0, 0, REAP_INGRESS_IF, 0);
        insert_cache_entry(&mut binding, &key, None);
        assert!(cache_hits(&mut binding, &key, &rg_epochs), "premise: descriptor cached");
        // The replica's conntrack mirror row, as its import publishes it.
        let ct = crate::afxdp::bpf_map::CONNTRACK_TEST_MAP_FD;
        crate::afxdp::bpf_map::clear_conntrack_rows_for_test();
        assert_eq!(
            crate::afxdp::bpf_map::publish_bpf_conntrack_entry_with_source_nat(
                ct,
                ct,
                &key,
                reap_decision(None),
                &reap_metadata(),
                &FastMap::default(),
                0,
                0,
                0x4_8722,
                1_800,
                SessionOrigin::SyncImport,
                None,
            ),
            crate::afxdp::bpf_map::ConntrackPublishResult::Written,
            "premise: the replica's mirror row is published"
        );
        let mirror_row = || crate::afxdp::bpf_map::conntrack_row_for_test(&key).is_some();
        assert!(mirror_row(), "premise: the mirror row exists");
        let shared = std::sync::Arc::new(std::sync::Mutex::new(FastMap::default()));
        let nat_aliases = std::sync::Arc::new(std::sync::Mutex::new(FastMap::default()));
        let wires = std::sync::Arc::new(std::sync::Mutex::new(FastMap::default()));
        let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
        crate::afxdp::shared_ops::publish_shared_session(
            &shared,
            &nat_aliases,
            &wires,
            &shared_owner_rg_indexes,
            &serving_shared_entry(&key, 0x4_8722),
        );
        let node_served = |k: &SessionKey| {
            crate::afxdp::shared_ops::shared_node_served_evidence(
                &shared,
                &shared_owner_rg_indexes,
                k,
            )
        };
        let forwards = |_: i32| true;
        let epoch = |_: i32| 0u32;
        let ha = crate::session::ExpireHaContext {
            node_active: true,
            forwards_rg: &forwards,
            epoch_of: &epoch,
            ceiling_mult: crate::session::STALE_SYNCED_CEILING_MULT,
            ceiling_abs_ns: crate::session::STALE_SYNCED_CEILING_ABS_NS,
            node_served: &node_served,
        };
        let gc = |table: &mut crate::session::SessionTable,
                      binding: &mut BindingWorker,
                      now: u64|
         -> bool {
            let expired = table.expire_stale_entries_ha(now, Some(&ha));
            let hit = expired.iter().any(|e| e.key == key || e.key == reverse);
            reap_expired_sessions(
                std::slice::from_mut(binding),
                &expired,
                &forwarding,
                SteeringMap::unshared_for_test(-1),
                ct,
                ct,
                now,
                0,
                &shared,
            );
            hit
        };
        // Live: the serving worker forwards; its ct-slice restamps every 10 s.
        let live_until = t0 + 3 * window;
        let mut now = t0;
        while now < live_until {
            now += SEC;
            if (now - t0) % (10 * SEC) == 0 {
                let n = (now - t0) / SEC;
                crate::afxdp::shared_ops::restamp_shared_packet_counts_batch(
                    &shared,
                    &wires,
                    table.session_id_namespace(),
                    &[(
                        key.clone(),
                        NatDecision::default(),
                        10 * n,
                        10 * n,
                        now,
                    )],
                );
            }
            assert!(
                !gc(&mut table, &mut binding, now),
                "#18742 F1: the live flow's replica reached teardown at +{} s",
                (now - t0) / SEC
            );
        }
        assert!(
            mirror_row(),
            "#18742 F1: the live flow's conntrack mirror row must survive (show security flow session)"
        );
        assert!(
            cache_hits(&mut binding, &key, &rg_epochs),
            "#18742 F1: the live flow's flow-cache descriptor must survive"
        );
        // Control: the flow dies (no more restamps); the replica now expires
        // and the teardown evicts the descriptor.
        let mut reaped = false;
        while now < live_until + 3 * window && !reaped {
            now += SEC;
            reaped = gc(&mut table, &mut binding, now);
        }
        assert!(reaped, "control: the dead replica must expire");
        assert!(
            !mirror_row(),
            "control: the replica teardown deletes the mirror row, so the live half above can see one"
        );
        assert!(
            !cache_hits(&mut binding, &key, &rg_epochs),
            "control: the replica teardown evicts the descriptor"
        );
    }

    /// #18742 Cycle 3: A's local pair has a 5 s window and a high counter
    /// baseline; RSS moves service to B, whose shared counters stay max-only
    /// below A's baseline. B's packet timestamp must retain A through multiple
    /// crossed checks, then a frozen timestamp must age out and reap A.
    /// RED without sibling packet-timestamp evidence: check 1 reaped A.
    #[test]
    fn rss_moved_completed_local_row_preserves_sibling_mirror_18722() {
        const SEC: u64 = 1_000_000_000;
        let rg_epochs = reap_rg_epochs();
        let forwarding = ForwardingState::default();
        let key = reap_key(40101);
        let reverse = crate::session::reverse_session_key(&key, NatDecision::default());
        let t0 = 1_000 * SEC;

        // Worker A owns a high local baseline. Worker B can serve packets
        // without catching that cumulative max, so liveness must follow the
        // serving worker's source timestamp rather than the shared total.
        let mut table_a = crate::session::SessionTable::new();
        table_a.set_session_id_namespace(0, 0);
        let mut short_timeouts = crate::session::SessionTimeouts::default();
        short_timeouts.tcp_established_ns = 5 * SEC;
        table_a.set_timeouts(short_timeouts);
        assert!(table_a.install_with_protocol_with_origin(
            key.clone(),
            reap_decision(None),
            reap_metadata(),
            SessionOrigin::ForwardFlow,
            t0,
            PROTO_TCP,
            crate::tcp_flags::TCP_ACK,
        ));
        let mut reverse_metadata = reap_metadata();
        reverse_metadata.is_reverse = true;
        assert!(table_a.install_with_protocol_with_origin(
            reverse.clone(),
            reap_decision(None),
            reverse_metadata.clone(),
            SessionOrigin::ReverseFlow,
            t0,
            PROTO_TCP,
            crate::tcp_flags::TCP_ACK,
        ));
        for _ in 0..100 {
            table_a.account_packet(&key, 64, crate::tcp_flags::TCP_ACK, 0);
            table_a.account_packet(&reverse, 64, crate::tcp_flags::TCP_ACK, 0);
        }
        let session_id = table_a.session_id_for(&key);
        let reverse_id = table_a.session_id_for(&reverse);
        assert_ne!(session_id, 0, "premise: A owns a stable session id");

        // Worker B adopts the same forward incarnation and serves packets.
        let mut table_b = crate::session::SessionTable::new();
        table_b.set_session_id_namespace(0, 1);
        for (k, metadata, id) in [
            (&key, reap_metadata(), session_id),
            (&reverse, reverse_metadata, reverse_id),
        ] {
            assert!(table_b.upsert_synced_with_origin(
                crate::session::SessionInstall {
                    key: k.clone(),
                    decision: reap_decision(None),
                    metadata,
                    source_nat_static: None,
                    origin: SessionOrigin::SyncImport,
                    now_ns: t0,
                    protocol: PROTO_TCP,
                    tcp_flags: crate::tcp_flags::TCP_ACK,
                    session_id: id,
                    tcp_close_class: 0,
                    tcp_handshake_state: crate::session::TcpHandshakeState::Established
                        .to_wire(),
                    persistent_lease_hold: None,
                    fwd_packets: 0,
                    rev_packets: 0,
                },
                false,
            ));
        }
        assert!(
            table_b
                .lookup(&key, t0 + SEC, crate::tcp_flags::TCP_ACK)
                .is_some(),
            "premise: B serves the active row"
        );
        table_b.account_packet(&key, 64, crate::tcp_flags::TCP_ACK, 0);
        assert!(
            table_b
                .lookup(&reverse, t0 + 2 * SEC, crate::tcp_flags::TCP_ACK)
                .is_some(),
            "premise: B serves the reverse direction too"
        );
        table_b.account_packet(&reverse, 64, crate::tcp_flags::TCP_ACK, 0);
        let shared = std::sync::Arc::new(std::sync::Mutex::new(FastMap::default()));
        let nat_aliases = std::sync::Arc::new(std::sync::Mutex::new(FastMap::default()));
        let wires = std::sync::Arc::new(std::sync::Mutex::new(FastMap::default()));
        let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
        crate::afxdp::shared_ops::publish_shared_session(
            &shared,
            &nat_aliases,
            &wires,
            &shared_owner_rg_indexes,
            &serving_shared_entry(&key, session_id),
        );
        crate::afxdp::shared_ops::restamp_shared_packet_counts_batch(
            &shared,
            &wires,
            table_a.session_id_namespace(),
            &[(
                key.clone(),
                NatDecision::default(),
                table_a.fwd_packets_for(&key),
                table_a.rev_packets_for(&key),
                table_a.packet_counts_and_last_packet_seen_for(&key).2,
            )],
        );
        crate::afxdp::shared_ops::restamp_shared_packet_counts_batch(
            &shared,
            &wires,
            table_b.session_id_namespace(),
            &[(
                key.clone(),
                NatDecision::default(),
                table_b.fwd_packets_for(&key),
                table_b.rev_packets_for(&key),
                table_b.packet_counts_and_last_packet_seen_for(&key).2,
            )],
        );
        assert!(
            crate::afxdp::shared_ops::shared_node_served_evidence(
                &shared,
                &shared_owner_rg_indexes,
                &key,
            )
                .shared_served
                .is_some_and(|count| count > 0),
            "premise: B's serving counters are visible in shared evidence"
        );
        let served = crate::afxdp::shared_ops::shared_node_served_evidence(
            &shared,
            &shared_owner_rg_indexes,
            &key,
        );
        assert_eq!(
            served.shared_incarnation,
            Some((session_id, 0)),
            "premise: shared row names A's exact incarnation"
        );
        assert_eq!(
            served.shared_sibling_last_seen_ns,
            Some(t0 + 2 * SEC),
            "premise: the latest packet timestamp from either half is exposed in shared evidence"
        );
        let shared_total = {
            let sessions = shared.lock().unwrap();
            let entry = sessions.get(&key).expect("premise: shared forward row");
            entry.fwd_packets.saturating_add(entry.rev_packets)
        };
        let b_total = table_b
            .fwd_packets_for(&key)
            .saturating_add(table_b.rev_packets_for(&key));
        assert!(
            shared_total > b_total,
            "premise: shared high-water count {shared_total} exceeds B's {b_total}"
        );

        let node_served = |k: &SessionKey| {
            let mut evidence = crate::afxdp::shared_ops::shared_node_served_evidence(
                &shared,
                &shared_owner_rg_indexes,
                k,
            );
            evidence.shared_evidence_max_cadence_ns = Some(30 * SEC);
            evidence
        };
        let forwards = |_: i32| true;
        let epoch = |_: i32| 0u32;
        let ha = crate::session::ExpireHaContext {
            node_active: true,
            forwards_rg: &forwards,
            epoch_of: &epoch,
            ceiling_mult: crate::session::STALE_SYNCED_CEILING_MULT,
            ceiling_abs_ns: crate::session::STALE_SYNCED_CEILING_ABS_NS,
            node_served: &node_served,
        };

        let mut binding = BindingWorker::new_for_mirror_test(0, 0, REAP_INGRESS_IF, 0);
        insert_cache_entry(&mut binding, &key, None);
        assert!(cache_hits(&mut binding, &key, &rg_epochs), "premise: A has a cached descriptor");
        let ct = crate::afxdp::bpf_map::CONNTRACK_TEST_MAP_FD;
        crate::afxdp::bpf_map::clear_conntrack_rows_for_test();
        assert_eq!(
            crate::afxdp::bpf_map::publish_bpf_conntrack_entry_with_source_nat(
                ct,
                ct,
                &key,
                reap_decision(None),
                &reap_metadata(),
                &FastMap::default(),
                0,
                0,
                session_id,
                1_800,
                SessionOrigin::ForwardFlow,
                None,
            ),
            crate::afxdp::bpf_map::ConntrackPublishResult::Written,
            "premise: the sibling's live mirror row is published"
        );
        let mirror_row = || crate::afxdp::bpf_map::conntrack_row_for_test(&key).is_some();
        assert!(mirror_row(), "premise: B's mirror row exists");

        let window = table_a.timeout_secs_for(&key) as u64 * SEC;
        assert_eq!(window, 5 * SEC, "premise: A uses the short configured window");
        let check_step = window + SEC;
        let mut now = t0 + check_step;
        for check in 1..=4 {
            // Shared evidence remains at B's first restamp for four crossed
            // checks while B continues to serve locally.
            let expired = table_a.expire_stale_entries_ha(now, Some(&ha));
            let reaped_flow = expired.iter().any(|entry| entry.key == key || entry.key == reverse);
            reap_expired_sessions(
                std::slice::from_mut(&mut binding),
                &expired,
                &forwarding,
                SteeringMap::unshared_for_test(-1),
                ct,
                ct,
                now,
                0,
                &shared,
            );
            let descriptor_live = cache_hits(&mut binding, &key, &rg_epochs);
            assert!(
                !reaped_flow
                    && table_a.session_id_for(&key) == session_id
                    && table_a.session_id_for(&reverse) == reverse_id
                    && mirror_row()
                    && descriptor_live
                    && table_b.session_id_for(&key) == session_id,
                "#18742: check={check} reaped={reaped_flow}, mirror={}, descriptor={descriptor_live}, \
                 B-live={}; matching shared activity must cover crossed checks within its cadence",
                mirror_row(),
                table_b.session_id_for(&key) == session_id
            );
            assert!(
                table_b
                    .lookup(&key, now, crate::tcp_flags::TCP_ACK)
                    .is_some(),
                "premise: B continues serving"
            );
            table_b.account_packet(&key, 64, crate::tcp_flags::TCP_ACK, 0);
            now += check_step;
        }

        // B's next production-style restamp advances the shared count after
        // the intervening expiry checks; A must observe and retain on it.
        crate::afxdp::shared_ops::restamp_shared_packet_counts_batch(
            &shared,
            &wires,
            table_b.session_id_namespace(),
            &[(
                key.clone(),
                NatDecision::default(),
                table_b.fwd_packets_for(&key),
                table_b.rev_packets_for(&key),
                table_b.packet_counts_and_last_packet_seen_for(&key).2,
            )],
        );
        let expired = table_a.expire_stale_entries_ha(now, Some(&ha));
        let reaped_flow = expired.iter().any(|entry| entry.key == key || entry.key == reverse);
        reap_expired_sessions(
            std::slice::from_mut(&mut binding),
            &expired,
            &forwarding,
            SteeringMap::unshared_for_test(-1),
            ct,
            ct,
            now,
            0,
            &shared,
        );
        let descriptor_live = cache_hits(&mut binding, &key, &rg_epochs);
        assert!(
            !reaped_flow
                && table_a.session_id_for(&key) == session_id
                && table_a.session_id_for(&reverse) == reverse_id
                && mirror_row()
                && descriptor_live
                && table_b.session_id_for(&key) == session_id,
            "#18742: restamped sibling count reaped={reaped_flow}, mirror={}, \
             descriptor={descriptor_live}, B-live={}; the next shared advance must retain A's row",
            mirror_row(),
            table_b.session_id_for(&key) == session_id
        );

        // Once B stops restamping, the frozen matching evidence is bounded by
        // its cadence. A eventually reaps and its GC removes the stale mirror.
        let cadence = 30 * SEC;
        let idle_checks = (cadence / check_step + 2) as usize;
        let mut reaped_when_idle = false;
        for _ in 0..idle_checks {
            now += check_step;
            let expired = table_a.expire_stale_entries_ha(now, Some(&ha));
            let reaped_flow = expired.iter().any(|entry| entry.key == key || entry.key == reverse);
            reap_expired_sessions(
                std::slice::from_mut(&mut binding),
                &expired,
                &forwarding,
                SteeringMap::unshared_for_test(-1),
                ct,
                ct,
                now,
                0,
                &shared,
            );
            if reaped_flow {
                reaped_when_idle = true;
                break;
            }
        }
        assert!(
            reaped_when_idle
                && table_a.session_id_for(&key) == 0
                && table_a.session_id_for(&reverse) == 0
                && !mirror_row()
                && !cache_hits(&mut binding, &key, &rg_epochs),
            "#18742: frozen sibling evidence must eventually reap A's rows and mirror"
        );


    }
    // #16223/#17683: a WorkerLocalImport replica's expiry must NOT evict
    // the serving pair's cache or release its NAT state. Its own exact
    // persistent lease reference is still released while the serving entry's
    // reference remains counted. Control: with no serving entry, full teardown
    // is preserved.
    #[test]
    fn replica_expiry_does_not_evict_serving_cache_16223() {
        let rg_epochs = reap_rg_epochs();
        let mut forwarding = ForwardingState::default();
        let nat_now_ns = 1_000_000_000;
        let internal_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102));
        let remote_ip = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        forwarding.source_nat_rules =
            crate::nat::parse_source_nat_rules(&[crate::SourceNATRuleSnapshot {
                name: "reap-persistent-lease-16223".into(),
                from_zone: "lan".into(),
                to_zone: "wan".into(),
                source_addresses: vec!["0.0.0.0/0".into()],
                pool_name: "reap-persistent-lease-16223".into(),
                pool_addresses: vec!["203.0.113.10/32".into()],
                port_low: 40_000,
                port_high: 40_000,
                persistent_nat: true,
                persistent_nat_permit_any_remote_host: true,
                persistent_nat_inactivity_timeout: 1,
                ..crate::SourceNATRuleSnapshot::default()
            }]);
        let mut counter = None;
        let outbound_nat = match crate::nat::match_source_nat_result_for_tuple(
            &forwarding.iface_nat_allocators,
            &forwarding.source_nat_rules,
            &crate::nat::NatScopeCtx::default(),
            "lan",
            "wan",
            internal_ip,
            remote_ip,
            Some(crate::ip_proto::PROTO_TCP),
            41_001,
            443,
            None,
            None,
            nat_now_ns,
            false,
            false,
            crate::nat::NatHolder::Untracked,
            &mut counter,
        ) {
            crate::nat::SourceNatLookup::Matched(nat) => nat,
            other => panic!("persistent source NAT allocation failed: {other:?}"),
        };
        let translated_ip = outbound_nat.rewrite_src.expect("translated pool address");
        let translated_port = outbound_nat.rewrite_src_port.expect("translated pool port");
        let outbound_key = SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: crate::ip_proto::PROTO_TCP,
            src_ip: internal_ip,
            dst_ip: remote_ip,
            src_port: 41_001,
            dst_port: 443,
            discriminator: Default::default(),
            routing_domain: 0,
        };
        crate::nat::release_source_nat_allocation(
            &forwarding.iface_nat_allocators,
            &forwarding.source_nat_rules,
            &outbound_key,
            outbound_nat,
            false,
            nat_now_ns + 1,
        );
        let source_key = crate::nat::PersistentSourceKey {
            protocol: crate::ip_proto::PROTO_TCP,
            src_ip: internal_ip,
            src_port: 41_001,
            routing_scope: 0,
            remote: None,
        };
        let flow = crate::nat::SourceNatFlowKey {
            protocol: crate::ip_proto::PROTO_TCP,
            src_ip: internal_ip,
            dst_ip: remote_ip,
            src_port: 41_001,
            dst_port: 443,
            routing_scope: 0,
        };
        let allocator = &forwarding.source_nat_rules[0].pool_allocator;
        let serving_hold = allocator
            .acquire_persistent_inbound_with_hold(source_key, nat_now_ns + 2)
            .expect("serving session owns one lease reference");
        let replica_hold = allocator
            .acquire_persistent_inbound_with_hold(source_key, nat_now_ns + 2)
            .expect("local replica owns a separate lease reference");
        let inbound_flows = || {
            allocator
                .debug_persistent_lease_for_flow(
                    &flow,
                    crate::nat::PersistentNatPermit::AnyRemoteHost,
                )
                .map(|lease| lease.inbound_flows)
        };
        assert_eq!(inbound_flows(), Some(2), "owner and replica holds start counted");

        // This inbound tuple targets the persistent lease's translated endpoint.
        let key = SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: crate::ip_proto::PROTO_TCP,
            src_ip: remote_ip,
            dst_ip: translated_ip,
            src_port: 443,
            dst_port: translated_port,
            discriminator: Default::default(),
            routing_domain: 0,
        };

        // Fenced case: serving entry present in the shared map.
        let mut binding = BindingWorker::new_for_mirror_test(0, 0, REAP_INGRESS_IF, 0);
        insert_cache_entry(&mut binding, &key, None);
        assert!(cache_hits(&mut binding, &key, &rg_epochs));
        let shared = std::sync::Arc::new(std::sync::Mutex::new({
            let mut map = FastMap::default();
            let mut serving = serving_shared_entry(&key, 4242);
            serving.persistent_lease_hold = Some(serving_hold);
            map.insert(key.clone(), serving);
            map
        }));
        let mut expired = expired_replica(key.clone(), 4242);
        expired.persistent_lease_hold = Some(replica_hold);
        reap_expired_sessions(
            std::slice::from_mut(&mut binding),
            &[expired],
            &forwarding,
            SteeringMap::unshared_for_test(-1),
            -1,
            -1,
            nat_now_ns + 3,
            0,
            &shared,
        );
        assert!(
            cache_hits(&mut binding, &key, &rg_epochs),
            "#16223 B4: replica expiry must not evict the serving descriptor"
        );
        assert_eq!(
            inbound_flows(),
            Some(1),
            "#17683: fenced expiry releases only the local replica's exact reference"
        );

        // Control: no serving entry -> replica expiry tears down fully.
        let mut binding = BindingWorker::new_for_mirror_test(0, 0, REAP_INGRESS_IF, 0);
        insert_cache_entry(&mut binding, &key, None);
        assert!(cache_hits(&mut binding, &key, &rg_epochs));
        reap_expired_sessions(
            std::slice::from_mut(&mut binding),
            &[expired_replica(key.clone(), 4242)],
            &forwarding,
            SteeringMap::unshared_for_test(-1),
            -1,
            -1,
            nat_now_ns + 3,
            0,
            &std::sync::Arc::new(std::sync::Mutex::new(FastMap::default())),
        );
        assert!(
            !cache_hits(&mut binding, &key, &rg_epochs),
            "#16223 B4 control: unserved replica expiry must still evict"
        );
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
            &std::sync::Arc::new(std::sync::Mutex::new(FastMap::default())),
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
            &std::sync::Arc::new(std::sync::Mutex::new(FastMap::default())),
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
            &std::sync::Arc::new(std::sync::Mutex::new(FastMap::default())),
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

    // #18656 (review): the reap of a forward session with a translating
    // decision also evicts the slot keyed by its forward-WIRE tuple (the slot a
    // moved session's post-NAT fabric data seeds on the new owner). RED on
    // revert: the wire-keyed slot survives the reap.
    #[test]
    fn reap_also_evicts_the_forward_wire_slot_18656() {
        let rg_epochs = reap_rg_epochs();
        let forwarding = ForwardingState::default();
        let mut binding = BindingWorker::new_for_mirror_test(0, 0, REAP_INGRESS_IF, 0);
        let key = reap_key(34601);
        let wire = crate::session::forward_wire_key(&key, reap_decision(Some(41001)).nat);
        assert_ne!(wire, key, "fixture: SNAT moves the forward wire tuple");
        insert_cache_entry(&mut binding, &wire, Some(41001));
        assert!(cache_hits(&mut binding, &wire, &rg_epochs), "precondition: the wire-keyed slot hits");
        reap_expired_sessions(
            std::slice::from_mut(&mut binding),
            &[expired(key.clone(), Some(41001))],
            &forwarding,
            SteeringMap::unshared_for_test(-1),
            -1,
            -1,
            1_000_000_000,
            0,
            &std::sync::Arc::new(std::sync::Mutex::new(FastMap::default())),
        );
        assert!(
            !cache_hits(&mut binding, &wire, &rg_epochs),
            "the reaped session's forward-wire slot is evicted"
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
            &std::sync::Arc::new(std::sync::Mutex::new(FastMap::default())),
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
        use crate::afxdp::bpf_map::global_tuple_gate;
        use crate::afxdp::bpf_map::{
            CONNTRACK_TEST_MAP_FD, conntrack_row_for_test,
            publish_bpf_conntrack_entry_with_source_nat,
        };
        use crate::afxdp::worker::SyncedSessionEntry;
        use crate::session::SessionTable;
        use std::sync::{Arc, Mutex};

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
                &std::sync::Arc::new(std::sync::Mutex::new(FastMap::default())),
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
                SyncedSessionEntry { sibling_last_seen_ns: 0, key: key.clone(),
                decision: reap_decision(None),
                metadata: reap_metadata(),
                persistent_lease_hold: None,
                source_nat_static: None,
                leak_incarnation: 0,
                origin: SessionOrigin::ForwardFlow,
                protocol: PROTO_TCP,
                tcp_flags: crate::tcp_flags::TCP_ACK,
                generation: 0,
                session_id: 0,
                tcp_close_class: 0, tcp_handshake_state: 0, rev_packets: 0u64, fwd_packets: 0, pptp_call_ids: 0, },
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
            let shared_owner_rg_indexes =
                crate::afxdp::types::SharedSessionOwnerRgIndexes::default();
            crate::afxdp::worker::retry_deferred_conntrack_deletes(
                &mut sessions,
                CONNTRACK_TEST_MAP_FD,
                CONNTRACK_TEST_MAP_FD,
                &shared_sessions,
                &shared_owner_rg_indexes,
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
                &shared_owner_rg_indexes,
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

    // #16491: a poisoned shared_sessions mutex must be recovered, not
    // re-panicked, and a shared row in a different scope sharing the
    // bare tuple must still fence the delete (the kernel conntrack row
    // is keyed by bare tuple alone, and close_delta_is_stale_incarnation
    // treats has_other_scope as stale for the same reason).
    #[test]
    fn conntrack_retry_recovers_poison_and_other_scope_fences_16491() {
        use crate::afxdp::bpf_map::{
            CONNTRACK_TEST_MAP_FD, conntrack_row_for_test,
            publish_bpf_conntrack_entry_with_source_nat,
        };
        use crate::afxdp::types::SharedSessionOwnerRgIndexes;
        use crate::afxdp::worker::SyncedSessionEntry;
        use crate::session::SessionTable;
        use std::sync::{Arc, Mutex};

        crate::afxdp::bpf_map::clear_conntrack_rows_for_test();
        let key = reap_key(63001);
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
                72001,
                300,
                SessionOrigin::ForwardFlow,
                None,
            ),
            crate::afxdp::bpf_map::ConntrackPublishResult::Written
        );
        // Shared replacement lives in a DIFFERENT scope (routing_domain
        // 99) with a different session_id, sharing the bare tuple. The
        // kernel conntrack row is keyed by bare tuple alone, so this
        // fences the delete exactly as the pre-fix scan did (and as
        // close_delta_is_stale_incarnation's has_other_scope arm does).
        let mut other_scope_key = key.clone();
        other_scope_key.routing_domain = 99;
        let indexes = SharedSessionOwnerRgIndexes::default();
        {
            let mut idx = crate::afxdp::shared_ops::lock_shared_recover(
                &indexes.bare_tuple_sessions,
            );
            idx.insert(&other_scope_key);
        }
        let shared_sessions = Arc::new(Mutex::new({
            let mut map = FastMap::default();
            map.insert(
                other_scope_key.clone(),
                SyncedSessionEntry { sibling_last_seen_ns: 0, key: other_scope_key.clone(),
                decision: reap_decision(None),
                metadata: reap_metadata(),
                persistent_lease_hold: None,
                source_nat_static: None,
                leak_incarnation: 0,
                origin: SessionOrigin::ForwardFlow,
                protocol: PROTO_TCP,
                tcp_flags: crate::tcp_flags::TCP_ACK,
                generation: 0,
                session_id: 72002,
                tcp_close_class: 0, tcp_handshake_state: 0, rev_packets: 0u64, fwd_packets: 0, pptp_call_ids: 0, },
            );
            map
        }));
        // Poison the shared mutex the way a prior worker panic would.
        let poison_target = Arc::clone(&shared_sessions);
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = poison_target.lock().expect("test lock");
            panic!("poison shared_sessions for #16491 test");
        }));
        assert!(shared_sessions.lock().is_err(), "precondition: poisoned");
        let before = crate::afxdp::shared_ops::SHARED_SESSION_POISON_RECOVERIES
            .load(std::sync::atomic::Ordering::Relaxed);
        let mut sessions = SessionTable::new();
        sessions.defer_conntrack_delete(crate::session::DeferredConntrackDelete {
            key: key.clone(),
            session_id: 72001,
        });
        // Pre-fix this panics with "shared sessions poisoned".
        crate::afxdp::worker::retry_deferred_conntrack_deletes(
            &mut sessions,
            CONNTRACK_TEST_MAP_FD,
            CONNTRACK_TEST_MAP_FD,
            &shared_sessions,
            &indexes,
        );
        let after = crate::afxdp::shared_ops::SHARED_SESSION_POISON_RECOVERIES
            .load(std::sync::atomic::Ordering::Relaxed);
        assert!(after > before, "#16491: poison must be recovered and counted");
        assert_eq!(
            conntrack_row_for_test(&key).unwrap().session_id,
            72001,
            "#16491: other-scope shared row sharing the bare tuple must fence \
             the delete (kernel row is bare-tuple keyed)"
        );
        crate::afxdp::bpf_map::clear_conntrack_rows_for_test();
    }

    // #16491: an exact-scope shared replacement with a different
    // session_id must still fence the delete (no fail-open weakening),
    // and the check must stay O(1) as the shared map grows.
    #[test]
    fn conntrack_retry_exact_scope_replacement_still_fences_16491() {
        use crate::afxdp::bpf_map::{
            CONNTRACK_TEST_MAP_FD, conntrack_row_for_test,
            publish_bpf_conntrack_entry_with_source_nat,
        };
        use crate::afxdp::types::SharedSessionOwnerRgIndexes;
        use crate::afxdp::worker::SyncedSessionEntry;
        use crate::session::SessionTable;
        use std::sync::{Arc, Mutex};

        crate::afxdp::bpf_map::clear_conntrack_rows_for_test();
        let key = reap_key(63002);
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
                72011,
                300,
                SessionOrigin::ForwardFlow,
                None,
            ),
            crate::afxdp::bpf_map::ConntrackPublishResult::Written
        );
        let indexes = SharedSessionOwnerRgIndexes::default();
        {
            let mut idx = crate::afxdp::shared_ops::lock_shared_recover(
                &indexes.bare_tuple_sessions,
            );
            idx.insert(&key);
            // Grow the shared population: the fence verdict must not
            // depend on scanning these unrelated rows.
            for i in 0..2000u16 {
                idx.insert(&reap_key(40000u16.wrapping_add(i)));
            }
        }
        let shared_sessions = Arc::new(Mutex::new({
            let mut map = FastMap::default();
            for i in 0..2000u16 {
                let filler = reap_key(40000u16.wrapping_add(i));
                map.insert(
                    filler.clone(),
                    SyncedSessionEntry { sibling_last_seen_ns: 0, key: filler.clone(),
                    decision: reap_decision(None),
                    metadata: reap_metadata(),
                    persistent_lease_hold: None,
                    source_nat_static: None,
                    leak_incarnation: 0,
                    origin: SessionOrigin::ForwardFlow,
                    protocol: PROTO_TCP,
                    tcp_flags: crate::tcp_flags::TCP_ACK,
                    generation: 0,
                    session_id: 90000 + u64::from(i),
                    tcp_close_class: 0, tcp_handshake_state: 0, rev_packets: 0u64, fwd_packets: 0, pptp_call_ids: 0, },
                );
            }
            map.insert(
                key.clone(),
                SyncedSessionEntry { sibling_last_seen_ns: 0, key: key.clone(),
                decision: reap_decision(None),
                metadata: reap_metadata(),
                persistent_lease_hold: None,
                source_nat_static: None,
                leak_incarnation: 0,
                origin: SessionOrigin::ForwardFlow,
                protocol: PROTO_TCP,
                tcp_flags: crate::tcp_flags::TCP_ACK,
                generation: 0,
                session_id: 72012,
                tcp_close_class: 0, tcp_handshake_state: 0, rev_packets: 0u64, fwd_packets: 0, pptp_call_ids: 0, },
            );
            map
        }));
        let mut sessions = SessionTable::new();
        sessions.defer_conntrack_delete(crate::session::DeferredConntrackDelete {
            key: key.clone(),
            session_id: 72011,
        });
        crate::afxdp::worker::retry_deferred_conntrack_deletes(
            &mut sessions,
            CONNTRACK_TEST_MAP_FD,
            CONNTRACK_TEST_MAP_FD,
            &shared_sessions,
            &indexes,
        );
        assert_eq!(
            conntrack_row_for_test(&key).unwrap().session_id,
            72011,
            "#16491: exact-scope replacement must fence the delete (row survives)"
        );
        crate::afxdp::bpf_map::clear_conntrack_rows_for_test();
    }

    // ---- #18780: the #16223 replica fence as ONE shared-map pass per call ----

    fn udp_replica_key(i: u32) -> SessionKey {
        SessionKey {
            protocol: crate::ip_proto::PROTO_UDP,
            src_ip: IpAddr::V4(Ipv4Addr::from(0x0a3d_0000u32 + i)),
            src_port: 40_000,
            dst_port: 9,
            ..reap_key(0)
        }
    }

    fn shared_row(key: &SessionKey, session_id: u64, handshake_wire: u8) -> SyncedSessionEntry {
        SyncedSessionEntry {
            protocol: key.protocol,
            tcp_handshake_state: handshake_wire,
            ..serving_shared_entry(key, session_id)
        }
    }

    fn fence_rows_visited() -> u64 {
        super::super::gc_teardown::REPLICA_FENCE_ROWS_VISITED_18780.with(|c| c.get())
    }

    /// #18780: the reap of C WorkerLocalImport replicas against a shared map of
    /// N rows must read each shared row once per call (O(N + C)), not once per
    /// replica (O(N x C)). That per-replica scan under the node-global lock
    /// was the quadratic left on master after #18663: at T0+120 the authoring
    /// node's 5/6 WorkerLocalImport rows each scanned the whole map. UDP rows
    /// are never Established here, so `any()` never short-circuited.
    /// Decisions unchanged: none of these replicas has a serving Established
    /// row, so every one is torn down (its descriptor evicted).
    /// RED on master (with the test-only visit counter): C x N visits.
    #[test]
    fn replica_fence_reads_shared_map_once_per_reap_call_18780() {
        let rg_epochs = reap_rg_epochs();
        let forwarding = ForwardingState::default();
        let shared_rows = 512u32;
        let shared = std::sync::Arc::new(std::sync::Mutex::new({
            let mut map = FastMap::default();
            for i in 0..shared_rows {
                let key = udp_replica_key(10_000 + i);
                map.insert(key.clone(), shared_row(&key, 90_000 + u64::from(i), 0));
            }
            map
        }));
        for replicas in [64u32, 256] {
            let mut binding = BindingWorker::new_for_mirror_test(0, 0, REAP_INGRESS_IF, 0);
            let mut expired = Vec::new();
            for i in 0..replicas {
                let key = udp_replica_key(i);
                insert_cache_entry(&mut binding, &key, None);
                expired.push(expired_replica(key, 70_000 + u64::from(i)));
            }
            let before = fence_rows_visited();
            reap_expired_sessions(
                std::slice::from_mut(&mut binding),
                &expired,
                &forwarding,
                SteeringMap::unshared_for_test(-1),
                -1,
                -1,
                1_000_000_000,
                0,
                &shared,
            );
            let visited = fence_rows_visited() - before;
            assert!(
                visited <= u64::from(shared_rows),
                "#18780: {replicas} replica reaps read {visited} shared rows (map holds {shared_rows}); \
                 the fence must be one pass per call, not one per replica"
            );
            for e in &expired {
                assert!(
                    !cache_hits(&mut binding, &e.key, &rg_epochs),
                    "#18780: an unserved replica is still torn down"
                );
            }
        }
    }

    /// #18780 pin: a UDP shared row CAN carry the Established wire on master,
    /// through production code. The ct-slice collector
    /// (`SessionTable::established_forward_slice`) is protocol-blind: any
    /// forward row that is established, not pending, not closing and has
    /// `rev_packets > 0` (an answered UDP flow qualifies), and its keys feed
    /// `restamp_shared_handshakes_established`. Today's fence then matches a
    /// UDP WorkerLocalImport replica with the same session id and skips its
    /// teardown. The batched fence keeps that decision exactly, so a "skip the
    /// fence for non-TCP" shortcut reds here. Control: a different tuple is
    /// torn down.
    #[test]
    fn udp_shared_row_in_established_keeps_todays_fence_decision_18780() {
        let rg_epochs = reap_rg_epochs();
        let forwarding = ForwardingState::default();
        let key = udp_replica_key(7);
        let shared = std::sync::Arc::new(std::sync::Mutex::new({
            let mut map = FastMap::default();
            map.insert(key.clone(), shared_row(&key, 8_780, 0));
            map
        }));
        // The production chain, on a serving worker's table: an answered UDP
        // flow -> ct-slice collector -> shared Established restamp.
        let mut table = crate::session::SessionTable::new();
        let reverse = crate::session::reverse_session_key(&key, NatDecision::default());
        assert!(table.install_with_protocol(
            key.clone(),
            reap_decision(None),
            reap_metadata(),
            1_000_000_000,
            crate::ip_proto::PROTO_UDP,
            0,
        ));
        let mut reverse_md = reap_metadata();
        reverse_md.is_reverse = true;
        assert!(table.install_with_protocol(
            reverse.clone(),
            reap_decision(None),
            reverse_md,
            1_000_000_000,
            crate::ip_proto::PROTO_UDP,
            0,
        ));
        assert!(table.lookup(&reverse, 2_000_000_000, 0).is_some(), "premise: the reply hits");
        table.account_packet(&reverse, 100, 0, 0);
        let mut established = Vec::new();
        let _ = table.established_forward_slice(0, 64, &mut established);
        assert!(
            established.iter().any(|(k, _)| *k == key),
            "premise: the ct-slice collector takes an answered UDP forward row"
        );
        let _ = crate::afxdp::shared_ops::restamp_shared_handshakes_established(
            &shared,
            &established,
        );
        assert_eq!(
            shared.lock().unwrap().get(&key).map(|e| e.tcp_handshake_state),
            Some(crate::session::TcpHandshakeState::Established.to_wire()),
            "premise: the ct-slice restamp stamps the UDP shared row Established"
        );
        let other = udp_replica_key(8);
        let mut binding = BindingWorker::new_for_mirror_test(0, 0, REAP_INGRESS_IF, 0);
        insert_cache_entry(&mut binding, &key, None);
        insert_cache_entry(&mut binding, &other, None);
        // `other` has the same session id but its own tuple: no row matches.
        reap_expired_sessions(
            std::slice::from_mut(&mut binding),
            &[expired_replica(key.clone(), 8_780), expired_replica(other.clone(), 8_780)],
            &forwarding,
            SteeringMap::unshared_for_test(-1),
            -1,
            -1,
            1_000_000_000,
            0,
            &shared,
        );
        assert!(
            cache_hits(&mut binding, &key, &rg_epochs),
            "#18780: a UDP replica whose shared row is Established stays fenced (today's decision)"
        );
        assert!(
            !cache_hits(&mut binding, &other, &rg_epochs),
            "#18780 control: a replica with no matching row is torn down"
        );
    }

    /// #18780: the batched fence is the per-replica predicate, arm by arm, in
    /// ONE call: fenced iff origin is WorkerLocalImport, session id is nonzero
    /// and equal, the shared row is Established, and its stored key or its
    /// derived reverse key has the replica's bare tuple. Each negative row
    /// differs from a fenced one in exactly one arm.
    #[test]
    fn batched_fence_matches_the_per_replica_predicate_18780() {
        let rg_epochs = reap_rg_epochs();
        let forwarding = ForwardingState::default();
        let established = crate::session::TcpHandshakeState::Established.to_wire();
        let opening = crate::session::TcpHandshakeState::Opening.to_wire();
        let direct = reap_key(41_001);
        let alias_forward = reap_key(41_002);
        let alias = crate::session::reverse_session_key(&alias_forward, NatDecision::default());
        let opening_row = reap_key(41_003);
        let zero_id = reap_key(41_004);
        let not_replica = reap_key(41_005);
        let other_id = reap_key(41_006);
        // A shared row in another routing domain still matches: the fence
        // compares bare tuples (today's predicate, kept exactly).
        let other_domain_row = SessionKey {
            routing_domain: 9,
            ..reap_key(41_007)
        };
        let other_domain = reap_key(41_007);
        let shared = std::sync::Arc::new(std::sync::Mutex::new({
            let mut map = FastMap::default();
            map.insert(direct.clone(), shared_row(&direct, 1, established));
            map.insert(alias_forward.clone(), shared_row(&alias_forward, 2, established));
            map.insert(opening_row.clone(), shared_row(&opening_row, 3, opening));
            map.insert(zero_id.clone(), shared_row(&zero_id, 0, established));
            map.insert(not_replica.clone(), shared_row(&not_replica, 5, established));
            map.insert(other_id.clone(), shared_row(&other_id, 6, established));
            map.insert(
                other_domain_row.clone(),
                shared_row(&other_domain_row, 7, established),
            );
            map
        }));
        let cases: [(&SessionKey, ExpiredSession, bool, &str); 7] = [
            (&direct, expired_replica(direct.clone(), 1), true, "direct key"),
            (&alias, expired_replica(alias.clone(), 2), true, "derived reverse key"),
            (&opening_row, expired_replica(opening_row.clone(), 3), false, "row not Established"),
            (&zero_id, expired_replica(zero_id.clone(), 0), false, "session id 0"),
            (
                &not_replica,
                ExpiredSession {
                    session_id: 5,
                    ..expired(not_replica.clone(), None)
                },
                false,
                "not a WorkerLocalImport replica",
            ),
            (&other_id, expired_replica(other_id.clone(), 66), false, "different session id"),
            (&other_domain, expired_replica(other_domain.clone(), 7), true, "bare tuple across domains"),
        ];
        let mut binding = BindingWorker::new_for_mirror_test(0, 0, REAP_INGRESS_IF, 0);
        for (key, _, _, _) in &cases {
            insert_cache_entry(&mut binding, key, None);
        }
        let batch: Vec<ExpiredSession> = cases.iter().map(|(_, e, _, _)| e.clone()).collect();
        reap_expired_sessions(
            std::slice::from_mut(&mut binding),
            &batch,
            &forwarding,
            SteeringMap::unshared_for_test(-1),
            -1,
            -1,
            1_000_000_000,
            0,
            &shared,
        );
        for (key, _, fenced, arm) in &cases {
            assert_eq!(
                cache_hits(&mut binding, key, &rg_epochs),
                *fenced,
                "#18780: fence decision for `{arm}` must equal the per-replica predicate"
            );
        }
    }

    /// #18780 (R8 F1): the batched fence's MULTI-ROW accounting. In
    /// production both halves of a WorkerLocalImport replica carry the
    /// serving session's id and expire in the same tick, and
    /// `restamp_shared_handshakes_established` stamps BOTH shared rows
    /// Established. So one session id has two candidates, and each candidate
    /// is matched by two shared rows (directly, and through the other row's
    /// derived reverse key). Every replica must stay fenced:
    /// - both rows Established: the `fenced[idx]` skip keeps a candidate's
    ///   second match from decrementing `unresolved` again. Without it the
    ///   pass breaks once half the rows are visited and leaves the remaining
    ///   sessions' replicas to the full teardown (#16223). The candidate count
    ///   is EVEN on purpose: with an odd count the double decrement wraps
    ///   past zero (release has no overflow checks) and hides the defect.
    /// - forward row only: the reverse replica is matched only through the
    ///   forward row's derived reverse key, so every same-id candidate must
    ///   be considered, not only the first.
    /// Sessions are many (32) so FxHash visit order cannot happen to cover
    /// every session before an early break. A replica with no serving row is
    /// torn down in a separate call (its candidate would make the count odd).
    #[test]
    fn batched_fence_keeps_every_replica_of_paired_sessions_18780() {
        let rg_epochs = reap_rg_epochs();
        let forwarding = ForwardingState::default();
        let established = crate::session::TcpHandshakeState::Established.to_wire();
        const SESSIONS: u32 = 32;
        for both_rows_established in [true, false] {
            let mut map = FastMap::default();
            let mut batch = Vec::new();
            let mut binding = BindingWorker::new_for_mirror_test(0, 0, REAP_INGRESS_IF, 0);
            for s in 0..SESSIONS {
                let id = 50_000 + u64::from(s);
                let forward = udp_replica_key(20_000 + s);
                let reverse = crate::session::reverse_session_key(&forward, NatDecision::default());
                map.insert(forward.clone(), shared_row(&forward, id, established));
                let mut reverse_row = shared_row(
                    &reverse,
                    id,
                    if both_rows_established { established } else { 0 },
                );
                reverse_row.metadata.is_reverse = true;
                map.insert(reverse.clone(), reverse_row);
                for key in [&forward, &reverse] {
                    insert_cache_entry(&mut binding, key, None);
                    batch.push(expired_replica(key.clone(), id));
                }
            }
            assert_eq!(batch.len() % 2, 0, "premise: an even candidate count");
            let shared = std::sync::Arc::new(std::sync::Mutex::new(map));
            reap_expired_sessions(
                std::slice::from_mut(&mut binding),
                &batch,
                &forwarding,
                SteeringMap::unshared_for_test(-1),
                -1,
                -1,
                1_000_000_000,
                0,
                &shared,
            );
            let unfenced: Vec<String> = batch
                .iter()
                .filter(|e| !cache_hits(&mut binding, &e.key, &rg_epochs))
                .map(|e| format!("id {} {}", e.session_id, if e.key.src_port == 9 { "rev" } else { "fwd" }))
                .collect();
            assert!(
                unfenced.is_empty(),
                "#18780 (R8 F1, both rows Established = {both_rows_established}): {} of {} served \
                 replicas lost the #16223 fence and were torn down: {unfenced:?}",
                unfenced.len(),
                batch.len()
            );
            // Control, same shared map: a replica with no serving row is torn down.
            let orphan = udp_replica_key(29_999);
            insert_cache_entry(&mut binding, &orphan, None);
            reap_expired_sessions(
                std::slice::from_mut(&mut binding),
                &[expired_replica(orphan.clone(), 49_999)],
                &forwarding,
                SteeringMap::unshared_for_test(-1),
                -1,
                -1,
                1_000_000_000,
                0,
                &shared,
            );
            assert!(
                !cache_hits(&mut binding, &orphan, &rg_epochs),
                "#18780 control: an unserved replica is still torn down"
            );
        }
    }

    /// #18780 (R7 F1): a budget cut must never split a forward/reverse pair
    /// whose halves are both due in the pass. A reverse row owes no Close: its
    /// shared copy and steering rows are retired by the FORWARD's Close
    /// (`session_delta.rs`). Were the cut to fall between the halves, the
    /// reaped reverse would miss locally as `Absent` (not `IdleCrossed`) and
    /// `lookup_session_across_scopes_with_shared_and_payload` would resolve a
    /// reply through its still-published shared copy for the inter-call window,
    /// against #10419 (`housekeeping.rs`). Two hint orders, both legal
    /// (bucket order follows handle/touch order):
    /// - R7's: one lone row, then pairs with the reverse hint first, so the
    ///   256th reap lands on a reverse;
    /// - every reverse first, then every forward: a cut there strands 144
    ///   pairs at once.
    /// After EVERY call: no pair is left reverse-reaped / forward-present, every
    /// reaped reverse's forward was reaped and Closed in the SAME call, and one
    /// call reaps at most `2 * EXPIRY_PASS_MAX_REAPS` rows. The control: a
    /// split pair (the RED shape) resolves the reaped reverse through shared.
    /// RED at 956417850a (R7: exactly one split pair in the first order).
    #[test]
    fn budget_cut_never_splits_a_due_pair_18780() {
        use crate::session::SessionExpiryProbe as P;
        const SEC: u64 = 1_000_000_000;
        const PAIRS: u32 = 200;
        let t0 = 1_000 * SEC;
        let udp = crate::ip_proto::PROTO_UDP;
        for reverses_first in [false, true] {
            let mut table = crate::session::SessionTable::new();
            let mut reverse_md = reap_metadata();
            reverse_md.is_reverse = true;
            let pairs: Vec<(SessionKey, SessionKey)> = (0..PAIRS)
                .map(|i| {
                    let forward = udp_replica_key(i);
                    let reverse =
                        crate::session::reverse_session_key(&forward, NatDecision::default());
                    (forward, reverse)
                })
                .collect();
            let install = |table: &mut crate::session::SessionTable, key: &SessionKey, md| {
                assert!(table.install_with_protocol(key.clone(), reap_decision(None), md, t0, udp, 0));
            };
            if reverses_first {
                for (_, reverse) in &pairs {
                    install(&mut table, reverse, reverse_md.clone());
                }
                for (forward, _) in &pairs {
                    install(&mut table, forward, reap_metadata());
                }
            } else {
                install(&mut table, &udp_replica_key(900_000), reap_metadata());
                for (forward, reverse) in &pairs {
                    install(&mut table, reverse, reverse_md.clone());
                    install(&mut table, forward, reap_metadata());
                }
            }
            let _ = table.drain_deltas(usize::MAX);
            let _ = table.expire_stale_entries(t0);
            let now = t0 + 61 * SEC;
            let state = |t: &crate::session::SessionTable, k: &SessionKey| match t
                .probe_with_origin_expiry(k, now)
            {
                P::Live(_) => 'L',
                P::IdleCrossed => 'X',
                P::Absent => 'A',
            };
            let mut calls = 0u64;
            let mut cut_calls = 0usize;
            let mut completions = 0usize;
            loop {
                calls += 1;
                assert!(calls <= 16, "drain bound (order reverses_first={reverses_first})");
                let reaped = table.expire_stale_entries(now + calls * 1_000);
                let stats = table.last_pop_stats();
                cut_calls += stats.budget_cuts;
                completions += stats.pair_completions;
                assert!(
                    reaped.len() <= 2 * crate::session::EXPIRY_PASS_MAX_REAPS,
                    "#18780: call {calls} reaped {} rows (bound 2 x cap)",
                    reaped.len()
                );
                let closed: Vec<SessionKey> = table
                    .drain_deltas(usize::MAX)
                    .into_iter()
                    .filter(|d| d.kind == crate::session::SessionDeltaKind::Close)
                    .map(|d| d.key)
                    .collect();
                for (forward, reverse) in &pairs {
                    let pair_state = (state(&table, reverse), state(&table, forward));
                    assert_ne!(
                        pair_state,
                        ('A', 'X'),
                        "#18780 (R7 F1, reverses_first={reverses_first}): after call {calls} the \
                         reverse half is reaped while its forward is still crossed and un-Closed"
                    );
                    if reaped.iter().any(|e| e.key == *reverse) {
                        assert!(
                            closed.contains(forward),
                            "#18780 (R7 F1): a reverse reaped in call {calls} must have its \
                             forward Closed in the SAME call (that Close retires its shared copy)"
                        );
                    }
                }
                if !table.expiry_backlog() {
                    break;
                }
            }
            assert_eq!(table.len(), 0, "premise: the whole cohort drained");
            assert_eq!(cut_calls, 1, "premise: exactly one call was cut by the budget");
            assert!(
                completions > 0,
                "premise: the cut fell mid-pair, so pair completion ran (order reverses_first={reverses_first})"
            );
        }
        // Control, the RED shape: a reverse reaped while its forward is only
        // crossed resolves through the still-published shared copy, which is
        // exactly what pair completion prevents.
        let mut table = crate::session::SessionTable::new();
        let shared = std::sync::Arc::new(std::sync::Mutex::new(FastMap::default()));
        let shared_nat = std::sync::Arc::new(std::sync::Mutex::new(FastMap::default()));
        let shared_wire = std::sync::Arc::new(std::sync::Mutex::new(FastMap::default()));
        let indexes = SharedSessionOwnerRgIndexes::default();
        let forward = udp_replica_key(7);
        let reverse = crate::session::reverse_session_key(&forward, NatDecision::default());
        let mut reverse_md = reap_metadata();
        reverse_md.is_reverse = true;
        // The forward half is local and crossed; the reverse half is gone
        // locally (as a reap leaves it) and still published in shared.
        assert!(table.install_with_protocol(forward.clone(), reap_decision(None), reap_metadata(), t0, udp, 0));
        let mut reverse_row = shared_row(&reverse, 0, 0);
        reverse_row.metadata = reverse_md;
        shared.lock().unwrap().insert(reverse.clone(), reverse_row);
        let now = t0 + 61 * SEC;
        assert!(
            matches!(table.probe_with_origin_expiry(&reverse, now), P::Absent)
                && matches!(table.probe_with_origin_expiry(&forward, now), P::IdleCrossed),
            "control premise: the split shape (reverse Absent, forward crossed)"
        );
        let resolves = crate::afxdp::shared_ops::lookup_session_across_scopes_with_shared_and_payload(
            &mut table,
            &shared,
            &shared_nat,
            &shared_wire,
            &indexes,
            &reverse,
            now,
            0,
            0,
        )
        .is_some();
        assert!(
            resolves,
            "#18780 control: a split pair's reaped reverse resolves through its shared copy"
        );
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
                    neighbor_generation: 0,
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
                neighbor_generation: 0,
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
        SessionMetadata { forward_wire_alias_origin: false, ingress_zone: 1,
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
        nat_scope_ifindex: None, }
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
                    source_ifindex: 0,
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
            persistent_lease_hold: None,
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
        crate::nat::SyncedSourceNatDomains::default(),
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
            &std::sync::Arc::new(std::sync::Mutex::new(FastMap::default())),
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
        crate::nat::SyncedSourceNatDomains::default(),
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
            &std::sync::Arc::new(std::sync::Mutex::new(FastMap::default())),
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
        crate::session::SessionMetadata { forward_wire_alias_origin: false,
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
            nat_scope_ifindex: None,
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
                    source_ifindex: 0,
                    route_mtu: 0,
                    transport_route_mtu: 0,
                },
                nat,
                install_table_domain: 0,
                install_table_check: 0,
            },
            metadata: metadata(),
            persistent_lease_hold: None,
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
            &std::sync::Arc::new(std::sync::Mutex::new(FastMap::default())),
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
            "precondition: a live NAT64 flow reuses its endpoint-independent mapping",
        );

        reap(
            &forwarding,
            &[expired(
                key_for(c, 5000),
                Nat64State::forward_decision(snat, DST_V4, port),
            )],
        );
        let flow = crate::nat::SourceNatFlowKey {
            protocol: PROTO_TCP,
            src_ip: IpAddr::V6(c),
            dst_ip: IpAddr::V4(DST_V4),
            src_port: 5000,
            dst_port: 443,
            routing_scope: 0,
        };
        assert_eq!(
            forwarding.nat64.prefixes[0]
                .port_allocator
                .debug_persistent_lease_for_flow(
                    &flow,
                    crate::nat::PersistentNatPermit::AnyRemoteHost
                )
                .unwrap()
                .active_flows,
            0,
            "reap must drop the active flow reference"
        );

        let (snat2, port2) = forwarding
            .nat64
            .allocate_source(0, PROTO_TCP, c, DST_V4, 5000, 443, 3)
            .expect("post-reap allocate");
        assert_eq!(snat2, snat, "same one-address pool");
        assert_eq!(
            (snat2, port2),
            (snat, port),
            "reap releases the active session but preserves its idle BIB mapping"
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
        let flow1 = crate::nat::SourceNatFlowKey {
            protocol: PROTO_TCP,
            src_ip: IpAddr::V6(c1),
            dst_ip: IpAddr::V4(DST_V4),
            src_port: 5000,
            dst_port: 443,
            routing_scope: 0,
        };
        assert_eq!(
            forwarding.nat64.prefixes[0]
                .port_allocator
                .debug_persistent_lease_for_flow(
                    &flow1,
                    crate::nat::PersistentNatPermit::AnyRemoteHost
                )
                .unwrap()
                .active_flows,
            0,
            "reap must retire only the first flow's active BIB reference"
        );
        assert_eq!(
            forwarding.nat64.prefixes[0]
                .port_allocator
                .snapshot()
                .live_flows,
            1,
            "the second flow remains active"
        );

        let fresh1 = forwarding
            .nat64
            .allocate_source(0, PROTO_TCP, c1, DST_V4, 5000, 443, 3)
            .expect("post-reap allocate c1");
        assert_eq!(
            fresh1,
            (snat1, port1),
            "reap releases the active session but retains its idle BIB mapping"
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

        #[test]
        fn slice_pacing_constants_are_shared_after_extraction_17015() {
            const CONSTANTS: [&str; 6] = [
                "EXPORT_SLICE_BUDGET",
                "EXPORT_SLICE_EMITS",
                "EXPORT_SLICE_DEADLINE_NS",
                "CT_REFRESH_WINDOW_NS",
                "CT_SLICE_INTERVAL_NS",
                "CT_REFRESH_SLICE_BUDGET",
            ];
            let source_dir =
                std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/afxdp/worker/loop_body");
            let slice_pacing = std::fs::read_to_string(source_dir.join("slice_pacing.rs"))
                .expect("read shared slice_pacing.rs");
            let loop_body =
                std::fs::read_to_string(source_dir.join("mod.rs")).expect("read loop_body/mod.rs");
            let export_slice = std::fs::read_to_string(source_dir.join("export_slice.rs"))
                .expect("read export_slice.rs");
            let ct_slice =
                std::fs::read_to_string(source_dir.join("ct_slice.rs")).expect("read ct_slice.rs");
            assert!(
                slice_pacing.contains(
                    "const _: () = assert!(EXPORT_SLICE_EMITS <= EXPORT_SLICE_BUDGET);"
                ),
                "slice pacing must keep the emit cap within the scanned-slot budget"
            );
            for name in CONSTANTS {
                let declaration = format!("const {name}:");
                assert_eq!(
                    slice_pacing.matches(&declaration).count(),
                    1,
                    "{name} must have one definition in loop_body/slice_pacing.rs"
                );
                assert_eq!(
                    loop_body.matches(&declaration).count()
                        + export_slice.matches(&declaration).count()
                        + ct_slice.matches(&declaration).count(),
                    0,
                    "{name} must not be copied into worker_loop or its slices"
                );
            }
        }
    }
}

mod expiry_resync_lossless_wait_18780_tests {
    //! #18780 (R9 P1): an expiry continuation, a connected-but-unread event
    //! stream and the #2442 loss-of-sync resync, in ONE worker-loop iteration,
    //! driven through the production pieces in production order:
    //! `run_session_housekeeping` (expire, reap, Close flush) then
    //! `run_delta_recovery` (resync), both flushing through
    //! `flush_session_deltas_loop` with the per-iteration latches
    //! `worker_loop` resets.
    //!
    //! The Close flush times out once (one `WORKER_LOSSLESS_QUEUE_BUDGET`),
    //! latches loss-of-sync, and the same iteration's resync re-exports every
    //! owned forward row in 256-delta batches. #14646 gated the bulk kind per
    //! CALL, so each batch paid its own budget. With a budget cut the
    //! not-yet-reaped tail of an expiring cohort is still in the table and is
    //! re-exported too (on the base an expiry-only cohort was gone first), so
    //! the branch made the shape reachable from expiry alone; the per-call
    //! gate itself predates it and stalls a resync of LIVE rows the same way
    //! (second cell).
    //!
    //! The observable is the number of failed lossless pushes per kind
    //! (`LOSSLESS_FAILURES_18780`): against a connected-but-full stream each
    //! is exactly one budget wait, so the count is the stall in budgets
    //! without timing it (#8218). The elapsed time is reported, not asserted.
    use super::*;
    use crate::nat::NatDecision;
    use crate::session::{SessionDecision, SessionKey, SessionMetadata, SessionTable};
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::atomic::AtomicU32;

    const SEC: u64 = 1_000_000_000;
    // Out of range of every per-worker global (delete-drop epoch, purge flag),
    // so no other cell's state can reach this one.
    const WORKER: u32 = 18_780;

    fn key(i: u32) -> SessionKey {
        SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: crate::ip_proto::PROTO_UDP,
            src_ip: IpAddr::V4(Ipv4Addr::from(0x0a46_0000u32 + i)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 211)),
            src_port: 40_000,
            dst_port: 9,
            discriminator: Default::default(),
            routing_domain: 0,
        }
    }

    fn metadata(is_reverse: bool) -> SessionMetadata {
        SessionMetadata {
            forward_wire_alias_origin: false,
            ingress_zone: 1,
            egress_zone: 2,
            ingress_zone_check: 0,
            egress_zone_check: 0,
            ingress_ifindex: 0,
            ingress_vlan_id: 0,
            forward_ingress_vlan_id: None,
            owner_rg_id: 1,
            fabric_ingress: false,
            is_reverse,
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

    fn decision() -> SessionDecision {
        SessionDecision {
            resolution: ForwardingResolution {
                disposition: ForwardingDisposition::ForwardCandidate,
                local_ifindex: 0,
                egress_ifindex: 12,
                tx_ifindex: 12,
                tunnel_endpoint_id: 0,
                next_hop: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 1))),
                neighbor_mac: Some([0, 1, 2, 3, 4, 5]),
                src_mac: Some([6, 7, 8, 9, 10, 11]),
                tx_vlan_id: 0,
                source_ifindex: 0,
                route_mtu: 0,
                transport_route_mtu: 0,
            },
            nat: NatDecision::default(),
            install_table_domain: 0,
            install_table_check: 0,
        }
    }

    /// A locally authored UDP pair (ForwardFlow), forward hint first.
    fn install_pair(table: &mut SessionTable, i: u32, now_ns: u64) {
        let forward = key(i);
        let reverse = crate::session::reverse_session_key(&forward, NatDecision::default());
        let udp = crate::ip_proto::PROTO_UDP;
        assert!(table.install_with_protocol(forward, decision(), metadata(false), now_ns, udp, 0));
        assert!(table.install_with_protocol(reverse, decision(), metadata(true), now_ns, udp, 0));
    }

    /// A connected event stream whose reader never reads, already full.
    fn unread_full_stream() -> (
        Option<crate::event_stream::EventStreamWorkerHandle>,
        std::sync::mpsc::Receiver<crate::event_stream::EventFrame>,
    ) {
        unread_full_stream_with(4)
    }

    /// A connected event stream of `capacity` frames, already full, with the
    /// receiver handed back so a cell can start reading it later.
    fn unread_full_stream_with(
        capacity: usize,
    ) -> (
        Option<crate::event_stream::EventStreamWorkerHandle>,
        std::sync::mpsc::Receiver<crate::event_stream::EventFrame>,
    ) {
        let (handle, rx) = crate::event_stream::test_worker_handle_connected(
            capacity,
            crate::event_stream::DataplaneEventRateLimitConfig::default(),
        );
        let mut scratch = SessionTable::new();
        install_pair(&mut scratch, 999_999, SEC);
        let filler = scratch
            .drain_deltas(1)
            .into_iter()
            .next()
            .expect("an install emits an Open delta");
        let zones = ForwardingState::default().zone_name_to_id;
        for _ in 0..capacity {
            handle.push_delta(&filler, &zones);
        }
        (Some(handle), rx)
    }

    struct Iteration {
        incremental_waits: u64,
        bulk_waits: u64,
        reaped: usize,
        elapsed: std::time::Duration,
    }

    /// One worker-loop iteration's housekeeping + delta recovery.
    fn run_iteration(
        sessions: &mut SessionTable,
        now_ns: u64,
        event_stream: &Option<crate::event_stream::EventStreamWorkerHandle>,
    ) -> Iteration {
        let forwarding = ForwardingState::default();
        let shared = Arc::new(Mutex::new(FastMap::default()));
        let shared_nat = Arc::new(Mutex::new(FastMap::default()));
        let shared_wire = Arc::new(Mutex::new(FastMap::default()));
        let indexes = SharedSessionOwnerRgIndexes::default();
        let recent = Arc::new(Mutex::new(VecDeque::new()));
        let channel = crate::afxdp::types::RuntimeViewChannel::default();
        let reader = channel.reader();
        let rg_epochs: [AtomicU32; MAX_RG_EPOCHS] = std::array::from_fn(|_| AtomicU32::new(0));
        let lookup = WorkerBindingLookup::default();
        let commands = crate::afxdp::empty_worker_commands_by_id();
        let pptp_control = crate::session::pptp_control::PptpControlInbox::default();
        // The per-iteration latches `worker_loop` resets at the loop top.
        let mut worker_lossless_wedged = false;
        let mut worker_bulk_lossless_wedged = false;
        let mut flush_deltas = |sessions: &mut SessionTable,
                                bindings: &mut [BindingWorker],
                                wedged: &mut bool,
                                deltas: &[SessionDelta]| {
            flush_session_deltas_loop(
                sessions,
                bindings,
                SteeringMap::unshared_for_test(-1),
                -1,
                -1,
                &shared,
                &shared_nat,
                &shared_wire,
                &indexes,
                &recent,
                &[],
                commands,
                event_stream,
                &forwarding,
                &reader,
                wedged,
                &mut worker_bulk_lossless_wedged,
                WORKER,
                deltas,
            );
        };
        let before = crate::afxdp::session_delta::LOSSLESS_FAILURES_18780.with(|c| c.get());
        let rows_before = sessions.len();
        let start = std::time::Instant::now();
        let skipped = run_session_housekeeping(
            sessions,
            &mut [],
            &lookup,
            &forwarding,
            &BTreeMap::new(),
            now_ns,
            now_ns / SEC,
            &rg_epochs,
            SteeringMap::unshared_for_test(-1),
            -1,
            -1,
            WORKER,
            commands,
            &pptp_control,
            None,
            &[],
            &shared,
            &shared_nat,
            &shared_wire,
            &indexes,
            &reader,
            &mut worker_lossless_wedged,
            &mut Vec::new(),
            &mut Vec::new(),
            &mut flush_deltas,
        );
        assert!(!skipped, "premise: no deferred cleanup (no bindings, no gate contention)");
        let reaped = rows_before - sessions.len();
        let skipped = run_delta_recovery(
            sessions,
            &mut [],
            &lookup,
            &forwarding,
            0,
            WORKER,
            now_ns,
            -1,
            -1,
            &[],
            true,
            SteeringMap::unshared_for_test(-1),
            &shared,
            &shared_nat,
            &shared_wire,
            &indexes,
            &mut 0,
            &mut crate::afxdp::session_glue::DeleteDropSweep::default(),
            &mut crate::afxdp::session_glue::InstallTablePurge::default(),
            &mut Vec::new(),
            &reader,
            &mut worker_lossless_wedged,
            &mut flush_deltas,
        );
        assert!(!skipped, "premise: the resync ran to completion");
        let elapsed = start.elapsed();
        let after = crate::afxdp::session_delta::LOSSLESS_FAILURES_18780.with(|c| c.get());
        Iteration {
            incremental_waits: after.0 - before.0,
            bulk_waits: after.1 - before.1,
            reaped,
            elapsed,
        }
    }

    /// THE R9 SHAPE. 1,280 idle locally authored UDP pairs cross in one tick
    /// while the event stream is connected but unread. Each iteration reaps
    /// one budget slice, its Close flush times out once and latches
    /// loss-of-sync, and the same iteration's resync re-exports the overdue
    /// forward tail (1,152 rows after the first slice, 5 batches). The
    /// iteration must wait at most ONE budget per kind; two iterations show
    /// the bulk latch is per cycle (the second still attempts once, #14646).
    /// RED at 956417850a: 5 then 4 bulk waits (~6 s, then ~5 s, of worker loop
    /// in one iteration; `HEARTBEAT_STALE_AFTER` is 5 s).
    #[test]
    fn expiry_continuation_resync_waits_one_budget_per_kind_18780() {
        let t0 = 1_000 * SEC;
        let pairs = 1_280u32;
        let mut sessions = SessionTable::new();
        for i in 0..pairs {
            install_pair(&mut sessions, i, t0);
        }
        let _ = sessions.drain_deltas(usize::MAX);
        let _ = sessions.expire_stale_entries(t0);
        let (event_stream, _unread) = unread_full_stream();
        let now = t0 + 61 * SEC;
        let mut reports = Vec::new();
        for iteration in 0..2u64 {
            // Two seconds apart: a stalled iteration takes at least its one
            // incremental budget, and a refused export defers its owed retry
            // by `LOSS_RESYNC_RETRY_INTERVAL_NS` (#18780 review cycle 3).
            let it = run_iteration(&mut sessions, now + iteration * 2 * SEC, &event_stream);
            assert_eq!(
                it.reaped,
                crate::session::EXPIRY_PASS_MAX_REAPS,
                "premise: one budget slice per iteration"
            );
            assert!(sessions.expiry_backlog(), "premise: an expiry continuation is pending");
            reports.push(format!(
                "iteration {iteration}: {} incremental + {} bulk lossless waits, {:?}",
                it.incremental_waits, it.bulk_waits, it.elapsed
            ));
            assert_eq!(
                it.incremental_waits, 1,
                "premise: the Close flush hit the unread stream once ({reports:?})"
            );
            assert_eq!(
                it.bulk_waits, 1,
                "#18780 (R9 P1): one iteration's resync must wait at most ONE lossless budget for \
                 the bulk kind, and still attempt once per cycle (#14646): {reports:?}"
            );
        }
    }

    struct Resync {
        incremental_waits: u64,
        bulk_waits: u64,
    }

    /// One iteration's `run_delta_recovery` alone (the resync), flushing
    /// through `flush_session_deltas_loop` with fresh per-iteration latches and
    /// a REAL binding, so stream-refused deltas land in its bounded RPC
    /// fallback (`MAX_PENDING_SESSION_DELTAS`) exactly as in production.
    fn run_resync(
        sessions: &mut SessionTable,
        bindings: &mut [BindingWorker],
        now_ns: u64,
        event_stream: &Option<crate::event_stream::EventStreamWorkerHandle>,
    ) -> Resync {
        let forwarding = ForwardingState::default();
        let shared = Arc::new(Mutex::new(FastMap::default()));
        let shared_nat = Arc::new(Mutex::new(FastMap::default()));
        let shared_wire = Arc::new(Mutex::new(FastMap::default()));
        let indexes = SharedSessionOwnerRgIndexes::default();
        let recent = Arc::new(Mutex::new(VecDeque::new()));
        let channel = crate::afxdp::types::RuntimeViewChannel::default();
        let reader = channel.reader();
        let lookup = WorkerBindingLookup::default();
        let commands = crate::afxdp::empty_worker_commands_by_id();
        let mut worker_lossless_wedged = false;
        let mut worker_bulk_lossless_wedged = false;
        let mut flush_deltas = |sessions: &mut SessionTable,
                                bindings: &mut [BindingWorker],
                                wedged: &mut bool,
                                deltas: &[SessionDelta]| {
            flush_session_deltas_loop(
                sessions,
                bindings,
                SteeringMap::unshared_for_test(-1),
                -1,
                -1,
                &shared,
                &shared_nat,
                &shared_wire,
                &indexes,
                &recent,
                &[],
                commands,
                event_stream,
                &forwarding,
                &reader,
                wedged,
                &mut worker_bulk_lossless_wedged,
                WORKER,
                deltas,
            );
        };
        let before = crate::afxdp::session_delta::LOSSLESS_FAILURES_18780.with(|c| c.get());
        let skipped = run_delta_recovery(
            sessions,
            bindings,
            &lookup,
            &forwarding,
            0,
            WORKER,
            now_ns,
            -1,
            -1,
            &[],
            true,
            SteeringMap::unshared_for_test(-1),
            &shared,
            &shared_nat,
            &shared_wire,
            &indexes,
            &mut 0,
            &mut crate::afxdp::session_glue::DeleteDropSweep::default(),
            &mut crate::afxdp::session_glue::InstallTablePurge::default(),
            &mut Vec::new(),
            &reader,
            &mut worker_lossless_wedged,
            &mut flush_deltas,
        );
        assert!(!skipped, "premise: no deferred cleanup");
        let after = crate::afxdp::session_delta::LOSSLESS_FAILURES_18780.with(|c| c.get());
        Resync {
            incremental_waits: after.0 - before.0,
            bulk_waits: after.1 - before.1,
        }
    }

    /// The EXACT session-open payload (wire bytes after the per-send header)
    /// the LossResync export sends for every owned forward row the table holds
    /// now, built with the production emit and encoder. Comparing payloads, not
    /// counting frames, makes a duplicate unable to stand in for an omission
    /// and a stale copy unable to stand in for the row (#18780 cycle 3, Codex F4).
    fn expected_open_payloads(sessions: &mut SessionTable) -> std::collections::HashSet<Vec<u8>> {
        assert!(!sessions.has_pending_deltas(), "premise: an empty ring to borrow");
        let owner_rgs = sessions.all_owner_rg_ids();
        let candidates =
            crate::afxdp::forward_export_candidates_for_owner_rgs(sessions, &owner_rgs, u64::MAX);
        let mut payloads = std::collections::HashSet::new();
        // In ring-sized chunks, as the export itself does (the ring holds 4096).
        for chunk in candidates.chunks(2048) {
            for (key, decision, metadata, origin) in chunk.iter().cloned() {
                sessions.emit_open_delta_with_origin(key, decision, metadata, origin, true);
            }
            payloads.extend(sessions.drain_deltas(usize::MAX).iter().map(open_payload));
        }
        assert!(!sessions.delta_loss_pending(), "premise: the helper did not overflow the ring");
        payloads
    }

    fn open_payload(delta: &SessionDelta) -> Vec<u8> {
        let zones = ForwardingState::default().zone_name_to_id;
        let frame = crate::event_stream::EventFrame::encode_session_open_with_handshake_state(
            0,
            &delta.key,
            &delta.decision,
            &delta.metadata,
            &zones,
            delta.fabric_redirect_sync,
            delta.session_id,
            delta.tcp_close_class,
            delta.tcp_handshake_state,
            delta.source_nat_static,
            delta.pptp_call_ids,
            delta.counters.fwd_packets,
            delta.counters.rev_packets,
        );
        frame.as_bytes()[crate::event_stream::codec::FRAME_HEADER_SIZE..].to_vec()
    }

    /// Session-open payloads among `frames`, with how often each arrived.
    fn received_open_payloads(
        frames: &[crate::event_stream::EventFrame],
    ) -> std::collections::HashMap<Vec<u8>, usize> {
        let mut seen = std::collections::HashMap::new();
        for frame in frames {
            let bytes = frame.as_bytes();
            if bytes.len() > crate::event_stream::codec::FRAME_HEADER_SIZE
                && bytes[4] == crate::event_stream::codec::MSG_SESSION_OPEN
            {
                *seen
                    .entry(bytes[crate::event_stream::codec::FRAME_HEADER_SIZE..].to_vec())
                    .or_insert(0) += 1;
            }
        }
        seen
    }

    fn take_frames(
        rx: &std::sync::mpsc::Receiver<crate::event_stream::EventFrame>,
        into: &mut Vec<crate::event_stream::EventFrame>,
    ) {
        while let Ok(frame) = rx.try_recv() {
            into.push(frame);
        }
    }

    /// A reader thread that keeps reading `rx` until told to stop, returning
    /// every frame it read.
    fn spawn_reader(
        rx: std::sync::mpsc::Receiver<crate::event_stream::EventFrame>,
        stop: Arc<std::sync::atomic::AtomicBool>,
    ) -> std::thread::JoinHandle<Vec<crate::event_stream::EventFrame>> {
        std::thread::spawn(move || {
            let mut frames = Vec::new();
            while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                match rx.recv_timeout(std::time::Duration::from_millis(20)) {
                    Ok(frame) => frames.push(frame),
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                    Err(_) => break,
                }
            }
            take_frames(&rx, &mut frames);
            frames
        })
    }

    /// Drive owed-resync iterations (simulated time 20 ms apart, past the retry
    /// deferral) until the resync is no longer owed.
    fn run_until_delivered(
        sessions: &mut SessionTable,
        bindings: &mut [BindingWorker],
        mut now_ns: u64,
        event_stream: &Option<crate::event_stream::EventStreamWorkerHandle>,
    ) {
        let mut rounds = 0u32;
        while sessions.delta_loss_pending() {
            rounds += 1;
            assert!(rounds <= 500, "#18780: the owed resync was never delivered");
            now_ns += 20 * 1_000_000;
            let _ = run_resync(sessions, bindings, now_ns, event_stream);
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
    }

    fn owned_forward_tuples(sessions: &SessionTable) -> std::collections::HashSet<(String, u16, String, u16)> {
        let owner_rgs = sessions.all_owner_rg_ids();
        crate::afxdp::forward_export_candidates_for_owner_rgs(sessions, &owner_rgs, u64::MAX)
            .into_iter()
            .map(|(key, ..)| (key.src_ip.to_string(), key.src_port, key.dst_ip.to_string(), key.dst_port))
            .collect()
    }

    /// #18780 cycle 2 (R9 P1, R7 N1), strengthened in cycle 3 (Codex F4): a
    /// TRANSIENT consumer stall must not lose the resync. 6,000 owned rows,
    /// loss armed without any incremental failure this cycle (the ring- or
    /// fallback-overflow trigger), a connected stream that is full at the first
    /// bulk push.
    /// - Stalled iteration: one bulk budget, then the resync stays OWED and the
    ///   export stops, so the bounded fallback takes at most one page and drops
    ///   nothing.
    /// - The consumer resumes WITHOUT a reconnect (so no FullResync), and the
    ///   owed retries run until delivered.
    /// - EXACT identity: every owned row's export payload, as the table holds
    ///   it, arrives on the stream (decoded, not counted). The fallback, drained
    ///   as the RPC poll would, holds only copies of owned rows and dropped none.
    /// RED at 40c98be80e: the per-cycle latch routed the rest of the export to
    /// the fallback (R7 measured 0 rows streamed, 1,904 dropped) and nothing
    /// re-armed it.
    #[test]
    fn transient_consumer_stall_keeps_the_resync_owed_and_delivers_it_18780() {
        let t0 = 1_000 * SEC;
        let owned = 6_000u32;
        let fillers = 64usize;
        let mut sessions = SessionTable::new();
        for i in 0..owned {
            install_pair(&mut sessions, i, t0);
        }
        let _ = sessions.drain_deltas(usize::MAX);
        sessions.set_delta_loss();
        let (event_stream, rx) = unread_full_stream_with(fillers);
        let mut bindings = vec![BindingWorker::new_for_mirror_test(0, WORKER, 24, 0)];
        let stalled = run_resync(&mut sessions, &mut bindings, t0 + 10 * SEC, &event_stream);
        assert_eq!(stalled.incremental_waits, 0, "premise: no incremental send this cycle");
        assert_eq!(stalled.bulk_waits, 1, "premise: the stalled export waited one bulk budget");
        assert!(
            sessions.delta_loss_pending(),
            "#18780 (R9 P1 cycle 2): a bulk push the CONNECTED stream refused must keep the \
             resync owed; no reconnect FullResync follows a stall that just ends"
        );
        let after_stall = bindings[0].live.snapshot();
        assert_eq!(
            after_stall.session_delta_dropped, 0,
            "#18780 (R7 N1): the refused export must stop, not overflow the 4,096-slot fallback \
             ({} pending)",
            after_stall.session_delta_pending
        );
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let reader = spawn_reader(rx, stop.clone());
        run_until_delivered(&mut sessions, &mut bindings, t0 + 10 * SEC, &event_stream);
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        let frames = reader.join().expect("reader thread");
        let received = received_open_payloads(&frames);
        let expected = expected_open_payloads(&mut sessions);
        assert_eq!(expected.len(), owned as usize, "premise: one export payload per owned row");
        let missing = expected.iter().filter(|p| !received.contains_key(*p)).count();
        assert_eq!(
            missing, 0,
            "#18780 (Codex F4): {missing} of {owned} owned rows never reached the stream as the \
             table holds them ({} frames read)",
            frames.len()
        );
        let owned_tuples = owned_forward_tuples(&sessions);
        let fallback = bindings[0].live.drain_session_deltas(usize::MAX);
        for info in &fallback {
            assert!(
                owned_tuples.contains(&(info.src_ip.clone(), info.src_port, info.dst_ip.clone(), info.dst_port)),
                "#18780: the fallback held a delta for a row the table does not own: {}:{} -> {}:{}",
                info.src_ip,
                info.src_port,
                info.dst_ip,
                info.dst_port
            );
        }
        let after = bindings[0].live.snapshot();
        assert_eq!(after.session_delta_dropped, 0, "#18780: no resync delta was dropped");
        assert_eq!(after.session_delta_pending, 0, "the fallback was drained");
    }

    /// #18780 review cycle 3 (Codex F1, R7 R2): export progress is DURABLE.
    /// A consumer that keeps stalling for more than a budget within one export
    /// window (here: a 64-frame channel the test empties between rounds, with
    /// nothing reading in between) must not keep the resync's suffix away from
    /// the stream: each owed retry resumes at the first row that was refused,
    /// not at slot 0. Rows are re-read live: a row deleted before it was
    /// delivered is never exported, and a row replaced before it was delivered
    /// is exported as the table now holds it, never from a stale copy.
    /// Asserts EVERY owned row's exact payload arrives. RED at f5f0fd40d8: each
    /// retry restarted at slot 0 and re-sent the same 64-row prefix.
    #[test]
    fn recurring_stalls_cannot_starve_the_resync_suffix_18780() {
        let t0 = 1_000 * SEC;
        let owned = 300u32;
        let mut sessions = SessionTable::new();
        for i in 0..owned {
            install_pair(&mut sessions, i, t0);
        }
        let _ = sessions.drain_deltas(usize::MAX);
        sessions.set_delta_loss();
        let (handle, rx) = crate::event_stream::test_worker_handle_connected(
            64,
            crate::event_stream::DataplaneEventRateLimitConfig::default(),
        );
        let event_stream = Some(handle);
        let mut bindings = vec![BindingWorker::new_for_mirror_test(0, WORKER, 24, 0)];
        let mut frames = Vec::new();
        let mut now = t0 + 10 * SEC;
        // Round 0: the channel fills after 64 rows and the 65th push times out.
        let first = run_resync(&mut sessions, &mut bindings, now, &event_stream);
        assert_eq!(first.bulk_waits, 1, "premise: the first round stalls");
        assert!(sessions.delta_loss_pending(), "premise: the refused export stays owed");
        take_frames(&rx, &mut frames);
        // Between rounds, before they are delivered: delete one row and replace
        // another with a different decision (a new incarnation of the same key).
        let deleted = key(owned - 1);
        let replaced = key(owned - 2);
        let stale_payloads: Vec<Vec<u8>> = [&deleted, &replaced]
            .into_iter()
            .map(|k| {
                let md = metadata(false);
                sessions.emit_open_delta_with_origin(
                    (*k).clone(),
                    decision(),
                    md,
                    crate::session::SessionOrigin::ForwardFlow,
                    true,
                );
                open_payload(&sessions.drain_deltas(1)[0])
            })
            .collect();
        sessions.delete(&deleted);
        sessions.delete(&replaced);
        let mut new_decision = decision();
        new_decision.resolution.egress_ifindex = 13;
        new_decision.resolution.tx_ifindex = 13;
        assert!(sessions.install_with_protocol(
            replaced.clone(),
            new_decision,
            metadata(false),
            t0 + SEC,
            crate::ip_proto::PROTO_UDP,
            0,
        ));
        let mut rounds = 1u32;
        while sessions.delta_loss_pending() {
            rounds += 1;
            assert!(
                rounds <= owned.div_ceil(63) + 2,
                "#18780 (Codex F1): the owed resync made no progress across {rounds} stalls \
                 ({} frames read) — every retry restarts at the same prefix",
                frames.len()
            );
            now += 2 * SEC;
            let _ = run_resync(&mut sessions, &mut bindings, now, &event_stream);
            take_frames(&rx, &mut frames);
        }
        let received = received_open_payloads(&frames);
        let expected = expected_open_payloads(&mut sessions);
        assert_eq!(expected.len(), owned as usize - 1, "premise: one row deleted");
        let missing = expected.iter().filter(|p| !received.contains_key(*p)).count();
        assert_eq!(
            missing, 0,
            "#18780 (Codex F1): {missing} owned rows never reached the stream as the table holds them"
        );
        for (stale, what) in stale_payloads.iter().zip(["deleted", "replaced"]) {
            assert!(
                !received.contains_key(stale),
                "#18780: the {what} row was exported from a stale copy after it changed"
            );
        }
    }

    /// #18780 review cycle 3: a FRESH loss episode discards the resume point.
    /// After a refused export has delivered a prefix and recorded where to
    /// resume, a new loss (here `set_delta_loss`, standing for a failed
    /// incremental delta or a ring overflow) means the peer may now be wrong
    /// about rows in that prefix too, so the next export starts again at slot 0
    /// and re-sends the first row, rather than resuming after it.
    #[test]
    fn fresh_loss_restarts_the_resync_from_the_beginning_18780() {
        let t0 = 1_000 * SEC;
        let owned = 300u32;
        let mut sessions = SessionTable::new();
        for i in 0..owned {
            install_pair(&mut sessions, i, t0);
        }
        let _ = sessions.drain_deltas(usize::MAX);
        let first_row = {
            let owner_rgs = sessions.all_owner_rg_ids();
            let (key, decision, metadata, origin) =
                crate::afxdp::forward_export_candidates_for_owner_rgs(&sessions, &owner_rgs, u64::MAX)
                    .into_iter()
                    .next()
                    .expect("an owned row");
            sessions.emit_open_delta_with_origin(key, decision, metadata, origin, true);
            open_payload(&sessions.drain_deltas(1)[0])
        };
        sessions.set_delta_loss();
        let (handle, rx) = crate::event_stream::test_worker_handle_connected(
            64,
            crate::event_stream::DataplaneEventRateLimitConfig::default(),
        );
        let event_stream = Some(handle);
        let mut bindings = vec![BindingWorker::new_for_mirror_test(0, WORKER, 24, 0)];
        let now = t0 + 10 * SEC;
        let first = run_resync(&mut sessions, &mut bindings, now, &event_stream);
        assert_eq!(first.bulk_waits, 1, "premise: the first export stalls after a prefix");
        let mut frames = Vec::new();
        take_frames(&rx, &mut frames);
        assert!(
            received_open_payloads(&frames).contains_key(&first_row),
            "premise: the first row was in the delivered prefix"
        );
        // A fresh loss episode, then the consumer reads again.
        sessions.set_delta_loss();
        let _ = run_resync(&mut sessions, &mut bindings, now + 2 * SEC, &event_stream);
        let mut again = Vec::new();
        take_frames(&rx, &mut again);
        assert!(
            received_open_payloads(&again).contains_key(&first_row),
            "#18780: after a fresh loss the resync must restart at slot 0, not resume after the \
             previously delivered prefix"
        );
    }

    /// #18780 review cycle 3 (R8 H1, R7 R1): an OWED retry must not cost a
    /// quiet worker a full budget per iteration while the consumer stays
    /// stalled. 600 owned rows, no churn, a connected stream that is never read.
    /// The first (fresh) export waits one budget and is refused; every owed
    /// retry after that is a single zero-wait PROBE: no budget wait, no fallback
    /// copy, still owed. Once the consumer reads again the next retry delivers
    /// every row exactly. RED at f5f0fd40d8: every retry waited a full budget.
    #[test]
    fn owed_retry_probes_a_stalled_consumer_without_waiting_18780() {
        let t0 = 1_000 * SEC;
        let owned = 600u32;
        let mut sessions = SessionTable::new();
        for i in 0..owned {
            install_pair(&mut sessions, i, t0);
        }
        let _ = sessions.drain_deltas(usize::MAX);
        sessions.set_delta_loss();
        let (event_stream, rx) = unread_full_stream_with(4);
        let mut bindings = vec![BindingWorker::new_for_mirror_test(0, WORKER, 24, 0)];
        let mut now = t0 + 10 * SEC;
        let fresh = run_resync(&mut sessions, &mut bindings, now, &event_stream);
        assert_eq!(fresh.bulk_waits, 1, "premise: the fresh export waited one budget");
        assert!(sessions.delta_loss_pending(), "premise: refused and owed");
        let after_fresh = bindings[0].live.snapshot();
        // Inside the retry deferral nothing is attempted at all.
        let probes_before = crate::afxdp::session_delta::LOSS_RESYNC_PROBES_18780.with(|c| c.get());
        let early = run_resync(&mut sessions, &mut bindings, now + 1_000_000, &event_stream);
        let probes_after = crate::afxdp::session_delta::LOSS_RESYNC_PROBES_18780.with(|c| c.get());
        assert_eq!(
            (early.bulk_waits, probes_after.0 - probes_before.0),
            (0, 0),
            "#18780: an owed retry inside LOSS_RESYNC_RETRY_INTERVAL_NS must not probe yet"
        );
        assert!(sessions.delta_loss_pending(), "the deferred resync stays owed");
        for retry in 1..=5u32 {
            now += 20 * 1_000_000;
            let probes_before =
                crate::afxdp::session_delta::LOSS_RESYNC_PROBES_18780.with(|c| c.get());
            let it = run_resync(&mut sessions, &mut bindings, now, &event_stream);
            let probes_after =
                crate::afxdp::session_delta::LOSS_RESYNC_PROBES_18780.with(|c| c.get());
            assert_eq!(
                it.bulk_waits, 0,
                "#18780 (R8 H1): owed retry {retry} against a stalled consumer waited a full budget"
            );
            assert_eq!(
                (probes_after.0 - probes_before.0, probes_after.1 - probes_before.1),
                (1, 1),
                "#18780: owed retry {retry} must be exactly one refused zero-wait probe"
            );
            assert!(sessions.delta_loss_pending(), "retry {retry}: still owed");
        }
        let after_probes = bindings[0].live.snapshot();
        assert_eq!(
            (after_probes.session_delta_pending, after_probes.session_delta_dropped),
            (after_fresh.session_delta_pending, after_fresh.session_delta_dropped),
            "#18780: a refused probe must not copy into the fallback (it would repeat per retry)"
        );
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let reader = spawn_reader(rx, stop.clone());
        run_until_delivered(&mut sessions, &mut bindings, now, &event_stream);
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        let frames = reader.join().expect("reader thread");
        let received = received_open_payloads(&frames);
        let expected = expected_open_payloads(&mut sessions);
        let missing = expected.iter().filter(|p| !received.contains_key(*p)).count();
        assert_eq!(missing, 0, "#18780: {missing} of {owned} rows not delivered after recovery");
    }

    /// #14646 kept (the other half of the cycle-2 fix): a bulk push refused by
    /// a DISCONNECTED stream does not re-arm and does not stop the export —
    /// the reconnect FullResync covers it, and re-arming per pass would be the
    /// outage-long re-export storm #14646 removed. The export runs to the end
    /// into the fallback (600 rows, under its capacity).
    #[test]
    fn bulk_refusal_on_a_disconnected_stream_does_not_owe_the_resync_18780() {
        let t0 = 1_000 * SEC;
        let owned = 600u32;
        let mut sessions = SessionTable::new();
        for i in 0..owned {
            install_pair(&mut sessions, i, t0);
        }
        let _ = sessions.drain_deltas(usize::MAX);
        sessions.set_delta_loss();
        let (handle, _rx) = crate::event_stream::test_worker_handle(
            4,
            crate::event_stream::DataplaneEventRateLimitConfig::default(),
        );
        let event_stream = Some(handle);
        let mut bindings = vec![BindingWorker::new_for_mirror_test(0, WORKER, 24, 0)];
        let it = run_resync(&mut sessions, &mut bindings, t0 + 10 * SEC, &event_stream);
        assert_eq!(it.bulk_waits, 1, "premise: the first bulk push failed (instantly)");
        assert!(
            !sessions.delta_loss_pending(),
            "#14646: a disconnected stream's bulk refusal must not re-arm the resync"
        );
        let snap = bindings[0].live.snapshot();
        assert_eq!(
            snap.session_delta_pending,
            u64::from(owned),
            "#14646: the export is not stopped on a disconnected stream; every row reaches the fallback"
        );
        assert_eq!(snap.session_delta_dropped, 0);
    }

    /// SOURCE PIN for the cycle scope of the bulk latch. `worker_loop` is
    /// spawned only against real AF_XDP sockets, so no cell drives it (the
    /// #6971 precedent); the cells above construct the latch per iteration
    /// themselves. What makes it per CYCLE in production is that it is
    /// declared INSIDE the `while !stop` body, next to the #5468
    /// `worker_lossless_wedged = false` reset, and captured only by that
    /// iteration's `flush_deltas` closure. Hoisted above the loop it would
    /// close the bulk gate for the worker's lifetime after one failure.
    #[test]
    fn worker_loop_resets_the_bulk_lossless_latch_per_iteration_18780() {
        let src = include_str!("mod.rs");
        let find_once = |needle: &str| {
            let at = src.find(needle).unwrap_or_else(|| panic!("#18780: `{needle}` is gone"));
            assert_eq!(src.matches(needle).count(), 1, "#18780: `{needle}` must appear once");
            at
        };
        let loop_top = find_once("while !stop.load(Ordering::Relaxed) {");
        let incremental_reset = find_once("        worker_lossless_wedged = false;\n");
        let bulk_decl = find_once("let mut worker_bulk_lossless_wedged = false;");
        let closure = find_once("let mut flush_deltas = |");
        let capture = find_once("&mut worker_bulk_lossless_wedged,");
        assert!(
            loop_top < incremental_reset && incremental_reset < bulk_decl,
            "#18780: the bulk latch must be declared inside the worker loop, after the \
             #5468 per-iteration reset"
        );
        assert!(
            bulk_decl - incremental_reset < 1_000,
            "#18780: the bulk latch drifted away from the #5468 reset it mirrors"
        );
        assert!(
            bulk_decl < closure && closure < capture,
            "#18780: the per-iteration flush closure must be what captures the bulk latch"
        );
    }

    /// The same per-cycle bound for a resync of LIVE rows: one idle pair
    /// produces the Close that times out, and the resync re-exports 1,280
    /// live forward rows (5 batches). This predates #18780 (#14646's per-call
    /// bulk gate) and is RED on b57a950e21 as well; it pins that the fix is
    /// the cycle-scoped bulk latch, not anything about expiry.
    #[test]
    fn loss_resync_of_live_rows_waits_one_bulk_budget_per_cycle_18780() {
        let t0 = 1_000 * SEC;
        let mut sessions = SessionTable::new();
        install_pair(&mut sessions, 0, t0);
        for i in 1..=1_280u32 {
            install_pair(&mut sessions, i, t0 + 30 * SEC);
        }
        let _ = sessions.drain_deltas(usize::MAX);
        let _ = sessions.expire_stale_entries(t0);
        let (event_stream, _unread) = unread_full_stream();
        let it = run_iteration(&mut sessions, t0 + 61 * SEC, &event_stream);
        assert_eq!(it.reaped, 2, "premise: only the idle pair reaps");
        assert!(!sessions.expiry_backlog(), "premise: no expiry continuation here");
        assert_eq!(it.incremental_waits, 1, "premise: its Close hit the unread stream once");
        assert_eq!(
            it.bulk_waits, 1,
            "#18780: a resync of 1,280 live rows waited {} bulk lossless budgets in one \
             iteration ({:?}); the bulk gate must be per cycle",
            it.bulk_waits, it.elapsed
        );
    }
}
